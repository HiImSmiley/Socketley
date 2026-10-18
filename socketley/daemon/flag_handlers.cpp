#include "flag_handlers.h"
#include "../shared/util/duration_parse.h"
#include "../shared/runtime/runtime_instance.h"
#include "../shared/net/unix_listener.h"
#include "../shared/net/dial_address.h"
#include "../shared/persist/appending_file.h"
#include "../shared/lua/lua_context.h"
#include "../shared/crypto/tls_context.h"
#include "../shared/crypto/cert_keeper.h"
#include <iostream>
#include <algorithm>
#include <charconv>
#include <sys/un.h>
#include <arpa/inet.h>
#include "../shared/runtime/runtime_manager.h"
#include "../runtime/server/server_instance.h"
#include "../runtime/client/client_instance.h"
#include "../runtime/proxy/proxy_instance.h"
#include "../runtime/cache/cache_instance.h"
#include "../runtime/storage/storage_instance.h"
#include "../runtime/dns/dns_instance.h"
#include "../runtime/sync/sync_instance.h"
#include "../runtime/idp/idp_instance.h"
#include "../runtime/db/db_instance.h"
#include "../runtime/idp/idp_logic.h"
#include "../shared/net/ip_block.h"
#include "../shared/net/dns_feed.h"
#include "../runtime/storage/s3_vhost.h"
#include "../runtime/storage/sync_mode.h"
#include "../runtime/storage/sync_runners.h"
#include "../shared/util/number_parse.h"

// Five flags that describe inbound traffic are refused on a client, which
// accepts none, because they were stored and reported by `show` while no code
// implemented them -- and giving each a meaning on a client is a feature to
// design rather than a gap to plug.
static bool refuse_inbound_flag_on_client(const runtime_instance* instance,
                                          const char* flag, const char* why)
{
    if (!instance || instance->get_type() != runtime_client)
        return false;

    std::cout << flag << " does not apply to a client: " << why << "\n";
    return true;
}

// The mirror, for the one flag that describes OUTBOUND traffic.  --reconnect is
// read in client_instance.cpp and nowhere else, and the man page documents it
// under CLIENT FLAGS, so on a server, proxy or cache it was stored, persisted
// and reported by `show` with nothing to act on it -- the same shape the three
// above were refused for.
static bool refuse_client_flag_elsewhere(const runtime_instance* instance,
                                         const char* flag, const char* why)
{
    if (!instance || instance->get_type() == runtime_client)
        return false;

    std::cout << flag << " applies to a client: " << why << "\n";
    return true;
}

// Defined further down, beside validate_listen_value; declared here because
// the common create and edit parsers dispatch to it.
static int parse_listen_flag(runtime_instance* rt, const parsed_args& pa, size_t& i);

// `--bind address`, the IPv4 address the port is bound on alone, 0.0.0.0 for every address again.
static int apply_bind_address(runtime_instance* instance, std::string_view address)
{
    in_addr a{};
    const std::string text(address);
    if (::inet_pton(AF_INET, text.c_str(), &a) != 1)
    {
        std::cout << "invalid listen address \"" << text << "\": an IPv4 address such as 127.0.0.1\n";
        return 1;
    }
    instance->set_bind_address(a.s_addr == htonl(INADDR_ANY) ? std::string() : text);
    return 0;
}

// `-p port`, or `-p address:port` for --bind and -p at once.
static int parse_port_flag(runtime_instance* instance, std::string_view value)
{
    const size_t colon = value.rfind(':');
    uint16_t port;
    if (!socketley::parse_whole(colon == std::string_view::npos ? value : value.substr(colon + 1), port))
    {
        std::cout << "invalid port number\n";
        return 1;
    }
    if (colon != std::string_view::npos && apply_bind_address(instance, value.substr(0, colon)) != 0)
        return 1;
    instance->set_port(port);
    return 0;
}

// Every duration flag parses through here, so the next one cannot grow a
// second grammar and no site can forget the range check.
// --acme and --acme-email, one decision for create and edit: the names are checked as a CA would take them for
// HTTP-01, and the certificate's files become the ones --acme keeps.
static int parse_acme_flag(runtime_instance* instance, const parsed_args& pa, size_t& i)
{
    const bool email = pa.hashes[i] == fnv1a("--acme-email");
    const char* flag = email ? "--acme-email" : "--acme";
    if (!tls_role_has_handshake(instance->get_type()) || instance->get_type() == runtime_client)
    {
        std::cout << flag << ": a certificate is issued for a runtime that listens: server, proxy, cache or storage\n";
        return 1;
    }
    if (i + 1 >= pa.count)
    {
        std::cout << flag << (email ? " requires an address\n" : " requires a name, or several separated by commas\n");
        return 1;
    }
    const std::string_view v = pa.args[++i];
    if (email)
    {
        if (v.find('@') == std::string_view::npos || v.find_first_of(" ,\t") != std::string_view::npos)
        {
            std::cout << "--acme-email: '" << v << "' is not an address\n";
            return 1;
        }
        instance->set_acme_email(v);
        return 0;
    }
    instance->set_acme_domains(v);
    const auto& names = instance->get_acme_domains();
    if (names.empty())
    {
        std::cout << "--acme requires a name, or several separated by commas\n";
        return 1;
    }
    for (const std::string& name : names)
    {
        // A wildcard of one label, which is proven over DNS-01 by a dns runtime serving its zone.
        const std::string_view n = std::string_view(name).starts_with("*.") ? std::string_view(name).substr(2)
                                                                             : std::string_view(name);
        // A name whose last label is all digits is an address, which no challenge proves.
        const std::string_view tld = n.substr(n.rfind('.') + 1);
        const bool ok = n.size() <= 253 && n.find('.') != std::string::npos && n.front() != '.' && n.back() != '.' &&
                        !std::all_of(tld.begin(), tld.end(), [](char ch) { return ch >= '0' && ch <= '9'; }) &&
                        std::all_of(n.begin(), n.end(), [](char ch) {
                            return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
                                   ch == '-' || ch == '.';
                        });
        if (!ok)
        {
            std::cout << "--acme: '" << name << "' is not a name a certificate is issued for "
                         "(no addresses, at least one dot, a wildcard only as its first label)\n";
            return 1;
        }
    }
    instance->set_tls(true);
    instance->set_cert_path(cert_keeper::acme_cert_path(names.front()));
    instance->set_key_path(cert_keeper::acme_key_path(names.front()));
    return 0;
}

// --domain on every runtime but storage, whose own flag of that name also names its buckets' virtual hosts.
static int parse_domain_flag(runtime_instance* instance, const parsed_args& pa, size_t& i)
{
    if (instance->get_type() == runtime_storage)
        return -1;
    // Without a value -- nothing follows, or the next word is another flag -- the runtime's own name is its name.
    const bool own = i + 1 >= pa.count || pa.args[i + 1].starts_with('-');
    if (!own && pa.args[i + 1].empty())
    {
        std::cout << "--domain requires a name, or several separated by commas; alone it takes the runtime's\n";
        return 1;
    }
    const std::string_view v = own ? instance->get_name() : pa.args[++i];
    for (size_t p = 0; p <= v.size();)
    {
        const size_t comma = std::min(v.find(',', p), v.size());
        if (std::string why; !dns_feed::valid_name(v.substr(p, comma - p), why))
        {
            std::cout << "--domain: " << why << (own ? " (the runtime's name, taken since no name followed --domain)" : "")
                      << "\n";
            return 1;
        }
        p = comma + 1;
    }
    instance->set_domains(v);
    return 0;
}

static bool parse_duration_flag(const char* flag, std::string_view value,
                                uint64_t max_seconds, uint64_t& out)
{
    switch (parse_duration_seconds(value, max_seconds, out))
    {
        case duration_parse::ok:
            return true;
        case duration_parse::out_of_range:
            std::cout << flag << " value out of range\n";
            return false;
        default:
            std::cout << "invalid " << flag << " value\n";
            return false;
    }
}

// The counts, next to the durations and for the same reason: three flags spelled
// this check by hand and all three forgot the end pointer, so `--retry 2x` was
// two and said nothing about the x.
static bool parse_count_flag(const char* flag, std::string_view value,
                             int min, int& out)
{
    int val = 0;
    auto [ptr, ec] = std::from_chars(value.data(), value.data() + value.size(), val);
    if (ec == std::errc::result_out_of_range)
    {
        std::cout << flag << " value out of range\n";
        return false;
    }
    if (ec != std::errc{} || ptr != value.data() + value.size() || val < min)
    {
        std::cout << "invalid " << flag << " value\n";
        return false;
    }
    out = val;
    return true;
}

int parse_common_flags(runtime_instance* instance, const parsed_args& pa,
                       size_t& i, bool& autostart, std::string& lua_script)
{
    switch (pa.hashes[i])
    {
        // One flag for where a runtime runs, naming the non-default state,
        // because two names for one bit have to be kept level in four places
        // -- and --listen is here rather than in three per-type parsers for
        // the same reason.
        case fnv1a("--listen"):
            return parse_listen_flag(instance, pa, i);

        // N workers sharing one listening socket, for the saturated case and
        // no other, asked for and never inferred, because sharding is correct
        // exactly when nothing is shared between connections and nothing can
        // detect that.
        // ─── WHO MAY DECLARE IT ─────────────────────────────────────────────
        // The whole rule with the reason for each half is in
        // shards_config_refusal, asked from five places, so a second copy of
        // the reasoning is a copy that drifts.
        case fnv1a("--shards"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--shards requires a count\n";
                return 1;
            }

            uint32_t n = 0;
            if (!socketley::parse_whole(pa.args[++i], n) || n < 1)
            {
                std::cout << "invalid shard count\n";
                return 1;
            }

            // Asked here with only the facts that cannot change further along
            // the command line, because a --listen path may be typed after
            // this flag and the whole question is asked again in cmd_create.
            if (const std::string msg = shards_config_refusal(
                    instance->get_type(), n); !msg.empty())
            {
                std::cout << msg;
                return 1;
            }

            instance->set_shards(n);
            return 0;
        }

        case fnv1a("-p"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "-p requires a port\n";
                return 1;
            }
            return parse_port_flag(instance, pa.args[++i]);
        }

        case fnv1a("--bind"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--bind requires an address\n";
                return 1;
            }
            return apply_bind_address(instance, pa.args[++i]);
        }

        case fnv1a("-s"):
            autostart = true;
            return 0;

        case fnv1a("--test"):
            instance->set_test_mode(true);
            return 0;

        case fnv1a("--log"):
            if (i + 1 >= pa.count)
            {
                std::cout << "--log requires a file\n";
                return 1;
            }
            // Absolute only: a relative path is resolved against the
            // daemon's working directory, not the operator's.
            if (const std::string why = socketley::appended_path_refusal(
                    "--log", pa.args[i + 1]); !why.empty())
            {
                std::cout << why;
                return 1;
            }
            instance->set_log_file(pa.args[++i]);
            return 0;

        case fnv1a("-w"):
            if (i + 1 >= pa.count)
            {
                std::cout << "-w requires a file\n";
                return 1;
            }
            // Absolute only: a relative path is resolved against the
            // daemon's working directory, not the operator's.
            if (const std::string why = socketley::appended_path_refusal(
                    "-w", pa.args[i + 1]); !why.empty())
            {
                std::cout << why;
                return 1;
            }
            instance->set_write_file(pa.args[++i]);
            return 0;

        // Recorded here and loaded by the caller, because loading snapshots
        // the `self` table as the instance is at that moment, so `--lua x.lua
        // -p 9000` and `-p 9000 --lua x.lua` gave one runtime two different
        // self.port values.
        case fnv1a("--lua"):
            if (i + 1 >= pa.count)
            {
                std::cout << "--lua requires a Lua script path\n";
                return 1;
            }
            lua_script = pa.args[++i];
            return 0;

        case fnv1a("-b"):
            instance->set_bash_output(true);
            return 0;

        case fnv1a("-bp"):
            instance->set_bash_output(true);
            instance->set_bash_prefix(true);
            return 0;

        case fnv1a("-bt"):
            instance->set_bash_output(true);
            instance->set_bash_timestamp(true);
            return 0;

        case fnv1a("-bpt"):
        case fnv1a("-btp"):
            instance->set_bash_output(true);
            instance->set_bash_prefix(true);
            instance->set_bash_timestamp(true);
            return 0;

        case fnv1a("--max-connections"):
        case fnv1a("--max-conn"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--max-connections requires a value\n";
                return 1;
            }
            uint32_t max;
            if (!socketley::parse_whole(pa.args[++i], max))
            {
                std::cout << "invalid max-connections value\n";
                return 1;
            }
            if (refuse_inbound_flag_on_client(instance, "--max-connections",
                                              "it opens one connection outward and "
                                              "accepts none"))
                return 1;
            instance->set_max_connections(max);
            return 0;
        }

        case fnv1a("--rate-limit"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--rate-limit requires a value\n";
                return 1;
            }
            double rate;
            if (!parse_double(pa.args[++i], rate) || rate < 0)
            {
                std::cout << "invalid rate-limit value\n";
                return 1;
            }
            if (refuse_inbound_flag_on_client(instance, "--rate-limit",
                                              "it limits what a peer may send to a "
                                              "runtime, and nothing connects to a client"))
                return 1;
            instance->set_rate_limit(rate);
            return 0;
        }

        case fnv1a("--global-rate-limit"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--global-rate-limit requires a value\n";
                return 1;
            }
            double rate;
            if (!parse_double(pa.args[++i], rate) || rate < 0)
            {
                std::cout << "invalid global-rate-limit value\n";
                return 1;
            }
            // The fourth of them, and the one whose sibling was already
            // refused: check_global_rate_limit() is called by the cache, the
            // server and the proxy and by no client code at all, and "across
            // all connections" means nothing to a runtime that has one.
            if (refuse_inbound_flag_on_client(instance, "--global-rate-limit",
                                              "it caps the total across all "
                                              "inbound connections, and a client "
                                              "has one outbound connection -- "
                                              "--rate-limit is refused here for "
                                              "the same reason"))
                return 1;
            instance->set_global_rate_limit(rate);
            return 0;
        }

        case fnv1a("--idle-timeout"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--idle-timeout requires a value\n";
                return 1;
            }
            uint64_t secs;
            if (!parse_duration_flag("idle-timeout", pa.args[++i],
                                     std::numeric_limits<uint32_t>::max(), secs))
                return 1;
            if (refuse_inbound_flag_on_client(instance, "--idle-timeout",
                                              "it reaps idle inbound connections, and "
                                              "a client's own connection is reconnected "
                                              "the moment it is dropped"))
                return 1;
            instance->set_idle_timeout(static_cast<uint32_t>(secs));
            return 0;
        }

        case fnv1a("--read-buffer"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--read-buffer requires a size value\n";
                return 1;
            }
            size_t bytes;
            if (!parse_size_suffix(pa.args[++i], bytes))
            {
                std::cout << "invalid --read-buffer value (use K/M/G suffix)\n";
                return 1;
            }
            instance->set_read_buffer(bytes);
            return 0;
        }

        case fnv1a("--write-buffer"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--write-buffer requires a size value\n";
                return 1;
            }
            size_t bytes;
            if (!parse_size_suffix(pa.args[++i], bytes))
            {
                std::cout << "invalid --write-buffer value (use K/M/G suffix)\n";
                return 1;
            }
            // Every runtime has a write queue, so unlike --idle-timeout there
            // is nothing to refuse this on: the client's queue is the one that
            // fills when its server stops reading.
            instance->set_write_buffer(bytes);
            return 0;
        }

        case fnv1a("--drain"):
            // The fifth of them.  get_drain() is read by the server, the proxy
            // and the cache and by no client code, so a client stored it,
            // persisted it and reported it in `show` while its teardown did the
            // opposite of what the flag promises: m_write_queue.clear(), under
            // a comment reading "Drain write queue".
            //
            // Refused rather than implemented, and that is a judgement worth
            // stating.  Half the documented meaning -- "closes its listener" --
            // has nothing to say about a runtime with no listener, and the
            // other half is a feature to design: what a client owes its peer on
            // the way down, and for how long, is not answered by copying the
            // server's loop.  This helper's own rule is what decides it.
            if (refuse_inbound_flag_on_client(instance, "--drain",
                                              "it flushes the write queues of "
                                              "inbound connections before closing "
                                              "them, and a client has none -- what "
                                              "it owes its peer on the way down is "
                                              "a separate question"))
                return 1;
            instance->set_drain(true);
            return 0;

        case fnv1a("--reconnect"):
        {
            if (refuse_client_flag_elsewhere(
                    instance, "--reconnect",
                    "it re-dials a connection this runtime made, and a server, "
                    "a proxy and a cache take connections rather than make them"))
                return 1;
            int max_attempts = 0; // default: infinite
            if (i + 1 < pa.count)
            {
                // The value is optional, so only a token that is entirely a
                // number is one: `--reconnect -s` is this flag with no value
                // followed by the autostart flag, and has to stay that way.
                int val = 0;
                auto sv = std::string_view(pa.args[i + 1]);
                auto [p, e] = std::from_chars(sv.data(), sv.data() + sv.size(), val);
                const bool numeric = p == sv.data() + sv.size() &&
                                     (e == std::errc{} || e == std::errc::result_out_of_range);
                if (numeric)
                {
                    // ─── -1 IS THE STORED "OFF" ─────────────────────────────
                    // m_reconnect defaults to -1 = disabled, so a negative
                    // count switched off the one thing this flag exists to
                    // switch on -- silently, at exit 0, and `show` then printed
                    // no reconnect line at all, because a field at its default
                    // is not printed.
                    if (e == std::errc::result_out_of_range)
                    {
                        std::cout << "--reconnect value out of range: " << sv << "\n"
                                     "  Give it no value or 0 for unlimited attempts, "
                                     "which is what a number that large was asking "
                                     "for.\n";
                        return 1;
                    }
                    if (val < 0)
                    {
                        std::cout << "--reconnect does not take " << sv << "\n"
                                     "  It is the flag that turns reconnection ON: "
                                     "give it no value or 0 for unlimited attempts, "
                                     "or a positive count to stop after that many.\n"
                                     "  Reconnection is off until the flag is given, "
                                     "so leaving it out is how it stays off.\n";
                        return 1;
                    }
                    max_attempts = val;
                    i++;
                }
            }
            instance->set_reconnect(max_attempts);
            return 0;
        }

        // Stored for the roles that perform a handshake and refused for a type
        // that would answer cleartext on an endpoint `inspect` calls
        // encrypted, while whether the set is complete is decided once parsing
        // is done.
        case fnv1a("--tls"):
            if (!tls_role_has_handshake(instance->get_type()))
            {
                std::cout << tls_not_implemented_error("--tls");
                return 1;
            }
            instance->set_tls(true);
            return 0;

        case fnv1a("--acme"):
        case fnv1a("--acme-email"):
            return parse_acme_flag(instance, pa, i);

        case fnv1a("--domain"):
            return parse_domain_flag(instance, pa, i);

        case fnv1a("--cert"):
        case fnv1a("--key"):
        case fnv1a("--ca"):
        {
            const uint32_t which = pa.hashes[i];
            const char* flag = which == fnv1a("--cert") ? "--cert"
                             : which == fnv1a("--key")  ? "--key"
                                                        : "--ca";
            if (!tls_role_has_handshake(instance->get_type()))
            {
                std::cout << tls_not_implemented_error(flag);
                return 1;
            }
            if (i + 1 >= pa.count)
            {
                std::cout << flag << " requires a file\n";
                return 1;
            }
            const std::string_view path = pa.args[++i];
            if (which == fnv1a("--cert"))     instance->set_cert_path(path);
            else if (which == fnv1a("--key")) instance->set_key_path(path);
            else                              instance->set_ca_path(path);
            return 0;
        }

        case fnv1a("--group"):
        case fnv1a("-g"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--group requires a value\n";
                return 1;
            }
            instance->set_group(pa.args[++i]);
            return 0;
        }

        // ── Where this runtime's I/O runs ────────────────────────────────────
        // --cpus takes max, a range or a list, refusing a set this machine
        // cannot satisfy rather than rounding up to "all" -- and there is
        // deliberately no --rings, because a count of rings is a count of I/O
        // threads in disguise.
        case fnv1a("--cpus"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--cpus requires a CPU set: max | 0-3 | 0,1,2,3\n";
                return 1;
            }
            cpu_set_spec cpus;
            std::string err;
            if (!parse_cpu_set(pa.args[++i], cpus, err))
            {
                std::cout << "invalid --cpus value: " << err << "\n";
                return 1;
            }
            instance->set_cpus(cpus);
            return 0;
        }

        default:
            return -1;
    }
}

bool parse_server_mode(uint32_t hash, server_mode& mode)
{
    switch (hash)
    {
        case fnv1a("inout"):  mode = mode_inout;  return true;
        case fnv1a("in"):     mode = mode_in;     return true;
        case fnv1a("out"):    mode = mode_out;     return true;
        case fnv1a("master"): mode = mode_master;  return true;
        default: return false;
    }
}

// A comma separated set, because the recipients are disjoint and a message can
// reach more than one of them: `sender,master` is an answer to whoever spoke
// and a copy to the master, which had no spelling at all before.
bool parse_server_send_to(std::string_view value, uint8_t& mask, std::string& bad)
{
    mask = 0;
    size_t start = 0;
    while (start <= value.size())
    {
        size_t comma = value.find(',', start);
        if (comma == std::string_view::npos)
            comma = value.size();
        std::string_view one = value.substr(start, comma - start);
        // A trailing or doubled comma is a typo, not an empty recipient.
        if (one.empty())
        {
            bad = "<empty>";
            return false;
        }
        switch (fnv1a(one))
        {
            case fnv1a("sender"): mask |= send_to_sender; break;
            case fnv1a("others"): mask |= send_to_others; break;
            case fnv1a("master"): mask |= send_to_master; break;
            default:
                bad = std::string(one);
                return false;
        }
        if (comma == value.size())
            break;
        start = comma + 1;
    }
    return mask != 0;
}

bool parse_client_mode(uint32_t hash, client_mode& mode)
{
    switch (hash)
    {
        case fnv1a("inout"): mode = client_mode_inout; return true;
        case fnv1a("in"):    mode = client_mode_in;    return true;
        case fnv1a("out"):   mode = client_mode_out;   return true;
        default: return false;
    }
}

bool parse_cache_mode(uint32_t hash, cache_mode& mode)
{
    switch (hash)
    {
        case fnv1a("readonly"):  mode = cache_mode_readonly;  return true;
        case fnv1a("readwrite"): mode = cache_mode_readwrite; return true;
        case fnv1a("admin"):     mode = cache_mode_admin;     return true;
        default: return false;
    }
}

// `--listen unix:/path`, shared by create and edit so the two cannot disagree,
// refusing at configuration time because the kernel truncates a path of 108
// bytes without saying so and a trimmed path names a different socket.
std::string validate_listen_value(std::string_view value, std::string& out)
{
    if (!value.starts_with("unix:"))
        return "takes unix:/path/to.sock; a TCP port is -p";

    const std::string_view path = value.substr(5);
    if (path.empty())
        return "no socket path after the unix: prefix";

    // The path rules themselves — absolute, under sun_path, no NUL — are
    // shared/net/unix_listener.h's, the same ones every setup() re-asks on the
    // restore and import paths this parser never sees.
    if (std::string why = socketley::unix_sock::path_refusal(path); !why.empty())
        return why;

    out.assign(path);
    return {};
}

static int parse_listen_flag(runtime_instance* rt, const parsed_args& pa, size_t& i)
{
    // A client dials out and listens on nothing, so the flag cannot mean
    // anything on one — but the thing the operator probably wants exists, and
    // the refusal says where it is rather than "unknown flag".
    if (rt->get_type() == runtime_client)
    {
        std::cout << "--listen does not apply to a client: a client dials out"
                     " and has no listener.  The connect side of a unix socket"
                     " is -t unix:/path/to.sock\n";
        return 1;
    }
    if (i + 1 >= pa.count)
    {
        std::cout << "--listen requires an address (unix:/path/to.sock)\n";
        return 1;
    }
    std::string path;
    const std::string why = validate_listen_value(pa.args[++i], path);
    if (!why.empty())
    {
        std::cout << "--listen: " << why << "\n";
        return 1;
    }
    rt->set_listen_path(path);
    return 0;
}

// Spellings that were removed, answered by name instead of as "unknown flag":
// each one worked yesterday and what it named still exists under another name.
//
// Ahead of the switch and not a case in it, because a case IS the flag surface
// -- test_edit_flag_surface reads the parsers' `case fnv1a("-...")` labels and
// requires every one of them to be documented, which a removed flag cannot be.
// One copy for both server parsers, for the reason the style file gives.
static int refuse_removed_server_flag(uint32_t which)
{
    if (which == fnv1a("--master-forward"))
    {
        std::cout << "--master-forward is now --send-to master: it was one "
                     "recipient carrying its own flag, and the recipients are "
                     "a set\n";
        return 1;
    }
    return -1;
}

int parse_server_flags(server_instance* srv, const parsed_args& pa, size_t& i,
                       runtime_manager* mgr, std::string_view /*name*/)
{
    if (const int removed = refuse_removed_server_flag(pa.hashes[i]); removed >= 0)
        return removed;

    switch (pa.hashes[i])
    {

        case fnv1a("--mode"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--mode requires a value\n";
                return 1;
            }
            ++i;
            server_mode mode;
            if (!parse_server_mode(pa.hashes[i], mode))
            {
                std::cout << "unknown mode: " << pa.args[i] << "\n";
                return 1;
            }
            srv->set_mode(mode);
            return 0;
        }
        case fnv1a("--send-to"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--send-to requires sender, others or master, "
                             "comma separated\n";
                return 1;
            }
            ++i;
            uint8_t mask = 0;
            std::string bad;
            if (!parse_server_send_to(pa.args[i], mask, bad))
            {
                std::cout << "unknown --send-to: " << (bad.empty() ? pa.args[i] : bad)
                          << " (sender, others, master; comma separated)\n";
                return 1;
            }
            srv->set_send_to(mask);
            return 0;
        }
        case fnv1a("--cache"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--cache requires a cache name\n";
                return 1;
            }
            srv->set_cache_name(pa.args[++i]);
            srv->set_runtime_manager(mgr);
            return 0;
        }
        case fnv1a("--udp"):
            srv->set_udp(true);
            return 0;
        case fnv1a("--master-pw"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--master-pw requires a password\n";
                return 1;
            }
            srv->set_master_pw(pa.args[++i]);
            return 0;
        }
        case fnv1a("--http"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--http requires a directory path\n";
                return 1;
            }
            srv->set_http_dir(pa.args[++i]);
            return 0;
        }
        case fnv1a("--http-cache"):
            srv->set_http_cache(true);
            return 0;
        case fnv1a("-u"):
        case fnv1a("--upstream"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "-u requires host:port\n";
                return 1;
            }
            std::string_view upstream_str = pa.args[++i];
            // A refused address fails the whole flag rather than being
            // skipped, because coming up with one of two requested targets is
            // a silent half-configuration.
            size_t start = 0;
            size_t semi;
            while ((semi = upstream_str.find(';', start)) != std::string_view::npos)
            {
                auto addr = upstream_str.substr(start, semi - start);
                if (!addr.empty() && !srv->add_upstream_target(addr))
                {
                    std::cout << "invalid upstream address: " << addr
                              << " (the port must be a number between 1 and 65535)\n";
                    return 1;
                }
                start = semi + 1;
            }
            if (start < upstream_str.size())
            {
                auto addr = upstream_str.substr(start);
                if (!srv->add_upstream_target(addr))
                {
                    std::cout << "invalid upstream address: " << addr
                              << " (the port must be a number between 1 and 65535)\n";
                    return 1;
                }
            }
            return 0;
        }
        default:
            return -1;
    }
}

int parse_client_flags(client_instance* cli, const parsed_args& pa, size_t& i,
                       std::string_view /*name*/)
{
    switch (pa.hashes[i])
    {
        case fnv1a("-t"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "-t requires a target address\n";
                return 1;
            }
            // A unix: target is judged now and not at dial time, because this
            // is the last point at which the operator is told which socket
            // they asked for.
            ++i;
            if (std::string_view v = pa.args[i]; v.starts_with("unix:"))
            {
                if (std::string why =
                        socketley::unix_sock::path_refusal(v.substr(5));
                    !why.empty())
                {
                    std::cout << "-t: " << why << "\n";
                    return 1;
                }
            }
            else if (std::string why = socketley::dial_addr::refusal(v); !why.empty())
            {
                std::cout << "-t: " << why << "\n";
                return 1;
            }
            cli->set_target(pa.args[i]);
            return 0;
        }
        case fnv1a("--mode"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--mode requires a value\n";
                return 1;
            }
            ++i;
            client_mode mode;
            if (!parse_client_mode(pa.hashes[i], mode))
            {
                std::cout << "unknown mode: " << pa.args[i] << "\n";
                return 1;
            }
            cli->set_mode(mode);
            return 0;
        }
        case fnv1a("--udp"):
            cli->set_udp(true);
            return 0;
        default:
            return -1;
    }
}

// --auth and --redirect-https, which create and edit read alike; -1 for any other flag.
static int parse_proxy_gate_flag(proxy_instance* proxy, const parsed_args& pa, size_t& i)
{
    switch (pa.hashes[i])
    {
        case fnv1a("--auth"):
        {
            if (i + 1 >= pa.count || pa.args[i + 1].starts_with('-'))
            {
                std::cout << "--auth requires bearer:<file> or basic:<file>\n";
                return 1;
            }
            const std::string_view spec = pa.args[++i];
            if (spec == "none")
            {
                proxy->set_auth("");
                return 0;
            }
            if (const std::string why = proxy_auth::spec_error(spec); !why.empty())
            {
                std::cout << why << "\n";
                return 1;
            }
            proxy->set_auth(spec);
            return 0;
        }
        // The port HTTPS is reached on, 443 when none is given.
        case fnv1a("--redirect-https"):
        {
            uint16_t port = 443;
            if (i + 1 < pa.count && !pa.args[i + 1].starts_with('-'))
            {
                const std::string_view v = pa.args[++i];
                if (v == "none")
                    port = 0;
                else
                {
                    unsigned long n = 0;
                    const auto [end, ec] = std::from_chars(v.data(), v.data() + v.size(), n);
                    if (ec != std::errc{} || end != v.data() + v.size() || n == 0 || n > 65535)
                    {
                        std::cout << "--redirect-https takes the port HTTPS is reached on, or none\n";
                        return 1;
                    }
                    port = static_cast<uint16_t>(n);
                }
            }
            proxy->set_https_redirect(port);
            return 0;
        }
        default:
            return -1;
    }
}

int parse_proxy_flags(proxy_instance* proxy, const parsed_args& pa, size_t& i,
                      std::string_view /*name*/)
{
    if (const int rc = parse_proxy_gate_flag(proxy, pa, i); rc >= 0)
        return rc;
    switch (pa.hashes[i])
    {
        case fnv1a("--backend"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--backend requires a value\n";
                return 1;
            }
            std::string_view backend_str = pa.args[++i];

            size_t start = 0;
            size_t comma;
            while ((comma = backend_str.find(',', start)) != std::string_view::npos)
            {
                // An empty component is a doubled comma and not a backend,
                // which is the rule --upstream's own loop already applies.
                if (comma > start)
                    proxy->add_backend(backend_str.substr(start, comma - start));
                start = comma + 1;
            }
            if (start < backend_str.size())
                proxy->add_backend(backend_str.substr(start));
            return 0;
        }
        case fnv1a("--strategy"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--strategy requires a value\n";
                return 1;
            }
            ++i;
            switch (pa.hashes[i])
            {
                case fnv1a("round-robin"):
                    proxy->set_strategy(strategy_round_robin);
                    break;
                case fnv1a("random"):
                    proxy->set_strategy(strategy_random);
                    break;
                case fnv1a("lua"):
                    proxy->set_strategy(strategy_lua);
                    break;
                default:
                    std::cout << "unknown strategy: " << pa.args[i] << "\n";
                    return 1;
            }
            return 0;
        }
        case fnv1a("--protocol"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--protocol requires a value\n";
                return 1;
            }
            ++i;
            switch (pa.hashes[i])
            {
                case fnv1a("http"):
                    proxy->set_protocol(protocol_http);
                    break;
                case fnv1a("tcp"):
                    proxy->set_protocol(protocol_tcp);
                    break;
                default:
                    std::cout << "unknown protocol: " << pa.args[i] << "\n";
                    return 1;
            }
            return 0;
        }
        case fnv1a("--health-check"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--health-check requires tcp or http\n";
                return 1;
            }
            ++i;
            switch (pa.hashes[i])
            {
                case fnv1a("tcp"):
                    proxy->set_health_check(mesh_config::health_tcp);
                    break;
                case fnv1a("http"):
                    proxy->set_health_check(mesh_config::health_http);
                    break;
                default:
                    std::cout << "unknown health-check type: " << pa.args[i] << "\n";
                    return 1;
            }
            return 0;
        }
        case fnv1a("--health-interval"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--health-interval requires a value\n";
                return 1;
            }
            uint64_t secs;
            if (!parse_duration_flag("health-interval", pa.args[++i],
                                     std::numeric_limits<int>::max(), secs))
                return 1;
            if (secs == 0)
            {
                std::cout << "invalid health-interval value\n";
                return 1;
            }
            proxy->set_health_interval(static_cast<int>(secs));
            return 0;
        }
        case fnv1a("--health-path"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--health-path requires a value\n";
                return 1;
            }
            {
                // Only the leading slash is checked, because parsed_args
                // splits on whitespace before this runs, so a whitespace check
                // here would be unreachable code with a comment claiming it
                // guarded something.
                const std::string_view hp = pa.args[i + 1];
                if (hp.empty() || hp.front() != '/')
                {
                    std::cout << "--health-path must begin with '/'\n";
                    return 1;
                }
            }
            proxy->set_health_path(pa.args[++i]);
            return 0;
        }
        case fnv1a("--health-threshold"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--health-threshold requires a value\n";
                return 1;
            }
            int val;
            if (!parse_count_flag("health-threshold", pa.args[++i], 1, val))
                return 1;
            proxy->set_health_threshold(val);
            return 0;
        }
        case fnv1a("--circuit-threshold"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--circuit-threshold requires a value\n";
                return 1;
            }
            int val;
            if (!parse_count_flag("circuit-threshold", pa.args[++i], 1, val))
                return 1;
            proxy->set_circuit_threshold(val);
            return 0;
        }
        case fnv1a("--circuit-timeout"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--circuit-timeout requires a value\n";
                return 1;
            }
            uint64_t secs;
            if (!parse_duration_flag("circuit-timeout", pa.args[++i],
                                     std::numeric_limits<int>::max(), secs))
                return 1;
            if (secs == 0)
            {
                std::cout << "invalid circuit-timeout value\n";
                return 1;
            }
            proxy->set_circuit_timeout(static_cast<int>(secs));
            return 0;
        }
        // How long a backend may take to produce the first byte, defaulted
        // rather than opt-in because an operator who has never heard of this
        // flag is the one it has to protect.
        case fnv1a("--backend-timeout"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--backend-timeout requires a value\n";
                return 1;
            }
            uint64_t secs;
            if (!parse_duration_flag("backend-timeout", pa.args[++i],
                                     std::numeric_limits<int>::max(), secs))
                return 1;
            proxy->set_backend_timeout(static_cast<int>(secs));
            return 0;
        }
        case fnv1a("--retry"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--retry requires a value\n";
                return 1;
            }
            int val;
            if (!parse_count_flag("retry", pa.args[++i], 0, val))
                return 1;
            proxy->set_retry_count(val);
            return 0;
        }
        case fnv1a("--retry-all"):
            proxy->set_retry_all(true);
            return 0;
        // --client-ca is the listener's and --client-cert/--client-key are the
        // backend leg's, with completeness decided once parsing is done
        // because the flag that completes a pair may be further along.
        case fnv1a("--client-ca"):
        case fnv1a("--client-cert"):
        case fnv1a("--client-key"):
        {
            const uint32_t which = pa.hashes[i];
            const char* flag = which == fnv1a("--client-ca")   ? "--client-ca"
                             : which == fnv1a("--client-cert") ? "--client-cert"
                                                               : "--client-key";
            if (i + 1 >= pa.count)
            {
                std::cout << flag << " requires a file\n";
                return 1;
            }
            const std::string_view path = pa.args[++i];
            if (which == fnv1a("--client-ca"))        proxy->set_mesh_client_ca(path);
            else if (which == fnv1a("--client-cert")) proxy->set_mesh_client_cert(path);
            else                                      proxy->set_mesh_client_key(path);
            return 0;
        }
        case fnv1a("--sidecar"):
            // Sidecar mode: shorthand for health-check tcp + circuit + retry + drain
            proxy->set_health_check(mesh_config::health_tcp);
            proxy->set_circuit_threshold(5);
            proxy->set_circuit_timeout(30);
            proxy->set_retry_count(2);
            proxy->set_drain(true);
            return 0;
        default:
            return -1;
    }
}

int parse_cache_flags(cache_instance* cache, const parsed_args& pa, size_t& i,
                      std::string_view /*name*/)
{
    switch (pa.hashes[i])
    {
        case fnv1a("--persistent"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--persistent requires a file path\n";
                return 1;
            }
            cache->set_persistent(pa.args[++i]);
            return 0;
        }
        // How far behind the disk may run: writes are journaled beside the
        // dump and flushed at this cadence, and whether --persistent was
        // typed at all is judged once every flag has been seen.
        case fnv1a("--persistent-interval"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--persistent-interval requires a value\n";
                return 1;
            }
            uint64_t secs;
            if (!parse_duration_flag("persistent-interval", pa.args[++i],
                                     std::numeric_limits<uint32_t>::max(), secs))
                return 1;
            if (secs == 0)
            {
                std::cout << "invalid persistent-interval value\n";
                return 1;
            }
            cache->set_persist_interval(static_cast<uint32_t>(secs));
            return 0;
        }
        case fnv1a("--mode"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--mode requires a value\n";
                return 1;
            }
            ++i;
            cache_mode mode;
            if (!parse_cache_mode(pa.hashes[i], mode))
            {
                std::cout << "unknown mode: " << pa.args[i] << "\n";
                return 1;
            }
            cache->set_mode(mode);
            return 0;
        }
        case fnv1a("--maxmemory"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--maxmemory requires a size value\n";
                return 1;
            }
            size_t bytes;
            if (!parse_size_suffix(pa.args[++i], bytes))
            {
                std::cout << "invalid maxmemory value (use K/M/G suffix)\n";
                return 1;
            }
            cache->set_max_memory(bytes);
            return 0;
        }
        case fnv1a("--eviction"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--eviction requires a policy\n";
                return 1;
            }
            ++i;
            switch (pa.hashes[i])
            {
                case fnv1a("noeviction"):
                    cache->set_eviction(evict_none);
                    break;
                case fnv1a("allkeys-lru"):
                    cache->set_eviction(evict_allkeys_lru);
                    break;
                case fnv1a("allkeys-random"):
                    cache->set_eviction(evict_allkeys_random);
                    break;
                default:
                    std::cout << "unknown eviction policy: " << pa.args[i] << "\n";
                    return 1;
            }
            return 0;
        }
        case fnv1a("--resp"):
            cache->set_resp_forced(true);
            return 0;
        // Off by default, and deliberately a flag rather than a consequence of
        // --shards: see cache_instance::set_cluster() for what it gives up.
        case fnv1a("--cluster"):
            cache->set_cluster(true);
            return 0;
        case fnv1a("--public"):
            cache->set_public(true);
            return 0;
        case fnv1a("--replicate"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--replicate requires host:port\n";
                return 1;
            }
            // An empty value means follows nobody, which set_replicate_target
            // documents; anything else has to be an address a follower can
            // dial, port included, because there is no second flag to take one
            // from.
            if (std::string_view v = pa.args[++i]; !v.empty())
            {
                if (std::string why = socketley::dial_addr::refusal(v, true);
                    !why.empty())
                {
                    std::cout << "--replicate: " << why << "\n";
                    return 1;
                }
            }
            cache->set_replicate_target(pa.args[i]);
            return 0;
        }
        // The cluster's own word for the process it makes of a replica, which it numbers so a restart is told from a survivor.
        case fnv1a("--cluster-replica"):
        {
            if (!cache->is_cluster_owned())
            {
                std::cout << "--cluster-replica is the cluster's to set: `socketley cluster create cache ...` makes replicas\n";
                return 1;
            }
            uint64_t incarnation = 0;
            const std::string_view v = i + 1 < pa.count ? pa.args[i + 1] : std::string_view{};
            const auto [end, ec] = std::from_chars(v.data(), v.data() + v.size(), incarnation);
            if (ec != std::errc{} || end != v.data() + v.size() || incarnation == 0)
            {
                std::cout << "--cluster-replica requires a nonzero number\n";
                return 1;
            }
            ++i;
            cache->set_cluster_replica(incarnation);
            return 0;
        }
        default:
            return -1;
    }
}

int parse_dns_flags(dns_instance* dns, const parsed_args& pa, size_t& i, std::string_view /*name*/)
{
    switch (pa.hashes[i])
    {
        // A zone file, absolute as the CLI makes it; given again for each further zone.
        case fnv1a("--zone"):
        {
            const std::string_view v = i + 1 < pa.count ? pa.args[i + 1] : std::string_view{};
            if (v.empty() || v.find('\0') != std::string_view::npos)
            {
                std::cout << "--zone requires the path of a zone file, or several separated by commas\n";
                return 1;
            }
            ++i;
            dns->add_zone(v);
            return 0;
        }
        // The secondaries that may copy a zone whole: addresses and blocks.
        case fnv1a("--transfer"):
        {
            std::vector<socketley::ip_block> blocks;
            std::string bad;
            if (i + 1 >= pa.count || !socketley::ip_block::parse_list(pa.args[i + 1], blocks, bad))
            {
                std::cout << "--transfer requires addresses or blocks such as 192.0.2.7 or 2001:db8::/32"
                          << (bad.empty() ? std::string{} : ", not '" + bad + "'") << "\n";
                return 1;
            }
            dns->set_transfer(pa.args[++i]);
            return 0;
        }
        // The secondaries told of a new serial, checked whole when the runtime is created.
        case fnv1a("--notify"):
        {
            if (i + 1 >= pa.count || pa.args[i + 1].empty())
            {
                std::cout << "--notify requires addresses, with :port where it is not 53\n";
                return 1;
            }
            dns->set_notify(pa.args[++i]);
            return 0;
        }
        // The entrance the names of runtimes are reached through: made by `create` when it does not exist yet,
        // named <dns>-proxy when not given, and none at all with `--proxy none`.
        case fnv1a("--proxy"):
        {
            if (i + 1 >= pa.count || pa.args[i + 1].empty() || pa.args[i + 1].starts_with('-'))
            {
                std::cout << "--proxy requires the name of the entrance (a proxy without --backend), or none\n";
                return 1;
            }
            dns->set_proxy(pa.args[++i]);
            return 0;
        }
        case fnv1a("--proxy-port"):
        {
            uint32_t port = 0;
            if (i + 1 >= pa.count || !socketley::parse_whole(pa.args[i + 1], port) || port == 0 || port > 65535)
            {
                std::cout << "--proxy-port requires the port the entrance listens on, 1 to 65535\n";
                return 1;
            }
            ++i;
            dns->set_proxy_port(static_cast<uint16_t>(port));
            return 0;
        }
        // The addresses the names runtimes are reached by are published with, checked whole at create.
        case fnv1a("--publish"):
        {
            if (i + 1 >= pa.count || pa.args[i + 1].empty())
            {
                std::cout << "--publish requires this machine's public addresses, IPv4 and IPv6, comma-separated\n";
                return 1;
            }
            dns->set_publish(pa.args[++i]);
            return 0;
        }
        case fnv1a("--rrl"):
        {
            uint32_t n = 0;
            if (i + 1 >= pa.count || !socketley::parse_whole(pa.args[i + 1], n) || n > 1000000)
            {
                std::cout << "--rrl requires responses a second per client network, 0 for no limit\n";
                return 1;
            }
            ++i;
            dns->set_rrl(n);
            return 0;
        }
        default:
            return -1;
    }
}

int parse_sync_flags(sync_instance* sy, const parsed_args& pa, size_t& i, std::string_view /*name*/)
{
    switch (pa.hashes[i])
    {
        // The directory whose files are carried, which must be there when the runtime starts.
        case fnv1a("--dir"):
        {
            if (i + 1 >= pa.count || pa.args[i + 1].empty() || pa.args[i + 1].front() != '/')
            {
                std::cout << "--dir requires the absolute path of the directory whose files are carried\n";
                return 1;
            }
            sy->set_dir(pa.args[++i]);
            return 0;
        }
        // Where they go: a runtime of this daemon and a bucket, or a URL and a bucket; more than one, comma-separated.
        case fnv1a("--storage"):
        {
            if (i + 1 >= pa.count || pa.args[i + 1].empty() || pa.args[i + 1].find('/') == std::string_view::npos)
            {
                std::cout << "--storage requires a runtime and a bucket (ui/photos), or a URL and one "
                             "(https://storage.example/photos)\n";
                return 1;
            }
            sy->set_storage(pa.args[++i]);
            return 0;
        }
        // The key everything is written under, beneath the bucket.
        case fnv1a("--prefix"):
        {
            if (i + 1 >= pa.count || pa.args[i + 1].empty() || pa.args[i + 1].front() == '/')
            {
                std::cout << "--prefix requires a key below the bucket, without a leading slash\n";
                return 1;
            }
            sy->set_prefix(pa.args[++i]);
            return 0;
        }
        // The file access_key and secret_key are read from.
        case fnv1a("--credentials"):
        {
            if (i + 1 >= pa.count || pa.args[i + 1].empty())
            {
                std::cout << "--credentials requires the path of a file holding access_key and secret_key\n";
                return 1;
            }
            sy->set_credentials(pa.args[++i]);
            return 0;
        }
        case fnv1a("--mode"):
        {
            sync_mode m{};
            if (i + 1 >= pa.count || !parse_sync_runtime_mode(pa.args[i + 1], m))
            {
                std::cout << "--mode requires out (the directory to the storage), in (the storage to the "
                             "directory) or inout (both)\n";
                return 1;
            }
            ++i;
            sy->set_mode(m);
            return 0;
        }
        // How often the whole directory is walked; `never` walks it once at a start and then only when told.
        case fnv1a("--every"):
        {
            const std::string_view v = i + 1 < pa.count ? pa.args[i + 1] : std::string_view{};
            uint64_t secs = 0;
            if (v == "never")
                secs = 0;
            else if (v.empty() || parse_duration_seconds(v, 365ull * 24 * 3600, secs) != duration_parse::ok)
            {
                std::cout << "--every requires how often the whole directory is walked, as 30s, 10m, 1h or 1d, "
                             "or never\n";
                return 1;
            }
            ++i;
            sy->set_every(static_cast<uint32_t>(secs));
            return 0;
        }
        // Shell patterns matched against the path below --dir.
        case fnv1a("--exclude"):
        {
            if (i + 1 >= pa.count || pa.args[i + 1].empty())
            {
                std::cout << "--exclude requires patterns such as '*.tmp, .git, node_modules', comma-separated\n";
                return 1;
            }
            sy->set_exclude(pa.args[++i]);
            return 0;
        }
        case fnv1a("--repositories"):
        {
            if (i + 1 >= pa.count || pa.args[i + 1].empty())
            {
                std::cout << "--repositories requires the file a storage runtime writes for a user's sync runtime\n";
                return 1;
            }
            sy->set_repositories(pa.args[++i]);
            return 0;
        }
        default:
            return -1;
    }
}

int parse_idp_flags(idp_instance* ip, const parsed_args& pa, size_t& i, std::string_view /*name*/)
{
    switch (pa.hashes[i])
    {
        // The relying parties: `id secret redirect...` a line, `-` as the secret of a public client.
        case fnv1a("--clients"):
        {
            if (i + 1 >= pa.count || pa.args[i + 1].empty() || pa.args[i + 1].front() != '/')
            {
                std::cout << "--clients requires the absolute path of a file with one client a line: "
                             "id secret redirect...\n";
                return 1;
            }
            ip->set_clients(pa.args[++i]);
            return 0;
        }
        // The https address the provider is reached at, which every token names as its issuer.
        case fnv1a("--issuer"):
        {
            const std::string_view v = i + 1 < pa.count ? pa.args[i + 1] : std::string_view{};
            if (v.empty() || socketley::idp::url_host(v).empty() || v.find_first_of("?#") != std::string_view::npos)
            {
                std::cout << "--issuer requires the https address the provider is reached at, "
                             "such as https://auth.example.com\n";
                return 1;
            }
            ip->set_issuer(pa.args[++i]);
            return 0;
        }
        // The domain the sign-in cookie is set for, so a proxy on any name below it shares the sign-in.
        case fnv1a("--cookie-domain"):
        {
            const std::string_view v = i + 1 < pa.count ? pa.args[i + 1] : std::string_view{};
            if (v.empty() || v.find_first_of("/:; ,") != std::string_view::npos || v.find('.') == std::string_view::npos)
            {
                std::cout << "--cookie-domain requires a domain such as example.com, whose names share the sign-in\n";
                return 1;
            }
            ip->set_cookie_domain(pa.args[++i]);
            return 0;
        }
        default:
            return -1;
    }
}

int parse_db_flags(db_instance* db, const parsed_args& pa, size_t& i, std::string_view /*name*/)
{
    const std::string_view next = i + 1 < pa.count ? pa.args[i + 1] : std::string_view{};
    switch (pa.hashes[i])
    {
        // The collections, their access and their indexes, a line each.
        case fnv1a("--schema"):
            if (next.empty() || next.front() != '/')
            {
                std::cout << "--schema requires the absolute path of a file with one collection a line: "
                             "name access index...\n";
                return 1;
            }
            db->set_schema_path(pa.args[++i]);
            return 0;
        // The service keys, `name secret` a line.
        case fnv1a("--keys"):
            if (next.empty() || next.front() != '/')
            {
                std::cout << "--keys requires the absolute path of a file with one key a line: name secret\n";
                return 1;
            }
            db->set_keys_path(pa.args[++i]);
            return 0;
        // The idp runtime whose accounts own documents.
        case fnv1a("--idp"):
            if (next.empty() || next.find_first_of("/ ") != std::string_view::npos)
            {
                std::cout << "--idp requires the name of an idp runtime of this daemon\n";
                return 1;
            }
            db->set_idp(pa.args[++i]);
            return 0;
        // The web origins a browser may call it from.
        case fnv1a("--origins"):
            if (next.empty() || next.find_first_of(" ;") != std::string_view::npos)
            {
                std::cout << "--origins requires origins such as https://app.example.com, comma-separated, or *\n";
                return 1;
            }
            db->set_origins(pa.args[++i]);
            return 0;
        case fnv1a("--max-bytes"):
        {
            size_t bytes = 0;
            if (next.empty() || !parse_size_suffix(pa.args[++i], bytes))
            {
                std::cout << "--max-bytes requires a size such as 2G\n";
                return 1;
            }
            db->set_max_bytes(bytes);
            return 0;
        }
        // The memory the documents last read are kept in; the rest come from the disk.
        case fnv1a("--cache"):
        {
            size_t bytes = 0;
            if (next.empty() || !parse_size_suffix(pa.args[++i], bytes))
            {
                std::cout << "--cache requires a size such as 256M\n";
                return 1;
            }
            db->set_cache_bytes(bytes);
            return 0;
        }
        // The database this one copies, and the file holding the key it asks with.
        case fnv1a("--replicate"):
            if (!next.starts_with("http://") && !next.starts_with("https://"))
            {
                std::cout << "--replicate requires the http or https address of the database to copy\n";
                return 1;
            }
            db->set_replicate(pa.args[++i]);
            return 0;
        case fnv1a("--replicate-key"):
            if (next.empty() || next.front() != '/')
            {
                std::cout << "--replicate-key requires the absolute path of a file holding a key's secret\n";
                return 1;
            }
            db->set_replicate_key(pa.args[++i]);
            return 0;
        // Backups into a directory, how often, and how many are kept.
        case fnv1a("--backup-dir"):
            if (next.empty() || next.front() != '/')
            {
                std::cout << "--backup-dir requires the absolute path of a directory\n";
                return 1;
            }
            db->set_backup_dir(pa.args[++i]);
            return 0;
        case fnv1a("--backup-every"):
        {
            uint64_t secs = 0;
            if (next.empty() || parse_duration_seconds(next, 365ull * 24 * 3600, secs) != duration_parse::ok || secs < 1)
            {
                std::cout << "--backup-every requires how often, as 6h or 1d\n";
                return 1;
            }
            ++i;
            db->set_backup_every(static_cast<uint32_t>(secs));
            return 0;
        }
        case fnv1a("--backup-keep"):
        {
            uint32_t n = 0;
            const auto r = std::from_chars(next.data(), next.data() + next.size(), n);
            if (next.empty() || r.ec != std::errc() || r.ptr != next.data() + next.size() || n < 1 || n > 10000)
            {
                std::cout << "--backup-keep requires how many backups are kept, from 1\n";
                return 1;
            }
            ++i;
            db->set_backup_keep(n);
            return 0;
        }
        default:
            return -1;
    }
}

int parse_storage_flags(storage_instance* stg, const parsed_args& pa, size_t& i,
                        std::string_view /*name*/)
{
    switch (pa.hashes[i])
    {
        // Where the buckets live.  Made absolute by the CLI against the
        // caller's directory, because the worker resolves it against its own.
        case fnv1a("--dir"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--dir requires a directory path\n";
                return 1;
            }
            const std::string_view dir = pa.args[++i];
            if (dir.empty() || dir.find('\0') != std::string_view::npos)
            {
                std::cout << "--dir requires a directory path\n";
                return 1;
            }
            stg->set_dir(dir);
            return 0;
        }
        // Off by default: an endpoint that answers anybody has to be asked to.
        case fnv1a("--anonymous"):
            stg->set_anonymous(true);
            return 0;
        // The idp runtime whose sign-in the web interface takes.
        case fnv1a("--idp"):
        {
            if (i + 1 >= pa.count || pa.args[i + 1].empty() || pa.args[i + 1].find_first_of("/ ") != std::string_view::npos)
            {
                std::cout << "--idp requires the name of an idp runtime of this daemon\n";
                return 1;
            }
            stg->set_idp(pa.args[++i]);
            return 0;
        }
        // Off by default, as S3 has ACLs: a bucket given no ownership controls takes them.
        case fnv1a("--acls"):
            stg->set_acls(true);
            return 0;
        // The one pair every request is signed with.
        case fnv1a("--access-key"):
        case fnv1a("--secret-key"):
        {
            const bool access = pa.hashes[i] == fnv1a("--access-key");
            if (i + 1 >= pa.count || pa.args[i + 1].empty())
            {
                std::cout << (access ? "--access-key" : "--secret-key") << " requires a value\n";
                return 1;
            }
            const std::string_view v = pa.args[++i];
            if (access)
                stg->set_access_key(v);
            else
                stg->set_secret_key(v);
            return 0;
        }
        // Several pairs, one access:secret per line, re-read when the file changes.
        case fnv1a("--credentials"):
        {
            if (i + 1 >= pa.count || pa.args[i + 1].empty())
            {
                std::cout << "--credentials requires a file path\n";
                return 1;
            }
            stg->set_credentials_file(pa.args[++i]);
            return 0;
        }
        // The master key of SSE-S3, a file only its owner may read, so the key itself is never on a command line.
        case fnv1a("--sse-key-file"):
        {
            if (i + 1 >= pa.count || pa.args[i + 1].empty())
            {
                std::cout << "--sse-key-file requires a file path\n";
                return 1;
            }
            stg->set_sse_key_file(pa.args[++i]);
            return 0;
        }
        // The endpoint's own names, under which a Host of `<bucket>.<domain>` is virtual-hosted style.
        case fnv1a("--domain"):
        {
            std::vector<std::string> domains;
            std::string why;
            // Without a value, the runtime's own name, as on every other runtime.
            const bool own = i + 1 >= pa.count || pa.args[i + 1].starts_with('-');
            const std::string_view v = own ? stg->get_name() : pa.args[i + 1];
            if (!socketley::storage::parse_domains(v, domains, why))
            {
                std::cout << (own ? "--domain: the runtime's name is no domain name; give one: " : "") << why << "\n";
                return 1;
            }
            if (!own)
                ++i;
            stg->set_domain(v);
            return 0;
        }
        // When an answered write reaches the disk: before its answer, within --fsync-interval after it, or at a stop.
        case fnv1a("--fsync"):
        {
            socketley::storage::sync_mode m;
            if (i + 1 >= pa.count || !socketley::storage::parse_sync_mode(pa.args[i + 1], m))
            {
                std::cout << "--fsync requires always, interval or never\n";
                return 1;
            }
            stg->set_fsync(pa.args[++i]);
            return 0;
        }
        // Which sync runtimes pull the users' git repositories: none, one for the storage, or one per user.
        case fnv1a("--sync"):
        {
            socketley::storage::sync_runners r;
            if (i + 1 >= pa.count || !socketley::storage::parse_sync_runners(pa.args[i + 1], r))
            {
                std::cout << "--sync requires never, active or per-user\n";
                return 1;
            }
            stg->set_sync(pa.args[++i]);
            return 0;
        }
        case fnv1a("--fsync-interval"):
        {
            uint64_t secs = 0;
            const std::string_view v = i + 1 < pa.count ? pa.args[i + 1] : std::string_view{};
            if (parse_duration_seconds(v, 3600, secs) != duration_parse::ok || secs == 0)
            {
                std::cout << "--fsync-interval requires a duration from 1s to 1h\n";
                return 1;
            }
            ++i;
            stg->set_fsync_interval_secs(static_cast<uint32_t>(secs));
            return 0;
        }
        // The domains under which a Host of `<bucket>.<domain>` is that bucket's website rather than the S3 API.
        case fnv1a("--website-domain"):
        {
            std::vector<std::string> domains;
            std::string why;
            if (i + 1 >= pa.count || !socketley::storage::parse_domains(pa.args[i + 1], domains, why))
            {
                std::cout << (why.empty() ? "--website-domain requires a domain name, or several separated by commas"
                                          : "--website-domain: " + why)
                          << "\n";
                return 1;
            }
            stg->set_website_domain(pa.args[++i]);
            return 0;
        }
        // The webhooks event notifications go to, a file of `name url` lines read at every start.
        case fnv1a("--notify-targets"):
        {
            if (i + 1 >= pa.count || pa.args[i + 1].empty())
            {
                std::cout << "--notify-targets requires a file path\n";
                return 1;
            }
            stg->set_notify_targets(pa.args[++i]);
            return 0;
        }
        // The endpoints buckets replicate to, a file of `name url region access_key secret` lines read at every start.
        case fnv1a("--replication-targets"):
        {
            if (i + 1 >= pa.count || pa.args[i + 1].empty())
            {
                std::cout << "--replication-targets requires a file path\n";
                return 1;
            }
            stg->set_replication_targets(pa.args[++i]);
            return 0;
        }
        // The tiers a lifecycle moves versions to, a file of `name url region access_key secret` lines read at every start.
        case fnv1a("--tiers"):
        {
            if (i + 1 >= pa.count || pa.args[i + 1].empty())
            {
                std::cout << "--tiers requires a file path\n";
                return 1;
            }
            stg->set_tiers_file(pa.args[++i]);
            return 0;
        }
        // The OIDC provider and LDAP directory STS takes identities from, a file of lines read at every start.
        case fnv1a("--federation"):
        {
            if (i + 1 >= pa.count || pa.args[i + 1].empty())
            {
                std::cout << "--federation requires a file path\n";
                return 1;
            }
            stg->set_federation_file(pa.args[++i]);
            return 0;
        }
        // The proxies that terminate TLS before the runtime, whose connections count as secure ones.
        case fnv1a("--tls-offloaded"):
        {
            if (i + 1 >= pa.count || pa.args[i + 1].empty())
            {
                std::cout << "--tls-offloaded requires addresses such as 10.0.0.5 or 10.0.0.0/24\n";
                return 1;
            }
            stg->set_tls_offloaded(pa.args[++i]);
            return 0;
        }
        // The nodes that each keep every bucket, a file of `self`, `node` and `key` lines read at every start.
        case fnv1a("--nodes"):
        {
            if (i + 1 >= pa.count || pa.args[i + 1].empty())
            {
                std::cout << "--nodes requires a file path\n";
                return 1;
            }
            stg->set_nodes_file(pa.args[++i]);
            return 0;
        }
        // Open multipart uploads are aborted after this long, and never when it is absent.
        case fnv1a("--mpu-expire"):
        {
            uint64_t secs = 0;
            const std::string_view v = i + 1 < pa.count ? pa.args[i + 1] : std::string_view{};
            if (parse_duration_seconds(v, uint64_t{10} * 365 * 86400, secs) != duration_parse::ok || secs == 0)
            {
                std::cout << "--mpu-expire requires a duration such as 24h or 7d\n";
                return 1;
            }
            ++i;
            stg->set_mpu_expire_secs(static_cast<uint32_t>(std::min<uint64_t>(secs, UINT32_MAX)));
            return 0;
        }
        // Every object read back and checked once in this long, at a pace that spreads the reads over it.
        case fnv1a("--scrub"):
        {
            uint64_t secs = 0;
            const std::string_view v = i + 1 < pa.count ? pa.args[i + 1] : std::string_view{};
            if (parse_duration_seconds(v, uint64_t{10} * 365 * 86400, secs) != duration_parse::ok || secs == 0)
            {
                std::cout << "--scrub requires a duration such as 7d or 30d\n";
                return 1;
            }
            ++i;
            stg->set_scrub_secs(static_cast<uint32_t>(std::min<uint64_t>(secs, UINT32_MAX)));
            return 0;
        }
        // Versions left unwritten this long are compressed where they lie.
        case fnv1a("--compress"):
        {
            uint64_t secs = 0;
            const std::string_view v = i + 1 < pa.count ? pa.args[i + 1] : std::string_view{};
            if (parse_duration_seconds(v, uint64_t{10} * 365 * 86400, secs) != duration_parse::ok || secs == 0)
            {
                std::cout << "--compress requires a duration such as 1h or 7d\n";
                return 1;
            }
            ++i;
            stg->set_compress_secs(static_cast<uint32_t>(std::min<uint64_t>(secs, UINT32_MAX)));
            return 0;
        }
        case fnv1a("--max-bytes"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--max-bytes requires a size value\n";
                return 1;
            }
            size_t bytes;
            if (!parse_size_suffix(pa.args[++i], bytes))
            {
                std::cout << "invalid max-bytes value (use K/M/G suffix)\n";
                return 1;
            }
            stg->set_max_bytes(bytes);
            return 0;
        }
        default:
            return -1;
    }
}

int parse_common_edit_flags(runtime_instance* instance, const parsed_args& pa,
                            size_t& i, bool is_running)
{
    switch (pa.hashes[i])
    {
        // Refused rather than ignored, because a running runtime is bound to
        // the socket node it has and moving it would leave the first node for
        // a teardown that never comes.
        case fnv1a("--listen"):
            if (is_running)
            {
                std::cout << "cannot change the listen socket while running\n";
                return 1;
            }
            return parse_listen_flag(instance, pa, i);

        // Editable and refused while running, because applying it means
        // forking or retiring workers under live connections and there is no
        // answer yet for the connections a retired shard holds.
        case fnv1a("--shards"):
        {
            if (is_running)
            {
                std::cout << "cannot change the shard count while running\n";
                return 1;
            }
            if (i + 1 >= pa.count)
            {
                std::cout << "--shards requires a count\n";
                return 1;
            }
            uint32_t n = 0;
            if (!socketley::parse_whole(pa.args[++i], n) || n < 1)
            {
                std::cout << "invalid shard count\n";
                return 1;
            }
            // --listen can be typed further along this same command line, so
            // this asks only the half of the question whose inputs are final.
            if (const std::string msg = shards_config_refusal(
                    instance->get_type(), n); !msg.empty())
            {
                std::cout << msg;
                return 1;
            }
            instance->set_shards(n);
            return 0;
        }

        case fnv1a("-p"):
        {
            if (is_running)
            {
                std::cout << "cannot change port while running\n";
                return 1;
            }
            if (i + 1 >= pa.count)
            {
                std::cout << "-p requires a port number\n";
                return 1;
            }
            return parse_port_flag(instance, pa.args[++i]);
        }
        case fnv1a("--bind"):
        {
            if (is_running)
            {
                std::cout << "cannot change the bind address while running\n";
                return 1;
            }
            if (i + 1 >= pa.count)
            {
                std::cout << "--bind requires an address\n";
                return 1;
            }
            return apply_bind_address(instance, pa.args[++i]);
        }
        case fnv1a("-b"):
            instance->set_bash_output(true);
            return 0;

        case fnv1a("-bp"):
            instance->set_bash_output(true);
            instance->set_bash_prefix(true);
            return 0;

        case fnv1a("-bt"):
            instance->set_bash_output(true);
            instance->set_bash_timestamp(true);
            return 0;

        case fnv1a("-bpt"):
        case fnv1a("-btp"):
            instance->set_bash_output(true);
            instance->set_bash_prefix(true);
            instance->set_bash_timestamp(true);
            return 0;

        case fnv1a("--log"):
            if (i + 1 >= pa.count)
            {
                std::cout << "--log requires a file path\n";
                return 1;
            }
            // Absolute only: a relative path is resolved against the
            // daemon's working directory, not the operator's.
            if (const std::string why = socketley::appended_path_refusal(
                    "--log", pa.args[i + 1]); !why.empty())
            {
                std::cout << why;
                return 1;
            }
            instance->set_log_file(pa.args[++i]);
            return 0;

        case fnv1a("-w"):
            if (i + 1 >= pa.count)
            {
                std::cout << "-w requires a file path\n";
                return 1;
            }
            // Absolute only: a relative path is resolved against the
            // daemon's working directory, not the operator's.
            if (const std::string why = socketley::appended_path_refusal(
                    "-w", pa.args[i + 1]); !why.empty())
            {
                std::cout << why;
                return 1;
            }
            instance->set_write_file(pa.args[++i]);
            return 0;

        case fnv1a("--max-connections"):
        case fnv1a("--max-conn"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--max-connections requires a value\n";
                return 1;
            }
            uint32_t max;
            if (!socketley::parse_whole(pa.args[++i], max))
            {
                std::cout << "invalid max-connections value\n";
                return 1;
            }
            if (refuse_inbound_flag_on_client(instance, "--max-connections",
                                              "it opens one connection outward and "
                                              "accepts none"))
                return 1;
            instance->set_max_connections(max);
            return 0;
        }

        case fnv1a("--rate-limit"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--rate-limit requires a value\n";
                return 1;
            }
            double rate;
            if (!parse_double(pa.args[++i], rate) || rate < 0)
            {
                std::cout << "invalid rate-limit value\n";
                return 1;
            }
            if (refuse_inbound_flag_on_client(instance, "--rate-limit",
                                              "it limits what a peer may send to a "
                                              "runtime, and nothing connects to a client"))
                return 1;
            instance->set_rate_limit(rate);
            return 0;
        }

        case fnv1a("--global-rate-limit"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--global-rate-limit requires a value\n";
                return 1;
            }
            double rate;
            if (!parse_double(pa.args[++i], rate) || rate < 0)
            {
                std::cout << "invalid global-rate-limit value\n";
                return 1;
            }
            // The fourth of them, and the one whose sibling was already
            // refused: check_global_rate_limit() is called by the cache, the
            // server and the proxy and by no client code at all, and "across
            // all connections" means nothing to a runtime that has one.
            if (refuse_inbound_flag_on_client(instance, "--global-rate-limit",
                                              "it caps the total across all "
                                              "inbound connections, and a client "
                                              "has one outbound connection -- "
                                              "--rate-limit is refused here for "
                                              "the same reason"))
                return 1;
            instance->set_global_rate_limit(rate);
            return 0;
        }

        case fnv1a("--idle-timeout"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--idle-timeout requires a value\n";
                return 1;
            }
            uint64_t secs;
            if (!parse_duration_flag("idle-timeout", pa.args[++i],
                                     std::numeric_limits<uint32_t>::max(), secs))
                return 1;
            if (refuse_inbound_flag_on_client(instance, "--idle-timeout",
                                              "it reaps idle inbound connections, and "
                                              "a client's own connection is reconnected "
                                              "the moment it is dropped"))
                return 1;
            instance->set_idle_timeout(static_cast<uint32_t>(secs));
            return 0;
        }

        case fnv1a("--read-buffer"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--read-buffer requires a size value\n";
                return 1;
            }
            size_t bytes;
            if (!parse_size_suffix(pa.args[++i], bytes))
            {
                std::cout << "invalid --read-buffer value (use K/M/G suffix)\n";
                return 1;
            }
            // Live, like its outbound twin: the bound is compared on every
            // read and the bulk cap is derived at each parse, so nothing holds
            // the old value.  A buffer already past a lowered bound is closed
            // at its next read, which is the same answer it would get for
            // having grown there.
            instance->set_read_buffer(bytes);
            return 0;
        }

        case fnv1a("--write-buffer"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--write-buffer requires a size value\n";
                return 1;
            }
            size_t bytes;
            if (!parse_size_suffix(pa.args[++i], bytes))
            {
                std::cout << "invalid --write-buffer value (use K/M/G suffix)\n";
                return 1;
            }
            // Live: the bound is read on every send rather than cached per
            // connection, so there is nothing to refresh and nothing holding
            // the old value.  A queue already past a lowered bound is closed
            // at its next send, which is the same answer it would get for
            // having grown there.
            instance->set_write_buffer(bytes);
            return 0;
        }

        case fnv1a("--group"):
        case fnv1a("-g"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--group requires a value\n";
                return 1;
            }
            instance->set_group(pa.args[++i]);
            return 0;
        }

        // Same rule as the create path, and the path that matters most,
        // because a generic "unknown flag" reads as a typo and sends the
        // operator to try a different spelling.
        // Not a setting of the runtime: it says the caller wants the change carried across a stop and a start, and
        // the command has already acted on it by the time the flags are read.
        case fnv1a("--restart"):
            return 0;

        case fnv1a("--tls"):
            if (!tls_role_has_handshake(instance->get_type()))
            {
                std::cout << tls_not_implemented_error("--tls");
                return 1;
            }
            instance->set_tls(true);
            return 0;

        case fnv1a("--acme"):
        case fnv1a("--acme-email"):
            return parse_acme_flag(instance, pa, i);

        case fnv1a("--domain"):
            return parse_domain_flag(instance, pa, i);

        case fnv1a("--cert"):
        case fnv1a("--key"):
        case fnv1a("--ca"):
        {
            const uint32_t which = pa.hashes[i];
            const char* flag = which == fnv1a("--cert") ? "--cert"
                             : which == fnv1a("--key")  ? "--key"
                                                        : "--ca";
            if (!tls_role_has_handshake(instance->get_type()))
            {
                std::cout << tls_not_implemented_error(flag);
                return 1;
            }
            if (i + 1 >= pa.count)
            {
                std::cout << flag << " requires a file\n";
                return 1;
            }
            const std::string_view path = pa.args[++i];
            if (which == fnv1a("--cert"))     instance->set_cert_path(path);
            else if (which == fnv1a("--key")) instance->set_key_path(path);
            else                              instance->set_ca_path(path);
            return 0;
        }

        // Not editable, because io_uring fixes a ring's CPU set at creation
        // and accepting the edit would store a value the next `stats`
        // contradicts.
        case fnv1a("--cpus"):
            std::cout << "the ring's CPU set is fixed when the ring is created; "
                         "recreate the runtime to change it\n";
            return 1;

        default:
            return -1;
    }
}

int parse_server_edit_flags(server_instance* srv, const parsed_args& pa, size_t& i,
                            bool is_running, runtime_manager* mgr)
{
    if (const int removed = refuse_removed_server_flag(pa.hashes[i]); removed >= 0)
        return removed;

    switch (pa.hashes[i])
    {
        case fnv1a("--mode"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--mode requires a value\n";
                return 1;
            }
            ++i;
            server_mode mode;
            if (!parse_server_mode(pa.hashes[i], mode))
            {
                std::cout << "unknown mode: " << pa.args[i] << "\n";
                return 1;
            }
            srv->set_mode(mode);
            return 0;
        }
        case fnv1a("--send-to"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--send-to requires sender, others or master, "
                             "comma separated\n";
                return 1;
            }
            ++i;
            uint8_t mask = 0;
            std::string bad;
            if (!parse_server_send_to(pa.args[i], mask, bad))
            {
                std::cout << "unknown --send-to: " << (bad.empty() ? pa.args[i] : bad)
                          << " (sender, others, master; comma separated)\n";
                return 1;
            }
            srv->set_send_to(mask);
            return 0;
        }
        case fnv1a("--cache"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--cache requires a cache name\n";
                return 1;
            }
            srv->set_cache_name(pa.args[++i]);
            srv->set_runtime_manager(mgr);
            return 0;
        }
        case fnv1a("--udp"):
        {
            if (is_running)
            {
                std::cout << "cannot change protocol while running\n";
                return 1;
            }
            srv->set_udp(true);
            return 0;
        }
        case fnv1a("--master-pw"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--master-pw requires a password\n";
                return 1;
            }
            srv->set_master_pw(pa.args[++i]);
            return 0;
        }
        // The way back out of master mode.  `--master-pw ""` cannot express
        // this: the daemon receives one line and splits it on whitespace, so an
        // empty argument does not survive the wire and arrives as the flag with
        // nothing after it.  Without a spelling of its own, a server that once
        // had a password could never be edited to another mode again, because
        // the pair is refused as a set and only one half was removable.
        case fnv1a("--no-master-pw"):
            srv->set_master_pw("");
            return 0;
        case fnv1a("--http"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--http requires a directory path\n";
                return 1;
            }
            srv->set_http_dir(pa.args[++i]);
            return 0;
        }
        case fnv1a("--http-cache"):
            srv->set_http_cache(true);
            return 0;
        case fnv1a("-u"):
        case fnv1a("--upstream"):
        {
            if (is_running)
            {
                std::cout << "cannot change upstreams while running\n";
                return 1;
            }
            if (i + 1 >= pa.count)
            {
                std::cout << "-u requires host:port\n";
                return 1;
            }
            std::string_view upstream_str = pa.args[++i];
            // Same contract as the create path, except that on `edit` the list
            // is already cleared, so a refusal leaves fewer upstreams and the
            // message names the address that could not be read.
            size_t start = 0;
            size_t semi;
            while ((semi = upstream_str.find(';', start)) != std::string_view::npos)
            {
                auto addr = upstream_str.substr(start, semi - start);
                if (!addr.empty() && !srv->add_upstream_target(addr))
                {
                    std::cout << "invalid upstream address: " << addr
                              << " (the port must be a number between 1 and 65535)\n";
                    return 1;
                }
                start = semi + 1;
            }
            if (start < upstream_str.size())
            {
                auto addr = upstream_str.substr(start);
                if (!srv->add_upstream_target(addr))
                {
                    std::cout << "invalid upstream address: " << addr
                              << " (the port must be a number between 1 and 65535)\n";
                    return 1;
                }
            }
            return 0;
        }
        default:
            return -1;
    }
}

int parse_client_edit_flags(client_instance* cli, const parsed_args& pa, size_t& i,
                            bool is_running)
{
    switch (pa.hashes[i])
    {
        case fnv1a("-t"):
        {
            if (is_running)
            {
                std::cout << "cannot change target while running\n";
                return 1;
            }
            if (i + 1 >= pa.count)
            {
                std::cout << "-t requires a target address\n";
                return 1;
            }
            // The same judgment as create's -t, for the same reason.
            ++i;
            if (std::string_view v = pa.args[i]; v.starts_with("unix:"))
            {
                if (std::string why =
                        socketley::unix_sock::path_refusal(v.substr(5));
                    !why.empty())
                {
                    std::cout << "-t: " << why << "\n";
                    return 1;
                }
            }
            else if (std::string why = socketley::dial_addr::refusal(v); !why.empty())
            {
                std::cout << "-t: " << why << "\n";
                return 1;
            }
            cli->set_target(pa.args[i]);
            return 0;
        }
        case fnv1a("--mode"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--mode requires a value\n";
                return 1;
            }
            ++i;
            client_mode mode;
            if (!parse_client_mode(pa.hashes[i], mode))
            {
                std::cout << "unknown mode: " << pa.args[i] << "\n";
                return 1;
            }
            cli->set_mode(mode);
            return 0;
        }
        case fnv1a("--udp"):
        {
            if (is_running)
            {
                std::cout << "cannot change protocol while running\n";
                return 1;
            }
            cli->set_udp(true);
            return 0;
        }
        default:
            return -1;
    }
}

int parse_proxy_edit_flags(proxy_instance* proxy, const parsed_args& pa, size_t& i, bool is_running)
{
    // Both are taken up when the proxy starts, so a running one is not told it has them.
    if (pa.hashes[i] == fnv1a("--auth") || pa.hashes[i] == fnv1a("--redirect-https"))
    {
        if (is_running)
        {
            std::cout << "cannot change " << pa.args[i] << " while running; stop it first\n";
            return 1;
        }
        return parse_proxy_gate_flag(proxy, pa, i);
    }
    switch (pa.hashes[i])
    {
        case fnv1a("--strategy"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--strategy requires a value\n";
                return 1;
            }
            ++i;
            switch (pa.hashes[i])
            {
                case fnv1a("round-robin"):
                    proxy->set_strategy(strategy_round_robin);
                    break;
                case fnv1a("random"):
                    proxy->set_strategy(strategy_random);
                    break;
                case fnv1a("lua"):
                    proxy->set_strategy(strategy_lua);
                    break;
                default:
                    std::cout << "unknown strategy: " << pa.args[i] << "\n";
                    return 1;
            }
            return 0;
        }
        case fnv1a("--health-check"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--health-check requires tcp or http\n";
                return 1;
            }
            ++i;
            switch (pa.hashes[i])
            {
                case fnv1a("tcp"):
                    proxy->set_health_check(mesh_config::health_tcp);
                    break;
                case fnv1a("http"):
                    proxy->set_health_check(mesh_config::health_http);
                    break;
                default:
                    std::cout << "unknown health-check type: " << pa.args[i] << "\n";
                    return 1;
            }
            return 0;
        }
        case fnv1a("--health-interval"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--health-interval requires a value\n";
                return 1;
            }
            uint64_t secs;
            if (!parse_duration_flag("health-interval", pa.args[++i],
                                     std::numeric_limits<int>::max(), secs))
                return 1;
            if (secs == 0)
            {
                std::cout << "invalid health-interval value\n";
                return 1;
            }
            proxy->set_health_interval(static_cast<int>(secs));
            return 0;
        }
        case fnv1a("--health-path"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--health-path requires a value\n";
                return 1;
            }
            {
                // The value is written into a GET request line as it stands,
                // so anything that is not a path fails every health check for
                // what is a typo in a flag nobody re-reads.
                const std::string_view hp = pa.args[i + 1];
                if (hp.empty() || hp.front() != '/')
                {
                    std::cout << "--health-path must begin with '/'\n";
                    return 1;
                }
            }
            proxy->set_health_path(pa.args[++i]);
            return 0;
        }
        case fnv1a("--health-threshold"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--health-threshold requires a value\n";
                return 1;
            }
            int val;
            if (!parse_count_flag("health-threshold", pa.args[++i], 1, val))
                return 1;
            proxy->set_health_threshold(val);
            return 0;
        }
        case fnv1a("--circuit-threshold"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--circuit-threshold requires a value\n";
                return 1;
            }
            int val;
            if (!parse_count_flag("circuit-threshold", pa.args[++i], 1, val))
                return 1;
            proxy->set_circuit_threshold(val);
            return 0;
        }
        case fnv1a("--circuit-timeout"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--circuit-timeout requires a value\n";
                return 1;
            }
            uint64_t secs;
            if (!parse_duration_flag("circuit-timeout", pa.args[++i],
                                     std::numeric_limits<int>::max(), secs))
                return 1;
            if (secs == 0)
            {
                std::cout << "invalid circuit-timeout value\n";
                return 1;
            }
            proxy->set_circuit_timeout(static_cast<int>(secs));
            return 0;
        }
        // 0 is accepted and means "no deadline" — see the create-path handler
        // for why that is a choice an operator has to make explicitly.
        case fnv1a("--backend-timeout"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--backend-timeout requires a value\n";
                return 1;
            }
            uint64_t secs;
            if (!parse_duration_flag("backend-timeout", pa.args[++i],
                                     std::numeric_limits<int>::max(), secs))
                return 1;
            proxy->set_backend_timeout(static_cast<int>(secs));
            return 0;
        }
        case fnv1a("--retry"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--retry requires a value\n";
                return 1;
            }
            int val;
            if (!parse_count_flag("retry", pa.args[++i], 0, val))
                return 1;
            proxy->set_retry_count(val);
            return 0;
        }
        case fnv1a("--retry-all"):
            proxy->set_retry_all(true);
            return 0;
        // The mesh client-certificate flags live with the proxy because that
        // is where they exist at all, and like every TLS option they take
        // effect at the next start.
        case fnv1a("--client-ca"):
        case fnv1a("--client-cert"):
        case fnv1a("--client-key"):
        {
            const uint32_t which = pa.hashes[i];
            const char* flag = which == fnv1a("--client-ca")   ? "--client-ca"
                             : which == fnv1a("--client-cert") ? "--client-cert"
                                                               : "--client-key";
            if (i + 1 >= pa.count)
            {
                std::cout << flag << " requires a file\n";
                return 1;
            }
            const std::string_view path = pa.args[++i];
            if (which == fnv1a("--client-ca"))        proxy->set_mesh_client_ca(path);
            else if (which == fnv1a("--client-cert")) proxy->set_mesh_client_cert(path);
            else                                      proxy->set_mesh_client_key(path);
            return 0;
        }
        default:
            return -1;
    }
}
