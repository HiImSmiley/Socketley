#include "flag_handlers.h"
#include "../shared/runtime_instance.h"
#include "../shared/lua_context.h"
#include "../shared/tls_context.h"
#include <iostream>
#include <charconv>
#include "../shared/runtime_manager.h"
#include "../runtime/server/server_instance.h"
#include "../runtime/client/client_instance.h"
#include "../runtime/proxy/proxy_instance.h"
#include "../runtime/cache/cache_instance.h"

int parse_common_flags(runtime_instance* instance, const parsed_args& pa,
                       size_t& i, bool& autostart, std::string& lua_script)
{
    switch (pa.hashes[i])
    {
        // Run this runtime inside the daemon rather than in a process of its
        // own.  The only flag for where a runtime runs, and it names the
        // non-default state — a runtime with no such flag gets its own worker
        // process.
        //
        // There were two for a while, `--out-of-process` and `--in-daemon`, one
        // per side of a boolean.  Two names for one bit means the pair has to be
        // kept level in the create parser, the edit parser, the precedence rule
        // and the documentation, and this file has already shown what happens
        // when it is not: `--out-of-process` reached the common create parser
        // while its edit refusal stayed behind in parse_proxy_flags, so
        // `edit proxy x` answered a refusal and `edit server x` answered
        // "unknown flag" for the same request against the same field.
        //
        // Create-time only — see parse_common_edit_flags.
        //
        // Taken here so it is not an unknown flag, and acted on nowhere but the
        // pre-scan in daemon_handler, which is the only place that sees the
        // whole command line before --lua is executed.
        case fnv1a("--daemon-process"):
            return 0;

        case fnv1a("-p"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "-p requires a port\n";
                return 1;
            }
            uint16_t port;
            if (!parse_uint16(pa.args[++i], port))
            {
                std::cout << "invalid port number\n";
                return 1;
            }
            instance->set_port(port);
            return 0;
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
            instance->set_log_file(pa.args[++i]);
            return 0;

        case fnv1a("-w"):
            if (i + 1 >= pa.count)
            {
                std::cout << "-w requires a file\n";
                return 1;
            }
            instance->set_write_file(pa.args[++i]);
            return 0;

        // ─── RECORDED HERE, LOADED BY THE CALLER ────────────────────────────
        //
        // This used to call load_lua_script() on the spot, and that made a
        // create mean different things depending on where on the command line
        // it was written.  Loading a script builds the interpreter, runs the
        // file's top level and snapshots the `self` table — name, port, type,
        // state — out of the instance AS IT IS AT THAT MOMENT.  So:
        //
        //     create server s --lua x.lua -p 9000    self.port == 0, forever
        //     create server s -p 9000 --lua x.lua    self.port == 9000
        //
        // for the same runtime, with `socketley.get("s").port` answering 9000
        // in both — so a script could not even detect the case by comparing.
        // A script that binds its behaviour to self.port, which is what the
        // field is for, silently did the wrong thing for one of the two
        // spellings and nothing anywhere said so.
        //
        // The file itself already states the rule, at the --daemon-process
        // pre-scan in cmd_create: "A create whose behaviour depends on argument
        // order is a bug waiting for someone to reorder a command line."  That
        // pre-scan fixed it for one flag, by finding the flag that had to be
        // known early.  This is the other half — the flag that has to be acted
        // on late — and there is only one of those, because loading the script
        // is the only step in a create that reads the configuration back.
        //
        // `edit` never had this: cmd_edit applies every field from its parsed
        // config and only then reloads.
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
            if (!parse_uint32(pa.args[++i], max))
            {
                std::cout << "invalid max-connections value\n";
                return 1;
            }
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
            uint32_t secs;
            if (!parse_uint32(pa.args[++i], secs))
            {
                std::cout << "invalid idle-timeout value\n";
                return 1;
            }
            instance->set_idle_timeout(secs);
            return 0;
        }

        case fnv1a("--drain"):
            instance->set_drain(true);
            return 0;

        case fnv1a("--reconnect"):
        {
            int max_attempts = 0; // default: infinite
            if (i + 1 < pa.count)
            {
                int val = 0;
                auto sv = std::string_view(pa.args[i + 1]);
                auto [p, e] = std::from_chars(sv.data(), sv.data() + sv.size(), val);
                if (e == std::errc{} && p == sv.data() + sv.size())
                {
                    max_attempts = val;
                    i++;
                }
            }
            instance->set_reconnect(max_attempts);
            return 0;
        }

        // ── TLS ──
        // Stored for the roles that perform a handshake — a server's and a
        // cache's own listener, a client's outbound socket, a proxy's two legs
        // — and refused for a runtime type that would answer cleartext on an
        // endpoint `inspect` reports as encrypted.  Every type in the enum
        // handshakes today; the gate stays because the next one added will not,
        // and failing at the point the flag is typed is the only place the
        // operator is still looking.
        //
        // Whether the *set* is complete — --tls with a key pair, a key pair
        // with --tls, and on a cache whether it also replicates in cleartext —
        // cannot be decided here, because the flag that completes it may be
        // further along the command line.  cmd_create asks that once parsing is
        // done, and runtime_instance::start() asks it again for configurations
        // that never went through a command line at all.
        case fnv1a("--tls"):
            if (!tls_role_has_handshake(instance->get_type()))
            {
                std::cout << tls_not_implemented_error("--tls");
                return 1;
            }
            instance->set_tls(true);
            return 0;

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
        // --cpus takes `max`, a range, or a list: max | 0-3 | 0,1,2,3 | 0-1,3.
        //
        // A set this machine cannot satisfy is refused here rather than rounded
        // up to "all".  Pinning to a CPU that does not exist is the mistake this
        // flag makes easy — a config written for a 16-core box, deployed on a
        // four-core one — and the silent version of it is worse than the loud
        // one: the runtime runs, it just runs nowhere near where its operator
        // believes, and every measurement taken afterwards is measuring
        // something else.
        //
        // There is deliberately no --rings to go with this.  A ring is a queue
        // between one thread and the kernel, so a count of rings is only ever a
        // count of I/O threads wearing a disguise, and two rings on one thread
        // are strictly worse than one — more submission state, no more
        // parallelism.  The honest knob is which CPUs the thread may use, and
        // that is this one.
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

        // Opt in to the io_uring submission poller for this runtime's ring.
        //
        // It costs a kernel thread that spins on the submission queue for as
        // long as the ring exists, which is why it is not the default and why it
        // is per runtime rather than per daemon: a runtime saturating a link
        // wants its submissions to be a store to a tail pointer, and the three
        // idle ones next to it want their core back.
        case fnv1a("--sqpoll"):
            instance->set_sqpoll(true);
            return 0;

        case fnv1a("--no-sqpoll"):
            instance->set_sqpoll(false);
            return 0;

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

int parse_server_flags(server_instance* srv, const parsed_args& pa, size_t& i,
                       runtime_manager* mgr, std::string_view /*name*/)
{
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
        case fnv1a("--master-forward"):
            srv->set_master_forward(true);
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
            if (i + 1 >= pa.count)
            {
                std::cout << "-u requires host:port\n";
                return 1;
            }
            std::string_view upstream_str = pa.args[++i];
            // Parse semicolon-separated: "host1:port1;host2:port2"
            size_t start = 0;
            size_t semi;
            while ((semi = upstream_str.find(';', start)) != std::string_view::npos)
            {
                auto addr = upstream_str.substr(start, semi - start);
                if (!addr.empty())
                    srv->add_upstream_target(addr);
                start = semi + 1;
            }
            if (start < upstream_str.size())
                srv->add_upstream_target(upstream_str.substr(start));
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
            cli->set_target(pa.args[++i]);
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

int parse_proxy_flags(proxy_instance* proxy, const parsed_args& pa, size_t& i,
                      std::string_view /*name*/)
{
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
            int val;
            auto sv = std::string_view(pa.args[++i]);
            auto [p, e] = std::from_chars(sv.data(), sv.data() + sv.size(), val);
            if (e != std::errc{} || val <= 0)
            {
                std::cout << "invalid health-interval value\n";
                return 1;
            }
            proxy->set_health_interval(val);
            return 0;
        }
        case fnv1a("--health-path"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--health-path requires a value\n";
                return 1;
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
            auto sv = std::string_view(pa.args[++i]);
            auto [p, e] = std::from_chars(sv.data(), sv.data() + sv.size(), val);
            if (e != std::errc{} || val <= 0)
            {
                std::cout << "invalid health-threshold value\n";
                return 1;
            }
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
            auto sv = std::string_view(pa.args[++i]);
            auto [p, e] = std::from_chars(sv.data(), sv.data() + sv.size(), val);
            if (e != std::errc{} || val <= 0)
            {
                std::cout << "invalid circuit-threshold value\n";
                return 1;
            }
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
            int val;
            auto sv = std::string_view(pa.args[++i]);
            auto [p, e] = std::from_chars(sv.data(), sv.data() + sv.size(), val);
            if (e != std::errc{} || val <= 0)
            {
                std::cout << "invalid circuit-timeout value\n";
                return 1;
            }
            proxy->set_circuit_timeout(val);
            return 0;
        }
        // How long a backend may take to produce the first byte of a response.
        // Defaulted rather than opt-in: a backend that accepts and then stops
        // answering is invisible to every other check the proxy has, so an
        // operator who has never heard of this flag is exactly the one it has to
        // protect.  0 is accepted and restores the old unbounded wait, but it is
        // a decision someone has to take deliberately.
        case fnv1a("--backend-timeout"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--backend-timeout requires a value\n";
                return 1;
            }
            int val;
            auto sv = std::string_view(pa.args[++i]);
            auto [p, e] = std::from_chars(sv.data(), sv.data() + sv.size(), val);
            if (e != std::errc{} || val < 0)
            {
                std::cout << "invalid backend-timeout value\n";
                return 1;
            }
            proxy->set_backend_timeout(val);
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
            auto sv = std::string_view(pa.args[++i]);
            auto [p, e] = std::from_chars(sv.data(), sv.data() + sv.size(), val);
            if (e != std::errc{} || val < 0)
            {
                std::cout << "invalid retry value\n";
                return 1;
            }
            proxy->set_retry_count(val);
            return 0;
        }
        case fnv1a("--retry-all"):
            proxy->set_retry_all(true);
            return 0;
        // ── mTLS, both directions ──
        //
        // --client-ca is the listener's: the CA a certificate presented *by a
        // client* has to be signed by, so it goes with --tls --cert --key.
        // --client-cert/--client-key are the backend leg's: the certificate
        // this proxy presents to a backend that asks for one.
        //
        // Which of those is complete, and whether the listener they describe
        // is encrypted at all, is decided once parsing is done — the flag that
        // completes a pair may be further along the command line.  See
        // tls_config_refusal.
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
        case fnv1a("--replicate"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--replicate requires host:port\n";
                return 1;
            }
            cache->set_replicate_target(pa.args[++i]);
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
        // Refused rather than ignored.  Honouring it would mean moving a
        // configured runtime from one address space to another underneath
        // whatever is already pointing at it, and quietly dropping it would
        // leave the operator believing a runtime is isolated when it is not.
        //
        // Here rather than in parse_proxy_edit_flags, where it lived while this
        // was a proxy-only flag: `edit server x --out-of-process` answered
        // "unknown flag" and `edit proxy x --out-of-process` answered the
        // refusal, for the same request against the same field.
        // Refused rather than ignored.  Honouring it would mean moving a
        // configured runtime from one address space to another underneath
        // whatever is already pointing at it, and quietly dropping it would
        // leave the operator believing a runtime is isolated when it is not.
        case fnv1a("--daemon-process"):
            std::cout << "where a runtime runs can only be set when it is created\n";
            return 1;

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
            uint16_t port;
            if (!parse_uint16(pa.args[++i], port))
            {
                std::cout << "invalid port number\n";
                return 1;
            }
            instance->set_port(port);
            return 0;
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
            instance->set_log_file(pa.args[++i]);
            return 0;

        case fnv1a("-w"):
            if (i + 1 >= pa.count)
            {
                std::cout << "-w requires a file path\n";
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
            if (!parse_uint32(pa.args[++i], max))
            {
                std::cout << "invalid max-connections value\n";
                return 1;
            }
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
            uint32_t secs;
            if (!parse_uint32(pa.args[++i], secs))
            {
                std::cout << "invalid idle-timeout value\n";
                return 1;
            }
            instance->set_idle_timeout(secs);
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

        // Same rule as the create path — and this is the path that matters
        // most, because `edit` is where an operator goes to put TLS on
        // something that is already serving traffic.  Every runtime type takes
        // them today; a type that did not would be refused with the reason
        // rather than falling through to the generic "unknown flag", which
        // gave that operator the same exit status and a wrong explanation: it
        // reads as a typo, so the answer to it is to try again with different
        // spelling, not to go and terminate TLS somewhere else.
        //
        // The edit takes effect at the next start; the completeness check for
        // the resulting set is made there, on whatever the runtime is carrying
        // by then, and not on this one flag.  That is also where a cache that
        // would end up encrypted *and* replicating is caught — cmd_edit
        // re-asks tls_config_refusal with the whole configuration and puts the
        // old values back if it refuses.
        case fnv1a("--tls"):
            if (!tls_role_has_handshake(instance->get_type()))
            {
                std::cout << tls_not_implemented_error("--tls");
                return 1;
            }
            instance->set_tls(true);
            return 0;

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

        // Neither is editable, and the reason is not a policy this daemon
        // chose: io_uring fixes a ring's flags and its poller's CPU when the
        // ring is created and offers nothing to change them with afterwards.
        // Accepting the edit would store a value that the next `stats` would
        // then contradict.
        case fnv1a("--cpus"):
        case fnv1a("--sqpoll"):
        case fnv1a("--no-sqpoll"):
            std::cout << "the ring's CPU set and polling mode are fixed when the "
                         "ring is created; recreate the runtime to change them\n";
            return 1;

        default:
            return -1;
    }
}

int parse_server_edit_flags(server_instance* srv, const parsed_args& pa, size_t& i,
                            bool is_running, runtime_manager* mgr)
{
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
        case fnv1a("--master-forward"):
            srv->set_master_forward(true);
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
            size_t start = 0;
            size_t semi;
            while ((semi = upstream_str.find(';', start)) != std::string_view::npos)
            {
                auto addr = upstream_str.substr(start, semi - start);
                if (!addr.empty())
                    srv->add_upstream_target(addr);
                start = semi + 1;
            }
            if (start < upstream_str.size())
                srv->add_upstream_target(upstream_str.substr(start));
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
            cli->set_target(pa.args[++i]);
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

int parse_proxy_edit_flags(proxy_instance* proxy, const parsed_args& pa, size_t& i)
{
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
            int val;
            auto sv = std::string_view(pa.args[++i]);
            auto [p, e] = std::from_chars(sv.data(), sv.data() + sv.size(), val);
            if (e != std::errc{} || val <= 0)
            {
                std::cout << "invalid health-interval value\n";
                return 1;
            }
            proxy->set_health_interval(val);
            return 0;
        }
        case fnv1a("--health-path"):
        {
            if (i + 1 >= pa.count)
            {
                std::cout << "--health-path requires a value\n";
                return 1;
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
            auto sv = std::string_view(pa.args[++i]);
            auto [p, e] = std::from_chars(sv.data(), sv.data() + sv.size(), val);
            if (e != std::errc{} || val <= 0)
            {
                std::cout << "invalid health-threshold value\n";
                return 1;
            }
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
            auto sv = std::string_view(pa.args[++i]);
            auto [p, e] = std::from_chars(sv.data(), sv.data() + sv.size(), val);
            if (e != std::errc{} || val <= 0)
            {
                std::cout << "invalid circuit-threshold value\n";
                return 1;
            }
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
            int val;
            auto sv = std::string_view(pa.args[++i]);
            auto [p, e] = std::from_chars(sv.data(), sv.data() + sv.size(), val);
            if (e != std::errc{} || val <= 0)
            {
                std::cout << "invalid circuit-timeout value\n";
                return 1;
            }
            proxy->set_circuit_timeout(val);
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
            int val;
            auto sv = std::string_view(pa.args[++i]);
            auto [p, e] = std::from_chars(sv.data(), sv.data() + sv.size(), val);
            if (e != std::errc{} || val < 0)
            {
                std::cout << "invalid backend-timeout value\n";
                return 1;
            }
            proxy->set_backend_timeout(val);
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
            auto sv = std::string_view(pa.args[++i]);
            auto [p, e] = std::from_chars(sv.data(), sv.data() + sv.size(), val);
            if (e != std::errc{} || val < 0)
            {
                std::cout << "invalid retry value\n";
                return 1;
            }
            proxy->set_retry_count(val);
            return 0;
        }
        case fnv1a("--retry-all"):
            proxy->set_retry_all(true);
            return 0;
        // The mesh client-certificate flags, taken here as they are on the
        // create path.  They live with the proxy rather than in the common
        // edit handler because that is where they exist at all: a server or
        // client runtime has no mesh_config, so "unknown flag" is the true
        // answer there.
        //
        // Like every other TLS option the change takes effect at the next
        // start — certificates are read in setup(), so a running proxy keeps
        // the identity it handshook with until it is restarted.
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
