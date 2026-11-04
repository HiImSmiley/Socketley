#include "state_persistence.h"
#include <cmath>
#include <type_traits>
#include <limits>
#include <cstring>
#include "../runtime/runtime_instance.h"
#include "../../runtime/server/server_instance.h"
#include "../../runtime/client/client_instance.h"
#include "../../runtime/proxy/proxy_instance.h"
#include "../../runtime/cache/cache_instance.h"
#include "../../runtime/storage/storage_instance.h"
#include "../../runtime/dns/dns_instance.h"
#include "../../runtime/sync/sync_instance.h"
#include "../../runtime/idp/idp_instance.h"
#include "../../runtime/tunnel/tunnel_instance.h"
#include "../../runtime/db/db_instance.h"
#include "../../runtime/metrics/metrics_instance.h"
#include "../../runtime/mcp/mcp_instance.h"
#include "../../runtime/mqtt/mqtt_instance.h"
#include "../../runtime/mail/mail_instance.h"
#include "../../cli/command_hashing.h"
#include "../runtime/type_registry.h"

#include "../util/logging.h"
#include "../util/thread_stop.h"
#include "../util/text_list.h"
#include "../json/json_escape.h"
#include "replaced_file.h"

#include <fstream>
#include <sstream>
#include <charconv>
#include <stdexcept>
#include <cerrno>
#include <cstdio>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

namespace fs = std::filesystem;

// ─── Minimal JSON helpers ───

namespace sp_detail {

std::string json_unescape(std::string_view s)
{
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i)
    {
        if (s[i] == '\\' && i + 1 < s.size())
        {
            ++i;
            switch (s[i])
            {
                case '"':  out += '"';  break;
                case '\\': out += '\\'; break;
                case '/':  out += '/';  break;
                case 'n':  out += '\n'; break;
                case 'r':  out += '\r'; break;
                case 't':  out += '\t'; break;
                case 'b':  out += '\b'; break;
                case 'f':  out += '\f'; break;
                case 'u':
                {
                    // json_escape writes \u00xx for every byte below 0x20, and
                    // nothing here read it back: `--log $'a\001b.log'` came out
                    // of a daemon restart as the seven literal characters
                    // a\u0001b, so the daemon held one path and the file named
                    // another.
                    unsigned cp = 0;
                    bool hex_ok = (i + 4 < s.size());
                    for (size_t d = 0; hex_ok && d < 4; ++d)
                    {
                        const char h = s[i + 1 + d];
                        cp <<= 4;
                        if      (h >= '0' && h <= '9') cp |= static_cast<unsigned>(h - '0');
                        else if (h >= 'a' && h <= 'f') cp |= static_cast<unsigned>(h - 'a' + 10);
                        else if (h >= 'A' && h <= 'F') cp |= static_cast<unsigned>(h - 'A' + 10);
                        else hex_ok = false;
                    }
                    // Kept verbatim when it is not four hex digits, which is
                    // what this function does for every escape it does not
                    // know.
                    if (!hex_ok) { out += '\\'; out += 'u'; break; }
                    i += 4;
                    // A surrogate half on its own is not a codepoint, and
                    // U+FFFD is the answer lua_json.h's decoder gives it.
                    if (cp >= 0xD800 && cp <= 0xDFFF) cp = 0xFFFD;
                    if (cp < 0x80)
                        out += static_cast<char>(cp);
                    else if (cp < 0x800)
                    {
                        out += static_cast<char>(0xC0 | (cp >> 6));
                        out += static_cast<char>(0x80 | (cp & 0x3F));
                    }
                    else
                    {
                        out += static_cast<char>(0xE0 | (cp >> 12));
                        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                        out += static_cast<char>(0x80 | (cp & 0x3F));
                    }
                    break;
                }
                default:   out += '\\'; out += s[i]; break;
            }
        }
        else
        {
            out += s[i];
        }
    }
    return out;
}

runtime_type str_to_type(std::string_view s)
{
    // The historical fallback for a name this process cannot resolve; readers
    // that must not silently repair compare cfg.type_name themselves.
    runtime_type t;
    if (type_registry::lookup(s, t))
        return t;
    return runtime_server;
}

const char* server_mode_str(uint8_t m)
{
    switch (m)
    {
        case 0: return "inout";
        case 1: return "in";
        case 2: return "out";
        case 3: return "master";
        default: return "inout";
    }
}

uint8_t str_to_server_mode(std::string_view s)
{
    switch (fnv1a(s))
    {
        case fnv1a("in"):     return 1;
        case fnv1a("out"):    return 2;
        case fnv1a("master"): return 3;
        default:              return 0;
    }
}

// The same comma spelling the flag takes, so a state file reads back as what
// was typed rather than as a number nobody can check.
std::string server_send_to_str(uint8_t mask)
{
    std::string out;
    if (mask & 1) out += "sender";
    if (mask & 2) { if (!out.empty()) out += ','; out += "others"; }
    if (mask & 4) { if (!out.empty()) out += ','; out += "master"; }
    return out;
}

uint8_t str_to_server_send_to(std::string_view s)
{
    uint8_t mask = 0;
    while (!s.empty())
    {
        switch (fnv1a(socketley::take_item(s)))
        {
            case fnv1a("sender"): mask |= 1; break;
            case fnv1a("others"): mask |= 2; break;
            case fnv1a("master"): mask |= 4; break;
            default: break;
        }
    }
    return mask;
}

const char* proxy_protocol_str(uint8_t p)
{
    return p == 1 ? "tcp" : "http";
}

uint8_t str_to_proxy_protocol(std::string_view s)
{
    return fnv1a(s) == fnv1a("tcp") ? 1 : 0;
}

const char* proxy_strategy_str(uint8_t s)
{
    switch (s)
    {
        case 1: return "random";
        case 2: return "lua";
        default: return "round-robin";
    }
}

uint8_t str_to_proxy_strategy(std::string_view s)
{
    switch (fnv1a(s))
    {
        case fnv1a("random"): return 1;
        case fnv1a("lua"):    return 2;
        default:              return 0;
    }
}

const char* cache_mode_str(uint8_t m)
{
    switch (m)
    {
        case 0: return "readonly";
        case 2: return "admin";
        default: return "readwrite";
    }
}

uint8_t str_to_cache_mode(std::string_view s)
{
    switch (fnv1a(s))
    {
        case fnv1a("readonly"): return 0;
        case fnv1a("admin"):    return 2;
        default:                return 1;
    }
}

const char* eviction_str(uint8_t e)
{
    switch (e)
    {
        case 1: return "allkeys-lru";
        case 2: return "allkeys-random";
        default: return "noeviction";
    }
}

uint8_t str_to_eviction(std::string_view s)
{
    switch (fnv1a(s))
    {
        case fnv1a("allkeys-lru"):    return 1;
        case fnv1a("allkeys-random"): return 2;
        default:                      return 0;
    }
}

// Where the value of the document's own `key` begins, npos when it has none: only the outermost object's keys count,
// so a field of "extra" that a registered type names `domain` is never read as the runtime's domain.
size_t top_value_of(const std::string& json, std::string_view key)
{
    int depth = 0;
    for (size_t pos = 0; pos < json.size(); ++pos)
    {
        const char c = json[pos];
        if (c == '{' || c == '[')
            ++depth;
        else if (c == '}' || c == ']')
            --depth;
        else if (c == '"')
        {
            size_t end = pos + 1;
            while (end < json.size() && json[end] != '"')
            {
                if (json[end] == '\\' && end + 1 < json.size()) ++end;   // \" is not the end
                ++end;
            }
            if (end >= json.size())
                return std::string::npos;
            // A key is followed by a colon, without which the scan also matches a value that reads like a key name.
            const size_t colon = json.find_first_not_of(" \t\n\r", end + 1);
            if (depth == 1 && colon != std::string::npos && json[colon] == ':' && end - pos - 1 == key.size() &&
                json.compare(pos + 1, key.size(), key.data(), key.size()) == 0)
            {
                const size_t v = json.find_first_not_of(" \t\n\r", colon + 1);
                return v == std::string::npos ? json.size() : v;
            }
            pos = end;
        }
    }
    return std::string::npos;
}

// Is this key named in the document, which `import` needs to tell a
// field set to its default from one left out, as a second walk rather than a
// flag threaded through the getters.
bool json_has_key(const std::string& json, std::string_view key)
{
    return top_value_of(json, key) != std::string::npos;
}

// Every key the document names at its top, enumerated in one walk rather than
// from a hand-written list that goes stale the first time somebody adds a field.
void json_collect_keys(const std::string& json, std::set<std::string, std::less<>>& out)
{
    int depth = 0;
    for (size_t pos = 0; pos < json.size(); ++pos)
    {
        const char c = json[pos];
        if (c == '{' || c == '[')
            ++depth;
        else if (c == '}' || c == ']')
            --depth;
        else if (c == '"')
        {
            size_t end = pos + 1;
            while (end < json.size() && json[end] != '"')
            {
                if (json[end] == '\\' && end + 1 < json.size()) ++end;   // \" is not the end
                ++end;
            }
            if (end >= json.size())
                return;
            const size_t after = json.find_first_not_of(" \t\n\r", end + 1);
            if (depth == 1 && after != std::string::npos && json[after] == ':')
                out.insert(json.substr(pos + 1, end - pos - 1));
            // Past this token whether it was a key or a value, so a value is never examined as if it were a key.
            pos = end;
        }
    }
}

// Simple JSON value parser: extract string value for a key from JSON text
std::string json_get_string(const std::string& json, std::string_view key)
{
    size_t vpos = top_value_of(json, key);
    if (vpos >= json.size())
        return {};

    if (json[vpos] == '"')
    {
        ++vpos;
        std::string result;
        while (vpos < json.size() && json[vpos] != '"')
        {
            if (json[vpos] == '\\' && vpos + 1 < json.size())
            {
                result += json[vpos];
                result += json[vpos + 1];
                vpos += 2;
            }
            else
            {
                result += json[vpos];
                ++vpos;
            }
        }
        return json_unescape(result);
    }

    // Not a string — extract until comma, ], or }
    size_t end = json.find_first_of(",]}", vpos);
    if (end == std::string::npos) end = json.size();
    std::string val = json.substr(vpos, end - vpos);
    // Trim whitespace
    while (!val.empty() && (val.back() == ' ' || val.back() == '\n' || val.back() == '\r' || val.back() == '\t'))
        val.pop_back();
    return val;
}

bool json_get_bool(const std::string& json, std::string_view key, bool default_val = false)
{
    std::string v = json_get_string(json, key);
    if (v == "true")  return true;
    if (v == "false") return false;
    return default_val;
}

// The whole of the token or nothing, because std::sto* stops at the first
// character it cannot use and read "80abc" as 80, where the default is the
// honest answer.
template <typename T, typename Fn>
T json_get_number(const std::string& json, std::string_view key, T default_val, Fn convert)
{
    std::string v = json_get_string(json, key);
    if (v.empty()) return default_val;
    // stoul and stoull take a minus and wrap it, so -1 would come back as the largest value there is.
    if (std::is_unsigned_v<T> && v.find('-') != std::string::npos) return default_val;
    try
    {
        size_t consumed = 0;
        const T out = convert(v, consumed);
        if (consumed != v.size()) return default_val;   // trailing anything
        return out;
    }
    catch (...) { return default_val; }
}

int json_get_int(const std::string& json, std::string_view key, int default_val = 0)
{
    return json_get_number<int>(json, key, default_val,
        [](const std::string& s, size_t& n) { return std::stoi(s, &n); });
}

uint32_t json_get_uint32(const std::string& json, std::string_view key, uint32_t default_val = 0)
{
    return json_get_number<uint32_t>(json, key, default_val,
        [](const std::string& s, size_t& n) {
            const unsigned long v = std::stoul(s, &n);
            if (v > std::numeric_limits<uint32_t>::max()) throw std::out_of_range("uint32");
            return static_cast<uint32_t>(v);
        });
}

double json_get_double(const std::string& json, std::string_view key, double default_val = 0.0)
{
    const double v = json_get_number<double>(json, key, default_val,
        [](const std::string& s, size_t& n) { return std::stod(s, &n); });
    // A NaN read back out of a state file is not a number anything here can act
    // on -- it is false against every comparison a caller makes -- so it gets
    // the answer a field that would not parse gets, which is the default.
    return std::isnan(v) ? default_val : v;
}

size_t json_get_size(const std::string& json, std::string_view key, size_t default_val = 0)
{
    return json_get_number<size_t>(json, key, default_val,
        [](const std::string& s, size_t& n) { return static_cast<size_t>(std::stoull(s, &n)); });
}

std::vector<std::string> json_get_array(const std::string& json, std::string_view key)
{
    std::vector<std::string> result;

    size_t pos = top_value_of(json, key);
    if (pos >= json.size() || json[pos] != '[') return result;
    ++pos;

    // String by string to the bracket that closes the array, since a value may hold a ']' of its own.
    while (pos < json.size())
    {
        pos = json.find_first_not_of(" \t\n\r,", pos);
        if (pos == std::string::npos || json[pos] != '"')
            break;
        ++pos;
        std::string val;
        while (pos < json.size() && json[pos] != '"')
        {
            if (json[pos] == '\\' && pos + 1 < json.size())
            {
                val += json[pos];
                val += json[pos + 1];
                pos += 2;
            }
            else
            {
                val += json[pos];
                ++pos;
            }
        }
        if (pos < json.size()) ++pos; // skip closing quote
        result.push_back(json_unescape(val));
    }

    return result;
}

// The one nested object in this format: "extra"'s string pairs in document
// order, which the flat getters above cannot be pointed at.
void json_get_extra(const std::string& json,
                    std::vector<std::pair<std::string, std::string>>& out)
{
    out.clear();

    size_t pos = top_value_of(json, "extra");
    if (pos >= json.size() || json[pos] != '{')
        return;
    ++pos;

    // Quote-delimited tokens alternate key and value, so a brace inside a
    // string never ends the walk early.
    auto take_string = [&](std::string& s) -> bool {
        pos = json.find('"', pos);
        if (pos == std::string::npos) return false;
        ++pos;
        s.clear();
        while (pos < json.size() && json[pos] != '"')
        {
            if (json[pos] == '\\' && pos + 1 < json.size())
            {
                s += json[pos];
                s += json[pos + 1];
                pos += 2;
            }
            else
            {
                s += json[pos];
                ++pos;
            }
        }
        if (pos >= json.size()) return false;
        ++pos;
        return true;
    };

    while (pos < json.size())
    {
        const size_t next = json.find_first_not_of(" \t\n\r,", pos);
        if (next == std::string::npos || json[next] == '}')
            return;
        pos = next;

        std::string key, val;
        if (!take_string(key))
            return;
        const size_t colon = json.find_first_not_of(" \t\n\r", pos);
        if (colon == std::string::npos || json[colon] != ':')
            return;
        pos = colon + 1;
        const size_t vstart = json.find_first_not_of(" \t\n\r", pos);
        if (vstart == std::string::npos || json[vstart] != '"')
            return;
        if (!take_string(val))
            return;
        out.emplace_back(json_unescape(key), json_unescape(val));
    }
}

std::string resolve_absolute(std::string_view path)
{
    if (path.empty()) return {};
    std::error_code ec;
    auto canonical = fs::canonical(fs::path(path), ec);
    if (!ec)
        return canonical.string();
    // File doesn't exist yet — use absolute instead
    return fs::absolute(fs::path(path)).string();
}

} // namespace sp_detail

// ─── state_persistence ───

state_persistence::state_persistence(const fs::path& state_dir)
    : m_state_dir(state_dir)
{
    // An empty directory means this object is a parser and nothing else: five
    // places build one only to decode a config, and each was starting and
    // joining a thread to do it, two of them on the worker-restart path.
    //
    // The cost is not the thread.  It is that this constructor could not fail
    // gracefully -- std::thread throws std::system_error on EAGAIN, nothing on
    // these paths catches it, and a daemon that could not make one more thread
    // died with `terminate called ... Resource temporarily unavailable` in
    // place of refusing a single command.  Measured with RLIMIT_NPROC at 1:
    // the daemon aborted and dumped core on `create`.
    if (!m_state_dir.empty())
        m_writer = std::thread(&state_persistence::writer_loop, this);
}

// Where this runtime's state file goes, or an empty path if it may not have one.
//
// ─── A SHARED BIN IS NOT A REFUSAL ──────────────────────────────────────────
// Names are validated at both doors now, but this stays as the second line
// because it guards the filesystem, and it answers with an empty path rather
// than routing every rejected name to one shared file.
fs::path state_persistence::config_path(std::string_view name) const
{
    for (char c : name)
    {
        if (c == '/' || c == '\\' || c == '\0')
            return {};
    }
    if (name.empty() || name.find("..") != std::string_view::npos)
        return {};

    return m_state_dir / (std::string(name) + ".json");
}

runtime_config state_persistence::read_from_instance(const runtime_instance* instance) const
{
    using namespace sp_detail;
    runtime_config cfg;
    cfg.name = instance->get_name();
    cfg.id = instance->get_id();
    cfg.type = instance->get_type();
    cfg.port = instance->get_port();
    cfg.was_running = (instance->get_state() == runtime_running);

    // Common
    cfg.log_file = instance->get_log_file();
    cfg.write_file = instance->get_write_file();
    cfg.lua_script = resolve_absolute(instance->get_lua_script_path());
    cfg.bash_output = instance->get_bash_output();
    cfg.bash_prefix = instance->get_bash_prefix();
    cfg.bash_timestamp = instance->get_bash_timestamp();
    cfg.max_connections = instance->get_max_connections();
    cfg.rate_limit = instance->get_rate_limit();
    cfg.global_rate_limit = instance->get_global_rate_limit();
    cfg.idle_timeout = instance->get_idle_timeout();
    cfg.congestion = instance->get_congestion();
    cfg.write_buffer = instance->get_write_buffer();
    cfg.read_buffer  = instance->get_read_buffer();
    cfg.drain = instance->get_drain();
    cfg.reconnect = instance->get_reconnect();
    cfg.tls = instance->get_tls();
    cfg.cert_path = instance->get_cert_path();
    cfg.key_path = instance->get_key_path();
    for (const std::string& d : instance->get_acme_domains())
        cfg.acme_domains += (cfg.acme_domains.empty() ? "" : ",") + d;
    cfg.acme_email = instance->get_acme_email();
    cfg.domains = std::string(instance->get_domains());
    cfg.ca_path = instance->get_ca_path();
    cfg.target = instance->get_target();
    cfg.listen_path = instance->get_listen_path();
    cfg.bind_address = instance->get_bind_address();
    cfg.cache_name = instance->get_cache_name();
    cfg.group = instance->get_group();
    cfg.owner = instance->get_owner();
    cfg.child_policy = (instance->get_child_policy() == runtime_instance::child_policy::remove) ? 1 : 0;
    cfg.shards = instance->get_shards();
    // Only a request that was actually made is written, or every plain
    // `create` would become an explicit CPU set on the next restart.
    if (instance->has_cpus_request())
        cfg.cpus = instance->get_cpus().to_string();
    cfg.external_runtime = instance->is_external();
    if (cfg.external_runtime)
    {
        cfg.managed = instance->is_managed();
        cfg.exec_path = instance->get_exec_path();
        cfg.pid = static_cast<int32_t>(instance->get_pid());
        if (!cfg.managed)
            cfg.was_running = false;  // prevent daemon from trying to re-bind on restart
    }

    // Type-specific
    switch (cfg.type)
    {
        case runtime_server:
        {
            auto* srv = static_cast<const server_instance*>(instance);
            cfg.mode = static_cast<uint8_t>(srv->get_mode());
            cfg.send_to = srv->get_send_to();
            cfg.udp = srv->is_udp();
            cfg.master_pw = std::string(srv->get_master_pw());
            cfg.http_dir = srv->get_http_dir().string();
            cfg.http_cache = srv->get_http_cache();
            cfg.compress = srv->get_compress();
            cfg.no_inject = !srv->get_inject();
            cfg.origins = std::string(srv->get_origins());
            for (const auto& ut : srv->get_upstream_targets())
                cfg.upstreams.push_back(ut.address);
            break;
        }
        case runtime_client:
        {
            auto* cli = static_cast<const client_instance*>(instance);
            cfg.mode = static_cast<uint8_t>(cli->get_mode());
            cfg.udp = cli->is_udp();
            break;
        }
        case runtime_proxy:
        {
            auto* prx = static_cast<const proxy_instance*>(instance);
            cfg.protocol = static_cast<uint8_t>(prx->get_protocol());
            cfg.strategy = static_cast<uint8_t>(prx->get_strategy());
            for (const auto& b : prx->get_backends())
                cfg.backends.push_back(b.address);
            const auto& mesh = prx->get_mesh_config();
            cfg.health_check = static_cast<uint8_t>(mesh.health_check);
            cfg.health_interval = mesh.health_interval;
            cfg.health_path = mesh.health_path;
            cfg.fcgi_root = std::string(prx->get_root());
            cfg.fcgi_remote_root = std::string(prx->get_fastcgi_root());
            cfg.fcgi_index = std::string(prx->get_index());
            cfg.compress = prx->get_compress();
            cfg.health_threshold = mesh.health_threshold;
            cfg.circuit_threshold = mesh.circuit_threshold;
            cfg.circuit_timeout = mesh.circuit_timeout;
            cfg.backend_timeout = mesh.backend_timeout;
            cfg.retry_count = mesh.retry_count;
            cfg.retry_all = mesh.retry_all;
            cfg.mesh_client_ca = mesh.client_ca;
            cfg.mesh_client_cert = mesh.client_cert;
            cfg.mesh_client_key = mesh.client_key;
            cfg.proxy_auth = prx->get_auth();
            cfg.https_redirect = prx->get_https_redirect();
            break;
        }
        case runtime_cache:
        {
            auto* cache = static_cast<const cache_instance*>(instance);
            cfg.persistent_path = cache->get_persistent();
            cfg.persistent_interval = cache->get_persist_interval();
            cfg.cache_mode = static_cast<uint8_t>(cache->get_mode());
            cfg.resp_forced = cache->get_resp_forced();
            cfg.cluster = cache->get_cluster();
            cfg.replicate_target = cache->get_replicate_target();
            cfg.cluster_replica = cache->get_cluster_replica();
            cfg.max_memory = cache->get_max_memory();
            cfg.eviction = static_cast<uint8_t>(cache->get_eviction());
            cfg.cache_public = cache->get_public();
            break;
        }
        case runtime_dns:
        {
            auto* d = static_cast<const dns_instance*>(instance);
            cfg.dns_zones = std::string(d->get_zones());
            cfg.dns_transfer = std::string(d->get_transfer());
            cfg.dns_notify = std::string(d->get_notify());
            cfg.dns_publish = std::string(d->get_publish());
            cfg.dns_proxy = std::string(d->get_proxy());
            cfg.dns_rrl = d->get_rrl();
            cfg.dns_dnssec = d->get_dnssec();
            break;
        }
        case runtime_sync:
        {
            auto* sy = static_cast<const sync_instance*>(instance);
            cfg.sync_dir = std::string(sy->get_dir());
            cfg.sync_storage = std::string(sy->get_storage());
            cfg.sync_prefix = std::string(sy->get_prefix());
            cfg.sync_credentials = std::string(sy->get_credentials());
            cfg.sync_exclude = std::string(sy->get_exclude());
            cfg.sync_repositories = std::string(sy->get_repositories());
            cfg.sync_every = sy->get_every();
            cfg.mode = static_cast<uint8_t>(sy->get_mode());
            break;
        }
        case runtime_idp:
        {
            auto* ip = static_cast<const idp_instance*>(instance);
            cfg.idp_clients = std::string(ip->get_clients());
            cfg.idp_issuer = std::string(ip->get_issuer_flag());
            cfg.idp_cookie_domain = std::string(ip->get_cookie_domain());
            cfg.idp_resources = std::string(ip->get_resources());
            cfg.idp_ssh_ca_hours = ip->get_ssh_ca_hours();
            break;
        }
        case runtime_tunnel:
        {
            auto* tn = static_cast<const tunnel_instance*>(instance);
            cfg.tunnel_mode = static_cast<uint8_t>(tn->get_mode());
            cfg.tunnel_to = std::string(tn->get_to());
            cfg.tunnel_join = std::string(tn->get_join());
            cfg.tunnel_offers = std::string(tn->get_offers());
            cfg.tunnel_forward = std::string(tn->get_forward());
            cfg.tunnel_idp = std::string(tn->get_idp());
            cfg.tunnel_idp_audience = std::string(tn->get_idp_audience());
            break;
        }
        case runtime_db:
        {
            auto* db = static_cast<const db_instance*>(instance);
            cfg.db_schema = std::string(db->get_schema_path());
            cfg.db_keys = std::string(db->get_keys_path());
            cfg.db_idp = std::string(db->get_idp());
            cfg.db_idp_audience = std::string(db->get_idp_audience());
            cfg.db_origins = std::string(db->get_origins());
            cfg.db_max_bytes = db->get_max_bytes();
            cfg.db_cache = db->get_cache_bytes();
            cfg.db_replicate = std::string(db->get_replicate());
            cfg.db_replicate_key = std::string(db->get_replicate_key());
            cfg.db_backup_dir = std::string(db->get_backup_dir());
            cfg.db_backup_every = db->get_backup_every();
            cfg.db_backup_keep = db->get_backup_keep();
            break;
        }
        case runtime_mcp:
        {
            auto* mc = static_cast<const mcp_instance*>(instance);
            cfg.mcp_keys = std::string(mc->get_keys_path());
            cfg.mcp_anonymous = mc->get_anonymous();
            cfg.mcp_origins = std::string(mc->get_origins());
            cfg.mcp_tools = std::string(mc->get_tools());
            cfg.mcp_instructions = std::string(mc->get_instructions());
            cfg.mcp_idp = std::string(mc->get_idp());
            cfg.mcp_idp_audience = std::string(mc->get_idp_audience());
            break;
        }
        case runtime_metrics:
        {
            auto* mt = static_cast<const metrics_instance*>(instance);
            cfg.metrics_keys = std::string(mt->get_keys_path());
            cfg.metrics_idp = std::string(mt->get_idp());
            cfg.metrics_idp_audience = std::string(mt->get_idp_audience());
            cfg.metrics_no_local = !mt->get_local();
            cfg.metrics_scrape = std::string(mt->get_scrape_path());
            cfg.metrics_archive = std::string(mt->get_archive());
            cfg.metrics_archive_credentials = std::string(mt->get_archive_credentials());
            cfg.metrics_every = mt->get_every();
            cfg.metrics_keep = mt->get_keep();
            cfg.metrics_downsample = std::string(mt->get_downsample());
            cfg.metrics_max_series = mt->get_max_series();
            cfg.metrics_durable = mt->get_durable();
            cfg.metrics_logs = mt->get_logs();
            cfg.metrics_logs_keep = mt->get_logs_keep();
            cfg.metrics_rules = std::string(mt->get_rules_path());
            cfg.metrics_notify = std::string(mt->get_notify());
            cfg.metrics_receive = mt->get_receive();
            break;
        }
        case runtime_mqtt:
        {
            auto* mq = static_cast<const mqtt_instance*>(instance);
            cfg.mqtt_users = std::string(mq->get_users());
            cfg.mqtt_idp = std::string(mq->get_idp());
            cfg.mqtt_idp_audience = std::string(mq->get_idp_audience());
            cfg.mqtt_acl = std::string(mq->get_acl());
            cfg.mqtt_routes = std::string(mq->get_routes());
            cfg.mqtt_anonymous = mq->get_anonymous();
            cfg.mqtt_ws_port = mq->get_ws_port();
            cfg.mqtt_max_packet = mq->get_max_packet();
            cfg.mqtt_session_expiry = mq->get_session_expiry();
            cfg.mqtt_session_queue = mq->get_session_queue();
            cfg.mqtt_retained_max = mq->get_retained_max();
            cfg.mqtt_max_sessions = mq->get_max_sessions();
            cfg.mqtt_keepalive_max = mq->get_keepalive_max();
            cfg.persistent_path = std::string(mq->get_persistent());
            cfg.persistent_interval = mq->get_persist_interval();
            break;
        }
        case runtime_mail:
        {
            auto* ml = static_cast<const mail_instance*>(instance);
            cfg.mail_submission = ml->get_submission_port();
            cfg.mail_submissions = ml->get_submissions_port();
            cfg.mail_imap = ml->get_imap_port();
            cfg.mail_imaps = ml->get_imaps_port();
            cfg.mail_sieve = ml->get_sieve_port();
            cfg.mail_dnsbl = std::string(ml->get_dnsbl());
            cfg.mail_pop3 = ml->get_pop3_port();
            cfg.mail_pop3s = ml->get_pop3s_port();
            cfg.mail_jmap = ml->get_jmap_port();
            cfg.mail_web = ml->get_web_port();
            cfg.mail_lmtp = ml->get_lmtp_port();
            cfg.mail_sts_port = ml->get_mta_sts_port();
            cfg.mail_greylist = ml->get_greylist();
            cfg.mail_rspamd = std::string(ml->get_rspamd());
            cfg.mail_delimiter = std::string(ml->get_recipient_delimiter());
            cfg.mail_reports = ml->get_reports();
            cfg.mail_dmarc_rua = std::string(ml->get_dmarc_rua());
            cfg.mail_dmarc_policy = std::string(ml->get_dmarc_policy());
            cfg.mail_bimi = std::string(ml->get_bimi());
            cfg.mail_refused_attachments = std::string(ml->get_refused_attachments());
            cfg.mail_clamav = std::string(ml->get_clamav());
            cfg.mail_tls_rpt = std::string(ml->get_tls_rpt());
            cfg.mail_mta_sts = std::string(ml->get_mta_sts());
            cfg.mail_default_quota = ml->get_default_quota();
            cfg.mail_quota_warn = ml->get_quota_warn();
            cfg.mail_arc_trust = std::string(ml->get_arc_trust());
            cfg.mail_dkim_next = std::string(ml->get_dkim_next());
            cfg.mail_dns = std::string(ml->get_dns());
            cfg.mail_domains = std::string(ml->get_mail_domains());
            cfg.mail_hostname = std::string(ml->get_hostname());
            cfg.mail_no_reply = ml->get_no_reply();
            cfg.mail_idp = std::string(ml->get_idp());
            cfg.mail_idp_audience = std::string(ml->get_idp_audience());
            cfg.mail_storage = std::string(ml->get_storage());
            cfg.mail_users = std::string(ml->get_users());
            cfg.mail_relay = std::string(ml->get_relay());
            cfg.mail_aliases = std::string(ml->get_aliases());
            cfg.mail_notify = std::string(ml->get_notify_targets());
            cfg.mail_max_size = ml->get_max_size();
            cfg.mail_max_rcpt = ml->get_max_recipients();
            cfg.mail_lifetime = ml->get_queue_lifetime();
            cfg.mail_autoexpunge = ml->get_autoexpunge();
            cfg.mail_selector = std::string(ml->get_dkim_selector());
            break;
        }
        case runtime_storage:
        {
            auto* stg = static_cast<const storage_instance*>(instance);
            cfg.storage_dir = std::string(stg->get_dir());
            cfg.storage_anonymous = stg->get_anonymous();
            cfg.storage_idp = std::string(stg->get_idp());
            cfg.storage_acls = stg->get_acls();
            cfg.storage_max_bytes = stg->get_max_bytes();
            cfg.storage_access_key = std::string(stg->get_access_key());
            cfg.storage_secret_key = std::string(stg->get_secret_key());
            cfg.storage_credentials = std::string(stg->get_credentials_file());
            cfg.storage_sse_key_file = std::string(stg->get_sse_key_file());
            cfg.storage_domain = std::string(stg->get_domain());
            cfg.storage_website_domain = std::string(stg->get_website_domain());
            cfg.storage_notify_targets = std::string(stg->get_notify_targets());
            cfg.storage_replication_targets = std::string(stg->get_replication_targets());
            cfg.storage_tiers = std::string(stg->get_tiers_file());
            cfg.storage_federation = std::string(stg->get_federation_file());
            cfg.storage_tls_offloaded = std::string(stg->get_tls_offloaded());
            cfg.storage_nodes = std::string(stg->get_nodes_file());
            cfg.storage_fsync = std::string(stg->get_fsync());
            cfg.storage_sync = std::string(stg->get_sync());
            cfg.storage_fsync_interval_secs = stg->get_fsync_interval_secs();
            cfg.storage_mpu_expire_secs = stg->get_mpu_expire_secs();
            cfg.storage_scrub_secs = stg->get_scrub_secs();
            cfg.storage_compress_secs = stg->get_compress_secs();
            break;
        }
    }

    cfg.type_name = type_to_string(cfg.type);

    // A registered type's fields come from the instance, because this file
    // knows neither their names nor their kinds.
    instance->capture_config(cfg.extra);

    return cfg;
}

std::string state_persistence::format_json_pretty(const runtime_config& cfg) const
{
    using namespace sp_detail;
    // What a field is when nobody set it, so only a field that differs is written.
    static const runtime_config defaults;

    // Helper lambdas for direct string building
    std::string j;
    j.reserve(1024);

    auto append_int = [&](auto v) {
        char buf[24];
        auto [end, ec] = std::to_chars(buf, buf + sizeof(buf), v);
        j.append(buf, end - buf);
    };

    auto append_str_field = [&](const char* key, std::string_view val) {
        j += "    \"";
        j += key;
        j += "\": \"";
        socketley::json::escape_into(j, val);
        j += "\",\n";
    };

    auto append_bool_field = [&](const char* key, bool val) {
        j += "    \"";
        j += key;
        j += "\": ";
        j += val ? "true" : "false";
        j += ",\n";
    };

    auto append_int_field = [&](const char* key, auto val) {
        j += "    \"";
        j += key;
        j += "\": ";
        append_int(val);
        j += ",\n";
    };

    auto append_double_field = [&](const char* key, double val) {
        char buf[64];
        // %g writes `inf`, which is not a JSON token and is what
        // `--rate-limit inf` put in this file: parse_double accepts an
        // infinity on purpose, so the value is kept as the largest number this
        // format can say rather than written as one nothing can read.
        // The shortest text that reads back as the same double, where %g's six digits turned 1234567 into 1234570.
        const auto end = std::to_chars(buf, buf + sizeof(buf),
                                             std::isfinite(val) ? val : std::numeric_limits<double>::max()).ptr;
        const int n = static_cast<int>(end - buf);
        j += "    \"";
        j += key;
        j += "\": ";
        j.append(buf, static_cast<size_t>(n));
        j += ",\n";
    };

    j += "{\n";
    append_str_field("name", cfg.name);
    append_str_field("id", cfg.id);
    append_str_field("type", type_to_string(cfg.type));
    append_int_field("port", cfg.port);
    // Written only when there is one, with the `unix:` prefix kept because
    // this is the field an operator edits and re-imports.
    if (!cfg.listen_path.empty())
        append_str_field("listen", "unix:" + cfg.listen_path);
    if (!cfg.bind_address.empty())
        append_str_field("bind", cfg.bind_address);
    append_bool_field("was_running", cfg.was_running);

    // Common fields (only write non-default)
    if (!cfg.log_file.empty())
        append_str_field("log_file", cfg.log_file);
    if (!cfg.write_file.empty())
        append_str_field("write_file", cfg.write_file);
    if (!cfg.lua_script.empty())
        append_str_field("lua_script", cfg.lua_script);
    if (cfg.bash_output)
        append_bool_field("bash_output", true);
    if (cfg.bash_prefix)
        append_bool_field("bash_prefix", true);
    if (cfg.bash_timestamp)
        append_bool_field("bash_timestamp", true);
    if (cfg.max_connections > 0)
        append_int_field("max_connections", cfg.max_connections);
    if (cfg.rate_limit > 0.0)
        append_double_field("rate_limit", cfg.rate_limit);
    if (cfg.global_rate_limit > 0.0)
        append_double_field("global_rate_limit", cfg.global_rate_limit);
    if (cfg.idle_timeout > 0)
        append_int_field("idle_timeout", cfg.idle_timeout);
    if (!cfg.congestion.empty())
        append_str_field("congestion", cfg.congestion);
    // Written only when it differs, so the records of every runtime nobody
    // configured stay byte-identical to what they were.
    if (cfg.write_buffer > 0 && cfg.write_buffer != socketley::write_queue_max_bytes)
        append_int_field("write_buffer", cfg.write_buffer);
    if (cfg.read_buffer > 0 && cfg.read_buffer != 1u * 1024 * 1024)
        append_int_field("read_buffer", cfg.read_buffer);
    if (cfg.drain)
        append_bool_field("drain", true);
    if (cfg.reconnect >= 0)
        append_int_field("reconnect", cfg.reconnect);
    if (cfg.tls)
        append_bool_field("tls", true);
    if (!cfg.cert_path.empty())
        append_str_field("cert_path", cfg.cert_path);
    if (!cfg.key_path.empty())
        append_str_field("key_path", cfg.key_path);
    if (!cfg.acme_domains.empty())
        append_str_field("acme_domains", cfg.acme_domains);
    if (!cfg.acme_email.empty())
        append_str_field("acme_email", cfg.acme_email);
    if (!cfg.domains.empty() && cfg.type != runtime_storage)
        append_str_field("domain", cfg.domains);
    if (!cfg.ca_path.empty())
        append_str_field("ca_path", cfg.ca_path);
    if (!cfg.target.empty())
        append_str_field("target", cfg.target);
    if (!cfg.cache_name.empty())
        append_str_field("cache_name", cfg.cache_name);
    if (!cfg.group.empty())
        append_str_field("group", cfg.group);
    if (!cfg.owner.empty())
        append_str_field("owner", cfg.owner);
    if (cfg.child_policy != 0)
        append_int_field("child_policy", cfg.child_policy);
    // Written only when it is not the default, on the rule this function states
    // above: a `create` nobody typed --shards on must not start producing a
    // state file that differs from the one the previous build wrote for it.
    if (cfg.shards > 1)
        append_int_field("shards", static_cast<int>(cfg.shards));
    // Above zero only, because the daemon's placeholder reads 0 and absent
    // parses back as 0, which is what shard 0 is.
    if (cfg.shard_index > 0)
        append_int_field("shard_index", static_cast<int>(cfg.shard_index));
    // Written only when true, so it reaches a child's config frame and never a
    // state file: a restored runtime is forked fresh and wired anew.
    if (cfg.mesh_wired)
        append_bool_field("mesh_wired", true);
    // Same rule, same reason: derived, so it belongs to the daemon that
    // derived it and not to a document that outlives it.
    if (!cfg.companion_path.empty())
        append_str_field("companion_path", cfg.companion_path);
    if (!cfg.cpus.empty())
        append_str_field("cpus", cfg.cpus);
    if (cfg.external_runtime)
    {
        append_bool_field("external_runtime", true);
        if (cfg.managed)
        {
            append_bool_field("managed", true);
            if (!cfg.exec_path.empty())
                append_str_field("exec_path", cfg.exec_path);
        }
        if (cfg.pid > 0)
            append_int_field("pid", cfg.pid);
    }

    // Type-specific
    switch (cfg.type)
    {
        case runtime_server:
            append_str_field("mode", server_mode_str(cfg.mode));
            if (cfg.send_to != 0)
                append_str_field("send_to", server_send_to_str(cfg.send_to));
            if (cfg.udp)
                append_bool_field("udp", true);
            if (!cfg.master_pw.empty())
                append_str_field("master_pw", cfg.master_pw);
            if (!cfg.http_dir.empty())
                append_str_field("http_dir", cfg.http_dir);
            if (cfg.http_cache)
                append_bool_field("http_cache", true);
            if (cfg.compress)
                append_bool_field("compress", true);
            if (cfg.no_inject)
                append_bool_field("no_inject", true);
            if (!cfg.origins.empty())
                append_str_field("origins", cfg.origins);
            if (!cfg.upstreams.empty())
            {
                j += "    \"upstreams\": [";
                for (size_t i = 0; i < cfg.upstreams.size(); ++i)
                {
                    if (i > 0) j += ", ";
                    j += "\"";
                    socketley::json::escape_into(j, cfg.upstreams[i]);
                    j += "\"";
                }
                j += "],\n";
            }
            break;
        case runtime_client:
            append_str_field("mode", server_mode_str(cfg.mode));
            if (cfg.udp)
                append_bool_field("udp", true);
            break;
        case runtime_proxy:
            append_str_field("protocol", proxy_protocol_str(cfg.protocol));
            append_str_field("strategy", proxy_strategy_str(cfg.strategy));
            if (!cfg.backends.empty())
            {
                j += "    \"backends\": [";
                for (size_t i = 0; i < cfg.backends.size(); ++i)
                {
                    if (i > 0) j += ", ";
                    j += "\"";
                    socketley::json::escape_into(j, cfg.backends[i]);
                    j += "\"";
                }
                j += "],\n";
            }
            if (cfg.health_check > 0)
                append_int_field("health_check", static_cast<int>(cfg.health_check));
            if (cfg.health_interval != defaults.health_interval)
                append_int_field("health_interval", cfg.health_interval);
            if (!cfg.health_path.empty() && cfg.health_path != "/health")
                append_str_field("health_path", cfg.health_path);
            if (!cfg.fcgi_root.empty())
                append_str_field("root", cfg.fcgi_root);
            if (!cfg.fcgi_remote_root.empty())
                append_str_field("fastcgi_root", cfg.fcgi_remote_root);
            if (!cfg.fcgi_index.empty() && cfg.fcgi_index != "index.php")
                append_str_field("index", cfg.fcgi_index);
            if (cfg.compress)
                append_bool_field("compress", true);
            if (!cfg.proxy_auth.empty())
                append_str_field("auth", cfg.proxy_auth);
            if (cfg.https_redirect != 0)
                append_int_field("redirect_https", cfg.https_redirect);
            if (cfg.health_threshold != defaults.health_threshold)
                append_int_field("health_threshold", cfg.health_threshold);
            if (cfg.circuit_threshold != defaults.circuit_threshold)
                append_int_field("circuit_threshold", cfg.circuit_threshold);
            if (cfg.circuit_timeout != defaults.circuit_timeout)
                append_int_field("circuit_timeout", cfg.circuit_timeout);
            if (cfg.backend_timeout != defaults.backend_timeout)
                append_int_field("backend_timeout", cfg.backend_timeout);
            if (cfg.retry_count > 0)
                append_int_field("retry_count", cfg.retry_count);
            if (cfg.retry_all)
                append_bool_field("retry_all", true);
            if (!cfg.mesh_client_ca.empty())
                append_str_field("mesh_client_ca", cfg.mesh_client_ca);
            if (!cfg.mesh_client_cert.empty())
                append_str_field("mesh_client_cert", cfg.mesh_client_cert);
            if (!cfg.mesh_client_key.empty())
                append_str_field("mesh_client_key", cfg.mesh_client_key);
            break;
        case runtime_cache:
            if (!cfg.persistent_path.empty())
                append_str_field("persistent_path", cfg.persistent_path);
            if (cfg.persistent_interval > 0)
                append_int_field("persistent_interval", cfg.persistent_interval);
            append_str_field("cache_mode", cache_mode_str(cfg.cache_mode));
            if (cfg.resp_forced)
                append_bool_field("resp_forced", true);
            if (cfg.cluster)
                append_bool_field("cluster", true);
            if (!cfg.replicate_target.empty())
                append_str_field("replicate_target", cfg.replicate_target);
            if (cfg.cluster_replica != 0)
                append_str_field("cluster_replica", std::to_string(cfg.cluster_replica));
            if (cfg.max_memory > 0)
                append_int_field("max_memory", cfg.max_memory);
            append_str_field("eviction", eviction_str(cfg.eviction));
            if (cfg.cache_public)
                append_bool_field("public", true);
            break;
        case runtime_storage:
            append_str_field("dir", cfg.storage_dir);
            if (!cfg.storage_idp.empty())
                append_str_field("idp", cfg.storage_idp);
            if (cfg.storage_anonymous)
                append_bool_field("anonymous", true);
            if (cfg.storage_acls)
                append_bool_field("acls", true);
            if (cfg.storage_max_bytes > 0)
                append_int_field("max_bytes", cfg.storage_max_bytes);
            if (!cfg.storage_access_key.empty())
                append_str_field("access_key", cfg.storage_access_key);
            if (!cfg.storage_secret_key.empty())
                append_str_field("secret_key", cfg.storage_secret_key);
            if (!cfg.storage_credentials.empty())
                append_str_field("credentials", cfg.storage_credentials);
            if (!cfg.storage_sse_key_file.empty())
                append_str_field("sse_key_file", cfg.storage_sse_key_file);
            if (!cfg.storage_domain.empty())
                append_str_field("domain", cfg.storage_domain);
            if (!cfg.storage_website_domain.empty())
                append_str_field("website_domain", cfg.storage_website_domain);
            if (!cfg.storage_notify_targets.empty())
                append_str_field("notify_targets", cfg.storage_notify_targets);
            if (!cfg.storage_replication_targets.empty())
                append_str_field("replication_targets", cfg.storage_replication_targets);
            if (!cfg.storage_tiers.empty())
                append_str_field("tiers", cfg.storage_tiers);
            if (!cfg.storage_federation.empty())
                append_str_field("federation", cfg.storage_federation);
            if (!cfg.storage_tls_offloaded.empty())
                append_str_field("tls_offloaded", cfg.storage_tls_offloaded);
            if (!cfg.storage_nodes.empty())
                append_str_field("nodes", cfg.storage_nodes);
            if (!cfg.storage_fsync.empty())
                append_str_field("fsync", cfg.storage_fsync);
            if (!cfg.storage_sync.empty() && cfg.storage_sync != "never")
                append_str_field("sync", cfg.storage_sync);
            if (cfg.storage_fsync_interval_secs > 0)
                append_int_field("fsync_interval", cfg.storage_fsync_interval_secs);
            if (cfg.storage_mpu_expire_secs > 0)
                append_int_field("mpu_expire", cfg.storage_mpu_expire_secs);
            if (cfg.storage_scrub_secs > 0)
                append_int_field("scrub", cfg.storage_scrub_secs);
            if (cfg.storage_compress_secs > 0)
                append_int_field("compress", cfg.storage_compress_secs);
            break;
        case runtime_dns:
            append_str_field("zones", cfg.dns_zones);
            if (!cfg.dns_transfer.empty())
                append_str_field("transfer", cfg.dns_transfer);
            if (!cfg.dns_notify.empty())
                append_str_field("notify", cfg.dns_notify);
            if (!cfg.dns_publish.empty())
                append_str_field("publish", cfg.dns_publish);
            if (!cfg.dns_proxy.empty())
                append_str_field("proxy", cfg.dns_proxy);
            append_int_field("rrl", cfg.dns_rrl);
            if (cfg.dns_dnssec)
                append_bool_field("dnssec", true);
            break;
        case runtime_sync:
            append_str_field("mode", sync_mode_name(static_cast<sync_mode>(cfg.mode)));
            append_str_field("dir", cfg.sync_dir);
            append_str_field("storage", cfg.sync_storage);
            if (!cfg.sync_prefix.empty())
                append_str_field("prefix", cfg.sync_prefix);
            if (!cfg.sync_credentials.empty())
                append_str_field("credentials", cfg.sync_credentials);
            if (!cfg.sync_exclude.empty())
                append_str_field("exclude", cfg.sync_exclude);
            if (!cfg.sync_repositories.empty())
                append_str_field("repositories", cfg.sync_repositories);
            append_int_field("every", cfg.sync_every);
            break;
        case runtime_idp:
            if (!cfg.idp_clients.empty())
                append_str_field("clients", cfg.idp_clients);
            if (!cfg.idp_issuer.empty())
                append_str_field("issuer", cfg.idp_issuer);
            if (!cfg.idp_cookie_domain.empty())
                append_str_field("cookie_domain", cfg.idp_cookie_domain);
            if (!cfg.idp_resources.empty())
                append_str_field("resources", cfg.idp_resources);
            if (cfg.idp_ssh_ca_hours)
                append_int_field("ssh_ca", cfg.idp_ssh_ca_hours);
            break;
        case runtime_tunnel:
            append_str_field("mode", cfg.tunnel_mode ? "agent" : "edge");
            if (!cfg.tunnel_to.empty())
                append_str_field("to", cfg.tunnel_to);
            if (!cfg.tunnel_join.empty())
                append_str_field("join", cfg.tunnel_join);
            if (!cfg.tunnel_offers.empty())
                append_str_field("offer", cfg.tunnel_offers);
            if (!cfg.tunnel_forward.empty())
                append_str_field("forward", cfg.tunnel_forward);
            if (!cfg.tunnel_idp.empty())
                append_str_field("idp", cfg.tunnel_idp);
            if (!cfg.tunnel_idp_audience.empty())
                append_str_field("idp_audience", cfg.tunnel_idp_audience);
            break;
        case runtime_db:
            if (!cfg.db_schema.empty())
                append_str_field("schema", cfg.db_schema);
            if (!cfg.db_keys.empty())
                append_str_field("keys", cfg.db_keys);
            if (!cfg.db_idp.empty())
                append_str_field("idp", cfg.db_idp);
            if (!cfg.db_idp_audience.empty())
                append_str_field("idp_audience", cfg.db_idp_audience);
            if (!cfg.db_origins.empty())
                append_str_field("origins", cfg.db_origins);
            if (cfg.db_max_bytes > 0)
                append_int_field("max_bytes", cfg.db_max_bytes);
            append_int_field("cache", cfg.db_cache);
            if (!cfg.db_replicate.empty())
                append_str_field("replicate", cfg.db_replicate);
            if (!cfg.db_replicate_key.empty())
                append_str_field("replicate_key", cfg.db_replicate_key);
            if (!cfg.db_backup_dir.empty())
                append_str_field("backup_dir", cfg.db_backup_dir);
            append_int_field("backup_every", cfg.db_backup_every);
            append_int_field("backup_keep", cfg.db_backup_keep);
            break;
        case runtime_mcp:
            if (!cfg.mcp_keys.empty())
                append_str_field("keys", cfg.mcp_keys);
            append_bool_field("anonymous", cfg.mcp_anonymous);
            if (!cfg.mcp_origins.empty())
                append_str_field("origins", cfg.mcp_origins);
            append_str_field("tools", cfg.mcp_tools);
            if (!cfg.mcp_instructions.empty())
                append_str_field("instructions", cfg.mcp_instructions);
            if (!cfg.mcp_idp.empty())
                append_str_field("idp", cfg.mcp_idp);
            if (!cfg.mcp_idp_audience.empty())
                append_str_field("idp_audience", cfg.mcp_idp_audience);
            break;
        case runtime_metrics:
            if (!cfg.metrics_keys.empty())
                append_str_field("keys", cfg.metrics_keys);
            if (!cfg.metrics_idp.empty())
                append_str_field("idp", cfg.metrics_idp);
            if (!cfg.metrics_idp_audience.empty())
                append_str_field("idp_audience", cfg.metrics_idp_audience);
            append_bool_field("no_local", cfg.metrics_no_local);
            if (!cfg.metrics_scrape.empty())
                append_str_field("scrape", cfg.metrics_scrape);
            if (!cfg.metrics_archive.empty())
                append_str_field("archive", cfg.metrics_archive);
            if (!cfg.metrics_archive_credentials.empty())
                append_str_field("archive_credentials", cfg.metrics_archive_credentials);
            append_int_field("every", cfg.metrics_every);
            append_int_field("keep", cfg.metrics_keep);
            append_str_field("downsample", cfg.metrics_downsample);
            append_int_field("max_series", cfg.metrics_max_series);
            append_bool_field("durable", cfg.metrics_durable);
            append_bool_field("logs", cfg.metrics_logs);
            append_int_field("logs_keep", cfg.metrics_logs_keep);
            if (!cfg.metrics_rules.empty())
                append_str_field("rules", cfg.metrics_rules);
            if (!cfg.metrics_notify.empty())
                append_str_field("notify", cfg.metrics_notify);
            append_bool_field("receive", cfg.metrics_receive);
            break;
        case runtime_mqtt:
            if (!cfg.mqtt_users.empty())
                append_str_field("users", cfg.mqtt_users);
            if (!cfg.mqtt_idp.empty())
                append_str_field("idp", cfg.mqtt_idp);
            if (!cfg.mqtt_idp_audience.empty())
                append_str_field("idp_audience", cfg.mqtt_idp_audience);
            if (!cfg.mqtt_acl.empty())
                append_str_field("acl", cfg.mqtt_acl);
            if (!cfg.mqtt_routes.empty())
                append_str_field("routes", cfg.mqtt_routes);
            if (cfg.mqtt_anonymous)
                append_bool_field("anonymous", true);
            if (cfg.mqtt_ws_port)
                append_int_field("ws_port", cfg.mqtt_ws_port);
            append_int_field("max_packet", cfg.mqtt_max_packet);
            append_int_field("session_expiry", cfg.mqtt_session_expiry);
            append_int_field("session_queue", cfg.mqtt_session_queue);
            append_int_field("retained_max", cfg.mqtt_retained_max);
            append_int_field("max_sessions", cfg.mqtt_max_sessions);
            append_int_field("keepalive_max", cfg.mqtt_keepalive_max);
            if (!cfg.persistent_path.empty())
                append_str_field("persistent_path", cfg.persistent_path);
            append_int_field("persistent_interval", cfg.persistent_interval);
            break;
        case runtime_mail:
            if (cfg.mail_submission)
                append_int_field("submission", cfg.mail_submission);
            if (cfg.mail_submissions)
                append_int_field("submissions", cfg.mail_submissions);
            if (cfg.mail_imap)
                append_int_field("imap", cfg.mail_imap);
            if (cfg.mail_imaps)
                append_int_field("imaps", cfg.mail_imaps);
            if (cfg.mail_sieve)
                append_int_field("sieve", cfg.mail_sieve);
            if (!cfg.mail_dnsbl.empty())
                append_str_field("dnsbl", cfg.mail_dnsbl);
            if (cfg.mail_pop3 != 0)
                append_int_field("pop3", cfg.mail_pop3);
            if (cfg.mail_pop3s != 0)
                append_int_field("pop3s", cfg.mail_pop3s);
            if (cfg.mail_jmap != 0)
                append_int_field("jmap", cfg.mail_jmap);
            if (cfg.mail_web != 0)
                append_int_field("web", cfg.mail_web);
            if (cfg.mail_lmtp != 0)
                append_int_field("lmtp", cfg.mail_lmtp);
            if (cfg.mail_sts_port != 0)
                append_int_field("mta_sts_port", cfg.mail_sts_port);
            if (cfg.mail_greylist != 0)
                append_int_field("greylist", cfg.mail_greylist);
            if (!cfg.mail_rspamd.empty())
                append_str_field("rspamd", cfg.mail_rspamd);
            if (cfg.mail_delimiter != "+")
                append_str_field("recipient_delimiter", cfg.mail_delimiter);
            if (cfg.mail_reports)
                append_bool_field("reports", true);
            if (!cfg.mail_dmarc_rua.empty())
                append_str_field("dmarc_rua", cfg.mail_dmarc_rua);
            if (cfg.mail_dmarc_policy != "quarantine")
                append_str_field("dmarc_policy", cfg.mail_dmarc_policy);
            if (!cfg.mail_bimi.empty())
                append_str_field("bimi", cfg.mail_bimi);
            if (cfg.mail_refused_attachments != "default")
                append_str_field("refuse_attachments", cfg.mail_refused_attachments);
            if (!cfg.mail_clamav.empty())
                append_str_field("clamav", cfg.mail_clamav);
            if (!cfg.mail_tls_rpt.empty())
                append_str_field("tls_rpt", cfg.mail_tls_rpt);
            if (!cfg.mail_mta_sts.empty())
                append_str_field("mta_sts", cfg.mail_mta_sts);
            if (cfg.mail_default_quota != 0)
                append_int_field("default_quota", cfg.mail_default_quota);
            if (cfg.mail_quota_warn != 90)
                append_int_field("quota_warn", cfg.mail_quota_warn);
            if (!cfg.mail_arc_trust.empty())
                append_str_field("arc_trust", cfg.mail_arc_trust);
            if (!cfg.mail_dkim_next.empty())
                append_str_field("dkim_next", cfg.mail_dkim_next);
            if (!cfg.mail_dns.empty())
                append_str_field("dns", cfg.mail_dns);
            if (!cfg.mail_domains.empty())
                append_str_field("mail_domain", cfg.mail_domains);
            if (!cfg.mail_hostname.empty())
                append_str_field("hostname", cfg.mail_hostname);
            if (cfg.mail_no_reply)
                append_bool_field("no_reply", true);
            if (!cfg.mail_idp.empty())
                append_str_field("idp", cfg.mail_idp);
            if (!cfg.mail_idp_audience.empty())
                append_str_field("idp_audience", cfg.mail_idp_audience);
            if (!cfg.mail_storage.empty())
                append_str_field("storage", cfg.mail_storage);
            if (!cfg.mail_users.empty())
                append_str_field("users", cfg.mail_users);
            if (!cfg.mail_relay.empty())
                append_str_field("relay", cfg.mail_relay);
            if (!cfg.mail_aliases.empty())
                append_str_field("aliases", cfg.mail_aliases);
            if (!cfg.mail_notify.empty())
                append_str_field("notify_targets", cfg.mail_notify);
            append_int_field("max_size", cfg.mail_max_size);
            append_int_field("max_recipients", cfg.mail_max_rcpt);
            append_int_field("queue_lifetime", cfg.mail_lifetime);
            if (cfg.mail_autoexpunge)
                append_int_field("autoexpunge", cfg.mail_autoexpunge);
            append_str_field("dkim_selector", cfg.mail_selector);
            break;
    }

    // A registered type's fields as one nested object, absent when there are
    // none, so a built-in's file does not change by a byte.
    if (!cfg.extra.empty())
    {
        j += "    \"extra\": {";
        bool first = true;
        for (const auto& [k, v] : cfg.extra)
        {
            if (!first)
                j += ", ";
            first = false;
            j += "\"";
            socketley::json::escape_into(j, k);
            j += "\": \"";
            socketley::json::escape_into(j, v);
            j += "\"";
        }
        j += "},\n";
    }

    // Remove trailing comma+newline and close
    if (j.size() >= 2 && j[j.size()-2] == ',' && j[j.size()-1] == '\n')
    {
        j[j.size()-2] = '\n';
        j.pop_back();
    }
    j += "}\n";

    return j;
}

bool state_persistence::parse_json_string(const std::string& json, runtime_config& cfg,
                                          std::optional<runtime_type> assumed) const
{
    using namespace sp_detail;

    // Before any value is read, because every field has a default and `import`
    // cannot otherwise tell an omitted field from one set to it.
    cfg.present.clear();
    json_collect_keys(json, cfg.present);

    cfg.name = json_get_string(json, "name");
    cfg.id = json_get_string(json, "id");
    cfg.type_name = json_get_string(json, "type");
    cfg.type = cfg.type_name.empty() && assumed ? *assumed : str_to_type(cfg.type_name);
    cfg.port = static_cast<uint16_t>(json_get_int(json, "port"));
    {
        // The prefix is stripped here and stored bare, so nothing downstream
        // has to know that "listen" is a family plus an address.
        const std::string listen = json_get_string(json, "listen");
        if (listen.rfind("unix:", 0) == 0)
            cfg.listen_path = listen.substr(5);
    }
    cfg.bind_address = json_get_string(json, "bind");
    cfg.was_running = json_get_bool(json, "was_running");

    // Common
    cfg.log_file = json_get_string(json, "log_file");
    cfg.write_file = json_get_string(json, "write_file");
    cfg.lua_script = json_get_string(json, "lua_script");
    cfg.bash_output = json_get_bool(json, "bash_output");
    cfg.bash_prefix = json_get_bool(json, "bash_prefix");
    cfg.bash_timestamp = json_get_bool(json, "bash_timestamp");
    cfg.max_connections = json_get_uint32(json, "max_connections");
    cfg.rate_limit = json_get_double(json, "rate_limit");
    cfg.global_rate_limit = json_get_double(json, "global_rate_limit");
    cfg.idle_timeout = json_get_uint32(json, "idle_timeout");
    cfg.congestion = json_get_string(json, "congestion");
    cfg.write_buffer = json_get_size(json, "write_buffer");
    cfg.read_buffer  = json_get_size(json, "read_buffer");
    cfg.drain = json_get_bool(json, "drain");
    cfg.reconnect = json_get_int(json, "reconnect", -1);
    cfg.tls = json_get_bool(json, "tls");
    cfg.cert_path = json_get_string(json, "cert_path");
    cfg.key_path = json_get_string(json, "key_path");
    cfg.acme_domains = json_get_string(json, "acme_domains");
    cfg.acme_email = json_get_string(json, "acme_email");
    if (cfg.type != runtime_storage)
        cfg.domains = json_get_string(json, "domain");
    cfg.ca_path = json_get_string(json, "ca_path");
    cfg.target = json_get_string(json, "target");
    cfg.cache_name = json_get_string(json, "cache_name");
    cfg.group = json_get_string(json, "group");
    cfg.owner = json_get_string(json, "owner");
    cfg.child_policy = json_get_int(json, "child_policy");
    // Absent means one and not zero, because the field is omitted for every
    // runtime that did not ask for shards.
    if (const uint32_t s = json_get_uint32(json, "shards"); s > 0)
        cfg.shards = s;
    // Absent means shard 0, which is a real answer and not a missing one.
    cfg.shard_index = json_get_uint32(json, "shard_index");
    // Absent means no mesh, which is the answer for every runtime that is not
    // a shard set forked whole.
    cfg.mesh_wired = json_get_bool(json, "mesh_wired");
    cfg.companion_path = json_get_string(json, "companion_path");
    cfg.cpus = json_get_string(json, "cpus");
    cfg.external_runtime = json_get_bool(json, "external_runtime");
    cfg.managed = json_get_bool(json, "managed");
    cfg.exec_path = json_get_string(json, "exec_path");
    cfg.pid = static_cast<int32_t>(json_get_int(json, "pid"));

    // Type-specific
    switch (cfg.type)
    {
        case runtime_server:
            cfg.mode = str_to_server_mode(json_get_string(json, "mode"));
            cfg.send_to = str_to_server_send_to(json_get_string(json, "send_to"));
            cfg.udp = json_get_bool(json, "udp");
            cfg.master_pw = json_get_string(json, "master_pw");
            // A state file this daemon wrote before --send-to absorbed the flag
            // still says master_forward, and that is exactly one recipient.
            // Read and folded in, never written back, so an old configuration
            // survives the upgrade without anybody retyping it.
            if (json_get_bool(json, "master_forward"))
                cfg.send_to |= 4;
            cfg.http_dir = json_get_string(json, "http_dir");
            cfg.http_cache = json_get_bool(json, "http_cache");
            cfg.compress = json_get_bool(json, "compress");
            cfg.no_inject = json_get_bool(json, "no_inject");
            cfg.origins = json_get_string(json, "origins");
            cfg.upstreams = json_get_array(json, "upstreams");
            break;
        case runtime_client:
            cfg.mode = str_to_server_mode(json_get_string(json, "mode"));
            cfg.udp = json_get_bool(json, "udp");
            break;
        case runtime_proxy:
            cfg.protocol = str_to_proxy_protocol(json_get_string(json, "protocol"));
            cfg.strategy = str_to_proxy_strategy(json_get_string(json, "strategy"));
            cfg.backends = json_get_array(json, "backends");
            cfg.health_check = static_cast<uint8_t>(json_get_int(json, "health_check"));
            { auto v = json_get_int(json, "health_interval"); if (v > 0) cfg.health_interval = v; }
            { auto s = json_get_string(json, "health_path"); if (!s.empty()) cfg.health_path = s; }
            cfg.fcgi_root = json_get_string(json, "root");
            cfg.fcgi_remote_root = json_get_string(json, "fastcgi_root");
            cfg.fcgi_index = json_get_string(json, "index");
            cfg.compress = json_get_bool(json, "compress");
            cfg.proxy_auth = json_get_string(json, "auth");
            { auto v = json_get_int(json, "redirect_https"); if (v > 0 && v <= 65535) cfg.https_redirect = static_cast<uint16_t>(v); }
            { auto v = json_get_int(json, "health_threshold"); if (v > 0) cfg.health_threshold = v; }
            { auto v = json_get_int(json, "circuit_threshold"); if (v > 0) cfg.circuit_threshold = v; }
            { auto v = json_get_int(json, "circuit_timeout"); if (v > 0) cfg.circuit_timeout = v; }
            // 0 means "no deadline" and is written out like any other value, so
            // this one asks for the default on absence instead of rejecting 0.
            cfg.backend_timeout = json_get_int(json, "backend_timeout", 2);
            cfg.retry_count = json_get_int(json, "retry_count");
            cfg.retry_all = json_get_bool(json, "retry_all");
            cfg.mesh_client_ca = json_get_string(json, "mesh_client_ca");
            cfg.mesh_client_cert = json_get_string(json, "mesh_client_cert");
            cfg.mesh_client_key = json_get_string(json, "mesh_client_key");
            break;
        case runtime_cache:
            cfg.persistent_path = json_get_string(json, "persistent_path");
            { auto v = json_get_int(json, "persistent_interval");
              if (v > 0) cfg.persistent_interval = static_cast<uint32_t>(v); }
            cfg.cache_mode = str_to_cache_mode(json_get_string(json, "cache_mode"));
            cfg.resp_forced = json_get_bool(json, "resp_forced");
            cfg.cluster = json_get_bool(json, "cluster");
            cfg.replicate_target = json_get_string(json, "replicate_target");
            {
                const std::string inc = json_get_string(json, "cluster_replica");
                if (!inc.empty())
                    std::from_chars(inc.data(), inc.data() + inc.size(), cfg.cluster_replica);
            }
            cfg.max_memory = json_get_size(json, "max_memory");
            cfg.eviction = str_to_eviction(json_get_string(json, "eviction"));
            cfg.cache_public = json_get_bool(json, "public");
            break;
        case runtime_storage:
            cfg.storage_dir = json_get_string(json, "dir");
            cfg.storage_anonymous = json_get_bool(json, "anonymous");
            cfg.storage_idp = json_get_string(json, "idp");
            cfg.storage_acls = json_get_bool(json, "acls");
            cfg.storage_max_bytes = json_get_size(json, "max_bytes");
            cfg.storage_access_key = json_get_string(json, "access_key");
            cfg.storage_secret_key = json_get_string(json, "secret_key");
            cfg.storage_credentials = json_get_string(json, "credentials");
            cfg.storage_sse_key_file = json_get_string(json, "sse_key_file");
            cfg.storage_domain = json_get_string(json, "domain");
            cfg.storage_website_domain = json_get_string(json, "website_domain");
            cfg.storage_notify_targets = json_get_string(json, "notify_targets");
            cfg.storage_replication_targets = json_get_string(json, "replication_targets");
            cfg.storage_tiers = json_get_string(json, "tiers");
            cfg.storage_federation = json_get_string(json, "federation");
            cfg.storage_tls_offloaded = json_get_string(json, "tls_offloaded");
            cfg.storage_nodes = json_get_string(json, "nodes");
            cfg.storage_fsync = json_get_string(json, "fsync");
            cfg.storage_sync = json_get_string(json, "sync");
            cfg.storage_fsync_interval_secs = static_cast<uint32_t>(json_get_size(json, "fsync_interval"));
            cfg.storage_mpu_expire_secs = static_cast<uint32_t>(json_get_size(json, "mpu_expire"));
            cfg.storage_scrub_secs = static_cast<uint32_t>(json_get_size(json, "scrub"));
            cfg.storage_compress_secs = static_cast<uint32_t>(json_get_size(json, "compress"));
            break;
        case runtime_dns:
            cfg.dns_zones = json_get_string(json, "zones");
            cfg.dns_transfer = json_get_string(json, "transfer");
            cfg.dns_notify = json_get_string(json, "notify");
            cfg.dns_publish = json_get_string(json, "publish");
            cfg.dns_proxy = json_get_string(json, "proxy");
            cfg.dns_rrl = json_get_uint32(json, "rrl", 100);
            cfg.dns_dnssec = json_get_bool(json, "dnssec");
            break;
        case runtime_sync:
        {
            sync_mode m = sync_mode_out;
            parse_sync_runtime_mode(json_get_string(json, "mode"), m);
            cfg.mode = static_cast<uint8_t>(m);
            cfg.sync_dir = json_get_string(json, "dir");
            cfg.sync_storage = json_get_string(json, "storage");
            cfg.sync_prefix = json_get_string(json, "prefix");
            cfg.sync_credentials = json_get_string(json, "credentials");
            cfg.sync_exclude = json_get_string(json, "exclude");
            cfg.sync_repositories = json_get_string(json, "repositories");
            cfg.sync_every = json_get_uint32(json, "every", sync_default_every);
            break;
        }
        case runtime_idp:
            cfg.idp_clients = json_get_string(json, "clients");
            cfg.idp_issuer = json_get_string(json, "issuer");
            cfg.idp_cookie_domain = json_get_string(json, "cookie_domain");
            cfg.idp_resources = json_get_string(json, "resources");
            cfg.idp_ssh_ca_hours = json_get_uint32(json, "ssh_ca");
            break;
        case runtime_tunnel:
            cfg.tunnel_mode = json_get_string(json, "mode") == "agent" ? 1 : 0;
            cfg.tunnel_to = json_get_string(json, "to");
            cfg.tunnel_join = json_get_string(json, "join");
            cfg.tunnel_offers = json_get_string(json, "offer");
            cfg.tunnel_forward = json_get_string(json, "forward");
            cfg.tunnel_idp = json_get_string(json, "idp");
            cfg.tunnel_idp_audience = json_get_string(json, "idp_audience");
            break;
        case runtime_db:
            cfg.db_schema = json_get_string(json, "schema");
            cfg.db_keys = json_get_string(json, "keys");
            cfg.db_idp = json_get_string(json, "idp");
            cfg.db_idp_audience = json_get_string(json, "idp_audience");
            cfg.db_origins = json_get_string(json, "origins");
            cfg.db_max_bytes = json_get_size(json, "max_bytes");
            cfg.db_cache = json_get_size(json, "cache", 64ull << 20);
            cfg.db_replicate = json_get_string(json, "replicate");
            cfg.db_replicate_key = json_get_string(json, "replicate_key");
            cfg.db_backup_dir = json_get_string(json, "backup_dir");
            cfg.db_backup_every = json_get_uint32(json, "backup_every", 86400);
            cfg.db_backup_keep = json_get_uint32(json, "backup_keep", 7);
            break;
        case runtime_mcp:
            cfg.mcp_keys = json_get_string(json, "keys");
            cfg.mcp_anonymous = json_get_bool(json, "anonymous");
            cfg.mcp_origins = json_get_string(json, "origins");
            cfg.mcp_tools = json_get_string(json, "tools");
            if (cfg.mcp_tools.empty())
                cfg.mcp_tools = "none";
            cfg.mcp_instructions = json_get_string(json, "instructions");
            cfg.mcp_idp = json_get_string(json, "idp");
            cfg.mcp_idp_audience = json_get_string(json, "idp_audience");
            break;
        case runtime_metrics:
            cfg.metrics_keys = json_get_string(json, "keys");
            cfg.metrics_idp = json_get_string(json, "idp");
            cfg.metrics_idp_audience = json_get_string(json, "idp_audience");
            cfg.metrics_no_local = json_get_bool(json, "no_local");
            cfg.metrics_scrape = json_get_string(json, "scrape");
            cfg.metrics_archive = json_get_string(json, "archive");
            cfg.metrics_archive_credentials = json_get_string(json, "archive_credentials");
            cfg.metrics_every = json_get_uint32(json, "every", 10);
            cfg.metrics_keep = json_get_size(json, "keep", 30ull * 86400);
            cfg.metrics_downsample = json_get_string(json, "downsample");
            if (!json_has_key(json, "downsample"))
                cfg.metrics_downsample = "5m:1y,1h:5y";
            cfg.metrics_max_series = json_get_uint32(json, "max_series", 200000);
            cfg.metrics_durable = json_get_bool(json, "durable");
            cfg.metrics_logs = json_get_bool(json, "logs");
            cfg.metrics_logs_keep = json_get_size(json, "logs_keep", 14ull * 86400);
            cfg.metrics_rules = json_get_string(json, "rules");
            cfg.metrics_notify = json_get_string(json, "notify");
            cfg.metrics_receive = json_get_bool(json, "receive");
            break;
        case runtime_mqtt:
            cfg.mqtt_users = json_get_string(json, "users");
            cfg.mqtt_idp = json_get_string(json, "idp");
            cfg.mqtt_idp_audience = json_get_string(json, "idp_audience");
            cfg.mqtt_acl = json_get_string(json, "acl");
            cfg.mqtt_routes = json_get_string(json, "routes");
            cfg.mqtt_anonymous = json_get_bool(json, "anonymous");
            cfg.mqtt_ws_port = static_cast<uint16_t>(json_get_uint32(json, "ws_port"));
            cfg.mqtt_max_packet = json_get_uint32(json, "max_packet", 256u << 10);
            cfg.mqtt_session_expiry = json_get_uint32(json, "session_expiry", 86400);
            cfg.mqtt_session_queue = json_get_uint32(json, "session_queue", 1000);
            cfg.mqtt_retained_max = json_get_size(json, "retained_max", 64ull << 20);
            cfg.mqtt_max_sessions = json_get_uint32(json, "max_sessions", 100000);
            cfg.mqtt_keepalive_max = static_cast<uint16_t>(json_get_uint32(json, "keepalive_max", 1200));
            cfg.persistent_path = json_get_string(json, "persistent_path");
            cfg.persistent_interval = json_get_uint32(json, "persistent_interval", 1);
            break;
        case runtime_mail:
            cfg.mail_submission = static_cast<uint16_t>(json_get_uint32(json, "submission"));
            cfg.mail_submissions = static_cast<uint16_t>(json_get_uint32(json, "submissions"));
            cfg.mail_imap = static_cast<uint16_t>(json_get_uint32(json, "imap"));
            cfg.mail_imaps = static_cast<uint16_t>(json_get_uint32(json, "imaps"));
            cfg.mail_sieve = static_cast<uint16_t>(json_get_uint32(json, "sieve"));
            cfg.mail_dnsbl = json_get_string(json, "dnsbl");
            cfg.mail_pop3 = static_cast<uint16_t>(json_get_uint32(json, "pop3"));
            cfg.mail_pop3s = static_cast<uint16_t>(json_get_uint32(json, "pop3s"));
            cfg.mail_jmap = static_cast<uint16_t>(json_get_uint32(json, "jmap"));
            cfg.mail_web = static_cast<uint16_t>(json_get_uint32(json, "web"));
            cfg.mail_lmtp = static_cast<uint16_t>(json_get_uint32(json, "lmtp"));
            cfg.mail_sts_port = static_cast<uint16_t>(json_get_uint32(json, "mta_sts_port"));
            cfg.mail_greylist = json_get_uint32(json, "greylist", 0);
            cfg.mail_rspamd = json_get_string(json, "rspamd");
            if (json_has_key(json, "recipient_delimiter"))
                cfg.mail_delimiter = json_get_string(json, "recipient_delimiter");
            cfg.mail_reports = json_get_bool(json, "reports");
            cfg.mail_dmarc_rua = json_get_string(json, "dmarc_rua");
            if (json_has_key(json, "dmarc_policy"))
                cfg.mail_dmarc_policy = json_get_string(json, "dmarc_policy");
            cfg.mail_bimi = json_get_string(json, "bimi");
            if (json_has_key(json, "refuse_attachments"))
                cfg.mail_refused_attachments = json_get_string(json, "refuse_attachments");
            cfg.mail_clamav = json_get_string(json, "clamav");
            cfg.mail_tls_rpt = json_get_string(json, "tls_rpt");
            cfg.mail_mta_sts = json_get_string(json, "mta_sts");
            cfg.mail_default_quota = json_get_size(json, "default_quota", 0);
            cfg.mail_quota_warn = json_get_uint32(json, "quota_warn", 90);
            cfg.mail_arc_trust = json_get_string(json, "arc_trust");
            cfg.mail_dkim_next = json_get_string(json, "dkim_next");
            cfg.mail_dns = json_get_string(json, "dns");
            cfg.mail_domains = json_get_string(json, "mail_domain");
            cfg.mail_hostname = json_get_string(json, "hostname");
            cfg.mail_no_reply = json_get_bool(json, "no_reply");
            cfg.mail_idp = json_get_string(json, "idp");
            cfg.mail_idp_audience = json_get_string(json, "idp_audience");
            cfg.mail_storage = json_get_string(json, "storage");
            cfg.mail_users = json_get_string(json, "users");
            cfg.mail_relay = json_get_string(json, "relay");
            cfg.mail_aliases = json_get_string(json, "aliases");
            cfg.mail_notify = json_get_string(json, "notify_targets");
            cfg.mail_max_size = json_get_size(json, "max_size", 25ull << 20);
            cfg.mail_max_rcpt = json_get_uint32(json, "max_recipients", 100);
            cfg.mail_lifetime = json_get_uint32(json, "queue_lifetime", 5 * 86400);
            cfg.mail_autoexpunge = json_get_uint32(json, "autoexpunge", 0);
            if (json_has_key(json, "dkim_selector"))
                cfg.mail_selector = json_get_string(json, "dkim_selector");
            break;
    }

    json_get_extra(json, cfg.extra);

    return !cfg.name.empty();
}

// Every state file is written here, at a mode stated rather than inherited
// from the umask and made new rather than through a link -- because the record
// carries --master-pw, the TLS key paths and the --lua script the daemon runs,
// so whoever can write one chooses what the daemon runs next.
static bool write_state_file(const fs::path& path, std::string_view bytes)
{
    // Said out loud: both callers drop the bool, and a state directory that was
    // full or read-only once produced a daemon that served a runtime it would
    // never have heard of at the next start.
    std::string why;
    if (!socketley::replace_file(path.string(), bytes, socketley::durability::data_and_dir, &why))
    {
        LOG_ERROR(("state file " + path.string() + ": " + why +
                   " -- this runtime will not come back after a restart").c_str());
        return false;
    }
    return true;
}

bool state_persistence::write_json(const runtime_config& cfg) const
{
    // An empty path is config_path() refusing the name, reported because a
    // runtime whose state cannot be stored will not come back.
    const fs::path path = config_path(cfg.name);
    if (path.empty())
    {
        LOG_ERROR(("state: refusing to write a file for runtime \"" + cfg.name +
                   "\": the name cannot be part of a path").c_str());
        return false;
    }
    return write_state_file(path, format_json_pretty(cfg));
}

bool state_persistence::read_json(const fs::path& path, runtime_config& cfg) const
{
    std::ifstream f(path);
    if (!f.is_open())
        return false;

    std::ostringstream ss;
    ss << f.rdbuf();
    return parse_json_string(ss.str(), cfg);
}

void state_persistence::save_runtime(const runtime_instance* instance)
{
    // A cluster replica is placed by the log, so a state file would bring it back on a node that no longer owns it.
    if (instance->is_lua_created() || instance->is_cluster_owned())
        return;
    // Read off the instance here on the caller's thread, because a `create`
    // followed by a `remove` may have freed it before the writer runs.
    job j;
    j.k = job::write_cfg;
    j.cfg = read_from_instance(instance);
    enqueue(std::move(j));
}

void state_persistence::remove_runtime(std::string_view name)
{
    job j;
    j.k = job::remove_file;
    j.name = std::string(name);
    enqueue(std::move(j));
}

// ─── the writer ─────────────────────────────────────────────────────────────

void state_persistence::enqueue(job j)
{
    // No writer means no state directory, and config_path() would answer a
    // bare "name.json" for one -- a relative path into whatever directory the
    // daemon happens to be in.  Dropping is what a parser-only object already
    // meant; queueing was the accident.
    if (!m_writer.joinable())
        return;

    {
        std::lock_guard<std::mutex> lk(m_mx);
        m_queue.push_back(std::move(j));
        ++m_queued;                 // what drain() waits to see completed
    }
    m_cv.notify_one();
}

void state_persistence::writer_loop()
{
    for (;;)
    {
        job j;
        {
            std::unique_lock<std::mutex> lk(m_mx);
            m_cv.wait(lk, [&]{ return m_stop || !m_queue.empty(); });
            if (m_queue.empty())
                return;                     // stopping, and nothing left owed
            j = std::move(m_queue.front());
            m_queue.pop_front();
        }

        switch (j.k)
        {
            case job::write_cfg:    write_json(j.cfg); break;
            case job::remove_file:  { std::error_code ec;
                                      // An empty path removes nothing, which is
                                      // right: nothing was ever written for it.
                                      if (const fs::path p = config_path(j.name); !p.empty())
                                          fs::remove(p, ec); } break;
            case job::flip_running: flip_was_running(j.name, j.running); break;
        }

        {
            std::lock_guard<std::mutex> lk(m_mx);
            ++m_done;
        }
        m_cv.notify_all();
    }
}

void state_persistence::drain()
{
    // Waits for the work to be done and not merely picked up, on a target read
    // under the lock and fixed so jobs enqueued later cannot hold a caller
    // here indefinitely.
    std::unique_lock<std::mutex> lk(m_mx);
    const uint64_t target = m_queued;
    m_cv.wait(lk, [&]{ return m_done >= target; });
}

state_persistence::~state_persistence()
{
    socketley::stop_and_join(m_writer, m_mx, m_cv, m_stop);
}

std::string state_persistence::raw_field(const std::string& json,
                                         std::string_view key) const
{
    return sp_detail::json_get_string(json, key);
}

void state_persistence::set_was_running(std::string_view name, bool running)
{
    job j;
    j.k = job::flip_running;
    j.name = std::string(name);
    j.running = running;
    enqueue(std::move(j));
}

// The old body, now on the writer thread.  Unchanged apart from the name.
void state_persistence::flip_was_running(std::string_view name, bool running)
{
    fs::path path = config_path(name);
    if (path.empty())
        return;   // no file was ever written for this name; see config_path()

    // Fast path that flips the "was_running" literal in place, avoiding a full
    // parse and re-serialization for one boolean.
    std::ifstream f(path);
    if (!f.is_open())
        return;

    std::ostringstream ss;
    ss << f.rdbuf();
    f.close();
    std::string json = ss.str();

    // ─── THE VALUE IS FOUND, NOT COUNTED ────────────────────────────────────
    // Finds the value rather than counting to it, which also heals a record an
    // older build corrupted by replacing the whole alphabetic token after the
    // key.
    static constexpr std::string_view key = "\"was_running\":";
    const auto kpos = json.find(key);
    if (kpos == std::string::npos)
        return;   // no such field; nothing to flip

    size_t vpos = kpos + key.size();
    while (vpos < json.size() && (json[vpos] == ' ' || json[vpos] == '\t'))
        ++vpos;
    size_t vend = vpos;
    while (vend < json.size() &&
           ((json[vend] >= 'a' && json[vend] <= 'z') ||
            (json[vend] >= 'A' && json[vend] <= 'Z')))
        ++vend;

    const std::string_view cur = std::string_view(json).substr(vpos, vend - vpos);
    const std::string_view new_val = running ? "true" : "false";
    if (cur == new_val)
        return;   // already what it should be — no rewrite, no fsync

    if (cur == "true" || cur == "false")
    {
        json.replace(vpos, vend - vpos, new_val);
    }
    else
    {
        // A damaged record is parsed and written out whole rather than
        // patched, because the comma an off-by-one ate is load-bearing to
        // json_get_string.
        runtime_config cfg;
        if (!parse_json_string(json, cfg))
            return;
        cfg.was_running = running;
        json = format_json_pretty(cfg);
    }

    // Through the same writer as write_json, because this path rewrites the
    // whole record on every start and stop and an ofstream here would hand the
    // mode back to the umask.
    if (!write_state_file(path, json)) {}
}

// ─── THE FILES THAT WERE ALREADY THERE ──────────────────────────────────────
// The daemon narrows the state files it finds, once, at startup -- files only
// and never the directory, which is a deployment decision -- and every
// decision is made on a descriptor opened O_NOFOLLOW|O_NONBLOCK rather than on
// the path, which both stat() and chmod() would follow.
static size_t tighten_dir_files(const fs::path& dir, size_t& symlinks)
{
    size_t fixed = 0;
    std::error_code ec;
    symlinks = 0;

    for (const auto& entry : fs::directory_iterator(dir, ec))
    {
        const fs::path ext = entry.path().extension();
        if (ext != ".json" && ext != ".tmp")
            continue;

        const int fd = ::open(entry.path().c_str(),
                              O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0)
        {
            if (errno == ELOOP)
                ++symlinks;
            continue;
        }

        struct stat st{};
        if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
            (st.st_mode & 0077) == 0)
        {
            ::close(fd);
            continue;                       // not ours to touch, or already 0600
        }

        if (::fchmod(fd, 0600) == 0)
            ++fixed;
        ::close(fd);
    }

    return fixed;
}

size_t state_persistence::tighten_existing() const
{
    size_t symlinks = 0;
    const size_t fixed = tighten_dir_files(m_state_dir, symlinks);

    if (symlinks > 0)
        LOG_WARN(("state: " + std::to_string(symlinks) +
                  " symlink(s) in " + m_state_dir.string() +
                  " were left alone — socketley does not create them, and "
                  "following one would change the mode of whatever it points "
                  "at").c_str());

    return fixed;
}

std::vector<runtime_config> state_persistence::load_all()
{
    // Everything asked for before this call has to be visible to it, and
    // blocking here is free because load_all() never runs on the event loop
    // thread.
    drain();

    // Before anything is read out of them, and said out loud when it does
    // something, because an operator who sees it twice knows something is
    // putting the modes back.
    if (const size_t fixed = tighten_existing(); fixed > 0)
        LOG_INFO(("state: tightened " + std::to_string(fixed) +
                  " file(s) in " + m_state_dir.string() +
                  " to 0600 — they carry master passwords and key paths and "
                  "were readable by other users on this machine").c_str());

    std::vector<runtime_config> configs;

    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(m_state_dir, ec))
    {
        if (!entry.is_regular_file())
            continue;
        if (entry.path().extension() != ".json")
            continue;

        runtime_config cfg;
        if (read_json(entry.path(), cfg))
            configs.push_back(std::move(cfg));
    }

    return configs;
}
