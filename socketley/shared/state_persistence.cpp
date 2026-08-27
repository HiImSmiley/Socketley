#include "state_persistence.h"
#include "runtime_instance.h"
#include "../runtime/server/server_instance.h"
#include "../runtime/client/client_instance.h"
#include "../runtime/proxy/proxy_instance.h"
#include "../runtime/cache/cache_instance.h"
#include "../cli/command_hashing.h"

#include "logging.h"

#include <fstream>
#include <sstream>
#include <charconv>
#include <cerrno>
#include <cstdio>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

namespace fs = std::filesystem;

// ─── Minimal JSON helpers ───

namespace sp_detail {

std::string json_escape(std::string_view s)
{
    std::string out;
    out.reserve(s.size() + 4);
    for (char c : s)
    {
        switch (c)
        {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                // Everything below 0x20 has to go as \u00xx or the document is
                // not JSON.  Three of them were named above and the other
                // twenty-six were emitted raw — reachable through any path
                // field, which is operator text nothing validates.  The Lua
                // encoder in lua_context.cpp has had this for longer.
                if (static_cast<unsigned char>(c) < 0x20)
                {
                    char hex[8];
                    std::snprintf(hex, sizeof(hex), "\\u%04x",
                                  static_cast<unsigned>(static_cast<unsigned char>(c)));
                    out += hex;
                }
                else
                    out += c;
                break;
        }
    }
    return out;
}

void json_escape_into(std::string& out, std::string_view s)
{
    for (char c : s)
    {
        switch (c)
        {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                // Everything below 0x20 has to go as \u00xx or the document is
                // not JSON.  Three of them were named above and the other
                // twenty-six were emitted raw — reachable through any path
                // field, which is operator text nothing validates.  The Lua
                // encoder in lua_context.cpp has had this for longer.
                if (static_cast<unsigned char>(c) < 0x20)
                {
                    char hex[8];
                    std::snprintf(hex, sizeof(hex), "\\u%04x",
                                  static_cast<unsigned>(static_cast<unsigned char>(c)));
                    out += hex;
                }
                else
                    out += c;
                break;
        }
    }
}

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
                case 'n':  out += '\n'; break;
                case 'r':  out += '\r'; break;
                case 't':  out += '\t'; break;
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

const char* type_str(runtime_type t)
{
    switch (t)
    {
        case runtime_server: return "server";
        case runtime_client: return "client";
        case runtime_proxy:  return "proxy";
        case runtime_cache:  return "cache";
        default:             return "unknown";
    }
}

runtime_type str_to_type(std::string_view s)
{
    switch (fnv1a(s))
    {
        case fnv1a("server"): return runtime_server;
        case fnv1a("client"): return runtime_client;
        case fnv1a("proxy"):  return runtime_proxy;
        case fnv1a("cache"):  return runtime_cache;
        default:              return runtime_server;
    }
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

// Is this key named anywhere in the document.
//
// The same scan as json_get_string below, stopping at the question it is asked
// rather than going on to read a value — because "the key is there" and "the
// value is non-empty" are different things, and `import` needs the first to
// tell a field that was set to its default from one that was left out.
//
// Deliberately a second walk rather than a flag threaded through the getters:
// the getters are called forty times from one function and each one already
// walks the document, so a second walk per key is the same order of work and
// keeps both functions doing one thing.
bool json_has_key(const std::string& json, std::string_view key)
{
    size_t pos = 0;
    while (pos < json.size())
    {
        pos = json.find('"', pos);
        if (pos == std::string::npos) break;

        if (pos + 1 + key.size() + 1 <= json.size() &&
            json.compare(pos + 1, key.size(), key.data(), key.size()) == 0 &&
            json[pos + 1 + key.size()] == '"')
        {
            // A key is followed by a colon.  Without this check the scan also
            // matches a VALUE that happens to read like a key name — `"mode":
            // "port"` would answer yes to "port".
            const size_t after = pos + 1 + key.size() + 1;
            const size_t colon = json.find_first_not_of(" \t\n\r", after);
            if (colon != std::string::npos && json[colon] == ':')
                return true;
        }
        pos++;
    }
    return false;
}

// Every key the document names, collected in one walk.
//
// Enumerated rather than asked field by field, because parse_json_string reads
// sixty-one of them: a hand-written list is a list that goes stale the first
// time somebody adds a field, and the failure mode would be that the new field
// is silently cleared by every partial import — which is the defect this is
// being added to fix.
//
// A key is a quoted token followed by a colon.  That is enough for this schema:
// it is flat apart from arrays of plain strings, and an array element is
// followed by a comma or a bracket, never a colon.
void json_collect_keys(const std::string& json, std::set<std::string, std::less<>>& out)
{
    size_t pos = 0;
    while (pos < json.size())
    {
        pos = json.find('"', pos);
        if (pos == std::string::npos) break;

        size_t end = pos + 1;
        while (end < json.size() && json[end] != '"')
        {
            if (json[end] == '\\' && end + 1 < json.size()) ++end;   // \" is not the end
            ++end;
        }
        if (end >= json.size()) break;

        const size_t after = json.find_first_not_of(" \t\n\r", end + 1);
        if (after != std::string::npos && json[after] == ':')
            out.insert(json.substr(pos + 1, end - pos - 1));

        // Past this token whether it was a key or a value, so a value is never
        // examined as if it were a key of its own.
        pos = end + 1;
    }
}

// Simple JSON value parser: extract string value for a key from JSON text
std::string json_get_string(const std::string& json, std::string_view key)
{
    // Search for "key" pattern without allocating a needle string
    size_t pos = 0;
    while (pos < json.size())
    {
        pos = json.find('"', pos);
        if (pos == std::string::npos) break;

        // Check if this quoted string matches the key
        if (pos + 1 + key.size() + 1 <= json.size() &&
            json.compare(pos + 1, key.size(), key.data(), key.size()) == 0 &&
            json[pos + 1 + key.size()] == '"')
        {
            // Found the key — skip past closing quote
            size_t after_key = pos + 1 + key.size() + 1;

            size_t colon = json.find(':', after_key);
            if (colon == std::string::npos) break;

            // Skip whitespace
            size_t vpos = json.find_first_not_of(" \t\n\r", colon + 1);
            if (vpos == std::string::npos) break;

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
        pos++;
    }
    return {};
}

bool json_get_bool(const std::string& json, std::string_view key, bool default_val = false)
{
    std::string v = json_get_string(json, key);
    if (v == "true")  return true;
    if (v == "false") return false;
    return default_val;
}

// ─── A VALUE THAT IS ONLY PARTLY A NUMBER IS NOT A NUMBER ───────────────────
//
// The four below all wrapped a std::sto* in a try/catch and returned the
// default when it threw — which covered "abc" and did nothing at all for
// "80abc", because stoi stops at the first character it cannot use and returns
// what it read.  A field whose value had a typo in the tail was silently taken
// as the digits in front of it:
//
//     "port": "80abc"          ->  80
//     "max_memory": "4mb"      ->  4
//
// The same defect the flag parsers had, one layer in.  parse_uint16 and
// parse_uint32 in flag_handlers.h are the shape this follows: the whole of the
// token, or nothing.
//
// "Or nothing" means the default, which is what an ABSENT key already gives —
// so a malformed value now behaves exactly like a missing one, and that is the
// point.  It is also no change at all for a value that will not parse in any
// part: `stoi("abc")` already threw and already fell back here.  What changes is
// only the half-parsed case, and there the default is the honest answer.
//
// These read files this daemon wrote, so in practice the input is clean.  They
// also read whatever `import` was handed, which is a document a person edited.
template <typename T, typename Fn>
T json_get_number(const std::string& json, std::string_view key, T default_val, Fn convert)
{
    std::string v = json_get_string(json, key);
    if (v.empty()) return default_val;
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
        [](const std::string& s, size_t& n) { return static_cast<uint32_t>(std::stoul(s, &n)); });
}

double json_get_double(const std::string& json, std::string_view key, double default_val = 0.0)
{
    return json_get_number<double>(json, key, default_val,
        [](const std::string& s, size_t& n) { return std::stod(s, &n); });
}

size_t json_get_size(const std::string& json, std::string_view key, size_t default_val = 0)
{
    return json_get_number<size_t>(json, key, default_val,
        [](const std::string& s, size_t& n) { return static_cast<size_t>(std::stoull(s, &n)); });
}

std::vector<std::string> json_get_array(const std::string& json, std::string_view key)
{
    std::vector<std::string> result;

    // Search for "key" pattern without allocating a needle string
    size_t pos = 0;
    bool found = false;
    while (pos < json.size())
    {
        pos = json.find('"', pos);
        if (pos == std::string::npos) return result;
        if (pos + 1 + key.size() + 1 <= json.size() &&
            json.compare(pos + 1, key.size(), key.data(), key.size()) == 0 &&
            json[pos + 1 + key.size()] == '"')
        {
            pos = pos + 1 + key.size() + 1;
            found = true;
            break;
        }
        pos++;
    }
    if (!found) return result;

    pos = json.find('[', pos);
    if (pos == std::string::npos) return result;
    ++pos;

    size_t end = json.find(']', pos);
    if (end == std::string::npos) return result;

    std::string arr = json.substr(pos, end - pos);
    size_t i = 0;
    while (i < arr.size())
    {
        i = arr.find('"', i);
        if (i == std::string::npos) break;
        ++i;
        std::string val;
        while (i < arr.size() && arr[i] != '"')
        {
            if (arr[i] == '\\' && i + 1 < arr.size())
            {
                val += arr[i];
                val += arr[i + 1];
                i += 2;
            }
            else
            {
                val += arr[i];
                ++i;
            }
        }
        if (i < arr.size()) ++i; // skip closing quote
        result.push_back(json_unescape(val));
    }

    return result;
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
    m_writer = std::thread(&state_persistence::writer_loop, this);
}

// Where this runtime's state file goes, or an empty path if it may not have one.
//
// ─── A SHARED BIN IS NOT A REFUSAL ──────────────────────────────────────────
//
// The traversal guard was here and it worked — but it answered by routing every
// rejected name to one `invalid.json`, so two runtimes with unusable names
// overwrote each other's state.  Measured: a daemon holding `q"uote/../x` and
// `second/../bad` had one file, with the second name in it, and the first
// runtime did not come back after a restart.  Nothing said so.
//
// Names are validated at both doors now — create() and rename() share
// runtime_manager::valid_name() — so nothing that reaches this function should
// fail it.  It stays as the second line, because it guards the filesystem and a
// state directory can hold files an older daemon wrote.  What changes is the
// answer: an empty path, which every caller reports rather than silently
// sharing one file.
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
    cfg.drain = instance->get_drain();
    cfg.reconnect = instance->get_reconnect();
    cfg.tls = instance->get_tls();
    cfg.cert_path = instance->get_cert_path();
    cfg.key_path = instance->get_key_path();
    cfg.ca_path = instance->get_ca_path();
    cfg.target = instance->get_target();
    cfg.listen_path = instance->get_listen_path();
    cfg.cache_name = instance->get_cache_name();
    cfg.group = instance->get_group();
    cfg.owner = instance->get_owner();
    cfg.child_policy = (instance->get_child_policy() == runtime_instance::child_policy::remove) ? 1 : 0;
    cfg.out_of_process = instance->is_out_of_process();
    cfg.shards = instance->get_shards();
    // Only a request that was actually made is written.  Storing the default
    // value of a flag nobody typed would turn every plain `create` into an
    // explicit --no-sqpoll on the next restart, and a runtime that asked for
    // nothing would start being refused by a daemon whose ring carries a poller.
    if (instance->has_cpus_request())
        cfg.cpus = instance->get_cpus().to_string();
    cfg.sqpoll_set = instance->has_sqpoll_request();
    cfg.sqpoll = instance->get_sqpoll();
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
            cfg.udp = srv->is_udp();
            cfg.master_pw = std::string(srv->get_master_pw());
            cfg.master_forward = srv->get_master_forward();
            cfg.http_dir = srv->get_http_dir().string();
            cfg.http_cache = srv->get_http_cache();
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
            cfg.health_threshold = mesh.health_threshold;
            cfg.circuit_threshold = mesh.circuit_threshold;
            cfg.circuit_timeout = mesh.circuit_timeout;
            cfg.backend_timeout = mesh.backend_timeout;
            cfg.retry_count = mesh.retry_count;
            cfg.retry_all = mesh.retry_all;
            cfg.mesh_client_ca = mesh.client_ca;
            cfg.mesh_client_cert = mesh.client_cert;
            cfg.mesh_client_key = mesh.client_key;
            break;
        }
        case runtime_cache:
        {
            auto* cache = static_cast<const cache_instance*>(instance);
            cfg.persistent_path = cache->get_persistent();
            cfg.cache_mode = static_cast<uint8_t>(cache->get_mode());
            cfg.resp_forced = cache->get_resp_forced();
            cfg.cluster = cache->get_cluster();
            cfg.replicate_target = cache->get_replicate_target();
            cfg.max_memory = cache->get_max_memory();
            cfg.eviction = static_cast<uint8_t>(cache->get_eviction());
            break;
        }
    }

    return cfg;
}

std::string state_persistence::format_json_pretty(const runtime_config& cfg) const
{
    using namespace sp_detail;

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
        json_escape_into(j, val);
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
        // Use snprintf for doubles to match ostringstream default formatting
        char buf[64];
        int n = snprintf(buf, sizeof(buf), "%g", val);
        j += "    \"";
        j += key;
        j += "\": ";
        j.append(buf, static_cast<size_t>(n));
        j += ",\n";
    };

    j += "{\n";
    append_str_field("name", cfg.name);
    append_str_field("id", cfg.id);
    append_str_field("type", type_str(cfg.type));
    append_int_field("port", cfg.port);
    // Written only when there is one, so every state file that ever existed
    // reads back as the TCP listener it is.  The `unix:` prefix stays on it:
    // this is the field an operator edits and re-imports, and it has to say
    // the same thing the flag said.
    if (!cfg.listen_path.empty())
        append_str_field("listen", "unix:" + cfg.listen_path);
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
    if (cfg.out_of_process)
        append_bool_field("out_of_process", true);
    // Written only when it is not the default, on the rule this function states
    // above: a `create` nobody typed --shards on must not start producing a
    // state file that differs from the one the previous build wrote for it.
    if (cfg.shards > 1)
        append_int_field("shards", static_cast<int>(cfg.shards));
    // Above zero only, and that is not merely tidiness: read_from_instance()
    // describes the daemon's placeholder, which is not any shard and reads 0,
    // so a state file never gains this key.  Shard 0's own config frame does
    // not carry it either and does not need to — absent parses as 0, which is
    // what shard 0 is.
    if (cfg.shard_index > 0)
        append_int_field("shard_index", static_cast<int>(cfg.shard_index));
    if (!cfg.cpus.empty())
        append_str_field("cpus", cfg.cpus);
    // Written for both values and omitted only when nothing was asked for, so
    // that absence and `false` stay distinguishable in the file itself.  Every
    // other boolean here is written only when true, which is fine for a flag
    // whose absence and whose false mean the same thing; this one's do not.
    if (cfg.sqpoll_set)
        append_bool_field("sqpoll", cfg.sqpoll);
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
            if (cfg.udp)
                append_bool_field("udp", true);
            if (!cfg.master_pw.empty())
                append_str_field("master_pw", cfg.master_pw);
            if (cfg.master_forward)
                append_bool_field("master_forward", true);
            if (!cfg.http_dir.empty())
                append_str_field("http_dir", cfg.http_dir);
            if (cfg.http_cache)
                append_bool_field("http_cache", true);
            if (!cfg.upstreams.empty())
            {
                j += "    \"upstreams\": [";
                for (size_t i = 0; i < cfg.upstreams.size(); ++i)
                {
                    if (i > 0) j += ", ";
                    j += "\"";
                    json_escape_into(j, cfg.upstreams[i]);
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
                    json_escape_into(j, cfg.backends[i]);
                    j += "\"";
                }
                j += "],\n";
            }
            if (cfg.health_check > 0)
                append_int_field("health_check", static_cast<int>(cfg.health_check));
            if (cfg.health_interval != 5)
                append_int_field("health_interval", cfg.health_interval);
            if (!cfg.health_path.empty() && cfg.health_path != "/health")
                append_str_field("health_path", cfg.health_path);
            if (cfg.health_threshold != 3)
                append_int_field("health_threshold", cfg.health_threshold);
            if (cfg.circuit_threshold != 5)
                append_int_field("circuit_threshold", cfg.circuit_threshold);
            if (cfg.circuit_timeout != 30)
                append_int_field("circuit_timeout", cfg.circuit_timeout);
            if (cfg.backend_timeout != 2)
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
            append_str_field("cache_mode", cache_mode_str(cfg.cache_mode));
            if (cfg.resp_forced)
                append_bool_field("resp_forced", true);
            if (cfg.cluster)
                append_bool_field("cluster", true);
            if (!cfg.replicate_target.empty())
                append_str_field("replicate_target", cfg.replicate_target);
            if (cfg.max_memory > 0)
                append_int_field("max_memory", cfg.max_memory);
            append_str_field("eviction", eviction_str(cfg.eviction));
            break;
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

bool state_persistence::parse_json_string(const std::string& json, runtime_config& cfg) const
{
    using namespace sp_detail;

    // Before any value is read: which keys the document actually names.  Every
    // field below has a default, so without this a document that omitted a
    // field was indistinguishable from one that set it to that default — and
    // `import` applied all of them either way.  See runtime_config::present.
    cfg.present.clear();
    json_collect_keys(json, cfg.present);

    cfg.name = json_get_string(json, "name");
    cfg.id = json_get_string(json, "id");
    cfg.type = str_to_type(json_get_string(json, "type"));
    cfg.port = static_cast<uint16_t>(json_get_int(json, "port"));
    {
        // The prefix is stripped here and stored bare, so nothing downstream
        // has to know that "listen" is a family plus an address rather than an
        // address.  A value without it is refused by the flag reader and by
        // import alike; accepting it here would let a document say
        // `"listen": "/run/x.sock"` and mean something the flag cannot.
        const std::string listen = json_get_string(json, "listen");
        if (listen.rfind("unix:", 0) == 0)
            cfg.listen_path = listen.substr(5);
    }
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
    cfg.drain = json_get_bool(json, "drain");
    cfg.reconnect = json_get_int(json, "reconnect", -1);
    cfg.tls = json_get_bool(json, "tls");
    cfg.cert_path = json_get_string(json, "cert_path");
    cfg.key_path = json_get_string(json, "key_path");
    cfg.ca_path = json_get_string(json, "ca_path");
    cfg.target = json_get_string(json, "target");
    cfg.cache_name = json_get_string(json, "cache_name");
    cfg.group = json_get_string(json, "group");
    cfg.owner = json_get_string(json, "owner");
    cfg.child_policy = json_get_int(json, "child_policy");
    cfg.out_of_process = json_get_bool(json, "out_of_process");
    // Absent means one, not zero: the field is omitted for every runtime that
    // did not ask for shards, which is every runtime written by a build older
    // than this one.  Reading a missing key as zero would restore them all with
    // no worker at all.
    if (const uint32_t s = json_get_uint32(json, "shards"); s > 0)
        cfg.shards = s;
    // Absent means shard 0, which is a real answer and not a missing one.  See
    // the note on runtime_config::shard_index.
    cfg.shard_index = json_get_uint32(json, "shard_index");
    cfg.cpus = json_get_string(json, "cpus");
    // Read through json_get_string rather than json_get_bool: the question here
    // is whether the key is there at all, and json_get_bool answers false to
    // both "absent" and "false".  Anything that is neither spelling reads as no
    // request, which is what a file hand-edited into nonsense should get.
    {
        const std::string v = json_get_string(json, "sqpoll");
        cfg.sqpoll_set = (v == "true" || v == "false");
        cfg.sqpoll = (v == "true");
    }
    cfg.external_runtime = json_get_bool(json, "external_runtime");
    cfg.managed = json_get_bool(json, "managed");
    cfg.exec_path = json_get_string(json, "exec_path");
    cfg.pid = static_cast<int32_t>(json_get_int(json, "pid"));

    // Type-specific
    switch (cfg.type)
    {
        case runtime_server:
            cfg.mode = str_to_server_mode(json_get_string(json, "mode"));
            cfg.udp = json_get_bool(json, "udp");
            cfg.master_pw = json_get_string(json, "master_pw");
            cfg.master_forward = json_get_bool(json, "master_forward");
            cfg.http_dir = json_get_string(json, "http_dir");
            cfg.http_cache = json_get_bool(json, "http_cache");
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
            cfg.cache_mode = str_to_cache_mode(json_get_string(json, "cache_mode"));
            cfg.resp_forced = json_get_bool(json, "resp_forced");
            cfg.cluster = json_get_bool(json, "cluster");
            cfg.replicate_target = json_get_string(json, "replicate_target");
            cfg.max_memory = json_get_size(json, "max_memory");
            cfg.eviction = str_to_eviction(json_get_string(json, "eviction"));
            break;
    }

    return !cfg.name.empty();
}

// ─── EVERY STATE FILE IS WRITTEN HERE, AND NOWHERE ELSE KNOWS HOW ───────────
//
// A state file is not a note about a runtime, it is the runtime.  The record
// carries a server's --master-pw verbatim, the paths of the TLS and mTLS
// private keys, and the --lua script the daemon runs with its own privileges;
// and the daemon restores every runtime from these files at startup, so
// whoever can write one chooses what the daemon runs next time it comes up.
//
// Both writers used std::ofstream, which creates with 0666 & ~umask.  That is
// not a mode, it is whatever the daemon inherited.  Measured on the parent
// commit, packaged shape — daemon as `socketley`, /var/lib/socketley/runtimes
// at 0755 as packaging/install.sh creates it:
//
//     daemon's umask 002    state file 0664   uid nobody read master_pw
//     daemon's umask 022    state file 0644   uid nobody read master_pw
//     daemon's umask 0      state file 0666   uid nobody REWROTE the record
//
// The third line is the one that matters.  Disclosure of a password is bad;
// a world-writable file that the daemon reads back as a runtime definition is
// the same privilege escalation that the IPC socket's 0666 was — the socket
// was closed in 8e4cff7 and this is the same door in the filesystem.
//
// So the mode is stated, not inherited, and it is stated at creation rather
// than fixed afterwards.  A chmod after the write has a window that is
// genuinely reachable here: unlike the daemon's listening socket, which
// refuses connect() until listen(), a file is readable the instant it exists,
// and the content is written into it before any chmod could run.  A umask
// around the write would work and was rejected for the same reason it was
// rejected for the socket, only more so: umask is process-wide and this code
// runs on state_persistence's own writer thread, so the narrow window would
// apply to whatever any other thread created inside it.
//
// O_EXCL on a path that was just unlinked is what makes 0600 a guarantee.
// O_CREAT does not touch the mode of a file that already exists, and the .tmp
// name is deterministic per runtime, so a leftover from a killed daemon would
// otherwise donate its old mode to every write that followed it.
static bool write_state_file(const fs::path& path, std::string_view bytes)
{
    fs::path tmp_path = path;
    tmp_path += ".tmp";

    std::error_code ec;
    fs::remove(tmp_path, ec);

    int fd = ::open(tmp_path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0)
        return false;

    size_t off = 0;
    while (off < bytes.size())
    {
        ssize_t n = ::write(fd, bytes.data() + off, bytes.size() - off);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
        {
            ::close(fd);
            fs::remove(tmp_path, ec);
            return false;
        }
        off += static_cast<size_t>(n);
    }

    // fsync before rename to guarantee data is on disk — prevents
    // partial/empty state files on power loss or kernel crash.
    //
    // Its failure is ignored, exactly as it was before this function existed.
    // That is a durability question and this change is about the mode; turning
    // a spurious fsync error into a failed save would be a different decision
    // wearing this one's clothes.  It is now the descriptor that wrote the
    // file rather than a second open() of the same path, which is one fewer
    // moment in which the path could have become something else.
    if (::fsync(fd) < 0) {}

    // Checked, where the fsync is not: close is where a deferred write error
    // surfaces, and it stands in for the f.fail() the ofstream form tested.
    if (::close(fd) < 0)
    {
        fs::remove(tmp_path, ec);
        return false;
    }

    fs::rename(tmp_path, path, ec);
    if (ec)
    {
        fs::remove(tmp_path, ec);
        return false;
    }
    return true;
}

bool state_persistence::write_json(const runtime_config& cfg) const
{
    // An empty path is config_path() refusing the name — see there.  Reported
    // rather than written somewhere shared: a runtime whose state cannot be
    // stored is a runtime that will not come back, and that is worth a line.
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
    if (instance->is_lua_created())
        return;
    // Read off the instance HERE, on the caller's thread.  The writer must not
    // touch a runtime_instance: by the time it runs, a `create` followed by a
    // `remove` may already have freed it.  A runtime_config is a value and
    // survives the crossing.
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
    // Waits for the work to be DONE, not for it to have been picked up.
    //
    // This waited on m_queue.empty(), which the writer satisfies the moment it
    // pops a job — before write, before fsync, before the rename that publishes
    // the file.  So drain() returned while the state directory still did not
    // contain what had been saved, which is the one thing a caller can want from
    // it: `save_runtime(x); drain(); load_all()` came back without x about one
    // time in ten, and read as a persistence bug rather than as a wait that did
    // not wait.  m_done has been sitting here for this, with a comment saying so.
    //
    // The target is read under the lock and fixed: jobs enqueued after this call
    // are somebody else's to wait for, and including them would let a busy
    // daemon hold a caller here indefinitely.
    std::unique_lock<std::mutex> lk(m_mx);
    const uint64_t target = m_queued;
    m_cv.wait(lk, [&]{ return m_done >= target; });
}

state_persistence::~state_persistence()
{
    {
        std::lock_guard<std::mutex> lk(m_mx);
        m_stop = true;
    }
    m_cv.notify_all();
    if (m_writer.joinable())
        m_writer.join();
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

    // Fast path: read file, find "was_running" key, flip in-place, atomic rewrite.
    // Avoids full JSON parse + re-serialization for a single boolean toggle.
    std::ifstream f(path);
    if (!f.is_open())
        return;

    std::ostringstream ss;
    ss << f.rdbuf();
    f.close();
    std::string json = ss.str();

    // ─── THE VALUE IS FOUND, NOT COUNTED ────────────────────────────────────
    //
    // This searched for `"was_running": <old>` and then wrote the new literal
    // at `pos + 16`.  `"was_running": ` is FIFTEEN characters, so every flip
    // landed one byte into the value and one byte past its end:
    //
    //     "was_running": true,    ->    "was_running": tfalse
    //     "was_running": false,   ->    "was_running": ftrue
    //
    // — the first character of the old value kept, the trailing comma eaten.
    // And it was self-sealing: the next flip searched for `": true` or
    // `": false`, found neither in `tfalse`, and returned having changed
    // nothing.  So one `stop` corrupted the field permanently and every later
    // start and stop was a silent no-op on it.
    //
    // What that cost is the whole was_running feature, which the man page
    // states as "Runtimes that were running when the daemon last stopped are
    // auto-started".  Measured on a plain TCP server with nothing unusual about
    // it: create -s, stop, start, restart the daemon — and `ls` reports
    // Created.  Any runtime ever stopped once stopped coming back, for the rest
    // of that install, with nothing anywhere saying so.  Reproduced on `main`,
    // which has the same line.
    //
    // Rewritten to find the value rather than to count to it, which also heals
    // a record an older build corrupted: the whole alphabetic token after the
    // key is replaced, so `tfalse` and `ftrue` become the literal they should
    // have been.  The comma that flip ate does not come back here — this
    // parser looks up keys by name and does not need one — and the next full
    // write of the record restores it.
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
        // A record an older build damaged.  Patching the value alone is not
        // enough to recover one: the comma the off-by-one ate is load-bearing,
        // because json_get_string reads a non-string value up to the next `,`,
        // `]` or `}` — so `"was_running": true` with no comma is read as
        // `true\n    "out_of_process": true`, which is not "true", and the
        // whole field silently reverts to its default of false.  Every
        // auto-restart stayed broken with the value looking right in the file.
        //
        // So a damaged record is parsed and written out whole rather than
        // patched.  It costs a full serialization exactly once per damaged
        // file: the record that comes out of it takes the fast path from then
        // on.  Every other field survives the damage, because each of them
        // still has the comma that ends it.
        runtime_config cfg;
        if (!parse_json_string(json, cfg))
            return;
        cfg.was_running = running;
        json = format_json_pretty(cfg);
    }

    // Through the same writer as write_json, and that is the point rather than
    // tidiness.  This path rewrites the whole record — master_pw and all — on
    // every start and every stop, so an ofstream here would have handed the
    // mode back to the umask the first time a runtime was started, and a fix
    // that only covered write_json would have looked correct on a fresh
    // `create` and quietly undone itself on the next `start`.
    if (!write_state_file(path, json)) {}
}

// ─── THE FILES THAT WERE ALREADY THERE ──────────────────────────────────────
//
// Writing new files at 0600 does nothing for an install that already has a
// directory full of 0644 ones, and those are the files with the passwords in
// them.  Nor does the problem age out on its own: a record is rewritten only
// when its runtime changes, so a server created once and left running keeps
// the mode it was born with for as long as the install lasts, and nothing
// anywhere tells the operator to look.
//
// So the daemon repairs what it finds, once, when it takes ownership of the
// directory at startup.  It only ever narrows — a file that is already
// owner-only is not touched — it is idempotent, and it costs one stat per
// runtime on a path that already walks every one of them.
//
// FILES ONLY, NOT THE DIRECTORY.  The mode on the files is what protects the
// contents; the mode on the directory is a deployment decision, set by
// packaging/install.sh and the deb postinst to 0750, and a daemon that
// silently renarrowed a directory an operator had widened on purpose would be
// changing a configuration it was not asked about.  The files it owns
// outright.
//
// .tmp is included because a daemon killed mid-write leaves one, with the same
// record and the same password in it, under a name nothing else cleans up
// until that runtime is next written.
// ─── THROUGH A DESCRIPTOR, NEVER THROUGH THE PATH ───────────────────────────
//
// This began as stat() then chmod() on entry.path(), and both follow symlinks.
// A name in this directory pointing at /etc/shadow would have been a chmod of
// /etc/shadow, and the daemon runs as root under `sudo socketley daemon`.
//
// It was not exploitable as written, because the same change puts the packaged
// state directory at 0750 and nobody else can create a name in it.  That is
// precisely the objection: the defence was the directory mode, and the file
// layer was leaning on it.  A later loosening of that mode, or a state
// directory somewhere else, would have moved the whole risk here with nothing
// to see it coming — and the cache dump twenty lines' worth of file away
// already does this correctly with fchmod, so the tree would have disagreed
// with itself about the same hazard.
//
// So the file is opened once and every decision is made on that descriptor:
//
//   O_NOFOLLOW  a symlink fails the open with ELOOP instead of being followed.
//               That is counted and reported rather than silently skipped —
//               a symlink in this directory is not something socketley puts
//               there, and an operator should hear that it is present.
//   O_NONBLOCK  a FIFO named x.json would otherwise block open(O_RDONLY) until
//               somebody wrote to it, which is a daemon that never finishes
//               starting.  On a regular file the flag does nothing.
//   fstat       the type and mode come from the object actually opened, so
//               there is no window between the test and the change.
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
    // Everything asked for before this call has to be visible to it.  The
    // writes are on another thread now, so read-after-write on the same object
    // would otherwise be a race — and it is not a theoretical one: a unit test
    // that saved a runtime and loaded it back caught this immediately.
    //
    // Blocking here is free.  load_all() runs at startup and in tests, never on
    // the event loop thread, which is the only place the stall mattered.
    drain();

    // Before anything is read out of them.  Said out loud when it does
    // something, because "your state files were readable by every user on this
    // machine until just now" is news, and because an operator who sees it
    // twice knows something is putting the modes back.
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
