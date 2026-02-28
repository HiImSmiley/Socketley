#include "state_persistence.h"
#include "runtime_instance.h"
#include "../runtime/server/server_instance.h"
#include "../runtime/client/client_instance.h"
#include "../runtime/proxy/proxy_instance.h"
#include "../runtime/cache/cache_instance.h"
#include "../cli/command_hashing.h"

#include <fstream>
#include <sstream>
#include <charconv>
#include <cstdio>
#include <unistd.h>
#include <fcntl.h>

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
            default:   out += c;      break;
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
            default:   out += c;      break;
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

int json_get_int(const std::string& json, std::string_view key, int default_val = 0)
{
    std::string v = json_get_string(json, key);
    if (v.empty()) return default_val;
    try { return std::stoi(v); } catch (...) { return default_val; }
}

uint32_t json_get_uint32(const std::string& json, std::string_view key, uint32_t default_val = 0)
{
    std::string v = json_get_string(json, key);
    if (v.empty()) return default_val;
    try { return static_cast<uint32_t>(std::stoul(v)); } catch (...) { return default_val; }
}

double json_get_double(const std::string& json, std::string_view key, double default_val = 0.0)
{
    std::string v = json_get_string(json, key);
    if (v.empty()) return default_val;
    try { return std::stod(v); } catch (...) { return default_val; }
}

size_t json_get_size(const std::string& json, std::string_view key, size_t default_val = 0)
{
    std::string v = json_get_string(json, key);
    if (v.empty()) return default_val;
    try { return static_cast<size_t>(std::stoull(v)); } catch (...) { return default_val; }
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
}

fs::path state_persistence::config_path(std::string_view name) const
{
    // Reject path traversal characters in name
    for (char c : name)
    {
        if (c == '/' || c == '\\' || c == '\0')
            return m_state_dir / "invalid.json";
    }
    if (name.find("..") != std::string_view::npos)
        return m_state_dir / "invalid.json";

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
    cfg.cache_name = instance->get_cache_name();
    cfg.group = instance->get_group();
    cfg.owner = instance->get_owner();
    cfg.child_policy = (instance->get_child_policy() == runtime_instance::child_policy::remove) ? 1 : 0;
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
    cfg.name = json_get_string(json, "name");
    cfg.id = json_get_string(json, "id");
    cfg.type = str_to_type(json_get_string(json, "type"));
    cfg.port = static_cast<uint16_t>(json_get_int(json, "port"));
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
            cfg.replicate_target = json_get_string(json, "replicate_target");
            cfg.max_memory = json_get_size(json, "max_memory");
            cfg.eviction = str_to_eviction(json_get_string(json, "eviction"));
            break;
    }

    return !cfg.name.empty();
}

bool state_persistence::write_json(const runtime_config& cfg) const
{
    std::string json = format_json_pretty(cfg);

    // Atomic write: write to .tmp then rename
    fs::path path = config_path(cfg.name);
    fs::path tmp_path = path;
    tmp_path += ".tmp";

    std::ofstream f(tmp_path, std::ios::trunc);
    if (!f.is_open())
        return false;

    f << json;
    f.flush();

    // fsync before rename to guarantee data is on disk — prevents
    // partial/empty state files on power loss or kernel crash
    int fd = ::open(tmp_path.c_str(), O_RDONLY);
    if (fd >= 0) { if (fsync(fd) < 0) {} ::close(fd); }

    f.close();

    if (f.fail())
    {
        fs::remove(tmp_path);
        return false;
    }

    std::error_code ec;
    fs::rename(tmp_path, path, ec);
    return !ec;
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
    runtime_config cfg = read_from_instance(instance);
    write_json(cfg);
}

void state_persistence::remove_runtime(std::string_view name)
{
    fs::remove(config_path(name));
}

void state_persistence::set_was_running(std::string_view name, bool running)
{
    fs::path path = config_path(name);

    // Fast path: read file, find "was_running" key, flip in-place, atomic rewrite.
    // Avoids full JSON parse + re-serialization for a single boolean toggle.
    std::ifstream f(path);
    if (!f.is_open())
        return;

    std::ostringstream ss;
    ss << f.rdbuf();
    f.close();
    std::string json = ss.str();

    std::string_view old_val = running ? "false" : "true";
    std::string_view new_val = running ? "true" : "false";
    std::string needle = "\"was_running\": ";
    needle += old_val;

    auto pos = json.find(needle);
    if (pos == std::string::npos)
        return; // Already set or key missing

    json.replace(pos + 16, old_val.size(), new_val);

    // Atomic write via .tmp + rename
    fs::path tmp_path = path;
    tmp_path += ".tmp";
    std::ofstream out(tmp_path, std::ios::trunc);
    if (!out.is_open())
        return;
    out << json;
    out.close();
    if (!out.fail())
    {
        std::error_code ec;
        fs::rename(tmp_path, path, ec);
    }
}

std::vector<runtime_config> state_persistence::load_all()
{
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
