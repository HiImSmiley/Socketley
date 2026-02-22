#include "state_persistence.h"
#include "runtime_instance.h"
#include "../runtime/server/server_instance.h"
#include "../runtime/client/client_instance.h"
#include "../runtime/proxy/proxy_instance.h"
#include "../runtime/cache/cache_instance.h"
#include "../cli/command_hashing.h"

#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

// ─── Minimal JSON helpers ───

namespace {

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
std::string json_get_string(const std::string& json, const std::string& key)
{
    std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) return {};

    pos = json.find(':', pos + needle.size());
    if (pos == std::string::npos) return {};

    // Skip whitespace
    pos = json.find_first_not_of(" \t\n\r", pos + 1);
    if (pos == std::string::npos) return {};

    if (json[pos] == '"')
    {
        ++pos;
        std::string result;
        while (pos < json.size() && json[pos] != '"')
        {
            if (json[pos] == '\\' && pos + 1 < json.size())
            {
                result += json[pos];
                result += json[pos + 1];
                pos += 2;
            }
            else
            {
                result += json[pos];
                ++pos;
            }
        }
        return json_unescape(result);
    }

    // Not a string — extract until comma, ], or }
    size_t end = json.find_first_of(",]}", pos);
    if (end == std::string::npos) end = json.size();
    std::string val = json.substr(pos, end - pos);
    // Trim whitespace
    while (!val.empty() && (val.back() == ' ' || val.back() == '\n' || val.back() == '\r' || val.back() == '\t'))
        val.pop_back();
    return val;
}

bool json_get_bool(const std::string& json, const std::string& key, bool default_val = false)
{
    std::string v = json_get_string(json, key);
    if (v == "true")  return true;
    if (v == "false") return false;
    return default_val;
}

int json_get_int(const std::string& json, const std::string& key, int default_val = 0)
{
    std::string v = json_get_string(json, key);
    if (v.empty()) return default_val;
    try { return std::stoi(v); } catch (...) { return default_val; }
}

uint32_t json_get_uint32(const std::string& json, const std::string& key, uint32_t default_val = 0)
{
    std::string v = json_get_string(json, key);
    if (v.empty()) return default_val;
    try { return static_cast<uint32_t>(std::stoul(v)); } catch (...) { return default_val; }
}

double json_get_double(const std::string& json, const std::string& key, double default_val = 0.0)
{
    std::string v = json_get_string(json, key);
    if (v.empty()) return default_val;
    try { return std::stod(v); } catch (...) { return default_val; }
}

size_t json_get_size(const std::string& json, const std::string& key, size_t default_val = 0)
{
    std::string v = json_get_string(json, key);
    if (v.empty()) return default_val;
    try { return static_cast<size_t>(std::stoull(v)); } catch (...) { return default_val; }
}

std::vector<std::string> json_get_array(const std::string& json, const std::string& key)
{
    std::vector<std::string> result;
    std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) return result;

    pos = json.find('[', pos + needle.size());
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

} // namespace

// ─── state_persistence ───

state_persistence::state_persistence(const fs::path& state_dir)
    : m_state_dir(state_dir)
{
}

fs::path state_persistence::config_path(std::string_view name) const
{
    return m_state_dir / (std::string(name) + ".json");
}

runtime_config state_persistence::read_from_instance(const runtime_instance* instance) const
{
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
        cfg.was_running = false;  // prevent daemon from trying to re-bind on restart
        cfg.pid = static_cast<int32_t>(instance->get_pid());
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
    std::ostringstream out;
    out << "{\n";
    out << "    \"name\": \"" << json_escape(cfg.name) << "\",\n";
    out << "    \"id\": \"" << json_escape(cfg.id) << "\",\n";
    out << "    \"type\": \"" << type_str(cfg.type) << "\",\n";
    out << "    \"port\": " << cfg.port << ",\n";
    out << "    \"was_running\": " << (cfg.was_running ? "true" : "false") << ",\n";

    // Common fields (only write non-default)
    if (!cfg.log_file.empty())
        out << "    \"log_file\": \"" << json_escape(cfg.log_file) << "\",\n";
    if (!cfg.write_file.empty())
        out << "    \"write_file\": \"" << json_escape(cfg.write_file) << "\",\n";
    if (!cfg.lua_script.empty())
        out << "    \"lua_script\": \"" << json_escape(cfg.lua_script) << "\",\n";
    if (cfg.bash_output)
        out << "    \"bash_output\": true,\n";
    if (cfg.bash_prefix)
        out << "    \"bash_prefix\": true,\n";
    if (cfg.bash_timestamp)
        out << "    \"bash_timestamp\": true,\n";
    if (cfg.max_connections > 0)
        out << "    \"max_connections\": " << cfg.max_connections << ",\n";
    if (cfg.rate_limit > 0.0)
        out << "    \"rate_limit\": " << cfg.rate_limit << ",\n";
    if (cfg.drain)
        out << "    \"drain\": true,\n";
    if (cfg.reconnect >= 0)
        out << "    \"reconnect\": " << cfg.reconnect << ",\n";
    if (cfg.tls)
        out << "    \"tls\": true,\n";
    if (!cfg.cert_path.empty())
        out << "    \"cert_path\": \"" << json_escape(cfg.cert_path) << "\",\n";
    if (!cfg.key_path.empty())
        out << "    \"key_path\": \"" << json_escape(cfg.key_path) << "\",\n";
    if (!cfg.ca_path.empty())
        out << "    \"ca_path\": \"" << json_escape(cfg.ca_path) << "\",\n";
    if (!cfg.target.empty())
        out << "    \"target\": \"" << json_escape(cfg.target) << "\",\n";
    if (!cfg.cache_name.empty())
        out << "    \"cache_name\": \"" << json_escape(cfg.cache_name) << "\",\n";
    if (!cfg.group.empty())
        out << "    \"group\": \"" << json_escape(cfg.group) << "\",\n";
    if (!cfg.owner.empty())
        out << "    \"owner\": \"" << json_escape(cfg.owner) << "\",\n";
    if (cfg.child_policy != 0)
        out << "    \"child_policy\": " << cfg.child_policy << ",\n";
    if (cfg.external_runtime)
    {
        out << "    \"external_runtime\": true,\n";
        if (cfg.pid > 0)
            out << "    \"pid\": " << cfg.pid << ",\n";
    }

    // Type-specific
    switch (cfg.type)
    {
        case runtime_server:
            out << "    \"mode\": \"" << server_mode_str(cfg.mode) << "\",\n";
            if (cfg.udp)
                out << "    \"udp\": true,\n";
            if (!cfg.master_pw.empty())
                out << "    \"master_pw\": \"" << json_escape(cfg.master_pw) << "\",\n";
            if (cfg.master_forward)
                out << "    \"master_forward\": true,\n";
            if (!cfg.http_dir.empty())
                out << "    \"http_dir\": \"" << json_escape(cfg.http_dir) << "\",\n";
            if (cfg.http_cache)
                out << "    \"http_cache\": true,\n";
            break;
        case runtime_client:
            out << "    \"mode\": \"" << server_mode_str(cfg.mode) << "\",\n";
            if (cfg.udp)
                out << "    \"udp\": true,\n";
            break;
        case runtime_proxy:
            out << "    \"protocol\": \"" << proxy_protocol_str(cfg.protocol) << "\",\n";
            out << "    \"strategy\": \"" << proxy_strategy_str(cfg.strategy) << "\",\n";
            if (!cfg.backends.empty())
            {
                out << "    \"backends\": [";
                for (size_t i = 0; i < cfg.backends.size(); ++i)
                {
                    if (i > 0) out << ", ";
                    out << "\"" << json_escape(cfg.backends[i]) << "\"";
                }
                out << "],\n";
            }
            break;
        case runtime_cache:
            if (!cfg.persistent_path.empty())
                out << "    \"persistent_path\": \"" << json_escape(cfg.persistent_path) << "\",\n";
            out << "    \"cache_mode\": \"" << cache_mode_str(cfg.cache_mode) << "\",\n";
            if (cfg.resp_forced)
                out << "    \"resp_forced\": true,\n";
            if (!cfg.replicate_target.empty())
                out << "    \"replicate_target\": \"" << json_escape(cfg.replicate_target) << "\",\n";
            if (cfg.max_memory > 0)
                out << "    \"max_memory\": " << cfg.max_memory << ",\n";
            out << "    \"eviction\": \"" << eviction_str(cfg.eviction) << "\",\n";
            break;
    }

    // Remove trailing comma+newline and close
    std::string json = out.str();
    if (json.size() >= 2 && json[json.size()-2] == ',' && json[json.size()-1] == '\n')
    {
        json[json.size()-2] = '\n';
        json.pop_back();
    }
    json += "}\n";

    return json;
}

bool state_persistence::parse_json_string(const std::string& json, runtime_config& cfg) const
{
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
            break;
        case runtime_client:
            cfg.mode = str_to_server_mode(json_get_string(json, "mode"));
            cfg.udp = json_get_bool(json, "udp");
            break;
        case runtime_proxy:
            cfg.protocol = str_to_proxy_protocol(json_get_string(json, "protocol"));
            cfg.strategy = str_to_proxy_strategy(json_get_string(json, "strategy"));
            cfg.backends = json_get_array(json, "backends");
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

    runtime_config cfg;
    if (!read_json(path, cfg))
        return;

    cfg.was_running = running;
    write_json(cfg);
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
