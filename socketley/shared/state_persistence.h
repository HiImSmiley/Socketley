#pragma once
#include <string>
#include <string_view>
#include <vector>
#include <filesystem>
#include <cstdint>

#include "runtime_definitions.h"

struct runtime_config
{
    std::string name;
    std::string id;
    runtime_type type = runtime_server;
    uint16_t port = 0;
    bool was_running = false;

    // Common
    std::string log_file;
    std::string write_file;
    std::string lua_script;
    bool bash_output = false;
    bool bash_prefix = false;
    bool bash_timestamp = false;
    uint32_t max_connections = 0;
    double rate_limit = 0.0;
    bool drain = false;
    int reconnect = -1;
    bool tls = false;
    std::string cert_path;
    std::string key_path;
    std::string ca_path;
    std::string target;
    std::string cache_name;

    // Ownership
    std::string owner;
    int child_policy = 0; // 0 = stop, 1 = remove

    // External (attach) mode
    bool external_runtime = false;
    int32_t pid = 0;  // PID of external process (0 = unknown)

    // Server/Client
    uint8_t mode = 0;       // server_mode or client_mode
    bool udp = false;

    // Server master mode
    std::string master_pw;
    bool master_forward = false;

    // Proxy
    uint8_t protocol = 0;   // proxy_protocol
    uint8_t strategy = 0;   // proxy_strategy
    std::vector<std::string> backends;

    // Cache
    std::string persistent_path;
    uint8_t cache_mode = 1;  // cache_mode (default readwrite)
    bool resp_forced = false;
    std::string replicate_target;
    size_t max_memory = 0;
    uint8_t eviction = 0;    // eviction_policy
};

class runtime_instance;
class runtime_manager;

class state_persistence
{
public:
    explicit state_persistence(const std::filesystem::path& state_dir);

    void save_runtime(const runtime_instance* instance);
    void remove_runtime(std::string_view name);
    void set_was_running(std::string_view name, bool running);

    std::vector<runtime_config> load_all();

    runtime_config read_from_instance(const runtime_instance* instance) const;
    std::string format_json_pretty(const runtime_config& cfg) const;
    bool parse_json_string(const std::string& json, runtime_config& cfg) const;

private:
    std::filesystem::path config_path(std::string_view name) const;
    bool write_json(const runtime_config& cfg) const;
    bool read_json(const std::filesystem::path& path, runtime_config& cfg) const;

    std::filesystem::path m_state_dir;
};
