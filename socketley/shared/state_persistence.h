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
    double global_rate_limit = 0.0;
    uint32_t idle_timeout = 0;
    bool drain = false;
    int reconnect = -1;
    bool tls = false;
    std::string cert_path;
    std::string key_path;
    std::string ca_path;
    std::string target;
    std::string cache_name;

    // Group
    std::string group;

    // Ownership
    std::string owner;
    int child_policy = 0; // 0 = stop, 1 = remove

    // Out-of-process: the runtime is served by a worker process the daemon
    // supervises.  Persisted because was_running auto-restart has to bring a
    // runtime back where it was running, not merely bring it back.
    bool out_of_process = false;

    // Ring policy: what this runtime's --cpus / --sqpoll asked its I/O to run
    // as.  See runtime_instance.h — these are a request, not a result, and the
    // daemon refuses one its ring cannot meet.
    //
    // Persisted because the refusal is the whole value of the request.  A ring
    // belongs to a process, so dropping these across a restart never changed
    // where a restored runtime's I/O ran; what it dropped was the operator's
    // stated requirement, and with it the refusal that would have said the new
    // ring does not meet it.  A daemon restarted without SOCKETLEY_CPUS brought
    // a runtime created with --cpus 0-1 back up on an unpinned ring, reported
    // cpus:max, and said nothing.
    //
    // `cpus` is stored as it would be typed — max | 0-3 | 0,1,2,3 — because
    // cpu_set_spec::to_string() round-trips through parse_cpu_set and a state
    // file a human can read is worth more here than a bitmask.  Empty means no
    // request was made, which is not the same as a request for the default:
    // see the note on has_cpus_request() in runtime_instance.h.
    std::string cpus;
    bool sqpoll = false;
    bool sqpoll_set = false;

    // External (attach) mode
    bool external_runtime = false;
    bool managed = false;
    std::string exec_path;
    int32_t pid = 0;  // PID of external process (0 = unknown)

    // Server/Client
    uint8_t mode = 0;       // server_mode or client_mode
    bool udp = false;

    // Server master mode
    std::string master_pw;
    bool master_forward = false;

    // Server HTTP static file serving
    std::string http_dir;
    bool http_cache = false;

    // Server upstreams
    std::vector<std::string> upstreams;

    // Proxy
    uint8_t protocol = 0;   // proxy_protocol
    uint8_t strategy = 0;   // proxy_strategy
    std::vector<std::string> backends;

    // Proxy service mesh
    uint8_t health_check = 0;    // mesh_config::health_type
    int health_interval = 5;
    std::string health_path;
    int health_threshold = 3;
    int circuit_threshold = 5;
    int circuit_timeout = 30;
    // Mirrors mesh_config::backend_timeout, default and all: 0 is a meaningful
    // value here ("no deadline"), so absence has to be told apart from it —
    // which is why the reader asks for this default rather than treating 0 as
    // "not set" the way the fields above do.
    int backend_timeout = 2;
    int retry_count = 0;
    bool retry_all = false;
    std::string mesh_client_ca;
    std::string mesh_client_cert;
    std::string mesh_client_key;

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
