#pragma once
#include <string>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <set>
#include <thread>
#include <string_view>
#include <vector>
#include <filesystem>
#include <cstdint>

#include "runtime_definitions.h"

namespace sp_detail
{
// Quote-and-backslash escaping for a JSON string body, without the quotes;
// shared because `ls --json` and `ps --json` also build documents by hand.
std::string json_escape(std::string_view s);
}

struct runtime_config
{
    std::string name;
    std::string id;
    runtime_type type = runtime_server;
    uint16_t port = 0;
    // `--listen unix:/path` — an AF_UNIX listener instead of a port.  See
    // runtime_instance::set_listen_path.  Mutually exclusive with `port`; the
    // refusal is where the flag is read, not here.
    std::string listen_path;
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

    // `out_of_process` used to live here; there is one where now, so the key is
    // neither read nor written and an old file carrying it still parses.

    // Persisted because a proxy restored with one shard of four is a quarter of
    // the configured throughput, reported by nothing as wrong.
    uint32_t shards = 1;

    // Which child this config frame is for, 0..shards-1 -- the only field that
    // differs between the N frames, and a worker has no other way to learn it.
    // Never written to a state file: a restore would give every shard index 0.
    uint32_t shard_index = 0;

    // A request, not a result: persisted because the refusal is the whole value
    // of it, and a restore that drops it silently meets no requirement.
    // Stored as typed (max | 0-3 | 0,1,2,3); empty means no request was made.
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
    // 0 means "no deadline" here, so absence cannot be read off the value.
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
    bool cluster = false;
    std::string replicate_target;
    size_t max_memory = 0;
    uint8_t eviction = 0;    // eviction_policy

    // Which keys the document actually named, so `import` can tell a field set
    // to its default from one left out.  Filled only by parse_json_string.
    std::set<std::string, std::less<>> present;

    bool has(std::string_view key) const { return present.find(key) != present.end(); }
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

    // One field exactly as written, for a value that parsing normalises away --
    // `listen` loses its `unix:` prefix and cannot be judged afterwards.
    std::string raw_field(const std::string& json, std::string_view key) const;

    // Blocks until everything queued is on disk; never call it on the loop
    // thread, which reintroduces the stall the queue exists to remove.
    void drain();

private:
    // Queued off the loop thread because write_json ends in an fsync; rename
    // still follows fsync, and one writer on one FIFO preserves order.
    struct job
    {
        enum kind { write_cfg, remove_file, flip_running } k;
        runtime_config cfg;      // write_cfg
        std::string    name;     // remove_file, flip_running
        bool           running;  // flip_running
    };

    void writer_loop();
    void enqueue(job j);
    void flip_was_running(std::string_view name, bool running);

    std::thread             m_writer;
    std::mutex              m_mx;
    std::condition_variable m_cv;
    std::deque<job>         m_queue;
    bool                    m_stop{false};
    uint64_t                m_queued{0}; // jobs accepted, for drain()
    uint64_t                m_done{0};   // jobs completed, for drain()

    std::filesystem::path config_path(std::string_view name) const;
    bool write_json(const runtime_config& cfg) const;

    // Narrow any state file this directory already holds to 0600, returning
    // how many were changed.  Called once from load_all(); see the reasoning
    // there and at the definition.
    size_t tighten_existing() const;

    bool read_json(const std::filesystem::path& path, runtime_config& cfg) const;

    std::filesystem::path m_state_dir;

public:
    ~state_persistence();
};
