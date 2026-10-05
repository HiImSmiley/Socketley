#pragma once
#include <string>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <set>
#include <thread>
#include <string_view>
#include <utility>
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
    // The name the document spelled for "type", kept beside the resolved id so
    // a reader can tell resolution from str_to_type's runtime_server fallback.
    std::string type_name = "server";
    uint16_t port = 0;
    // `--listen unix:/path`, an AF_UNIX listener instead of a port, mutually
    // exclusive with `port` and refused where the flag is read.
    std::string listen_path;
    // `--bind`, the IPv4 address `port` is bound on alone, empty for every address.
    std::string bind_address;
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
    // 0 means "not given", so a record written before this existed restores a
    // runtime to the default rather than to a bound of zero.
    size_t   write_buffer = 0;
    size_t   read_buffer  = 0;
    bool drain = false;
    int reconnect = -1;
    bool tls = false;
    std::string cert_path;
    std::string key_path;
    // --acme's names, comma-joined, and its account contact.
    std::string acme_domains;
    std::string acme_email;
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

    // Which child this config frame is for, never written to a state file
    // because a restore would give every shard index 0.
    uint32_t shard_index = 0;

    // Whether the daemon handed this child a row of the shard mesh, told
    // rather than inferred: a worker cannot tell a sibling's socketpair from
    // its own descriptor sitting on the same number.
    bool mesh_wired = false;

    // A second listener beside the port, for callers already on this box.
    // Derived by the daemon from its own socket and this runtime's name, never
    // written to a state file, because a restore recomputes it and a daemon on
    // a different socket would restore somebody else's path.
    std::string companion_path;

    // A request rather than a result, persisted because a restore that drops
    // the refusal silently meets no requirement.
    std::string cpus;

    // External (attach) mode
    bool external_runtime = false;
    bool managed = false;
    std::string exec_path;
    int32_t pid = 0;  // PID of external process (0 = unknown)

    // Server/Client
    uint8_t mode = 0;       // server_mode or client_mode
    uint8_t send_to = 0;    // server_send_to, server only
    bool udp = false;

    // Server master mode
    std::string master_pw;

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
    // Seconds between journal flushes, 0 meaning no journal, which is what
    // every state file written before the flag existed means.
    uint32_t persistent_interval = 0;
    uint8_t cache_mode = 1;  // cache_mode (default readwrite)
    bool resp_forced = false;
    bool cluster = false;
    std::string replicate_target;
    // The incarnation of a cluster cache replica, zero for a cache that is not one.
    uint64_t cluster_replica = 0;
    size_t max_memory = 0;
    uint8_t eviction = 0;    // eviction_policy
    // --public, false for every state file written before it existed, which
    // is the protected default those caches start under.
    bool cache_public = false;

    // Storage
    std::string storage_dir;
    bool storage_anonymous = false;
    bool storage_acls = false;
    uint64_t storage_max_bytes = 0;
    std::string storage_access_key;
    std::string storage_secret_key;
    std::string storage_credentials;
    std::string storage_sse_key_file;
    std::string storage_domain;
    std::string storage_website_domain;
    std::string storage_notify_targets;
    std::string storage_replication_targets;
    std::string storage_tiers;
    std::string storage_federation;
    std::string storage_tls_offloaded;
    std::string storage_nodes;
    std::string storage_fsync;
    uint32_t storage_fsync_interval_secs = 0;
    uint32_t storage_mpu_expire_secs = 0;
    uint32_t storage_scrub_secs = 0;
    uint32_t storage_compress_secs = 0;

    // A registered type's own fields in declaration order, opaque here, held
    // as strings because the schema that gives them kinds lives in a manifest.
    std::vector<std::pair<std::string, std::string>> extra;

    // Which keys the document actually named, so `import` can tell a default
    // from an omission, filled only by parse_json_string.
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
        enum kind { write_cfg, remove_file, flip_running } k{write_cfg};
        runtime_config cfg;      // write_cfg
        std::string    name;     // remove_file, flip_running
        // Initialised because every job is moved into the queue, and moving a
        // write_cfg reads a bool no caller ever set.
        bool           running{false};
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
    // how many were changed.
    size_t tighten_existing() const;

    bool read_json(const std::filesystem::path& path, runtime_config& cfg) const;

    std::filesystem::path m_state_dir;

public:
    ~state_persistence();
};
