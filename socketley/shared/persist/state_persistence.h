#pragma once
#include <optional>
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

#include "../runtime/runtime_definitions.h"
#include "../net/mesh_defaults.h"

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
    // The TCP congestion control its listener's connections run (--congestion), the kernel's default when empty.
    std::string congestion;
    // 0 means "not given", so a record written before this existed restores a
    // runtime to the default rather than to a bound of zero.
    size_t   write_buffer = 0;
    size_t   read_buffer  = 0;
    bool drain = false;
    int reconnect = -1;
    // A client's --connections, held to the one target; 1 is not written.
    int connections = 1;
    bool tls = false;
    std::string cert_path;
    std::string key_path;
    // --acme's names, comma-joined, and its account contact.
    std::string acme_domains;
    std::string acme_email;
    // --domain's names, comma-joined, for every runtime but storage, which keeps its own under the same key.
    std::string domains;
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
    bool no_inject = false;

    // Server WebSocket origins besides its own
    std::string origins;

    // Server upstreams
    std::vector<std::string> upstreams;

    // Proxy
    uint8_t protocol = 0;   // proxy_protocol
    uint8_t strategy = 0;   // proxy_strategy
    std::vector<std::string> backends;

    // Proxy service mesh
    uint8_t health_check = 0;    // mesh_config::health_type
    int health_interval = socketley::mesh_defaults::health_interval;
    std::string health_path;
    int health_threshold = socketley::mesh_defaults::health_threshold;
    int circuit_threshold = socketley::mesh_defaults::circuit_threshold;
    int circuit_timeout = socketley::mesh_defaults::circuit_timeout;
    // 0 means "no deadline" here, so absence cannot be read off the value.
    int backend_timeout = socketley::mesh_defaults::backend_timeout;
    int retry_count = 0;
    bool retry_all = false;
    // A server's --http or a FastCGI proxy sends a file's compressed copy beside it (--compress).
    bool compress = false;
    std::string mesh_client_ca;
    std::string mesh_client_cert;
    std::string mesh_client_key;
    // --root, --fastcgi-root and --index, a FastCGI proxy's.
    std::string fcgi_root;
    std::string fcgi_remote_root;
    std::string fcgi_index;
    // --auth and --redirect-https.
    std::string proxy_auth;
    uint16_t https_redirect = 0;

    // Cache
    std::string persistent_path;
    // Seconds between journal flushes, 0 meaning no journal, which is what
    // every state file written before the flag existed means.
    uint32_t persistent_interval = 0;
    uint8_t cache_mode = 1;  // cache_mode (default readwrite)
    bool resp_forced = false;
    // --cluster said aloud, and --no-cluster: neither is the default, which is cluster mode above one shard.
    bool cluster = false;
    bool no_cluster = false;
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
    std::string storage_idp;
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
    // --sync: never, active or per-user; empty is never.
    std::string storage_sync;
    uint32_t storage_fsync_interval_secs = 0;
    uint32_t storage_mpu_expire_secs = 0;
    uint32_t storage_scrub_secs = 0;
    uint32_t storage_compress_secs = 0;

    // DNS
    std::string dns_zones;
    std::string dns_transfer;
    std::string dns_notify;
    std::string dns_publish;
    std::string dns_proxy;
    // Written always, since 0 is a setting (no rate limit) and not "not given".
    uint32_t dns_rrl = 100;
    bool dns_dnssec = false;

    // Sync
    std::string sync_dir;
    std::string sync_storage;
    std::string sync_prefix;
    std::string sync_credentials;
    std::string sync_exclude;
    // The file a storage hands its users' sync runtimes, which makes the job that user's repositories.
    std::string sync_repositories;
    // Written always, since 0 is a setting (walk only when told) and not "not given".
    uint32_t sync_every = 3600;

    // Idp
    std::string idp_clients;
    std::string idp_issuer;
    std::string idp_cookie_domain;
    std::string idp_resources;
    uint32_t idp_ssh_ca_hours = 0;

    // Tunnel
    uint8_t tunnel_mode = 0;
    std::string tunnel_to;
    std::string tunnel_join;
    std::string tunnel_offers;
    std::string tunnel_forward;
    std::string tunnel_idp;
    std::string tunnel_idp_audience;

    // Db
    std::string db_schema;
    std::string db_keys;
    std::string db_idp;
    std::string db_idp_audience;
    std::string db_origins;
    uint64_t db_max_bytes = 0;
    uint64_t db_cache = 64ull << 20;
    std::string db_replicate;
    std::string db_replicate_key;
    std::string db_backup_dir;
    uint32_t db_backup_every = 86400;
    uint32_t db_backup_keep = 7;

    // Mcp
    std::string mcp_keys;
    bool mcp_anonymous = false;
    std::string mcp_origins;
    std::string mcp_tools = "none";
    std::string mcp_instructions;
    std::string mcp_idp;
    std::string mcp_idp_audience;

    // Web
    std::string web_root;
    std::string web_index = "index.html";
    std::string web_fallback;

    // Metrics
    std::string metrics_keys;
    std::string metrics_idp;
    std::string metrics_idp_audience;
    bool metrics_no_local = false;
    std::string metrics_scrape;
    std::string metrics_archive;
    std::string metrics_archive_credentials;
    uint32_t metrics_every = 10;
    uint64_t metrics_keep = 30ull * 86400;
    std::string metrics_downsample = "5m:1y,1h:5y";
    uint32_t metrics_max_series = 200000;
    bool metrics_durable = false;
    bool metrics_logs = false;
    uint64_t metrics_logs_keep = 14ull * 86400;
    std::string metrics_rules;
    std::string metrics_notify;
    bool metrics_receive = false;

    // Mqtt; its snapshot is persistent_path and persistent_interval, as a cache's file is.
    std::string mqtt_users;
    std::string mqtt_idp;
    std::string mqtt_idp_audience;
    std::string mqtt_acl;
    std::string mqtt_routes;
    bool mqtt_anonymous = false;
    uint16_t mqtt_ws_port = 0;
    uint32_t mqtt_max_packet = 256u << 10;
    uint32_t mqtt_session_expiry = 86400;
    uint32_t mqtt_session_queue = 1000;
    uint64_t mqtt_retained_max = 64ull << 20;
    uint32_t mqtt_max_sessions = 100000;
    uint16_t mqtt_keepalive_max = 1200;

    // Mail; its spool and DKIM key live under the state directory.
    uint16_t mail_submission = 0;
    uint16_t mail_submissions = 0;
    uint16_t mail_imap = 0;
    uint16_t mail_imaps = 0;
    uint16_t mail_sieve = 0;
    std::string mail_dnsbl;
    uint16_t mail_pop3{0};
    uint16_t mail_pop3s{0};
    uint16_t mail_jmap{0};
    uint16_t mail_web{0};
    uint16_t mail_lmtp{0};
    uint16_t mail_sts_port{0};
    uint32_t mail_greylist{0};
    std::string mail_rspamd;
    std::string mail_delimiter{"+"};
    bool mail_reports{false};
    std::string mail_dmarc_rua;
    std::string mail_dmarc_policy{"quarantine"};
    std::string mail_refused_attachments{"default"};
    std::string mail_clamav;
    std::string mail_bimi;
    std::string mail_tls_rpt;
    std::string mail_mta_sts;
    uint64_t mail_default_quota{0};
    uint32_t mail_quota_warn{90};
    std::string mail_arc_trust;
    std::string mail_dkim_next;
    std::string mail_dns;
    std::string mail_domains;
    std::string mail_hostname;
    bool mail_no_reply = false;
    std::string mail_idp;
    std::string mail_idp_audience;
    std::string mail_storage;
    std::string mail_users;
    std::string mail_relay;
    std::string mail_aliases;
    std::string mail_notify;
    uint64_t mail_max_size = 25ull << 20;
    uint32_t mail_max_rcpt = 100;
    uint32_t mail_lifetime = 5 * 86400;
    uint32_t mail_autoexpunge = 0;
    std::string mail_selector = "skl";

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
    // `assumed` is the type of a document that names none, as an import for a runtime that exists may leave out.
    bool parse_json_string(const std::string& json, runtime_config& cfg,
                           std::optional<runtime_type> assumed = std::nullopt) const;

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
