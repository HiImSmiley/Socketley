#pragma once
#include <string>
#include <string_view>
#include <unordered_map>
#include <memory>
#include <queue>
#include <vector>
#include <netinet/in.h>
#include <sys/uio.h>
#include <filesystem>

#include "../../shared/runtime_instance.h"
#include "../../shared/event_loop_definitions.h"
#include <linux/time_types.h>

class runtime_manager;

enum ws_state : uint8_t { ws_unknown = 0, ws_tcp = 1, ws_upgrading = 2, ws_active = 3 };

struct server_connection
{
    static constexpr size_t MAX_WRITE_BATCH = 16;
    static constexpr size_t MAX_WRITE_QUEUE = 4096;
    static constexpr size_t MAX_PARTIAL_SIZE = 1 * 1024 * 1024;

    int fd;
    io_request read_req;
    io_request write_req;
    char read_buf[4096];
    std::string partial;
    std::queue<std::shared_ptr<const std::string>> write_queue;

    // writev batch: holds refs alive until CQE completes
    std::shared_ptr<const std::string> write_batch[MAX_WRITE_BATCH];
    struct iovec write_iovs[MAX_WRITE_BATCH];
    uint32_t write_batch_count{0};

    bool read_pending{false};
    bool write_pending{false};
    bool closing{false};

    // WebSocket auto-detect state
    ws_state ws{ws_unknown};

    // WebSocket handshake headers (non-empty only for ws_active connections)
    std::string ws_cookie;
    std::string ws_origin;
    std::string ws_protocol;  // Sec-WebSocket-Protocol
    std::string ws_auth;      // Authorization

    // Rate limiting (token bucket)
    double rl_tokens{0.0};
    double rl_max{0.0};
    std::chrono::steady_clock::time_point rl_last{};

    // Master auth attempt tracking
    uint8_t auth_failures{0};

    // Idle connection tracking
    std::chrono::steady_clock::time_point last_activity{};

    // Per-connection metadata (freed automatically on disconnect)
    std::unordered_map<std::string, std::string> meta;
};

enum server_mode : uint8_t
{
    mode_inout  = 0,
    mode_in     = 1,
    mode_out    = 2,
    mode_master = 3
};

struct upstream_target
{
    std::string address;        // "host:port" as specified by user
    std::string resolved_host;
    uint16_t resolved_port{0};
};

struct upstream_connection
{
    static constexpr size_t MAX_WRITE_BATCH = 16;
    static constexpr size_t MAX_WRITE_QUEUE = 4096;
    static constexpr size_t MAX_PARTIAL_SIZE = 1 * 1024 * 1024;

    int conn_id;                  // 1-based Lua-facing ID (stable across reconnects)
    int fd{-1};
    upstream_target target;
    io_request read_req;
    io_request write_req;
    char read_buf[4096];
    std::string partial;
    std::queue<std::shared_ptr<const std::string>> write_queue;
    std::shared_ptr<const std::string> write_batch[MAX_WRITE_BATCH];
    struct iovec write_iovs[MAX_WRITE_BATCH];
    uint32_t write_batch_count{0};
    bool read_pending{false};
    bool write_pending{false};
    bool closing{false};
    bool connected{false};
    int reconnect_attempt{0};
    io_request timeout_req{};
    struct __kernel_timespec timeout_ts{};
};

class server_instance : public runtime_instance
{
public:
    server_instance(std::string_view name);
    ~server_instance() override;

    void set_mode(server_mode mode);
    server_mode get_mode() const;

    void set_udp(bool udp);
    bool is_udp() const override;

    void on_cqe(struct io_uring_cqe* cqe) override;
    bool setup(event_loop& loop) override;
    void teardown(event_loop& loop) override;

    size_t get_connection_count() const override;

    // Lua actions
    void lua_broadcast(std::string_view msg) override;
    void lua_send_to(int client_id, std::string_view msg) override;
    void        lua_disconnect(int client_fd);
    std::string lua_peer_ip(int client_fd);

    // Lua client enumeration + multicast
    std::vector<int> lua_clients() const;
    void lua_multicast(const std::vector<int>& fds, std::string_view msg);

    // Lua per-connection metadata
    void        lua_set_data(int fd, std::string_view key, std::string_view val);
    void        lua_del_data(int fd, std::string_view key);
    std::string lua_get_data(int fd, std::string_view key) const;

    struct ws_headers_result {
        bool is_websocket{false};
        std::string cookie, origin, protocol, auth;
    };
    ws_headers_result lua_ws_headers(int client_fd) const;

    // Stats
    std::string get_stats() const override;

    // Client routing
    bool route_client(int client_fd, std::string_view target_name);
    bool unroute_client(int client_fd);
    std::string_view get_client_route(int client_fd) const;
    void process_forwarded_message(int client_fd, std::string_view msg, std::string_view parent_name);
    void remove_forwarded_client(int client_fd);
    void send_to_client(int client_fd, std::string_view msg);

    // Owner-targeted sending (sub-server → owner's clients)
    bool owner_send(int client_fd, std::string_view msg);
    bool owner_broadcast(std::string_view msg);

    // Master mode
    void set_master_pw(std::string_view pw);
    std::string_view get_master_pw() const;
    void set_master_forward(bool fwd);
    bool get_master_forward() const;
    int get_master_fd() const;

    // HTTP static file serving
    void set_http_dir(std::string_view path);
    const std::filesystem::path& get_http_dir() const;
    void set_http_cache(bool enabled);
    bool get_http_cache() const;
    void rebuild_http_cache();

    // Upstream connections
    void add_upstream_target(std::string_view addr);
    void clear_upstream_targets();
    const std::vector<upstream_target>& get_upstream_targets() const;

    // Lua upstream actions
    void lua_upstream_send(int conn_id, std::string_view msg);
    void lua_upstream_broadcast(std::string_view msg);
    std::vector<int> lua_upstreams() const;

private:
    void handle_accept(struct io_uring_cqe* cqe);
    void handle_read(struct io_uring_cqe* cqe, io_request* req);
    void handle_write(struct io_uring_cqe* cqe, io_request* req);
    void invoke_on_websocket(int fd);
    void serve_http(server_connection* conn, std::string_view path);

    // Upstream helpers
    bool upstream_try_connect(upstream_connection* uc);
    void upstream_schedule_reconnect(upstream_connection* uc);
    void upstream_disconnect(upstream_connection* uc);
    void handle_upstream_read(struct io_uring_cqe* cqe, upstream_connection* uc);
    void handle_upstream_write(struct io_uring_cqe* cqe, upstream_connection* uc);
    void upstream_send(upstream_connection* uc, const std::shared_ptr<const std::string>& msg);
    void upstream_flush_write_queue(upstream_connection* uc);
    void invoke_on_upstream(int conn_id, std::string_view data);
    void invoke_on_upstream_connect(int conn_id);
    void invoke_on_upstream_disconnect(int conn_id);

    void process_message(server_connection* sender, std::string_view msg);
    void broadcast(const std::shared_ptr<const std::string>& msg, int exclude_fd);
    void send_to(server_connection* conn, const std::shared_ptr<const std::string>& msg);
    void flush_write_queue(server_connection* conn);

    // UDP helpers
    void handle_udp_read(struct io_uring_cqe* cqe);
    void udp_broadcast(std::string_view msg, const struct sockaddr_in* exclude);
    int find_or_add_peer(const struct sockaddr_in& addr);

    server_mode m_mode;
    bool m_udp{false};

    // Master mode
    int m_master_fd{-1};
    bool m_master_forward{false};
    std::string m_master_pw;
    int m_listen_fd;
    struct sockaddr_in m_accept_addr;
    socklen_t m_accept_addrlen;
    io_request m_accept_req;
    event_loop* m_loop;

    // EMFILE/ENFILE accept backoff
    io_request m_accept_backoff_req{};
    struct __kernel_timespec m_accept_backoff_ts{};

    // Idle connection sweep timer
    io_request m_idle_sweep_req{};
    struct __kernel_timespec m_idle_sweep_ts{};

    std::unordered_map<int, std::unique_ptr<server_connection>> m_clients;
    // O(1) fd→conn lookup for CQE dispatch (non-owning, m_clients owns)
    static constexpr int MAX_FDS = 8192;
    server_connection* m_conn_idx[MAX_FDS]{};
    bool m_multishot_active{false};

    uint64_t m_message_counter = 0;

    // Client routing: fd → target runtime name
    std::unordered_map<int, std::string> m_routes;
    // Forwarded clients: fd → source (parent) runtime name
    std::unordered_map<int, std::string> m_forwarded_clients;

    // Stats
    uint32_t m_stat_peak_connections{0};

    // Provided buffer ring
    static constexpr uint16_t BUF_GROUP_ID = 1;
    static constexpr uint32_t BUF_COUNT = 1024;
    static constexpr uint32_t BUF_SIZE = 4096;
    bool m_use_provided_bufs{false};

    // UDP mode
    static constexpr size_t MAX_UDP_PEERS = 10000;
    struct udp_peer { struct sockaddr_in addr; };
    int m_udp_fd{-1};
    char m_udp_recv_buf[65536];
    struct sockaddr_in m_udp_recv_addr{};
    struct iovec m_udp_recv_iov{};
    struct msghdr m_udp_recv_msg{};
    io_request m_udp_recv_req{};
    std::vector<udp_peer> m_udp_peers;

    // Per-IP auth failure tracking
    struct auth_ip_record {
        uint32_t failures{0};
        std::chrono::steady_clock::time_point last_failure{};
    };
    std::unordered_map<uint32_t, auth_ip_record> m_auth_ip_failures;

    // HTTP static file serving
    std::filesystem::path m_http_dir;
    std::filesystem::path m_http_base;  // canonical resolved path (set at setup/rebuild time)
    bool m_http_cache_enabled{false};
    struct cached_file { std::shared_ptr<const std::string> response; };
    std::unordered_map<std::string, cached_file> m_http_cache;

    // Upstream connections
    std::vector<upstream_target> m_upstream_targets;
    std::unordered_map<int, std::unique_ptr<upstream_connection>> m_upstreams;     // conn_id → upstream
    std::unordered_map<int, upstream_connection*> m_upstream_by_fd;                // fd → upstream (CQE dispatch)
    int m_next_upstream_id{1};
};
