#pragma once
#include <string>
#include <string_view>
#include <unordered_map>
#include <memory>
#include <vector>
#include <queue>
#include <random>
#include <optional>
#include <functional>
#include <netinet/in.h>
#include <sys/uio.h>

#include "../../shared/runtime_instance.h"
#include "../../shared/write_queue.h"
#include "../../shared/event_loop_definitions.h"
#include "../../shared/trace.h"

class runtime_manager;

enum proxy_protocol : uint8_t { protocol_http = 0, protocol_tcp = 1 };
enum proxy_strategy : uint8_t { strategy_round_robin = 0, strategy_random = 1, strategy_lua = 2 };
enum conn_side : uint8_t { conn_none = 0, conn_client, conn_backend };

struct backend_info
{
    std::string address;
    std::string resolved_host;
    uint16_t resolved_port = 0;
    bool is_group = false;
    bool has_cached_addr = false;
    struct sockaddr_in cached_addr{};
};

struct resolved_backend
{
    std::string host;
    uint16_t port = 0;
};

// 64KB read buffer for high-throughput TCP forwarding.
// The bottleneck is often the number of read syscalls — larger buffers
// amortize the per-syscall overhead across more data.
static constexpr size_t PROXY_READ_BUF_SIZE = 65536;

struct alignas(64) proxy_client_connection
{
    static constexpr size_t MAX_WRITE_BATCH = 16;
    static constexpr size_t MAX_PARTIAL_SIZE = 1 * 1024 * 1024;
    static constexpr size_t MAX_HEADER_SIZE = 16384;

    // === HOT fields (CQE dispatch) — first 2 cache lines ===
    int fd;
    bool read_pending{false};
    bool write_pending{false};
    bool closing{false};
    bool zc_notif_pending{false};
    bool splice_active{false};
    bool splice_in_pending{false};
    bool splice_out_pending{false};
    bool header_parsed{false};
    bool response_started{false};
    bool client_conn_close{false};  // client sent Connection: close
    int backend_fd{-1};
    uint32_t write_batch_count{0};
    io_request read_req;
    io_request write_req;

    // === WARM fields ===
    io_request splice_in_req;
    io_request splice_out_req;
    std::string partial;
    socketley::byte_counted_queue<std::string> write_queue;
    std::string write_batch[MAX_WRITE_BATCH];
    struct iovec write_iovs[MAX_WRITE_BATCH];

    // === COLD fields ===
    int pipe_to_backend[2]{-1, -1};
    std::string method;
    std::string path;
    std::string version;
    std::chrono::steady_clock::time_point last_activity{};
    int retries_remaining{0};
    size_t backend_idx{0};
    std::string saved_request;

    // Group routing (@groupname) picks a member per connection, so backend_idx
    // does not identify the target — it still points at the group entry, whose
    // resolved_host/resolved_port are deliberately left unset.  These carry the
    // endpoint that was actually selected.
    // The client sent FIN while the backend connect was still in flight; its
    // buffered payload still has to go out before this pair is torn down.
    // Bumped on every reuse from the pool; stamped into io_requests so late
    // completions from the previous occupant can be recognised and dropped.
    uint32_t generation{0};
    // One re-attempt when a connect completion turns out to reference a
    // descriptor that is no longer valid.  That is an internal inconsistency,
    // not a refusal by the backend, and it must not cost the client its
    // connection.  Bounded so a persistent problem still surfaces.
    bool connect_reattempted{false};
    bool client_eof{false};
    bool backend_from_group{false};
    std::string backend_host;
    uint16_t backend_port{0};

    // Async connect state
    bool connect_pending{false};
    int connect_fd{-1};
    io_request connect_req;
    struct sockaddr_in connect_addr{};

    SKL_TRACE_FIELD(tr)

    // 64KB read buffer — at the END to keep hot fields in first cache lines
    alignas(64) char read_buf[PROXY_READ_BUF_SIZE];

    void reset(int new_fd);
};

struct alignas(64) proxy_backend_connection
{
    static constexpr size_t MAX_WRITE_BATCH = 16;
    static constexpr size_t MAX_PARTIAL_SIZE = 1 * 1024 * 1024;

    // === HOT fields (CQE dispatch) — first 2 cache lines ===
    int fd;
    bool read_pending{false};
    bool write_pending{false};
    bool closing{false};
    bool zc_notif_pending{false};
    bool splice_active{false};
    bool splice_in_pending{false};
    bool splice_out_pending{false};
    // The response is finished and this connection is on its way to the pool,
    // but the read that was armed on it has been cancelled and its completion
    // is still owed.  Nothing may touch the fd until that completion lands.
    bool pool_draining{false};
    int client_fd;
    uint32_t write_batch_count{0};
    // Bumped on every reuse from the struct pool and stamped into read_req.
    // Backend structs and backend fds are both pooled, so a completion that
    // outlives its connection is indistinguishable from the next occupant's
    // own — same struct address, same fd number, valid owner — and acting on
    // it appends one backend's bytes to a different client's response.
    uint32_t generation{0};
    io_request read_req;
    io_request write_req;

    // === WARM fields ===
    io_request splice_in_req;
    io_request splice_out_req;
    std::string partial;
    socketley::byte_counted_queue<std::string> write_queue;
    std::string write_batch[MAX_WRITE_BATCH];
    struct iovec write_iovs[MAX_WRITE_BATCH];

    // === COLD fields ===
    int pipe_to_client[2]{-1, -1};

    // HTTP response tracking for connection pooling
    bool http_headers_parsed{false};
    bool http_has_content_length{false};
    bool http_conn_close{false};
    bool http_chunked{false};
    bool http_no_body{false};      // 204/304/1xx: no message body
    uint16_t http_status_code{0};
    size_t http_body_remaining{0};

    // Set while pool_draining when the cancelled read turns out to have
    // delivered something other than the cancellation: data past the end of
    // the response, an EOF, or an error.  Any of those leaves the stream at an
    // offset the next request cannot start from, so the fd is closed instead
    // of pooled — but only once the read has actually finished owing us a
    // completion, which is why the verdict has to be remembered.
    bool pool_abandoned{false};
    // The client is detached the moment draining starts and is free to be
    // routed somewhere else before the cancellation lands, so the pool this
    // connection belongs to cannot be read off it later.
    size_t pool_backend_idx{0};

    SKL_TRACE_FIELD(tr)

    // 64KB read buffer — at the END to keep hot fields in first cache lines
    alignas(64) char read_buf[PROXY_READ_BUF_SIZE];

    void reset(int new_fd);
};

struct proxy_conn_entry
{
    conn_side side = conn_none;
    union {
        proxy_client_connection* client;
        proxy_backend_connection* backend;
    };
};

// Health check state per backend
struct backend_health
{
    bool healthy{true};
    int consecutive_failures{0};
    std::chrono::steady_clock::time_point last_check{};
};

// Circuit breaker per backend
struct circuit_breaker
{
    enum state : uint8_t { closed = 0, open = 1, half_open = 2 };
    state current{closed};
    int error_count{0};
    std::chrono::steady_clock::time_point opened_at{};
};

// Service mesh configuration
struct mesh_config
{
    // Health checks
    enum health_type : uint8_t { health_none = 0, health_tcp = 1, health_http = 2 };
    health_type health_check{health_none};
    int health_interval{5};      // seconds
    std::string health_path{"/health"};
    int health_threshold{3};     // consecutive failures to mark unhealthy

    // Circuit breaker
    int circuit_threshold{5};    // errors to open circuit
    int circuit_timeout{30};     // seconds before half-open

    // Retries
    int retry_count{0};          // 0 = disabled
    bool retry_all{false};       // retry non-idempotent methods too

    // mTLS
    std::string client_ca;       // server-side: CA to verify client certs
    std::string client_cert;     // proxy-side: client cert for backend mTLS
    std::string client_key;      // proxy-side: client key for backend mTLS
};

// Async health check state per backend
struct async_health_check
{
    int fd{-1};
    size_t backend_idx{0};
    enum phase : uint8_t { idle, connecting, writing, reading, done };
    phase current{idle};
    io_request req;
    char buf[256];
    std::string write_buf;
};

// Connection pool entry for backend reuse
struct pooled_backend
{
    int fd;
    size_t backend_idx;             // which backend_info this connects to
    std::chrono::steady_clock::time_point idle_since;
};

class proxy_instance : public runtime_instance
{
public:
    using proxy_hook = std::function<std::optional<std::string>(int client_fd, std::string_view data)>;

    proxy_instance(std::string_view name);
    ~proxy_instance() override;

    void add_backend(std::string_view addr);
    void clear_backends();
    void set_protocol(proxy_protocol p);
    void set_strategy(proxy_strategy s);
    void set_runtime_manager(runtime_manager* mgr);

    proxy_protocol get_protocol() const;
    proxy_strategy get_strategy() const;
    const std::vector<backend_info>& get_backends() const;
    const mesh_config& get_mesh_config() const;

    // Service mesh configuration
    void set_health_check(mesh_config::health_type type);
    void set_health_interval(int seconds);
    void set_health_path(std::string_view path);
    void set_health_threshold(int threshold);
    void set_circuit_threshold(int threshold);
    void set_circuit_timeout(int seconds);
    void set_retry_count(int count);
    void set_retry_all(bool val);
    void set_mesh_client_ca(std::string_view path);
    void set_mesh_client_cert(std::string_view path);
    void set_mesh_client_key(std::string_view path);

    void on_cqe(struct io_uring_cqe* cqe) override;
    bool setup(event_loop& loop) override;
    void teardown(event_loop& loop) override;

    size_t get_connection_count() const override;

    // C++ proxy intercept hooks
    void set_on_proxy_request(proxy_hook cb);
    void set_on_proxy_response(proxy_hook cb);

    // Stats
    std::string get_stats() const override;

    // Lua API
    std::string lua_peer_ip(int client_fd);
    void lua_close_client(int client_fd);
    std::vector<std::string> lua_backends() const;
    std::vector<std::pair<int, std::string>> lua_backend_health() const;
    std::vector<int> lua_clients() const;

private:
    void handle_accept(struct io_uring_cqe* cqe);
    void handle_client_read(struct io_uring_cqe* cqe, io_request* req);
    void handle_backend_read(struct io_uring_cqe* cqe, io_request* req);
    void handle_client_write(struct io_uring_cqe* cqe, io_request* req);
    void handle_backend_write(struct io_uring_cqe* cqe, io_request* req);
    void handle_splice(struct io_uring_cqe* cqe, io_request* req);
    void handle_connect(struct io_uring_cqe* cqe, io_request* req);
    void handle_health_cqe(struct io_uring_cqe* cqe, io_request* req);

    bool parse_http_request_line(proxy_client_connection* conn);
    std::string rewrite_http_request(proxy_client_connection* conn,
                                     std::string_view new_path);

    bool resolve_backend(backend_info& b);
    const backend_info* select_and_resolve_backend(proxy_client_connection* conn);
    bool connect_to_backend(proxy_client_connection* conn, const backend_info* target);
    void close_pair(int client_fd, int backend_fd);
    inline void close_pair_close_backend(int backend_fd,
                                          proxy_backend_connection* bconn,
                                          proxy_client_connection* cconn);
    void reset_client_for_next_request(proxy_client_connection* cconn);
    void detach_and_pool_backend(proxy_client_connection* cconn, int backend_fd);
    // Consumes the completion of the read that detach_and_pool_backend
    // cancelled, and releases the fd and the struct once it is the last one.
    void finish_pool_drain(proxy_backend_connection* bconn,
                           struct io_uring_cqe* cqe, io_request* req);
    void setup_splice_pipes(proxy_client_connection* conn, proxy_backend_connection* bconn);
    void start_splice_forwarding(proxy_client_connection* conn, proxy_backend_connection* bconn);

    // Connection pool: reuse idle backend connections
    int acquire_pooled_backend(size_t backend_idx);
    void release_to_pool(int backend_fd, size_t backend_idx);

    // Append "Host: <backend>:<port>\r\n" for the endpoint this connection was
    // actually routed to.  Returns false when no usable endpoint is known, in
    // which case the caller must leave the client's own Host header alone.
    bool append_backend_host_header(std::string& out, const proxy_client_connection* conn) const;

    void forward_to_backend(proxy_client_connection* conn, std::string_view data);
    void forward_to_client(proxy_backend_connection* conn, std::string_view data);
    void send_error(proxy_client_connection* conn, std::string_view status, std::string_view body);
    // Re-arm the listener, falling back to the backoff timer when the
    // submission does not reach the ring.  Without that the proxy stops
    // accepting connections silently — there is no completion to report it.
    void rearm_accept();
    void schedule_accept_backoff();

    // Both report whether the submission reached the ring; see the
    // definitions for why a caller must not ignore that.
    bool flush_client_write_queue(proxy_client_connection* conn);
    bool flush_backend_write_queue(proxy_backend_connection* conn);

    // Socket tuning: set optimal buffer sizes and options
    void tune_socket(int fd);

    // Service mesh
    bool is_backend_available(size_t idx) const;
    void health_check_sweep();
    void record_backend_error(size_t backend_idx);
    void record_backend_success(size_t backend_idx);
    bool try_retry(proxy_client_connection* conn);

    proxy_protocol m_protocol = protocol_http;
    proxy_strategy m_strategy = strategy_round_robin;
    std::vector<backend_info> m_backends;
    std::string m_prefix;  // pre-built "/<name>/" to avoid repeated allocation

    int m_listen_fd = -1;
    sockaddr_in m_accept_addr{};
    socklen_t m_accept_addrlen = sizeof(sockaddr_in);
    io_request m_accept_req{};
    event_loop* m_loop = nullptr;
    bool m_multishot_active = false;

    // EMFILE/ENFILE accept backoff
    io_request m_accept_backoff_req{};
    struct __kernel_timespec m_accept_backoff_ts{};

    // Idle connection sweep timer
    io_request m_idle_sweep_req{};
    struct __kernel_timespec m_idle_sweep_ts{};

    static constexpr int MAX_FDS = 65536;
    std::unique_ptr<proxy_client_connection> m_client_slots[MAX_FDS];
    std::unique_ptr<proxy_backend_connection> m_backend_slots[MAX_FDS];
    size_t m_client_count{0};
    size_t m_backend_count{0};

    proxy_conn_entry m_conn_idx[MAX_FDS]{};
    backend_info m_scratch_backend{};

    size_t m_rr_index = 0;
    std::mt19937 m_rng{std::random_device{}()};

    // Provided buffer ring — 64KB buffers for high throughput
    static constexpr uint16_t BUF_GROUP_ID = 2;
    static constexpr uint32_t BUF_COUNT = 512;
    static constexpr uint32_t BUF_SIZE = PROXY_READ_BUF_SIZE;
    bool m_use_provided_bufs{false};
    bool m_recv_multishot{false};
    bool m_send_zc{false};
    bool m_splice_supported{false};

    // Connection pool for backend reuse (avoids connect() per request)
    static constexpr size_t MAX_POOL_PER_BACKEND = 32;
    static constexpr int POOL_IDLE_TIMEOUT_SEC = 60;
    std::vector<std::vector<pooled_backend>> m_backend_pool; // per-backend pool

    // Service mesh
    mesh_config m_mesh{};
    std::vector<backend_health> m_backend_health;
    std::vector<circuit_breaker> m_circuit_breakers;
    io_request m_health_check_req{};
    struct __kernel_timespec m_health_check_ts{};

    // Async health checks
    std::vector<async_health_check> m_health_checks;
    bool m_health_checks_pending{false};
    io_request m_health_timeout_req{};
    struct __kernel_timespec m_health_timeout_ts{};

    // C++ proxy intercept hooks
    proxy_hook m_cb_on_proxy_request;
    proxy_hook m_cb_on_proxy_response;

    // Connection struct pools — reuse allocations to avoid malloc/free per connect/disconnect
    static constexpr size_t CONN_POOL_INIT = 32;
    std::vector<std::unique_ptr<proxy_client_connection>> m_client_pool;
    std::vector<std::unique_ptr<proxy_backend_connection>> m_backend_struct_pool;

    std::unique_ptr<proxy_client_connection> client_pool_acquire(int fd);
    void client_pool_release(std::unique_ptr<proxy_client_connection> conn);
    std::unique_ptr<proxy_backend_connection> backend_pool_acquire(int fd);
    void backend_pool_release(std::unique_ptr<proxy_backend_connection> conn);

    // Cached config to avoid virtual calls on hot path
    uint32_t m_idle_timeout_cached{0};
    uint32_t m_max_conns_cached{0};

    // Peak connections high-water mark
    size_t m_peak_connections{0};

    // Max backends for fixed-size array in select_and_resolve_backend
    // Reused availability list for random selection over healthy backends.
    // Held here rather than on the stack so the number of backends is not
    // silently bounded by a frame-sized array; reserved in setup().
    std::vector<size_t> m_avail_scratch;
};
