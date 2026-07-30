#include "proxy_instance.h"
#include "../../shared/blocking_write.h"
#include "../../shared/event_loop.h"
#include "../../shared/runtime_manager.h"
#include "../../shared/cluster_discovery.h"
#include "../../shared/lua_context.h"
#include "../../shared/logging.h"
#include "../../shared/invariants.h"

#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <charconv>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <algorithm>
#include <liburing.h>

// Defined below, next to the read handlers they belong to; handle_accept needs
// them earlier than that.
static inline bool submit_read_op(event_loop* loop, int fd, proxy_client_connection* conn,
                                  bool recv_multishot, bool use_provided_bufs, uint16_t buf_group);
static inline bool submit_read_op_backend(event_loop* loop, int fd, proxy_backend_connection* conn,
                                          bool recv_multishot, bool use_provided_bufs, uint16_t buf_group);


// Socket buffer sizes: 256KB gives good throughput for bulk transfers
static constexpr int SOCK_BUF_SIZE = 256 * 1024;

// Splice pipe capacity: 64KB is the default, but we can request more via F_SETPIPE_SZ
static constexpr int SPLICE_PIPE_SIZE = 256 * 1024;

proxy_instance::proxy_instance(std::string_view name)
    : runtime_instance(runtime_proxy, name)
{
}

void proxy_instance::retire(std::shared_ptr<void> storage, io_request* const* owed, size_t count)
{
    // Nothing outstanding: the ring has no way to reach this object again, so
    // holding on to it would only leak.
    if (count == 0)
        return;

    if (m_loop)
        m_retired_loop = m_loop;

    retired_op op;
    op.storage = std::move(storage);
    constexpr size_t max_waiting = sizeof(op.waiting) / sizeof(op.waiting[0]);
    for (size_t i = 0; i < count && op.count < max_waiting; i++)
        op.waiting[op.count++] = owed[i];
    m_retired.push_back(std::move(op));
}

bool proxy_instance::absorb_retired(io_request* req, struct io_uring_cqe* cqe)
{
    for (size_t i = 0; i < m_retired.size(); i++)
    {
        auto& op = m_retired[i];
        for (uint8_t k = 0; k < op.count; k++)
        {
            if (op.waiting[k] != req)
                continue;

            // A read that came out of the provided-buffer ring still holds one
            // even when it is only reporting its own cancellation.  Hand it
            // back, or every restart costs the ring a few buffers for good.
            if ((cqe->flags & IORING_CQE_F_BUFFER) && m_retired_loop)
                m_retired_loop->return_buf(BUF_GROUP_ID,
                                           static_cast<uint16_t>(cqe->flags >> IORING_CQE_BUFFER_SHIFT));

            // More to come: a multishot read keeps delivering until it reports
            // without this flag, and a zero-copy send answers twice — once for
            // the write and once to say the kernel is done reading the buffer.
            // The memory stays where it is until that last word.
            if (cqe->flags & IORING_CQE_F_MORE)
                return true;

            op.waiting[k] = op.waiting[op.count - 1];
            op.count--;
            if (op.count == 0)
            {
                if (i + 1 != m_retired.size())
                    m_retired[i] = std::move(m_retired.back());
                m_retired.pop_back();
            }
            return true;
        }
    }
    return false;
}

proxy_instance::~proxy_instance()
{
    if (m_listen_fd >= 0)
        close(m_listen_fd);

    // Close any pooled backend connections
    for (auto& pool : m_backend_pool)
    {
        for (auto& pb : pool)
        {
            if (pb.fd >= 0)
                close(pb.fd);
        }
    }
}

void proxy_client_connection::reset(int new_fd)
{
    // Process-wide, not a per-struct count: both check sites resolve the struct
    // by descriptor first, so a per-struct counter is compared against a
    // different object's value once a descriptor moves between structs — and
    // with a small pool those values sit in a narrow band, so agreeing by
    // accident is common rather than rare.
    generation = next_io_generation();
    connect_reattempted = false;
    fd = new_fd;
    read_pending = false;
    write_pending = false;
    closing = false;
    zc_notif_pending = false;
    splice_active = false;
    splice_in_pending = false;
    splice_out_pending = false;
    header_parsed = false;
    response_started = false;
    client_conn_close = false;
    backend_fd = -1;
    write_batch_count = 0;
    read_req = {};
    write_req = {};
    splice_in_req = {};
    splice_out_req = {};
    partial.clear();
    write_queue.clear();
    for (uint32_t i = 0; i < MAX_WRITE_BATCH; i++) write_batch[i].clear();
    if (pipe_to_backend[0] >= 0) { close(pipe_to_backend[0]); pipe_to_backend[0] = -1; }
    if (pipe_to_backend[1] >= 0) { close(pipe_to_backend[1]); pipe_to_backend[1] = -1; }
    method.clear();
    path.clear();
    version.clear();
    last_activity = {};
    retries_remaining = 0;
    backend_idx = 0;
    saved_request.clear();
    SKL_TRACE_RESET(*this);
    client_eof = false;
    backend_from_group = false;
    backend_host.clear();
    backend_port = 0;
    connect_pending = false;
    connect_fd = -1;
    connect_req = {};
    std::memset(&connect_addr, 0, sizeof(connect_addr));
}

void proxy_backend_connection::reset(int new_fd)
{
    SKL_TRACE_RESET(*this);
    // Process-wide, not a per-struct count: both check sites resolve the struct
    // by descriptor first, so a per-struct counter is compared against a
    // different object's value once a descriptor moves between structs — and
    // with a small pool those values sit in a narrow band, so agreeing by
    // accident is common rather than rare.
    generation = next_io_generation();
    fd = new_fd;
    read_pending = false;
    write_pending = false;
    closing = false;
    zc_notif_pending = false;
    splice_active = false;
    splice_in_pending = false;
    splice_out_pending = false;
    pool_draining = false;
    pool_abandoned = false;
    pool_backend_idx = 0;
    client_fd = -1;
    write_batch_count = 0;
    read_req = {};
    write_req = {};
    splice_in_req = {};
    splice_out_req = {};
    partial.clear();
    write_queue.clear();
    for (uint32_t i = 0; i < MAX_WRITE_BATCH; i++) write_batch[i].clear();
    if (pipe_to_client[0] >= 0) { close(pipe_to_client[0]); pipe_to_client[0] = -1; }
    if (pipe_to_client[1] >= 0) { close(pipe_to_client[1]); pipe_to_client[1] = -1; }
    http_headers_parsed = false;
    http_has_content_length = false;
    http_conn_close = false;
    http_chunked = false;
    http_no_body = false;
    http_status_code = 0;
    http_body_remaining = 0;
}

std::unique_ptr<proxy_client_connection> proxy_instance::client_pool_acquire(int fd)
{
    std::unique_ptr<proxy_client_connection> conn;
    if (SOCKETLEY_LIKELY(!m_client_pool.empty()))
    {
        conn = std::move(m_client_pool.back());
        m_client_pool.pop_back();
        conn->reset(fd);
    }
    else
    {
        conn = std::make_unique<proxy_client_connection>();
        conn->fd = fd;
        // A fresh struct skips reset(), and zero is what an unstamped request
        // carries — so without this every brand new connection matches one.
        conn->generation = next_io_generation();
    }
    return conn;
}

void proxy_instance::client_pool_release(std::unique_ptr<proxy_client_connection> conn)
{
    // The splice pipes go back to the kernel here even when the struct does not.
    // A splice already in flight keeps working on the file it was handed at
    // submission time, exactly as an armed read does after its socket is
    // closed, so nothing is lost — whereas leaving the descriptors to a struct
    // that may sit retired for minutes leaks two of them per connection.
    if (conn->pipe_to_backend[0] >= 0) { close(conn->pipe_to_backend[0]); conn->pipe_to_backend[0] = -1; }
    if (conn->pipe_to_backend[1] >= 0) { close(conn->pipe_to_backend[1]); conn->pipe_to_backend[1] = -1; }

    // The half-open connect socket goes the same way, and for the same reason.
    // Every caller closes it before getting here, but nothing downstream would:
    // reset() only sets connect_fd to -1, so a struct that ever reached the pool
    // still carrying one lost that descriptor for good, and a retired struct
    // would hold it until its last completion landed — which, once the runtime
    // is stopped and its completions are dropped, is never.  This is the funnel;
    // it is the place that has to know.
    if (SOCKETLEY_UNLIKELY(conn->connect_fd >= 0))
    {
        if (m_loop) m_loop->submit_cancel_fd(conn->connect_fd);
        close(conn->connect_fd);
        conn->connect_fd = -1;
    }

    // A struct only goes back into the pool once the ring is finished with it.
    // The pool hands its structs to the very next accepted connection, and a
    // completion landing on one that has already been reissued is charged to a
    // connection it has nothing to do with — while the kernel may still be
    // reading out of write_batch[0], which reset() clears.  Anything still owed
    // is retired instead, requests included, so its completion comes back to
    // absorb_retired() and the memory is released only then.
    //
    // Callers used to null the owners here and there and get it half right:
    // close_pair's client path left out both splice requests, and a retry left
    // out everything.  This is the one place that has to know.
    {
        io_request* owed[5];
        size_t n = 0;
        if (conn->read_pending)
            owed[n++] = &conn->read_req;
        // A zero-copy send clears write_pending on its first completion and
        // still owes the notification that says the kernel has stopped reading
        // the buffer, so the two flags together are the condition.
        if (conn->write_pending || conn->zc_notif_pending)
            owed[n++] = &conn->write_req;
        if (conn->splice_in_pending)
            owed[n++] = &conn->splice_in_req;
        if (conn->splice_out_pending)
            owed[n++] = &conn->splice_out_req;
        if (conn->connect_pending)
            owed[n++] = &conn->connect_req;
        if (n > 0)
        {
            retire(std::shared_ptr<void>(std::move(conn)), owed, n);
            return;
        }
    }

    // Nothing is owed, so nothing can arrive: clear the owners anyway, because
    // that is the only protection a struct sitting in the pool has if this
    // reasoning is ever wrong.
    conn->read_req.owner = nullptr;
    conn->write_req.owner = nullptr;
    conn->splice_in_req.owner = nullptr;
    conn->splice_out_req.owner = nullptr;
    conn->connect_req.owner = nullptr;
    conn->partial.clear();
    conn->write_queue.clear();
    for (uint32_t i = 0; i < conn->write_batch_count; i++) conn->write_batch[i].clear();
    conn->write_batch_count = 0;
    conn->method.clear();
    conn->path.clear();
    conn->version.clear();
    conn->saved_request.clear();

    SKL_INV_POOLABLE("proxy::client_pool_release", conn->fd,
        conn->read_pending || conn->write_pending || conn->zc_notif_pending ||
        conn->splice_in_pending || conn->splice_out_pending || conn->connect_pending,
        conn->read_req.owner || conn->write_req.owner || conn->splice_in_req.owner ||
        conn->splice_out_req.owner || conn->connect_req.owner);

    m_client_pool.push_back(std::move(conn));
}

std::unique_ptr<proxy_backend_connection> proxy_instance::backend_pool_acquire(int fd)
{
    std::unique_ptr<proxy_backend_connection> conn;
    if (SOCKETLEY_LIKELY(!m_backend_struct_pool.empty()))
    {
        conn = std::move(m_backend_struct_pool.back());
        m_backend_struct_pool.pop_back();
        conn->reset(fd);
    }
    else
    {
        conn = std::make_unique<proxy_backend_connection>();
        conn->fd = fd;
        // A fresh struct skips reset(), and zero is what an unstamped request
        // carries — so without this every brand new connection matches one.
        conn->generation = next_io_generation();
    }
    return conn;
}

void proxy_instance::backend_pool_release(std::unique_ptr<proxy_backend_connection> conn)
{
    // Pipes first, for the reason in client_pool_release.
    if (conn->pipe_to_client[0] >= 0) { close(conn->pipe_to_client[0]); conn->pipe_to_client[0] = -1; }
    if (conn->pipe_to_client[1] >= 0) { close(conn->pipe_to_client[1]); conn->pipe_to_client[1] = -1; }

    // Same rule as the client side — see client_pool_release.
    {
        io_request* owed[4];
        size_t n = 0;
        if (conn->read_pending)
            owed[n++] = &conn->read_req;
        if (conn->write_pending || conn->zc_notif_pending)
            owed[n++] = &conn->write_req;
        if (conn->splice_in_pending)
            owed[n++] = &conn->splice_in_req;
        if (conn->splice_out_pending)
            owed[n++] = &conn->splice_out_req;
        if (n > 0)
        {
            retire(std::shared_ptr<void>(std::move(conn)), owed, n);
            return;
        }
    }

    conn->read_req.owner = nullptr;
    conn->write_req.owner = nullptr;
    conn->splice_in_req.owner = nullptr;
    conn->splice_out_req.owner = nullptr;
    conn->partial.clear();
    conn->write_queue.clear();
    for (uint32_t i = 0; i < conn->write_batch_count; i++) conn->write_batch[i].clear();
    conn->write_batch_count = 0;

    SKL_INV_POOLABLE("proxy::backend_pool_release", conn->fd,
        conn->read_pending || conn->write_pending || conn->zc_notif_pending ||
        conn->splice_in_pending || conn->splice_out_pending,
        conn->read_req.owner || conn->write_req.owner || conn->splice_in_req.owner ||
        conn->splice_out_req.owner);

    m_backend_struct_pool.push_back(std::move(conn));
}

void proxy_instance::add_backend(std::string_view addr)
{
    backend_info b;
    b.address = std::string(addr);
    m_backends.push_back(std::move(b));
}

void proxy_instance::clear_backends() { m_backends.clear(); }
void proxy_instance::set_protocol(proxy_protocol p) { m_protocol = p; }
void proxy_instance::set_strategy(proxy_strategy s) { m_strategy = s; }
void proxy_instance::set_runtime_manager(runtime_manager* mgr) { runtime_instance::set_runtime_manager(mgr); }
proxy_protocol proxy_instance::get_protocol() const { return m_protocol; }
proxy_strategy proxy_instance::get_strategy() const { return m_strategy; }
const std::vector<backend_info>& proxy_instance::get_backends() const { return m_backends; }
const mesh_config& proxy_instance::get_mesh_config() const { return m_mesh; }

void proxy_instance::set_health_check(mesh_config::health_type type) { m_mesh.health_check = type; }
void proxy_instance::set_health_interval(int seconds) { m_mesh.health_interval = seconds; }
void proxy_instance::set_health_path(std::string_view path) { m_mesh.health_path = std::string(path); }
void proxy_instance::set_health_threshold(int threshold) { m_mesh.health_threshold = threshold; }
void proxy_instance::set_circuit_threshold(int threshold) { m_mesh.circuit_threshold = threshold; }
void proxy_instance::set_circuit_timeout(int seconds) { m_mesh.circuit_timeout = seconds; }
void proxy_instance::set_retry_count(int count) { m_mesh.retry_count = count; }
void proxy_instance::set_retry_all(bool val) { m_mesh.retry_all = val; }
void proxy_instance::set_mesh_client_ca(std::string_view path) { m_mesh.client_ca = std::string(path); }
void proxy_instance::set_mesh_client_cert(std::string_view path) { m_mesh.client_cert = std::string(path); }
void proxy_instance::set_mesh_client_key(std::string_view path) { m_mesh.client_key = std::string(path); }

size_t proxy_instance::get_connection_count() const
{
    return m_client_count;
}

// Tune socket for high-throughput proxying: TCP_NODELAY, SO_SNDBUF/RCVBUF, keepalive
inline void proxy_instance::tune_socket(int fd)
{
    int opt = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    // Increase kernel socket buffers for throughput
    int buf_size = SOCK_BUF_SIZE;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));

    // TCP keepalive: detect dead connections
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
    int idle = 60, intvl = 10, cnt = 3;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle)) < 0) {}
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl)) < 0) {}
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt)) < 0) {}
}

bool proxy_instance::resolve_backend(backend_info& b)
{
    // Group references (@groupname) are resolved dynamically at connection time
    if (b.address.size() > 1 && b.address[0] == '@')
    {
        b.is_group = true;
        return true;
    }

    auto colon = b.address.find(':');
    if (colon != std::string::npos)
    {
        b.resolved_host = b.address.substr(0, colon);
        auto port_str = b.address.data() + colon + 1;
        auto port_end = b.address.data() + b.address.size();
        std::from_chars(port_str, port_end, b.resolved_port);
        if (inet_pton(AF_INET, b.resolved_host.c_str(), &b.cached_addr.sin_addr) == 1)
        {
            b.cached_addr.sin_family = AF_INET;
            b.cached_addr.sin_port = htons(b.resolved_port);
            b.has_cached_addr = true;
        }
        else
        {
            // Hostname — resolve via getaddrinfo at setup time to avoid blocking on hot path
            char port_str[8];
            auto [pe, pec] = std::to_chars(port_str, port_str + sizeof(port_str), b.resolved_port);
            *pe = '\0';

            struct addrinfo hints{};
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;

            struct addrinfo* result = nullptr;
            if (getaddrinfo(b.resolved_host.c_str(), port_str, &hints, &result) == 0 && result)
            {
                if (result->ai_family == AF_INET && result->ai_addrlen == sizeof(struct sockaddr_in))
                {
                    std::memcpy(&b.cached_addr, result->ai_addr, sizeof(struct sockaddr_in));
                    b.has_cached_addr = true;
                }
                freeaddrinfo(result);
            }
            // If DNS fails at setup, connect_to_backend will retry with blocking DNS
        }
        return true;
    }

    if (!get_runtime_manager())
        return false;

    auto* inst = get_runtime_manager()->get(b.address);
    if (!inst)
        return false;

    uint16_t port = inst->get_port();
    if (port == 0)
        return false;

    b.resolved_host = "127.0.0.1";
    b.resolved_port = port;
    b.cached_addr.sin_family = AF_INET;
    b.cached_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    b.cached_addr.sin_port = htons(port);
    b.has_cached_addr = true;
    return true;
}

bool proxy_instance::setup(event_loop& loop)
{
    // Nothing from the previous run is cleaned up here any more.  teardown()
    // hands everything it cannot free to retire(), which owns it for as long as
    // the ring might still touch it.  Freeing it here was the crash: "all
    // in-flight CQEs have been processed" is not something a restart can
    // assume — a POLLOUT armed on a connect socket, a splice parked on a pipe
    // and a health-check read all outlive a stop, and the event loop reads
    // req->owner out of the struct before it can find out the runtime moved on.
    //
    // What can go is whatever the loop confirms is finished with.  A completion
    // from a previous registration is dropped rather than delivered, so
    // absorb_retired() never hears about those and this is the only thing that
    // releases them.
    if (!m_retired.empty() && loop.owner_inflight(this) == 0)
        m_retired.clear();

    m_client_count = 0;
    m_backend_count = 0;

    m_loop = &loop;

    if (m_backends.empty())
        return false;

    for (auto& b : m_backends)
    {
        if (!resolve_backend(b))
            return false;
    }

    m_avail_scratch.reserve(m_backends.size());

    m_use_provided_bufs = loop.setup_buf_ring(BUF_GROUP_ID, BUF_COUNT, BUF_SIZE);
    m_recv_multishot = m_use_provided_bufs && loop.recv_multishot_supported();
    m_send_zc = loop.send_zc_supported();

    // Probe for splice support (available on Linux 5.7+)
    {
        struct io_uring_probe* probe = io_uring_get_probe_ring(loop.get_ring());
        if (probe)
        {
            m_splice_supported = io_uring_opcode_supported(probe, IORING_OP_SPLICE);
            io_uring_free_probe(probe);
        }
    }

    // Pre-build prefix once to avoid per-request allocation
    m_prefix = "/" + std::string(get_name()) + "/";

    uint16_t port = get_port();
    if (port == 0)
        port = 8080;

    m_listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (m_listen_fd < 0)
        return false;

    int opt = 1;
    setsockopt(m_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(m_listen_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    setsockopt(m_listen_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    // TCP_DEFER_ACCEPT: kernel delays accept CQE until client sends data,
    // eliminating the empty-accept + read round-trip on the hot path
    int defer_secs = 1;
    setsockopt(m_listen_fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &defer_secs, sizeof(defer_secs));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(m_listen_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }

    if (listen(m_listen_fd, 4096) < 0)
    {
        close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }

    // A fresh accept request for this run.  The previous one may still be owed
    // a completion — a multishot accept stays armed until it reports without
    // IORING_CQE_F_MORE — and re-arming that same request would leave the
    // listener with two accept chains sharing one io_request and one address
    // buffer.
    m_accept = std::make_unique<accept_op>();
    m_accept->req = { this, nullptr, -1, 0, op_accept };
    if (event_loop::supports_multishot_accept())
    {
        m_accept->req.type = op_multishot_accept;
        loop.submit_multishot_accept(m_listen_fd, &m_accept->req);
        m_multishot_active = true;
    }
    else
    {
        m_accept->req.type = op_accept;
        loop.submit_accept(m_listen_fd, &m_accept->addr, &m_accept->addrlen, &m_accept->req);
        m_multishot_active = false;
    }

    m_idle_timeout_cached = get_idle_timeout();
    m_max_conns_cached = get_max_connections();

    // Fresh timer for this run, for the reason spelled out on timer_op.  It is
    // built whether or not it is armed here, because the backend pool arms it on
    // demand — see release_to_pool().
    m_idle_sweep_timer = std::make_unique<timer_op>();
    m_idle_sweep_timer->ts.tv_sec = 30;
    m_idle_sweep_timer->ts.tv_nsec = 0;
    m_idle_sweep_timer->req = { this, nullptr, -1, 0, op_timeout };
    m_idle_sweep_armed = false;
    m_idle_sweep_warned = false;
    if (m_idle_timeout_cached > 0)
        arm_idle_sweep();

    // Pre-allocate connection struct pools
    if (m_client_pool.empty())
    {
        m_client_pool.reserve(CONN_POOL_INIT);
        for (size_t i = 0; i < CONN_POOL_INIT; i++)
            m_client_pool.push_back(std::make_unique<proxy_client_connection>());
        m_backend_struct_pool.reserve(CONN_POOL_INIT);
        for (size_t i = 0; i < CONN_POOL_INIT; i++)
            m_backend_struct_pool.push_back(std::make_unique<proxy_backend_connection>());
    }

    // Initialize per-backend health and circuit breaker state
    m_backend_health.clear();
    m_backend_health.resize(m_backends.size());
    m_circuit_breakers.clear();
    m_circuit_breakers.resize(m_backends.size());

    // Initialize connection pool (one pool per backend)
    m_backend_pool.clear();
    m_backend_pool.resize(m_backends.size());

    // Async health checks: one empty slot per backend, filled by the sweep.
    // teardown() has already retired whatever the previous run left behind.
    m_health_checks.clear();
    m_health_checks.resize(m_backends.size());
    m_health_checks_pending = false;

    // Start health check timer if configured
    if (m_mesh.health_check != mesh_config::health_none && m_mesh.health_interval > 0)
    {
        m_health_check_timer = std::make_unique<timer_op>();
        m_health_check_timer->ts.tv_sec = m_mesh.health_interval;
        m_health_check_timer->ts.tv_nsec = 0;
        m_health_check_timer->req = { this, nullptr, -1, 0, op_timeout };
        if (SOCKETLEY_UNLIKELY(!m_loop->submit_timeout(&m_health_check_timer->ts,
                                                       &m_health_check_timer->req)))
            LOG_ERROR("proxy: health check timer refused — backend health will not be tracked");
    }

    return true;
}

void proxy_instance::teardown(event_loop& /*loop*/)
{
    // Everything here is closed and then handed to the release path, which
    // keeps whatever the ring is still working on — the struct, its buffers,
    // and its io_requests, still pointing at this instance — until the last
    // completion has landed.  Nulling the owners was the old answer, and it
    // only holds while there is an object left to read the null out of: the
    // next setup() deleted them all, and the loop went on dereferencing
    // req->owner inside freed memory.
    for (size_t i = 0; i < m_health_checks.size(); i++)
        drop_health_check(i);
    m_health_checks_pending = false;

    // proxy_conn_entry has a default member initializer, so memset over it is
    // not defined behaviour even though conn_none happens to be 0.
    for (auto& e : m_conn_idx) e = {};

    // Shutdown the listen socket before closing
    if (m_listen_fd >= 0)
    {
        shutdown(m_listen_fd, SHUT_RDWR);
        close(m_listen_fd);
        m_listen_fd = -1;
    }

    // Drain: flush pending write queues before closing
    if (get_drain())
    {
        for (int i = 0; i < MAX_FDS; i++)
        {
            auto& conn = m_client_slots[i];
            if (!conn) continue;
            while (!conn->write_queue.empty())
            {
                const auto& msg = conn->write_queue.front();
                // A short write leaves half a message on the wire; sending the
                // next one after it would misframe everything that follows.
                if (!socketley::write_all(i, msg.data(), msg.size())) break;
                conn->write_queue.pop();
            }
        }
    }

    // shutdown() before close() on every socket, so that a read, a write or a
    // splice armed on it is completed by the kernel now rather than whenever
    // the peer gets around to it.  The release path below then only has to wait
    // for completions that are genuinely on their way.
    for (int i = 0; i < MAX_FDS; i++)
    {
        auto& conn = m_backend_slots[i];
        if (!conn) continue;
        shutdown(i, SHUT_RDWR);
        close(i);
        backend_pool_release(std::move(conn));
    }

    for (int i = 0; i < MAX_FDS; i++)
    {
        auto& conn = m_client_slots[i];
        if (!conn) continue;
        // A connect that has not finished is waiting on POLLOUT, and closing
        // the socket does not take that back — the poll holds its own reference
        // and would otherwise report minutes later, when TCP finally gives up.
        // Cancelling first turns it into a completion we get straight away.
        if (conn->connect_fd >= 0)
        {
            if (m_loop) m_loop->submit_cancel_fd(conn->connect_fd);
            close(conn->connect_fd);
            conn->connect_fd = -1;
        }
        shutdown(i, SHUT_RDWR);
        close(i);
        client_pool_release(std::move(conn));
    }
    m_client_count = 0;
    m_backend_count = 0;

    // Close pooled backend connections
    for (auto& pool : m_backend_pool)
    {
        for (auto& pb : pool)
        {
            if (pb.fd >= 0)
            {
                shutdown(pb.fd, SHUT_RDWR);
                close(pb.fd);
                pb.fd = -1;
            }
        }
        pool.clear();
    }

    // The timers and the listener, for the reason on timer_op: nothing cancels
    // an io_uring timeout, and the accept completion is still owed.  Retiring
    // them costs a few dozen bytes per stop; re-arming them cost an extra timer
    // chain per restart, each one keeping the next alive — and for the health
    // check, two sweeps driving one state machine.
    {
        io_request* owed[1];
        if (m_accept)
        {
            owed[0] = &m_accept->req;
            retire(std::shared_ptr<void>(std::move(m_accept)), owed, 1);
        }
        if (m_idle_sweep_timer)
        {
            // Only owed a completion while the chain is actually running: the
            // sweep stops re-arming itself once there is nothing left to
            // reclaim, and retiring an object nothing will ever complete for
            // holds it until the instance is destroyed.
            const size_t n = m_idle_sweep_armed ? 1 : 0;
            owed[0] = &m_idle_sweep_timer->req;
            retire(std::shared_ptr<void>(std::move(m_idle_sweep_timer)), owed, n);
        }
        if (m_accept_backoff_timer)
        {
            owed[0] = &m_accept_backoff_timer->req;
            retire(std::shared_ptr<void>(std::move(m_accept_backoff_timer)), owed, 1);
        }
        if (m_health_check_timer)
        {
            owed[0] = &m_health_check_timer->req;
            retire(std::shared_ptr<void>(std::move(m_health_check_timer)), owed, 1);
        }
        if (m_health_timeout_timer)
        {
            owed[0] = &m_health_timeout_timer->req;
            retire(std::shared_ptr<void>(std::move(m_health_timeout_timer)), owed, 1);
        }
    }

    m_idle_sweep_armed = false;
    m_loop = nullptr;
    m_multishot_active = false;
}

void proxy_instance::on_cqe(struct io_uring_cqe* cqe)
{
    auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
    if (SOCKETLEY_UNLIKELY(!req))
        return;

    // Before anything else, and before the check below that gives up while the
    // runtime is stopped: this may be the completion a previous run is still
    // owed, and it is the one that lets the memory behind it go.
    if (SOCKETLEY_UNLIKELY(!m_retired.empty()) && absorb_retired(req, cqe))
        return;

    if (SOCKETLEY_UNLIKELY(!m_loop))
        return;

#ifdef SOCKETLEY_INVARIANTS
    // Remembered before the dispatch: the handler may release the struct and
    // the request along with it.  Only per-connection operations name a pair —
    // an accept, a timer or a health probe does not.
    const int inv_fd = (req->type == op_accept || req->type == op_multishot_accept ||
                        req->type == op_timeout || req->type == op_health_check)
                       ? -1 : req->fd;
#endif

    switch (req->type)
    {
        case op_accept:
        case op_multishot_accept:
            handle_accept(cqe);
            break;
        case op_read:
        case op_read_provided:
        case op_recv_multishot:
        {
            // Both ways out of this without a handler have to give the buffer
            // back: it is the ring's, not the connection's, and the group is
            // shared by every proxy on this loop.
            if (SOCKETLEY_UNLIKELY(req->fd < 0 || req->fd >= MAX_FDS))
            {
                if (m_loop) m_loop->return_cqe_buf(cqe, req);
                break;
            }
            auto& re = m_conn_idx[req->fd];
            if (SOCKETLEY_LIKELY(re.side == conn_client))
                handle_client_read(cqe, req);
            else if (re.side == conn_backend)
                handle_backend_read(cqe, req);
            else if (m_loop)
                m_loop->return_cqe_buf(cqe, req);
            break;
        }
        case op_write:
        case op_writev:
        case op_send_zc:
        case op_send_zc_notif:
        {
            if (SOCKETLEY_UNLIKELY(req->fd < 0 || req->fd >= MAX_FDS)) break;
            auto& we = m_conn_idx[req->fd];
            if (SOCKETLEY_LIKELY(we.side == conn_client))
                handle_client_write(cqe, req);
            else if (we.side == conn_backend)
                handle_backend_write(cqe, req);
            break;
        }
        case op_splice:
            handle_splice(cqe, req);
            break;
        case op_connect:
        case op_poll:
            handle_connect(cqe, req);
            break;
        case op_health_check:
            handle_health_cqe(cqe, req);
            break;
        case op_timeout:
            if (m_idle_sweep_timer && req == &m_idle_sweep_timer->req)
            {
                // This link of the chain has spoken; nothing is owed on it now.
                m_idle_sweep_armed = false;

                auto now = std::chrono::steady_clock::now();
                if (m_idle_timeout_cached > 0)
                {
                    auto timeout = std::chrono::seconds(m_idle_timeout_cached);
                    size_t found = 0;
                    for (int cfd = 0; cfd < MAX_FDS && found < m_client_count; cfd++)
                    {
                        auto& cconn = m_client_slots[cfd];
                        if (!cconn) continue;
                        found++;
                        if (cconn->closing) continue;
                        if ((now - cconn->last_activity) > timeout)
                        {
                            cconn->closing = true;
                            shutdown(cfd, SHUT_RD);
                        }
                    }
                }

                // Evict stale pooled connections.  This half runs for every
                // proxy, configured idle timeout or not: the pool is the only
                // place a backend socket can sit with nobody watching it.
                bool pooled_left = false;
                for (auto& pool : m_backend_pool)
                {
                    pool.erase(
                        std::remove_if(pool.begin(), pool.end(),
                            [&](const pooled_backend& pb) {
                                bool stale = (now - pb.idle_since) >
                                             std::chrono::seconds(POOL_IDLE_TIMEOUT_SEC);
                                if (stale && pb.fd >= 0)
                                {
                                    shutdown(pb.fd, SHUT_RDWR);
                                    close(pb.fd);
                                }
                                return stale;
                            }),
                        pool.end());
                    pooled_left = pooled_left || !pool.empty();
                }

                // Keep the chain going only while it still has work.  An armed
                // timeout is attached to no descriptor and cannot be cancelled,
                // so one that runs for ever holds a removed proxy in the
                // manager's graveyard for ever with it.
                if (m_idle_timeout_cached > 0 || pooled_left)
                    arm_idle_sweep();
            }
            // Accept backoff expired — resubmit accept.  The timer has spoken,
            // so it owes nothing more and the next shortage may arm a new one.
            else if (m_accept_backoff_timer && req == &m_accept_backoff_timer->req)
            {
                m_accept_backoff_timer.reset();
                if (m_listen_fd >= 0)
                    rearm_accept();
            }
            // Health check sweep timer
            else if (m_health_check_timer && req == &m_health_check_timer->req)
            {
                health_check_sweep();
                if (SOCKETLEY_UNLIKELY(!m_loop->submit_timeout(&m_health_check_timer->ts,
                                                               &m_health_check_timer->req)))
                    LOG_ERROR("proxy: health check timer refused — no further sweeps will run");
            }
            // Health check deadline — give up on whatever has not answered.
            else if (m_health_timeout_timer && req == &m_health_timeout_timer->req)
            {
                for (size_t i = 0; i < m_health_checks.size(); i++)
                {
                    auto* hc = m_health_checks[i].get();
                    if (!hc || hc->current == async_health_check::idle ||
                        hc->current == async_health_check::done)
                        continue;

                    // Timed out — count as failure
                    if (hc->backend_idx < m_backend_health.size())
                    {
                        auto& health = m_backend_health[hc->backend_idx];
                        health.consecutive_failures++;
                        if (health.consecutive_failures >= m_mesh.health_threshold)
                            health.healthy = false;
                        health.last_check = std::chrono::steady_clock::now();
                    }
                    // The operation it was waiting on is not cancelled by this
                    // deadline and is still owed a completion, so the probe is
                    // let go rather than handed to the next sweep — which used
                    // to overwrite the address the connect was reading and the
                    // string the write was sending from.
                    drop_health_check(i);
                }
                // This deadline has spoken; the next sweep brings its own.
                m_health_timeout_timer.reset();
                m_health_checks_pending = false;
            }
            break;
        default:
            break;
    }

#ifdef SOCKETLEY_INVARIANTS
    inv_check_pair(inv_fd, "proxy::on_cqe");
#endif
}

#ifdef SOCKETLEY_INVARIANTS
// Invariant (1) from invariants.h, in the form this runtime takes.  A proxied
// connection is half of a pair and only the pair can answer the question: a
// client waiting on its backend's connect or its reply has nothing of its own
// in flight and is perfectly healthy, and so is a backend still reading a
// response for a client that is doing nothing but wait for it.  What is not
// healthy is neither of them having anything in flight while both are still
// indexed — no completion is coming, nothing else drives either side, so
// whatever is in their write queues is never going out and the descriptors are
// held until the runtime stops.
void proxy_instance::inv_check_pair(int fd, const char* where)
{
    if (fd < 0 || fd >= MAX_FDS)
        return;

    const auto& entry = m_conn_idx[fd];
    const proxy_client_connection*  cconn = nullptr;
    const proxy_backend_connection* bconn = nullptr;

    if (entry.side == conn_client)
    {
        cconn = entry.client;
        const int bfd = cconn->backend_fd;
        if (bfd >= 0 && bfd < MAX_FDS && m_conn_idx[bfd].side == conn_backend)
            bconn = m_conn_idx[bfd].backend;
    }
    else if (entry.side == conn_backend)
    {
        bconn = entry.backend;
        const int cfd = bconn->client_fd;
        if (cfd >= 0 && cfd < MAX_FDS && m_conn_idx[cfd].side == conn_client)
            cconn = m_conn_idx[cfd].client;
    }
    else
    {
        return;   // already torn down: nothing left that needs waking
    }

    skl_inv::half c{}, b{};
    if (cconn)
    {
        c.present   = true;
        c.in_flight = cconn->read_pending || cconn->write_pending ||
                      cconn->zc_notif_pending || cconn->splice_in_pending ||
                      cconn->splice_out_pending || cconn->connect_pending;
        c.queued    = !cconn->write_queue.empty();
        c.closing   = cconn->closing;
        c.fd        = cconn->fd;
    }
    if (bconn)
    {
        b.present   = true;
        b.in_flight = bconn->read_pending || bconn->write_pending ||
                      bconn->zc_notif_pending || bconn->splice_in_pending ||
                      bconn->splice_out_pending;
        b.queued    = !bconn->write_queue.empty();
        b.closing   = bconn->closing;
        b.fd        = bconn->fd;
    }

    SKL_INV_PAIR(where, c, b);
}
#endif

void proxy_instance::handle_accept(struct io_uring_cqe* cqe)
{
    int client_fd = cqe->res;

    if (SOCKETLEY_LIKELY(client_fd >= 0))
    {
        if (SOCKETLEY_UNLIKELY(client_fd >= MAX_FDS ||
            (m_max_conns_cached > 0 && m_client_count >= m_max_conns_cached)))
        {
            close(client_fd);
            goto proxy_resubmit_accept;
        }

        tune_socket(client_fd);

        // Auth check: reject before allocating connection state
        if (!invoke_on_auth(client_fd))
        {
            close(client_fd);
            goto proxy_resubmit_accept;
        }

        m_stat_total_connections.fetch_add(1, std::memory_order_relaxed);

        auto conn = client_pool_acquire(client_fd);
        // Only reserve partial buffer for HTTP mode — TCP forwards raw bytes
        if (m_protocol == protocol_http)
            conn->partial.reserve(PROXY_READ_BUF_SIZE);
        conn->read_req = { this, conn->read_buf, client_fd, sizeof(conn->read_buf), op_read };
        conn->write_req = { this, nullptr, client_fd, 0, op_write };
        conn->splice_in_req = { this, nullptr, client_fd, 0, op_splice };
        conn->splice_out_req = { this, nullptr, client_fd, 0, op_splice };

        auto* ptr = conn.get();
        m_client_slots[client_fd] = std::move(conn);
        m_client_count++;
        m_conn_idx[client_fd].side = conn_client;
        m_conn_idx[client_fd].client = ptr;

        // Track peak connections
        if (m_client_count > m_peak_connections)
            m_peak_connections = m_client_count;

        if (m_idle_timeout_cached > 0)
            ptr->last_activity = std::chrono::steady_clock::now();

        SKL_TRACE_SET(ptr, opened_ms, ::skl_trace::now_ms());
        invoke_on_connect(client_fd);

        // TCP: which backend this goes to does not depend on anything the client
        // sends, so connect first and only start reading once there is somewhere
        // to put the data.  Reading earlier means acknowledging bytes at the TCP
        // level that we may then have to discard if no backend materialises —
        // the client is told they arrived and nobody ever finds out otherwise.
        // Until the read is armed the bytes simply stay in the socket buffer and
        // TCP flow control slows the client down, which is the honest signal.
        if (m_protocol == protocol_tcp)
        {
            auto* target = select_and_resolve_backend(ptr);
            bool have_target = (target != nullptr);
            bool ours = false;
            bool connected = have_target && connect_to_backend(ptr, target, &ours);
            if (SOCKETLEY_UNLIKELY(!connected))
            {
                SKL_TRACE_LOG("accept-connect-failed cfd=%d target=%d ours=%d errno=%d (%s) clients=%u",
                              client_fd, (int)have_target, (int)ours, errno, strerror(errno),
                              (unsigned)m_client_count);
                // Only a backend that actually refused belongs in the breaker.
                // Charging it for our own full ring took the one healthy backend
                // out of rotation after circuit_threshold connections and then
                // refused every client that followed.
                if (have_target && !ours) record_backend_error(ptr->backend_idx);
                close_pair(client_fd, -1);
                goto proxy_resubmit_accept;
            }

            // Still connecting — handle_connect arms the read once it is up.
            if (ptr->connect_pending)
                goto proxy_resubmit_accept;

            // Connected synchronously.  If that path already handed the
            // connection to the splice pipeline, the pipeline is the reader —
            // arming a userspace read as well would put two readers on the same
            // socket and let their data reach the backend out of order.
            if (ptr->splice_active)
                goto proxy_resubmit_accept;
        }

        if (SOCKETLEY_UNLIKELY(!submit_read_op(m_loop, client_fd, ptr, m_recv_multishot,
                                               m_use_provided_bufs, BUF_GROUP_ID)))
            close_pair(client_fd, ptr->backend_fd);
    }

    // EMFILE/ENFILE: backoff 100ms to avoid CPU spin when fd limit is hit
    if (SOCKETLEY_UNLIKELY(client_fd == -EMFILE || client_fd == -ENFILE))
    {
        schedule_accept_backoff();
        return;
    }

proxy_resubmit_accept:
    if (m_multishot_active)
    {
        if (!(cqe->flags & IORING_CQE_F_MORE))
            rearm_accept();
    }
    else
    {
        rearm_accept();
    }
}

// Arm the read that fits the configured mode.  Returns false when the
// submission did not make it into the ring: the caller must not leave the
// connection marked pending then, because no completion is coming for it and
// the connection would sit there until the idle sweep eventually reaps it —
// with the peer waiting on a reply that is never read, let alone answered.
static inline bool submit_read_op(event_loop* loop, int fd, proxy_client_connection* conn,
                                   bool recv_multishot, bool use_provided_bufs, uint16_t buf_group)
{
    conn->read_pending = true;
    bool queued;
    if (recv_multishot)
        queued = loop->submit_recv_multishot(fd, buf_group, &conn->read_req);
    else if (use_provided_bufs)
        queued = loop->submit_read_provided(fd, buf_group, &conn->read_req);
    else
        queued = loop->submit_read(fd, conn->read_buf, sizeof(conn->read_buf), &conn->read_req);

    if (SOCKETLEY_UNLIKELY(!queued))
        conn->read_pending = false;
    return queued;
}

static inline bool submit_read_op_backend(event_loop* loop, int fd, proxy_backend_connection* conn,
                                           bool recv_multishot, bool use_provided_bufs, uint16_t buf_group)
{
    conn->read_pending = true;
    bool queued;
    if (recv_multishot)
        queued = loop->submit_recv_multishot(fd, buf_group, &conn->read_req);
    else if (use_provided_bufs)
        queued = loop->submit_read_provided(fd, buf_group, &conn->read_req);
    else
        queued = loop->submit_read(fd, conn->read_buf, sizeof(conn->read_buf), &conn->read_req);

    if (SOCKETLEY_UNLIKELY(!queued))
        conn->read_pending = false;
    return queued;
}

void proxy_instance::schedule_accept_backoff()
{
    if (SOCKETLEY_UNLIKELY(!m_loop))
        return;

    // One backoff timer at a time.  A second one on the same request would give
    // the listener two retry chains, and the earlier timeout cannot be taken
    // back — it is attached to no descriptor.
    if (m_accept_backoff_timer)
        return;

    m_accept_backoff_timer = std::make_unique<timer_op>();
    m_accept_backoff_timer->ts.tv_sec = 0;
    m_accept_backoff_timer->ts.tv_nsec = 100000000LL;
    m_accept_backoff_timer->req = { this, nullptr, -1, 0, op_timeout };
    if (SOCKETLEY_UNLIKELY(!m_loop->submit_timeout(&m_accept_backoff_timer->ts,
                                                   &m_accept_backoff_timer->req)))
    {
        m_accept_backoff_timer.reset();
        LOG_ERROR("proxy: accept could not be re-armed and the retry timer was refused too — "
                  "the listener has stopped taking connections");
    }
}

void proxy_instance::rearm_accept()
{
    if (SOCKETLEY_UNLIKELY(m_listen_fd < 0 || !m_loop || !m_accept))
        return;

    bool queued;
    if (m_multishot_active)
    {
        queued = m_loop->submit_multishot_accept(m_listen_fd, &m_accept->req);
    }
    else
    {
        m_accept->addrlen = sizeof(m_accept->addr);
        queued = m_loop->submit_accept(m_listen_fd, &m_accept->addr, &m_accept->addrlen,
                                       &m_accept->req);
    }

    if (SOCKETLEY_UNLIKELY(!queued))
        schedule_accept_backoff();
}

static bool header_name_equals(std::string_view line, const char* lower_name, size_t name_len)
{
    if (line.size() < name_len + 1 || line[name_len] != ':')
        return false;
    for (size_t i = 0; i < name_len; i++)
    {
        if ((line[i] | 0x20) != lower_name[i])
            return false;
    }
    return true;
}

void proxy_instance::handle_client_read(struct io_uring_cqe* cqe, io_request* req)
{
    int fd = req->fd;
    auto& entry = m_conn_idx[fd];
    if (SOCKETLEY_UNLIKELY(entry.side != conn_client))
        return;

    auto* conn = entry.client;

    bool is_multishot_recv = (req->type == op_recv_multishot);
    bool multishot_more = is_multishot_recv && (cqe->flags & IORING_CQE_F_MORE);

    if (!is_multishot_recv)
        conn->read_pending = false;
    else if (!multishot_more)
        conn->read_pending = false;

    bool is_provided = (req->type == op_read_provided || is_multishot_recv);

    if (SOCKETLEY_UNLIKELY(cqe->res <= 0))
    {
        SKL_TRACE_SET(conn, last_read_res, cqe->res);
        SKL_TRACE_SET(conn, last_read_flags, cqe->flags);

        // Return provided buffer if kernel allocated one before error
        if (is_provided && (cqe->flags & IORING_CQE_F_BUFFER))
        {
            uint16_t buf_id = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
            m_loop->return_buf(BUF_GROUP_ID, buf_id);
        }

        // ENOBUFS: buffer pool exhausted — fall back to regular read
        if (is_provided && cqe->res == -ENOBUFS)
        {
            conn->read_pending = true;
            // Reset the request type: the fallback is a plain read into the
            // connection's own buffer, not a provided-buffer one.  Leaving it
            // as a recv/provided type makes the completion handler treat the
            // result as a buffer-ring delivery — it then appends whatever sits
            // in ring buffer 0 instead of the bytes just read, discards those
            // bytes, and returns a buffer it never took, corrupting the ring's
            // free list.
            conn->read_req.type = op_read;
            if (SOCKETLEY_UNLIKELY(!m_loop->submit_read(fd, conn->read_buf,
                                                        sizeof(conn->read_buf), &conn->read_req)))
            {
                conn->read_pending = false;
                close_pair(fd, conn->backend_fd);
            }
            return;
        }

        close_pair(fd, conn->backend_fd);
        return;
    }

    SKL_TRACE_ADD(conn, bytes_read, (unsigned long long)cqe->res);
    SKL_TRACE_ADD(conn, reads, 1);

    if (SOCKETLEY_UNLIKELY(m_idle_timeout_cached > 0))
        conn->last_activity = std::chrono::steady_clock::now();

    // Track bytes in
    m_stat_bytes_in.fetch_add(static_cast<uint64_t>(cqe->res), std::memory_order_relaxed);
    m_stat_total_messages.fetch_add(1, std::memory_order_relaxed);

    // Global rate limiting
    if (SOCKETLEY_UNLIKELY(!check_global_rate_limit()))
    {
        if (is_provided && (cqe->flags & IORING_CQE_F_BUFFER))
        {
            uint16_t buf_id_rl = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
            m_loop->return_buf(BUF_GROUP_ID, buf_id_rl);
        }
        // A zero-length completion is end of stream only when the socket is
        // actually drained.  IORING_CQE_F_SOCK_NONEMPTY says the opposite: the
        // multishot recv ended while data is still queued.  Treating that as
        // EOF tears the connection down under a client that is still writing,
        // and its next write fails for data the proxy simply never collected.
        if (cqe->res == 0 && (cqe->flags & IORING_CQE_F_SOCK_NONEMPTY) && !conn->closing)
        {
            SKL_TRACE_ADD(conn, multishot_ends, 1);
            if (!conn->read_pending)
                if (SOCKETLEY_UNLIKELY(!submit_read_op(m_loop, fd, conn, m_recv_multishot, m_use_provided_bufs, BUF_GROUP_ID)))
                {
                    close_pair(fd, conn->backend_fd);
                    return;
                }
            return;
        }

        // A clean EOF from the client means it will send no more — not that we
        // may throw away what it already sent.  With the backend connect still
        // in flight the whole payload sits in saved_request, and tearing down
        // here discards it silently: the client's writes all succeeded, and the
        // backend never sees a byte.  Hold the connection until the connect
        // completes and handle_connect has forwarded it.
        if (cqe->res == 0 && conn->connect_pending && !conn->saved_request.empty())
        {
            conn->client_eof = true;
            return;
        }

        close_pair(fd, conn->backend_fd);
        return;
    }

    // Extract read data
    char* read_data;
    uint16_t buf_id = 0;
    if (is_provided)
    {
        buf_id = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
        read_data = m_loop->get_buf_ptr(BUF_GROUP_ID, buf_id);
        if (SOCKETLEY_UNLIKELY(!read_data))
        {
            close_pair(fd, conn->backend_fd);
            return;
        }
    }
    else
    {
        read_data = conn->read_buf;
    }

    if (m_protocol == protocol_tcp)
    {
        // If async connect is pending, buffer incoming data (with limit)
        if (SOCKETLEY_UNLIKELY(conn->connect_pending))
        {
            if (conn->saved_request.size() < proxy_client_connection::MAX_PARTIAL_SIZE)
                conn->saved_request.append(read_data, static_cast<size_t>(cqe->res));
            if (is_provided)
                m_loop->return_buf(BUF_GROUP_ID, buf_id);
            // Pause reads if too much data buffered, resume in handle_connect
            if (SOCKETLEY_LIKELY(!conn->closing) && !conn->read_pending &&
                conn->saved_request.size() < proxy_client_connection::MAX_PARTIAL_SIZE)
                if (SOCKETLEY_UNLIKELY(!submit_read_op(m_loop, fd, conn, m_recv_multishot, m_use_provided_bufs, BUF_GROUP_ID)))
                {
                    close_pair(fd, conn->backend_fd);
                    return;
                }
            return;
        }

        // TCP mode: connect on first read, then forward raw bytes
        if (SOCKETLEY_UNLIKELY(conn->backend_fd < 0))
        {
            auto* target = select_and_resolve_backend(conn);
            if (SOCKETLEY_UNLIKELY(!target))
            {
                if (is_provided)
                    m_loop->return_buf(BUF_GROUP_ID, buf_id);
                close_pair(fd, -1);
                return;
            }

            // Save initial data for forwarding after connect
            conn->saved_request.assign(read_data, static_cast<size_t>(cqe->res));
            if (is_provided)
                m_loop->return_buf(BUF_GROUP_ID, buf_id);

            bool ours = false;
            if (SOCKETLEY_UNLIKELY(!connect_to_backend(conn, target, &ours)))
            {
                if (!ours) record_backend_error(conn->backend_idx);
                close_pair(fd, -1);
                return;
            }

            if (conn->connect_pending)
            {
                // Async connect submitted — handle_connect will forward saved data
                if (SOCKETLEY_LIKELY(!conn->closing) && !conn->read_pending)
                    if (SOCKETLEY_UNLIKELY(!submit_read_op(m_loop, fd, conn, m_recv_multishot, m_use_provided_bufs, BUF_GROUP_ID)))
                    {
                        close_pair(fd, conn->backend_fd);
                        return;
                    }
                return;
            }

            // Pooled connection acquired synchronously — forward saved data
            forward_to_backend(conn, conn->saved_request);
            conn->saved_request.clear();

            if (SOCKETLEY_LIKELY(!conn->closing))
            {
                if (!conn->splice_active && !conn->read_pending)
                    if (SOCKETLEY_UNLIKELY(!submit_read_op(m_loop, fd, conn, m_recv_multishot, m_use_provided_bufs, BUF_GROUP_ID)))
                    {
                        close_pair(fd, conn->backend_fd);
                        return;
                    }
            }
            else if (!conn->write_pending)
            {
                close_pair(fd, conn->backend_fd);
            }
            return;
        }

        std::string_view data(read_data, cqe->res);
        forward_to_backend(conn, data);
        if (is_provided)
            m_loop->return_buf(BUF_GROUP_ID, buf_id);

        if (SOCKETLEY_LIKELY(!conn->closing) && conn->splice_active &&
            conn->backend_fd >= 0 && conn->backend_fd < MAX_FDS)
        {
            // The read that raced the splice start has now been handed to the
            // write queue; once that has drained the pipeline can take over.
            auto& be2 = m_conn_idx[conn->backend_fd];
            if (be2.side == conn_backend && !be2.backend->write_pending &&
                be2.backend->write_queue.empty())
                start_splice_forwarding(conn, be2.backend);
        }

        if (SOCKETLEY_LIKELY(!conn->closing))
        {
            // When splice is active, all subsequent data flows through the
            // kernel-space splice pipeline — no userspace reads needed.
            if (!conn->splice_active && !conn->read_pending)
            {
                // Backpressure: if backend write queue is filling up, pause client reads.
                // handle_backend_write will resume reads when the queue drains.
                bool backpressured = false;
                if (conn->backend_fd >= 0 && conn->backend_fd < MAX_FDS)
                {
                    auto& be = m_conn_idx[conn->backend_fd];
                    if (be.side == conn_backend &&
                        be.backend->write_queue.bytes() >= socketley::write_queue_backpressure_bytes)
                        backpressured = true;
                }
                if (!backpressured)
                    if (SOCKETLEY_UNLIKELY(!submit_read_op(m_loop, fd, conn, m_recv_multishot, m_use_provided_bufs, BUF_GROUP_ID)))
                    {
                        close_pair(fd, conn->backend_fd);
                        return;
                    }
            }
        }
        else if (!conn->write_pending)
        {
            // Closing and no more pending ops — clean up now.
            close_pair(fd, conn->backend_fd);
        }
        return;
    }

    // HTTP mode
    conn->partial.append(read_data, cqe->res);
    if (is_provided)
        m_loop->return_buf(BUF_GROUP_ID, buf_id);

    // If async connect is pending, just buffer data in partial
    if (SOCKETLEY_UNLIKELY(conn->connect_pending))
    {
        if (SOCKETLEY_LIKELY(!conn->closing) && !conn->read_pending)
            if (SOCKETLEY_UNLIKELY(!submit_read_op(m_loop, fd, conn, m_recv_multishot, m_use_provided_bufs, BUF_GROUP_ID)))
            {
                close_pair(fd, conn->backend_fd);
                return;
            }
        return;
    }

    if (SOCKETLEY_UNLIKELY(conn->partial.size() > proxy_client_connection::MAX_PARTIAL_SIZE))
    {
        close_pair(fd, conn->backend_fd);
        return;
    }

    if (!conn->header_parsed)
    {
        // Slowloris / oversized header protection
        if (SOCKETLEY_UNLIKELY(conn->partial.size() > proxy_client_connection::MAX_HEADER_SIZE))
        {
            send_error(conn, "431 Request Header Fields Too Large", "Header Too Large\n");
            return;
        }

        if (!parse_http_request_line(conn))
        {
            // Need more data
            if (!conn->read_pending)
                if (SOCKETLEY_UNLIKELY(!submit_read_op(m_loop, fd, conn, m_recv_multishot, m_use_provided_bufs, BUF_GROUP_ID)))
                {
                    close_pair(fd, conn->backend_fd);
                    return;
                }
            return;
        }

        conn->header_parsed = true;

        // Check path prefix (m_prefix = "/<name>/", strip trailing slash for bare match)
        std::string_view bare = std::string_view(m_prefix).substr(0, m_prefix.size() - 1);
        if (!conn->path.starts_with(m_prefix) && conn->path != bare)
        {
            send_error(conn, "404 Not Found", "Not Found\n");
            return;
        }

        // Strip prefix
        std::string_view new_path;
        if (conn->path == bare)
            new_path = "/";
        else
            new_path = std::string_view(conn->path).substr(m_prefix.size() - 1); // Keep leading /

        // Select and connect to backend
        auto* target = select_and_resolve_backend(conn);
        if (SOCKETLEY_UNLIKELY(!target))
        {
            send_error(conn, "503 Service Unavailable", "Service Unavailable\n");
            return;
        }

        // Rewrite request before connect — save for forwarding
        std::string rewritten = rewrite_http_request(conn, new_path);
        conn->saved_request = std::move(rewritten);

        bool ours = false;
        if (SOCKETLEY_UNLIKELY(!connect_to_backend(conn, target, &ours)))
        {
            if (!ours) record_backend_error(conn->backend_idx);
            if (!try_retry(conn))
            {
                send_error(conn, "502 Bad Gateway", "Bad Gateway\n");
                return;
            }
            // Retry succeeded — request already forwarded by try_retry
            goto proxy_http_resubmit;
        }

        if (conn->connect_pending)
        {
            // Async connect submitted — handle_connect will forward saved_request
            if (SOCKETLEY_LIKELY(!conn->closing) && !conn->read_pending)
                if (SOCKETLEY_UNLIKELY(!submit_read_op(m_loop, fd, conn, m_recv_multishot, m_use_provided_bufs, BUF_GROUP_ID)))
                {
                    close_pair(fd, conn->backend_fd);
                    return;
                }
            return;
        }

        // Pooled connection acquired synchronously — forward now
        forward_to_backend(conn, conn->saved_request);
        if (m_mesh.retry_count <= 0)
            conn->saved_request.clear();
    }
    else
    {
        // Subsequent data (request body) — forward as-is
        if (conn->backend_fd >= 0)
        {
            forward_to_backend(conn, conn->partial);
            conn->partial.clear();
        }
    }

proxy_http_resubmit:
    if (SOCKETLEY_LIKELY(!conn->closing))
    {
        if (!conn->read_pending)
        {
            // Backpressure: if backend write queue is filling up, pause client reads.
            // handle_backend_write will resume reads when the queue drains.
            bool bp = false;
            if (conn->backend_fd >= 0 && conn->backend_fd < MAX_FDS)
            {
                auto& be = m_conn_idx[conn->backend_fd];
                if (be.side == conn_backend &&
                    be.backend->write_queue.bytes() >= socketley::write_queue_backpressure_bytes)
                    bp = true;
            }
            if (!bp)
                if (SOCKETLEY_UNLIKELY(!submit_read_op(m_loop, fd, conn, m_recv_multishot, m_use_provided_bufs, BUF_GROUP_ID)))
                {
                    close_pair(fd, conn->backend_fd);
                    return;
                }
        }
    }
    else if (!conn->write_pending)
    {
        // Closing and no more pending ops — clean up now.
        close_pair(fd, conn->backend_fd);
    }
}

void proxy_instance::handle_backend_read(struct io_uring_cqe* cqe, io_request* req)
{
    int fd = req->fd;
    auto& entry = m_conn_idx[fd];
    if (SOCKETLEY_UNLIKELY(entry.side != conn_backend))
        return;

    auto* conn = entry.backend;

    // Backend fds and backend structs are both pooled, so this completion may
    // belong to whoever held them before: same struct address, same fd number,
    // valid owner.  Crediting it to the current occupant would splice one
    // backend's bytes into an unrelated client's response, which nothing
    // downstream could detect.  The generation stamped at submit time is what
    // tells the two apart.
    if (SOCKETLEY_UNLIKELY(req->generation != conn->generation))
    {
        // The buffer is the ring's regardless of who the completion was for;
        // dropping it along with the completion bleeds the pool one entry at a
        // time until reads start failing with ENOBUFS.
        if (cqe->flags & IORING_CQE_F_BUFFER)
        {
            uint16_t stale_buf_id = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
            m_loop->return_buf(BUF_GROUP_ID, stale_buf_id);
        }
        return;
    }

    // Response already delivered and the fd promised to the pool — this is the
    // cancelled read finishing, not traffic.
    if (SOCKETLEY_UNLIKELY(conn->pool_draining))
    {
        finish_pool_drain(conn, cqe, req);
        return;
    }

    bool is_multishot_recv = (req->type == op_recv_multishot);
    bool multishot_more = is_multishot_recv && (cqe->flags & IORING_CQE_F_MORE);

    if (!is_multishot_recv)
        conn->read_pending = false;
    else if (!multishot_more)
        conn->read_pending = false;

    bool is_provided = (req->type == op_read_provided || is_multishot_recv);

    if (SOCKETLEY_UNLIKELY(cqe->res <= 0))
    {
        SKL_TRACE_LOG("backend-read-end bfd=%d cfd=%d res=%d flags=0x%x queued=%llu written=%llu",
                      fd, conn->client_fd, cqe->res, cqe->flags,
                      (unsigned long long)conn->tr.bytes_queued,
                      (unsigned long long)conn->tr.bytes_written);

        // Return provided buffer if kernel allocated one before error
        if (is_provided && (cqe->flags & IORING_CQE_F_BUFFER))
        {
            uint16_t buf_id = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
            m_loop->return_buf(BUF_GROUP_ID, buf_id);
        }

        // ENOBUFS: buffer pool exhausted — fall back to regular read
        if (is_provided && cqe->res == -ENOBUFS)
        {
            conn->read_pending = true;
            // Reset the request type: the fallback is a plain read into the
            // connection's own buffer, not a provided-buffer one.  Leaving it
            // as a recv/provided type makes the completion handler treat the
            // result as a buffer-ring delivery — it then appends whatever sits
            // in ring buffer 0 instead of the bytes just read, discards those
            // bytes, and returns a buffer it never took, corrupting the ring's
            // free list.
            conn->read_req.type = op_read;
            if (SOCKETLEY_UNLIKELY(!m_loop->submit_read(fd, conn->read_buf,
                                                        sizeof(conn->read_buf), &conn->read_req)))
            {
                conn->read_pending = false;
                close_pair(conn->client_fd, fd);
            }
            return;
        }

        // Record a circuit breaker error only when the backend actually failed.
        //
        // res == 0 is a clean EOF, which a backend produces in the ordinary
        // course of things: HTTP/1.0, Connection: close, or a keep-alive server
        // reaching its idle timeout.  Counting those as failures took a
        // perfectly healthy backend out of rotation after circuit_threshold
        // requests — five by default.  A close is only a failure if it arrived
        // before any of the response did, which response_started already tracks.
        if (conn->client_fd >= 0 && conn->client_fd < MAX_FDS)
        {
            auto& ce = m_conn_idx[conn->client_fd];
            if (ce.side == conn_client)
            {
                const bool backend_failed =
                    (cqe->res < 0) || !ce.client->response_started;
                if (backend_failed)
                    record_backend_error(ce.client->backend_idx);
            }
        }

        close_pair(conn->client_fd, fd);
        return;
    }

    // Backend responded successfully — record for circuit breaker (once per connection, HTTP only)
    if (m_protocol == protocol_http && conn->client_fd >= 0 && conn->client_fd < MAX_FDS)
    {
        auto& ce = m_conn_idx[conn->client_fd];
        if (ce.side == conn_client && !ce.client->response_started)
        {
            // Mark that we've started receiving response data — no retry after this
            ce.client->response_started = true;
            record_backend_success(ce.client->backend_idx);
        }
    }

    // Extract data pointer for forwarding and HTTP response tracking
    char* data_ptr;
    uint16_t buf_id = 0;
    size_t data_len = static_cast<size_t>(cqe->res);

    if (is_provided)
    {
        buf_id = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
        data_ptr = m_loop->get_buf_ptr(BUF_GROUP_ID, buf_id);
        if (SOCKETLEY_UNLIKELY(!data_ptr))
        {
            close_pair(conn->client_fd, fd);
            return;
        }
    }
    else
    {
        data_ptr = conn->read_buf;
    }

    // Forward to client
    forward_to_client(conn, {data_ptr, data_len});

    // HTTP response tracking for connection pooling
    if (m_protocol == protocol_http)
    {
        if (!conn->http_headers_parsed)
        {
            // Try to find response headers in this chunk (covers 99%+ of responses)
            std::string_view sv(data_ptr, data_len);
            auto hdr_end = sv.find("\r\n\r\n");
            if (hdr_end != std::string_view::npos)
            {
                conn->http_headers_parsed = true;
                std::string_view headers(data_ptr, hdr_end);

                // Parse status code from "HTTP/1.x NNN ..."
                auto first_nl = headers.find("\r\n");
                std::string_view status_line = (first_nl != std::string_view::npos)
                    ? headers.substr(0, first_nl) : headers;
                auto sp1 = status_line.find(' ');
                if (sp1 != std::string_view::npos && sp1 + 3 <= status_line.size())
                {
                    uint16_t code = 0;
                    auto [p, ec] = std::from_chars(status_line.data() + sp1 + 1,
                                                    status_line.data() + sp1 + 4, code);
                    if (ec == std::errc{})
                        conn->http_status_code = code;
                }

                // 1xx informational: reset header state and continue waiting for real response
                if (conn->http_status_code >= 100 && conn->http_status_code < 200)
                {
                    conn->http_headers_parsed = false;
                    conn->http_status_code = 0;
                    goto proxy_backend_read_done;
                }

                // 204 No Content, 304 Not Modified: no message body per RFC 7230
                if (conn->http_status_code == 204 || conn->http_status_code == 304)
                    conn->http_no_body = true;

                // Parse Content-Length, Transfer-Encoding, Connection
                size_t h_pos = (first_nl != std::string_view::npos) ? first_nl + 2 : 0;

                while (h_pos < headers.size())
                {
                    auto nl = headers.find("\r\n", h_pos);
                    if (nl == std::string_view::npos) nl = headers.size();
                    auto line = headers.substr(h_pos, nl - h_pos);

                    if (header_name_equals(line, "content-length", 14))
                    {
                        auto colon = line.find(':');
                        if (colon != std::string_view::npos)
                        {
                            auto val = line.substr(colon + 1);
                            while (!val.empty() && val[0] == ' ') val.remove_prefix(1);
                            size_t cl_val = 0;
                            auto [p, ec] = std::from_chars(val.data(), val.data() + val.size(), cl_val);
                            if (ec == std::errc{})
                            {
                                conn->http_has_content_length = true;
                                conn->http_body_remaining = cl_val;
                            }
                        }
                    }
                    else if (header_name_equals(line, "transfer-encoding", 17))
                    {
                        auto colon = line.find(':');
                        if (colon != std::string_view::npos)
                        {
                            auto val = line.substr(colon + 1);
                            while (!val.empty() && val[0] == ' ') val.remove_prefix(1);
                            if (val.size() >= 7 && (val[0] | 0x20) == 'c' && (val[1] | 0x20) == 'h')
                                conn->http_chunked = true;
                        }
                    }
                    else if (header_name_equals(line, "connection", 10))
                    {
                        auto colon = line.find(':');
                        if (colon != std::string_view::npos)
                        {
                            auto val = line.substr(colon + 1);
                            while (!val.empty() && val[0] == ' ') val.remove_prefix(1);
                            if (val.size() >= 5 && (val[0] | 0x20) == 'c' && (val[1] | 0x20) == 'l')
                                conn->http_conn_close = true;
                        }
                    }

                    h_pos = nl + 2;
                }

                // Deduct body bytes already received in this chunk
                if (conn->http_has_content_length)
                {
                    size_t body_start = hdr_end + 4;
                    size_t body_in_chunk = (data_len > body_start) ? data_len - body_start : 0;
                    if (body_in_chunk >= conn->http_body_remaining)
                        conn->http_body_remaining = 0;
                    else
                        conn->http_body_remaining -= body_in_chunk;
                }
            }
        }
        else if (conn->http_has_content_length && conn->http_body_remaining > 0)
        {
            if (data_len >= conn->http_body_remaining)
                conn->http_body_remaining = 0;
            else
                conn->http_body_remaining -= data_len;
        }
    }

proxy_backend_read_done:

    // Return provided buffer after scanning
    if (is_provided)
        m_loop->return_buf(BUF_GROUP_ID, buf_id);

    // Check if HTTP response is complete — detach backend and pool it
    if (m_protocol == protocol_http && conn->http_headers_parsed &&
        !conn->http_chunked && !conn->http_conn_close &&
        !conn->closing && !conn->splice_active)
    {
        // Response complete when: Content-Length body fully received, OR no-body response (204/304)
        bool response_complete = false;
        if (conn->http_no_body)
            response_complete = true;
        else if (conn->http_has_content_length && conn->http_body_remaining == 0)
            response_complete = true;

        if (response_complete && conn->client_fd >= 0 && conn->client_fd < MAX_FDS)
        {
            auto& ce = m_conn_idx[conn->client_fd];
            if (ce.side == conn_client && !ce.client->closing &&
                !ce.client->client_conn_close)
            {
                size_t b_idx = ce.client->backend_idx;
                if (b_idx < m_backends.size() && !m_backends[b_idx].is_group)
                {
                    detach_and_pool_backend(ce.client, fd);
                    return;
                }
            }
        }
    }

    if (SOCKETLEY_LIKELY(!conn->closing))
    {
        if (!conn->read_pending)
        {
            // Backpressure: if client write queue is filling up, pause backend reads.
            // handle_client_write will resume when the queue drains.
            bool backpressured = false;
            if (conn->client_fd >= 0 && conn->client_fd < MAX_FDS)
            {
                auto& ce = m_conn_idx[conn->client_fd];
                if (ce.side == conn_client &&
                    ce.client->write_queue.bytes() >= socketley::write_queue_backpressure_bytes)
                    backpressured = true;
            }
            if (!backpressured)
                if (SOCKETLEY_UNLIKELY(!submit_read_op_backend(m_loop, fd, conn, m_recv_multishot, m_use_provided_bufs, BUF_GROUP_ID)))
                {
                    close_pair(conn->client_fd, fd);
                    return;
                }
        }
    }
    else if (!conn->write_pending)
    {
        // Closing and no more pending ops — clean up now.
        close_pair(conn->client_fd, fd);
    }
}

bool proxy_instance::parse_http_request_line(proxy_client_connection* conn)
{
    auto pos = conn->partial.find("\r\n");
    if (pos == std::string::npos)
        return false;

    std::string_view line(conn->partial.data(), pos);

    // Parse: METHOD SP PATH SP VERSION
    auto sp1 = line.find(' ');
    if (sp1 == std::string_view::npos)
        return false;

    auto sp2 = line.find(' ', sp1 + 1);
    if (sp2 == std::string_view::npos)
        return false;

    conn->method.assign(line.data(), sp1);
    conn->path.assign(line.data() + sp1 + 1, sp2 - sp1 - 1);
    conn->version.assign(line.data() + sp2 + 1, line.size() - sp2 - 1);

    // HTTP request smuggling prevention: reject if both Content-Length and
    // Transfer-Encoding are present (RFC 7230 Section 3.3.3)
    auto hdr_end = conn->partial.find("\r\n\r\n");
    if (hdr_end != std::string::npos)
    {
        std::string_view headers(conn->partial.data() + pos + 2, hdr_end - pos - 2);
        bool has_cl = false, has_te = false;
        size_t search_pos = 0;
        while (search_pos < headers.size())
        {
            auto nl = headers.find("\r\n", search_pos);
            if (nl == std::string_view::npos)
                nl = headers.size();
            std::string_view hdr_line = headers.substr(search_pos, nl - search_pos);
            if (hdr_line.size() >= 15)
            {
                // Case-insensitive prefix check for Content-Length: and Transfer-Encoding:
                if ((hdr_line[0] == 'C' || hdr_line[0] == 'c') &&
                    (hdr_line[7] == '-' || hdr_line[7] == '-') &&
                    hdr_line.find(':') != std::string_view::npos)
                {
                    // Check "content-length"
                    auto colon = hdr_line.find(':');
                    std::string_view name = hdr_line.substr(0, colon);
                    if (name.size() == 14)
                    {
                        bool is_cl = true;
                        const char* cl_str = "content-length";
                        for (size_t i = 0; i < 14; i++)
                        {
                            if ((name[i] | 0x20) != cl_str[i]) { is_cl = false; break; }
                        }
                        if (is_cl) has_cl = true;
                    }
                }
                if ((hdr_line[0] == 'T' || hdr_line[0] == 't') &&
                    hdr_line.find(':') != std::string_view::npos)
                {
                    auto colon = hdr_line.find(':');
                    std::string_view name = hdr_line.substr(0, colon);
                    if (name.size() == 17)
                    {
                        bool is_te = true;
                        const char* te_str = "transfer-encoding";
                        for (size_t i = 0; i < 17; i++)
                        {
                            if ((name[i] | 0x20) != te_str[i]) { is_te = false; break; }
                        }
                        if (is_te) has_te = true;
                    }
                }
            }
            search_pos = nl + 2;
        }
        if (SOCKETLEY_UNLIKELY(has_cl && has_te))
            return false;
    }

    return true;
}

bool proxy_instance::append_backend_host_header(std::string& out,
                                                const proxy_client_connection* conn) const
{
    std::string_view host;
    uint16_t port = 0;

    if (conn->backend_from_group)
    {
        host = conn->backend_host;
        port = conn->backend_port;
    }
    else if (conn->backend_idx < m_backends.size())
    {
        host = m_backends[conn->backend_idx].resolved_host;
        port = m_backends[conn->backend_idx].resolved_port;
    }

    // A group entry keeps resolved_host empty and resolved_port zero; emitting
    // it would put a literal "Host: :0" on the wire.
    if (host.empty() || port == 0)
        return false;

    out += "Host: ";
    out += host;
    out += ':';
    char port_buf[8];
    auto [pend, pec] = std::to_chars(port_buf, port_buf + sizeof(port_buf), port);
    out.append(port_buf, static_cast<size_t>(pend - port_buf));
    out += "\r\n";
    return true;
}

// Case-insensitive header name match helper
std::string proxy_instance::rewrite_http_request(proxy_client_connection* conn,
                                                  std::string_view new_path)
{
    // Find end of request line
    auto pos = conn->partial.find("\r\n");
    std::string result;
    result.reserve(conn->method.size() + 1 + new_path.size() + 1
                   + conn->version.size() + conn->partial.size() - pos + 64);
    result += conn->method;
    result += ' ';
    result += new_path;
    result += ' ';
    result += conn->version;
    result += "\r\n";

    // Parse remaining headers: strip hop-by-hop headers, rewrite Host
    std::string_view remaining(conn->partial.data() + pos + 2, conn->partial.size() - pos - 2);
    auto hdr_end = remaining.find("\r\n\r\n");
    std::string_view headers_section = (hdr_end != std::string_view::npos)
        ? remaining.substr(0, hdr_end)
        : remaining;
    std::string_view body_section = (hdr_end != std::string_view::npos)
        ? remaining.substr(hdr_end + 4)
        : std::string_view{};

    bool host_written = false;
    size_t h_pos = 0;
    while (h_pos < headers_section.size())
    {
        auto nl = headers_section.find("\r\n", h_pos);
        if (nl == std::string_view::npos)
            nl = headers_section.size();
        std::string_view hdr_line = headers_section.substr(h_pos, nl - h_pos);

        // Track client's Connection: close intent before stripping
        if (header_name_equals(hdr_line, "connection", 10))
        {
            auto colon = hdr_line.find(':');
            if (colon != std::string_view::npos)
            {
                auto val = hdr_line.substr(colon + 1);
                while (!val.empty() && val[0] == ' ') val.remove_prefix(1);
                if (val.size() >= 5 && (val[0] | 0x20) == 'c' && (val[1] | 0x20) == 'l')
                    conn->client_conn_close = true;
            }
        }

        // Skip hop-by-hop headers (RFC 7230 Section 6.1)
        bool skip = false;
        if (header_name_equals(hdr_line, "connection", 10) ||
            header_name_equals(hdr_line, "keep-alive", 10) ||
            header_name_equals(hdr_line, "proxy-authenticate", 18) ||
            header_name_equals(hdr_line, "proxy-authorization", 19) ||
            header_name_equals(hdr_line, "te", 2) ||
            header_name_equals(hdr_line, "trailer", 7) ||
            header_name_equals(hdr_line, "upgrade", 7))
            skip = true;

        // Rewrite Host header to backend address
        if (header_name_equals(hdr_line, "host", 4))
        {
            if (!append_backend_host_header(result, conn))
            {
                result += hdr_line;
                result += "\r\n";
            }
            host_written = true;
            h_pos = nl + 2;
            continue;
        }

        if (!skip)
        {
            result += hdr_line;
            result += "\r\n";
        }

        h_pos = nl + 2;
    }

    // Add Host if not present
    if (!host_written)
        append_backend_host_header(result, conn);

    // Request keep-alive to enable backend connection pooling,
    // unless the client sent Connection: close
    if (conn->client_conn_close)
        result += "Connection: close\r\n";
    else
        result += "Connection: keep-alive\r\n";

    result += "\r\n";
    if (!body_section.empty())
        result += body_section;

    conn->partial.clear();
    return result;
}

const backend_info* proxy_instance::select_and_resolve_backend(proxy_client_connection* conn)
{
    if (SOCKETLEY_UNLIKELY(m_backends.empty()))
        return nullptr;

    // Cleared up front so every non-group return path leaves it false, including
    // a keep-alive connection that was group-routed on an earlier request.
    conn->backend_from_group = false;

    // Fast path: check if any backend is a group
    bool has_group = false;
    for (const auto& b : m_backends)
    {
        if (b.is_group) { has_group = true; break; }
    }

    if (SOCKETLEY_LIKELY(!has_group))
    {
        bool mesh_enabled = (m_mesh.health_check != mesh_config::health_none) ||
                            (m_mesh.circuit_threshold > 0);

        // Zero-alloc fast path: select directly from m_backends
        if (m_backends.size() == 1)
        {
            // Check circuit breaker: if open and timeout not expired, check half_open
            if (mesh_enabled && !m_circuit_breakers.empty())
            {
                auto& cb = m_circuit_breakers[0];
                if (SOCKETLEY_UNLIKELY(cb.current == circuit_breaker::open))
                {
                    auto elapsed = std::chrono::steady_clock::now() - cb.opened_at;
                    if (elapsed >= std::chrono::seconds(m_mesh.circuit_timeout))
                        cb.current = circuit_breaker::half_open;
                    else
                        return nullptr; // circuit open, no alternative
                }
            }
            conn->backend_idx = 0;
            conn->retries_remaining = m_mesh.retry_count;
            return &m_backends[0];
        }

        size_t pool_size = m_backends.size();

        if (m_strategy == strategy_lua && lua() && lua()->has_on_route())
        {
#ifndef SOCKETLEY_NO_LUA
            sol::object result;
            if (m_protocol == protocol_http)
                result = lua()->on_route()(conn->method, conn->path);
            else
                result = lua()->on_route()();

            if (result.is<int>())
            {
                int idx = result.as<int>();
                if (idx >= 0 && static_cast<size_t>(idx) < pool_size)
                {
                    conn->backend_idx = static_cast<size_t>(idx);
                    conn->retries_remaining = m_mesh.retry_count;
                    return &m_backends[static_cast<size_t>(idx)];
                }
            }
#endif
            // Fallback to round-robin
        }

        // Build list of available indices (health + circuit breaker aware)
        size_t selected_idx = 0;
        bool found = false;

        if (mesh_enabled)
        {
            // Transition expired open circuits to half_open
            auto now = std::chrono::steady_clock::now();
            for (size_t i = 0; i < m_circuit_breakers.size() && i < pool_size; i++)
            {
                auto& cb = m_circuit_breakers[i];
                if (cb.current == circuit_breaker::open &&
                    (now - cb.opened_at) >= std::chrono::seconds(m_mesh.circuit_timeout))
                    cb.current = circuit_breaker::half_open;
            }

            if (m_strategy == strategy_random)
            {
                // Build availability list in a single pass.  This used to fill a
                // fixed 256-entry stack array from a loop bounded only by the
                // number of configured backends, so a 257th backend wrote past
                // the end of the frame — reliably fatal, since the stack
                // protector catches it and aborts the whole daemon.  Nothing
                // capped the backend count, so the array's size was never a
                // limit anyone enforced.  The scratch vector is a member and is
                // reserved at setup, so this stays allocation-free per call.
                m_avail_scratch.clear();
                for (size_t i = 0; i < pool_size; i++)
                {
                    if (is_backend_available(i))
                        m_avail_scratch.push_back(i);
                }

                if (m_avail_scratch.empty())
                    return nullptr;

                std::uniform_int_distribution<size_t> dist(0, m_avail_scratch.size() - 1);
                selected_idx = m_avail_scratch[dist(m_rng)];
                found = true;
            }
            else
            {
                // Round-robin over available backends
                for (size_t attempts = 0; attempts < pool_size; attempts++)
                {
                    size_t idx = (m_rr_index + attempts) % pool_size;
                    if (is_backend_available(idx))
                    {
                        selected_idx = idx;
                        m_rr_index = idx + 1;
                        found = true;
                        break;
                    }
                }
                if (!found)
                    m_rr_index++;
            }
        }
        else
        {
            // No mesh — original behavior
            if (m_strategy == strategy_random)
            {
                std::uniform_int_distribution<size_t> dist(0, pool_size - 1);
                selected_idx = dist(m_rng);
            }
            else
            {
                selected_idx = m_rr_index % pool_size;
                ++m_rr_index;
            }
            found = true;
        }

        if (SOCKETLEY_UNLIKELY(!found))
            return nullptr;

        conn->backend_idx = selected_idx;
        conn->retries_remaining = m_mesh.retry_count;
        return &m_backends[selected_idx];
    }

    // Slow path: has group backends — build pool and resolve dynamically
    std::vector<resolved_backend> pool;
    pool.reserve(m_backends.size());

    for (const auto& b : m_backends)
    {
        if (b.is_group)
        {
            auto* mgr = get_runtime_manager();
            if (mgr)
            {
                std::string_view group_name(b.address.data() + 1, b.address.size() - 1);

                auto members = mgr->get_by_group(group_name);
                for (auto* inst : members)
                {
                    uint16_t port = inst->get_port();
                    if (port > 0)
                        pool.push_back({"127.0.0.1", port});
                }

                auto* cd = mgr->get_cluster_discovery();
                if (cd)
                {
                    auto remotes = cd->get_remote_group(group_name);
                    for (auto& ep : remotes)
                        pool.push_back({std::move(ep.host), ep.port});
                }
            }
        }
        else
        {
            pool.push_back({b.resolved_host, b.resolved_port});
        }
    }

    if (pool.empty())
        return nullptr;

    resolved_backend* selected = &pool[0];

    if (pool.size() > 1)
    {
        if (m_strategy == strategy_lua && lua() && lua()->has_on_route())
        {
#ifndef SOCKETLEY_NO_LUA
            sol::object result;
            if (m_protocol == protocol_http)
                result = lua()->on_route()(conn->method, conn->path);
            else
                result = lua()->on_route()();

            if (result.is<int>())
            {
                int idx = result.as<int>();
                if (idx >= 0 && static_cast<size_t>(idx) < pool.size())
                    selected = &pool[static_cast<size_t>(idx)];
            }
#endif
        }
        else if (m_strategy == strategy_random)
        {
            std::uniform_int_distribution<size_t> dist(0, pool.size() - 1);
            selected = &pool[dist(m_rng)];
        }
        else
        {
            size_t idx = m_rr_index % pool.size();
            ++m_rr_index;
            selected = &pool[idx];
        }
    }

    // Write selected result into scratch space.  The scratch is shared by all
    // connections and is overwritten by the next selection, so the endpoint is
    // also recorded on the connection itself — everything after the connect
    // (Host rewrite, pool eligibility) has to read it from there.
    m_scratch_backend.resolved_host = std::move(selected->host);
    m_scratch_backend.resolved_port = selected->port;
    m_scratch_backend.has_cached_addr = false;
    conn->backend_from_group = true;
    conn->backend_host = m_scratch_backend.resolved_host;
    conn->backend_port = m_scratch_backend.resolved_port;
    if (inet_pton(AF_INET, m_scratch_backend.resolved_host.c_str(),
                  &m_scratch_backend.cached_addr.sin_addr) == 1)
    {
        m_scratch_backend.cached_addr.sin_family = AF_INET;
        m_scratch_backend.cached_addr.sin_port = htons(m_scratch_backend.resolved_port);
        m_scratch_backend.has_cached_addr = true;
    }
    return &m_scratch_backend;
}

// Try to get a pooled backend connection for the given backend index
int proxy_instance::acquire_pooled_backend(size_t backend_idx)
{
    if (backend_idx >= m_backend_pool.size())
        return -1;

    auto& pool = m_backend_pool[backend_idx];
    if (pool.empty())
        return -1;

    auto now = std::chrono::steady_clock::now();

    // Try from the back (most recently idle) — better chance of being alive
    while (!pool.empty())
    {
        auto pb = pool.back();
        pool.pop_back();

        // Check if stale
        if ((now - pb.idle_since) > std::chrono::seconds(POOL_IDLE_TIMEOUT_SEC))
        {
            if (pb.fd >= 0)
            {
                shutdown(pb.fd, SHUT_RDWR);
                close(pb.fd);
            }
            continue;
        }

        // Skip the liveness probe for recently-idle connections — probability
        // of a FIN/RST arriving in the first 5s is very low, and the syscall
        // is expensive on the hot path.
        if ((now - pb.idle_since) < std::chrono::seconds(5))
            return pb.fd;

        // Quick liveness probe: if the remote has sent a RST/FIN while pooled,
        // recv(MSG_PEEK|MSG_DONTWAIT) returns 0 (FIN) or -1/ECONNRESET.
        // EAGAIN means the socket is alive with no pending data — good to reuse.
        char probe;
        ssize_t r = recv(pb.fd, &probe, 1, MSG_PEEK | MSG_DONTWAIT);
        if (r == 0 || (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK))
        {
            // Dead connection
            close(pb.fd);
            continue;
        }
        return pb.fd;
    }

    return -1;
}

// The idle sweep is what reclaims pooled backend sockets, so it has to run for
// every proxy that pools — not only for one that was configured with an idle
// timeout for its clients.  Arming it was tied to that timeout, which meant a
// proxy without one kept up to MAX_POOL_PER_BACKEND sockets per backend open
// for the rest of its life: acquire_pooled_backend() drops stale entries, but
// only when somebody asks for a connection, and an idle proxy never does.
//
// It is armed on demand rather than always, so a proxy that never pools costs
// no timer chain at all, and the chain stops itself once the pools are empty
// again — a timeout is attached to no descriptor, so an armed one keeps the
// instance in the manager's graveyard until it fires.
void proxy_instance::arm_idle_sweep()
{
    if (m_idle_sweep_armed || !m_loop || !m_idle_sweep_timer)
        return;

    m_idle_sweep_armed = true;
    if (SOCKETLEY_UNLIKELY(!m_loop->submit_timeout(&m_idle_sweep_timer->ts,
                                                   &m_idle_sweep_timer->req)))
    {
        m_idle_sweep_armed = false;
        // Once per run.  release_to_pool() calls this on a hot path, and a ring
        // that is full stays full for a while — reporting every attempt would
        // bury the log under one message per pooled connection.
        if (!m_idle_sweep_warned)
        {
            m_idle_sweep_warned = true;
            LOG_ERROR("proxy: idle sweep timer refused — idle connections and pooled "
                      "backend sockets will not be reclaimed");
        }
    }
}

// Return a backend fd to the pool for later reuse
void proxy_instance::release_to_pool(int backend_fd, size_t backend_idx)
{
    if (backend_fd < 0 || backend_idx >= m_backend_pool.size())
        return;

    auto& pool = m_backend_pool[backend_idx];
    if (pool.size() >= MAX_POOL_PER_BACKEND)
    {
        // Pool full — close the oldest (swap with last, then pop)
        if (pool.front().fd >= 0)
        {
            shutdown(pool.front().fd, SHUT_RDWR);
            close(pool.front().fd);
        }
        pool.front() = std::move(pool.back());
        pool.pop_back();
    }

    pool.push_back({backend_fd, backend_idx, std::chrono::steady_clock::now()});

    // Something is in the pool now, so there is something for the sweep to
    // reclaim.  No-op while it is already running.
    arm_idle_sweep();
}

// Finish setting up backend after connect (pooled or async connect completion).
// Creates backend conn struct, registers in maps, sets up splice/read.
// Returns true if backend is ready. connect_pending will be false.
bool proxy_instance::connect_to_backend(proxy_client_connection* conn, const backend_info* target,
                                       bool* resource_failure)
{
    // Local helper: mark this as our own shortage rather than the backend's fault.
    const auto ours = [resource_failure]() { if (resource_failure) *resource_failure = true; };
    if (SOCKETLEY_UNLIKELY(!target || target->resolved_port == 0))
        return false;

    int bfd = -1;

    // Try connection pool first (both TCP and HTTP, non-group backends).
    // A group-routed connection must not touch the pool: its backend_idx still
    // points at the group entry, so it would hand back a connection to some
    // other endpoint entirely.
    if (!target->is_group && !conn->backend_from_group && conn->backend_idx < m_backend_pool.size())
    {
        bfd = acquire_pooled_backend(conn->backend_idx);
    }

    if (bfd >= 0)
    {
        // Got pooled connection — set up immediately (no async connect)
        if (SOCKETLEY_UNLIKELY(bfd >= MAX_FDS))
        {
            close(bfd);
            return false;
        }

        conn->backend_fd = bfd;

        auto bconn = backend_pool_acquire(bfd);
        bconn->client_fd = conn->fd;
        bconn->read_req = { this, bconn->read_buf, bfd, sizeof(bconn->read_buf), op_read,
                            bconn->generation };
        bconn->write_req = { this, nullptr, bfd, 0, op_write };
        bconn->splice_in_req = { this, nullptr, bfd, 0, op_splice };
        bconn->splice_out_req = { this, nullptr, bfd, 0, op_splice };

        auto* ptr = bconn.get();
        m_backend_slots[bfd] = std::move(bconn);
        m_backend_count++;
        m_conn_idx[bfd].side = conn_backend;
        m_conn_idx[bfd].backend = ptr;

        // Set up splice for TCP mode
        if (m_protocol == protocol_tcp && m_splice_supported &&
            !m_cb_on_proxy_request && !m_cb_on_proxy_response)
        {
#ifndef SOCKETLEY_NO_LUA
            auto* lctx = lua();
            bool has_lua_hooks = lctx && (lctx->has_on_proxy_request() || lctx->has_on_proxy_response());
#else
            bool has_lua_hooks = false;
#endif
            if (!has_lua_hooks)
            {
                setup_splice_pipes(conn, ptr);
                if (conn->splice_active)
                {
                    start_splice_forwarding(conn, ptr);
                    return true;
                }
            }
        }

        if (SOCKETLEY_UNLIKELY(!submit_read_op_backend(m_loop, bfd, ptr, m_recv_multishot,
                                                       m_use_provided_bufs, BUF_GROUP_ID)))
        {
            // Give up the backend only.  Every caller of this function keeps
            // working with conn after a false return — closing the pair here
            // would hand them a freed connection — so this looks to them
            // exactly like any other failed connect.
            //
            // The client's half of the splice pipeline goes with it.  Only the
            // backend's pipe used to be closed here, and setup_splice_pipes()
            // writes straight into pipe_to_backend[] without looking at what is
            // already there — so the next attempt on this same client
            // overwrote two live descriptors with two new ones, and the pair it
            // replaced was in no index for teardown to find.
            if (ptr->pipe_to_client[0] >= 0) close(ptr->pipe_to_client[0]);
            if (ptr->pipe_to_client[1] >= 0) close(ptr->pipe_to_client[1]);
            ptr->pipe_to_client[0] = -1;
            ptr->pipe_to_client[1] = -1;
            if (conn->pipe_to_backend[0] >= 0) close(conn->pipe_to_backend[0]);
            if (conn->pipe_to_backend[1] >= 0) close(conn->pipe_to_backend[1]);
            conn->pipe_to_backend[0] = -1;
            conn->pipe_to_backend[1] = -1;
            conn->splice_active = false;
            conn->backend_fd = -1;
            close_pair_close_backend(bfd, ptr, conn);
            ours();
            return false;
        }

        return true;  // connect_pending stays false
    }

    // No pooled connection — resolve address and submit async connect
    struct sockaddr_in addr{};
    if (target->has_cached_addr)
    {
        addr = target->cached_addr;
    }
    else
    {
        // Slow path: getaddrinfo for hostname resolution (Docker DNS, etc.)
        char port_str[8];
        auto [pend, pec] = std::to_chars(port_str, port_str + sizeof(port_str), target->resolved_port);
        *pend = '\0';

        struct addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        struct addrinfo* result = nullptr;
        if (getaddrinfo(target->resolved_host.c_str(), port_str, &hints, &result) != 0 || !result)
            return false;

        if (result->ai_family == AF_INET && result->ai_addrlen == sizeof(struct sockaddr_in))
            std::memcpy(&addr, result->ai_addr, sizeof(addr));

        // Cache for future connections
        auto* mutable_target = const_cast<backend_info*>(target);
        std::memcpy(&mutable_target->cached_addr, result->ai_addr, sizeof(struct sockaddr_in));
        mutable_target->has_cached_addr = true;

        freeaddrinfo(result);

        if (addr.sin_family == 0)
            return false;
    }

    bfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (bfd < 0)
        return false;

    if (SOCKETLEY_UNLIKELY(bfd >= MAX_FDS))
    {
        close(bfd);
        return false;
    }

    tune_socket(bfd);

    // Try synchronous connect first — on loopback this often succeeds instantly
    // (returns 0), avoiding a full io_uring round-trip. If EINPROGRESS, fall back
    // to async io_uring connect where handle_connect() finishes the setup.
    int cr = ::connect(bfd, reinterpret_cast<const struct sockaddr*>(&addr), sizeof(addr));
    if (cr == 0)
    {
        // Instant connect success — set up backend inline (same as handle_connect)
        conn->backend_fd = bfd;

        auto bconn = backend_pool_acquire(bfd);
        bconn->client_fd = conn->fd;
        bconn->read_req = { this, bconn->read_buf, bfd, sizeof(bconn->read_buf), op_read,
                            bconn->generation };
        bconn->write_req = { this, nullptr, bfd, 0, op_write };
        bconn->splice_in_req = { this, nullptr, bfd, 0, op_splice };
        bconn->splice_out_req = { this, nullptr, bfd, 0, op_splice };

        auto* ptr = bconn.get();
        m_backend_slots[bfd] = std::move(bconn);
        m_backend_count++;
        m_conn_idx[bfd].side = conn_backend;
        m_conn_idx[bfd].backend = ptr;

        // Set up splice for TCP mode
        if (m_protocol == protocol_tcp && m_splice_supported &&
            !m_cb_on_proxy_request && !m_cb_on_proxy_response)
        {
#ifndef SOCKETLEY_NO_LUA
            auto* lctx = lua();
            bool has_lua_hooks = lctx && (lctx->has_on_proxy_request() || lctx->has_on_proxy_response());
#else
            bool has_lua_hooks = false;
#endif
            if (!has_lua_hooks)
            {
                setup_splice_pipes(conn, ptr);
                if (conn->splice_active)
                {
                    // Forward saved data before splice takes over
                    if (!conn->saved_request.empty())
                    {
                        forward_to_backend(conn, conn->saved_request);
                        conn->saved_request.clear();
                    }
                    // Only queued, not written yet — see handle_connect.
                    if (!ptr->write_pending && ptr->write_queue.empty())
                        start_splice_forwarding(conn, ptr);
                    return true;  // connect_pending stays false, splice handles data flow
                }
            }
        }

        // Submit read on backend
        if (SOCKETLEY_UNLIKELY(!submit_read_op_backend(m_loop, bfd, ptr, m_recv_multishot,
                                                       m_use_provided_bufs, BUF_GROUP_ID)))
        {
            // Give up the backend only.  Every caller of this function keeps
            // working with conn after a false return — closing the pair here
            // would hand them a freed connection — so this looks to them
            // exactly like any other failed connect.
            //
            // The client's half of the splice pipeline goes with it.  Only the
            // backend's pipe used to be closed here, and setup_splice_pipes()
            // writes straight into pipe_to_backend[] without looking at what is
            // already there — so the next attempt on this same client
            // overwrote two live descriptors with two new ones, and the pair it
            // replaced was in no index for teardown to find.
            if (ptr->pipe_to_client[0] >= 0) close(ptr->pipe_to_client[0]);
            if (ptr->pipe_to_client[1] >= 0) close(ptr->pipe_to_client[1]);
            ptr->pipe_to_client[0] = -1;
            ptr->pipe_to_client[1] = -1;
            if (conn->pipe_to_backend[0] >= 0) close(conn->pipe_to_backend[0]);
            if (conn->pipe_to_backend[1] >= 0) close(conn->pipe_to_backend[1]);
            conn->pipe_to_backend[0] = -1;
            conn->pipe_to_backend[1] = -1;
            conn->splice_active = false;
            conn->backend_fd = -1;
            close_pair_close_backend(bfd, ptr, conn);
            ours();
            return false;
        }

        return true;  // connect_pending stays false — caller forwards saved_request
    }

    if (cr < 0 && errno != EINPROGRESS)
    {
        close(bfd);
        return false;
    }

    // EINPROGRESS — the kernel is already completing the handshake for the
    // socket we just called connect() on.  Waiting for it means polling for
    // writability, not issuing a second connect: io_uring runs that against an
    // fd that is already connected and answers EISCONN, and that completion was
    // then dropped rather than acted on, leaving the connection wedged.
    conn->connect_pending = true;
    conn->connect_fd = bfd;
    conn->connect_addr = addr;
    conn->connect_req = { this, nullptr, conn->fd, 0, op_poll, conn->generation };

    if (SOCKETLEY_UNLIKELY(!m_loop->submit_poll_add(bfd, POLLOUT, &conn->connect_req)))
    {
        close(bfd);
        conn->connect_fd = -1;
        conn->connect_pending = false;
        ours();
        return false;
    }

    return true;  // connect_pending = true — caller must check
}

void proxy_instance::setup_splice_pipes(proxy_client_connection* conn, proxy_backend_connection* bconn)
{
    // Create pipe for client -> backend direction
    if (pipe2(conn->pipe_to_backend, O_NONBLOCK) < 0)
        return;

    // Create pipe for backend -> client direction
    if (pipe2(bconn->pipe_to_client, O_NONBLOCK) < 0)
    {
        close(conn->pipe_to_backend[0]);
        close(conn->pipe_to_backend[1]);
        conn->pipe_to_backend[0] = -1;
        conn->pipe_to_backend[1] = -1;
        return;
    }

    // Increase pipe buffer sizes for throughput
    if (fcntl(conn->pipe_to_backend[0], F_SETPIPE_SZ, SPLICE_PIPE_SIZE) < 0) {}
    if (fcntl(bconn->pipe_to_client[0], F_SETPIPE_SZ, SPLICE_PIPE_SIZE) < 0) {}

    conn->splice_active = true;
    bconn->splice_active = true;
}

void proxy_instance::start_splice_forwarding(proxy_client_connection* conn, proxy_backend_connection* bconn)
{
    if (!m_loop || !conn->splice_active || !bconn->splice_active)
        return;

    // Client -> pipe_write (first leg of client -> backend).
    //
    // Not while a userspace read is still in flight: that read's data goes to
    // the backend through the write queue, and the pipe would carry newer bytes
    // to the same socket at the same time.  Two independent writers on one
    // connection is exactly how later data ends up ahead of earlier data.
    // handle_client_read starts the pipeline once the read has been consumed.
    if (!conn->splice_in_pending && !conn->read_pending)
    {
        conn->splice_in_pending = true;
        if (SOCKETLEY_UNLIKELY(!m_loop->submit_splice(conn->fd, conn->pipe_to_backend[1],
                              PROXY_READ_BUF_SIZE, &conn->splice_in_req)))
        {
            conn->splice_in_pending = false;
            close_pair(conn->fd, conn->backend_fd);
            return;
        }
    }

    // Backend -> pipe_write (first leg of backend -> client)
    if (!bconn->splice_in_pending)
    {
        bconn->splice_in_pending = true;
        if (SOCKETLEY_UNLIKELY(!m_loop->submit_splice(bconn->fd, bconn->pipe_to_client[1],
                              PROXY_READ_BUF_SIZE, &bconn->splice_in_req)))
        {
            bconn->splice_in_pending = false;
            close_pair(bconn->client_fd, bconn->fd);
            return;
        }
    }
}

void proxy_instance::handle_splice(struct io_uring_cqe* cqe, io_request* req)
{
    if (SOCKETLEY_UNLIKELY(req->fd < 0 || req->fd >= MAX_FDS))
        return;

    auto& entry = m_conn_idx[req->fd];

    if (entry.side == conn_client)
    {
        auto* conn = entry.client;

        // Determine which splice op completed
        if (req == &conn->splice_in_req)
        {
            conn->splice_in_pending = false;
            SKL_TRACE_SET(conn, last_splice_res, cqe->res);
            SKL_TRACE_SET(conn, splice_leg, entry.side == conn_client ? 1u : 3u);
            if (cqe->res > 0) { SKL_TRACE_ADD(conn, spliced, (unsigned long long)cqe->res); SKL_TRACE_ADD(conn, sp_in, (unsigned long long)cqe->res); }

            if (SOCKETLEY_UNLIKELY(cqe->res <= 0))
            {
                // EAGAIN: pipe full or socket has no data yet — retry
                if (cqe->res == -EAGAIN && !conn->closing)
                {
                    conn->splice_in_pending = true;
                    if (SOCKETLEY_UNLIKELY(!m_loop->submit_splice(conn->fd, conn->pipe_to_backend[1],
                                          PROXY_READ_BUF_SIZE, &conn->splice_in_req)))
                    {
                        conn->splice_in_pending = false;
                        close_pair(conn->fd, conn->backend_fd);
                        return;
                    }
                    return;
                }
                close_pair(conn->fd, conn->backend_fd);
                return;
            }

            // Data is now in pipe_to_backend — splice it out to the backend fd
            if (conn->backend_fd >= 0)
            {
                conn->splice_out_pending = true;
                if (SOCKETLEY_UNLIKELY(!m_loop->submit_splice(conn->pipe_to_backend[0], conn->backend_fd,
                                      static_cast<uint32_t>(cqe->res), &conn->splice_out_req)))
                {
                    conn->splice_out_pending = false;
                    close_pair(conn->fd, conn->backend_fd);
                    return;
                }
            }
            else
            {
                // No backend to deliver to.  There used to be no else here, and
                // falling through was fatal: splice_in_pending had just been
                // cleared and nothing new was armed, so no completion was owed —
                // and since every teardown in this runtime runs out of a
                // completion handler, the connection was never torn down at all.
                // Its descriptors stayed until the runtime stopped.
                close_pair(conn->fd, -1);
                return;
            }
        }
        else if (req == &conn->splice_out_req)
        {
            if (cqe->res > 0) SKL_TRACE_ADD(conn, sp_out, (unsigned long long)cqe->res);
            conn->splice_out_pending = false;
            SKL_TRACE_SET(conn, last_splice_res, cqe->res);
            SKL_TRACE_SET(conn, splice_leg, entry.side == conn_client ? 2u : 4u);

            if (SOCKETLEY_UNLIKELY(cqe->res <= 0))
            {
                // EAGAIN: backend send buffer full — retry
                if (cqe->res == -EAGAIN && !conn->closing && conn->backend_fd >= 0)
                {
                    conn->splice_out_pending = true;
                    if (SOCKETLEY_UNLIKELY(!m_loop->submit_splice(conn->pipe_to_backend[0], conn->backend_fd,
                                          PROXY_READ_BUF_SIZE, &conn->splice_out_req)))
                    {
                        conn->splice_out_pending = false;
                        close_pair(conn->fd, conn->backend_fd);
                        return;
                    }
                    return;
                }
                close_pair(conn->fd, conn->backend_fd);
                return;
            }

            // Same on this leg: what a partial splice left in the pipe has to go
            // out before anything else happens, or it is lost.
            int pipe_left = 0;
            if (conn->pipe_to_backend[0] >= 0)
                ioctl(conn->pipe_to_backend[0], FIONREAD, &pipe_left);
            if (pipe_left > 0 && conn->backend_fd >= 0)
            {
                conn->splice_out_pending = true;
                if (SOCKETLEY_UNLIKELY(!m_loop->submit_splice(conn->pipe_to_backend[0], conn->backend_fd,
                                      static_cast<uint32_t>(pipe_left), &conn->splice_out_req)))
                {
                    conn->splice_out_pending = false;
                    close_pair(conn->fd, conn->backend_fd);
                    return;
                }
                return;
            }

            // Resubmit the inbound splice (client -> pipe)
            if (SOCKETLEY_LIKELY(!conn->closing))
            {
                conn->splice_in_pending = true;
                if (SOCKETLEY_UNLIKELY(!m_loop->submit_splice(conn->fd, conn->pipe_to_backend[1],
                                      PROXY_READ_BUF_SIZE, &conn->splice_in_req)))
                {
                    conn->splice_in_pending = false;
                    close_pair(conn->fd, conn->backend_fd);
                    return;
                }
            }
            else
            {
                close_pair(conn->fd, conn->backend_fd);
            }
        }
    }
    else if (entry.side == conn_backend)
    {
        auto* conn = entry.backend;

        if (req == &conn->splice_in_req)
        {
            conn->splice_in_pending = false;
            SKL_TRACE_SET(conn, last_splice_res, cqe->res);
            SKL_TRACE_SET(conn, splice_leg, entry.side == conn_client ? 1u : 3u);
            if (cqe->res > 0) { SKL_TRACE_ADD(conn, spliced, (unsigned long long)cqe->res); SKL_TRACE_ADD(conn, sp_in, (unsigned long long)cqe->res); }

            if (SOCKETLEY_UNLIKELY(cqe->res <= 0))
            {
                // EAGAIN: pipe full or backend has no data yet — retry
                if (cqe->res == -EAGAIN && !conn->closing)
                {
                    conn->splice_in_pending = true;
                    if (SOCKETLEY_UNLIKELY(!m_loop->submit_splice(conn->fd, conn->pipe_to_client[1],
                                          PROXY_READ_BUF_SIZE, &conn->splice_in_req)))
                    {
                        conn->splice_in_pending = false;
                        close_pair(conn->client_fd, conn->fd);
                        return;
                    }
                    return;
                }
                close_pair(conn->client_fd, conn->fd);
                return;
            }

            // Data is now in pipe_to_client — splice it out to the client fd.
            // Only ever into a client that still names us as its backend: a
            // descriptor alone does not prove identity once fd numbers are reused.
            if (conn->client_fd >= 0 && conn->client_fd < MAX_FDS &&
                m_conn_idx[conn->client_fd].side == conn_client &&
                m_conn_idx[conn->client_fd].client->backend_fd == conn->fd)
            {
                conn->splice_out_pending = true;
                if (SOCKETLEY_UNLIKELY(!m_loop->submit_splice(conn->pipe_to_client[0], conn->client_fd,
                                      static_cast<uint32_t>(cqe->res), &conn->splice_out_req)))
                {
                    conn->splice_out_pending = false;
                    close_pair(conn->client_fd, conn->fd);
                    return;
                }
            }
            else
            {
                // Same hole in this direction, and this is the one the churn
                // measurement hit: thousands of backends outliving a client that
                // had aborted, each left with nothing in flight and therefore
                // unreachable for the lifetime of the runtime.  Only the backend
                // goes — whatever sits at client_fd is either gone or somebody
                // else's, which is precisely why we are here.
                close_pair(-1, conn->fd);
                return;
            }
        }
        else if (req == &conn->splice_out_req)
        {
            if (cqe->res > 0) SKL_TRACE_ADD(conn, sp_out, (unsigned long long)cqe->res);
            conn->splice_out_pending = false;
            SKL_TRACE_SET(conn, last_splice_res, cqe->res);
            SKL_TRACE_SET(conn, splice_leg, entry.side == conn_client ? 2u : 4u);

            if (SOCKETLEY_UNLIKELY(cqe->res <= 0))
            {
                // EAGAIN: client send buffer full — retry
                if (cqe->res == -EAGAIN && !conn->closing && conn->client_fd >= 0)
                {
                    conn->splice_out_pending = true;
                    if (SOCKETLEY_UNLIKELY(!m_loop->submit_splice(conn->pipe_to_client[0], conn->client_fd,
                                          PROXY_READ_BUF_SIZE, &conn->splice_out_req)))
                    {
                        conn->splice_out_pending = false;
                        close_pair(conn->client_fd, conn->fd);
                        return;
                    }
                    return;
                }
                close_pair(conn->client_fd, conn->fd);
                return;
            }

            // A splice can move fewer bytes than the pipe holds.  Whatever stays
            // there is in neither a socket buffer nor a write queue, so going
            // back to the inbound leg — or closing — simply loses it.  Drain the
            // pipe first; only then continue.
            int pipe_left = 0;
            if (conn->pipe_to_client[0] >= 0)
                ioctl(conn->pipe_to_client[0], FIONREAD, &pipe_left);
            if (pipe_left > 0 && conn->client_fd >= 0)
            {
                conn->splice_out_pending = true;
                if (SOCKETLEY_UNLIKELY(!m_loop->submit_splice(conn->pipe_to_client[0], conn->client_fd,
                                      static_cast<uint32_t>(pipe_left), &conn->splice_out_req)))
                {
                    conn->splice_out_pending = false;
                    close_pair(conn->client_fd, conn->fd);
                    return;
                }
                return;
            }

            // Resubmit the inbound splice (backend -> pipe)
            if (SOCKETLEY_LIKELY(!conn->closing))
            {
                conn->splice_in_pending = true;
                if (SOCKETLEY_UNLIKELY(!m_loop->submit_splice(conn->fd, conn->pipe_to_client[1],
                                      PROXY_READ_BUF_SIZE, &conn->splice_in_req)))
                {
                    conn->splice_in_pending = false;
                    close_pair(conn->client_fd, conn->fd);
                    return;
                }
            }
            else
            {
                close_pair(conn->client_fd, conn->fd);
            }
        }
    }
}

// Helper: check if a backend fd is eligible for connection pooling
static inline bool backend_pool_eligible(const proxy_backend_connection* bconn,
                                          const proxy_client_connection* cconn,
                                          const std::vector<backend_info>& backends,
                                          proxy_protocol protocol)
{
    // Only pool HTTP connections — TCP connections are long-lived streams
    if (protocol != protocol_http)
        return false;
    if (bconn->closing || bconn->splice_active)
        return false;
    if (!bconn->write_queue.empty() || bconn->write_batch_count > 0)
        return false;
    if (bconn->pipe_to_client[0] >= 0)
        return false;
    // Don't pool if backend signalled Connection: close
    if (bconn->http_conn_close)
        return false;
    if (!cconn)
        return false;
    // Group-routed connections carry a per-connection endpoint that backend_idx
    // does not describe; pooling one would file it under an unrelated backend.
    if (cconn->backend_from_group)
        return false;
    size_t idx = cconn->backend_idx;
    if (idx >= backends.size() || backends[idx].is_group)
        return false;
    return true;
}

// Helper: close or pool a backend fd (no pending ops case)
inline void proxy_instance::close_pair_close_backend(int backend_fd,
                                                      proxy_backend_connection* bconn,
                                                      proxy_client_connection* cconn)
{
    // Check pool eligibility
    bool can_pool = cconn && backend_pool_eligible(bconn, cconn, m_backends, m_protocol);

    m_conn_idx[backend_fd] = {};

    if (can_pool)
    {
        // Release fd to pool — pool takes ownership, don't close
        release_to_pool(backend_fd, cconn->backend_idx);
    }
    else
    {
        shutdown(backend_fd, SHUT_RDWR);
        close(backend_fd);
    }

    if (m_backend_slots[backend_fd])
    {
        // The owners are backend_pool_release()'s business: it keeps them
        // pointing here for anything the ring has not finished with, and clears
        // them for what it puts back in the pool.  Clearing them from out here
        // took away the only way a late completion could be recognised.
        backend_pool_release(std::move(m_backend_slots[backend_fd]));
        m_backend_count--;
    }
}

void proxy_instance::close_pair(int client_fd, int backend_fd)
{
    // Find client conn for pool-eligibility checks
    proxy_client_connection* client_for_pool = nullptr;
    if (client_fd >= 0 && client_fd < MAX_FDS && m_conn_idx[client_fd].side == conn_client)
        client_for_pool = m_conn_idx[client_fd].client;

    if (backend_fd >= 0 && backend_fd < MAX_FDS)
    {
        auto& be = m_conn_idx[backend_fd];
        if (be.side == conn_backend)
        {
            auto* bconn = be.backend;
            // Deferring is only right while something is actually in flight.  If
            // the flush below cannot reach the ring there will be no completion
            // to finish the teardown, and the connection would sit here until
            // the idle sweep reaps it — so that case falls through to the
            // immediate teardown instead.
            // zc_notif_pending belongs in this list: a zero-copy send answers
            // twice and clears write_pending on the first of them, so the flag
            // on its own says "finished" while the kernel is still DMA-ing out
            // of write_batch[0] — which reset() clears the moment the struct is
            // handed on, and the fd may already be serving a new request out of
            // the pool.  One 512 KB message is enough, which is a routine HTTP
            // body.
            bool defer = bconn->read_pending || bconn->write_pending ||
                         bconn->zc_notif_pending ||
                         bconn->splice_in_pending || bconn->splice_out_pending ||
                         !bconn->write_queue.empty();
            if (defer)
            {
                // A queue that still holds data is as good a reason to defer as an
                // operation in flight: closing here throws away bytes the client
                // already handed us and considers delivered.  Keep the write side
                // open and push them out; the write completion tears down once the
                // queue has actually drained.
                bconn->closing = true;
                if (!bconn->write_pending && !bconn->write_queue.empty() &&
                    !flush_backend_write_queue(bconn))
                    defer = false;
                else
                    shutdown(backend_fd, SHUT_RD);
            }
            if (!defer)
            {
                // Clear the stale reference on the client side
                if (bconn->client_fd >= 0 && bconn->client_fd < MAX_FDS)
                {
                    auto& ce = m_conn_idx[bconn->client_fd];
                    if (ce.side == conn_client)
                        ce.client->backend_fd = -1;
                }

                // Close splice pipes
                if (bconn->pipe_to_client[0] >= 0) close(bconn->pipe_to_client[0]);
                if (bconn->pipe_to_client[1] >= 0) close(bconn->pipe_to_client[1]);
                bconn->pipe_to_client[0] = -1;
                bconn->pipe_to_client[1] = -1;

                close_pair_close_backend(backend_fd, bconn, client_for_pool);
            }
        }
    }

    if (client_fd >= 0 && client_fd < MAX_FDS)
    {
        auto& ce = m_conn_idx[client_fd];
        if (ce.side == conn_client)
        {
            auto* conn = ce.client;

            // Also close the other side of the pair
            if (conn->backend_fd >= 0 && conn->backend_fd != backend_fd && conn->backend_fd < MAX_FDS)
            {
                auto& be2 = m_conn_idx[conn->backend_fd];
                if (be2.side == conn_backend)
                {
                    auto* bconn2 = be2.backend;
                    // Same list as above, zero-copy notification included.
                    bool defer2 = bconn2->read_pending || bconn2->write_pending ||
                                  bconn2->zc_notif_pending ||
                                  bconn2->splice_in_pending || bconn2->splice_out_pending ||
                                  !bconn2->write_queue.empty();
                    if (defer2)
                    {
                        bconn2->closing = true;
                        if (!bconn2->write_pending && !bconn2->write_queue.empty() &&
                            !flush_backend_write_queue(bconn2))
                            defer2 = false;
                        else
                            shutdown(conn->backend_fd, SHUT_RD);
                    }
                    if (!defer2)
                    {
                        // Close splice pipes
                        if (bconn2->pipe_to_client[0] >= 0) close(bconn2->pipe_to_client[0]);
                        if (bconn2->pipe_to_client[1] >= 0) close(bconn2->pipe_to_client[1]);
                        bconn2->pipe_to_client[0] = -1;
                        bconn2->pipe_to_client[1] = -1;

                        close_pair_close_backend(conn->backend_fd, bconn2, conn);
                    }
                }
                conn->backend_fd = -1;
            }

            // Close pending async connect fd.  The POLLOUT armed on it is not
            // taken back by the close — the poll holds its own reference to the
            // file — so cancel it to get the completion now rather than when
            // TCP eventually gives up.  connect_pending stays set on purpose:
            // it is what tells client_pool_release() that this struct cannot be
            // reused yet.
            if (conn->connect_fd >= 0)
            {
                if (m_loop) m_loop->submit_cancel_fd(conn->connect_fd);
                close(conn->connect_fd);
                conn->connect_fd = -1;
            }

            // Zero-copy notification included, for the reason given on the
            // backend side above.
            bool defer_c = conn->read_pending || conn->write_pending ||
                           conn->zc_notif_pending ||
                           conn->splice_in_pending || conn->splice_out_pending ||
                           !conn->write_queue.empty();
            if (defer_c)
            {
                conn->closing = true;
                if (!conn->write_pending && !conn->write_queue.empty() &&
                    !flush_client_write_queue(conn))
                    defer_c = false;
                else
                    shutdown(client_fd, SHUT_RD);
            }
            if (!defer_c)
            {
                invoke_on_disconnect(client_fd);

                // Close splice pipes
                if (conn->pipe_to_backend[0] >= 0) close(conn->pipe_to_backend[0]);
                if (conn->pipe_to_backend[1] >= 0) close(conn->pipe_to_backend[1]);
                conn->pipe_to_backend[0] = -1;
                conn->pipe_to_backend[1] = -1;

#ifdef SOCKETLEY_TRACE
                // One report per connection, at the point it actually goes away.
                // Emitting it on every close_pair call produced snapshots of a
                // teardown still in progress, which is worse than no number at
                // all.  "unread" is the discriminator: bytes still sitting in
                // the socket when we close are bytes the client believes it
                // delivered, and its next write will fail.
                {
                    [[maybe_unused]] int unread = 0;
                    ioctl(client_fd, FIONREAD, &unread);
                    [[maybe_unused]] unsigned long long be_spliced = 0;
                    [[maybe_unused]] long long be_owed = 0;
                    if (conn->backend_fd >= 0 && conn->backend_fd < MAX_FDS &&
                        m_conn_idx[conn->backend_fd].side == conn_backend)
                    {
                        [[maybe_unused]] auto* tb = m_conn_idx[conn->backend_fd].backend;
                        be_owed = (long long)(tb->tr.bytes_queued - tb->tr.bytes_written);
                    }
                    [[maybe_unused]] unsigned long long be_in = 0, be_out = 0;
                    [[maybe_unused]] int pipe_c = 0, pipe_b = 0, unread_b = 0;
                    if (conn->pipe_to_backend[0] >= 0)
                        ioctl(conn->pipe_to_backend[0], FIONREAD, &pipe_c);
                    if (conn->backend_fd >= 0 && conn->backend_fd < MAX_FDS &&
                        m_conn_idx[conn->backend_fd].side == conn_backend)
                    {
                        [[maybe_unused]] auto* tb2 = m_conn_idx[conn->backend_fd].backend;
                        be_in = tb2->tr.sp_in; be_out = tb2->tr.sp_out;
                        if (tb2->pipe_to_client[0] >= 0)
                            ioctl(tb2->pipe_to_client[0], FIONREAD, &pipe_b);
                        ioctl(conn->backend_fd, FIONREAD, &unread_b);
                    }
                    // Conservation: c_in == c_out + pipe_c, and be_in == be_out + pipe_b.
                    // Whichever equation fails names the hop the bytes vanished on.
                    SKL_TRACE_LOG("final cfd=%d life=%.1fms | c_in=%llu c_out=%llu pipe_c=%d "
                                  "| be_in=%llu be_out=%llu pipe_b=%d "
                                  "| unread_c=%d unread_b=%d owed=%lld sres=%d leg=%u rres=%d",
                        client_fd, ::skl_trace::now_ms() - conn->tr.opened_ms,
                        (unsigned long long)conn->tr.sp_in, (unsigned long long)conn->tr.sp_out, pipe_c,
                        be_in, be_out, pipe_b,
                        unread, unread_b, be_owed,
                        conn->tr.last_splice_res, conn->tr.splice_leg,
                        conn->tr.last_read_res);
                }

#endif
                // Drop every back-reference to this descriptor before it goes
                // back to the kernel.  The detach used to be one-sided: tearing
                // the backend down clears the client's backend_fd, but a client
                // that dies first leaves a deferred backend still holding
                // client_fd.  The number is reused by the next accept within
                // microseconds, and the stale backend then splices its data into
                // a stranger's socket and takes that connection down with it when
                // it sees EOF — a healthy client killed mid-transfer, with no
                // error recorded anywhere.
                for (int cand : { backend_fd, conn->backend_fd })
                {
                    if (cand < 0 || cand >= MAX_FDS) continue;
                    auto& bslot = m_conn_idx[cand];
                    if (bslot.side == conn_backend && bslot.backend->client_fd == client_fd)
                        bslot.backend->client_fd = -1;
                }

                shutdown(client_fd, SHUT_RDWR);
                close(client_fd);
                m_conn_idx[client_fd] = {};
                if (m_client_slots[client_fd])
                {
                    // See close_pair_close_backend: the owners belong to the
                    // release path.  This one used to null three of the five and
                    // leave both splice requests pointing at a struct that went
                    // straight back into the pool.
                    client_pool_release(std::move(m_client_slots[client_fd]));
                    m_client_count--;
                }
            }
        }
    }
}

// Detach backend from client and release to connection pool (HTTP response complete)
void proxy_instance::detach_and_pool_backend(proxy_client_connection* cconn, int backend_fd)
{
    if (backend_fd < 0 || backend_fd >= MAX_FDS)
        return;

    auto& be = m_conn_idx[backend_fd];
    if (be.side != conn_backend)
        return;

    auto* bconn = be.backend;

    // A backend read is armed essentially all of the time — under multishot
    // recv it stays armed across completions — so "no pending ops" was almost
    // never true here and the connection was thrown away after every response.
    // A read is the one operation that can be taken back: it owns nothing but
    // the connection's own buffer, and cancelling it costs no data because the
    // response is already complete.  Writes, zero-copy notifications and
    // splices are not cancellable this way; their buffers and pipes have to
    // outlive them, so those still cost the connection.
    const bool only_read_pending =
        bconn->read_pending && !bconn->write_pending && !bconn->zc_notif_pending &&
        !bconn->splice_in_pending && !bconn->splice_out_pending;

    // submit_cancel_fd is the last condition on purpose: a refused submission
    // must leave no trace, because there would be no completion to finish what
    // it started and the connection would sit in a half-detached state until
    // the runtime stops.  Nothing below is touched unless it reached the ring.
    if (only_read_pending && m_loop &&
        backend_pool_eligible(bconn, cconn, m_backends, m_protocol) &&
        m_loop->submit_cancel_fd(backend_fd))
    {
        // The fd stays registered and the struct stays alive until that
        // cancellation has been accounted for; only then is it safe to pool
        // either.  Handing the fd over now would let the next request pick it
        // up while a completion still points at the struct behind it.
        bconn->pool_draining = true;
        bconn->pool_abandoned = false;
        bconn->pool_backend_idx = cconn->backend_idx;

        // The client is released immediately — it has its full response and
        // should not wait a round trip for the backend's paperwork.  Its next
        // request takes whatever the pool offers by then, which is why the
        // backend has to carry its own pool index from here on.
        bconn->client_fd = -1;
        cconn->backend_fd = -1;
        reset_client_for_next_request(cconn);
        return;
    }

    // Cannot pool if there are pending io_uring ops — CQEs would arrive for a
    // pooled (unregistered) fd, causing UAF or misrouted completions.
    if (bconn->read_pending || bconn->write_pending || bconn->zc_notif_pending ||
        bconn->splice_in_pending || bconn->splice_out_pending)
    {
        // The backend cannot be pooled while a completion is still owed to it.
        // That is no reason to take the client with it: it negotiated
        // keep-alive, its response has been delivered in full, and it has done
        // nothing wrong.  Closing the pair here ended the client connection
        // after every single response — and since a backend read is armed
        // essentially all the time, this branch is the one that runs, so
        // keep-alive through the proxy never worked and every request paid for
        // a fresh TCP handshake.
        //
        // Detach the two and let the backend go on its own.  Its pending
        // completion arrives with client_fd already cleared, so the teardown
        // that follows touches only the backend.
        cconn->backend_fd = -1;
        bconn->client_fd = -1;
        bconn->closing = true;
        shutdown(backend_fd, SHUT_RDWR);
        reset_client_for_next_request(cconn);
        return;
    }

    size_t b_idx = cconn->backend_idx;

    // Clear tracking
    m_conn_idx[backend_fd] = {};
    cconn->backend_fd = -1;

    // Release fd to pool
    release_to_pool(backend_fd, b_idx);

    // Release struct to struct pool.  Nothing is pending on this path — the
    // check above returned for every case that is — so the release clears all
    // four owners itself; this used to null two of them and leave the splice
    // pair pointing at a struct on its way back into circulation.
    if (m_backend_slots[backend_fd])
    {
        backend_pool_release(std::move(m_backend_slots[backend_fd]));
        m_backend_count--;
    }

    reset_client_for_next_request(cconn);
}

// Last step of handing a finished backend to the pool: consume the completion
// of the read that detach_and_pool_backend cancelled.
//
// Nothing about the fd or the struct may be released before this runs.  A
// pooled fd can be handed to another client on the very next request and a
// released struct to the connection after that, so a completion arriving later
// would be charged to a connection it has nothing to do with — the exact
// use-after-free / misrouted-completion pair this whole detour exists to avoid.
void proxy_instance::finish_pool_drain(proxy_backend_connection* conn,
                                       struct io_uring_cqe* cqe, io_request* req)
{
    const int fd = conn->fd;

    // The buffer belongs to the ring whatever the result says.
    if (cqe->flags & IORING_CQE_F_BUFFER)
    {
        uint16_t buf_id = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
        m_loop->return_buf(BUF_GROUP_ID, buf_id);
    }

    // -ECANCELED is the answer we asked for, and the only one that leaves the
    // connection reusable.  Bytes past the end of the response mean the stream
    // sits at an offset the next request cannot start from; an EOF or error
    // means there is nothing left to reuse at all.  Either way the verdict has
    // to be remembered rather than acted on, because a multishot recv can still
    // owe a terminating completion and the fd must not move until it arrives.
    if (cqe->res != -ECANCELED)
        conn->pool_abandoned = true;

    // Still armed — the completion that ends the read is yet to come.
    if (req->type == op_recv_multishot && (cqe->flags & IORING_CQE_F_MORE))
        return;

    conn->read_pending = false;
    conn->pool_draining = false;

    m_conn_idx[fd] = {};

    // release_to_pool returns without taking the fd when the index is out of
    // range, so asking it to pool one it will refuse leaks the descriptor
    // silently — this is the last owner the fd has.
    if (SOCKETLEY_LIKELY(!conn->pool_abandoned &&
                         conn->pool_backend_idx < m_backend_pool.size()))
    {
        release_to_pool(fd, conn->pool_backend_idx);
    }
    else
    {
        shutdown(fd, SHUT_RDWR);
        close(fd);
    }

    if (m_backend_slots[fd])
    {
        // backend_pool_release() decides whether this can be reused at all; the
        // owners are its business, not the caller's.
        backend_pool_release(std::move(m_backend_slots[fd]));
        m_backend_count--;
    }
}

void proxy_instance::reset_client_for_next_request(proxy_client_connection* cconn)
{
    cconn->header_parsed = false;
    cconn->response_started = false;
    cconn->client_conn_close = false;
    cconn->partial.clear();
    cconn->method.clear();
    cconn->path.clear();
    cconn->version.clear();
    cconn->saved_request.clear();
}

bool proxy_instance::is_backend_available(size_t idx) const
{
    if (SOCKETLEY_UNLIKELY(idx >= m_backends.size()))
        return false;

    // Check health
    if (idx < m_backend_health.size() && !m_backend_health[idx].healthy)
        return false;

    // Check circuit breaker
    if (idx < m_circuit_breakers.size())
    {
        const auto& cb = m_circuit_breakers[idx];
        if (SOCKETLEY_UNLIKELY(cb.current == circuit_breaker::open))
        {
            auto elapsed = std::chrono::steady_clock::now() - cb.opened_at;
            if (elapsed < std::chrono::seconds(m_mesh.circuit_timeout))
                return false;
            // Expired: will transition to half_open on next request
        }
    }

    return true;
}

void proxy_instance::drop_health_check(size_t idx)
{
    if (idx >= m_health_checks.size() || !m_health_checks[idx])
        return;

    auto probe = std::move(m_health_checks[idx]);
    if (probe->fd >= 0)
    {
        // Cancel before closing: an operation still in flight is not taken back
        // by close() — it holds its own reference to the file — and without
        // this its completion could be minutes away, keeping the probe retired
        // for just as long.
        if (probe->op_pending && m_loop)
            m_loop->submit_cancel_fd(probe->fd);
        close(probe->fd);
        probe->fd = -1;
    }

    io_request* owed[1];
    size_t n = 0;
    if (probe->op_pending)
        owed[n++] = &probe->req;
    retire(std::shared_ptr<void>(std::move(probe)), owed, n);
}

void proxy_instance::health_check_sweep()
{
    // Skip if previous checks are still in flight
    if (m_health_checks_pending)
        return;

    m_health_checks_pending = true;

    for (size_t i = 0; i < m_backends.size() && i < m_health_checks.size(); i++)
    {
        auto& b = m_backends[i];

        // Whatever is left in this slot belongs to an earlier sweep.  It is let
        // go rather than reused: reusing it is what let a late completion write
        // into the address the next connect was about to read.
        drop_health_check(i);

        if (b.is_group)
            continue;

        int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (fd < 0)
        {
            if (i < m_backend_health.size())
            {
                auto& health = m_backend_health[i];
                health.consecutive_failures++;
                if (health.consecutive_failures >= m_mesh.health_threshold)
                    health.healthy = false;
                health.last_check = std::chrono::steady_clock::now();
            }
            continue;
        }

        m_health_checks[i] = std::make_unique<async_health_check>();
        auto& hc = *m_health_checks[i];
        hc.backend_idx = i;
        hc.fd = fd;
        hc.current = async_health_check::connecting;
        hc.req = { this, nullptr, fd, 0, op_health_check };

        struct sockaddr_in addr{};
        if (b.has_cached_addr)
        {
            addr = b.cached_addr;
        }
        else
        {
            addr.sin_family = AF_INET;
            addr.sin_port = htons(b.resolved_port);

            // has_cached_addr is only false for a hostname that failed to
            // resolve at setup.  inet_pton cannot parse a hostname and leaves
            // sin_addr zeroed — connecting to 0.0.0.0 reaches localhost, so the
            // check would probe an unrelated local service and record the
            // result as this backend's health.  Skip the check instead and
            // leave the health state untouched; the data path still retries DNS
            // on each connect.
            if (inet_pton(AF_INET, b.resolved_host.c_str(), &addr.sin_addr) != 1)
            {
                close(fd);
                hc.fd = -1;
                m_health_checks[i].reset();
                continue;
            }
        }

        // The kernel reads the address asynchronously, so it lives in the probe
        // for the duration of the connect.  It used to share `buf` with the HTTP
        // response, which meant a late read from an abandoned probe rewrote the
        // address the next connect was about to use.
        hc.write_buf.clear();
        hc.addr = addr;

        // A refused submission is our problem, not the backend's: recording it
        // as a failure would take a healthy backend out of rotation whenever the
        // ring is busy.  The probe is dropped and the next sweep tries again.
        hc.op_pending = true;
        if (SOCKETLEY_UNLIKELY(!m_loop->submit_connect(fd,
                reinterpret_cast<const struct sockaddr*>(&hc.addr),
                sizeof(struct sockaddr_in), &hc.req)))
        {
            close(fd);
            hc.fd = -1;
            hc.op_pending = false;
            m_health_checks[i].reset();
        }
    }

    // A 500 ms deadline of its own for this sweep.  The previous one cannot be
    // cancelled, so if it somehow has not reported yet it is retired rather than
    // written over.
    if (m_health_timeout_timer)
    {
        io_request* owed[1] = { &m_health_timeout_timer->req };
        retire(std::shared_ptr<void>(std::move(m_health_timeout_timer)), owed, 1);
    }
    m_health_timeout_timer = std::make_unique<timer_op>();
    m_health_timeout_timer->ts.tv_sec = 0;
    m_health_timeout_timer->ts.tv_nsec = 500000000LL;
    m_health_timeout_timer->req = { this, nullptr, -1, 0, op_timeout };
    if (SOCKETLEY_UNLIKELY(!m_loop->submit_timeout(&m_health_timeout_timer->ts,
                                                   &m_health_timeout_timer->req)))
    {
        m_health_timeout_timer.reset();
        // Without a deadline nothing would ever clear the pending flag, and the
        // sweep after this one would decline to run at all.
        m_health_checks_pending = false;
        LOG_WARN("proxy: health check deadline timer refused — this sweep has no timeout");
    }
}

void proxy_instance::handle_health_cqe(struct io_uring_cqe* cqe, io_request* req)
{
    // Find which health check this belongs to
    async_health_check* hc = nullptr;
    size_t slot = 0;
    for (size_t i = 0; i < m_health_checks.size(); i++)
    {
        if (m_health_checks[i] && &m_health_checks[i]->req == req)
        {
            hc = m_health_checks[i].get();
            slot = i;
            break;
        }
    }
    if (!hc || hc->current == async_health_check::done || hc->current == async_health_check::idle)
        return;

    // Whatever this completion says, the operation it belongs to is finished.
    hc->op_pending = false;

    size_t idx = hc->backend_idx;

    // Every path below either arms the next step of this probe or finishes it.
    // Finishing means letting the probe go — drop_health_check() closes the
    // socket and releases the state — rather than parking it in `done` for the
    // next sweep to write over while its last operation is still in flight.
    const auto record = [&](bool ok) {
        if (idx >= m_backend_health.size())
            return;
        auto& health = m_backend_health[idx];
        if (ok)
        {
            health.consecutive_failures = 0;
            health.healthy = true;
        }
        else
        {
            health.consecutive_failures++;
            if (health.consecutive_failures >= m_mesh.health_threshold)
                health.healthy = false;
        }
        health.last_check = std::chrono::steady_clock::now();
    };

    if (hc->current == async_health_check::connecting)
    {
        if (cqe->res < 0)
        {
            // Connect failed
            record(false);
            drop_health_check(slot);
            return;
        }

        // Connect succeeded
        if (m_mesh.health_check == mesh_config::health_tcp)
        {
            // TCP check: connect success is enough
            record(true);
            drop_health_check(slot);
            return;
        }

        // HTTP check: send GET request
        if (idx >= m_backends.size())
        {
            drop_health_check(slot);
            return;
        }

        auto& b = m_backends[idx];
        hc->write_buf = "GET " + m_mesh.health_path + " HTTP/1.0\r\nHost: " +
                        b.resolved_host + "\r\nConnection: close\r\n\r\n";
        hc->current = async_health_check::writing;
        hc->req.type = op_health_check;
        hc->op_pending = true;
        if (SOCKETLEY_UNLIKELY(!m_loop->submit_write(hc->fd, hc->write_buf.data(),
                                 static_cast<uint32_t>(hc->write_buf.size()), &hc->req)))
        {
            // Our shortage, not the backend's: no verdict is recorded.
            hc->op_pending = false;
            drop_health_check(slot);
        }
    }
    else if (hc->current == async_health_check::writing)
    {
        if (cqe->res <= 0)
        {
            record(false);
            drop_health_check(slot);
            return;
        }

        // Write succeeded — read response.  Into the probe's own buffer, which
        // nothing else shares: the connect address has a field of its own.
        hc->current = async_health_check::reading;
        hc->req.type = op_health_check;
        hc->op_pending = true;
        if (SOCKETLEY_UNLIKELY(!m_loop->submit_read(hc->fd, hc->buf, sizeof(hc->buf) - 1, &hc->req)))
        {
            hc->op_pending = false;
            drop_health_check(slot);
        }
    }
    else if (hc->current == async_health_check::reading)
    {
        bool got_2xx = false;
        if (cqe->res > 12)
        {
            hc->buf[cqe->res] = '\0';
            if (hc->buf[9] == '2')
                got_2xx = true;
        }

        record(got_2xx);
        drop_health_check(slot);
    }
}

void proxy_instance::handle_connect(struct io_uring_cqe* cqe, io_request* req)
{
    int client_fd = req->fd;
    if (SOCKETLEY_UNLIKELY(client_fd < 0 || client_fd >= MAX_FDS))
        return;

    auto& entry = m_conn_idx[client_fd];
    if (SOCKETLEY_UNLIKELY(entry.side != conn_client))
        return;

    auto* conn = entry.client;

    // The struct at this fd may already belong to a different connection than
    // the one that issued this connect; the generation says which.
    if (SOCKETLEY_UNLIKELY(req->generation != conn->generation))
        return;

    if (SOCKETLEY_UNLIKELY(!conn->connect_pending))
        return;

    conn->connect_pending = false;
    int bfd = conn->connect_fd;
    conn->connect_fd = -1;

    // A poll completion only reports readiness; whether the connect succeeded
    // is in SO_ERROR.  Fold it into one value so the failure path stays shared.
    int res = cqe->res;
    bool fd_ours = (bfd >= 0);
    if (res >= 0 && req->type == op_poll)
    {
        // A poll completion carries the revents mask, and POLLNVAL, POLLERR and
        // POLLHUP are all positive — testing only the sign accepts them as
        // "writable".  POLLNVAL in particular means the descriptor is no longer
        // valid, so the socket must not be touched again, least of all closed:
        // the number may already belong to someone else.
        const int revents = res;
        int so_err = 0;
        socklen_t elen = sizeof(so_err);
        if (bfd < 0 || (revents & POLLNVAL))
        {
            res = -EBADF;
            fd_ours = false;
        }
        else if (getsockopt(bfd, SOL_SOCKET, SO_ERROR, &so_err, &elen) < 0)
        {
            // The descriptor is already gone.  It is not ours to close: the
            // number has very likely been handed to another socket by now, and
            // closing it again destroys a live connection that has nothing to
            // do with this one — turning one failure into several.
            res = -errno;
            fd_ours = false;
        }
        else if (so_err != 0)
        {
            res = -so_err;
        }
    }

    if (res < 0)
    {
        SKL_TRACE_LOG("connect-result-failed cfd=%d bfd=%d res=%d (%s) saved=%zu",
                      client_fd, bfd, res, strerror(res < 0 ? -res : 0),
                      conn->saved_request.size());
        // Connect failed
        if (fd_ours && bfd >= 0) close(bfd);

        // The descriptor was gone rather than the backend refusing us.  Nothing
        // about the client is wrong in that case, and it may already have data
        // waiting — take one fresh socket before giving up on it.
        bool retry_ours = false;
        if (!fd_ours && !conn->connect_reattempted && !conn->closing &&
            m_protocol == protocol_tcp)
        {
            conn->connect_reattempted = true;
            auto* again = select_and_resolve_backend(conn);
            if (again && connect_to_backend(conn, again, &retry_ours))
                return;
        }
        // Two things that are not the backend's fault must not reach the
        // breaker: a descriptor that vanished under us (see above), and a retry
        // that failed on our own resources rather than on a refusal.
        if (fd_ours && !retry_ours)
            record_backend_error(conn->backend_idx);

        if (m_protocol == protocol_http)
        {
            if (!try_retry(conn))
                send_error(conn, "502 Bad Gateway", "Bad Gateway\n");
        }
        else
        {
            close_pair(client_fd, -1);
        }
        return;
    }

    // Connect succeeded — create backend connection struct
    if (SOCKETLEY_UNLIKELY(bfd < 0 || bfd >= MAX_FDS))
    {
        if (bfd >= 0) close(bfd);
        close_pair(client_fd, -1);
        return;
    }

    conn->backend_fd = bfd;

    auto bconn = backend_pool_acquire(bfd);
    bconn->client_fd = conn->fd;
    bconn->read_req = { this, bconn->read_buf, bfd, sizeof(bconn->read_buf), op_read,
                        bconn->generation };
    bconn->write_req = { this, nullptr, bfd, 0, op_write };
    bconn->splice_in_req = { this, nullptr, bfd, 0, op_splice };
    bconn->splice_out_req = { this, nullptr, bfd, 0, op_splice };

    auto* ptr = bconn.get();
    m_backend_slots[bfd] = std::move(bconn);
    m_backend_count++;
    m_conn_idx[bfd].side = conn_backend;
    m_conn_idx[bfd].backend = ptr;

    // Set up splice for TCP mode
    if (m_protocol == protocol_tcp && m_splice_supported &&
        !m_cb_on_proxy_request && !m_cb_on_proxy_response)
    {
#ifndef SOCKETLEY_NO_LUA
        auto* lctx = lua();
        bool has_lua_hooks = lctx && (lctx->has_on_proxy_request() || lctx->has_on_proxy_response());
#else
        bool has_lua_hooks = false;
#endif
        if (!has_lua_hooks)
        {
            setup_splice_pipes(conn, ptr);
            if (conn->splice_active)
            {
                // Forward saved data via write, then start splice.
                if (!conn->saved_request.empty())
                {
                    forward_to_backend(conn, conn->saved_request);
                    conn->saved_request.clear();
                }

                // forward_to_backend only queues; the write is still in flight.
                // Splice writes to the same backend socket through a separate
                // io_uring operation, and nothing orders the two against each
                // other — starting it now lets later data overtake the bytes
                // that opened the stream.  handle_backend_write starts splice
                // once the queue has actually drained.
                if (!ptr->write_pending && ptr->write_queue.empty())
                    start_splice_forwarding(conn, ptr);
                return;
            }
        }
    }

    // Submit read on backend
    if (SOCKETLEY_UNLIKELY(!submit_read_op_backend(m_loop, bfd, ptr, m_recv_multishot,
                                                   m_use_provided_bufs, BUF_GROUP_ID)))
    {
        close_pair(conn->fd, bfd);
        return;
    }

    // Forward any saved data
    if (!conn->saved_request.empty())
    {
        forward_to_backend(conn, conn->saved_request);
        if (m_mesh.retry_count <= 0)
            conn->saved_request.clear();
    }

    // The client read was deliberately left unarmed until a backend existed;
    // now that one does, start taking data.  (The splice path returns earlier —
    // there the pipeline does the reading.)
    if (!conn->closing && !conn->read_pending && !conn->splice_active &&
        SOCKETLEY_UNLIKELY(!submit_read_op(m_loop, conn->fd, conn, m_recv_multishot,
                                           m_use_provided_bufs, BUF_GROUP_ID)))
    {
        close_pair(conn->fd, bfd);
        return;
    }

    // The client had already half-closed while this connect was in flight.  Now
    // that its payload is on its way, pass the half-close on rather than leaving
    // the pair open waiting for a client that will never write again.
    if (conn->client_eof)
        shutdown(bfd, SHUT_WR);
}

void proxy_instance::record_backend_error(size_t backend_idx)
{
    if (SOCKETLEY_UNLIKELY(backend_idx >= m_circuit_breakers.size()))
        return;

    auto& cb = m_circuit_breakers[backend_idx];

    if (cb.current == circuit_breaker::half_open)
    {
        // Half-open probe failed -> back to open
        cb.current = circuit_breaker::open;
        cb.opened_at = std::chrono::steady_clock::now();
        return;
    }

    cb.error_count++;
    if (cb.error_count >= m_mesh.circuit_threshold && cb.current == circuit_breaker::closed)
    {
        cb.current = circuit_breaker::open;
        cb.opened_at = std::chrono::steady_clock::now();
    }
}

void proxy_instance::record_backend_success(size_t backend_idx)
{
    if (SOCKETLEY_UNLIKELY(backend_idx >= m_circuit_breakers.size()))
        return;

    auto& cb = m_circuit_breakers[backend_idx];

    if (cb.current == circuit_breaker::half_open)
    {
        // Half-open probe succeeded -> close circuit
        cb.current = circuit_breaker::closed;
        cb.error_count = 0;
        return;
    }

    // A success while closed clears the tally, making circuit_threshold mean
    // "this many failures in a row".  Without this the count only ever rose,
    // so the breaker measured a backend's lifetime error total rather than its
    // current health and would eventually open on any backend that had ever
    // failed, however long ago and however healthy since.
    cb.error_count = 0;
}

bool proxy_instance::try_retry(proxy_client_connection* conn)
{
    if (conn->retries_remaining <= 0 || m_mesh.retry_count <= 0)
        return false;

    // Never retry after response data has started flowing to the client
    if (conn->response_started)
        return false;

    // Only retry idempotent methods unless retry_all is set
    if (!m_mesh.retry_all)
    {
        if (conn->method != "GET" && conn->method != "HEAD" &&
            conn->method != "PUT" && conn->method != "DELETE")
            return false;
    }

    conn->retries_remaining--;

    // Disconnect from current backend safely
    if (conn->backend_fd >= 0 && conn->backend_fd < MAX_FDS)
    {
        auto& be = m_conn_idx[conn->backend_fd];
        if (be.side == conn_backend)
        {
            auto* old_bconn = be.backend;
            old_bconn->closing = true;

            // Close splice pipes
            if (old_bconn->pipe_to_client[0] >= 0) close(old_bconn->pipe_to_client[0]);
            if (old_bconn->pipe_to_client[1] >= 0) close(old_bconn->pipe_to_client[1]);
            old_bconn->pipe_to_client[0] = -1;
            old_bconn->pipe_to_client[1] = -1;

            shutdown(conn->backend_fd, SHUT_RDWR);
            close(conn->backend_fd);
            m_conn_idx[conn->backend_fd] = {};
            if (m_backend_slots[conn->backend_fd])
            {
                // A retry abandons the backend mid-request, so this is the one
                // release that regularly happens with a read — sometimes a
                // write — still in flight.  backend_pool_release() keeps the
                // struct out of the pool until those have landed; nulling the
                // owners here instead let it be reused immediately, and the
                // completion was charged to whoever had it by then.
                backend_pool_release(std::move(m_backend_slots[conn->backend_fd]));
                m_backend_count--;
            }
        }
        conn->backend_fd = -1;

        // Close client's splice pipes too
        if (conn->pipe_to_backend[0] >= 0) close(conn->pipe_to_backend[0]);
        if (conn->pipe_to_backend[1] >= 0) close(conn->pipe_to_backend[1]);
        conn->pipe_to_backend[0] = -1;
        conn->pipe_to_backend[1] = -1;
        conn->splice_active = false;
    }

    // Select next healthy backend (skip the one that just failed)
    size_t start_idx = (conn->backend_idx + 1) % m_backends.size();
    for (size_t attempts = 0; attempts < m_backends.size(); attempts++)
    {
        size_t idx = (start_idx + attempts) % m_backends.size();
        if (idx == conn->backend_idx)
            continue;
        if (!is_backend_available(idx))
            continue;

        auto* target = &m_backends[idx];
        if (!connect_to_backend(conn, target))
            continue;

        conn->backend_idx = idx;
        conn->backend_from_group = false;

        // If async connect pending, handle_connect will forward saved_request
        if (conn->connect_pending)
            return true;

        // Re-forward saved request
        if (!conn->saved_request.empty())
            forward_to_backend(conn, conn->saved_request);

        return true;
    }

    return false;
}

std::string proxy_instance::get_stats() const
{
    std::string base = runtime_instance::get_stats();
    // Use char buffer for integer formatting to avoid ostringstream overhead in stats path
    char num_buf[32];
    std::string out;
    out.reserve(base.size() + 256);
    out += base;

    out += "backend_connections:";
    auto [p1, e1] = std::to_chars(num_buf, num_buf + sizeof(num_buf), m_backend_count);
    out.append(num_buf, static_cast<size_t>(p1 - num_buf));
    out += '\n';

    out += "protocol:";
    out += (m_protocol == protocol_http ? "http" : "tcp");
    out += '\n';

    out += "backends:";
    auto [p2, e2] = std::to_chars(num_buf, num_buf + sizeof(num_buf), m_backends.size());
    out.append(num_buf, static_cast<size_t>(p2 - num_buf));
    out += '\n';

    // Pool stats
    size_t pool_total = 0;
    for (const auto& pool : m_backend_pool)
        pool_total += pool.size();
    if (pool_total > 0)
    {
        out += "pooled_connections:";
        auto [p3, e3] = std::to_chars(num_buf, num_buf + sizeof(num_buf), pool_total);
        out.append(num_buf, static_cast<size_t>(p3 - num_buf));
        out += '\n';
    }

    // Include health/circuit info if mesh is configured
    if (m_mesh.health_check != mesh_config::health_none)
    {
        size_t healthy = 0;
        for (const auto& h : m_backend_health)
            if (h.healthy) healthy++;
        out += "healthy_backends:";
        auto [p4, e4] = std::to_chars(num_buf, num_buf + sizeof(num_buf), healthy);
        out.append(num_buf, static_cast<size_t>(p4 - num_buf));
        out += '\n';
    }

    out += "peak_connections:";
    auto [p6, e6] = std::to_chars(num_buf, num_buf + sizeof(num_buf), m_peak_connections);
    out.append(num_buf, static_cast<size_t>(p6 - num_buf));
    out += '\n';

    size_t open_circuits = 0;
    for (const auto& cb : m_circuit_breakers)
        if (cb.current == circuit_breaker::open) open_circuits++;
    if (open_circuits > 0)
    {
        out += "open_circuits:";
        auto [p5, e5] = std::to_chars(num_buf, num_buf + sizeof(num_buf), open_circuits);
        out.append(num_buf, static_cast<size_t>(p5 - num_buf));
        out += '\n';
    }

    // Per-backend circuit breaker state
    for (size_t i = 0; i < m_circuit_breakers.size(); i++)
    {
        auto& cb = m_circuit_breakers[i];
        if (cb.current != circuit_breaker::closed)
        {
            out += "backend_";
            auto [pi, ei] = std::to_chars(num_buf, num_buf + sizeof(num_buf), i);
            out.append(num_buf, static_cast<size_t>(pi - num_buf));
            out += "_circuit:";
            out += (cb.current == circuit_breaker::open ? "open" : "half_open");
            out += '\n';
        }
    }

    return out;
}

std::string proxy_instance::lua_peer_ip(int client_fd)
{
    struct sockaddr_storage addr{};
    socklen_t len = sizeof(addr);
    if (getpeername(client_fd, reinterpret_cast<struct sockaddr*>(&addr), &len) != 0)
        return "";
    char ip[INET6_ADDRSTRLEN]{};
    if (addr.ss_family == AF_INET)
        inet_ntop(AF_INET,
            &reinterpret_cast<struct sockaddr_in*>(&addr)->sin_addr, ip, sizeof(ip));
    else if (addr.ss_family == AF_INET6)
        inet_ntop(AF_INET6,
            &reinterpret_cast<struct sockaddr_in6*>(&addr)->sin6_addr, ip, sizeof(ip));
    return ip;
}

void proxy_instance::lua_close_client(int client_fd)
{
    if (client_fd < 0 || client_fd >= MAX_FDS) return;
    auto& ce = m_conn_idx[client_fd];
    if (ce.side != conn_client) return;
    auto* conn = ce.client;
    if (conn->closing) return;
    close_pair(client_fd, conn->backend_fd);
}

std::vector<std::string> proxy_instance::lua_backends() const
{
    std::vector<std::string> result;
    result.reserve(m_backends.size());
    for (const auto& b : m_backends)
        result.push_back(b.address);
    return result;
}

std::vector<std::pair<int, std::string>> proxy_instance::lua_backend_health() const
{
    std::vector<std::pair<int, std::string>> result;
    result.reserve(m_circuit_breakers.size());
    for (size_t i = 0; i < m_circuit_breakers.size(); ++i)
    {
        const char* state_str = "closed";
        switch (m_circuit_breakers[i].current)
        {
            case circuit_breaker::closed:    state_str = "closed";    break;
            case circuit_breaker::open:      state_str = "open";      break;
            case circuit_breaker::half_open: state_str = "half_open"; break;
        }
        result.emplace_back(static_cast<int>(i), state_str);
    }
    return result;
}

std::vector<int> proxy_instance::lua_clients() const
{
    std::vector<int> result;
    result.reserve(m_client_count);
    for (int i = 0; i < MAX_FDS; i++)
    {
        if (m_client_slots[i])
            result.push_back(i);
    }
    return result;
}

void proxy_instance::set_on_proxy_request(proxy_hook cb) { m_cb_on_proxy_request = std::move(cb); }
void proxy_instance::set_on_proxy_response(proxy_hook cb) { m_cb_on_proxy_response = std::move(cb); }

void proxy_instance::forward_to_backend(proxy_client_connection* conn, std::string_view data)
{
    // Every path out of here that does not deliver has to take the client down
    // with it.  Returning quietly leaves the client connection open and
    // accepting: it keeps writing, every write succeeds, and not one byte
    // reaches the backend.  A dropped connection is a bad outcome; a connection
    // that silently swallows data is a worse one, because nobody finds out.
    if (SOCKETLEY_UNLIKELY(conn->backend_fd < 0 || !m_loop))
    {
        conn->closing = true;
        return;
    }

    if (SOCKETLEY_UNLIKELY(conn->backend_fd >= MAX_FDS))
    {
        conn->closing = true;
        return;
    }

    auto& be = m_conn_idx[conn->backend_fd];
    if (SOCKETLEY_UNLIKELY(be.side != conn_backend))
    {
        conn->closing = true;
        return;
    }

    auto* bconn = be.backend;
    // The pairing has to be mutual.  A descriptor number does not prove
    // identity once numbers are reused, and forwarding into a backend that
    // belongs to somebody else delivers this client's request on a stranger's
    // connection — the same failure the splice path guards against, on the
    // path that carries HTTP.
    if (SOCKETLEY_UNLIKELY(bconn->client_fd != conn->fd))
    {
        conn->closing = true;
        return;
    }

    if (SOCKETLEY_UNLIKELY(bconn->closing))
    {
        conn->closing = true;
        return;
    }

    std::string hook_storage;
    bool hook_modified = false;

    if (m_cb_on_proxy_request)
    {
        auto result = m_cb_on_proxy_request(conn->fd, data);
        if (!result) return;  // nullopt = drop
        if (!result->empty()) { hook_storage = std::move(*result); hook_modified = true; }
    }
#ifndef SOCKETLEY_NO_LUA
    else if (auto* lctx = lua(); lctx && lctx->has_on_proxy_request())
    {
        try {
            sol::object r = lctx->on_proxy_request()(conn->fd, data);
            if (r.get_type() == sol::type::nil) return;   // drop
            if (r.is<std::string>()) {
                hook_storage = r.as<std::string>();
                hook_modified = true;
            }
        } catch (const sol::error& e) {
            fprintf(stderr, "[lua] on_proxy_request error: %s\n", e.what());
        }
    }
#endif

    SKL_TRACE_ADD(bconn, bytes_queued, (unsigned long long)data.size());
    if (SOCKETLEY_UNLIKELY(bconn->write_queue.bytes() >= socketley::write_queue_max_bytes))
    {
        // The backend is not draining and the queue has hit its memory bound.
        // Marking only the backend left the client writing into a void.
        bconn->closing = true;
        conn->closing = true;
        return;
    }

    if (hook_modified)
    {
        m_stat_bytes_out.fetch_add(hook_storage.size(), std::memory_order_relaxed);
        bconn->write_queue.emplace(std::move(hook_storage));
    }
    else
    {
        m_stat_bytes_out.fetch_add(data.size(), std::memory_order_relaxed);
        bconn->write_queue.emplace(data);
    }

    // Undeliverable.  Marking the connection is all this may do — the callers
    // go on using conn right after this returns, and the read handlers tear the
    // pair down once they see closing with nothing left in flight.
    if (!bconn->write_pending && !flush_backend_write_queue(bconn))
        conn->closing = true;
}

void proxy_instance::forward_to_client(proxy_backend_connection* conn, std::string_view data)
{
    if (SOCKETLEY_UNLIKELY(!m_loop))
        return;

    if (SOCKETLEY_UNLIKELY(conn->client_fd < 0 || conn->client_fd >= MAX_FDS))
        return;

    auto& ce = m_conn_idx[conn->client_fd];
    if (SOCKETLEY_UNLIKELY(ce.side != conn_client))
        return;

    auto* cconn = ce.client;
    if (SOCKETLEY_UNLIKELY(cconn->backend_fd != conn->fd))
        return;   // not our client any more; see forward_to_backend

    if (SOCKETLEY_UNLIKELY(cconn->closing))
        return;

    std::string hook_storage;
    bool hook_modified = false;

    if (m_cb_on_proxy_response)
    {
        auto result = m_cb_on_proxy_response(conn->client_fd, data);
        if (!result) return;  // nullopt = drop
        if (!result->empty()) { hook_storage = std::move(*result); hook_modified = true; }
    }
#ifndef SOCKETLEY_NO_LUA
    else if (auto* lctx = lua(); lctx && lctx->has_on_proxy_response())
    {
        try {
            sol::object r = lctx->on_proxy_response()(conn->client_fd, data);
            if (r.get_type() == sol::type::nil) return;   // drop
            if (r.is<std::string>()) {
                hook_storage = r.as<std::string>();
                hook_modified = true;
            }
        } catch (const sol::error& e) {
            fprintf(stderr, "[lua] on_proxy_response error: %s\n", e.what());
        }
    }
#endif

    if (SOCKETLEY_UNLIKELY(cconn->write_queue.bytes() >= socketley::write_queue_max_bytes))
    {
        cconn->closing = true;
        return;
    }

    if (hook_modified)
    {
        m_stat_bytes_out.fetch_add(hook_storage.size(), std::memory_order_relaxed);
        cconn->write_queue.emplace(std::move(hook_storage));
    }
    else
    {
        m_stat_bytes_out.fetch_add(data.size(), std::memory_order_relaxed);
        cconn->write_queue.emplace(data);
    }

    if (!cconn->write_pending && !flush_client_write_queue(cconn))
        cconn->closing = true;
}

void proxy_instance::send_error(proxy_client_connection* conn, std::string_view status, std::string_view body)
{
    if (!m_loop || conn->closing)
        return;

    // Build response in a stack buffer when possible
    // Layout: "HTTP/1.1 " (9) + status + "\r\nContent-Length: " (18) + digits (max 20) + trailer (23) = ~70 + status
    char hdr_buf[256];
    size_t hdr_len = 0;

    // Bounds check: 9 + status + 18 + 20 + 23 = 70 + status.size()
    if (status.size() > 180)
    {
        conn->closing = true;
        return;
    }

    // "HTTP/1.1 "
    std::memcpy(hdr_buf, "HTTP/1.1 ", 9);
    hdr_len = 9;
    std::memcpy(hdr_buf + hdr_len, status.data(), status.size());
    hdr_len += status.size();
    std::memcpy(hdr_buf + hdr_len, "\r\nContent-Length: ", 18);
    hdr_len += 18;
    auto [clen_end, clen_ec] = std::to_chars(hdr_buf + hdr_len, hdr_buf + sizeof(hdr_buf), body.size());
    hdr_len = static_cast<size_t>(clen_end - hdr_buf);
    std::memcpy(hdr_buf + hdr_len, "\r\nConnection: close\r\n\r\n", 23);
    hdr_len += 23;

    std::string response;
    response.reserve(hdr_len + body.size());
    response.append(hdr_buf, hdr_len);
    response += body;

    conn->write_queue.push(std::move(response));
    conn->closing = true;

    // conn->closing is already set above.  If the error body cannot be handed
    // to the ring it simply never goes out; the caller's teardown proceeds
    // either way, so there is nothing for this to decide.
    if (!conn->write_pending && !flush_client_write_queue(conn))
        conn->write_queue.clear();
}

// Returns false when nothing reached the ring.  A caller that leaves
// write_pending set after that waits for a completion that cannot come:
// the connection stops making progress and the peer is left holding a
// request nobody will ever answer.  On failure the pending flag is
// cleared and the batch dropped — the bytes are undeliverable, and
// saying so is the difference between a closed connection and a hung one.
bool proxy_instance::flush_client_write_queue(proxy_client_connection* conn)
{
    if (SOCKETLEY_UNLIKELY(!m_loop || conn->write_queue.empty() || conn->zc_notif_pending))
        return true;

    uint32_t count = 0;
    while (!conn->write_queue.empty() && count < proxy_client_connection::MAX_WRITE_BATCH)
    {
        conn->write_batch[count] = conn->write_queue.take_front();

        conn->write_iovs[count].iov_base = conn->write_batch[count].data();
        conn->write_iovs[count].iov_len = conn->write_batch[count].size();
        count++;
    }

    conn->write_batch_count = count;
    conn->write_pending = true;

    bool queued;
    if (count == 1)
    {
        auto len = static_cast<uint32_t>(std::min(conn->write_batch[0].size(),
                                                   static_cast<size_t>(UINT32_MAX)));
        if (m_send_zc && len >= (512u << 10))
        {
            conn->zc_notif_pending = true;
            conn->write_req.type = op_send_zc;
            queued = m_loop->submit_send_zc(conn->fd, conn->write_batch[0].data(), len, &conn->write_req);
        }
        else
        {
            conn->write_req.type = op_write;
            queued = m_loop->submit_write(conn->fd, conn->write_batch[0].data(), len, &conn->write_req);
        }
    }
    else
    {
        conn->write_req.type = op_writev;
        queued = m_loop->submit_writev(conn->fd, conn->write_iovs, count, &conn->write_req);
    }

    if (SOCKETLEY_UNLIKELY(!queued))
    {
        conn->write_pending = false;
        conn->zc_notif_pending = false;
        conn->write_batch_count = 0;
        return false;
    }
    return true;
}

// Returns false when nothing reached the ring.  A caller that leaves
// write_pending set after that waits for a completion that cannot come:
// the connection stops making progress and the peer is left holding a
// request nobody will ever answer.  On failure the pending flag is
// cleared and the batch dropped — the bytes are undeliverable, and
// saying so is the difference between a closed connection and a hung one.
bool proxy_instance::flush_backend_write_queue(proxy_backend_connection* conn)
{
    if (SOCKETLEY_UNLIKELY(!m_loop || conn->write_queue.empty() || conn->zc_notif_pending))
        return true;

    uint32_t count = 0;
    while (!conn->write_queue.empty() && count < proxy_backend_connection::MAX_WRITE_BATCH)
    {
        conn->write_batch[count] = conn->write_queue.take_front();

        conn->write_iovs[count].iov_base = conn->write_batch[count].data();
        conn->write_iovs[count].iov_len = conn->write_batch[count].size();
        count++;
    }

    conn->write_batch_count = count;
    conn->write_pending = true;

    bool queued;
    if (count == 1)
    {
        auto len = static_cast<uint32_t>(std::min(conn->write_batch[0].size(),
                                                   static_cast<size_t>(UINT32_MAX)));
        if (m_send_zc && len >= (512u << 10))
        {
            conn->zc_notif_pending = true;
            conn->write_req.type = op_send_zc;
            queued = m_loop->submit_send_zc(conn->fd, conn->write_batch[0].data(), len, &conn->write_req);
        }
        else
        {
            conn->write_req.type = op_write;
            queued = m_loop->submit_write(conn->fd, conn->write_batch[0].data(), len, &conn->write_req);
        }
    }
    else
    {
        conn->write_req.type = op_writev;
        queued = m_loop->submit_writev(conn->fd, conn->write_iovs, count, &conn->write_req);
    }

    if (SOCKETLEY_UNLIKELY(!queued))
    {
        conn->write_pending = false;
        conn->zc_notif_pending = false;
        conn->write_batch_count = 0;
        return false;
    }
    return true;
}

void proxy_instance::handle_client_write(struct io_uring_cqe* cqe, io_request* req)
{
    int fd = req->fd;
    auto& entry = m_conn_idx[fd];
    if (SOCKETLEY_UNLIKELY(entry.side != conn_client))
        return;

    auto* conn = entry.client;

    // Zero-copy send notification: buffer is now safe to release
    if (SOCKETLEY_UNLIKELY(cqe->flags & IORING_CQE_F_NOTIF))
    {
        conn->zc_notif_pending = false;
        for (uint32_t i = 0; i < conn->write_batch_count; i++)
            conn->write_batch[i].clear();
        conn->write_batch_count = 0;

        if (!conn->write_queue.empty() && !conn->write_pending)
        {
            if (SOCKETLEY_UNLIKELY(!flush_client_write_queue(conn)))
            {
                close_pair(conn->fd, conn->backend_fd);
                return;
            }
        }
        else if (conn->write_queue.empty() && !conn->write_pending &&
                 conn->closing && !conn->read_pending &&
                 !conn->splice_in_pending && !conn->splice_out_pending)
            close_pair(fd, conn->backend_fd);
        return;
    }

    conn->write_pending = false;

    if (SOCKETLEY_UNLIKELY(cqe->res <= 0))
    {
        if (SOCKETLEY_LIKELY(!conn->zc_notif_pending))
        {
            for (uint32_t i = 0; i < conn->write_batch_count; i++)
                conn->write_batch[i].clear();
            conn->write_batch_count = 0;
        }
        close_pair(fd, conn->backend_fd);
        return;
    }

    // Short write handling: resubmit remaining bytes
    if (!conn->zc_notif_pending && conn->write_batch_count > 0)
    {
        size_t total_submitted = 0;
        for (uint32_t i = 0; i < conn->write_batch_count; i++)
            total_submitted += conn->write_iovs[i].iov_len;

        size_t written = static_cast<size_t>(cqe->res);
        if (written < total_submitted)
        {
            // Advance past fully-written iovecs
            size_t remaining = written;
            uint32_t first_iov = 0;
            for (; first_iov < conn->write_batch_count; first_iov++)
            {
                if (remaining < conn->write_iovs[first_iov].iov_len)
                {
                    conn->write_iovs[first_iov].iov_base =
                        static_cast<char*>(conn->write_iovs[first_iov].iov_base) + remaining;
                    conn->write_iovs[first_iov].iov_len -= remaining;
                    break;
                }
                remaining -= conn->write_iovs[first_iov].iov_len;
            }

            // Shift remaining iovecs and batch refs to front
            uint32_t new_count = conn->write_batch_count - first_iov;
            if (first_iov > 0)
            {
                for (uint32_t i = 0; i < new_count; i++)
                {
                    conn->write_iovs[i] = conn->write_iovs[first_iov + i];
                    conn->write_batch[i] = std::move(conn->write_batch[first_iov + i]);
                }
                for (uint32_t i = new_count; i < conn->write_batch_count; i++)
                    conn->write_batch[i].clear();
            }
            conn->write_batch_count = new_count;

            conn->write_pending = true;
            bool queued;
            if (new_count == 1)
            {
                conn->write_req.type = op_write;
                queued = m_loop->submit_write(conn->fd,
                    static_cast<const char*>(conn->write_iovs[0].iov_base),
                    static_cast<uint32_t>(conn->write_iovs[0].iov_len),
                    &conn->write_req);
            }
            else
            {
                conn->write_req.type = op_writev;
                queued = m_loop->submit_writev(conn->fd, conn->write_iovs, new_count, &conn->write_req);
            }
            if (SOCKETLEY_UNLIKELY(!queued))
            {
                // The remainder of a short write cannot be handed over.  Leaving
                // write_pending set would strand the connection mid-message with
                // no completion coming to finish it.
                conn->write_pending = false;
                close_pair(conn->fd, conn->backend_fd);
            }
            return;
        }
    }

    // Full write completed — release batch
    if (SOCKETLEY_LIKELY(!conn->zc_notif_pending))
    {
        for (uint32_t i = 0; i < conn->write_batch_count; i++)
            conn->write_batch[i].clear();
        conn->write_batch_count = 0;
    }

    if (!conn->write_queue.empty() && !conn->zc_notif_pending)
    {
        if (SOCKETLEY_UNLIKELY(!flush_client_write_queue(conn)))
        {
            close_pair(conn->fd, conn->backend_fd);
            return;
        }
    }
    else if (conn->closing && !conn->read_pending && !conn->zc_notif_pending &&
             !conn->splice_in_pending && !conn->splice_out_pending)
    {
        close_pair(fd, conn->backend_fd);
        return;
    }

    // Backpressure resume: if client write queue drained below threshold, restart backend reads
    if (conn->write_queue.bytes() < socketley::write_queue_backpressure_bytes &&
        conn->backend_fd >= 0 && conn->backend_fd < MAX_FDS)
    {
        auto& be = m_conn_idx[conn->backend_fd];
        if (be.side == conn_backend && !be.backend->read_pending &&
            !be.backend->closing && !be.backend->splice_active)
        {
            if (SOCKETLEY_UNLIKELY(!submit_read_op_backend(m_loop, conn->backend_fd, be.backend,
                                                           m_recv_multishot, m_use_provided_bufs,
                                                           BUF_GROUP_ID)))
            {
                close_pair(conn->fd, conn->backend_fd);
                return;
            }
        }
    }
}

void proxy_instance::handle_backend_write(struct io_uring_cqe* cqe, io_request* req)
{
    int fd = req->fd;
    auto& entry = m_conn_idx[fd];
    if (SOCKETLEY_UNLIKELY(entry.side != conn_backend))
        return;

    auto* conn = entry.backend;

    // Zero-copy send notification: buffer is now safe to release
    if (SOCKETLEY_UNLIKELY(cqe->flags & IORING_CQE_F_NOTIF))
    {
        conn->zc_notif_pending = false;
        for (uint32_t i = 0; i < conn->write_batch_count; i++)
            conn->write_batch[i].clear();
        conn->write_batch_count = 0;

        if (!conn->write_queue.empty() && !conn->write_pending)
        {
            if (SOCKETLEY_UNLIKELY(!flush_backend_write_queue(conn)))
            {
                close_pair(conn->client_fd, conn->fd);
                return;
            }
        }
        else if (conn->write_queue.empty() && !conn->write_pending &&
                 conn->closing && !conn->read_pending &&
                 !conn->splice_in_pending && !conn->splice_out_pending)
            close_pair(conn->client_fd, fd);
        return;
    }

    conn->write_pending = false;

    if (SOCKETLEY_UNLIKELY(cqe->res <= 0))
    {
        if (SOCKETLEY_LIKELY(!conn->zc_notif_pending))
        {
            for (uint32_t i = 0; i < conn->write_batch_count; i++)
                conn->write_batch[i].clear();
            conn->write_batch_count = 0;
        }
        close_pair(conn->client_fd, fd);
        return;
    }

    // Short write handling: resubmit remaining bytes
    if (!conn->zc_notif_pending && conn->write_batch_count > 0)
    {
        size_t total_submitted = 0;
        for (uint32_t i = 0; i < conn->write_batch_count; i++)
            total_submitted += conn->write_iovs[i].iov_len;

        size_t written = static_cast<size_t>(cqe->res);
        if (written < total_submitted)
        {
            // Advance past fully-written iovecs
            size_t remaining = written;
            uint32_t first_iov = 0;
            for (; first_iov < conn->write_batch_count; first_iov++)
            {
                if (remaining < conn->write_iovs[first_iov].iov_len)
                {
                    conn->write_iovs[first_iov].iov_base =
                        static_cast<char*>(conn->write_iovs[first_iov].iov_base) + remaining;
                    conn->write_iovs[first_iov].iov_len -= remaining;
                    break;
                }
                remaining -= conn->write_iovs[first_iov].iov_len;
            }

            // Shift remaining iovecs and batch refs to front
            uint32_t new_count = conn->write_batch_count - first_iov;
            if (first_iov > 0)
            {
                for (uint32_t i = 0; i < new_count; i++)
                {
                    conn->write_iovs[i] = conn->write_iovs[first_iov + i];
                    conn->write_batch[i] = std::move(conn->write_batch[first_iov + i]);
                }
                for (uint32_t i = new_count; i < conn->write_batch_count; i++)
                    conn->write_batch[i].clear();
            }
            conn->write_batch_count = new_count;

            conn->write_pending = true;
            bool queued;
            if (new_count == 1)
            {
                conn->write_req.type = op_write;
                queued = m_loop->submit_write(conn->fd,
                    static_cast<const char*>(conn->write_iovs[0].iov_base),
                    static_cast<uint32_t>(conn->write_iovs[0].iov_len),
                    &conn->write_req);
            }
            else
            {
                conn->write_req.type = op_writev;
                queued = m_loop->submit_writev(conn->fd, conn->write_iovs, new_count, &conn->write_req);
            }
            if (SOCKETLEY_UNLIKELY(!queued))
            {
                // The remainder of a short write cannot be handed over.  Leaving
                // write_pending set would strand the connection mid-message with
                // no completion coming to finish it.
                conn->write_pending = false;
                close_pair(conn->client_fd, conn->fd);
            }
            return;
        }
    }

    SKL_TRACE_ADD(conn, bytes_written, (unsigned long long)(cqe->res > 0 ? cqe->res : 0));
    SKL_TRACE_ADD(conn, writes, 1);

    // Full write completed — release batch
    if (SOCKETLEY_LIKELY(!conn->zc_notif_pending))
    {
        for (uint32_t i = 0; i < conn->write_batch_count; i++)
            conn->write_batch[i].clear();
        conn->write_batch_count = 0;
    }

    if (!conn->write_queue.empty() && !conn->zc_notif_pending)
    {
        if (SOCKETLEY_UNLIKELY(!flush_backend_write_queue(conn)))
        {
            close_pair(conn->client_fd, conn->fd);
            return;
        }
    }
    else if (conn->closing && !conn->read_pending && !conn->zc_notif_pending &&
             !conn->splice_in_pending && !conn->splice_out_pending)
    {
        close_pair(conn->client_fd, fd);
        return;
    }

    // Splice was held back while queued bytes were still on their way to this
    // socket; now that the queue has drained it is safe to let the kernel take
    // over without anything overtaking what came before.
    if (conn->write_queue.empty() && !conn->write_pending && !conn->splice_in_pending &&
        conn->client_fd >= 0 && conn->client_fd < MAX_FDS)
    {
        auto& se = m_conn_idx[conn->client_fd];
        if (se.side == conn_client && se.client->splice_active && conn->splice_active)
            start_splice_forwarding(se.client, conn);
    }

    // Backpressure resume: if write queue drained below threshold, restart client reads
    if (conn->write_queue.bytes() < socketley::write_queue_backpressure_bytes &&
        conn->client_fd >= 0 && conn->client_fd < MAX_FDS)
    {
        auto& ce = m_conn_idx[conn->client_fd];
        if (ce.side == conn_client && !ce.client->read_pending &&
            !ce.client->closing && !ce.client->splice_active)
        {
            if (SOCKETLEY_UNLIKELY(!submit_read_op(m_loop, conn->client_fd, ce.client,
                                                   m_recv_multishot, m_use_provided_bufs,
                                                   BUF_GROUP_ID)))
            {
                close_pair(conn->client_fd, conn->fd);
                return;
            }
        }
    }
}
