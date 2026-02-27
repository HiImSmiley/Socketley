#include "proxy_instance.h"
#include "../../shared/event_loop.h"
#include "../../shared/runtime_manager.h"
#include "../../shared/cluster_discovery.h"
#include "../../shared/lua_context.h"

#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <charconv>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <algorithm>
#include <poll.h>
#include <liburing.h>
#include <sstream>

// Socket buffer sizes: 256KB gives good throughput for bulk transfers
static constexpr int SOCK_BUF_SIZE = 256 * 1024;

// Splice pipe capacity: 64KB is the default, but we can request more via F_SETPIPE_SZ
static constexpr int SPLICE_PIPE_SIZE = 256 * 1024;

proxy_instance::proxy_instance(std::string_view name)
    : runtime_instance(runtime_proxy, name)
{
    std::memset(&m_accept_addr, 0, sizeof(m_accept_addr));
    m_accept_addrlen = sizeof(m_accept_addr);
    m_accept_req = { op_accept, -1, nullptr, 0, this };
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
    return m_clients.size();
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
    // Clear any connections left from a previous stop() — safe to free now that
    // all in-flight CQEs have been processed (we're starting a fresh run).
    std::memset(m_conn_idx, 0, sizeof(m_conn_idx));
    m_clients.clear();
    m_backend_conns.clear();

    m_loop = &loop;

    if (m_backends.empty())
        return false;

    for (auto& b : m_backends)
    {
        if (!resolve_backend(b))
            return false;
    }

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

    if (event_loop::supports_multishot_accept())
    {
        m_accept_req.type = op_multishot_accept;
        loop.submit_multishot_accept(m_listen_fd, &m_accept_req);
        m_multishot_active = true;
    }
    else
    {
        m_accept_req.type = op_accept;
        loop.submit_accept(m_listen_fd, &m_accept_addr, &m_accept_addrlen, &m_accept_req);
        m_multishot_active = false;
    }

    if (get_idle_timeout() > 0)
    {
        m_idle_sweep_ts.tv_sec = 30;
        m_idle_sweep_ts.tv_nsec = 0;
        m_idle_sweep_req = { op_timeout, -1, nullptr, 0, this };
        m_loop->submit_timeout(&m_idle_sweep_ts, &m_idle_sweep_req);
    }

    // Initialize per-backend health and circuit breaker state
    m_backend_health.clear();
    m_backend_health.resize(m_backends.size());
    m_circuit_breakers.clear();
    m_circuit_breakers.resize(m_backends.size());

    // Initialize connection pool (one pool per backend)
    m_backend_pool.clear();
    m_backend_pool.resize(m_backends.size());

    // Start health check timer if configured
    if (m_mesh.health_check != mesh_config::health_none && m_mesh.health_interval > 0)
    {
        m_health_check_ts.tv_sec = m_mesh.health_interval;
        m_health_check_ts.tv_nsec = 0;
        m_health_check_req = { op_timeout, -1, nullptr, 0, this };
        m_loop->submit_timeout(&m_health_check_ts, &m_health_check_req);
    }

    return true;
}

void proxy_instance::teardown(event_loop& loop)
{
    // Null out all req->owner pointers FIRST so any stale CQEs that arrive after
    // teardown (e.g. from SQPOLL processing a write SQE that was queued late) are
    // safely skipped by the event loop's `if (req && req->owner)` guard.
    m_accept_req.owner = nullptr;
    m_idle_sweep_req.owner = nullptr;
    m_health_check_req.owner = nullptr;
    for (auto& [fd, conn] : m_clients)
    {
        conn->read_req.owner  = nullptr;
        conn->write_req.owner = nullptr;
        conn->splice_in_req.owner = nullptr;
        conn->splice_out_req.owner = nullptr;
    }
    for (auto& [fd, conn] : m_backend_conns)
    {
        conn->read_req.owner  = nullptr;
        conn->write_req.owner = nullptr;
        conn->splice_in_req.owner = nullptr;
        conn->splice_out_req.owner = nullptr;
    }

    std::memset(m_conn_idx, 0, sizeof(m_conn_idx));

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
        for (auto& [fd, conn] : m_clients)
        {
            while (!conn->write_queue.empty())
            {
                auto& msg = conn->write_queue.front();
                if (::write(fd, msg.data(), msg.size()) < 0) break;
                conn->write_queue.pop();
            }
        }
    }

    for (auto& [fd, conn] : m_backend_conns)
    {
        // Close splice pipes
        if (conn->pipe_to_client[0] >= 0) close(conn->pipe_to_client[0]);
        if (conn->pipe_to_client[1] >= 0) close(conn->pipe_to_client[1]);
        shutdown(fd, SHUT_RDWR);
        close(fd);
    }

    for (auto& [fd, conn] : m_clients)
    {
        // Close splice pipes
        if (conn->pipe_to_backend[0] >= 0) close(conn->pipe_to_backend[0]);
        if (conn->pipe_to_backend[1] >= 0) close(conn->pipe_to_backend[1]);
        shutdown(fd, SHUT_RDWR);
        close(fd);
    }

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

    m_loop = nullptr;
    m_multishot_active = false;
}

void proxy_instance::on_cqe(struct io_uring_cqe* cqe)
{
    auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
    if (PROXY_UNLIKELY(!req || !m_loop))
        return;

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
            if (PROXY_UNLIKELY(req->fd < 0 || req->fd >= MAX_FDS)) break;
            auto& re = m_conn_idx[req->fd];
            if (PROXY_LIKELY(re.side == conn_client))
                handle_client_read(cqe, req);
            else if (re.side == conn_backend)
                handle_backend_read(cqe, req);
            break;
        }
        case op_write:
        case op_writev:
        case op_send_zc:
        case op_send_zc_notif:
        {
            if (PROXY_UNLIKELY(req->fd < 0 || req->fd >= MAX_FDS)) break;
            auto& we = m_conn_idx[req->fd];
            if (PROXY_LIKELY(we.side == conn_client))
                handle_client_write(cqe, req);
            else if (we.side == conn_backend)
                handle_backend_write(cqe, req);
            break;
        }
        case op_splice:
            handle_splice(cqe, req);
            break;
        case op_timeout:
            if (req == &m_idle_sweep_req)
            {
                auto now = std::chrono::steady_clock::now();
                auto timeout = std::chrono::seconds(get_idle_timeout());
                for (auto& [cfd, cconn] : m_clients)
                {
                    if (!cconn->closing && (now - cconn->last_activity) > timeout)
                    {
                        cconn->closing = true;
                        shutdown(cfd, SHUT_RD);
                    }
                }
                // Evict stale pooled connections
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
                }
                m_loop->submit_timeout(&m_idle_sweep_ts, &m_idle_sweep_req);
            }
            // Accept backoff expired — resubmit accept
            else if (req == &m_accept_backoff_req && m_listen_fd >= 0)
            {
                if (m_multishot_active)
                    m_loop->submit_multishot_accept(m_listen_fd, &m_accept_req);
                else
                {
                    m_accept_addrlen = sizeof(m_accept_addr);
                    m_loop->submit_accept(m_listen_fd, &m_accept_addr, &m_accept_addrlen, &m_accept_req);
                }
            }
            // Health check sweep timer
            else if (req == &m_health_check_req)
            {
                health_check_sweep();
                m_loop->submit_timeout(&m_health_check_ts, &m_health_check_req);
            }
            break;
        default:
            break;
    }
}

void proxy_instance::handle_accept(struct io_uring_cqe* cqe)
{
    int client_fd = cqe->res;

    if (PROXY_LIKELY(client_fd >= 0))
    {
        if (PROXY_UNLIKELY(client_fd >= MAX_FDS ||
            (get_max_connections() > 0 && m_clients.size() >= get_max_connections())))
        {
            close(client_fd);
            goto proxy_resubmit_accept;
        }

        tune_socket(client_fd);

        m_stat_total_connections.fetch_add(1, std::memory_order_relaxed);

        auto conn = std::make_unique<proxy_client_connection>();
        conn->fd = client_fd;
        conn->partial.reserve(PROXY_READ_BUF_SIZE);
        conn->read_req = { op_read, client_fd, conn->read_buf, sizeof(conn->read_buf), this };
        conn->write_req = { op_write, client_fd, nullptr, 0, this };
        conn->splice_in_req = { op_splice, client_fd, nullptr, 0, this };
        conn->splice_out_req = { op_splice, client_fd, nullptr, 0, this };

        auto* ptr = conn.get();
        m_clients[client_fd] = std::move(conn);
        m_conn_idx[client_fd].side = conn_client;
        m_conn_idx[client_fd].client = ptr;

        ptr->last_activity = std::chrono::steady_clock::now();

        invoke_on_connect(client_fd);

        ptr->read_pending = true;
        if (m_recv_multishot)
            m_loop->submit_recv_multishot(client_fd, BUF_GROUP_ID, &ptr->read_req);
        else if (m_use_provided_bufs)
            m_loop->submit_read_provided(client_fd, BUF_GROUP_ID, &ptr->read_req);
        else
            m_loop->submit_read(client_fd, ptr->read_buf, sizeof(ptr->read_buf), &ptr->read_req);
    }

    // EMFILE/ENFILE: backoff 100ms to avoid CPU spin when fd limit is hit
    if (PROXY_UNLIKELY(client_fd == -EMFILE || client_fd == -ENFILE))
    {
        m_accept_backoff_ts.tv_sec = 0;
        m_accept_backoff_ts.tv_nsec = 100000000LL;
        m_accept_backoff_req = { op_timeout, -1, nullptr, 0, this };
        m_loop->submit_timeout(&m_accept_backoff_ts, &m_accept_backoff_req);
        return;
    }

proxy_resubmit_accept:
    if (m_multishot_active)
    {
        if (!(cqe->flags & IORING_CQE_F_MORE))
        {
            if (PROXY_LIKELY(m_listen_fd >= 0))
                m_loop->submit_multishot_accept(m_listen_fd, &m_accept_req);
        }
    }
    else
    {
        if (PROXY_LIKELY(m_listen_fd >= 0))
        {
            m_accept_addrlen = sizeof(m_accept_addr);
            m_loop->submit_accept(m_listen_fd, &m_accept_addr, &m_accept_addrlen, &m_accept_req);
        }
    }
}

// Inline helper to submit the appropriate read op
static inline void submit_read_op(event_loop* loop, int fd, proxy_client_connection* conn,
                                   bool recv_multishot, bool use_provided_bufs, uint16_t buf_group)
{
    conn->read_pending = true;
    if (recv_multishot)
        loop->submit_recv_multishot(fd, buf_group, &conn->read_req);
    else if (use_provided_bufs)
        loop->submit_read_provided(fd, buf_group, &conn->read_req);
    else
        loop->submit_read(fd, conn->read_buf, sizeof(conn->read_buf), &conn->read_req);
}

static inline void submit_read_op_backend(event_loop* loop, int fd, proxy_backend_connection* conn,
                                           bool recv_multishot, bool use_provided_bufs, uint16_t buf_group)
{
    conn->read_pending = true;
    if (recv_multishot)
        loop->submit_recv_multishot(fd, buf_group, &conn->read_req);
    else if (use_provided_bufs)
        loop->submit_read_provided(fd, buf_group, &conn->read_req);
    else
        loop->submit_read(fd, conn->read_buf, sizeof(conn->read_buf), &conn->read_req);
}

void proxy_instance::handle_client_read(struct io_uring_cqe* cqe, io_request* req)
{
    int fd = req->fd;
    auto& entry = m_conn_idx[fd];
    if (PROXY_UNLIKELY(entry.side != conn_client))
        return;

    auto* conn = entry.client;

    bool is_multishot_recv = (req->type == op_recv_multishot);
    bool multishot_more = is_multishot_recv && (cqe->flags & IORING_CQE_F_MORE);

    if (!is_multishot_recv)
        conn->read_pending = false;
    else if (!multishot_more)
        conn->read_pending = false;

    bool is_provided = (req->type == op_read_provided || is_multishot_recv);

    if (PROXY_UNLIKELY(cqe->res <= 0))
    {
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
            m_loop->submit_read(fd, conn->read_buf, sizeof(conn->read_buf), &conn->read_req);
            return;
        }

        close_pair(fd, conn->backend_fd);
        return;
    }

    conn->last_activity = std::chrono::steady_clock::now();

    // Extract read data
    char* read_data;
    uint16_t buf_id = 0;
    if (is_provided)
    {
        buf_id = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
        read_data = m_loop->get_buf_ptr(BUF_GROUP_ID, buf_id);
        if (PROXY_UNLIKELY(!read_data))
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
        // TCP mode: connect on first read, then forward raw bytes
        if (PROXY_UNLIKELY(conn->backend_fd < 0))
        {
            auto* target = select_and_resolve_backend(conn);
            if (PROXY_UNLIKELY(!target))
            {
                if (is_provided)
                    m_loop->return_buf(BUF_GROUP_ID, buf_id);
                close_pair(fd, -1);
                return;
            }
            if (PROXY_UNLIKELY(!connect_to_backend(conn, target)))
            {
                record_backend_error(conn->backend_idx);
                if (is_provided)
                    m_loop->return_buf(BUF_GROUP_ID, buf_id);
                close_pair(fd, -1);
                return;
            }
        }

        std::string_view data(read_data, cqe->res);
        forward_to_backend(conn, data);
        if (is_provided)
            m_loop->return_buf(BUF_GROUP_ID, buf_id);

        if (PROXY_LIKELY(!conn->closing))
        {
            if (!conn->read_pending)
                submit_read_op(m_loop, fd, conn, m_recv_multishot, m_use_provided_bufs, BUF_GROUP_ID);
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

    if (PROXY_UNLIKELY(conn->partial.size() > proxy_client_connection::MAX_PARTIAL_SIZE))
    {
        close_pair(fd, conn->backend_fd);
        return;
    }

    if (!conn->header_parsed)
    {
        if (!parse_http_request_line(conn))
        {
            // Need more data
            if (!conn->read_pending)
                submit_read_op(m_loop, fd, conn, m_recv_multishot, m_use_provided_bufs, BUF_GROUP_ID);
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
        if (PROXY_UNLIKELY(!target))
        {
            send_error(conn, "503 Service Unavailable", "Service Unavailable\n");
            return;
        }

        if (PROXY_UNLIKELY(!connect_to_backend(conn, target)))
        {
            record_backend_error(conn->backend_idx);
            if (!try_retry(conn))
            {
                send_error(conn, "502 Bad Gateway", "Bad Gateway\n");
                return;
            }
            // Retry succeeded — request already forwarded by try_retry
            goto proxy_http_resubmit;
        }

        // Rewrite request and forward
        {
            std::string rewritten = rewrite_http_request(conn, new_path);
            if (m_mesh.retry_count > 0)
                conn->saved_request = rewritten;
            forward_to_backend(conn, rewritten);
        }
    }
    else
    {
        // Subsequent data (request body) — forward as-is
        forward_to_backend(conn, conn->partial);
        conn->partial.clear();
    }

proxy_http_resubmit:
    if (PROXY_LIKELY(!conn->closing))
    {
        if (!conn->read_pending)
            submit_read_op(m_loop, fd, conn, m_recv_multishot, m_use_provided_bufs, BUF_GROUP_ID);
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
    if (PROXY_UNLIKELY(entry.side != conn_backend))
        return;

    auto* conn = entry.backend;

    bool is_multishot_recv = (req->type == op_recv_multishot);
    bool multishot_more = is_multishot_recv && (cqe->flags & IORING_CQE_F_MORE);

    if (!is_multishot_recv)
        conn->read_pending = false;
    else if (!multishot_more)
        conn->read_pending = false;

    bool is_provided = (req->type == op_read_provided || is_multishot_recv);

    if (PROXY_UNLIKELY(cqe->res <= 0))
    {
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
            m_loop->submit_read(fd, conn->read_buf, sizeof(conn->read_buf), &conn->read_req);
            return;
        }

        // Record circuit breaker error for the backend that failed
        if (conn->client_fd >= 0 && conn->client_fd < MAX_FDS)
        {
            auto& ce = m_conn_idx[conn->client_fd];
            if (ce.side == conn_client)
                record_backend_error(ce.client->backend_idx);
        }

        close_pair(conn->client_fd, fd);
        return;
    }

    // Backend responded successfully — record for circuit breaker
    if (conn->client_fd >= 0 && conn->client_fd < MAX_FDS)
    {
        auto& ce = m_conn_idx[conn->client_fd];
        if (ce.side == conn_client)
            record_backend_success(ce.client->backend_idx);
    }

    if (is_provided)
    {
        uint16_t buf_id = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
        char* buf_ptr = m_loop->get_buf_ptr(BUF_GROUP_ID, buf_id);
        if (PROXY_LIKELY(buf_ptr))
        {
            std::string_view data(buf_ptr, cqe->res);
            forward_to_client(conn, data);
            m_loop->return_buf(BUF_GROUP_ID, buf_id);
        }
    }
    else
    {
        std::string_view data(conn->read_buf, cqe->res);
        forward_to_client(conn, data);
    }

    if (PROXY_LIKELY(!conn->closing))
    {
        if (!conn->read_pending)
            submit_read_op_backend(m_loop, fd, conn, m_recv_multishot, m_use_provided_bufs, BUF_GROUP_ID);
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

    return true;
}

std::string proxy_instance::rewrite_http_request(proxy_client_connection* conn,
                                                  std::string_view new_path)
{
    // Find end of request line
    auto pos = conn->partial.find("\r\n");
    std::string result;
    result.reserve(conn->method.size() + 1 + new_path.size() + 1
                   + conn->version.size() + conn->partial.size() - pos);
    result += conn->method;
    result += ' ';
    result += new_path;
    result += ' ';
    result += conn->version;
    result.append(conn->partial, pos); // includes \r\n and rest of headers+body
    conn->partial.clear();
    return result;
}

const backend_info* proxy_instance::select_and_resolve_backend(proxy_client_connection* conn)
{
    if (PROXY_UNLIKELY(m_backends.empty()))
        return nullptr;

    // Fast path: check if any backend is a group
    bool has_group = false;
    for (const auto& b : m_backends)
    {
        if (b.is_group) { has_group = true; break; }
    }

    if (PROXY_LIKELY(!has_group))
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
                if (PROXY_UNLIKELY(cb.current == circuit_breaker::open))
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
                // Count available backends
                size_t avail_count = 0;
                for (size_t i = 0; i < pool_size; i++)
                    if (is_backend_available(i)) avail_count++;

                if (avail_count == 0)
                    return nullptr;

                std::uniform_int_distribution<size_t> dist(0, avail_count - 1);
                size_t pick = dist(m_rng);
                size_t k = 0;
                for (size_t i = 0; i < pool_size; i++)
                {
                    if (!is_backend_available(i)) continue;
                    if (k == pick) { selected_idx = i; found = true; break; }
                    k++;
                }
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

        if (PROXY_UNLIKELY(!found))
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

    // Write selected result into scratch space
    m_scratch_backend.resolved_host = std::move(selected->host);
    m_scratch_backend.resolved_port = selected->port;
    m_scratch_backend.has_cached_addr = false;
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

        // Check if still connected (non-blocking poll for hangup)
        struct pollfd pfd{pb.fd, POLLIN | POLLHUP, 0};
        int ret = poll(&pfd, 1, 0);
        if (ret > 0 && (pfd.revents & (POLLHUP | POLLERR)))
        {
            close(pb.fd);
            continue;
        }

        return pb.fd;
    }

    return -1;
}

// Return a backend fd to the pool for later reuse
void proxy_instance::release_to_pool(int backend_fd, size_t backend_idx)
{
    if (backend_fd < 0 || backend_idx >= m_backend_pool.size())
        return;

    auto& pool = m_backend_pool[backend_idx];
    if (pool.size() >= MAX_POOL_PER_BACKEND)
    {
        // Pool full — close the oldest
        auto& oldest = pool.front();
        if (oldest.fd >= 0)
        {
            shutdown(oldest.fd, SHUT_RDWR);
            close(oldest.fd);
        }
        pool.erase(pool.begin());
    }

    pool.push_back({backend_fd, backend_idx, std::chrono::steady_clock::now()});
}

bool proxy_instance::connect_to_backend(proxy_client_connection* conn, const backend_info* target)
{
    if (PROXY_UNLIKELY(!target || target->resolved_port == 0))
        return false;

    int bfd = -1;

    // Try connection pool first (TCP mode, non-group backends)
    if (m_protocol == protocol_tcp && !target->is_group &&
        conn->backend_idx < m_backend_pool.size())
    {
        bfd = acquire_pooled_backend(conn->backend_idx);
    }

    if (bfd < 0)
    {
        // No pooled connection — create new one
        if (target->has_cached_addr)
        {
            // Fast path: use pre-cached sockaddr_in directly — no getaddrinfo
            bfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
            if (bfd < 0)
                return false;

            if (::connect(bfd, reinterpret_cast<const struct sockaddr*>(&target->cached_addr),
                           sizeof(target->cached_addr)) < 0 && errno != EINPROGRESS)
            {
                close(bfd);
                return false;
            }
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

            bfd = socket(result->ai_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
            if (bfd < 0)
            {
                freeaddrinfo(result);
                return false;
            }

            if (::connect(bfd, result->ai_addr, result->ai_addrlen) < 0 && errno != EINPROGRESS)
            {
                close(bfd);
                freeaddrinfo(result);
                return false;
            }

            // Cache the resolved address for future connections (avoids blocking DNS)
            if (result->ai_family == AF_INET && result->ai_addrlen == sizeof(struct sockaddr_in))
            {
                auto* mutable_target = const_cast<backend_info*>(target);
                std::memcpy(&mutable_target->cached_addr, result->ai_addr, sizeof(struct sockaddr_in));
                mutable_target->has_cached_addr = true;
            }

            freeaddrinfo(result);
        }

        tune_socket(bfd);
    }

    if (PROXY_UNLIKELY(bfd >= MAX_FDS))
    {
        close(bfd);
        return false;
    }

    conn->backend_fd = bfd;

    auto bconn = std::make_unique<proxy_backend_connection>();
    bconn->fd = bfd;
    bconn->client_fd = conn->fd;
    bconn->read_req = { op_read, bfd, bconn->read_buf, sizeof(bconn->read_buf), this };
    bconn->write_req = { op_write, bfd, nullptr, 0, this };
    bconn->splice_in_req = { op_splice, bfd, nullptr, 0, this };
    bconn->splice_out_req = { op_splice, bfd, nullptr, 0, this };

    auto* ptr = bconn.get();
    m_backend_conns[bfd] = std::move(bconn);
    m_conn_idx[bfd].side = conn_backend;
    m_conn_idx[bfd].backend = ptr;

    // Set up splice pipes for TCP mode zero-copy forwarding if:
    // 1. TCP mode (no HTTP rewriting needed)
    // 2. No Lua/C++ intercept hooks (splice bypasses userspace)
    // 3. Kernel supports splice
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
            setup_splice_pipes(conn, ptr);
    }

    ptr->read_pending = true;
    if (m_recv_multishot)
        m_loop->submit_recv_multishot(bfd, BUF_GROUP_ID, &ptr->read_req);
    else if (m_use_provided_bufs)
        m_loop->submit_read_provided(bfd, BUF_GROUP_ID, &ptr->read_req);
    else
        m_loop->submit_read(bfd, ptr->read_buf, sizeof(ptr->read_buf), &ptr->read_req);

    return true;
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

    // Client -> pipe_write (first leg of client -> backend)
    if (!conn->splice_in_pending)
    {
        conn->splice_in_pending = true;
        m_loop->submit_splice(conn->fd, conn->pipe_to_backend[1],
                              PROXY_READ_BUF_SIZE, &conn->splice_in_req);
    }

    // Backend -> pipe_write (first leg of backend -> client)
    if (!bconn->splice_in_pending)
    {
        bconn->splice_in_pending = true;
        m_loop->submit_splice(bconn->fd, bconn->pipe_to_client[1],
                              PROXY_READ_BUF_SIZE, &bconn->splice_in_req);
    }
}

void proxy_instance::handle_splice(struct io_uring_cqe* cqe, io_request* req)
{
    if (PROXY_UNLIKELY(req->fd < 0 || req->fd >= MAX_FDS))
        return;

    auto& entry = m_conn_idx[req->fd];

    if (entry.side == conn_client)
    {
        auto* conn = entry.client;

        // Determine which splice op completed
        if (req == &conn->splice_in_req)
        {
            conn->splice_in_pending = false;

            if (PROXY_UNLIKELY(cqe->res <= 0))
            {
                close_pair(conn->fd, conn->backend_fd);
                return;
            }

            // Data is now in pipe_to_backend — splice it out to the backend fd
            if (conn->backend_fd >= 0)
            {
                conn->splice_out_pending = true;
                m_loop->submit_splice(conn->pipe_to_backend[0], conn->backend_fd,
                                      static_cast<uint32_t>(cqe->res), &conn->splice_out_req);
            }
        }
        else if (req == &conn->splice_out_req)
        {
            conn->splice_out_pending = false;

            if (PROXY_UNLIKELY(cqe->res <= 0))
            {
                close_pair(conn->fd, conn->backend_fd);
                return;
            }

            // Resubmit the inbound splice (client -> pipe)
            if (PROXY_LIKELY(!conn->closing))
            {
                conn->splice_in_pending = true;
                m_loop->submit_splice(conn->fd, conn->pipe_to_backend[1],
                                      PROXY_READ_BUF_SIZE, &conn->splice_in_req);
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

            if (PROXY_UNLIKELY(cqe->res <= 0))
            {
                close_pair(conn->client_fd, conn->fd);
                return;
            }

            // Data is now in pipe_to_client — splice it out to the client fd
            if (conn->client_fd >= 0)
            {
                conn->splice_out_pending = true;
                m_loop->submit_splice(conn->pipe_to_client[0], conn->client_fd,
                                      static_cast<uint32_t>(cqe->res), &conn->splice_out_req);
            }
        }
        else if (req == &conn->splice_out_req)
        {
            conn->splice_out_pending = false;

            if (PROXY_UNLIKELY(cqe->res <= 0))
            {
                close_pair(conn->client_fd, conn->fd);
                return;
            }

            // Resubmit the inbound splice (backend -> pipe)
            if (PROXY_LIKELY(!conn->closing))
            {
                conn->splice_in_pending = true;
                m_loop->submit_splice(conn->fd, conn->pipe_to_client[1],
                                      PROXY_READ_BUF_SIZE, &conn->splice_in_req);
            }
            else
            {
                close_pair(conn->client_fd, conn->fd);
            }
        }
    }
}

void proxy_instance::close_pair(int client_fd, int backend_fd)
{
    if (backend_fd >= 0 && backend_fd < MAX_FDS)
    {
        auto& be = m_conn_idx[backend_fd];
        if (be.side == conn_backend)
        {
            auto* bconn = be.backend;
            if (bconn->read_pending || bconn->write_pending ||
                bconn->splice_in_pending || bconn->splice_out_pending)
            {
                bconn->closing = true;
            }
            else
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

                close(backend_fd);
                m_conn_idx[backend_fd] = {};
                m_backend_conns.erase(backend_fd);
            }
        }
        // else: backend was already closed and erased.
        // Do NOT call close() here — the fd integer may have been reused.
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
                    if (bconn2->read_pending || bconn2->write_pending ||
                        bconn2->splice_in_pending || bconn2->splice_out_pending)
                    {
                        bconn2->closing = true;
                    }
                    else
                    {
                        // Close splice pipes
                        if (bconn2->pipe_to_client[0] >= 0) close(bconn2->pipe_to_client[0]);
                        if (bconn2->pipe_to_client[1] >= 0) close(bconn2->pipe_to_client[1]);
                        bconn2->pipe_to_client[0] = -1;
                        bconn2->pipe_to_client[1] = -1;

                        close(conn->backend_fd);
                        m_conn_idx[conn->backend_fd] = {};
                        m_backend_conns.erase(conn->backend_fd);
                    }
                }
                // else: already closed and erased — do not close again.
                conn->backend_fd = -1;
            }

            if (conn->read_pending || conn->write_pending ||
                conn->splice_in_pending || conn->splice_out_pending)
            {
                conn->closing = true;
            }
            else
            {
                invoke_on_disconnect(client_fd);

                // Close splice pipes
                if (conn->pipe_to_backend[0] >= 0) close(conn->pipe_to_backend[0]);
                if (conn->pipe_to_backend[1] >= 0) close(conn->pipe_to_backend[1]);
                conn->pipe_to_backend[0] = -1;
                conn->pipe_to_backend[1] = -1;

                close(client_fd);
                m_conn_idx[client_fd] = {};
                m_clients.erase(client_fd);
            }
        }
        // else: client was already closed and erased.
        // Do NOT call close() here for the same fd-reuse reason.
    }
}

bool proxy_instance::is_backend_available(size_t idx) const
{
    if (PROXY_UNLIKELY(idx >= m_backends.size()))
        return false;

    // Check health
    if (idx < m_backend_health.size() && !m_backend_health[idx].healthy)
        return false;

    // Check circuit breaker
    if (idx < m_circuit_breakers.size())
    {
        const auto& cb = m_circuit_breakers[idx];
        if (PROXY_UNLIKELY(cb.current == circuit_breaker::open))
        {
            auto elapsed = std::chrono::steady_clock::now() - cb.opened_at;
            if (elapsed < std::chrono::seconds(m_mesh.circuit_timeout))
                return false;
            // Expired: will transition to half_open on next request
        }
    }

    return true;
}

void proxy_instance::health_check_sweep()
{
    auto now = std::chrono::steady_clock::now();

    for (size_t i = 0; i < m_backends.size(); i++)
    {
        auto& b = m_backends[i];
        if (b.is_group)
            continue;

        if (i >= m_backend_health.size())
            break;

        auto& health = m_backend_health[i];

        // TCP health check: try to connect
        if (m_mesh.health_check == mesh_config::health_tcp)
        {
            int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
            if (fd < 0)
            {
                health.consecutive_failures++;
                if (health.consecutive_failures >= m_mesh.health_threshold)
                    health.healthy = false;
                health.last_check = now;
                continue;
            }

            struct sockaddr_in addr{};
            if (b.has_cached_addr)
            {
                addr = b.cached_addr;
            }
            else
            {
                addr.sin_family = AF_INET;
                addr.sin_port = htons(b.resolved_port);
                inet_pton(AF_INET, b.resolved_host.c_str(), &addr.sin_addr);
            }

            int ret = ::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
            if (ret == 0 || errno == EINPROGRESS)
            {
                // Connection succeeded or in progress — backend is reachable
                health.consecutive_failures = 0;
                health.healthy = true;
            }
            else
            {
                health.consecutive_failures++;
                if (health.consecutive_failures >= m_mesh.health_threshold)
                    health.healthy = false;
            }

            close(fd);
            health.last_check = now;
        }
        else if (m_mesh.health_check == mesh_config::health_http)
        {
            // HTTP health check: connect + send GET request + check for 2xx
            int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
            if (fd < 0)
            {
                health.consecutive_failures++;
                if (health.consecutive_failures >= m_mesh.health_threshold)
                    health.healthy = false;
                health.last_check = now;
                continue;
            }

            struct sockaddr_in addr{};
            if (b.has_cached_addr)
                addr = b.cached_addr;
            else
            {
                addr.sin_family = AF_INET;
                addr.sin_port = htons(b.resolved_port);
                inet_pton(AF_INET, b.resolved_host.c_str(), &addr.sin_addr);
            }

            int ret = ::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
            bool connected = (ret == 0);
            if (!connected && errno == EINPROGRESS)
            {
                // Wait briefly for connection (blocking poll with 1s timeout)
                struct pollfd pfd{fd, POLLOUT, 0};
                if (poll(&pfd, 1, 1000) > 0 && (pfd.revents & POLLOUT))
                {
                    int err = 0;
                    socklen_t elen = sizeof(err);
                    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
                    connected = (err == 0);
                }
            }

            if (connected)
            {
                // Send HTTP GET health path
                std::string req_str = "GET " + m_mesh.health_path + " HTTP/1.0\r\nHost: " +
                                       b.resolved_host + "\r\nConnection: close\r\n\r\n";
                if (::write(fd, req_str.data(), req_str.size()) < 0) { /* ignore */ }

                // Read response (blocking with short timeout)
                struct pollfd pfd{fd, POLLIN, 0};
                char buf[256];
                bool got_2xx = false;
                if (poll(&pfd, 1, 2000) > 0 && (pfd.revents & POLLIN))
                {
                    ssize_t n = ::read(fd, buf, sizeof(buf) - 1);
                    if (n > 12)
                    {
                        buf[n] = '\0';
                        // Check "HTTP/1.x 2xx"
                        if (buf[9] == '2')
                            got_2xx = true;
                    }
                }

                if (got_2xx)
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
            }
            else
            {
                health.consecutive_failures++;
                if (health.consecutive_failures >= m_mesh.health_threshold)
                    health.healthy = false;
            }

            close(fd);
            health.last_check = now;
        }
    }
}

void proxy_instance::record_backend_error(size_t backend_idx)
{
    if (PROXY_UNLIKELY(backend_idx >= m_circuit_breakers.size()))
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
    if (PROXY_UNLIKELY(backend_idx >= m_circuit_breakers.size()))
        return;

    auto& cb = m_circuit_breakers[backend_idx];

    if (cb.current == circuit_breaker::half_open)
    {
        // Half-open probe succeeded -> close circuit
        cb.current = circuit_breaker::closed;
        cb.error_count = 0;
    }
}

bool proxy_instance::try_retry(proxy_client_connection* conn)
{
    if (conn->retries_remaining <= 0 || m_mesh.retry_count <= 0)
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
            m_backend_conns.erase(conn->backend_fd);
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
    auto [p1, e1] = std::to_chars(num_buf, num_buf + sizeof(num_buf), m_backend_conns.size());
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

    return out;
}

void proxy_instance::set_on_proxy_request(proxy_hook cb) { m_cb_on_proxy_request = std::move(cb); }
void proxy_instance::set_on_proxy_response(proxy_hook cb) { m_cb_on_proxy_response = std::move(cb); }

void proxy_instance::forward_to_backend(proxy_client_connection* conn, std::string_view data)
{
    if (PROXY_UNLIKELY(conn->backend_fd < 0 || !m_loop))
        return;

    if (PROXY_UNLIKELY(conn->backend_fd >= MAX_FDS))
        return;

    auto& be = m_conn_idx[conn->backend_fd];
    if (PROXY_UNLIKELY(be.side != conn_backend))
        return;

    auto* bconn = be.backend;
    if (PROXY_UNLIKELY(bconn->closing))
        return;

    std::string hook_storage;
    std::string_view effective = data;

    if (m_cb_on_proxy_request)
    {
        auto result = m_cb_on_proxy_request(conn->fd, data);
        if (!result) return;  // nullopt = drop
        if (!result->empty()) { hook_storage = std::move(*result); effective = hook_storage; }
    }
#ifndef SOCKETLEY_NO_LUA
    else if (auto* lctx = lua(); lctx && lctx->has_on_proxy_request())
    {
        try {
            sol::object r = lctx->on_proxy_request()(conn->fd, data);
            if (r.get_type() == sol::type::nil) return;   // drop
            if (r.is<std::string>()) {
                hook_storage = r.as<std::string>();
                effective = hook_storage;
            }
        } catch (const sol::error& e) {
            fprintf(stderr, "[lua] on_proxy_request error: %s\n", e.what());
        }
    }
#endif

    if (PROXY_UNLIKELY(bconn->write_queue.size() >= proxy_backend_connection::MAX_WRITE_QUEUE))
    {
        bconn->closing = true;
        return;
    }

    bconn->write_queue.emplace(effective);

    if (!bconn->write_pending)
        flush_backend_write_queue(bconn);
}

void proxy_instance::forward_to_client(proxy_backend_connection* conn, std::string_view data)
{
    if (PROXY_UNLIKELY(!m_loop))
        return;

    if (PROXY_UNLIKELY(conn->client_fd < 0 || conn->client_fd >= MAX_FDS))
        return;

    auto& ce = m_conn_idx[conn->client_fd];
    if (PROXY_UNLIKELY(ce.side != conn_client))
        return;

    auto* cconn = ce.client;
    if (PROXY_UNLIKELY(cconn->closing))
        return;

    std::string hook_storage;
    std::string_view effective = data;

    if (m_cb_on_proxy_response)
    {
        auto result = m_cb_on_proxy_response(conn->client_fd, data);
        if (!result) return;  // nullopt = drop
        if (!result->empty()) { hook_storage = std::move(*result); effective = hook_storage; }
    }
#ifndef SOCKETLEY_NO_LUA
    else if (auto* lctx = lua(); lctx && lctx->has_on_proxy_response())
    {
        try {
            sol::object r = lctx->on_proxy_response()(conn->client_fd, data);
            if (r.get_type() == sol::type::nil) return;   // drop
            if (r.is<std::string>()) {
                hook_storage = r.as<std::string>();
                effective = hook_storage;
            }
        } catch (const sol::error& e) {
            fprintf(stderr, "[lua] on_proxy_response error: %s\n", e.what());
        }
    }
#endif

    if (PROXY_UNLIKELY(cconn->write_queue.size() >= proxy_client_connection::MAX_WRITE_QUEUE))
    {
        cconn->closing = true;
        return;
    }

    cconn->write_queue.emplace(effective);

    if (!cconn->write_pending)
        flush_client_write_queue(cconn);
}

void proxy_instance::send_error(proxy_client_connection* conn, std::string_view status, std::string_view body)
{
    if (!m_loop || conn->closing)
        return;

    // Build response in a stack buffer when possible
    char hdr_buf[256];
    size_t hdr_len = 0;

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

    if (!conn->write_pending)
        flush_client_write_queue(conn);
}

void proxy_instance::flush_client_write_queue(proxy_client_connection* conn)
{
    if (PROXY_UNLIKELY(!m_loop || conn->write_queue.empty() || conn->zc_notif_pending))
        return;

    uint32_t count = 0;
    while (!conn->write_queue.empty() && count < proxy_client_connection::MAX_WRITE_BATCH)
    {
        conn->write_batch[count] = std::move(conn->write_queue.front());
        conn->write_queue.pop();

        conn->write_iovs[count].iov_base = conn->write_batch[count].data();
        conn->write_iovs[count].iov_len = conn->write_batch[count].size();
        count++;
    }

    conn->write_batch_count = count;
    conn->write_pending = true;

    if (count == 1)
    {
        auto len = static_cast<uint32_t>(conn->write_batch[0].size());
        if (m_send_zc && len >= (512u << 10))
        {
            conn->zc_notif_pending = true;
            conn->write_req.type = op_send_zc;
            m_loop->submit_send_zc(conn->fd, conn->write_batch[0].data(), len, &conn->write_req);
        }
        else
        {
            conn->write_req.type = op_write;
            m_loop->submit_write(conn->fd, conn->write_batch[0].data(), len, &conn->write_req);
        }
    }
    else
    {
        conn->write_req.type = op_writev;
        m_loop->submit_writev(conn->fd, conn->write_iovs, count, &conn->write_req);
    }
}

void proxy_instance::flush_backend_write_queue(proxy_backend_connection* conn)
{
    if (PROXY_UNLIKELY(!m_loop || conn->write_queue.empty() || conn->zc_notif_pending))
        return;

    uint32_t count = 0;
    while (!conn->write_queue.empty() && count < proxy_backend_connection::MAX_WRITE_BATCH)
    {
        conn->write_batch[count] = std::move(conn->write_queue.front());
        conn->write_queue.pop();

        conn->write_iovs[count].iov_base = conn->write_batch[count].data();
        conn->write_iovs[count].iov_len = conn->write_batch[count].size();
        count++;
    }

    conn->write_batch_count = count;
    conn->write_pending = true;

    if (count == 1)
    {
        auto len = static_cast<uint32_t>(conn->write_batch[0].size());
        if (m_send_zc && len >= (512u << 10))
        {
            conn->zc_notif_pending = true;
            conn->write_req.type = op_send_zc;
            m_loop->submit_send_zc(conn->fd, conn->write_batch[0].data(), len, &conn->write_req);
        }
        else
        {
            conn->write_req.type = op_write;
            m_loop->submit_write(conn->fd, conn->write_batch[0].data(), len, &conn->write_req);
        }
    }
    else
    {
        conn->write_req.type = op_writev;
        m_loop->submit_writev(conn->fd, conn->write_iovs, count, &conn->write_req);
    }
}

void proxy_instance::handle_client_write(struct io_uring_cqe* cqe, io_request* req)
{
    int fd = req->fd;
    auto& entry = m_conn_idx[fd];
    if (PROXY_UNLIKELY(entry.side != conn_client))
        return;

    auto* conn = entry.client;

    // Zero-copy send notification: buffer is now safe to release
    if (PROXY_UNLIKELY(cqe->flags & IORING_CQE_F_NOTIF))
    {
        conn->zc_notif_pending = false;
        for (uint32_t i = 0; i < conn->write_batch_count; i++)
            conn->write_batch[i].clear();
        conn->write_batch_count = 0;

        if (!conn->write_queue.empty() && !conn->write_pending)
            flush_client_write_queue(conn);
        else if (conn->write_queue.empty() && !conn->write_pending &&
                 conn->closing && !conn->read_pending &&
                 !conn->splice_in_pending && !conn->splice_out_pending)
            close_pair(fd, conn->backend_fd);
        return;
    }

    conn->write_pending = false;

    // Release batch references (unless ZC notif still pending)
    if (PROXY_LIKELY(!conn->zc_notif_pending))
    {
        for (uint32_t i = 0; i < conn->write_batch_count; i++)
            conn->write_batch[i].clear();
        conn->write_batch_count = 0;
    }

    if (PROXY_UNLIKELY(cqe->res <= 0))
    {
        close_pair(fd, conn->backend_fd);
        return;
    }

    if (!conn->write_queue.empty() && !conn->zc_notif_pending)
    {
        flush_client_write_queue(conn);
    }
    else if (conn->closing && !conn->read_pending && !conn->zc_notif_pending &&
             !conn->splice_in_pending && !conn->splice_out_pending)
    {
        close_pair(fd, conn->backend_fd);
    }
}

void proxy_instance::handle_backend_write(struct io_uring_cqe* cqe, io_request* req)
{
    int fd = req->fd;
    auto& entry = m_conn_idx[fd];
    if (PROXY_UNLIKELY(entry.side != conn_backend))
        return;

    auto* conn = entry.backend;

    // Zero-copy send notification: buffer is now safe to release
    if (PROXY_UNLIKELY(cqe->flags & IORING_CQE_F_NOTIF))
    {
        conn->zc_notif_pending = false;
        for (uint32_t i = 0; i < conn->write_batch_count; i++)
            conn->write_batch[i].clear();
        conn->write_batch_count = 0;

        if (!conn->write_queue.empty() && !conn->write_pending)
            flush_backend_write_queue(conn);
        else if (conn->write_queue.empty() && !conn->write_pending &&
                 conn->closing && !conn->read_pending &&
                 !conn->splice_in_pending && !conn->splice_out_pending)
            close_pair(conn->client_fd, fd);
        return;
    }

    conn->write_pending = false;

    // Release batch references (unless ZC notif still pending)
    if (PROXY_LIKELY(!conn->zc_notif_pending))
    {
        for (uint32_t i = 0; i < conn->write_batch_count; i++)
            conn->write_batch[i].clear();
        conn->write_batch_count = 0;
    }

    if (PROXY_UNLIKELY(cqe->res <= 0))
    {
        close_pair(conn->client_fd, fd);
        return;
    }

    if (!conn->write_queue.empty() && !conn->zc_notif_pending)
    {
        flush_backend_write_queue(conn);
    }
    else if (conn->closing && !conn->read_pending && !conn->zc_notif_pending &&
             !conn->splice_in_pending && !conn->splice_out_pending)
    {
        close_pair(conn->client_fd, fd);
    }
}
