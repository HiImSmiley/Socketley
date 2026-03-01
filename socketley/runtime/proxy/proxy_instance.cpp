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
#include <liburing.h>


// Socket buffer sizes: 256KB gives good throughput for bulk transfers
static constexpr int SOCK_BUF_SIZE = 256 * 1024;

// Splice pipe capacity: 64KB is the default, but we can request more via F_SETPIPE_SZ
static constexpr int SPLICE_PIPE_SIZE = 256 * 1024;

proxy_instance::proxy_instance(std::string_view name)
    : runtime_instance(runtime_proxy, name)
{
    std::memset(&m_accept_addr, 0, sizeof(m_accept_addr));
    m_accept_addrlen = sizeof(m_accept_addr);
    m_accept_req = { this, nullptr, -1, 0, op_accept };
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
    while (!write_queue.empty()) write_queue.pop();
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
    connect_pending = false;
    connect_fd = -1;
    connect_req = {};
    std::memset(&connect_addr, 0, sizeof(connect_addr));
}

void proxy_backend_connection::reset(int new_fd)
{
    fd = new_fd;
    read_pending = false;
    write_pending = false;
    closing = false;
    zc_notif_pending = false;
    splice_active = false;
    splice_in_pending = false;
    splice_out_pending = false;
    client_fd = -1;
    write_batch_count = 0;
    read_req = {};
    write_req = {};
    splice_in_req = {};
    splice_out_req = {};
    partial.clear();
    while (!write_queue.empty()) write_queue.pop();
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
    }
    return conn;
}

void proxy_instance::client_pool_release(std::unique_ptr<proxy_client_connection> conn)
{
    conn->partial.clear();
    while (!conn->write_queue.empty()) conn->write_queue.pop();
    for (uint32_t i = 0; i < conn->write_batch_count; i++) conn->write_batch[i].clear();
    conn->write_batch_count = 0;
    if (conn->pipe_to_backend[0] >= 0) { close(conn->pipe_to_backend[0]); conn->pipe_to_backend[0] = -1; }
    if (conn->pipe_to_backend[1] >= 0) { close(conn->pipe_to_backend[1]); conn->pipe_to_backend[1] = -1; }
    conn->method.clear();
    conn->path.clear();
    conn->version.clear();
    conn->saved_request.clear();
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
    }
    return conn;
}

void proxy_instance::backend_pool_release(std::unique_ptr<proxy_backend_connection> conn)
{
    conn->partial.clear();
    while (!conn->write_queue.empty()) conn->write_queue.pop();
    for (uint32_t i = 0; i < conn->write_batch_count; i++) conn->write_batch[i].clear();
    conn->write_batch_count = 0;
    if (conn->pipe_to_client[0] >= 0) { close(conn->pipe_to_client[0]); conn->pipe_to_client[0] = -1; }
    if (conn->pipe_to_client[1] >= 0) { close(conn->pipe_to_client[1]); conn->pipe_to_client[1] = -1; }
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
    // Clear any connections left from a previous stop() — safe to free now that
    // all in-flight CQEs have been processed (we're starting a fresh run).
    std::memset(m_conn_idx, 0, sizeof(m_conn_idx));
    for (int i = 0; i < MAX_FDS; i++)
    {
        if (m_client_slots[i]) m_client_slots[i].reset();
        if (m_backend_slots[i]) m_backend_slots[i].reset();
    }
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

    m_idle_timeout_cached = get_idle_timeout();
    m_max_conns_cached = get_max_connections();
    if (m_idle_timeout_cached > 0)
    {
        m_idle_sweep_ts.tv_sec = 30;
        m_idle_sweep_ts.tv_nsec = 0;
        m_idle_sweep_req = { this, nullptr, -1, 0, op_timeout };
        m_loop->submit_timeout(&m_idle_sweep_ts, &m_idle_sweep_req);
    }

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

    // Initialize async health check state
    m_health_checks.clear();
    m_health_checks.resize(m_backends.size());
    for (size_t i = 0; i < m_health_checks.size(); i++)
    {
        m_health_checks[i].backend_idx = i;
        m_health_checks[i].current = async_health_check::idle;
    }
    m_health_checks_pending = false;

    // Start health check timer if configured
    if (m_mesh.health_check != mesh_config::health_none && m_mesh.health_interval > 0)
    {
        m_health_check_ts.tv_sec = m_mesh.health_interval;
        m_health_check_ts.tv_nsec = 0;
        m_health_check_req = { this, nullptr, -1, 0, op_timeout };
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
    m_accept_backoff_req.owner = nullptr;
    m_idle_sweep_req.owner = nullptr;
    m_health_check_req.owner = nullptr;
    m_health_timeout_req.owner = nullptr;
    for (int i = 0; i < MAX_FDS; i++)
    {
        if (m_client_slots[i])
        {
            m_client_slots[i]->read_req.owner  = nullptr;
            m_client_slots[i]->write_req.owner = nullptr;
            m_client_slots[i]->splice_in_req.owner = nullptr;
            m_client_slots[i]->splice_out_req.owner = nullptr;
            m_client_slots[i]->connect_req.owner = nullptr;
        }
        if (m_backend_slots[i])
        {
            m_backend_slots[i]->read_req.owner  = nullptr;
            m_backend_slots[i]->write_req.owner = nullptr;
            m_backend_slots[i]->splice_in_req.owner = nullptr;
            m_backend_slots[i]->splice_out_req.owner = nullptr;
        }
    }
    // Null health check req owners and close fds
    for (auto& hc : m_health_checks)
    {
        hc.req.owner = nullptr;
        if (hc.fd >= 0) { close(hc.fd); hc.fd = -1; }
        hc.current = async_health_check::idle;
    }
    m_health_checks_pending = false;

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
        for (int i = 0; i < MAX_FDS; i++)
        {
            auto& conn = m_client_slots[i];
            if (!conn) continue;
            while (!conn->write_queue.empty())
            {
                auto& msg = conn->write_queue.front();
                if (::write(i, msg.data(), msg.size()) < 0) break;
                conn->write_queue.pop();
            }
        }
    }

    for (int i = 0; i < MAX_FDS; i++)
    {
        auto& conn = m_backend_slots[i];
        if (!conn) continue;
        // Close splice pipes
        if (conn->pipe_to_client[0] >= 0) close(conn->pipe_to_client[0]);
        if (conn->pipe_to_client[1] >= 0) close(conn->pipe_to_client[1]);
        shutdown(i, SHUT_RDWR);
        close(i);
    }

    for (int i = 0; i < MAX_FDS; i++)
    {
        auto& conn = m_client_slots[i];
        if (!conn) continue;
        // Close splice pipes
        if (conn->pipe_to_backend[0] >= 0) close(conn->pipe_to_backend[0]);
        if (conn->pipe_to_backend[1] >= 0) close(conn->pipe_to_backend[1]);
        // Close pending async connect fd
        if (conn->connect_fd >= 0) { close(conn->connect_fd); conn->connect_fd = -1; }
        shutdown(i, SHUT_RDWR);
        close(i);
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
    if (SOCKETLEY_UNLIKELY(!req || !m_loop))
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
            if (SOCKETLEY_UNLIKELY(req->fd < 0 || req->fd >= MAX_FDS)) break;
            auto& re = m_conn_idx[req->fd];
            if (SOCKETLEY_LIKELY(re.side == conn_client))
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
            handle_connect(cqe, req);
            break;
        case op_health_check:
            handle_health_cqe(cqe, req);
            break;
        case op_timeout:
            if (req == &m_idle_sweep_req)
            {
                auto now = std::chrono::steady_clock::now();
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
            // Health check timeout — mark all still-pending checks as failed
            else if (req == &m_health_timeout_req)
            {
                for (auto& hc : m_health_checks)
                {
                    if (hc.current != async_health_check::idle && hc.current != async_health_check::done)
                    {
                        // Timed out — count as failure
                        if (hc.fd >= 0) { close(hc.fd); hc.fd = -1; }
                        hc.current = async_health_check::done;
                        if (hc.backend_idx < m_backend_health.size())
                        {
                            auto& health = m_backend_health[hc.backend_idx];
                            health.consecutive_failures++;
                            if (health.consecutive_failures >= m_mesh.health_threshold)
                                health.healthy = false;
                            health.last_check = std::chrono::steady_clock::now();
                        }
                    }
                }
                m_health_checks_pending = false;
            }
            break;
        default:
            break;
    }
}

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
    if (SOCKETLEY_UNLIKELY(client_fd == -EMFILE || client_fd == -ENFILE))
    {
        m_accept_backoff_ts.tv_sec = 0;
        m_accept_backoff_ts.tv_nsec = 100000000LL;
        m_accept_backoff_req = { this, nullptr, -1, 0, op_timeout };
        m_loop->submit_timeout(&m_accept_backoff_ts, &m_accept_backoff_req);
        return;
    }

proxy_resubmit_accept:
    if (m_multishot_active)
    {
        if (!(cqe->flags & IORING_CQE_F_MORE))
        {
            if (SOCKETLEY_LIKELY(m_listen_fd >= 0))
                m_loop->submit_multishot_accept(m_listen_fd, &m_accept_req);
        }
    }
    else
    {
        if (SOCKETLEY_LIKELY(m_listen_fd >= 0))
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
                submit_read_op(m_loop, fd, conn, m_recv_multishot, m_use_provided_bufs, BUF_GROUP_ID);
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

            if (SOCKETLEY_UNLIKELY(!connect_to_backend(conn, target)))
            {
                record_backend_error(conn->backend_idx);
                close_pair(fd, -1);
                return;
            }

            if (conn->connect_pending)
            {
                // Async connect submitted — handle_connect will forward saved data
                if (SOCKETLEY_LIKELY(!conn->closing) && !conn->read_pending)
                    submit_read_op(m_loop, fd, conn, m_recv_multishot, m_use_provided_bufs, BUF_GROUP_ID);
                return;
            }

            // Pooled connection acquired synchronously — forward saved data
            forward_to_backend(conn, conn->saved_request);
            conn->saved_request.clear();

            if (SOCKETLEY_LIKELY(!conn->closing))
            {
                if (!conn->splice_active && !conn->read_pending)
                    submit_read_op(m_loop, fd, conn, m_recv_multishot, m_use_provided_bufs, BUF_GROUP_ID);
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
                        be.backend->write_queue.size() >= WRITE_QUEUE_BACKPRESSURE)
                        backpressured = true;
                }
                if (!backpressured)
                    submit_read_op(m_loop, fd, conn, m_recv_multishot, m_use_provided_bufs, BUF_GROUP_ID);
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
            submit_read_op(m_loop, fd, conn, m_recv_multishot, m_use_provided_bufs, BUF_GROUP_ID);
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
        if (SOCKETLEY_UNLIKELY(!target))
        {
            send_error(conn, "503 Service Unavailable", "Service Unavailable\n");
            return;
        }

        // Rewrite request before connect — save for forwarding
        std::string rewritten = rewrite_http_request(conn, new_path);
        conn->saved_request = std::move(rewritten);

        if (SOCKETLEY_UNLIKELY(!connect_to_backend(conn, target)))
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

        if (conn->connect_pending)
        {
            // Async connect submitted — handle_connect will forward saved_request
            if (SOCKETLEY_LIKELY(!conn->closing) && !conn->read_pending)
                submit_read_op(m_loop, fd, conn, m_recv_multishot, m_use_provided_bufs, BUF_GROUP_ID);
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
                    be.backend->write_queue.size() >= WRITE_QUEUE_BACKPRESSURE)
                    bp = true;
            }
            if (!bp)
                submit_read_op(m_loop, fd, conn, m_recv_multishot, m_use_provided_bufs, BUF_GROUP_ID);
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

    bool is_multishot_recv = (req->type == op_recv_multishot);
    bool multishot_more = is_multishot_recv && (cqe->flags & IORING_CQE_F_MORE);

    if (!is_multishot_recv)
        conn->read_pending = false;
    else if (!multishot_more)
        conn->read_pending = false;

    bool is_provided = (req->type == op_read_provided || is_multishot_recv);

    if (SOCKETLEY_UNLIKELY(cqe->res <= 0))
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
                    ce.client->write_queue.size() >= WRITE_QUEUE_BACKPRESSURE)
                    backpressured = true;
            }
            if (!backpressured)
                submit_read_op_backend(m_loop, fd, conn, m_recv_multishot, m_use_provided_bufs, BUF_GROUP_ID);
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
            if (conn->backend_idx < m_backends.size())
            {
                auto& b = m_backends[conn->backend_idx];
                result += "Host: ";
                result += b.resolved_host;
                result += ':';
                char port_buf[8];
                auto [pend, pec] = std::to_chars(port_buf, port_buf + sizeof(port_buf), b.resolved_port);
                result.append(port_buf, static_cast<size_t>(pend - port_buf));
                result += "\r\n";
            }
            else
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
    if (!host_written && conn->backend_idx < m_backends.size())
    {
        auto& b = m_backends[conn->backend_idx];
        result += "Host: ";
        result += b.resolved_host;
        result += ':';
        char port_buf[8];
        auto [pend, pec] = std::to_chars(port_buf, port_buf + sizeof(port_buf), b.resolved_port);
        result.append(port_buf, static_cast<size_t>(pend - port_buf));
        result += "\r\n";
    }

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
                // Build availability list in a single pass
                size_t avail_indices[MAX_BACKENDS];
                size_t avail_count = 0;
                for (size_t i = 0; i < pool_size; i++)
                {
                    if (is_backend_available(i))
                        avail_indices[avail_count++] = i;
                }

                if (avail_count == 0)
                    return nullptr;

                std::uniform_int_distribution<size_t> dist(0, avail_count - 1);
                selected_idx = avail_indices[dist(m_rng)];
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
}

// Finish setting up backend after connect (pooled or async connect completion).
// Creates backend conn struct, registers in maps, sets up splice/read.
// Returns true if backend is ready. connect_pending will be false.
bool proxy_instance::connect_to_backend(proxy_client_connection* conn, const backend_info* target)
{
    if (SOCKETLEY_UNLIKELY(!target || target->resolved_port == 0))
        return false;

    int bfd = -1;

    // Try connection pool first (both TCP and HTTP, non-group backends)
    if (!target->is_group && conn->backend_idx < m_backend_pool.size())
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
        bconn->read_req = { this, bconn->read_buf, bfd, sizeof(bconn->read_buf), op_read };
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

        ptr->read_pending = true;
        if (m_recv_multishot)
            m_loop->submit_recv_multishot(bfd, BUF_GROUP_ID, &ptr->read_req);
        else if (m_use_provided_bufs)
            m_loop->submit_read_provided(bfd, BUF_GROUP_ID, &ptr->read_req);
        else
            m_loop->submit_read(bfd, ptr->read_buf, sizeof(ptr->read_buf), &ptr->read_req);

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
        bconn->read_req = { this, bconn->read_buf, bfd, sizeof(bconn->read_buf), op_read };
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
                    start_splice_forwarding(conn, ptr);
                    return true;  // connect_pending stays false, splice handles data flow
                }
            }
        }

        // Submit read on backend
        ptr->read_pending = true;
        if (m_recv_multishot)
            m_loop->submit_recv_multishot(bfd, BUF_GROUP_ID, &ptr->read_req);
        else if (m_use_provided_bufs)
            m_loop->submit_read_provided(bfd, BUF_GROUP_ID, &ptr->read_req);
        else
            m_loop->submit_read(bfd, ptr->read_buf, sizeof(ptr->read_buf), &ptr->read_req);

        return true;  // connect_pending stays false — caller forwards saved_request
    }

    if (cr < 0 && errno != EINPROGRESS)
    {
        close(bfd);
        return false;
    }

    // EINPROGRESS — async connect via io_uring
    conn->connect_pending = true;
    conn->connect_fd = bfd;
    conn->connect_addr = addr;
    conn->connect_req = { this, nullptr, conn->fd, 0, op_connect };

    m_loop->submit_connect(bfd,
        reinterpret_cast<const struct sockaddr*>(&conn->connect_addr),
        sizeof(conn->connect_addr), &conn->connect_req);

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

            if (SOCKETLEY_UNLIKELY(cqe->res <= 0))
            {
                // EAGAIN: pipe full or socket has no data yet — retry
                if (cqe->res == -EAGAIN && !conn->closing)
                {
                    conn->splice_in_pending = true;
                    m_loop->submit_splice(conn->fd, conn->pipe_to_backend[1],
                                          PROXY_READ_BUF_SIZE, &conn->splice_in_req);
                    return;
                }
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

            if (SOCKETLEY_UNLIKELY(cqe->res <= 0))
            {
                // EAGAIN: backend send buffer full — retry
                if (cqe->res == -EAGAIN && !conn->closing && conn->backend_fd >= 0)
                {
                    conn->splice_out_pending = true;
                    m_loop->submit_splice(conn->pipe_to_backend[0], conn->backend_fd,
                                          PROXY_READ_BUF_SIZE, &conn->splice_out_req);
                    return;
                }
                close_pair(conn->fd, conn->backend_fd);
                return;
            }

            // Resubmit the inbound splice (client -> pipe)
            if (SOCKETLEY_LIKELY(!conn->closing))
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

            if (SOCKETLEY_UNLIKELY(cqe->res <= 0))
            {
                // EAGAIN: pipe full or backend has no data yet — retry
                if (cqe->res == -EAGAIN && !conn->closing)
                {
                    conn->splice_in_pending = true;
                    m_loop->submit_splice(conn->fd, conn->pipe_to_client[1],
                                          PROXY_READ_BUF_SIZE, &conn->splice_in_req);
                    return;
                }
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

            if (SOCKETLEY_UNLIKELY(cqe->res <= 0))
            {
                // EAGAIN: client send buffer full — retry
                if (cqe->res == -EAGAIN && !conn->closing && conn->client_fd >= 0)
                {
                    conn->splice_out_pending = true;
                    m_loop->submit_splice(conn->pipe_to_client[0], conn->client_fd,
                                          PROXY_READ_BUF_SIZE, &conn->splice_out_req);
                    return;
                }
                close_pair(conn->client_fd, conn->fd);
                return;
            }

            // Resubmit the inbound splice (backend -> pipe)
            if (SOCKETLEY_LIKELY(!conn->closing))
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
        // Null io_request owners before releasing to pool —
        // stale CQEs could arrive after the struct is reused.
        bconn->read_req.owner = nullptr;
        bconn->write_req.owner = nullptr;
        bconn->splice_in_req.owner = nullptr;
        bconn->splice_out_req.owner = nullptr;
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
            if (bconn->read_pending || bconn->write_pending ||
                bconn->splice_in_pending || bconn->splice_out_pending)
            {
                bconn->closing = true;
                shutdown(backend_fd, SHUT_RD);
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
                    if (bconn2->read_pending || bconn2->write_pending ||
                        bconn2->splice_in_pending || bconn2->splice_out_pending)
                    {
                        bconn2->closing = true;
                        shutdown(conn->backend_fd, SHUT_RD);
                    }
                    else
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

            // Close pending async connect fd
            if (conn->connect_fd >= 0)
            {
                close(conn->connect_fd);
                conn->connect_fd = -1;
                conn->connect_pending = false;
            }

            if (conn->read_pending || conn->write_pending ||
                conn->splice_in_pending || conn->splice_out_pending)
            {
                conn->closing = true;
                shutdown(client_fd, SHUT_RD);
            }
            else
            {
                invoke_on_disconnect(client_fd);

                // Close splice pipes
                if (conn->pipe_to_backend[0] >= 0) close(conn->pipe_to_backend[0]);
                if (conn->pipe_to_backend[1] >= 0) close(conn->pipe_to_backend[1]);
                conn->pipe_to_backend[0] = -1;
                conn->pipe_to_backend[1] = -1;

                shutdown(client_fd, SHUT_RDWR);
                close(client_fd);
                m_conn_idx[client_fd] = {};
                if (m_client_slots[client_fd])
                {
                    // Null io_request owners before releasing to pool —
                    // stale CQEs (e.g. async connect) could arrive after reuse.
                    conn->read_req.owner = nullptr;
                    conn->write_req.owner = nullptr;
                    conn->connect_req.owner = nullptr;
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

    // Cannot pool if there are pending io_uring ops — CQEs would arrive for a
    // pooled (unregistered) fd, causing UAF or misrouted completions.
    if (bconn->read_pending || bconn->write_pending || bconn->zc_notif_pending ||
        bconn->splice_in_pending || bconn->splice_out_pending)
    {
        // Fall back to normal close — shutdown will drain pending CQEs
        close_pair(cconn->fd, backend_fd);
        return;
    }

    size_t b_idx = cconn->backend_idx;

    // Clear tracking
    m_conn_idx[backend_fd] = {};
    cconn->backend_fd = -1;

    // Release fd to pool
    release_to_pool(backend_fd, b_idx);

    // Release struct to struct pool
    if (m_backend_slots[backend_fd])
    {
        bconn->read_req.owner = nullptr;
        bconn->write_req.owner = nullptr;
        backend_pool_release(std::move(m_backend_slots[backend_fd]));
        m_backend_count--;
    }

    // Reset client for next HTTP request
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

void proxy_instance::health_check_sweep()
{
    // Skip if previous checks are still in flight
    if (m_health_checks_pending)
        return;

    m_health_checks_pending = true;

    for (size_t i = 0; i < m_backends.size() && i < m_health_checks.size(); i++)
    {
        auto& b = m_backends[i];
        auto& hc = m_health_checks[i];
        hc.backend_idx = i;

        if (b.is_group)
        {
            hc.current = async_health_check::done;
            continue;
        }

        int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (fd < 0)
        {
            hc.current = async_health_check::done;
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

        hc.fd = fd;
        hc.current = async_health_check::connecting;
        hc.req = { this, nullptr, fd, 0, op_health_check };

        struct sockaddr_in addr{};
        if (b.has_cached_addr)
            addr = b.cached_addr;
        else
        {
            addr.sin_family = AF_INET;
            addr.sin_port = htons(b.resolved_port);
            inet_pton(AF_INET, b.resolved_host.c_str(), &addr.sin_addr);
        }

        // Store addr in write_buf for connect (we need it to persist)
        hc.write_buf.clear();
        std::memcpy(hc.buf, &addr, sizeof(addr));

        m_loop->submit_connect(fd,
            reinterpret_cast<const struct sockaddr*>(hc.buf),
            sizeof(struct sockaddr_in), &hc.req);
    }

    // Submit a 500ms timeout for all checks
    m_health_timeout_ts.tv_sec = 0;
    m_health_timeout_ts.tv_nsec = 500000000LL;
    m_health_timeout_req = { this, nullptr, -1, 0, op_timeout };
    m_loop->submit_timeout(&m_health_timeout_ts, &m_health_timeout_req);
}

void proxy_instance::handle_health_cqe(struct io_uring_cqe* cqe, io_request* req)
{
    // Find which health check this belongs to
    async_health_check* hc = nullptr;
    for (auto& check : m_health_checks)
    {
        if (&check.req == req)
        {
            hc = &check;
            break;
        }
    }
    if (!hc || hc->current == async_health_check::done || hc->current == async_health_check::idle)
        return;

    size_t idx = hc->backend_idx;

    if (hc->current == async_health_check::connecting)
    {
        if (cqe->res < 0)
        {
            // Connect failed
            if (hc->fd >= 0) { close(hc->fd); hc->fd = -1; }
            hc->current = async_health_check::done;
            if (idx < m_backend_health.size())
            {
                auto& health = m_backend_health[idx];
                health.consecutive_failures++;
                if (health.consecutive_failures >= m_mesh.health_threshold)
                    health.healthy = false;
                health.last_check = std::chrono::steady_clock::now();
            }
            return;
        }

        // Connect succeeded
        if (m_mesh.health_check == mesh_config::health_tcp)
        {
            // TCP check: connect success is enough
            if (hc->fd >= 0) { close(hc->fd); hc->fd = -1; }
            hc->current = async_health_check::done;
            if (idx < m_backend_health.size())
            {
                auto& health = m_backend_health[idx];
                health.consecutive_failures = 0;
                health.healthy = true;
                health.last_check = std::chrono::steady_clock::now();
            }
            return;
        }

        // HTTP check: send GET request
        if (idx < m_backends.size())
        {
            auto& b = m_backends[idx];
            hc->write_buf = "GET " + m_mesh.health_path + " HTTP/1.0\r\nHost: " +
                            b.resolved_host + "\r\nConnection: close\r\n\r\n";
            hc->current = async_health_check::writing;
            hc->req.type = op_health_check;
            m_loop->submit_write(hc->fd, hc->write_buf.data(),
                                 static_cast<uint32_t>(hc->write_buf.size()), &hc->req);
        }
    }
    else if (hc->current == async_health_check::writing)
    {
        if (cqe->res <= 0)
        {
            if (hc->fd >= 0) { close(hc->fd); hc->fd = -1; }
            hc->current = async_health_check::done;
            if (idx < m_backend_health.size())
            {
                auto& health = m_backend_health[idx];
                health.consecutive_failures++;
                if (health.consecutive_failures >= m_mesh.health_threshold)
                    health.healthy = false;
                health.last_check = std::chrono::steady_clock::now();
            }
            return;
        }

        // Write succeeded — read response
        hc->current = async_health_check::reading;
        hc->req.type = op_health_check;
        m_loop->submit_read(hc->fd, hc->buf, sizeof(hc->buf) - 1, &hc->req);
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

        if (hc->fd >= 0) { close(hc->fd); hc->fd = -1; }
        hc->current = async_health_check::done;

        if (idx < m_backend_health.size())
        {
            auto& health = m_backend_health[idx];
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
            health.last_check = std::chrono::steady_clock::now();
        }
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
    if (SOCKETLEY_UNLIKELY(!conn->connect_pending))
        return;

    conn->connect_pending = false;
    int bfd = conn->connect_fd;
    conn->connect_fd = -1;

    if (cqe->res < 0)
    {
        // Connect failed
        if (bfd >= 0) close(bfd);
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
    bconn->read_req = { this, bconn->read_buf, bfd, sizeof(bconn->read_buf), op_read };
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
                // Forward saved data via write, then start splice
                if (!conn->saved_request.empty())
                {
                    forward_to_backend(conn, conn->saved_request);
                    conn->saved_request.clear();
                }
                start_splice_forwarding(conn, ptr);
                return;
            }
        }
    }

    // Submit read on backend
    ptr->read_pending = true;
    if (m_recv_multishot)
        m_loop->submit_recv_multishot(bfd, BUF_GROUP_ID, &ptr->read_req);
    else if (m_use_provided_bufs)
        m_loop->submit_read_provided(bfd, BUF_GROUP_ID, &ptr->read_req);
    else
        m_loop->submit_read(bfd, ptr->read_buf, sizeof(ptr->read_buf), &ptr->read_req);

    // Forward any saved data
    if (!conn->saved_request.empty())
    {
        forward_to_backend(conn, conn->saved_request);
        if (m_mesh.retry_count <= 0)
            conn->saved_request.clear();
    }
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
    }
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
                // Null io_request owners before releasing to pool —
                // pending CQEs would dereference recycled struct memory.
                old_bconn->read_req.owner = nullptr;
                old_bconn->write_req.owner = nullptr;
                old_bconn->splice_in_req.owner = nullptr;
                old_bconn->splice_out_req.owner = nullptr;
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
    if (SOCKETLEY_UNLIKELY(conn->backend_fd < 0 || !m_loop))
        return;

    if (SOCKETLEY_UNLIKELY(conn->backend_fd >= MAX_FDS))
        return;

    auto& be = m_conn_idx[conn->backend_fd];
    if (SOCKETLEY_UNLIKELY(be.side != conn_backend))
        return;

    auto* bconn = be.backend;
    if (SOCKETLEY_UNLIKELY(bconn->closing))
        return;

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

    if (SOCKETLEY_UNLIKELY(bconn->write_queue.size() >= proxy_backend_connection::MAX_WRITE_QUEUE))
    {
        bconn->closing = true;
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

    if (!bconn->write_pending)
        flush_backend_write_queue(bconn);
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

    if (SOCKETLEY_UNLIKELY(cconn->write_queue.size() >= proxy_client_connection::MAX_WRITE_QUEUE))
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

    if (!cconn->write_pending)
        flush_client_write_queue(cconn);
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

    if (!conn->write_pending)
        flush_client_write_queue(conn);
}

void proxy_instance::flush_client_write_queue(proxy_client_connection* conn)
{
    if (SOCKETLEY_UNLIKELY(!m_loop || conn->write_queue.empty() || conn->zc_notif_pending))
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
        auto len = static_cast<uint32_t>(std::min(conn->write_batch[0].size(),
                                                   static_cast<size_t>(UINT32_MAX)));
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
    if (SOCKETLEY_UNLIKELY(!m_loop || conn->write_queue.empty() || conn->zc_notif_pending))
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
        auto len = static_cast<uint32_t>(std::min(conn->write_batch[0].size(),
                                                   static_cast<size_t>(UINT32_MAX)));
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
            flush_client_write_queue(conn);
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
            if (new_count == 1)
            {
                conn->write_req.type = op_write;
                m_loop->submit_write(conn->fd,
                    static_cast<const char*>(conn->write_iovs[0].iov_base),
                    static_cast<uint32_t>(conn->write_iovs[0].iov_len),
                    &conn->write_req);
            }
            else
            {
                conn->write_req.type = op_writev;
                m_loop->submit_writev(conn->fd, conn->write_iovs, new_count, &conn->write_req);
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
        flush_client_write_queue(conn);
    }
    else if (conn->closing && !conn->read_pending && !conn->zc_notif_pending &&
             !conn->splice_in_pending && !conn->splice_out_pending)
    {
        close_pair(fd, conn->backend_fd);
        return;
    }

    // Backpressure resume: if client write queue drained below threshold, restart backend reads
    if (conn->write_queue.size() < WRITE_QUEUE_BACKPRESSURE &&
        conn->backend_fd >= 0 && conn->backend_fd < MAX_FDS)
    {
        auto& be = m_conn_idx[conn->backend_fd];
        if (be.side == conn_backend && !be.backend->read_pending &&
            !be.backend->closing && !be.backend->splice_active)
        {
            submit_read_op_backend(m_loop, conn->backend_fd, be.backend,
                                   m_recv_multishot, m_use_provided_bufs, BUF_GROUP_ID);
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
            flush_backend_write_queue(conn);
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
            if (new_count == 1)
            {
                conn->write_req.type = op_write;
                m_loop->submit_write(conn->fd,
                    static_cast<const char*>(conn->write_iovs[0].iov_base),
                    static_cast<uint32_t>(conn->write_iovs[0].iov_len),
                    &conn->write_req);
            }
            else
            {
                conn->write_req.type = op_writev;
                m_loop->submit_writev(conn->fd, conn->write_iovs, new_count, &conn->write_req);
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
        flush_backend_write_queue(conn);
    }
    else if (conn->closing && !conn->read_pending && !conn->zc_notif_pending &&
             !conn->splice_in_pending && !conn->splice_out_pending)
    {
        close_pair(conn->client_fd, fd);
        return;
    }

    // Backpressure resume: if write queue drained below threshold, restart client reads
    if (conn->write_queue.size() < WRITE_QUEUE_BACKPRESSURE &&
        conn->client_fd >= 0 && conn->client_fd < MAX_FDS)
    {
        auto& ce = m_conn_idx[conn->client_fd];
        if (ce.side == conn_client && !ce.client->read_pending &&
            !ce.client->closing && !ce.client->splice_active)
        {
            submit_read_op(m_loop, conn->client_fd, ce.client,
                           m_recv_multishot, m_use_provided_bufs, BUF_GROUP_ID);
        }
    }
}
