#include "../../shared/socket_tuning.h"
#include "proxy_instance.h"
#include "../../shared/blocking_write.h"
#include "../../shared/event_loop.h"
#include "../../shared/runtime_manager.h"
#include "../../shared/cluster_discovery.h"
#include "../../shared/lua_context.h"
#include "../../shared/logging.h"
#include "../../shared/invariants.h"
#include "../../shared/unix_listener.h"

#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cerrno>
#include <cstdlib>
#include <cstddef>
#include <charconv>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/tcp.h>
#include <algorithm>
#include <type_traits>
#include <liburing.h>
#ifdef SOCKETLEY_TRACE
#include <dirent.h>
#include <cstdio>
#endif

// Defined below, next to the read handlers they belong to; handle_accept needs
// them earlier than that.
static inline bool submit_read_op(event_loop* loop, int fd, proxy_client_connection* conn,
                                  bool recv_multishot, bool use_provided_bufs, uint16_t buf_group);
static inline bool submit_read_op_backend(event_loop* loop, int fd, proxy_backend_connection* conn,
                                          bool recv_multishot, bool use_provided_bufs, uint16_t buf_group);


// Is this (host, port) something a backend socket may be filed under, asked in
// one place because a pooled connection goes to whoever asks for the same key
// next -- and (path, 0) cannot collide with a TCP key, since resolve_backend
// refuses a relative path.
static inline bool pool_key_ok(std::string_view host, uint16_t port)
{
    return !host.empty() && (port != 0 || host.front() == '/');
}

// Which endpoint a client's current backend socket is connected to, false when
// that cannot be established, because backend_idx answers it only for a plain
// backend and a group leaves the index on the group entry.
static inline bool backend_endpoint_of(const proxy_client_connection* cconn,
                                       const std::vector<backend_info>& backends,
                                       std::string_view& host, uint16_t& port)
{
    if (!cconn)
        return false;
    if (cconn->backend_from_group)
    {
        host = cconn->backend_host;
        port = cconn->backend_port;
    }
    else
    {
        if (cconn->backend_idx >= backends.size())
            return false;
        const auto& b = backends[cconn->backend_idx];
        if (b.is_group)
            return false;  // routed to a group without the per-request endpoint
        host = b.resolved_host;
        port = b.resolved_port;
    }
    return pool_key_ok(host, port);
}

// The address a connect to this backend has to use, in one function because
// the request path and the health sweep must agree about where a backend is --
// false meaning the lookup has not come back, which the two callers answer
// differently.
static bool backend_connect_addr(const backend_info& b,
                                 struct sockaddr_storage& out, socklen_t& len)
{
    if (b.is_unix)
    {
        // configure_unix_backend has already refused a path that would not
        // fit, and the byte-for-byte address rules are
        // shared/unix_listener.h's.
        len = socketley::unix_sock::fill_addr(
            b.unix_path, *reinterpret_cast<struct sockaddr_un*>(&out));
        return true;
    }

    if (!b.has_cached_addr)
        return false;

    std::memcpy(&out, &b.cached_addr, sizeof(struct sockaddr_in));
    len = sizeof(struct sockaddr_in);
    return true;
}

// Whether the ring still owes this half a completion, which is the question a
// deferred teardown asks and the same predicate inv_check_pair asserts on --
// and read_pending counts here, unlike in the cache and the server, because
// this proxy arms its reads on the descriptor rather than a fixed index, so
// they are cancellable and reachable by the socket's error: measured at 33,364
// deferrals on an armed read alone with zero stranded.
static inline bool client_op_in_flight(const proxy_client_connection* c)
{
    return c->read_pending || c->write_pending || c->zc_notif_pending ||
           c->splice_in_pending || c->splice_out_pending || c->connect_pending ||
           c->abort_watch_pending;
}

// Same rule and reason as the client half, because backend reads are armed on
// the descriptor too: 993 of 23,189 backend deferrals were on an armed read
// alone and none stranded.
static inline bool backend_op_in_flight(const proxy_backend_connection* b)
{
    return b->read_pending || b->write_pending || b->zc_notif_pending ||
           b->splice_in_pending || b->splice_out_pending;
}

// Splice is off unless SOCKETLEY_PROXY_SPLICE says otherwise, because
// IORING_OP_SPLICE is prepped REQ_F_FORCE_ASYNC and costs a thread hand-off
// per transfer -- the copy path measured 1.79x the rate at 128 B and still
// 1.14x at 256 KB, at a third of the CPU -- and the code stays because bulk
// streaming across a real NIC was never measured here.
static bool splice_opt_in()
{
    static const bool on = [] {
        const char* e = std::getenv("SOCKETLEY_PROXY_SPLICE");
        return e && *e && *e != '0';
    }();
    return on;
}

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

    // An entry that does not fit waiting[] is a completion nobody waits for,
    // which is the use-after-free this machinery exists to prevent --
    // unreachable today at six requests against an array of six, and the bound
    // costs one comparison per teardown.
    if (SOCKETLEY_UNLIKELY(count > max_waiting))
        LOG_ERROR("proxy: a retired connection owes the ring more requests than "
                  "the graveyard can track; its storage may be freed early");

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

            // A read out of the provided-buffer ring still holds one even when
            // reporting its own cancellation, so every restart would otherwise
            // cost the ring buffers.
            if ((cqe->flags & IORING_CQE_F_BUFFER) && m_retired_loop)
                m_retired_loop->return_buf(BUF_GROUP_ID,
                                           static_cast<uint16_t>(cqe->flags >> IORING_CQE_BUFFER_SHIFT));

            // More to come, because a multishot read keeps delivering and a
            // zero-copy send answers twice, so the memory stays until that
            // last word.
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
    close_tracked(m_listen_fd);

    // Close any pooled backend connections, and free the sessions the
    // encrypted ones hold — the pool owns both.
    for (auto& pool : m_backend_pool)
    {
        for (auto& pb : pool)
            discard_pooled(pb, false);
    }
}

void proxy_instance::close_tracked(int fd)
{
    if (fd < 0)
        return;
    // m_loop while running and m_retired_loop once teardown has cleared it,
    // because the descriptors closed after a stop are the ones the ring is
    // most likely to be naming.
    event_loop* lp = m_loop ? m_loop : m_retired_loop;
    if (SOCKETLEY_LIKELY(lp != nullptr))
        lp->close_fd(fd);
    else
        close(fd);
}

void proxy_client_connection::reset(int new_fd)
{
    // Process-wide and not a per-struct count, because both check sites
    // resolve by descriptor first and a per-struct counter agrees by accident
    // once a descriptor moves between structs.
    generation = next_io_generation();
    connect_reattempted = false;
    fd = new_fd;
    // client_pool_release() already did this, repeated because a struct
    // leaving the pool must not carry the previous connection's session.
    tls_context::free_ssl(ssl);
    ssl = nullptr;
    tls_state = tls_conn_none;
    tls_peer_closed = false;
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
    // Not close_tracked(), because a struct only reaches reset() through
    // client_pool_release(), which has already closed both pipes -- so these
    // are a guard against a path that does not exist.
    if (pipe_to_backend[0] >= 0) { close(pipe_to_backend[0]); pipe_to_backend[0] = -1; }
    if (pipe_to_backend[1] >= 0) { close(pipe_to_backend[1]); pipe_to_backend[1] = -1; }
    method.clear();
    path.clear();
    version.clear();
    filter_headers.clear();
    filter_removed_headers.clear();
    declared_body_len = 0;
    declared_body_chunked = false;
    body_remaining = 0;
    body_unbounded = false;
    last_activity = {};
    retries_remaining = 0;
    backend_idx = 0;
    saved_request.clear();
    SKL_TRACE_RESET(*this);
    SKL_INV_RESET(*this);
    client_eof = false;
    backend_half_closed = false;
    backend_from_group = false;
    backend_host.clear();
    backend_port = 0;
    // A struct out of the pool must not carry the previous connection's
    // allowance, nor a limit this proxy is not configured with.
    rl_tokens = 0.0;
    rl_max = 0.0;
    rl_last = {};
    connect_pending = false;
    connect_fd = -1;
    connect_req = {};
    abort_watch_pending = false;
    abort_req = {};
    awaiting_response = false;
    response_deadline = {};
    awaiting_headers = false;
    header_deadline = {};
}

void proxy_backend_connection::reset(int new_fd)
{
    SKL_TRACE_RESET(*this);
    SKL_INV_RESET(*this);
    // Process-wide and not a per-struct count, because both check sites
    // resolve by descriptor first and a per-struct counter agrees by accident
    // once a descriptor moves between structs.
    generation = next_io_generation();
    fd = new_fd;
    // See proxy_client_connection::reset, which matters more here because
    // backend fds are pooled too, so a session left behind would belong to a
    // different peer.
    tls_context::free_ssl(ssl);
    ssl = nullptr;
    tls_state = tls_conn_none;
    tls_peer_closed = false;
    read_pending = false;
    write_pending = false;
    closing = false;
    zc_notif_pending = false;
    splice_active = false;
    splice_in_pending = false;
    splice_out_pending = false;
    pool_draining = false;
    sent_to_client = false;
    pool_abandoned = false;
    pool_backend_idx = 0;
    pool_host.clear();
    pool_port = 0;
    client_fd = -1;
    write_batch_count = 0;
    read_req = {};
    write_req = {};
    splice_in_req = {};
    splice_out_req = {};
    partial.clear();
    write_queue.clear();
    for (uint32_t i = 0; i < MAX_WRITE_BATCH; i++) write_batch[i].clear();
    // Not close_tracked(), for the reason given in proxy_client_connection::reset:
    // backend_pool_release() has already closed and cleared both.
    if (pipe_to_client[0] >= 0) { close(pipe_to_client[0]); pipe_to_client[0] = -1; }
    if (pipe_to_client[1] >= 0) { close(pipe_to_client[1]); pipe_to_client[1] = -1; }
    http_frame = {};
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
    // The splice pipes go back to the kernel here even when the struct does
    // not, and close_tracked() is what makes that safe: a pipe number is
    // reissued as readily as a socket number.
    if (conn->pipe_to_backend[0] >= 0) { close_tracked(conn->pipe_to_backend[0]); conn->pipe_to_backend[0] = -1; }
    if (conn->pipe_to_backend[1] >= 0) { close_tracked(conn->pipe_to_backend[1]); conn->pipe_to_backend[1] = -1; }

    // The TLS session dies with the connection whether the struct is pooled or
    // retired, needing none of the ring's care because no completion can name
    // it.
    tls_context::free_ssl(conn->ssl);
    conn->ssl = nullptr;
    conn->tls_state = tls_conn_none;
    conn->tls_peer_closed = false;

    // The half-open connect socket goes the same way, because reset() only
    // sets it to -1 and a struct reaching the pool with one lost that
    // descriptor for good -- with the cancel now close_fd's job.
    close_tracked(conn->connect_fd);
    conn->connect_fd = -1;

    // A struct only goes back into the pool once the ring is finished with it,
    // because the pool hands structs to the next accepted connection -- and
    // callers nulling owners themselves got it half right.
    {
        io_request* owed[6];
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
        // The abort watch is a poll, which survives the close of the
        // descriptor it is armed on, so its completion is owed like the rest.
        if (conn->abort_watch_pending)
            owed[n++] = &conn->abort_req;
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
    conn->abort_req.owner = nullptr;
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
        conn->splice_in_pending || conn->splice_out_pending || conn->connect_pending ||
        conn->abort_watch_pending,
        conn->read_req.owner || conn->write_req.owner || conn->splice_in_req.owner ||
        conn->splice_out_req.owner || conn->connect_req.owner || conn->abort_req.owner);

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
    if (conn->pipe_to_client[0] >= 0) { close_tracked(conn->pipe_to_client[0]); conn->pipe_to_client[0] = -1; }
    if (conn->pipe_to_client[1] >= 0) { close_tracked(conn->pipe_to_client[1]); conn->pipe_to_client[1] = -1; }

    // And the session, because the descriptor may go on to the connection pool
    // and the session it negotiated may not.
    tls_context::free_ssl(conn->ssl);
    conn->ssl = nullptr;
    conn->tls_state = tls_conn_none;
    conn->tls_peer_closed = false;

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

void proxy_instance::set_endpoints(std::shared_ptr<const endpoint_table> tbl)
{
    // Straight assignment on the event-loop thread, because a connection
    // already being routed keeps the table it started with.
    m_endpoints = std::move(tbl);

    // What the new snapshot says this proxy's backends will answer, rebuilt
    // here and in setup(), which are the only two moments it can change.
    rebuild_route_view();

    // Whatever the pool holds to a member no longer in the group is dead
    // weight, and the breakers go with it, which is what keeps that map the
    // size of the group rather than of its history.
    drop_departed_endpoints();

    // And the addresses for whatever the new snapshot added, after the
    // pruning, so a member that just left is not looked up on its way out.
    resolve_group_hosts();
}

// The declarations of this proxy's backends folded into one table, where one
// backend named by address leaves it empty -- deliberately, because refusing a
// method at the edge that a possible target might have served is the one
// failure this feature must not have.
void proxy_instance::rebuild_route_view()
{
    m_routes.clear();
    if (!m_endpoints || !m_endpoints->any_routes() || m_backends.empty())
        return;

    // Configuration order, so that the Allow header a client is given does not
    // depend on anything but what the operator wrote.
    bool started = false;
    for (const auto& b : m_backends)
    {
        const route_table* rt = nullptr;
        if (b.address.size() > 1 && b.address[0] == '@')
            rt = m_endpoints->find_group_routes(
                     std::string_view(b.address.data() + 1, b.address.size() - 1));
        else
            rt = m_endpoints->find_name_routes(b.address);

        if (!rt || rt->empty())
        {
            m_routes.clear();
            return;
        }

        if (!started)
        {
            m_routes = *rt;
            started = true;
        }
        else
        {
            m_routes.merge_alternative(*rt);
        }
    }
}

// A group member's address arrives in the membership snapshot and the idle
// sweep never sees it, so resolution belongs here, on the membership change --
// otherwise an @group backend whose members advertise names stopped routing
// entirely.
void proxy_instance::resolve_group_hosts()
{
    if (!m_endpoints || m_backends.empty())
    {
        m_group_addr.clear();
        m_group_unresolved = false;
        return;
    }

    std::unordered_map<std::string, in_addr> kept;
    bool unresolved = false;

    for (const auto& b : m_backends)
    {
        if (!b.is_group)
            continue;

        const std::string_view group_name(b.address.data() + 1, b.address.size() - 1);
        const auto* members = m_endpoints->find_group(group_name);
        if (!members)
            continue;

        for (const auto& ep : *members)
        {
            // A literal address needs nothing: the selection path reads it with
            // inet_pton and never asks this map.
            in_addr literal{};
            if (inet_pton(AF_INET, ep.host.c_str(), &literal) == 1)
                continue;

            if (kept.find(ep.host) != kept.end())
                continue;

            // Carried over rather than looked up again, because a membership
            // change is one member joining or leaving and re-resolving the
            // whole group would scale with the cluster.
            if (const auto prev = m_group_addr.find(ep.host); prev != m_group_addr.end())
            {
                kept.emplace(ep.host, prev->second);
                continue;
            }

            struct addrinfo hints{};
            hints.ai_family   = AF_INET;
            hints.ai_socktype = SOCK_STREAM;

            struct addrinfo* res = nullptr;
            if (getaddrinfo(ep.host.c_str(), nullptr, &hints, &res) == 0 && res)
            {
                if (res->ai_family == AF_INET &&
                    res->ai_addrlen == sizeof(struct sockaddr_in))
                {
                    const auto* sin = reinterpret_cast<const struct sockaddr_in*>(res->ai_addr);
                    kept.emplace(ep.host, sin->sin_addr);
                }
                freeaddrinfo(res);
            }

            if (kept.find(ep.host) == kept.end())
                unresolved = true;
        }
    }

    m_group_addr.swap(kept);
    m_group_unresolved = unresolved;

    // A name that did not resolve is work for the sweep, the same way an
    // unresolved configured backend is: without arming it, a member whose DNS
    // was down when it joined would never be looked up again.
    if (m_group_unresolved)
        arm_idle_sweep();
}

// Called only when the membership snapshot changes, which is per control
// action rather than per request.
void proxy_instance::drop_departed_endpoints()
{
    // No table is not the same answer as an empty group: without one there is
    // nothing to say an endpoint has departed, and a pool emptied on no
    // evidence is a pool that pays for every request again.
    if (m_backends.empty() || !m_endpoints)
        return;

    const auto still_a_member = [this](std::string_view host, uint16_t port) {
        for (const auto& b : m_backends)
        {
            if (!b.is_group)
            {
                // A plain backend is not membership; it is configuration, and
                // it does not change under us.
                if (b.resolved_port == port && b.resolved_host == host)
                    return true;
                continue;
            }
            const std::string_view group(b.address.data() + 1, b.address.size() - 1);
            if (const auto* members = m_endpoints->find_group(group))
                for (const auto& ep : *members)
                    if (ep.port == port && ep.host == host)
                        return true;
        }
        return false;
    };

    for (auto& pool : m_backend_pool)
    {
        pool.erase(std::remove_if(pool.begin(), pool.end(),
                                  [&](pooled_backend& pb) {
                                      if (still_a_member(pb.host, pb.port))
                                          return false;
                                      // Session and descriptor together — see
                                      // discard_pooled.
                                      discard_pooled(pb, true);
                                      return true;
                                  }),
                   pool.end());
    }

    for (auto it = m_group_breakers.begin(); it != m_group_breakers.end(); )
    {
        const std::string_view key(it->first);
        const auto colon = key.rfind(':');
        uint16_t port = 0;
        if (colon != std::string_view::npos)
            std::from_chars(key.data() + colon + 1, key.data() + key.size(), port);
        if (colon == std::string_view::npos || !still_a_member(key.substr(0, colon), port))
            it = m_group_breakers.erase(it);
        else
            ++it;
    }
}
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
void proxy_instance::set_backend_timeout(int seconds) { m_mesh.backend_timeout = seconds; }
void proxy_instance::set_retry_count(int count) { m_mesh.retry_count = count; }
void proxy_instance::set_retry_all(bool val) { m_mesh.retry_all = val; }
void proxy_instance::set_mesh_client_ca(std::string_view path) { m_mesh.client_ca = std::string(path); }
void proxy_instance::set_mesh_client_cert(std::string_view path) { m_mesh.client_cert = std::string(path); }
void proxy_instance::set_mesh_client_key(std::string_view path) { m_mesh.client_key = std::string(path); }

void proxy_instance::get_mesh_tls_paths(std::string_view& ca, std::string_view& cert,
                                        std::string_view& key) const
{
    ca   = m_mesh.client_ca;
    cert = m_mesh.client_cert;
    key  = m_mesh.client_key;
}

size_t proxy_instance::get_connection_count() const
{
    // A placeholder for a proxy running in its own process has no clients of
    // its own; the count it should answer with is the one the worker reported.
    if (worker_backed())
        return static_cast<size_t>(m_stat_active_connections.load(std::memory_order_relaxed));
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

    socket_tuning::keepalive_dead_peer(fd);
}

// Make `b` a unix-socket backend or refuse and say why, in one function
// because `--backend unix:` and a runtime name that listens on one are the
// same backend -- and every refusal fails the start, because a backend that
// provably cannot work is known at configuration time.
static bool configure_unix_backend(backend_info& b, std::string_view path,
                                   std::string_view where)
{
    // The path rules are shared/unix_listener.h's, with absoluteness mattering
    // here because a relative path resolves against the daemon's working
    // directory and the pool key needs a leading '/' that no hostname can
    // produce.
    if (const std::string why = socketley::unix_sock::path_refusal(path);
        !why.empty())
    {
        LOG_ERROR(("proxy backend " + std::string(where) + ": " + why).c_str());
        return false;
    }

    // TLS to a unix socket is refused rather than ignored, because encrypting
    // a socket the kernel never puts on a wire buys nothing the node's
    // permissions do not, and dropping the flags would be the fail-open
    // answer.
    if (b.tls)
    {
        LOG_ERROR(("proxy backend " + std::string(where) +
                   ": --ca, --client-cert and --client-key encrypt every backend "
                   "leg, and there is no TLS to a unix socket").c_str());
        return false;
    }

    b.is_unix = true;
    b.unix_path = std::string(path);

    // Said out loud, because a backend written as a port and reached over a
    // node is a transport nobody can see -- tcpdump on loopback shows nothing
    // and the configuration still reads like TCP.
    LOG_INFO(("proxy backend " + std::string(where) + " is reached over "
              + std::string(path)).c_str());
    // The path is the endpoint with resolved_port at 0, and has_cached_addr is
    // true because there is no lookup to fail and nothing for the sweep to
    // retry.
    b.resolved_host = b.unix_path;
    b.resolved_port = 0;
    b.has_cached_addr = true;
    return true;
}

bool proxy_instance::resolve_backend(backend_info& b)
{
    // Group references (@groupname) are resolved dynamically at connection time
    if (b.address.size() > 1 && b.address[0] == '@')
    {
        b.is_group = true;
        return true;
    }

    // ─── unix:/path/to.sock ─────────────────────────────────────────────────
    if (std::string_view(b.address).starts_with("unix:"))
        return configure_unix_backend(b, std::string_view(b.address).substr(5),
                                      "\"" + b.address + "\"");

    // A scheme says how to reach this backend as well as where, and it only
    // ever turns TLS on; it stays on b.address because an operator reading
    // `stats` has to see what they configured.
    std::string_view addr(b.address);
    uint16_t default_port = 0;
    if (addr.starts_with("https://"))
    {
        addr.remove_prefix(8);
        b.tls = true;
        default_port = 443;
    }
    else if (addr.starts_with("http://"))
    {
        addr.remove_prefix(7);
        default_port = 80;
    }

    const auto colon = addr.find(':');
    // A scheme with no port is a URL whose port is implied, which would
    // otherwise fall through to the runtime-name lookup and be reported as an
    // unknown runtime.
    const bool have_endpoint = (colon != std::string_view::npos) ||
                               (default_port != 0 && !addr.empty());
    if (have_endpoint)
    {
        if (colon != std::string_view::npos)
        {
            b.resolved_host = std::string(addr.substr(0, colon));
            const char* pstart = addr.data() + colon + 1;
            const char* pend   = addr.data() + addr.size();

            // Checked, and a failure fails the whole setup, because a
            // discarded result left `host:abc` at port 0 -- an address that
            // provably cannot work, reported at traffic time as a 503.
            const auto [pptr, pec] = std::from_chars(pstart, pend, b.resolved_port);
            if (pec != std::errc{} || pptr != pend || b.resolved_port == 0)
            {
                LOG_ERROR(("proxy backend \"" + b.address +
                           "\": the port is not a number between 1 and 65535").c_str());
                return false;
            }
        }
        else
        {
            b.resolved_host = std::string(addr);
            b.resolved_port = default_port;
        }
        // The same runtime, reached the short way.  Only when the address is
        // exactly what a runtime publishes: `myserver` asks for a runtime and
        // may choose its transport, while `127.0.0.1:9000` asks for an address
        // -- so this fires only while that address IS that runtime, and the
        // moment it stops being, the address means what it says again.
        if (!b.tls && m_endpoints)
        {
            const std::string_view node =
                m_endpoints->find_node_at(b.resolved_host, b.resolved_port);
            if (!node.empty())
                return configure_unix_backend(b, node, "\"" + b.address + "\"");
        }

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
            // A name that does not resolve now is retried by the idle sweep,
            // once a tick, and not by the request path -- which does no DNS at
            // all, because a getaddrinfo on the event-loop thread froze the
            // whole daemon for the resolver's timeout.  See the sweep's own
            // block, and backend_connect_addr(), which arms the sweep rather
            // than resolving.
        }
        return true;
    }

    // A bare runtime name, resolved from the published table rather than by
    // reading get_port() off an instance, so nothing here holds a pointer into
    // another runtime.
    if (!m_endpoints)
        return false;

    const runtime_endpoint* ep = m_endpoints->find_name(b.address);
    if (!ep)
        return false;

    // A runtime listening on a unix socket publishes its path with the port at
    // 0, and reaches the same validation the written-out form does.
    if (ep->port == 0)
    {
        if (ep->host.empty() || ep->host[0] != '/')
            return false;
        return configure_unix_backend(b, ep->host, "\"" + b.address + "\"");
    }

    // A runtime with a port may also answer on a node.  A name asks for the
    // runtime, so this leg is free to pick the shorter way to it -- except
    // under backend TLS, which asks for something a node cannot give and is
    // refused rather than quietly dropped one line further down.
    if (!ep->unix_path.empty() && !b.tls)
        return configure_unix_backend(b, ep->unix_path, "\"" + b.address + "\"");

    b.resolved_host = ep->host;
    const uint16_t port = ep->port;
    b.resolved_port = port;
    b.cached_addr.sin_family = AF_INET;
    b.cached_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    b.cached_addr.sin_port = htons(port);
    b.has_cached_addr = true;
    return true;
}

#ifdef SOCKETLEY_TRACE
namespace {
std::vector<proxy_instance*>& skl_proxy_registry()
{
    static std::vector<proxy_instance*> v;
    return v;
}
}

void proxy_instance::trace_register(proxy_instance* p)
{
    auto& v = skl_proxy_registry();
    for (auto* e : v) if (e == p) return;
    v.push_back(p);
}

void proxy_instance::trace_unregister(proxy_instance* p)
{
    auto& v = skl_proxy_registry();
    v.erase(std::remove(v.begin(), v.end(), p), v.end());
}

// Report every splice pipeline with bytes somewhere that has not moved,
// because the two states -- armed and waiting, or moved and never pushed on --
// name different hops and neither is visible from the flags; with the io-wq
// worker count, which a splice on a quiet socket holds.
static void skl_count_iowq(int& total, int& parked)
{
    total = 0; parked = 0;
    DIR* d = opendir("/proc/self/task");
    if (!d) return;
    while (struct dirent* e = readdir(d))
    {
        if (e->d_name[0] == '.') continue;
        char p[128];
        std::snprintf(p, sizeof(p), "/proc/self/task/%s/comm", e->d_name);
        FILE* f = std::fopen(p, "r");
        if (!f) continue;
        char comm[64] = {0};
        const bool is_wrk = std::fgets(comm, sizeof(comm), f) &&
                            std::strncmp(comm, "iou-wrk", 7) == 0;
        std::fclose(f);
        if (!is_wrk) continue;
        total++;
        std::snprintf(p, sizeof(p), "/proc/self/task/%s/wchan", e->d_name);
        FILE* g = std::fopen(p, "r");
        if (!g) continue;
        char wch[64] = {0};
        if (std::fgets(wch, sizeof(wch), g) && std::strstr(wch, "wait_woken"))
            parked++;
        std::fclose(g);
    }
    closedir(d);
}

// Nothing here may ioctl() a pipe, because a splice from a socket holds the
// pipe's mutex while it waits and FIONREAD takes the same one -- measured, a
// probe that did this wedged the whole daemon in uninterruptible sleep.
void proxy_instance::trace_splice_sweep()
{
    const double now = ::skl_trace::now_ms();

    // Armed splices across every proxy on this loop against the number of
    // io-wq threads, which are the demand and the supply.
    int armed = 0, parked_pipelines = 0;
    for (auto* inst : skl_proxy_registry())
    {
        if (!inst) continue;
        size_t rem = inst->m_backend_count;
        for (int fd = 0; fd < MAX_FDS && rem > 0; ++fd)
        {
            auto* b = inst->m_backend_slots[fd].get();
            if (!b) continue;
            rem--;
            armed += (int)b->splice_in_pending + (int)b->splice_out_pending;
        }
        size_t remc = inst->m_client_count;
        for (int fd = 0; fd < MAX_FDS && remc > 0; ++fd)
        {
            auto* c = inst->m_client_slots[fd].get();
            if (!c) continue;
            remc--;
            armed += (int)c->splice_in_pending + (int)c->splice_out_pending;
            if (c->splice_in_pending) parked_pipelines++;
        }
    }

    {
        static double last_wq = 0.0;
        static bool asked_max = false;
        if (now - last_wq > 240.0)
        {
            last_wq = now;
            int t = 0, p = 0;
            skl_count_iowq(t, p);
            SKL_TRACE_LOG("iowq workers=%d parked=%d armed_splices=%d client_in_armed=%d",
                          t, p, armed, parked_pipelines);
            if (!asked_max)
            {
                asked_max = true;
                for (auto* inst : skl_proxy_registry())
                {
                    if (!inst || !inst->m_loop) continue;
                    unsigned vals[2] = { 0, 0 };
                    const int r = io_uring_register_iowq_max_workers(inst->m_loop->get_ring(), vals);
                    SKL_TRACE_LOG("iowq-max rc=%d bounded=%u unbounded=%u", r, vals[0], vals[1]);
                    break;
                }
            }
        }
    }

    for (auto* inst : skl_proxy_registry())
    {
        if (!inst) continue;
        size_t remaining = inst->m_backend_count;
        for (int fd = 0; fd < MAX_FDS && remaining > 0; ++fd)
        {
            auto* b = inst->m_backend_slots[fd].get();
            if (!b) continue;
            remaining--;
            if (!b->splice_active) continue;

            const double idle = now - b->tr.splice_cqe_ms;
            if (idle < 400.0) continue;

            int sock_un = 0, cl_un = 0;
            if (ioctl(fd, FIONREAD, &sock_un) < 0) {}
            proxy_client_connection* c = nullptr;
            if (b->client_fd >= 0 && b->client_fd < MAX_FDS &&
                inst->m_conn_idx[b->client_fd].side == conn_client)
            {
                c = inst->m_conn_idx[b->client_fd].client;
                if (ioctl(b->client_fd, FIONREAD, &cl_un) < 0) {}
            }

            // What is owed on this pipeline, from the counters rather than from
            // the pipe: bytes taken off a socket that have not reached the peer.
            const long long owed_b = (long long)(b->tr.sp_in - b->tr.sp_out);
            const long long owed_c = c ? (long long)(c->tr.sp_in - c->tr.sp_out) : 0;

            // Moving normally and nothing owed anywhere: an idle keep-alive
            // pipeline, which is the ordinary state and not worth a line.
            if (sock_un == 0 && cl_un == 0 && owed_b == 0 && owed_c == 0)
                continue;

            SKL_TRACE_LOG("sp-stall inst=%.*s bfd=%d cfd=%d idle=%.0fms "
                          "b_inflight=%u c_inflight=%u "
                          "b_in_pend=%d b_out_pend=%d b_closing=%d "
                          "c_in_pend=%d c_out_pend=%d c_closing=%d "
                          "backend_unread=%d client_unread=%d owed_b=%lld owed_c=%lld "
                          "b_sp_in=%llu b_sp_out=%llu b_lastres=%d b_leg=%u "
                          "c_sp_in=%llu c_sp_out=%llu c_lastres=%d c_leg=%u",
                (int)inst->get_name().size(), inst->get_name().data(), fd, b->client_fd, idle,
                inst->m_loop ? inst->m_loop->fd_inflight(fd) : 0u,
                (inst->m_loop && b->client_fd >= 0) ? inst->m_loop->fd_inflight(b->client_fd) : 0u,
                (int)b->splice_in_pending, (int)b->splice_out_pending, (int)b->closing,
                c ? (int)c->splice_in_pending : -1, c ? (int)c->splice_out_pending : -1,
                c ? (int)c->closing : -1,
                sock_un, cl_un, owed_b, owed_c,
                (unsigned long long)b->tr.sp_in, (unsigned long long)b->tr.sp_out,
                b->tr.last_splice_res, b->tr.splice_leg,
                c ? (unsigned long long)c->tr.sp_in : 0ULL,
                c ? (unsigned long long)c->tr.sp_out : 0ULL,
                c ? c->tr.last_splice_res : 0, c ? c->tr.splice_leg : 0u);
        }
    }
}
#endif

bool proxy_instance::setup(event_loop& loop)
{
#ifdef SOCKETLEY_TRACE
    trace_register(this);
#endif
    // Nothing from the previous run is cleaned up here, because teardown()
    // hands what it cannot free to retire() -- a POLLOUT on a connect socket,
    // a parked splice and a health-check read all outlive a stop.
    if (!m_retired.empty() && loop.owner_inflight(this) == 0)
        m_retired.clear();

    m_client_count = 0;
    m_backend_count = 0;

    m_loop = &loop;
    // Kept across teardown: a descriptor closed after a stop still has to be
    // checked against the ring, and m_loop is null exactly then.
    m_retired_loop = &loop;

    if (m_backends.empty())
        return false;

    // ─── --listen unix:/path/to.sock ────────────────────────────────────────
    // Judged here rather than only in the flag parser, because setup() is the
    // one function every route to a listening socket passes through, and
    // before the TLS block so a doomed configuration loads no certificates.
    const std::string listen_path(get_listen_path());
    if (const std::string msg = socketley::unix_sock::listen_config_refusal(
            listen_path, get_port(), get_tls()); !msg.empty())
    {
        LOG_ERROR(("proxy: " + msg).c_str());
        return false;
    }

    // ── TLS ─────────────────────────────────────────────────────────────────
    // Certificates are read here at setup because that is blocking file I/O
    // neither handshake does, and every refusal returns false rather than
    // falling through to a cleartext leg.
    m_tls.reset();
    m_backend_tls.reset();

    if (get_tls())
    {
        auto ctx = std::make_unique<tls_context>();
        // --client-ca is the listener's mutual-TLS CA: with it, a client that
        // presents no certificate, or one signed by anybody else, is rejected
        // during the handshake.
        if (!ctx->init_server(get_cert_path(), get_key_path(), m_mesh.client_ca))
        {
            // init_server has already said which file and what OpenSSL made of
            // it, so this says what it cost.
            LOG_ERROR("proxy: TLS listener not started -- the certificate, key or "
                      "client CA could not be loaded");
            return false;
        }
        m_tls = std::move(ctx);
    }

    // The backend-TLS options apply to every backend at once, and none of them
    // means anything against a cleartext peer, so honouring them without
    // encrypting would be the fail-open reading.
    m_backend_tls_all = !get_ca_path().empty() || !m_mesh.client_cert.empty() ||
                        !m_mesh.client_key.empty();

    bool any_backend_tls = false;
    for (auto& b : m_backends)
    {
        b.tls = m_backend_tls_all;   // resolve_backend adds an https:// scheme
        if (!resolve_backend(b))
            return false;
        any_backend_tls = any_backend_tls || b.tls;
    }

    if (any_backend_tls)
    {
        // --health-check http used to be refused on a TLS backend, and the
        // probe handshakes now, so all that is left to say is that the context
        // below is what it verifies against.
        auto ctx = std::make_unique<tls_context>();
        // --ca is this leg's trust store and the system store is used without
        // one, with the chain and the endpoint's name always checked.
        if (!ctx->init_client(get_ca_path(), m_mesh.client_cert, m_mesh.client_key))
        {
            LOG_ERROR("proxy: TLS backend leg not started -- the CA file or the client "
                      "certificate could not be loaded");
            return false;
        }
        m_backend_tls = std::move(ctx);
    }

    m_avail_scratch.reserve(m_backends.size());

    // The backends are known now, because the last publication before start()
    // may have arrived while m_backends was still empty and a view built from
    // none enforces nothing.
    rebuild_route_view();

    m_use_provided_bufs = loop.setup_buf_ring(BUF_GROUP_ID, BUF_COUNT, BUF_SIZE);
    m_recv_multishot = m_use_provided_bufs && loop.recv_multishot_supported();
    // This proxy deliberately does not bundle, because handle_read takes one
    // contiguous buffer out of the completion and a bundle would hand it k
    // discontiguous ones -- and it does not send zero-copy either, because a
    // pending notification would hold the instance in the graveyard.
    m_send_zc = loop.send_zc_enabled();

    // Probe for splice support even when the opt-in is off, so `stats` can say
    // whether this kernel could do it and the probe is exercised on every
    // build.
    {
        struct io_uring_probe* probe = io_uring_get_probe_ring(loop.get_ring());
        if (probe)
        {
            m_splice_supported = io_uring_opcode_supported(probe, IORING_OP_SPLICE);
            io_uring_free_probe(probe);
        }
    }
    m_splice_enabled = m_splice_supported && splice_opt_in();

    // Pre-build prefix once to avoid per-request allocation
    m_prefix = "/" + std::string(get_name()) + "/";

    if (!listen_path.empty())
    {
        // The mechanism is shared/unix_listener.h's, one implementation for
        // every runtime that listens, with everything below the branch the
        // same for both families.
        auto r = socketley::unix_sock::bind_listener(listen_path);
        if (r.fd < 0)
        {
            LOG_ERROR(("proxy: " + r.error).c_str());
            return false;
        }
        m_listen_fd = r.fd;
        // Remembered so teardown() removes exactly the node this bind created,
        // and not whatever the configuration says by then.
        m_bound_listen_path = listen_path;
    }
    else
    {
        uint16_t port = get_port();
        if (port == 0)
            port = 8080;

        // SOCK_CLOEXEC, because in the daemon this listener must not reach a
        // worker forked for another runtime and in a worker it costs nothing.
        m_listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (m_listen_fd < 0)
            return false;

        int opt = 1;
        setsockopt(m_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        setsockopt(m_listen_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
        setsockopt(m_listen_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

        // No TCP_DEFER_ACCEPT, because a client-speaks-first protocol does not
        // make it free -- a SYN-RECV connection is dropped without FIN or RST
        // when the listener closes, and is in no count, no stat and no hook --
        // and measured on this listener's own workload it is worth nothing
        // this instrument can tell from zero.
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        if (bind(m_listen_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
        {
            LOG_ERROR(("proxy: port " + std::to_string(port) + " could not be bound: " +
                       std::string(std::strerror(errno))).c_str());
            close_tracked(m_listen_fd);
            m_listen_fd = -1;
            return false;
        }

        if (listen(m_listen_fd, 4096) < 0)
        {
            close_tracked(m_listen_fd);
            m_listen_fd = -1;
            return false;
        }
    }

    // A fresh accept request for this run, because the previous one may still
    // be owed a completion and re-arming would leave two chains on one
    // io_request.
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
    m_rate_limit_cached = get_rate_limit();

    // Fresh timer for this run, built whether or not it is armed here, because
    // the backend pool arms it on demand.
    m_idle_sweep_timer = std::make_unique<timer_op>();
    m_idle_sweep_timer->ts.tv_sec = 30;
    m_idle_sweep_timer->ts.tv_nsec = 0;
    m_idle_sweep_timer->req = { this, nullptr, -1, 0, op_timeout };
    m_idle_sweep_armed = false;
    m_idle_sweep_warned = false;
    if (m_idle_timeout_cached > 0)
        arm_idle_sweep();

    // Same reasoning, own chain: this one runs only while a request is actually
    // waiting on a backend, so it is built here and armed by the first request.
    m_response_sweep_timer = std::make_unique<timer_op>();
    m_response_sweep_timer->ts.tv_sec = 0;
    m_response_sweep_timer->ts.tv_nsec = RESPONSE_SWEEP_NSEC;
    m_response_sweep_timer->req = { this, nullptr, -1, 0, op_timeout };
    m_response_sweep_armed = false;
    m_response_sweep_warned = false;

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
    // A previous run's verdicts about group members do not carry over: the
    // membership may be entirely different by now, and an endpoint left open
    // would be refused for circuit_timeout after a restart that fixed it.
    m_group_breakers.clear();

    // teardown() empties the pool, but clear() on entries owning a descriptor
    // and a session would leak both silently -- and this is the point past
    // which a pooled session must not survive, the backend context having just
    // been rebuilt.
    for (auto& pool : m_backend_pool)
        for (auto& pb : pool)
            discard_pooled(pb, true);
    m_backend_pool.clear();
    m_backend_pool.resize(m_backends.size());

    // Async health checks: one empty slot per backend, filled by the sweep,
    // with whatever the previous run left already retired.
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
#ifdef SOCKETLEY_TRACE
    trace_unregister(this);
#endif
    // Everything here is closed and handed to the release path, which holds
    // what the ring is still working on -- nulling the owners only holds while
    // there is an object left to read the null out of.
    for (size_t i = 0; i < m_health_checks.size(); i++)
        drop_health_check(i);
    m_health_checks_pending = false;

    // proxy_conn_entry has a default member initializer, so memset over it is
    // not defined behaviour even though conn_none happens to be 0.
    for (auto& e : m_conn_idx) e = {};

    // Shutdown before closing, because a multishot accept holds its own
    // reference and close() leaves the loop owing this owner forever -- with
    // the cancel now inside close_fd, which holds the number until both have
    // reported.
    if (m_listen_fd >= 0)
    {
        shutdown(m_listen_fd, SHUT_RDWR);
        close_tracked(m_listen_fd);
        m_listen_fd = -1;
    }

    // The socket node for a unix listener, exactly the one this run bound,
    // because closing the descriptor does not unlink the path and an
    // operator's `stop` should not need a start to clean up after.
    if (!m_bound_listen_path.empty())
    {
        if (unlink(m_bound_listen_path.c_str()) < 0) {}
        m_bound_listen_path.clear();
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

    // shutdown() before close() on every socket, so an armed read, write or
    // splice is completed by the kernel now rather than whenever the peer gets
    // round to it.
    for (int i = 0; i < MAX_FDS; i++)
    {
        auto& conn = m_backend_slots[i];
        if (!conn) continue;
        shutdown(i, SHUT_RDWR);
        close_tracked(i);
        backend_pool_release(std::move(conn));
    }

    for (int i = 0; i < MAX_FDS; i++)
    {
        auto& conn = m_client_slots[i];
        if (!conn) continue;
        // A connect that has not finished is waiting on POLLOUT, which closing
        // the socket does not take back, so close_fd submits the cancel and
        // holds the number until both have reported.
        close_tracked(conn->connect_fd);
        conn->connect_fd = -1;
        // Same for the abort watch on the client socket: a poll outlives the
        // close of the descriptor it names, so it is withdrawn rather than left
        // to the shutdown below.
        if (conn->abort_watch_pending && m_loop)
            m_loop->submit_poll_remove(&conn->abort_req);
        shutdown(i, SHUT_RDWR);
        close_tracked(i);
        client_pool_release(std::move(conn));
    }
    m_client_count = 0;
    m_backend_count = 0;

    // Close pooled backend connections and free their sessions, before start()
    // can build a new context -- and acquire_pooled_backend checks tls_owner
    // anyway, because impossible here means impossible given the order of two
    // functions.
    for (auto& pool : m_backend_pool)
    {
        for (auto& pb : pool)
            discard_pooled(pb, true);
        pool.clear();
    }

    // Withdraw every timer this run armed, because nothing above reached them
    // and the ring went on owing this owner a completion for the whole
    // interval -- and a withdrawal brings that completion forward rather than
    // taking it away.
    if (m_loop)
    {
        bool withdrawn = true;
        if (m_idle_sweep_armed && m_idle_sweep_timer)
            withdrawn &= m_loop->submit_timeout_remove(&m_idle_sweep_timer->req);
        if (m_response_sweep_armed && m_response_sweep_timer)
            withdrawn &= m_loop->submit_timeout_remove(&m_response_sweep_timer->req);
        if (m_accept_backoff_timer)
            withdrawn &= m_loop->submit_timeout_remove(&m_accept_backoff_timer->req);
        if (m_health_check_timer)
            withdrawn &= m_loop->submit_timeout_remove(&m_health_check_timer->req);
        if (m_health_timeout_timer)
            withdrawn &= m_loop->submit_timeout_remove(&m_health_timeout_timer->req);
        m_loop->flush();

        if (SOCKETLEY_UNLIKELY(!withdrawn))
            LOG_WARN("proxy: a timer withdrawal did not reach the ring — this instance "
                     "stays retired until the timer fires on its own");
    }

    // The timers and the listener retired, because nothing cancels an io_uring
    // timeout and re-arming cost an extra chain per restart -- two sweeps
    // driving one health-check state machine.
    {
        io_request* owed[1];
        if (m_accept)
        {
            owed[0] = &m_accept->req;
            retire(std::shared_ptr<void>(std::move(m_accept)), owed, 1);
        }
        if (m_idle_sweep_timer)
        {
            // Only owed a completion while the chain is running, because the
            // sweep stops re-arming once there is nothing to reclaim and
            // retiring an object nothing completes for holds it until the
            // instance is destroyed.
            const size_t n = m_idle_sweep_armed ? 1 : 0;
            owed[0] = &m_idle_sweep_timer->req;
            retire(std::shared_ptr<void>(std::move(m_idle_sweep_timer)), owed, n);
        }
        if (m_response_sweep_timer)
        {
            // Armed on demand as well, so the same rule applies: claiming a
            // completion is owed when none is holds the storage for the life of
            // the instance.
            const size_t n = m_response_sweep_armed ? 1 : 0;
            owed[0] = &m_response_sweep_timer->req;
            retire(std::shared_ptr<void>(std::move(m_response_sweep_timer)), owed, n);
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
    m_response_sweep_armed = false;
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
    // Remembered before the dispatch because the handler may release the
    // struct and the request with it; an accept, a timer or a probe names no
    // pair.
    const int inv_fd = (req->type == op_accept || req->type == op_multishot_accept ||
                        req->type == op_timeout || req->type == op_health_check)
                       ? -1 : req->fd;
    // For the same reason, and one more: cqe is the loop's and is not promised
    // to outlive the handler either.
    const int     inv_res  = cqe->res;
    const uint8_t inv_type = static_cast<uint8_t>(req->type);
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
        case op_splice_poll:
            handle_splice(cqe, req);
            break;
        case op_connect:
        case op_poll:
            handle_connect(cqe, req);
            break;
        case op_poll_abort:
            handle_client_abort(cqe, req);
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

                // Evict stale pooled connections, for every proxy whether or
                // not a client idle timeout is configured, because the pool is
                // the only place a backend socket sits with nobody watching
                // it.
                bool pooled_left = false;
                for (auto& pool : m_backend_pool)
                {
                    pool.erase(
                        std::remove_if(pool.begin(), pool.end(),
                            [&](pooled_backend& pb) {
                                bool stale = (now - pb.idle_since) >
                                             std::chrono::seconds(POOL_IDLE_TIMEOUT_SEC);
                                // Through discard_pooled, so a session ages
                                // out with the descriptor it belongs to,
                                // because a pool entry freed anywhere else
                                // leaks an SSL.
                                if (stale)
                                    discard_pooled(pb, true);
                                return stale;
                            }),
                        pool.end());
                    pooled_left = pooled_left || !pool.empty();
                }

                // And the DNS the request path no longer does, once per sweep,
                // where a resolver that hangs costs one tick instead of one
                // request.
                bool unresolved_left = false;
                for (auto& b : m_backends)
                {
                    if (b.has_cached_addr || b.resolved_host.empty() ||
                        b.resolved_port == 0)
                        continue;

                    char port_str[8];
                    auto [pend, pec] = std::to_chars(port_str,
                                                     port_str + sizeof(port_str),
                                                     b.resolved_port);
                    *pend = '\0';

                    struct addrinfo hints{};
                    hints.ai_family = AF_INET;
                    hints.ai_socktype = SOCK_STREAM;

                    struct addrinfo* res = nullptr;
                    if (getaddrinfo(b.resolved_host.c_str(), port_str, &hints, &res) == 0 && res)
                    {
                        if (res->ai_family == AF_INET &&
                            res->ai_addrlen == sizeof(struct sockaddr_in))
                        {
                            std::memcpy(&b.cached_addr, res->ai_addr, sizeof(struct sockaddr_in));
                            b.has_cached_addr = true;
                        }
                        freeaddrinfo(res);
                    }

                    if (!b.has_cached_addr)
                        unresolved_left = true;
                }

                // The group members too, on the same tick, with
                // resolve_group_hosts() carrying over what it has so only the
                // failed names are retried.
                if (m_group_unresolved)
                {
                    resolve_group_hosts();
                    unresolved_left = unresolved_left || m_group_unresolved;
                }

                // Keep the chain going only while it has work, because an
                // armed timeout holds a removed proxy in the graveyard -- and
                // an unresolved backend is work, without which the name is
                // never looked up again.
                if (m_idle_timeout_cached > 0 || pooled_left || unresolved_left)
                    arm_idle_sweep();
            }
            // Backend response deadline sweep: this link has spoken, so it may
            // arm the next one while something is still outstanding to watch.
            else if (m_response_sweep_timer && req == &m_response_sweep_timer->req)
            {
                m_response_sweep_armed = false;
                response_deadline_sweep();
            }
            // Accept backoff expired, so the timer owes nothing more and the
            // next shortage may arm a new one.
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
                    // deadline, so the probe is let go rather than handed to
                    // the next sweep, which used to overwrite what the connect
                    // was reading.
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
    // Charged here rather than inside the handlers, because the subject is the
    // completion rather than what any handler chose to do with it.
    inv_check_progress(inv_fd, inv_res, inv_type, "proxy::on_cqe");
    // See inv_sweep_all: the check above can only ever look at the pair this
    // completion named, and says nothing at all when the handler tore that pair
    // down — which is exactly when another one gets stranded.
    if (++m_inv_sweep_countdown >= INV_SWEEP_EVERY)
    {
        m_inv_sweep_countdown = 0;
        inv_sweep_all("proxy::sweep");
    }
#endif
}

#ifdef SOCKETLEY_INVARIANTS
// Declared here and defined beside handle_client_read, because invariant (1b)
// has to ask the same question the hold does, out of the same predicate.
static inline bool backend_response_complete(const proxy_backend_connection* bconn);
static inline bool client_answer_owed(const proxy_client_connection* cconn,
                                      const proxy_backend_connection* bconn);

// Invariant (1) in this runtime's form, where only the pair can answer: what
// is unhealthy is neither half having anything in flight while both are still
// indexed, because no completion is coming and nothing else drives either
// side.
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
                      cconn->splice_out_pending || cconn->connect_pending ||
                      cconn->abort_watch_pending;
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

    // Invariant (1b)'s two terms, read out of the exchange rather than the
    // ring and stated as the same two facts the hold is taken on -- and
    // deliberately not extended to TCP, where a byte relay can never say an
    // answer is no longer owed.
    skl_inv::exchange x{};
    if (cconn && m_protocol == protocol_http)
    {
        x.stated      = true;
        x.half_closed = cconn->client_eof;
        x.answer_owed = client_answer_owed(cconn, bconn);
    }

    SKL_INV_PAIR_X(where, c, b, x);
}

// Everything about a client connection a caller could observe folded into one
// number, mixed with FNV-1a rather than summed so opposite movements do not
// cancel -- collisions cost a delayed report and never a false one.
static inline uint64_t inv_mix(uint64_t h, uint64_t v)
{
    for (int i = 0; i < 8; i++)
    {
        h ^= (v >> (i * 8)) & 0xFF;
        h *= 0x100000001B3ull;
    }
    return h;
}

uint64_t proxy_instance::inv_digest(const proxy_client_connection* c)
{
    uint64_t h = 0xCBF29CE484222325ull;
    h = inv_mix(h, static_cast<uint64_t>(c->fd));
    h = inv_mix(h, c->generation);
    h = inv_mix(h, c->partial.size());
    h = inv_mix(h, c->write_queue.bytes());
    h = inv_mix(h, c->write_queue.size());
    h = inv_mix(h, c->write_batch_count);
    h = inv_mix(h, c->declared_body_len);
    h = inv_mix(h, c->body_remaining);
    h = inv_mix(h, static_cast<uint64_t>(c->backend_fd));
    h = inv_mix(h, c->backend_idx);
    h = inv_mix(h, c->backend_port);
    h = inv_mix(h, static_cast<uint64_t>(c->retries_remaining));
    h = inv_mix(h, static_cast<uint64_t>(c->connect_fd));
    h = inv_mix(h, static_cast<uint64_t>(c->tls_state));
    h = inv_mix(h, c->saved_request.size());
    h = inv_mix(h, c->method.size() + c->path.size() + c->version.size());

    // One word of flags, where a flag that flips and flips back between two
    // completions is invisible, because the digest compares against the
    // previous value rather than a history.
    uint64_t f = 0;
    f |= uint64_t(c->read_pending)          << 0;
    f |= uint64_t(c->write_pending)         << 1;
    f |= uint64_t(c->closing)               << 2;
    f |= uint64_t(c->zc_notif_pending)      << 3;
    f |= uint64_t(c->splice_active)         << 4;
    f |= uint64_t(c->splice_in_pending)     << 5;
    f |= uint64_t(c->splice_out_pending)    << 6;
    f |= uint64_t(c->header_parsed)         << 7;
    f |= uint64_t(c->response_started)      << 8;
    f |= uint64_t(c->client_conn_close)     << 9;
    f |= uint64_t(c->tls_peer_closed)       << 10;
    f |= uint64_t(c->declared_body_chunked) << 11;
    f |= uint64_t(c->body_unbounded)        << 12;
    f |= uint64_t(c->connect_reattempted)   << 13;
    f |= uint64_t(c->client_eof)            << 14;
    f |= uint64_t(c->backend_from_group)    << 15;
    f |= uint64_t(c->connect_pending)       << 16;
    f |= uint64_t(c->abort_watch_pending)   << 17;
    f |= uint64_t(c->awaiting_response)     << 18;
    f |= uint64_t(c->awaiting_headers)      << 19;
    f |= uint64_t(c->ssl != nullptr)        << 20;
    f |= uint64_t(c->backend_half_closed)   << 21;
    return inv_mix(h, f);
}

uint64_t proxy_instance::inv_digest(const proxy_backend_connection* b)
{
    uint64_t h = 0xCBF29CE484222325ull;
    h = inv_mix(h, static_cast<uint64_t>(b->fd));
    h = inv_mix(h, b->generation);
    h = inv_mix(h, b->partial.size());
    h = inv_mix(h, b->write_queue.bytes());
    h = inv_mix(h, b->write_queue.size());
    h = inv_mix(h, b->write_batch_count);
    h = inv_mix(h, static_cast<uint64_t>(b->client_fd));
    h = inv_mix(h, static_cast<uint64_t>(b->tls_state));
    h = inv_mix(h, b->pool_backend_idx);
    h = inv_mix(h, b->pool_port);
    // The response frame is this half's whole notion of "further on than it
    // was": body_remaining counts down as the answer arrives, and the rest of
    // it changes exactly once per response.
    h = inv_mix(h, b->http_frame.body_remaining);
    h = inv_mix(h, b->http_frame.status_code);
    h = inv_mix(h, b->http_frame.interim_blocks);

    uint64_t f = 0;
    f |= uint64_t(b->read_pending)                   << 0;
    f |= uint64_t(b->write_pending)                  << 1;
    f |= uint64_t(b->closing)                        << 2;
    f |= uint64_t(b->zc_notif_pending)               << 3;
    f |= uint64_t(b->splice_active)                  << 4;
    f |= uint64_t(b->splice_in_pending)              << 5;
    f |= uint64_t(b->splice_out_pending)             << 6;
    f |= uint64_t(b->pool_draining)                  << 7;
    f |= uint64_t(b->pool_abandoned)                 << 8;
    f |= uint64_t(b->tls_peer_closed)                << 9;
    f |= uint64_t(b->http_frame.headers_parsed)      << 10;
    f |= uint64_t(b->http_frame.has_content_length)  << 11;
    f |= uint64_t(b->http_frame.conn_close)          << 12;
    f |= uint64_t(b->http_frame.chunked)             << 13;
    f |= uint64_t(b->http_frame.no_body)             << 14;
    f |= uint64_t(b->http_frame.transfer_encoding)   << 15;
    f |= uint64_t(b->http_frame.response_bytes_seen) << 16;
    f |= uint64_t(b->http_frame.unknown)             << 17;
    f |= uint64_t(b->ssl != nullptr)                 << 18;
    f |= uint64_t(b->sent_to_client)                 << 19;
    // Here because it is a state change like the rest, and leaving it out
    // would make the one transition that travels separately invisible to the
    // progress ledger.
    f |= uint64_t(b->http_frame.overrun)             << 20;
    return inv_mix(h, f);
}

// Invariant (3) charged to the half the completion named rather than to the
// pair, so a client parked while its backend answers accrues nothing and
// cannot be suspected.
void proxy_instance::inv_check_progress(int fd, int res, uint8_t type, const char* where)
{
    if (fd < 0 || fd >= MAX_FDS)
        return;

    // Only operations that carry traffic report a byte count, so counting a
    // poll's revents or a connect's zero would excuse a connection for the
    // wrong reason.
    uint64_t bytes = 0;
    if (res > 0)
    {
        switch (type)
        {
            case op_read:  case op_read_provided: case op_recv_multishot:
            case op_write: case op_writev:        case op_send_zc:
            case op_splice:
                bytes = static_cast<uint64_t>(res);
                break;
            default:
                break;
        }
    }

    const auto& entry = m_conn_idx[fd];
    if (entry.side == conn_client)
    {
        auto* c = entry.client;
        SKL_INV_PROGRESS(where, c->pr, inv_digest(c), bytes, c->fd, io_op_name(type), res);
    }
    else if (entry.side == conn_backend)
    {
        auto* b = entry.backend;
        SKL_INV_PROGRESS(where, b->pr, inv_digest(b), bytes, b->fd, io_op_name(type), res);
    }
    // Anything else is a connection the handler has just torn down, with
    // nothing left to make progress and the ledger gone with the struct.
}

void proxy_instance::inv_sweep_all(const char* where)
{
    // Both sides, not just the client side: a backend whose client has already
    // gone keeps client_fd == -1 and is reachable from no client slot at all,
    // and that is the half most likely to have been left behind.
    for (int fd = 0; fd < MAX_FDS; fd++)
    {
        if (m_conn_idx[fd].side != conn_none)
            inv_check_pair(fd, where);
    }
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
            close_tracked(client_fd);
            goto proxy_resubmit_accept;
        }

        // A descriptor can come off the backlog already broken, which under a
        // flood is nearly every connection, so one getsockopt saves seven
        // socket options, a 64 KB struct, a backend socket and a handshake
        // spent on a peer that cannot receive a byte.
        {
            int sock_err = 0;
            socklen_t err_len = sizeof(sock_err);
            if (SOCKETLEY_UNLIKELY(
                    getsockopt(client_fd, SOL_SOCKET, SO_ERROR, &sock_err, &err_len) == 0 &&
                    sock_err != 0))
            {
                close_tracked(client_fd);
                goto proxy_resubmit_accept;
            }
        }

        // Everything tune_socket sets is TCP-level, so a client accepted off a
        // unix listener has nothing to hear from it — same reasoning, and the
        // same cost argument, as the backend connect's family guard.
        if (m_bound_listen_path.empty())
            tune_socket(client_fd);

        // Auth check: reject before allocating connection state
        if (!invoke_on_auth(client_fd))
        {
            close_tracked(client_fd);
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

        // A --tls listener gives every accepted socket a session before
        // on_connect and before the TCP-mode backend connect, because a
        // connection that did not know it was encrypted would send in the
        // clear.
        if (SOCKETLEY_UNLIKELY(m_tls != nullptr))
        {
            ptr->ssl = m_tls->create_ssl_server();
            if (SOCKETLEY_UNLIKELY(!ptr->ssl))
            {
                // No session, no encryption, so no connection, because serving
                // this client in cleartext is worse than dropping it.
                close_pair(client_fd, -1);
                goto proxy_resubmit_accept;
            }
            ptr->tls_state = tls_conn_handshake;
        }

        if (m_idle_timeout_cached > 0)
            ptr->last_activity = std::chrono::steady_clock::now();

        // The bucket starts full, so a burst up to the configured rate is
        // allowed, because a limiter that started empty would delay every
        // first request on every connection.
        if (m_rate_limit_cached > 0)
        {
            ptr->rl_max = m_rate_limit_cached;
            ptr->rl_tokens = m_rate_limit_cached;
            ptr->rl_last = std::chrono::steady_clock::now();
        }

        SKL_TRACE_SET(ptr, opened_ms, ::skl_trace::now_ms());
        invoke_on_connect(client_fd);

        // TCP connects first and reads second, because acknowledging bytes at
        // the TCP level and then discarding them tells the client they
        // arrived, while an unarmed read lets flow control slow it down
        // honestly.
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
                // Only a backend that actually refused belongs in the breaker,
                // because charging it for our own full ring took the one
                // healthy backend out of rotation.
                if (have_target && !ours) note_backend_failure(ptr);
                close_pair(client_fd, -1);
                goto proxy_resubmit_accept;
            }

            // Still connecting — handle_connect arms the read once it is up.
            if (ptr->connect_pending)
                goto proxy_resubmit_accept;

            // Connected synchronously, and if the splice pipeline is already
            // the reader, arming a userspace read as well would put two
            // readers on one socket.
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

// Arm the read that fits the configured mode, false when the submission did
// not reach the ring, because the caller must not leave the connection marked
// pending with no completion coming.
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

    // One backoff timer at a time, because a second on the same request gives
    // the listener two retry chains and the earlier timeout cannot be taken
    // back.
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

// header_name_equals and http_eol_framing_ok moved to shared/http_framing.h
// with the response side, rather than being declared in two places.

// te_line_codings_ok() moved to shared/http_framing.h with the rest of the
// request framing decision it was one clause of, so the server has the same
// rules from the same copy.

// backend_response_complete() moved to http_framing.h alongside the scan that
// produces the state it reads, so both pooling paths ask one predicate a test
// can call.
static inline bool backend_response_complete(const proxy_backend_connection* bconn)
{
    return http_response_frame_complete(bconn->http_frame);
}

// "A request left this client and its answer has not come back", written once
// because three places have to agree -- which is what makes the invariant the
// specification for the hold rather than a second opinion about it.
static inline bool client_answer_owed(const proxy_client_connection* cconn,
                                      const proxy_backend_connection* bconn)
{
    return cconn->connect_pending ||   // the request has not reached a backend yet
           (bconn && !(cconn->response_started && backend_response_complete(bconn)));
}

void proxy_instance::handle_client_read(struct io_uring_cqe* cqe, io_request* req)
{
    int fd = req->fd;
    auto& entry = m_conn_idx[fd];
    if (SOCKETLEY_UNLIKELY(entry.side != conn_client))
        return;

    auto* conn = entry.client;

    bool is_multishot_recv = is_multishot_recv_op(req->type);
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
            // Reset the request type, because leaving it as a provided-buffer
            // type makes the handler append ring buffer 0's contents and
            // return a buffer it never took.
            conn->read_req.type = op_read;
            if (SOCKETLEY_UNLIKELY(!m_loop->submit_read(fd, conn->read_buf,
                                                        sizeof(conn->read_buf), &conn->read_req)))
            {
                conn->read_pending = false;
                close_pair(fd, conn->backend_fd);
            }
            return;
        }

        // IORING_CQE_F_SOCK_NONEMPTY on a zero-length completion is the FIN's
        // own sequence number and not data left to collect, so re-arming on it
        // was a loop -- measured at 1.35 million iterations on one connection
        // with the pair never torn down.

        // A clean EOF means the client will send no more, not that its request
        // or the answer may be thrown away, so the pair is held while an
        // answer is genuinely owed -- bounded by --backend-timeout, with no
        // read re-armed so a client cannot buy time with a FIN, and ended by
        // reset_client_for_next_request or the deadline sweep.
        if (cqe->res == 0 && !conn->closing && m_protocol == protocol_tcp &&
            hold_tcp_half_close(conn))
            return;

        if (cqe->res == 0 && !conn->closing && m_protocol == protocol_http)
        {
            const proxy_backend_connection* b = nullptr;
            if (conn->backend_fd >= 0 && conn->backend_fd < MAX_FDS &&
                m_conn_idx[conn->backend_fd].side == conn_backend)
                b = m_conn_idx[conn->backend_fd].backend;

            // Stated out of the exchange and deliberately not out of
            // awaiting_response, which arm_response_deadline leaves unset when
            // --backend-timeout is 0 -- the one configuration where nothing
            // else would catch it either.
            const bool answer_owed = client_answer_owed(conn, b);

            if (answer_owed)
            {
                conn->client_eof = true;
                return;
            }
        }

        // Everything reaching here has already declined the hold, so what is
        // left is a read that failed -- and a socket the kernel has reset
        // cannot carry an answer however much is owed on it, stated with force
        // because the gate cannot see the difference.
        close_pair(fd, conn->backend_fd,
                   cqe->res < 0 ? close_reason::force : close_reason::normal);
        return;
    }

    SKL_TRACE_ADD(conn, bytes_read, (unsigned long long)cqe->res);
    SKL_TRACE_ADD(conn, reads, 1);

    if (SOCKETLEY_UNLIKELY(m_idle_timeout_cached > 0))
        conn->last_activity = std::chrono::steady_clock::now();

    // Track bytes in
    m_stat_bytes_in.fetch_add(static_cast<uint64_t>(cqe->res), std::memory_order_relaxed);
    m_stat_total_messages.fetch_add(1, std::memory_order_relaxed);

    // --rate-limit is implemented here, having been parsed, stored and
    // reported while nothing read it, charged per read completion so the two
    // limiters agree -- and exceeding it costs the connection, because a
    // silently dropped request is a hang rather than a refusal.
    if (SOCKETLEY_UNLIKELY(conn->rl_max > 0))
    {
        const auto rl_now = std::chrono::steady_clock::now();
        const double elapsed = std::chrono::duration<double>(rl_now - conn->rl_last).count();
        conn->rl_last = rl_now;
        conn->rl_tokens += elapsed * conn->rl_max;
        if (conn->rl_tokens > conn->rl_max)
            conn->rl_tokens = conn->rl_max;

        if (conn->rl_tokens < 1.0)
        {
            if (is_provided && (cqe->flags & IORING_CQE_F_BUFFER))
            {
                uint16_t buf_id_rl = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
                m_loop->return_buf(BUF_GROUP_ID, buf_id_rl);
            }
            close_pair(fd, conn->backend_fd);
            return;
        }
        conn->rl_tokens -= 1.0;
    }

    // Global rate limiting
    if (SOCKETLEY_UNLIKELY(!check_global_rate_limit()))
    {
        if (is_provided && (cqe->flags & IORING_CQE_F_BUFFER))
        {
            uint16_t buf_id_rl = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
            m_loop->return_buf(BUF_GROUP_ID, buf_id_rl);
        }
        // The end-of-stream tests could not fire here, because every path out
        // of the block above returns and res is positive by construction; they
        // are stated once where a zero-length completion is seen.
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

    // These bytes are ciphertext: tls_feed leaves plaintext in conn->partial
    // and tls_flush puts back what the session owes, flushed here so a failed
    // handshake's alert is in flight before any teardown path decides nothing
    // is pending.
    std::string tls_plain;
    if (SOCKETLEY_UNLIKELY(conn->ssl != nullptr))
    {
        tls_feed(conn, read_data, static_cast<size_t>(cqe->res));
        if (is_provided)
        {
            m_loop->return_buf(BUF_GROUP_ID, buf_id);
            is_provided = false;   // returned; the branches below must not again
        }
        if (!tls_flush(conn))
            conn->closing = true;
        // The peer's close_notify is applied now rather than where it was
        // read, because the read that carried it can carry a last request
        // ahead of it.
        if (conn->tls_peer_closed)
            conn->closing = true;

        if (SOCKETLEY_UNLIKELY(conn->closing))
        {
            if (!conn->write_pending && !conn->read_pending &&
                !conn->splice_in_pending && !conn->splice_out_pending)
                close_pair(fd, conn->backend_fd);
            return;
        }

        // Mid-handshake, so nothing was decrypted and there is nothing to
        // route; the read is re-armed and the next flight arrives.
        if (conn->partial.empty())
        {
            if (!conn->read_pending &&
                SOCKETLEY_UNLIKELY(!submit_read_op(m_loop, fd, conn, m_recv_multishot,
                                                   m_use_provided_bufs, BUF_GROUP_ID)))
                close_pair(fd, conn->backend_fd);
            return;
        }

        // TCP mode forwards what it is given rather than parsing it, so the
        // plaintext is taken out of `partial` into a buffer of its own while
        // HTTP reads partial directly.
        if (m_protocol == protocol_tcp)
        {
            tls_plain.swap(conn->partial);
            read_data = tls_plain.data();
        }
    }

    if (m_protocol == protocol_tcp)
    {
        // The decrypted length when there is a session, the completion's own
        // when there is not.
        const size_t data_len = conn->ssl ? tls_plain.size()
                                          : static_cast<size_t>(cqe->res);
        // If async connect is pending, buffer incoming data (with limit)
        if (SOCKETLEY_UNLIKELY(conn->connect_pending))
        {
            if (conn->saved_request.size() < proxy_client_connection::MAX_PARTIAL_SIZE)
                conn->saved_request.append(read_data, data_len);
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
            conn->saved_request.assign(read_data, data_len);
            if (is_provided)
                m_loop->return_buf(BUF_GROUP_ID, buf_id);

            bool ours = false;
            if (SOCKETLEY_UNLIKELY(!connect_to_backend(conn, target, &ours)))
            {
                if (!ours) note_backend_failure(conn);
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

        std::string_view data(read_data, data_len);
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
                // Backpressure: pause client reads while the backend write
                // queue fills, and handle_backend_write resumes them when it
                // drains.
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

    // HTTP mode, where on a TLS connection tls_feed has already put the
    // plaintext in `partial` and returned the provided buffer.
    if (SOCKETLEY_LIKELY(conn->ssl == nullptr))
    {
        conn->partial.append(read_data, cqe->res);
        if (is_provided)
            m_loop->return_buf(BUF_GROUP_ID, buf_id);
    }

    // If async connect is pending, just buffer data in partial
    if (SOCKETLEY_UNLIKELY(conn->connect_pending))
    {
        if (SOCKETLEY_LIKELY(!conn->closing) && !conn->read_pending)
            if (SOCKETLEY_UNLIKELY(!submit_read_op(m_loop, fd, conn, m_recv_multishot, m_use_provided_bufs, BUF_GROUP_ID)))
            {
                // A submission that did not reach the ring is this proxy's
                // shortage while a whole request waits on a handshake, so 503
                // rather than silence.
                answer_gateway_failure(conn, true);
                close_pair(fd, conn->backend_fd);
                return;
            }
        return;
    }

    // More buffered than this proxy will hold, which is one client asking it
    // to carry a megabyte rather than a malformed request, so 413 -- declined
    // by client_answerable when a response has already started, and answered
    // by tls_feed on a session, which hits its own ceiling while decrypting.
    if (SOCKETLEY_UNLIKELY(conn->partial.size() > proxy_client_connection::MAX_PARTIAL_SIZE))
    {
        answer_request_too_large(conn);
        // force: the refusal is the answer, and holding would leave the
        // multishot recv armed and go on accepting the very bytes the ceiling
        // exists to stop.
        close_pair(fd, conn->backend_fd, close_reason::force);
        return;
    }

    // An error response is queued and this connection is going down, but a
    // multishot recv stays armed -- so without this the bytes behind it were
    // parsed as a brand new request and forwarded on a socket already told to
    // close.
    if (SOCKETLEY_UNLIKELY(conn->closing))
    {
        conn->partial.clear();
        if (!conn->write_pending)
            close_pair(fd, conn->backend_fd);
        return;
    }

    drive_client_request(conn, fd);
}

// See the declaration for why the answer lives on the backend.
bool proxy_instance::conn_tunnelled(const proxy_client_connection* conn) const
{
    if (conn->backend_fd < 0 || conn->backend_fd >= MAX_FDS)
        return false;
    const auto& be = m_conn_idx[conn->backend_fd];
    if (be.side != conn_backend)
        return false;
    // Mutual, like every cross-half read here, because a descriptor number
    // does not prove identity and reading a stranger's framing state would
    // relay this client's bytes on somebody else's 101.
    if (be.backend->client_fd != conn->fd)
        return false;
    return be.backend->http_frame.switched_protocols;
}

// The connection has stopped being HTTP, so the header deadline is disarmed --
// it would answer 408 to a working tunnel -- and the buffered first frames are
// flushed, since nothing else will collect them.
void proxy_instance::begin_tunnel(proxy_client_connection* cconn)
{
    cconn->awaiting_headers = false;

    if (!cconn->partial.empty() && !cconn->closing && cconn->backend_fd >= 0)
    {
        std::string pending;
        pending.swap(cconn->partial);
        forward_to_backend(cconn, pending);
    }
}

// A request pipelined behind one in flight waits for that exchange to end, and
// a backend whose header block straddles a read boundary never ends it -- so
// the same 408 bound a half-arrived request gets, because holding is only safe
// if something ends the hold.
void proxy_instance::bound_pipelined_hold(proxy_client_connection* conn)
{
    if (conn->closing || conn->partial.empty())
        return;
    // What is buffered is body, not a request; the body path forwards it.
    if (conn->body_unbounded || conn->body_remaining > 0)
        return;
    arm_header_deadline(conn);
}

// See the declaration for why this is reachable from two places; everything
// below is the same code that sat inline at the end of handle_client_read.
void proxy_instance::drive_client_request(proxy_client_connection* conn, int fd)
{
    // ── the tunnel ──────────────────────────────────────────────────────────
    // A tunnel is relayed rather than read, and this branch is first because
    // every question below would be asked of bytes that cannot answer --
    // relayed with ordinary read and write rather than splice, because a
    // multishot recv already is a poll until data arrives.
    if (SOCKETLEY_UNLIKELY(conn_tunnelled(conn)))
    {
        if (!conn->partial.empty())
        {
            std::string relay;
            relay.swap(conn->partial);
            forward_to_backend(conn, relay);
        }
    }
    else if (!conn->header_parsed)
    {
        // Slowloris / oversized header protection
        if (SOCKETLEY_UNLIKELY(conn->partial.size() > proxy_client_connection::MAX_HEADER_SIZE))
        {
            send_error(conn, "431 Request Header Fields Too Large", "Header Too Large\n");
            return;
        }

        const auto parsed = parse_http_request_line(conn);
        if (parsed != http_request_parse::complete)
        {
            if (parsed == http_request_parse::invalid)
            {
                // Refused, and the connection goes with it, because answering
                // and carrying on would mean deciding where this request ends
                // -- which is what could not be decided.
                conn->partial.clear();
                send_error(conn, "400 Bad Request", "Bad Request\n");
                return;
            }

            // Need more data, and from here on not for ever: the 16 KiB limit
            // counts bytes and a client that stops sends none, while
            // --idle-timeout defaults to sweeping nothing.
            arm_header_deadline(conn);

            if (!conn->read_pending)
                if (SOCKETLEY_UNLIKELY(!submit_read_op(m_loop, fd, conn, m_recv_multishot, m_use_provided_bufs, BUF_GROUP_ID)))
                {
                    close_pair(fd, conn->backend_fd);
                    return;
                }
            return;
        }

        conn->header_parsed = true;
        // The block arrived; what happens next is the request's own business
        // and is timed by --backend-timeout, not by this.
        conn->awaiting_headers = false;

        // Check path prefix (m_prefix = "/<name>/", strip trailing slash for bare match)
        std::string_view bare = std::string_view(m_prefix).substr(0, m_prefix.size() - 1);
        if (!conn->path.starts_with(m_prefix) && conn->path != bare)
        {
            send_error(conn, "404 Not Found", "Not Found\n");
            return;
        }

        // Strip prefix through backend_path(), because on_route needs the same
        // answer and two copies of a string transformation is two chances to
        // tell a script a path the backend never sees.
        std::string_view new_path = backend_path(conn->path);

        // The route declaration, first of everything, because it is the
        // cheapest verdict available and the only one derived from what the
        // handler said.
        if (SOCKETLEY_UNLIKELY(!m_routes.empty()) &&
            enforce_declared_route(conn, new_path))
            return;   // answered here; no filter ran and no backend was chosen

        // The filter chain, above the selection, because everything a filter
        // exists to stop begins on the next line -- guarded by the callback
        // mask like every other hook.
        if (SOCKETLEY_UNLIKELY(lua() && lua()->has_filters()) &&
            run_request_filters(conn))
            return;   // answered by a filter; no backend was ever chosen

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

        // Before the connect, because an asynchronous one returns out of this
        // function below and the bound would never be armed for the commonest
        // shape of all: both requests in the first read of a fresh connection.
        bound_pipelined_hold(conn);

        bool ours = false;
        if (SOCKETLEY_UNLIKELY(!connect_to_backend(conn, target, &ours)))
        {
            if (!ours) note_backend_failure(conn);
            if (!try_retry(conn))
            {
                answer_gateway_failure(conn, ours);
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
                    answer_gateway_failure(conn, true);
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
    else if (conn->backend_fd >= 0 && !conn->partial.empty())
    {
        // Only the body may go out here, because forwarding the whole buffer
        // is the same hole rewrite_http_request had: bytes nothing has parsed
        // reaching a backend that parses them.
        const size_t n = conn->body_unbounded
            ? conn->partial.size()
            : std::min(conn->body_remaining, conn->partial.size());
        if (n > 0)
        {
            forward_to_backend(conn, std::string_view(conn->partial.data(), n));
            if (!conn->body_unbounded)
                conn->body_remaining -= n;
            conn->partial.erase(0, n);
        }
        // Whatever is still buffered is the next request, which waits for this
        // one's response and is then parsed from the top.
    }

    bound_pipelined_hold(conn);

proxy_http_resubmit:
    if (SOCKETLEY_LIKELY(!conn->closing))
    {
        if (!conn->read_pending)
        {
            // Backpressure: pause client reads while the backend write queue
            // fills, and handle_backend_write resumes them when it drains.
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
                    // The request has gone to a backend and the pair is being
                    // torn down, which is our shortage rather than the
                    // backend's, so 503 -- declined on its own if any of the
                    // answer has reached the client.
                    answer_gateway_failure(conn, true);
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

    // Backend fds and structs are both pooled, so the generation stamped at
    // submit time is what stops one backend's bytes being spliced into an
    // unrelated client's response.
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

    bool is_multishot_recv = is_multishot_recv_op(req->type);
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
            // Reset the request type, because leaving it as a provided-buffer
            // type makes the handler append ring buffer 0's contents and
            // return a buffer it never took.
            conn->read_req.type = op_read;
            if (SOCKETLEY_UNLIKELY(!m_loop->submit_read(fd, conn->read_buf,
                                                        sizeof(conn->read_buf), &conn->read_req)))
            {
                conn->read_pending = false;
                close_pair(conn->client_fd, fd);
            }
            return;
        }

        // Charge the breaker only when the backend actually failed: a clean
        // EOF is ordinary, and our own shutdown(SHUT_RD) makes an armed read
        // return 0 -- which took a healthy backend out of rotation after five
        // aborting clients, measured as 7067 connections and 84 messages
        // delivered.
        const bool teardown_is_ours = conn->closing;

        if (conn->client_fd >= 0 && conn->client_fd < MAX_FDS)
        {
            auto& ce = m_conn_idx[conn->client_fd];
            // Charged to whichever breaker describes this connection's
            // backend, because reading backend_idx unconditionally put every
            // group member's failure on whatever occupied that slot.
            if (ce.side == conn_client)
            {
                // "The backend answered" is not "bytes arrived", so the charge
                // is stated over the framing state -- all three terms, because
                // a header block split across two reads leaves headers_parsed
                // false for ever and `unknown` is this proxy saying it cannot
                // tell.
                const bool never_framed =
                    (m_protocol == protocol_http) &&
                    conn->http_frame.response_bytes_seen &&
                    !conn->http_frame.headers_parsed &&
                    !conn->http_frame.unknown;
                // sent_to_client states the same question where a byte relay
                // can answer it, because response_started is only assigned on
                // the HTTP path, so on a TCP proxy this term was a constant
                // true and five ordinary exchanges opened the breaker.
                const bool backend_answered = (m_protocol == protocol_http)
                                                  ? ce.client->response_started
                                                  : conn->sent_to_client;
                const bool backend_failed =
                    (cqe->res < 0) || !backend_answered || never_framed;
                if (backend_failed && !teardown_is_ours)
                    note_backend_failure(ce.client);

                // The backend went away before a byte of the answer did, and
                // closing the client told it nothing -- commonly a pooled
                // socket the backend had already closed, so a retry where one
                // is configured and 502 where it is not.
                if (m_protocol == protocol_http && backend_failed &&
                    !ce.client->closing && !ce.client->response_started)
                {
                    auto* cconn = ce.client;
                    // Detach the pair before either branch runs, because a
                    // retry opens a backend of its own and leaving the two
                    // pointing at each other lets this teardown take the
                    // client with it.
                    cconn->backend_fd = -1;
                    conn->client_fd = -1;
                    if (!try_retry(cconn))
                        answer_gateway_failure(cconn, false);
                    close_pair(-1, fd);
                    return;
                }
            }
        }

        // force: this pair has no source of further bytes and everything
        // answerable was answered above -- the answer-owed invariant found
        // this site, on a truncating backend whose framing is incomplete
        // although RFC 9112 6.3 makes the response complete.
        close_pair(conn->client_fd, fd, close_reason::force);
        return;
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

    // The mirror of the client leg, flushing what the session owes before
    // anything decides the connection is idle -- and returning rather than
    // falling through with zero, because a handshake round produces no
    // plaintext and must not be mistaken for a response.
    std::string tls_plain;
    if (SOCKETLEY_UNLIKELY(conn->ssl != nullptr))
    {
        tls_feed(conn, data_ptr, data_len);
        if (is_provided)
        {
            m_loop->return_buf(BUF_GROUP_ID, buf_id);
            is_provided = false;
        }
        if (!tls_flush(conn))
            conn->closing = true;
        if (conn->tls_peer_closed)
            conn->closing = true;

        if (SOCKETLEY_UNLIKELY(conn->closing && conn->partial.empty()))
        {
            // A failed handshake leaves nothing decrypted and the client
            // waiting on a request that was never sent, so 502 says which half
            // failed, and a retry is safe because not one byte has reached the
            // client.
            if (m_protocol == protocol_http && conn->client_fd >= 0 &&
                conn->client_fd < MAX_FDS)
            {
                auto& ce = m_conn_idx[conn->client_fd];
                if (ce.side == conn_client && !ce.client->closing &&
                    !ce.client->response_started)
                {
                    auto* cconn = ce.client;
                    // A backend this proxy cannot complete a handshake with is
                    // as unusable as one refusing connections, and belongs in
                    // the breaker for the same reason.
                    note_backend_failure(cconn);
                    // Detached before either branch runs: a retry opens a
                    // backend of its own and this one is torn down next line.
                    cconn->backend_fd = -1;
                    conn->client_fd = -1;
                    // 502 and not 503, because this is a handshake the backend
                    // answered and rejected: the record layer has been on the
                    // wire and the far end is what said no.
                    if (!try_retry(cconn))
                        answer_gateway_failure(cconn, false);
                    close_pair(-1, fd);
                    return;
                }
            }
            if (!conn->write_pending && !conn->read_pending &&
                !conn->splice_in_pending && !conn->splice_out_pending)
                close_pair(conn->client_fd, fd);
            return;
        }

        if (conn->partial.empty())
        {
            // Mid-handshake, or a record that carried no application data, so
            // re-arm and wait for the next flight.
            if (!conn->read_pending &&
                SOCKETLEY_UNLIKELY(!submit_read_op_backend(m_loop, fd, conn, m_recv_multishot,
                                                           m_use_provided_bufs, BUF_GROUP_ID)))
                close_pair(conn->client_fd, fd);
            return;
        }

        tls_plain.swap(conn->partial);
        data_ptr = tls_plain.data();
        data_len = tls_plain.size();
    }

    // Below the decryption, because on a TLS leg counting a handshake
    // completion as "the backend answered" would clear the deadline and bar a
    // retry before the request went out -- with the plain fact recorded for
    // both protocols.
    conn->sent_to_client = true;

    if (m_protocol == protocol_http && conn->client_fd >= 0 && conn->client_fd < MAX_FDS)
    {
        auto& ce = m_conn_idx[conn->client_fd];
        if (ce.side == conn_client && !ce.client->response_started)
        {
            // Mark that we've started receiving response data — no retry after this
            ce.client->response_started = true;
            // The backend has answered, so the first-byte deadline is over:
            // cutting a slow or streaming body short would be a new defect
            // rather than a fix.
            clear_response_deadline(ce.client);
        }
    }

    // The scan runs before the forward because it decides its length: a
    // backend flushing an answer and the head of another put bytes on the
    // client's wire that answer no outstanding request, and those are dropped.
    const bool framed_before  = conn->http_frame.headers_parsed;
    const bool tunnel_before  = conn->http_frame.switched_protocols;
    size_t forward_len = data_len;
    if (m_protocol == protocol_http)
    {
        http_response_scan_chunk(conn->http_frame, {data_ptr, data_len});
        const size_t excess = conn->http_frame.excess_in_chunk;
        if (SOCKETLEY_UNLIKELY(excess > 0 && excess <= data_len))
            forward_len = data_len - excess;
    }

    // Forward to client
    forward_to_client(conn, {data_ptr, forward_len});

    // The response framing decides both whether the socket may be pooled and
    // how much of this chunk the client may see, which were one question all
    // along -- with the scan itself in shared/http_framing.h, where a fuzz
    // target can drive it.

    // The breaker hears the backend answered here rather than on the first
    // byte, because a status line and one header followed by a half-close was
    // recorded as a success on every request and cancelled the failure out.
    if (m_protocol == protocol_http && !framed_before && conn->http_frame.headers_parsed &&
        conn->client_fd >= 0 && conn->client_fd < MAX_FDS)
    {
        auto& ce = m_conn_idx[conn->client_fd];
        if (ce.side == conn_client)
            note_backend_success(ce.client);
    }

    // Return provided buffer after scanning
    if (is_provided)
        m_loop->return_buf(BUF_GROUP_ID, buf_id);

    // ── the switch ──────────────────────────────────────────────────────────
    // The 101 has been forwarded and this pair is a byte relay from here,
    // handled on the backend leg because that is the only place the 101
    // exists, as the false-to-true transition of a field the scan sets once.
    if (m_protocol == protocol_http && !tunnel_before &&
        conn->http_frame.switched_protocols &&
        conn->client_fd >= 0 && conn->client_fd < MAX_FDS)
    {
        auto& ce = m_conn_idx[conn->client_fd];
        if (ce.side == conn_client && ce.client->backend_fd == fd)
            begin_tunnel(ce.client);
    }

    // The "is it finished" half of the pool test is one shared predicate now,
    // so a change to what finished means reaches the teardown paths as well as
    // this one.
    if (m_protocol == protocol_http && !conn->http_frame.conn_close &&
        !conn->closing && !conn->splice_active &&
        backend_response_complete(conn))
    {
        if (conn->client_fd >= 0 && conn->client_fd < MAX_FDS)
        {
            auto& ce = m_conn_idx[conn->client_fd];
            if (ce.side == conn_client && !ce.client->closing)
            {
                // The client's own `Connection: close` is not a condition
                // here, because it says nothing about whether the backend
                // socket is at a message boundary -- refusing on it cost a
                // backend connection per request -- and the group guard read
                // slot 0, so an @group gateway never detached and every later
                // request reached the member with the prefix still on it.
                detach_and_pool_backend(ce.client, fd);
                return;
            }
        }
    }

    // ── the end of the hold ─────────────────────────────────────────────────
    // A held half-closed client whose answer is now complete is closed here,
    // because everything past the detach had no ending at all and the pair sat
    // with only the backend's idle read armed -- asked out of
    // client_answer_owed(), the same predicate the hold and the invariant use.
    if (m_protocol == protocol_http && conn->client_fd >= 0 &&
        conn->client_fd < MAX_FDS)
    {
        auto& ce = m_conn_idx[conn->client_fd];
        if (ce.side == conn_client && ce.client->client_eof &&
            !ce.client->closing && !client_answer_owed(ce.client, conn))
        {
            ce.client->closing = true;
            close_pair(ce.client->fd, fd);
            return;
        }
    }

    if (SOCKETLEY_LIKELY(!conn->closing))
    {
        if (!conn->read_pending)
        {
            // Backpressure: pause backend reads while the client write queue
            // fills, and handle_client_write resumes them when it drains.
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

http_request_parse proxy_instance::parse_http_request_line(proxy_client_connection* conn)
{
    // The header block ends at the first blank line, which under the rule
    // above is "\r\n\r\n" and no other, so until it turns up every byte
    // received is still header.
    const auto hdr_end = conn->partial.find("\r\n\r\n");
    const bool block_complete = (hdr_end != std::string::npos);
    const size_t scan_len = block_complete ? hdr_end : conn->partial.size();

    // Scanned before anything is parsed out of these bytes, request line
    // included, because a bare LF put a whole header line inside conn->version
    // and sent it on the request line.
    if (SOCKETLEY_UNLIKELY(!http_eol_framing_ok(
            std::string_view(conn->partial.data(), scan_len), block_complete)))
        return http_request_parse::invalid;

    // Ready means the whole header block and not just the request line,
    // because returning early meant the smuggling check never ran and the
    // client's real headers were forwarded as a body the backend read as a
    // second request.
    if (!block_complete)
        return http_request_parse::need_more;

    const auto pos = conn->partial.find("\r\n");   // exists: "\r\n\r\n" contains it
    std::string_view line(conn->partial.data(), pos);

    // A miss here is not "read more", because the header block is already
    // complete and asking for more bytes only stalls until a limit fires.
    auto sp1 = line.find(' ');
    if (SOCKETLEY_UNLIKELY(sp1 == std::string_view::npos))
        return http_request_parse::invalid;

    auto sp2 = line.find(' ', sp1 + 1);
    if (SOCKETLEY_UNLIKELY(sp2 == std::string_view::npos))
        return http_request_parse::invalid;

    conn->method.assign(line.data(), sp1);
    conn->path.assign(line.data() + sp1 + 1, sp2 - sp1 - 1);
    conn->version.assign(line.data() + sp2 + 1, line.size() - sp2 - 1);

    // pos and hdr_end are equal for a request that carries no headers, and the
    // subtraction then wrapped to SIZE_MAX-1 and sent the scan across the
    // address space -- reachable by anyone who can open the port.
    const size_t hdr_len = (hdr_end > pos + 2) ? (hdr_end - pos - 2) : 0;
    std::string_view headers(conn->partial.data() + pos + 2, hdr_len);

    // The framing rules in their one copy, which used to be eighty lines here
    // and nowhere else -- which is why the server disagreed with this function
    // about where four malformed requests ended.
    const http_request_framing_scan scan = http_scan_request_headers(headers);
    if (SOCKETLEY_UNLIKELY(!scan.ok))
        return http_request_parse::invalid;

    // How long this request's body is, from a header block just proved to give
    // exactly one answer, with everything past it held back by
    // rewrite_http_request.
    conn->declared_body_len = scan.has_content_length ? scan.content_length : 0;
    conn->declared_body_chunked = scan.transfer_encoding;

    return http_request_parse::complete;
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

// The path the backend is given, written once for the forwarding site and
// on_route's third argument -- with the bare `/gw` case the point, since a
// script stripping the prefix by hand yields "", which no router matches.
std::string_view proxy_instance::backend_path(std::string_view client_path) const
{
    // "/" + name + "/" is at least two characters, so a shorter prefix means
    // the name was never set and there is nothing to strip.
    if (m_prefix.size() < 2)
        return client_path;

    const std::string_view bare(m_prefix.data(), m_prefix.size() - 1);
    if (client_path == bare)
        return "/";
    if (client_path.starts_with(m_prefix))
        return client_path.substr(m_prefix.size() - 1);   // keeps the leading /
    return client_path;
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

    // The block is measured from the same terminator parse_http_request_line
    // used, because searching behind the request line finds the next request's
    // terminator for a request with no headers -- found by fuzz_http_request,
    // and the same mistake check_no_smuggling made on the other side of the
    // seam.
    const auto hdr_end = conn->partial.find("\r\n\r\n");
    std::string_view headers_section;
    size_t body_off;
    if (SOCKETLEY_UNLIKELY(hdr_end == std::string::npos))
    {
        headers_section = std::string_view(conn->partial.data() + pos + 2,
                                           conn->partial.size() - pos - 2);
        body_off = conn->partial.size();
    }
    else if (hdr_end <= pos)
    {
        headers_section = {};              // no headers at all
        body_off = pos + 4;
    }
    else
    {
        headers_section = std::string_view(conn->partial.data() + pos + 2, hdr_end - pos - 2);
        body_off = hdr_end + 4;
    }
    std::string_view body_section(conn->partial.data() + body_off,
                                  conn->partial.size() - body_off);

    // Connection and Upgrade survive the hop-by-hop strip on a request that
    // carries an upgrade offer, because they are the offer (RFC 7230 Section
    // 6.7) -- and stripping them made a strict backend answer a plain response
    // to a handshake the client believed had succeeded.
    bool upgrade_offered = false;
    {
        bool conn_has_upgrade = false, has_upgrade_field = false;
        size_t u_pos = 0;
        while (u_pos < headers_section.size())
        {
            auto nl = headers_section.find("\r\n", u_pos);
            if (nl == std::string_view::npos)
                nl = headers_section.size();
            const std::string_view line = headers_section.substr(u_pos, nl - u_pos);
            u_pos = nl + 2;
            const auto colon = line.find(':');
            if (colon == std::string_view::npos)
                continue;
            if (header_name_equals(line, "connection", 10))
            {
                if (http_list_has_token(http_trim_ows(line.substr(colon + 1)), "upgrade", 7))
                    conn_has_upgrade = true;
            }
            else if (header_name_equals(line, "upgrade", 7))
            {
                if (!http_trim_ows(line.substr(colon + 1)).empty())
                    has_upgrade_field = true;
            }
        }
        upgrade_offered = conn_has_upgrade && has_upgrade_field;
    }

    bool host_written = false;
    size_t h_pos = 0;
    while (h_pos < headers_section.size())
    {
        auto nl = headers_section.find("\r\n", h_pos);
        if (nl == std::string_view::npos)
            nl = headers_section.size();
        std::string_view hdr_line = headers_section.substr(h_pos, nl - h_pos);

        // The client's `Connection: close` is found by the same list parse the
        // Upgrade check uses, because a two-character prefix test missed
        // "keep-alive, close" and fired on "clientinfo".
        if (header_name_equals(hdr_line, "connection", 10))
        {
            const auto colon = hdr_line.find(':');
            if (colon != std::string_view::npos &&
                http_list_has_token(http_trim_ows(hdr_line.substr(colon + 1)), "close", 5))
                conn->client_conn_close = true;
        }

        // Skip hop-by-hop headers, except the two that make up an upgrade
        // offer on a request that carries one.
        bool skip = false;
        if (header_name_equals(hdr_line, "connection", 10) ||
            header_name_equals(hdr_line, "upgrade", 7))
            skip = !upgrade_offered;
        else if (header_name_equals(hdr_line, "keep-alive", 10) ||
                 header_name_equals(hdr_line, "proxy-authenticate", 18) ||
                 header_name_equals(hdr_line, "proxy-authorization", 19) ||
                 header_name_equals(hdr_line, "te", 2) ||
                 header_name_equals(hdr_line, "trailer", 7))
            skip = true;
        // Transfer-Encoding is deliberately not on this list, because this
        // proxy forwards the body byte for byte and removing the header would
        // leave the backend reading chunk sizes as content.

        // A header a filter set replaces the client's rather than joining it,
        // with the names lowercased and checked when they were collected, so
        // this loop cannot be made to skip a line it is responsible for.
        if (SOCKETLEY_UNLIKELY(!conn->filter_headers.empty()))
        {
            bool overridden = false;
            for (const auto& [n, v] : conn->filter_headers)
            {
                if (header_name_equals(hdr_line, n.c_str(), n.size()))
                {
                    overridden = true;
                    break;
                }
            }
            if (overridden)
            {
                h_pos = nl + 2;
                continue;
            }
        }

        // A header a filter removed is dropped here in every occurrence,
        // because taking away half of a field sent twice leaves the backend
        // reading a value the filter meant to delete.
        if (SOCKETLEY_UNLIKELY(!conn->filter_removed_headers.empty()))
        {
            bool removed = false;
            for (const auto& n : conn->filter_removed_headers)
            {
                if (header_name_equals(hdr_line, n.c_str(), n.size()))
                {
                    removed = true;
                    break;
                }
            }
            if (removed)
            {
                h_pos = nl + 2;
                continue;
            }
        }

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

    // What the chain asked for, once each and after the client's own block,
    // with name and value validated where they were taken from Lua.
    for (const auto& [n, v] : conn->filter_headers)
    {
        result += n;
        result += ": ";
        result += v;
        result += "\r\n";
    }

    // Keep-alive is requested unconditionally and never copied from the
    // client, because Connection is hop-by-hop -- copying it turned a
    // connection-per-request client into one backend socket per request,
    // measured at 12,000 sockets and 9,593 still in TIME-WAIT when the run
    // ended.
    if (!upgrade_offered)
        result += "Connection: keep-alive\r\n";

    result += "\r\n";

    // Only this request's declared body follows it, because forwarding
    // everything behind the header terminator handed a pipelined second
    // request to the backend without a single check running on it.
    size_t body_len;
    if (conn->declared_body_chunked)
    {
        // Except for chunked, where there is no length to compute, so the body
        // streams on -- bounding it would mean guessing where it ends and
        // truncating a legitimate upload.
        body_len = body_section.size();
        conn->body_unbounded = true;
        conn->body_remaining = 0;
    }
    else
    {
        body_len = std::min(conn->declared_body_len, body_section.size());
        conn->body_unbounded = false;
        conn->body_remaining = conn->declared_body_len - body_len;
    }

    if (body_len > 0)
        result.append(body_section.data(), body_len);

    // Consume exactly what was forwarded, with body_off the whole buffer on
    // the unreachable npos path so that case still clears it.
    conn->partial.erase(0, body_off + body_len);

    return result;
}

// ─── Declared routes ────────────────────────────────────────────────────────
// One question asked of a table the handler filled in: is this method one the
// handler said it would take on this path.

bool proxy_instance::request_has_header(const proxy_client_connection* conn,
                                        const char* lower_name, size_t len)
{
    const auto line_end = conn->partial.find("\r\n");
    const auto hdr_end  = conn->partial.find("\r\n\r\n");
    if (line_end == std::string::npos || hdr_end == std::string::npos || hdr_end <= line_end)
        return false;

    std::string_view block(conn->partial.data() + line_end + 2, hdr_end - line_end - 2);
    size_t p = 0;
    while (p < block.size())
    {
        auto nl = block.find("\r\n", p);
        if (nl == std::string_view::npos)
            nl = block.size();
        if (header_name_equals(block.substr(p, nl - p), lower_name, len))
            return true;
        p = nl + 2;
    }
    return false;
}

bool proxy_instance::enforce_declared_route(proxy_client_connection* conn,
                                            std::string_view path)
{
    const route_decl* route = m_routes.find(route_path_only(path));
    if (!route)
        return false;   // nobody declared this path; it is not this gate's business

    // OPTIONS is never refused here — route_table::method_allowed says why —
    // but there are three different right answers to it and the declaration
    // picks between them.
    if (conn->method == "OPTIONS")
    {
        // The handler asked for OPTIONS itself, so forward rather than
        // second-guess it: that is how a CORS layer written in Lua keeps
        // working.
        for (const auto& m : route->methods)
            if (m == "OPTIONS")
                return false;

        // A CORS preflight is always forwarded, because answering it from the
        // declaration answers without an origin policy -- and reflecting
        // whatever Origin arrives is how a credentialed endpoint is opened to
        // every site on the internet.
        if (request_has_header(conn, "origin", 6) &&
            request_has_header(conn, "access-control-request-method", 29))
            return false;

        // A plain OPTIONS asks what may be done here, which the declaration is
        // exactly, so it is answered without a backend or a round trip.
        std::string response;
        response.reserve(128);
        response += "HTTP/1.1 204 No Content\r\nAllow: ";
        response += route_table::allow_header(*route);
        // No Content-Length, because a 204 carries no content and must not
        // claim to, and closed like every response this proxy writes itself.
        response += "\r\nConnection: close\r\n\r\n";

        conn->partial.clear();
        queue_final_response(conn, std::move(response));
        return true;
    }

    if (route_table::method_allowed(*route, conn->method))
        return false;

    // Refused with the Allow header RFC 9110 Section 15.5.6 requires, which
    // costs nothing because the declaration is the list.
    const std::string allow = route_table::allow_header(*route);
    static constexpr std::string_view body = "Method Not Allowed\n";

    std::string response;
    response.reserve(128 + allow.size() + body.size());
    response += "HTTP/1.1 405 Method Not Allowed\r\nAllow: ";
    response += allow;
    response += "\r\nContent-Length: ";
    char len_buf[24];
    auto [lend, lec] = std::to_chars(len_buf, len_buf + sizeof(len_buf), body.size());
    response.append(len_buf, static_cast<size_t>(lend - len_buf));
    response += "\r\nConnection: close\r\n\r\n";
    // A response to HEAD carries the length its GET would have had and none of
    // the bytes, which is rare here and still has to be framed right.
    if (conn->method != "HEAD")
        response += body;

    // Same reason as every other self-answered path here: what is still
    // buffered must not be picked up as a fresh request while the answer is on
    // its way out.
    conn->partial.clear();
    queue_final_response(conn, std::move(response));
    return true;
}

// ─── Filter chain ───────────────────────────────────────────────────────────
// Everything below serves run_request_filters, which runs on an accepted
// request before anything has been decided about where it is going.
#ifndef SOCKETLEY_NO_LUA

// A field name a filter supplied must be a tchar and nothing else, because
// filter input is frequently derived from the request and "the script wrote
// it" is not evidence that the peer did not.
static bool filter_token_ok(std::string_view s)
{
    if (s.empty() || s.size() > 256)
        return false;
    for (char c : s)
    {
        const unsigned char u = static_cast<unsigned char>(c);
        if (u <= 0x20 || u >= 0x7F)
            return false;
        switch (c)
        {
            case '(': case ')': case ',': case '/': case ':': case ';':
            case '<': case '=': case '>': case '?': case '@': case '[':
            case '\\': case ']': case '{': case '}': case '"':
                return false;
            default: break;
        }
    }
    return true;
}

// A field value a filter supplied, where the bytes that end a line and a
// header block are what matter and obs-text is left alone as legal.
static bool filter_value_ok(std::string_view s)
{
    if (s.size() > 8192)
        return false;
    for (char c : s)
    {
        const unsigned char u = static_cast<unsigned char>(c);
        if (u == '\r' || u == '\n' || u == 0 || (u < 0x20 && u != '\t') || u == 0x7F)
            return false;
    }
    return true;
}

// Names a filter may not set: the framing pair, because that would make this
// proxy and its backend disagree about where the request ends, plus the
// hop-by-hop set and Host, which the rewrite owns.
static bool filter_request_header_forbidden(std::string_view lower)
{
    static constexpr std::string_view banned[] = {
        "content-length", "transfer-encoding", "host", "connection",
        "keep-alive", "te", "trailer", "upgrade",
        "proxy-authenticate", "proxy-authorization",
    };
    for (auto b : banned)
        if (lower == b)
            return true;
    return false;
}

// The same question for a response header, with a shorter list, because the
// proxy writes the length and the connection disposition itself.
static bool filter_response_header_forbidden(std::string_view lower)
{
    return lower == "content-length" || lower == "transfer-encoding" ||
           lower == "connection";
}

static std::string_view filter_reason(int status)
{
    switch (status)
    {
        case 200: return "OK";
        case 201: return "Created";
        case 202: return "Accepted";
        case 204: return "No Content";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 304: return "Not Modified";
        case 307: return "Temporary Redirect";
        case 308: return "Permanent Redirect";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 407: return "Proxy Authentication Required";
        case 409: return "Conflict";
        case 413: return "Content Too Large";
        case 418: return "I'm a teapot";
        case 421: return "Misdirected Request";
        case 422: return "Unprocessable Content";
        case 429: return "Too Many Requests";
        case 451: return "Unavailable For Legal Reasons";
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        case 504: return "Gateway Timeout";
        default:  return "Unknown";
    }
}

// Lowercase the name and trim the value for the table handed to a filter,
// because a table lookup is exact and HTTP field names are not.
static void filter_collect_header(sol::table& out, std::string_view line)
{
    const auto colon = line.find(':');
    if (colon == std::string_view::npos || colon == 0)
        return;   // parse_http_request_line has already refused these
    std::string name(line.substr(0, colon));
    for (auto& c : name)
        c = static_cast<char>(c | 0x20);
    const std::string_view value = http_trim_ows(line.substr(colon + 1));

    // Repeats are combined in the order sent, as RFC 9110 Section 5.2 defines,
    // because dropping the later ones would hide half a Cookie.
    sol::optional<std::string> prev = out[name].get<sol::optional<std::string>>();
    if (prev)
    {
        std::string joined = std::move(*prev);
        joined += ", ";
        joined.append(value);
        out[name] = joined;
    }
    else
        out[name] = std::string(value);
}

#endif // SOCKETLEY_NO_LUA

bool proxy_instance::run_request_filters(proxy_client_connection* conn)
{
#ifdef SOCKETLEY_NO_LUA
    (void)conn;
    return false;
#else
    auto* lctx = lua();
    if (!lctx || !lctx->has_filters())
        return false;

    sol::state& L = lctx->state();

    // The request as the client sent it, with `path` carrying this proxy's
    // prefix, because a filter judges what arrived rather than what will be
    // forwarded.
    sol::table req = L.create_table(0, 5);
    req["method"]    = conn->method;
    req["path"]      = conn->path;
    req["version"]   = conn->version;
    req["client_id"] = conn->fd;

    // The header block measured from the same terminator, with guards for the
    // day the caller's precondition stops holding, because a chain that
    // silently sees no headers is an auth filter that admits everyone.
    sol::table hdrs = L.create_table();
    const auto line_end = conn->partial.find("\r\n");
    const auto hdr_end  = conn->partial.find("\r\n\r\n");
    if (line_end != std::string::npos && hdr_end != std::string::npos && hdr_end > line_end)
    {
        std::string_view block(conn->partial.data() + line_end + 2, hdr_end - line_end - 2);
        size_t p = 0;
        while (p < block.size())
        {
            auto nl = block.find("\r\n", p);
            if (nl == std::string_view::npos)
                nl = block.size();
            filter_collect_header(hdrs, block.substr(p, nl - p));
            p = nl + 2;
        }
    }
    req["headers"] = hdrs;

    // Headers a filter asked to set or remove, cleared here rather than only
    // between requests, because a request that reaches the chain twice must
    // not accumulate.
    conn->filter_headers.clear();
    conn->filter_removed_headers.clear();

    // One budget for the whole chain rather than per filter, because a request
    // costs what its chain costs and measuring them one at a time would call
    // ten seconds fine.
    lua_deadline::scope deadline_guard("a filter in the `filters` chain",
                                       lctx->callback_timeout_ms());

    for (const auto& filter : lctx->filters())
    {
        auto result = filter(req);

        // A filter that failed did not say carry on, and the opinion it was
        // there to express is usually no, so the request is refused and the
        // operator told.
        if (SOCKETLEY_UNLIKELY(!result.valid()))
        {
            sol::error err = result;
            fprintf(stderr, "%s filter error: %s\n",
                    lua_diag::tag(get_name()).c_str(), err.what());
            conn->partial.clear();
            send_error(conn, "500 Internal Server Error", "Filter Error\n");
            return true;
        }

        // Nothing returned, or nil: this filter has no opinion, which is the
        // commonest outcome and the only one that costs nothing.
        if (result.return_count() == 0)
            continue;
        sol::object r = result.get<sol::object>();
        if (!r.valid() || r == sol::nil)
            continue;

        if (SOCKETLEY_UNLIKELY(!r.is<sol::table>()))
        {
            // Deliberately not "anything truthy carries on", because a filter
            // has two vocabularies and a third value is a script meaning
            // something this side cannot read.
            fprintf(stderr, "%s filter returned a %s; expected nil or a table\n",
                    lua_diag::tag(get_name()).c_str(),
                    lua_typename(L.lua_state(), static_cast<int>(r.get_type())));
            conn->partial.clear();
            send_error(conn, "500 Internal Server Error", "Filter Error\n");
            return true;
        }

        sol::table t = r.as<sol::table>();
        sol::optional<sol::object> status_obj = t["status"].get<sol::optional<sol::object>>();
        const bool is_answer = status_obj && *status_obj != sol::nil;

        if (!is_answer)
        {
            // Continue with the request rewritten, which is the only other
            // thing a returned table may be.
            sol::optional<sol::table> set = t["set_headers"].get<sol::optional<sol::table>>();
            sol::optional<sol::table> remove = t["remove_headers"].get<sol::optional<sol::table>>();
            if (!set && !remove)
            {
                fprintf(stderr, "%s filter returned a table with none of "
                                "`status`, `set_headers` or `remove_headers`\n",
                        lua_diag::tag(get_name()).c_str());
                conn->partial.clear();
                send_error(conn, "500 Internal Server Error", "Filter Error\n");
                return true;
            }

            // Taking a header off the request, which a filter could not do at
            // all before, under the same ban list as set_headers -- removing
            // the framing pair would be smuggling in the direction the set ban
            // does not cover.
            if (remove)
            {
                for (size_t i = 1;; ++i)
                {
                    sol::object entry = (*remove)[i];
                    if (!entry.valid() || entry == sol::nil)
                        break;
                    if (!entry.is<std::string>())
                    {
                        fprintf(stderr, "%s filter remove_headers: entry %zu is not a "
                                        "string\n",
                                lua_diag::tag(get_name()).c_str(), i);
                        continue;
                    }
                    std::string name = entry.as<std::string>();
                    for (auto& c : name)
                        c = static_cast<char>(c | 0x20);
                    if (!filter_token_ok(name))
                    {
                        fprintf(stderr, "%s filter remove_headers: `%s` is not a field "
                                        "name\n",
                                lua_diag::tag(get_name()).c_str(), name.c_str());
                        continue;
                    }
                    if (filter_request_header_forbidden(name))
                    {
                        fprintf(stderr, "%s filter remove_headers: `%s` is the proxy's "
                                        "to decide, not a filter's\n",
                                lua_diag::tag(get_name()).c_str(), name.c_str());
                        continue;
                    }
                    // A name cannot be both set and removed, so the last
                    // statement wins, or the removal takes the client's line
                    // out and the set puts the proxy's back.
                    for (auto it = conn->filter_headers.begin();
                         it != conn->filter_headers.end(); ++it)
                    {
                        if (it->first == name) { conn->filter_headers.erase(it); break; }
                    }
                    bool already = false;
                    for (const auto& have : conn->filter_removed_headers)
                        if (have == name) { already = true; break; }
                    if (!already)
                        conn->filter_removed_headers.push_back(std::move(name));
                }
            }

            if (!set)
                continue;
            set->for_each([&](sol::object key, sol::object val) {
                if (!key.is<std::string>() || !val.is<std::string>())
                {
                    fprintf(stderr, "%s filter set_headers: name and value must be strings\n",
                            lua_diag::tag(get_name()).c_str());
                    return;
                }
                std::string name = key.as<std::string>();
                std::string value = val.as<std::string>();
                for (auto& c : name)
                    c = static_cast<char>(c | 0x20);
                if (!filter_token_ok(name) || !filter_value_ok(value))
                {
                    fprintf(stderr, "%s filter set_headers: refused a header this "
                                    "proxy will not put on the wire\n",
                            lua_diag::tag(get_name()).c_str());
                    return;
                }
                if (filter_request_header_forbidden(name))
                {
                    fprintf(stderr, "%s filter set_headers: `%s` is the proxy's to "
                                    "decide, not a filter's\n",
                            lua_diag::tag(get_name()).c_str(), name.c_str());
                    return;
                }
                // The other half of the rule above: setting a name a filter
                // removed puts it back, because that is the later statement.
                for (auto it = conn->filter_removed_headers.begin();
                     it != conn->filter_removed_headers.end(); ++it)
                {
                    if (*it == name) { conn->filter_removed_headers.erase(it); break; }
                }
                // Last writer wins, so a later filter can correct an earlier one
                // instead of appending a second copy the backend has to combine.
                for (auto& [n, v] : conn->filter_headers)
                {
                    if (n == name) { v = std::move(value); return; }
                }
                conn->filter_headers.emplace_back(std::move(name), std::move(value));
            });
            continue;
        }

        // The answer, and everything from here ends the request without a
        // backend having been selected, resolved, connected to or told
        // anything.
        int status = 0;
        if (status_obj->is<int>())
            status = status_obj->as<int>();
        if (status < 200 || status > 599)
        {
            fprintf(stderr, "%s filter answer: status must be 200..599\n",
                    lua_diag::tag(get_name()).c_str());
            conn->partial.clear();
            send_error(conn, "500 Internal Server Error", "Filter Error\n");
            return true;
        }

        std::string body;
        {
            sol::optional<std::string> b = t["body"].get<sol::optional<std::string>>();
            if (b)
                body = std::move(*b);
        }

        std::string response;
        response.reserve(128 + body.size());
        response += "HTTP/1.1 ";
        char code_buf[8];
        auto [cend, cec] = std::to_chars(code_buf, code_buf + sizeof(code_buf), status);
        response.append(code_buf, static_cast<size_t>(cend - code_buf));
        response += ' ';
        response += filter_reason(status);
        response += "\r\n";

        sol::optional<sol::table> rh = t["headers"].get<sol::optional<sol::table>>();
        if (rh)
        {
            rh->for_each([&](sol::object key, sol::object val) {
                if (!key.is<std::string>() || !val.is<std::string>())
                {
                    fprintf(stderr, "%s filter answer headers: name and value must be strings\n",
                            lua_diag::tag(get_name()).c_str());
                    return;
                }
                const std::string name = key.as<std::string>();
                const std::string value = val.as<std::string>();
                std::string lower = name;
                for (auto& c : lower)
                    c = static_cast<char>(c | 0x20);
                if (!filter_token_ok(name) || !filter_value_ok(value))
                {
                    fprintf(stderr, "%s filter answer headers: refused a header this "
                                    "proxy will not put on the wire\n",
                            lua_diag::tag(get_name()).c_str());
                    return;
                }
                if (filter_response_header_forbidden(lower))
                {
                    fprintf(stderr, "%s filter answer headers: `%s` is framing, and "
                                    "this proxy writes it\n",
                            lua_diag::tag(get_name()).c_str(), lower.c_str());
                    return;
                }
                response += name;
                response += ": ";
                response += value;
                response += "\r\n";
            });
        }

        // A 204 or 304 carries no content and RFC 9112 Section 6.2 forbids the
        // header saying how much, while a HEAD response carries its GET's
        // length and no bytes.
        const bool no_content = (status == 204 || status == 304);
        const bool head = (conn->method == "HEAD");
        if (no_content)
            body.clear();
        else
        {
            response += "Content-Length: ";
            char len_buf[24];
            auto [lend, lec] = std::to_chars(len_buf, len_buf + sizeof(len_buf), body.size());
            response.append(len_buf, static_cast<size_t>(lend - len_buf));
            response += "\r\n";
            if (head)
                body.clear();
        }

        // Closed like every response this proxy writes itself, because keeping
        // the connection would mean consuming a body that may not have arrived
        // to find where this request ends.
        response += "Connection: close\r\n\r\n";
        response += body;

        // Same reason as the 400 path in drive_client_request: what is still
        // buffered must not be picked up as a fresh request while the answer is
        // on its way out.
        conn->partial.clear();
        queue_final_response(conn, std::move(response));
        return true;
    }

    return false;
#endif
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
                    {
                        cb.current = circuit_breaker::half_open;
                        cb.probe_in_flight = false;
                    }
                    else
                        return nullptr; // circuit open, no alternative
                }
                // One probe at a time here as well, because with a single
                // backend a second request into one already judged broken
                // costs a whole deadline when the fault is a stall.
                else if (SOCKETLEY_UNLIKELY(cb.current == circuit_breaker::half_open) &&
                         cb.probe_in_flight &&
                         (std::chrono::steady_clock::now() - cb.probe_started) <
                             std::chrono::seconds(m_mesh.circuit_timeout))
                    return nullptr;
            }
            conn->backend_idx = 0;
            conn->retries_remaining = m_mesh.retry_count;
            note_backend_selected(0);
            return &m_backends[0];
        }

        size_t pool_size = m_backends.size();

        if (m_strategy == strategy_lua && lua() && lua()->has_on_route())
        {
#ifndef SOCKETLEY_NO_LUA
            // A protected call, because an error inside on_route used to leave
            // as an unwind out of the accept path and end the process in the
            // Lua panic handler.
            sol::protected_function_result r =
                m_protocol == protocol_http
                    ? lua()->on_route()(conn->method, conn->path,
                                        backend_path(conn->path))
                    : lua()->on_route()();

            // A raising on_route is routed round-robin rather than refused,
            // unlike the filter chain, because on_route expresses no opinion
            // about whether a request may proceed and this path already
            // answers a callback that produced no usable index.
            if (SOCKETLEY_UNLIKELY(!r.valid()))
            {
                sol::error err = r;
                fprintf(stderr, "%s on_route error: %s\n",
                        lua_diag::tag(get_name()).c_str(), err.what());
            }
            else if (r.return_count() > 0)
            {
                sol::object result = r;
                if (result.is<int>())
                {
                    int idx = result.as<int>();
                    if (idx >= 0 && static_cast<size_t>(idx) < pool_size)
                    {
                        conn->backend_idx = static_cast<size_t>(idx);
                        conn->retries_remaining = m_mesh.retry_count;
                        note_backend_selected(static_cast<size_t>(idx));
                        return &m_backends[static_cast<size_t>(idx)];
                    }
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
                {
                    cb.current = circuit_breaker::half_open;
                    cb.probe_in_flight = false;
                }
            }

            if (m_strategy == strategy_random)
            {
                // Build the availability list in one pass into a member vector
                // reserved at setup, because a fixed 256-entry stack array was
                // written past the end by a 257th backend and nothing capped
                // the count.
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
        note_backend_selected(selected_idx);
        return &m_backends[selected_idx];
    }

    // Slow path: has group backends — build pool and resolve dynamically
    std::vector<resolved_backend> pool;
    pool.reserve(m_backends.size());

    for (const auto& b : m_backends)
    {
        if (b.is_group)
        {
            // Local and remote members both come out of the published
            // snapshot, so the manager's lock and the walk of every runtime
            // happen once per membership change rather than once per
            // connection.
            if (m_endpoints)
            {
                const std::string_view group_name(b.address.data() + 1, b.address.size() - 1);
                if (const auto* members = m_endpoints->find_group(group_name))
                {
                    for (const auto& ep : *members)
                        pool.push_back({ep.host, ep.port});
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

    // Members the breaker has taken out come off the list before anything is
    // selected, because choosing first means either using a broken member or
    // biasing the round-robin by skipping a turn.
    if (m_mesh.circuit_threshold > 0 && !m_group_breakers.empty())
    {
        pool.erase(std::remove_if(pool.begin(), pool.end(),
                                  [this](const resolved_backend& rb) {
                                      return !group_endpoint_available(rb.host, rb.port);
                                  }),
                   pool.end());
        // Every member is out, so 503 now is the honest answer: there is
        // nowhere to send this request, and the breakers expire on their own.
        if (pool.empty())
            return nullptr;
    }

    resolved_backend* selected = &pool[0];

    if (pool.size() > 1)
    {
        if (m_strategy == strategy_lua && lua() && lua()->has_on_route())
        {
#ifndef SOCKETLEY_NO_LUA
            // The group half of the same call, protected for the same reason,
            // because `--strategy lua` could take the process down through
            // either path.
            sol::protected_function_result r =
                m_protocol == protocol_http
                    ? lua()->on_route()(conn->method, conn->path,
                                        backend_path(conn->path))
                    : lua()->on_route()();

            // Report and leave `selected` at pool[0], which is what an
            // out-of-range index already gets here and this path's own
            // fallback.
            if (SOCKETLEY_UNLIKELY(!r.valid()))
            {
                sol::error err = r;
                fprintf(stderr, "%s on_route error: %s\n",
                        lua_diag::tag(get_name()).c_str(), err.what());
            }
            else if (r.return_count() > 0)
            {
                sol::object result = r;
                if (result.is<int>())
                {
                    int idx = result.as<int>();
                    if (idx >= 0 && static_cast<size_t>(idx) < pool.size())
                        selected = &pool[static_cast<size_t>(idx)];
                }
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

    // The scratch is shared and overwritten by the next selection, so the
    // chosen endpoint is also recorded on the connection, where everything
    // after the connect reads it.
    m_scratch_backend.resolved_host = std::move(selected->host);
    m_scratch_backend.resolved_port = selected->port;
    m_scratch_backend.has_cached_addr = false;
    conn->backend_from_group = true;
    conn->backend_host = m_scratch_backend.resolved_host;
    conn->backend_port = m_scratch_backend.resolved_port;
    // Claim the single half-open probe if this selection is the one that gets
    // it — the group counterpart of note_backend_selected().
    note_group_selected(conn->backend_host, conn->backend_port);
    if (inet_pton(AF_INET, m_scratch_backend.resolved_host.c_str(),
                  &m_scratch_backend.cached_addr.sin_addr) == 1)
    {
        m_scratch_backend.cached_addr.sin_family = AF_INET;
        m_scratch_backend.cached_addr.sin_port = htons(m_scratch_backend.resolved_port);
        m_scratch_backend.has_cached_addr = true;
    }
    else if (const auto it = m_group_addr.find(m_scratch_backend.resolved_host);
             it != m_group_addr.end())
    {
        // A name resolved when the membership arrived, with the port the
        // member's rather than the entry's, because one host can appear in
        // several groups on several ports.
        m_scratch_backend.cached_addr.sin_family = AF_INET;
        m_scratch_backend.cached_addr.sin_addr   = it->second;
        m_scratch_backend.cached_addr.sin_port   = htons(m_scratch_backend.resolved_port);
        m_scratch_backend.has_cached_addr = true;
    }
    else
    {
        // A member advertising a name that has not resolved yet costs this one
        // request, and the sweep is what makes it temporary -- resolving here
        // is what froze the daemon.
        m_group_unresolved = true;
        arm_idle_sweep();
    }
    return &m_scratch_backend;
}

// Stop holding a pooled entry, descriptor and session together because the
// pool owns both -- with `reset` picking a reset for a socket given up as
// broken, and no close_notify either way, since every response it carried was
// complete.
void proxy_instance::discard_pooled(pooled_backend& pb, bool reset)
{
    if (pb.ssl)
    {
        tls_context::free_ssl(pb.ssl);
        pb.ssl = nullptr;
    }
    pb.tls_owner = nullptr;
    if (pb.fd >= 0)
    {
        if (reset)
            shutdown(pb.fd, SHUT_RDWR);
        close_tracked(pb.fd);
        pb.fd = -1;
    }
}

// On a pooled TLS socket the question is asked of OpenSSL rather than the
// kernel and about application data rather than bytes, because a peer's ticket
// or KeyUpdate makes recv() positive without anything being wrong -- consuming
// rather than peeking, which is safe only because the session is pooled with
// the socket.
bool proxy_instance::probe_pooled_tls(pooled_backend& pb)
{
    if (SOCKETLEY_UNLIKELY(!pb.ssl || pb.fd < 0))
    {
        discard_pooled(pb, false);
        return false;
    }

    // Ciphertext off the socket and into the record layer, all of it, because
    // "is there application data" cannot be answered from a prefix.
    char cipher[16384];
    for (;;)
    {
        const ssize_t r = recv(pb.fd, cipher, sizeof(cipher), MSG_DONTWAIT);
        if (r > 0)
        {
            size_t off = 0;
            bool fed = true;
            while (off < static_cast<size_t>(r))
            {
                const int n = tls_context::bio_write_in(pb.ssl, cipher + off,
                                                        static_cast<int>(static_cast<size_t>(r) - off));
                if (SOCKETLEY_UNLIKELY(n <= 0))
                {
                    // The buffer cap, or a BIO that failed, fatal by contract
                    // because there is nowhere to put what was not taken.
                    fed = false;
                    break;
                }
                off += static_cast<size_t>(n);
            }
            if (SOCKETLEY_UNLIKELY(!fed))
            {
                discard_pooled(pb, true);
                return false;
            }
            continue;
        }
        if (r == 0)
        {
            // A FIN while the socket sat idle, so there is nothing left to
            // reuse -- the same verdict the cleartext probe gives.
            discard_pooled(pb, false);
            return false;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            break;                       // the socket is drained
        if (errno == EINTR)
            continue;
        // RST, or a descriptor that has gone wrong underneath us.
        discard_pooled(pb, false);
        return false;
    }

    // One call is enough, because SSL_read processes every whole record it has
    // before deciding it has no application data.
    char plain[16384];
    const int n = tls_context::ssl_read(pb.ssl, plain, sizeof(plain));
    if (SOCKETLEY_UNLIKELY(n > 0))
    {
        // Once per instance, as on the cleartext side, and worded so the two
        // are not confused: this backend did not merely write on an idle
        // socket, it wrote *application data* on one, which is the finding.
        if (!m_pool_tls_unbidden_warned)
        {
            m_pool_tls_unbidden_warned = true;
            LOG_WARN("proxy: a pooled TLS backend socket had application data waiting on it "
                     "— the backend sent a response nobody asked for, or an answer this "
                     "proxy judged finished was not.  The connection is dropped rather than "
                     "reused; reusing it would give that data to the next client.  (Session "
                     "tickets and key updates are not this: they are consumed and the "
                     "connection is kept.)");
        }
        discard_pooled(pb, true);
        return false;
    }
    if (SOCKETLEY_UNLIKELY(n < 0))
    {
        // close_notify, or a record the session cannot use, and either way
        // this one is finished.
        discard_pooled(pb, false);
        return false;
    }

    return true;
}

// The index picks the shelf and the endpoint picks the socket, which for a TLS
// connection also fixes the SNI name, the name verified and the peer --
// because start_backend_tls derives all three from the same endpoint this
// compares.
int proxy_instance::acquire_pooled_backend(size_t backend_idx, std::string_view host,
                                           uint16_t port, bool want_tls, SSL** out_ssl)
{
    if (out_ssl)
        *out_ssl = nullptr;
    if (backend_idx >= m_backend_pool.size() || !pool_key_ok(host, port))
        return -1;
    // A TLS request with no context to have built the session against cannot
    // be matched to anything, which is unreachable and is the backstop for the
    // day it is not.
    if (want_tls && !m_backend_tls)
        return -1;

    auto& pool = m_backend_pool[backend_idx];
    if (pool.empty())
        return -1;

    auto now = std::chrono::steady_clock::now();

    // Try from the back, where the most recently idle entry has the best
    // chance of being alive, stepping over entries for other endpoints rather
    // than dropping them.
    for (size_t scan = pool.size(); scan-- > 0; )
    {
        if (pool[scan].port != port || pool[scan].host != host)
            continue;
        // Encryption is part of the key rather than a preference, and a
        // mismatch is stepped over because the entry is perfectly good for
        // somebody else.
        if ((pool[scan].ssl != nullptr) != want_tls)
            continue;
        // An entry built against a context this instance has replaced was
        // verified against a different trust store, so it is dropped rather
        // than stepped over: nobody is coming for it.
        if (want_tls && pool[scan].tls_owner != m_backend_tls.get())
        {
            discard_pooled(pool[scan], true);
            pool.erase(pool.begin() + static_cast<std::ptrdiff_t>(scan));
            continue;
        }

        auto pb = std::move(pool[scan]);
        pool.erase(pool.begin() + static_cast<std::ptrdiff_t>(scan));

        // Check if stale
        if ((now - pb.idle_since) > std::chrono::seconds(POOL_IDLE_TIMEOUT_SEC))
        {
            discard_pooled(pb, true);
            continue;
        }

        // Every socket is probed however recently it went idle, because a
        // backend with a short keep-alive timeout closes by design --
        // measured, every second request was written into a socket that was
        // already gone.

        // A readable pooled socket is a byte nobody asked for, which means the
        // stream is at an offset no request can start from, so it is destroyed
        // here rather than re-shelved -- with shutdown() first, so the unread
        // bytes leave with a reset.
        if (pb.ssl != nullptr)
        {
            if (!probe_pooled_tls(pb))
                continue;
            if (out_ssl)
                *out_ssl = pb.ssl;
            // The caller owns the session from here; the entry is already off
            // the shelf, and nothing else may free it.
            pb.ssl = nullptr;
            return pb.fd;
        }

        char probe;
        ssize_t r = recv(pb.fd, &probe, 1, MSG_PEEK | MSG_DONTWAIT);
        if (SOCKETLEY_UNLIKELY(r > 0))
        {
            // Once per instance, because a backend that does this does it on
            // every socket it has, and a client receiving somebody else's
            // answer is what the silent version cost.
            if (!m_pool_unbidden_warned)
            {
                m_pool_unbidden_warned = true;
                LOG_WARN("proxy: a pooled backend socket had unread data on it — the backend "
                         "sent bytes nobody asked for, or an answer this proxy judged "
                         "finished was not.  The connection is dropped rather than reused; "
                         "reusing it would give those bytes to the next client.");
            }
            discard_pooled(pb, true);
            continue;
        }
        if (r == 0 || (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK))
        {
            // Dead connection
            discard_pooled(pb, false);
            continue;
        }
        return pb.fd;
    }

    return -1;
}

// The idle sweep reclaims pooled backend sockets, so it runs for every proxy
// that pools rather than only one configured with a client idle timeout, armed
// on demand and stopping itself once the pools are empty.
void proxy_instance::arm_idle_sweep()
{
    if (m_idle_sweep_armed || !m_loop || !m_idle_sweep_timer)
        return;

    m_idle_sweep_armed = true;
    if (SOCKETLEY_UNLIKELY(!m_loop->submit_timeout(&m_idle_sweep_timer->ts,
                                                   &m_idle_sweep_timer->req)))
    {
        m_idle_sweep_armed = false;
        // Once per run, because release_to_pool() calls this on a hot path and
        // a full ring stays full for a while.
        if (!m_idle_sweep_warned)
        {
            m_idle_sweep_warned = true;
            LOG_ERROR("proxy: idle sweep timer refused — idle connections and pooled "
                      "backend sockets will not be reclaimed");
        }
    }
}

// Every path that pools a backend fd comes through here, which is where it is
// decided whether the socket may change hands -- with the session moved out of
// the connection on the one path that files an entry, so there is one owner at
// every instant.
void proxy_instance::release_to_pool(int backend_fd, size_t backend_idx,
                                     std::string_view host, uint16_t port,
                                     proxy_backend_connection* bconn)
{
    if (backend_fd < 0 || backend_idx >= m_backend_pool.size())
        return;

    // A socket with no endpoint on it cannot be given back to one, so this
    // backstop closes rather than files.
    if (!pool_key_ok(host, port))
    {
        shutdown(backend_fd, SHUT_RDWR);
        close_tracked(backend_fd);
        return;
    }

    // Pooling has the same hazard as closing even though the number never goes
    // back to the kernel, and the callers' own flags cannot answer it -- the
    // loop counts the number itself, including the peer's outbound splice.
    if (m_loop && m_loop->fd_inflight(backend_fd) > 0)
    {
        shutdown(backend_fd, SHUT_RDWR);
        close_tracked(backend_fd);
        return;
    }

    auto& pool = m_backend_pool[backend_idx];
    if (pool.size() >= MAX_POOL_PER_BACKEND)
    {
        // Pool full — close the oldest (swap with last, then pop)
        discard_pooled(pool.front(), true);
        pool.front() = std::move(pool.back());
        pool.pop_back();
    }

    // The session moves here, backend_pool_eligible() having already
    // established it may be reused, so this is the transfer and not the
    // decision.
    SSL* ssl = nullptr;
    if (bconn && bconn->ssl)
    {
        ssl = bconn->ssl;
        bconn->ssl = nullptr;
        bconn->tls_state = tls_conn_none;
        bconn->tls_peer_closed = false;
    }

    pool.push_back({backend_fd, backend_idx, std::string(host), port,
                    std::chrono::steady_clock::now(), ssl,
                    ssl ? m_backend_tls.get() : nullptr});

    // Something is in the pool now, so there is something for the sweep to
    // reclaim; a no-op while it is already running.
    arm_idle_sweep();
}

// Whether this connection's backend leg is encrypted, which backend_idx cannot
// answer for a group -- and does not need to, since the backend-TLS options
// apply to every backend at once.
bool proxy_instance::conn_backend_tls(const proxy_client_connection* conn) const
{
    if (SOCKETLEY_LIKELY(!m_backend_tls))
        return false;
    if (m_backend_tls_all)
        return true;
    return !conn->backend_from_group && conn->backend_idx < m_backends.size() &&
           m_backends[conn->backend_idx].tls;
}

// Give a backend connection its session and put the ClientHello on the wire,
// pinned to the endpoint this request was routed to and never to a name read
// back from the certificate, so this can only fail closed.
bool proxy_instance::start_backend_tls(proxy_client_connection* cconn,
                                       proxy_backend_connection* bconn)
{
    if (SOCKETLEY_UNLIKELY(!m_backend_tls))
        return false;

    std::string_view host;
    uint16_t port = 0;
    if (SOCKETLEY_UNLIKELY(!backend_endpoint_of(cconn, m_backends, host, port)))
    {
        LOG_ERROR("proxy: TLS backend connection refused -- the endpoint this request "
                  "was routed to is not known, so there is no name to verify against");
        return false;
    }

    bconn->ssl = m_backend_tls->create_ssl_client(host);
    if (SOCKETLEY_UNLIKELY(!bconn->ssl))
        return false;
    bconn->tls_state = tls_conn_handshake;

    // One turn of the handshake, which produces the ClientHello, where a
    // negative is a local failure rather than a rejection because nothing is
    // on the wire yet.
    if (SOCKETLEY_UNLIKELY(tls_context::do_handshake(bconn->ssl) < 0))
        return false;
    return tls_flush(bconn);
}

// Which end a failed connect belongs to, read off errno, in one function
// because the synchronous connect reports through errno and the asynchronous
// one through SO_ERROR -- and the same shortage arriving the second way used
// to be read as the backend refusing.
static inline bool connect_errno_is_ours(int err)
{
    switch (err)
    {
    case EADDRNOTAVAIL:
    case EADDRINUSE:
    case ENOBUFS:
    case ENOMEM:
    case EMFILE:
    case ENFILE:
        return true;
    default:
        return false;
    }
}

bool proxy_instance::connect_to_backend(proxy_client_connection* conn, const backend_info* target,
                                       bool* resource_failure)
{
    // Local helper: mark this as our own shortage rather than the backend's fault.
    const auto ours = [resource_failure]() { if (resource_failure) *resource_failure = true; };
    // A backend with no port has nowhere to go, unless it is a unix one, where
    // the path is the whole address.
    if (SOCKETLEY_UNLIKELY(!target || (target->resolved_port == 0 && !target->is_unix)))
        return false;

    // The wait starts here rather than at the first byte sent, so the
    // handshake and the queueing are inside it, armed in the one place every
    // route to a backend passes through.
    if (m_protocol == protocol_http)
        arm_response_deadline(conn);

    int bfd = -1;
    const bool backend_tls = conn_backend_tls(conn);

    // The pool is asked for an idle socket to this endpoint, which the group
    // path can answer as precisely as any other -- and for a TLS backend too,
    // since what is passed is the same endpoint start_backend_tls built the
    // session from.
    SSL* pooled_ssl = nullptr;
    {
        std::string_view host;
        uint16_t port = 0;
        if (backend_endpoint_of(conn, m_backends, host, port) &&
            conn->backend_idx < m_backend_pool.size())
        {
            bfd = acquire_pooled_backend(conn->backend_idx, host, port, backend_tls,
                                         &pooled_ssl);
        }
    }

    if (bfd >= 0)
    {
        // Got pooled connection — set up immediately (no async connect)
        if (SOCKETLEY_UNLIKELY(bfd >= MAX_FDS))
        {
            // A descriptor past this runtime's slot table is our shortage
            // rather than a backend refusing, and the session goes with the
            // descriptor, as everywhere.
            tls_context::free_ssl(pooled_ssl);
            pooled_ssl = nullptr;
            close_tracked(bfd);
            ours();
            return false;
        }

        conn->backend_fd = bfd;

        auto bconn = backend_pool_acquire(bfd);
        // The session before anything else looks at the struct, as an
        // assignment rather than an overwrite -- and tls_conn_ready rather
        // than handshake, because this connection finished its handshake
        // before it was pooled and tls_flush would otherwise hold the request
        // back.
        if (pooled_ssl)
        {
            bconn->ssl = pooled_ssl;
            bconn->tls_state = tls_conn_ready;
            pooled_ssl = nullptr;
        }
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
        if (m_protocol == protocol_tcp && m_splice_enabled &&
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
            // Give up the backend only, because every caller keeps working
            // with conn after a false return -- and the client's half of the
            // splice pipeline goes with it, or the next attempt overwrites two
            // live descriptors.
            if (ptr->pipe_to_client[0] >= 0) close_tracked(ptr->pipe_to_client[0]);
            if (ptr->pipe_to_client[1] >= 0) close_tracked(ptr->pipe_to_client[1]);
            ptr->pipe_to_client[0] = -1;
            ptr->pipe_to_client[1] = -1;
            if (conn->pipe_to_backend[0] >= 0) close_tracked(conn->pipe_to_backend[0]);
            if (conn->pipe_to_backend[1] >= 0) close_tracked(conn->pipe_to_backend[1]);
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

    // No pooled connection — take the address and submit async connect
    struct sockaddr_storage addr{};
    socklen_t addr_len = 0;
    if (!backend_connect_addr(*target, addr, addr_len))
    {
        // The request path does not resolve, because a per-request getaddrinfo
        // on the event-loop thread froze the whole daemon for the resolver's
        // timeout -- so recovery is bounded by the sweep interval instead,
        // which is the right way round for a proxy.
        const_cast<proxy_instance*>(this)->arm_idle_sweep();
        return false;
    }

    bfd = socket(addr.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (bfd < 0)
    {
        // Out of descriptors is our shortage, not the backend's.
        ours();
        return false;
    }

    if (SOCKETLEY_UNLIKELY(bfd >= MAX_FDS))
    {
        // The same shortage as the pooled branch, reached with a socket this
        // function opened: a number past MAX_FDS is this process holding too
        // many descriptors.
        close_tracked(bfd);
        ours();
        return false;
    }

    // Everything tune_socket sets is TCP-level, so on another family it would
    // be four failing setsockopts per connect spent on nothing.
    if (addr.ss_family == AF_INET)
        tune_socket(bfd);

    // Try a synchronous connect first, which on loopback often succeeds
    // instantly, falling back to the async io_uring connect on EINPROGRESS.
    int cr = ::connect(bfd, reinterpret_cast<const struct sockaddr*>(&addr), addr_len);
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
        if (m_protocol == protocol_tcp && m_splice_enabled &&
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
                    // And the same for a half-close taken during the connect.
                    forward_client_half_close(conn);
                    return true;  // connect_pending stays false, splice handles data flow
                }
            }
        }

        // Submit read on backend
        if (SOCKETLEY_UNLIKELY(!submit_read_op_backend(m_loop, bfd, ptr, m_recv_multishot,
                                                       m_use_provided_bufs, BUF_GROUP_ID)))
        {
            // Give up the backend only, because every caller keeps working
            // with conn after a false return -- and the client's half of the
            // splice pipeline goes with it, or the next attempt overwrites two
            // live descriptors.
            if (ptr->pipe_to_client[0] >= 0) close_tracked(ptr->pipe_to_client[0]);
            if (ptr->pipe_to_client[1] >= 0) close_tracked(ptr->pipe_to_client[1]);
            ptr->pipe_to_client[0] = -1;
            ptr->pipe_to_client[1] = -1;
            if (conn->pipe_to_backend[0] >= 0) close_tracked(conn->pipe_to_backend[0]);
            if (conn->pipe_to_backend[1] >= 0) close_tracked(conn->pipe_to_backend[1]);
            conn->pipe_to_backend[0] = -1;
            conn->pipe_to_backend[1] = -1;
            conn->splice_active = false;
            conn->backend_fd = -1;
            close_pair_close_backend(bfd, ptr, conn);
            ours();
            return false;
        }

        // The session goes on after the read is armed and before anything is
        // forwarded, and failing here is our own shortage rather than the
        // backend's answer.
        if (SOCKETLEY_UNLIKELY(backend_tls && !start_backend_tls(conn, ptr)))
        {
            conn->backend_fd = -1;
            close_pair_close_backend(bfd, ptr, conn);
            ours();
            return false;
        }

        return true;  // connect_pending stays false — caller forwards saved_request
    }

    if (cr < 0 && errno != EINPROGRESS)
    {
        // Which end failed decides whether the breaker hears about it, because
        // a gateway charging its own port exhaustion to every member opened
        // all three breakers and answered 503 for a full circuit_timeout.
        if (connect_errno_is_ours(errno))
            ours();
        close_tracked(bfd);
        return false;
    }

    // EINPROGRESS is waited on with a poll rather than a second connect, which
    // io_uring answers EISCONN and then drops -- and connect_addr is gone,
    // because the kernel has already taken the address and a poll names none.
    conn->connect_pending = true;
    conn->connect_fd = bfd;
    conn->connect_req = { this, nullptr, conn->fd, 0, op_poll, conn->generation };

    if (SOCKETLEY_UNLIKELY(!m_loop->submit_poll_add(bfd, POLLOUT, &conn->connect_req)))
    {
        close_tracked(bfd);
        conn->connect_fd = -1;
        conn->connect_pending = false;
        ours();
        return false;
    }

    // Watch the client for death while the handshake lasts, because nothing
    // else is armed on that socket and a client looping connect/write/reset
    // put 14,000 corpses and a gigabyte in the proxy -- and a failure to arm
    // is not unwound.
    if (!conn->abort_watch_pending)
    {
        conn->abort_req = { this, nullptr, conn->fd, 0, op_poll_abort, conn->generation };
        if (SOCKETLEY_LIKELY(m_loop->submit_poll_add(conn->fd, POLLERR | POLLHUP,
                                                     &conn->abort_req)))
            conn->abort_watch_pending = true;
    }

    return true;  // connect_pending = true — caller must check
}

void proxy_instance::setup_splice_pipes(proxy_client_connection* conn, proxy_backend_connection* bconn)
{
    // Never on a connection with a TLS session on either leg, because a splice
    // moves bytes the record layer never sees -- guarded here rather than at
    // the three call sites, since leaving splice_active false is all it takes.
    if (SOCKETLEY_UNLIKELY(conn->ssl != nullptr || bconn->ssl != nullptr))
        return;

    // O_CLOEXEC on both pipe pairs, because a worker forked mid-transfer would
    // inherit four descriptors per connection in flight and hold them until it
    // exits.
    if (pipe2(conn->pipe_to_backend, O_NONBLOCK | O_CLOEXEC) < 0)
        return;

    // Create pipe for backend -> client direction
    if (pipe2(bconn->pipe_to_client, O_NONBLOCK | O_CLOEXEC) < 0)
    {
        close_tracked(conn->pipe_to_backend[0]);
        close_tracked(conn->pipe_to_backend[1]);
        conn->pipe_to_backend[0] = -1;
        conn->pipe_to_backend[1] = -1;
        return;
    }

    // Increase pipe buffer sizes for throughput
    if (fcntl(conn->pipe_to_backend[0], F_SETPIPE_SZ, SPLICE_PIPE_SIZE) < 0) {}
    if (fcntl(bconn->pipe_to_client[0], F_SETPIPE_SZ, SPLICE_PIPE_SIZE) < 0) {}

    conn->splice_active = true;
    bconn->splice_active = true;
#ifdef SOCKETLEY_TRACE
    conn->tr.splice_cqe_ms  = ::skl_trace::now_ms();
    bconn->tr.splice_cqe_ms = ::skl_trace::now_ms();
#endif
}

// The socket half is a poll and not the splice, because io_uring runs every
// splice on an io-wq worker that then sits inside tcp_splice_read holding the
// pipe's mutex -- measured, four silent connections cost a core and
// forty-eight cost two and fifty threads.
bool proxy_instance::arm_splice_in_poll(int src_fd, io_request* req)
{
    if (!m_loop || src_fd < 0)
        return false;
    req->type = op_splice_poll;
    return m_loop->submit_poll_add(src_fd, POLLIN, req);
}

void proxy_instance::start_splice_forwarding(proxy_client_connection* conn, proxy_backend_connection* bconn)
{
    if (!m_loop || !conn->splice_active || !bconn->splice_active)
        return;

    // Not while a userspace read is in flight, because two independent writers
    // put later data ahead of earlier -- and never once the client has
    // reported end of stream, stated here because all four call sites can
    // reach it with client_eof set.
    if (!conn->splice_in_pending && !conn->read_pending && !conn->client_eof)
    {
        conn->splice_in_pending = true;
        if (SOCKETLEY_UNLIKELY(!arm_splice_in_poll(conn->fd, &conn->splice_in_req)))
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
        if (SOCKETLEY_UNLIKELY(!arm_splice_in_poll(bconn->fd, &bconn->splice_in_req)))
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
#ifdef SOCKETLEY_TRACE
    if (entry.side == conn_client)  entry.client->tr.splice_cqe_ms  = ::skl_trace::now_ms();
    if (entry.side == conn_backend) entry.backend->tr.splice_cqe_ms = ::skl_trace::now_ms();
#endif

    // The readiness half of the inbound leg reporting, where a failure is
    // treated exactly as a failed splice was: the pair goes.
    if (req->type == op_splice_poll)
    {
        if (entry.side == conn_client)
        {
            auto* conn = entry.client;
            if (SOCKETLEY_UNLIKELY(req != &conn->splice_in_req))
                return;
            conn->splice_in_req.type = op_splice;
            if (SOCKETLEY_UNLIKELY(cqe->res < 0 || conn->closing ||
                                   conn->pipe_to_backend[1] < 0 ||
                                   !m_loop->submit_splice(conn->fd, conn->pipe_to_backend[1],
                                                          PROXY_READ_BUF_SIZE,
                                                          &conn->splice_in_req)))
            {
                conn->splice_in_pending = false;
                close_pair(conn->fd, conn->backend_fd);
            }
        }
        else if (entry.side == conn_backend)
        {
            auto* conn = entry.backend;
            if (SOCKETLEY_UNLIKELY(req != &conn->splice_in_req))
                return;
            conn->splice_in_req.type = op_splice;
            if (SOCKETLEY_UNLIKELY(cqe->res < 0 || conn->closing ||
                                   conn->pipe_to_client[1] < 0 ||
                                   !m_loop->submit_splice(conn->fd, conn->pipe_to_client[1],
                                                          PROXY_READ_BUF_SIZE,
                                                          &conn->splice_in_req)))
            {
                conn->splice_in_pending = false;
                close_pair(conn->client_fd, conn->fd);
            }
        }
        return;
    }

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
                    // Back through the readiness poll rather than straight
                    // into the ring, because a splice resubmitted on a socket
                    // that answered EAGAIN answers EAGAIN again.
                    conn->splice_in_pending = true;
                    if (SOCKETLEY_UNLIKELY(!arm_splice_in_poll(conn->fd, &conn->splice_in_req)))
                    {
                        conn->splice_in_pending = false;
                        close_pair(conn->fd, conn->backend_fd);
                        return;
                    }
                    return;
                }

                // res == 0 on this leg is the client's half-close rather than
                // a failure, held rather than closed, with nothing re-armed
                // because the backend's own leg keeps the pair reachable.
                if (cqe->res == 0 && !conn->closing && hold_tcp_half_close(conn))
                    return;

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
                // No backend to deliver to, and falling through was fatal:
                // nothing new was armed, so no completion was owed and the
                // connection was never torn down at all.
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

            // The pipe is empty and this leg is idle, which is the moment the
            // held half-close may go out without overtaking anything the
            // client sent.
            if (SOCKETLEY_UNLIKELY(conn->client_eof))
            {
                forward_client_half_close(conn);

                // Deliberately not re-armed, because a splice on a socket at
                // end of stream answers res=0 for ever, so the pair now rests
                // entirely on the peer and that is asked again here.
                const int hbfd = conn->backend_fd;
                bool reachable = client_op_in_flight(conn);
                if (!conn->closing && !reachable && hbfd >= 0 && hbfd < MAX_FDS &&
                    m_conn_idx[hbfd].side == conn_backend)
                {
                    auto* hb = m_conn_idx[hbfd].backend;
                    reachable = backend_op_in_flight(hb) || !hb->write_queue.empty();
                }
                if (reachable)
                    return;
                close_pair(conn->fd, conn->backend_fd);
                return;
            }

            // Re-arm the inbound leg through readiness, because the connection
            // is quiet again and that is exactly the state a splice must not
            // be left parked in.
            if (SOCKETLEY_LIKELY(!conn->closing))
            {
                conn->splice_in_pending = true;
                if (SOCKETLEY_UNLIKELY(!arm_splice_in_poll(conn->fd, &conn->splice_in_req)))
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
                    // The same loop as on the client leg, and this is the one
                    // that actually ran: a backend socket is opened
                    // SOCK_NONBLOCK for the async connect, so tcp_splice_read
                    // answers EAGAIN the instant the backend has nothing to say
                    // — which, between requests, is all the time.
                    conn->splice_in_pending = true;
                    if (SOCKETLEY_UNLIKELY(!arm_splice_in_poll(conn->fd, &conn->splice_in_req)))
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

            // Splice out to the client, and only into one that still names us
            // as its backend, because a descriptor alone does not prove
            // identity once numbers are reused.
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
                // The same hole in this direction, which the churn measurement
                // hit: thousands of backends outliving an aborted client, each
                // unreachable for the runtime's life.
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

            // A splice can move fewer bytes than the pipe holds, and what
            // stays there is in no socket buffer and no write queue, so the
            // pipe is drained first.
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

            // Re-arm the inbound leg (backend -> pipe), on readiness for the
            // reason given above: the exchange is over and this socket is quiet
            // until the next request comes down the other side.
            if (SOCKETLEY_LIKELY(!conn->closing))
            {
                conn->splice_in_pending = true;
                if (SOCKETLEY_UNLIKELY(!arm_splice_in_poll(conn->fd, &conn->splice_in_req)))
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
    // What is decided here is whether there is a session worth reusing at all,
    // the identity questions having moved to acquire_pooled_backend and
    // pooled_backend, and the record layer being answered by pooling the
    // session with the descriptor.
    if (bconn->ssl != nullptr)
    {
        // A handshake that has not finished has negotiated nothing, so the
        // next borrower's request would wait on a peer that may never answer.
        if (bconn->tls_state != tls_conn_ready)
            return false;
        // close_notify, or a record the session could not use, so a request
        // written into it goes into a stream the peer has stopped reading.
        if (bconn->tls_peer_closed)
            return false;
        // The record layer still owes the wire an alert, which pooling would
        // strand in a BIO nobody drains -- the write-queue test below does not
        // cover it, because a record layer's own traffic is queued nowhere.
        if (tls_context::has_pending_out(bconn->ssl))
            return false;
    }
    if (bconn->closing || bconn->splice_active)
        return false;
    if (!bconn->write_queue.empty() || bconn->write_batch_count > 0)
        return false;
    if (bconn->pipe_to_client[0] >= 0)
        return false;
    // Don't pool if backend signalled Connection: close
    if (bconn->http_frame.conn_close)
        return false;
    // Where this response ended could not be established, and reuse needs both
    // ends to agree the stream is at a message boundary -- asked here, because
    // every path that pools comes through.
    if (bconn->http_frame.unknown)
        return false;
    // A response that has not finished leaves the socket at an offset just as
    // surely, which the armed read normally hides -- and this is also where a
    // tunnel is refused, asked through http_response_pool_safe() because
    // finished is about the message and poolable is about the stream position.
    if (!http_response_pool_safe(bconn->http_frame))
        return false;
    if (!cconn)
        return false;
    // The key is read off the client, so the client has to be this socket's
    // own -- cheap, and it makes the key's provenance a checked fact rather
    // than a caller's promise.
    if (bconn->client_fd != cconn->fd)
        return false;
    // A group-routed connection is poolable under the member it actually
    // reached, and refusing here made an @group gateway open a fresh
    // connection for every request.
    std::string_view host;
    uint16_t port = 0;
    if (!backend_endpoint_of(cconn, backends, host, port))
        return false;
    return true;
}

// Helper: close or pool a backend fd (no pending ops case)
inline void proxy_instance::close_pair_close_backend(int backend_fd,
                                                      proxy_backend_connection* bconn,
                                                      proxy_client_connection* cconn)
{
    // The endpoint comes out of the same predicate that approved the socket,
    // so the two cannot disagree about which peer it is filed under.
    std::string_view host;
    uint16_t port = 0;
    bool can_pool = cconn && backend_pool_eligible(bconn, cconn, m_backends, m_protocol) &&
                    backend_endpoint_of(cconn, m_backends, host, port);

    m_conn_idx[backend_fd] = {};

    if (can_pool)
    {
        // Release fd to pool — pool takes ownership of the descriptor and, on
        // a TLS leg, of the session with it; don't close either.
        release_to_pool(backend_fd, cconn->backend_idx, host, port, bconn);
    }
    else
    {
        shutdown(backend_fd, SHUT_RDWR);
        close_tracked(backend_fd);
    }

    if (m_backend_slots[backend_fd])
    {
        // The owners are backend_pool_release()'s business, and clearing them
        // from out here took away the only way a late completion could be
        // recognised.
        backend_pool_release(std::move(m_backend_slots[backend_fd]));
        m_backend_count--;
    }
}

void proxy_instance::close_pair(int client_fd, int backend_fd, close_reason reason)
{
    // This checks rather than decides, because close_pair cannot tell a polite
    // half-close from a connection torn out from under its client -- so the
    // hold stays where the knowledge is and the invariant fires at 86 call
    // sites the fuzzer can catch; HTTP only, because response_started is never
    // set on a TCP proxy and a byte relay cannot say an answer is no longer
    // owed.
    if (reason == close_reason::normal &&
        m_protocol == protocol_http &&
        client_fd >= 0 && client_fd < MAX_FDS &&
        m_conn_idx[client_fd].side == conn_client)
    {
        proxy_client_connection* c = m_conn_idx[client_fd].client;
        const proxy_backend_connection* b = nullptr;
        if (backend_fd >= 0 && backend_fd < MAX_FDS &&
            m_conn_idx[backend_fd].side == conn_backend)
            b = m_conn_idx[backend_fd].backend;

        if (!c->closing && !conn_tunnelled(c) && client_answer_owed(c, b))
            SKL_INV_FAIL("answer-owed-close", "proxy::close_pair");
    }

    // Find client conn for pool-eligibility checks
    proxy_client_connection* client_for_pool = nullptr;
    if (client_fd >= 0 && client_fd < MAX_FDS && m_conn_idx[client_fd].side == conn_client)
        client_for_pool = m_conn_idx[client_fd].client;

    // A splice the backend started towards the client's descriptor is as good
    // a reason to hold it as one of the client's own, which is where an
    // aborting client's payload landed in a stranger's socket -- kept although
    // close_fd now holds every number on this rule, because it also holds the
    // struct the splice request lives in.
    bool peer_splicing_into_client = false;
    if (client_for_pool)
    {
        for (int cand : { backend_fd, client_for_pool->backend_fd })
        {
            if (cand < 0 || cand >= MAX_FDS) continue;
            const auto& bslot = m_conn_idx[cand];
            if (bslot.side == conn_backend && bslot.backend->client_fd == client_fd &&
                bslot.backend->splice_out_pending)
                peer_splicing_into_client = true;
        }
    }

    if (backend_fd >= 0 && backend_fd < MAX_FDS)
    {
        auto& be = m_conn_idx[backend_fd];
        if (be.side == conn_backend)
        {
            auto* bconn = be.backend;
            // Deferring is only right while something is in flight, so a flush
            // that cannot reach the ring falls through -- and zc_notif_pending
            // belongs in the list, because a zero-copy send clears
            // write_pending on the first of its two answers.
            bool defer = bconn->read_pending || bconn->write_pending ||
                         bconn->zc_notif_pending ||
                         bconn->splice_in_pending || bconn->splice_out_pending ||
                         !bconn->write_queue.empty() ||
                         // The record layer's own bytes: the alert that says
                         // why a handshake failed is the only diagnosis the
                         // other end will ever get, and it is queued nowhere.
                         tls_owes_output(bconn) ||
                         // The other direction of the same rule as below: the
                         // client's outbound splice writes into *this*
                         // descriptor, so closing it while that operation is
                         // outstanding hands the number away with the write
                         // still to come.
                         (client_for_pool && client_for_pool->splice_out_pending &&
                          client_for_pool->backend_fd == backend_fd);
            if (defer)
            {
                // A queue that still holds data is as good a reason to defer
                // as an operation in flight, because closing throws away bytes
                // the client considers delivered.
                bconn->closing = true;
                // This one earns its keep, because a backend socket is
                // ESTABLISHED at teardown and 7054 of 7054 shutdowns succeeded
                // -- which is why the resulting res == 0 must not be charged
                // to the breaker.
                if (!bconn->write_pending &&
                    (!bconn->write_queue.empty() || tls_owes_output(bconn)) &&
                    !flush_backend_write_queue(bconn))
                    defer = false;
                else
                    shutdown(backend_fd, SHUT_RD);

                // A flush that reported success is not a completion on its
                // way, because tls_flush holds application data back on an
                // unfinished handshake -- so the test is what the invariant
                // tests rather than what the flush returned.
                if (defer && !backend_op_in_flight(bconn))
                    defer = false;
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
                if (bconn->pipe_to_client[0] >= 0) close_tracked(bconn->pipe_to_client[0]);
                if (bconn->pipe_to_client[1] >= 0) close_tracked(bconn->pipe_to_client[1]);
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
                                  !bconn2->write_queue.empty() || tls_owes_output(bconn2);
                    if (defer2)
                    {
                        bconn2->closing = true;
                        // Same as the backend block above and on the same
                        // reasoning, not separately measured because the proxy
                        // group never reached this arm.
                        if (!bconn2->write_pending &&
                            (!bconn2->write_queue.empty() || tls_owes_output(bconn2)) &&
                            !flush_backend_write_queue(bconn2))
                            defer2 = false;
                        else
                            shutdown(conn->backend_fd, SHUT_RD);

                        // Same rule as the block above: a deferral is only
                        // honest while a completion is actually owed.
                        if (defer2 && !backend_op_in_flight(bconn2))
                            defer2 = false;
                    }
                    if (!defer2)
                    {
                        // Close splice pipes
                        if (bconn2->pipe_to_client[0] >= 0) close_tracked(bconn2->pipe_to_client[0]);
                        if (bconn2->pipe_to_client[1] >= 0) close_tracked(bconn2->pipe_to_client[1]);
                        bconn2->pipe_to_client[0] = -1;
                        bconn2->pipe_to_client[1] = -1;

                        close_pair_close_backend(conn->backend_fd, bconn2, conn);
                    }
                }
                conn->backend_fd = -1;
            }

            // Close the pending connect fd through close_fd, which cancels the
            // POLLOUT that the close does not take back, with connect_pending
            // left set to tell client_pool_release the struct cannot be
            // reused.
            close_tracked(conn->connect_fd);
            conn->connect_fd = -1;

            // The abort watch is withdrawn by request rather than by
            // descriptor, because a read or a splice may be armed on the same
            // socket and the deferral is counting on it.
            if (conn->abort_watch_pending && m_loop)
                m_loop->submit_poll_remove(&conn->abort_req);

            // Zero-copy notification included, with peer_splicing_into_client
            // the descriptor the backend is still writing into.
            bool defer_c = conn->read_pending || conn->write_pending ||
                           conn->zc_notif_pending ||
                           conn->splice_in_pending || conn->splice_out_pending ||
                           !conn->write_queue.empty() || tls_owes_output(conn) ||
                           peer_splicing_into_client;
            if (defer_c)
            {
                conn->closing = true;
                // Expected to fail on the abort path, where the armed read
                // takes the socket error instead, and kept for the 359
                // teardowns the proxy starts against a live client -- do not
                // read a failure here as a fault.
                if (!conn->write_pending &&
                    (!conn->write_queue.empty() || tls_owes_output(conn)) &&
                    !flush_client_write_queue(conn))
                    defer_c = false;
                else
                    shutdown(client_fd, SHUT_RD);

                // Same rule as the two backend blocks above, with the peer's
                // splice counted in: it names this descriptor and its
                // completion is what makes the number safe to give away, so it
                // is as good a reason to wait as one of this connection's own.
                if (defer_c && !client_op_in_flight(conn) && !peer_splicing_into_client)
                    defer_c = false;
            }
            if (!defer_c)
            {
                invoke_on_disconnect(client_fd);

                // Close splice pipes
                if (conn->pipe_to_backend[0] >= 0) close_tracked(conn->pipe_to_backend[0]);
                if (conn->pipe_to_backend[1] >= 0) close_tracked(conn->pipe_to_backend[1]);
                conn->pipe_to_backend[0] = -1;
                conn->pipe_to_backend[1] = -1;

#ifdef SOCKETLEY_TRACE
                // One report per connection at the point it actually goes
                // away, with "unread" the discriminator: bytes still in the
                // socket are bytes the client believes it delivered.
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
                    // The two pipe residencies must not be read with FIONREAD,
                    // because that takes the same mutex a splice holds while
                    // it waits -- and they are implied by the counters anyway.
                    pipe_c = (int)(long long)(conn->tr.sp_in - conn->tr.sp_out);
                    if (conn->backend_fd >= 0 && conn->backend_fd < MAX_FDS &&
                        m_conn_idx[conn->backend_fd].side == conn_backend)
                    {
                        [[maybe_unused]] auto* tb2 = m_conn_idx[conn->backend_fd].backend;
                        be_in = tb2->tr.sp_in; be_out = tb2->tr.sp_out;
                        pipe_b = (int)(long long)(tb2->tr.sp_in - tb2->tr.sp_out);
                        ioctl(conn->backend_fd, FIONREAD, &unread_b);
                    }
                    // Conservation, where whichever of the two equations fails
                    // names the hop the bytes vanished on.
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
                // back, because a client that dies first left a deferred
                // backend splicing into a stranger's socket.
                for (int cand : { backend_fd, conn->backend_fd })
                {
                    if (cand < 0 || cand >= MAX_FDS) continue;
                    auto& bslot = m_conn_idx[cand];
                    if (bslot.side == conn_backend && bslot.backend->client_fd == client_fd)
                        bslot.backend->client_fd = -1;
                }

                shutdown(client_fd, SHUT_RDWR);
                close_tracked(client_fd);
                m_conn_idx[client_fd] = {};
                if (m_client_slots[client_fd])
                {
                    // The owners belong to the release path, which this used
                    // to pre-empt by nulling three of the five and leaving
                    // both splice requests pointing at a pooled struct.
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

    // A backend read is armed essentially all of the time, so "no pending ops"
    // was almost never true and the connection was thrown away after every
    // response -- and a read is the one operation that can be taken back.
    const bool only_read_pending =
        bconn->read_pending && !bconn->write_pending && !bconn->zc_notif_pending &&
        !bconn->splice_in_pending && !bconn->splice_out_pending;

    // The cancel is the last condition, because a refused submission must
    // leave no trace -- and this is the one cancel submitted for a descriptor
    // meant to change hands, made safe by pooling only once the read came back
    // -ECANCELED.
    if (only_read_pending && m_loop &&
        backend_pool_eligible(bconn, cconn, m_backends, m_protocol) &&
        m_loop->submit_cancel_fd(backend_fd))
    {
        // The fd stays registered and the struct alive until that cancellation
        // is accounted for, or the next request picks up the fd while a
        // completion still points at the struct.
        bconn->pool_draining = true;
        bconn->pool_abandoned = false;
        bconn->pool_backend_idx = cconn->backend_idx;
        // Read now while the pair is still a pair, because the client may be
        // routed to a different member before the cancellation lands.
        {
            std::string_view dh;
            uint16_t dp = 0;
            if (backend_endpoint_of(cconn, m_backends, dh, dp))
            {
                bconn->pool_host.assign(dh);
                bconn->pool_port = dp;
            }
            else
            {
                bconn->pool_host.clear();
                bconn->pool_port = 0;
            }
        }

        // The client is released immediately rather than waiting a round trip
        // for the backend's paperwork, which is why the backend carries its
        // own pool index from here.
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
        // A backend that cannot be pooled is no reason to take the client with
        // it, which ended every keep-alive connection after one response -- so
        // the two are detached and the backend goes on its own.
        cconn->backend_fd = -1;
        bconn->client_fd = -1;
        bconn->closing = true;
        shutdown(backend_fd, SHUT_RDWR);
        reset_client_for_next_request(cconn);
        return;
    }

    // Handed over here and now, but only if it may be pooled and only under
    // the endpoint it reached -- pooling under backend_idx would give one
    // member's socket to a request routed to any of them.
    std::string_view host;
    uint16_t port = 0;
    const bool can_pool = backend_pool_eligible(bconn, cconn, m_backends, m_protocol) &&
                          backend_endpoint_of(cconn, m_backends, host, port);
    const size_t b_idx = cconn->backend_idx;
    // The view points into the client (group route) or into m_backends (plain
    // one); neither is touched between here and the release, but the copy
    // costs nothing and outlives the argument about which.
    const std::string host_key(host);

    // Clear tracking
    m_conn_idx[backend_fd] = {};
    cconn->backend_fd = -1;

    if (can_pool)
    {
        release_to_pool(backend_fd, b_idx, host_key, port, bconn);
    }
    else
    {
        shutdown(backend_fd, SHUT_RDWR);
        close_tracked(backend_fd);
    }

    // Nothing is pending on this path, so the release clears all four owners
    // itself rather than nulling two and leaving the splice pair pointing at a
    // struct back in circulation.
    if (m_backend_slots[backend_fd])
    {
        backend_pool_release(std::move(m_backend_slots[backend_fd]));
        m_backend_count--;
    }

    reset_client_for_next_request(cconn);
}

// Consume the completion of the read detach_and_pool_backend cancelled, before
// which nothing about the fd or the struct may be released -- a pooled fd goes
// to the next request and a released struct to the one after.
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

    // -ECANCELED is the answer we asked for and the only one that leaves the
    // connection reusable, and it is also what makes this the one place
    // allowed to pool a descriptor the loop is still counting a cancel
    // against.
    if (cqe->res != -ECANCELED)
        conn->pool_abandoned = true;

    // Still armed — the completion that ends the read is yet to come.
    if (is_multishot_recv_op(req->type) && (cqe->flags & IORING_CQE_F_MORE))
        return;

    conn->read_pending = false;
    conn->pool_draining = false;

    m_conn_idx[fd] = {};

    // release_to_pool refuses an out-of-range index and this is the fd's last
    // owner, asked through pool_key_ok rather than a fourth copy of the test
    // -- which is the copy that closed every unix backend's socket while the
    // pool looked healthy.
    if (SOCKETLEY_LIKELY(!conn->pool_abandoned &&
                         conn->pool_backend_idx < m_backend_pool.size() &&
                         pool_key_ok(conn->pool_host, conn->pool_port)))
    {
        release_to_pool(fd, conn->pool_backend_idx, conn->pool_host, conn->pool_port, conn);
    }
    else
    {
        shutdown(fd, SHUT_RDWR);
        close_tracked(fd);
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
    // There is no next request, said by client_eof or by client_conn_close, so
    // the connection ends here -- asked once of the client connection, because
    // answering it at the detach instead cost a backend connection per
    // request.
    if (SOCKETLEY_UNLIKELY(cconn->client_eof || cconn->client_conn_close) &&
        cconn->fd >= 0)
    {
        cconn->closing = true;
        close_pair(cconn->fd, cconn->backend_fd);
        return;
    }

    cconn->header_parsed = false;
    cconn->response_started = false;
    // The exchange this connection was timed for is over, and the next request
    // arms deadlines of its own; until then it is merely idle, which is
    // --idle-timeout's business.
    cconn->awaiting_response = false;
    cconn->awaiting_headers = false;
    cconn->client_conn_close = false;
    cconn->method.clear();
    cconn->path.clear();
    cconn->version.clear();
    // Per request and not per connection, because a keep-alive connection
    // whose second request is answered before it reaches the chain would
    // otherwise carry the first request's headers.
    cconn->filter_headers.clear();
    cconn->filter_removed_headers.clear();

    // The answer arrived before the client finished its body, so what is
    // buffered is the tail of that body rather than a request, and is dropped
    // as unclassifiable.
    const bool body_owing = cconn->body_unbounded || cconn->body_remaining > 0;
    cconn->declared_body_len = 0;
    cconn->declared_body_chunked = false;
    cconn->body_remaining = 0;
    cconn->body_unbounded = false;
    if (body_owing)
        cconn->partial.clear();
    cconn->saved_request.clear();

    // conn->partial is deliberately not cleared, because the pipelined request
    // in it has to go through the framing checks -- and nothing else will wake
    // it, so the parse is driven here as the last statement of every branch.
    if (m_protocol == protocol_http && !cconn->partial.empty() &&
        !cconn->closing && cconn->fd >= 0)
        drive_client_request(cconn, cconn->fd);
}

// A TCP client's half-close holds the pair open for the answer that was thrown
// away with it, passes the FIN on because it is the only thing that can tell a
// framing-less backend the request is over, and is ended by the backend's own
// close, a client reset, --idle-timeout or nothing -- with invariant (1) asked
// before the abort watch is armed, so the watch cannot vouch for a pair it
// alone is holding.
bool proxy_instance::hold_tcp_half_close(proxy_client_connection* conn)
{
    if (m_protocol != protocol_tcp || conn->closing)
        return false;

    // The backend handshake is still in flight with the payload in
    // saved_request, which is the worst version of the loss and the easiest to
    // hit -- the connect completion is what keeps the pair reachable until
    // then.
    const bool connecting = conn->connect_pending;

    const int bfd = conn->backend_fd;
    proxy_backend_connection* bconn = nullptr;
    if (bfd >= 0 && bfd < MAX_FDS && m_conn_idx[bfd].side == conn_backend)
        bconn = m_conn_idx[bfd].backend;

    if (!connecting && !bconn)
        return false;
    if (bconn && bconn->closing)
        return false;

    // Reachability, before anything is changed.
    const bool peer_alive = bconn && (backend_op_in_flight(bconn) ||
                                      !bconn->write_queue.empty());
    if (!connecting && !peer_alive &&
        !client_op_in_flight(conn) && conn->write_queue.empty())
        return false;

    conn->client_eof = true;

    // A failure to arm costs this connection the early notice of a reset and
    // nothing else, so nothing is unwound on refusal.
    if (!conn->abort_watch_pending)
    {
        conn->abort_req = { this, nullptr, conn->fd, 0, op_poll_abort, conn->generation };
        if (SOCKETLEY_LIKELY(m_loop && m_loop->submit_poll_add(conn->fd, POLLERR | POLLHUP,
                                                              &conn->abort_req)))
            conn->abort_watch_pending = true;
    }

    forward_client_half_close(conn);
    return true;
}

// The ordering is the whole function: shutdown() is a syscall and everything
// else is a submission, so a FIN issued with a write still queued overtakes
// the bytes it terminates -- which is why this is called from every place the
// client's outbound bytes can finish.
void proxy_instance::forward_client_half_close(proxy_client_connection* conn)
{
    if (m_protocol != protocol_tcp || !conn->client_eof || conn->backend_half_closed)
        return;

    const int bfd = conn->backend_fd;
    if (bfd < 0 || bfd >= MAX_FDS || m_conn_idx[bfd].side != conn_backend)
        return;
    auto* bconn = m_conn_idx[bfd].backend;

    // Anything the copy path still owes this socket, zc_notif_pending
    // included, because a zero-copy send clears write_pending on its first
    // completion.
    if (bconn->write_pending || bconn->zc_notif_pending || !bconn->write_queue.empty())
        return;

    // And anything the splice path still owes it, where the two pending flags
    // also say the pipe is empty, because a partial splice is resubmitted
    // immediately.
    if (conn->splice_in_pending || conn->splice_out_pending)
        return;

    // A TLS backend leg is not reachable from here, and the FIN is the
    // transport's rather than the session's -- a close_notify would be, and
    // TCP mode never sends one.
    if (shutdown(bfd, SHUT_WR) < 0) {}
    conn->backend_half_closed = true;
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
        // Half-open is meant to cost one request, because saying available to
        // every selection poured the whole rotation in -- with an elapsed
        // bound, since the probe's answer may never arrive.
        else if (SOCKETLEY_UNLIKELY(cb.current == circuit_breaker::half_open) &&
                 cb.probe_in_flight)
        {
            auto elapsed = std::chrono::steady_clock::now() - cb.probe_started;
            if (elapsed < std::chrono::seconds(m_mesh.circuit_timeout))
                return false;
        }
    }

    return true;
}

// A backend has just been picked, and while it is half-open that request is
// the probe, so no second one goes out until it reports.
void proxy_instance::note_backend_selected(size_t idx)
{
    if (idx >= m_circuit_breakers.size())
        return;

    auto& cb = m_circuit_breakers[idx];
    if (SOCKETLEY_UNLIKELY(cb.current == circuit_breaker::half_open) && !cb.probe_in_flight)
    {
        cb.probe_in_flight = true;
        cb.probe_started = std::chrono::steady_clock::now();
    }
}

void proxy_instance::drop_health_check(size_t idx)
{
    if (idx >= m_health_checks.size() || !m_health_checks[idx])
        return;

    auto probe = std::move(m_health_checks[idx]);
    // An operation in flight is not taken back by close(), so close_fd submits
    // the cancel and holds the number -- a health probe's descriptors are
    // recycled as fast as any in the runtime.
    close_tracked(probe->fd);
    probe->fd = -1;

    io_request* owed[1];
    size_t n = 0;
    if (probe->op_pending)
        owed[n++] = &probe->req;
    retire(std::shared_ptr<void>(std::move(probe)), owed, n);
}

bool proxy_instance::health_submit_write(async_health_check* hc)
{
    if (SOCKETLEY_UNLIKELY(!m_loop || hc->fd < 0 ||
                           hc->write_off >= hc->write_buf.size()))
        return false;
    hc->req.type = op_health_check;
    hc->op_pending = true;
    const size_t left = hc->write_buf.size() - hc->write_off;
    if (SOCKETLEY_UNLIKELY(!m_loop->submit_write(hc->fd,
                                                 hc->write_buf.data() + hc->write_off,
                                                 static_cast<uint32_t>(left), &hc->req)))
    {
        hc->op_pending = false;
        return false;
    }
    return true;
}

bool proxy_instance::health_submit_read(async_health_check* hc)
{
    if (SOCKETLEY_UNLIKELY(!m_loop || hc->fd < 0))
        return false;
    // Ciphertext into the probe's own buffer and plaintext into the one the
    // verdict is read from, both memory this struct owns and retire() holds.
    char* dst = hc->ssl ? hc->cipher_in.data() : hc->buf;
    const size_t len = hc->ssl ? hc->cipher_in.size() : sizeof(hc->buf) - 1;
    if (SOCKETLEY_UNLIKELY(len == 0))
        return false;
    hc->req.type = op_health_check;
    hc->op_pending = true;
    if (SOCKETLEY_UNLIKELY(!m_loop->submit_read(hc->fd, dst,
                                                static_cast<uint32_t>(len), &hc->req)))
    {
        hc->op_pending = false;
        return false;
    }
    return true;
}

bool proxy_instance::health_tls_feed(async_health_check* hc, int len)
{
    size_t off = 0;
    while (off < static_cast<size_t>(len))
    {
        const int n = tls_context::bio_write_in(hc->ssl, hc->cipher_in.data() + off,
                                                static_cast<int>(static_cast<size_t>(len) - off));
        if (SOCKETLEY_UNLIKELY(n <= 0))
            return false;
        off += static_cast<size_t>(n);
    }
    return true;
}

bool proxy_instance::health_tls_arm(async_health_check* hc)
{
    hc->write_buf.clear();
    hc->write_off = 0;

    char out[async_health_check::TLS_READ_SIZE];
    for (;;)
    {
        const int n = tls_context::bio_read_out(hc->ssl, out, sizeof(out));
        if (n <= 0)
            break;
        hc->write_buf.append(out, static_cast<size_t>(n));
    }

    // Which pair of phases this belongs to is not remembered anywhere: it is
    // read off the session's own state, which the handshake sets exactly once.
    const bool shaking = (hc->tls_state == tls_conn_handshake);
    if (!hc->write_buf.empty())
    {
        hc->current = shaking ? async_health_check::tls_writing
                              : async_health_check::writing;
        return health_submit_write(hc);
    }
    hc->current = shaking ? async_health_check::tls_reading
                          : async_health_check::reading;
    return health_submit_read(hc);
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

        // Whatever is left in this slot belongs to an earlier sweep and is let
        // go, because reusing it let a late completion write into the address
        // the next connect was about to read.
        drop_health_check(i);

        if (b.is_group)
            continue;

        // Where this backend is, from the same function the request path asks
        // and before the socket, because the family decides what to open --
        // and false means an unresolved hostname, which the old code reached
        // by running inet_pton over a name and probing 0.0.0.0.
        struct sockaddr_storage addr{};
        socklen_t addr_len = 0;
        if (!backend_connect_addr(b, addr, addr_len))
            continue;

        int fd = socket(addr.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
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

        // The kernel reads the address asynchronously, so it lives in the
        // probe for the connect's duration rather than sharing `buf` with the
        // response.
        hc.write_buf.clear();
        hc.addr = addr;
        hc.addr_len = addr_len;

        // A refused submission is our problem rather than the backend's, so
        // the probe is dropped and the next sweep tries again.
        hc.op_pending = true;
        if (SOCKETLEY_UNLIKELY(!m_loop->submit_connect(fd,
                reinterpret_cast<const struct sockaddr*>(&hc.addr),
                hc.addr_len, &hc.req)))
        {
            close_tracked(fd);
            hc.fd = -1;
            hc.op_pending = false;
            m_health_checks[i].reset();
        }
    }

    // A 500 ms deadline of its own for this sweep, with a previous one that
    // has not reported retired rather than written over.
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

// Is this an HTTP response with a 2xx status, asked properly rather than by
// reading offset nine, which marked anything with a '2' there healthy -- with
// the version digit deliberately not pinned.
static bool health_is_2xx(const char* buf, size_t len)
{
    if (len < 13) return false;
    if (std::memcmp(buf, "HTTP/1.", 7) != 0) return false;
    if (buf[8] != ' ') return false;
    return buf[9] == '2';
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

    // Every path below either arms the next step or finishes the probe, and
    // finishing means letting it go rather than parking it for the next sweep
    // to write over.
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

        // An HTTPS probe is the same probe one layer down, verifying through
        // the same session factory as the data path -- because a probe that
        // accepted any certificate would report a backend healthy that the
        // data path refuses to send to.
        if (b.tls)
        {
            // No trust store or no name to pin, so nothing is recorded rather
            // than the peer being charged for a question it was never asked;
            // neither is reachable from a started proxy.
            if (SOCKETLEY_UNLIKELY(!m_backend_tls || b.resolved_host.empty()))
            {
                drop_health_check(slot);
                return;
            }

            hc->ssl = m_backend_tls->create_ssl_client(b.resolved_host);
            if (SOCKETLEY_UNLIKELY(!hc->ssl))
            {
                drop_health_check(slot);
                return;
            }
            hc->tls_state = tls_conn_handshake;
            hc->cipher_in.resize(async_health_check::TLS_READ_SIZE);

            // The first turn produces the ClientHello and nothing else, and a
            // negative is local rather than a rejection because nothing is on
            // the wire yet.
            if (SOCKETLEY_UNLIKELY(tls_context::do_handshake(hc->ssl) < 0) ||
                SOCKETLEY_UNLIKELY(!health_tls_arm(hc)))
                drop_health_check(slot);
            return;
        }

        // A unix backend's path is not a Host field-value, so it is asked as
        // "localhost": a strict backend answers 400 and this probe would take
        // it out of rotation for a header it sent itself.
        hc->write_buf = "GET " + m_mesh.health_path + " HTTP/1.0\r\nHost: " +
                        (b.is_unix ? std::string("localhost") : b.resolved_host) +
                        "\r\nConnection: close\r\n\r\n";
        hc->write_off = 0;
        hc->current = async_health_check::writing;
        // Our shortage, not the backend's: no verdict is recorded.
        if (SOCKETLEY_UNLIKELY(!health_submit_write(hc)))
            drop_health_check(slot);
    }
    else if (hc->current == async_health_check::tls_writing ||
             hc->current == async_health_check::writing)
    {
        if (cqe->res <= 0)
        {
            record(false);
            drop_health_check(slot);
            return;
        }

        // A short write treated as complete leaves the record stream with a
        // hole or the GET truncated, and neither is the backend's doing.
        hc->write_off += static_cast<size_t>(cqe->res);
        if (SOCKETLEY_UNLIKELY(hc->write_off < hc->write_buf.size()))
        {
            if (SOCKETLEY_UNLIKELY(!health_submit_write(hc)))
                drop_health_check(slot);
            return;
        }

        // Read the answer into the probe's own buffer, which nothing else
        // shares now that the connect address has a field of its own.
        hc->current = (hc->tls_state == tls_conn_handshake)
                    ? async_health_check::tls_reading
                    : async_health_check::reading;
        if (SOCKETLEY_UNLIKELY(!health_submit_read(hc)))
            drop_health_check(slot);
    }
    else if (hc->current == async_health_check::tls_reading)
    {
        // A peer that closes or errors in the middle of a handshake has failed
        // this probe: it is the same peer the data path would have to give up
        // on, and the request that found out would be answered 502.
        if (cqe->res <= 0 || SOCKETLEY_UNLIKELY(!health_tls_feed(hc, cqe->res)))
        {
            record(false);
            drop_health_check(slot);
            return;
        }

        const int r = tls_context::do_handshake(hc->ssl);
        if (r < 0)
        {
            // Every verification failure lands here, and a backend this proxy
            // would not send a request to is not a healthy backend.
            record(false);
            drop_health_check(slot);
            return;
        }
        if (r == 0)
        {
            // Another round, whose records go out below if it produced any and
            // whose turn is the peer's if it did not.
            if (SOCKETLEY_UNLIKELY(!health_tls_arm(hc)))
                drop_health_check(slot);
            return;
        }

        hc->tls_state = tls_conn_ready;
        if (SOCKETLEY_UNLIKELY(idx >= m_backends.size()))
        {
            drop_health_check(slot);
            return;
        }

        const std::string request = "GET " + m_mesh.health_path + " HTTP/1.0\r\nHost: " +
                                    m_backends[idx].resolved_host +
                                    "\r\nConnection: close\r\n\r\n";
        // Partial writes are not enabled on this context, so a short count
        // would mean the record layer and this probe disagree -- and it is
        // local, so no verdict is recorded.
        const int w = tls_context::ssl_write(hc->ssl, request.data(),
                                             static_cast<int>(request.size()));
        if (SOCKETLEY_UNLIKELY(w <= 0 || static_cast<size_t>(w) != request.size()) ||
            SOCKETLEY_UNLIKELY(!health_tls_arm(hc)))
            drop_health_check(slot);
    }
    else if (hc->current == async_health_check::reading)
    {
        bool got_2xx = false;

        if (hc->ssl)
        {
            if (cqe->res <= 0 || SOCKETLEY_UNLIKELY(!health_tls_feed(hc, cqe->res)))
            {
                record(false);
                drop_health_check(slot);
                return;
            }

            // Decrypt everything the record layer has, accumulated rather than
            // judged per read, because a status line split across two records
            // is ordinary.
            bool peer_done = false;
            while (hc->plain_len < sizeof(hc->buf) - 1)
            {
                const int n = tls_context::ssl_read(
                    hc->ssl, hc->buf + hc->plain_len,
                    static_cast<int>(sizeof(hc->buf) - 1 - hc->plain_len));
                if (n > 0)
                {
                    hc->plain_len = static_cast<uint16_t>(hc->plain_len + n);
                    continue;
                }
                // Below zero is the peer's close_notify or a record this
                // session cannot use; either way nothing more is coming.
                peer_done = (n < 0);
                break;
            }

            if (hc->plain_len <= 12 && !peer_done)
            {
                // Not enough of the status line yet, bounded by the sweep's
                // own 500 ms deadline like every other step.
                if (SOCKETLEY_UNLIKELY(!health_submit_read(hc)))
                    drop_health_check(slot);
                return;
            }
            got_2xx = health_is_2xx(hc->buf, hc->plain_len);
        }
        else if (cqe->res > 12)
        {
            hc->buf[cqe->res] = '\0';
            got_2xx = health_is_2xx(hc->buf, static_cast<size_t>(cqe->res));
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

    // The abort watch covered exactly this handshake and is withdrawn rather
    // than left armed, because a struct that still owes a completion is
    // retired instead of pooled.
    if (conn->abort_watch_pending && m_loop)
        m_loop->submit_poll_remove(&conn->abort_req);

    // A poll completion only reports readiness, so SO_ERROR is folded into one
    // value and the failure path stays shared.
    int res = cqe->res;
    bool fd_ours = (bfd >= 0);
    if (res >= 0 && req->type == op_poll)
    {
        // POLLNVAL, POLLERR and POLLHUP are all positive, so testing only the
        // sign accepts them as writable -- and POLLNVAL means the number may
        // already belong to someone else.
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
            // The descriptor is already gone and is not ours to close, because
            // closing it again destroys a live connection with nothing to do
            // with this one.
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
        if (fd_ours && bfd >= 0) close_tracked(bfd);

        // The descriptor was gone rather than the backend refusing, so nothing
        // about the client is wrong and it gets one fresh socket.
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
            note_backend_failure(conn);

        // The same three things decide what the client is told, because the
        // asynchronous connect reports through SO_ERROR and local shortages
        // reached the client as 502 either way.
        const bool ours = !fd_ours || retry_ours || connect_errno_is_ours(-res);

        if (m_protocol == protocol_http)
        {
            if (!try_retry(conn))
                answer_gateway_failure(conn, ours);
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
        // The connect worked and this process has nowhere to put the result,
        // which is ours either way.
        if (bfd >= 0) close_tracked(bfd);
        answer_gateway_failure(conn, true);
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
    if (m_protocol == protocol_tcp && m_splice_enabled &&
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

                // forward_to_backend only queues, and nothing orders a splice
                // against that write, so starting it now lets later data
                // overtake the bytes that opened the stream.
                if (!ptr->write_pending && ptr->write_queue.empty())
                    start_splice_forwarding(conn, ptr);
                // And the same for a half-close taken during the connect.
                forward_client_half_close(conn);
                return;
            }
        }
    }

    // Submit read on backend
    if (SOCKETLEY_UNLIKELY(!submit_read_op_backend(m_loop, bfd, ptr, m_recv_multishot,
                                                   m_use_provided_bufs, BUF_GROUP_ID)))
    {
        // The backend is connected and this proxy cannot arm a read on it,
        // which is our shortage and left the client waiting in silence.
        answer_gateway_failure(conn, true);
        close_pair(conn->fd, bfd);
        return;
    }

    // The handshake starts before the saved request is forwarded, and a
    // session that cannot be created costs the pair -- 503 rather than 502,
    // because nothing has reached the backend yet.
    if (SOCKETLEY_UNLIKELY(conn_backend_tls(conn) && !start_backend_tls(conn, ptr)))
    {
        if (m_protocol == protocol_http && !conn->closing && !conn->response_started)
        {
            conn->backend_fd = -1;
            ptr->client_fd = -1;
            answer_gateway_failure(conn, true);
            close_pair(-1, bfd);
            return;
        }
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

    // The client read was left unarmed until a backend existed, and is not
    // armed onto a socket that reported end of stream while the connect was in
    // flight.
    if (!conn->closing && !conn->read_pending && !conn->splice_active &&
        !conn->client_eof &&
        SOCKETLEY_UNLIKELY(!submit_read_op(m_loop, conn->fd, conn, m_recv_multishot,
                                           m_use_provided_bufs, BUF_GROUP_ID)))
    {
        answer_gateway_failure(conn, true);
        close_pair(conn->fd, bfd);
        return;
    }

    // A TCP client that half-closed during the connect has its payload queued
    // above, so the FIN goes out behind it from handle_backend_write or from
    // here.
    forward_client_half_close(conn);

    // Not a shutdown() on the next line, because forward_to_backend only
    // prepares the send and a syscall would overtake the request -- and it is
    // not needed, since a validated request tells the backend where it ends.
}

void proxy_instance::handle_client_abort(struct io_uring_cqe* cqe, io_request* req)
{
    int client_fd = req->fd;
    if (SOCKETLEY_UNLIKELY(client_fd < 0 || client_fd >= MAX_FDS))
        return;

    auto& entry = m_conn_idx[client_fd];
    if (SOCKETLEY_UNLIKELY(entry.side != conn_client))
        return;

    auto* conn = entry.client;

    // The struct at this fd may already belong to a different connection than
    // the one that armed this watch; the generation says which.  (A struct that
    // was still owed this completion is retired rather than reused, so a
    // mismatch here means the descriptor moved, not the memory.)
    if (SOCKETLEY_UNLIKELY(req->generation != conn->generation))
        return;

    if (SOCKETLEY_UNLIKELY(!conn->abort_watch_pending))
        return;
    conn->abort_watch_pending = false;

    // Negative is the withdrawal (-ECANCELED) that handle_connect or close_pair
    // asked for, and nothing beyond clearing the flag is owed for it.
    if (cqe->res < 0)
        return;

    const int revents = cqe->res;

    // POLLNVAL says the descriptor is no longer valid, so it must not be
    // closed on the strength of this.
    if (SOCKETLEY_UNLIKELY(revents & POLLNVAL))
        return;

    if (!(revents & (POLLERR | POLLHUP)))
        return;

    // Already being torn down: whatever is in flight will finish the job, and
    // re-entering here would only race it.
    if (conn->closing)
        return;

    // The client is gone for good, so whatever the backend eventually says has
    // nowhere to go and the handshake still running is work nobody will
    // collect.
    SKL_TRACE_LOG("client-abort cfd=%d revents=0x%x connect_pending=%d clients=%u",
                  client_fd, revents, (int)conn->connect_pending, (unsigned)m_client_count);
    // force: POLLERR/POLLHUP means the peer is gone, so holding would keep the
    // pair for a reply nobody will read.
    close_pair(client_fd, conn->backend_fd, close_reason::force);
}

void proxy_instance::arm_response_deadline(proxy_client_connection* conn)
{
    if (m_mesh.backend_timeout <= 0)
        return;

    conn->awaiting_response = true;
    conn->response_deadline = std::chrono::steady_clock::now() +
                              std::chrono::seconds(m_mesh.backend_timeout);
    arm_response_deadline_sweep();
}

void proxy_instance::clear_response_deadline(proxy_client_connection* conn)
{
    conn->awaiting_response = false;
}

void proxy_instance::arm_header_deadline(proxy_client_connection* conn)
{
    // Already running, because the deadline dates from the first incomplete
    // read and renewing it would hand the bound back to the client.
    if (conn->awaiting_headers)
        return;

    conn->awaiting_headers = true;
    conn->header_deadline = std::chrono::steady_clock::now() +
                            std::chrono::seconds(PROXY_HEADER_TIMEOUT_SEC);
    arm_response_deadline_sweep();
}

void proxy_instance::arm_response_deadline_sweep()
{
    if (m_response_sweep_armed || !m_loop || !m_response_sweep_timer)
        return;

    m_response_sweep_armed = true;
    if (SOCKETLEY_UNLIKELY(!m_loop->submit_timeout(&m_response_sweep_timer->ts,
                                                   &m_response_sweep_timer->req)))
    {
        m_response_sweep_armed = false;
        // Once per run, for the same reason as the idle sweep: this is on the
        // request path, and a full ring stays full for a while.
        if (!m_response_sweep_warned)
        {
            m_response_sweep_warned = true;
            LOG_ERROR("proxy: backend response deadline timer refused — a backend that "
                      "accepts and then stops answering will not be detected");
        }
    }
}

// The only evidence a stalled backend or client ever produces, because a
// request that never completes is recorded as neither success nor failure and
// the surviving backends look flawless while throughput collapses.
void proxy_instance::response_deadline_sweep()
{
#ifdef SOCKETLEY_TRACE
    // The only periodic tick this process has while a request is outstanding.
    trace_splice_sweep();
#endif
    const auto now = std::chrono::steady_clock::now();

    // A snapshot, not the live count: giving up on a request can tear the pair
    // down and m_client_count falls with it, so using the live value as the
    // bound would end the scan early and leave every connection after this one
    // waiting exactly as long as before.
    size_t remaining = m_client_count;
    bool still_waiting = false;

    for (int cfd = 0; cfd < MAX_FDS && remaining > 0; cfd++)
    {
        auto* conn = m_client_slots[cfd].get();
        if (!conn)
            continue;
        remaining--;

        if (conn->closing)
            continue;

        // Half-sent request, which cannot coincide with waiting on a backend,
        // so the order between the two arms is only about which is cheaper to
        // test.
        if (conn->awaiting_headers)
        {
            if (now < conn->header_deadline)
            {
                still_waiting = true;
                continue;
            }

            conn->awaiting_headers = false;
            // Dropped for the same reason the malformed-request path drops
            // them: the error carries Connection: close, and bytes still
            // sitting in `partial` must not be picked up as a fresh request
            // behind it.
            conn->partial.clear();
            send_error(conn, "408 Request Timeout", "Request Timeout\n");
            continue;
        }

        if (!conn->awaiting_response)
            continue;

        if (now < conn->response_deadline)
        {
            still_waiting = true;
            continue;
        }

        conn->awaiting_response = false;

        // Charged to the backend so the breaker opens, and to the member a
        // group-routed connection reached rather than to the index that names
        // the whole group.
        note_backend_failure(conn);

        // The handshake itself never finished, so try_retry() must not be used
        // and the connect is withdrawn by hand -- answered 504 rather than
        // closed in silence, which a client cannot act on.
        if (conn->connect_pending)
        {
            close_tracked(conn->connect_fd);
            conn->connect_fd = -1;
            send_error(conn, "504 Gateway Timeout", "Gateway Timeout\n");
            continue;
        }

        // A retry sends the same request to a different backend, which is the
        // answer the client would rather have than a 504; it gets a deadline of
        // its own from connect_to_backend.
        if (try_retry(conn))
            still_waiting = true;
        else
            send_error(conn, "504 Gateway Timeout", "Gateway Timeout\n");
    }

    if (still_waiting)
        arm_response_deadline_sweep();
}

// One breaker's state machine, over the breaker rather than over an index —
// group members reach it through a map and plain backends through a vector, and
// the rules must not be able to drift apart between the two.
static inline void breaker_record_error(circuit_breaker& cb, int threshold)
{
    if (cb.current == circuit_breaker::half_open)
    {
        // Half-open probe failed -> back to open
        cb.current = circuit_breaker::open;
        cb.opened_at = std::chrono::steady_clock::now();
        cb.probe_in_flight = false;
        return;
    }

    cb.error_count++;
    if (cb.error_count >= threshold && cb.current == circuit_breaker::closed)
    {
        cb.current = circuit_breaker::open;
        cb.opened_at = std::chrono::steady_clock::now();
    }
}

static inline void breaker_record_success(circuit_breaker& cb)
{
    if (cb.current == circuit_breaker::half_open)
    {
        // Half-open probe succeeded -> close circuit
        cb.current = circuit_breaker::closed;
        cb.error_count = 0;
        cb.probe_in_flight = false;
        return;
    }

    // A success while closed clears the tally, making circuit_threshold mean
    // this many failures in a row rather than a lifetime total.
    cb.error_count = 0;
}

// "host:port" written out rather than hashed, because a collision would take a
// healthy member out of rotation for its neighbour's failures, and empty means
// no breaker.
static inline std::string_view endpoint_key(char* buf, size_t cap,
                                            std::string_view host, uint16_t port)
{
    if (host.empty() || port == 0 || host.size() + 8 > cap)
        return {};
    std::memcpy(buf, host.data(), host.size());
    size_t n = host.size();
    buf[n++] = ':';
    auto [p, ec] = std::to_chars(buf + n, buf + cap, port);
    if (ec != std::errc())
        return {};
    return std::string_view(buf, static_cast<size_t>(p - buf));
}

void proxy_instance::record_backend_error(size_t backend_idx)
{
    if (SOCKETLEY_UNLIKELY(backend_idx >= m_circuit_breakers.size()))
        return;

    breaker_record_error(m_circuit_breakers[backend_idx], m_mesh.circuit_threshold);
}

void proxy_instance::record_backend_success(size_t backend_idx)
{
    if (SOCKETLEY_UNLIKELY(backend_idx >= m_circuit_breakers.size()))
        return;

    breaker_record_success(m_circuit_breakers[backend_idx]);
}

void proxy_instance::record_group_error(std::string_view host, uint16_t port)
{
    char buf[320];
    const auto key = endpoint_key(buf, sizeof(buf), host, port);
    if (key.empty())
        return;

    auto it = m_group_breakers.find(key);
    if (it == m_group_breakers.end())
        it = m_group_breakers.emplace(std::string(key), circuit_breaker{}).first;

    breaker_record_error(it->second, m_mesh.circuit_threshold);
}

void proxy_instance::record_group_success(std::string_view host, uint16_t port)
{
    if (m_group_breakers.empty())
        return;

    char buf[320];
    const auto key = endpoint_key(buf, sizeof(buf), host, port);
    if (key.empty())
        return;

    auto it = m_group_breakers.find(key);
    if (it == m_group_breakers.end())
        return;  // never failed — nothing to clear, and nothing to remember

    breaker_record_success(it->second);

    // An endpoint with a clean record needs no entry, which keeps this map the
    // size of the broken part of the group rather than a tally of everyone who
    // has been in it.
    if (it->second.current == circuit_breaker::closed && it->second.error_count == 0)
        m_group_breakers.erase(it);
}

bool proxy_instance::group_endpoint_available(std::string_view host, uint16_t port)
{
    char buf[320];
    const auto key = endpoint_key(buf, sizeof(buf), host, port);
    if (key.empty())
        return true;

    auto it = m_group_breakers.find(key);
    if (it == m_group_breakers.end())
        return true;

    auto& cb = it->second;
    const auto now = std::chrono::steady_clock::now();

    if (SOCKETLEY_UNLIKELY(cb.current == circuit_breaker::open))
    {
        if ((now - cb.opened_at) < std::chrono::seconds(m_mesh.circuit_timeout))
            return false;
        // Expired — one request may go and find out whether it is back.
        cb.current = circuit_breaker::half_open;
        cb.probe_in_flight = false;
    }

    // Half-open means exactly one request, for the reason given on
    // is_backend_available: saying yes to every selection pours the whole
    // rotation into a member that has just been taken out of it, and against
    // one that stalls rather than refuses, that is a burst of full deadlines.
    if (SOCKETLEY_UNLIKELY(cb.current == circuit_breaker::half_open) && cb.probe_in_flight &&
        (now - cb.probe_started) < std::chrono::seconds(m_mesh.circuit_timeout))
        return false;

    return true;
}

void proxy_instance::note_group_selected(std::string_view host, uint16_t port)
{
    if (m_group_breakers.empty())
        return;

    char buf[320];
    const auto key = endpoint_key(buf, sizeof(buf), host, port);
    if (key.empty())
        return;

    auto it = m_group_breakers.find(key);
    if (it == m_group_breakers.end())
        return;

    auto& cb = it->second;
    if (SOCKETLEY_UNLIKELY(cb.current == circuit_breaker::half_open) && !cb.probe_in_flight)
    {
        cb.probe_in_flight = true;
        cb.probe_started = std::chrono::steady_clock::now();
    }
}

void proxy_instance::note_backend_failure(proxy_client_connection* conn)
{
    if (conn->backend_from_group)
        record_group_error(conn->backend_host, conn->backend_port);
    else
        record_backend_error(conn->backend_idx);
}

void proxy_instance::note_backend_success(proxy_client_connection* conn)
{
    if (conn->backend_from_group)
        record_group_success(conn->backend_host, conn->backend_port);
    else
        record_backend_success(conn->backend_idx);
}

bool proxy_instance::try_retry(proxy_client_connection* conn)
{
    if (conn->retries_remaining <= 0 || m_mesh.retry_count <= 0)
        return false;

    // Never retry after response data has started flowing to the client
    if (conn->response_started)
        return false;

    // Nor after the client has been answered, because handle_connect would
    // read the cancelled handshake's report as a failed connect and open a
    // fresh backend for a request already answered.
    if (conn->closing)
        return false;

    // Only idempotent methods unless retry_all, with OPTIONS added because the
    // man page has always named it and the code was the half that was wrong --
    // TRACE stays out as a behaviour change nobody asked for.
    if (!m_mesh.retry_all)
    {
        if (conn->method != "GET" && conn->method != "HEAD" &&
            conn->method != "PUT" && conn->method != "DELETE" &&
            conn->method != "OPTIONS")
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
            if (old_bconn->pipe_to_client[0] >= 0) close_tracked(old_bconn->pipe_to_client[0]);
            if (old_bconn->pipe_to_client[1] >= 0) close_tracked(old_bconn->pipe_to_client[1]);
            old_bconn->pipe_to_client[0] = -1;
            old_bconn->pipe_to_client[1] = -1;

            shutdown(conn->backend_fd, SHUT_RDWR);
            close_tracked(conn->backend_fd);
            m_conn_idx[conn->backend_fd] = {};
            if (m_backend_slots[conn->backend_fd])
            {
                // A retry abandons the backend mid-request, so
                // backend_pool_release() keeps the struct out of the pool
                // until its completions land.
                backend_pool_release(std::move(m_backend_slots[conn->backend_fd]));
                m_backend_count--;
            }
        }
        conn->backend_fd = -1;

        // Close client's splice pipes too
        if (conn->pipe_to_backend[0] >= 0) close_tracked(conn->pipe_to_backend[0]);
        if (conn->pipe_to_backend[1] >= 0) close_tracked(conn->pipe_to_backend[1]);
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
        note_backend_selected(idx);

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

// The proxy-specific half of `stats`, every figure a walk of this process's
// own tables, which is why it still crosses the socket while the counters no
// longer do.
std::string proxy_instance::stats_lines() const
{
    // Use char buffer for integer formatting to avoid ostringstream overhead in stats path
    char num_buf[32];
    std::string out;
    out.reserve(256);

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

    // How many routes this proxy is enforcing out of what its backends
    // published, because a backend that declares nothing and a script that
    // failed to load look alike from the client side.
    out += "declared_routes:";
    auto [p2b, e2b] = std::to_chars(num_buf, num_buf + sizeof(num_buf), m_routes.size());
    out.append(num_buf, static_cast<size_t>(p2b - num_buf));
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

    // A group member has no index to be named by, so it is named by its
    // endpoint -- without which an operator looking at a 503 sees nothing
    // about the breaker refusing it.
    for (const auto& [key, cb] : m_group_breakers)
    {
        if (cb.current == circuit_breaker::closed)
            continue;
        out += "member_";
        // host_port, not host:port — every other line here is one key, one
        // colon, one value, and a second colon in the middle of a key is the
        // kind of thing a reader gets wrong once and then forever.
        for (const char c : key)
            out += (c == ':' ? '_' : c);
        out += "_circuit:";
        out += (cb.current == circuit_breaker::open ? "open" : "half_open");
        out += '\n';
    }

    return out;
}

std::string proxy_instance::peer_ip(int client_fd)
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

// Whether there was a client connection here to close, with three silent
// returns of which the backend half is the one a script gets wrong, because
// both halves are ints.
bool proxy_instance::close_client(int client_fd)
{
    if (client_fd < 0 || client_fd >= MAX_FDS) return false;
    auto& ce = m_conn_idx[client_fd];
    if (ce.side != conn_client) return false;
    auto* conn = ce.client;
    if (conn->closing) return false;
    // force: the script asked for this connection to be closed, and
    // self.close_client() promising to close is the whole of its contract.
    close_pair(client_fd, conn->backend_fd, close_reason::force);
    return true;
}

std::vector<std::string> proxy_instance::backends() const
{
    std::vector<std::string> result;
    result.reserve(m_backends.size());
    for (const auto& b : m_backends)
        result.push_back(b.address);
    return result;
}

std::vector<std::pair<int, std::string>> proxy_instance::backend_health_report() const
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

std::vector<int> proxy_instance::clients() const
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
    // Every path out that does not deliver takes the client down with it,
    // because a connection that silently swallows data is worse than one that
    // drops.
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
    // The pairing has to be mutual, because a descriptor number does not prove
    // identity and forwarding into somebody else's backend delivers this
    // request on a stranger's connection.
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
        // A hook that raised has not said carry on, so it refuses -- by
        // closing rather than a 500, because this is the byte path -- and it
        // is a protected call, because a try/catch reported nothing at all in
        // the Sanitize build.
        sol::protected_function_result r = lctx->on_proxy_request()(conn->fd, data);

        if (SOCKETLEY_UNLIKELY(!r.valid()))
        {
            sol::error err = r;
            fprintf(stderr, "%s on_proxy_request error: %s — refusing the "
                            "request\n",
                    lua_diag::tag(get_name()).c_str(), err.what());
            bconn->closing = true;
            conn->closing = true;
            return;
        }

        // Saying nothing is not saying nil, because a hook that only logs ends
        // without a return and reading that as nil emptied the connection --
        // while explicit nil stays the documented way to drop a chunk.
        if (r.return_count() > 0)
        {
            sol::object obj = r;
            if (obj.get_type() == sol::type::nil) return;   // drop

            if (SOCKETLEY_LIKELY(obj.is<std::string>()))
            {
                hook_storage = obj.as<std::string>();
                hook_modified = true;
            }
            else
            {
                // Refused rather than forwarded, the same answer the filter
                // chain gives a value it cannot read, because `return false`
                // meant as a rejection must not be an admission.
                fprintf(stderr, "%s on_proxy_request returned a %s; expected "
                                "a string or nil — refusing the request\n",
                        lua_diag::tag(get_name()).c_str(),
                        lua_typename(lctx->state().lua_state(),
                                     static_cast<int>(obj.get_type())));
                bconn->closing = true;
                conn->closing = true;
                return;
            }
        }
    }
#endif

    SKL_TRACE_ADD(bconn, bytes_queued, (unsigned long long)data.size());
    if (SOCKETLEY_UNLIKELY(bconn->write_queue.bytes() >= socketley::write_queue_max_bytes))
    {
        // The backend is not draining and the queue has hit its bound, and
        // marking only the backend left the client writing into a void.
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

    // Undeliverable, and marking is all this may do, because the callers go on
    // using conn and the read handlers tear the pair down when they see
    // closing.
    if (!bconn->write_pending && !flush_backend_write_queue(bconn))
        conn->closing = true;
}

// A refused response marks both sides, because only the running handler's own
// completion acts on the flag and handle_backend_read tests the backend's --
// so the pair was left up with a client waiting for ever on a truncated
// answer.
void proxy_instance::refuse_response(proxy_backend_connection* bconn,
                                     proxy_client_connection* cconn)
{
    cconn->closing = true;
    bconn->closing = true;
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

    // --idle-timeout is measured by the client's own reads, which is right for
    // a request/response exchange and wrong for a tunnel, where a
    // one-directional stream reads as perfectly idle while it is delivering.
    if (SOCKETLEY_UNLIKELY(m_idle_timeout_cached > 0) &&
        conn->http_frame.switched_protocols)
        cconn->last_activity = std::chrono::steady_clock::now();

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
        // The same rule on the way back, because forwarding the backend's
        // bytes unchanged when the redactor raised delivers exactly the
        // response the hook existed to prevent.
        sol::protected_function_result r =
            lctx->on_proxy_response()(conn->client_fd, data);

        if (SOCKETLEY_UNLIKELY(!r.valid()))
        {
            sol::error err = r;
            fprintf(stderr, "%s on_proxy_response error: %s — refusing the "
                            "response\n",
                    lua_diag::tag(get_name()).c_str(), err.what());
            refuse_response(conn, cconn);
            return;
        }

        // The request hook's reasoning unchanged: an empty return is an
        // observer and forwards, an explicit nil is a refusal and drops.
        if (r.return_count() > 0)
        {
            sol::object obj = r;
            if (obj.get_type() == sol::type::nil) return;   // drop

            if (SOCKETLEY_LIKELY(obj.is<std::string>()))
            {
                hook_storage = obj.as<std::string>();
                hook_modified = true;
            }
            else
            {
                fprintf(stderr, "%s on_proxy_response returned a %s; expected "
                                "a string or nil — refusing the response\n",
                        lua_diag::tag(get_name()).c_str(),
                        lua_typename(lctx->state().lua_state(),
                                     static_cast<int>(obj.get_type())));
                refuse_response(conn, cconn);
                return;
            }
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

    queue_final_response(conn, std::move(response));
}

// See the declaration for why the status is chosen here, which is the whole of
// what `ours` buys the client -- a local shortage and a dead backend used to
// reach it as the same 502.
bool proxy_instance::client_answerable(const proxy_client_connection* conn) const
{
    // TCP mode is exempt on principle, because there is no status line on that
    // path and inventing something would be worse than the silence.
    if (m_protocol != protocol_http || !conn)
        return false;
    // Already answered, or on its way out carrying an answer.
    if (conn->closing)
        return false;
    // Bytes of a backend's response are already on this client's wire, so a
    // status line behind them is the middle of somebody else's message and the
    // close is the honest answer.
    if (conn->response_started)
        return false;
    return true;
}

// The buffered request has outgrown what this proxy will hold, which is not
// the malformed-input path it looks like.
bool proxy_instance::answer_request_too_large(proxy_client_connection* conn)
{
    if (!client_answerable(conn))
        return false;
    send_error(conn, "413 Request Entity Too Large", "Request Too Large\n");
    return true;
}

bool proxy_instance::answer_gateway_failure(proxy_client_connection* conn, bool ours)
{
    if (!client_answerable(conn))
        return false;
    if (ours)
        send_error(conn, "503 Service Unavailable", "Service Unavailable\n");
    else
        send_error(conn, "502 Bad Gateway", "Bad Gateway\n");
    return true;
}

// The tail of every response this proxy produces on its own account, a
// function because the filter chain answers requests too and a second exit
// would skip the two things below.
void proxy_instance::queue_final_response(proxy_client_connection* conn,
                                          std::string&& response)
{
    conn->write_queue.push(std::move(response));
    conn->closing = true;

    // conn->closing is already set, so a body that cannot reach the ring
    // simply never goes out and the caller's teardown proceeds either way.
    if (!conn->write_pending && !flush_client_write_queue(conn))
        conn->write_queue.clear();

    // Saying "Connection: close" is not closing it, because under multishot
    // recv a read is pending for the connection's life -- so an error response
    // was the cheapest way there is to hold one open, and the half-close is
    // what ends it.
    shutdown(conn->fd, SHUT_RD);
}

// ─── TLS record layer ───────────────────────────────────────────────────────
// Ciphertext in and plaintext into conn->partial, one call per read
// completion, which is what makes the handshake asynchronous with nothing
// blocking.
template <typename Conn>
void proxy_instance::tls_feed(Conn* conn, const char* data, size_t len)
{
    // Inbound ciphertext into the read BIO, whose refusal is fatal by contract
    // because there is nowhere to hold what was not taken.
    size_t off = 0;
    while (off < len)
    {
        const int n = tls_context::bio_write_in(conn->ssl, data + off,
                                                static_cast<int>(len - off));
        if (SOCKETLEY_UNLIKELY(n <= 0))
        {
            conn->closing = true;
            return;
        }
        off += static_cast<size_t>(n);
    }

    if (conn->tls_state == tls_conn_handshake)
    {
        const int r = tls_context::do_handshake(conn->ssl);
        if (SOCKETLEY_UNLIKELY(r < 0))
        {
            // Closing but not silently, because the alert is the only
            // diagnosis the other end gets -- and on the backend leg this is
            // also where a certificate is rejected, answered 502 rather than
            // forwarded in the clear.
            conn->closing = true;
            return;
        }
        if (r == 0)
            return;   // another round; its records go out with the flush below

        conn->tls_state = tls_conn_ready;
        // Deliberately falling through rather than returning: the same read can
        // already carry application data behind the handshake's last flight —
        // under TLS 1.3 a peer's Finished and its first message routinely
        // arrive in one packet, and returning here would leave that message
        // sitting in the BIO until something else was sent.
    }

    char plain[16384];
    bool over_ceiling = false;
    for (;;)
    {
        const int n = tls_context::ssl_read(conn->ssl, plain, sizeof(plain));
        if (SOCKETLEY_LIKELY(n > 0))
        {
            conn->partial.append(plain, static_cast<size_t>(n));
            // The same ceiling the cleartext path applies, checked inside the
            // loop rather than after it: one read completion can decrypt
            // everything the inbound BIO had buffered, so "one read cannot
            // produce more than one buffer's worth" is not true here.
            if (SOCKETLEY_UNLIKELY(conn->partial.size() > Conn::MAX_PARTIAL_SIZE))
            {
                over_ceiling = true;
                break;
            }
            continue;
        }
        if (n < 0)
        {
            // Either the peer's close_notify or an unusable record, recorded
            // and applied by the caller once the bytes decrypted above have
            // been delivered.
            conn->tls_peer_closed = true;
        }
        break;
    }

    // The ceiling's answer, produced here because a TLS connection never
    // reaches the cleartext site -- before `closing`, since
    // client_answerable() refuses a connection already on its way out, and
    // only for the client half.
    if (SOCKETLEY_UNLIKELY(over_ceiling))
    {
        if constexpr (std::is_same_v<Conn, proxy_client_connection>)
            answer_request_too_large(conn);
        conn->closing = true;
    }
}

template <typename Conn>
bool proxy_instance::tls_owes_output(const Conn* conn)
{
    return conn->ssl != nullptr && tls_context::has_pending_out(conn->ssl);
}

// Every byte this connection sends is a TLS record, including the ones nobody
// queued, and there is no other way onto the wire.
template <typename Conn>
bool proxy_instance::tls_flush(Conn* conn)
{
    if (SOCKETLEY_UNLIKELY(!m_loop || !conn->ssl))
        return true;

    // One write in flight at a time, because a second submission would need a
    // second buffer and would interleave two record streams on one socket.
    if (conn->write_pending || conn->zc_notif_pending)
        return true;

    // Application data only once the handshake is done, so a request queued
    // during it waits rather than being handed to an SSL that answers
    // WANT_READ.
    if (conn->tls_state == tls_conn_ready)
    {
        while (!conn->write_queue.empty())
        {
            const std::string& msg = conn->write_queue.front();
            const int n = tls_context::ssl_write(conn->ssl, msg.data(),
                                                 static_cast<int>(msg.size()));
            if (n <= 0)
            {
                // 0 is backpressure and the same buffer is offered again once
                // the write BIO drains, which leaving the message at the front
                // of the queue arranges; -1 is fatal.
                if (n < 0)
                    conn->closing = true;
                break;
            }
            // Partial writes are not enabled on this context, so a short count
            // would mean the record layer and this queue disagree about what
            // has been sent.
            if (SOCKETLEY_UNLIKELY(static_cast<size_t>(n) != msg.size()))
            {
                conn->closing = true;
                break;
            }
            conn->write_queue.pop();
        }
    }

    if (!tls_context::has_pending_out(conn->ssl))
        return true;

    // Ciphertext copied out of the write BIO into a buffer this connection
    // owns, because the BIO's storage moves under an SQE -- and it rides in
    // write_batch[0] so the retry paths need no TLS case.
    std::string cipher;
    char buf[16384];
    for (;;)
    {
        const int n = tls_context::bio_read_out(conn->ssl, buf, sizeof(buf));
        if (n <= 0)
            break;
        cipher.append(buf, static_cast<size_t>(n));
    }
    if (SOCKETLEY_UNLIKELY(cipher.empty()))
        return true;

    // Nothing is in flight (checked above), so any batch entries still held are
    // from a completed write and are this function's to drop.
    for (uint32_t i = 0; i < conn->write_batch_count; i++)
        conn->write_batch[i].clear();

    conn->write_batch[0] = std::move(cipher);
    conn->write_iovs[0].iov_base = conn->write_batch[0].data();
    conn->write_iovs[0].iov_len  = conn->write_batch[0].size();
    conn->write_batch_count = 1;
    conn->write_pending = true;
    conn->write_req.type = op_write;

    const auto len = static_cast<uint32_t>(conn->write_batch[0].size());
    if (SOCKETLEY_UNLIKELY(!m_loop->submit_write(conn->fd, conn->write_batch[0].data(),
                                                 len, &conn->write_req)))
    {
        // Nothing reached the ring, so the in-flight bookkeeping is undone and
        // reported, because a write_pending that never clears keeps the
        // teardown waiting.
        conn->write_pending = false;
        conn->write_batch[0].clear();
        conn->write_batch_count = 0;
        return false;
    }
    return true;
}

// False when nothing reached the ring, after which the pending flag is cleared
// and the batch dropped, because the difference is a closed connection rather
// than a hung one.
bool proxy_instance::flush_client_write_queue(proxy_client_connection* conn)
{
    // A TLS connection's bytes go through the record layer, which keeps every
    // caller above from having to know which kind of connection it holds.
    if (SOCKETLEY_UNLIKELY(conn->ssl != nullptr))
        return tls_flush(conn);

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

// False when nothing reached the ring, after which the pending flag is cleared
// and the batch dropped, because the difference is a closed connection rather
// than a hung one.
bool proxy_instance::flush_backend_write_queue(proxy_backend_connection* conn)
{
    // See flush_client_write_queue: on a TLS backend leg the record layer is
    // the only thing that writes, and it is also what holds a request back
    // until the handshake behind it has finished.
    if (SOCKETLEY_UNLIKELY(conn->ssl != nullptr))
        return tls_flush(conn);

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
                // The remainder of a short write cannot be handed over,
                // because leaving write_pending set strands the connection
                // mid-message.
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

    // A TLS connection can owe the wire bytes with an empty queue, and asking
    // only about the queue is how a handshake stalls one round short.
    if ((!conn->write_queue.empty() || tls_owes_output(conn)) && !conn->zc_notif_pending)
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
                // The remainder of a short write cannot be handed over,
                // because leaving write_pending set strands the connection
                // mid-message.
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

    // See handle_client_write: the record layer owes bytes the queue cannot
    // account for.
    if ((!conn->write_queue.empty() || tls_owes_output(conn)) && !conn->zc_notif_pending)
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
        if (se.side == conn_client && se.client->splice_active && conn->splice_active &&
            !se.client->client_eof)
            start_splice_forwarding(se.client, conn);
    }

    // The client's half-close, held back for exactly the same reason and let go
    // at exactly the same moment: the last of what it sent has now reached this
    // socket, so the FIN that terminates it can no longer overtake anything.
    if (conn->client_fd >= 0 && conn->client_fd < MAX_FDS)
    {
        auto& he = m_conn_idx[conn->client_fd];
        if (he.side == conn_client && he.client->backend_fd == conn->fd)
            forward_client_half_close(he.client);
    }

    // Backpressure resume, never onto a socket that reported end of stream,
    // because a read armed there completes res=0 at once and re-enters the
    // loop the EOF branch documents.
    if (conn->write_queue.bytes() < socketley::write_queue_backpressure_bytes &&
        conn->client_fd >= 0 && conn->client_fd < MAX_FDS)
    {
        auto& ce = m_conn_idx[conn->client_fd];
        if (ce.side == conn_client && !ce.client->read_pending &&
            !ce.client->closing && !ce.client->splice_active &&
            !ce.client->client_eof)
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
