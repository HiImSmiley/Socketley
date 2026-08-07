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


// Which endpoint a client's current backend socket is connected to.  Returns
// false when that cannot be established, and then the socket must not be
// pooled: a pooled connection is handed to whoever asks for the same endpoint
// next, so a key that is a guess is a crossed delivery waiting to happen.
//
// backend_idx answers this only for a plain backend.  A group-routed request
// picks one member per request and leaves the index pointing at the group
// entry, whose resolved_host is deliberately empty — the endpoint that was
// actually chosen is recorded on the connection.
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
    return !host.empty() && port != 0;
}

// "The ring still owes this half a completion."
//
// One statement of it, for the question a deferred teardown asks: may this
// descriptor be held back, because something will come back and finish what is
// queued on it?  A deferral without that is a promise nothing keeps, and a
// promise nothing keeps is how a pair ends up holding its descriptors until the
// runtime stops.
//
// Deliberately the same predicate inv_check_pair asserts on — see
// shared/invariants.h.  The invariant is the specification for these two; if
// they ever disagree with it, they are the ones that are wrong.
//
// It answers that question and no other.  In particular it does not answer
// "does this client still have an answer coming", which is what deciding to
// hold a half-closed client turns on: a backend read stays armed across
// completions under multishot recv, so this reads true for a backend that owes
// nothing at all.  handle_client_read asks that one for itself, out of the
// state that describes the exchange rather than the ring.
static inline bool client_op_in_flight(const proxy_client_connection* c)
{
    return c->read_pending || c->write_pending || c->zc_notif_pending ||
           c->splice_in_pending || c->splice_out_pending || c->connect_pending ||
           c->abort_watch_pending;
}

static inline bool backend_op_in_flight(const proxy_backend_connection* b)
{
    return b->read_pending || b->write_pending || b->zc_notif_pending ||
           b->splice_in_pending || b->splice_out_pending;
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
    // m_loop while running, m_retired_loop once teardown has cleared it — the
    // descriptors closed after a stop are exactly the ones the ring is most
    // likely to still be naming, so falling back to plain close() there would
    // leave the hazard open on the worst case.
    event_loop* lp = m_loop ? m_loop : m_retired_loop;
    if (SOCKETLEY_LIKELY(lp != nullptr))
        lp->close_fd(fd);
    else
        close(fd);
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
    // client_pool_release() already did this; repeated here because a struct
    // leaving the pool must not carry the previous connection's session under
    // any circumstances, and this is the last point at which that can still be
    // true.
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
    // Not close_tracked(): this is a struct method with no loop to ask, and by
    // construction there is nothing to ask about.  A struct only reaches reset()
    // through client_pool_release(), which closes both pipes and sets them to -1
    // first, so these two are a guard against a path that does not exist rather
    // than a close the ring could still be naming.  A new such path must close
    // its pipes through proxy_instance::close_tracked, not here.
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
    backend_from_group = false;
    backend_host.clear();
    backend_port = 0;
    connect_pending = false;
    connect_fd = -1;
    connect_req = {};
    abort_watch_pending = false;
    abort_req = {};
    awaiting_response = false;
    response_deadline = {};
    awaiting_headers = false;
    header_deadline = {};
    std::memset(&connect_addr, 0, sizeof(connect_addr));
}

void proxy_backend_connection::reset(int new_fd)
{
    SKL_TRACE_RESET(*this);
    SKL_INV_RESET(*this);
    // Process-wide, not a per-struct count: both check sites resolve the struct
    // by descriptor first, so a per-struct counter is compared against a
    // different object's value once a descriptor moves between structs — and
    // with a small pool those values sit in a narrow band, so agreeing by
    // accident is common rather than rare.
    generation = next_io_generation();
    fd = new_fd;
    // See proxy_client_connection::reset.  It matters more here: backend fds
    // are pooled as well as backend structs, so a session left behind would be
    // the session of a *different peer*.
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
    // The splice pipes go back to the kernel here even when the struct does not.
    // Leaving the descriptors to a struct that may sit retired for minutes leaks
    // two of them per connection.
    //
    // The justification used to be that "a splice already in flight keeps
    // working on the file it was handed at submission time, exactly as an armed
    // read does after its socket is closed, so nothing is lost".  That is true
    // of a submission the kernel has consumed and false of one it has not — and
    // a pipe number is reissued as readily as a socket number, so a queued
    // splice could find another connection's pipe at the other end.  It is
    // close_tracked() that makes the sentence true now, by not handing the
    // number back until the ring has stopped naming it.
    if (conn->pipe_to_backend[0] >= 0) { close_tracked(conn->pipe_to_backend[0]); conn->pipe_to_backend[0] = -1; }
    if (conn->pipe_to_backend[1] >= 0) { close_tracked(conn->pipe_to_backend[1]); conn->pipe_to_backend[1] = -1; }

    // The TLS session dies with the connection that owned it, whether the
    // struct goes back to the pool or is retired with completions still owed.
    // No completion can name it — every byte the ring carries was copied out
    // of a BIO first — so unlike the write batch beside it this needs none of
    // the "wait until the kernel is finished" reasoning below.
    tls_context::free_ssl(conn->ssl);
    conn->ssl = nullptr;
    conn->tls_state = tls_conn_none;
    conn->tls_peer_closed = false;

    // The half-open connect socket goes the same way, and for the same reason.
    // Every caller closes it before getting here, but nothing downstream would:
    // reset() only sets connect_fd to -1, so a struct that ever reached the pool
    // still carrying one lost that descriptor for good, and a retired struct
    // would hold it until its last completion landed — which, once the runtime
    // is stopped and its completions are dropped, is never.  This is the funnel;
    // it is the place that has to know.
    //
    // The explicit cancel that stood here is close_fd's job now: it submits one
    // only when something is actually armed, and — unlike a cancel followed
    // straight away by close() — holds the number until that cancel has been
    // consumed, so it cannot be resolved against whoever inherits the number.
    close_tracked(conn->connect_fd);
    conn->connect_fd = -1;

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
        // The abort watch is a poll, and a poll survives the close of the
        // descriptor it is armed on — it holds its own reference to the file.
        // Its completion is owed exactly like the rest.
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

    // And the session, for the reason in client_pool_release.  The descriptor
    // this struct was using may go on to the connection pool; the session it
    // negotiated may not, and does not outlive this call.
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
    // Straight assignment, on the event-loop thread.  A connection already
    // being routed keeps the table it started with: the pool it built is a copy
    // of the endpoints, and the shared_ptr it came from stays alive as long as
    // anything holds it.
    m_endpoints = std::move(tbl);

    // What the new snapshot says this proxy's backends will answer.  Here and
    // in setup(), which are the only two moments it can change: the table is
    // republished whenever a runtime starts, stops, is created, removed,
    // renamed or has its script reloaded, and setup() covers a proxy whose own
    // backends were configured after the last publication.
    rebuild_route_view();

    // Whatever the pool still holds to a member that is no longer in the group
    // is dead weight: selection will never ask for that endpoint again, so the
    // socket would sit there until the idle sweep reached it a minute later —
    // and the runtime on the other end is usually stopping, which is what took
    // it out of the group.  Holding its socket open keeps it in TIME_WAIT
    // negotiations it has no reason to be in and keeps a descriptor at both
    // ends for nothing.  The breakers go the same way and for the same reason:
    // a verdict about an endpoint that is no longer being routed to has nothing
    // left to say, and dropping it here is what keeps that map the size of the
    // group rather than the size of its history.
    drop_departed_endpoints();
}

// The declarations of the backends this proxy forwards to, folded into one
// table.  Called only when the published snapshot changes or the runtime
// starts, never per request.
//
// One silent backend is enough to leave this proxy enforcing nothing, and that
// is deliberate rather than a limitation.  A backend written as a bare
// host:port has no entry in the snapshot and never will — it is keyed by
// runtime name and by group, and an address is neither — so this proxy has no
// basis whatever on which to claim it knows what that server answers.  Refusing
// a method at the edge while one of the possible targets might have served it
// is the one failure this feature must not have; forwarding as before is the
// safe half of the fork.  See route_table::merge_alternative.
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

    // A scheme says how to reach this backend, not only where.  "https://" is
    // how one backend is asked for over TLS while its neighbours stay
    // cleartext; the backend-TLS options ask for it everywhere at once and
    // have already set b.tls before this runs, so this only ever turns it on.
    //
    // The scheme stays on b.address, which is what `stats` and the Lua API
    // report: an operator reading that back has to see what they configured.
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
    // A scheme with no port is a URL, and a URL's port is implied rather than
    // absent.  Without this it would fall through to the runtime-name lookup
    // below and be reported as an unknown runtime, which is a confusing answer
    // to something an operator wrote as a perfectly ordinary address.
    const bool have_endpoint = (colon != std::string_view::npos) ||
                               (default_port != 0 && !addr.empty());
    if (have_endpoint)
    {
        if (colon != std::string_view::npos)
        {
            b.resolved_host = std::string(addr.substr(0, colon));
            const char* pstart = addr.data() + colon + 1;
            const char* pend   = addr.data() + addr.size();
            std::from_chars(pstart, pend, b.resolved_port);
        }
        else
        {
            b.resolved_host = std::string(addr);
            b.resolved_port = default_port;
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
            // If DNS fails at setup, connect_to_backend will retry with blocking DNS
        }
        return true;
    }

    // A bare runtime name.  This used to call runtime_manager::get() and read
    // get_port() off the instance it returned; the manager now publishes that
    // number instead, so nothing here holds a pointer into another runtime.
    if (!m_endpoints)
        return false;

    const runtime_endpoint* ep = m_endpoints->find_name(b.address);
    if (!ep || ep->port == 0)
        return false;

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

// Report every splice pipeline on this process that has bytes somewhere and has
// not moved in a while.  The two states this exists to tell apart:
//
//   sock_unread>0, in_pend=1   the splice is armed, the data is on the socket,
//                              and the kernel has not answered.
//   pipe>0,        in_pend=0   the kernel moved the bytes and the completion
//                              that would have pushed them on never arrived.
//
// Which of the two it is names the hop, and neither is visible from the flags.
// How many io-wq worker threads this process currently has, and how many of
// them are not runnable.  Every IORING_OP_SPLICE is prepped REQ_F_FORCE_ASYNC by
// the kernel, so it never runs on the submitter: it is handed to an io-wq
// worker, which then sits inside splice() until the socket has data.  A splice
// armed on a quiet socket therefore *holds a thread*, and how many threads there
// are is not something this process ever asked for or can see from the ring.
// `parked` counts the workers sitting in wait_woken — the wait sk_wait_data
// uses, i.e. a worker inside tcp_splice_read with no data yet.  Those are the
// ones a splice armed on a quiet socket is holding.
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

// NOTHING HERE MAY ioctl() A PIPE.  A splice from a socket into a pipe holds
// that pipe's mutex for the whole time it is waiting for the socket to produce
// data (splice_file_to_pipe takes pipe_lock around the socket read), and
// FIONREAD on a pipe takes the same mutex.  Asking that question from this
// thread puts the event loop into uninterruptible sleep until some client
// happens to send a byte — the whole daemon, for every runtime on the loop.
// Measured: a probe that did exactly this wedged the daemon permanently and
// every one of its threads read D / pipe_ioctl.  The socket ioctls below are
// safe because sk_wait_data drops the socket lock while it waits.
void proxy_instance::trace_splice_sweep()
{
    const double now = ::skl_trace::now_ms();

    // Armed splices across every proxy on this loop, against the number of
    // io-wq threads there are to run them.  A splice only ever runs on an io-wq
    // worker, and one waiting on a quiet socket holds its worker for the whole
    // wait, so these two numbers are the supply and the demand.
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
    // Kept across teardown: a descriptor closed after a stop still has to be
    // checked against the ring, and m_loop is null exactly then.
    m_retired_loop = &loop;

    if (m_backends.empty())
        return false;

    // ── TLS ─────────────────────────────────────────────────────────────────
    //
    // Certificates are read and parsed here, at setup, before a single
    // completion is armed.  That is file I/O and it blocks, which is exactly
    // why it happens here and nowhere near the event loop's hot path: neither
    // handshake ever touches a file, and neither touches a socket either — see
    // tls_feed/tls_flush.
    //
    // Every refusal below returns false, which puts the runtime in the failed
    // state.  None of them may fall through to a cleartext leg: a
    // configuration that asked for encryption and got a plaintext port, or a
    // plaintext request sent to a backend, is the one outcome the operator
    // cannot see.
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
            // it.  This says what it cost.
            LOG_ERROR("proxy: TLS listener not started -- the certificate, key or "
                      "client CA could not be loaded");
            return false;
        }
        m_tls = std::move(ctx);
    }

    // The backend-TLS options apply to every backend at once.  None of them
    // means anything against a cleartext peer — a trust store with nothing to
    // verify, a client certificate nobody is asked for — so honouring them
    // without encrypting the leg would be the fail-open reading of all three.
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
        // --health-check http used to be refused here, because the probe wrote
        // a plaintext GET straight at the backend socket and a TLS backend
        // answers that with a handshake failure: every backend would have been
        // marked unhealthy while they were all fine.  The probe handshakes now
        // — see handle_health_cqe — so the refusal is gone and the only thing
        // left to say is that the context below is what it verifies against.
        auto ctx = std::make_unique<tls_context>();
        // --ca is this leg's trust store; without one the system store is used.
        // Either way the chain is verified and the endpoint's name is checked
        // per connection (see start_backend_tls) -- there is deliberately no
        // way to turn either off.
        if (!ctx->init_client(get_ca_path(), m_mesh.client_cert, m_mesh.client_key))
        {
            LOG_ERROR("proxy: TLS backend leg not started -- the CA file or the client "
                      "certificate could not be loaded");
            return false;
        }
        m_backend_tls = std::move(ctx);
    }

    m_avail_scratch.reserve(m_backends.size());

    // The backends are known now.  set_endpoints() builds this too, but a
    // proxy is configured and then started, so the last publication before
    // start() may have arrived while m_backends was still empty — and a view
    // built from no backends is a proxy that enforces nothing.
    rebuild_route_view();

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

    // SOCK_CLOEXEC: in the daemon this listener belongs to one proxy and must
    // not reach any worker the daemon forks for another; in a worker it is the
    // only listener there is, opened after the exec from the config frame, so
    // the flag costs it nothing.  Same reasoning as the server's listener.
    m_listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
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

    // Initialize connection pool (one pool per backend).
    //
    // teardown() empties this, so by the time a start gets here there should be
    // nothing to give up — but clear() on a vector of entries that own a
    // descriptor and a session would leak both silently, and "should be" is not
    // a reason to write the version that leaks if it is ever wrong.  This is
    // also the point past which a pooled session must not survive: the backend
    // tls_context above has just been rebuilt, so anything still on a shelf was
    // verified against a trust store that is no longer the one in force.
    for (auto& pool : m_backend_pool)
        for (auto& pb : pool)
            discard_pooled(pb, true);
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
#ifdef SOCKETLEY_TRACE
    trace_unregister(this);
#endif
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

    // Shutdown before closing.  A multishot accept holds its own reference to
    // the socket, so close() does not end it and the terminating completion
    // never arrives — which leaves the loop counting one operation this owner
    // still owes, forever.  reap_retired waits for that count to reach zero, so
    // the whole instance was never freed: about 6 MB per removed runtime, held
    // until the daemon exited.  shutdown() also ends the listen state, which is
    // what takes the socket out of the SO_REUSEPORT group so a restart's bind
    // is not competing with it.
    //
    // The explicit cancel-and-flush that used to stand here is gone into
    // close_fd, which submits the same cancel and — unlike a flush, which under
    // SQPOLL does not even make a syscall — holds the descriptor number until
    // both the accept and the cancel have actually reported.
    if (m_listen_fd >= 0)
    {
        shutdown(m_listen_fd, SHUT_RDWR);
        close_tracked(m_listen_fd);
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
        close_tracked(i);
        backend_pool_release(std::move(conn));
    }

    for (int i = 0; i < MAX_FDS; i++)
    {
        auto& conn = m_client_slots[i];
        if (!conn) continue;
        // A connect that has not finished is waiting on POLLOUT, and closing
        // the socket does not take that back — the poll holds its own reference
        // and would otherwise report minutes later, when TCP finally gives up.
        // close_fd submits that cancel, and holds the number until both it and
        // the poll have reported rather than freeing it the instant the cancel
        // is queued.
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

    // Close pooled backend connections, and free the sessions the encrypted
    // ones are holding.  This runs before start() can build a new
    // tls_context, which is what makes an entry outliving the context that
    // produced it impossible rather than merely unlikely — and
    // acquire_pooled_backend checks tls_owner anyway, because "impossible"
    // here means "impossible given the order of two functions".
    for (auto& pool : m_backend_pool)
    {
        for (auto& pb : pool)
            discard_pooled(pb, true);
        pool.clear();
    }

    // Withdraw every timer this run armed, before they are retired below.
    //
    // Nothing above reached them: a timeout hangs off no descriptor, so the
    // shutdown()s and the cancel on the listen fd walked straight past, and the
    // ring went on owing this owner one completion per armed timer for as long
    // as the interval — thirty seconds for the sweep.  reap_retired() frees a
    // removed instance only once that count reaches zero, so it never did, and
    // the whole proxy stayed in the graveyard: about 6 MB, held until the daemon
    // exited.
    //
    // A withdrawal does not take the completion away, it brings it forward: the
    // timeout reports once more with -ECANCELED, which is the completion the
    // retire() below is already waiting for, so every `owed` count here stays
    // exactly as it was.  Withdrawing only where a completion is genuinely owed
    // matters for the same reason — the cancelled timeout is delivered carrying
    // the address of its request, and retire() with a count of zero would have
    // freed the storage that address points into.
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
    // Remembered before the dispatch: the handler may release the struct and
    // the request along with it.  Only per-connection operations name a pair —
    // an accept, a timer or a health probe does not.
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

                // Evict stale pooled connections.  This half runs for every
                // proxy, configured idle timeout or not: the pool is the only
                // place a backend socket can sit with nobody watching it.
                bool pooled_left = false;
                for (auto& pool : m_backend_pool)
                {
                    pool.erase(
                        std::remove_if(pool.begin(), pool.end(),
                            [&](pooled_backend& pb) {
                                bool stale = (now - pb.idle_since) >
                                             std::chrono::seconds(POOL_IDLE_TIMEOUT_SEC);
                                // discard_pooled, so that a session ages out
                                // with the descriptor it belongs to.  A pool
                                // entry freed anywhere but there is the one
                                // that leaks an SSL.
                                if (stale)
                                    discard_pooled(pb, true);
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
            // Backend response deadline sweep.  As above: this link has spoken,
            // so the sweep is free to arm the next one when there is still
            // something outstanding to watch.
            else if (m_response_sweep_timer && req == &m_response_sweep_timer->req)
            {
                m_response_sweep_armed = false;
                response_deadline_sweep();
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
    // Charged here rather than inside the handlers, because the subject is the
    // completion and not what any one handler chose to do with it: a loop that
    // returns early down a path nobody instrumented is exactly the loop this is
    // for.  Every completion this runtime is dispatched, once.
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
// Declared here and defined beside handle_client_read, which is the reader that
// gives it its meaning.  Invariant (1b) has to ask the same question the hold in
// that function asks, out of the same predicate, or the invariant is not the
// specification for it.
static inline bool backend_response_complete(const proxy_backend_connection* bconn);
static inline bool client_answer_owed(const proxy_client_connection* cconn,
                                      const proxy_backend_connection* bconn);

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

    // Invariant (1b)'s two terms, and this runtime is the only thing that can
    // state them.  Both are read out of the exchange and neither out of the
    // ring — that distinction is the whole of the invariant, because the pair
    // that leaked passed (1) on the strength of an idle multishot read.
    //
    // They are deliberately the SAME two facts handle_client_read decides the
    // hold on, expressed once each: client_eof is set there and nowhere else,
    // and answer_owed is the predicate written three lines below where the hold
    // is taken.  The invariant is the specification and the hold is the
    // implementation; when they disagree, the hold is the one that is wrong.
    //
    // Stated only in HTTP mode.  A TCP pair has no request and no response, so
    // "an answer is owed" is not a question that can be asked about it — and it
    // is never held on a half-close either, for the same reason.
    skl_inv::exchange x{};
    if (cconn && m_protocol == protocol_http)
    {
        x.stated      = true;
        x.half_closed = cconn->client_eof;
        x.answer_owed = client_answer_owed(cconn, bconn);
    }

    SKL_INV_PAIR_X(where, c, b, x);
}

// Everything about a client connection a caller could observe, folded into one
// number: how much is buffered awaiting a parse, how much is queued to go out,
// where the request framing has got to, which backend it is bound to, and every
// lifecycle flag.  Change any one of them and this changes.
//
// The mixing is FNV-1a over the terms rather than a sum, so that two terms
// moving in opposite directions by the same amount is not a state that reads as
// unchanged.  Collisions are possible and cost a delayed report, never a false
// one: the digest is only ever compared with the immediately preceding value of
// itself on the same connection.
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

    // One word of flags.  A flag that flips and flips back between two
    // completions is invisible to this and says so in the header: the digest
    // compares against the previous value, not against a history.
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
    return inv_mix(h, f);
}

// Invariant (3) from invariants.h, in the form this runtime takes.
//
// The ledger is charged to the half the completion named, not to the pair.  A
// client parked while its backend answers receives no completions at all, so it
// accrues nothing and cannot be suspected; the half that is being completed over
// and over is the half that has to justify it.
void proxy_instance::inv_check_progress(int fd, int res, uint8_t type, const char* where)
{
    if (fd < 0 || fd >= MAX_FDS)
        return;

    // Only the operations that carry traffic report a byte count in res.  A
    // poll answers with a revents mask and a connect with nought, and counting
    // either as bytes moved would be a connection excused from the invariant for
    // the wrong reason.
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
    // Anything else is a connection the handler has just torn down.  There is
    // nothing left to make progress, and the ledger went with the struct.
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

        // A descriptor can come off the backlog already broken.  The handshake
        // completes in the kernel, so a client is free to connect, push a
        // payload and reset long before its turn to be accepted comes round —
        // and under a flood that is not the exception, it is nearly every
        // connection: the backlog is thousands deep and takes hundreds of
        // milliseconds to drain.  Everything below is then spent on a peer that
        // cannot receive one byte of the answer: seven socket options on the
        // client, a 64KB connection struct, a backend socket with seven more,
        // a TCP handshake, and the cancel and close that undo them.  One
        // getsockopt separates the two cases, and it costs a live connection
        // nothing — sk_err is zero there, so there is nothing to read and clear
        // and the abort watch armed later still has its POLLERR to report.
        //
        // The bytes such a client sent are dropped with it.  That is the same
        // answer the read paths already give — a reset is an abort, not a
        // half-close, and a half-close (FIN) leaves sk_err at zero and comes
        // through here untouched.
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
        // anybody else touches the connection, and in particular before
        // on_connect below and before the TCP-mode backend connect: whatever
        // those set in motion ends in bytes going to this client, and a
        // connection that did not know it was encrypted would send them in the
        // clear.
        //
        // The session is created here and the handshake starts on the first
        // read completion.  Nothing is written yet — the client speaks first.
        if (SOCKETLEY_UNLIKELY(m_tls != nullptr))
        {
            ptr->ssl = m_tls->create_ssl_server();
            if (SOCKETLEY_UNLIKELY(!ptr->ssl))
            {
                // No session, no encryption, so no connection.  Serving this
                // client in cleartext is the one alternative and it is worse
                // than dropping it.
                close_pair(client_fd, -1);
                goto proxy_resubmit_accept;
            }
            ptr->tls_state = tls_conn_handshake;
        }

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
                if (have_target && !ours) note_backend_failure(ptr);
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

// header_name_equals and http_eol_framing_ok used to live here.  Both are read
// by the response side as well as the request side, and the response side now
// lives in runtime/proxy/http_response_framing.h so that a fuzz target can call
// it — so they moved there too rather than being declared in two places.

// Walk one Transfer-Encoding field value left to right, carrying `chunked_seen`
// across the field lines of one request.  False means a coding was applied
// after chunked, i.e. chunked is not the final coding.
//
// Codings are a comma list, each optionally carrying parameters after a ';',
// and empty list elements are legal in an HTTP list and mean nothing.
static bool te_line_codings_ok(std::string_view hdr_line, bool& chunked_seen)
{
    const auto colon = hdr_line.find(':');
    if (colon == std::string_view::npos)
        return false;

    std::string_view val = hdr_line.substr(colon + 1);
    size_t pos = 0;
    for (;;)
    {
        const auto comma = val.find(',', pos);
        const size_t end = (comma == std::string_view::npos) ? val.size() : comma;
        std::string_view coding = val.substr(pos, end - pos);

        if (const auto semi = coding.find(';'); semi != std::string_view::npos)
            coding = coding.substr(0, semi);
        while (!coding.empty() && (coding.front() == ' ' || coding.front() == '\t'))
            coding.remove_prefix(1);
        while (!coding.empty() && (coding.back() == ' ' || coding.back() == '\t'))
            coding.remove_suffix(1);

        if (!coding.empty())
        {
            // Anything at all after the chunked coding — including a second
            // chunked, which RFC 9112 Section 6.1 forbids outright — means the
            // body is not framed by chunk sizes the way it claims to be.
            if (chunked_seen)
                return false;
            if (coding.size() == 7)
            {
                static constexpr char kChunked[] = "chunked";
                bool match = true;
                for (size_t i = 0; i < 7; i++)
                    if ((coding[i] | 0x20) != kChunked[i]) { match = false; break; }
                if (match)
                    chunked_seen = true;
            }
        }

        if (comma == std::string_view::npos)
            return true;
        pos = comma + 1;
    }
}

// backend_response_complete() moved to http_response_framing.h as
// http_response_frame_complete(), alongside the scan that produces the state it
// reads.  Both pooling paths still ask exactly one predicate; it is simply one
// a test can call.
static inline bool backend_response_complete(const proxy_backend_connection* bconn)
{
    return http_response_frame_complete(bconn->http_frame);
}

// "A request left this client for a backend and its answer has not come back."
//
// Three places have to agree on this and used to state it three times.
// handle_client_read decides on it whether to HOLD a half-closed client;
// handle_backend_read decides on it whether that hold is OVER; and invariant
// (1b) reports a pair that is held while it reads false.  Writing it once is
// what makes the invariant the specification for the hold rather than a second
// opinion about it — when the two disagree the hold is wrong, and they cannot
// disagree if there is only one of them.
//
// `bconn` is the backend this client is paired with, or null when it has none.
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

        // IORING_CQE_F_SOCK_NONEMPTY on a zero-length completion does NOT mean
        // there is data left to collect, and this is the one place it must not
        // be read that way.
        //
        // recv() on a stream socket returns 0 for exactly one reason: the peer
        // has shut its write side.  It hands back everything queued before it
        // will ever return 0, so "ended while data is still queued" is not a
        // shape `res == 0` can have.  The flag is set anyway, because what the
        // kernel puts in msg_inq is tcp_inq_hint() — rcv_nxt minus copied_seq —
        // and the FIN carries a sequence number of its own.  So the completion
        // that reports end of stream reports one byte outstanding, and that byte
        // is the FIN.  FIONREAD on the same socket in the same instant reads 0:
        // tcp_inq() subtracts the FIN and tcp_inq_hint() does not.  Measured on
        // every clean half-close this proxy sees: res=0, flags=0x4, FIONREAD=0.
        //
        // Re-arming on that was therefore not a guard against losing a request,
        // it was a loop: the read is armed on a socket at end of stream, the
        // kernel completes it immediately with res=0 and the same flag, and the
        // pair is never torn down and never reaches anything below.  Measured at
        // 1.35 million iterations on a single connection in one run of
        // test_proxy_group_keepalive_load, with the descriptors of the pair —
        // and of every runtime splicing behind it — held until the proxy
        // stopped.
        //
        // The genuine "the socket still has data" signal comes with res > 0 and
        // no IORING_CQE_F_MORE, which is a multishot that ended with the socket
        // non-empty, and the re-arm for it is further down where the data is
        // consumed.  Here res is zero, which is end of stream and nothing else.

        // A clean EOF from the client means it will send no more — not that we
        // may throw away what it already sent, or the answer to it.  The
        // request is at the backend, or on its way there; whatever it does
        // there HAPPENS, and closing the pair here is the one outcome the
        // client cannot act on.  It has shut down its write side only: it is
        // still reading, and the answer still has somewhere to go.
        //
        // What bounds the hold:
        //
        //   * it is the request's bound, not a new one.  A request that has
        //     reached connect_to_backend is being timed by --backend-timeout
        //     from that moment, half-close or no half-close, and
        //     response_deadline_sweep answers it 502/504 and closes when that
        //     expires.  This connection is held no longer than one that never
        //     half-closed at all;
        //   * no read is re-armed, so a client cannot buy time with a FIN.  It
        //     gets the answer to the request already in flight and nothing
        //     else: reset_client_for_next_request closes rather than waiting
        //     for a second request that by definition cannot come;
        //   * and it is held only while an answer is genuinely OWED.  That is
        //     the question, and "does the ring owe this backend a completion"
        //     is not it: under multishot recv a backend read is armed
        //     essentially all of the time — detach_and_pool_backend says so
        //     itself, three hundred lines down, and pools the socket on exactly
        //     that basis — so backend_op_in_flight() reads true for a backend
        //     sitting idle with its answer long since delivered, and the hold
        //     became unconditional.  What that cost: a client that sends
        //     `Connection: close`, is answered, and then closes.  Its pair is
        //     deliberately never detached (see handle_backend_read: a client
        //     that asked for the connection to close is not put back in the
        //     keep-alive pool), so reset_client_for_next_request is never
        //     called for it and the hold below has nothing that can ever end
        //     it.  The pair was held — client socket, backend socket, and the
        //     splice pipes of every runtime behind it — until the proxy
        //     stopped.  Measured: 13 pairs and 110 descriptors left over from
        //     one run of test_proxy_group_keepalive_load, on a check whose
        //     whole ceiling is 40 descriptors of slack.
        //
        //     So the two disjuncts below are the two states in which a request
        //     has gone and its answer has not arrived: it has not reached a
        //     backend yet, or a backend is attached and has not finished
        //     answering.  Nothing is held for a connection that has been
        //     answered — close_pair still defers on the write queue, so the
        //     tail of that answer goes out before the descriptor does.
        //
        //     What ends the hold in each: reset_client_for_next_request on the
        //     completed response, which closes on client_eof; and
        //     response_deadline_sweep with 502/504 when --backend-timeout
        //     expires.  With --backend-timeout 0 there is no sweep and the wait
        //     is unbounded — which is what that value is documented to mean,
        //     and it is the SAME unbounded wait a client that never half-closed
        //     already gets on such a proxy.  That is the bound this hold claims
        //     and the only one it needs: a half-closed client is held no longer
        //     than one that did not half-close, whatever the timeout is set to.
        //
        // TCP mode is deliberately not held: it has no request and no response
        // to be owed one, and a byte pipe whose client has finished writing has
        // nothing left to be told.
        if (cqe->res == 0 && !conn->closing && m_protocol == protocol_http)
        {
            const proxy_backend_connection* b = nullptr;
            if (conn->backend_fd >= 0 && conn->backend_fd < MAX_FDS &&
                m_conn_idx[conn->backend_fd].side == conn_backend)
                b = m_conn_idx[conn->backend_fd].backend;

            // "A request left this connection for a backend and its answer has
            // not come back."  Stated out of the exchange itself, and
            // deliberately NOT out of awaiting_response: that flag is only ever
            // set by arm_response_deadline, which returns without setting it
            // when --backend-timeout is 0.  Nought is a documented value that
            // means "wait as long as it takes", so a predicate resting on that
            // flag reads "nothing is owed" for every request on such a proxy —
            // and that is the one configuration where nothing else would catch
            // it either, because with no deadline there is no sweep to answer
            // 502/504 in its place.  A guard that switches off with an optional
            // feature is how the guard above this one came to be unreachable.
            const bool answer_owed = client_answer_owed(conn, b);

            if (answer_owed)
            {
                conn->client_eof = true;
                return;
            }
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
        // The end-of-stream tests used to be written out here as well, and they
        // could not fire: every path out of the `cqe->res <= 0` block above
        // returns, so `res` is positive by construction from here down and
        // `res == 0` is not a condition this branch can meet.  They are stated
        // once now, in the block that sees a zero-length completion.
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

    // ── the record layer, when this listener terminates TLS ──
    //
    // These bytes are ciphertext.  tls_feed leaves the plaintext in
    // conn->partial — the same buffer the cleartext HTTP path fills — and
    // tls_flush puts back whatever the session owes the wire: the next
    // handshake flight, an alert explaining one that just failed, a session
    // ticket.  Flushing here rather than at the end means a connection the
    // handshake has just failed on has its alert in flight before any of the
    // teardown paths below can decide there is nothing pending to wait for.
    //
    // Everything past this point reads plaintext and knows nothing about TLS.
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
        // read: the read that carried it can carry a last request ahead of it,
        // and marking the connection closing any earlier would have thrown
        // that request away with the answer half computed.
        if (conn->tls_peer_closed)
            conn->closing = true;

        if (SOCKETLEY_UNLIKELY(conn->closing))
        {
            if (!conn->write_pending && !conn->read_pending &&
                !conn->splice_in_pending && !conn->splice_out_pending)
                close_pair(fd, conn->backend_fd);
            return;
        }

        // Mid-handshake: nothing was decrypted, so there is nothing to route.
        // The read is re-armed and the next flight is what arrives.
        if (conn->partial.empty())
        {
            if (!conn->read_pending &&
                SOCKETLEY_UNLIKELY(!submit_read_op(m_loop, fd, conn, m_recv_multishot,
                                                   m_use_provided_bufs, BUF_GROUP_ID)))
                close_pair(fd, conn->backend_fd);
            return;
        }

        // TCP mode forwards what it is given rather than parsing it, so the
        // plaintext is taken out of `partial` here and handed on in a buffer
        // of its own.  HTTP mode reads partial directly and is left alone.
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

    // HTTP mode.  On a TLS connection the plaintext is already in `partial` —
    // tls_feed put it there — and the provided buffer has already gone back.
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
                // shortage, and this connection is carrying a whole request
                // whose backend handshake is still in flight.  503, not
                // silence: the backend is fine and the next attempt will very
                // likely work.  See answer_gateway_failure.
                answer_gateway_failure(conn, true);
                close_pair(fd, conn->backend_fd);
                return;
            }
        return;
    }

    // More buffered than this proxy will hold for one request, and — this is the
    // part that decides the status — not a malformed request at all.  What is in
    // `partial` here is everything the client sent past the point the request in
    // flight accounts for: the body beyond its declared length, or the requests
    // pipelined behind it.  It gets there on a perfectly well-formed connection
    // whenever the client writes faster than the backend answers, because
    // nothing drains those bytes until the response that precedes them is
    // finished.  So this is not the 400 path and not slowloris; it is one client
    // asking this proxy to hold more than a megabyte on its behalf.
    //
    // 413 says so, and is the sibling of the 431 the header block gets a few
    // lines down: same shape, same reason, one size class up.  Silence was the
    // whole of what it used to get — no status, no framing error, nothing to
    // tell a proxy that has gone away from a backend that has.
    //
    // BOTH CASES IN client_answerable ARE REACHABLE HERE, and only one of them
    // may be answered.  Measured against a backend holding its response: with a
    // 512 KiB flood behind the request the exchange completes normally, with a
    // 3 MiB flood the connection goes.  With the backend still silent the client
    // had received nothing, so a status line starts at a message boundary and
    // 413 is what it gets.  With the backend already streaming — the same flood
    // sent after its first bytes had arrived — 62 bytes of a response were
    // already on that client's wire, and a 413 written behind them would be read
    // as their continuation.  client_answerable declines that one on
    // response_started, exactly as it declines it for a gateway failure, and the
    // truncated response is left truncated: the client can see that it is.
    // This is the CLEARTEXT half of the ceiling.  A connection with a session
    // never reaches this line — the TLS branch above returns as soon as it sees
    // `closing`, and the ceiling is hit inside tls_feed while it is decrypting —
    // so tls_feed answers its own, and the two must stay in step.  See the note
    // there for why the refusal is produced at the limit rather than here.
    if (SOCKETLEY_UNLIKELY(conn->partial.size() > proxy_client_connection::MAX_PARTIAL_SIZE))
    {
        answer_request_too_large(conn);
        close_pair(fd, conn->backend_fd);
        return;
    }

    // An error response has already been queued and this connection is on its
    // way down.  A multishot recv stays armed across completions, so bytes keep
    // arriving after that decision — and nothing below looked at `closing`, so
    // whatever came next was parsed as a brand new request and taken all the
    // way through backend selection, connect and forward on a socket that had
    // already been sent "Connection: close".  That matters most for the
    // rejection added below: refusing a request because its framing is
    // ambiguous is worth nothing if the bytes right behind it are then treated
    // as the start of the next one, which is the very thing being prevented.
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
    // Mutual, like every other cross-half read in this file: a descriptor
    // number does not prove identity once numbers are reused, and reading a
    // stranger's framing state would relay this client's bytes on the strength
    // of somebody else's 101.
    if (be.backend->client_fd != conn->fd)
        return false;
    return be.backend->http_frame.switched_protocols;
}

// The connection has just stopped being HTTP.  Two things the request path set
// up on the assumption that an answer to a request was coming back have to be
// undone, and both of them are bounds that would otherwise end the tunnel.
//
//   The header deadline.  A frame the client sent in the same segment as its
//   upgrade request is sitting in conn->partial, and bound_pipelined_hold()
//   correctly read that as "a request held back behind the exchange in flight"
//   — it could not have known better, because the 101 had not come back yet.
//   Left armed it answers 408 and closes, ten seconds into a connection that is
//   working perfectly.  Nothing else can disarm it: the bytes it is waiting on
//   are not a header block and never will be.
//
//   Those buffered bytes themselves.  They are the first bytes of the tunnel
//   and nothing else is going to come and collect them — the client is waiting
//   for its echo, not sending — so they have to go out here or the session
//   hangs on its first frame.
//
// The response deadline needs nothing: it bounds the wait for a backend's FIRST
// response byte, and the 101 is that byte, so handle_backend_read has already
// cleared it one screen above this being called.  That is why --backend-timeout
// does not have to learn about tunnels — the tunnel begins after the only thing
// it measures is over.
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

// A request pipelined behind the one now in flight waits for that exchange to
// end, and what ends it is the response being judged finished.  There is a
// shape where that judgement never comes: a backend whose header block straddles
// a read boundary leaves http_response_framing::unknown set, so the pair is
// never detached and this connection would sit holding a request nobody is ever
// going to send it.  Measured with a backend that splits its status line from
// its headers — the second response never arrives and the descriptor is held
// until the peer gives up.
//
// Holding is only safe if something ends the hold, which is the same argument
// PROXY_HEADER_TIMEOUT_SEC was added under.  So a whole request that cannot be
// acted on gets the bound a half-arrived one gets: the sweep answers 408 and
// closes, which at least tells the client its pipelined request was not served
// instead of leaving it waiting on an answer that is never coming.
void proxy_instance::bound_pipelined_hold(proxy_client_connection* conn)
{
    if (conn->closing || conn->partial.empty())
        return;
    // What is buffered is body, not a request; the body path forwards it.
    if (conn->body_unbounded || conn->body_remaining > 0)
        return;
    arm_header_deadline(conn);
}

// See the declaration in proxy_instance.h for why this is reachable from two
// places.  Everything below used to sit inline at the end of
// handle_client_read; it is the same code, and the same order.
void proxy_instance::drive_client_request(proxy_client_connection* conn, int fd)
{
    // ── the tunnel ──────────────────────────────────────────────────────────
    //
    // This connection carries a protocol the two endpoints negotiated between
    // themselves; the proxy relays it and does not read it.  No parsing, no
    // framing, no header block, no body length — those questions have no
    // answers here, which is precisely why this branch is first: every one of
    // them below would be asked of bytes that cannot answer.
    //
    // What the second branch below did with them instead, and why the harness
    // saw a hang: header_parsed is still true from the upgrade request, so a
    // frame landed in "the rest of this request's body", where the amount to
    // forward is min(body_remaining, size) — and an upgrade request declares no
    // body, so body_remaining is zero.  Every frame the client sent was
    // buffered and none was forwarded.  The connection then sat there until the
    // pipelined-request bound answered it 408.
    //
    // RELAY MECHANISM.  Ordinary read and write, not splice.  A tunnel is idle
    // most of the time by nature, and a splice armed on a quiet socket costs an
    // io-wq kernel thread for as long as the peer says nothing (df093ed: four
    // such connections burned 95.7% of a core, forty-eight burned two cores and
    // fifty threads).  The poll-first pattern that fixed it would apply here
    // too, but a multishot recv already IS a poll until data arrives, so it
    // reaches the same idle cost with none of the machinery — no pipe pair per
    // connection, no 256 KB of pipe buffer, and no bypass on a TLS leg, where
    // splice cannot go at all and a WebSocket over an https:// listener is an
    // entirely ordinary thing to ask for.  Zero-copy buys nothing against
    // frames this size.  Measured idle cost: see
    // test/integration/test_proxy_websocket_tunnel.sh and the commit message.
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
                // Refused, and the connection goes with it.  Answering and then
                // carrying on would mean deciding where this request ends so
                // the next one can start — and not being able to decide that is
                // the whole reason it was refused.  send_error emits
                // "Connection: close" and sets conn->closing, and the buffered
                // bytes are dropped here so that nothing still queued on the
                // socket can be picked up as a fresh request while the error is
                // on its way out.
                conn->partial.clear();
                send_error(conn, "400 Bad Request", "Bad Request\n");
                return;
            }

            // Need more data — and from here on, not for ever.  Waiting for the
            // terminating blank line is right (see parse_http_request_line),
            // but the wait had no bound: the 16 KiB limit counts bytes, and a
            // client that sends a request line and then stops sends none, while
            // --idle-timeout defaults to 0 and so sweeps nothing.  A connection
            // held this way costs a descriptor and a 64 KB struct apiece.
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

        // Strip prefix
        std::string_view new_path;
        if (conn->path == bare)
            new_path = "/";
        else
            new_path = std::string_view(conn->path).substr(m_prefix.size() - 1); // Keep leading /

        // The route declaration, and the one place it is enforced.
        //
        // First of everything, because it is the cheapest verdict available and
        // because it is the only one derived from what the *handler* said: a
        // method the backend was always going to refuse should not cost a Lua
        // call, an endpoint resolution, a socket or a round trip.  A proxy
        // whose backends declare nothing has an empty table and pays one
        // comparison.
        if (SOCKETLEY_UNLIKELY(!m_routes.empty()) &&
            enforce_declared_route(conn, new_path))
            return;   // answered here; no filter ran and no backend was chosen

        // The filter chain, and the one place it may be called from.
        //
        // Above the selection, not beside it: a filter exists to stop a request
        // before it costs anything, and everything it is meant to stop —
        // resolving an endpoint, claiming a circuit breaker's half-open probe,
        // taking a socket from the pool, opening a new one — begins on the next
        // line.  A chain that ran after any of that would be decorative.
        //
        // The guard is the callback mask, as it is for every other Lua hook
        // here: a proxy whose script declares no `filters` array never makes
        // the call.
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
        // The rest of this request's body — and, possibly right behind it, the
        // start of the next request on the connection.  Only the body may go out
        // here.  This used to forward the whole buffer and clear it, which is
        // the same hole rewrite_http_request had: bytes nothing has parsed,
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
        // Whatever is still buffered is the next request.  It waits for this
        // one's response and is then parsed from the top — see
        // reset_client_for_next_request.
    }

    bound_pipelined_hold(conn);

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
                    // The request has gone to a backend and the pair is about
                    // to be torn down, so its answer can no longer be
                    // delivered.  Our shortage, not the backend's: 503.
                    // answer_gateway_failure declines on its own if any of that
                    // answer has already reached this client.
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
            // Charged to whichever breaker describes this connection's backend.
            // Reading backend_idx unconditionally is what took a healthy direct
            // backend out of rotation for a group member's fault: the group
            // path leaves the index pointing at the group entry, so every
            // member's failure landed on whatever occupied that slot.  Skipping
            // group-routed connections stopped that, at the price of a group
            // member never being charged at all; a breaker per member is what
            // lets the failure be recorded where it belongs.
            if (ce.side == conn_client)
            {
                // "The backend answered" is not "bytes arrived from the
                // backend", and response_started is the second of those.  It is
                // set by the first byte off this socket, so a backend that wrote
                // a fragment of a header block and then half-closed was recorded
                // as having answered — note_backend_success ran on that first
                // byte too — and kept its full share of the rotation while
                // doing the same to the next client.  The proxy has already
                // forwarded that fragment, so it cannot take it back and cannot
                // write a status line behind it; the one thing it can still do
                // is stop sending traffic to a backend that ends messages in the
                // middle, and that is what the breaker is for.
                //
                // Stated over the framing state the response path already
                // maintains for the pool's sake, rather than over a flag of its
                // own: response_bytes_seen says this socket began a response,
                // headers_parsed says its header block resolved, and `unknown`
                // says the scan gave up on tracking it.
                //
                // All three, and not headers_parsed alone.  A header block
                // split across two reads is ordinary and leaves headers_parsed
                // false for ever — the scan sets `unknown` on the second chunk
                // and stops — so charging on headers_parsed by itself would
                // take a perfectly healthy backend with large headers out of
                // rotation on every close.  `unknown` is this proxy saying it
                // cannot tell; only its absence makes the silence the backend's.
                // TCP mode has no framing and is left alone.
                const bool never_framed =
                    (m_protocol == protocol_http) &&
                    conn->http_frame.response_bytes_seen &&
                    !conn->http_frame.headers_parsed &&
                    !conn->http_frame.unknown;
                const bool backend_failed =
                    (cqe->res < 0) || !ce.client->response_started || never_framed;
                if (backend_failed)
                    note_backend_failure(ce.client);

                // The backend went away before one byte of the answer did, and
                // the client is still waiting for it.  Closing the client here
                // told it nothing at all — the same silence the deadline sweep
                // used to produce, and unlike that one this arrives instantly,
                // so a client cannot even tell it apart from the proxy dying.
                //
                // The commonest way to reach this is a connection out of the
                // pool that the backend had already closed: a server with a
                // short keep-alive idle timeout hangs up while the socket sits
                // idle, and acquire_pooled_backend deliberately skips its
                // liveness probe under five seconds, so the next request is
                // written into a socket that is already gone and reads EOF.
                // Measured against a backend that hangs up 150 ms after
                // answering: every second request was closed with no response
                // at all.  That is older than the pool key this file changed
                // today — the probe skip and this teardown are both unchanged
                // since before it — but a group-routed request could not reach
                // it while the group path was excluded from the pool, and now
                // it can, so it is this change's business to answer for.
                //
                // A retry is the better answer where one is configured, and it
                // is safe by the same test the retry path already applies:
                // nothing has been sent to the client, so the exchange can
                // start again elsewhere.  Where it is not configured, 502 says
                // which half failed, which is the least a client needs to
                // decide whether to try again.
                if (m_protocol == protocol_http && backend_failed &&
                    !ce.client->closing && !ce.client->response_started)
                {
                    auto* cconn = ce.client;
                    // Detach the pair before either branch runs: a retry opens
                    // a backend of its own, and this one is torn down on the
                    // next line whatever happens.  Leaving the two pointing at
                    // each other would let that teardown take the client with
                    // it, which is the behaviour being removed.
                    cconn->backend_fd = -1;
                    conn->client_fd = -1;
                    if (!try_retry(cconn))
                        answer_gateway_failure(cconn, false);
                    close_pair(-1, fd);
                    return;
                }
            }
        }

        close_pair(conn->client_fd, fd);
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

    // ── the record layer, when this backend is reached over TLS ──
    //
    // The mirror of the client leg: ciphertext in, plaintext out of
    // conn->partial and into a buffer of its own, and whatever the session
    // owes the wire — the rest of the handshake, the request that has been
    // waiting behind it, an alert — flushed before anything below can decide
    // the connection has nothing left to do.
    //
    // A handshake round produces no plaintext at all, and that must not be
    // mistaken for a response: everything from the circuit breaker's "the
    // backend answered" to the pool's "the response is over" is downstream of
    // data_len, so this returns rather than falling through with zero.
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
            // A handshake that failed — an unknown CA, an expired chain, a
            // name that does not match the endpoint this request was routed
            // to — ends up here with nothing decrypted.  do_handshake has
            // already logged which of those it was.
            //
            // The client is waiting on a request that was never sent and, on
            // this leg, never will be in the clear.  Dropping it would tell it
            // nothing; 502 says which half failed, and a retry — where one is
            // configured — is safe by the same test the retry path already
            // applies: not one byte has reached the client.
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
                    // 502 and not 503: this is a handshake the backend answered
                    // and rejected — an unknown CA, an expired chain, a name
                    // that does not match.  The record layer has been on the
                    // wire; the far end is what said no.
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
            // Mid-handshake, or a record that carried no application data.
            // Re-arm and wait for the next flight.
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

    // Backend responded successfully — record for circuit breaker (once per connection, HTTP only)
    //
    // Below the decryption on purpose: on a TLS leg the first completions
    // carry a handshake, and counting one of those as "the backend answered"
    // would clear the response deadline and bar a retry before the request had
    // even gone out.
    if (m_protocol == protocol_http && conn->client_fd >= 0 && conn->client_fd < MAX_FDS)
    {
        auto& ce = m_conn_idx[conn->client_fd];
        if (ce.side == conn_client && !ce.client->response_started)
        {
            // Mark that we've started receiving response data — no retry after this
            ce.client->response_started = true;
            // The backend has answered, so the deadline it was being measured
            // against is over.  It bounds the wait for the *first* byte only:
            // once bytes are flowing, a slow or streaming body is the backend
            // doing its job, and cutting it short would be a new defect rather
            // than a fix for this one.
            clear_response_deadline(ce.client);
        }
    }

    // Forward to client
    forward_to_client(conn, {data_ptr, data_len});

    // HTTP response tracking for connection pooling.
    //
    // The mirror image of request smuggling lives here.  What this decides is
    // not what the client sees — every byte is forwarded either way, just
    // above — but whether the backend socket may be handed to the pool once the
    // response is judged finished.  Judge it finished early and the socket is
    // pooled with the rest of the answer still coming, and the next request to
    // borrow it reads the tail of a stranger's response as the head of its own.
    //
    // The scan itself is in runtime/proxy/http_response_framing.h.  It used to
    // be a hundred and twenty lines here, in the middle of a completion
    // handler, which meant nothing short of a running daemon could call it and
    // it was the last parser in the tree with no fuzz target.  It is the same
    // code, in a form test/fuzz/fuzz_http_response.cpp can drive directly.
    const bool framed_before  = conn->http_frame.headers_parsed;
    const bool tunnel_before  = conn->http_frame.switched_protocols;
    if (m_protocol == protocol_http)
        http_response_scan_chunk(conn->http_frame, {data_ptr, data_len});

    // And here, not above the forward, is where the breaker hears that this
    // backend answered.
    //
    // It used to hear it from the same test that sets response_started: the
    // first byte to arrive on the socket.  A byte is not an answer.  A backend
    // that wrote a status line and one header and then half-closed was recorded
    // as a success on every single request, so its failure at the end of that
    // request — which the EOF path does charge — was cancelled out before it
    // could ever reach circuit_threshold, and the breaker sat at zero errors
    // for ever while every client got a message the backend never finished.
    //
    // The two facts are kept apart because they are timed differently on
    // purpose: response_started bars a retry and ends the first-byte deadline
    // the moment anything arrives, which is right and is why that test stays
    // where it is.  This one waits for the header block to resolve, which is
    // the earliest moment this proxy can say the peer produced a response
    // rather than bytes.
    //
    // Stated as a transition of headers_parsed rather than as a flag of its
    // own: the scan clears that field per response and sets it exactly once,
    // so false-to-true is "the header block of this response just resolved"
    // and needs nothing new to remember it.
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
    //
    // The backend answered 101 and the whole of that answer has just been
    // forwarded verbatim, headers and all — the proxy adds nothing to it,
    // removes nothing from it and computes no part of it.  From the next byte
    // on, this pair is a byte relay in both directions until one end closes.
    //
    // Here and not in the client read handler because this is the only place
    // the 101 exists: it arrives on the backend leg, once, and the client leg
    // has no way to know it happened except by asking.  Stated as the
    // false-to-true transition of a field the scan sets exactly once, so it
    // runs exactly once per connection without a flag to remember it by.
    if (m_protocol == protocol_http && !tunnel_before &&
        conn->http_frame.switched_protocols &&
        conn->client_fd >= 0 && conn->client_fd < MAX_FDS)
    {
        auto& ce = m_conn_idx[conn->client_fd];
        if (ce.side == conn_client && ce.client->backend_fd == fd)
            begin_tunnel(ce.client);
    }

    // Check if HTTP response is complete — detach backend and pool it.
    //
    // The "is it finished" half of this test used to be written out here, and
    // nowhere else; backend_pool_eligible() answered a different question and
    // the two drifted apart in exactly the way they were bound to.  It is one
    // shared predicate now, so a change to what "finished" means reaches the
    // teardown paths as well as this one.
    if (m_protocol == protocol_http && !conn->http_frame.conn_close &&
        !conn->closing && !conn->splice_active &&
        backend_response_complete(conn))
    {
        if (conn->client_fd >= 0 && conn->client_fd < MAX_FDS)
        {
            auto& ce = m_conn_idx[conn->client_fd];
            if (ce.side == conn_client && !ce.client->closing &&
                !ce.client->client_conn_close)
            {
                // This used to run only when !m_backends[backend_idx].is_group,
                // and backend_idx does not describe a group-routed connection at
                // all — the group path writes the chosen endpoint onto the
                // connection and leaves the index alone, so the guard always
                // read slot 0.  With an @group gateway that slot *is* the group,
                // so the detach never happened: header_parsed stayed true and
                // every request after the first on a keep-alive connection fell
                // into the "subsequent data (request body) — forward as-is"
                // branch.  It reached the member verbatim, gateway prefix still
                // on the request line, and every real backend answered 404.  The
                // connection was pinned to the member picked for request one as
                // well, so a member leaving the group kept receiving traffic.
                //
                // Detaching is the right thing for a group-routed connection
                // too; whether the socket may be *pooled* afterwards is a
                // separate question, and backend_pool_eligible() is the one
                // place that answers it.
                detach_and_pool_backend(ce.client, fd);
                return;
            }
        }
    }

    // ── the end of the hold ─────────────────────────────────────────────────
    //
    // A client that half-closes while its answer is still owed is HELD rather
    // than closed — see handle_client_read, which sets client_eof and returns
    // instead of tearing the pair down, so that the answer already asked for is
    // finished rather than thrown away.  That hold has to be ended by whatever
    // delivers the answer, and until now only one path did: the detach above,
    // through reset_client_for_next_request, which closes on client_eof.
    //
    // Everything that falls PAST the detach had no ending at all.  The detach is
    // refused for a client that sent `Connection: close` (it must not go back in
    // the keep-alive pool), for a backend whose own response said the same, and
    // for a response relayed by splice — and none of those three reaches
    // reset_client_for_next_request.  So the client sat there answered in full,
    // half-closed, write queue empty and nothing of its own in flight, while the
    // only thing armed anywhere was the backend's idle read; and that read
    // completes only if the backend sends something, which it will not, because
    // its response is finished and the client has said it will send no more.
    // Nothing could ever wake the pair again and both descriptors were held
    // until the runtime stopped.
    //
    // Asked out of client_answer_owed(), the same predicate the hold is taken on
    // and invariant (1b) reports against, so the three cannot drift: the hold
    // ends exactly when the condition that justified it stops being true.
    //
    // close_pair defers on whatever is still in flight and on whatever is still
    // queued — the client's own write of the response tail included — so the
    // answer goes out before the descriptors do.
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

http_request_parse proxy_instance::parse_http_request_line(proxy_client_connection* conn)
{
    // The header block ends at the first blank line, and under the rule above
    // that spelling is "\r\n\r\n" and no other.  Until it turns up, every byte
    // received so far is still header: a body cannot have started, because
    // reaching one would have required a terminator we have not seen.
    const auto hdr_end = conn->partial.find("\r\n\r\n");
    const bool block_complete = (hdr_end != std::string::npos);
    const size_t scan_len = block_complete ? hdr_end : conn->partial.size();

    // Scanned before anything is parsed out of these bytes, request line
    // included.  "GET / HTTP/1.1\nHost: h\r\n\r\n" put the whole of "Host: h"
    // inside conn->version otherwise, and sent it to the backend on the request
    // line.  Bodies are outside scan_len and may of course contain LF.
    if (SOCKETLEY_UNLIKELY(!http_eol_framing_ok(
            std::string_view(conn->partial.data(), scan_len), block_complete)))
        return http_request_parse::invalid;

    // This used to return "ready" the instant the request *line* was complete,
    // without waiting for the headers, and everything below — the smuggling
    // check and the hop-by-hop stripper in rewrite_http_request — simply did
    // not run on a request whose headers arrived in a later read than its
    // request line.  Worse than skipped checks: rewrite_http_request found no
    // header block, so it emitted the request line, a Host, a Connection and a
    // terminating blank line, i.e. a complete request, and the client's real
    // headers then arrived and were forwarded raw as though they were its body.
    // The backend read them as a second request.  Two packets, no malformed
    // byte anywhere, and the peer chooses what that second request says.
    if (!block_complete)
        return http_request_parse::need_more;

    const auto pos = conn->partial.find("\r\n");   // exists: "\r\n\r\n" contains it
    std::string_view line(conn->partial.data(), pos);

    // Parse: METHOD SP PATH SP VERSION.  A miss here is not "read more" — the
    // header block is already complete, so this is all the request line there
    // will ever be, and asking for more bytes only stalls until a limit fires.
    auto sp1 = line.find(' ');
    if (SOCKETLEY_UNLIKELY(sp1 == std::string_view::npos))
        return http_request_parse::invalid;

    auto sp2 = line.find(' ', sp1 + 1);
    if (SOCKETLEY_UNLIKELY(sp2 == std::string_view::npos))
        return http_request_parse::invalid;

    conn->method.assign(line.data(), sp1);
    conn->path.assign(line.data() + sp1 + 1, sp2 - sp1 - 1);
    conn->version.assign(line.data() + sp2 + 1, line.size() - sp2 - 1);

    // pos is the first "\r\n", hdr_end the first "\r\n\r\n" — and the latter
    // *begins* with the former, so the two are equal for a request that
    // carries no headers at all.  "GET / HTTP/1.1\r\n\r\n" is eighteen bytes
    // of ordinary HTTP/1.0, and the subtraction then wrapped to SIZE_MAX-1
    // and sent the scan below across the address space.  Remote, unauthenticated,
    // and reachable by anyone who can open the port.
    const size_t hdr_len = (hdr_end > pos + 2) ? (hdr_end - pos - 2) : 0;
    std::string_view headers(conn->partial.data() + pos + 2, hdr_len);

    // Splitting on "\r\n" is only sound because http_eol_framing_ok has already
    // ruled out every other line ending.  It did not run before, and the
    // consequence was precisely the hole this check exists to close: in
    //   Content-Length: 6\nTransfer-Encoding: chunked\r\n
    // the CRLF split yields one line, whose field name is Content-Length, so
    // has_te never set, no conflict was seen, and the request went to a backend
    // with both headers on it.  A backend that accepts bare LF — most do — sees
    // two.  From that point on the two ends disagree about where the request
    // ends, which is the whole of request smuggling.
    bool has_te = false;
    bool te_chunked_final = false;
    unsigned cl_count = 0;
    size_t cl_value = 0;
    size_t search_pos = 0;
    while (search_pos < headers.size())
    {
        auto nl = headers.find("\r\n", search_pos);
        if (nl == std::string_view::npos)
            nl = headers.size();
        std::string_view hdr_line = headers.substr(search_pos, nl - search_pos);

        // An obs-fold continuation (RFC 7230 Section 3.2.4) is a line the two
        // ends can also read differently — as more of the previous field's
        // value, or as a field of its own.  A proxy MUST reject it or flatten
        // it, and flattening is another guess about the backend.
        if (SOCKETLEY_UNLIKELY(hdr_line.empty() || hdr_line[0] == ' ' || hdr_line[0] == '\t'))
            return http_request_parse::invalid;

        const auto colon = hdr_line.find(':');
        if (SOCKETLEY_UNLIKELY(colon == std::string_view::npos || colon == 0))
            return http_request_parse::invalid;

        // Whitespace before the colon is a MUST-reject for a server (RFC 9112
        // Section 5.1) for this exact reason: "Content-Length : 6" is not a
        // Content-Length to a strict parser and is one to a lenient parser, so
        // it walks straight past the conflict check below while the backend
        // still frames the body by it.
        if (SOCKETLEY_UNLIKELY(hdr_line[colon - 1] == ' ' || hdr_line[colon - 1] == '\t'))
            return http_request_parse::invalid;

        if (header_name_equals(hdr_line, "content-length", 14))
        {
            cl_count++;
            // The number, not merely the presence.  It is what bounds the body
            // the proxy is willing to forward behind this header block, so a
            // field it cannot read is a body it cannot end, and RFC 9112
            // Section 6.3 already calls an invalid Content-Length unrecoverable.
            // from_chars would have stopped at the first byte it could not use
            // and reported success for what it read, so "6x" would have come
            // back as 6 — a boundary six bytes into a body the backend frames
            // differently, which is the disagreement this whole function exists
            // to prevent.
            if (SOCKETLEY_UNLIKELY(!http_whole_decimal(
                    http_trim_ows(hdr_line.substr(colon + 1)), cl_value)))
                return http_request_parse::invalid;
        }
        else if (header_name_equals(hdr_line, "transfer-encoding", 17))
        {
            has_te = true;
            // Carried across field lines on purpose: "Transfer-Encoding:
            // chunked" followed by "Transfer-Encoding: gzip" is the same
            // message as "chunked, gzip" on one line, and just as unframeable.
            if (SOCKETLEY_UNLIKELY(!te_line_codings_ok(hdr_line, te_chunked_final)))
                return http_request_parse::invalid;
        }

        search_pos = nl + 2;
    }

    // Content-Length together with Transfer-Encoding (RFC 7230 Section 3.3.3),
    // and two Content-Length fields (RFC 9112 Section 6.3) — in both cases the
    // message carries two answers to "how long is the body" and the recipient
    // picks one.  Two recipients pick independently.
    if (SOCKETLEY_UNLIKELY((cl_count > 0 && has_te) || cl_count > 1))
        return http_request_parse::invalid;

    // A Transfer-Encoding whose final coding is not chunked leaves the body
    // with no length at all: RFC 9112 Section 6.1 makes that a MUST-400 for a
    // request, and the reason is the same one every other rule above exists
    // for.  It was argued that this proxy introduces no desync because the
    // bytes reach the backend verbatim, and that argument does not survive
    // contact with the pool: the backend socket is *reused*, so whatever the
    // backend decides is left over after a body it could not frame becomes the
    // opening bytes of the next request on that socket — a request belonging to
    // a different client.  The proxy also cannot forward such a body
    // faithfully in any case; it never de-chunks and cannot decode a standalone
    // "gzip" transfer coding, so it has no idea where the body ends either.
    // Refusing is the only answer here that requires agreement with nobody.
    if (SOCKETLEY_UNLIKELY(has_te && !te_chunked_final))
        return http_request_parse::invalid;

    // How long this request's body is, established from a header block that has
    // just been proved to give exactly one answer to the question.  Everything
    // past that is not this request's, and rewrite_http_request holds it back.
    conn->declared_body_len = (cl_count == 1) ? cl_value : 0;
    conn->declared_body_chunked = has_te;

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
    //
    // This walks the block on "\r\n" alone, which is correct only because
    // parse_http_request_line has already refused anything else — it is the
    // same assumption the smuggling check makes, and it used to be just as
    // unfounded here.  A header block containing a bare LF was split into
    // fewer, longer lines than the backend would split it into, so a name this
    // loop is supposed to remove could be carried across as part of the
    // previous line's *value* and reach the backend as a header of its own.
    // That is how Transfer-Encoding survived into the forwarded bytes even
    // though the block it came from was meant to have been rejected.
    //
    // The block is measured from the *same* terminator parse_http_request_line
    // measured it from: the first "\r\n\r\n" in the whole buffer.  Searching the
    // bytes behind the request line for another one is not the same question,
    // and gets a different answer for a request that carries no headers at all —
    // there the first "\r\n\r\n" *is* the request line's own CRLF followed by
    // the blank line, so the block is empty and the search walks straight past
    // it to the terminator of the *next* request in the buffer.  Everything in
    // between was then emitted as this request's headers.
    //
    // Found by fuzz_http_request on "POST /px/ HTTP/1.1\r\n\r\n" followed by a
    // pipelined request: the second request's fields — a bare-LF line and a
    // Transfer-Encoding among them — came out on the first request's header
    // block, having passed no check whatever, because the parser had correctly
    // seen that block as empty and looked at nothing.  It is the same mistake
    // check_no_smuggling made about the same shape (86c825a), on the other side
    // of the seam.
    //
    // The npos fallback is unreachable: the caller only gets here on
    // http_request_parse::complete, which requires the "\r\n\r\n" to have
    // arrived.  It is kept because being wrong about that used to mean
    // forwarding a terminated request and then the client's real headers behind
    // it, which the backend read as a second request.
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

    // ── an upgrade request, and why two hop-by-hop headers survive it ──
    //
    // Connection and Upgrade are hop-by-hop and are stripped below, which is
    // right for every request except the one whose entire meaning they are.
    // "Connection: Upgrade" + "Upgrade: websocket" is not a pair of headers
    // about this hop; it is the offer, and a backend that does not receive it
    // has not been asked to switch protocols.  RFC 7230 Section 6.7 says so
    // directly: a proxy that will relay the switch MUST forward both.
    //
    // What it cost to strip them is not visible from the client's side at all,
    // which is why it survived: a lenient backend answers 101 on the strength
    // of Sec-WebSocket-Key alone, so the handshake appears to succeed while the
    // request the backend actually saw was an ordinary GET.  A strict one —
    // socketley's own server runtime among them, which requires the Upgrade
    // header before it will look at the key — answers with a plain HTTP
    // response instead, and the client sees a WebSocket connection that was
    // never negotiated.
    //
    // Both are required, and the token is looked for in the Connection list
    // rather than at its front: "Connection: keep-alive, Upgrade" is an
    // ordinary spelling.  An Upgrade header without the token in Connection is
    // not an offer at all (RFC 9110 Section 7.8) and is stripped as before, so
    // this cannot be used to smuggle a hop-by-hop header past the proxy by
    // naming it alone.
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

        // Skip hop-by-hop headers (RFC 7230 Section 6.1) — except the two that
        // make up an upgrade offer, on a request that carries one.  See above.
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
        // Transfer-Encoding is on RFC 7230 Section 6.1's list too and is
        // deliberately not on this one.  This proxy forwards the request body
        // byte for byte and never de-chunks it, so removing the header that
        // says the body is chunked would leave the backend reading chunk-size
        // lines as content — a worse desync than the one being prevented.  It
        // is safe to forward because it can no longer arrive alongside a
        // Content-Length: parse_http_request_line refuses that combination now
        // that it can actually see both headers.

        // A header a filter set replaces the client's, rather than joining it:
        // "set" would mean very little if the value it was meant to overwrite
        // travelled alongside it and the backend combined the two.  The names
        // were lowercased and checked when they were collected — Host and the
        // framing pair among them are refused there, so this loop cannot be
        // made to skip a line it is responsible for.
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

        // A header a filter removed, dropped here and never written back — the
        // list below carries no value to re-emit.  Every occurrence goes: a
        // field the client sent twice is one field, and taking away half of it
        // would leave the backend reading a value the filter meant to delete.
        // The names were lowercased and checked when they were collected, and
        // the framing pair, Host and the hop-by-hop set are refused there, so
        // this loop cannot be made to drop a line it is responsible for.
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

    // What the chain asked for, once each, after the client's own block.  Name
    // and value were validated at the point they were taken from Lua — no CR,
    // no LF, a bare token for a name — so nothing here can add a line the
    // backend would frame differently from this proxy.
    for (const auto& [n, v] : conn->filter_headers)
    {
        result += n;
        result += ": ";
        result += v;
        result += "\r\n";
    }

    // Request keep-alive to enable backend connection pooling, unless the
    // client sent Connection: close — or unless this request carries an upgrade
    // offer, whose own Connection header has just been forwarded verbatim.
    // Adding one here as well would put two Connection fields on the request,
    // with conflicting tokens, and leave the backend to pick.
    if (!upgrade_offered)
    {
        if (conn->client_conn_close)
            result += "Connection: close\r\n";
        else
            result += "Connection: keep-alive\r\n";
    }

    result += "\r\n";

    // How much of what follows the header terminator belongs to *this* request.
    //
    // This used to be "all of it", and conn->partial was then cleared.  But the
    // bytes behind a request are whatever the client chose to put there, and
    // parse_http_request_line validates only the first message in the buffer —
    // so a client that sent a clean request and pipelined a second one carrying
    // Content-Length together with Transfer-Encoding got that second request
    // handed to the backend verbatim.  Not one of the checks above ran on it:
    // not CL+TE, not the duplicate Content-Length, not the bare-LF framing scan,
    // not obs-fold, not whitespace before the colon.  Putting the payload second
    // was the whole of the bypass, and it needed no malformed byte in the first
    // request at all.
    //
    // A validated request declares its body length exactly once — the parser has
    // just refused two Content-Lengths and refused Content-Length alongside
    // Transfer-Encoding — so that length is known, and nothing beyond it is
    // body.  What is beyond it stays in conn->partial and comes back through
    // this same function as a request of its own, checks included.
    size_t body_len;
    if (conn->declared_body_chunked)
    {
        // Except for chunked, where there is no length to compute: this proxy
        // forwards the body byte for byte and never de-chunks it, so it cannot
        // point at the terminating chunk any more than the response side can
        // (see http_response_frame_complete).  Its body streams on exactly as
        // before — bounding it would mean guessing where it ends, and a guess
        // that truncates a legitimate upload is worse than the case it closes.
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

    // Consume exactly what was forwarded.  body_off is the whole buffer on the
    // unreachable npos path above, so that case still clears it.
    conn->partial.erase(0, body_off + body_len);

    return result;
}

// ─── Declared routes ────────────────────────────────────────────────────────
//
// One question, asked of a table the handler filled in: is this method one the
// handler said it would take on this path.  See shared/route_table.h for why
// the answer is published rather than configured, and for the two things this
// gate is deliberately not (a router, and input validation).

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
        // The handler asked for OPTIONS itself.  Forward, and do not second
        // guess it: a script that declares OPTIONS has an answer of its own in
        // mind, and this is how a CORS layer written in Lua keeps working.
        for (const auto& m : route->methods)
            if (m == "OPTIONS")
                return false;

        // A CORS preflight.  Forwarded, always, and this is the single most
        // important line in the file.
        //
        // A browser sends OPTIONS ahead of any request that is not "simple" —
        // any POST that is not a form encoding, anything carrying an
        // Authorization or a custom header — and it needs
        // Access-Control-Allow-Origin back.  A gateway that answers the
        // preflight out of the declaration answers it without one, because the
        // declaration says nothing about origins and this proxy will not invent
        // an origin policy: reflecting whatever Origin arrives is how a
        // credentialed endpoint gets opened to every site on the internet.
        //
        // The failure that produces is indistinguishable from the 405 this
        // whole feature was written to avoid — the real request is never sent,
        // the browser reports a CORS error, and nothing in either runtime's log
        // mentions a preflight.  Origin policy lives with the handler, so the
        // preflight goes to the handler.
        if (request_has_header(conn, "origin", 6) &&
            request_has_header(conn, "access-control-request-method", 29))
            return false;

        // A plain OPTIONS, which is RFC 9110 Section 9.3.7 and has nothing to
        // do with CORS: "what may I do here".  The declaration is exactly that
        // answer, so it is answered here — no backend, no round trip.
        std::string response;
        response.reserve(128);
        response += "HTTP/1.1 204 No Content\r\nAllow: ";
        response += route_table::allow_header(*route);
        // No Content-Length: RFC 9112 Section 6.2 — a 204 carries no content
        // and must not claim to.  Closed for the same reason every response
        // this proxy writes itself is closed; see queue_final_response.
        response += "\r\nConnection: close\r\n\r\n";

        conn->partial.clear();
        queue_final_response(conn, std::move(response));
        return true;
    }

    if (route_table::method_allowed(*route, conn->method))
        return false;

    // Refused, and with the one header that makes the refusal actionable.
    // RFC 9110 Section 15.5.6 requires Allow on a 405, and it costs nothing
    // here: the declaration is the list.  Without it the client is told no and
    // not told what would have worked.
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
    // the bytes.  HEAD only reaches this line for a route that declares
    // neither GET nor HEAD, which is rare and still has to be framed right.
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
//
// Everything below serves run_request_filters at the end of this block.  It runs
// on a request whose header block has been parsed and accepted and whose path
// belongs to this proxy, and before anything at all has been decided about where
// that request is going.
#ifndef SOCKETLEY_NO_LUA

// A field name a filter supplied.  RFC 9110 Section 5.1 tchar, and nothing else:
// a name carrying a colon, a space or a CR splits into something the backend
// reads as two fields, which is header injection with the proxy as the vehicle.
// Filter input is frequently derived from the request — a rate limiter echoing
// back a client-supplied identifier is the ordinary case — so "the script wrote
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

// A field value a filter supplied.  The bytes that end a line and the bytes that
// end a header block are the ones that matter; obs-text (>= 0x80) is left alone
// because it is legal and this is not the place to start transcoding.
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

// Names a filter may not set on the request it is letting through.
//
// The framing pair first: parse_http_request_line has just proved this request
// gives exactly one answer to "how long is the body", and rewrite_http_request
// forwards precisely that many bytes.  A filter that sets Content-Length or
// Transfer-Encoding makes the proxy and the backend disagree about where the
// request ends — request smuggling, introduced by the feature meant to stop it.
// Then the hop-by-hop set, which rewrite_http_request strips on purpose, and
// Host, which it rewrites to the endpoint actually selected.
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

// The same question for a header on the answer a filter is sending.  Shorter
// list: the proxy writes the length and the connection disposition itself, and
// a filter's copy of either would be a second answer to a question that has one.
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

// Lowercase the name and trim the value of one field line, for the table handed
// to a filter.  Names are lowercased because a lookup on a table is exact and
// HTTP field names are not — a filter written as req.headers["authorization"]
// must not depend on which capitalisation the client happened to send.
static void filter_collect_header(sol::table& out, std::string_view line)
{
    const auto colon = line.find(':');
    if (colon == std::string_view::npos || colon == 0)
        return;   // parse_http_request_line has already refused these
    std::string name(line.substr(0, colon));
    for (auto& c : name)
        c = static_cast<char>(c | 0x20);
    const std::string_view value = http_trim_ows(line.substr(colon + 1));

    // Repeats are combined, in the order sent, as RFC 9110 Section 5.2 defines
    // the field value of a field that appears more than once.  A table holds one
    // value per key, and dropping the later ones would hide half a Cookie.
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

    // The request, as the client sent it.  `path` carries this proxy's own
    // prefix, exactly as on_route sees it: a filter judging a request judges
    // what arrived, not what the proxy will forward.
    sol::table req = L.create_table(0, 5);
    req["method"]    = conn->method;
    req["path"]      = conn->path;
    req["version"]   = conn->version;
    req["client_id"] = conn->fd;

    // The header block, measured from the same terminator parse_http_request_line
    // measured it from.  Both finds succeed by construction — the caller only
    // reaches here on http_request_parse::complete — and the guards below are
    // for the day that stops being true, because a filter chain that silently
    // sees no headers is an auth filter that admits everyone.
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

    // Headers a filter has asked to be set or taken off on the way out.  Cleared
    // here rather than only between requests: this is the one place that fills
    // them, and a request that reaches the chain twice must not accumulate.
    conn->filter_headers.clear();
    conn->filter_removed_headers.clear();

    // One budget for the whole chain, armed here rather than handed out per
    // filter by the accessor the way every other callback gets it.  A request
    // costs what its chain costs: ten filters that each take a second are ten
    // seconds of the event-loop thread for one request, and measuring them one
    // at a time would call that fine.  A filter that outruns it raises, and the
    // loop below already has the right answer for a filter that raises —
    // refuse the request and say so.
    lua_deadline::scope deadline_guard("a filter in the `filters` chain",
                                       lctx->callback_timeout_ms());

    for (const auto& filter : lctx->filters())
    {
        auto result = filter(req);

        // A filter that failed did not say "carry on".  Nothing that raises an
        // error has expressed an opinion about this request, and the opinion it
        // was there to express is usually "no" — so the request is refused and
        // the operator is told, rather than the chain silently shortening.
        if (SOCKETLEY_UNLIKELY(!result.valid()))
        {
            sol::error err = result;
            fprintf(stderr, "[lua] filter error: %s\n", err.what());
            conn->partial.clear();
            send_error(conn, "500 Internal Server Error", "Filter Error\n");
            return true;
        }

        // Nothing returned, or nil: this filter has no opinion.  The commonest
        // outcome by far, and the only one that costs nothing.
        if (result.return_count() == 0)
            continue;
        sol::object r = result.get<sol::object>();
        if (!r.valid() || r == sol::nil)
            continue;

        if (SOCKETLEY_UNLIKELY(!r.is<sol::table>()))
        {
            // Deliberately not "anything truthy carries on".  A filter is
            // allowed exactly two vocabularies — say nothing, or return the
            // answer — and a third value is a script that means something this
            // side cannot read.  Guessing at it is how a `return false` meant as
            // a rejection becomes an admission.
            fprintf(stderr, "[lua] filter returned a %s; expected nil or a table\n",
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
            // Continue, with the request rewritten.  The only other thing a
            // returned table may be.
            sol::optional<sol::table> set = t["set_headers"].get<sol::optional<sol::table>>();
            sol::optional<sol::table> remove = t["remove_headers"].get<sol::optional<sol::table>>();
            if (!set && !remove)
            {
                fprintf(stderr, "[lua] filter returned a table with none of "
                                "`status`, `set_headers` or `remove_headers`\n");
                conn->partial.clear();
                send_error(conn, "500 Internal Server Error", "Filter Error\n");
                return true;
            }

            // Taking a header *off* the request, which until now a filter could
            // not do at all: it could add one and it could overwrite one, so a
            // header the client sent and the backend must never see — an
            // internal trust header a caller forged, a cookie that has no
            // business past the edge — could only be blanked, not removed.
            //
            // An array of names, because that is what it is, and the same ban
            // list as set_headers.  Removing Content-Length or
            // Transfer-Encoding would make this proxy and its backend disagree
            // about where the request ends, which is request smuggling in the
            // one direction the set ban does not cover; Host and the
            // hop-by-hop set are the proxy's to write, and a filter that could
            // delete them would be deciding how the message is framed and where
            // it is addressed.
            if (remove)
            {
                for (size_t i = 1;; ++i)
                {
                    sol::object entry = (*remove)[i];
                    if (!entry.valid() || entry == sol::nil)
                        break;
                    if (!entry.is<std::string>())
                    {
                        fprintf(stderr, "[lua] filter remove_headers: entry %zu is not a "
                                        "string\n", i);
                        continue;
                    }
                    std::string name = entry.as<std::string>();
                    for (auto& c : name)
                        c = static_cast<char>(c | 0x20);
                    if (!filter_token_ok(name))
                    {
                        fprintf(stderr, "[lua] filter remove_headers: `%s` is not a field "
                                        "name\n", name.c_str());
                        continue;
                    }
                    if (filter_request_header_forbidden(name))
                    {
                        fprintf(stderr, "[lua] filter remove_headers: `%s` is the proxy's "
                                        "to decide, not a filter's\n", name.c_str());
                        continue;
                    }
                    // A name cannot be both set and removed: the last statement
                    // about it wins, exactly as two set_headers for one name
                    // resolve.  Without this the removal would take the
                    // client's line out and the set would put the proxy's line
                    // back, which reads as "remove did nothing".
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
                    fprintf(stderr, "[lua] filter set_headers: name and value must be strings\n");
                    return;
                }
                std::string name = key.as<std::string>();
                std::string value = val.as<std::string>();
                for (auto& c : name)
                    c = static_cast<char>(c | 0x20);
                if (!filter_token_ok(name) || !filter_value_ok(value))
                {
                    fprintf(stderr, "[lua] filter set_headers: refused a header this "
                                    "proxy will not put on the wire\n");
                    return;
                }
                if (filter_request_header_forbidden(name))
                {
                    fprintf(stderr, "[lua] filter set_headers: `%s` is the proxy's to "
                                    "decide, not a filter's\n", name.c_str());
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

        // The answer.  Everything from here on ends the request: no backend is
        // selected, no endpoint is resolved, no socket is opened or taken from
        // the pool, and no circuit breaker is told anything — because none of
        // those has happened yet, which is the reason this function is called
        // where it is.
        int status = 0;
        if (status_obj->is<int>())
            status = status_obj->as<int>();
        if (status < 200 || status > 599)
        {
            fprintf(stderr, "[lua] filter answer: status must be 200..599\n");
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
                    fprintf(stderr, "[lua] filter answer headers: name and value must be strings\n");
                    return;
                }
                const std::string name = key.as<std::string>();
                const std::string value = val.as<std::string>();
                std::string lower = name;
                for (auto& c : lower)
                    c = static_cast<char>(c | 0x20);
                if (!filter_token_ok(name) || !filter_value_ok(value))
                {
                    fprintf(stderr, "[lua] filter answer headers: refused a header this "
                                    "proxy will not put on the wire\n");
                    return;
                }
                if (filter_response_header_forbidden(lower))
                {
                    fprintf(stderr, "[lua] filter answer headers: `%s` is framing, and "
                                    "this proxy writes it\n", lower.c_str());
                    return;
                }
                response += name;
                response += ": ";
                response += value;
                response += "\r\n";
            });
        }

        // A 204 or a 304 carries no content and RFC 9112 Section 6.2 forbids the
        // header that would say how much; a response to HEAD carries the length
        // its GET would have had and none of the bytes.  Everything else gets
        // both.  Nothing here is left to the peer to work out from the close.
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

        // Closed, like every other response this proxy writes itself.  Keeping
        // the connection alive would mean deciding where this request ends so
        // the next one can begin — consuming a body that may not have arrived
        // yet — and that decision is exactly what the answered-here path does
        // not have a backend response to make for it.
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
                // One probe at a time here as well: with a single backend the
                // alternative to waiting is a second request into a backend
                // that has already been judged broken, and that costs a whole
                // deadline when the way it is broken is a stall.  Only the
                // probe is gated — health is deliberately not consulted on this
                // path, exactly as before, because with one backend there is
                // nowhere for an unhealthy verdict to send the request instead.
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
            // A protected call, and the only reason it can be written on one
            // line: an error inside on_route used to leave here as an unwind out
            // of the accept path, where nothing between this and main() catches
            // anything, and the process ended in the Lua panic handler.  The
            // whole of that outage was a script that raised.
            sol::protected_function_result r =
                m_protocol == protocol_http ? lua()->on_route()(conn->method, conn->path)
                                            : lua()->on_route()();

            // A raising on_route is routed round-robin, not refused, and that is
            // the deliberate difference from the filter chain.  A filter that
            // raised has not said "carry on", and the opinion it was there to
            // express is usually "no" — so refusing is the safe reading of its
            // silence.  on_route expresses no opinion about whether a request
            // may proceed, only about where it goes, and this path already has
            // an answer for a callback that produced no usable index: the
            // fallback immediately below.  An error is that same non-answer.
            // Refusing instead would turn one typo in a routing script into the
            // same total outage the unwind used to cause, only politer.
            if (SOCKETLEY_UNLIKELY(!r.valid()))
            {
                sol::error err = r;
                fprintf(stderr, "[lua] on_route error: %s\n", err.what());
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
            // Local and remote members both come out of the published snapshot.
            // This used to take the manager's mutex here, walk every runtime in
            // the daemon, and read a port off each matching *instance pointer* —
            // once per connection, on the connection path, from inside another
            // runtime's object.  Nothing crossed but a host and a port, which is
            // what the table carries; the walk and the lock are now done once
            // per membership change instead of once per connection, and the
            // proxy no longer needs a manager at all to route.
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

    // Members the breaker has taken out of rotation come off the list before
    // anything is selected from it — the same order the indexed path uses, and
    // for the same reason: choosing first and checking afterwards means either
    // sending the request to a member already judged broken, or biasing the
    // round-robin by skipping a turn.  Costs one empty-map test while every
    // member is healthy, which is the normal case.
    if (m_mesh.circuit_threshold > 0 && !m_group_breakers.empty())
    {
        pool.erase(std::remove_if(pool.begin(), pool.end(),
                                  [this](const resolved_backend& rb) {
                                      return !group_endpoint_available(rb.host, rb.port);
                                  }),
                   pool.end());
        // Every member is out.  Answering 503 now is what the indexed path does
        // with its last backend open, and it is the honest answer: there is
        // nowhere to send this request.  The breakers expire on their own.
        if (pool.empty())
            return nullptr;
    }

    resolved_backend* selected = &pool[0];

    if (pool.size() > 1)
    {
        if (m_strategy == strategy_lua && lua() && lua()->has_on_route())
        {
#ifndef SOCKETLEY_NO_LUA
            // The group half of the same call, protected for the same reason —
            // see the indexed path above.  Reached by an @group backend with
            // more than one member, so `--strategy lua` could take the process
            // down through either path and this one needed no traffic the other
            // did not.
            sol::protected_function_result r =
                m_protocol == protocol_http ? lua()->on_route()(conn->method, conn->path)
                                            : lua()->on_route()();

            // Report and leave `selected` where it is — pool[0], which is
            // already what an out-of-range index gets here.  Same decision as
            // the indexed path, spelled with this path's own fallback: the
            // callback failed to name a member, and this path's answer to that
            // is the first one.
            if (SOCKETLEY_UNLIKELY(!r.valid()))
            {
                sol::error err = r;
                fprintf(stderr, "[lua] on_route error: %s\n", err.what());
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
    return &m_scratch_backend;
}

// Stop holding a pooled entry.  The descriptor and the session go together
// because the pool owns both together — freeing one without the other is either
// a leaked SSL or a record layer still pointing at a number somebody else has.
//
// `reset` picks the signal.  A socket given up because something is wrong with
// it — unread bytes, application data behind a session, a record that would not
// parse — leaves with shutdown(SHUT_RDWR) so the peer gets a reset rather than
// being left holding a half-open connection this proxy will never read again,
// and so those bytes are not mistaken for a message that ended cleanly.  A
// socket given up because nobody wanted it in time is closed plainly.
//
// No close_notify either way, and that is deliberate rather than an omission.
// Writing one means encrypting an alert into the write BIO and then getting it
// onto the wire, which is a submission and a completion on a path that has
// neither — the idle sweep has no connection struct to hang a write on, and the
// probe is on the request's critical path.  Nothing is lost by leaving it out:
// every response this session carried is complete (that is what let the socket
// be pooled), so there is no truncation for the peer to be misled about, and a
// TLS peer reading EOF without close_notify treats the connection as broken,
// which is exactly what it is.  It is also what this proxy has always done to a
// backend session it tears down — see backend_pool_release.
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

// ─── the probe, for a socket that has a session ─────────────────────────────
//
// ed07f12 settled what a readable pooled socket means, and its answer does not
// survive being carried across a record layer unchanged.
//
// In cleartext the reasoning is airtight and needs nothing but the kernel: a
// socket is in this pool because a request went out on it and the whole of its
// answer came back, nothing has been asked of it since, so a byte waiting on it
// is a byte nobody asked for.  recv(MSG_PEEK) answers that directly, and a
// positive result is a confidentiality defect — the next borrower would read
// those bytes as the head of its own response.
//
// Under TLS the same syscall answers a different question.  What is waiting on
// the socket is a record, and a peer that has said nothing at all still sends
// records: a TLS 1.3 server routinely posts NewSessionTicket after the exchange
// it belongs to is over, either end may send KeyUpdate whenever it likes, and
// close_notify is an alert.  None of those is the peer speaking unbidden in any
// sense a client could be harmed by, and all three make recv() return a
// positive number.  Keeping ed07f12's test would throw away a working
// connection every time a backend rotated a ticket — which is to say, on most
// of them, which is to say TLS pooling would be pooling in name only.
//
// Relaxing it is worse.  A record *may* be application data: the backend's
// second answer, or the tail of one this proxy judged finished, sitting at an
// offset no request can start from.  That is the same defect it always was, and
// it is now invisible from outside — the bytes are indistinguishable from a
// ticket until they are decrypted.
//
// So the question is asked of OpenSSL instead of the kernel, and it is asked
// about application data rather than about bytes:
//
//   drain whatever ciphertext is on the socket into the record layer, then ask
//   SSL_read whether anything comes out of it.
//
// and the four answers map onto ed07f12's four exactly:
//
//   nothing came out           the records were the peer's housekeeping — a
//   (ssl_read -> 0)            ticket, a KeyUpdate, or a partial record still
//                              waiting for the rest of itself.  The session is
//                              healthy and the stream is at a message boundary.
//                              This is the EAGAIN case, and it is now reached
//                              through work rather than through idleness.
//   application data           the defect.  Whatever this is, it is queued
//   (ssl_read -> n > 0)        ahead of the next request's answer and the next
//                              client would read it as its own.  Destroyed, for
//                              the same reason ed07f12 destroys rather than
//                              re-shelves: decrypting it does not put it back,
//                              so the trap stays set for whoever comes next.
//   close_notify, or a         the session is over, or the record layer cannot
//   record that will not       go on.  Nothing left to reuse.
//   parse (ssl_read -> -1)
//   FIN or reset on the        as before, and read off the socket rather than
//   socket                     out of the session.
//
// Consuming rather than peeking is forced: a record cannot be judged without
// being decrypted, and decrypting it means feeding it to the record layer,
// which advances the sequence number.  That is safe here and nowhere else —
// the session is pooled with the socket, so what this consumes is consumed on
// the connection that will carry the next request, not on some other one.  It
// is also why the reads below are bounded: bio_write_in enforces the
// per-connection buffer cap and answers -1 when a peer runs past it, and a
// pooled socket that has 512 KB of unconsumed records on it is not a candidate
// for reuse under any reading.
//
// Whatever the record layer wants to say back — a KeyUpdate answering a
// KeyUpdate is the case that exists — is left in the write BIO.  It goes out
// ahead of the request, because tls_flush drains that BIO after ssl_write has
// appended to it and a memory BIO is a queue: the correct order, with no
// special case for it here.
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
                    // The buffer cap, or a BIO that failed.  Fatal by contract
                    // and fatal here too: there is nowhere to put what was not
                    // taken, and a record layer fed a stream with a hole in it
                    // has no framing left to recover.
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
            // A FIN while the socket sat idle.  Nothing left to reuse — the
            // same verdict the cleartext probe gives, for the same reason.
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

    // And the question itself.  One call is enough to answer it: SSL_read
    // processes every whole record it has before it can decide it has no
    // application data, so a 0 here means the record layer looked at all of
    // them and none was for the application.
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
        // close_notify, or a record the session cannot use.  Either way this
        // one is finished; ssl_read has already logged which, when there was
        // anything to log.
        discard_pooled(pb, false);
        return false;
    }

    return true;
}

// Try to get a pooled backend connection for the given endpoint.
//
// The index picks the shelf and the endpoint picks the socket.  For a plain
// backend every socket on the shelf has the same peer and the comparison is a
// formality; for a group entry the shelf holds sockets to every member that
// has been used, and handing one of them to a request routed elsewhere would
// deliver it to the wrong runtime.
//
// For an encrypted socket the endpoint is doing more work than that, and it is
// worth being explicit about how much, because the comment this replaces said
// it could not be done.  A TLS connection carries an SNI name, a peer whose
// certificate was checked against a name, a client certificate that may have
// been presented, and a record layer part way through a stream.  Three of those
// four are not independent of this key at all: start_backend_tls builds the
// session with create_ssl_client(host), where `host` comes from the same
// backend_endpoint_of() call that release_to_pool files the entry under and
// this function compares.  Same host string, same SNI, same name verified,
// same peer — not because the key describes the identity, but because the
// identity is derived from the key and from nothing else.  The fourth, the
// client certificate and the trust store, belongs to the tls_context, and
// tls_owner below is what holds it: see pooled_backend.  The record layer is
// answered by pooling the session rather than the descriptor alone.
int proxy_instance::acquire_pooled_backend(size_t backend_idx, std::string_view host,
                                           uint16_t port, bool want_tls, SSL** out_ssl)
{
    if (out_ssl)
        *out_ssl = nullptr;
    if (backend_idx >= m_backend_pool.size() || host.empty() || port == 0)
        return -1;
    // A TLS request with no context to have built the session against cannot
    // be matched to anything: tls_owner would have nothing to equal.  This is
    // unreachable — conn_backend_tls is false without m_backend_tls — and it
    // is the backstop for the day it is not.
    if (want_tls && !m_backend_tls)
        return -1;

    auto& pool = m_backend_pool[backend_idx];
    if (pool.empty())
        return -1;

    auto now = std::chrono::steady_clock::now();

    // Try from the back (most recently idle) — better chance of being alive.
    // Entries for other endpoints are stepped over rather than dropped: they
    // belong to somebody else's peer and are the idle sweep's business.
    for (size_t scan = pool.size(); scan-- > 0; )
    {
        if (pool[scan].port != port || pool[scan].host != host)
            continue;
        // Encryption is part of the key, not a preference — see the header.
        // A mismatch is stepped over rather than dropped for the same reason a
        // foreign endpoint is: the entry is perfectly good for somebody else.
        if ((pool[scan].ssl != nullptr) != want_tls)
            continue;
        // And the identity the endpoint cannot carry.  An entry built against
        // a context this instance has replaced was verified against a
        // different trust store, or presented a different client certificate,
        // than the request now asking for it — so it is not this request's
        // connection whatever its address says.  Dropped rather than stepped
        // over: unlike a foreign endpoint, nobody is coming for it.
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

        // Every socket is probed, however recently it went idle.  This used to
        // skip anything under five seconds, on the argument that a FIN arriving
        // that fast is unlikely and the syscall is expensive on the hot path.
        // The first half is wrong wherever it matters: a backend with a short
        // keep-alive idle timeout closes in well under five seconds by design,
        // and a group member that is stopping closes immediately — and the
        // proxy learns that a member has left through a published table that
        // cannot arrive before the sockets do.  Measured against a backend that
        // hangs up 150 ms after answering: every second request was written
        // into a socket that was already gone, and the client got nothing at
        // all for it.  The cost of being wrong is a whole request; the cost of
        // asking is one non-blocking recv on a socket already in cache.
        //
        // It does not close the window — a FIN can still arrive between this
        // probe and the write, and nothing can prevent that — which is why the
        // read path answers rather than dropping when it does.

        // Quick liveness probe, and the four things it can say.
        //
        //   -1/EAGAIN   the socket is alive and the receive queue is empty.
        //               This is the only answer that means "reusable", and it
        //               is the only one this used to act on correctly.
        //   0           the peer sent a FIN while the socket was idle.  There
        //               is nothing left to reuse; drop it and try the next.
        //   -1/other    RST, or a descriptor that has gone wrong underneath us.
        //               Same verdict, same reason.
        //   >0          bytes are waiting, and this is the answer the check had
        //               backwards.
        //
        // A socket is in this pool because a request went out on it and the
        // whole of its answer came back — that judgement is what put it here,
        // through backend_pool_eligible() and http_response_frame_complete().
        // Nothing has been asked of it since.  So a byte waiting on it is a
        // byte nobody asked for: either the answer this proxy called finished
        // was not, or the backend volunteered a second one, or the peer is not
        // speaking the protocol we think it is.  In every one of those the
        // stream is at an offset no request can start from, and handing the
        // socket over makes those bytes the head of the next client's response
        // — one client reading another client's data, which is exactly what
        // this pool exists to make impossible.
        //
        // So readable is not merely "not reusable now".  It is evidence about
        // the socket that does not expire: leaving it on the shelf leaves the
        // same bytes on it for the next borrower to inherit, and re-probing it
        // later can only reach the same conclusion.  It is destroyed here.
        // shutdown() first so the backend is told the connection is over rather
        // than being left with a half-open socket this proxy will never read,
        // and so the unread bytes leave with a reset instead of being mistaken
        // for a graceful end of message.
        //
        // A socket carrying a session is asked the same question by
        // probe_pooled_tls(), which has to decrypt to answer it.  The
        // discrimination is identical and the mechanism cannot be: see there.
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
            // Once per instance.  A backend that does this does it on every
            // socket it has, and a message per pooled connection would bury the
            // log — but a client receiving somebody else's answer is what the
            // silent version of this cost, so it is not nothing either.
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

// Return a backend fd to the pool for later reuse.  Every path that pools one
// comes through here — close_pair_close_backend, detach_and_pool_backend and
// finish_pool_drain — so this is where it is decided whether the socket may
// change hands at all.
// The session travels with the descriptor or it does not travel at all.
// `bconn` is the connection being given up: on the one path that files an
// entry, the session is moved out of it here and backend_pool_release — which
// every caller runs afterwards, and which frees whatever session it still finds
// — has nothing left to free.  On every path that closes instead, the session
// is deliberately left where it is, so that same call frees it.  One owner at
// every instant, and the transfer is the same statement as the filing.
void proxy_instance::release_to_pool(int backend_fd, size_t backend_idx,
                                     std::string_view host, uint16_t port,
                                     proxy_backend_connection* bconn)
{
    if (backend_fd < 0 || backend_idx >= m_backend_pool.size())
        return;

    // A socket with no endpoint on it cannot be given back to one.  Callers
    // establish the key through backend_endpoint_of and only pool when it
    // answered; this is the backstop, and it closes rather than files.
    if (host.empty() || port == 0)
    {
        shutdown(backend_fd, SHUT_RDWR);
        close_tracked(backend_fd);
        return;
    }

    // Pooling is the third way to give a descriptor away, next to closing it
    // and freeing its fixed-file slot, and it has the same hazard even though
    // the number never goes back to the kernel: the socket is handed to the
    // next request while an SQE the kernel has not consumed yet still names it,
    // and that operation then belongs to a connection it was never part of.  A
    // queued read steals the new request's response; a queued splice writes the
    // old request's tail into it.
    //
    // The callers' own flags cannot answer this.  They track what *this* struct
    // armed, and the flags are cleared by the completion, which is what makes
    // them look finished while the submission is still queued.  The loop counts
    // the number itself, so it answers for anything that named the descriptor —
    // including, on this runtime, the peer's outbound splice.
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

    // The session, if this connection has one, moves here.  backend_pool_
    // eligible() has already established that it is one that may be reused —
    // handshake finished, no alert owed, the peer has not said close_notify —
    // so this is the transfer and not the decision.
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
    // reclaim.  No-op while it is already running.
    arm_idle_sweep();
}

// Finish setting up backend after connect (pooled or async connect completion).
// Creates backend conn struct, registers in maps, sets up splice/read.
// Returns true if backend is ready. connect_pending will be false.
// Whether this connection's backend leg is encrypted.
//
// backend_idx cannot answer it on its own: the group path leaves the index
// pointing at the group entry rather than at the member it chose.  It does not
// need to — the backend-TLS options apply to every backend at once, and a
// group's members have no address of their own to carry an https:// scheme —
// so the group case is answered by the all-backends flag and the indexed case
// by the entry itself.
bool proxy_instance::conn_backend_tls(const proxy_client_connection* conn) const
{
    if (SOCKETLEY_LIKELY(!m_backend_tls))
        return false;
    if (m_backend_tls_all)
        return true;
    return !conn->backend_from_group && conn->backend_idx < m_backends.size() &&
           m_backends[conn->backend_idx].tls;
}

// Give a backend connection its session and put the ClientHello on the wire.
//
// The name pinned to the session is the endpoint this request was routed to —
// the host an operator configured, or the member the group selected — and
// never one read back out of the certificate that turns up.  create_ssl_client
// refuses to build a session without one, which is why this can only fail
// closed: a false return costs the socket, and the request is answered 502 or
// retried rather than sent in the clear.
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

    // One turn of the handshake, which produces the ClientHello; the peer
    // speaks next and the read armed on this socket carries the answer.  A
    // negative here is a local failure — no memory, no usable cipher — rather
    // than a rejection: there is nothing on the wire yet to be rejected.
    if (SOCKETLEY_UNLIKELY(tls_context::do_handshake(bconn->ssl) < 0))
        return false;
    return tls_flush(bconn);
}

// Which end a failed connect belongs to, read off errno.
//
// EADDRNOTAVAIL — "cannot assign requested address", the local ephemeral port
// range exhausted — and the out-of-memory family are this machine running short,
// and the backend has not been asked anything at all.  Everything else is the
// backend's own answer: a refusal, an unreachable host, a reset.
//
// One function because the two connects have to agree.  The synchronous
// ::connect() below reports through errno and the asynchronous one reports
// through SO_ERROR in handle_connect; the same shortage arriving by the second
// route used to be read as the backend refusing, which charged the breaker and
// told the client the wrong thing about which end to give up on.
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
    if (SOCKETLEY_UNLIKELY(!target || target->resolved_port == 0))
        return false;

    // The wait for this backend's answer starts here rather than at the first
    // byte sent, so the handshake and the queueing are inside it too — a
    // backend that never accepts is the same problem for the client as one that
    // accepts and never answers.  Every route to a backend passes through this
    // function, including a retry, so this is the one place it has to be armed.
    // TCP mode has no request/response framing to measure and is left alone.
    if (m_protocol == protocol_http)
        arm_response_deadline(conn);

    int bfd = -1;
    const bool backend_tls = conn_backend_tls(conn);

    // Try connection pool first — for a group-routed request too.  What the
    // pool is asked for is an idle socket to *this endpoint*, which is a
    // question the group path can answer as precisely as any other: the member
    // it just selected is on the connection.  Asking by index alone could not,
    // which is why this used to be skipped altogether and why an @group gateway
    // paid for a TCP handshake, and left a TIME_WAIT behind, on every request.
    //
    // For a TLS backend too, now.  This used to be skipped, on the argument
    // that the pool's key cannot express the identity a session carries; the
    // key was never doing that work alone, and acquire_pooled_backend says
    // which part each half does.  What is passed here is the same
    // backend_endpoint_of answer start_backend_tls builds the session from, so
    // a socket can only come back for the name it was verified against.
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
            // A descriptor number past this runtime's own slot table is this
            // process having run out of room, not a backend refusing anything —
            // the connection to it is established and working.  Left
            // unclassified, it charged the breaker and answered the client 502,
            // which is a verdict about a backend that was never asked.
            //
            // The session goes with the descriptor, here as everywhere: this
            // function is its owner from the moment acquire handed it over.
            tls_context::free_ssl(pooled_ssl);
            pooled_ssl = nullptr;
            close_tracked(bfd);
            ours();
            return false;
        }

        conn->backend_fd = bfd;

        auto bconn = backend_pool_acquire(bfd);
        // The session this descriptor's record layer belongs to, before
        // anything else can look at the struct.  reset() has just cleared both
        // fields — a struct out of the struct pool must never carry the
        // previous connection's session — so this is the assignment and not an
        // overwrite, and there is nothing here to free.
        //
        // tls_conn_ready, not tls_conn_handshake: this connection finished its
        // handshake before it was ever pooled (backend_pool_eligible requires
        // it) and there is no second one.  That is the whole saving.  It also
        // has to be said, because tls_flush holds application data back in any
        // other state and the request would sit in the write queue for a
        // handshake that is not going to happen.
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

    bfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (bfd < 0)
    {
        // Out of descriptors is our shortage, not the backend's.
        ours();
        return false;
    }

    if (SOCKETLEY_UNLIKELY(bfd >= MAX_FDS))
    {
        // Same shortage as the pooled branch above, reached with a socket this
        // function opened itself.  socket() succeeding and the number being
        // past MAX_FDS is this process holding too many descriptors.
        close_tracked(bfd);
        ours();
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

        // The session goes on after the read is armed and before the caller
        // forwards anything: the request it is about to queue waits in the
        // write queue until the handshake this starts has finished.  Failing
        // here is our own shortage, not the backend's answer — nothing has
        // reached it yet — so the breaker is not charged.
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
        // Which of the two ends failed decides whether the breaker hears about
        // it.  A refusal, an unreachable host or a handshake that timed out is
        // the backend's answer and belongs in its tally.  EADDRNOTAVAIL —
        // "cannot assign requested address", the local ephemeral port range
        // exhausted — and the out-of-memory family are this machine running
        // short, and the backend has not been asked anything at all.
        //
        // Measured while the machine's port table was full: a gateway charged
        // its own shortage to every member of the group in turn, opened all
        // three breakers, and then answered 503 to everything for a full
        // circuit_timeout — a local resource problem turned into a verdict
        // about three healthy runtimes.  This is the same rule handle_accept
        // already applies to a full ring.  The list itself is in
        // connect_errno_is_ours, because handle_connect has to apply it too.
        if (connect_errno_is_ours(errno))
            ours();
        close_tracked(bfd);
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
        close_tracked(bfd);
        conn->connect_fd = -1;
        conn->connect_pending = false;
        ours();
        return false;
    }

    // Watch the client for death for as long as this handshake lasts.  Nothing
    // else is armed on that socket while a connect is pending, so until this
    // existed a client that reset the moment it had pushed its payload stayed
    // invisible: the pair was held — a 64KB client struct, a client socket and
    // a half-open backend socket — until the handshake finished on its own.
    // With a backend that is slow to accept, that is a second or more each, and
    // a single client looping connect/write/reset put 14000 of those corpses in
    // the proxy at once and a gigabyte of them in its RSS.  The proxy then fell
    // behind on its own listen queue and healthy clients were refused at the
    // SYN, which is how one misbehaving connection took the whole runtime's
    // capacity.  Failing to arm it is not fatal — it only means this connection
    // goes back to being noticed late — so nothing is unwound on refusal.
    // See proxy_instance.h for why POLLERR|POLLHUP and nothing more.
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
    // Never on a connection with a TLS session on either leg.  A splice moves
    // bytes from one descriptor to the other inside the kernel, and OpenSSL
    // never sees them: what left an encrypted client would arrive at the
    // backend as ciphertext nothing decrypted, and — the direction that
    // matters — what this proxy was asked to encrypt would be handed to the
    // wire exactly as it arrived, in the clear, on a port an operator was told
    // was encrypted.
    //
    // The guard is here rather than at the three call sites because leaving
    // splice_active false is all it takes: the pair then runs on the ordinary
    // read/write path, which is where the record layer lives.
    if (SOCKETLEY_UNLIKELY(conn->ssl != nullptr || bconn->ssl != nullptr))
        return;

    // Create pipe for client -> backend direction.
    //
    // O_CLOEXEC on both pairs: these live for the whole splice-mode connection,
    // so a proxy worker forked mid-transfer would inherit four descriptors per
    // connection in flight and hold them until it exits — the busiest leak of
    // the set, because it scales with concurrency rather than with runtimes.
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

// Arm the socket half of a splice pipeline.
//
// WHY THIS IS A POLL AND NOT THE SPLICE
//
// io_uring never runs IORING_OP_SPLICE on the submitting thread: the opcode is
// prepped REQ_F_FORCE_ASYNC, so every splice is handed to an io-wq worker and
// executed there synchronously.  A splice reading from a socket that has no data
// yet therefore does not "wait in the kernel" for free — it sits inside
// tcp_splice_read on a worker thread, and it holds the destination pipe's mutex
// the whole time, because splice_file_to_pipe takes pipe_lock around the read.
//
// Arming it on a quiet socket, which is what an idle keep-alive connection is
// almost all of the time, costs one kernel thread per connection for as long as
// the peer says nothing.  Whether it *also* burns a CPU depends on an accident:
// tcp_splice_read decides whether to wait from the socket file's O_NONBLOCK, not
// from the splice flags.  Accepted client sockets here are blocking, so that leg
// parks a thread; backend sockets are opened SOCK_NONBLOCK for the async
// connect, so that leg returns -EAGAIN at once and the completion handler
// resubmits it — an unbounded resubmit loop for as long as the backend has
// nothing to say.
//
// Measured on this tree, a --protocol tcp proxy with nothing whatsoever
// happening on it:
//
//     idle connections   daemon CPU   io-wq threads   parked in the socket wait
//                    0         0.0%               0                          0
//                    4        95.7%               7                          4
//                   16       143.0%              20                         16
//                   48       210.6%              53                         48
//
// Four silent connections cost a core.  Forty-eight cost two cores and fifty
// threads.  That is the whole cost of a proxy that is doing nothing at all, and
// it is also what makes a splice that *does* have work wait: every worker is
// parked in someone else's idle read, and the io-wq run queue is being churned
// by the resubmit loop.
//
// A poll costs no thread and no CPU.  Once it fires the splice is submitted with
// data already waiting, so the worker it runs on returns immediately, holds the
// pipe mutex for microseconds, and goes back to the pool.  splice_in_pending
// stays set across both steps on purpose: every teardown path already reads it
// as "this connection still owes a completion", and that is true of the poll
// exactly as it was of the splice.
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

    // The readiness half of the inbound leg reporting.  See arm_splice_in_poll:
    // the splice is only submitted once the socket has something, so that the
    // io-wq worker it runs on is not spent waiting.  A poll that reports a
    // failure — a cancellation from a teardown, an error on the socket — is
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
                    // Back through the readiness poll, not straight back into
                    // the ring.  A splice resubmitted on a socket that answered
                    // EAGAIN answers EAGAIN again, so the direct retry was a
                    // loop bounded by nothing at all.
                    conn->splice_in_pending = true;
                    if (SOCKETLEY_UNLIKELY(!arm_splice_in_poll(conn->fd, &conn->splice_in_req)))
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

            // Re-arm the inbound leg (client -> pipe).  The connection is quiet
            // again at this point, which is exactly the state a splice must not
            // be left parked in — so this waits on readiness instead.
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
    // ── a connection carrying a session ──
    //
    // This used to be a flat refusal, and the reason given was that the pool
    // is keyed on a host and a port while a TLS connection carries more: a
    // negotiated session, a peer verified against a name, a client certificate
    // that may have been presented, and a record layer part way through a
    // stream.  Every one of those is true.  What was wrong was the conclusion
    // that none of it is expressible — three of the four are functions of the
    // key already and the fourth is a function of the instance, which is what
    // acquire_pooled_backend and pooled_backend now say in the two places they
    // are decided.  The record layer is answered by pooling the session with
    // the descriptor instead of the descriptor alone.
    //
    // What is decided *here* is narrower and is about this connection rather
    // than about identity: whether there is a session worth reusing at all.
    if (bconn->ssl != nullptr)
    {
        // A handshake that has not finished has negotiated nothing.  The next
        // borrower would have to carry it on, which means the request waiting
        // behind it waits on a peer that may never answer — and tls_flush
        // would hold that request back, correctly, for as long as it took.
        if (bconn->tls_state != tls_conn_ready)
            return false;
        // close_notify, or a record the session could not use.  Either ends
        // it; there is no more application data to be had on this one, and a
        // request written into it would be written into a stream the peer has
        // already stopped reading.
        if (bconn->tls_peer_closed)
            return false;
        // The record layer still owes the wire bytes.  On this path that is an
        // alert on its way out — the diagnosis the far end is entitled to —
        // and pooling would strand it in a write BIO nobody is draining.  The
        // write-queue test below is the same rule one layer up and does not
        // cover this: application data is queued there, but a record layer's
        // own traffic is queued nowhere.
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
    // Where this response ended could not be established (see
    // http_frame.unknown).  Reuse only works if both ends agree the stream is
    // back at a message boundary, and here we cannot say that it is — the
    // socket may still have the tail of this response on it, which the next
    // borrower would read as the first bytes of its own.  Every path that gives
    // a backend socket back to the pool comes through here, including the
    // teardown ones, so this is the one place the answer has to be no.
    if (bconn->http_frame.unknown)
        return false;
    // The same argument one step earlier: a response that has not *finished*
    // leaves the socket at an offset just as surely as one whose framing could
    // not be read.  Only the detach path used to ask this, and it asked at its
    // own call site rather than here — so a pair torn down mid-response was
    // poolable from every close_pair() there is.
    //
    // What normally hides it is the armed read: a multishot recv stays pending
    // across completions, so teardown defers, sets `closing`, and the answer is
    // no for that reason instead.  The window is whenever that read is *not*
    // armed while the response is only half delivered — the backpressure pause
    // (a plain read is not re-armed while the client's write queue is over the
    // limit, so nothing is in flight), the ENOBUFS fallback that replaces the
    // multishot with one plain read, a re-arm the ring refused, and the
    // completion that ends a multishot stream.  On those paths nothing defers,
    // `closing` is false, and a client aborting at that moment used to hand the
    // pool a socket with the rest of somebody's response still on it.  Cheap to
    // ask, and the question does not depend on which read mode is in force,
    // which is the point: it stops the answer being a coincidence.
    //
    // This is also where a tunnel is refused.  A connection that answered 101
    // has no message boundary at all — it stopped carrying messages — and
    // http_response_frame_complete() says so as its first act rather than
    // failing to find the end of a response that does not exist.  Handing one
    // to the pool would give the next request a live WebSocket session.
    if (!backend_response_complete(bconn))
        return false;
    if (!cconn)
        return false;
    // The key is read off the client, so the client has to be this socket's
    // own.  Every caller passes the pair it is tearing down, but close_pair
    // takes two descriptor numbers rather than a pair, and a caller that gets
    // them from different connections would otherwise file this socket under
    // an endpoint it was never opened to.  Cheap, and it makes the key's
    // provenance a checked fact instead of a caller's promise.
    if (bconn->client_fd != cconn->fd)
        return false;
    // A group-routed connection is poolable — under the member it actually
    // reached, which is what backend_endpoint_of returns and what
    // release_to_pool files it by.  Refusing here is what made an @group
    // gateway open a fresh TCP connection for every single request.
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
    // Check pool eligibility.  The endpoint comes out of the same predicate
    // that approved the socket, so the two cannot disagree about which peer it
    // is being filed under.
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

    // A splice the backend has already started towards the client's descriptor
    // is as good a reason to keep that descriptor as one of the client's own
    // operations, and it is not covered by any of the client's flags: the
    // request lives on the backend's struct, and it names the *client's* fd.
    //
    // This is where an aborting client's payload was landing in a stranger's
    // socket.  A submission carries a descriptor *number*, and the kernel
    // resolves it when it consumes the SQE — with SQPOLL that is a separate
    // thread, and even without it this loop batches a whole completion round
    // before it submits.  So closing the number here and letting the next accept
    // take it does not cancel that write, it redirects it: the 8KB an aborted
    // client had already pushed to the backend came back and was spliced
    // straight into whoever inherited the number, in the middle of that
    // connection's own stream.  The mutual-pairing checks on the forwarding
    // paths cannot catch it, because they were right when they ran — the
    // descriptor moved afterwards.  Holding it until that splice reports is what
    // makes the number safe to give away.
    //
    // event_loop::close_fd now holds every descriptor number on exactly this
    // rule, for every operation naming it and not only for a peer's splice, so
    // this test is no longer the thing standing between the bug and the user.
    // It is kept because it is the one path that was actually reproduced, and
    // because it holds something close_fd cannot: the whole teardown, and with
    // it the struct the splice request lives in.  Remove it only with a
    // reproducer to remove it against.
    //
    // Read before anything below runs: the block that closes the client's other
    // backend clears conn->backend_fd on its way out, and the answer would be no
    // by the time it is asked.
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
                // A queue that still holds data is as good a reason to defer as an
                // operation in flight: closing here throws away bytes the client
                // already handed us and considers delivered.  Keep the write side
                // open and push them out; the write completion tears down once the
                // queue has actually drained.
                bconn->closing = true;
                if (!bconn->write_pending &&
                    (!bconn->write_queue.empty() || tls_owes_output(bconn)) &&
                    !flush_backend_write_queue(bconn))
                    defer = false;
                else
                    shutdown(backend_fd, SHUT_RD);

                // And a flush that reported success is not the same as a
                // completion on its way.  On a TLS leg whose handshake never
                // finished, tls_flush holds the application data back on
                // purpose — a request handed to an SSL that would answer
                // WANT_READ is a request nobody can say was sent — and returns
                // true with the queue untouched and nothing submitted.  The
                // deferral was then a promise nothing keeps: the queue is only
                // ever flushed from inside a completion handler, no completion
                // is coming, so those bytes never go out and this descriptor is
                // held until the runtime stops.  That is the state
                // SKL_INV_PAIR names — "nothing in flight on either half, this
                // pair will never be woken again" — and it was reachable from
                // any backend torn down mid-handshake with a request queued
                // behind it.
                //
                // So the test is what the invariant tests, and not what the
                // flush returned.  When nothing is in flight the queue can no
                // longer drain and holding the descriptor buys nobody
                // anything; the teardown below is the honest outcome, and it is
                // the same one this function already reaches when the flush
                // fails outright.
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

            // Close pending async connect fd.  The POLLOUT armed on it is not
            // taken back by the close — the poll holds its own reference to the
            // file — so close_fd cancels it to get the completion now rather
            // than when TCP eventually gives up.  connect_pending stays set on
            // purpose: it is what tells client_pool_release() that this struct
            // cannot be reused yet.
            //
            // This was the one site the earlier fix named and left alone —
            // "submit_cancel_fd(connect_fd) immediately followed by
            // close(connect_fd), the same hazard class; I have no evidence it
            // fires, so I left it rather than guess."  There is still no
            // evidence it fires.  It is closed here because the mechanism costs
            // nothing to apply and does not need any.
            close_tracked(conn->connect_fd);
            conn->connect_fd = -1;

            // The abort watch is a poll on the client socket and survives its
            // close for the same reason.  Withdrawing it by request rather than
            // by descriptor matters here: a read or a splice may be armed on
            // this same socket and the deferral below is counting on it.
            // abort_watch_pending stays set on purpose — it is what tells
            // client_pool_release() this struct cannot be reused yet.
            if (conn->abort_watch_pending && m_loop)
                m_loop->submit_poll_remove(&conn->abort_req);

            // Zero-copy notification included, for the reason given on the
            // backend side above.  peer_splicing_into_client is the descriptor
            // the backend is still writing into — see the top of this function.
            bool defer_c = conn->read_pending || conn->write_pending ||
                           conn->zc_notif_pending ||
                           conn->splice_in_pending || conn->splice_out_pending ||
                           !conn->write_queue.empty() || tls_owes_output(conn) ||
                           peer_splicing_into_client;
            if (defer_c)
            {
                conn->closing = true;
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
                    // The two pipe residencies used to be read with FIONREAD.
                    // They must not be: a splice from a socket into a pipe holds
                    // that pipe's mutex for the whole time it waits for the
                    // socket, and pipe_ioctl takes the same mutex — so this
                    // trace could park the event loop in uninterruptible sleep
                    // until some unrelated client sent a byte.  The residency is
                    // already implied by the counters below (sp_in - sp_out), so
                    // the question did not need asking of the kernel at all.
                    pipe_c = (int)(long long)(conn->tr.sp_in - conn->tr.sp_out);
                    if (conn->backend_fd >= 0 && conn->backend_fd < MAX_FDS &&
                        m_conn_idx[conn->backend_fd].side == conn_backend)
                    {
                        [[maybe_unused]] auto* tb2 = m_conn_idx[conn->backend_fd].backend;
                        be_in = tb2->tr.sp_in; be_out = tb2->tr.sp_out;
                        pipe_b = (int)(long long)(tb2->tr.sp_in - tb2->tr.sp_out);
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
                close_tracked(client_fd);
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
    //
    // This is the one cancel in the daemon submitted for a descriptor that is
    // meant to stay open and change hands rather than be closed, which is why
    // it is here and not left to close_fd.  What makes that safe is that the
    // socket is only ever pooled from finish_pool_drain, and only when the read
    // came back -ECANCELED — proof that this cancel has already been consumed.
    // Pooling it any earlier would let IORING_ASYNC_CANCEL_ALL take back the
    // *next* request's read on the same socket.
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
        // Read now, while the pair is still a pair.  The client is released
        // three lines below and may be routed to a different member of the
        // same group before the cancellation lands, taking the endpoint this
        // socket belongs to with it.
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

    // Nothing is in flight, so the socket can be handed over here and now — but
    // only if it may be pooled at all, and only under the endpoint it actually
    // reached.  This used to pool it unconditionally under cconn->backend_idx,
    // which describes nothing for a group-routed connection: the group path
    // leaves the index on the group entry, so the socket of one member would
    // have been handed to the next request routed to any of them.
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
    //
    // -ECANCELED is also what makes this the one place allowed to pool a
    // descriptor that event_loop is still counting a cancel against.  The read
    // came back cancelled, so the cancel detach_and_pool_backend submitted has
    // demonstrably been consumed — its own completion may still be in this same
    // batch, but the number was resolved before this CQE existed.  Any other
    // answer sets pool_abandoned and the socket is closed rather than pooled,
    // which is the safe side of the same question.  fd_inflight() deliberately
    // does not count cancels for exactly this reason; see event_loop.h.
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
                         conn->pool_backend_idx < m_backend_pool.size() &&
                         !conn->pool_host.empty() && conn->pool_port != 0))
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
    // There is no next request.  The client half-closed its write side during
    // this exchange, which says exactly that, and handle_client_read held the
    // pair open so this answer could be finished rather than thrown away.  It
    // has been: every caller of this function reaches it with the response
    // already forwarded or queued.  So the hold ends here — close_pair defers
    // on whatever is still in flight and on whatever is still in the write
    // queue, so the tail of the answer goes out first.
    //
    // This is what keeps the hold bounded on the happy path: the connection is
    // not put back into the keep-alive pool to wait for a second request that
    // by definition cannot come, and no read is armed on it that would let it
    // sit there.
    if (SOCKETLEY_UNLIKELY(cconn->client_eof) && cconn->fd >= 0)
    {
        cconn->closing = true;
        close_pair(cconn->fd, cconn->backend_fd);
        return;
    }

    cconn->header_parsed = false;
    cconn->response_started = false;
    // The exchange this connection was being timed for is over.  The next
    // request arms deadlines of its own — one when its first bytes turn out not
    // to be a whole header block, one when it reaches a backend.  Until then
    // this connection is merely idle between requests, which is --idle-timeout's
    // business and not the header deadline's.
    cconn->awaiting_response = false;
    cconn->awaiting_headers = false;
    cconn->client_conn_close = false;
    cconn->method.clear();
    cconn->path.clear();
    cconn->version.clear();
    // Per request, not per connection: the next request on this socket gets the
    // chain's verdict on itself, not the last one's.  run_request_filters
    // clears it too, but only for requests that reach the chain — a keep-alive
    // connection whose second request is answered 404 before it does would
    // otherwise still be carrying the first request's headers if it ever
    // reached a backend.
    cconn->filter_headers.clear();
    cconn->filter_removed_headers.clear();

    // The answer arrived before the client had finished sending its body — an
    // early 4xx, say.  Then what is buffered is the tail of that body rather
    // than a request, there is no longer a backend to send it to, and reading it
    // as a request line would answer 400 to bytes the client never meant as one.
    // Unclassifiable, so dropped.
    const bool body_owing = cconn->body_unbounded || cconn->body_remaining > 0;
    cconn->declared_body_len = 0;
    cconn->declared_body_chunked = false;
    cconn->body_remaining = 0;
    cconn->body_unbounded = false;
    if (body_owing)
        cconn->partial.clear();
    cconn->saved_request.clear();

    // conn->partial is deliberately *not* cleared any more.  A request pipelined
    // behind the one just answered is sitting in it: rewrite_http_request now
    // forwards only the body its request declared and leaves the rest here,
    // precisely so that the rest goes through the framing checks instead of
    // round the back of them.  Dropping it here would turn that hold into a lost
    // request and break pipelining outright — the point is that the second
    // request is checked, not that it is discarded.
    //
    // Nothing else will come to wake it, either: the client is waiting for its
    // answer, so there is no further read to trigger the parse.  Drive it here,
    // down exactly the path a read would have taken.  This is the last statement
    // of every branch that calls this function, because it can conclude that the
    // pipelined request is malformed and take the connection down with it.
    if (m_protocol == protocol_http && !cconn->partial.empty() &&
        !cconn->closing && cconn->fd >= 0)
        drive_client_request(cconn, cconn->fd);
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
        // Half-open is meant to cost one request to find out whether the
        // backend is back.  Saying "available" to every selection instead
        // poured the whole rotation into it until the first answer came back,
        // so each timeout transition cost a burst — and against a backend that
        // stalls rather than refuses, that burst is a burst of full deadlines.
        // The elapsed bound is there because the probe's answer is not
        // guaranteed to arrive at all: the client can go away first.
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

// A backend has just been picked for a request.  While it is half-open that
// request *is* the probe, and no second one may go out until it has reported.
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
    // An operation still in flight is not taken back by close() — it holds its
    // own reference to the file — and without a cancel its completion could be
    // minutes away, keeping the probe retired for just as long.  close_fd
    // submits that cancel when, and only when, something is armed, and holds
    // the number until it and the operation have both reported: a health probe
    // runs on a freshly created socket and is dropped at a rate the backend
    // decides, so its numbers are recycled as fast as any in the runtime.
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
    // Ciphertext goes into the probe's own buffer, plaintext into the one the
    // verdict is read out of.  Either way it is memory this struct owns and
    // retire() holds for as long as the ring can reach it.
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

        // Whatever is left in this slot belongs to an earlier sweep.  It is let
        // go rather than reused: reusing it is what let a late completion write
        // into the address the next connect was about to read.
        drop_health_check(i);

        if (b.is_group)
            continue;

        int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
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
                close_tracked(fd);
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
            close_tracked(fd);
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

        // An HTTPS probe is this same probe one layer down.  The request is the
        // same GET, the verdict is read off the same status line, and what
        // changes is that the bytes on the wire are TLS records — and that the
        // backend has to prove who it is before it can be called healthy at
        // all.  That last part is not a side effect: a probe that accepted any
        // certificate would report a backend healthy that the data path is
        // about to refuse to send a request to, and an operator would be
        // looking at a rotation full of endpoints nothing can reach.
        //
        // Same session factory as the data path — create_ssl_client, which
        // will not build a session without a name to pin it to — so the chain
        // is checked against --ca or the system store, the certificate against
        // this endpoint's own name, TLS 1.2 minimum, with nothing to switch
        // off.  Same memory BIO pair, same io_uring submissions, and the
        // handshake advanced one completion at a time.
        if (b.tls)
        {
            // No trust store, or no name to pin: this proxy cannot verify
            // anything here, so it records nothing rather than charging the
            // peer for a question it was never asked.  Neither is reachable
            // from a started proxy — start() builds the context whenever any
            // backend is TLS, and a backend that did not resolve is skipped by
            // the sweep — which is why they cost the backend nothing.
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

            // The first turn produces the ClientHello and nothing else; the
            // peer speaks next.  A negative here is local — no memory, no
            // usable cipher — rather than a rejection, because there is
            // nothing on the wire yet to be rejected.
            if (SOCKETLEY_UNLIKELY(tls_context::do_handshake(hc->ssl) < 0) ||
                SOCKETLEY_UNLIKELY(!health_tls_arm(hc)))
                drop_health_check(slot);
            return;
        }

        hc->write_buf = "GET " + m_mesh.health_path + " HTTP/1.0\r\nHost: " +
                        b.resolved_host + "\r\nConnection: close\r\n\r\n";
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

        // A short write is ordinary and used to be treated as a completed one.
        // Mid-handshake that leaves the record stream with a hole in it and the
        // peer answering an alert; mid-request it leaves a truncated GET the
        // backend answers 4xx to.  Both would be recorded against the backend,
        // and neither is the backend's doing.
        hc->write_off += static_cast<size_t>(cqe->res);
        if (SOCKETLEY_UNLIKELY(hc->write_off < hc->write_buf.size()))
        {
            if (SOCKETLEY_UNLIKELY(!health_submit_write(hc)))
                drop_health_check(slot);
            return;
        }

        // Read the answer.  Into the probe's own buffer, which nothing else
        // shares: the connect address has a field of its own.
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
            // Every verification failure lands here — an unknown CA, an expired
            // chain, a certificate that is not valid for the name this endpoint
            // was configured under — along with a peer that refused outright.
            // A backend this proxy would not send a request to is not a healthy
            // backend, and recording it as one is the exact hole this probe was
            // not allowed to become.  do_handshake has already logged which.
            record(false);
            drop_health_check(slot);
            return;
        }
        if (r == 0)
        {
            // Another round.  Its records go out below if it produced any, and
            // it is the peer's turn again if it did not.
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
        // Partial writes are not enabled on this context, so this is
        // all-or-nothing; a short count would mean the record layer and this
        // probe disagree about what was sent.  Either way it is local, so no
        // verdict is recorded on it.
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

            // Decrypt everything the record layer now has.  Accumulated rather
            // than judged per read: a status line split across two records is
            // ordinary, and a verdict taken off the first of them would call a
            // healthy backend dead for answering in two pieces.
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
                // Not enough of the status line yet.  The sweep's own 500 ms
                // deadline is what bounds this, exactly as it bounds every
                // other step of the probe.
                if (SOCKETLEY_UNLIKELY(!health_submit_read(hc)))
                    drop_health_check(slot);
                return;
            }
            got_2xx = (hc->plain_len > 12 && hc->buf[9] == '2');
        }
        else if (cqe->res > 12)
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

    // The abort watch covered exactly this handshake; from here on the client's
    // own read, or the splice pipeline, reports its death.  Withdraw it rather
    // than leave a poll armed for the rest of the connection's life: every
    // struct that still owes a completion is retired instead of pooled, so a
    // watch nobody takes back costs the pool one struct per connection.  The
    // flag stays set until the -ECANCELED lands, which is what tells
    // client_pool_release the struct is not reusable yet.
    if (conn->abort_watch_pending && m_loop)
        m_loop->submit_poll_remove(&conn->abort_req);

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
        if (fd_ours && bfd >= 0) close_tracked(bfd);

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
            note_backend_failure(conn);

        // And the same three things decide what the client is told.  The
        // asynchronous connect reports its errno through SO_ERROR, so the local
        // shortages arrive here exactly as they arrive at the synchronous
        // connect — and reached the client as 502 either way, which named a
        // backend that had not been asked anything.
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
        // The connect worked and this process has nowhere to put the result:
        // a descriptor number past the slot table, or one the deadline sweep
        // withdrew while this completion was in flight.  Ours either way.
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
        // The backend is connected and this proxy cannot arm a read on it.  Our
        // shortage, and the client had been waiting on it in silence.
        answer_gateway_failure(conn, true);
        close_pair(conn->fd, bfd);
        return;
    }

    // The handshake starts here, before the saved request is forwarded: what
    // forward_to_backend queues waits in the write queue until the session is
    // ready, and goes out as records when it is.  A session that cannot be
    // created costs the pair — the alternative is sending the request in the
    // clear to a backend the operator asked to reach over TLS.
    //
    // 503 and not 502, which is what this used to say.  Nothing has reached the
    // backend yet — start_backend_tls fails on a session that could not be built
    // or a first handshake turn that could not be taken, and its own comment
    // calls that "a local failure — no memory, no usable cipher — rather than a
    // rejection: there is nothing on the wire yet to be rejected".
    // connect_to_backend classifies the identical failure as ours already; the
    // two disagreed only because this one wrote its status by hand.  A backend
    // that *refuses* the handshake is a different event and still answers 502,
    // from handle_backend_read, where the rejection actually arrives.
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

    // The client read was deliberately left unarmed until a backend existed;
    // now that one does, start taking data.  (The splice path returns earlier —
    // there the pipeline does the reading.)
    if (!conn->closing && !conn->read_pending && !conn->splice_active &&
        SOCKETLEY_UNLIKELY(!submit_read_op(m_loop, conn->fd, conn, m_recv_multishot,
                                           m_use_provided_bufs, BUF_GROUP_ID)))
    {
        answer_gateway_failure(conn, true);
        close_pair(conn->fd, bfd);
        return;
    }

    // The client had already half-closed while this connect was in flight, and
    // its payload has just been queued for the backend above.  What used to
    // stand here was `shutdown(bfd, SHUT_WR)` — passing the half-close on — and
    // it must not: forward_to_backend only PREPARES the send, and nothing
    // reaches the kernel until this completion round submits.  A FIN issued
    // here is a syscall, so it overtakes the request it is supposed to
    // terminate; the backend gets an empty stream and the send that follows it
    // fails EPIPE.  That is the same loss this whole path exists to prevent,
    // reintroduced one line further along.
    //
    // Nor is it needed.  A request only reaches a backend after
    // parse_http_request_line has proved its framing gives exactly one answer
    // to "how long is the body" — Content-Length or chunked, never both, never
    // twice — so the backend knows where the request ends without being told.
    // client_eof is read where it changes an outcome instead: the connection
    // gets the answer to this request and is then closed rather than kept alive
    // for a second one, in reset_client_for_next_request.
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

    // POLLNVAL says the descriptor is no longer valid.  The number may already
    // belong to someone else, so it must not be closed on the strength of this
    // — the same reasoning as the POLLNVAL branch in handle_connect.
    if (SOCKETLEY_UNLIKELY(revents & POLLNVAL))
        return;

    if (!(revents & (POLLERR | POLLHUP)))
        return;

    // Already being torn down: whatever is in flight will finish the job, and
    // re-entering here would only race it.
    if (conn->closing)
        return;

    // The client is gone for good — reset, or shut down in both directions.
    // Whatever the backend eventually says has nowhere to go, so the handshake
    // still running for it is work nobody will ever collect.
    SKL_TRACE_LOG("client-abort cfd=%d revents=0x%x connect_pending=%d clients=%u",
                  client_fd, revents, (int)conn->connect_pending, (unsigned)m_client_count);
    close_pair(client_fd, conn->backend_fd);
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
    // Already running: the deadline dates from the first incomplete read of
    // this request and is not renewed by later ones.  Renewing it would hand
    // the bound straight back to the client — one byte before every expiry is
    // cheaper for an attacker than a whole connection.
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

// The only evidence a stalled backend ever produces — and, since the header
// deadline was added, the only evidence a stalled *client* produces either.
// Both are the same failure seen from opposite ends: a peer that holds a
// connection open and never finishes what it started, which no error counter,
// no health check and no byte limit can see.
//
// Nothing else notices one: a TCP health probe connects to it perfectly well, a
// request that never completes is recorded as neither success nor failure, so
// the breaker counts nothing and the backend keeps its full share of the
// rotation.  The client is what eventually gives up, one connection at a time,
// which is why the surviving backends look flawless while throughput collapses.
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

        // Half-sent request.  A connection cannot be waiting on a header block
        // and on a backend at the same time — the request has to be whole
        // before it is forwarded — so this arm and the one below never both
        // apply to the same connection, and the order between them is only
        // about which is cheaper to test.
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

        // Charged to the backend, so the breaker opens and takes it out of
        // rotation — the same route a refusal or a reset takes.  A group-routed
        // connection is charged to the member it actually reached rather than
        // to backend_idx, which names the whole group; before there was a
        // breaker per member this had to be skipped altogether, and a group
        // member that accepted connections and never answered them kept its
        // full third of the traffic indefinitely.
        note_backend_failure(conn);

        // The handshake itself never finished — the backend is not refusing and
        // not answering, it is swallowing SYNs.  try_retry() must not be used
        // here: it does not look at connect_pending, so it would overwrite
        // connect_fd (leaking the socket the poll is still watching) and arm a
        // second operation on the one connect_req.
        //
        // This used to call close_pair() and be done, which closed the client
        // without writing a byte to it.  That is the one outcome a client
        // cannot act on: no status, no framing error, nothing to distinguish a
        // proxy that has gone away from a backend that has, so a keep-alive
        // client cannot even tell whether re-sending the request is safe.  It
        // is also silent in every log and every metric on the client's side.
        // A backend that never completed its handshake inside the deadline is
        // precisely what 504 means, and saying so costs one write.
        //
        // The connect is withdrawn by hand rather than by close_pair because
        // the client has to outlive it: close_tracked() cancels the POLLOUT
        // armed on the socket and holds the descriptor number until that
        // cancellation has been consumed, so nothing inherits it early.  The
        // completion still arrives — handle_connect finds connect_fd already
        // cleared, treats it as a failed connect, and its send_error is a
        // no-op against a connection that is already closing.  connect_pending
        // deliberately stays set: it is what tells client_pool_release the
        // struct is still owed a completion and must be retired, not reused.
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
    // "this many failures in a row".  Without this the count only ever rose,
    // so the breaker measured a backend's lifetime error total rather than its
    // current health and would eventually open on any backend that had ever
    // failed, however long ago and however healthy since.
    cb.error_count = 0;
}

// "host:port" in a caller-owned buffer.  Written out rather than hashed
// because a hash collision here would take a healthy member out of rotation
// for its neighbour's failures, and returned as a view so a lookup on the
// selection path allocates nothing.  Empty when the host will not fit, which
// every caller reads as "no breaker" — the safe answer, since it can only
// leave an endpoint in rotation, never remove one wrongly.
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

    // An endpoint with a clean record needs no entry.  Erasing it is what keeps
    // this map the size of the *broken* part of the group rather than a tally
    // of every member that has ever been in it — the group's membership is not
    // the proxy's to bound.
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

    // Nor after the client has been answered and is on its way out.  The
    // deadline sweep now answers a connect that timed out with a 504 and lets
    // the cancelled handshake report afterwards; handle_connect reads that
    // report as a failed connect and would otherwise open a fresh backend
    // connection to serve a request that has already been answered — and then
    // deliver the second answer into a half-closed socket.
    if (conn->closing)
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
            if (old_bconn->pipe_to_client[0] >= 0) close_tracked(old_bconn->pipe_to_client[0]);
            if (old_bconn->pipe_to_client[1] >= 0) close_tracked(old_bconn->pipe_to_client[1]);
            old_bconn->pipe_to_client[0] = -1;
            old_bconn->pipe_to_client[1] = -1;

            shutdown(conn->backend_fd, SHUT_RDWR);
            close_tracked(conn->backend_fd);
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

std::string proxy_instance::get_stats() const
{
    // Out-of-process: the text was built by the worker, on the worker's
    // event-loop thread, walking the connection tables that only that thread
    // may walk.  Returning it verbatim is what makes `stats` and `inspect`
    // answer identically on both paths — and rebuilding it here from this
    // object's own empty containers is precisely the wrong answer.
    if (worker_backed())
        return stat_detail_snapshot();

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

    // How many routes this proxy is enforcing, out of what its backends
    // published.  Zero is the answer to most of the questions this feature will
    // ever be asked — "why is my 405 not happening", "did my declaration
    // arrive" — and every one of them is otherwise unanswerable from outside:
    // a backend that declares nothing, a backend named by address, a script
    // that failed to load and a proxy started before the handler all look
    // exactly alike from the client side.
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
    // endpoint.  Without this an operator looking at a gateway answering 503
    // has nothing to look at: the breaker that is refusing the request would
    // not appear anywhere in the output.  Healthy members leave no entry, so
    // this line is absent while the group is working.
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
        // ─── A hook that could not say what it meant refuses ────────────────
        //
        // This is where a script strips a header, redacts a field or rejects a
        // request outright.  Both branches below used to fall through to the
        // forward at the bottom of this function with the bytes untouched, so
        // an error in the hook admitted precisely what the hook was there to
        // refuse — and `return false`, the one unambiguous way to write a
        // rejection, was an admission.
        //
        // run_request_filters settled this question the other way, one screen
        // up, with the reasoning written out: a filter that raises has not said
        // "carry on", and a third kind of return value is a script that means
        // something this side cannot read.  Two hook APIs on one runtime with
        // opposite rules is the part that could not stand.
        //
        // Refusal here is closing rather than a 500.  This function is the byte
        // path: it carries TCP as readily as HTTP, and on HTTP it is called
        // with body chunks as well as with the head, so a status line written
        // from here would either be injected into a stream that is not HTTP or
        // spliced into the middle of one that is.  Closing is also this
        // function's own stated rule — see its header: every path out of it
        // that does not deliver takes the client down with it, because a
        // connection that silently swallows data is worse than one that drops.
        // Protected, like on_route above and the filter chain.  A try/catch
        // here reported nothing at all under the Sanitize build — measured: the
        // hook ran, the request was refused, and no `on_proxy_request error`
        // line was written — because the catch depends on the panic handler
        // throwing and on that throw unwinding out of the interpreter.  A
        // refusal nobody can explain is barely better than the admission it
        // replaced, so the error has to come back as a value.
        sol::protected_function_result r = lctx->on_proxy_request()(conn->fd, data);

        if (SOCKETLEY_UNLIKELY(!r.valid()))
        {
            sol::error err = r;
            fprintf(stderr, "[lua] on_proxy_request error: %s — refusing the "
                            "request\n", err.what());
            bconn->closing = true;
            conn->closing = true;
            return;
        }

        // Saying nothing is not the same as saying nil, and this is the whole
        // difference between an observer and a refusal.
        //
        //     function on_proxy_request(id, data) log(data) end
        //
        // is how anyone writes a hook that watches traffic, and it ends without
        // a return.  Reading that as `nil` made it drop every byte through the
        // proxy — the most natural three lines in this API silently emptied the
        // connection.  run_request_filters settled the same question the same
        // way one screen up: "Nothing returned, or nil: this filter has no
        // opinion", and it continues the chain.
        //
        // The two part company here only because `nil` is already documented as
        // the way to drop a chunk, and that is worth keeping — so `nil` stays a
        // refusal and an empty return becomes what it reads as.
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
                // Refused, not forwarded, and deliberately the same answer the
                // filter chain gives a value it cannot read.  `return false`
                // meant as a rejection is the case this exists for: forwarding
                // it would admit exactly what the hook was written to refuse,
                // and on_auth reaches the same conclusion with value_or(false).
                fprintf(stderr, "[lua] on_proxy_request returned a %s; expected "
                                "a string or nil — refusing the request\n",
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

// ─── Refusing a response has to mark the side whose handler is running ──────
//
// Both hook arms set a `closing` flag, and setting a flag is not closing a
// connection: something has to act on it, and only one thing does — the
// completion handler of whichever descriptor is running.
//
// The request arm works because the two line up.  forward_to_backend is called
// from handle_client_read with the CLIENT connection in hand, its refusal sets
// that client's flag, and handle_client_read tears the pair down on it.
//
// forward_to_client is the mirror image and the flags were not mirrored with
// it.  Its caller is handle_backend_read, which ends on
//
//     if (!conn->closing) { ...re-arm the backend read... }
//     else if (!conn->write_pending) { close_pair(conn->client_fd, fd); }
//
// where `conn` is the BACKEND.  The refusal set only the client's flag, so that
// test read false, the backend read was re-armed, and the pair was left up.
// Nothing else could ever have noticed: the refusal happens before anything is
// queued to the client, so the client has no write in flight and no completion
// of its own coming.  Measured against a backend that keeps its connection open
// — one that hangs up after replying tears the pair down by itself and hides
// this entirely:
//
//     request arm    closed_by_peer=True    0.0s   0 bytes
//     response arm   closed_by_peer=False   6.0s   0 bytes
//
// No refused byte ever reached the client, so this was never a disclosure. It
// was a client left connected to a proxy that had decided not to answer it —
// and on a multi-chunk response, one holding a truncated answer whose declared
// Content-Length will never be satisfied, which a conforming client waits on
// for ever. The descriptor pair went with it.
//
// So the refusal marks both sides, exactly as the request arm does, and the
// teardown that already exists is what acts. Deliberately not a close_pair()
// from here: this function is called from the middle of a completion handler
// that goes on using both connections after it returns, and close_pair releases
// them. Marking is the whole of what a refusal may do; handle_backend_read owns
// the timing, and it defers on anything still in flight.
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

    // --idle-timeout reaps a client that has said nothing for too long, and
    // "said nothing" is measured by that client's own reads and nothing else.
    // On a request/response exchange that is the right measure: between
    // requests a keep-alive connection genuinely is doing nothing, and a
    // response on its way out belongs to a request that was counted when it
    // arrived.
    //
    // A tunnel has no such cycle.  The peer talking IS the connection working,
    // and a WebSocket where the server pushes and the client only listens —
    // a feed, a notification stream, anything one-directional — reads as
    // perfectly idle from the client side while it is delivering.  It would be
    // cut off mid-stream, at exactly the interval an operator set to reap
    // connections that are doing nothing.
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
        // The same rule on the way back, for the same reason.  This hook is
        // where a script strips a Set-Cookie, masks a field or takes a stack
        // trace out of an error page; forwarding the backend's bytes unchanged
        // because the redactor raised delivers exactly the response the hook
        // existed to prevent.  The client is closed rather than answered: the
        // status line, if there was one, may already be on its wire.
        // Protected, for the same reason as the request hook.
        sol::protected_function_result r =
            lctx->on_proxy_response()(conn->client_fd, data);

        if (SOCKETLEY_UNLIKELY(!r.valid()))
        {
            sol::error err = r;
            fprintf(stderr, "[lua] on_proxy_response error: %s — refusing the "
                            "response\n", err.what());
            refuse_response(conn, cconn);
            return;
        }

        // The request hook's reasoning, unchanged: an empty return is an
        // observer and forwards, an explicit nil is a refusal and drops.  A
        // hook that only logs the backend's answer is written exactly like one
        // that only logs the client's request, and it must not empty the
        // response for the same reason.
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
                fprintf(stderr, "[lua] on_proxy_response returned a %s; expected "
                                "a string or nil — refusing the response\n",
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

// See the declaration in proxy_instance.h for why the status is chosen here and
// nowhere else.  This is the whole of what `ours` buys the client; it was
// already being computed on every connect failure and spent only on the circuit
// breaker, so a local shortage and a dead backend reached the client as the
// same 502 and every path that could not answer at all closed in silence.
bool proxy_instance::client_answerable(const proxy_client_connection* conn) const
{
    // TCP mode is exempt on principle rather than convenience.  There is no
    // request and no status line on that path, so a byte pipe whose backend
    // never came up has nothing it could say; inventing something would be
    // worse than the silence.  The accept-time connect takes exactly this exit.
    if (m_protocol != protocol_http || !conn)
        return false;
    // Already answered, or on its way out carrying an answer.
    if (conn->closing)
        return false;
    // Bytes of a backend's response are already on this client's wire.  A status
    // line written behind them is not an answer, it is the middle of somebody
    // else's message — the same fault as a socket pooled off a boundary, seen
    // from the client's end.  The close is all there is here, and it is honest:
    // the client has a truncated response and can see that it is truncated.
    if (conn->response_started)
        return false;
    return true;
}

// The buffered request has outgrown what this proxy will hold for it.  See the
// call site in handle_client_read for how it gets there and why it is not the
// malformed-input path it looks like.
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

// The tail of every response this proxy produces on its own account: an error
// above, or a filter's answer.  It was inline in send_error, and it is a
// function now because the filter chain answers requests too — and an answer
// that reached the client down a path of its own would be an exit that skips
// exactly the two things below.
void proxy_instance::queue_final_response(proxy_client_connection* conn,
                                          std::string&& response)
{
    conn->write_queue.push(std::move(response));
    conn->closing = true;

    // conn->closing is already set above.  If the body cannot be handed to the
    // ring it simply never goes out; the caller's teardown proceeds either way,
    // so there is nothing for this to decide.
    if (!conn->write_pending && !flush_client_write_queue(conn))
        conn->write_queue.clear();

    // Saying "Connection: close" is not the same as closing it.  The teardown
    // in handle_client_write only runs when no read is pending, and under
    // multishot recv a read is pending for the whole life of the connection —
    // so every error this proxy has ever sent left its connection standing
    // afterwards, held open by nothing but the client's good manners.
    // Measured: a 400 answered in under a millisecond, the socket still
    // established 25 seconds later, and with --idle-timeout at its default of 0
    // nothing was ever going to reap it.  That made an error response the
    // cheapest way there is to hold a connection open — cheaper than the
    // half-sent request the header deadline above was added to bound, which
    // would have made that deadline worth very little.
    //
    // Half-closing is the same lever close_pair pulls when it has to defer: the
    // armed read completes with 0, the EOF path calls close_pair, and that
    // tears the pair down once this response has drained.  The write direction
    // is untouched, so the error body still goes out in full.
    shutdown(conn->fd, SHUT_RD);
}

// ─── TLS record layer ───────────────────────────────────────────────────────
//
// Ciphertext in, plaintext into conn->partial.  One call per read completion,
// which is what makes the handshake asynchronous: OpenSSL is handed the bytes
// that have arrived and asked what it makes of them, and whatever it wants to
// say back is drained by tls_flush at the same point.  Several rounds of that
// is a handshake; there is no loop here waiting for one, and nothing blocks.
template <typename Conn>
void proxy_instance::tls_feed(Conn* conn, const char* data, size_t len)
{
    // Inbound ciphertext into the read BIO.  A refusal is fatal by contract —
    // the peer is over the per-connection buffer cap, or the BIO failed — and
    // it has to be: there is nowhere to hold what was not taken, and handing a
    // record layer a stream with a hole in it is worse than closing.
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
            // Closing, but not silently: what OpenSSL produced on its way to
            // failing is the alert that tells the peer why, and it is the only
            // diagnosis the other end will ever get.  The tls_flush that
            // follows this call puts it on the wire, and the connection is
            // torn down when that write completes.
            //
            // On the backend leg this is also where a certificate is rejected
            // — an unknown CA, an expired chain, a name that does not match
            // the endpoint we meant to reach.  do_handshake has already logged
            // which; the request it belonged to is answered 502 by the read
            // path, never forwarded in the clear.
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
            // Either the peer's close_notify or a record we cannot use.  Both
            // end the connection, and neither ends it here: the bytes decrypted
            // above may be a request or a response that deserves to be
            // delivered, so this is recorded and applied by the caller once
            // they have been.
            conn->tls_peer_closed = true;
        }
        break;
    }

    // The ceiling has an answer, and this is the only place a TLS connection can
    // give it.
    //
    // handle_client_read has the sibling check and writes the 413 — but it is
    // below the branch that runs for a connection with a session, and that
    // branch returns as soon as it sees `closing`.  So on a --tls listener the
    // only thing that ever happened here was the flag: the client was closed on
    // in silence, which is precisely the state the 413 was added to end, and the
    // man page promised the status with exactly one exception that this was not.
    //
    // Answering here rather than teaching the TLS branch to fall through into
    // the cleartext path is the difference between one refusal being produced
    // where its limit is found and two paths having to agree forever about
    // which of them owns it.  Nothing about how the bytes reach the wire is
    // special: send_error queues a response like any other, and
    // flush_client_write_queue routes a session's bytes through tls_flush,
    // which is the only thing allowed to put them on the wire.  The caller's
    // own tls_flush, one line after this returns, is what carries the records
    // out — the same way it already carries a handshake alert.
    //
    // Before `closing`, not after: client_answerable() refuses a connection
    // that is already on its way out, so setting the flag first would silence
    // the very answer this exists to produce.  It also still refuses when a
    // backend's response has already started, which is the one exception the
    // page names and the one case where a status line would land mid-message.
    //
    // Only the client half.  A backend connection has no client to answer and
    // no status to send it; the ceiling there is a teardown and nothing else.
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
// queued: a handshake flight, an alert, a session ticket.  There is no other
// way onto the wire for a connection that has a session.
template <typename Conn>
bool proxy_instance::tls_flush(Conn* conn)
{
    if (SOCKETLEY_UNLIKELY(!m_loop || !conn->ssl))
        return true;

    // One write in flight at a time, exactly as the cleartext path does — the
    // ciphertext buffer built below is what the kernel reads out of, and a
    // second submission would need a second buffer and would interleave two
    // record streams on one socket.  Whatever does not go now stays in the
    // queue or in the write BIO; the write completion comes back here.
    if (conn->write_pending || conn->zc_notif_pending)
        return true;

    // Application data only once the handshake is done.  A request queued
    // while the backend handshake is still in flight waits here rather than
    // being handed to an SSL that would answer WANT_READ and leave the caller
    // unsure what was consumed.
    if (conn->tls_state == tls_conn_ready)
    {
        while (!conn->write_queue.empty())
        {
            const std::string& msg = conn->write_queue.front();
            const int n = tls_context::ssl_write(conn->ssl, msg.data(),
                                                 static_cast<int>(msg.size()));
            if (n <= 0)
            {
                // 0 is backpressure: the write BIO is at its cap, and OpenSSL's
                // contract is that the same buffer is offered again once it has
                // drained — which is what leaving this message at the front of
                // the queue arranges.  -1 is fatal for the session.
                if (n < 0)
                    conn->closing = true;
                break;
            }
            // Partial writes are not enabled on this context, so SSL_write is
            // all-or-nothing.  A short count would mean the record layer and
            // this queue disagree about what has been sent, and a stream with a
            // hole in it has no framing left to recover: close instead.
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

    // Ciphertext out of the write BIO and into a buffer this connection owns.
    // It has to be copied rather than pointed at: an SQE names an address the
    // kernel reads at its leisure, and the BIO's storage moves under it as
    // OpenSSL writes the next record.  Copying is also what keeps the SSL free
    // of anything the ring can name, which is what makes the session safe to
    // release the moment the connection is torn down.
    //
    // The buffer then rides in write_batch[0] like any other message, so the
    // short-write retry and the batch release in the write handlers need no
    // TLS-specific case at all.
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
        // Nothing reached the ring, so no completion will arrive.  Undo the
        // in-flight bookkeeping and report it, as the cleartext path does: a
        // write_pending that never clears keeps the teardown waiting for a
        // completion that cannot come.
        conn->write_pending = false;
        conn->write_batch[0].clear();
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
bool proxy_instance::flush_client_write_queue(proxy_client_connection* conn)
{
    // A TLS connection's bytes go through the record layer, which is the only
    // thing allowed to put them on the wire.  This branch is what keeps every
    // caller above — forwarded responses, error pages, Lua-rewritten bodies —
    // from having to know which kind of connection it is holding.
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

// Returns false when nothing reached the ring.  A caller that leaves
// write_pending set after that waits for a completion that cannot come:
// the connection stops making progress and the peer is left holding a
// request nobody will ever answer.  On failure the pending flag is
// cleared and the batch dropped — the bytes are undeliverable, and
// saying so is the difference between a closed connection and a hung one.
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

    // A TLS connection can owe the wire bytes with an empty queue — the rest
    // of a handshake, an alert, a session ticket, or ciphertext that did not
    // fit in the write that just completed.  Asking only about the queue is
    // how a handshake stalls one round short of finishing.
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
