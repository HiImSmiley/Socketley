#include "server_instance.h"
#include "../../shared/conn_reachability.h"

// The HTTP header-line helpers: http_whole_decimal, http_trim_ows,
// http_list_has_token.  Shared rather than copied — a second implementation of
// "is this a whole decimal" is a second place for the answer to differ.
//
// This was "../proxy/http_response_framing.h" until the header moved to
// shared/, which is to say this runtime reached into another runtime's
// directory for it — the exact thing the note on cache_instance.h below exists
// to prevent, eight lines apart and going unremarked.
#include "../../shared/http_framing.h"
#include "../../shared/unix_listener.h"
#include "../../shared/blocking_write.h"
#include "../../shared/event_loop.h"
#include "../../shared/runtime_manager.h"
#include "../../shared/lua_context.h"
#include "../../shared/ws_protocol.h"
#include "../../shared/invariants.h"
#include "../../shared/logging.h"
#include "../../cli/command_hashing.h"
// Deliberately not cache_instance.h.  Everything this runtime needs of a cache
// now goes through shared/request_channel.h as bytes; the day it included the
// other runtime's header was the day it could hold a pointer to one.
#include "../cache/resp_parser.h"

#include <unistd.h>
#include <unordered_set>
#include <cstring>
#include <cstdlib>
#include <charconv>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <cstddef>
#include <cerrno>
#include <netinet/tcp.h>
#include <netdb.h>
#include <liburing.h>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <fstream>
#include <filesystem>
#include <fcntl.h>
#include <sys/stat.h>
#include <linux/openat2.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>

server_instance::server_instance(std::string_view name)
    : runtime_instance(runtime_server, name), m_mode(mode_inout), m_listen_fd(-1), m_loop(nullptr)
{
    std::memset(&m_accept_addr, 0, sizeof(m_accept_addr));
    m_accept_addrlen = sizeof(m_accept_addr);
    m_accept_req  = std::make_unique<io_request>();
    *m_accept_req = { this, nullptr, -1, 0, op_accept };
    m_udp_recv    = std::make_unique<udp_recv_state>();
}

server_instance::~server_instance()
{
    // The last word on the cache requests this server made.  teardown() already
    // does it, but a runtime can be destroyed without ever having been stopped
    // — `create` then `remove` — and the channel would then be holding a
    // pointer into this object's storage with a reply still to deliver.
    if (auto* mgr = get_runtime_manager())
        mgr->requests().drop_origin(this);

    close_tracked(m_listen_fd);
    close_tracked(m_udp_fd);
    // Not through close_tracked: this descriptor was never given to the ring,
    // and handing the ring a close for something it does not know about is how
    // a teardown starts owing a completion nobody will deliver.
    if (m_http_root_fd >= 0) { ::close(m_http_root_fd); m_http_root_fd = -1; }
}

void server_instance::close_tracked(int fd)
{
    if (fd < 0)
        return;
    if (SOCKETLEY_LIKELY(m_ring_loop != nullptr))
        m_ring_loop->close_fd(fd);
    else
        close(fd);
}

std::unique_ptr<server_connection> server_instance::pool_acquire(int fd)
{
    std::unique_ptr<server_connection> conn;
    if (SOCKETLEY_LIKELY(!m_conn_pool.empty()))
    {
        conn = std::move(m_conn_pool.back());
        m_conn_pool.pop_back();
        conn->reset(fd);
    }
    else
    {
        conn = std::make_unique<server_connection>();
        conn->fd = fd;
    }
    // A new connection is a new identity even when it inherits the struct and
    // the descriptor number of the one before it.
    conn->generation = next_io_generation();

    // The name another runtime is allowed to hold.  Minted here rather than at
    // the first route, so that a connection has one identity for its whole life
    // and not one that appears when somebody first asks: `routed` can be set
    // and cleared several times, and a name that came and went with it would
    // let two spells of routing share a name.
    conn->ref_serial = next_serial();
    if (fd >= 0)
        m_conn_by_serial[conn->ref_serial] = fd;
    return conn;
}

// The shard field in a conn_ref serial has to be wide enough for every shard a
// build allows.  conn_identity.h cannot check this itself — it does not include
// runtime_definitions.h, deliberately, because it is included by things that
// have no notion of a runtime — so the check lives here, where both are already
// in scope.  Raising max_shards past 64 fails this rather than silently minting
// refs whose shard index has been truncated into a sibling's.
static_assert(max_shards <= (1u << conn_serial_shard_bits),
              "conn_ref's serial cannot name every shard --shards allows");

// Mints a serial, having first told the source which shard it is minting for.
//
// Lazy for exactly the reason owner_key() below is lazy, and the two are
// deliberately adjacent: both need a value the daemon supplies after this
// object is constructed.  The shard index arrives in the config frame, and the
// first connection cannot be accepted before that frame has been read — the
// listener is bound from it — so "before the first mint" and "after the config"
// are never in the wrong order.
//
// One flag rather than comparing the index to zero: shard 0 is a real shard,
// and a source rebased every time it minted for shard 0 would work but would
// invite somebody to write the comparison the other way round.
uint64_t server_instance::next_serial()
{
    if (!m_serials_shard_set)
    {
        m_serials.set_shard(get_shard_index());
        m_serials_shard_set = true;
    }
    return m_serials.next();
}

uint64_t server_instance::owner_key() const
{
    // get_id() is assigned after construction — daemon.cpp does it when the
    // runtime is created or restored — so this cannot be a constructor's job.
    // Recomputed while it is still zero rather than cached unconditionally, so
    // a runtime that is asked for a ref before it has an id does not cache the
    // invalid answer for ever.
    if (m_owner_key == 0)
        m_owner_key = conn_owner_key(get_id());
    return m_owner_key;
}

conn_ref server_instance::ref_for_fd(int fd) const
{
    if (fd < 0 || fd >= MAX_FDS || !m_conn_idx[fd])
        return {};
    return conn_ref{owner_key(), m_conn_idx[fd]->ref_serial};
}

// "Anything at all is outstanding on this connection."
//
// Two different questions are asked of this, and only one of them is answered
// correctly by it.  As "may this struct be reused / released" — release_conn(),
// pool_release(), reap_retired() — it is exactly right: a read still armed means
// the ring still names this memory, whether or not the read will ever report.
//
// As "may the teardown be deferred" it is not, because an armed read makes no
// promise to come back.  That question now has its own answer in
// shared/conn_reachability.h and its own caller at the tail of on_cqe(); the 16
// guards in this file that ask it through this predicate are deliberately left
// alone, because a teardown they decline is picked up there one dispatch later
// rather than never.  See finish_unreachable_client().
bool server_instance::conn_ops_pending(const server_connection* conn) const
{
    return conn->read_pending || conn->write_pending || conn->zc_notif_pending
        || conn->file_read_pending || conn->splice_in_pending || conn->splice_out_pending;
}

// Every flag this connection can carry, sorted by who is obliged to report it.
// The sorting is shared/conn_reachability.h's business and the flags are this
// runtime's, so this function is the whole of the seam between them: a flag
// added to server_connection has to appear here to be counted anywhere.
//
// cache_pending is a promised reply rather than a ring operation — the request
// sits in a channel, which guarantees exactly one reply per request, `dropped`
// included, and delivers it back into this loop.  close_conn() defers on it for
// that reason and says so.
socketley::reach::owed server_instance::conn_owed(const server_connection* conn) const
{
    socketley::reach::owed o;
    o.write          = conn->write_pending;
    o.zc_notif       = conn->zc_notif_pending;
    o.file_read      = conn->file_read_pending;
    o.splice_in      = conn->splice_in_pending;
    o.splice_out     = conn->splice_out_pending;
    o.promised_reply = conn->cache_pending > 0;
    o.read           = conn->read_pending;   // not counted; see the header
    return o;
}

void server_instance::release_conn(std::unique_ptr<server_connection> conn)
{
    // The fixed-file slot belongs to the descriptor, not to the struct, and the
    // descriptor is already closed by the time anything gets here — so the slot
    // goes back now, whether or not the struct itself is free to be reused.
    //
    // Leaving it to pool_release() meant a connection with anything in flight
    // carried its slot into the retired list, and a stop deregisters the runtime
    // from the loop, after which its completions are dropped rather than
    // dispatched — so reap_retired() never ran and pool_release() never
    // happened.  The slot then survives the instance itself.  That costs more
    // than a table entry: free_fixed_file_slot() is what unregisters the file,
    // so until it runs the kernel still holds a reference to that socket and
    // close() did not really close it.  The table is 8192 entries and shared by
    // every server and cache on this loop, so one runtime bleeds all of them.
    //
    // Doing this while a request is still in flight was justified as safe "for
    // the same reason closing the socket is: the request took its own reference
    // to the file when it was issued".  That is true of a submission the kernel
    // has already consumed and false of one it has not, which is the entire
    // hazard — a fixed-file SQE carries the slot *index*, and an index handed
    // straight back to the allocator is claimed by the next accept before the
    // kernel ever looks at the SQE.  The call stays here, because the slot does
    // have to go back on this path or a stopped runtime keeps it forever; what
    // changed is that free_fixed_file_slot() now unregisters the file at once
    // and releases the index only when nothing in the ring still names it.
    release_fixed_slot(conn.get());

    if (SOCKETLEY_UNLIKELY(conn_ops_pending(conn.get())))
    {
        // The kernel is still working on something that names this struct: its
        // read buffer, its write batch, one of its io_requests.  Reusing it now
        // gives the next client a second writer into its own buffers; freeing it
        // gives the loop a dangling request.  It waits instead — see
        // reap_retired(), which puts it back once the last completion lands.
        m_conn_retired.push_back(std::move(conn));
        return;
    }
    pool_release(std::move(conn));
}

void server_instance::pool_release(std::unique_ptr<server_connection> conn)
{
    // A splice that was still armed when the connection was closed kept
    // splice_cleanup() from running — it would have closed the file the kernel
    // was reading from and handed the shared pipe to somebody else mid-transfer.
    // Nothing is armed by the time a struct reaches here, so this is where that
    // deferred cleanup finally happens.  Without it the file descriptor rode
    // into the pool, held until the struct happened to be reused and lost for
    // good if it never was — and m_splice_busy stayed true, which takes the
    // splice path out of service for the rest of the runtime's life.
    if (SOCKETLEY_UNLIKELY(conn->splice_file_fd >= 0 || conn->splice_pending ||
                           conn->splice_remaining))
        splice_cleanup(conn.get());

    // Normally already done by release_conn(), which is where the slot is given
    // up; this covers reap_retired(), which reaches the pool directly.
    release_fixed_slot(conn.get());

    // The TLS session dies with the connection that owned it.  No completion
    // can ever land on one — every byte is copied into or out of a buffer this
    // struct owns before an SQE is built, so the kernel never holds an address
    // inside the SSL or its BIOs — which is why this needs none of the "wait
    // until the ring is finished" care the write batch beside it does.  The one
    // rule is that it must not survive into whoever takes this struct next: an
    // inherited session would decrypt the newcomer's bytes with the previous
    // peer's keys, and the newcomer's first read would look like a protocol
    // error rather than the leak it is.
    if (SOCKETLEY_UNLIKELY(conn->ssl != nullptr))
    {
        tls_context::free_ssl(conn->ssl);
        conn->ssl = nullptr;
    }
    conn->tls_state = tls_conn_none;
    conn->tls_peer_closed = false;

    // Nothing is in flight for this struct (release_conn checked), but the
    // requests still carry a live owner pointer.  Clearing it means a completion
    // that reaches the loop anyway is dropped there instead of being dispatched
    // into whichever connection took the struct over.
    conn->read_req.owner = nullptr;
    conn->write_req.owner = nullptr;
    conn->file_read_req.owner = nullptr;
    conn->splice_in_req.owner = nullptr;
    conn->splice_out_req.owner = nullptr;

    // Unpipe: clear peer's back-pointer
    if (conn->pipe_peer_fd >= 0)
    {
        auto* peer = (conn->pipe_peer_fd >= 0 && conn->pipe_peer_fd < MAX_FDS)
            ? m_conn_idx[conn->pipe_peer_fd] : nullptr;
        if (peer && peer->pipe_peer_fd == conn->fd)
            peer->pipe_peer_fd = -1;
        conn->pipe_peer_fd = -1;
    }

    // Reset heavy state but keep allocations for reuse (no shrink_to_fit —
    // the next connection will likely need the same buffer sizes).
    conn->partial.clear();
    conn->meta.clear();
    conn->write_queue.clear();
    conn->relay_hold.clear();
    conn->relay_hold_since = {};
    conn->spoke = false;
    conn->http_seen = false;
    for (uint32_t i = 0; i < conn->write_batch_count; i++) conn->write_batch[i].reset();
    conn->write_batch_count = 0;
    conn->ws_cookie.clear();
    conn->ws_origin.clear();
    conn->ws_protocol.clear();
    conn->ws_auth.clear();
    if (conn->file_fd >= 0) { close_tracked(conn->file_fd); conn->file_fd = -1; }
    if (conn->file_buf) { free(conn->file_buf); conn->file_buf = nullptr; }
    conn->file_size = 0;
    conn->file_content_type.clear();
    conn->file_is_html = false;
    conn->file_read_pending = false;
    conn->http_keep_alive = false;
    conn->wr_shutdown = false;

    SKL_INV_POOLABLE("server::pool_release", conn->fd,
        conn_ops_pending(conn.get()),
        conn->read_req.owner || conn->write_req.owner || conn->file_read_req.owner ||
        conn->splice_in_req.owner || conn->splice_out_req.owner);

    conn->fd = -1;
    m_conn_pool.push_back(std::move(conn));
}

void server_instance::return_provided_buf(struct io_uring_cqe* cqe)
{
    if (SOCKETLEY_LIKELY(!(cqe->flags & IORING_CQE_F_BUFFER)) || !m_ring_loop)
        return;
    m_ring_loop->return_buf(BUF_GROUP_ID,
        static_cast<uint16_t>(cqe->flags >> IORING_CQE_BUFFER_SHIFT));
}

// One teardown for a client connection, reached from every path that closes
// one.  They used to do the same ten steps in their own order and with their
// own idea of what made a release unsafe, which is how the zero-copy
// notification came to be checked in three of them and forgotten in two.
void server_instance::close_conn(server_connection* conn, bool notify_disconnect)
{
    // An answer from the cache is still owed to this client.
    //
    // Every caller here has already asked whether the ring still names the
    // struct, and it does not — a cache request is queued in the channel, not
    // in the ring, so nothing on this connection's behalf is armed while it
    // waits.  That is exactly the case a request/response client produces: ask,
    // shut down the write side, wait for the line.  Closing now throws away an
    // answer the client is still holding its socket open for, which the
    // synchronous version of this path could not do because it had already
    // written the answer before it ever saw the FIN.
    //
    // This always ends.  The channel promises exactly one reply for every
    // request it accepted, `dropped` included if it is torn down underneath us,
    // and the reply that brings the count to zero comes back here to finish the
    // close it deferred.  A runtime that stops first revokes its queued
    // requests and empties m_clients itself, so nothing is left waiting on a
    // reply that is no longer coming.
    if (SOCKETLEY_UNLIKELY(conn->cache_pending > 0))
    {
        conn->closing = true;
        return;
    }

    const int fd = conn->fd;

    // This connection may still be holding the shared splice pipe.  No splice op
    // is armed (the caller checked conn_ops_pending), so handing the pipe on is
    // safe here and nowhere else.
    if (SOCKETLEY_UNLIKELY(conn->splice_file_fd >= 0 || conn->splice_pending || conn->splice_remaining))
        splice_cleanup(conn);

    // Authority and group membership are keyed by fd, and the kernel reissues
    // that number to the next accepted connection.  Leaving either behind hands
    // the newcomer what belonged to the client that just left — for m_master_fd
    // that is broadcast authority granted without the password.
    if (SOCKETLEY_UNLIKELY(fd == m_master_fd))
        m_master_fd = -1;
    unroute_client(fd);
    if (notify_disconnect)
        invoke_on_disconnect(fd);
    remove_from_all_groups(fd);

    // Before the index entry goes, not after: remove_active_fd() finds the
    // connection through m_conn_idx to learn its slot, so clearing the index
    // first turned every one of these calls into a no-op and left closed
    // descriptors in the broadcast list for the rest of the run.
    remove_active_fd(fd);

    // The serial stops resolving here, and this is the moment that matters:
    // close_tracked() below hands the number back to the kernel, which will
    // reissue it to the next accept.  Anyone still holding this connection's
    // name — a sub-server's Lua that kept the id it was given — now gets a
    // clean refusal from write_to_ref() instead of a write into whoever
    // inherited the number.
    if (conn->ref_serial != 0)
        m_conn_by_serial.erase(conn->ref_serial);

    if (fd >= 0 && fd < MAX_FDS)
        m_conn_idx[fd] = nullptr;
    close_tracked(fd);

    // The file a response is being served out of is this connection's, not the
    // pool's.  pool_release() closes it — but a connection with anything in
    // flight never reaches pool_release(), it is retired, so the descriptor was
    // held for as long as the struct was, and for good once the runtime stopped
    // and the completion that would have released it was dropped.  Closing it
    // here ends the read armed on it exactly as closing the socket above ends
    // the read armed on that; file_buf deliberately stays where it is, because
    // that is where the kernel is writing.
    if (SOCKETLEY_UNLIKELY(conn->file_fd >= 0))
    {
        close_tracked(conn->file_fd);
        conn->file_fd = -1;
    }

    auto it = m_clients.find(fd);
    if (it != m_clients.end())
    {
        // The disconnect callback may have queued a write on this connection,
        // so what is in flight is re-examined here rather than above.
        release_conn(std::move(it->second));
        m_clients.erase(it);
    }
}

// A completion whose request lives inside a retired struct.  There is no index
// to find it through any more — the fd is closed and may already belong to
// somebody else — so it is found by the one thing the kernel hands back
// unchanged: the address of the request itself.
bool server_instance::reap_retired(struct io_uring_cqe* cqe, io_request* req)
{
    const auto* r = reinterpret_cast<const char*>(req);

    for (size_t i = 0; i < m_conn_retired.size(); i++)
    {
        auto* c = m_conn_retired[i].get();
        const auto* base = reinterpret_cast<const char*>(c);
        if (r < base || r >= base + sizeof(server_connection))
            continue;

        return_provided_buf(cqe);

        if (req == &c->read_req)
        {
            // A multishot recv is still armed until it completes without MORE.
            if (!(cqe->flags & IORING_CQE_F_MORE))
                c->read_pending = false;
        }
        else if (req == &c->write_req)
        {
            // A zero-copy send completes twice: once when the kernel has taken
            // the request, once when it has finished reading the pages.
            if (cqe->flags & IORING_CQE_F_NOTIF)
                c->zc_notif_pending = false;
            else
                c->write_pending = false;
        }
        else if (req == &c->file_read_req)   c->file_read_pending = false;
        else if (req == &c->splice_in_req)   c->splice_in_pending = false;
        else if (req == &c->splice_out_req)  c->splice_out_pending = false;

        if (!conn_ops_pending(c))
        {
            // Nothing in the ring names it any more, so the messages it was
            // sending can go and the struct can serve somebody else.
            for (uint32_t k = 0; k < c->write_batch_count; k++)
                c->write_batch[k].reset();
            c->write_batch_count = 0;

            auto owned = std::move(m_conn_retired[i]);
            if (i + 1 != m_conn_retired.size())
                m_conn_retired[i] = std::move(m_conn_retired.back());
            m_conn_retired.pop_back();
            pool_release(std::move(owned));
        }
        return true;
    }

    for (size_t i = 0; i < m_upstream_retired.size(); i++)
    {
        auto* u = m_upstream_retired[i].get();
        const auto* base = reinterpret_cast<const char*>(u);
        if (r < base || r >= base + sizeof(upstream_connection))
            continue;

        return_provided_buf(cqe);

        if (req == &u->read_req)            u->read_pending = false;
        else if (req == &u->write_req)      u->write_pending = false;
        else if (req == &u->timeout_req)    u->timeout_pending = false;

        if (!u->read_pending && !u->write_pending && !u->timeout_pending)
        {
            if (i + 1 != m_upstream_retired.size())
                m_upstream_retired[i] = std::move(m_upstream_retired.back());
            m_upstream_retired.pop_back();
        }
        return true;
    }

    return false;
}

void server_instance::set_mode(server_mode mode)
{
    m_mode = mode;
}

server_mode server_instance::get_mode() const
{
    return m_mode;
}

void server_instance::set_udp(bool udp)
{
    m_udp = udp;
}

bool server_instance::is_udp() const
{
    return m_udp;
}

// Routing: get_runtime_manager() from base class replaces per-type get_runtime_manager()

void server_instance::set_master_pw(std::string_view pw)
{
    m_master_pw = std::string(pw);
}

std::string_view server_instance::get_master_pw() const
{
    return m_master_pw;
}

void server_instance::set_master_forward(bool fwd)
{
    m_master_forward = fwd;
}

bool server_instance::get_master_forward() const
{
    return m_master_forward;
}

int server_instance::get_master_fd() const
{
    return m_master_fd;
}

void server_instance::set_http_dir(std::string_view path)
{
    m_http_dir = std::filesystem::path(path);
}

const std::filesystem::path& server_instance::get_http_dir() const
{
    return m_http_dir;
}

void server_instance::set_http_cache(bool enabled)
{
    m_http_cache_enabled = enabled;
}

bool server_instance::get_http_cache() const
{
    return m_http_cache_enabled;
}

// ─── AN UPSTREAM WITHOUT A USABLE PORT IS NOT AN UPSTREAM ───────────────────
//
// The from_chars result was discarded, so `--upstream host:abc`, `--upstream
// host:` and any port above 65535 all left resolved_port at 0 and were stored
// anyway.  A target that can never be connected to sat in the list looking
// exactly like one that could, and `upstream_try_connect` discovered it at
// traffic time — the same shape as the proxy's backend, one runtime over.
//
// The address with no colon at all is a different thing and stays: it is the
// documented spelling for a target whose port comes from elsewhere, and it has
// always stored 0 deliberately.  Only an address that ASKED for a port and gave
// an unusable one is refused.
//
// Returns false without storing anything, so a caller that can refuse has a
// list it did not half-fill.
bool server_instance::add_upstream_target(std::string_view addr)
{
    upstream_target t;
    t.address = std::string(addr);
    auto colon = addr.rfind(':');
    if (colon != std::string_view::npos)
    {
        t.resolved_host = std::string(addr.substr(0, colon));
        auto port_sv = addr.substr(colon + 1);
        const auto [ptr, ec] = std::from_chars(
            port_sv.data(), port_sv.data() + port_sv.size(), t.resolved_port);
        if (ec != std::errc{} || ptr != port_sv.data() + port_sv.size() ||
            t.resolved_port == 0)
            return false;
    }
    else
    {
        t.resolved_host = std::string(addr);
        t.resolved_port = 0;
    }
    m_upstream_targets.push_back(std::move(t));
    return true;
}

void server_instance::clear_upstream_targets()
{
    m_upstream_targets.clear();
}

const std::vector<upstream_target>& server_instance::get_upstream_targets() const
{
    return m_upstream_targets;
}

static std::string_view http_content_type(std::string_view ext)
{
    switch (fnv1a(ext))
    {
        case fnv1a(".html"): case fnv1a(".htm"):
            return "text/html; charset=utf-8";
        case fnv1a(".css"):  return "text/css; charset=utf-8";
        case fnv1a(".js"):   return "application/javascript; charset=utf-8";
        case fnv1a(".json"): return "application/json; charset=utf-8";
        case fnv1a(".png"):  return "image/png";
        case fnv1a(".jpg"):  case fnv1a(".jpeg"):
            return "image/jpeg";
        case fnv1a(".gif"):  return "image/gif";
        case fnv1a(".svg"):  return "image/svg+xml";
        case fnv1a(".ico"):  return "image/x-icon";
        case fnv1a(".woff2"): return "font/woff2";
        case fnv1a(".woff"): return "font/woff";
        case fnv1a(".ttf"):  return "font/ttf";
        case fnv1a(".txt"):  return "text/plain; charset=utf-8";
        case fnv1a(".xml"):  return "application/xml";
        case fnv1a(".wasm"): return "application/wasm";
        case fnv1a(".webp"): return "image/webp";
        case fnv1a(".mp4"):  return "video/mp4";
        case fnv1a(".webm"): return "video/webm";
        case fnv1a(".mp3"):  return "audio/mpeg";
        case fnv1a(".ogg"):  return "audio/ogg";
        case fnv1a(".pdf"):  return "application/pdf";
        default:             return "application/octet-stream";
    }
}

static constexpr std::string_view WS_INJECT_SCRIPT =
    "<script>const socketley=new WebSocket("
    "`ws${location.protocol==='https:'?'s':''}://${location.host}`);</script>";

static std::string inject_ws_script(std::string_view content)
{
    std::string result(content);

    // Try </head> first
    auto pos = result.find("</head>");
    if (pos == std::string::npos)
        pos = result.find("</HEAD>");
    if (pos != std::string::npos)
    {
        result.insert(pos, WS_INJECT_SCRIPT);
        return result;
    }

    // Try </body>
    pos = result.find("</body>");
    if (pos == std::string::npos)
        pos = result.find("</BODY>");
    if (pos != std::string::npos)
    {
        result.insert(pos, WS_INJECT_SCRIPT);
        return result;
    }

    // Append at end
    result.append(WS_INJECT_SCRIPT);
    return result;
}

static std::string build_http_response(std::string_view content_type, std::string_view body, bool keep_alive = false)
{
    std::string resp;
    resp.reserve(128 + body.size());
    resp.append("HTTP/1.1 200 OK\r\nContent-Type: ");
    resp.append(content_type);
    resp.append("\r\nContent-Length: ");
    char len_buf[24];
    auto [len_end, len_ec] = std::to_chars(len_buf, len_buf + sizeof(len_buf), body.size());
    resp.append(len_buf, len_end - len_buf);
    resp.append(keep_alive ? "\r\nConnection: keep-alive\r\n\r\n" : "\r\nConnection: close\r\n\r\n");
    resp.append(body);
    return resp;
}

static std::string build_http_headers_only(std::string_view content_type, size_t body_size, bool keep_alive)
{
    std::string resp;
    resp.reserve(128);
    resp.append("HTTP/1.1 200 OK\r\nContent-Type: ");
    resp.append(content_type);
    resp.append("\r\nContent-Length: ");
    char len_buf[24];
    auto [len_end, len_ec] = std::to_chars(len_buf, len_buf + sizeof(len_buf), body_size);
    resp.append(len_buf, len_end - len_buf);
    resp.append(keep_alive ? "\r\nConnection: keep-alive\r\n\r\n" : "\r\nConnection: close\r\n\r\n");
    return resp;
}

// One comma-separated field, one token, case-insensitive: `Connection` is a
// list header, and "keep-alive, Upgrade" has to match "keep-alive".
static bool header_list_has_token(std::string_view v, std::string_view lower_tok)
{
    size_t i = 0;
    while (i < v.size())
    {
        while (i < v.size() && (v[i] == ' ' || v[i] == '\t' || v[i] == ',')) ++i;
        const size_t start = i;
        while (i < v.size() && v[i] != ',') ++i;
        size_t end = i;
        while (end > start && (v[end - 1] == ' ' || v[end - 1] == '\t')) --end;
        if (end - start == lower_tok.size())
        {
            bool eq = true;
            for (size_t j = 0; j < lower_tok.size(); ++j)
            {
                if (static_cast<char>(std::tolower(static_cast<unsigned char>(v[start + j])))
                    != lower_tok[j])
                {
                    eq = false;
                    break;
                }
            }
            if (eq)
                return true;
        }
        if (i < v.size()) ++i;
    }
    return false;
}

// ─── THE CLIENT'S `Connection` HEADER DECIDES, NOT THE VERSION ──────────────
//
// This was `req.version.find("1.1")` and nothing else, written out at 2 places
// and read at 26.  The version only supplies the *default* (RFC 9112 §9.3); an
// explicit `Connection: close` overrides it and an explicit
// `Connection: keep-alive` overrides an HTTP/1.0 default.  Neither was
// consulted, so a client that asked to close was answered
// `Connection: keep-alive`, was never closed on, and had to perform the active
// close itself — which is what put the TIME-WAIT on the client's *ephemeral*
// port instead of on our fixed listening port.
//
// It lives here, on its own, because 2 deciders against 26 readers is how the
// two deciders came to disagree in the first place: the cached-response path
// and the Lua path each grew their own copy.  There is one now, and
// conn->http_keep_alive is the only place its answer is kept.
static bool http_request_keep_alive(const http_request& req)
{
    for (const auto& [k, v] : req.headers)
    {
        if (fnv1a_lower(k) != fnv1a("connection"))
            continue;
        if (header_list_has_token(v, "close"))
            return false;
        if (header_list_has_token(v, "keep-alive"))
            return true;
        break;
    }
    return req.version.find("1.1") != std::string_view::npos;
}

static const std::shared_ptr<const std::string>& http_404_response(bool keep_alive = false)
{
    static const auto resp_close = std::make_shared<const std::string>(
        "HTTP/1.1 404 Not Found\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 13\r\n"
        "Connection: close\r\n\r\n"
        "404 Not Found");
    static const auto resp_ka = std::make_shared<const std::string>(
        "HTTP/1.1 404 Not Found\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 13\r\n"
        "Connection: keep-alive\r\n\r\n"
        "404 Not Found");
    return keep_alive ? resp_ka : resp_close;
}

// ─── THE TWO WAYS A REQUEST IS REFUSED BEFORE IT IS A REQUEST ───────────────
//
// Both are `Connection: close` unconditionally, and that is not politeness.
// Refusing means this end could not decide where the message ends; carrying on
// would mean deciding exactly that, so the next request on the socket could
// start.  The connection goes with the refusal, and handle_read drops whatever
// is still buffered so that nothing already on the wire is picked up as a
// fresh request while the error is on its way out.
static const std::shared_ptr<const std::string>& http_400_response()
{
    static const auto resp = std::make_shared<const std::string>(
        "HTTP/1.1 400 Bad Request\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 12\r\n"
        "Connection: close\r\n\r\n"
        "Bad Request\n");
    return resp;
}

// A Transfer-Encoding this server does not implement — which is all of them.
// RFC 9112 Section 6.1 asks for 501 here rather than 400: the request is
// well-formed, it is this recipient that cannot follow it.  The distinction is
// worth keeping because it is the honest one, and because a client that gets a
// 400 for a legal chunked request has been told something untrue about its own
// message.
//
// The alternative was to implement chunked framing, and it was rejected for
// this change rather than forgotten: it is a body-reading feature with its own
// buffer limits, its own trailer handling and its own size cap, and none of
// that belongs in a change whose subject is where a header block ends.  What is
// NOT defensible is the third option, which is what stood here — a chunked body
// read as a body of length zero, so the chunk data was parsed as the next
// request on the connection.
static const std::shared_ptr<const std::string>& http_501_response()
{
    static const auto resp = std::make_shared<const std::string>(
        "HTTP/1.1 501 Not Implemented\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 34\r\n"
        "Connection: close\r\n\r\n"
        "Transfer-Encoding not implemented\n");
    return resp;
}

void server_instance::rebuild_http_cache()
{
    m_http_cache.clear();
    if (m_http_dir.empty())
        return;

    namespace fs = std::filesystem;
    std::error_code ec;

    // Resolve canonical base path (also cached for disk-mode serve_http)
    m_http_base = fs::canonical(m_http_dir, ec);
    open_http_root();
    if (ec)
        return;

    for (const auto& entry : fs::recursive_directory_iterator(m_http_base, ec))
    {
        if (!entry.is_regular_file())
            continue;

        // Compute URL path relative to base dir
        auto rel = fs::relative(entry.path(), m_http_base, ec);
        if (ec)
            continue;
        std::string url_path = "/" + rel.string();

        // Read file content
        std::ifstream f(entry.path(), std::ios::binary);
        if (!f.is_open())
            continue;
        std::string content((std::istreambuf_iterator<char>(f)),
                             std::istreambuf_iterator<char>());

        // Detect content type
        std::string ext = entry.path().extension().string();
        for (auto& c : ext) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        uint32_t ext_hash = fnv1a(ext);
        auto ct = http_content_type(ext);

        // Inject WebSocket script into HTML files
        if (ext_hash == fnv1a(".html") || ext_hash == fnv1a(".htm"))
            content = inject_ws_script(content);

        // Store pre-built responses as shared_ptrs (zero-copy on cache hit).
        // Both, not just the keep-alive one: this map used to hold a single
        // string built with keep_alive=true, so `--http-cache` answered
        // `Connection: keep-alive` to every request including the ones that
        // asked to close — and, unlike disk mode, even to HTTP/1.0.
        m_http_cache[url_path] = {
            std::make_shared<const std::string>(build_http_response(ct, content, true)),
            std::make_shared<const std::string>(build_http_response(ct, content, false))
        };
    }
}

// One entry, or none.  Called only from handle_file_read, and only for a read
// that completed in full through the openat2(RESOLVE_BENEATH) path.
void server_instance::http_reval_store(const std::string& url_path, const struct stat& st,
                                       std::shared_ptr<const std::string> ka,
                                       std::shared_ptr<const std::string> cl)
{
    size_t cost = (ka ? ka->size() : 0) + (cl ? cl->size() : 0);
    // What this key already costs is reclaimed before the cap is tested, or a
    // file edited repeatedly near the limit would stop being kept the moment
    // its own entry pushed the total over -- refused on the strength of the
    // bytes it is about to give back.
    auto old_it = m_http_reval.find(url_path);
    size_t reclaimed = (old_it != m_http_reval.end()) ? old_it->second.bytes : 0;
    if (m_http_reval_bytes - reclaimed + cost > HTTP_REVAL_MAX_TOTAL)
    {
        // Full: stop taking new files rather than evicting one.  What is in the
        // map stays correct either way -- every hit is revalidated -- so the
        // only thing at stake is which files are fast, and an operator whose
        // document root is larger than the cap is better served by a stable
        // answer than by a cache that thrashes.  Said once, not per request.
        if (!m_http_reval_full_logged)
        {
            m_http_reval_full_logged = true;
            LOG_INFO("server: --http content cache reached its 64 MiB limit; the "
                     "files already in it stay fast, the rest are read per request");
        }
        return;
    }
    auto& e = m_http_reval[url_path];
    m_http_reval_bytes -= e.bytes;          // replacing an existing entry
    e.dev        = st.st_dev;
    e.ino        = st.st_ino;
    e.size       = static_cast<uint64_t>(st.st_size);
    e.mtime_sec  = st.st_mtim.tv_sec;
    e.mtime_nsec = static_cast<uint32_t>(st.st_mtim.tv_nsec);
    e.bytes      = cost;
    e.response       = std::move(ka);
    e.response_close = std::move(cl);
    m_http_reval_bytes += cost;
}

// The directory every --http request is opened relative to.  Opened once, here,
// because openat2(RESOLVE_BENEATH) needs a descriptor to be beneath and because
// re-opening it per request would put back the syscall this exists to remove.
// O_PATH is deliberately NOT used: openat2 resolves against a real directory fd.
void server_instance::open_http_root()
{
    if (m_http_root_fd >= 0)
    {
        ::close(m_http_root_fd);
        m_http_root_fd = -1;
    }
    if (m_http_base.empty())
        return;
    // Every key in the revalidating map is relative to the descriptor being
    // replaced, so it does not survive the replacement.
    m_http_reval.clear();
    m_http_reval_bytes = 0;
    m_http_reval_full_logged = false;
    m_http_root_fd = ::open(m_http_base.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    // -1 is survivable: serve_http falls back to canonicalising per request,
    // which is what it did before this existed.
}

void server_instance::serve_http(server_connection* conn, std::string_view path)
{
    // Normalize: "/" → "/index.html"
    std::string url_path(path);
    if (url_path == "/")
        url_path = "/index.html";

    // Percent-decode the path to catch %2e%2e → .. traversal
    auto percent_decode = [](std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (size_t i = 0; i < s.size(); i++)
        {
            if (s[i] == '%' && i + 2 < s.size())
            {
                auto hex = [](char c) -> int {
                    if (c >= '0' && c <= '9') return c - '0';
                    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                    return -1;
                };
                int h = hex(s[i+1]), l = hex(s[i+2]);
                if (h >= 0 && l >= 0)
                {
                    out += static_cast<char>((h << 4) | l);
                    i += 2;
                    continue;
                }
            }
            out += s[i];
        }
        s = std::move(out);
    };
    percent_decode(url_path);

    // Security: reject path traversal and null bytes
    if (url_path.find("..") != std::string::npos ||
        url_path.find('\0') != std::string::npos)
    {
        conn->write_queue.push(http_404_response(conn->http_keep_alive));
        if (!conn->write_pending)
            flush_write_queue(conn);
        if (!conn->http_keep_alive)
            conn->closing = true;
        else
            conn->proto = proto_unknown;
        return;
    }

    // Strip query string
    auto qpos = url_path.find('?');
    if (qpos != std::string::npos)
        url_path = url_path.substr(0, qpos);

    if (m_http_cache_enabled && !m_http_cache.empty())
    {
        // Cached mode: zero-copy lookup — just bump shared_ptr refcount
        auto it = m_http_cache.find(url_path);
        conn->write_queue.push(it != m_http_cache.end()
            ? (conn->http_keep_alive ? it->second.response : it->second.response_close)
            : http_404_response(conn->http_keep_alive));

        if (!conn->write_pending)
            flush_write_queue(conn);
        if (!conn->http_keep_alive)
            conn->closing = true;
        else
            conn->proto = proto_unknown;
    }
    else
    {
        // Disk mode: async file read via io_uring
        namespace fs = std::filesystem;
        std::error_code ec;

        // Resolve base once if not yet done (dev mode, no rebuild_http_cache call)
        if (m_http_base.empty())
        {
            m_http_base = fs::canonical(m_http_dir, ec);
            open_http_root();
            if (ec)
            {
                conn->write_queue.push(http_404_response(conn->http_keep_alive));
                if (!conn->write_pending)
                    flush_write_queue(conn);
                if (!conn->http_keep_alive)
                    conn->closing = true;
                else
                    conn->proto = proto_unknown;
                return;
            }
        }

        // ─── ONE statx INSTEAD OF open + fstat + read + close ───────────────
        //
        // The bytes of a file already served are kept, exactly as --http-cache
        // keeps them, and this decides whether they are still the file's bytes.
        // A hit is a refcount bump and one syscall; a miss falls through to the
        // path below, which is the only code that ever admits bytes into the
        // map.  So the map cannot serve anything that path would refuse: a hit
        // requires dev+ino to equal an inode that openat2(RESOLVE_BENEATH)
        // already accepted, and a symlink pointing somewhere else is a
        // different inode and therefore a miss.
        //
        // dev+ino is in the comparison for a second, independent reason: `mv`
        // into place puts a new inode at the same path, and `touch -r` gives it
        // the old mtime to the nanosecond.  On (mtime, size) alone that request
        // is a hit and the old bytes are served forever.
        std::string rel_path(url_path.substr(1));
        if (rel_path.empty())
            rel_path = ".";

        bool reval_ok = http_reval_active();
        if (reval_ok)
        {
            auto rit = m_http_reval.find(url_path);
            if (rit != m_http_reval.end())
            {
                struct statx sx{};
                const unsigned want = STATX_TYPE | STATX_INO | STATX_MTIME | STATX_SIZE;
                if (::statx(m_http_root_fd, rel_path.c_str(), 0, want, &sx) == 0 &&
                    (sx.stx_mask & want) == want &&
                    S_ISREG(sx.stx_mode) &&
                    makedev(sx.stx_dev_major, sx.stx_dev_minor) == rit->second.dev &&
                    static_cast<ino_t>(sx.stx_ino) == rit->second.ino &&
                    sx.stx_size == rit->second.size &&
                    sx.stx_mtime.tv_sec == rit->second.mtime_sec &&
                    sx.stx_mtime.tv_nsec == rit->second.mtime_nsec)
                {
                    conn->write_queue.push(conn->http_keep_alive ? rit->second.response
                                                                 : rit->second.response_close);
                    if (!conn->write_pending)
                        flush_write_queue(conn);
                    if (!conn->http_keep_alive)
                        conn->closing = true;
                    else
                        conn->proto = proto_unknown;
                    return;
                }
                // Stale, replaced or gone.  Dropped rather than left to be
                // re-checked: a file deleted from the tree would otherwise hold
                // its bytes in the map for the life of the process.
                m_http_reval_bytes -= rit->second.bytes;
                m_http_reval.erase(rit);
            }
        }

        // ─── THE ESCAPE CHECK IS THE KERNEL'S, NOT A STRING COMPARISON ──────
        //
        // This was fs::canonical(requested) followed by "does the result still
        // begin with the canonical root".  Correct, and it cost a readlink per
        // path component on EVERY request: measured with strace on a root nine
        // directories deep, 9.01 readlink calls per connection — more than every
        // other syscall on the path put together, and 43.9 us of the 42.5 us a
        // connection costs beyond its own connect and its own request work.
        // The cost scaled with how deep the operator's document root happened
        // to be, which is not a property anyone would expect to pay per request.
        //
        // openat2(RESOLVE_BENEATH) asks the kernel for the same guarantee inside
        // the open itself: the resolution may not leave the directory the fd
        // names, by `..`, by an absolute path, or by a symlink.  One syscall,
        // no readlinks, and the check cannot be raced — fs::canonical() and the
        // open() that followed it were two syscalls against a path that could
        // change in between, which this also closes.
        //
        // RESOLVE_NO_MAGICLINKS as well: /proc/self/fd/N is not a path this
        // server has any business following, and the old prefix check only
        // caught it after the fact.
        //
        // ENOSYS means a kernel older than 5.6.  The old path is still here for
        // that case and is exercised by the same test file, which pins the
        // behaviour rather than the implementation.
        int ffd = -1;
        bool used_beneath = false;
        fs::path resolved;
        if (m_http_root_fd >= 0)
        {
            const std::string& rel = rel_path;
            struct open_how how{};
            how.flags   = static_cast<uint64_t>(O_RDONLY | O_CLOEXEC);
            how.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS;
            long r = ::syscall(__NR_openat2, m_http_root_fd, rel.c_str(), &how, sizeof(how));
            if (r >= 0)
            {
                ffd = static_cast<int>(r);
                used_beneath = true;
                // The path is still needed below — `resolved.extension()` picks
                // the Content-Type — and leaving it empty here served every file
                // with the wrong type.  Under keep-alive that desynchronised the
                // connection rather than merely mislabelling it: measured, 1 to
                // 4 failures per 20,000 requests and the run's rate collapsing
                // from 74,000 to 4,000 when it happened.
                //
                // A join, not a canonicalisation: this is only ever read for the
                // extension, and for that the path as asked for is the right
                // answer.  It costs no syscall, which is the entire point of the
                // branch it sits in.
                resolved = m_http_base / rel;
            }
            else if (errno != ENOSYS)
            {
                // EXDEV, ELOOP, ENOENT, EACCES — every one of them is "not a
                // file this server may serve", and they are answered alike.
                conn->write_queue.push(http_404_response(conn->http_keep_alive));
                if (!conn->write_pending)
                    flush_write_queue(conn);
                if (!conn->http_keep_alive)
                    conn->closing = true;
                else
                    conn->proto = proto_unknown;
                return;
            }
        }

        if (!used_beneath)
        {
        fs::path file_path = m_http_base / url_path.substr(1); // strip leading /
        resolved = fs::canonical(file_path, ec);

        // Verify the resolved path is within the base directory (symlink escape check)
        auto base_str = m_http_base.native();
        auto resolved_str = resolved.native();
        if (ec || resolved_str.size() < base_str.size() ||
            resolved_str.compare(0, base_str.size(), base_str) != 0)
        {
            conn->write_queue.push(http_404_response(conn->http_keep_alive));
            if (!conn->write_pending)
                flush_write_queue(conn);
            if (!conn->http_keep_alive)
                conn->closing = true;
            else
                conn->proto = proto_unknown;
            return;
        }

        // Open file and get size.  O_CLOEXEC: this is on the request path, so a
        // proxy worker forked while a file is being served would otherwise
        // inherit a descriptor on a file it has no business holding open.
        ffd = open(resolved.c_str(), O_RDONLY | O_CLOEXEC);
        }
        if (ffd < 0)
        {
            conn->write_queue.push(http_404_response(conn->http_keep_alive));
            if (!conn->write_pending)
                flush_write_queue(conn);
            if (!conn->http_keep_alive)
                conn->closing = true;
            else
                conn->proto = proto_unknown;
            return;
        }

        struct stat st;
        if (fstat(ffd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size <= 0)
        {
            close_tracked(ffd);
            conn->write_queue.push(http_404_response(conn->http_keep_alive));
            if (!conn->write_pending)
                flush_write_queue(conn);
            if (!conn->http_keep_alive)
                conn->closing = true;
            else
                conn->proto = proto_unknown;
            return;
        }

        auto fsize = static_cast<size_t>(st.st_size);

        // Detect content type
        std::string ext = resolved.extension().string();
        for (auto& c : ext)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        uint32_t ext_hash = fnv1a(ext);
        bool is_html = (ext_hash == fnv1a(".html") || ext_hash == fnv1a(".htm"));
        auto ct = http_content_type(ext);

        // Whether this miss may be turned into a map entry.  Storing needs the
        // bytes in user space, which the splice path never has, so a small
        // non-HTML file is deliberately routed to the read path below: it pays
        // one read once and one statx thereafter, instead of a splice every
        // time.  Nothing is lost by that -- IORING_OP_SPLICE is prepped
        // REQ_F_FORCE_ASYNC and measured 17.19 us against read's 0.72 us, and
        // is only ahead above ~128 KB, which is well over the per-file cap.
        // Files over the cap keep today's behaviour exactly.
        const bool reval_take = reval_ok && used_beneath &&
                                fsize <= HTTP_REVAL_MAX_FILE &&
                                m_http_reval_bytes < HTTP_REVAL_MAX_TOTAL;

        // Splice path: zero-copy file→pipe→socket for non-HTML files.
        //
        // Never on a TLS connection.  A splice moves the file's bytes into the
        // socket without OpenSSL ever seeing them, so the peer would be handed
        // plaintext in the middle of an encrypted stream — a silent downgrade
        // of exactly the kind this whole feature is gated to prevent, and one
        // that reads as a protocol error rather than as a leak.  The
        // read-and-encrypt path below serves the same file correctly; the cost
        // is one copy on a connection that is already paying for a cipher.
        if (!is_html && !conn->ssl && !m_splice_busy && m_splice_pipe[0] >= 0 && !reval_take)
        {
            conn->splice_file_fd = ffd;
            conn->splice_remaining = fsize;
            conn->splice_pipe_pending = 0;
            conn->splice_pending = true;
            conn->file_content_type = std::string(ct);
            m_splice_busy = true;

            // Send HTTP headers via normal write path; splice starts after headers are sent
            conn->write_queue.push(
                std::make_shared<const std::string>(
                    build_http_headers_only(ct, fsize, conn->http_keep_alive)));
            if (!conn->write_pending)
                flush_write_queue(conn);
            return;
        }

        // Fallback: malloc + async read (HTML files or splice busy)
        char* fbuf = static_cast<char*>(malloc(fsize));
        if (!fbuf)
        {
            close_tracked(ffd);
            conn->write_queue.push(http_404_response(conn->http_keep_alive));
            if (!conn->write_pending)
                flush_write_queue(conn);
            if (!conn->http_keep_alive)
                conn->closing = true;
            else
                conn->proto = proto_unknown;
            return;
        }

        // Store state on connection for completion handler
        conn->file_fd = ffd;
        conn->file_buf = fbuf;
        conn->file_size = fsize;
        conn->file_content_type = std::string(ct);
        conn->file_is_html = is_html;
        conn->file_read_pending = true;
        // Non-empty only when the completion may keep the bytes.  The identity
        // is the one fstat() reported on this very descriptor, so it describes
        // the inode the bytes actually came from and not whatever is at the
        // path by the time the read completes.
        if (reval_take)
        {
            conn->file_url_path = url_path;
            conn->file_st = st;
        }
        else
        {
            conn->file_url_path.clear();
        }

        // Submit async read — req->fd = socket fd for CQE dispatch
        conn->file_read_req = { this, fbuf, conn->fd, static_cast<uint32_t>(fsize), op_file_read,
                                conn->generation };
        if (SOCKETLEY_UNLIKELY(!m_loop->submit_file_read(ffd, fbuf, static_cast<uint32_t>(fsize), 0,
                                                         &conn->file_read_req)))
        {
            // No completion will arrive for a read that was never queued.  The
            // teardown closes file_fd and frees file_buf, both already recorded
            // on the connection above.
            conn->file_read_pending = false;
            conn->closing = true;
        }
    }
}

// Only reachable from the Lua on_http_request path below, so the no-Lua build
// has no caller for either helper.
#ifndef SOCKETLEY_NO_LUA
static std::string build_http_response_full(int status, std::string_view reason,
    const std::vector<std::pair<std::string, std::string>>& headers,
    std::string_view body, bool keep_alive)
{
    std::string resp;
    resp.reserve(256 + body.size());
    resp.append("HTTP/1.1 ");
    char status_buf[8];
    auto [s_end, s_ec] = std::to_chars(status_buf, status_buf + sizeof(status_buf), status);
    resp.append(status_buf, s_end - status_buf);
    resp.append(" ");
    resp.append(reason);
    resp.append("\r\n");

    // Add Content-Length if not already present
    bool has_cl = false;
    bool has_conn = false;
    for (const auto& [k, v] : headers)
    {
        resp.append(k);
        resp.append(": ");
        resp.append(v);
        resp.append("\r\n");
        if (fnv1a_lower(k) == fnv1a("content-length")) has_cl = true;
        if (fnv1a_lower(k) == fnv1a("connection")) has_conn = true;
    }

    if (!has_cl)
    {
        resp.append("Content-Length: ");
        char len_buf[24];
        auto [l_end, l_ec] = std::to_chars(len_buf, len_buf + sizeof(len_buf), body.size());
        resp.append(len_buf, l_end - len_buf);
        resp.append("\r\n");
    }

    if (!has_conn)
    {
        resp.append(keep_alive ? "Connection: keep-alive\r\n" : "Connection: close\r\n");
    }

    resp.append("\r\n");
    resp.append(body);
    return resp;
}

static std::string_view http_reason(int status)
{
    switch (status)
    {
        case 200: return "OK";
        case 201: return "Created";
        case 204: return "No Content";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 304: return "Not Modified";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 500: return "Internal Server Error";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        default:  return "Unknown";
    }
}
#endif

void server_instance::refuse_http_request(server_connection* conn,
                                          const std::shared_ptr<const std::string>& resp)
{
    // The buffer goes first.  Everything in it was measured against a header
    // block this end could not frame, so its boundaries are exactly what is in
    // doubt; leaving it for the reparse loop at the bottom of handle_read would
    // hand the client the second answer the refusal exists to withhold.
    conn->partial.clear();

    conn->write_queue.push(resp);
    if (!conn->write_pending)
        flush_write_queue(conn);

    // Unconditional, and not conditioned on http_keep_alive the way the 404
    // path is: keep-alive means "the next request starts where this one ends",
    // and this end has just said it cannot tell where that is.
    conn->closing = true;
}

void server_instance::handle_http_request(server_connection* conn, const http_request& req, size_t total_consumed)
{
    // Decided once, before anything can answer, so that every path below —
    // Lua, cached, disk, 404 — agrees about what the client asked for.
    conn->http_keep_alive = http_request_keep_alive(req);

#ifndef SOCKETLEY_NO_LUA
    // ─── The Lua handler ────────────────────────────────────────────────────
    //
    // Protected, like every other callback in this tree since 2a1e135..df02e6f,
    // and this was the last one to come across.  It used to be a sol::function
    // called inside `try { ... } catch (const std::exception&)`, and the result
    // was read with no check at all:
    //
    //     sol::object result = lua()->on_http_request()(lua_req);
    //
    // Two things were wrong with that.  The catch only fires when sol2's panic
    // handler throws AND the throw unwinds out of the interpreter, which it does
    // not in this repository's Sanitize configuration — so the one diagnostic
    // this path had was dead in the build the nightly job uses.  And reading
    // index 0 without asking valid() is the read df02e6f records the cost of on
    // the cache path: on a failed call index 0 is the error object.
    //
    // A raise is answered with 500, not with the fall-through below.  `return
    // nil` from this callback is documented as "I have no answer, serve the
    // static file or 404"; answering a raise the same way made a handler that
    // broke indistinguishable at the client from one that declined, and left
    // the operator nothing to read either.  The proxy hook settled the same
    // question the same way — a hook that raises has not said carry on.
    if (lua() && lua()->has_on_http_request())
    {
        // Build Lua request table
        sol::table lua_req = lua()->state().create_table();
        lua_req["method"] = req.method;
        lua_req["path"] = req.path;
        lua_req["query"] = req.query;
        lua_req["body"] = req.body;
        lua_req["client_id"] = req.client_id;
        lua_req["version"] = req.version;

        sol::table lua_headers = lua()->state().create_table();
        for (const auto& [k, v] : req.headers)
            lua_headers[std::string(k)] = std::string(v);
        lua_req["headers"] = lua_headers;

        const bool keep_alive = conn->http_keep_alive;

        sol::protected_function_result r = lua()->on_http_request()(lua_req);

        if (SOCKETLEY_UNLIKELY(!r.valid()))
        {
            sol::error e = r;
            std::cerr << lua_diag::tag(get_name()) << " on_http_request error: " << e.what()
                      << " — answering 500" << std::endl;

            auto response = build_http_response_full(500, http_reason(500), {},
                                                     "500 Internal Server Error",
                                                     keep_alive);
            conn->write_queue.push(std::make_shared<const std::string>(std::move(response)));
            if (!conn->write_pending)
                flush_write_queue(conn);

            conn->partial.erase(0, total_consumed);

            if (!keep_alive)
                conn->closing = true;
            else
                conn->proto = proto_unknown;  // Reset for next request (pipelining)

            return;
        }

        // return_count() before get(), for the same reason valid() came before
        // both: a handler that ends without a `return` — which is how anyone
        // writes one that only handles some paths — returns nothing, and index 0
        // of nothing is not a value to ask about.  Falling through is the right
        // answer for it and is what the documentation promises.
        if (r.return_count() > 0)
        {
            sol::object result = r;
            if (result.is<sol::table>())
            {
                sol::table resp_tbl = result.as<sol::table>();
                int status = resp_tbl.get_or("status", 200);
                std::string body = resp_tbl.get_or<std::string>("body", "");
                std::string_view reason = http_reason(status);

                std::vector<std::pair<std::string, std::string>> resp_headers;
                sol::optional<sol::table> h = resp_tbl["headers"].get<sol::optional<sol::table>>();
                if (h)
                {
                    h->for_each([&](sol::object key, sol::object val) {
                        if (key.is<std::string>() && val.is<std::string>())
                            resp_headers.emplace_back(key.as<std::string>(), val.as<std::string>());
                    });
                }

                auto response = build_http_response_full(status, reason, resp_headers, body, keep_alive);
                conn->write_queue.push(std::make_shared<const std::string>(std::move(response)));
                if (!conn->write_pending)
                    flush_write_queue(conn);

                conn->partial.erase(0, total_consumed);

                if (!keep_alive)
                    conn->closing = true;
                else
                    conn->proto = proto_unknown;  // Reset for next request (pipelining)

                return;
            }
        }
    }
#endif

    // Fallback: serve static files if configured
    if (!m_http_dir.empty())
    {
        std::string path_str(req.path);
        conn->partial.erase(0, total_consumed);
        serve_http(conn, path_str);
    }
    else
    {
        // No http_dir and no Lua callback — 404
        conn->write_queue.push(http_404_response(conn->http_keep_alive));
        if (!conn->write_pending)
            flush_write_queue(conn);
        if (!conn->http_keep_alive)
            conn->closing = true;
        else
            conn->proto = proto_unknown;
        conn->partial.erase(0, total_consumed);
    }
}

size_t server_instance::get_connection_count() const
{
    if (m_udp)
        return m_udp_peers.size();
    size_t upstream_connected = 0;
    for (const auto& [_, uc] : m_upstreams)
        if (uc->connected) ++upstream_connected;
    return m_active_fds.size() + m_forwarded.size() + upstream_connected;
}

// The TCP listener, lifted out of setup() unchanged so that the address family
// is one branch there rather than a second copy of everything after it.
//
// SOCK_CLOEXEC: this listener belongs to one runtime in the daemon, and the
// daemon forks a worker for every runtime that does not ask for
// --daemon-process.  Without the flag every such worker inherits this port —
// measured, as fd 6 of a worker whose own port was a different one — and holds
// it after this runtime is stopped and after the daemon exits.  The shutdown()
// in teardown() unhashes the socket for every dup at once and so hides it on
// the ordinary stop path; a daemon that is killed rather than stopped never
// reaches that line, and then the port is bound by a process with no runtime
// and no daemon to account for it.
bool server_instance::setup_tcp_listener(uint16_t port)
{
    m_listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (m_listen_fd < 0)
    {
        LOG_ERROR(("server: socket() failed: " + std::string(std::strerror(errno))).c_str());
        return false;
    }

    int opt = 1;
    setsockopt(m_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(m_listen_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    setsockopt(m_listen_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    // ─── NO TCP_DEFER_ACCEPT, AND THAT IS THE POINT ─────────────────────────
    //
    // This set it with a one-second timeout, "eliminating the empty-accept +
    // read round-trip on the hot path".  What it actually does is tell the
    // kernel not to complete a connection until the CLIENT sends data — so a
    // connection that has not spoken yet is not a connection this server has,
    // and everything downstream of accept() is simply not running for it.
    //
    // Measured on Release, one idle client against a --mode inout server:
    //
    //     t=0.5s   server side SYN-RECV,  `ls` says CONN=0, client connected
    //     t=2.0s   server side ESTAB,     `ls` says CONN=0
    //     t=5.0s                          `ls` says CONN=1
    //
    // Five seconds during which the client believes it is connected and the
    // server does not know it exists.  on_connect has not fired, the connection
    // is in no count and no listing, and a server whose protocol speaks first —
    // a greeting, a banner, a push — cannot, because there is nobody to speak
    // to yet.  Without the option the same connection is CONN=1 at 0.5s.
    //
    // And the failure mode is worse than the delay.  A connection still in
    // SYN-RECV is a request sock, not a socket; when the listener closes, the
    // kernel drops it SILENTLY — no FIN, no RST.  The client is left
    // ESTABLISHED against a peer that no longer exists, with nothing to notice:
    // there is no SO_KEEPALIVE on either end, so it holds that dead connection
    // until it next tries to write.  That is how test_client_reconnect.sh fails
    // on a Sanitize build, where the window is wide enough to remove a server
    // inside it: four clients reporting a live connection to a server that was
    // deleted, indefinitely.
    //
    // WHAT IT COSTS TO REMOVE IT, and this number was got wrong once.
    //
    // The first measurement said "nothing": 17,064/s with the option against
    // 16,842/s without.  That was `server conn` at 20,000 connections a run,
    // which on this box is past the 28,231 ephemeral ports it has -- both arms
    // were bottlenecked on TIME-WAIT and the figure was the port pool, not the
    // listener.  The same test at 2,000 connections with the pool drained
    // between runs, twelve interleaved passes, three builds:
    //
    //     server burst   main                       104,488/s
    //                    main, this line removed     86,870/s   -17%
    //                    this tree                   88,156/s   -16%
    //
    // main-minus-this-line lands on this tree, so the whole difference is this
    // option and nothing else in the branch regressed.  Checked further, 800
    // connections opened and held: both builds accept all 800, so the loss is
    // real establishment cost and not a listener declining to answer -- 9.7 us
    // per connection with the option, 13.0 without.  The deferral lets connect()
    // return before the server is involved, so the client can fire the next one
    // sooner.
    //
    // Removed anyway, and the trade is worth stating plainly rather than hiding
    // behind a wrong number: about a sixth of the connection-establishment rate
    // on a connection-storm workload, against a connection that is visible to
    // the server when it happens instead of up to five seconds later, an
    // on_connect that fires, a server that can speak first, and a client that is
    // told when its connection dies instead of holding it forever.
    //
    // Not kept for HTTP mode either, where the client does speak first: the
    // deferral would be free there, but a mode-dependent branch in listener
    // setup is a second configuration of the accept path to keep correct, and
    // the failure it would reintroduce is the silent one above.

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(m_listen_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        // ─── Say which port and why ─────────────────────────────────────────
        //
        // setup_unix_listener(), fifteen lines below and chosen from the same
        // `if`, reports "--listen <path> could not be bound: <strerror>".  This
        // path reported nothing at all, and the two are the only ways a server
        // acquires a listener.
        //
        // What that silence cost is a whole sentence being untrue: the CLI
        // answers `runtime <n> could not start: the worker did not accept its
        // configuration (the reason is in the daemon log)`, and the daemon log
        // then held only "proxy worker: proxy failed to start".  For the single
        // most common startup failure there is -- a port already in use -- the
        // message named a place to look and there was nothing there.
        LOG_ERROR(("server: port " + std::to_string(port) + " could not be bound: " +
                   std::string(std::strerror(errno))).c_str());
        close_tracked(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }

    if (listen(m_listen_fd, 4096) < 0)
    {
        LOG_ERROR(("server: listen() on port " + std::to_string(port) + " failed: " +
                   std::string(std::strerror(errno))).c_str());
        close_tracked(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }
    return true;
}

// The AF_UNIX listener, for `--listen unix:/path/to.sock`.
//
// The mechanism — the stale-node probe, the bind, the 0600, the listen — is
// shared/unix_listener.h now, with the reasoning that used to live here.  This
// wrapper is what stays a server's own: which member holds the fd, and the
// record of which path was actually bound.
bool server_instance::setup_unix_listener(const std::string& path)
{
    auto r = socketley::unix_sock::bind_listener(path);
    if (r.fd < 0)
    {
        LOG_ERROR(("server: " + r.error).c_str());
        return false;
    }
    m_listen_fd = r.fd;

    // Remembered so teardown() removes exactly the node this bind created, and
    // not whatever the configuration happens to say by then.  A runtime edited
    // between start and stop would otherwise unlink a path it never bound.
    m_bound_listen_path = path;
    return true;
}

bool server_instance::setup(event_loop& loop)
{
    // Nothing is freed here.  teardown() emptied m_clients into the pool and the
    // retired list, and a retired struct is one the kernel has not finished
    // with: this used to call m_clients.clear() and destroy exactly the structs
    // the teardown had deliberately kept, so a completion that arrived in the
    // gap read a freed io_request.  What is left over is a restart's business
    // only in so far as it must not be touched.
    m_active_fds.clear();
    m_active_fds.reserve(256);  // Pre-allocate to avoid reallocs on first connections
    // And the shared view of it.  A restart that left the previous lifetime's
    // names in place would have siblings routing to connections that no longer
    // exist -- resolved to nothing at the far end, but reported to the script
    // as clients it has.
    shard_clients_table().clear_own();

    m_loop = &loop;
    m_ring_loop = &loop;

    // Fix this runtime's half of every conn_ref it is about to mint.  The id it
    // is derived from is assigned at construction and replaced only once, by
    // the restore path, immediately after — long before a listener exists.
    // Resolving it here rather than on first use means every name this runtime
    // hands out over one run carries the same owner, even if something were to
    // change the id underneath it.
    owner_key();

    // ── requests an earlier run armed and never saw the end of ──────────────
    //
    // The flags below say "this request is occupied, do not arm it again", and
    // they are set when a request is armed and lowered by its completion.  Only
    // by a completion the loop *delivers*, though — and stop() deregisters this
    // owner, so from that moment the loop drops them instead.  on_cqe does not
    // run, the flag is never lowered, and it survives into the next run: the
    // start that follows declines to arm a request that is in fact free, and the
    // thing it belongs to is off for the life of the process.  A client that
    // comes up connected and permanently deaf is the same defect on the client
    // runtime; here it is an idle sweep that never runs again, an accept backoff
    // that can never re-arm, and a UDP socket nothing ever receives on.
    //
    // Leaving them standing across a stop is still right — the request really is
    // occupied until its completion lands, delivered or dropped.  What was
    // missing is anything that lowers them once it has.  The loop is the only
    // thing that knows: owner_inflight() counts what is still in the ring for
    // this handler over every registration it has ever held, whatever became of
    // the completions.  Zero means every one of these requests is free.
    //
    // owner_table_full() is the case it cannot answer: a handler that never got
    // a slot reads zero whatever it has outstanding, so a full table leaves the
    // flags alone rather than clearing them on a zero that means "unknown".
    if (loop.owner_inflight(this) == 0 && !loop.owner_table_full())
    {
        m_accept_armed         = false;
        m_idle_sweep_armed     = false;
        m_relay_deadline_armed = false;
        m_accept_backoff_armed = false;
        m_udp_recv_armed       = false;
        // Nothing in the ring names any of them any more.
        m_accept_spent.clear();
        m_udp_recv_spent.clear();
    }

    // Cache config getters once at setup to avoid virtual calls on the hot path
    m_idle_timeout_cached = get_idle_timeout();
    m_max_conns_cached = get_max_connections();
    m_rate_limit_cached = get_rate_limit();

    // Pre-allocate the connection pool if empty (first run or after teardown)
    if (m_conn_pool.empty())
    {
        uint32_t pool_size = std::max(512u, m_max_conns_cached > 0 ? m_max_conns_cached / 4 : 512u);
        m_conn_pool.reserve(pool_size);
        for (uint32_t i = 0; i < pool_size && i < 2048; i++)
            m_conn_pool.push_back(std::make_unique<server_connection>());
    }

    // ── TLS listener ────────────────────────────────────────────────────────
    //
    // Certificates are read and parsed here, at setup, before a single
    // completion is armed.  That is file I/O and it blocks, which is exactly
    // why it happens here and nowhere near the event loop's hot path: the
    // handshake itself never touches a file, and never touches a socket
    // either — see tls_feed/tls_flush.
    //
    // Rebuilt on every start rather than kept.  `reload` is a stop followed by
    // a start, and it is how an operator installs a renewed certificate; an
    // SSL_CTX that outlived the file would go on serving the expired one.
    // Sessions handed out by the previous context keep it alive through their
    // own reference, so dropping ours here cannot pull the ground from under a
    // connection that is still talking.
    //
    // Every refusal below returns false, which puts the runtime in the failed
    // state.  None of them may fall through to a plaintext listener: a config
    // that asked for encryption and got a cleartext port is the one outcome
    // the operator cannot see.
    m_tls.reset();
    if (get_tls())
    {
        if (!m_upstream_targets.empty())
        {
            LOG_ERROR("server: --tls encrypts this server's own listener, and nothing "
                      "dials an upstream over TLS yet -- refusing rather than "
                      "connecting upstream in cleartext under a TLS configuration");
            return false;
        }
        auto ctx = std::make_unique<tls_context>();
        if (!ctx->init_server(get_cert_path(), get_key_path(), get_ca_path()))
        {
            // init_server has already said which file and what OpenSSL made of
            // it.  This says what it cost.
            LOG_ERROR("server: TLS listener not started -- the certificate, key or "
                      "client CA could not be loaded");
            return false;
        }
        m_tls = std::move(ctx);
    }

    // ─── --listen unix:/path/to.sock ────────────────────────────────────────
    //
    // Checked here rather than only in the flag parser because this is the one
    // function every route to a listening socket passes through: create, the
    // daemon's restore of a persisted runtime, a worker rebuilding from its
    // config frame, `import`, and a restart after `edit`.  A rule kept in the
    // flag parser alone is one that import and restore never hear about.
    const std::string listen_path(get_listen_path());
    if (!listen_path.empty())
    {
        // The shared set first — the -p conflict, --tls, and the path rules
        // re-checked because the flag parser is not on the restore path.
        if (const std::string msg = socketley::unix_sock::listen_config_refusal(
                listen_path, get_port(), get_tls()); !msg.empty())
        {
            LOG_ERROR(("server: " + msg).c_str());
            return false;
        }
        // And the member only this runtime carries: --udp is a server's flag,
        // so the pair can only be asked for here and the refusal stays here.
        if (m_udp)
        {
            LOG_ERROR("server: --listen names a stream socket and --udp asks for "
                      "datagrams -- a unix datagram listener is a different thing "
                      "and this is not it");
            return false;
        }
    }

    // Internal-only server (port=0, used for Lua-managed sub-servers).  A
    // listen path is a listener, so a runtime that has one is not this case
    // however its owner is set.
    if (listen_path.empty() && get_port() == 0 && !get_owner().empty())
        return true;

    uint16_t port = get_port();
    if (port == 0)
        port = 8000;

    if (m_udp)
    {
        m_udp_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (m_udp_fd < 0)
            return false;

        int opt = 1;
        setsockopt(m_udp_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        setsockopt(m_udp_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        if (bind(m_udp_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
        {
            LOG_ERROR(("server: UDP port " + std::to_string(port) + " could not be bound: " +
                       std::string(std::strerror(errno))).c_str());
            close_tracked(m_udp_fd);
            m_udp_fd = -1;
            return false;
        }

        // The previous run's recvmsg reads into this struct's buffer and writes
        // the sender into its sockaddr, and a stop does not end it: the socket
        // holds a reference of its own, so close() does not, and the completion
        // that would lower m_udp_recv_armed is dropped rather than dispatched
        // once stop() has deregistered this owner.  Arming a second recvmsg on
        // the same msghdr would give the kernel two writers into one buffer and
        // one address, and answers would go to whichever peer landed there last;
        // declining to arm one at all — which is what the flag used to make this
        // do — left the restarted server bound to the port and receiving
        // nothing, for good.
        //
        // So the old chain keeps its struct and this run takes a fresh one.  The
        // old one is not freed: the kernel may still be writing into it, and the
        // loop reads the request inside it to drop the completion.  setup()
        // releases the spent ones once owner_inflight() says nothing is left.
        if (m_udp_recv_armed)
        {
            m_udp_recv_spent.push_back(std::move(m_udp_recv));
            m_udp_recv = std::make_unique<udp_recv_state>();
            m_udp_recv_armed = false;
        }

        // Setup recvmsg structures
        m_udp_recv->iov.iov_base = m_udp_recv->buf;
        m_udp_recv->iov.iov_len = sizeof(m_udp_recv->buf);
        m_udp_recv->msg.msg_name = &m_udp_recv->addr;
        m_udp_recv->msg.msg_namelen = sizeof(m_udp_recv->addr);
        m_udp_recv->msg.msg_iov = &m_udp_recv->iov;
        m_udp_recv->msg.msg_iovlen = 1;

        m_udp_recv->req = { this, nullptr, m_udp_fd, 0, op_recvmsg };
        arm_udp_recv();

        return true;
    }

    // The listener itself, in whichever family this runtime was configured for.
    // Everything below this line is the same for both: one accept chain, one
    // buffer ring, one set of connection tables.
    if (!(listen_path.empty() ? setup_tcp_listener(port)
                              : setup_unix_listener(listen_path)))
        return false;

    // Setup provided buffer ring for zero-copy reads
    m_use_provided_bufs = loop.setup_buf_ring(BUF_GROUP_ID, BUF_COUNT, BUF_SIZE);
    m_recv_multishot = m_use_provided_bufs && loop.recv_multishot_supported();
    // Bundled recv: one completion carries as many provided buffers as the
    // socket queue could fill.  Probed by a real submission inside
    // recv_bundle_enabled() and off under SOCKETLEY_RECV_BUNDLE=0, which is
    // also the A/B switch -- same binary, same pool geometry, only the arm
    // differs.  Measured on the cache: nothing at 1 KB buffers, +48% at 2 KB,
    // and it flattens the buffer-size curve rather than moving its peak.
    m_recv_bundle = m_recv_multishot && loop.recv_bundle_enabled();
    // Not send_zc_supported(): the kernel having the opcode is not the
    // question.  A pending zero-copy notification is not a cancellable request
    // and only the peer can release it, so it would hold this instance in
    // retire()'s graveyard for as long as one client declines to read.  See
    // event_loop::send_zc_enabled().
    m_send_zc = loop.send_zc_enabled();

    // Use multishot accept if supported (kernel 5.19+)
    // Note: direct-descriptor accept (kernel 6.0+) is NOT used because
    // cqe->res returns a fixed file index, not a real fd — setsockopt,
    // getpeername, and other syscalls require a real fd.  Instead, we
    // register the accepted fd into the fixed file table post-accept.
    m_direct_accept = false;
    m_multishot_active = event_loop::supports_multishot_accept();

    // The previous run's accept chain does NOT reliably end before this line.
    //
    // teardown() shuts the listener down and close_fd() submits a cancel for
    // it, both of which make the chain report — but reporting means a CQE in
    // the ring, and nothing reaps the ring between a stop and the start that
    // follows it.  `restart` is exactly that order, and so is any Lua callback
    // that stops and starts a server: both run inside a single completion
    // handler, and the ring is not looked at again until it returns.
    //
    // Arming a second submission on a request the ring is still carrying one for
    // is the one thing that must not happen to any request here.  arm() stamps
    // the owner identity into the request and there is one field for it, so the
    // second submission overwrites the first's: the *old* completion then passes
    // the check meant for the new one and the disarm it triggers lands on the new
    // registration's slot.  Both halves of that are wrong and one of them is
    // fatal.  The old slot is left owing a completion for ever, and
    // runtime_manager waits on that count before it frees a removed runtime —
    // about six megabytes per restart, held until the daemon exits, with one of
    // the loop's 1024 owner slots gone each time.  Worse, the new slot has been
    // discounted for an operation that is still in the ring: it can read zero
    // while the accept is live, and an instance freed on the strength of that
    // zero is a use-after-free the next time the chain reports.
    //
    // So the old chain keeps its request and this run takes a fresh one.  The
    // old one is not freed here — the loop reads it to drop its completion, so
    // it has to outlive the ring's interest in it, which is what m_accept_spent
    // is for and what the sweep at the top of this function releases.
    if (m_accept_armed)
    {
        m_accept_spent.push_back(std::move(m_accept_req));
        m_accept_req  = std::make_unique<io_request>();
        *m_accept_req = { this, nullptr, -1, 0, op_accept };
        m_accept_armed = false;
    }

    if (m_multishot_active)
    {
        m_accept_req->type = op_multishot_accept;
        m_accept_armed = loop.submit_multishot_accept(m_listen_fd, m_accept_req.get());
    }
    else
    {
        m_accept_addrlen = sizeof(m_accept_addr);
        m_accept_req->type = op_accept;
        m_accept_armed = loop.submit_accept(m_listen_fd, &m_accept_addr, &m_accept_addrlen,
                                            m_accept_req.get());
    }

    // SOCKETLEY_HTTP_REVALIDATE=0 puts disk mode back on an open+read per
    // request.  Read here rather than at construction so a restart picks it up.
    if (const char* rv = ::getenv("SOCKETLEY_HTTP_REVALIDATE"))
        m_http_reval_enabled = !(rv[0] == '0' && rv[1] == '\0');
    else
        m_http_reval_enabled = true;
    m_http_reval.clear();
    m_http_reval_bytes = 0;
    m_http_reval_full_logged = false;

    // Build HTTP file cache if enabled
    if (m_http_cache_enabled && !m_http_dir.empty())
        rebuild_http_cache();

    // A timeout hangs off no fd, so a stop cannot cancel one: the sweep armed by
    // the previous run is still counting down on this very request.  Arming
    // another gave the server a second self-perpetuating chain, one more per
    // restart.  The one still in flight re-arms itself when it fires.
    if (m_idle_timeout_cached > 0 && !m_idle_sweep_armed)
    {
        m_idle_sweep_ts.tv_sec = 30;
        m_idle_sweep_ts.tv_nsec = 0;
        m_idle_sweep_req = { this, nullptr, -1, 0, op_timeout };
        m_idle_sweep_armed = m_loop->submit_timeout(&m_idle_sweep_ts, &m_idle_sweep_req);
    }

    // Create splice pipe for zero-copy HTTP file serving
    if (m_splice_pipe[0] < 0 && !m_http_dir.empty())
    {
        // O_CLOEXEC as well: this pipe lives as long as the runtime does, so
        // without it every proxy worker forked afterwards carries both halves.
        if (pipe2(m_splice_pipe, O_NONBLOCK | O_CLOEXEC) == 0)
            fcntl(m_splice_pipe[0], F_SETPIPE_SZ, 1048576);  // 1MB pipe buffer
        else
            m_splice_pipe[0] = m_splice_pipe[1] = -1;
    }
    m_splice_busy = false;

    // Connect to upstreams.  Nothing to clear: teardown() either dropped the
    // previous run's structs or moved the ones with work still in the ring to
    // m_upstream_retired.  Clearing here destroyed both kinds alike.
    m_upstream_by_fd.clear();
    m_next_upstream_id = 1;
    for (const auto& target : m_upstream_targets)
    {
        auto uc = std::make_unique<upstream_connection>();
        uc->conn_id = m_next_upstream_id++;
        uc->target = target;
        auto* ptr = uc.get();
        m_upstreams[uc->conn_id] = std::move(uc);
        if (!upstream_try_connect(ptr))
            upstream_schedule_reconnect(ptr);
    }

    return true;
}

void server_instance::teardown(event_loop& loop)
{
    // The requests this server is owed answers for go first.  Everything below
    // closes the connections those replies would have gone to, so a queued
    // request whose origin has stopped is discarded rather than served: the
    // answer has nowhere to go, and computing it is work the cache does not
    // have to do.
    //
    // Then, and deliberately after, whatever the last read produced for the
    // cache.  A stop is not a reason to throw away messages that arrived before
    // it, and posting on this side of the revocation is what keeps the batch
    // out of the sweep that has just run.  The store is performed on the next
    // turn of the loop whether or not this runtime is still up — the channel
    // serves the request before it asks whether anyone is left to answer.  A
    // `remove` in the same loop iteration as the `stop` does take it back with
    // the instance, which is the one message this can lose and the only place
    // it can lose one.
    if (auto* mgr = get_runtime_manager())
    {
        mgr->requests().drop_origin(this);
        flush_cache_store();
    }
    m_cache_store_batch.clear();

    if (m_udp)
    {
        if (m_udp_fd >= 0)
        {
            // The recvmsg holds a reference to the socket, so close() does not
            // end it — it stays armed on m_udp_recv->buf and m_udp_recv->addr.
            // SO_REUSEPORT then makes that matter: once a restart binds a new
            // socket to the same port the kernel delivers datagrams to the old
            // one as well, and the completion used to arm a second recvmsg on
            // the same msghdr.
            //
            // This used to cancel, flush and close, in that order, and the order
            // was the whole defence.  It is not one: flush() hands the SQE to
            // the ring and returns — under SQPOLL without even a syscall — so
            // the close could and did run before the kernel had looked at either
            // the cancel or the recvmsg.  A recvmsg consumed after this number
            // was reissued reads a stranger's datagram into m_udp_recv->buf, and
            // a cancel consumed after it takes back a stranger's I/O.  close_fd
            // submits the cancel itself and holds the number until both have
            // reported.
            close_tracked(m_udp_fd);
            m_udp_fd = -1;
        }
        m_udp_peers.clear();
        m_udp_peer_idx.clear();
        m_loop = nullptr;
        return;
    }

    // Shut down, then close — and the close is close_fd's, which is where the
    // cancel now comes from.
    //
    // The cancel is what ends the accept chain.  A multishot accept holds its
    // own reference to the socket, so close() does not end it and the
    // terminating completion never arrives, which leaves the loop counting one
    // operation this owner still owes, forever.  reap_retired waits for that
    // count to reach zero, so the whole instance was never freed: about 6 MB
    // per removed runtime, held until the daemon exited.
    //
    // Submitting it before the close was necessary but never sufficient: after
    // close(), fget(fd) answers NULL and the cancel fails -ENOENT, but a cancel
    // the SQPOLL thread has not consumed *yet* is no better off — by the time it
    // is, the number belongs to the next accepted connection and the cancel
    // takes that connection's read away instead.  Holding the number until both
    // the accept and the cancel have reported is what actually makes the order
    // hold, and close_fd does that.
    //
    // shutdown() stays, and stays first: it ends the listen state — which is
    // what takes this socket out of the SO_REUSEPORT group, so a restart's bind
    // is not competing with it — and completes what the cancel did not reach,
    // synchronously inside the syscall via the socket wait queue.
    if (m_listen_fd >= 0)
    {
        shutdown(m_listen_fd, SHUT_RDWR);
        close_tracked(m_listen_fd);
        m_listen_fd = -1;
    }

    // And the socket node, for a unix listener.  Closing the descriptor does
    // not remove it — the path is a filesystem entry, not a socket state — so
    // without this every stopped server leaves one behind, and the next start
    // meets its own leftovers.  setup_unix_listener probes those and recovers,
    // so the cost of missing this is not a failure to start; it is a directory
    // filling up with dead nodes that nothing ever accounts for.
    //
    // After the close, deliberately.  Unlinking first would leave a live
    // listener bound to a path no longer in the filesystem, which is a
    // perfectly legal state and an invisible one.
    if (!m_bound_listen_path.empty())
    {
        if (unlink(m_bound_listen_path.c_str()) < 0) {}
        m_bound_listen_path.clear();
    }

    // Drain: flush pending write queues with blocking writes before closing
    if (get_drain())
    {
        for (auto& [fd, conn] : m_clients)
        {
            if (SOCKETLEY_UNLIKELY(conn->ssl != nullptr))
            {
                // The same drain, through the record layer.  The obvious
                // shortcut — write the queue straight to the socket, as the
                // loop below does — would put plaintext on a connection whose
                // peer is decrypting, so the client sees corruption and the
                // message is on the wire in the clear regardless.
                //
                // A session that never finished its handshake has no keys to
                // encrypt with, so its queue is dropped rather than sent.
                if (conn->tls_state != tls_conn_ready)
                    continue;
                while (!conn->write_queue.empty())
                {
                    const auto& msg = conn->write_queue.front();
                    if (tls_context::ssl_write(conn->ssl, msg->data(),
                                               static_cast<int>(msg->size())) <= 0)
                        break;
                    conn->write_queue.pop();
                }
                char cbuf[16384];
                bool ok = true;
                while (ok)
                {
                    const int n = tls_context::bio_read_out(conn->ssl, cbuf, sizeof(cbuf));
                    if (n <= 0)
                        break;
                    ok = socketley::write_all(fd, cbuf, static_cast<size_t>(n));
                }
                continue;
            }

            while (!conn->write_queue.empty())
            {
                const auto& msg = conn->write_queue.front();
                // A short write leaves half a message on the wire; sending the
                // next one after it would misframe everything that follows.
                if (!socketley::write_all(fd, msg->data(), msg->size())) break;
                conn->write_queue.pop();
            }
        }
    }

    m_active_fds.clear();
    shard_clients_table().clear_own();

    for (auto& [fd, conn] : m_clients)
    {
        if (fd >= 0 && fd < MAX_FDS)
            m_conn_idx[fd] = nullptr;

        conn->closing = true;

        // The cache requests this connection was waiting on were revoked above,
        // so nothing is owed to it any more.  Clearing the count says so.
        //
        // Leaving it standing put a struct in the pool still counting replies
        // that were never coming, and the next client to be handed that struct
        // inherited the backlog: it would be closed at MAX_CACHE_PENDING for
        // traffic somebody else sent, sooner the more often the server had been
        // restarted.  reset() clears it on the way out of the pool, which is why
        // this was invisible until a fuzz run walked the pool at rest.
        conn->cache_pending = 0;

        // The slot first, which is what unregisters the file — and until that
        // runs the kernel still holds a reference to this socket, so the
        // close() below does not really close it.  release_conn() and
        // pool_release() both call it; this path, the one a stop takes, did
        // not, so it was the only way a connection could reach the end of its
        // life with its file still registered.
        //
        // What that costs is a read the socket can no longer end.  A multishot
        // recv armed through submit_recv_multishot_fixed_file() is counted on
        // the fixed index, not on the descriptor number, so close_fd() sees
        // m_fd_armed[fd] == 0, takes its fast path and submits no cancel — and
        // a multishot recv holds its own reference to the file, so nothing else
        // is going to end it either.  On this machine shutdown() does: the
        // socket's wait queue completes the recv before close_tracked() runs.
        // The nightly runner's kernel does not, and the fuzz harness has been
        // reporting the result there since June, in the only words it has for
        // it — "1 operation(s) still owed at end of input: recv-multishot=1",
        // on no descriptor the loop can name, because the operation was never
        // counted against one.
        //
        // Before the shutdown and the close, which is the order
        // cache_instance::teardown() has always used for the same three calls.
        // The sibling runtime doing exactly this is also the reason to read the
        // omission here as an oversight rather than a difference somebody meant.
        release_fixed_slot(conn.get());

        // Shutdown the connection before closing it.  Like for the listen fd,
        // shutdown() completes any pending io_uring read/write ops synchronously
        // (the kernel wakes up the socket wait queue, completing the ops and
        // placing their CQEs in the ring before we return from shutdown()).
        // This avoids the cancel-SQE fd-closed race described above.
        shutdown(fd, SHUT_RDWR);
        close_tracked(fd);

        // The file read and the file→pipe splice target the file fd, not the
        // socket, so the shutdown above does not touch them.  Closing the file
        // ends them; the ops themselves keep the struct out of the pool until
        // their completions arrive, and file_buf stays allocated until then
        // because that is where the kernel is writing.
        if (conn->file_fd >= 0) { close_tracked(conn->file_fd); conn->file_fd = -1; }
        if (conn->splice_file_fd >= 0) { close_tracked(conn->splice_file_fd); conn->splice_file_fd = -1; }
        conn->splice_remaining = 0;
        conn->splice_pipe_pending = 0;
        conn->splice_pending = false;

        // The queue is ours to drop.  The batch is not: a write that has reached
        // the ring is reading out of write_batch[0] right now, and a zero-copy
        // send is doing so long after write_pending went down.  Those refs are
        // released where every other path releases them — when the completion
        // says the kernel is finished with them.
        conn->write_queue.clear();
        if (!conn->write_pending && !conn->zc_notif_pending)
        {
            for (size_t i = 0; i < conn->write_batch_count; i++)
                conn->write_batch[i].reset();
            conn->write_batch_count = 0;
        }
    }

    // Empty m_clients: idle structs go back to the pool, the rest to the
    // retired list, where they stay valid until their completions arrive.
    for (auto& [fd, conn] : m_clients)
        release_conn(std::move(conn));
    m_clients.clear();

    // Set false by any timer withdrawal the ring refused; reported once at the
    // end rather than per timer, because they all fail for the same reason and
    // they all fail together.
    bool timers_withdrawn = true;

    // Tear down upstream connections
    for (auto& [cid, uc] : m_upstreams)
    {
        if (uc->fd >= 0)
        {
            m_upstream_by_fd.erase(uc->fd);
            shutdown(uc->fd, SHUT_RDWR);
            close_tracked(uc->fd);
            uc->fd = -1;
        }
        uc->connected = false;
        // Release write queue refs
        uc->write_queue.clear();
        if (!uc->write_pending)
        {
            for (size_t j = 0; j < uc->write_batch_count; j++)
                uc->write_batch[j].reset();
            uc->write_batch_count = 0;
        }

        // The reconnect timer is attached to no fd, so nothing above reached it
        // and it can still be counting down thirty seconds from here.  Its owner
        // stays set on purpose: the completion is the only thing that can tell
        // us this struct is free, and the struct is kept for it to arrive in.
        //
        // Withdrawing it does not change that — the timeout still reports, with
        // -ECANCELED, and timeout_pending is still cleared by that completion
        // and by nothing else.  It only stops the wait being thirty seconds
        // long, which is thirty seconds this whole instance spends in the
        // manager's graveyard.
        if (uc->timeout_pending)
            timers_withdrawn &= loop.submit_timeout_remove(&uc->timeout_req);

        if (uc->read_pending || uc->write_pending || uc->timeout_pending)
            m_upstream_retired.push_back(std::move(uc));
    }
    m_upstreams.clear();

    // Close splice pipe
    if (m_splice_pipe[0] >= 0) { close_tracked(m_splice_pipe[0]); m_splice_pipe[0] = -1; }
    if (m_splice_pipe[1] >= 0) { close_tracked(m_splice_pipe[1]); m_splice_pipe[1] = -1; }
    m_splice_busy = false;

    // The timers this server armed.  Everything above closed a descriptor and
    // was done; a timeout is attached to none, so shutdown() and
    // submit_cancel_fd() both walked straight past these and the ring went on
    // owing this owner a completion for as long as thirty seconds — long enough
    // that reap_retired() never saw the count reach zero on any pass, and the
    // whole instance stayed in the graveyard: about 6 MB per removed runtime.
    // Withdrawing them is the only way to end one early.
    //
    // The armed flags decide, not a guess: they say "this request is occupied",
    // and withdrawing a timeout that is not there would submit a removal for a
    // request the ring is not carrying, which answers -ENOENT and wastes an SQE.
    if (m_idle_sweep_armed)
        timers_withdrawn &= loop.submit_timeout_remove(&m_idle_sweep_req);
    // 250 ms rather than thirty seconds, so this one would end the retirement
    // on its own soon enough — but "soon enough" is not the contract, and a
    // timer left in the ring is a completion this owner is still owed however
    // short its fuse.
    if (m_relay_deadline_armed)
        timers_withdrawn &= loop.submit_timeout_remove(&m_relay_deadline_req);
    if (m_accept_backoff_armed)
        timers_withdrawn &= loop.submit_timeout_remove(&m_accept_backoff_req);
    loop.flush();

    if (SOCKETLEY_UNLIKELY(!timers_withdrawn))
        LOG_WARN("server: a timer withdrawal did not reach the ring — this instance "
                 "stays retired until the timer fires on its own");

    // The armed flags are deliberately left standing.  A withdrawn timeout is
    // still owed exactly one completion, and that completion has not landed yet
    // — it cannot, nothing reaps the ring until this call returns.  Clearing the
    // flags here would let a start() in this same loop iteration, which is what
    // `restart` does, submit a fresh timeout on a request the kernel is still
    // carrying one for: the new submission overwrites owner_token, the old
    // completion then passes the check meant for the new one, and the disarm it
    // triggers lands on the wrong slot — leaving the old slot owing a completion
    // for ever, which is the leak this whole change is about.
    //
    // What clears them is on_cqe below, but only for a completion the loop still
    // delivers.  After stop() has deregistered this owner it drops them instead,
    // so across a stop the flags survive and the next start() declines to re-arm
    // a sweep it believes is still occupied.  That was equally true when the
    // timer simply ran its thirty seconds out, so it is not something this
    // withdrawal introduces — but it is why the flags cannot be cleared here to
    // fix it either.
    //
    // m_idle_sweep_req keeps its owner for the same reason.  Nulling it made the
    // loop drop the sweep's completion, which left m_idle_sweep_armed true for
    // ever and the next start() unable to tell an armed timer from a lost one.
    // The request lives in this instance, and an instance that ever armed I/O is
    // retired rather than freed, so the loop reading it is reading valid memory.
    m_loop = nullptr;
    m_multishot_active = false;
    m_master_fd = -1;

    // Tell every origin that what it routed here has nowhere to go.  This used
    // to reach into the origin's private route table and delete an entry by
    // descriptor number, which worked only because both runtimes were the same
    // class in the same process; it is a message now, named by the same
    // conn_ref the route was made with.
    for (auto& [handle, fc] : m_forwarded)
    {
        (void)handle;
        auto* mgr = get_runtime_manager();
        if (mgr)
        {
            auto* origin = mgr->get(fc.origin);
            if (auto* srv = origin ? origin->as_server() : nullptr)
                srv->drop_route(fc.ref);
        }
    }
    m_forwarded.clear();
    m_forwarded_by_ref.clear();

    // And the other direction: every connection this runtime had routed away is
    // being closed by the stop, so the runtime holding its name has to be told.
    //
    // Nothing told it before.  A stop does not go through close_conn — it walks
    // m_clients and clears the index directly — so unroute_client never ran for
    // any of these, and the target kept an entry per routed connection naming a
    // runtime that had gone.  Harmless in that owner_send answered false on
    // them, and unbounded: a parent restarted a hundred times left a hundred
    // connections' worth of them behind, and its own connection count reported
    // them as live.
    {
        auto* mgr = get_runtime_manager();
        for (const auto& [serial, target_name] : m_routes)
        {
            if (!mgr) break;
            auto* target = mgr->get(target_name);
            if (auto* srv = target ? target->as_server() : nullptr)
                srv->release_routed(conn_ref{owner_key(), serial});
        }
    }

    // Our own side: whatever we had routed away, and the serial index that
    // resolves a name to a descriptor.  Both describe connections that are
    // being closed as this runtime stops, so a name minted before the stop must
    // not resolve after it.
    m_routes.clear();
    m_conn_by_serial.clear();
    m_groups.clear();

    // Zeroize password memory
    if (!m_master_pw.empty())
    {
        volatile char* p = m_master_pw.data();
        for (size_t i = 0; i < m_master_pw.size(); i++)
            p[i] = 0;
    }
}

void server_instance::on_cqe(struct io_uring_cqe* cqe)
{
    auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
    if (SOCKETLEY_UNLIKELY(!req))
        return;

    // Structs the ring has not finished with are recognised by the address the
    // kernel handed back, before anything tries to find them by descriptor —
    // theirs are closed and may belong to somebody else by now.
    if (SOCKETLEY_UNLIKELY(!m_conn_retired.empty() || !m_upstream_retired.empty()))
    {
        if (reap_retired(cqe, req))
            return;
    }

    if (SOCKETLEY_UNLIKELY(!m_loop))
    {
        // Stopped.  Nothing may be submitted from here, but the completion is
        // not nothing: the buffer it carries belongs to a group shared with
        // every other server on this loop, and a timer that completes here is
        // no longer armed, which is what the next start() needs to know.
        return_provided_buf(cqe);
        if (req == &m_idle_sweep_req)          m_idle_sweep_armed = false;
        else if (req == &m_relay_deadline_req) m_relay_deadline_armed = false;
        else if (req == &m_accept_backoff_req) m_accept_backoff_armed = false;
        else if (req == &m_udp_recv->req)       m_udp_recv_armed = false;
        else if (req == m_accept_req.get()) m_accept_armed = false;
        return;
    }

    // Remembered before the dispatch, because the handler may release the
    // struct and the request with it.  Only per-connection operations are worth
    // asking about; an accept or a timer names no connection.
    const int cqe_fd = (req->type == op_accept || req->type == op_multishot_accept ||
                        req->type == op_timeout || req->type == op_recvmsg)
                       ? -1 : req->fd;

    switch (req->type)
    {
        case op_accept:
        case op_multishot_accept:
            handle_accept(cqe);
            break;
        case op_recvmsg:
            handle_udp_read(cqe);
            break;
        case op_file_read:
        {
            // Async file read completion — route via socket fd in req->fd
            auto* conn = (req->fd >= 0 && req->fd < MAX_FDS) ? m_conn_idx[req->fd] : nullptr;
            if (SOCKETLEY_LIKELY(conn && req == &conn->file_read_req
                                 && req->generation == conn->generation))
                handle_file_read(cqe, req);
            break;
        }
        case op_splice:
        {
            auto* conn = (req->fd >= 0 && req->fd < MAX_FDS) ? m_conn_idx[req->fd] : nullptr;
            if (SOCKETLEY_LIKELY(conn && req->generation == conn->generation))
            {
                if (req == &conn->splice_in_req)
                    handle_splice_in(cqe, conn);
                else if (req == &conn->splice_out_req)
                    handle_splice_out(cqe, conn);
            }
            else
            {
                // Nobody owns this splice any more, so nobody is going to hand
                // the shared pipe back; without this no later request could ever
                // use the zero-copy path again.
                m_splice_busy = false;
            }
            break;
        }
        case op_read:
        case op_read_provided:
        case op_recv_multishot:
        case op_recv_multishot_bundle:
        case op_write:
        case op_writev:
        case op_send_zc:
        case op_send_zc_notif:
        {
            const bool is_read = is_read_op(req->type);

            // The descriptor says where to look; the request address and the
            // generation say whether what we found is who submitted it.  An
            // upstream's fd can be reissued to an accepted client, and the
            // client index is consulted first — without this the upstream's
            // completion was applied to a client connection.
            auto* conn = (req->fd >= 0 && req->fd < MAX_FDS) ? m_conn_idx[req->fd] : nullptr;
            if (SOCKETLEY_LIKELY(conn && (req == &conn->read_req || req == &conn->write_req)
                                 && req->generation == conn->generation))
            {
                if (is_read)
                    handle_read(cqe, req);
                else
                    handle_write(cqe, req);
                break;
            }

            // Slow path: check upstream connections
            auto uit = m_upstream_by_fd.find(req->fd);
            if (uit != m_upstream_by_fd.end())
            {
                auto* uc = uit->second;
                if (SOCKETLEY_LIKELY((req == &uc->read_req || req == &uc->write_req)
                                     && req->generation == uc->generation))
                {
                    if (is_read)
                        handle_upstream_read(cqe, uc);
                    else
                        handle_upstream_write(cqe, uc);
                    break;
                }
            }

            // Nobody owns this any more — but the buffer it carries is still
            // the ring's.
            return_provided_buf(cqe);
            break;
        }
        case op_timeout:
            if (req == &m_idle_sweep_req)
            {
                m_idle_sweep_armed = false;   // this link of the chain is done
                auto now = std::chrono::steady_clock::now();
                auto timeout = std::chrono::seconds(m_idle_timeout_cached);
                for (int cfd : m_active_fds)
                {
                    auto* cconn = m_conn_idx[cfd];
                    if (cconn && !cconn->closing && (now - cconn->last_activity) > timeout)
                    {
                        cconn->closing = true;
                        shutdown(cfd, SHUT_RD);
                    }
                }
                if (m_idle_timeout_cached > 0)
                    m_idle_sweep_armed = m_loop->submit_timeout(&m_idle_sweep_ts, &m_idle_sweep_req);
            }
            // Relay-hold deadline.  Lowered before the sweep and not after it,
            // because the sweep re-arms this very request for whatever is still
            // waiting; clearing the flag afterwards would clear the arming the
            // sweep had just done, and the timer would stop for good the first
            // time two listeners were holding at once.
            else if (req == &m_relay_deadline_req)
            {
                m_relay_deadline_armed = false;
                relay_deadline_sweep();
            }
            // Accept backoff expired — resubmit accept
            else if (req == &m_accept_backoff_req)
            {
                m_accept_backoff_armed = false;
                // Not if an accept is already armed: this timer can outlive the
                // stop that closed the listener it was waiting for, and the
                // start() that followed has armed a chain of its own.
                if (m_listen_fd >= 0 && !m_accept_armed)
                {
                    if (m_multishot_active)
                        m_accept_armed = m_loop->submit_multishot_accept(m_listen_fd, m_accept_req.get());
                    else
                    {
                        m_accept_addrlen = sizeof(m_accept_addr);
                        m_accept_armed = m_loop->submit_accept(m_listen_fd, &m_accept_addr,
                                                               &m_accept_addrlen, m_accept_req.get());
                    }
                }
            }
            else
            {
                // Upstream reconnect timers
                for (auto& [cid, uc] : m_upstreams)
                {
                    if (req == &uc->timeout_req)
                    {
                        uc->timeout_pending = false;
                        uc->reconnect_attempt++;
                        if (!upstream_try_connect(uc.get()))
                            upstream_schedule_reconnect(uc.get());
                        break;
                    }
                }
            }
            break;
        default:
            break;
    }

    // ── The chokepoint ──────────────────────────────────────────────────────
    //
    // Every teardown in this runtime runs out of a completion handler, and every
    // completion handler runs from here.  Each handler decides for itself whether
    // the connection it just touched may be finished, and all 16 of those
    // decisions ask conn_ops_pending(), which counts an armed read as a
    // completion that is owed.  It is not one: see shared/conn_reachability.h for
    // why, and for the two runtimes this has now been found in.
    //
    // So the rule goes here, after the dispatch, for the connection the
    // completion named — the one place every path already goes through.  The 16
    // guards keep their own answer and are not touched; a teardown one of them
    // declines for the wrong reason is picked up here on the same dispatch
    // instead of never.
    finish_unreachable_conn(cqe_fd);

#ifdef SOCKETLEY_INVARIANTS
    inv_check_reachable(cqe_fd, "server::on_cqe");
#endif
}

// See the call site in on_cqe() for why this exists.  Everything before the
// verdict is a guard: a descriptor with no connection on it, or one that is not
// closing, is somebody else's business.
void server_instance::finish_unreachable_conn(int fd)
{
    if (fd < 0 || fd >= MAX_FDS)
        return;
    auto* conn = m_conn_idx[fd];
    if (SOCKETLEY_LIKELY(conn == nullptr || !conn->closing))
        return;

    using socketley::reach::verdict;

    switch (socketley::reach::classify(conn->closing, conn_owed(conn),
                                       conn_has_output(conn)))
    {
        case verdict::keep:
            return;

        case verdict::flush:
            // Bytes the client already handed us and considers answered are not
            // "nothing left".  flush_write_queue() marks the connection closing
            // on any failure it cannot recover from, so the only thing to do
            // afterwards is ask again — which is what the second classify below
            // is.  A flush that reached the ring answers `keep` and its
            // completion finishes the teardown; one that submitted nothing
            // answers `finish`, because nothing would wake it either.
            flush_write_queue(conn);
            if (socketley::reach::classify(conn->closing, conn_owed(conn),
                                           /*has_output=*/false) == verdict::keep)
                return;
            close_conn(conn);
            return;

        case verdict::finish:
            close_conn(conn);
            return;
    }
}

#ifdef SOCKETLEY_INVARIANTS
// Invariant (1) from invariants.h, in the form this runtime takes: a client
// connection is normally its own pair — nothing else drives it — except while
// it is piped to another connection for zero-copy forwarding, where the peer's
// read is what will wake both of them.
void server_instance::inv_check_reachable(int fd, const char* where)
{
    if (fd < 0 || fd >= MAX_FDS)
        return;

    const auto* conn = m_conn_idx[fd];
    if (!conn)
        return;   // already torn down: nothing left that needs waking

    const auto fill = [](const server_connection* c) {
        skl_inv::half h{};
        if (!c) return h;
        h.present   = true;
        // A cache request counts.  Nothing of this connection's is in the ring
        // while one is outstanding — the request lives in the channel's queue —
        // but the channel's own wakeup is, and the reply it produces comes back
        // here.  So the connection has something that will wake it, which is
        // what the invariant is about.
        h.in_flight = c->read_pending || c->write_pending || c->zc_notif_pending ||
                      c->file_read_pending || c->splice_in_pending || c->splice_out_pending ||
                      c->cache_pending > 0;
        h.queued    = !c->write_queue.empty();
        h.closing   = c->closing;
        h.fd        = c->fd;
        return h;
    };

    const server_connection* peer = nullptr;
    if (conn->pipe_peer_fd >= 0 && conn->pipe_peer_fd < MAX_FDS)
        peer = m_conn_idx[conn->pipe_peer_fd];

    SKL_INV_PAIR(where, fill(conn), fill(peer));
}
#endif

// O(1) removal from active_fds using the index stored in the connection.
// The swapped-in element's connection gets its index updated.
inline void server_instance::remove_active_fd(int fd)
{
    auto* conn = (fd >= 0 && fd < MAX_FDS) ? m_conn_idx[fd] : nullptr;
    if (!conn) return;
    uint32_t idx = conn->active_idx;
    if (idx >= m_active_fds.size()) return;
    int back_fd = m_active_fds.back();
    m_active_fds[idx] = back_fd;
    m_active_fds.pop_back();
    if (back_fd != fd && back_fd >= 0 && back_fd < MAX_FDS && m_conn_idx[back_fd])
        m_conn_idx[back_fd]->active_idx = idx;

    // The same swap-remove, at the same index, in the table this runtime's
    // sibling shards read.  Here rather than rebuilt from m_active_fds on a
    // timer, because `active_idx` IS the index into both and doing the same
    // operation to both is what keeps them aligned — a second structure
    // rebuilt from the first is how the two come to disagree, and a
    // disagreement here is a script sending to a connection that closed.
    //
    // A no-op for every unsharded runtime: the table is not mapped.
    shard_clients_table().swap_remove(idx);
}

inline void server_instance::submit_conn_read(server_connection* conn)
{
    // Bundle first, plain multishot behind it.  A refused bundle is not an
    // error -- the group's cursor may have tripped -- and the plain arm serves
    // the same bytes one buffer per completion.  Both are consumed through
    // for_each_cqe_buf, which cannot tell them apart.
    bool queued = false;
    if (conn->direct_fd)
    {
        if (m_recv_bundle)
            queued = m_loop->submit_recv_multishot_bundle_fixed_file(conn->fixed_idx, BUF_GROUP_ID, &conn->read_req);
        if (!queued && m_recv_multishot)
            queued = m_loop->submit_recv_multishot_fixed_file(conn->fixed_idx, BUF_GROUP_ID, &conn->read_req);
        else if (!queued && m_use_provided_bufs)
            queued = m_loop->submit_read_provided_fixed_file(conn->fixed_idx, BUF_GROUP_ID, &conn->read_req);
        else if (!queued)
            queued = m_loop->submit_read_fixed_file(conn->fixed_idx, conn->read_buf, server_connection::READ_BUF_SIZE, &conn->read_req);
    }
    else
    {
        if (m_recv_bundle)
            queued = m_loop->submit_recv_multishot_bundle(conn->fd, BUF_GROUP_ID, &conn->read_req);
        if (!queued && m_recv_multishot)
            queued = m_loop->submit_recv_multishot(conn->fd, BUF_GROUP_ID, &conn->read_req);
        else if (!queued && m_use_provided_bufs)
            queued = m_loop->submit_read_provided(conn->fd, BUF_GROUP_ID, &conn->read_req);
        else if (!queued)
            queued = m_loop->submit_read(conn->fd, conn->read_buf, server_connection::READ_BUF_SIZE, &conn->read_req);
    }

    // The flag goes up only once the read is actually queued.  Setting it first
    // and submitting into a full ring left the connection believing a read was
    // in flight when nothing was: no completion would ever arrive and it hung
    // until the runtime stopped.
    if (SOCKETLEY_UNLIKELY(!queued))
    {
        conn->read_pending = false;
        conn->closing = true;
        return;
    }
    conn->read_pending = true;
}

inline void server_instance::release_fixed_slot(server_connection* conn)
{
    // m_ring_loop, not m_loop: a retired connection can become releasable while
    // the runtime is stopped, and its slot has to go back all the same.
    if (conn->direct_fd && conn->fixed_idx >= 0 && m_ring_loop)
    {
        m_ring_loop->free_fixed_file_slot(static_cast<uint32_t>(conn->fixed_idx));
        conn->fixed_idx = -1;
        conn->direct_fd = false;
    }
}

void server_instance::handle_accept(struct io_uring_cqe* cqe)
{
    int client_fd = cqe->res;

    // A listener that was shut down completes its accepts with one of these, and
    // a stop does exactly that.  Such a completion can arrive after the start()
    // that followed, and resubmitting on the strength of it would arm a second
    // accept chain on the listener that start() created.
    if (SOCKETLEY_UNLIKELY(client_fd == -ECANCELED || client_fd == -EBADF
                           || client_fd == -EINVAL || client_fd == -ENOTSOCK))
        return;

    if (SOCKETLEY_LIKELY(client_fd >= 0))
    {
        // Reject fds beyond our O(1) lookup table — they'd become zombie connections
        if (SOCKETLEY_UNLIKELY(client_fd >= MAX_FDS))
        {
            close_tracked(client_fd);
            goto resubmit_accept;
        }

        // Max connections check
        if (SOCKETLEY_UNLIKELY(m_max_conns_cached > 0 && m_clients.size() >= m_max_conns_cached))
        {
            close_tracked(client_fd);
            goto resubmit_accept;
        }

        int opt = 1;
        setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

        // Larger socket receive buffer reduces kernel-to-user copies
        // Larger socket receive buffer reduces kernel-to-user copies
        int rcvbuf = 131072;  // 128KB
        setsockopt(client_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

        auto conn = pool_acquire(client_fd);
        conn->partial.reserve(8192);
        conn->read_req = { this, conn->read_buf, client_fd, server_connection::READ_BUF_SIZE,
                           op_read, conn->generation };
        conn->write_req = { this, nullptr, client_fd, 0, op_write, conn->generation };

        // Register fd in fixed file table for fget/fput-free I/O
        int slot = m_loop->alloc_fixed_file_slot();
        if (slot >= 0)
        {
            if (m_loop->update_registered_file(static_cast<uint32_t>(slot), client_fd))
            {
                conn->fixed_idx = slot;
                conn->direct_fd = true;
            }
            else
            {
                // The slot is already marked used in the bitmap.  If it cannot be
                // pointed at this fd it has to go back immediately: the connection
                // never learns its number, so no close path can ever release it.
                m_loop->free_fixed_file_slot(static_cast<uint32_t>(slot));
            }
        }

        auto* ptr = conn.get();
        m_clients[client_fd] = std::move(conn);
        m_conn_idx[client_fd] = ptr;
        ptr->active_idx = static_cast<uint32_t>(m_active_fds.size());
        m_active_fds.push_back(client_fd);

        // And into the shared table, at the same position.  The ref is minted
        // above in pool_acquire(), so it exists by now and is this connection's
        // name for its whole life.
        shard_clients_table().push(conn_ref{owner_key(), ptr->ref_serial});

        // A TLS listener gives every accepted socket a session before anybody
        // else touches the connection, and in particular before on_auth and
        // on_connect below: whatever those queue is plaintext that must go out
        // through the record layer, and a message queued on a connection that
        // did not know it was encrypted would be written in the clear.
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
                shutdown(client_fd, SHUT_RDWR);
                ptr->closing = true;
                close_conn(ptr, false);
                goto resubmit_accept;
            }
            ptr->tls_state = tls_conn_handshake;
        }

        auto now_tp = std::chrono::steady_clock::now();

        if (m_idle_timeout_cached > 0)
            ptr->last_activity = now_tp;

        m_stat_total_connections.fetch_add(1, std::memory_order_relaxed);
        auto current_size = static_cast<uint32_t>(m_clients.size());
        if (current_size > m_stat_peak_connections)
            m_stat_peak_connections = current_size;

        // Initialize rate limiting
        if (m_rate_limit_cached > 0)
        {
            ptr->rl_max = m_rate_limit_cached;
            ptr->rl_tokens = m_rate_limit_cached;
            ptr->rl_last = now_tp;
        }

        // Check per-IP auth failure rate.
        //
        // The term is the failure table itself, not a configuration value.  It
        // used to be `!m_master_pw.empty()`, and --master-pw is documented on
        // its own man-page entry as one of two ways to authenticate a master:
        // "Alternatively, use the on_master_auth(client_id, password) Lua
        // callback", which "if defined, overrides --master-pw".  A server that
        // takes the documented alternative has an empty m_master_pw, so this
        // block never ran on it — and the per-connection MAX_AUTH_FAILURES cap
        // is no answer, because it is per connection: an attacker gets five
        // guesses, hangs up, reconnects and gets five more, for ever.  The
        // lockout an operator can see working with --master-pw was silently
        // absent in the one configuration where the password is not a constant
        // in the state file.
        //
        // m_auth_ip_failures is written by the failure path for its own reasons
        // (mode_master's deny branch records every rejected attempt, whichever
        // authenticator rejected it) and nothing in the configuration can switch
        // that off.  Asking it directly is also cheaper than what stood here: an
        // empty table means no getpeername syscall per accept at all, where
        // before every accepted connection on a --master-pw server paid for one.
        //
        // Use getpeername() instead of m_accept_addr because multishot accept
        // passes nullptr for addr — m_accept_addr is never populated per-connection.
        if (SOCKETLEY_UNLIKELY(!m_auth_ip_failures.empty()))
        {
            struct sockaddr_in peer{};
            socklen_t peer_len = sizeof(peer);
            uint32_t ip = 0;
            if (getpeername(client_fd, reinterpret_cast<struct sockaddr*>(&peer), &peer_len) == 0)
                ip = peer.sin_addr.s_addr;
            auto it = m_auth_ip_failures.find(ip);
            if (it != m_auth_ip_failures.end())
            {
                auto elapsed = std::chrono::steady_clock::now() - it->second.last_failure;
                if (elapsed > std::chrono::seconds(60))
                {
                    m_auth_ip_failures.erase(it);
                }
                else if (it->second.failures >= 10)
                {
                    // No on_disconnect: this client never got an on_connect.
                    shutdown(client_fd, SHUT_RDWR);
                    ptr->closing = true;
                    close_conn(ptr, false);
                    goto resubmit_accept;
                }
            }
        }

        // on_auth fires before on_connect; a rejected client never triggers on_connect
        if (SOCKETLEY_UNLIKELY(!invoke_on_auth(client_fd)))
        {
            // A Lua on_auth that answers before rejecting leaves a write in the
            // ring, reading out of this connection's batch.  close_conn hands
            // the struct on through release_conn, which keeps it out of the pool
            // until that write completes — it used to go straight back and be
            // handed to the next client with the kernel still reading it.
            shutdown(client_fd, SHUT_RDWR);
            ptr->closing = true;
            close_conn(ptr, false);
            goto resubmit_accept;
        }

        invoke_on_connect(client_fd);

        submit_conn_read(ptr);
    }

    // EMFILE/ENFILE: backoff 100ms to avoid CPU spin when fd limit is hit
    if (SOCKETLEY_UNLIKELY(client_fd == -EMFILE || client_fd == -ENFILE))
    {
        // The chain ended with this completion unless the kernel kept it armed.
        m_accept_armed = m_multishot_active && (cqe->flags & IORING_CQE_F_MORE) != 0;
        if (!m_accept_backoff_armed)
        {
            m_accept_backoff_ts.tv_sec = 0;
            m_accept_backoff_ts.tv_nsec = 100000000LL;
            m_accept_backoff_req = { this, nullptr, -1, 0, op_timeout };
            m_accept_backoff_armed = m_loop->submit_timeout(&m_accept_backoff_ts, &m_accept_backoff_req);
        }
        return;
    }

resubmit_accept:
    // Resubmit accept if needed
    if (m_multishot_active)
    {
        // Multishot: only resubmit if IORING_CQE_F_MORE is NOT set
        if (!(cqe->flags & IORING_CQE_F_MORE))
        {
            m_accept_armed = false;
            if (m_listen_fd >= 0)
                m_accept_armed = m_loop->submit_multishot_accept(m_listen_fd, m_accept_req.get());
        }
    }
    else
    {
        // Regular accept: always resubmit
        m_accept_armed = false;
        if (m_listen_fd >= 0)
        {
            m_accept_addrlen = sizeof(m_accept_addr);
            m_accept_armed = m_loop->submit_accept(m_listen_fd, &m_accept_addr,
                                                   &m_accept_addrlen, m_accept_req.get());
        }
    }
}

// Ciphertext in, plaintext into conn->partial.  One call per read completion,
// which is what makes the handshake asynchronous: OpenSSL is handed the bytes
// that have arrived and asked what it makes of them, and whatever it wants to
// say back is drained by tls_flush at the end of handle_read.  Several rounds
// of that is a handshake; there is no loop here waiting for one.
void server_instance::tls_feed(server_connection* conn, const char* data, size_t len)
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
            // diagnosis the other end will ever get.  tls_flush at the end of
            // handle_read puts it on the wire, and the connection is torn down
            // when that write completes.
            conn->closing = true;
            return;
        }
        if (r == 0)
            return;   // another round; its records go out at the end of the read

        conn->tls_state = tls_conn_ready;
        // Deliberately falling through rather than returning: the same read can
        // already carry application data behind the handshake's last flight —
        // under TLS 1.3 a client's Finished and its first request routinely
        // arrive in one packet, and returning here would leave that request
        // sitting in the BIO until the client sent something else.
    }

    // Plaintext into partial, where every protocol above reads it from.
    char plain[16384];
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
            if (SOCKETLEY_UNLIKELY(conn->partial.size() > server_connection::MAX_PARTIAL_SIZE))
            {
                conn->closing = true;
                break;
            }
            continue;
        }
        if (n < 0)
        {
            // Either the peer's close_notify or a record we cannot use.  Both
            // end the connection, and neither ends it here: the bytes decrypted
            // above may be a request that deserves an answer, so this is
            // recorded and applied once handle_read has parsed them.
            conn->tls_peer_closed = true;
        }
        break;
    }
}

// ─── THE PARSE, MADE RE-DRIVABLE ────────────────────────────────────────────
//
// Lifted out of handle_read() unchanged except for the loop at the end of the
// HTTP arm, because a read completion is not the only moment at which
// `conn->partial` can hold a request nobody has answered.
//
// The guard in the HTTP arm below declines to parse while this connection is
// still finishing its last response, and said "the bytes stay in partial and
// are parsed when the next read completes".  Nothing re-parsed them.  A
// multishot recv is already armed, so it has ALREADY moved the next request out
// of the socket and into `partial`; the response completion then armed a read
// and waited for bytes the client had sent long before, while the client waited
// for a response that was never going to be produced.  Both sides waited.
//
// Counted before choosing where to put the rule: `partial` is parsed for HTTP
// in 1 place, and 15 places set conn->proto = proto_unknown to mean "this
// connection has finished its response and may have another".  None of the 15
// can resume a parse, and a rule that fifteen call sites have to remember is
// one that the sixteenth will not.  So it goes in the loop and in the three
// completion arms that own an async response -- handle_splice_out()'s
// keep-alive arm and handle_file_read()'s two -- rather than at the fifteen.
void server_instance::parse_partial(server_connection* conn)
{
reparse:
    // Multi-protocol auto-detection
    if (conn->proto == proto_unknown)
    {
        // Four bytes is what the tests below need: every HTTP method here is
        // matched on four characters, and the RESP markers on two.
        //
        // Waiting for a fourth byte is right while the client is still mid-line
        // and wrong the moment a whole line has arrived.  A line-protocol client
        // writes "hi\n" and then waits to be answered, so the bytes that would
        // end this wait are the ones it will not send until the wait ends.  That
        // is a deadlock, and it was a silent one: three bytes sat in `partial`,
        // no callback ran, nothing was logged, and the connection was
        // indistinguishable from a client that had sent nothing at all.  It has
        // been here since the first implementation — see the test.
        //
        // A completed short line is not ambiguous, so this decides rather than
        // guesses or refuses.  Every HTTP method prefix above is four characters
        // and none contains a newline, so a line that ended inside four bytes
        // cannot be one; the RESP markers are read out of the first two bytes
        // and are still applied when they are there.  What remains is TCP, which
        // is what such a line was always eventually classified as once some
        // later byte happened to unblock it.
        if (conn->partial.size() < 4)
        {
            if (conn->partial.find('\n') == std::string::npos)
                return;   // still mid-line: more may yet come

            const char s0 = conn->partial[0];
            const char s1 = conn->partial.size() > 1 ? conn->partial[1] : '\0';
            const bool resp =
                (s0 == '*' && s1 >= '0' && s1 <= '9') ||
                (s0 == '$' && s1 >= '0' && s1 <= '9') ||
                (s0 == '+' && ((s1 >= 'A' && s1 <= 'Z') || (s1 >= 'a' && s1 <= 'z')));
            conn->proto = resp ? proto_resp : proto_tcp;
        }
        else
        {
        char c0 = conn->partial[0], c1 = conn->partial[1];
        char c2 = conn->partial[2], c3 = conn->partial[3];

        // RESP2 wire protocol: starts with '*N', '$N', or '+A-Za-z'
        if ((c0 == '*' && c1 >= '0' && c1 <= '9') ||
            (c0 == '$' && c1 >= '0' && c1 <= '9') ||
            (c0 == '+' && ((c1 >= 'A' && c1 <= 'Z') || (c1 >= 'a' && c1 <= 'z'))))
        {
            conn->proto = proto_resp;
        }
        // HTTP methods → either WS upgrade or plain HTTP
        else if ((c0 == 'G' && c1 == 'E' && c2 == 'T' && c3 == ' ') ||
                 (c0 == 'P' && c1 == 'O' && c2 == 'S' && c3 == 'T') ||
                 (c0 == 'P' && c1 == 'U' && c2 == 'T' && c3 == ' ') ||
                 (c0 == 'H' && c1 == 'E' && c2 == 'A' && c3 == 'D') ||
                 (c0 == 'D' && c1 == 'E' && c2 == 'L' && c3 == 'E') ||
                 (c0 == 'P' && c1 == 'A' && c2 == 'T' && c3 == 'C') ||
                 (c0 == 'O' && c1 == 'P' && c2 == 'T' && c3 == 'I'))
        {
            // GET might be WS upgrade — defer to header parse
            if (c0 == 'G')
                conn->proto = proto_ws_upgrading;
            else
            {
                conn->proto = proto_http;
                // Out of the relay set from here on, and stickily: see
                // relay_targetable().  Set at the same statement that decides
                // the protocol so the two cannot drift apart.
                conn->http_seen = true;
            }
        }
        else
        {
            conn->proto = proto_tcp;
        }
        }
    }

    if (conn->proto == proto_ws_upgrading)
    {
        auto hdr_end = conn->partial.find("\r\n\r\n");
        if (hdr_end == std::string::npos)
        {
            // Reject oversized upgrade requests (belt-and-suspenders for F1 partial limit)
            if (conn->partial.size() > 16384)
            {
                conn->closing = true;
                return;
            }
            return; // Incomplete headers
        }

        // Single-pass header scan: find Upgrade + Sec-WebSocket-Key without allocation
        {
            std::string_view hdrs(conn->partial.data(), hdr_end + 4);
            bool has_upgrade = false;
            size_t ws_key_pos = std::string_view::npos;
            size_t ws_key_end = std::string_view::npos;

            // Walk headers line by line
            size_t line_start = hdrs.find("\r\n"); // skip request line
            if (line_start != std::string_view::npos)
                line_start += 2;

            while (line_start < hdr_end)
            {
                size_t line_end = hdrs.find("\r\n", line_start);
                if (line_end == std::string_view::npos || line_end > hdr_end)
                    break;

                std::string_view line = hdrs.substr(line_start, line_end - line_start);
                auto colon = line.find(':');
                if (colon != std::string_view::npos)
                {
                    std::string_view hdr_name = line.substr(0, colon);
                    uint32_t h = fnv1a_lower(hdr_name);

                    switch (h)
                    {
                        case fnv1a("upgrade"):
                        {
                            // Value after ": "
                            size_t val_start = colon + 1;
                            while (val_start < line.size() && line[val_start] == ' ')
                                ++val_start;
                            std::string_view val = line.substr(val_start);
                            if (fnv1a_lower(val) == fnv1a("websocket"))
                                has_upgrade = true;
                            break;
                        }
                        case fnv1a("sec-websocket-key"):
                        {
                            size_t val_start = colon + 1;
                            while (val_start < line.size() && line[val_start] == ' ')
                                ++val_start;
                            ws_key_pos = line_start + val_start;
                            ws_key_end = line_end;
                            break;
                        }
                        case fnv1a("cookie"):
                        case fnv1a("origin"):
                        case fnv1a("sec-websocket-protocol"):
                        case fnv1a("authorization"):
                        {
                            size_t vs = colon + 1;
                            while (vs < line.size() && line[vs] == ' ') ++vs;
                            std::string val(line.substr(vs));
                            switch (h) {
                                case fnv1a("cookie"):                 conn->ws_cookie   = std::move(val); break;
                                case fnv1a("origin"):                 conn->ws_origin   = std::move(val); break;
                                case fnv1a("sec-websocket-protocol"): conn->ws_protocol = std::move(val); break;
                                case fnv1a("authorization"):          conn->ws_auth     = std::move(val); break;
                            }
                            break;
                        }
                    }
                }

                line_start = line_end + 2;
            }

            if (!has_upgrade || ws_key_pos == std::string_view::npos)
            {
                // Not a WebSocket upgrade — treat as HTTP request
                conn->proto = proto_http;
                conn->http_seen = true;   // see relay_targetable()
                // Fall through to proto_http handler below
            }
            else
            {
                // ─── THE THIRD REQUEST-PARSE REGION, AND THE SAME GATE ──────
                //
                // A GET that turns out NOT to be an upgrade falls through to
                // proto_http above and is judged there.  One that IS an upgrade
                // used to be answered 101 without its header block having been
                // framed by anybody, so the same obs-fold and bare-LF blocks the
                // proxy refuses outright would have opened a WebSocket here.
                //
                // It is a weaker case than the pipelined one and worth saying
                // why: an upgrade consumes exactly hdr_end + 4 and then reads
                // frames, so a malformed block cannot produce a second answer —
                // no smuggle.  What it can do is let this end and a proxy in
                // front read the handshake's own fields differently, which is
                // the disagreement the rest of this change exists to remove.
                // The scan is not run on the fall-through path, so a plain GET
                // pays nothing for it.
                if (SOCKETLEY_UNLIKELY(
                        !http_eol_framing_ok(std::string_view(conn->partial.data(), hdr_end), true)))
                {
                    refuse_http_request(conn, http_400_response());
                    return;
                }
                {
                    // Same underflow guard as the proto_http arm below: an
                    // upgrade always carries fields in practice, but "in
                    // practice" is not what the subtraction is bounded by.
                    const size_t rl_end = hdrs.find("\r\n");
                    const size_t up_len =
                        (hdr_end > rl_end + 2) ? (hdr_end - rl_end - 2) : 0;
                    const http_request_framing_scan up =
                        http_scan_request_headers(hdrs.substr(rl_end + 2, up_len));
                    if (SOCKETLEY_UNLIKELY(!up.ok))
                    {
                        refuse_http_request(conn, http_400_response());
                        return;
                    }
                }

                std::string_view ws_key = hdrs.substr(ws_key_pos, ws_key_end - ws_key_pos);

                // Send 101 response
                auto resp_msg = std::make_shared<std::string>();
                resp_msg->reserve(160);
                ws_handshake_response_into(*resp_msg, ws_key);
                conn->write_queue.push(std::move(resp_msg));
                if (!conn->write_pending)
                    flush_write_queue(conn);

                conn->proto = proto_ws;
                invoke_on_websocket(conn->fd);
                conn->partial.erase(0, hdr_end + 4);
            }
        }
    }

    if (conn->proto == proto_ws)
    {
        // Parse WebSocket frames with fragment reassembly (RFC 6455 §5.4)
        // Fragments are compacted in-place at partial[0..ws_frag_len) — zero heap allocs.
        ws_frame_view frame;
        size_t offset = conn->ws_frag_len; // skip accumulated fragment payloads
        while (ws_parse_frame_inplace(conn->partial.data() + offset,
                                       conn->partial.size() - offset, frame))
        {
            offset += frame.consumed;

            // Control frames (opcode >= 0x8): process immediately, even mid-fragment
            if (frame.opcode >= 0x8)
            {
                std::string_view payload(frame.payload_ptr, frame.payload_len);
                if (frame.opcode == WS_OP_PING)
                {
                    conn->write_queue.push(ws_frame_pong_shared(payload));
                    if (!conn->write_pending)
                        flush_write_queue(conn);
                }
                else if (frame.opcode == WS_OP_CLOSE)
                {
                    conn->write_queue.push(ws_frame_close_shared());
                    if (!conn->write_pending)
                        flush_write_queue(conn);
                    conn->closing = true;
                }
                if (conn->closing)
                    break;
                continue;
            }

            // Data frame: compact payload into partial[ws_frag_len..], but only
            // when this frame is actually part of a reassembly.
            //
            // The unfragmented fast path below reads straight from
            // frame.payload_ptr, which points into partial past this frame's
            // header and mask.  Compacting first moves the payload down over
            // that very region, so the fast path then read the payload shifted
            // by header+mask — corrupting every message longer than those 6
            // bytes while leaving shorter ones intact.
            const bool needs_compaction = !frame.fin || conn->ws_frag_len > 0;
            if (frame.payload_len > 0 && needs_compaction)
            {
                std::memmove(conn->partial.data() + conn->ws_frag_len,
                             frame.payload_ptr, frame.payload_len);
            }

            if (!frame.fin)
            {
                // Non-final fragment: record opcode from first fragment, accumulate
                if (conn->ws_frag_len == 0)
                    conn->ws_frag_opcode = frame.opcode;
                conn->ws_frag_len += frame.payload_len;
            }
            else if (conn->ws_frag_len > 0)
            {
                // Final fragment of a fragmented message — deliver complete reassembled payload
                conn->ws_frag_len += frame.payload_len;
                std::string_view msg(conn->partial.data(), conn->ws_frag_len);
                if (!msg.empty())
                    process_message(conn, msg);
                conn->ws_frag_len = 0;
                conn->ws_frag_opcode = 0;
            }
            else
            {
                // Unfragmented frame (FIN=1, no prior fragments) — fast path
                std::string_view payload(frame.payload_ptr, frame.payload_len);
                if (!payload.empty())
                    process_message(conn, payload);
            }

            // Once the connection is marked closing, everything still
            // buffered belongs to a conversation that is over.  Parsing it
            // produces responses the teardown below discards, so the peer
            // waits for answers that were computed and thrown away.
            if (conn->closing)
                break;
        }
        // Batch erase consumed data
        if (conn->ws_frag_len > 0)
        {
            // Mid-fragment across reads: keep accumulated payloads at [0..ws_frag_len),
            // erase only the consumed headers between ws_frag_len and offset
            if (offset > conn->ws_frag_len)
                conn->partial.erase(conn->ws_frag_len, offset - conn->ws_frag_len);
        }
        else if (offset > 0)
        {
            if (offset >= conn->partial.size())
                conn->partial.clear();
            else
                conn->partial.erase(0, offset);
        }
        return;
    }

    // proto_http: full HTTP request handling
    if (conn->proto == proto_http)
    {
        // Not while this connection is still serving the last request.
        //
        // A static response lives in state this connection has exactly one of:
        // one file_buf, one file_read_req, one splice pair, one shared pipe.
        // Starting a second while the first is in flight overwrites all of it.
        // serve_http() mallocs a new file_buf over the one the kernel is
        // writing into — the old block is leaked and the buffer the kernel
        // holds is no longer the one anybody will read — and it re-arms
        // conn->file_read_req while a completion is still owed on it, which
        // gives one request two live submissions and puts the loop's accounting
        // out by one in each direction.  Then the first completion to land frees
        // file_buf and nulls it, and the second builds a string_view over a null
        // pointer: std::string throws logic_error out of a completion handler
        // and the daemon terminates.  A client that pipelines two requests for a
        // static file is all that takes.
        //
        // The guard has to be here and not at submit_next_read.  That one
        // declines to arm a *one-shot* read while a file read is pending, which
        // is enough for a one-shot read and nothing at all for a multishot recv:
        // that is already armed and goes on delivering whatever the client sends
        // for as long as the kernel keeps it alive.
        //
        // The bytes stay in partial and are parsed when the next read completes.
        if (SOCKETLEY_UNLIKELY(conn->file_read_pending || conn->splice_pending ||
                               conn->splice_in_pending || conn->splice_out_pending))
            return;

        // Wait for complete headers
        auto hdr_end = conn->partial.find("\r\n\r\n");
        if (hdr_end == std::string::npos)
        {
            if (conn->partial.size() > 16384)
            {
                conn->closing = true;
                return;
            }
            return;
        }

        // ─── THE BLOCK IS JUDGED BEFORE ANYTHING IS PARSED OUT OF IT ─────
        //
        // A bare LF in the header block is a line ending only one of the two
        // ends of a keep-alive conversation may honour, and the loop at the
        // bottom of this arm makes that a live boundary rather than a cosmetic
        // one: "Host: x\nContent-Length: 38\r\n" splits on CRLF into ONE line
        // whose name is Host, so the Content-Length is never seen, the body is
        // taken as empty, and the 38 bytes behind it are read as the NEXT
        // request.  Measured on c218738: two answers to one message, the second
        // one the client's to choose.  The proxy has refused this since it
        // learned to; the server did not, and the two sit in the same pipeline.
        //
        // `complete` is true: this runs only once "\r\n\r\n" has been found, so
        // a trailing CR is a real bare CR and not a CRLF split across reads.
        if (SOCKETLEY_UNLIKELY(!http_eol_framing_ok(
                std::string_view(conn->partial.data(), hdr_end), true)))
        {
            refuse_http_request(conn, http_400_response());
            return;
        }

        // Extract request line
        std::string_view full(conn->partial.data(), conn->partial.size());
        auto first_crlf = full.find("\r\n");
        std::string_view req_line = full.substr(0, first_crlf);
        auto sp1 = req_line.find(' ');
        auto sp2 = (sp1 != std::string_view::npos)
                    ? req_line.find(' ', sp1 + 1) : std::string_view::npos;

        if (sp1 == std::string_view::npos || sp2 == std::string_view::npos)
        {
            conn->closing = true;
            return;
        }

        http_request hreq;
        hreq.method = req_line.substr(0, sp1);
        std::string_view raw_path = req_line.substr(sp1 + 1, sp2 - sp1 - 1);
        hreq.version = req_line.substr(sp2 + 1);
        hreq.client_id = conn->fd;

        // Split path and query string
        auto qpos = raw_path.find('?');
        if (qpos != std::string_view::npos)
        {
            hreq.path = raw_path.substr(0, qpos);
            hreq.query = raw_path.substr(qpos + 1);
        }
        else
        {
            hreq.path = raw_path;
        }

        // ─── WHERE THIS MESSAGE ENDS: ONE DECISION, SHARED WITH THE PROXY ───
        //
        // This used to be a Content-Length lookup and nothing else, and every
        // shape it did not know about resolved the same way — length zero, body
        // empty, and whatever followed read as the next request on the
        // connection.  Four of those shapes were measured against this server
        // and the proxy side by side on one binary (c218738), one write each,
        // with a distinct file behind the smuggled request:
        //
        //     Content-Length : 38          proxy 400   server 2 answers, leaked
        //     Content-Length twice         proxy 400   server 2 answers, leaked
        //     obs-fold hiding the length   proxy 400   server 2 answers, leaked
        //     bare LF in the block         proxy 400   server 2 answers, leaked
        //
        // The comment that used to stand a few lines below said there was "no
        // second framing party here the way there is in the proxy".  There is:
        // ours, one hop in front, and it is the pipeline the proxy tests build.
        // So the rules moved to shared/http_framing.h and both runtimes ask the
        // same function.  What differs is the answer given back — the proxy
        // drops the connection with a 400, this server answers first — and that
        // difference is the runtime's own business, which is why only the
        // decision is shared.
        // first_crlf is the first "\r\n" and hdr_end the first "\r\n\r\n", and the
        // latter BEGINS with the former — so the two are equal for a request
        // that carries no header fields at all.  "GET / HTTP/1.0\r\n\r\n" is
        // eighteen legal bytes, and the subtraction then wraps to SIZE_MAX-1,
        // string_view::substr clamps it to the terminator itself, and the scan
        // sees an empty line and refuses a request nothing is wrong with.  The
        // proxy has carried this guard since a fuzzer walked the same
        // subtraction off the end of the address space; this call site is new
        // and needed it too.  Nothing in test/integration sends a header-less
        // request, so the suite did not catch it — test_http_request_framing.sh
        // now does.
        const size_t hdr_len =
            (hdr_end > first_crlf + 2) ? (hdr_end - first_crlf - 2) : 0;
        const http_request_framing_scan framing =
            http_scan_request_headers(full.substr(first_crlf + 2, hdr_len));

        if (SOCKETLEY_UNLIKELY(!framing.ok))
        {
            refuse_http_request(conn, http_400_response());
            return;
        }

        // A transfer coding this server does not implement — grep this file for
        // "transfer-encoding" before this change and the count was zero, so a
        // chunked request was framed by a Content-Length that was not there.
        // Refusing is not the only defensible answer; treating the chunk data
        // as the next request is the one that is not.
        if (SOCKETLEY_UNLIKELY(framing.transfer_encoding))
        {
            refuse_http_request(conn, http_501_response());
            return;
        }

        const size_t content_length = framing.content_length;

        // The header pairs, for the Lua API and for handle_http_request.  This
        // loop deliberately decides nothing: the block above has already ruled
        // on the framing, and a second walk that came to its own conclusions
        // about Content-Length is exactly the arrangement that produced the
        // table above.  It reads names and values and stops there.
        {
            size_t line_start = first_crlf + 2;
            while (line_start < hdr_end)
            {
                size_t line_end = full.find("\r\n", line_start);
                if (line_end == std::string_view::npos || line_end > hdr_end) break;
                std::string_view line = full.substr(line_start, line_end - line_start);
                auto colon = line.find(':');
                if (colon != std::string_view::npos)
                {
                    // OWS is SP or HTAB (RFC 9110 Section 5.6.3).  Skipping only
                    // spaces left the tab on the front of the value, and every
                    // consumer downstream then compared against a value that
                    // began with one — which is how "Content-Length:\t4", an
                    // ordinary legal request the proxy accepts, got this server
                    // to hang up without answering at all.
                    hreq.headers.emplace_back(line.substr(0, colon),
                                              http_trim_ows(line.substr(colon + 1)));
                }
                line_start = line_end + 2;
            }
        }

        size_t total_expected = hdr_end + 4 + content_length;
        if (conn->partial.size() < total_expected)
            return;  // Need more body data

        hreq.body = full.substr(hdr_end + 4, content_length);

        handle_http_request(conn, hreq, total_expected);

        // ─── ROUND AGAIN, RATHER THAN WAITING FOR A READ THAT IS NOT COMING ──
        //
        // This is the whole fix.  Every other arm in this function already
        // consumes everything it can -- proto_tcp loops on '\n', proto_resp
        // loops on a frame -- and HTTP took exactly one request per read
        // completion and left the rest of `partial` for "the next read", which
        // for a multishot recv is a read that only arrives if the client sends
        // MORE bytes.  It has none to send: it is waiting for the answer to the
        // request already sitting here.
        //
        // Deliberately a jump back to the protocol detection above and not a
        // second parse in place.  A pipelined GET may be a WebSocket upgrade,
        // and deciding that here would duplicate the sniff -- and duplicating
        // it is how the two copies come to disagree.  Detection is idempotent
        // on a fresh `partial`, so this is exactly what the next read
        // completion would have done, minus the wait.
        //
        // It terminates: handle_http_request() erases at least the four bytes
        // of one header terminator before returning, so every trip round is
        // strictly shorter, and the three exits above -- busy, need-more,
        // closing -- are unchanged.
        if (!conn->closing && !conn->partial.empty())
            goto reparse;
        return;
    }

    // proto_resp: RESP2 wire protocol (reuses resp_parser from cache)
    if (conn->proto == proto_resp)
    {
        static constexpr int MAX_RESP_ARGS = 64;
        std::string_view args[MAX_RESP_ARGS];
        int argc = 0;
        size_t consumed = 0;
        size_t offset = 0;

        while (offset < conn->partial.size())
        {
            std::string_view buf(conn->partial.data() + offset, conn->partial.size() - offset);
            auto result = resp::parse_message_views(buf, args, MAX_RESP_ARGS, argc, consumed);

            if (result == resp::parse_result::incomplete) break;
            if (result == resp::parse_result::error)
            {
                conn->closing = true;
                break;
            }

            offset += consumed;
            if (argc > 0)
            {
                // Build a single-line representation for process_message
                std::string cmd;
                cmd.reserve(consumed);
                for (int i = 0; i < argc; i++)
                {
                    if (i > 0) cmd += ' ';
                    cmd.append(args[i]);
                }
                process_message(conn, cmd);
            }

            // Once the connection is marked closing, everything still
            // buffered belongs to a conversation that is over.  Parsing it
            // produces responses the teardown below discards, so the peer
            // waits for answers that were computed and thrown away.
            if (conn->closing)
                break;
        }

        if (offset > 0)
        {
            if (offset >= conn->partial.size())
                conn->partial.clear();
            else
                conn->partial.erase(0, offset);
        }
        return;
    }

    // proto_tcp: existing newline-delimited parsing
    {
        size_t scan_from = 0;
        size_t pos;
        while ((pos = conn->partial.find('\n', scan_from)) != std::string::npos)
        {
            std::string_view line(conn->partial.data() + scan_from, pos - scan_from);

            if (!line.empty() && line.back() == '\r')
                line.remove_suffix(1);

            if (!line.empty())
                process_message(conn, line);

            scan_from = pos + 1;

            // Once the connection is marked closing, everything still
            // buffered belongs to a conversation that is over.  Parsing it
            // produces responses the teardown below discards, so the peer
            // waits for answers that were computed and thrown away.
            if (conn->closing)
                break;
        }

        if (scan_from > 0)
        {
            if (scan_from >= conn->partial.size())
                conn->partial.clear();
            else
                conn->partial.erase(0, scan_from);
        }
    }

}

void server_instance::handle_read(struct io_uring_cqe* cqe, io_request* req)
{
    int fd = req->fd;
    auto* conn = m_conn_idx[fd];
    if (SOCKETLEY_UNLIKELY(!conn))
        return;

    bool is_multishot_recv = is_multishot_recv_op(req->type);
    bool multishot_more = is_multishot_recv && (cqe->flags & IORING_CQE_F_MORE);

    // For multishot recv, the read remains pending as long as MORE flag is set
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
            // Reset the request type: the fallback is a plain read into the
            // connection's own buffer, not a provided-buffer one.  Leaving it
            // as a recv/provided type makes the completion handler treat the
            // result as a buffer-ring delivery — it then appends whatever sits
            // in ring buffer 0 instead of the bytes just read, discards those
            // bytes, and returns a buffer it never took, corrupting the ring's
            // free list.
            conn->read_req.type = op_read;
            bool queued;
            if (conn->direct_fd)
                queued = m_loop->submit_read_fixed_file(conn->fixed_idx, conn->read_buf, server_connection::READ_BUF_SIZE, &conn->read_req);
            else
                queued = m_loop->submit_read(fd, conn->read_buf, server_connection::READ_BUF_SIZE, &conn->read_req);
            if (SOCKETLEY_UNLIKELY(!queued))
            {
                conn->read_pending = false;
                conn->closing = true;
            }
            return;
        }

        // Connection closed or error.  A zero-copy send clears write_pending on
        // its first completion and keeps DMA-ing out of write_batch[0] until the
        // notification arrives, so the old guard here — which did not look at
        // zc_notif_pending — released the struct while the kernel was still
        // reading the pages, and another connection's bytes went out on the
        // wire.  Splices were not tracked at all.  conn_ops_pending() is now the
        // one answer to that question.
        conn->closing = true;
        if (!conn_ops_pending(conn))
            close_conn(conn);
        return;
    }

    if (SOCKETLEY_UNLIKELY(m_idle_timeout_cached > 0))
        conn->last_activity = std::chrono::steady_clock::now();
    m_stat_bytes_in.fetch_add(static_cast<uint64_t>(cqe->res), std::memory_order_relaxed);

    // On a TLS connection these bytes are ciphertext and tls_feed is what puts
    // plaintext into partial; everything below this point reads exactly the
    // same buffer it always did and knows nothing about TLS.
    if (is_provided)
    {
        // Reading the buffer id straight out of the CQE flags was correct only
        // while every completion carried exactly one buffer.  A bundle names
        // only its FIRST, so that form silently dropped every buffer after it
        // -- both the bytes and the buffer itself, which the group never got
        // back.  for_each_cqe_buf is the loop's rule for naming and slicing
        // them; what stays here is where the bytes go.
        m_loop->for_each_cqe_buf(BUF_GROUP_ID, cqe, [&](char* p, uint32_t n) {
            if (SOCKETLEY_UNLIKELY(conn->ssl != nullptr))
                tls_feed(conn, p, static_cast<size_t>(n));
            else
                conn->partial.append(p, n);
        });
    }
    else if (SOCKETLEY_UNLIKELY(conn->ssl != nullptr))
    {
        tls_feed(conn, conn->read_buf, static_cast<size_t>(cqe->res));
    }
    else
    {
        conn->partial.append(conn->read_buf, cqe->res);
    }

    // This client has said something, and from here on it is one that is owed
    // an answer rather than one that is only listening.  Here rather than in
    // each of the three branches above because this is where they meet, and on
    // `partial` rather than on cqe->res because on a TLS connection the bytes
    // that just arrived may be a handshake record the session answers by
    // itself: a client is not waiting on the relay for that.  Sticky — a
    // connection does not become a listener again by falling silent, and the
    // sticky part is what keeps a keep-alive HTTP client, whose protocol is
    // reset to unknown between requests, out of the deadline's reach.
    if (SOCKETLEY_UNLIKELY(!conn->spoke) && !conn->partial.empty())
        conn->spoke = true;

    if (SOCKETLEY_UNLIKELY(conn->partial.size() > server_connection::MAX_PARTIAL_SIZE))
    {
        conn->closing = true;
        goto submit_next_read;
    }

    parse_partial(conn);

submit_next_read:
    // Relay traffic that arrived while this connection had no protocol yet.
    //
    // Here and not at any of the points above that decide one, because every
    // path through this function reaches this label and only some of them
    // classify: a read that leaves the connection mid-line or mid-header
    // settles nothing, and proto_unsettled() is what tells those apart.  By
    // this point whatever this read produced — a 101, an HTTP response, a pong
    // — is already in the write queue, so the held bytes append behind it
    // rather than in front of it, which was the entire defect.
    if (SOCKETLEY_UNLIKELY(!conn->relay_hold.empty()) && !proto_unsettled(conn))
        relay_hold_flush(conn);

    // Everything this read produced for the cache goes now.  One post for the
    // whole buffer instead of one per line, and — because every path above
    // reaches this label — nothing is left sitting in the batch waiting for a
    // message that may never come.
    if (SOCKETLEY_UNLIKELY(!m_cache_store_batch.empty()))
        flush_cache_store();

    // ── the TLS half of the same idea ──
    // The peer's close_notify is applied here rather than where it was read:
    // the read that carried it can carry the last request ahead of it, and
    // marking the connection closing any earlier would have made the parse
    // above throw that request away with the answer half computed.
    //
    // Then one flush for everything the record layer owes the wire — the next
    // handshake flight, an alert explaining a handshake that just failed, a
    // session ticket, and whatever the parse above queued — as a single write.
    // Every path through this function reaches this label, so nothing is left
    // sitting in a BIO waiting for a completion that has no reason to come.
    if (SOCKETLEY_UNLIKELY(conn->ssl != nullptr))
    {
        if (conn->tls_peer_closed)
            conn->closing = true;
        tls_flush(conn);
    }

    // Only submit next read if connection is not closing and no file read pending
    if (SOCKETLEY_LIKELY(m_loop && !conn->closing))
    {
        // Don't resubmit socket read while async file read is in progress
        if (!conn->read_pending && !conn->file_read_pending)
        {
            submit_conn_read(conn);
            // A read that could not be queued marks the connection closing and
            // leaves nothing in flight to notice that later — no completion is
            // coming.  Without this it sits here until the runtime stops.
            if (SOCKETLEY_UNLIKELY(conn->closing && !conn_ops_pending(conn)))
                close_conn(conn);
        }
    }
    else if (conn->closing && !conn_ops_pending(conn))
    {
        // Nothing left in the ring for this connection, so it can go now.
        // Whichever operation is still outstanding owns the teardown instead:
        // its completion handler asks the same question and finds it answered.
        close_conn(conn);
    }
}

// Constant-time string compare to prevent timing attacks on password
static bool constant_time_eq(std::string_view a, std::string_view b)
{
    volatile uint8_t diff = static_cast<uint8_t>(a.size() != b.size());
    size_t max_len = std::max(a.size(), b.size());
    for (size_t i = 0; i < max_len; i++)
    {
        uint8_t ca = (i < a.size()) ? static_cast<uint8_t>(a[i]) : 0;
        uint8_t cb = (i < b.size()) ? static_cast<uint8_t>(b[i]) : 0;
        diff |= ca ^ cb;
    }
    return diff == 0;
}

static constexpr uint8_t MAX_AUTH_FAILURES = 5;

static inline __attribute__((always_inline)) bool check_rate_limit(server_connection* conn)
{
    if (SOCKETLEY_LIKELY(conn->rl_max <= 0))
        return true;

    auto now = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(now - conn->rl_last).count();
    conn->rl_last = now;
    conn->rl_tokens += elapsed * conn->rl_max;
    if (conn->rl_tokens > conn->rl_max)
        conn->rl_tokens = conn->rl_max;

    if (conn->rl_tokens < 1.0)
        return false;

    conn->rl_tokens -= 1.0;
    return true;
}

// ─── Cache requests ─────────────────────────────────────────────────────────
//
// What the channel hands back with a reply is one 64-bit cookie and nothing
// else, so everything needed to find the client that asked has to fit in it:
// the descriptor in the low half and the identity the connection had when it
// asked in the high half.  Both are required.  The descriptor alone finds a
// connection; the generation is what says it is the *same* connection, because
// a client that aborts mid-request has its number reissued by the next accept
// and its struct handed on by the pool.  That is exactly the shape of the
// completion-after-teardown defects this runtime has been finding all week, and
// it is answered here the same way on_cqe answers it.
//
// A request made on nobody's behalf — the auto-store, or a UDP datagram, which
// has no connection at all — uses a descriptor of -1, which no index can
// resolve, so its reply is dropped without ever looking anything up.
static constexpr uint64_t CACHE_COOKIE_NO_CONN = 0xFFFFFFFFull;

static inline uint64_t cache_cookie(const server_connection* conn, bool silent)
{
    if (!conn || silent)
        return CACHE_COOKIE_NO_CONN;
    return (static_cast<uint64_t>(conn->generation) << 32)
         | static_cast<uint64_t>(static_cast<uint32_t>(conn->fd));
}

void server_instance::flush_cache_store()
{
    if (SOCKETLEY_LIKELY(m_cache_store_batch.empty()))
        return;

    // Cleared whatever happens.  A batch the channel would not take is lost —
    // it is counted there as such — and holding on to it would only make the
    // next flush larger and no more likely to be taken.
    post_cache_request(nullptr, m_cache_store_batch, true);
    m_cache_store_batch.clear();
}

void server_instance::post_cache_request(server_connection* conn,
                                         std::string_view payload, bool silent)
{
    const std::string_view cname = get_cache_name();
    if (cname.empty())
        return;

    auto* mgr = get_runtime_manager();
    if (SOCKETLEY_UNLIKELY(!mgr))
        return;

    // The cap, and the one place it is enforced.  Charged only to requests the
    // client asked for: the auto-store is the server's own doing and closing a
    // connection over it would punish a client for a feature it never used.
    // The store is still bounded — by the channel's own queue, which refuses
    // below.
    if (!silent && conn)
    {
        if (SOCKETLEY_UNLIKELY(conn->cache_pending >= MAX_CACHE_PENDING))
        {
            conn->closing = true;
            return;
        }
    }

    const auto cls = silent ? request_class::background : request_class::client;
    if (!mgr->requests().post(this, cache_cookie(conn, silent), cname, payload, cls))
    {
        // The channel took nothing, so no reply is coming for this one.
        //
        // A command the client is waiting on cannot simply be dropped and
        // cannot be answered here either — an error written now would arrive
        // ahead of the answers already queued in front of it, and the client
        // would match the wrong reply to the wrong question.  Closing says the
        // same thing without lying about the order.
        //
        // The auto-store just goes.  Nobody asked for it and nobody is waiting
        // on it, and it only reaches here once the channel's background share
        // is full, which is a burst larger than the loop can drain in a turn.
        // The channel counts every one of these; it is loss, not a no-op.
        if (!silent && conn)
            conn->closing = true;
        return;
    }

    if (!silent && conn)
        ++conn->cache_pending;
}

void server_instance::on_request_reply(uint64_t cookie, request_status st,
                                       std::string_view reply)
{
    const int      fd  = static_cast<int>(static_cast<int32_t>(cookie & 0xFFFFFFFFull));
    const uint32_t gen = static_cast<uint32_t>(cookie >> 32);

    if (fd < 0 || fd >= MAX_FDS)
        return;   // the auto-store, or a datagram: nobody is waiting on this

    auto* conn = m_conn_idx[fd];
    if (!conn || conn->generation != gen)
        return;   // the client that asked is gone, and its number may already
                  // belong to somebody who never asked anything

    if (SOCKETLEY_LIKELY(conn->cache_pending > 0))
        --conn->cache_pending;

    // Written even when the connection is marked closing.  That flag normally
    // means "the conversation is over, anything produced now is thrown away",
    // and for output this runtime decided to send that is right.  This is not
    // that: the client asked for this line and its socket is open only because
    // the answer is owed — a request/response client that half-closes after
    // asking is marked closing by the FIN and is still sitting there reading.
    if (SOCKETLEY_LIKELY(m_loop != nullptr))
    {
        std::string text;
        if (SOCKETLEY_LIKELY(st == request_status::ok))
        {
            text.assign(reply);
        }
        else
        {
            // Said out loud rather than swallowed.  A client whose `cache get`
            // went to a runtime that has since stopped used to receive nothing
            // at all and wait for a line that was never coming.
            const char* why = request_status_text(st);
            text.reserve(8 + std::char_traits<char>::length(why));
            text.append("error: ").append(why);
        }

        if (!text.empty())
        {
            if (text.back() != '\n')
                text.push_back('\n');
            send_to(conn, std::make_shared<const std::string>(std::move(text)), true);
        }
    }

    // The close close_conn() deferred, if this was the last answer owed and
    // nothing else is armed.  Whichever operation is still outstanding owns the
    // teardown otherwise: its completion handler asks the same question and
    // finds it answered, exactly as on every other path here.
    if (SOCKETLEY_UNLIKELY(conn->closing) && conn->cache_pending == 0
        && !conn_ops_pending(conn))
        close_conn(conn);
}

void server_instance::process_message(server_connection* sender, std::string_view msg)
{
    // Rate limit check (per-connection)
    if (sender && !check_rate_limit(sender))
        return;

    // Global rate limit check (across all connections)
    if (!check_global_rate_limit())
        return;

    // Zero-copy pipe: forward directly to peer, bypassing Lua callbacks
    if (sender && SOCKETLEY_UNLIKELY(sender->pipe_peer_fd >= 0))
    {
        auto* peer = (sender->pipe_peer_fd < MAX_FDS)
            ? m_conn_idx[sender->pipe_peer_fd] : nullptr;
        if (peer && !peer->closing)
        {
            auto shared_msg = std::make_shared<const std::string>(msg);
            send_to(peer, shared_msg);
        }
        return;
    }

    // Check if this client is routed to a sub-server (cached flag avoids map lookup)
    if (sender && SOCKETLEY_UNLIKELY(sender->routed))
    {
        auto rit = m_routes.find(sender->ref_serial);
        if (rit != m_routes.end())
        {
            auto* mgr = get_runtime_manager();
            if (mgr)
            {
                auto* target = mgr->get(rit->second);
                if (target && target->get_state() == runtime_running)
                {
                    // The name, not the descriptor.  In one process this is the
                    // same call it always was; the argument is what changed,
                    // and it is the argument that decides whether the same call
                    // still means anything once the target is elsewhere.
                    if (auto* sub = target->as_server())
                        sub->deliver_routed(conn_ref{owner_key(), sender->ref_serial}, msg);
                }
            }
            return;
        }
    }

    m_stat_total_messages.fetch_add(1, std::memory_order_relaxed);
    print_bash_message(msg);
    notify_interactive(msg);

    // Fire on_client_message callback (sender-aware)
    if (sender)
        invoke_on_client_message(sender->fd, msg);

    // Cache command interception: "cache <cmd>" → asked of the linked cache and
    // answered to the sender alone, one turn of the event loop later.  This
    // used to run the cache's own interpreter here, on this stack, through a
    // pointer to the cache object; see shared/request_channel.h for why it does
    // not any more and what that costs.
    if (SOCKETLEY_UNLIKELY(sender && msg.size() > 6 && msg[0] == 'c' && msg.starts_with("cache ")))
    {
        // Ahead of the command, so that a client which sends a message and then
        // asks the cache for it by key sees its own write.  One queue, drained
        // in order, so posting the batch first is all the ordering needs.
        flush_cache_store();
        post_cache_request(sender, msg.substr(6), false);
        return; // Cache commands are never broadcast
    }

    // Store in cache if configured.  Appended to the batch rather than posted;
    // see m_cache_store_batch for why the granularity matters.
    if (SOCKETLEY_UNLIKELY(!get_cache_name().empty()))
    {
        char key_buf[24];
        auto [key_end, key_ec] = std::to_chars(key_buf, key_buf + sizeof(key_buf), ++m_message_counter);
        const auto key_len = static_cast<size_t>(key_end - key_buf);

        auto& batch = m_cache_store_batch;
        const size_t line_start = batch.size();
        batch.append("set ", 4).append(key_buf, key_len).push_back(' ');
        batch.append(msg);
        batch.push_back('\n');

        // A newline inside the value would end the line early and turn the rest
        // of the message into a command of its own.  The cache's own text
        // protocol is line-based and cannot carry one either — a client typing
        // `set k a<newline>b` at the cache's port stores "a" — so flattening is
        // what going through the protocol means rather than around it.  Only
        // the WebSocket and RESP paths can produce one; the line parser cannot.
        for (size_t i = line_start; i + 1 < batch.size(); i++)
            if (SOCKETLEY_UNLIKELY(batch[i] == '\n' || batch[i] == '\r'))
                batch[i] = ' ';

        if (SOCKETLEY_UNLIKELY(batch.size() >= CACHE_STORE_BATCH_BYTES))
            flush_cache_store();
    }

    switch (m_mode)
    {
        case mode_inout:
        {
            invoke_on_message(msg);

            if (lua() && lua()->has_on_message())
                break;

            if (m_udp)
            {
                // UDP: broadcast to all peers (exclude handled by caller via addr)
                udp_broadcast(msg, nullptr);
            }
            else
            {
                std::string buf;
                buf.reserve(msg.size() + 1);
                buf.append(msg);
                buf.push_back('\n');
                auto relay_msg = std::make_shared<const std::string>(std::move(buf));
                broadcast(relay_msg, sender ? sender->fd : -1);
            }
            break;
        }
        case mode_in:
        {
            invoke_on_message(msg);
            break;
        }
        case mode_out:
            break;
        case mode_master:
        {
            // Master authentication: "master <password>"
            if (msg.size() > 7 && msg.starts_with("master "))
            {
                // Auth attempt limit — disconnect after too many failures
                if (sender->auth_failures >= MAX_AUTH_FAILURES)
                {
                    sender->closing = true;
                    break;
                }

                std::string_view pw = msg.substr(7);
                bool auth_ok = false;

                // ─── An auth hook is read strictly, and a failure is a denial ───
                //
                // The Lua hook comes first and the `else if` below is the whole
                // point: a script that defines on_master_auth has REPLACED
                // --master-pw, not supplemented it, so whatever this block
                // decides is the entire gate on the master role.
                //
                // It used to be `result.get<bool>()`, which is lua_toboolean —
                // and in Lua the only false values are `false` and `nil`.  So
                // `return "denied"`, `return 0` and `return {}` all granted
                // master: every spelling of "no" that a script might reach for
                // except the two nobody writes by mistake.  Read as an optional
                // <bool>, which is a type check rather than a truth test, so a
                // hook that did not answer `true` has not authenticated anybody.
                //
                // The `result.valid()` guard it replaces could not fire.  The
                // callback is an unprotected sol::function, and converting its
                // unsafe_function_result to a protected_function_result stamps
                // call_status::ok on the way — so `valid()` was constant true
                // and the only thing standing between a raising hook and a
                // granted master role was the catch below.
                //
                // Which said nothing.  `catch (...) {}` meant an auth callback
                // with a typo in it denied in complete silence, indistinguishable
                // from one that had considered the request and refused it — so
                // the operator saw a gate that worked and had no way to learn
                // their gate was not running.  Fail closed and say why.
                //
                // A PROTECTED call, and that is not a detail.  Written with a
                // try/catch — the convention invoke_on_auth uses one file away —
                // the denial still happened but the message did not, because the
                // catch depends on sol2's panic handler throwing and on that
                // throw being able to unwind out of the interpreter.  Measured
                // in this repository's own Sanitize build: the hook ran, the
                // request was denied, and no `on_master_auth error` line was
                // ever written, while a `socketley.log` from the same callback
                // reached the same log file.  The catch simply never ran.
                //
                // A silent auth hook is the exact defect this callback was being
                // fixed for, so a reporting mechanism that stops working in a
                // build configuration is not good enough.  Protected calls
                // return the error as a value; see m_on_master_auth's note in
                // lua_context.h and the on_route precedent in proxy_instance.
                auto* lctx = lua();
                if (lctx && lctx->has_on_master_auth())
                {
#ifndef SOCKETLEY_NO_LUA
                    sol::protected_function_result r =
                        lctx->on_master_auth()(sender->fd, pw);

                    if (SOCKETLEY_UNLIKELY(!r.valid()))
                    {
                        sol::error err = r;
                        std::cerr << lua_diag::tag(get_name()) << " on_master_auth error: " << err.what()
                                  << std::endl;
                        auth_ok = false;
                    }
                    else
                    {
                        // Read as an optional<bool>, which is a type check
                        // rather than a truth test: only the boolean `true`
                        // grants.  A hook that returned nothing has not
                        // answered, and a non-answer is a denial.
                        sol::optional<bool> res = r.return_count() > 0
                                                  ? r.get<sol::optional<bool>>()
                                                  : sol::optional<bool>{};
                        auth_ok = res.value_or(false);
                    }
#endif
                }
                else if (!m_master_pw.empty())
                {
                    auth_ok = constant_time_eq(pw, m_master_pw);
                }

                if (auth_ok)
                {
                    m_master_fd = sender->fd;
                    sender->auth_failures = 0;
                    auto ok_msg = std::make_shared<const std::string>("master: ok\n");
                    send_to(sender, ok_msg);
                }
                else
                {
                    sender->auth_failures++;

                    // Record per-IP failure
                    {
                        struct sockaddr_in peer_addr{};
                        socklen_t peer_len = sizeof(peer_addr);
                        if (getpeername(sender->fd, reinterpret_cast<struct sockaddr*>(&peer_addr), &peer_len) == 0)
                        {
                            auto& rec = m_auth_ip_failures[peer_addr.sin_addr.s_addr];
                            rec.failures++;
                            rec.last_failure = std::chrono::steady_clock::now();
                        }
                    }

                    auto deny_msg = std::make_shared<const std::string>("master: denied\n");
                    send_to(sender, deny_msg);
                }
                break;
            }

            // If sender is master: broadcast to all except sender
            if (sender && sender->fd == m_master_fd)
            {
                invoke_on_message(msg);

                if (!(lua() && lua()->has_on_message()))
                {
                    std::string buf;
                    buf.reserve(msg.size() + 1);
                    buf.append(msg);
                    buf.push_back('\n');
                    auto relay_msg = std::make_shared<const std::string>(std::move(buf));
                    broadcast(relay_msg, sender->fd);
                }
                break;
            }

            // Non-master: forward to master if master_forward is set
            if (sender && m_master_forward && m_master_fd >= 0 &&
                m_master_fd < MAX_FDS && m_conn_idx[m_master_fd])
            {
                char fd_buf[16];
                auto [fd_end, fd_ec] = std::to_chars(fd_buf, fd_buf + sizeof(fd_buf), sender->fd);
                std::string buf;
                buf.reserve(msg.size() + 16);
                buf.push_back('[');
                buf.append(fd_buf, fd_end - fd_buf);
                buf.append("] ", 2);
                buf.append(msg.data(), msg.size());
                buf.push_back('\n');
                auto fwd_msg = std::make_shared<const std::string>(std::move(buf));
                send_to(m_conn_idx[m_master_fd], fwd_msg);
            }
            // Non-master messages are silently dropped (not broadcast)
            break;
        }
        default:
            break;
    }
}

void server_instance::lua_broadcast(std::string_view msg)
{
    if (SOCKETLEY_UNLIKELY(!m_loop))
        return;

    invoke_on_send(msg);

    if (SOCKETLEY_UNLIKELY(m_udp))
    {
        udp_broadcast(msg, nullptr);
        return;
    }

    // Build newline-terminated message (single allocation via make_shared)
    std::string buf;
    buf.reserve(msg.size() + 1);
    buf.append(msg);
    if (buf.empty() || buf.back() != '\n')
        buf.push_back('\n');
    auto full_msg = std::make_shared<const std::string>(std::move(buf));
    broadcast(full_msg, -1);  // -1 = don't exclude anyone

    // Also reach the connections routed here, each through the runtime that
    // owns it.  A ref that no longer resolves is dropped there rather than
    // written somewhere — which is the difference between a broadcast that
    // misses a departed client and one that reaches a stranger.
    for (auto& [handle, fc] : m_forwarded)
    {
        (void)handle;
        auto* mgr = get_runtime_manager();
        if (mgr)
        {
            auto* origin = mgr->get(fc.origin);
            if (origin && origin->get_state() == runtime_running)
            {
                if (auto* srv = origin->as_server())
                    srv->write_to_ref(fc.ref, msg);
            }
        }
    }
}

// One pass over every connection, one submission each, and no return to the
// event loop in between — the same shape as cache_instance::publish(), and it
// had the same defect for the same reason.  get_sqe() used to report a full
// submission queue as a permanent failure, so flush_write_queue() below dropped
// the bytes and set `closing`: measured on this tree, SQPOLL on, 3000 connected
// clients and a 2048-entry ring, one broadcast reached exactly 2048 of them and
// 952 were marked closing and never told the message existed.  Fixed in
// shared/event_loop.cpp, which is where it belongs — two runtimes had it.
// test_server_broadcast_reaches_all.sh is the guard.
//
// Anything added here that submits per connection inherits that history: this
// loop is bounded only by how many clients are connected.
void server_instance::broadcast(const std::shared_ptr<const std::string>& msg, int exclude_fd)
{
    if (SOCKETLEY_UNLIKELY(!m_loop))
        return;

    std::shared_ptr<const std::string> ws_msg; // Lazy WS frame creation

    // Iterate over flat active_fds vector (cache-friendly, no hash overhead)
    for (size_t i = 0; i < m_active_fds.size(); i++)
    {
        int fd = m_active_fds[i];
        auto* conn = m_conn_idx[fd];
        if (SOCKETLEY_UNLIKELY(!conn || fd == exclude_fd || conn->closing))
            continue;

        // This client speaks a request/response protocol — HTTP or RESP — and
        // no relayed line is well formed on one at any point in its life.
        // Skipped rather than held: a hold implies there is a later moment at
        // which these bytes would be correct, and for a connection whose
        // replies are matched to its requests by their order on the stream
        // there is not.  See relay_targetable().
        //
        // Ahead of the hold below, because an HTTP connection between two
        // keep-alive requests reads as unclassified and would otherwise
        // accumulate a hold that the next request's first read then flushes —
        // in front of the response to that very request.
        if (SOCKETLEY_UNLIKELY(!relay_targetable(conn)))
            continue;

        // Nothing is known yet about what this client speaks, and writing to it
        // now would put these bytes in front of the response to a request it
        // has already sent.  Hold them; handle_read releases them the moment
        // the protocol is settled, behind that response and in this order.
        if (SOCKETLEY_UNLIKELY(proto_unsettled(conn)))
        {
            relay_hold_push(conn, msg);
            continue;
        }

        if (SOCKETLEY_UNLIKELY(conn->write_queue.bytes() >= socketley::write_queue_max_bytes))
        {
            conn->closing = true;
            continue;
        }

        if (SOCKETLEY_UNLIKELY(conn->proto == proto_ws))
        {
            if (!ws_msg)
            {
                // Strip trailing newline for WS frame (WS messages are not newline-delimited)
                std::string_view payload(*msg);
                if (!payload.empty() && payload.back() == '\n')
                    payload.remove_suffix(1);
                ws_msg = ws_frame_text_shared(payload);
            }
            conn->write_queue.push(ws_msg);
            if (!conn->write_pending)
                flush_write_queue(conn);
        }
        else
        {
            conn->write_queue.push(msg);
            if (!conn->write_pending)
                flush_write_queue(conn);
        }
    }
}

void server_instance::send_to(server_connection* conn, const std::shared_ptr<const std::string>& msg,
                              bool even_when_closing)
{
    if (SOCKETLEY_UNLIKELY(!m_loop || (conn->closing && !even_when_closing)))
        return;

    if (SOCKETLEY_UNLIKELY(conn->write_queue.bytes() >= socketley::write_queue_max_bytes))
    {
        conn->closing = true;
        return;
    }

    if (SOCKETLEY_UNLIKELY(conn->proto == proto_ws))
    {
        // Strip trailing newline for WS frame
        std::string_view payload(*msg);
        if (!payload.empty() && payload.back() == '\n')
            payload.remove_suffix(1);
        conn->write_queue.push(ws_frame_text_shared(payload));
    }
    else
    {
        conn->write_queue.push(msg);
    }

    if (SOCKETLEY_LIKELY(!conn->write_pending))
        flush_write_queue(conn);
}

void server_instance::relay_hold_push(server_connection* conn,
                                      const std::shared_ptr<const std::string>& msg)
{
    // The deadline runs from the first message held, not from every one.  A
    // listener on a busy relay would otherwise have its clock reset by each new
    // broadcast and never reach the deadline at all — which is the "never
    // classified, never served" behaviour this exists to end, restored exactly
    // where it hurts most.
    if (conn->relay_hold.empty())
    {
        conn->relay_hold_since = std::chrono::steady_clock::now();
        if (relay_deadline_applies(conn))
            relay_deadline_arm(RELAY_HOLD_DEADLINE_MS);
    }

    conn->relay_hold.push(msg);

    // A loop and not a single pop: one relayed message can be larger than the
    // whole bound by itself, and popping once would leave the hold over its
    // limit for as long as the connection stayed silent — which for a pure
    // listener is for ever, and this bound is the only thing standing between
    // that and unbounded growth.
    while (SOCKETLEY_UNLIKELY(conn->relay_hold.bytes() > RELAY_HOLD_MAX_BYTES)
           && !conn->relay_hold.empty())
        conn->relay_hold.pop();
}

void server_instance::relay_hold_flush(server_connection* conn)
{
    if (SOCKETLEY_LIKELY(conn->relay_hold.empty()))
        return;

    // What was held before the classification turned out to be a
    // request/response protocol is dropped rather than delivered.  These bytes
    // were held on the guess that the connection would turn out to be a relay
    // target; it did not, and there is no framing on an HTTP or RESP
    // connection that could carry them.  Both windows are real and not
    // theoretical: a GET is classified proto_ws_upgrading, which holds, and
    // only the header parse says whether it was an upgrade or a plain request;
    // and a RESP client whose first write stops short of four bytes and of a
    // newline — "*1\r" — is unclassified until the rest of the command
    // arrives, so a broadcast in that gap is held and then flushed onto a
    // connection that turned out to speak RESP.
    if (SOCKETLEY_UNLIKELY(!relay_targetable(conn)))
    {
        conn->relay_hold.clear();
        conn->relay_hold_since = {};
        return;
    }

    // send_to() rather than a push straight into the write queue, and that is
    // the whole reason this is a function and not three lines at the call site:
    // the connection has a protocol *now*, and for a WebSocket that means every
    // one of these has to go out as a frame.  Flushing raw would trade one
    // corrupted stream for another — the client reads the 101, switches to
    // frame parsing, and is handed plain text.  send_to is where that framing
    // decision already lives, so this path cannot drift away from the one
    // broadcast() takes for a connection that was classified in time.
    while (!conn->relay_hold.empty())
        send_to(conn, conn->relay_hold.take_front());

    conn->relay_hold_since = {};
}

void server_instance::relay_deadline_arm(uint32_t after_ms)
{
    // Not if it is already counting.  A timeout is attached to no descriptor,
    // so a second submission on this request would leave the first one in the
    // ring with nothing able to name it — the same defect the idle sweep's
    // armed flag exists to prevent, and the reason that one is commented at
    // such length in setup().
    if (m_relay_deadline_armed || SOCKETLEY_UNLIKELY(!m_loop))
        return;

    m_relay_deadline_ts.tv_sec  = after_ms / 1000;
    m_relay_deadline_ts.tv_nsec = static_cast<long long>(after_ms % 1000) * 1000000LL;
    m_relay_deadline_req = { this, nullptr, -1, 0, op_timeout };
    m_relay_deadline_armed = m_loop->submit_timeout(&m_relay_deadline_ts, &m_relay_deadline_req);
}

void server_instance::relay_deadline_sweep()
{
    const auto now = std::chrono::steady_clock::now();
    const auto deadline = std::chrono::milliseconds(RELAY_HOLD_DEADLINE_MS);

    // The shortest wait any connection that is still holding has left.  Starts
    // at the full deadline because nothing can be owed longer than that.
    auto next = deadline;
    bool still_waiting = false;

    // The same shape broadcast() iterates m_active_fds with, for the same
    // reason: the flush below writes, a write that never reaches the ring marks
    // the connection closing, and re-reading size() each turn is what makes
    // that safe.  Nothing here removes an fd from the vector — only a
    // completion does that — so no entry is skipped.
    for (size_t i = 0; i < m_active_fds.size(); i++)
    {
        const int fd = m_active_fds[i];
        auto* conn = m_conn_idx[fd];
        if (SOCKETLEY_LIKELY(!conn || conn->closing || conn->relay_hold.empty()))
            continue;

        // Classified, spoken, or still handshaking: this hold is not the
        // deadline's to release, and its connection is not what the timer
        // should be re-armed for either.  A client mid-request is waiting for
        // an answer, and flushing in front of that answer is the defect the
        // hold exists to prevent.
        if (!relay_deadline_applies(conn))
            continue;

        const auto waited = now - conn->relay_hold_since;
        if (waited < deadline)
        {
            still_waiting = true;
            const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - waited);
            if (left < next)
                next = left;
            continue;
        }

        // Out of time.  This client has sent nothing since it was accepted, so
        // there is no response of its own for these bytes to arrive in front
        // of, and raw line-delimited text is what a connection that has never
        // announced anything else gets.  Settling the protocol rather than just
        // emptying the queue is the point: everything relayed after this goes
        // straight out, so the 250 ms is paid once per connection and not once
        // per message.
        conn->proto = proto_tcp;
        relay_hold_flush(conn);
    }

    if (still_waiting)
    {
        // A floor under the re-arm.  Without it a hold that is one microsecond
        // short of its deadline arms a one-microsecond timeout, and a busy
        // relay would spend more time in the timer wheel than in the sweep.
        static constexpr uint32_t MIN_REARM_MS = 5;
        auto ms = static_cast<uint32_t>(next.count());
        relay_deadline_arm(ms < MIN_REARM_MS ? MIN_REARM_MS : ms);
    }
}

bool server_instance::conn_has_output(const server_connection* conn) const
{
    if (!conn->write_queue.empty())
        return true;
    // A TLS connection can owe the wire bytes with an empty queue: a handshake
    // flight, an alert, a session ticket, or ciphertext that did not fit in
    // the write that just completed.  Asking only about the queue is how a
    // handshake stalls one round short of finishing.
    return conn->ssl != nullptr && tls_context::has_pending_out(conn->ssl);
}

// ─── WE SEND THE FIN, NOT THE CLIENT ────────────────────────────────────────
//
// Whoever performs the active close holds TIME-WAIT for that 4-tuple for 60 s.
// Ours sits on a fixed listening port and costs nothing scarce; the client's
// sits on an ephemeral port, and this box has 28,231 of them.  Measured over
// 2,000 connection-per-request requests before this existed: 0 closes from us,
// 2,004 from the client — we were structurally second, every time, and the
// client burned its cores in the port allocator finding a free one.
//
// Two things are load bearing:
//
//   shutdown(), not close().  close() on a socket that still has unread bytes
//   in its receive queue sends RST rather than FIN, and an RST can destroy the
//   answer just written.  The read stays armed; the client's own FIN completes
//   it and close_conn() still runs on exactly one path, so the teardown
//   bookkeeping is untouched.
//
//   Only from a write *completion*, never from where the write is queued.
//   shutdown() is a syscall and a ring submission is not, so calling this with
//   a write still in flight lets the FIN overtake the payload.  That is the
//   half-close defect this tree has already fixed four times on the proxy side;
//   the guard below is what keeps it from coming back here.  Every condition in
//   it is "is anything still owed to the wire", and it is one function rather
//   than a line repeated at each completion for the same reason.
//
// ─── DO NOT REPLACE THIS WITH A LINKED IORING_OP_SHUTDOWN ───────────────────
//
// It looks like the obvious improvement -- chain the FIN to the send with
// IOSQE_IO_LINK and it leaves from inside the kernel, with no completion
// crossing into userspace first.  It was built, and it is much WORSE.  Measured
// as "the client closes the instant it has the whole response; was our FIN
// already in its receive queue", 200 attempts, three repetitions, quiet box:
//
//     this function, from the write completion    200 / 182 / 200
//     linked IORING_OP_SHUTDOWN + MSG_WAITALL       4 /   0 /   1
//     linked, without MSG_WAITALL                   2 /   1 /   2
//
// The third row is there because MSG_WAITALL is the obvious suspect -- the
// linked send needs it, or a short send lets the FIN out on top of an
// unfinished response (measured directly: 6144 bytes of a 4 MB send delivered,
// then a clean FIN).  It is not the suspect.  Dropping it changes nothing, so
// the cost is the LINK itself: the kernel runs the second op out of the first
// one's completion, and by then the data has already woken the client, which
// closes before the FIN is issued.  An ordinary send completes inline and the
// shutdown() syscall right behind it beats the client to it.
//
// Rate was identical between the two (-0.4%, six interleaved pairs).  CPU per
// request could not be measured on this machine: kernel.sched_schedstats is 0,
// and a run lasts 86 ms against a 10 ms clock tick.
void server_instance::maybe_shutdown_write(server_connection* conn)
{
    if (SOCKETLEY_LIKELY(!conn->closing) || conn->wr_shutdown || conn->fd < 0)
        return;

    // A TLS connection owes a close_notify record first, and tls_flush() owns
    // that sequence.  Sending a bare FIN under it is a truncation attack as far
    // as the peer is concerned.
    if (conn->ssl != nullptr)
        return;

    // Still something to send, or something in the ring that is sending it.
    if (conn_has_output(conn) || conn->write_pending || conn->zc_notif_pending)
        return;
    if (conn->splice_pending || conn->splice_in_pending || conn->splice_out_pending)
        return;

    // An answer from the cache has not come back yet; close_conn() defers on
    // this same flag and so must we, or the FIN goes out before the reply.
    if (conn->cache_pending > 0)
        return;

    // Nothing is armed to hold the connection open, so the caller's own
    // `closing && !conn_ops_pending` branch is about to run close_conn() and do
    // this properly.  Only the armed-read case needs a FIN of its own — that is
    // the case that used to wait for the client.
    if (!conn->read_pending)
        return;

    conn->wr_shutdown = true;
    if (shutdown(conn->fd, SHUT_WR) < 0) {}
}

// Every byte this connection sends is a TLS record, including the ones nobody
// queued.  Called from flush_write_queue for a TLS connection and from the end
// of handle_read; there is no other way onto the wire.
void server_instance::tls_flush(server_connection* conn)
{
    if (SOCKETLEY_UNLIKELY(!m_loop || !conn->ssl))
        return;

    // One write in flight at a time, exactly as the cleartext path does — the
    // ciphertext buffer built below is what the kernel reads out of, and a
    // second submission would need a second buffer and would interleave two
    // record streams on one socket.  Whatever does not go now stays in the
    // queue or in the write BIO; handle_write comes back here when this write
    // lands.
    if (conn->write_pending || conn->zc_notif_pending)
        return;

    // Application data only once the handshake is done.  A message queued by
    // on_connect — which fires when the socket is accepted, before a single
    // record has crossed — waits here rather than being handed to an SSL that
    // would answer WANT_READ and leave the caller unsure what was consumed.
    if (conn->tls_state == tls_conn_ready)
    {
        while (!conn->write_queue.empty())
        {
            const auto& msg = conn->write_queue.front();
            const int n = tls_context::ssl_write(conn->ssl, msg->data(),
                                                 static_cast<int>(msg->size()));
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
            if (SOCKETLEY_UNLIKELY(static_cast<size_t>(n) != msg->size()))
            {
                conn->closing = true;
                break;
            }
            conn->write_queue.pop();
        }
    }

    if (!tls_context::has_pending_out(conn->ssl))
        return;

    // Ciphertext out of the write BIO and into a buffer this connection owns.
    // It has to be copied rather than pointed at: an SQE names an address the
    // kernel reads at its leisure, and the BIO's storage moves under it as
    // OpenSSL writes the next record.  Copying is also what keeps the SSL free
    // of anything the ring can name, which is what makes the session safe to
    // release the moment the connection is torn down.
    //
    // The buffer then rides in write_batch[0] like any other message, so the
    // short-write retry and the batch release in handle_write need no
    // TLS-specific case at all.
    auto cipher = std::make_shared<std::string>();
    char buf[16384];
    for (;;)
    {
        const int n = tls_context::bio_read_out(conn->ssl, buf, sizeof(buf));
        if (n <= 0)
            break;
        cipher->append(buf, static_cast<size_t>(n));
    }
    if (SOCKETLEY_UNLIKELY(cipher->empty()))
        return;

    // Nothing is in flight (checked above), so any refs still held are from a
    // completed write and are this function's to drop.
    for (uint32_t i = 0; i < conn->write_batch_count; i++)
        conn->write_batch[i].reset();

    conn->write_batch[0] = std::move(cipher);
    conn->write_iovs[0].iov_base = const_cast<char*>(conn->write_batch[0]->data());
    conn->write_iovs[0].iov_len  = conn->write_batch[0]->size();
    conn->write_batch_count = 1;
    conn->write_pending = true;
    conn->write_req.type = op_write;

    const auto len = static_cast<uint32_t>(conn->write_batch[0]->size());
    const bool queued = conn->direct_fd
        ? m_loop->submit_write_fixed_file(conn->fixed_idx, conn->write_batch[0]->data(),
                                          len, &conn->write_req)
        : m_loop->submit_write(conn->fd, conn->write_batch[0]->data(), len, &conn->write_req);

    // Nothing reached the ring, so no completion will arrive.  Undo the
    // in-flight bookkeeping and drop the connection, as the cleartext path
    // does: a write_pending that never clears keeps the teardown waiting for a
    // completion that cannot come.
    if (SOCKETLEY_UNLIKELY(!queued))
    {
        conn->write_pending = false;
        conn->write_batch[0].reset();
        conn->write_batch_count = 0;
        conn->closing = true;
    }
}

void server_instance::flush_write_queue(server_connection* conn)
{
    // A TLS connection's bytes go through the record layer, which is the only
    // thing allowed to put them on the wire.  This branch is what keeps every
    // caller above — Lua sends, HTTP responses, WebSocket frames, cache
    // replies — from having to know which kind of connection it is holding.
    if (SOCKETLEY_UNLIKELY(conn->ssl != nullptr))
    {
        tls_flush(conn);
        return;
    }

    if (SOCKETLEY_UNLIKELY(!m_loop || conn->write_queue.empty() || conn->zc_notif_pending))
        return;

    // Coalesce up to MAX_WRITE_BATCH messages into a single writev
    uint32_t count = 0;
    while (!conn->write_queue.empty() && count < server_connection::MAX_WRITE_BATCH)
    {
        conn->write_batch[count] = conn->write_queue.take_front();

        conn->write_iovs[count].iov_base = const_cast<char*>(conn->write_batch[count]->data());
        conn->write_iovs[count].iov_len = conn->write_batch[count]->size();
        count++;
    }

    conn->write_batch_count = count;
    conn->write_pending = true;

    bool queued;
    if (count == 1)
    {
        auto len = static_cast<uint32_t>(conn->write_batch[0]->size());

        // Use zero-copy send only for very large buffers (>= 512KB);
        // the NOTIF CQE round-trip kills throughput for smaller writes
        if (m_send_zc && len >= (512u << 10))
        {
            conn->zc_notif_pending = true;
            conn->write_req.type = op_send_zc;
            if (conn->direct_fd)
                queued = m_loop->submit_send_zc_fixed_file(conn->fixed_idx, conn->write_batch[0]->data(), len, &conn->write_req);
            else
                queued = m_loop->submit_send_zc(conn->fd, conn->write_batch[0]->data(), len, &conn->write_req);
        }
        else
        {
            // Single message — use plain write (lower overhead than writev)
            conn->write_req.type = op_write;
            if (conn->direct_fd)
                queued = m_loop->submit_write_fixed_file(conn->fixed_idx, conn->write_batch[0]->data(), len, &conn->write_req);
            else
                queued = m_loop->submit_write(conn->fd, conn->write_batch[0]->data(), len, &conn->write_req);
        }
    }
    else
    {
        conn->write_req.type = op_writev;
        if (conn->direct_fd)
            queued = m_loop->submit_writev_fixed_file(conn->fixed_idx, conn->write_iovs, count, &conn->write_req);
        else
            queued = m_loop->submit_writev(conn->fd, conn->write_iovs, count, &conn->write_req);
    }

    // Nothing reached the ring, so no write completion will arrive.  Undo the
    // in-flight bookkeeping and drop the connection — the batch is lost either
    // way, and a write_pending that never clears keeps the teardown waiting
    // forever for a completion that cannot come.
    if (SOCKETLEY_UNLIKELY(!queued))
    {
        conn->write_pending = false;
        conn->zc_notif_pending = false;
        for (uint32_t i = 0; i < conn->write_batch_count; i++)
            conn->write_batch[i].reset();
        conn->write_batch_count = 0;
        conn->closing = true;
    }
}

void server_instance::handle_write(struct io_uring_cqe* cqe, io_request* req)
{
    int fd = req->fd;
    auto* conn = m_conn_idx[fd];
    if (SOCKETLEY_UNLIKELY(!conn))
        return;

    // Zero-copy send notification: buffer is now safe to release
    if (SOCKETLEY_UNLIKELY(cqe->flags & IORING_CQE_F_NOTIF))
    {
        conn->zc_notif_pending = false;
        // Release batch references now that kernel is done with buffers
        for (uint32_t i = 0; i < conn->write_batch_count; i++)
            conn->write_batch[i].reset();
        conn->write_batch_count = 0;

        // Drain queue if we were waiting for NOTIF
        if (!conn->write_queue.empty() && !conn->write_pending)
            flush_write_queue(conn);
        else if (conn->write_queue.empty() && conn->closing && !conn_ops_pending(conn))
            close_conn(conn);
        else
            maybe_shutdown_write(conn);
        return;
    }

    conn->write_pending = false;

    if (SOCKETLEY_UNLIKELY(cqe->res <= 0))
    {
        // Release batch refs on error
        if (!conn->zc_notif_pending)
        {
            for (uint32_t i = 0; i < conn->write_batch_count; i++)
                conn->write_batch[i].reset();
            conn->write_batch_count = 0;
        }
        conn->closing = true;
        // splice_cleanup() declines while a splice is armed — it closes the file
        // fd and hands the shared pipe on, and doing that under a running splice
        // mixes one response's bytes into the next connection's.  The splice
        // completion does the cleanup, and the close, when it arrives.
        if (conn->splice_pending || conn->splice_remaining)
            splice_cleanup(conn);
        if (!conn_ops_pending(conn))
            close_conn(conn);
        return;
    }

    m_stat_bytes_out.fetch_add(static_cast<uint64_t>(cqe->res), std::memory_order_relaxed);

    // Short write handling: resubmit remaining bytes
    if (!conn->zc_notif_pending && conn->write_batch_count > 0)
    {
        size_t total_submitted = 0;
        for (uint32_t i = 0; i < conn->write_batch_count; i++)
            total_submitted += conn->write_iovs[i].iov_len;

        size_t written = static_cast<size_t>(cqe->res);
        if (written < total_submitted && SOCKETLEY_UNLIKELY(conn->wr_shutdown))
        {
            // Our write side is already closed, so the remainder cannot be sent
            // and retrying it would only earn an EPIPE.  maybe_shutdown_write()
            // only fires with the queue empty and nothing in flight, so getting
            // here means something queued more output after the FIN — a Lua
            // send, in practice.  Drop it rather than retry a truncated
            // response forever against a socket that will not take it.
            for (uint32_t i = 0; i < conn->write_batch_count; i++)
                conn->write_batch[i].reset();
            conn->write_batch_count = 0;
            conn->closing = true;
            if (!conn_ops_pending(conn))
                close_conn(conn);
            return;
        }
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
                    conn->write_batch[i].reset();
            }
            conn->write_batch_count = new_count;

            conn->write_pending = true;
            bool requeued;
            if (new_count == 1)
            {
                conn->write_req.type = op_write;
                if (conn->direct_fd)
                    requeued = m_loop->submit_write_fixed_file(conn->fixed_idx,
                        static_cast<const char*>(conn->write_iovs[0].iov_base),
                        static_cast<uint32_t>(conn->write_iovs[0].iov_len),
                        &conn->write_req);
                else
                    requeued = m_loop->submit_write(conn->fd,
                        static_cast<const char*>(conn->write_iovs[0].iov_base),
                        static_cast<uint32_t>(conn->write_iovs[0].iov_len),
                        &conn->write_req);
            }
            else
            {
                conn->write_req.type = op_writev;
                if (conn->direct_fd)
                    requeued = m_loop->submit_writev_fixed_file(conn->fixed_idx, conn->write_iovs, new_count, &conn->write_req);
                else
                    requeued = m_loop->submit_writev(conn->fd, conn->write_iovs, new_count, &conn->write_req);
            }
            if (SOCKETLEY_UNLIKELY(!requeued))
            {
                conn->write_pending = false;
                for (uint32_t i = 0; i < conn->write_batch_count; i++)
                    conn->write_batch[i].reset();
                conn->write_batch_count = 0;
                conn->closing = true;
            }
            return;
        }
    }

    // Full write completed — release batch
    if (!conn->zc_notif_pending)
    {
        for (uint32_t i = 0; i < conn->write_batch_count; i++)
            conn->write_batch[i].reset();
        conn->write_batch_count = 0;
    }

    // The response is on the wire and the queue behind it is empty: this is the
    // moment our write side is finished, and the only moment at which sending
    // the FIN cannot overtake anything.  It declines by itself if either is
    // untrue, so it goes before the branch rather than inside one arm of it.
    maybe_shutdown_write(conn);

    // Check if more messages to send.  conn_has_output and not the queue alone:
    // a TLS connection owes the wire the next handshake flight or a session
    // ticket with nothing queued at all, and asking only about the queue is how
    // a handshake stalls one round short of finishing.
    if (SOCKETLEY_LIKELY(conn_has_output(conn) && !conn->zc_notif_pending))
    {
        flush_write_queue(conn);
        // A flush can legitimately submit nothing — a TLS connection with
        // application data queued while the handshake is still running has
        // output and no way to send it yet.  Without this the connection would
        // be left closing with nothing in flight and nothing to wake it.
        if (SOCKETLEY_UNLIKELY(conn->closing && !conn_ops_pending(conn)))
            close_conn(conn);
    }
    else if (SOCKETLEY_UNLIKELY(conn->splice_pending && m_splice_pipe[0] >= 0 && !conn->closing))
    {
        // Headers sent — start file→pipe splice
        conn->splice_pending = false;
        uint32_t chunk = static_cast<uint32_t>(std::min(conn->splice_remaining, size_t(UINT32_MAX)));
        conn->splice_in_req = { this, nullptr, conn->fd, chunk, op_splice, conn->generation };
        conn->splice_in_pending =
            m_loop->submit_splice(conn->splice_file_fd, m_splice_pipe[1], chunk, &conn->splice_in_req);
        if (SOCKETLEY_UNLIKELY(!conn->splice_in_pending))
        {
            // Nothing reached the ring, so no completion will finish this
            // transfer.  Give the pipe back and drop the connection rather than
            // leave the response half-sent and the pipe marked busy for ever.
            splice_cleanup(conn);
            conn->closing = true;
            if (!conn_ops_pending(conn))
                close_conn(conn);
        }
    }
    else if (conn->closing && !conn_ops_pending(conn))
    {
        close_conn(conn);
    }
}

void server_instance::handle_file_read(struct io_uring_cqe* cqe, io_request* req)
{
    int fd = req->fd;  // socket fd
    auto* conn = m_conn_idx[fd];
    if (SOCKETLEY_UNLIKELY(!conn))
        return;

    conn->file_read_pending = false;

    // Client disconnected during file read — just clean up
    if (SOCKETLEY_UNLIKELY(conn->closing))
    {
        if (conn->file_fd >= 0) { close_tracked(conn->file_fd); conn->file_fd = -1; }
        free(conn->file_buf);
        conn->file_buf = nullptr;
        conn->file_size = 0;
        // The old guard here looked at the read and the write only, so a
        // zero-copy send still reading out of write_batch[0] — write_pending
        // long since down, notification not yet in — did not stop the release.
        if (!conn_ops_pending(conn))
            close_conn(conn);
        return;
    }

    // Read error — send 404.  A null buffer is treated as one: the caller that
    // could produce it is guarded in handle_read, and answering 404 is what this
    // function does with a read it cannot use.  Building the response out of it
    // instead means std::string_view(nullptr, n), and std::string throws
    // logic_error on that — from inside a completion handler, with no catch
    // anywhere above it, which ends the process.
    if (SOCKETLEY_UNLIKELY(cqe->res <= 0 || !conn->file_buf))
    {
        if (conn->file_fd >= 0) { close_tracked(conn->file_fd); conn->file_fd = -1; }
        free(conn->file_buf);
        conn->file_buf = nullptr;
        conn->file_size = 0;
        conn->write_queue.push(http_404_response(conn->http_keep_alive));
        if (!conn->write_pending)
            flush_write_queue(conn);
        if (!conn->http_keep_alive)
            conn->closing = true;
        else
        {
            conn->proto = proto_unknown;
            if (!conn->read_pending)
                submit_conn_read(conn);
            // ─── THE ERROR ARM OWES THE SAME DEBT AS THE SUCCESS ARM ─────
            //
            // The invariant is about the connection, not about the outcome: if
            // this connection deferred a parse in order to get here, a request
            // is sitting in conn->partial and somebody has to answer it.
            // Answering 404 to the FIRST request does not discharge that, and
            // an arm that returns without draining leaves the client waiting on
            // a response that will never be produced -- the exact failure this
            // whole change exists to remove, reintroduced on the path nobody
            // reads because it is the error path.
            //
            // This is why the rule is not "remember to drain after a successful
            // response".  A rule phrased that way is one every future arm has to
            // know about, and 15 places in this file already mean "finished, may
            // have another" without knowing anything of the sort.  Phrased as
            // "every arm that finishes a response drains", the omission is
            // visible as a missing line rather than invisible as a missing
            // thought.
            parse_partial(conn);
        }
        return;
    }

    // Close the file fd — we're done with it
    if (conn->file_fd >= 0)
    {
        close_tracked(conn->file_fd);
        conn->file_fd = -1;
    }

    // Use actual bytes read (handles short reads — Content-Length matches actual data)
    std::string_view file_content(conn->file_buf, static_cast<size_t>(cqe->res));
    std::string body;
    if (conn->file_is_html)
        body = inject_ws_script(file_content);

    std::string_view resp_body = conn->file_is_html
        ? std::string_view(body)
        : file_content;

    // A short read is served, and is deliberately NOT stored: cqe->res below
    // st_size means the bytes in hand are not the file, and an entry built from
    // them would be revalidated against the full size forever after and always
    // miss -- or, worse, match if the file were later truncated to exactly
    // this length.  Storing only a complete read keeps the map's contents and
    // its identity describing the same thing.
    const bool store = !conn->file_url_path.empty() &&
                       static_cast<uint64_t>(cqe->res) ==
                           static_cast<uint64_t>(conn->file_st.st_size);
    if (store)
    {
        auto ka = std::make_shared<const std::string>(
            build_http_response(conn->file_content_type, resp_body, true));
        auto cl = std::make_shared<const std::string>(
            build_http_response(conn->file_content_type, resp_body, false));
        conn->write_queue.push(conn->http_keep_alive ? ka : cl);
        http_reval_store(conn->file_url_path, conn->file_st, std::move(ka), std::move(cl));
    }
    else
    {
        conn->write_queue.push(
            std::make_shared<const std::string>(
                build_http_response(conn->file_content_type, resp_body, conn->http_keep_alive)));
    }
    conn->file_url_path.clear();

    // Free file buffer
    free(conn->file_buf);
    conn->file_buf = nullptr;
    conn->file_size = 0;

    if (!conn->write_pending)
        flush_write_queue(conn);

    if (!conn->http_keep_alive)
    {
        conn->closing = true;
    }
    else
    {
        conn->proto = proto_unknown;
        // Resubmit socket read for next HTTP request
        if (!conn->read_pending)
            submit_conn_read(conn);
        // Last statement -- see handle_splice_out.  Reachable here only by a
        // client that pipelines, because on the read path the client cannot
        // have the response before the read completes and so has no reason to
        // have sent anything; it is the same rule all the same.
        parse_partial(conn);
    }
}

void server_instance::splice_cleanup(server_connection* conn)
{
    // Not while a splice is armed.  This closes the file the kernel is reading
    // from, hands the shared pipe to the next connection and drains it — under a
    // running splice that mixes one response into another's socket.  The
    // completion handler calls back in once the op is really finished; until
    // then splice_in_pending / splice_out_pending keep the connection alive.
    if (SOCKETLEY_UNLIKELY(conn->splice_in_pending || conn->splice_out_pending))
        return;

    if (conn->splice_file_fd >= 0)
    {
        close_tracked(conn->splice_file_fd);
        conn->splice_file_fd = -1;
    }
    conn->splice_remaining = 0;
    conn->splice_pipe_pending = 0;
    conn->splice_pending = false;
    m_splice_busy = false;

    // Drain any residual data in pipe to prevent corruption for next user
    if (m_splice_pipe[0] >= 0)
    {
        char drain[4096];
        while (read(m_splice_pipe[0], drain, sizeof(drain)) > 0) {}
    }
}

void server_instance::handle_splice_in(struct io_uring_cqe* cqe, server_connection* conn)
{
    // The file→pipe op is done: it no longer names this connection's request.
    conn->splice_in_pending = false;

    if (SOCKETLEY_UNLIKELY(cqe->res <= 0 || conn->closing))
    {
        splice_cleanup(conn);
        if (conn->closing && !conn_ops_pending(conn))
            close_conn(conn);
        return;
    }

    auto bytes_in = static_cast<size_t>(cqe->res);
    conn->splice_remaining -= bytes_in;
    conn->splice_pipe_pending = static_cast<uint32_t>(bytes_in);

    // Submit pipe→socket splice
    conn->splice_out_req = { this, nullptr, conn->fd, conn->splice_pipe_pending, op_splice,
                             conn->generation };
    conn->splice_out_pending =
        m_loop->submit_splice(m_splice_pipe[0], conn->fd, conn->splice_pipe_pending, &conn->splice_out_req);
    if (SOCKETLEY_UNLIKELY(!conn->splice_out_pending))
    {
        // The bytes are in the pipe and nothing will move them; the drain in
        // splice_cleanup is what keeps them out of the next response.
        splice_cleanup(conn);
        conn->closing = true;
        if (!conn_ops_pending(conn))
            close_conn(conn);
    }
}

void server_instance::handle_splice_out(struct io_uring_cqe* cqe, server_connection* conn)
{
    conn->splice_out_pending = false;

    if (SOCKETLEY_UNLIKELY(cqe->res <= 0 || conn->closing))
    {
        splice_cleanup(conn);
        if (conn->closing && !conn_ops_pending(conn))
            close_conn(conn);
        return;
    }

    m_stat_bytes_out.fetch_add(static_cast<uint64_t>(cqe->res), std::memory_order_relaxed);

    auto bytes_out = static_cast<uint32_t>(cqe->res);
    conn->splice_pipe_pending -= bytes_out;

    if (conn->splice_pipe_pending > 0)
    {
        // Short write to socket — resubmit remaining pipe→socket
        conn->splice_out_req = { this, nullptr, conn->fd, conn->splice_pipe_pending, op_splice,
                                 conn->generation };
        conn->splice_out_pending =
            m_loop->submit_splice(m_splice_pipe[0], conn->fd, conn->splice_pipe_pending, &conn->splice_out_req);
        if (SOCKETLEY_UNLIKELY(!conn->splice_out_pending))
        {
            splice_cleanup(conn);
            conn->closing = true;
            if (!conn_ops_pending(conn))
                close_conn(conn);
        }
        return;
    }

    if (conn->splice_remaining > 0)
    {
        // More file data to transfer — submit next file→pipe chunk
        uint32_t chunk = static_cast<uint32_t>(std::min(conn->splice_remaining, size_t(UINT32_MAX)));
        conn->splice_in_req = { this, nullptr, conn->fd, chunk, op_splice, conn->generation };
        conn->splice_in_pending =
            m_loop->submit_splice(conn->splice_file_fd, m_splice_pipe[1], chunk, &conn->splice_in_req);
        if (SOCKETLEY_UNLIKELY(!conn->splice_in_pending))
        {
            splice_cleanup(conn);
            conn->closing = true;
            if (!conn_ops_pending(conn))
                close_conn(conn);
        }
        return;
    }

    // Splice complete — clean up and handle keep-alive
    splice_cleanup(conn);

    if (!conn->http_keep_alive)
    {
        conn->closing = true;
        // splice_cleanup() has just cleared the last splice flag, so this is the
        // write completion for the file path: same moment, same reasoning.
        maybe_shutdown_write(conn);
    }
    else
    {
        conn->proto = proto_unknown;
        if (!conn->read_pending)
            submit_conn_read(conn);

        // Last statement, and that is the whole contract: parse_partial() can
        // dispatch a request that arms the next splice on this same connection,
        // so anything after it would be operating on the next response's state.
        // The request it finds here arrived while splice_out_pending was set --
        // the pipe->socket completion lands after the client already holds the
        // whole response, so its next request has had time to arrive and be
        // deferred.  That is the one the client is waiting for.
        parse_partial(conn);
    }
}

// One recvmsg at a time, always.  It reads into m_udp_recv->buf and writes the
// sender into m_udp_recv->addr, both single-instance, so a second one armed
// beside it gives the kernel two writers into the same buffer and the same
// sockaddr: datagrams interleave and replies go to the wrong peer.
void server_instance::arm_udp_recv()
{
    if (!m_loop || m_udp_fd < 0)
    {
        m_udp_recv_armed = false;
        return;
    }
    m_udp_recv->msg.msg_namelen = sizeof(m_udp_recv->addr);
    m_udp_recv_armed = m_loop->submit_recvmsg(m_udp_fd, &m_udp_recv->msg, &m_udp_recv->req);
}

void server_instance::handle_udp_read(struct io_uring_cqe* cqe)
{
    // Whatever else happens below, the op that produced this is finished.
    m_udp_recv_armed = false;

    if (cqe->res <= 0)
    {
        arm_udp_recv();  // Resubmit on error
        return;
    }

    // Register peer if new; skip processing if peer list is full
    if (find_or_add_peer(m_udp_recv->addr) < 0)
    {
        arm_udp_recv();
        return;
    }

    // Extract message — whole datagram = one message
    std::string_view msg(m_udp_recv->buf, static_cast<size_t>(cqe->res));

    // Strip trailing newline if present
    if (!msg.empty() && msg.back() == '\n')
    {
        msg.remove_suffix(1);
        if (!msg.empty() && msg.back() == '\r')
            msg.remove_suffix(1);
    }

    if (!msg.empty())
        process_message(nullptr, msg);

    // A datagram is its own read, so this is where its cache batch goes.  Not
    // reachable through the label in handle_read: UDP has no connection and
    // does not go near it.
    if (SOCKETLEY_UNLIKELY(!m_cache_store_batch.empty()))
        flush_cache_store();

    // Resubmit for next datagram
    arm_udp_recv();
}

void server_instance::udp_broadcast(std::string_view msg, const struct sockaddr_in* exclude)
{
    if (m_udp_fd < 0)
        return;

    for (auto& peer : m_udp_peers)
    {
        if (exclude &&
            peer.addr.sin_addr.s_addr == exclude->sin_addr.s_addr &&
            peer.addr.sin_port == exclude->sin_port)
            continue;

        sendto(m_udp_fd, msg.data(), msg.size(), MSG_DONTWAIT,
               reinterpret_cast<const struct sockaddr*>(&peer.addr), sizeof(peer.addr));
    }
}

bool server_instance::lua_disconnect(int client_fd)
{
    auto* conn = (client_fd >= 0 && client_fd < MAX_FDS)
                 ? m_conn_idx[client_fd] : nullptr;
    if (!conn || conn->closing) return false;
    conn->closing = true;
    // SHUT_RD only: keeps the write side open so any queued message
    // (e.g. "AUTH FAIL" sent just before disconnect) still reaches the client.
    // If a pending read CQE exists, SHUT_RD triggers its EOF so handle_read
    // can clean up. If no ops are pending, handle_read's submit_next_read
    // branch handles the cleanup when it sees closing=true, write_pending=false.
    shutdown(client_fd, SHUT_RD);
    return true;
}

std::string server_instance::lua_peer_ip(int client_fd)
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

void server_instance::set_on_websocket(std::function<void(int fd, const ws_headers_result&)> cb)
{
    m_cb_on_websocket = std::move(cb);
}

void server_instance::invoke_on_websocket(int fd)
{
    if (m_cb_on_websocket)
    {
        auto hdrs = lua_ws_headers(fd);
        m_cb_on_websocket(fd, hdrs);
        return;
    }
#ifndef SOCKETLEY_NO_LUA
    auto* lctx = lua();
    if (!lctx || !lctx->has_on_websocket()) return;
    auto* conn = (fd >= 0 && fd < MAX_FDS) ? m_conn_idx[fd] : nullptr;
    if (!conn) return;
    sol::table h = lctx->state().create_table();
    if (!conn->ws_cookie.empty())   h["cookie"]        = conn->ws_cookie;
    if (!conn->ws_origin.empty())   h["origin"]        = conn->ws_origin;
    if (!conn->ws_protocol.empty()) h["protocol"]      = conn->ws_protocol;
    if (!conn->ws_auth.empty())     h["authorization"] = conn->ws_auth;

    sol::protected_function_result r = lctx->on_websocket()(fd, h);
    if (SOCKETLEY_UNLIKELY(!r.valid()))
    {
        sol::error e = r;
        fprintf(stderr, "%s on_websocket error: %s\n",
                lua_diag::tag(get_name()).c_str(), e.what());
    }
#endif
}

server_instance::ws_headers_result server_instance::lua_ws_headers(int client_fd) const
{
    if (client_fd < 0 || client_fd >= MAX_FDS) return {};
    const auto* conn = m_conn_idx[client_fd];
    if (!conn || conn->proto != proto_ws) return {};
    return {true, conn->ws_cookie, conn->ws_origin, conn->ws_protocol, conn->ws_auth};
}

bool server_instance::lua_send_to(int client_id, std::string_view msg)
{
    if (!m_loop || m_udp)
        return false;

    // This used to try its own connection table first and fall back to the
    // forwarded one, which is only unambiguous while the two ranges cannot
    // overlap — and they overlap by construction the moment the two runtimes
    // are separate processes, because both number their descriptors from zero.
    // A forwarded id that happened to equal one of this runtime's own
    // descriptors delivered to the wrong client, silently.
    //
    // The two ranges cannot meet now, so there is no order to get right:
    // send_to_client() reads which kind of id this is and asks the right
    // runtime.
    return send_to_client(client_id, msg);
}

// The server-specific half of `stats`.  peak_connections and the upstream
// count are computed from a connection table that lives in whichever process
// the runtime is in, so this is the part a worker still pushes; the counters
// above it are summed out of shared memory by whoever prints them.
//
// The ring lines are in stats_ring() and are pushed with this one, which is
// what keeps them the WORKER's: they depend on the worker being told the
// daemon's ring policy — see proxy_supervisor::spawn().  Without that, the
// worker reported its loop's configuration rather than the daemon's: pinned by
// an inherited affinity mask while printing cpus:max.
std::string server_instance::stats_extra() const
{
    std::ostringstream out;
    out << "peak_connections:" << m_stat_peak_connections << "\n"
        << "mode:" << static_cast<int>(m_mode) << "\n"
        << "udp:" << (m_udp ? "true" : "false") << "\n";
    if (m_mode == mode_master)
        out << "master_fd:" << m_master_fd << "\n";
    if (!m_upstream_targets.empty())
    {
        size_t connected = 0;
        for (const auto& [_, uc] : m_upstreams)
            if (uc->connected) ++connected;
        out << "upstreams:" << connected << "/" << m_upstream_targets.size() << "\n";
    }
    // The cross-runtime request queue, and in particular what it had to throw
    // away.  Daemon-wide rather than per-server, but this is where anyone
    // linked to a cache will look: a `--cache` auto-store batch that could not
    // be queued is a run of messages that are not in the cache, and a figure
    // nobody can see is a loss nobody can act on.
    if (!get_cache_name().empty())
    {
        if (const auto* mgr = get_runtime_manager())
        {
            const auto& rq = mgr->requests();
            out << "cache_requests:" << rq.stat_posted() << "\n"
                << "cache_requests_pending:" << rq.pending() << "\n"
                << "cache_requests_refused:" << rq.stat_refused() << "\n"
                << "cache_store_batches_dropped:" << rq.stat_dropped_bg() << "\n";
        }
    }
    return out.str();
}

// ─── Client Routing ───

// ── The Lua-facing half ─────────────────────────────────────────────────────

bool server_instance::route_client(int client_id, std::string_view target_name)
{
    // A connection that was routed *here* is not ours to route on.  It used to
    // be indistinguishable from one of our own — both were "an int" — so this
    // was reachable and did something incoherent: it wrote a route for a
    // descriptor number belonging to a third runtime.
    if (is_conn_handle(client_id))
        return false;

    const conn_ref ref = ref_for_fd(client_id);
    if (!ref.valid())
        return false;

    auto* mgr = get_runtime_manager();
    if (!mgr) return false;

    auto* target = mgr->get(target_name);
    if (!target) return false;

    // Our own bookkeeping first, the notification second.  accept_routed runs
    // the target's on_connect, and a script is allowed to answer that by
    // closing the connection — which frees the struct m_conn_idx[client_id]
    // points at.  Touching that pointer afterwards would be a read of a pooled
    // connection at best.
    auto* sub = target->as_server();
    if (!sub) return false;
    m_routes[ref.serial] = std::string(target_name);
    m_conn_idx[client_id]->routed = true;

    if (sub->accept_routed(ref, get_name()) >= 0)
        return true;

    // Refused.  Undo, and find the connection by name rather than by the
    // descriptor we were given: nothing ran in between here, but the rule that
    // a descriptor is not an identity does not get suspended for rollback.
    m_routes.erase(ref.serial);
    if (auto it = m_conn_by_serial.find(ref.serial); it != m_conn_by_serial.end())
    {
        const int fd = it->second;
        if (fd >= 0 && fd < MAX_FDS && m_conn_idx[fd] &&
            m_conn_idx[fd]->ref_serial == ref.serial)
            m_conn_idx[fd]->routed = false;
    }
    return false;
}

bool server_instance::unroute_client(int client_id)
{
    if (is_conn_handle(client_id))
        return false;
    if (client_id < 0 || client_id >= MAX_FDS || !m_conn_idx[client_id])
        return false;

    const uint64_t serial = m_conn_idx[client_id]->ref_serial;
    auto it = m_routes.find(serial);
    if (it == m_routes.end()) return false;

    // Everything read out of the map and the map left consistent before
    // anything else is called.  release_routed runs the target's on_disconnect,
    // a script may answer that by unrouting again, and a second pass through
    // here holding `it` would be using an erased iterator.
    const std::string target_name = it->second;
    m_routes.erase(it);
    m_conn_idx[client_id]->routed = false;

    auto* mgr = get_runtime_manager();
    if (mgr)
    {
        auto* target = mgr->get(target_name);
        if (auto* srv = target ? target->as_server() : nullptr)
            srv->release_routed(conn_ref{owner_key(), serial});
    }
    return true;
}

std::string_view server_instance::get_client_route(int client_id) const
{
    if (is_conn_handle(client_id) || client_id < 0 || client_id >= MAX_FDS ||
        !m_conn_idx[client_id])
        return {};

    auto it = m_routes.find(m_conn_idx[client_id]->ref_serial);
    if (it == m_routes.end()) return {};
    return it->second;
}

// Whether the bytes were handed to a connection.
//
// It was void, and every `return;` below was a message that went nowhere with
// nothing said: a handle naming a connection that has since gone, an origin
// runtime that has stopped, a descriptor that is not a connection, a
// connection already closing.  self.send() reported none of them because it
// had nothing to report with.
bool server_instance::send_to_client(int client_id, std::string_view msg)
{
    // A handle names a connection that lives somewhere else, so the write is
    // asked of whoever owns it rather than performed here.
    if (SOCKETLEY_UNLIKELY(is_conn_handle(client_id)))
    {
        auto it = m_forwarded.find(client_id);
        if (it == m_forwarded.end()) return false;
        const conn_ref ref = it->second.ref;

        // ─── A sibling shard of THIS runtime ────────────────────────────────
        //
        // Checked before the manager, because the manager cannot answer it: in
        // a worker every other runtime is a replica with no connections, and
        // this runtime's own name resolves to the copy in THIS process — which
        // does not hold the connection either.  What names the holder is the
        // ref itself: same owner as ours, a different shard in its top six
        // bits.  See conn_identity.h.
        if (ref.owner == owner_key()
            && conn_ref_shard(ref) != get_shard_index()
            && has_ref_sink())
        {
            send_to_ref(ref, msg);
            // Queued, which is what "sent" means on this path everywhere else
            // in this file — the in-process branch below says so in its own
            // words.  What has been established is that the id named a
            // connection this runtime has; whether the far shard still has it
            // is answered there, by write_to_ref, exactly as it would be here.
            return true;
        }

        auto* mgr = get_runtime_manager();
        if (!mgr) return false;
        auto* origin = mgr->get(it->second.origin);
        if (!origin || origin->get_state() != runtime_running) return false;
        auto* srv = origin->as_server();
        if (!srv) return false;

        return srv->write_to_ref(ref, msg);
    }

    if (SOCKETLEY_UNLIKELY(client_id < 0 || client_id >= MAX_FDS || !m_conn_idx[client_id])) return false;
    auto* conn = m_conn_idx[client_id];
    if (SOCKETLEY_UNLIKELY(conn->closing)) return false;

    std::string buf;
    buf.reserve(msg.size() + 1);
    buf.append(msg);
    if (buf.empty() || buf.back() != '\n') buf.push_back('\n');
    auto shared = std::make_shared<const std::string>(std::move(buf));
    send_to(conn, shared);
    // Queued, which is what "sent" means on an async write path everywhere else
    // in this file.  send_to() can still close the connection for exceeding the
    // write-queue bound, and that is reported by the connection going away
    // rather than by this call.
    return true;
}

bool server_instance::owner_send(int client_id, std::string_view msg)
{
    // Resolved through what was actually routed here, not through get_owner()
    // and a number.  The old form took any integer, looked up the configured
    // owner, and wrote into that runtime's connection table at that index — so
    // a sub-server could write to any of the owner's clients, including the one
    // that had inherited the descriptor number of the client this id used to
    // name.  A handle that names nothing here now answers false.
    auto it = m_forwarded.find(client_id);
    if (it == m_forwarded.end())
        return false;

    auto* mgr = get_runtime_manager();
    if (!mgr) return false;

    auto* origin = mgr->get(it->second.origin);
    if (!origin || origin->get_state() != runtime_running) return false;
    auto* srv = origin->as_server();
    if (!srv) return false;

    return srv->write_to_ref(it->second.ref, msg);
}

// ── The cross-runtime half ──────────────────────────────────────────────────

int server_instance::accept_routed(const conn_ref& ref, std::string_view origin_name)
{
    if (!ref.valid())
        return -1;

    // Idempotent.  A route asked for twice is one route, and answering with the
    // handle already in use means a caller that lost the first answer can ask
    // again — which is what a retry over a socket looks like.
    if (auto it = m_forwarded_by_ref.find(ref); it != m_forwarded_by_ref.end())
        return it->second;

    const int handle = alloc_handle();
    if (handle < 0)
        return -1;

    m_forwarded.emplace(handle, forwarded_client{ref, std::string(origin_name)});
    m_forwarded_by_ref.emplace(ref, handle);

    // The script hears about a client, and the integer it is handed is one it
    // can hand back — to owner_send, to send_to, to anything taking a client
    // id.  What it cannot do is collide with one of this runtime's own
    // descriptors, which is what used to make the two indistinguishable.
    invoke_on_connect(handle);
    return handle;
}

void server_instance::release_routed(const conn_ref& ref)
{
    auto it = m_forwarded_by_ref.find(ref);
    if (it == m_forwarded_by_ref.end())
        return;

    const int handle = it->second;

    // The name goes first, so a second release for the same connection — which
    // is what an origin retrying, or a script unrouting from inside its own
    // on_disconnect, looks like — finds nothing and does not fire the callback
    // twice.  The handle stays resolvable across the callback, so a script that
    // answers a disconnect by writing gets a clean false out of write_to_ref
    // rather than a lookup into an empty table.
    m_forwarded_by_ref.erase(it);
    invoke_on_disconnect(handle);
    m_forwarded.erase(handle);
}

void server_instance::deliver_routed(const conn_ref& ref, std::string_view msg)
{
    auto it = m_forwarded_by_ref.find(ref);
    if (it == m_forwarded_by_ref.end())
        return;

    m_stat_total_messages.fetch_add(1, std::memory_order_relaxed);
    invoke_on_client_message(it->second, msg);
    invoke_on_message(msg);
}

bool server_instance::write_to_ref(const conn_ref& ref, std::string_view msg)
{
    // Someone else's name for one of our connections.  Three things have to
    // hold and the descriptor version checked none of them: that the name is
    // ours to resolve at all, that it still resolves, and that what it resolves
    // to is the same connection it named when it was minted.
    if (!ref.valid() || ref.owner != owner_key())
        return false;

    auto it = m_conn_by_serial.find(ref.serial);
    if (it == m_conn_by_serial.end())
        return false;

    const int fd = it->second;
    if (fd < 0 || fd >= MAX_FDS)
        return false;

    auto* conn = m_conn_idx[fd];
    if (!conn || conn->ref_serial != ref.serial || conn->closing)
        return false;

    std::string buf;
    buf.reserve(msg.size() + 1);
    buf.append(msg);
    if (buf.empty() || buf.back() != '\n') buf.push_back('\n');
    auto shared = std::make_shared<const std::string>(std::move(buf));
    send_to(conn, shared);
    return true;
}

void server_instance::drop_route(const conn_ref& ref)
{
    if (ref.owner != owner_key())
        return;

    if (m_routes.erase(ref.serial) == 0)
        return;

    // And the cached flag on the connection itself, which the previous version
    // of this cleanup left set: the read path then took the routed branch on
    // every message, found nothing, and fell through — a lookup per message for
    // the rest of the connection's life, for a route that no longer existed.
    auto it = m_conn_by_serial.find(ref.serial);
    if (it == m_conn_by_serial.end())
        return;
    const int fd = it->second;
    if (fd >= 0 && fd < MAX_FDS && m_conn_idx[fd] &&
        m_conn_idx[fd]->ref_serial == ref.serial)
        m_conn_idx[fd]->routed = false;
}

int server_instance::alloc_handle()
{
    // Handles are 32-bit and start high, so the counter has about two billion
    // routes in it before it runs out.  A daemon that reaches that is still
    // owed a correct answer rather than a negative handle that would read as
    // "not a handle" everywhere it is tested.
    for (int tries = 0; tries < 1024; ++tries)
    {
        if (m_next_handle < conn_handle_base)
            m_next_handle = conn_handle_base;
        const int h = m_next_handle++;
        if (m_forwarded.find(h) == m_forwarded.end())
            return h;
    }
    return -1;
}

bool server_instance::owner_broadcast(std::string_view msg)
{
    auto owner_name = get_owner();
    if (owner_name.empty()) return false;

    auto* mgr = get_runtime_manager();
    if (!mgr) return false;

    // The one site of the nine reachable in a worker without a routed
    // connection: a runtime's owner is a name it was created with, and a worker
    // now holds a replica of every name in the daemon.  Before as_server() this
    // found nothing at all out there and answered false; with the replica map
    // and the old cast it would have run server_instance's code over a replica.
    auto* parent = mgr->get(owner_name);
    if (!parent || parent->get_state() != runtime_running) return false;
    auto* srv = parent->as_server();
    if (!srv) return false;

    srv->lua_broadcast(msg);
    return true;
}

int server_instance::find_or_add_peer(const struct sockaddr_in& addr)
{
    uint64_t key = (static_cast<uint64_t>(addr.sin_addr.s_addr) << 16) |
                    static_cast<uint64_t>(addr.sin_port);
    auto it = m_udp_peer_idx.find(key);
    if (it != m_udp_peer_idx.end())
        return it->second;

    if (m_udp_peers.size() >= MAX_UDP_PEERS)
        return -1;

    int idx = static_cast<int>(m_udp_peers.size());
    m_udp_peers.push_back({addr});
    m_udp_peer_idx[key] = idx;
    return idx;
}

// ─── Lua client enumeration ───

// Every client of this RUNTIME, not of this process.
//
// The descriptors this shard owns come back unchanged, because every script in
// existence treats them as opaque and they are what on_connect handed out.  A
// sibling's client has no descriptor here to be, so it comes back as a handle
// out of conn_identity.h's reserved range — the same mechanism a client routed
// in from another runtime already uses, and the reason that range exists.
//
// Not const any more: a handle for a sibling's connection is minted the first
// time it is asked for and kept, so the same client is the same number to a
// script that calls this twice.
std::vector<int> server_instance::lua_clients()
{
    if (!shard_clients_table().mapped())
        return m_active_fds;

    std::vector<conn_ref> foreign;
    const bool complete = shard_clients_table().read_others(foreign, shard_clients_table().index());
    if (!complete)
    {
        // A block that could not be read within its retry bound.  Said out
        // loud: a script handed a short list with no indication is exactly the
        // failure this whole step exists to remove, and the alternative to
        // saying so is becoming the thing being fixed.
        LOG_WARN(("self.clients() on " + std::string(get_name())
                  + " could not read one shard's client list; the list below "
                    "is missing it").c_str());
    }

    std::vector<int> out = m_active_fds;
    out.reserve(out.size() + foreign.size());

    std::unordered_set<conn_ref, conn_ref_hash> live;
    live.reserve(foreign.size() * 2);

    for (const conn_ref& r : foreign)
    {
        live.insert(r);
        out.push_back(handle_for_sibling_ref(r));
    }

    // Handles for siblings' connections that have since gone.  Pruned here
    // rather than never, because m_forwarded would otherwise grow for the life
    // of the runtime — one entry per connection any sibling ever accepted.
    //
    // Only the ones minted HERE: an entry whose origin is another runtime
    // belongs to route(), which owns its own lifetime, and dropping one of
    // those would unroute a client nobody asked to unroute.
    for (auto it = m_forwarded.begin(); it != m_forwarded.end();)
    {
        if (it->second.origin == get_name() && live.find(it->second.ref) == live.end())
        {
            m_forwarded_by_ref.erase(it->second.ref);
            it = m_forwarded.erase(it);
        }
        else
            ++it;
    }

    return out;
}

// A stable local number for a connection a sibling shard owns.
//
// Stable is the whole point: a script that calls self.clients() twice and
// compares must get the same number for the same client, or every id it stores
// is worthless.  m_forwarded_by_ref is what makes it stable, and it is the same
// table route() uses — the origin is this runtime's own name, which is what
// tells the two apart when one is pruned and the other is not.
int server_instance::handle_for_sibling_ref(const conn_ref& r)
{
    if (const auto it = m_forwarded_by_ref.find(r); it != m_forwarded_by_ref.end())
        return it->second;

    const int h = alloc_handle();
    if (h < 0)
        return h;
    m_forwarded[h] = forwarded_client{r, std::string(get_name())};
    m_forwarded_by_ref[r] = h;
    return h;
}

// How many of the named connections the message was queued to.
//
// Ids that name nothing are still skipped, as they always were — what changes
// is that the caller is told how many were skipped rather than having to
// assume none were.  A malformed LIST is refused by the binding before this is
// reached; this count is about ids that were well-formed and stale, which is
// ordinary and not an error.
size_t server_instance::lua_multicast(const std::vector<int>& fds, std::string_view msg)
{
    if (!m_loop || m_udp) return 0;
    auto shared = std::make_shared<const std::string>(msg);
    size_t sent = 0;
    for (int fd : fds)
    {
        if (fd < 0 || fd >= MAX_FDS) continue;
        auto* conn = m_conn_idx[fd];
        if (!conn || conn->closing) continue;
        send_to(conn, shared);
        ++sent;
    }
    return sent;
}

// ─── Lua per-connection metadata ───

bool server_instance::lua_set_data(int fd, std::string_view key, std::string_view val)
{
    if (fd < 0 || fd >= MAX_FDS || !m_conn_idx[fd]) return false;
    m_conn_idx[fd]->meta[std::string(key)] = std::string(val);
    return true;
}

bool server_instance::lua_del_data(int fd, std::string_view key)
{
    if (fd < 0 || fd >= MAX_FDS || !m_conn_idx[fd]) return false;
    m_conn_idx[fd]->meta.erase(std::string(key));
    return true;
}

std::string server_instance::lua_get_data(int fd, std::string_view key) const
{
    if (fd < 0 || fd >= MAX_FDS || !m_conn_idx[fd]) return "";
    const auto& m = m_conn_idx[fd]->meta;
    auto it = m.find(std::string(key));
    return (it != m.end()) ? it->second : "";
}

// ─── Multicast Groups ───

void server_instance::remove_from_all_groups(int fd)
{
    if (fd < 0 || fd >= MAX_FDS || !m_conn_idx[fd]) return;
    auto* conn = m_conn_idx[fd];
    for (const auto& g : conn->groups)
    {
        auto it = m_groups.find(g);
        if (it != m_groups.end())
        {
            auto& vec = it->second;
            vec.erase(std::remove(vec.begin(), vec.end(), fd), vec.end());
            if (vec.empty())
                m_groups.erase(it);
        }
    }
    conn->groups.clear();
}

bool server_instance::lua_join_group(int fd, std::string_view group)
{
    if (fd < 0 || fd >= MAX_FDS || !m_conn_idx[fd]) return false;
    auto* conn = m_conn_idx[fd];
    std::string gname(group);

    // Check if already in group
    // Already a member is not a failure: join is idempotent, and a script that
    // joins on every message must not read `false` as "it did not work".
    for (const auto& g : conn->groups)
        if (g == gname) return true;

    conn->groups.push_back(gname);
    m_groups[gname].push_back(fd);
    return true;
}

bool server_instance::lua_leave_group(int fd, std::string_view group)
{
    if (fd < 0 || fd >= MAX_FDS || !m_conn_idx[fd]) return false;
    auto* conn = m_conn_idx[fd];
    std::string gname(group);

    // Remove from conn's group list
    conn->groups.erase(
        std::remove(conn->groups.begin(), conn->groups.end(), gname),
        conn->groups.end());

    // Remove from global group
    auto it = m_groups.find(gname);
    if (it != m_groups.end())
    {
        auto& vec = it->second;
        vec.erase(std::remove(vec.begin(), vec.end(), fd), vec.end());
        if (vec.empty())
            m_groups.erase(it);
    }
    return true;
}

// How many connections the message was queued to.
//
// A count and not a bool, because the interesting failure is not "no such
// group" — it is "the group exists and has nobody left in it", which is what a
// misspelled group name looks like the moment its last real member leaves.
// Zero says that; a bool cannot.
size_t server_instance::lua_group_send(std::string_view group, std::string_view msg)
{
    if (!m_loop) return 0;
    auto it = m_groups.find(std::string(group));
    if (it == m_groups.end()) return 0;

    // Build newline-terminated message (single allocation, shared across all recipients)
    std::string buf;
    buf.reserve(msg.size() + 1);
    buf.append(msg);
    if (buf.empty() || buf.back() != '\n')
        buf.push_back('\n');
    auto shared_msg = std::make_shared<const std::string>(std::move(buf));

    size_t sent = 0;
    for (int fd : it->second)
    {
        auto* conn = (fd >= 0 && fd < MAX_FDS) ? m_conn_idx[fd] : nullptr;
        if (!conn || conn->closing) continue;
        if (conn->write_queue.bytes() >= socketley::write_queue_max_bytes)
        {
            conn->closing = true;
            continue;
        }
        send_to(conn, shared_msg);
        ++sent;
    }
    return sent;
}

bool server_instance::lua_pipe(int fd_a, int fd_b)
{
    if (!m_loop || fd_a == fd_b) return false;
    auto* a = (fd_a >= 0 && fd_a < MAX_FDS) ? m_conn_idx[fd_a] : nullptr;
    auto* b = (fd_b >= 0 && fd_b < MAX_FDS) ? m_conn_idx[fd_b] : nullptr;
    if (!a || !b || a->closing || b->closing) return false;

    // Unpipe any existing pairings first
    if (a->pipe_peer_fd >= 0) lua_unpipe(fd_a);
    if (b->pipe_peer_fd >= 0) lua_unpipe(fd_b);

    a->pipe_peer_fd = fd_b;
    b->pipe_peer_fd = fd_a;
    return true;
}

bool server_instance::lua_unpipe(int fd)
{
    auto* conn = (fd >= 0 && fd < MAX_FDS) ? m_conn_idx[fd] : nullptr;
    if (!conn || conn->pipe_peer_fd < 0) return false;

    int peer_fd = conn->pipe_peer_fd;
    conn->pipe_peer_fd = -1;

    auto* peer = (peer_fd >= 0 && peer_fd < MAX_FDS) ? m_conn_idx[peer_fd] : nullptr;
    if (peer && peer->pipe_peer_fd == fd)
        peer->pipe_peer_fd = -1;
    return true;
}

// ─── Upstream Connections ───

bool server_instance::upstream_try_connect(upstream_connection* uc)
{
    if (!m_loop)
        return false;

    const auto& host = uc->target.resolved_host;
    uint16_t port = uc->target.resolved_port;
    if (host.empty() || port == 0)
        return false;

    // Resolve the endpoint once and keep it.  Two things matter here: a literal
    // address needs no resolver at all, and a name that has been resolved once
    // must not be looked up again on every reconnect.  Both lookups happen on
    // the event loop thread, where they stall everything else this runtime is
    // serving for as long as the resolver takes.
    if (!uc->has_cached_addr)
    {
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);

        if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) == 1)
        {
            uc->cached_addr = addr;
            uc->has_cached_addr = true;
        }
        else
        {
            struct addrinfo hints{}, *addrs = nullptr;
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            char port_buf[8];
            auto [pe, pec] = std::to_chars(port_buf, port_buf + sizeof(port_buf), port);
            *pe = '\0';
            if (getaddrinfo(host.c_str(), port_buf, &hints, &addrs) != 0 || !addrs)
                return false;
            if (addrs->ai_addrlen == sizeof(struct sockaddr_in))
            {
                std::memcpy(&uc->cached_addr, addrs->ai_addr, sizeof(struct sockaddr_in));
                uc->has_cached_addr = true;
            }
            freeaddrinfo(addrs);
            if (!uc->has_cached_addr)
                return false;
        }
    }

    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return false;

    int opt = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    if (connect(fd, reinterpret_cast<const struct sockaddr*>(&uc->cached_addr),
                sizeof(uc->cached_addr)) < 0 && errno != EINPROGRESS)
    {
        close_tracked(fd);
        return false;
    }

    uc->fd = fd;
    uc->connected = true;
    uc->closing = false;
    uc->reconnect_attempt = 0;
    uc->partial.clear();
    uc->partial.reserve(4096);
    uc->read_pending = false;
    uc->write_pending = false;
    // A new socket is a new identity: this descriptor number may have belonged
    // to an accepted client a moment ago, and completions for that client can
    // still be on their way.
    uc->generation = next_io_generation();

    m_upstream_by_fd[fd] = uc;

    uc->read_req = { this, uc->read_buf, fd, sizeof(uc->read_buf), op_read, uc->generation };
    uc->write_req = { this, nullptr, fd, 0, op_write, uc->generation };

    // Submit first read
    uc->read_pending = true;
    // Nothing queued means no completion will arrive; leaving the flag up would
    // wedge this upstream connection for the life of the runtime.
    if (SOCKETLEY_UNLIKELY(!m_loop->submit_read(fd, uc->read_buf, sizeof(uc->read_buf), &uc->read_req)))
    {
        uc->read_pending = false;
        uc->closing = true;
    }

    // Fire on_upstream_connect callback
    invoke_on_upstream_connect(uc->conn_id);

    return true;
}

void server_instance::upstream_schedule_reconnect(upstream_connection* uc)
{
    // Not while one is already counting down: the timer request is a single
    // slot on this struct, and re-arming it while the kernel still holds it
    // gives one upstream two reconnect chains.
    if (!m_loop || uc->timeout_pending)
        return;

    // Exponential backoff: min(1s * 2^attempt, 30s) with jitter
    int base_sec = 1 << std::min(uc->reconnect_attempt, 4); // 1,2,4,8,16
    int delay_sec = std::min(base_sec, 30);
    int jitter_ms = (uc->reconnect_attempt * 137) % 500;

    uc->timeout_ts.tv_sec = delay_sec;
    uc->timeout_ts.tv_nsec = jitter_ms * 1000000LL;
    uc->timeout_req = { this, nullptr, -1, 0, op_timeout, uc->generation };
    uc->timeout_pending = m_loop->submit_timeout(&uc->timeout_ts, &uc->timeout_req);
}

void server_instance::upstream_disconnect(upstream_connection* uc)
{
    if (uc->fd >= 0)
    {
        m_upstream_by_fd.erase(uc->fd);
        shutdown(uc->fd, SHUT_RDWR);
        close_tracked(uc->fd);
        uc->fd = -1;
    }

    bool was_connected = uc->connected;
    uc->connected = false;
    uc->closing = false;
    uc->read_pending = false;
    uc->write_pending = false;
    uc->partial.clear();

    // Release write queue refs
    uc->write_queue.clear();
    for (size_t i = 0; i < uc->write_batch_count; i++)
        uc->write_batch[i].reset();
    uc->write_batch_count = 0;

    if (was_connected)
        invoke_on_upstream_disconnect(uc->conn_id);

    // Schedule reconnect
    upstream_schedule_reconnect(uc);
}

void server_instance::handle_upstream_read(struct io_uring_cqe* cqe, upstream_connection* uc)
{
    uc->read_pending = false;

    if (cqe->res <= 0)
    {
        // EOF or error
        if (uc->write_pending)
        {
            uc->closing = true;
        }
        else
        {
            upstream_disconnect(uc);
        }
        return;
    }

    m_stat_bytes_in.fetch_add(static_cast<uint64_t>(cqe->res), std::memory_order_relaxed);
    uc->partial.append(uc->read_buf, cqe->res);

    if (uc->partial.size() > upstream_connection::MAX_PARTIAL_SIZE)
    {
        uc->closing = true;
        goto submit_next;
    }

    // Parse newline-delimited messages
    {
        size_t scan_from = 0;
        size_t pos;
        while ((pos = uc->partial.find('\n', scan_from)) != std::string::npos)
        {
            std::string_view line(uc->partial.data() + scan_from, pos - scan_from);
            if (!line.empty() && line.back() == '\r')
                line.remove_suffix(1);
            if (!line.empty())
                invoke_on_upstream(uc->conn_id, line);
            scan_from = pos + 1;
        }
        if (scan_from > 0)
        {
            if (scan_from >= uc->partial.size())
                uc->partial.clear();
            else
                uc->partial.erase(0, scan_from);
        }
    }

submit_next:
    if (m_loop && !uc->closing)
    {
        uc->read_pending = true;
        if (SOCKETLEY_UNLIKELY(!m_loop->submit_read(uc->fd, uc->read_buf, sizeof(uc->read_buf), &uc->read_req)))
        {
            uc->read_pending = false;
            uc->closing = true;
        }
    }
    else if (uc->closing && !uc->write_pending)
    {
        upstream_disconnect(uc);
    }
}

// ─── UPSTREAMS ARE OUTSIDE THE CHOKEPOINT, AND THIS IS WHY ──────────────────
//
// The guard below is the same shape as the one on the client side that stranded
// a connection: mark closing, then defer the teardown to an armed read.  It is
// nevertheless left alone, and finish_unreachable_conn() cannot reach it anyway
// — an upstream's fd lives in m_upstream_by_fd, never in m_conn_idx, which is
// the only table that function looks in.
//
// That is a decision rather than an oversight, and it rests on the same property
// that excuses the proxy and the client: an upstream read is armed with
// submit_read(uc->fd, ...) — SINGLE-SHOT, on the DESCRIPTOR, never multishot and
// never on a fixed-file index.  So close_fd() can withdraw it and the socket's
// own error reaches it, which is exactly what a fixed-index multishot recv on an
// accepted client cannot promise.  See shared/conn_reachability.h.
//
// NOT MEASURED.  Unlike the proxy and the client, no storm was aimed at an
// upstream, so this rests on the structural argument alone.  A reproducer would
// move it, and the chokepoint would then have to grow a second table lookup
// rather than a second copy of the rule.
void server_instance::handle_upstream_write(struct io_uring_cqe* cqe, upstream_connection* uc)
{
    uc->write_pending = false;

    if (cqe->res <= 0)
    {
        for (uint32_t i = 0; i < uc->write_batch_count; i++)
            uc->write_batch[i].reset();
        uc->write_batch_count = 0;
        uc->closing = true;
        if (!uc->read_pending)
            upstream_disconnect(uc);
        return;
    }

    m_stat_bytes_out.fetch_add(static_cast<uint64_t>(cqe->res), std::memory_order_relaxed);

    // Short write handling: resubmit remaining bytes.
    //
    // The batch used to be released on any positive result, so a kernel that
    // took part of it dropped the rest — the upstream then read a truncated
    // message with the next one appended to it, and every message after that
    // was misframed. The client path a few hundred lines up already did this;
    // upstream connections go through the same writev and need the same care.
    if (uc->write_batch_count > 0)
    {
        size_t total_submitted = 0;
        for (uint32_t i = 0; i < uc->write_batch_count; i++)
            total_submitted += uc->write_iovs[i].iov_len;

        const size_t written = static_cast<size_t>(cqe->res);
        if (written < total_submitted)
        {
            size_t remaining = written;
            uint32_t first_iov = 0;
            for (; first_iov < uc->write_batch_count; first_iov++)
            {
                if (remaining < uc->write_iovs[first_iov].iov_len)
                {
                    uc->write_iovs[first_iov].iov_base =
                        static_cast<char*>(uc->write_iovs[first_iov].iov_base) + remaining;
                    uc->write_iovs[first_iov].iov_len -= remaining;
                    break;
                }
                remaining -= uc->write_iovs[first_iov].iov_len;
            }

            const uint32_t new_count = uc->write_batch_count - first_iov;
            if (first_iov > 0)
            {
                for (uint32_t i = 0; i < new_count; i++)
                {
                    uc->write_iovs[i] = uc->write_iovs[first_iov + i];
                    uc->write_batch[i] = std::move(uc->write_batch[first_iov + i]);
                }
                for (uint32_t i = new_count; i < uc->write_batch_count; i++)
                    uc->write_batch[i].reset();
            }
            uc->write_batch_count = new_count;

            uc->write_pending = true;
            bool requeued;
            if (new_count == 1)
            {
                uc->write_req.type = op_write;
                requeued = m_loop->submit_write(uc->fd,
                    static_cast<const char*>(uc->write_iovs[0].iov_base),
                    static_cast<uint32_t>(uc->write_iovs[0].iov_len), &uc->write_req);
            }
            else
            {
                uc->write_req.type = op_writev;
                requeued = m_loop->submit_writev(uc->fd, uc->write_iovs, new_count, &uc->write_req);
            }
            if (SOCKETLEY_UNLIKELY(!requeued))
            {
                uc->write_pending = false;
                for (uint32_t i = 0; i < uc->write_batch_count; i++)
                    uc->write_batch[i].reset();
                uc->write_batch_count = 0;
                uc->closing = true;
            }
            return;
        }
    }

    // Full write completed — release batch
    for (uint32_t i = 0; i < uc->write_batch_count; i++)
        uc->write_batch[i].reset();
    uc->write_batch_count = 0;

    if (!uc->write_queue.empty())
    {
        upstream_flush_write_queue(uc);
    }
    else if (uc->closing && !uc->read_pending)
    {
        upstream_disconnect(uc);
    }
}

void server_instance::upstream_send(upstream_connection* uc, const std::shared_ptr<const std::string>& msg)
{
    if (!m_loop || !uc->connected || uc->closing)
        return;

    if (uc->write_queue.bytes() >= socketley::write_queue_max_bytes)
    {
        uc->closing = true;
        return;
    }

    uc->write_queue.push(msg);
    if (!uc->write_pending)
        upstream_flush_write_queue(uc);
}

void server_instance::upstream_flush_write_queue(upstream_connection* uc)
{
    if (!m_loop || uc->write_queue.empty())
        return;

    uint32_t count = 0;
    while (!uc->write_queue.empty() && count < upstream_connection::MAX_WRITE_BATCH)
    {
        uc->write_batch[count] = uc->write_queue.take_front();
        uc->write_iovs[count].iov_base = const_cast<char*>(uc->write_batch[count]->data());
        uc->write_iovs[count].iov_len = uc->write_batch[count]->size();
        count++;
    }

    uc->write_batch_count = count;
    uc->write_pending = true;

    bool queued;
    if (count == 1)
    {
        uc->write_req.type = op_write;
        queued = m_loop->submit_write(uc->fd, uc->write_batch[0]->data(),
            static_cast<uint32_t>(uc->write_batch[0]->size()), &uc->write_req);
    }
    else
    {
        uc->write_req.type = op_writev;
        queued = m_loop->submit_writev(uc->fd, uc->write_iovs, count, &uc->write_req);
    }

    if (SOCKETLEY_UNLIKELY(!queued))
    {
        uc->write_pending = false;
        for (uint32_t i = 0; i < uc->write_batch_count; i++)
            uc->write_batch[i].reset();
        uc->write_batch_count = 0;
        uc->closing = true;
    }
}

// ─── Lua upstream actions ───

bool server_instance::lua_upstream_send(int conn_id, std::string_view msg)
{
    auto it = m_upstreams.find(conn_id);
    if (it == m_upstreams.end() || !it->second->connected)
        return false;

    std::string buf;
    buf.reserve(msg.size() + 1);
    buf.append(msg);
    if (buf.empty() || buf.back() != '\n')
        buf.push_back('\n');
    auto shared = std::make_shared<const std::string>(std::move(buf));
    upstream_send(it->second.get(), std::move(shared));
    return true;
}

void server_instance::lua_upstream_broadcast(std::string_view msg)
{
    std::string buf;
    buf.reserve(msg.size() + 1);
    buf.append(msg);
    if (buf.empty() || buf.back() != '\n')
        buf.push_back('\n');
    auto shared = std::make_shared<const std::string>(std::move(buf));
    for (auto& [cid, uc] : m_upstreams)
    {
        if (uc->connected && !uc->closing)
            upstream_send(uc.get(), shared);
    }
}

std::vector<int> server_instance::lua_upstreams() const
{
    std::vector<int> result;
    for (const auto& [cid, uc] : m_upstreams)
        if (uc->connected) result.push_back(cid);
    return result;
}

void server_instance::invoke_on_upstream([[maybe_unused]] int conn_id, [[maybe_unused]] std::string_view data)
{
#ifndef SOCKETLEY_NO_LUA
    auto* lctx = lua();
    if (!lctx || !lctx->has_on_upstream()) return;
    sol::protected_function_result r = lctx->on_upstream()(conn_id, data);
    if (SOCKETLEY_UNLIKELY(!r.valid()))
    {
        sol::error e = r;
        fprintf(stderr, "%s on_upstream error: %s\n",
                lua_diag::tag(get_name()).c_str(), e.what());
    }
#endif
}

void server_instance::invoke_on_upstream_connect([[maybe_unused]] int conn_id)
{
#ifndef SOCKETLEY_NO_LUA
    auto* lctx = lua();
    if (!lctx || !lctx->has_on_upstream_connect()) return;
    sol::protected_function_result r = lctx->on_upstream_connect()(conn_id);
    if (SOCKETLEY_UNLIKELY(!r.valid()))
    {
        sol::error e = r;
        fprintf(stderr, "%s on_upstream_connect error: %s\n",
                lua_diag::tag(get_name()).c_str(), e.what());
    }
#endif
}

void server_instance::invoke_on_upstream_disconnect([[maybe_unused]] int conn_id)
{
#ifndef SOCKETLEY_NO_LUA
    auto* lctx = lua();
    if (!lctx || !lctx->has_on_upstream_disconnect()) return;
    sol::protected_function_result r = lctx->on_upstream_disconnect()(conn_id);
    if (SOCKETLEY_UNLIKELY(!r.valid()))
    {
        sol::error e = r;
        fprintf(stderr, "%s on_upstream_disconnect error: %s\n",
                lua_diag::tag(get_name()).c_str(), e.what());
    }
#endif
}
