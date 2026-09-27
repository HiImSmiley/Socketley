#include "../../shared/socket_tuning.h"
#include "../../shared/conn_alloc.h"
#include "server_instance.h"
#include "../../shared/lua_suspend.h"
#include "../../shared/coarse_clock.h"
#include "../../shared/conn_reachability.h"

// The HTTP header-line helpers, shared rather than copied, because a second
// implementation of "is this a whole decimal" is a second place for the answer
// to differ.
#include "../../shared/http_framing.h"
#include "../../shared/unix_listener.h"
#include "../../shared/blocking_write.h"
#include "../../shared/event_loop.h"
#include "../../shared/runtime_manager.h"
#include "../../shared/route_relay.h"
#include "../../shared/lua_context.h"
#include "../../shared/ws_protocol.h"
#include "../../shared/invariants.h"
#include "../../shared/logging.h"
#include "../../cli/command_hashing.h"
// Deliberately not cache_instance.h, because everything this runtime needs of
// a cache goes through the request channel as bytes.
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
    // The last word on the cache requests this server made, because a runtime
    // can be destroyed without ever having been stopped and the channel would
    // hold a pointer into this object.
    if (auto* mgr = get_runtime_manager())
        mgr->requests().drop_origin(this);

    close_tracked(m_listen_fd);
    close_tracked(m_udp_fd);
    // Not through close_tracked: this descriptor was never given to the ring,
    // and handing the ring a close for something it does not know about is how
    // a teardown starts owing a completion nobody will deliver.
    if (m_http_root_fd >= 0) { ::close(m_http_root_fd); m_http_root_fd = -1; }
}

// The buffer the plain arms read into, made when an arm first needs one.
//
// Same defect and same repair as the cache's copy of this function: read_buf
// stopped being allocated at accept so an idle connection would not pay four
// kilobytes for it, and the arms below were left reading `&& conn->read_buf`.
// That pointer is null on every connection that has a buffer ring, so the last
// rung of the ladder was unreachable exactly when the ring was full and it was
// the point -- nothing armed, and the connection reads no more.  The chain
// above was fixed out of the same shape once through an `else`; this came back
// through a null pointer, in a commit about memory.
//
// The idle connection still never reaches this, because it never fails an arm.
static inline char* fallback_read_buf(server_connection* conn)
{
    if (!conn->read_buf)
        conn->read_buf = std::make_unique<char[]>(server_connection::READ_BUF_SIZE);
    return conn->read_buf.get();
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
        conn = socketley::make_connection<server_connection>();
        conn->fd = fd;
    }
    // A new connection is a new identity even when it inherits the struct and
    // the descriptor number of the one before it.
    conn->generation = next_io_generation();

    // The name another runtime is allowed to hold, minted here rather than at
    // the first route, so a connection has one identity for its whole life.
    conn->ref_serial = next_serial();
    if (fd >= 0)
        m_conn_by_serial[conn->ref_serial] = fd;
    return conn;
}

// The shard field in a conn_ref serial has to be wide enough for every shard a
// build allows, checked here because conn_identity.h deliberately does not
// include runtime_definitions.h.
static_assert(max_shards <= (1u << conn_serial_shard_bits),
              "conn_ref's serial cannot name every shard --shards allows");

// Mints a serial having first told the source which shard it is minting for,
// lazily because the index arrives in the config frame -- and with a flag
// rather than a comparison, since shard 0 is a real shard.
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
    // get_id() is assigned after construction, so this cannot be a
    // constructor's job, and it is recomputed while still zero rather than
    // caching the invalid answer.
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

// Exactly right as "may this struct be reused" and wrong as "may the teardown
// be deferred", because an armed read makes no promise to come back -- the 16
// guards asking it are left alone, since a teardown they decline is picked up
// one dispatch later.
bool server_instance::conn_ops_pending(const server_connection* conn) const
{
    return conn->read_pending || conn->write_pending || direct_owed(conn)
        || conn->file_read_pending || conn->splice_in_pending || conn->splice_out_pending
        // The streamed file's read writes into this struct's own buffer, so a
        // reuse while it is armed is the kernel writing into the next client's
        // connection.
        || conn->stream_pending;
}

// Every flag this connection can carry sorted by who must report it, which is
// the whole seam between conn_reachability.h and this runtime -- with
// cache_pending a promised reply rather than a ring operation.
socketley::reach::owed server_instance::conn_owed(const server_connection* conn) const
{
    socketley::reach::owed o;
    o.write          = conn->write_pending || direct_owed(conn);
    o.file_read      = conn->file_read_pending;
    o.splice_in      = conn->splice_in_pending;
    o.splice_out     = conn->splice_out_pending;
    o.promised_reply = conn->cache_pending > 0;
    o.drain          = conn->wr_shutdown && conn->read_pending && drains_on_close(conn);
    o.read           = conn->read_pending;   // not counted; see the header
    return o;
}

void server_instance::release_conn(std::unique_ptr<server_connection> conn)
{
    // The fixed-file slot goes back now rather than at pool_release(), because
    // a stopped runtime's dropped completions meant the slot outlived the
    // instance and the kernel still held a reference to the socket -- safe
    // because free_fixed_file_slot() now releases the index only when nothing
    // in the ring names it.
    release_fixed_slot(conn.get());

    if (SOCKETLEY_UNLIKELY(conn_ops_pending(conn.get())))
    {
        // The kernel is still working on something that names this struct, so
        // it waits rather than being reused or freed.
        m_conn_retired.push_back(std::move(conn));
        return;
    }
    pool_release(std::move(conn));
}

// ─── A pipe per connection, created when one is needed ──────────────────────
// pipe2() and fcntl() per download rather than once per runtime, which against
// a multi-megabyte transfer is two syscalls against thousands.  What it buys is
// that the second concurrent download is no longer excluded from the zero-copy
// path -- measured 975 us against 6087 on a 4 MiB file.
bool server_instance::splice_pipe_acquire(server_connection* conn)
{
    if (conn->splice_pipe[0] >= 0)
        return true;
    // Sized first, because how many fit is the budget divided by the size.
    const size_t pipe_bytes = std::min<size_t>(1024u * 1024, write_buffer_bytes());
    uint32_t allowed = static_cast<uint32_t>(MAX_SPLICE_PIPE_BYTES / pipe_bytes);
    if (allowed > MAX_CONCURRENT_SPLICE) allowed = MAX_CONCURRENT_SPLICE;
    if (allowed == 0) allowed = 1;
    if (m_splice_live >= allowed)
        return false;
    if (pipe2(conn->splice_pipe, O_NONBLOCK | O_CLOEXEC) != 0)
    {
        conn->splice_pipe[0] = conn->splice_pipe[1] = -1;
        return false;
    }
    // The same size the budget above was divided by, because both answer "how
    // much may be in flight for one connection" -- a runtime configured small
    // because it serves many streams should not then hold a megabyte of kernel
    // pipe per stream.  A pipe cannot be smaller than a page and the kernel
    // rounds, so the result is advisory and the return is not read.
    if (fcntl(conn->splice_pipe[0], F_SETPIPE_SZ, static_cast<int>(pipe_bytes)) < 0) {}
    ++m_splice_live;
    return true;
}

void server_instance::splice_pipe_release(server_connection* conn)
{
    if (conn->splice_pipe[0] < 0 && conn->splice_pipe[1] < 0)
        return;   // idempotent: every later caller finds it already gone
    if (conn->splice_pipe[0] >= 0) { close_tracked(conn->splice_pipe[0]); conn->splice_pipe[0] = -1; }
    if (conn->splice_pipe[1] >= 0) { close_tracked(conn->splice_pipe[1]); conn->splice_pipe[1] = -1; }
    if (m_splice_live > 0)
        --m_splice_live;
}

void server_instance::pool_release(std::unique_ptr<server_connection> conn)
{
    // A splice armed at close time kept splice_cleanup() from running, so this
    // is where that deferred cleanup happens -- without it the file descriptor
    // rode into the pool.  It used to also strand the runtime's one shared
    // pipe for the rest of its life; the pipe is this struct's now, so what is
    // at stake is one slot of MAX_CONCURRENT_SPLICE rather than all of them,
    // and the reap this is reached from has already waited for the ring.
    if (SOCKETLEY_UNLIKELY(conn->splice_file_fd >= 0 || conn->splice_pending ||
                           conn->splice_remaining || conn->splice_pipe[0] >= 0))
        splice_cleanup(conn.get());

    // Normally already done by release_conn(), which is where the slot is given
    // up; this covers reap_retired(), which reaches the pool directly.
    release_fixed_slot(conn.get());

    // The TLS session dies with the connection that owned it, needing none of
    // the ring's care because no completion can name it, and it must not
    // survive into whoever takes this struct next.
    if (SOCKETLEY_UNLIKELY(conn->ssl != nullptr))
    {
        tls_context::free_ssl(conn->ssl);
        conn->ssl = nullptr;
    }
    conn->tls_state = tls_conn_none;
    conn->tls_peer_closed = false;

    // Nothing is in flight but the requests still carry a live owner pointer,
    // so clearing it makes a completion that reaches the loop anyway get
    // dropped there.
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
    for (uint32_t i = 0; i < conn->write_batch_count; i++) conn->write_batch[i].clear();
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
    conn->drain_on_close = false;
    conn->drained_bytes = 0;

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

// One teardown for a client connection reached from every path that closes
// one, because ten steps in each path's own order is how a pending flag came
// to be checked in three and forgotten in two.
void server_instance::close_conn(server_connection* conn, bool notify_disconnect)
{
    // An answer from the cache is still owed, and closing now throws away what
    // the client is holding its socket open for -- and this always ends,
    // because the channel promises exactly one reply per request, `dropped`
    // included.
    if (SOCKETLEY_UNLIKELY(conn->cache_pending > 0))
    {
        conn->closing = true;
        return;
    }

    const int fd = conn->fd;

    // This connection may still hold the shared splice pipe, and with no
    // splice armed handing it on is safe here and nowhere else.
    if (SOCKETLEY_UNLIKELY(conn->splice_file_fd >= 0 || conn->splice_pending || conn->splice_remaining))
        splice_cleanup(conn);

    // Authority and group membership are keyed by fd and the kernel reissues
    // that number, so leaving either behind grants the newcomer broadcast
    // authority without the password.
    if (SOCKETLEY_UNLIKELY(fd == m_master_fd))
        m_master_fd = -1;
    unroute_client(fd);
    if (notify_disconnect)
        invoke_on_disconnect(fd);
    remove_from_all_groups(fd);

    // Before the index entry goes, because remove_active_fd() finds the
    // connection through m_conn_idx and clearing the index first made every
    // call a no-op.
    remove_active_fd(fd);

    // The serial stops resolving here, before close_tracked() hands the number
    // back, so anyone still holding this connection's name gets a clean
    // refusal rather than a write into whoever inherited it.
    if (conn->ref_serial != 0)
        m_conn_by_serial.erase(conn->ref_serial);

    if (fd >= 0 && fd < MAX_FDS)
        m_conn_idx[fd] = nullptr;
    close_tracked(fd);

    // The file a response is served out of is this connection's and a retired
    // struct never reaches pool_release(), so it is closed here -- while
    // file_buf stays, because that is where the kernel is writing.
    if (SOCKETLEY_UNLIKELY(conn->file_fd >= 0))
    {
        close_tracked(conn->file_fd);
        conn->file_fd = -1;
    }

    // And its pipe, for the same reason, but only once the ring is done with
    // it: a retired struct waits in m_conn_retired until conn_ops_pending() is
    // false, and releasing a pipe the kernel is still splicing into is the one
    // thing this must not do.  The wait ends at pool_release(), which reaches
    // splice_cleanup() and therefore this.
    if (SOCKETLEY_UNLIKELY(conn->splice_pipe[0] >= 0)
        && !conn->splice_in_pending && !conn->splice_out_pending)
        splice_pipe_release(conn);

    auto it = m_clients.find(fd);
    if (it != m_clients.end())
    {
        // The disconnect callback may have queued a write on this connection,
        // so what is in flight is re-examined here rather than above.
        release_conn(std::move(it->second));
        m_clients.erase(it);
    }
}

// A completion whose request lives inside a retired struct, found by the one
// thing the kernel hands back unchanged: the address of the request itself.
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
        else if (req == &c->write_req)       c->write_pending = false;
        else if (req == &c->file_read_req)   c->file_read_pending = false;
        else if (req == &c->splice_in_req)   c->splice_in_pending = false;
        else if (req == &c->splice_out_req)  c->splice_out_pending = false;

        if (!conn_ops_pending(c))
        {
            // Nothing in the ring names it any more, so the messages it was
            // sending can go and the struct can serve somebody else.
            for (uint32_t k = 0; k < c->write_batch_count; k++)
                c->write_batch[k].clear();
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

void server_instance::set_send_to(uint8_t mask)
{
    m_send_to = mask;
}

uint8_t server_instance::get_send_to() const
{
    return m_send_to;
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
    // Copied before the old value is scrubbed, because `pw` may point into the
    // string being replaced and zeroing it first would erase the source.
    std::string next(pw);

    // The same zeroize teardown() does, here as well because this setter is
    // how a password is REMOVED -- `edit --no-master-pw` -- and a clear that
    // leaves the bytes in the buffer has not cleared anything.
    if (!m_master_pw.empty())
    {
        volatile char* p = m_master_pw.data();
        for (size_t i = 0; i < m_master_pw.size(); i++)
            p[i] = 0;
    }

    m_master_pw = std::move(next);
}

std::string_view server_instance::get_master_pw() const
{
    return m_master_pw;
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

// An upstream that asked for a port and gave an unusable one is refused
// without storing anything, because a target that can never be connected to
// sat in the list looking exactly like one that could.
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

// Where the live-reload script goes: before </head>, else before </body>, else
// at the end.  The offset rather than an injected copy, because that is what
// lets a response be built in one pass instead of injecting into a copy of the
// file and then copying that into the response.
static size_t ws_inject_offset(std::string_view content)
{
    auto pos = content.find("</head>");
    if (pos == std::string_view::npos) pos = content.find("</HEAD>");
    if (pos == std::string_view::npos) pos = content.find("</body>");
    if (pos == std::string_view::npos) pos = content.find("</BODY>");
    return pos == std::string_view::npos ? content.size() : pos;
}

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

// One response, built once.  inject_at is npos for a body that takes no script;
// otherwise the script is a third piece appended between two halves of the file
// rather than a reason to hold an injected copy of it.
static std::string build_http_response_at(std::string_view content_type,
                                          std::string_view content,
                                          size_t inject_at,
                                          bool keep_alive)
{
    const bool inject = inject_at != std::string_view::npos;
    const size_t body_len = content.size() + (inject ? WS_INJECT_SCRIPT.size() : 0);

    std::string resp;
    resp.reserve(160 + body_len);
    resp.append("HTTP/1.1 200 OK\r\nContent-Type: ");
    resp.append(content_type);
    // Here as well as on the splice arm's headers, and the omission was worth
    // measuring: a first request for a small file takes THIS arm, so a whole
    // file was answered without the field while a slice of it was answered
    // with one.  A client that respects the field then never seeks at all,
    // which is the common case and would have made the 206 path unreachable
    // from a conforming player.
    //
    // Injected HTML is a 200 from this builder too, and a range on HTML is
    // declined in serve_http -- the offsets do not survive the injection --
    // so the field is not claimed for those.
    if (!inject)
        resp.append("\r\nAccept-Ranges: bytes");
    resp.append("\r\nContent-Length: ");
    char len_buf[24];
    auto [len_end, len_ec] = std::to_chars(len_buf, len_buf + sizeof(len_buf), body_len);
    resp.append(len_buf, len_end - len_buf);
    resp.append(keep_alive ? "\r\nConnection: keep-alive\r\n\r\n" : "\r\nConnection: close\r\n\r\n");
    if (inject)
    {
        resp.append(content.substr(0, inject_at));
        resp.append(WS_INJECT_SCRIPT);
        resp.append(content.substr(inject_at));
    }
    else
    {
        resp.append(content);
    }
    return resp;
}

static void append_num(std::string& out, size_t n)
{
    char buf[24];
    auto [end, ec] = std::to_chars(buf, buf + sizeof(buf), n);
    out.append(buf, end - buf);
}

static std::string build_http_headers_only(std::string_view content_type, size_t body_size, bool keep_alive)
{
    std::string resp;
    resp.reserve(160);
    resp.append("HTTP/1.1 200 OK\r\nContent-Type: ");
    resp.append(content_type);
    // Said on the whole-file answer, because a player asks for the file and
    // decides from this header whether it may seek at all.  Without it a
    // conforming client downloads linearly and cannot scrub.
    resp.append("\r\nAccept-Ranges: bytes\r\nContent-Length: ");
    append_num(resp, body_size);
    resp.append(keep_alive ? "\r\nConnection: keep-alive\r\n\r\n" : "\r\nConnection: close\r\n\r\n");
    return resp;
}

// ─── A slice, and the two headers that make it one ──────────────────────────
// Content-Length is the slice; Content-Range carries the whole length.  Giving
// Content-Length the file's size is the classic way to write this wrong -- the
// client then waits forever for bytes the server already finished sending.
static std::string build_http_206_headers(std::string_view content_type,
                                          size_t first, size_t last, size_t total,
                                          bool keep_alive)
{
    std::string resp;
    resp.reserve(192);
    resp.append("HTTP/1.1 206 Partial Content\r\nContent-Type: ");
    resp.append(content_type);
    resp.append("\r\nAccept-Ranges: bytes\r\nContent-Range: bytes ");
    append_num(resp, first);
    resp.push_back('-');
    append_num(resp, last);
    resp.push_back('/');
    append_num(resp, total);
    resp.append("\r\nContent-Length: ");
    append_num(resp, last - first + 1);
    resp.append(keep_alive ? "\r\nConnection: keep-alive\r\n\r\n" : "\r\nConnection: close\r\n\r\n");
    return resp;
}

// A seek past the end, which is how a player learns a file's length when it
// was not told: the answer has to state the length it could not satisfy.
static std::string build_http_416(size_t total, bool keep_alive)
{
    std::string resp;
    resp.reserve(160);
    resp.append("HTTP/1.1 416 Range Not Satisfiable\r\n"
                "Content-Type: text/plain\r\nAccept-Ranges: bytes\r\n"
                "Content-Range: bytes */");
    append_num(resp, total);
    resp.append("\r\nContent-Length: 0");
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

// The client's `Connection` header decides and the version only supplies the
// default, in one place, because two deciders against 26 readers is how the
// cached-response path and the Lua path came to disagree.
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

// Both refusals are `Connection: close` unconditionally, because refusing
// means this end could not decide where the message ends and carrying on would
// mean deciding exactly that.
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

// A head that stopped arriving.  Answered rather than dropped in silence,
// because the proxy answers this exact case with this exact status from its own
// sweep -- and a client that gets a bare close cannot tell a deadline from a
// crash, a firewall or the wrong port.  Closing for the same reason as the
// refusals above: what was in the buffer was measured against a block that
// never finished, so where the next message starts is precisely what is in
// doubt.
static const std::shared_ptr<const std::string>& http_408_response()
{
    static const auto resp = std::make_shared<const std::string>(
        "HTTP/1.1 408 Request Timeout\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 16\r\n"
        "Connection: close\r\n\r\n"
        "Request Timeout\n");
    return resp;
}

// A Transfer-Encoding this server does not implement is 501 rather than 400
// (RFC 9112 Section 6.1), because the request is well-formed -- and reading a
// chunked body as one of length zero parses the chunk data as the next
// request.
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

// Closing too, because the body this refuses is still on its way and would
// otherwise be read as the next request.
// RFC 6455 4.2.2: a version this server does not speak MUST be refused with an
// HTTP error and a Sec-WebSocket-Version naming what it does speak.  Measured
// before this existed: `Sec-WebSocket-Version: 8` was answered with 101, and
// the client then sent frames in a framing nobody here parses -- so what it
// got was a connection that wedged instead of a sentence telling it which
// version to use.
static const std::shared_ptr<const std::string>& http_426_response()
{
    static const auto resp = std::make_shared<const std::string>(
        "HTTP/1.1 426 Upgrade Required\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 41\r\n"
        "Connection: close\r\n\r\n"
        "this server speaks WebSocket version 13\r\n");
    return resp;
}

// RFC 6455 4.2.1 makes Sec-WebSocket-Key mandatory and 4.2.2 answers a
// handshake this end will not complete with an HTTP error, 400 being the one
// it names.  Named in the body rather than sharing the bare 400 because the
// one thing wrong with this request is a header the client can add, and a
// refusal that does not say which is a refusal with nothing to act on.
static const std::shared_ptr<const std::string>& http_400_ws_key_response()
{
    static const auto resp = std::make_shared<const std::string>(
        "HTTP/1.1 400 Bad Request\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 48\r\n"
        "Connection: close\r\n\r\n"
        "this WebSocket upgrade has no Sec-WebSocket-Key\n");
    return resp;
}

static const std::shared_ptr<const std::string>& http_413_response()
{
    static const auto resp = std::make_shared<const std::string>(
        "HTTP/1.1 413 Content Too Large\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 18\r\n"
        "Connection: close\r\n\r\n"
        "Content Too Large\n");
    return resp;
}

// A head past the 16 KiB this server frames, answered where it used to be
// closed in silence, as the proxy answers the same thing.
static const std::shared_ptr<const std::string>& http_431_response()
{
    static const std::string body = "Request Header Fields Too Large\n";
    static const auto resp = std::make_shared<const std::string>(
        "HTTP/1.1 431 Request Header Fields Too Large\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n"
        "Connection: close\r\n\r\n" + body);
    return resp;
}

// Closing, because the response the client was promised is not coming and
// nothing else on the connection is owed.
static const std::shared_ptr<const std::string>& http_500_response()
{
    static const auto resp = std::make_shared<const std::string>(
        "HTTP/1.1 500 Internal Server Error\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 26\r\n"
        "Connection: close\r\n\r\n"
        "500 Internal Server Error\n");
    return resp;
}

// A path with a segment that starts with a dot -- .env, .git/config,
// .htpasswd -- which is where a site's secrets sit beside its pages, so none is
// served; .well-known is the one such directory meant for the public.
static bool http_hidden_path(std::string_view path)
{
    size_t i = 0;
    while (i < path.size())
    {
        while (i < path.size() && path[i] == '/') ++i;
        const size_t end = path.find('/', i);
        const std::string_view seg = path.substr(i, end == std::string_view::npos
                                                        ? std::string_view::npos : end - i);
        if (!seg.empty() && seg.front() == '.' && seg != ".well-known")
            return true;
        if (end == std::string_view::npos)
            break;
        i = end;
    }
    return false;
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

        // Lexically, because fs::relative() resolves links and filed every one
        // under its target's name, so no link was ever served by its own.
        const auto rel = entry.path().lexically_relative(m_http_base);
        if (rel.empty())
            continue;
        std::string url_path = "/" + rel.string();
        if (http_hidden_path(url_path))
            continue;

        // A link is followed exactly where disk mode follows it, by asking the
        // same openat2(RESOLVE_BENEATH) -- where a symlink to /etc/shadow was
        // read into memory here and served -- with the canonical prefix test
        // kept for a kernel without it.
        {
            bool beneath = false;
            bool asked = false;
            if (m_http_root_fd >= 0)
            {
                struct open_how how{};
                how.flags   = static_cast<uint64_t>(O_RDONLY | O_CLOEXEC);
                how.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS;
                const long r = ::syscall(__NR_openat2, m_http_root_fd, rel.c_str(),
                                         &how, sizeof(how));
                if (r >= 0)
                {
                    ::close(static_cast<int>(r));
                    beneath = asked = true;
                }
                else if (errno != ENOSYS)
                    asked = true;
            }
            if (!asked)
            {
                std::error_code cec;
                const fs::path real = fs::canonical(entry.path(), cec);
                const auto mism = std::mismatch(m_http_base.begin(), m_http_base.end(),
                                                real.begin(), real.end());
                beneath = !cec && mism.first == m_http_base.end();
            }
            if (!beneath)
                continue;
        }

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

        // Both variants stored, because a single keep-alive string answered
        // `Connection: keep-alive` to every request including the ones that
        // asked to close.
        m_http_cache[url_path] = {
            std::make_shared<const std::string>(build_http_response(ct, content, true)),
            std::make_shared<const std::string>(build_http_response(ct, content, false))
        };
    }
}

// One entry or none, called only for a read that completed in full through the
// openat2(RESOLVE_BENEATH) path.
// Whether a file of this cost can be kept, asked before it is built.
//
// The cap used to be tested on two finished responses, so a 400 MiB .html had
// 800 MiB of them constructed and then dropped for being over a 64 MiB limit.
// What this key already costs is reclaimed before the test, or a file edited
// near the limit is refused on the strength of bytes it is about to give back.
bool server_instance::http_reval_would_fit(const std::string& url_path, size_t cost) const
{
    auto it = m_http_reval.find(url_path);
    const size_t reclaimed = (it != m_http_reval.end()) ? it->second.bytes : 0;
    return m_http_reval_bytes - reclaimed + cost <= HTTP_REVAL_MAX_TOTAL;
}

// Once per worker, because an operator needs to know the content cache stopped
// taking files and does not need telling per request.
//
// Called from both doors, which is the point.  The estimate at the read
// completion is what actually declines when the map is full -- it is checked
// before the responses are built, so the exact test inside http_reval_store()
// below is reached only in the sliver where a finished response is larger than
// the estimate was.  The line lived at that second door alone, so in practice it
// never fired: 200 files of 200 KiB fill the 64 MiB map and logged nothing.
void server_instance::note_http_reval_full()
{
    if (m_http_reval_full_logged)
        return;
    m_http_reval_full_logged = true;
    LOG_INFO("server: --http content cache reached its 64 MiB limit; the "
             "files already in it stay fast, the rest are spliced from the "
             "page cache -- or read per request on TLS and for .html, "
             "neither of which can be spliced");
}

void server_instance::http_reval_store(const std::string& url_path, const struct stat& st,
                                       std::shared_ptr<const std::string> ka,
                                       std::shared_ptr<const std::string> cl)
{
    size_t cost = (ka ? ka->size() : 0) + (cl ? cl->size() : 0);
    if (!http_reval_would_fit(url_path, cost))
    {
        // Full: stop taking new files rather than evicting one, because every
        // hit is revalidated so only speed is at stake and a stable answer
        // beats a cache that thrashes.
        note_http_reval_full();
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

// The directory every --http request is opened relative to, opened once
// because openat2(RESOLVE_BENEATH) needs a real directory fd and re-opening it
// per request restores the syscall this removes.
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

void server_instance::serve_http(server_connection* conn, std::string_view path,
                                 std::string_view range_hdr)
{
    // Cleared per request and not per connection: under keep-alive this struct
    // serves the next request without a reset(), and a path that does not
    // reach the two arms below -- a 404, a cache hit -- would leave the last
    // response's answer standing.
    conn->is_range = false;

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
        queue_http_response(conn, http_404_response(conn->http_keep_alive));
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

    if (http_hidden_path(url_path))
    {
        queue_http_response(conn, http_404_response(conn->http_keep_alive));
        if (!conn->http_keep_alive)
            conn->closing = true;
        else
            conn->proto = proto_unknown;
        return;
    }

    if (m_http_cache_enabled && !m_http_cache.empty())
    {
        // Cached mode: zero-copy lookup — just bump shared_ptr refcount
        auto it = m_http_cache.find(url_path);
        queue_http_response(conn, it != m_http_cache.end()
            ? (conn->http_keep_alive ? it->second.response : it->second.response_close)
            : http_404_response(conn->http_keep_alive));
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
                queue_http_response(conn, http_404_response(conn->http_keep_alive));
                if (!conn->http_keep_alive)
                    conn->closing = true;
                else
                    conn->proto = proto_unknown;
                return;
            }
        }

        // One statx decides whether the kept bytes are still the file's, and
        // dev+ino is in the comparison because `mv` into place plus `touch -r`
        // makes an (mtime, size) check serve the old bytes forever.
        std::string rel_path(url_path.substr(1));
        if (rel_path.empty())
            rel_path = ".";

        // A cached entry is the WHOLE file's response, so serving it for a
        // Range request would answer a seek with the entire body under a 200.
        // Judged on the header being present at all rather than on it being
        // usable, because usability needs the length and the length needs the
        // fstat below -- a malformed Range then costs one uncached answer,
        // which is the right way round.
        bool reval_ok = http_reval_active() && range_hdr.empty();
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
                    queue_http_response(conn, conn->http_keep_alive ? rit->second.response
                                                                    : rit->second.response_close);
                    if (!conn->http_keep_alive)
                        conn->closing = true;
                    else
                        conn->proto = proto_unknown;
                    return;
                }
                // Stale, replaced or gone, dropped rather than left to be
                // re-checked, or a deleted file would hold its bytes for the
                // life of the process.
                m_http_reval_bytes -= rit->second.bytes;
                m_http_reval.erase(rit);
            }
        }

        // openat2(RESOLVE_BENEATH) asks the kernel for the escape guarantee
        // inside the open, replacing 9.01 readlinks per connection that could
        // also be raced -- with RESOLVE_NO_MAGICLINKS, and the old path kept
        // for ENOSYS.
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
                // The path is still needed for the extension, and leaving it
                // empty served every file with the wrong type -- which under
                // keep-alive desynchronised the connection rather than merely
                // mislabelling it.
                resolved = m_http_base / rel;
            }
            else if (errno != ENOSYS)
            {
                // EXDEV, ELOOP, ENOENT, EACCES — every one of them is "not a
                // file this server may serve", and they are answered alike.
                queue_http_response(conn, http_404_response(conn->http_keep_alive));
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
            queue_http_response(conn, http_404_response(conn->http_keep_alive));
            if (!conn->http_keep_alive)
                conn->closing = true;
            else
                conn->proto = proto_unknown;
            return;
        }

        // O_CLOEXEC, because this is on the request path and a worker forked
        // while a file is being served would inherit a descriptor on it.
        ffd = open(resolved.c_str(), O_RDONLY | O_CLOEXEC);
        }
        if (ffd < 0)
        {
            queue_http_response(conn, http_404_response(conn->http_keep_alive));
            if (!conn->http_keep_alive)
                conn->closing = true;
            else
                conn->proto = proto_unknown;
            return;
        }

        struct stat st;
        if (fstat(ffd, &st) < 0 || !S_ISREG(st.st_mode))
        {
            close_tracked(ffd);
            queue_http_response(conn, http_404_response(conn->http_keep_alive));
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

        // ─── The range, against the length it is defined by ─────────────
        // Not for HTML: the injected script changes the body's length, so a
        // byte offset into the file is not an offset into what is served.
        // 14.2 lets a server ignore the field, and that is the honest answer
        // here rather than a slice of something else.
        const http_range rng = is_html ? http_range{}
                                       : http_parse_range(range_hdr, fsize);
        if (SOCKETLEY_UNLIKELY(rng.unsatisfiable))
        {
            close_tracked(ffd);
            queue_http_response(conn, std::make_shared<const std::string>(
                build_http_416(fsize, conn->http_keep_alive)));
            if (!conn->http_keep_alive)
                conn->closing = true;
            else
                conn->proto = proto_unknown;
            return;
        }
        const size_t send_first = rng.usable ? rng.first : 0;
        const size_t send_len   = rng.usable ? (rng.last - rng.first + 1) : fsize;

        // An empty file exists, so it is a 200 with the body --http-cache
        // would build for it and no read, since a zero-length read completes
        // with 0 and 0 was being answered as 404.
        if (fsize == 0)
        {
            close_tracked(ffd);
            queue_http_response(conn, std::make_shared<const std::string>(build_http_response(
                ct, is_html ? inject_ws_script({}) : std::string(), conn->http_keep_alive)));
            if (!conn->http_keep_alive)
                conn->closing = true;
            else
                conn->proto = proto_unknown;
            return;
        }

        // Whether this miss may become a map entry, which needs the bytes in
        // user space -- and the size it stops at depends on whether THIS
        // connection has the splice arm at all, because a kept response is sent
        // by COPYING it into the socket and the alternative sends the page cache
        // by reference.  Measured at 64 concurrent: 1 MiB is 5,931 responses a
        // second kept against 14,049 spliced, 512 KiB 11,977 against 26,599, and
        // the other way round at 4 KiB, 146,987 kept against 66,905, where
        // splice's own setup is the whole cost.  The 17.19 us against read's
        // 0.72 that this comment used to cite is that small-transfer figure, and
        // it was read as though it held at the cap.
        // 256 KiB and not lower, because splice buys that throughput partly with
        // CPU and the price falls with size: per MiB it is 340 us at 256 KiB,
        // 163 at 1 MiB and 143 at 2 MiB, against a flat ~170 for the copy.  So
        // above the cap the trade is free or better, at 512 KiB it is +31% CPU
        // for +122% throughput, and at 256 KiB it would be +59% for +115% --
        // a trade rather than a win, which is not what a default should make.
        // A TLS connection and an injected .html have no splice arm, so for them
        // the cap stays where it was: there the map is what keeps a file from
        // being read, and allocated, once per request.
        const size_t reval_cap = (!is_html && !conn->ssl) ? HTTP_REVAL_SPLICE_MAX_FILE
                                                          : HTTP_REVAL_MAX_FILE;
        const bool reval_take = reval_ok && used_beneath &&
                                fsize <= reval_cap &&
                                m_http_reval_bytes < HTTP_REVAL_MAX_TOTAL;

        // A HEAD owes the headers a GET would send and no body, so a non-HTML
        // file is answered from fstat() alone; HTML still takes the read below
        // because its Content-Length counts the injected script.
        if (conn->http_head && !is_html)
        {
            close_tracked(ffd);
            queue_http_response(conn, std::make_shared<const std::string>(
                build_http_headers_only(ct, fsize, conn->http_keep_alive)));
            if (!conn->http_keep_alive)
                conn->closing = true;
            else
                conn->proto = proto_unknown;
            return;
        }

        // Splice path for non-HTML files, never on a TLS connection, because
        // it would hand the peer plaintext in the middle of an encrypted
        // stream.
        // The cap is asked last, because acquiring a pipe for a request that
        // then declines the path would hold one for nothing.
        if (!is_html && !conn->ssl && !reval_take && splice_pipe_acquire(conn))
        {
            // The slice's start becomes the descriptor's offset, because
            // splice() from a file advances that offset and has no argument
            // for where to begin.  A failure here would splice from 0 and
            // answer a 206 whose Content-Range says otherwise, so it falls
            // through to the read arm instead of serving the wrong bytes.
            if (send_first == 0 || lseek(ffd, static_cast<off_t>(send_first), SEEK_SET)
                                       == static_cast<off_t>(send_first))
            {
                conn->splice_file_fd = ffd;
                conn->splice_remaining = send_len;
                conn->splice_pipe_pending = 0;
                conn->splice_pending = true;
                conn->file_content_type = std::string(ct);
                conn->is_range = rng.usable;
                conn->range_first = send_first;
                conn->range_total = fsize;

                // Send HTTP headers via normal write path; splice starts after headers are sent
                queue_http_response(conn, std::make_shared<const std::string>(
                    rng.usable
                        ? build_http_206_headers(ct, rng.first, rng.last, fsize,
                                                 conn->http_keep_alive)
                        : build_http_headers_only(ct, fsize, conn->http_keep_alive)),
                    /*ends_exchange=*/false);
                return;
            }
        }

        // A file this size, on a connection with no splice arm: headers now and
        // one piece at a time after them.  Two exclusions, both because the path
        // needs the whole body in user space: an .html has a script injected into
        // it and its Content-Length counts that, and a file the revalidation map
        // may keep has to be kept -- and that cap is below this threshold anyway.
        if (!is_html && !reval_take && send_len > HTTP_STREAM_MIN)
        {
            conn->file_content_type = std::string(ct);
            conn->is_range    = rng.usable;
            conn->range_first = send_first;
            conn->range_total = fsize;
            queue_http_response(conn, std::make_shared<const std::string>(
                rng.usable
                    ? build_http_206_headers(ct, rng.first, rng.last, fsize,
                                             conn->http_keep_alive)
                    : build_http_headers_only(ct, fsize, conn->http_keep_alive)),
                /*ends_exchange=*/false);
            if (SOCKETLEY_UNLIKELY(!stream_file_begin(conn, ffd, send_first, send_len)))
            {
                // The headers promised a length that is now not coming.
                conn->closing = true;
                maybe_shutdown_write(conn);
            }
            return;
        }

        // Fallback: malloc + async read (HTML files or splice busy)
        char* fbuf = static_cast<char*>(malloc(send_len));
        if (!fbuf)
        {
            close_tracked(ffd);
            queue_http_response(conn, http_404_response(conn->http_keep_alive));
            if (!conn->http_keep_alive)
                conn->closing = true;
            else
                conn->proto = proto_unknown;
            return;
        }

        // Store state on connection for completion handler
        conn->file_fd = ffd;
        conn->file_buf = fbuf;
        // The slice's length, because the completion compares what arrived
        // against this to decide whether it read the whole of what it asked
        // for -- a 206 that stored the file's length here would read as a
        // short read and answer 500.
        conn->file_size = send_len;
        conn->file_content_type = std::string(ct);
        conn->is_range = rng.usable;
        conn->range_first = send_first;
        conn->range_total = fsize;
        conn->file_is_html = is_html;
        conn->file_read_pending = true;
        // Non-empty only when the completion may keep the bytes, with the
        // identity fstat() reported on this very descriptor rather than
        // whatever is at the path later.
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
        conn->file_read_req = { this, fbuf, conn->fd, static_cast<uint32_t>(send_len), op_file_read,
                                conn->generation };
        if (SOCKETLEY_UNLIKELY(!m_loop->submit_file_read(ffd, fbuf, static_cast<uint32_t>(send_len),
                                                         send_first, &conn->file_read_req)))
        {
            // No completion will arrive for a read that was never queued, and
            // the teardown closes file_fd and frees file_buf, both already
            // recorded on the connection.
            conn->file_read_pending = false;
            conn->closing = true;
        }
    }
}

// Only reachable from the Lua on_http_request path below, so the no-Lua build
// has no caller for any of these helpers.
// Lifted out of the no-Lua guard below: a status-to-phrase map with no Lua
// in it, and begin_chunked_response() is a caller outside that path.
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

// A field a script actually set, as against one it never mentioned, since only
// the first can be of the wrong type.
static bool lua_field_present(const sol::object& v)
{
    return v.valid() && v != sol::nil;
}

// What the script returned, in Lua's own words, so a diagnostic names the type
// it got rather than only the type it wanted.
static const char* lua_value_type_name(lua_context& lc, const sol::object& v)
{
    return lua_typename(lc.state().lua_state(), static_cast<int>(v.get_type()));
}

#endif

// The one place an HTTP response enters the write queue, so a HEAD is cut to
// its header block here rather than at each of the seventeen emitters.
// ─── THE LAST BYTES AND THE FIN IN ONE TURN ─────────────────────────────────
// maybe_shutdown_write() sends the FIN from the write's completion, which wins
// the race with one client and loses it with many: at 32 connection-per-request
// clients 78% of the TIME-WAITs were the clients', and their port searches set
// the rate.  So a whole answer to a client that is closing, with nothing queued
// ahead of it, goes by a direct send() with MSG_MORE and the shutdown follows,
// the FIN riding in the data's own segment -- what the socket does not take is
// queued and the FIN is left to the completion as before.
bool server_instance::send_final_and_fin(server_connection* conn, std::string_view data)
{
    if (conn->fd < 0 || conn->ssl != nullptr || conn->wr_shutdown || conn->write_pending ||
        conn_has_output(conn) || conn->cache_pending > 0 ||
        conn->splice_pending || conn->splice_in_pending || conn->splice_out_pending)
        return false;

    size_t off = 0;
    while (off < data.size())
    {
        const ssize_t n = ::send(conn->fd, data.data() + off, data.size() - off,
                                 MSG_DONTWAIT | MSG_NOSIGNAL | MSG_MORE);
        if (n > 0) { off += static_cast<size_t>(n); continue; }
        if (n < 0 && errno == EINTR) continue;
        break;
    }
    m_stat_bytes_out.fetch_add(off, std::memory_order_relaxed);
    if (off < data.size())
    {
        conn->write_queue.push(std::make_shared<const std::string>(data.substr(off)));
        if (!conn->write_pending)
            flush_write_queue(conn);
        return true;
    }

    conn->wr_shutdown = true;
    if (shutdown(conn->fd, SHUT_WR) < 0) {}
    return true;
}

void server_instance::queue_http_response(server_connection* conn,
                                          std::shared_ptr<const std::string> resp,
                                          bool ends_exchange)
{
    if (SOCKETLEY_UNLIKELY(conn->http_head))
    {
        const auto hdr_end = resp->find("\r\n\r\n");
        if (hdr_end != std::string::npos && hdr_end + 4 < resp->size())
            resp = std::make_shared<const std::string>(resp->data(), hdr_end + 4);
    }
    // Through admit_send like every other write, because a client pipelining
    // requests and reading nothing was answered into a queue with no bound --
    // and allowed while closing, since a refusal marks that after queueing.
    if (!admit_send(conn, resp->size(), true))
        return;
    if (ends_exchange && !conn->http_keep_alive && send_final_and_fin(conn, *resp))
        return;
    conn->write_queue.push(std::move(resp));
    if (!conn->write_pending)
        flush_write_queue(conn);
}

void server_instance::refuse_http_request(server_connection* conn,
                                          const std::shared_ptr<const std::string>& resp,
                                          bool drain)
{
    // The rest of a refused request may still be on its way, and closing with
    // it unread resets the connection ahead of the answer; a peer that
    // stopped sending has nothing to drain.
    if (drain)
    {
        conn->drain_on_close = true;
        conn->header_deadline = std::chrono::steady_clock::now() +
                                std::chrono::seconds(DRAIN_LIMIT_SECS);
        m_drains_outstanding = true;
        arm_idle_sweep();
    }

    // The buffer goes first, because everything in it was measured against a
    // header block this end could not frame, so its boundaries are exactly
    // what is in doubt.
    conn->partial.clear();

    // Its teardown runs from the write's completion, which a direct send skips.
    queue_http_response(conn, resp, /*ends_exchange=*/false);

    // Unconditional, and not conditioned on http_keep_alive the way the 404
    // path is: keep-alive means "the next request starts where this one ends",
    // and this end has just said it cannot tell where that is.
    conn->closing = true;
}

void server_instance::handle_http_request(server_connection* conn, const http_request& req, size_t total_consumed)
{
    // A new request, so nothing the last one answered applies to it.  Here and
    // not in end_chunked_response, because the fall-through to the static file
    // and the 404 is tested after the callback RETURNS -- by which time
    // end_response has run, and a flag cleared there would have reopened the
    // fall-through for a request that was already answered.  Measured with it
    // cleared there: two status lines on one socket for a single request.
    conn->response_started = false;
    conn->chunked_response = false;

    // Decided once, before anything can answer, so that every path below —
    // Lua, cached, disk, 404 — agrees about what the client asked for.
    conn->http_keep_alive = http_request_keep_alive(req);

#ifndef SOCKETLEY_NO_LUA
    // ─── The Lua handler ────────────────────────────────────────────────────
    // Protected like every other callback, because the catch was dead in the
    // Sanitize build and reading index 0 without valid() reads the error
    // object -- and a raise is answered with 500, since returning nil is
    // documented as declining.
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
        // The views go straight through, because sol2 copies the bytes into the
        // Lua heap itself and the std::string between them was read by nobody.
        for (const auto& [k, v] : req.headers)
            lua_headers[k] = v;
        lua_req["headers"] = lua_headers;

        const bool keep_alive = conn->http_keep_alive;

        // The tail every answer from this callback shares, written once so a
        // path that queues a response cannot forget the bookkeeping that lets
        // the next pipelined request be parsed against the right bytes.
        auto answer = [&](std::string response) {
            // Through queue_http_response and not the write queue directly,
            // because that is where a HEAD is cut to its header block.
            queue_http_response(conn, std::make_shared<const std::string>(std::move(response)));

            conn->partial.erase(0, total_consumed);

            if (!keep_alive)
                conn->closing = true;
            else
                conn->proto = proto_unknown;  // Reset for next request (pipelining)
        };

        // What this end cannot build the script's response from, for the same
        // reason a raise is answered this way: a 200 with the unreadable part
        // dropped reads at the client exactly like a handler that meant it.
        auto answer_500 = [&] {
            answer(build_http_response_full(500, http_reason(500), {},
                                            "500 Internal Server Error", keep_alive));
        };

        sol::protected_function_result r = lua()->on_http_request()(lua_req);

        if (SOCKETLEY_UNLIKELY(!r.valid()))
        {
            sol::error e = r;
            std::cerr << lua_diag::tag(get_name()) << " on_http_request error: " << e.what()
                      << " — answering 500" << std::endl;

            answer_500();
            return;
        }

        // return_count() before get(), because a handler that ends without a
        // `return` returns nothing and index 0 of nothing is not a value to
        // ask about.
        if (r.return_count() > 0)
        {
            sol::object result = r;
            if (result.is<sol::table>())
            {
                sol::table resp_tbl = result.as<sol::table>();

                // Absent and unreadable are different answers: a field the
                // script never set takes the documented default, one of the
                // wrong type is a response this end cannot build -- and
                // get_or() cannot tell them apart, so it substituted the
                // default for both and said nothing.
                sol::object status_obj = resp_tbl["status"];
                sol::object body_obj   = resp_tbl["body"];

                if (SOCKETLEY_UNLIKELY(lua_field_present(status_obj) &&
                                       status_obj.get_type() != sol::type::number))
                {
                    std::cerr << lua_diag::tag(get_name())
                              << " on_http_request returned a table whose `status` is a "
                              << lua_value_type_name(*lua(), status_obj)
                              << "; expected a number — answering 500" << std::endl;
                    answer_500();
                    return;
                }

                if (SOCKETLEY_UNLIKELY(lua_field_present(body_obj) &&
                                       body_obj.get_type() != sol::type::string))
                {
                    std::cerr << lua_diag::tag(get_name())
                              << " on_http_request returned a table whose `body` is a "
                              << lua_value_type_name(*lua(), body_obj)
                              << "; expected a string — answering 500" << std::endl;
                    answer_500();
                    return;
                }

                int status = resp_tbl.get_or("status", 200);
                std::string body = resp_tbl.get_or<std::string>("body", "");
                std::string_view reason = http_reason(status);

                // A header this end cannot read costs the client that header,
                // while a status or body it cannot read costs the whole
                // answer, which is why only these are named and skipped.
                std::vector<std::pair<std::string, std::string>> resp_headers;
                sol::object headers_obj = resp_tbl["headers"];
                if (SOCKETLEY_UNLIKELY(lua_field_present(headers_obj) &&
                                       !headers_obj.is<sol::table>()))
                {
                    std::cerr << lua_diag::tag(get_name())
                              << " on_http_request returned a table whose `headers` is a "
                              << lua_value_type_name(*lua(), headers_obj)
                              << "; expected a table — sending none" << std::endl;
                }
                else if (headers_obj.is<sol::table>())
                {
                    headers_obj.as<sol::table>().for_each([&](sol::object key, sol::object val) {
                        if (key.is<std::string>() && val.is<std::string>())
                        {
                            resp_headers.emplace_back(key.as<std::string>(), val.as<std::string>());
                            return;
                        }
                        std::cerr << lua_diag::tag(get_name())
                                  << " on_http_request headers: a name and its value must both be"
                                     " strings, and one pair was a "
                                  << lua_value_type_name(*lua(), key) << " and a "
                                  << lua_value_type_name(*lua(), val)
                                  << " — dropped it" << std::endl;
                    });
                }

                answer(build_http_response_full(status, reason, resp_headers, body, keep_alive));
                return;
            }

            // Falling through to the static file or the 404 is what the manual
            // promises for this, so the client's answer does not change; said
            // out loud because only nil declines, and a script that returned a
            // string meant to answer with something this end cannot read.
            if (SOCKETLEY_UNLIKELY(lua_field_present(result)))
            {
                std::cerr << lua_diag::tag(get_name()) << " on_http_request returned a "
                          << lua_value_type_name(*lua(), result)
                          << "; expected a table or nil — falling through to the static file or"
                             " the 404" << std::endl;
            }
        }
    }
#endif

    // A response the script started itself is already on its way, so the two
    // fallbacks below must not send a second one down the same connection.
    if (SOCKETLEY_UNLIKELY(conn->response_started))
    {
        conn->partial.erase(0, total_consumed);
        return;
    }

    // Fallback: serve static files if configured
    if (!m_http_dir.empty())
    {
        std::string path_str(req.path);
        // Read here and turned into a plain string, because req.headers are
        // views into conn->partial and the erase below is what they point at.
        // The size is not known yet either, so the numbers are resolved in
        // serve_http once fstat has answered -- this only carries the text.
        std::string range_hdr;
        for (const auto& [k, v] : req.headers)
            if (fnv1a_lower(k) == fnv1a("range"))
            {
                range_hdr.assign(v);
                break;
            }
        conn->partial.erase(0, total_consumed);
        serve_http(conn, path_str, range_hdr);
    }
    else
    {
        // No http_dir and no Lua callback — 404
        queue_http_response(conn, http_404_response(conn->http_keep_alive));
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
        if (uc->established) ++upstream_connected;
    return m_active_fds.size() + m_forwarded.size() + upstream_connected;
}

// What this server owes right now, over every connection and every upstream.
//
// Summed once per loop turn rather than tracked per push, because a counter kept
// by hand across four runtimes is a counter that drifts, and this loop is the
// same size as the one above it: a few hundred adds on a turn that already walks
// its completions.  It decides the pacing point and nothing else, so a value one
// turn old only ever paces on the previous turn.
size_t server_instance::total_queued_bytes() const
{
    size_t total = 0;
    for (const auto& [_, conn] : m_clients)
        total += conn->write_queue.bytes();
    for (const auto& [_, uc] : m_upstreams)
        total += uc->write_queue.bytes();
    return total;
}

// The TCP listener lifted out of setup() so the address family is one branch,
// with SOCK_CLOEXEC because every worker would otherwise inherit this port and
// hold it after the daemon exits.
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

    // Once here rather than six times per accept: everything below is cloned
    // onto every connection this listener hands out.  On a connection storm --
    // which the comment below says this path is measured on -- that was six
    // syscalls per accept for values the socket already had.
    socket_tuning::tcp_listener_defaults(m_listen_fd, 131072, 0);

    // No TCP_DEFER_ACCEPT, because a connection in SYN-RECV is one this server
    // does not know exists -- no on_connect, no count, and silently dropped
    // without FIN or RST when the listener closes -- at a measured cost of
    // about a sixth of the connection-establishment rate on a connection
    // storm.

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(m_listen_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        // ─── Say which port and why ─────────────────────────────────────────
        // Said out loud, because this path reported nothing at all while its
        // unix sibling reported a reason -- so for a port already in use the
        // CLI named a log that held nothing.
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

// The AF_UNIX listener, whose mechanism is shared/unix_listener.h's; what
// stays here is which member holds the fd and the record of which path was
// bound.
bool server_instance::setup_unix_listener(const std::string& path)
{
    // One node per shard, for the reason the cache gives: a path is one
    // listener, and the second process to bind it unlinks the first.  Every
    // shard of a server answers every request, so which node a caller picks
    // does not matter here -- it matters on the cache, and the rule is the
    // same so the two cannot drift.
    const std::string mine = socketley::unix_sock::shard_listen_path(
        path, get_shard_index(), get_shards());
    auto r = socketley::unix_sock::bind_listener(mine);
    if (r.fd < 0)
    {
        LOG_ERROR(("server: " + r.error).c_str());
        return false;
    }
    m_listen_fd = r.fd;

    // Remembered so teardown() removes exactly the node this bind created,
    // because a runtime edited between start and stop would unlink a path it
    // never bound.
    m_bound_listen_path = mine;
    return true;
}

// The same three questions setup() asks below, in the same order and without
// the syscalls, so the manager can refuse a second claim on an address before
// a worker is forked to discover it.  Kept next to setup() because the two
// have to agree: an answer here that setup() does not honour is a refusal
// nobody earned.
// The one number both this and listen_addresses() are built from, so the port
// `ps` prints and the port the manager refuses a collision on cannot drift.
uint16_t server_instance::effective_port() const
{
    if (!get_listen_path().empty())
        return 0;                                   // a path, not a port
    if (get_port() == 0 && !get_owner().empty())
        return 0;                                   // internal-only: binds nothing
    return get_port() ? get_port() : server_default_port;
}

void server_instance::listen_addresses(std::vector<std::string>& out) const
{
    // A listen path and a port are mutually exclusive -- listen_config_refusal
    // in setup() is what makes that true -- so this is a full answer, not the
    // first half of one.
    const std::string listen_path(get_listen_path());
    if (!listen_path.empty())
    {
        out.push_back("unix:" + listen_path);
        return;
    }

    // Internal-only: a server reachable through its owner and through nothing
    // else binds no socket, so it claims no address and collides with nobody.
    if (get_port() == 0 && !get_owner().empty())
        return;

    // Datagrams and streams are separate namespaces in the kernel, and a UDP
    // server beside a TCP one on the same number is two listeners that never
    // meet -- measured, both up, each hearing only its own traffic.
    out.push_back((m_udp ? "udp:" : "tcp:") + std::to_string(effective_port()));
}

bool server_instance::setup(event_loop& loop)
{
    // Nothing is freed here, because teardown() deliberately kept the structs
    // the kernel has not finished with, and clearing them read a freed
    // io_request.
    m_active_fds.clear();
    m_active_fds.reserve(256);  // Pre-allocate to avoid reallocs on first connections
    // And the shared view of it, or a restart leaves siblings routing to
    // connections that no longer exist and reported to the script as clients
    // it has.
    shard_clients_table().clear_own();

    m_loop = &loop;
    m_ring_loop = &loop;

#ifndef SOCKETLEY_NO_LUA
    // What a finished await owes back.  Installed here rather than at the
    // script's load, because a runtime can be stopped and started again on the
    // same context and the hold belongs to this run's connections.
    if (lua())
        lua()->suspender().set_await_ended(
            [this](uint64_t ctx) { release_await_hold(ctx); });
#endif

    // Fix this runtime's half of every conn_ref it is about to mint, so every
    // name handed out over one run carries the same owner.
    owner_key();

    // The occupied flags survive a stop because a deregistered owner's
    // completions are dropped and never lower them, so this asks the loop --
    // zero means every request is free, and a full owner table leaves them
    // alone rather than acting on an unknown.
    if (loop.owner_inflight(this) == 0 && !loop.owner_table_full())
    {
        m_accept_armed         = false;
        m_idle_sweep_armed     = false;
        m_relay_deadline_armed = false;
        m_accept_backoff_armed = false;
        m_await_sweep_armed    = false;
        m_udp_recv_armed       = false;
        m_udp_recv_rearm_due   = false;
        // Nothing in the ring names any of them any more.
        m_accept_spent.clear();
        m_udp_recv_spent.clear();
    }

    // Cache config getters once at setup to avoid virtual calls on the hot path
    refresh_cached_limits();

    // Pre-allocate the connection pool if empty (first run or after teardown)
    if (m_conn_pool.empty())
    {
        uint32_t pool_size = std::max(512u, m_max_conns_cached > 0 ? m_max_conns_cached / 4 : 512u);
        m_conn_pool.reserve(pool_size);
        for (uint32_t i = 0; i < pool_size && i < 2048; i++)
            m_conn_pool.push_back(socketley::make_connection<server_connection>());
    }

    // ── TLS listener ────────────────────────────────────────────────────────
    // Certificates are read here at setup because that is blocking file I/O
    // the handshake never does, rebuilt on every start so `reload` installs a
    // renewed one -- and every refusal returns false rather than falling
    // through to a plaintext listener.
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
            // it, so this says what it cost.
            LOG_ERROR("server: TLS listener not started -- the certificate, key or "
                      "client CA could not be loaded");
            return false;
        }
        m_tls = std::move(ctx);
    }

    // ─── --listen unix:/path/to.sock ────────────────────────────────────────
    // Checked here rather than only in the flag parser, because this is the
    // one function every route to a listening socket passes through.
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
        // The set is judged by its longest member: a shard whose node does not
        // fit in the kernel's 108 bytes is a shard nothing can reach, and it
        // would fail at the bind with the earlier shards already serving.
        if (const std::string msg = socketley::unix_sock::shard_listen_path_refusal(
                listen_path, get_shards()); !msg.empty())
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

    // Internal-only server, where a listen path is a listener, so a runtime
    // that has one is not this case however its owner is set.
    if (listen_path.empty() && get_port() == 0 && !get_owner().empty())
        return true;

    uint16_t port = get_port();
    if (port == 0)
        port = server_default_port;

    if (m_udp)
    {
        m_udp_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (m_udp_fd < 0)
            return false;

        int opt = 1;
        setsockopt(m_udp_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        setsockopt(m_udp_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

        // Larger than the 128 KB every other listener here takes, because this
        // is the one socket with no window to close and no retransmit behind
        // it: what overruns the receive buffer is gone silently.  Measured on
        // the burst a runtime inside one callback cannot drain -- 221 hundred-
        // byte datagrams survived on the kernel default, 2,184 on this.
        int udp_rcvbuf = 1024 * 1024;
        setsockopt(m_udp_fd, SOL_SOCKET, SO_RCVBUF, &udp_rcvbuf, sizeof(udp_rcvbuf));

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

        // The old recvmsg keeps its struct and this run takes a fresh one,
        // because a stop does not end it: arming a second on the same msghdr
        // gives the kernel two writers, and declining to arm left the
        // restarted server receiving nothing.
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

        // Here as well as on the path below, because this return is what made
        // --idle-timeout inert on a UDP server: the flag was accepted, `show`
        // reported it, and no sweep was ever armed to act on it.
        arm_idle_sweep();
        // The same return and the same shape of defect: --upstream filled
        // m_upstream_targets and nothing ever dialled them, so `stats` read
        // upstreams:0/1 for the life of the runtime.  An upstream is a TCP
        // socket this runtime dials and is no business of the family its own
        // listener was configured in.
        start_upstreams();
        return true;
    }

    // The listener in whichever family this runtime was configured for, with
    // everything below the same for both.
    if (!(listen_path.empty() ? setup_tcp_listener(port)
                              : setup_unix_listener(listen_path)))
        return false;

    // And a second one beside the port for callers already on this box.  Only
    // beside a PORT -- a runtime already on a node has nothing to add -- and
    // not under TLS, where a cleartext node would undo what the port was
    // configured to give.  Its failure is not this runtime's failure: the port
    // is up either way.
    // get_port() and not `port`, which is 8000 by default a few lines up: the
    // daemon asks this same question about the configured value, and feeding
    // the two sides different numbers is exactly what one shared rule exists
    // to prevent.
    if (socketley::unix_sock::wants_companion(get_type(), get_port(), listen_path,
                                              get_tls(), is_udp(), get_shards())
        && !get_companion_path().empty())
    {
        // Made once and kept: the object owns an io_request the ring may still
        // be holding, and freeing it on a stop leaves dispatch_cqe reading a
        // token out of freed storage -- which is what the sanitizer found the
        // first time this was written with a reset() in teardown.
        if (!m_companion)
            m_companion = std::make_unique<socketley::unix_companion>(
                std::string(get_companion_path()),
                [this](int fd) { return adopt_client(fd, /*from_unix=*/true); });
        m_companion->start(loop);
    }

    // Setup provided buffer ring for zero-copy reads
    m_use_provided_bufs = loop.setup_buf_ring(BUF_GROUP_ID, BUF_COUNT, BUF_SIZE);
    // On, at every connection count measured, because this runtime declines a
    // read at the watermark in no place at all -- see the proxy's
    // MULTISHOT_MIN_CLIENTS for the rule that answer is the other half of.
    m_recv_multishot = m_use_provided_bufs && loop.recv_multishot_enabled();
    // Bundled recv, probed by a real submission and switchable by
    // SOCKETLEY_RECV_BUNDLE=0, which is also the A/B switch on one binary.
    m_recv_bundle = m_recv_multishot && loop.recv_bundle_enabled();

    // Multishot accept where supported, but not direct descriptors, because
    // cqe->res would be a fixed index and setsockopt and getpeername need a
    // real fd.
    m_direct_accept = false;
    m_multishot_active = event_loop::supports_multishot_accept();

    // The old accept chain keeps its request and this run takes a fresh one,
    // because nothing reaps the ring between a stop and the start that follows
    // -- and a second submission on one request overwrites its owner token,
    // leaving one slot owing a completion for ever and discounting the other.
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

    // SOCKETLEY_HTTP_REVALIDATE=0 puts disk mode back on an open and read per
    // request, read here so a restart picks it up.
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

    arm_idle_sweep();

    // Create splice pipe for zero-copy HTTP file serving
    // No runtime-wide pipe: each connection makes its own when it takes the
    // zero-copy path, so nothing here has to exist before the first request.
    m_splice_live = 0;

    start_upstreams();

    return true;
}

// What start_upstreams() undoes, and the reason both are functions: teardown()
// has two exits as well, and the pair has to be called from the same number of
// places or a restart frees a struct the ring still names.
void server_instance::stop_upstreams(event_loop& loop)
{
    // Set false by any withdrawal the ring refused, reported once rather than
    // per upstream, because they all fail for the same reason and together.
    bool timers_withdrawn = true;

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
        uc->established = false;
        // Release write queue refs
        uc->write_queue.clear();
        if (!uc->write_pending)
        {
            for (size_t j = 0; j < uc->write_batch_count; j++)
                uc->write_batch[j].clear();
            uc->write_batch_count = 0;
        }

        // The reconnect timer is attached to no fd, so its owner stays set and
        // it is withdrawn only to stop the wait being thirty seconds this
        // instance spends in the graveyard.
        if (uc->timeout_pending)
            timers_withdrawn &= loop.submit_timeout_remove(&uc->timeout_req);

        if (uc->read_pending || uc->write_pending || uc->timeout_pending)
            m_upstream_retired.push_back(std::move(uc));
    }
    m_upstreams.clear();

    if (SOCKETLEY_UNLIKELY(!timers_withdrawn))
        LOG_WARN("server: an upstream reconnect timer could not be withdrawn — this "
                 "instance stays retired until it fires on its own");
}

// Connect to upstreams with nothing to clear, because stop_upstreams() either
// dropped the previous structs or retired the ones with work still in the
// ring.  Its own function because setup() has two exits and both owe it.
void server_instance::start_upstreams()
{
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
}

void server_instance::teardown(event_loop& loop)
{
    // The requests this server is owed go first, because their answers have
    // nowhere to land -- and the last read's cache batch is posted afterwards,
    // so a stop does not throw away messages that arrived before it.
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
            // The recvmsg holds a reference to the socket, so close_fd submits
            // the cancel and holds the number until both have reported, which
            // is what keeps the descriptor from being reused under a
            // completion still naming it.
            close_tracked(m_udp_fd);
            m_udp_fd = -1;
        }
        m_udp_peers.clear();
        m_udp_peer_idx.clear();
        // This exit dials upstreams like the other one, so it gives them up
        // like the other one.  Without it they stayed in m_upstreams with
        // reads still in the ring and the next start() freed them under the
        // kernel -- a heap-use-after-free the fuzz target reported the moment
        // a UDP server could reach running state.
        stop_upstreams(loop);
        // Before the return, and this is the other half of arming the sweep on
        // the UDP path at all: this exit never reached the withdrawal below, so
        // the first version of that change left a timeout owed and the fuzz
        // target said so on the next run -- "the ring still owes this instance
        // a completion long after it stopped".
        withdraw_timers(loop);
        m_loop = nullptr;
        return;
    }

    // Shut down and then close through close_fd, because the cancel is what
    // ends a multishot accept and holding the number until both it and the
    // accept have reported is what makes the order hold -- with shutdown()
    // first, since it is what leaves the SO_REUSEPORT group.
    if (m_listen_fd >= 0)
    {
        shutdown(m_listen_fd, SHUT_RDWR);
        close_tracked(m_listen_fd);
        m_listen_fd = -1;
    }

    // Stopped, not freed: closed first and unlinked after, which its own stop()
    // does in that order, while the object stays for as long as this instance
    // does.  See setup() for why freeing it here was wrong.
    if (m_companion)
        m_companion->stop();

    // And the socket node for a unix listener, after the close, because
    // unlinking first leaves a live listener bound to a path no longer in the
    // filesystem.
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
                // The same drain through the record layer, because writing the
                // queue straight to the socket puts plaintext on a connection
                // whose peer is decrypting -- and an unfinished handshake has
                // no keys, so its queue is dropped.
                if (conn->tls_state != tls_conn_ready)
                    continue;
                while (!conn->write_queue.empty())
                {
                    const auto& msg = conn->write_queue.front();
                    if (tls_context::ssl_write(conn->ssl, msg.data(),
                                               static_cast<int>(msg.size())) <= 0)
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
                if (!socketley::write_all(fd, msg.data(), msg.size())) break;
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

        // The cache requests were revoked above so nothing is owed, and
        // leaving the count standing put a struct in the pool whose backlog
        // the next client inherited.
        conn->cache_pending = 0;

        // The slot first, because it is what unregisters the file and until
        // then the close does not really close it -- and a multishot recv on a
        // fixed index is counted on the index, so close_fd() sees nothing
        // armed and submits no cancel.
        release_fixed_slot(conn.get());

        // Shutdown before closing, because it completes pending reads and
        // writes synchronously through the socket's wait queue and avoids the
        // cancel-after-close race.
        shutdown(fd, SHUT_RDWR);
        close_tracked(fd);

        // The file read and the file-to-pipe splice target the file fd, so
        // closing the file ends them while file_buf stays allocated, being
        // where the kernel writes.
        if (conn->file_fd >= 0) { close_tracked(conn->file_fd); conn->file_fd = -1; }
        if (conn->splice_file_fd >= 0) { close_tracked(conn->splice_file_fd); conn->splice_file_fd = -1; }
        conn->splice_remaining = 0;
        conn->splice_pipe_pending = 0;
        conn->splice_pending = false;

        // The queue is ours to drop and the batch is not, because a write that
        // reached the ring is reading out of write_batch[0].
        conn->write_queue.clear();
        if (!conn->write_pending)
        {
            for (size_t i = 0; i < conn->write_batch_count; i++)
                conn->write_batch[i].clear();
            conn->write_batch_count = 0;
        }
    }

    // Empty m_clients: idle structs go back to the pool, the rest to the
    // retired list, where they stay valid until their completions arrive.
    for (auto& [fd, conn] : m_clients)
        release_conn(std::move(conn));
    m_clients.clear();

    stop_upstreams(loop);

    // Close splice pipe
    // The pipes went with the connections that owned them.
    m_splice_live = 0;

    withdraw_timers(loop);

    // The armed flags are left standing because a withdrawn timeout is still
    // owed a completion that cannot have landed yet, and m_idle_sweep_req
    // keeps its owner because nulling it made the loop drop the sweep's
    // completion and leave the flag true for ever.
    m_loop = nullptr;
    m_multishot_active = false;
    m_master_fd = -1;

    // Tell every origin that what it routed here has nowhere to go, as a
    // message named by the same conn_ref rather than a reach into the origin's
    // private table.
    for (auto& [handle, fc] : m_forwarded)
    {
        (void)handle;
        route_relay::drop(get_runtime_manager(), fc.origin, get_name(), fc.ref);
    }
    m_forwarded.clear();
    m_forwarded_by_ref.clear();

    // And every connection this runtime routed away, which nothing told
    // before, so a target kept an entry per routed connection naming a runtime
    // that had gone -- unbounded across restarts and counted as live.
    {
        auto* mgr = get_runtime_manager();
        for (const auto& [serial, target_name] : m_routes)
            route_relay::close(mgr, target_name, get_name(),
                               conn_ref{owner_key(), serial});
    }

    // Our own side too, so a name minted before the stop does not resolve
    // after it.
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
        // Stopped, so nothing may be submitted, but the buffer this completion
        // carries belongs to a shared group and a timer that completes here is
        // no longer armed.
        return_provided_buf(cqe);
        if (req == &m_idle_sweep_req)          m_idle_sweep_armed = false;
        else if (req == &m_relay_deadline_req) m_relay_deadline_armed = false;
        else if (req == &m_accept_backoff_req) m_accept_backoff_armed = false;
        else if (req == &m_udp_recv->req)       m_udp_recv_armed = false;
        else if (req == m_accept_req.get()) m_accept_armed = false;
        return;
    }

    // Remembered before the dispatch because the handler may release the
    // struct and the request with it; an accept or a timer names no
    // connection.
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
            if (SOCKETLEY_LIKELY(conn && req->generation == conn->generation))
            {
                // Two readers of the same operation, told apart by which request
                // the completion names -- the way the two splice arms are.
                if (req == &conn->file_read_req)
                    handle_file_read(cqe, req);
                else if (req == &conn->stream_req)
                    handle_file_stream(cqe, conn);
            }
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
            // No `else`: the pipe belongs to the connection rather than to the
            // runtime, and a struct that is no longer in m_conn_idx has either
            // been cleaned already or is in m_conn_retired, which holds it
            // until conn_ops_pending() is false and then releases it through
            // pool_release().  There is nothing runtime-wide left to hand back,
            // which is what made the old branch necessary.
            break;
        }
        case op_read:
        case op_read_provided:
        case op_recv_multishot:
        case op_recv_multishot_bundle:
        case op_write:
        case op_writev:
        {
            const bool is_read = is_read_op(req->type);

            // The descriptor says where to look and the request address and
            // generation say whether what we found is who submitted it,
            // because an upstream's fd can be reissued to a client.
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
                // Gated rather than left to the comparison: with no
                // --idle-timeout the timeout is zero seconds, so every
                // connection is past it and arming this sweep for the
                // handshake deadline alone would close the lot.
                const bool sweep_idle = (m_idle_timeout_cached > 0);
                const auto hs = std::chrono::seconds(tls_handshake_deadline_secs);
                bool heads_left = false;
                // Counted and reported once for the tick rather than per
                // connection: the attack this deadline exists for is many
                // peers at once, so a line each would be a log flood produced
                // by the defence.
                uint32_t hs_dropped = 0, head_dropped = 0;
                bool drains_left = false;
                for (int cfd : m_active_fds)
                {
                    auto* cconn = m_conn_idx[cfd];
                    if (!cconn)
                        continue;
                    // A refused peer that is still sending after the bound
                    // is cut off, which ends the read the drain was holding.
                    if (cconn->closing && cconn->drain_on_close)
                    {
                        if (now > cconn->header_deadline)
                        {
                            cconn->drain_on_close = false;
                            shutdown(cfd, SHUT_RD);
                        }
                        else
                            drains_left = true;
                    }
                    if (cconn->closing)
                        continue;
                    // A peer that has not finished its handshake is not a
                    // client yet, so this one does not wait for a timeout
                    // nobody configured.
                    if (cconn->tls_state == tls_conn_handshake &&
                        (now - cconn->handshake_since) > hs)
                    {
                        cconn->closing = true;
                        shutdown(cfd, SHUT_RD);
                        ++hs_dropped;
                        continue;
                    }
                    // A head that arrived in part and stopped.  Not the idle
                    // question: this connection HAS spoken, it just never
                    // finished saying anything a request could be made of.
                    if (cconn->awaiting_headers)
                    {
                        if (now > cconn->header_deadline)
                        {
                            // Answered, not dropped: this connection HAS
                            // spoken HTTP, so there is a protocol to say it in
                            // -- which is what the proxy does with the same
                            // status on the same deadline.  refuse_http_request
                            // sets closing itself.
                            cconn->awaiting_headers = false;
                            refuse_http_request(cconn, http_408_response(), /*drain=*/false);
                            ++head_dropped;
                            continue;
                        }
                        heads_left = true;
                    }
                    if (sweep_idle && (now - cconn->last_activity) > timeout)
                    {
                        cconn->closing = true;
                        shutdown(cfd, SHUT_RD);
                    }
                }
                // Decided by the walk that just finished rather than kept as a
                // count, because a connection can stop awaiting headers on any
                // read and nothing would have decremented it.
                m_headers_outstanding = heads_left;
                m_drains_outstanding  = drains_left;

                // A peer dropped on a deadline has nothing said to it -- there
                // is no protocol yet to say it in -- so the log is the only
                // record that this and not something else closed it.  Which
                // matters because the deadline is flat by choice: if half a
                // minute turns out to be too little for somebody's slow
                // client, the symptom is connections failing at random and
                // this line is what points at the cause.
                if (hs_dropped > 0)
                    LOG_WARN(("server \"" + std::string(get_name()) + "\": dropped " +
                              std::to_string(hs_dropped) + " connection(s) that did not "
                              "finish a TLS handshake within " +
                              std::to_string(tls_handshake_deadline_secs) + "s").c_str());
                if (head_dropped > 0)
                    LOG_WARN(("server \"" + std::string(get_name()) + "\": answered 408 to " +
                              std::to_string(head_dropped) + " connection(s) whose request "
                              "head stopped arriving within " +
                              std::to_string(http_header_deadline_secs) + "s").c_str());
                // A UDP peer has no connection to close, so the same timeout
                // means forgetting it: it is out of the broadcast fan-out and
                // out of the count `ps` prints, and its next datagram enters
                // it again.  Without --idle-timeout nothing is swept and the
                // eviction in find_or_add_peer is the only bound, which is
                // what keeps this from changing behaviour for anyone who has
                // not asked for a timeout.
                if (sweep_idle && m_udp && !m_udp_peers.empty())
                    forget_idle_udp_peers(now, timeout);

                if (sweep_idle || m_tls || m_headers_outstanding || m_drains_outstanding)
                    m_idle_sweep_armed = m_loop->submit_timeout(&m_idle_sweep_ts, &m_idle_sweep_req);
            }
#ifndef SOCKETLEY_NO_LUA
            // A handler that stopped on an await and never got its answer.
            // The same shape as every other deadline here: the wait is given
            // up on rather than waited out, and the script is told, so
            // `local v, err = self.cache(...)` returns either way.
            else if (req == &m_await_sweep_req)
            {
                m_await_sweep_armed = false;
                if (lua())
                {
                    auto& sus = lua()->suspender();
                    // The same clock the record was armed on; see shared/coarse_clock.h
                    // on why a deadline armed on one and tested on the other is
                    // wrong by a tick in whichever direction the pair happens to sit.
                    const size_t gone = sus.expire(socketley::coarse_now());
                    if (gone > 0)
                        LOG_WARN(("server \"" + std::string(get_name()) + "\": " +
                                  std::to_string(gone) + " callback(s) gave up waiting for "
                                  "the linked cache after " +
                                  std::to_string(cache_await_ms / 1000) + "s").c_str());
                    // Re-armed from its own firing and only while somebody is
                    // still waiting, so the chain stops on its own.
                    if (!sus.idle())
                        arm_await_sweep();
                }
            }
#endif
            // The relay-hold flag is lowered before the sweep and not after,
            // because the sweep re-arms this very request and clearing
            // afterwards would stop the timer for good.
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
    // The reachability rule goes here, after the dispatch, for the connection
    // the completion named, because all 16 guards count an armed read as a
    // completion that is owed and it is not one.
    finish_unreachable_conn(cqe_fd);

#ifdef SOCKETLEY_INVARIANTS
    inv_check_reachable(cqe_fd, "server::on_cqe");
#endif
}

// Everything before the verdict is a guard: a descriptor with no connection,
// or one that is not closing, is somebody else's business.
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
            // Bytes the client already handed us are not nothing left, so the
            // flush is followed by asking again -- one that reached the ring
            // answers `keep` and one that submitted nothing answers `finish`.
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
// Invariant (1) in this runtime's form: a client connection is its own pair
// except while piped to another, where the peer's read wakes both.
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
        // A cache request counts, because the channel's own wakeup is in the
        // ring and the reply comes back here, which is what the invariant is
        // about.
        h.in_flight = c->read_pending || c->write_pending ||
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

// O(1) removal from active_fds using the index stored in the connection, with
// the swapped-in element's index updated.
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

    // The same swap-remove at the same index in the shared table, because
    // `active_idx` is the index into both and a second structure rebuilt from
    // the first is how they come to disagree.
    shard_clients_table().swap_remove(idx);
}

inline void server_instance::submit_conn_read(server_connection* conn)
{
    // Bundle first and plain multishot behind it, both consumed through
    // for_each_cqe_buf, which cannot tell them apart.
    bool queued = false;
    if (conn->direct_fd)
    {
        // Every arm on `!queued` and none on `else`: with `else if`, a
        // multishot that was attempted and REFUSED skipped the two behind it,
        // so a busy ring closed a healthy client that a plain read would have
        // served.  The cache's copy of this chain was fixed; this one was not.
        if (m_recv_bundle)
            queued = m_loop->submit_recv_multishot_bundle_fixed_file(conn->fixed_idx, BUF_GROUP_ID, &conn->read_req);
        if (!queued && m_recv_multishot)
            queued = m_loop->submit_recv_multishot_fixed_file(conn->fixed_idx, BUF_GROUP_ID, &conn->read_req);
        if (!queued && m_use_provided_bufs)
            queued = m_loop->submit_read_provided_fixed_file(conn->fixed_idx, BUF_GROUP_ID, &conn->read_req);
        if (!queued)
        {
            conn->read_req.type = op_read;
            queued = m_loop->submit_read_fixed_file(conn->fixed_idx, fallback_read_buf(conn), server_connection::READ_BUF_SIZE, &conn->read_req);
        }
    }
    else
    {
        if (m_recv_bundle)
            queued = m_loop->submit_recv_multishot_bundle(conn->fd, BUF_GROUP_ID, &conn->read_req);
        if (!queued && m_recv_multishot)
            queued = m_loop->submit_recv_multishot(conn->fd, BUF_GROUP_ID, &conn->read_req);
        if (!queued && m_use_provided_bufs)
            queued = m_loop->submit_read_provided(conn->fd, BUF_GROUP_ID, &conn->read_req);
        if (!queued)
        {
            conn->read_req.type = op_read;
            queued = m_loop->submit_read(conn->fd, fallback_read_buf(conn), server_connection::READ_BUF_SIZE, &conn->read_req);
        }
    }

    // The flag goes up only once the read is queued, because setting it first
    // left the connection believing a read was in flight when nothing was.
    if (SOCKETLEY_UNLIKELY(!queued))
    {
        conn->read_pending = false;
        conn->closing = true;
        return;
    }
    conn->read_pending = true;
}

// See the declaration: the refusal is recorded on the connection and there is
// nothing left in the ring to carry it to finish_unreachable_conn().
bool server_instance::arm_conn_read(server_connection* conn)
{
    submit_conn_read(conn);
    if (SOCKETLEY_LIKELY(!conn->closing))
        return true;
    // Otherwise whichever operation is outstanding owns the teardown, which is
    // the same division close_conn()'s own precondition states.
    if (!conn_ops_pending(conn))
        close_conn(conn);
    return false;
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

// Everything an accepted descriptor goes through before it is a connection,
// lifted out of handle_accept because a second listener hands over a
// descriptor and nothing else: it has no completion of this one to resubmit,
// and copying the body would be two places to keep a connection contract in.
//
// `from_unix` and not m_bound_listen_path, because with two listeners the
// question is about THIS descriptor and not about the runtime.
//
// False means the descriptor has been dealt with and is not a client.
bool server_instance::adopt_client(int client_fd, bool from_unix)
{
    // Reject fds beyond our O(1) lookup table — they'd become zombie connections
    if (SOCKETLEY_UNLIKELY(client_fd >= MAX_FDS))
    {
        close_tracked(client_fd);
        return false;
    }

    // Max connections check
    if (SOCKETLEY_UNLIKELY(m_max_conns_cached > 0 && m_clients.size() >= m_max_conns_cached))
    {
        close_tracked(client_fd);
        return false;
    }

    // Nothing for a TCP client: setup_tcp_listener() carries TCP_NODELAY, the
    // keepalive trio and the receive buffer, and accept clones all of them.
    //
    // A unix client is not the same and keeps its own call: an accepted
    // AF_UNIX socket takes the DEFAULT receive buffer whatever its listener
    // holds -- measured, 212992 either way -- so this is the one of the six
    // that a unix listener cannot hand down.
    if (from_unix)
    {
        int rcvbuf = 131072;  // 128KB, fewer kernel-to-user copies
        if (setsockopt(client_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {}
    }

    auto conn = pool_acquire(client_fd);
    // Grown on demand: eight kilobytes charged at accept, before the client
    // has said anything, and clear() keeps whatever a busy connection grows
    // into anyway -- so the reserve only ever bought the first growth, for
    // every connection including the ones that never have a first command.

    // Sixteen kilobytes that a start WITH a buffer ring never writes to, which
    // is every start that gets one; only a start without one pays for them.
    if (SOCKETLEY_UNLIKELY(!m_use_provided_bufs) && !conn->read_buf)
        conn->read_buf = std::make_unique<char[]>(server_connection::READ_BUF_SIZE);
    conn->read_req = { this, conn->read_buf.get(), client_fd, server_connection::READ_BUF_SIZE,
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
            // The slot is already marked used, so a slot that cannot be
            // pointed at this fd has to go back at once: the connection
            // never learns its number.
            m_loop->free_fixed_file_slot(static_cast<uint32_t>(slot));
        }
    }

    auto* ptr = conn.get();
    m_clients[client_fd] = std::move(conn);
    m_conn_idx[client_fd] = ptr;
    ptr->active_idx = static_cast<uint32_t>(m_active_fds.size());
    m_active_fds.push_back(client_fd);

    // And into the shared table at the same position, with the ref minted
    // in pool_acquire() as this connection's name for its whole life.
    shard_clients_table().push(conn_ref{owner_key(), ptr->ref_serial});

    // A TLS listener gives every accepted socket a session before on_auth
    // and on_connect, because what those queue is plaintext that must go
    // through the record layer.
    if (SOCKETLEY_UNLIKELY(m_tls != nullptr))
    {
        ptr->ssl = m_tls->create_ssl_server();
        if (SOCKETLEY_UNLIKELY(!ptr->ssl))
        {
            // No session, no encryption, so no connection, because serving
            // this client in cleartext is worse than dropping it.
            shutdown(client_fd, SHUT_RDWR);
            ptr->closing = true;
            close_conn(ptr, false);
            return false;
        }
        ptr->tls_state = tls_conn_handshake;
        ptr->handshake_since = std::chrono::steady_clock::now();
    }

    auto now_tp = std::chrono::steady_clock::now();

    // Set whether or not --idle-timeout is on, because the handshake deadline
    // reads the same field and the clock is already taken one line up.  Under
    // the old guard it stayed at the epoch, which would have made the deadline
    // fire on the first sweep for every peer still handshaking -- legitimate
    // ones included.
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

    // The term is the failure table itself, because `!m_master_pw.empty()`
    // skipped the whole lockout for a server using the documented
    // on_master_auth callback -- and an empty table also means no
    // getpeername per accept.
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
                return false;
            }
        }
    }

    // on_auth fires before on_connect; a rejected client never triggers on_connect
    if (SOCKETLEY_UNLIKELY(!invoke_on_auth(client_fd)))
    {
        // A Lua on_auth that answers before rejecting leaves a write in
        // the ring, so the struct goes through release_conn rather than
        // straight back to the pool.
        shutdown(client_fd, SHUT_RDWR);
        ptr->closing = true;
        close_conn(ptr, false);
        return false;
    }

    invoke_on_connect(client_fd);

    // With on_disconnect, unlike the three refusals above: this client got its
    // on_connect one line up.
    if (SOCKETLEY_UNLIKELY(!arm_conn_read(ptr)))
        return false;
    return true;
}

void server_instance::on_loop_turn()
{
    // A direct send has no completion, so what one would have run runs here,
    // once the turn has settled what the connection wants -- a refusal marks
    // it closing only after its answer is queued.
    if (m_direct_serial != 0)
    {
        const auto it = m_conn_by_serial.find(m_direct_serial);
        m_direct_serial = 0;
        auto* c = (it != m_conn_by_serial.end() && it->second >= 0 && it->second < MAX_FDS)
                      ? m_conn_idx[it->second] : nullptr;
        if (c && !c->write_pending)
            after_write(c);
    }
    m_direct_gate.next_turn();
    if (m_companion)
        m_companion->pump();

    // The one read a UDP server has, when the ring would not take it.  Here
    // rather than on a timer because the timer needs the submission queue that
    // just refused, and this runs at the end of the very turn whose poll
    // drained it.
    if (SOCKETLEY_UNLIKELY(m_udp_recv_rearm_due) && !m_udp_recv_armed)
        arm_udp_recv();

    // Only while a dial is outstanding, so a server with no upstreams pays one
    // predictable branch and one with settled ones pays the same.
    if (SOCKETLEY_UNLIKELY(m_upstream_awaiting))
        note_upstream_established();

    // The same shape as the drain dispatch below, and for the same reason: a
    // streamed response that ended with a request already buffered behind it
    // cannot re-enter the parser from inside the callback that ended it.
    if (SOCKETLEY_UNLIKELY(!m_reparse_pending.empty()))
    {
        std::vector<uint64_t> due;
        due.swap(m_reparse_pending);
        for (const uint64_t serial : due)
        {
            auto it = m_conn_by_serial.find(serial);
            if (it == m_conn_by_serial.end())
                continue;
            const int fd = it->second;
            auto* c = (fd >= 0 && fd < MAX_FDS) ? m_conn_idx[fd] : nullptr;
            if (!c || c->closing || c->partial.empty())
                continue;
            parse_partial(c);
        }
    }

    // The upstream side of the same thing, resolved by conn_id: stable across
    // reconnects, and an upstream that went away in between simply is not found.
    if (SOCKETLEY_UNLIKELY(!m_upstream_drain_pending.empty()))
    {
        std::vector<int> due;
        due.swap(m_upstream_drain_pending);
        for (const int cid : due)
        {
            auto it = m_upstreams.find(cid);
            if (it == m_upstreams.end() || !it->second->connected || it->second->closing)
                continue;
            invoke_on_upstream_writable(cid);
        }
    }

    // Taken by value, because a script's on_writable may send enough to fill
    // the queue again and land a fresh serial in the member while this loop is
    // still walking it.
    if (SOCKETLEY_UNLIKELY(!m_drain_pending.empty()))
    {
        std::vector<uint64_t> due;
        due.swap(m_drain_pending);
        for (const uint64_t serial : due)
        {
            // Resolved now and not when it was queued: a connection that went
            // away in between is one whose producer has nothing left to write,
            // and its serial no longer resolving is how that is known.
            auto it = m_conn_by_serial.find(serial);
            if (it == m_conn_by_serial.end())
                continue;
            const int fd = it->second;
            auto* conn = (fd >= 0 && fd < MAX_FDS) ? m_conn_idx[fd] : nullptr;
            if (!conn || conn->closing)
                continue;
            // An internal producer first, and instead: a file being streamed to
            // this connection owes the rest of a response the script knows
            // nothing about, and on_writable is about the script's own sends.
            if (SOCKETLEY_UNLIKELY(conn->stream_remaining > 0))
            {
                stream_file_more(conn);
                continue;
            }
            invoke_on_writable(fd);
        }
    }
}

void server_instance::handle_accept(struct io_uring_cqe* cqe)
{
    int client_fd = cqe->res;

    // A shut-down listener completes its accepts with one of these, and
    // resubmitting would arm a second chain on the listener that start()
    // created.
    if (SOCKETLEY_UNLIKELY(client_fd == -ECANCELED || client_fd == -EBADF
                           || client_fd == -EINVAL || client_fd == -ENOTSOCK))
        return;

    if (SOCKETLEY_LIKELY(client_fd >= 0))
    {
        if (!adopt_client(client_fd, !m_bound_listen_path.empty()))
            goto resubmit_accept;
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

// Ciphertext in and plaintext into conn->partial, one call per read
// completion, which is what makes the handshake asynchronous with no loop
// waiting for one.
void server_instance::tls_feed(server_connection* conn, const char* data, size_t len)
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
            // diagnosis the other end gets and tls_flush puts it on the wire
            // before the teardown.
            conn->closing = true;
            return;
        }
        if (r == 0)
            return;   // another round; its records go out at the end of the read

        conn->tls_state = tls_conn_ready;
        // Deliberately falling through rather than returning, because under
        // TLS 1.3 a client's Finished and its first request routinely arrive
        // in one packet.
    }

    // Plaintext into partial, where every protocol above reads it from.
    //
    // Two shapes of this loop were tried and both measured nothing, on 512 KB
    // TLS echoes, six runs per arm, interleaved with the order reversed:
    //
    //   a 64 KB buffer instead of 16, to cut SSL_read calls from 32 per
    //   message to 8 -- ERR_clear_error alone is 1.9% of this worker's
    //   profile and it runs once per call.  Median 164 against 170 MB/s: it
    //   came out SLOWER, which is what a buffer that no longer fits beside
    //   the working set does.
    //
    //   ssl_read straight into the tail of `partial` through
    //   resize_and_overwrite, removing one full copy of every message.
    //   Median 171 against 173 at 512 KB, and 243 against 233 at 64 KB with
    //   the ranges overlapping.  The copy is sequential and already hot, so
    //   the prefetcher was paying for it and nobody else was.
    //
    // What DID move this path was the allocator, not the copying: see
    // set_read_buffer() in runtime_instance.cpp.
    char plain[16384];
    for (;;)
    {
        const int n = tls_context::ssl_read(conn->ssl, plain, sizeof(plain));
        if (SOCKETLEY_LIKELY(n > 0))
        {
            conn->partial.append(plain, static_cast<size_t>(n));
            // The same ceiling the cleartext path applies, checked inside the
            // loop, because one read completion can decrypt everything the
            // inbound BIO had buffered.
            if (SOCKETLEY_UNLIKELY(conn->partial.size() > read_buffer_bytes()))
            {
                conn->closing = true;
                break;
            }
            continue;
        }
        if (n < 0)
        {
            // Either the peer's close_notify or an unusable record, recorded
            // and applied once handle_read has parsed the bytes decrypted
            // above.
            conn->tls_peer_closed = true;
        }
        break;
    }
}

// A WebSocket connection is failed by telling the peer why and then closing,
// in one function because both of its callers are one decision made twice.
void server_instance::fail_ws_connection(server_connection* conn)
{
    conn->write_queue.push(ws_frame_close_protocol_error_shared());
    if (!conn->write_pending)
        flush_write_queue(conn);
    conn->closing = true;
}

// ─── THE PARSE, MADE RE-DRIVABLE ────────────────────────────────────────────
// Lifted out of handle_read() because a read completion is not the only moment
// `partial` can hold an unanswered request, and put in the loop and the three
// async-response arms rather than at the fifteen sites that mean "may have
// another".
// ─── A body handed over rather than gathered ─────────────────────────────────
// One read's worth at a time, which is what bounds the memory: `partial` holds
// the bytes only from the completion that delivered them to the call that takes
// them.  A 4 GB upload and a 4 KB one cost the same here.
// ── Sending a file in pieces, for a connection that cannot splice ───────────
//
// The splice arm carries a file with the pipe as its buffer and the write queue
// holding only the headers, so its memory does not follow the file's size.  A TLS
// connection has no splice arm, and what it had instead was one allocation of
// whatever was asked for.  This is the same shape as the splice arm, with a read
// where the splice was: one piece in flight, paced by the same crossing the write
// queue already reports, so the bound is the piece plus the queue.
bool server_instance::stream_file_begin(server_connection* conn, int ffd,
                                        uint64_t first, uint64_t len)
{
    conn->stream_fd        = ffd;
    conn->stream_offset    = first;
    conn->stream_remaining = len;
    conn->stream_pending   = false;
    // Forced: the queue holds the headers and nothing else at this point, and a
    // deferral here would be read below as a read that could not be submitted.
    stream_file_more(conn, true);
    // Nothing armed and nothing owed means the read could not be submitted, and
    // the headers have already gone out: the connection cannot be left promising
    // a length it will never send.
    if (!conn->stream_pending)
    {
        stream_file_cleanup(conn);
        return false;
    }
    return true;
}

void server_instance::stream_file_more(server_connection* conn, bool force)
{
    if (conn->stream_remaining == 0 || conn->stream_pending || conn->closing
        || conn->stream_fd < 0)
        return;
    // Paced on the same number a script would pace on, so a slow client holds a
    // piece and a queue rather than a file: without this the queue reaches its
    // hard bound and the connection is closed for a backlog it did not cause.
    if (!force && conn->write_queue.bytes() >= write_watermark_bytes())
        return;

    const size_t want = static_cast<size_t>(
        std::min<uint64_t>(conn->stream_remaining, HTTP_STREAM_PIECE));
    // Read into the string's own storage, so the piece is moved into the queue
    // rather than copied into it.
    conn->stream_buf.resize(want);
    conn->stream_req = { this, conn->stream_buf.data(), conn->fd,
                         static_cast<uint32_t>(want), op_file_read, conn->generation };
    if (!m_loop->submit_file_read(conn->stream_fd, conn->stream_buf.data(),
                                  static_cast<uint32_t>(want), conn->stream_offset,
                                  &conn->stream_req))
        return;
    conn->stream_pending = true;
}

void server_instance::stream_file_cleanup(server_connection* conn)
{
    if (conn->stream_fd >= 0) { close_tracked(conn->stream_fd); conn->stream_fd = -1; }
    conn->stream_buf.clear();
    conn->stream_buf.shrink_to_fit();
    conn->stream_offset    = 0;
    conn->stream_remaining = 0;
}

void server_instance::handle_file_stream(struct io_uring_cqe* cqe, server_connection* conn)
{
    conn->stream_pending = false;

    if (SOCKETLEY_UNLIKELY(conn->closing))
    {
        stream_file_cleanup(conn);
        if (!conn_ops_pending(conn))
            close_conn(conn);
        return;
    }

    // A short read or an error in the middle of a body whose length has already
    // been promised: there is no way to answer correctly from here, so the
    // connection goes rather than the client being left to wait for bytes that
    // are not coming.
    if (SOCKETLEY_UNLIKELY(cqe->res <= 0))
    {
        stream_file_cleanup(conn);
        conn->closing = true;
        maybe_shutdown_write(conn);
        if (!conn_ops_pending(conn))
            close_conn(conn);
        return;
    }

    const size_t got = static_cast<size_t>(cqe->res);
    conn->stream_buf.resize(got);
    conn->stream_offset    += got;
    conn->stream_remaining -= std::min<uint64_t>(conn->stream_remaining, got);
    queue_send(conn, std::make_shared<const std::string>(std::move(conn->stream_buf)));
    conn->stream_buf.clear();

    if (conn->stream_remaining > 0)
    {
        // Either there is room now, or the crossing the queue reports will bring
        // this back -- on_loop_turn() walks the same drain list a script's
        // producer is woken from.
        stream_file_more(conn);
        return;
    }

    stream_file_cleanup(conn);
    if (!conn->http_keep_alive)
    {
        conn->closing = true;
        maybe_shutdown_write(conn);
    }
    else
    {
        conn->proto = proto_unknown;
        if (!conn->read_pending && !arm_conn_read(conn))
            return;
        // Last statement, for the reason the splice arm gives: parse_partial()
        // can start the next response on this connection.
        parse_partial(conn);
    }
}

// A body the script is being handed in pieces does not have to be accumulated
// first, and accumulating it is not free: profiled on an 8 MiB upload through
// on_http_body, 18.1 per cent of the worker's core was handle_read appending the
// provided buffer into `partial` -- and the erase that follows moves whatever is
// behind it, so each byte is touched twice here before sol2 copies it a third
// time into a Lua string.  Delivered from the read buffer there is one copy left,
// the one the script's own string needs.
//
// Only the counted form takes this path.  A chunked body's framing is a resumable
// decoder whose state lives across reads, and splitting its bookkeeping between
// two callers is where a bug would hide; it keeps the accumulating path, which is
// the one its 147 split cases were verified against.
size_t server_instance::deliver_body_span(server_connection* conn, const char* p, size_t n)
{
    size_t off = 0;
    while (conn->body_remaining > 0 && off < n)
    {
        const size_t take = std::min(conn->body_remaining, n - off);
        conn->body_remaining -= take;
        // Read before the call, as in the accumulating twin: the script may send
        // from inside the callback, and this count is what it is told is left.
        const size_t left = conn->body_remaining;
        invoke_on_http_body(conn->fd, std::string_view(p + off, take), left);
        off += take;
        // The script may have disconnected this client, or a send may have: the
        // struct survives in m_conn_retired until no ring op names it, so reading
        // these fields is safe, but nothing more may be delivered into it.
        if (SOCKETLEY_UNLIKELY(conn->closing))
            return off;
    }
    // Said here rather than finished here, because finishing reaches
    // handle_http_request() and that belongs on the other side of this read's
    // buffer iteration, not inside it.
    if (conn->body_remaining == 0)
        conn->body_done_pending = true;
    return off;
}

void server_instance::deliver_body_chunks(server_connection* conn)
{
    if (SOCKETLEY_UNLIKELY(conn->body_chunked))
    {
        // No length to count down, so the decoder says where the payload runs
        // are.  It consumes from the front of what it is given, and what it
        // leaves is the start of framing it has not seen the end of yet.
        std::string_view in(conn->partial);
        for (;;)
        {
            std::string_view out;
            const chunk_step r = http_chunked_next(conn->chunk_dec, in, out);
            if (r == chunk_step::payload)
            {
                // Copied, not passed as a view: the erase below moves `partial`
                // and the script may send from inside the callback, either of
                // which invalidates a view into it.  One read's worth, so the
                // copy is bounded by the read and not by the body.
                const std::string piece(out);
                // nil for a chunked body, because how much is still owed is
                // genuinely unknown -- and 0 would claim the body has ended.
                invoke_on_http_body_unknown(conn->fd, piece);
                if (SOCKETLEY_UNLIKELY(conn->closing))
                {
                    conn->partial.erase(0, conn->partial.size() - in.size());
                    return;
                }
                continue;
            }
            const size_t consumed = conn->partial.size() - in.size();
            conn->partial.erase(0, consumed);
            if (r == chunk_step::done)
            {
                conn->body_chunked = false;
                // The one call that reaches zero, so "remaining reaches 0
                // exactly once per body" holds for both forms and a script
                // written against Content-Length works unchanged.
                invoke_on_http_body(conn->fd, std::string_view(), 0);
            }
            else if (r == chunk_step::bad)
            {
                // The framing is gone, so nothing after this is payload and
                // nothing can be resynchronised from it.
                conn->body_chunked = false;
                conn->http_head_saved.clear();
                refuse_http_request(conn, http_400_response());
            }
            return;   // need_more, done or bad all end this pass
        }
    }

    while (conn->body_remaining > 0 && !conn->partial.empty())
    {
        const size_t n = std::min(conn->body_remaining, conn->partial.size());
        conn->body_remaining -= n;
        // The count BEFORE the erase and the call, because the script may send
        // from inside the callback and anything holding a view into `partial`
        // across that is holding a view into a buffer that moved.
        const size_t left = conn->body_remaining;
        invoke_on_http_body(conn->fd, std::string_view(conn->partial.data(), n), left);
        conn->partial.erase(0, n);
        if (SOCKETLEY_UNLIKELY(conn->closing))
            return;   // the script disconnected it, or a send did
    }
}

void server_instance::finish_streamed_body(server_connection* conn)
{
    if (SOCKETLEY_UNLIKELY(conn->http_head_saved.empty()))
        return;

    // A copy, because handle_http_request() can reach code that resets this
    // connection, and the request it is given must not be the storage that
    // reset clears.  The views still point at http_head_saved, which reset
    // does not free before this call returns.
    http_request hreq = conn->http_req_saved;
    // Empty and not absent: the script was handed every byte as it arrived, so
    // req.body carrying them a second time is the memory this exists to avoid.
    hreq.body = std::string_view();
    handle_http_request(conn, hreq, 0);
}

// ─── A response the script writes itself ────────────────────────────────────
// on_http_request has to return a complete body, so a generated response had to
// fit in memory -- a file of any size was already served by the splice path and
// a generated one of any size was not expressible.  These three put the script
// on the other side of the same bound its reads already have.
bool server_instance::begin_chunked_response(server_connection* conn, int status,
    const std::vector<std::pair<std::string, std::string>>& headers)
{
    if (!m_loop || conn->closing || conn->response_started)
        return false;

    std::string head;
    head.reserve(160);
    head.append("HTTP/1.1 ");
    char sbuf[8];
    auto [s_end, s_ec] = std::to_chars(sbuf, sbuf + sizeof(sbuf), status);
    head.append(sbuf, s_end - sbuf);
    head.push_back(' ');
    head.append(http_reason(status));
    head.append("\r\n");

    // The script's headers first, minus the two this owns: a Content-Length
    // beside a chunked body is the message carrying two answers to how long it
    // is, which is the framing hole this server refuses on the way in.
    for (const auto& [k, v] : headers)
    {
        if (fnv1a_lower(k) == fnv1a("content-length") ||
            fnv1a_lower(k) == fnv1a("transfer-encoding") ||
            fnv1a_lower(k) == fnv1a("connection"))
            continue;
        head.append(k);
        head.append(": ");
        head.append(v);
        head.append("\r\n");
    }
    head.append("Transfer-Encoding: chunked\r\n");
    head.append(conn->http_keep_alive ? "Connection: keep-alive\r\n\r\n"
                                      : "Connection: close\r\n\r\n");

    conn->response_started = true;
    // Not for a HEAD: its headers are a GET's, and its body is nothing at all.
    conn->chunked_response = !conn->http_head;
    return queue_send(conn, std::make_shared<const std::string>(std::move(head)));
}

bool server_instance::send_response_chunk(server_connection* conn, std::string_view data)
{
    if (!m_loop || conn->closing || !conn->response_started)
        return false;
    // A HEAD asked for the headers and nothing else, so there is no chunk to
    // take -- answered false rather than dropped, because a script that thinks
    // it is sending a body to a HEAD has a bug this is the only report of.
    if (!conn->chunked_response)
        return false;
    // An empty chunk is the terminator's spelling, so it cannot be sent as
    // payload: it would end the response with the script still writing.
    if (data.empty())
        return true;

    std::string out;
    out.reserve(data.size() + 24);
    char hbuf[20];
    auto [h_end, h_ec] = std::to_chars(hbuf, hbuf + sizeof(hbuf),
                                      static_cast<uint64_t>(data.size()), 16);
    out.append(hbuf, h_end - hbuf);
    out.append("\r\n");
    out.append(data);
    out.append("\r\n");
    return queue_send(conn, std::make_shared<const std::string>(std::move(out)));
}

bool server_instance::end_chunked_response(server_connection* conn)
{
    if (!m_loop || !conn->response_started)
        return false;

    bool taken = true;
    if (conn->chunked_response)
        taken = queue_send(conn,
            std::make_shared<const std::string>(std::string("0\r\n\r\n")),
            /*even_when_closing=*/false);

    // response_started stays: it says this REQUEST has been answered, and the
    // fall-through to the static file and the 404 is tested after the callback
    // returns -- by which time end_response has already run.  Measured with it
    // cleared here: two status lines on one socket for a single request, the
    // streamed answer and then a 404 behind it.  It is cleared where the next
    // request's headers are parsed instead.
    conn->chunked_response = false;

    if (!conn->http_keep_alive)
    {
        conn->closing = true;
        return taken;
    }
    conn->proto = proto_unknown;
    // A request that was pipelined behind this one is already buffered, and the
    // client is waiting for its answer -- but this is reached from inside a Lua
    // callback, so the parser is entered on the next loop turn instead of from
    // within itself.
    if (!conn->partial.empty() && conn->ref_serial != 0)
        m_reparse_pending.push_back(conn->ref_serial);
    return taken;
}

void server_instance::parse_partial(server_connection* conn)
{
reparse:
    // A body being streamed is not a protocol.  These bytes belong to a request
    // whose headers were parsed already, so they go to the script and are
    // erased -- sniffing them would read a PUT's payload as the next request.
    // Checked before detection for that reason, which is where the proxy
    // checks the same thing.
    if (SOCKETLEY_UNLIKELY(conn->body_remaining > 0 || conn->body_chunked ||
                           conn->body_done_pending))
    {
        // A body that finished in the read buffer leaves nothing for
        // deliver_body_chunks() to do and everything below it still to do.
        conn->body_done_pending = false;
        deliver_body_chunks(conn);
        if (SOCKETLEY_UNLIKELY(conn->closing))
            return;
        if (conn->body_remaining > 0 || conn->body_chunked)
            return;   // more of it is still coming
        finish_streamed_body(conn);
        if (conn->closing || conn->partial.empty())
            return;
        goto reparse;   // what is left is the next request
    }

    // Multi-protocol auto-detection
    if (conn->proto == proto_unknown)
    {
        // Declared beats sniffed, because the sniffer reads the first four
        // bytes and a runtime of its own may legitimately open a line with
        // GET or PUT.
        if (m_wire_protocol != proto_unknown)
        {
            conn->proto = m_wire_protocol;
            goto reparse;
        }

        // Four bytes is what the tests below need, but a completed short line
        // is not ambiguous and is decided rather than waited on -- because a
        // line-protocol client writing "hi\n" will not send the fourth byte
        // until it is answered.
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
                // Out of the relay set from here on and stickily, set at the
                // same statement that decides the protocol so the two cannot
                // drift.
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
                refuse_http_request(conn, http_431_response());
                return;
            }
            // The size was bounded here and the time was not, so an upgrade
            // that stops one line short held its slot until the peer let go.
            arm_header_deadline(conn);
            return; // Incomplete headers
        }

        // The head is whole, so whatever clock was running on it is spent, the
        // same as in the plain HTTP branch below.
        conn->awaiting_headers = false;

        // Down here too, and not only in the plain HTTP branch below: an
        // upgrade is always a GET, so the refusals in this arm were cutting
        // their own bodies off for a HEAD the client sent before them on this
        // connection, under the Content-Length that says the body is there.
        conn->http_head = false;

        // Single-pass header scan: find Upgrade + Sec-WebSocket-Key without allocation
        {
            std::string_view hdrs(conn->partial.data(), hdr_end + 4);
            bool has_upgrade = false;
            size_t ws_key_pos = std::string_view::npos;
            size_t ws_key_end = std::string_view::npos;
            // Only "present and not 13" is refused.  A handshake that omits
            // the field altogether is what this server has always accepted,
            // and refusing it now would drop clients that work today for a
            // header no real one leaves out; a version it NAMES and we cannot
            // speak is the case where saying so is strictly better than 101.
            bool ws_version_seen = false;
            bool ws_version_13   = false;

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
                            // Through the same http_trim_ows the plain-HTTP
                            // scan below uses, because OWS is SP or HTAB and
                            // skipping only spaces left "Upgrade: websocket "
                            // matching nothing at all.
                            if (fnv1a_lower(http_trim_ows(line.substr(colon + 1)))
                                == fnv1a("websocket"))
                                has_upgrade = true;
                            break;
                        }
                        case fnv1a("sec-websocket-version"):
                        {
                            size_t vs = colon + 1;
                            while (vs < line.size() && line[vs] == ' ') ++vs;
                            std::string_view v = line.substr(vs);
                            ws_version_seen = true;
                            // A comma-separated list, because a client that
                            // offers "7, 13" is offering 13 and refusing it
                            // would be one refusal too many.  Each token
                            // trimmed on both ends: "13 " and " 13" are the
                            // same offer.
                            while (!v.empty())
                            {
                                const size_t comma = v.find(',');
                                std::string_view tok = v.substr(0, comma);
                                while (!tok.empty() && (tok.front() == ' ' || tok.front() == '\t'))
                                    tok.remove_prefix(1);
                                while (!tok.empty() && (tok.back() == ' ' || tok.back() == '\t'))
                                    tok.remove_suffix(1);
                                if (tok == "13")
                                {
                                    ws_version_13 = true;
                                    break;
                                }
                                if (comma == std::string_view::npos)
                                    break;
                                v.remove_prefix(comma + 1);
                            }
                            break;
                        }
                        case fnv1a("sec-websocket-key"):
                        {
                            // Trimmed for a second reason on top of the one
                            // above: the nonce is hashed, so whitespace folded
                            // into it makes this end hash a string the client
                            // did not and return an accept the client rejects.
                            const std::string_view kv =
                                http_trim_ows(line.substr(colon + 1));
                            ws_key_pos = static_cast<size_t>(kv.data() - hdrs.data());
                            ws_key_end = ws_key_pos + kv.size();
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

            // A nonce this end can hash, which an absent field and a field
            // whose whole value was whitespace both fail to be.
            const bool ws_key_present =
                ws_key_pos != std::string_view::npos && ws_key_end > ws_key_pos;

            if (!has_upgrade)
            {
                // Not a WebSocket upgrade — treat as HTTP request
                conn->proto = proto_http;
                conn->http_seen = true;   // see relay_targetable()
                // Fall through to proto_http handler below
            }
            else
            {
                // The upgrade path's header block is framed too, because
                // although a malformed block here cannot produce a second
                // answer it can still let this end and a proxy in front read
                // the handshake's fields differently.
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

                if (SOCKETLEY_UNLIKELY(ws_version_seen && !ws_version_13))
                {
                    refuse_http_request(conn, http_426_response());
                    return;
                }

                // Only "no nonce at all" is refused.  A key that is PRESENT
                // but does not decode to sixteen bytes (RFC 6455 4.1) still
                // gets 101, because the accept computed for it is correct for
                // the key that was sent and such a client works end to end
                // today -- so refusing it would take away a connection that
                // works, over a rule that protects the client and not this
                // end.  Missing is the other case: it cannot be completed at
                // all, and until this it was not refused but served as an
                // ordinary GET.
                if (SOCKETLEY_UNLIKELY(!ws_key_present))
                {
                    refuse_http_request(conn, http_400_ws_key_response());
                    return;
                }

                std::string_view ws_key = hdrs.substr(ws_key_pos, ws_key_end - ws_key_pos);

                // Send 101 response
                auto resp_msg = std::make_shared<std::string>();
                resp_msg->reserve(160);
                ws_handshake_response_into(*resp_msg, ws_key);
                conn->write_queue.push(std::shared_ptr<const std::string>(
                    std::move(resp_msg)));
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
        for (;;)
        {
            const ws_parse got = ws_parse_frame_inplace(conn->partial.data() + offset,
                                                        conn->partial.size() - offset, frame);
            if (got == ws_parse::incomplete)
                break;
            if (SOCKETLEY_UNLIKELY(got == ws_parse::invalid))
            {
                // A frame that can never become one is not a short read.  Read
                // as a short read it is asked again on every byte that follows,
                // so the connection stops answering and is never closed either
                // -- and with --idle-timeout off by default, that is forever.
                fail_ws_connection(conn);
                break;
            }
            if (SOCKETLEY_UNLIKELY(!frame.masked))
            {
                // RFC 6455 5.1 requires every frame from a client to be masked,
                // and the masking is what stops a chosen payload from reading
                // as a request to a cache or proxy in front of this listener.
                fail_ws_connection(conn);
                break;
            }
            offset += frame.consumed;

            // Control frames (opcode >= 0x8): process immediately, even mid-fragment
            if (frame.opcode >= 0x8)
            {
                std::string_view payload(frame.payload_ptr, frame.payload_len);
                if (frame.opcode == WS_OP_PING)
                {
                    // At most 127 bytes and exactly one recipient, so the
                    // shared form bought nothing and cost two allocations --
                    // make_shared for the control block, resize for the
                    // characters.  Built into a buffer the queue may still
                    // grow instead, and the empty pong a browser keepalive
                    // sends is two bytes, which never leaves the SSO.
                    //
                    // Through admit_send like every other write, because a peer
                    // that pings and never reads otherwise grew this queue by a
                    // byte for every byte it sent.
                    if (!admit_send(conn, 4 + payload.size(), false))
                        break;
                    std::string pong;
                    pong.reserve(4 + payload.size());
                    ws_frame_pong_into(pong, payload);
                    conn->write_queue.push_coalesced(std::move(pong),
                        server_connection::WRITE_COALESCE_LIMIT);
                    if (!conn->write_pending)
                        flush_write_queue(conn);
                }
                else if (frame.opcode == WS_OP_CLOSE)
                {
                    // RFC 6455 5.5.1: the Close sent in answer echoes the code
                    // it received, so a peer that said 1001 is not told 1000 by
                    // an end that never read what it said -- with ws_protocol.h
                    // holding which codes may be repeated and which are
                    // themselves the protocol error.
                    const uint16_t code = ws_close_echo_code(payload);
                    const auto* pre = ws_frame_close_pre(code);
                    // Four bytes with one recipient, written into the queue's
                    // own tail for the same reason as the pong above: the
                    // shared form would cost two allocations and buy nothing.
                    std::string close_frame;
                    if (!pre)
                        ws_frame_close_code_into(close_frame, code);
                    // RFC 6455 7.1.1 has the server close the TCP connection
                    // first, so the frame and our FIN leave together when
                    // nothing is queued ahead of them -- the reason and the
                    // measurement are send_final_and_fin()'s.
                    if (!send_final_and_fin(conn, pre ? std::string_view(**pre)
                                                      : std::string_view(close_frame)))
                    {
                        if (pre)
                            conn->write_queue.push(*pre);
                        else
                            conn->write_queue.push_coalesced(std::move(close_frame),
                                server_connection::WRITE_COALESCE_LIMIT);
                        if (!conn->write_pending)
                            flush_write_queue(conn);
                    }
                    conn->closing = true;
                }
                if (conn->closing)
                    break;
                continue;
            }

            // Whether a fragmented message is open, read off the opcode rather
            // than off ws_frag_len because a leading fragment may be empty.
            const bool message_open = conn->ws_frag_opcode != 0;

            // RFC 6455 5.4: a continuation belongs to a message that is open,
            // and a new message may not start inside one -- both of which were
            // silently concatenated into whatever was being reassembled.
            if (SOCKETLEY_UNLIKELY((frame.opcode == WS_OP_CONT) != message_open))
            {
                fail_ws_connection(conn);
                break;
            }

            // Compact only when this frame is part of a reassembly, because
            // the unfragmented fast path reads from payload_ptr into partial
            // and compacting first shifts the payload by header and mask.
            const bool needs_compaction = !frame.fin || message_open;
            if (frame.payload_len > 0 && needs_compaction)
            {
                std::memmove(conn->partial.data() + conn->ws_frag_len,
                             frame.payload_ptr, frame.payload_len);
            }

            if (!frame.fin)
            {
                // Non-final fragment: record opcode from first fragment, accumulate
                if (!message_open)
                    conn->ws_frag_opcode = frame.opcode;
                conn->ws_frag_len += frame.payload_len;
            }
            else if (message_open)
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

            // Once the connection is marked closing everything still buffered
            // belongs to a conversation that is over, so parsing it produces
            // responses the teardown discards.
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
        // Not while this connection is still serving the last request, because
        // a static response lives in state there is exactly one of and
        // starting a second overwrites all of it -- and the guard has to be
        // here rather than at submit_next_read, which a multishot recv walks
        // past.
        if (SOCKETLEY_UNLIKELY(conn->file_read_pending || conn->splice_pending ||
                               conn->splice_in_pending || conn->splice_out_pending ||
                               // The fifth arm, added later than this list and
                               // not added to it.  conn_ops_pending() carries
                               // it and says why: the streamed file's read
                               // writes into this struct's own buffer, so a
                               // second request starting while it is armed
                               // re-arms the kernel into the buffer the first
                               // one is still being served out of.
                               conn->stream_pending))
            return;

        // Wait for complete headers
        auto hdr_end = conn->partial.find("\r\n\r\n");
        if (hdr_end == std::string::npos)
        {
            if (conn->partial.size() > 16384)
            {
                refuse_http_request(conn, http_431_response());
                return;
            }
            arm_header_deadline(conn);
            return;
        }

        // The head is whole, so whatever clock was running on it is spent --
        // cleared here and not in the sweep, because the sweep may be thirty
        // seconds away and this connection is a client again now.
        conn->awaiting_headers = false;

        // Down before the refusals below, which can answer ahead of the
        // request line being parsed and would otherwise answer for the last
        // request's method.
        conn->http_head = false;

        // The block is judged before anything is parsed out of it, because a
        // bare LF makes "Host: x\nContent-Length: 38\r\n" one line whose
        // Content-Length is never seen and whose body bytes are read as the
        // next request.
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
        conn->http_head = (hreq.method == "HEAD");
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

        // Where this message ends is one decision shared with the proxy
        // through http_framing.h, because four framing shapes this server did
        // not know produced two answers to one message -- and first_crlf
        // equals hdr_end for a request with no header fields, which the
        // subtraction below has to survive.
        const size_t hdr_len =
            (hdr_end > first_crlf + 2) ? (hdr_end - first_crlf - 2) : 0;
        const http_request_framing_scan framing =
            http_scan_request_headers(full.substr(first_crlf + 2, hdr_len));

        if (SOCKETLEY_UNLIKELY(!framing.ok))
        {
            refuse_http_request(conn, http_400_response());
            return;
        }

        // A transfer coding this server does not implement, refused rather
        // than framed by a Content-Length that is not there -- treating the
        // chunk data as the next request is the answer that is not defensible.
        // Still 501 for a coding this server cannot take the framing off -- and
        // `chunked` with a script that asked for the body is now one it can.
        // The proxy forwards a chunked body without decoding it, which is all a
        // backend needs; delivering it to a script means taking the framing off,
        // and that decoder is the one piece the proxy could not lend.
        // Chunked and nothing else.  "gzip, chunked" is framable and its
        // contents are still compressed, so taking the framing off and handing
        // the bytes on as the body would hand on gzip and call it the body --
        // that stays 501, which is what a coding this does not implement is.
        const bool chunked_to_script =
            framing.transfer_encoding && framing.chunked
            && !framing.other_codings && wants_on_http_body();
        if (SOCKETLEY_UNLIKELY(framing.transfer_encoding && !chunked_to_script))
        {
            refuse_http_request(conn, http_501_response());
            return;
        }

        const size_t content_length = framing.content_length;

        // A body that cannot fit in `partial` is refused now, with an answer,
        // because waiting for it ends at handle_read's size cap with the
        // connection closed and nothing said.
        //
        // Unless nobody is going to gather it.  A script with on_http_body is
        // handed the bytes as they arrive and `partial` is erased behind them,
        // so the bound the refusal protects is never approached and the body's
        // size stops being this server's business -- which is what the proxy
        // has always done with a request body it forwards.
        const bool stream_body =
            chunked_to_script || (content_length > 0 && wants_on_http_body());
        if (SOCKETLEY_UNLIKELY(!stream_body && content_length >
                               read_buffer_bytes() - (hdr_end + 4)))
        {
            refuse_http_request(conn, http_413_response());
            return;
        }

        // The header pairs for the Lua API, deciding nothing, because a second
        // walk that came to its own conclusions about Content-Length is what
        // produced the table above.
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
                    // OWS is SP or HTAB, and skipping only spaces left the tab
                    // on the front of the value -- which made
                    // "Content-Length:\t4" get this server to hang up without
                    // answering.
                    hreq.headers.emplace_back(line.substr(0, colon),
                                              http_trim_ows(line.substr(colon + 1)));
                }
                line_start = line_end + 2;
            }
        }

        if (SOCKETLEY_UNLIKELY(stream_body))
        {
            // The head is copied because everything hreq holds is a view into
            // `partial`, and `partial` is about to be erased under it.  It is
            // re-parsed at the end rather than carried as fields: one parser
            // for the head means the streamed request and the gathered one
            // cannot come to different conclusions about it.
            conn->http_head_saved.assign(full.substr(0, hdr_end + 4));
            // Every view in hreq points into `full`, which is `partial`, and
            // `partial` is about to be erased under it.  The saved head is a
            // byte-for-byte prefix copy, so each view keeps its offset and
            // only its base moves -- which is what makes this one parse rather
            // than a second one that could disagree.
            {
                const char* from = full.data();
                const char* to   = conn->http_head_saved.data();
                auto rebase = [&](std::string_view& v) {
                    if (!v.empty())
                        v = std::string_view(to + (v.data() - from), v.size());
                };
                rebase(hreq.method); rebase(hreq.path);
                rebase(hreq.version); rebase(hreq.query);
                for (auto& kv : hreq.headers) { rebase(kv.first); rebase(kv.second); }
                hreq.body = std::string_view();
                conn->http_req_saved = std::move(hreq);
            }
            // For chunked there is no length: body_chunked is what says a body
            // is still owed, and the decoder holds the position in the framing.
            conn->body_chunked = chunked_to_script;
            conn->chunk_dec = http_chunked_decoder{};
            conn->body_remaining = chunked_to_script ? 0 : content_length;
            conn->partial.erase(0, hdr_end + 4);
            // Whatever of the body already arrived with the head goes now; the
            // rest is delivered by the branch at the top of this function as
            // the reads land.
            deliver_body_chunks(conn);
            if (SOCKETLEY_UNLIKELY(conn->closing))
                return;
            if (conn->body_remaining > 0 || conn->body_chunked)
                return;
            finish_streamed_body(conn);
            if (!conn->closing && !conn->partial.empty())
                goto reparse;
            return;
        }

        size_t total_expected = hdr_end + 4 + content_length;
        if (conn->partial.size() < total_expected)
            return;  // Need more body data

        hreq.body = full.substr(hdr_end + 4, content_length);

        handle_http_request(conn, hreq, total_expected);

        // Round again rather than waiting for a read that is not coming,
        // because a multishot recv has already moved the pipelined request
        // into `partial` while the client waits for its answer -- and back to
        // detection rather than a second parse, since duplicating the sniff is
        // how the copies disagree.
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
            auto result = resp::parse_message_views(buf, args, MAX_RESP_ARGS, argc,
                                                    consumed, read_bulk_limit());

            if (result == resp::parse_result::incomplete) break;
            // Anything that is not ok, and not a test against the one failure
            // that existed when this was written: a new parse_result would
            // otherwise fall through to `offset += consumed` with a consumed
            // the parser never set.
            if (result != resp::parse_result::ok)
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

            // Once the connection is marked closing everything still buffered
            // belongs to a conversation that is over, so parsing it produces
            // responses the teardown discards.
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

            // Once the connection is marked closing everything still buffered
            // belongs to a conversation that is over, so parsing it produces
            // responses the teardown discards.
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
            // Reset the request type, because leaving it as a provided-buffer
            // type makes the handler append ring buffer 0's contents and
            // return a buffer it never took.
            conn->read_req.type = op_read;
            bool queued;
            if (conn->direct_fd)
                queued = m_loop->submit_read_fixed_file(conn->fixed_idx, fallback_read_buf(conn), server_connection::READ_BUF_SIZE, &conn->read_req);
            else
                queued = m_loop->submit_read(fd, fallback_read_buf(conn), server_connection::READ_BUF_SIZE, &conn->read_req);
            if (SOCKETLEY_UNLIKELY(!queued))
            {
                conn->read_pending = false;
                conn->closing = true;
            }
            return;
        }

        // Connection closed or error, asked through conn_ops_pending(), so
        // that every operation still owed on this struct is counted.
        conn->closing = true;
        if (!conn_ops_pending(conn))
            close_conn(conn);
        return;
    }

    if (SOCKETLEY_UNLIKELY(m_idle_timeout_cached > 0))
        conn->last_activity = std::chrono::steady_clock::now();
    m_stat_bytes_in.fetch_add(static_cast<uint64_t>(cqe->res), std::memory_order_relaxed);

    // A connection on its way out takes nothing more in, because a multishot
    // recv stays armed after `closing` is set and went on filling `partial`
    // with everything the peer sent -- sixty megabytes of pings, held for a
    // client that had been dropped at the eight-megabyte write bound.
    if (SOCKETLEY_UNLIKELY(conn->closing))
    {
        if (is_provided)
            m_loop->for_each_cqe_buf(BUF_GROUP_ID, cqe, [](char*, uint32_t) {});
        const uint64_t drained = uint64_t{conn->drained_bytes} + static_cast<uint32_t>(cqe->res);
        conn->drained_bytes = static_cast<uint32_t>(std::min<uint64_t>(drained, DRAIN_LIMIT_BYTES + 1u));
        goto submit_next_read;
    }

    // On a TLS connection these bytes are ciphertext and tls_feed is what puts
    // plaintext into partial; everything below this point reads exactly the
    // same buffer it always did and knows nothing about TLS.
    if (is_provided)
    {
        // Reading the buffer id out of the CQE flags was correct only while
        // every completion carried one buffer, and a bundle names only its
        // first.
        m_loop->for_each_cqe_buf(BUF_GROUP_ID, cqe, [&](char* p, uint32_t n) {
            if (SOCKETLEY_UNLIKELY(conn->ssl != nullptr))
            {
                tls_feed(conn, p, static_cast<size_t>(n));
                return;
            }
            // Mid-body with nothing pending: these bytes are the script's and
            // nobody else's, so they go straight there.  `partial` has to be
            // empty for that -- bytes already accumulated come first, and this
            // read's would otherwise be delivered ahead of them.
            if (conn->body_remaining > 0 && !conn->body_chunked &&
                conn->partial.empty() && !conn->closing)
            {
                const size_t used = deliver_body_span(conn, p, static_cast<size_t>(n));
                if (used < n)
                    conn->partial.append(p + used, static_cast<size_t>(n) - used);
                return;
            }
            conn->partial.append(p, n);
        });
    }
    else if (SOCKETLEY_UNLIKELY(conn->ssl != nullptr))
    {
        tls_feed(conn, conn->read_buf.get(), static_cast<size_t>(cqe->res));
    }
    else
    {
        // The same decision at the other door, because a fix at one and not its
        // sibling is how this file grew most of its asymmetries: a runtime whose
        // reads do not come from the provided ring accumulates a streamed body
        // for exactly as little reason.
        if (conn->body_remaining > 0 && !conn->body_chunked &&
            conn->partial.empty() && !conn->closing)
        {
            const size_t n = static_cast<size_t>(cqe->res);
            const size_t used = deliver_body_span(conn, conn->read_buf.get(), n);
            if (used < n)
                conn->partial.append(conn->read_buf.get() + used, n - used);
        }
        else
        {
            conn->partial.append(conn->read_buf.get(), cqe->res);
        }
    }

    // This client has said something and is now owed an answer rather than
    // only listening, judged on `partial` rather than cqe->res because a
    // handshake record is not a client waiting -- and sticky, which keeps a
    // keep-alive HTTP client out of the deadline's reach.
    if (SOCKETLEY_UNLIKELY(!conn->spoke) && !conn->partial.empty())
        conn->spoke = true;

    if (SOCKETLEY_UNLIKELY(conn->partial.size() > read_buffer_bytes()))
    {
        // Said rather than done in silence.  What this used to be was
        // `closing = true` and nothing else: a websocket peer sending a frame
        // between this limit and WS_MAX_PAYLOAD -- which ws_parse_header
        // accepts up to sixteen megabytes -- lost its connection with no close
        // frame, no status and no line in the log.  Measured before this: a
        // 2 MB frame got an empty answer and a dead socket, where 900 KB was
        // echoed.
        //
        // 1009 and not 1002, because the frame was well formed and this end
        // simply will not hold it; a peer told "protocol error" concludes its
        // framing is broken and sends the same message again.
        // Once per connection: a read already in flight when the first one
        // tripped this lands afterwards and would say the same thing twice.
        const bool first_time = !conn->closing;
        if (first_time && conn->proto == proto_ws)
        {
            conn->write_queue.push(ws_frame_close_too_big_shared());
            if (!conn->write_pending)
                flush_write_queue(conn);
        }
        if (first_time)
        LOG_WARN(("server \"" + std::string(get_name()) + "\": a client sent "
                  + std::to_string(conn->partial.size()) + " bytes without a "
                  "complete message and this runtime holds at most "
                  + std::to_string(read_buffer_bytes())
                  + " -- dropped.  --read-buffer moves the limit").c_str());
        conn->closing = true;
        goto submit_next_read;
    }

    parse_partial(conn);

submit_next_read:
    // Relay traffic held across classification is released here, because every
    // path through this function reaches this label and only some classify --
    // and by now this read's own output is queued, so the held bytes append
    // behind it.
    if (SOCKETLEY_UNLIKELY(!conn->relay_hold.empty()) && !proto_unsettled(conn))
        relay_hold_flush(conn);

    // Everything this read produced for the cache goes now, one post for the
    // whole buffer, and nothing is left in the batch waiting for a message
    // that may never come.
    if (SOCKETLEY_UNLIKELY(!m_cache_store_batch.empty()))
        flush_cache_store();

    // close_notify is applied here because the read that carried it can carry
    // the last request ahead of it, and then one flush covers everything the
    // record layer owes -- at a label every path reaches.
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
            arm_conn_read(conn);
        }
    }
    else if (conn->closing)
    {
        // Our FIN is out and the peer may still be sending what we refused:
        // read it away until its EOF, because closing with it unread resets
        // the connection and takes our answer with it.
        if (m_loop && conn->wr_shutdown && !conn->read_pending && !conn->file_read_pending &&
            drains_on_close(conn))
            submit_conn_read(conn);
        // Nothing left in the ring for this connection, so it can go now;
        // otherwise whichever operation is outstanding owns the teardown.
        if (!conn_ops_pending(conn))
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
// The cookie carries the descriptor and the identity the connection had,
// because a client that aborts has its number reissued and its struct handed
// on -- and a request made on nobody's behalf uses -1, which no index
// resolves.
static constexpr uint64_t CACHE_COOKIE_NO_CONN = 0xFFFFFFFFull;

static inline uint64_t cache_cookie(const server_connection* conn, bool silent)
{
    if (!conn || silent)
        return CACHE_COOKIE_NO_CONN;
    return (static_cast<uint64_t>(conn->generation) << 32)
         | static_cast<uint64_t>(static_cast<uint32_t>(conn->fd));
}

#ifndef SOCKETLEY_NO_LUA
// ─── The cookie of a reply a script is waiting for ──────────────────────────
// A suspended handler is not a connection, so it needs a cookie no connection
// can produce.  The mark goes where the descriptor goes, beside
// CACHE_COOKIE_NO_CONN and for the same reason -- a real fd is below MAX_FDS,
// so neither value can be one.  The generation half is deliberately NOT used:
// next_io_generation() wraps, so a tag there would collide, quietly and once
// in four billion connections.
static constexpr uint64_t AWAIT_COOKIE_MARK = 0xFFFFFFFEull;

static inline uint64_t await_cookie(uint32_t id)
{
    return (static_cast<uint64_t>(id) << 32) | AWAIT_COOKIE_MARK;
}

static inline bool is_await_cookie(uint64_t cookie)
{
    return (cookie & 0xFFFFFFFFull) == AWAIT_COOKIE_MARK;
}

static inline uint32_t await_cookie_id(uint64_t cookie)
{
    return static_cast<uint32_t>(cookie >> 32);
}

// Which connection the callbacks inside this scope are serving.  Saved and
// restored rather than cleared, because one dispatch can reach another -- a
// script that answers by routing runs the target's callbacks on this stack.
class callback_conn_scope
{
public:
    callback_conn_scope(server_instance* s, server_connection* conn) noexcept
        : m_s(s), m_prev(s->m_callback_conn) { s->m_callback_conn = conn; }
    ~callback_conn_scope() noexcept { m_s->m_callback_conn = m_prev; }
    callback_conn_scope(const callback_conn_scope&)            = delete;
    callback_conn_scope& operator=(const callback_conn_scope&) = delete;

private:
    server_instance*   m_s;
    server_connection* m_prev;
};
#endif

void server_instance::flush_cache_store()
{
    if (SOCKETLEY_LIKELY(m_cache_store_batch.empty()))
        return;

    // Cleared whatever happens, because a batch the channel would not take is
    // lost and holding it only makes the next flush larger and no more likely
    // to be taken.
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

    // The cap, charged only to requests the client asked for, because closing
    // a connection over the server's own auto-store would punish a client for
    // a feature it never used.
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
        // The channel took nothing, so a command the client is waiting on is
        // answered by closing -- an error written now would arrive ahead of
        // the answers queued in front of it -- while the auto-store just goes.
        if (!silent && conn)
            conn->closing = true;
        return;
    }

    if (!silent && conn)
        ++conn->cache_pending;
}

#ifndef SOCKETLEY_NO_LUA
const char* server_instance::begin_cache_await(lua_State* th, std::string_view cmd)
{
    const std::string_view cname = get_cache_name();
    if (cname.empty())
        return "no cache is linked to this server (--cache)";

    auto* mgr = get_runtime_manager();
    if (SOCKETLEY_UNLIKELY(!mgr))
        return "this runtime has no runtime manager";
    if (SOCKETLEY_UNLIKELY(!lua()))
        return "this runtime has no script";

    // The handle is allocated here and not when the callback started: an
    // invocation that never waits must not be charged for the table entry, and
    // most never do.
    auto& sus = lua()->suspender();
    const lua_suspender::id_t id = sus.enrol_await(th);
    if (id == 0)
        return "self.cache may only be called from a callback that can wait, "
               "and not when this runtime already has its fill of waiting ones";

    // The connection this handler is answering, charged the same way a client's
    // own `cache get` is: a promised reply, which close_conn() and the FIN path
    // both defer on.  Without it a peer that half-closes after its request --
    // which is what every `echo | nc` does -- is gone before the answer exists.
    server_connection* held = m_callback_conn;
    if (held)
    {
        if (SOCKETLEY_UNLIKELY(held->cache_pending >= MAX_CACHE_PENDING))
            return "too many answers are already owed to this connection";
    }

    // Posted before the yield, so a channel that will not take it is a refusal
    // the script reads rather than a handler stopped for an answer nobody is
    // going to send.
    if (!mgr->requests().post(this, await_cookie(id), cname, cmd, request_class::client))
        return "the request channel is full";

    if (held)
        ++held->cache_pending;

    sus.note_await(id, cache_await_ms, held ? cache_cookie(held, false) : 0);
    arm_await_sweep();
    return nullptr;
}

void server_instance::release_await_hold(uint64_t ctx)
{
    if (ctx == 0 || ctx == CACHE_COOKIE_NO_CONN)
        return;

    const int      fd  = static_cast<int>(static_cast<int32_t>(ctx & 0xFFFFFFFFull));
    const uint32_t gen = static_cast<uint32_t>(ctx >> 32);
    if (fd < 0 || fd >= MAX_FDS)
        return;

    auto* conn = m_conn_idx[fd];
    if (!conn || conn->generation != gen)
        return;   // the connection went anyway, and took its count with it

    if (SOCKETLEY_LIKELY(conn->cache_pending > 0))
        --conn->cache_pending;

    // The close that was deferred while this answer was owed.
    if (SOCKETLEY_UNLIKELY(conn->closing) && conn->cache_pending == 0
        && !conn_ops_pending(conn))
        close_conn(conn);
}

void server_instance::arm_await_sweep()
{
    if (!m_loop || m_await_sweep_armed)
        return;

    // A second, not the sweep's thirty: this bounds a wait measured in the ten
    // seconds a callback gets, and a coarser tick would be most of the budget.
    m_await_sweep_ts.tv_sec  = 1;
    m_await_sweep_ts.tv_nsec = 0;
    m_await_sweep_req = { this, nullptr, -1, 0, op_timeout };
    m_await_sweep_armed = m_loop->submit_timeout(&m_await_sweep_ts, &m_await_sweep_req);
}
#endif

void server_instance::on_request_reply(uint64_t cookie, request_status st,
                                       std::string_view reply)
{
#ifndef SOCKETLEY_NO_LUA
    // First, because an await cookie carries an invocation id where this
    // function otherwise reads a descriptor, and a small id would resolve to
    // somebody else's connection.
    if (is_await_cookie(cookie))
    {
        if (!lua())
            return;
        // The hold this await took is let go by the suspender's own hook, after
        // the handler has run on -- so an answer the script writes on the way
        // out still finds the connection open.
        auto& sus = lua()->suspender();
        if (st == request_status::ok)
            sus.settle_value(await_cookie_id(cookie), reply);
        else
            sus.settle_nil(await_cookie_id(cookie), request_status_text(st));
        return;
    }
#endif

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

    // Written even when the connection is marked closing, because the client
    // asked for this line and its socket is open only because the answer is
    // owed.
    if (SOCKETLEY_LIKELY(m_loop != nullptr))
    {
        std::string text;
        if (SOCKETLEY_LIKELY(st == request_status::ok))
        {
            text.assign(reply);
        }
        else
        {
            // Said out loud rather than swallowed, because a client whose
            // `cache get` went to a stopped runtime used to receive nothing at
            // all.
            const char* why = request_status_text(st);
            text.reserve(8 + std::char_traits<char>::length(why));
            text.append("error: ").append(why);
        }

        if (!text.empty())
        {
            if (text.back() != '\n')
                text.push_back('\n');
            queue_send(conn, std::make_shared<const std::string>(std::move(text)), true);
        }
    }

    // The close close_conn() deferred, if this was the last answer owed and
    // nothing else is armed; otherwise the outstanding operation owns the
    // teardown.
    if (SOCKETLEY_UNLIKELY(conn->closing) && conn->cache_pending == 0
        && !conn_ops_pending(conn))
        close_conn(conn);
}

void server_instance::process_message(server_connection* sender, std::string_view msg)
{
    // Rate limit check (per-connection)
    if (sender && !check_rate_limit(sender))
        return;

#ifndef SOCKETLEY_NO_LUA
    // Whose message every callback below is running for.  One scope over the
    // whole dispatch rather than one per invoke: the modes call three different
    // callbacks and a fourth would have been added without this.
    callback_conn_scope serving(this, sender);
#endif

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
            // With the separator, because parse_partial() hands the line
            // WITHOUT it and this path forwarded exactly that.  Two lines from
            // one client therefore arrived at the other as `xy`, which no
            // reader can split again -- while broadcast(), send() and
            // group_send() all put the newline back.  queue_send() strips it
            // again for a websocket peer, so nothing changes there.
            auto shared_msg = std::make_shared<const std::string>(
                std::string(msg) + "\n");
            queue_send(peer, shared_msg);
        }
        return;
    }

    // Check if this client is routed to a sub-server (cached flag avoids map lookup)
    if (sender && SOCKETLEY_UNLIKELY(sender->routed))
    {
        auto rit = m_routes.find(sender->ref_serial);
        if (rit != m_routes.end())
        {
            // The name and not the descriptor, with the running check gone
            // from here because it read a replica one push interval old --
            // whoever holds the target decides, and a ref that names nothing
            // is dropped rather than delivered.
            route_relay::data(get_runtime_manager(), rit->second, get_name(),
                              conn_ref{owner_key(), sender->ref_serial}, msg);
            return;
        }
    }

    m_stat_total_messages.fetch_add(1, std::memory_order_relaxed);
    print_bash_message(msg);
    write_received_message(msg);
    notify_interactive(msg);

    // Fire on_client_message callback (sender-aware)
    if (sender)
        invoke_on_client_message(sender->fd, msg);

    // Cache command interception, asked of the linked cache and answered a
    // turn later, rather than run on this stack through a pointer to the cache
    // object.
    if (SOCKETLEY_UNLIKELY(sender && msg.size() > 6 && msg[0] == 'c' && msg.starts_with("cache ")))
    {
        // Ahead of the command, so a client that sends a message and then asks
        // the cache for it by key sees its own write.
        flush_cache_store();
        post_cache_request(sender, msg.substr(6), false);
        return; // Cache commands are never broadcast
    }

    // Store in cache if configured, appended to the batch rather than posted,
    // because the granularity matters.
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

        // A newline inside the value would end the line early and turn the
        // rest into a command, and the cache's own text protocol cannot carry
        // one either, so flattening is what going through the protocol means.
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

            // Unset keeps what inout has always answered.  There is no master
            // in this mode, so the mask is sender and others.
            const uint8_t to = m_send_to ? m_send_to
                                         : static_cast<uint8_t>(send_to_others);

            if (m_udp)
            {
                // process_message() is reached with a null sender from exactly
                // one place, handle_udp_read(), so for a datagram the receive
                // buffer's address is this datagram's own source.
                const struct sockaddr_in* from =
                    (!sender && m_udp_recv) ? &m_udp_recv->addr : nullptr;

                // The comment this replaced said the exclusion was handled by
                // the caller through an address; no caller ever passed one, so
                // a UDP sender had been receiving its own datagram back since
                // the mode existed while a TCP one did not.
                if ((to & send_to_sender) && from && m_udp_fd >= 0)
                    udp_send_one(msg, *from);
                if (to & send_to_others)
                    udp_broadcast(msg, from);
            }
            else
            {
                // A message routed here from another runtime has no sender on
                // this side, so `sender` names nobody and the set is empty:
                // dropped rather than sent to everyone, because an echo server
                // handed a message with nobody to echo to has no answer.
                //
                // One recipient and nobody to share with is its own case, and
                // it is the common one: `--send-to sender` is what an echo
                // server is.  A shared payload buys a fan-out the right to copy
                // once for N connections; for one connection it buys a second
                // allocation and an entry the queue may not coalesce, because
                // appending to a payload others hold would change it for them.
                // Measured on the no-script path: the allocator was 9.6 per
                // cent of the worker and push_shared another 3.0.
                //
                // And for one raw recipient the line is not built at all: the
                // queue takes the payload and the newline straight into its
                // tail, where the temporary was only ever copied out of and
                // freed.  A websocket still needs the bytes together, because
                // a frame is built from them.
                if (to == send_to_sender)
                {
                    if (!sender)
                    {
                        // nobody to echo to
                    }
                    else if (SOCKETLEY_LIKELY(sender->proto != proto_ws))
                    {
                        if (admit_send(sender, msg.size() + 1, false))
                        {
                            sender->write_queue.push_coalesced_line(
                                msg, server_connection::WRITE_COALESCE_LIMIT);
                            if (SOCKETLEY_LIKELY(!sender->write_pending))
                                flush_write_queue(sender);
                        }
                    }
                    else
                    {
                        std::string buf;
                        buf.reserve(msg.size() + 1);
                        buf.append(msg);
                        buf.push_back('\n');
                        queue_send(sender, std::move(buf));
                    }
                }
                else
                {
                    std::string buf;
                    buf.reserve(msg.size() + 1);
                    buf.append(msg);
                    buf.push_back('\n');
                    auto relay_msg = std::make_shared<const std::string>(std::move(buf));
                    if ((to & send_to_sender) && sender)
                        queue_send(sender, relay_msg);
                    if (to & send_to_others)
                        queue_broadcast(relay_msg, sender ? sender->fd : -1);
                }
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
            // Every branch below needs a connection to claim the master role,
            // to charge a failed attempt to, or to forward from -- and a
            // datagram has none.  Without this line a UDP server in master mode
            // dereferenced null on the first packet beginning "master ", which
            // is an unauthenticated remote SIGSEGV; instance_udp_master_refusal
            // now stops the pair being configured at all, and this stops a
            // state file that already carries it.
            if (!sender)
                break;

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

                // The auth hook replaces --master-pw entirely, so it is read
                // as an optional<bool> -- a type check rather than a truth
                // test, because `return "denied"` granted master -- through a
                // protected call, because the try/catch never ran in the
                // Sanitize build and a silent auth hook is the defect being
                // fixed.
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
                        // Read as an optional<bool>, so only the boolean
                        // `true` grants and a hook that returned nothing has
                        // not answered.
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
                    queue_send(sender, ok_msg);
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
                    queue_send(sender, deny_msg);
                }
                break;
            }

            // The master's own message reaches everyone else, which is what
            // this mode IS and not something --send-to chooses.
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
                    queue_broadcast(relay_msg, sender->fd);
                }
                break;
            }

            // What a NON-master said is what --send-to decides here.  Unset is
            // the empty set and drops it, which is what this mode did before
            // --master-forward and still does without a flag.
            if (m_send_to == send_to_unset)
                break;

            const bool master_live = m_master_fd >= 0 && m_master_fd < MAX_FDS &&
                                     m_conn_idx[m_master_fd];

            if ((m_send_to & send_to_master) && master_live)
            {
                // The sender's descriptor stays in front of it: it is how the
                // master tells two clients apart, and --master-forward wrote
                // it this way before this flag absorbed it.
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
                queue_send(m_conn_idx[m_master_fd], fwd_msg);
            }

            if (m_send_to & (send_to_sender | send_to_others))
            {
                std::string buf;
                buf.reserve(msg.size() + 1);
                buf.append(msg);
                buf.push_back('\n');
                auto relay_msg = std::make_shared<const std::string>(std::move(buf));
                if (m_send_to & send_to_sender)
                    queue_send(sender, relay_msg);
                // Two exclusions: the master has already had this message in
                // its own form above, or was deliberately left out of the set.
                if (m_send_to & send_to_others)
                    queue_broadcast(relay_msg, sender->fd, m_master_fd);
            }
            break;
        }
        default:
            break;
    }
}

server_instance::fanout_count server_instance::broadcast(std::string_view msg)
{
    if (SOCKETLEY_UNLIKELY(!m_loop))
        return {};

    invoke_on_send(msg);

    if (SOCKETLEY_UNLIKELY(m_udp))
    {
        // The socket send buffer IS that queue -- the comment this replaced
        // said a datagram has no queue to fall behind in.  Answering {0,0} made
        // a broadcast that reached every peer and one that reached nobody read
        // identically to the script, so the count is what sendto did.
        return udp_broadcast(msg, nullptr);
    }

    // Build newline-terminated message (single allocation via make_shared)
    std::string buf;
    buf.reserve(msg.size() + 1);
    buf.append(msg);
    if (buf.empty() || buf.back() != '\n')
        buf.push_back('\n');
    auto full_msg = std::make_shared<const std::string>(std::move(buf));
    const fanout_count counted = queue_broadcast(full_msg, -1);  // -1 = don't exclude anyone

    // Also reach the connections routed here through the runtime that owns
    // each, so a ref that no longer resolves is dropped there rather than
    // written to a stranger.
    for (auto& [handle, fc] : m_forwarded)
    {
        (void)handle;
        // Same removal as in the read path above, for the same reason: the
        // state this used to test was this process's copy of somebody else's.
        route_relay::write(get_runtime_manager(), fc.origin, get_name(),
                           fc.ref, msg);
    }

    // The routed ones are not in the count: their queues belong to the runtime
    // that owns each, and that runtime is the one that can report them.
    return counted;
}

// One pass, one submission per connection and no return to the loop between,
// which is why a full submission queue reported as permanent left 952 of 3000
// clients marked closing and never told -- fixed in event_loop.cpp, and
// anything added here inherits that history.
server_instance::fanout_count server_instance::queue_broadcast(
    const std::shared_ptr<const std::string>& msg, int exclude_fd,
    int exclude_fd2)
{
    fanout_count counted;
    if (SOCKETLEY_UNLIKELY(!m_loop))
        return counted;

    std::shared_ptr<const std::string> ws_msg; // Lazy WS frame creation
    // Placed at the first recipient that takes each form, once for all of them.
    std::shared_ptr<const std::string> seg, ws_seg;
    uint32_t off = 0, ws_off = 0;

    // Iterate over flat active_fds vector (cache-friendly, no hash overhead)
    for (size_t i = 0; i < m_active_fds.size(); i++)
    {
        int fd = m_active_fds[i];
        auto* conn = m_conn_idx[fd];
        if (SOCKETLEY_UNLIKELY(!conn || fd == exclude_fd || fd == exclude_fd2 || conn->closing))
            continue;

        // An HTTP or RESP client is skipped rather than held, because no
        // relayed line is well formed on one at any point -- and ahead of the
        // hold, since a keep-alive gap reads as unclassified and would
        // accumulate one.
        if (SOCKETLEY_UNLIKELY(!relay_targetable(conn)))
            continue;

        // Nothing is known yet about what this client speaks, so writing now
        // would put these bytes in front of the response to a request it has
        // already sent.
        if (SOCKETLEY_UNLIKELY(proto_unsettled(conn)))
        {
            // Counted as taken, because the hold is a deferred take and not a
            // drop: these bytes are delivered as soon as the protocol is
            // known.  Measured while this was `continue` alone -- a broadcast
            // to three connected clients reported taken=1, the only one that
            // had spoken yet, which reads as two clients missed.
            relay_hold_push(conn, msg);
            ++counted.taken;
            continue;
        }

        const size_t queued = conn->write_queue.bytes();
        if (SOCKETLEY_UNLIKELY(queued >= write_buffer_bytes()))
        {
            // Sticky here as at the send door, because otherwise a client this
            // broadcast dropped answers the script's next self.send() with
            // "there is no open connection" -- the peer's sentence for the
            // runtime's decision.  One flag, both entrances.
            abandon_for_backlog(conn);
            ++counted.backlogged;
            continue;
        }

        // The same watermark as the send door, so a broadcaster is woken by
        // on_writable too.  A publisher with 3000 subscribers is exactly the
        // producer that needs it.
        if (SOCKETLEY_UNLIKELY(queued + msg->size() >= write_watermark_bytes()))
            conn->drain_wanted = true;

        ++counted.taken;

        if (SOCKETLEY_UNLIKELY(conn->proto == proto_ws))
        {
            if (!ws_msg)
            {
                // Strip trailing newline for WS frame (WS messages are not newline-delimited)
                std::string_view payload(*msg);
                if (!payload.empty() && payload.back() == '\n')
                    payload.remove_suffix(1);
                // Text only if the bytes may travel in one; see queue_send()
                // for the rule and the measurement.  Built once for every
                // websocket in the set, as the text frame always was -- the
                // question is about the payload and not about the recipient.
                ws_msg = ws_payload_is_utf8(payload) ? ws_frame_text_shared(payload)
                                                      : ws_frame_binary_shared(payload);
                ws_off = socketley::place_in_segment(m_bcast_ws_seg, *ws_msg);
                ws_seg = m_bcast_ws_seg;
            }
            conn->write_queue.push_slice(ws_seg, ws_off, static_cast<uint32_t>(ws_msg->size()));
            if (!conn->write_pending)
                flush_write_queue(conn);
        }
        else
        {
            // One copy for every recipient, and a recipient whose queue still
            // ends at the previous broadcast takes this one by growing that slice.
            if (!seg)
            {
                off = socketley::place_in_segment(m_bcast_seg, *msg);
                seg = m_bcast_seg;
            }
            conn->write_queue.push_slice(seg, off, static_cast<uint32_t>(msg->size()));
            if (!conn->write_pending)
                flush_write_queue(conn);
        }
    }

    return counted;
}


// ─── Whether the message was taken ──────────────────────────────────────────
// It used to answer nothing, and the comment at its caller said the rest out
// loud: "a connection closed for exceeding the write-queue bound reported by
// the connection going away".  Which is to say not reported at all -- a script
// looping self.send() over a large body filled the queue, had the connection
// closed under it, and was told true for the message that was dropped doing so.
// The one after that answered "there is no open connection ... it may have
// closed", which names the symptom and not the cause.
//
// So it says. false means the bytes are not going anywhere, and the caller can
// pass that to whoever asked.
// A peer let go of because it outran its write bound, in one place for the
// send and the broadcast doors -- the queue it already has still drains, and
// handle_read takes nothing more from it.
void server_instance::abandon_for_backlog(server_connection* conn)
{
    conn->closed_for_backlog = true;
    conn->closing = true;
}

bool server_instance::admit_send(server_connection* conn, size_t bytes,
                                 bool even_when_closing)
{
    if (SOCKETLEY_UNLIKELY(!m_loop || (conn->closing && !even_when_closing)))
        return false;

    const size_t queued = conn->write_queue.bytes();
    if (SOCKETLEY_UNLIKELY(queued >= write_buffer_bytes()))
    {
        // Sticky, so the refusal one call later can say which of the five
        // reasons it was: a connection the runtime closed because the producer
        // outran the socket is a different thing from a peer that hung up, and
        // the answer a script acts on is different too -- one is "slow down",
        // the other is "it is gone".
        abandon_for_backlog(conn);
        return false;
    }

    // The soft watermark, which is the proxy's and the client's already and was
    // the server's nowhere -- so the server had the hard cap and no slope
    // leading up to it.  Nothing is refused here and the bytes still go: the
    // watermark only records that an on_writable is owed when the queue comes
    // back down, so a producer has somewhere to be woken.
    //
    // Judged on the size this message LEAVES behind, not the one it arrived
    // to.  A producer pacing on self.pending() stops on the same number, so
    // arming on the size before the append arms one send too late -- and that
    // send never comes, because the script has already stopped.  Measured
    // before this line said `queued`: the paced arm delivered 65 of 200 chunks
    // and waited forever for a callback it had itself prevented.
    if (SOCKETLEY_UNLIKELY(queued + bytes >= write_watermark_bytes()))
        conn->drain_wanted = true;

    return true;
}

bool server_instance::queue_send(server_connection* conn, const std::shared_ptr<const std::string>& msg,
                              bool even_when_closing,
                              std::shared_ptr<const std::string>* ws_cache)
{
    if (!admit_send(conn, msg->size(), even_when_closing))
        return false;

    if (SOCKETLEY_UNLIKELY(conn->proto == proto_ws))
    {
        // A frame already built for this payload, if the caller is walking a
        // set: the bytes are the same for every websocket in it.
        if (ws_cache && *ws_cache)
        {
            conn->write_queue.push_shared(*ws_cache,
                server_connection::WRITE_COALESCE_LIMIT,
                server_connection::MAX_WRITE_BATCH);
            if (SOCKETLEY_LIKELY(!conn->write_pending))
                flush_write_queue(conn);
            return true;
        }

        // Strip trailing newline for WS frame
        std::string_view payload(*msg);
        if (!payload.empty() && payload.back() == '\n')
            payload.remove_suffix(1);

        // ─── Which frame the bytes are allowed to travel in ──────────────────
        // Every outbound frame was 0x81, text, and RFC 6455 5.6 says a text
        // frame's payload MUST be valid UTF-8 -- with 8.1 saying a receiver
        // that finds it is not MUST fail the connection.  So this is not a
        // choice between two framings: for bytes that are not valid UTF-8,
        // binary is the only conforming one.
        //
        // Reachable, and measured: a client sent a BINARY frame carrying
        // ff fe 00 01 80 81, the server relayed it to the other client as
        // opcode 0x1 with the bytes intact, and a conforming peer must close on
        // that.  The opcode was the only thing wrong -- the payload arrived
        // byte for byte -- so the payload is what decides, here where the
        // destination is already known to be a websocket.
        //
        // Nothing that was already conforming moves: every relayed line is
        // valid UTF-8 and still goes out as text, and ws_payload_is_utf8()
        // spends one branch per byte on the ASCII that all of them are.
        auto frame = ws_payload_is_utf8(payload) ? ws_frame_text_shared(payload)
                                                 : ws_frame_binary_shared(payload);
        // Kept for the rest of the set, so the next recipient does not pay the
        // UTF-8 pass, the two allocations and the copy again.
        if (ws_cache)
            *ws_cache = frame;
        conn->write_queue.push_shared(frame,
            server_connection::WRITE_COALESCE_LIMIT,
            server_connection::MAX_WRITE_BATCH);
    }
    else
    {
        conn->write_queue.push_shared(msg,
            server_connection::WRITE_COALESCE_LIMIT,
            server_connection::MAX_WRITE_BATCH);
    }

    if (SOCKETLEY_LIKELY(!conn->write_pending))
        flush_write_queue(conn);

    return true;
}

// One recipient, bytes the caller owns.  Two things change against the
// shared_ptr form and both matter on the message path: the control block is
// not allocated, and the entry can be COALESCED -- a shared payload cannot,
// because appending to it would change it for everyone else holding it.  The
// queue's own note on that measured 0.036 TCP segments per delivery against
// 0.149 on a stream of small messages to one connection.
bool server_instance::queue_send(server_connection* conn, std::string&& msg,
                              bool even_when_closing)
{
    if (!admit_send(conn, msg.size(), even_when_closing))
        return false;

    if (SOCKETLEY_UNLIKELY(conn->proto == proto_ws))
    {
        // A frame has to be BUILT either way -- and that was taken as a reason
        // to SHARE it, which it is not.  This overload has exactly one
        // recipient, so a shared entry saves no copy and costs the whole of
        // what the comment above this function measured: a shared payload
        // cannot be coalesced, so a stream of small messages to one websocket
        // built one queue entry apiece where the same stream to a raw socket
        // built one entry, 0.149 TCP segments per delivery against 0.036.
        //
        // ws_frame_text_into writes the header and the payload straight into a
        // buffer the queue may still grow, which is the same shape the plain
        // branch below has always had.  Frames are self-delimiting, so two of
        // them sharing one entry is what the peer reads anyway.
        std::string_view payload(msg);
        if (!payload.empty() && payload.back() == '\n')
            payload.remove_suffix(1);

        // 14 is what ws_write_header() writes at most: two bytes of header and
        // an eight-byte length, plus the four a masked frame would carry.
        std::string frame;
        frame.reserve(14 + payload.size());
        if (ws_payload_is_utf8(payload))
            ws_frame_text_into(frame, payload);
        else
            ws_frame_binary_into(frame, payload);

        conn->write_queue.push_coalesced(std::move(frame),
            server_connection::WRITE_COALESCE_LIMIT);
    }
    else
    {
        conn->write_queue.push_coalesced(std::move(msg),
            server_connection::WRITE_COALESCE_LIMIT);
    }

    if (SOCKETLEY_LIKELY(!conn->write_pending))
        flush_write_queue(conn);

    return true;
}

void server_instance::relay_hold_push(server_connection* conn,
                                      const std::shared_ptr<const std::string>& msg)
{
    // The deadline runs from the first message held, or a listener on a busy
    // relay would have its clock reset by each broadcast and never reach it.
    if (conn->relay_hold.empty())
    {
        conn->relay_hold_since = std::chrono::steady_clock::now();
        if (relay_deadline_applies(conn))
            relay_deadline_arm(RELAY_HOLD_DEADLINE_MS);
    }

    conn->relay_hold.push(msg);

    // A loop and not a single pop, because one relayed message can be larger
    // than the whole bound and popping once would leave the hold over its
    // limit indefinitely.
    while (SOCKETLEY_UNLIKELY(conn->relay_hold.bytes() > RELAY_HOLD_MAX_BYTES)
           && !conn->relay_hold.empty())
        conn->relay_hold.pop();
}

void server_instance::relay_hold_flush(server_connection* conn)
{
    if (SOCKETLEY_LIKELY(conn->relay_hold.empty()))
        return;

    // What was held before the classification turned out to be a
    // request/response protocol is dropped, because there is no framing that
    // could carry it -- and both windows are real, a GET that is not an
    // upgrade and a RESP client whose first write stops short.
    if (SOCKETLEY_UNLIKELY(!relay_targetable(conn)))
    {
        conn->relay_hold.clear();
        conn->relay_hold_since = {};
        return;
    }

    // queue_send() rather than a push into the write queue, because the
    // connection has a protocol now and a WebSocket needs every one of these
    // framed.
    while (!conn->relay_hold.empty())
        queue_send(conn, conn->relay_hold.take_front());

    conn->relay_hold_since = {};
}

void server_instance::relay_deadline_arm(uint32_t after_ms)
{
    // Not if it is already counting, because a second submission on this
    // request would leave the first in the ring with nothing able to name it.
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

    // The shortest wait any connection that is still holding has left,
    // starting at the full deadline because nothing can be owed longer.
    auto next = deadline;
    bool still_waiting = false;

    // The same shape queue_broadcast() iterates m_active_fds with, re-reading size()
    // each turn because the flush below writes and a failed write marks the
    // connection closing.
    for (size_t i = 0; i < m_active_fds.size(); i++)
    {
        const int fd = m_active_fds[i];
        auto* conn = m_conn_idx[fd];
        if (SOCKETLEY_LIKELY(!conn || conn->closing || conn->relay_hold.empty()))
            continue;

        // Classified, spoken, or still handshaking: this hold is not the
        // deadline's to release, because a client mid-request is waiting for
        // an answer relay bytes would land in front of.
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

        // Out of time, so the protocol is settled as raw rather than the queue
        // merely emptied, which is what makes the 250 ms a per-connection cost
        // and not a per-message one.
        conn->proto = proto_tcp;
        relay_hold_flush(conn);
    }

    if (still_waiting)
    {
        // A floor under the re-arm, or a hold one microsecond short of its
        // deadline arms a one-microsecond timeout.
        static constexpr uint32_t MIN_REARM_MS = 5;
        auto ms = static_cast<uint32_t>(next.count());
        relay_deadline_arm(ms < MIN_REARM_MS ? MIN_REARM_MS : ms);
    }
}

bool server_instance::conn_has_output(const server_connection* conn) const
{
    if (!conn->write_queue.empty())
        return true;
    // A TLS connection can owe the wire bytes with an empty queue, and asking
    // only about the queue is how a handshake stalls one round short.
    return conn->ssl != nullptr && tls_context::has_pending_out(conn->ssl);
}

// ─── WE SEND THE FIN, NOT THE CLIENT ────────────────────────────────────────
// We perform the active close so the client's ephemeral port is not held in
// TIME-WAIT, through shutdown() rather than close() and only from a write
// completion so the FIN cannot overtake the payload -- and not through a
// linked IORING_OP_SHUTDOWN, which measured 4 of 200 against 200 of 200
// because the data wakes the client before the linked op runs.
void server_instance::maybe_shutdown_write(server_connection* conn)
{
    if (SOCKETLEY_LIKELY(!conn->closing) || conn->wr_shutdown || conn->fd < 0)
        return;

    // A TLS connection owes a close_notify record first, and a bare FIN under
    // it is a truncation attack as far as the peer is concerned.
    if (conn->ssl != nullptr)
        return;

    // Still something to send, or something in the ring that is sending it.
    if (conn_has_output(conn) || conn->write_pending)
        return;
    if (conn->splice_pending || conn->splice_in_pending || conn->splice_out_pending)
        return;

    // An answer from the cache has not come back yet; close_conn() defers on
    // this same flag and so must we, or the FIN goes out before the reply.
    if (conn->cache_pending > 0)
        return;

    // A read is what drains whatever the peer is still sending after our FIN;
    // without one the caller closes, which is only right when none can be armed.
    if (!conn->read_pending)
    {
        if (!m_loop || conn->file_read_pending || !drains_on_close(conn))
            return;
        submit_conn_read(conn);
        if (!conn->read_pending)
            return;
    }

    conn->wr_shutdown = true;
    if (shutdown(conn->fd, SHUT_WR) < 0) {}
}

// Every byte this connection sends is a TLS record, including the ones nobody
// queued, and there is no other way onto the wire.
void server_instance::tls_flush(server_connection* conn)
{
    if (SOCKETLEY_UNLIKELY(!m_loop || !conn->ssl))
        return;

    // One write in flight at a time, because a second submission would need a
    // second buffer and would interleave two record streams on one socket.
    if (conn->write_pending)
        return;

    // Application data only once the handshake is done, so a message queued by
    // on_connect waits rather than being handed to an SSL that answers
    // WANT_READ.
    if (conn->tls_state == tls_conn_ready)
    {
        while (!conn->write_queue.empty())
        {
            const auto& msg = conn->write_queue.front();
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
        return;

    // Ciphertext copied out of the write BIO into a buffer this connection
    // owns, because the BIO's storage moves under an SQE -- and it rides in
    // write_batch[0] so the short-write retry needs no TLS case.
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
        conn->write_batch[i].clear();

    conn->write_batch[0] = socketley::write_chunk(std::move(cipher));
    conn->write_iovs[0].iov_base = const_cast<char*>(conn->write_batch[0].data());
    conn->write_iovs[0].iov_len  = conn->write_batch[0].size();
    conn->write_batch_count = 1;
    conn->write_pending = true;
    conn->write_req.type = op_write;

    const auto len = static_cast<uint32_t>(conn->write_batch[0].size());
    const bool queued = conn->direct_fd
        ? m_loop->submit_write_fixed_file(conn->fixed_idx, conn->write_batch[0].data(),
                                          len, &conn->write_req)
        : m_loop->submit_write(conn->fd, conn->write_batch[0].data(), len, &conn->write_req);

    // Nothing reached the ring, so the in-flight bookkeeping is undone and the
    // connection dropped, because a write_pending that never clears keeps the
    // teardown waiting.
    if (SOCKETLEY_UNLIKELY(!queued))
    {
        conn->write_pending = false;
        conn->write_batch[0].clear();
        conn->write_batch_count = 0;
        conn->closing = true;
    }
}

void server_instance::flush_write_queue(server_connection* conn)
{
    // A TLS connection's bytes go through the record layer, which is what
    // keeps every caller above from having to know which kind of connection it
    // holds.
    if (SOCKETLEY_UNLIKELY(conn->ssl != nullptr))
    {
        tls_flush(conn);
        return;
    }

    if (SOCKETLEY_UNLIKELY(!m_loop || conn->write_queue.empty()))
        return;

    // Coalesce up to MAX_WRITE_BATCH messages into a single writev
    uint32_t count = 0;
    while (!conn->write_queue.empty() && count < server_connection::MAX_WRITE_BATCH)
    {
        conn->write_batch[count] = conn->write_queue.take_front();

        conn->write_iovs[count].iov_base = const_cast<char*>(conn->write_batch[count].data());
        conn->write_iovs[count].iov_len = conn->write_batch[count].size();
        count++;
    }

    conn->write_batch_count = count;
    if (send_direct(conn))
        return;

    // What send_direct() did not get out, which a partial send left starting
    // part way into the first iovec.
    count = conn->write_batch_count;
    conn->write_pending = true;

    bool queued;
    if (count == 1)
    {
        const auto* data = static_cast<const char*>(conn->write_iovs[0].iov_base);
        auto len = static_cast<uint32_t>(conn->write_iovs[0].iov_len);

        // Single message — use plain write (lower overhead than writev)
        conn->write_req.type = op_write;
        if (conn->direct_fd)
            queued = m_loop->submit_write_fixed_file(conn->fixed_idx, data, len, &conn->write_req);
        else
            queued = m_loop->submit_write(conn->fd, data, len, &conn->write_req);
    }
    else
    {
        conn->write_req.type = op_writev;
        if (conn->direct_fd)
            queued = m_loop->submit_writev_fixed_file(conn->fixed_idx, conn->write_iovs, count, &conn->write_req);
        else
            queued = m_loop->submit_writev(conn->fd, conn->write_iovs, count, &conn->write_req);
    }

    // Nothing reached the ring, so the in-flight bookkeeping is undone and the
    // connection dropped, because a write_pending that never clears waits
    // forever.
    if (SOCKETLEY_UNLIKELY(!queued))
    {
        conn->write_pending = false;
        for (uint32_t i = 0; i < conn->write_batch_count; i++)
            conn->write_batch[i].clear();
        conn->write_batch_count = 0;
        conn->closing = true;
    }
}

// Drops the first `written` bytes of the batch, whole iovecs and then part of
// one, so what is left is exactly what the socket did not take.
void server_instance::skip_written(server_connection* conn, size_t written)
{
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
    const uint32_t new_count = conn->write_batch_count - first_iov;
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
}

// True when the batch went out whole.  A lone write goes by sendmsg(), sparing
// it the ring entry and the completion (see direct_send_gate), and only when
// that completion would have had nothing to do but release the batch.
bool server_instance::send_direct(server_connection* conn)
{
    if (!m_direct_gate.admit(conn->fd) || conn->closing || conn->wr_shutdown || conn->fd < 0
        || conn->ref_serial == 0
        || conn->drain_wanted || conn->stream_remaining > 0 || conn->splice_pending
        || conn->splice_in_pending || conn->splice_out_pending)
        return false;

    size_t total = 0;
    for (uint32_t i = 0; i < conn->write_batch_count; i++)
        total += conn->write_iovs[i].iov_len;

    struct msghdr msg{};
    msg.msg_iov = conn->write_iovs;
    msg.msg_iovlen = conn->write_batch_count;
    const ssize_t n = ::sendmsg(conn->fd, &msg, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (n <= 0)
        return false;
    m_stat_bytes_out.fetch_add(static_cast<uint64_t>(n), std::memory_order_relaxed);

    if (static_cast<size_t>(n) < total)
    {
        skip_written(conn, static_cast<size_t>(n));
        return false;
    }

    for (uint32_t i = 0; i < conn->write_batch_count; i++)
        conn->write_batch[i].clear();
    conn->write_batch_count = 0;
    m_direct_serial = conn->ref_serial;

    // More than one batch was queued, and the rest takes the ring.
    if (!conn->write_queue.empty())
        flush_write_queue(conn);
    return true;
}

void server_instance::handle_write(struct io_uring_cqe* cqe, io_request* req)
{
    int fd = req->fd;
    auto* conn = m_conn_idx[fd];
    if (SOCKETLEY_UNLIKELY(!conn))
        return;

    conn->write_pending = false;

    if (SOCKETLEY_UNLIKELY(cqe->res <= 0))
    {
        // Release batch refs on error
        for (uint32_t i = 0; i < conn->write_batch_count; i++)
            conn->write_batch[i].clear();
        conn->write_batch_count = 0;
        conn->closing = true;
        // splice_cleanup() declines while a splice is armed, because closing
        // the file and handing the pipe on mixes one response's bytes into the
        // next connection's.
        if (conn->splice_pending || conn->splice_remaining)
            splice_cleanup(conn);
        if (!conn_ops_pending(conn))
            close_conn(conn);
        return;
    }

    m_stat_bytes_out.fetch_add(static_cast<uint64_t>(cqe->res), std::memory_order_relaxed);

    // Short write handling: resubmit remaining bytes
    if (conn->write_batch_count > 0)
    {
        size_t total_submitted = 0;
        for (uint32_t i = 0; i < conn->write_batch_count; i++)
            total_submitted += conn->write_iovs[i].iov_len;

        size_t written = static_cast<size_t>(cqe->res);
        if (written < total_submitted && SOCKETLEY_UNLIKELY(conn->wr_shutdown))
        {
            // Our write side is already closed so the remainder cannot be
            // sent, and getting here means something queued output after the
            // FIN -- dropped rather than retried forever.
            for (uint32_t i = 0; i < conn->write_batch_count; i++)
                conn->write_batch[i].clear();
            conn->write_batch_count = 0;
            conn->closing = true;
            if (!conn_ops_pending(conn))
                close_conn(conn);
            return;
        }
        if (written < total_submitted)
        {
            skip_written(conn, written);
            const uint32_t new_count = conn->write_batch_count;

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
                    conn->write_batch[i].clear();
                conn->write_batch_count = 0;
                conn->closing = true;
            }
            return;
        }
    }

    // Full write completed — release batch
    for (uint32_t i = 0; i < conn->write_batch_count; i++)
        conn->write_batch[i].clear();
    conn->write_batch_count = 0;

    after_write(conn);
}

// What a finished write leaves to do, run from its completion or, for a direct
// send that has none, from the end of the turn that made it.
void server_instance::after_write(server_connection* conn)
{
    // The queue has shrunk, so this is the moment the crossing can be seen.
    // Recorded and not called: a script's on_writable will send, which reaches
    // flush_write_queue and can mark this same connection closing, and the
    // rest of this function still holds the pointer.  The tree's own answer to
    // that shape is three lines below the read path's Lua call -- "answered a
    // turn later, rather than run on this stack through a pointer".
    if (SOCKETLEY_UNLIKELY(conn->drain_wanted)
        && conn->write_queue.bytes() < write_watermark_bytes())
    {
        conn->drain_wanted = false;
        // A file this runtime is streaming is a producer of its own, and it has
        // to be woken whether or not a script asked to hear about crossings: an
        // --http server with no Lua at all defines no on_writable, so the pump
        // was waiting for a wake-up nobody was going to send.  One request never
        // showed it -- 3.4 MB stays under the watermark -- and three at once hung.
        if ((wants_on_writable() || conn->stream_remaining > 0) && conn->ref_serial != 0)
            m_drain_pending.push_back(conn->ref_serial);
    }

    // The response is on the wire with an empty queue behind it, which is the
    // only moment sending the FIN cannot overtake anything; it declines by
    // itself otherwise.
    maybe_shutdown_write(conn);

    // conn_has_output and not the queue alone, because a TLS connection owes
    // handshake records with nothing queued at all.
    if (SOCKETLEY_LIKELY(conn_has_output(conn)))
    {
        flush_write_queue(conn);
        // A flush can legitimately submit nothing, and without this the
        // connection would be left closing with nothing to wake it.
        if (SOCKETLEY_UNLIKELY(conn->closing && !conn_ops_pending(conn)))
            close_conn(conn);
    }
    else if (SOCKETLEY_UNLIKELY(conn->splice_pending && conn->splice_pipe[0] >= 0 && !conn->closing))
    {
        // Headers sent — start file→pipe splice
        conn->splice_pending = false;
        uint32_t chunk = static_cast<uint32_t>(std::min(conn->splice_remaining, size_t(UINT32_MAX)));
        conn->splice_in_req = { this, nullptr, conn->fd, chunk, op_splice, conn->generation };
        conn->splice_in_pending =
            m_loop->submit_splice(conn->splice_file_fd, conn->splice_pipe[1], chunk, &conn->splice_in_req);
        if (SOCKETLEY_UNLIKELY(!conn->splice_in_pending))
        {
            // Nothing reached the ring, so the pipe goes back and the
            // connection is dropped rather than left half-sent with the pipe
            // marked busy.
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
        // Asked through conn_ops_pending(), so that every operation still owed
        // on this struct stops the release.
        if (!conn_ops_pending(conn))
            close_conn(conn);
        return;
    }

    // Read error, answered 404, treating a null buffer the same way, because
    // building a response out of it means std::string_view(nullptr, n) and a
    // logic_error from inside a completion handler.
    if (SOCKETLEY_UNLIKELY(cqe->res <= 0 || !conn->file_buf))
    {
        if (conn->file_fd >= 0) { close_tracked(conn->file_fd); conn->file_fd = -1; }
        free(conn->file_buf);
        conn->file_buf = nullptr;
        conn->file_size = 0;
        queue_http_response(conn, http_404_response(conn->http_keep_alive));
        if (!conn->http_keep_alive)
            conn->closing = true;
        else
        {
            conn->proto = proto_unknown;
            if (!conn->read_pending && !arm_conn_read(conn))
                return;
            // The error arm owes the same drain as the success arm, because
            // the invariant is about the connection rather than the outcome --
            // phrased as "every arm that finishes a response drains", an
            // omission is a missing line rather than a missing thought.
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

    // Fewer bytes than fstat() promised are not the file -- one read is capped
    // by the kernel at MAX_RW_COUNT and its length was cut to 32 bits -- and a
    // 200 built from them declared the truncation as the file's length.
    if (SOCKETLEY_UNLIKELY(static_cast<size_t>(cqe->res) != conn->file_size))
    {
        free(conn->file_buf);
        conn->file_buf = nullptr;
        conn->file_size = 0;
        conn->file_url_path.clear();
        queue_http_response(conn, http_500_response());
        conn->closing = true;
        return;
    }

    std::string_view file_content(conn->file_buf, static_cast<size_t>(cqe->res));

    // The script is a piece of the one response rather than a reason to hold an
    // injected copy of the file as well.  Measured on a 400 MiB .html: 1219 MiB
    // peak RSS for file_buf, the injected body and the response, against 20 MiB
    // for the same bytes on the splice path.  One copy of the file remains --
    // the response is a contiguous string and the bytes have to reach it --
    // and getting below that needs the body streamed rather than assembled.
    const size_t inject_at = conn->file_is_html
        ? ws_inject_offset(file_content) : std::string_view::npos;
    const size_t body_len = file_content.size() +
        (inject_at == std::string_view::npos ? 0 : WS_INJECT_SCRIPT.size());

    // A short read is served and deliberately not stored, because bytes below
    // st_size are not the file and an entry built from them would miss forever
    // or match a later truncation.  Whether it fits is asked here and not after
    // the fact: the store branch builds a second full response, and building
    // one to hand to a cache that will refuse it is the whole cost twice.
    // Never for a 206.  The map is keyed by url_path and holds the WHOLE
    // file's response, so storing a slice under that key would answer the next
    // request for the file with this request's bytes and this request's
    // Content-Range.  serve_http already declines the cache on the way in; this
    // is the other half, and the two together are why a seek cannot poison a
    // path for every later reader.
    const bool keepable = !conn->is_range && !conn->file_url_path.empty() &&
                          static_cast<uint64_t>(cqe->res) ==
                              static_cast<uint64_t>(conn->file_st.st_size);
    const bool fits = http_reval_would_fit(conn->file_url_path, 2 * (128 + body_len));
    // This is the door the full map is actually refused at, so this is where it
    // gets said -- and only for a file that was otherwise keepable, since a 206
    // or a short read is declined for its own reasons and says nothing about the
    // map being full.
    if (keepable && !fits)
        note_http_reval_full();
    const bool store = keepable && fits;
    if (store)
    {
        auto ka = std::make_shared<const std::string>(build_http_response_at(
            conn->file_content_type, file_content, inject_at, true));
        auto cl = std::make_shared<const std::string>(build_http_response_at(
            conn->file_content_type, file_content, inject_at, false));
        queue_http_response(conn, conn->http_keep_alive ? ka : cl);
        http_reval_store(conn->file_url_path, conn->file_st, std::move(ka), std::move(cl));
    }
    else if (conn->is_range)
    {
        // Headers and body assembled here rather than in build_http_response_at,
        // which has no notion of a slice: the length it would state is the one
        // it was handed, and a 206 needs two different lengths -- the slice in
        // Content-Length and the file in Content-Range.
        std::string out = build_http_206_headers(
            conn->file_content_type, conn->range_first,
            conn->range_first + file_content.size() - 1,
            conn->range_total, conn->http_keep_alive);
        out.append(file_content);
        queue_http_response(conn, std::make_shared<const std::string>(std::move(out)));
    }
    else
    {
        queue_http_response(conn, std::make_shared<const std::string>(build_http_response_at(
            conn->file_content_type, file_content, inject_at, conn->http_keep_alive)));
    }
    conn->is_range = false;
    conn->file_url_path.clear();

    // Free file buffer
    free(conn->file_buf);
    conn->file_buf = nullptr;
    conn->file_size = 0;

    if (!conn->http_keep_alive)
    {
        conn->closing = true;
        // An answer sent directly leaves no write completion to end this.
        if (!conn_ops_pending(conn))
            close_conn(conn);
    }
    else
    {
        conn->proto = proto_unknown;
        // Resubmit socket read for next HTTP request
        if (!conn->read_pending && !arm_conn_read(conn))
            return;
        // Last statement, reachable here only by a client that pipelines, but
        // the same rule all the same.
        parse_partial(conn);
    }
}

void server_instance::splice_cleanup(server_connection* conn)
{
    // Not while a splice is armed, because this closes the file the kernel is
    // reading from and hands the shared pipe on; the completion calls back in
    // once the op is finished.
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

    // No drain: the pipe is this connection's and goes with it, so there is no
    // "next user" to leave bytes for.  That loop was the whole cost of sharing
    // one pipe, and the hazard it was written against cannot arise now.
    splice_pipe_release(conn);
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
        m_loop->submit_splice(conn->splice_pipe[0], conn->fd, conn->splice_pipe_pending, &conn->splice_out_req);
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
            m_loop->submit_splice(conn->splice_pipe[0], conn->fd, conn->splice_pipe_pending, &conn->splice_out_req);
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
            m_loop->submit_splice(conn->splice_file_fd, conn->splice_pipe[1], chunk, &conn->splice_in_req);
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
        if (!conn->read_pending && !arm_conn_read(conn))
            return;

        // Last statement, because parse_partial() can arm the next splice on
        // this connection and anything after it would operate on the next
        // response's state.
        parse_partial(conn);
    }
}

// One recvmsg at a time always, because a second armed beside it gives the
// kernel two writers into the same buffer and sockaddr, so replies go to the
// wrong peer.
void server_instance::arm_udp_recv()
{
    if (!m_loop || m_udp_fd < 0)
    {
        m_udp_recv_armed = false;
        m_udp_recv_rearm_due = false;
        return;
    }
    m_udp_recv->msg.msg_namelen = sizeof(m_udp_recv->addr);
    m_udp_recv_armed = m_loop->submit_recvmsg(m_udp_fd, &m_udp_recv->msg, &m_udp_recv->req);
    // A refusal here is the whole ear, because the only things that ask again
    // are inside the completion of the read that was never armed -- so it is
    // remembered for on_loop_turn(), which owes the ring nothing and therefore
    // still works when a full submission queue is what refused.
    m_udp_recv_rearm_due = !m_udp_recv_armed;
}

void server_instance::handle_udp_read(struct io_uring_cqe* cqe)
{
    // Whatever else happens below, the op that produced this is finished.
    m_udp_recv_armed = false;

    // A socket closed under this read completes it with one of these, and
    // resubmitting would arm a second chain on the descriptor start() opened --
    // the same four handle_accept() returns on, for the same reason.
    if (SOCKETLEY_UNLIKELY(cqe->res == -ECANCELED || cqe->res == -EBADF
                           || cqe->res == -EINVAL || cqe->res == -ENOTSOCK))
        return;

    if (cqe->res < 0)
    {
        arm_udp_recv();  // Resubmit on error
        return;
    }

    // Counted before the peer check, because these bytes arrived whatever the
    // table decides about their sender.
    m_stat_bytes_in.fetch_add(static_cast<uint64_t>(cqe->res), std::memory_order_relaxed);

    // Register peer if new; skip processing if peer list is full.  Reached on
    // res == 0 as well: a zero-length datagram is a message its sender sent,
    // so it enters and refreshes a peer like any other -- 0 is an end of
    // stream on TCP and a legitimate datagram here.
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

    // A datagram is its own read, so this is where its cache batch goes: UDP
    // has no connection and never reaches the label in handle_read.
    if (SOCKETLEY_UNLIKELY(!m_cache_store_batch.empty()))
        flush_cache_store();

    // Resubmit for next datagram
    arm_udp_recv();
}

// The one door every outbound datagram leaves by, so what the socket did with
// it is counted in one place: the return value was discarded at both call
// sites and a UDP server reported bytes_out:0 for its whole life.
bool server_instance::udp_send_one(std::string_view msg, const struct sockaddr_in& to)
{
    const ssize_t n = sendto(m_udp_fd, msg.data(), msg.size(), MSG_DONTWAIT,
                             reinterpret_cast<const struct sockaddr*>(&to), sizeof(to));
    if (SOCKETLEY_LIKELY(n >= 0))
    {
        m_stat_bytes_out.fetch_add(static_cast<uint64_t>(n), std::memory_order_relaxed);
        return true;
    }

    // Throttled on the same rule the ring's own refusals use: the first one
    // says what happened and a flood does not become the log.  EAGAIN and
    // ENOBUFS are a full send buffer, EMSGSIZE a payload no peer can ever be
    // sent -- all three are silent losses without this line.
    const int err = errno;
    ++m_udp_send_failures;
    if (m_udp_send_failures == 1 || (m_udp_send_failures % 1000) == 0)
        LOG_ERROR(("server \"" + std::string(get_name()) + "\": a datagram of " +
                   std::to_string(msg.size()) + " bytes was not sent (" +
                   std::string(std::strerror(err)) + "); " +
                   std::to_string(m_udp_send_failures) +
                   " datagram(s) have now been dropped by the socket").c_str());
    return false;
}

// One sendto per peer, and sendmmsg() was tried here and withdrawn.
//
// Batching 128 headers over one shared iovec -- the payload is identical for
// every recipient, so only the address differs -- turned four hundred syscalls
// into four and changed nothing that could be measured: 535 microseconds of
// worker CPU per broadcast in both arms, six runs each, interleaved and with
// the order reversed, the only spread being a single scheduler tick that
// appeared once in each arm.
//
// The reason is worth keeping: the cost is per DATAGRAM inside the kernel --
// the UDP stack, the loopback delivery, the wake of each receiver -- and not
// per syscall, so removing 396 of 400 syscall entries removed a few percent of
// a few percent.  It is also why the 95.9% kernel share this runtime profiles
// at is not a share anybody can take: there is no userspace left to remove.
//
// Measured at 1, 10, 100 and 400 peers beforehand, and the shape says the same
// thing: 5.00, 27.50, 265 and 1020 microseconds of CPU per message, which is
// flat at about 2.55 microseconds per peer from ten peers upward.  A broadcast
// to four hundred costs a millisecond, and the receive socket has nothing
// armed on it for the whole of it.  If that ceiling ever has to move, it moves
// by not sending N datagrams -- multicast, or a relay the peers subscribe to --
// and not by sending them differently.
server_instance::fanout_count server_instance::udp_broadcast(std::string_view msg,
                                                             const struct sockaddr_in* exclude)
{
    fanout_count counted;
    if (m_udp_fd < 0)
        return counted;

    for (auto& peer : m_udp_peers)
    {
        if (exclude &&
            peer.addr.sin_addr.s_addr == exclude->sin_addr.s_addr &&
            peer.addr.sin_port == exclude->sin_port)
            continue;

        if (udp_send_one(msg, peer.addr))
            ++counted.taken;
        else
            ++counted.backlogged;
    }
    return counted;
}

bool server_instance::disconnect(int client_fd)
{
    auto* conn = (client_fd >= 0 && client_fd < MAX_FDS)
                 ? m_conn_idx[client_fd] : nullptr;
    if (!conn || conn->closing) return false;
    conn->closing = true;
    // SHUT_RD only, keeping the write side open so a queued message still
    // reaches the client, and triggering the pending read's EOF so handle_read
    // can clean up.
    shutdown(client_fd, SHUT_RD);
    return true;
}

std::string server_instance::peer_ip(int client_fd)
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
        auto hdrs = ws_headers(fd);
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

server_instance::ws_headers_result server_instance::ws_headers(int client_fd) const
{
    if (client_fd < 0 || client_fd >= MAX_FDS) return {};
    const auto* conn = m_conn_idx[client_fd];
    if (!conn || conn->proto != proto_ws) return {};
    return {true, conn->ws_cookie, conn->ws_origin, conn->ws_protocol, conn->ws_auth};
}

bool server_instance::send_to(int client_id, std::string_view msg)
{
    if (!m_loop || m_udp)
        return false;

    // send_to_client() reads which kind of id this is and asks the right
    // runtime, because trying the local table first was unambiguous only while
    // the two ranges could not overlap -- which they do the moment the
    // runtimes are separate processes.
    return send_to_client(client_id, msg);
}

// The server-specific half of `stats`, which a worker still pushes because it
// walks a connection table, together with the ring lines -- which depend on
// the worker being told the daemon's ring policy.
std::string server_instance::stats_lines() const
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
            if (uc->established) ++connected;
        out << "upstreams:" << connected << "/" << m_upstream_targets.size() << "\n";
    }
    // The cross-runtime request queue and what it had to throw away, reported
    // here because a dropped auto-store batch is messages that are not in the
    // cache.
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

bool server_instance::route_client(int client_id, std::string_view target_name,
                                   std::string* err)
{
    const auto fail = [&](const char* why) { if (err) *err = why; return false; };

    // A connection routed here is not ours to route on, which used to be
    // reachable because both kinds of id were "an int".
    if (is_conn_handle(client_id))
        return fail("that connection was routed here from another runtime, so "
                    "it is not this one's to route on");

    const conn_ref ref = ref_for_fd(client_id);
    if (!ref.valid())
        return fail("that is not an open connection of this server");

    auto* mgr = get_runtime_manager();
    if (!mgr) return fail("this runtime has no runtime manager");

    // Our own bookkeeping first and the notification second, because
    // accept_routed runs the target's on_connect and a script may close the
    // connection -- and the two pre-checks moved into route_relay::open, which
    // decides the case as_server() could not.
    m_routes[ref.serial] = std::string(target_name);
    m_conn_idx[client_id]->routed = true;

    std::string route_err;
    if (route_relay::open(mgr, target_name, get_name(), ref, route_err))
        return true;
    if (err) *err = std::move(route_err);

    // Refused, so undo and find the connection by name, because the rule that
    // a descriptor is not an identity is not suspended for rollback.
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
    // anything else is called, because release_routed runs on_disconnect and a
    // script may unroute again.
    const std::string target_name = it->second;
    m_routes.erase(it);
    m_conn_idx[client_id]->routed = false;

    route_relay::close(get_runtime_manager(), target_name, get_name(),
                       conn_ref{owner_key(), serial});
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

// The two questions a producer needs and could not ask.  Both answer about a
// connection this process holds; a routed handle belongs to another runtime and
// its backlog is that runtime's to report.
// Resolved the same way pending_bytes() below resolves, and refusing for the
// same reason: a routed handle names a connection another runtime holds, and a
// response is that runtime's to write.
bool server_instance::begin_chunked_response(int client_id, int status,
    const std::vector<std::pair<std::string, std::string>>& headers)
{
    if (client_id < 0 || client_id >= MAX_FDS || !m_conn_idx[client_id])
        return false;
    return begin_chunked_response(m_conn_idx[client_id], status, headers);
}

bool server_instance::send_response_chunk(int client_id, std::string_view data)
{
    if (client_id < 0 || client_id >= MAX_FDS || !m_conn_idx[client_id])
        return false;
    return send_response_chunk(m_conn_idx[client_id], data);
}

bool server_instance::finish_chunked_response(int client_id)
{
    if (client_id < 0 || client_id >= MAX_FDS || !m_conn_idx[client_id])
        return false;
    return end_chunked_response(m_conn_idx[client_id]);
}

long server_instance::pending_bytes(int client_id) const
{
    if (client_id < 0 || client_id >= MAX_FDS || !m_conn_idx[client_id])
        return -1;
    return static_cast<long>(m_conn_idx[client_id]->write_queue.bytes());
}

bool server_instance::closed_for_backlog(int client_id) const
{
    if (client_id < 0 || client_id >= MAX_FDS || !m_conn_idx[client_id])
        return false;
    return m_conn_idx[client_id]->closed_for_backlog;
}

// Whether the bytes were taken, which used to be "yes" unconditionally.
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
        // Checked before the manager, because in a worker every other runtime
        // is a replica and this runtime's own name resolves to the copy --
        // what names the holder is the ref's own shard bits.
        if (ref.owner == owner_key()
            && conn_ref_shard(ref) != get_shard_index()
            && has_ref_sink())
        {
            send_to_ref(ref, msg);
            // Queued, which is what "sent" means everywhere else here: what is
            // established is that the id named a connection this runtime has.
            return true;
        }

        // The eighth site of the same shape, and the one that made the feature
        // look half-built: a routed client could be reached and could not
        // reply, because self.send resolved the origin through as_server() and
        // found a replica.
        return route_relay::write(get_runtime_manager(), it->second.origin,
                                  get_name(), ref, msg);
    }

    if (SOCKETLEY_UNLIKELY(client_id < 0 || client_id >= MAX_FDS || !m_conn_idx[client_id])) return false;
    auto* conn = m_conn_idx[client_id];
    // Closing AND owed nothing.  A connection held open for an answer is still
    // a connection a script may answer; see the queue_send below.
    if (SOCKETLEY_UNLIKELY(conn->closing && conn->cache_pending == 0)) return false;

    std::string buf;
    buf.reserve(msg.size() + 1);
    buf.append(msg);
    if (buf.empty() || buf.back() != '\n') buf.push_back('\n');
    // Queued, which is what "sent" means on an async write path here -- and
    // NOT queued is now an answer too, rather than a true for a message that
    // was dropped on the way to closing the connection.
    //
    // A connection closing only because an answer is owed is still writable for
    // that answer: the same sentence the built-in cache reply carries, and what
    // lets a suspended handler answer a peer that half-closed while it waited.
    //
    // The owning form: this names ONE connection, so there is nobody to share
    // with and the shared_ptr was buying a second allocation and an entry the
    // queue could not coalesce.
    return queue_send(conn, std::move(buf), conn->cache_pending > 0);
}

bool server_instance::owner_send(int client_id, std::string_view msg)
{
    // Resolved through what was actually routed here rather than through
    // get_owner() and a number, because the old form let a sub-server write to
    // any of the owner's clients.
    auto it = m_forwarded.find(client_id);
    if (it == m_forwarded.end())
        return false;

    return route_relay::write(get_runtime_manager(), it->second.origin,
                              get_name(), it->second.ref, msg);
}

// ── The cross-runtime half ──────────────────────────────────────────────────

int server_instance::accept_routed(const conn_ref& ref, std::string_view origin_name)
{
    if (!ref.valid())
        return -1;

    // Idempotent, because a route asked for twice is one route and answering
    // with the handle already in use is what a retry over a socket looks like.
    if (auto it = m_forwarded_by_ref.find(ref); it != m_forwarded_by_ref.end())
        return it->second;

    const int handle = alloc_handle();
    if (handle < 0)
        return -1;

    m_forwarded.emplace(handle, forwarded_client{ref, std::string(origin_name)});
    m_forwarded_by_ref.emplace(ref, handle);

    // The script hears about a client and gets an integer it can hand back,
    // which cannot collide with one of this runtime's own descriptors.
    invoke_on_connect(handle);
    return handle;
}

void server_instance::release_routed(const conn_ref& ref)
{
    auto it = m_forwarded_by_ref.find(ref);
    if (it == m_forwarded_by_ref.end())
        return;

    const int handle = it->second;

    // The name goes first so a second release finds nothing and does not fire
    // the callback twice, while the handle stays resolvable across it so a
    // script that writes gets a clean false.
    m_forwarded_by_ref.erase(it);
    invoke_on_disconnect(handle);
    m_forwarded.erase(handle);
}

void server_instance::forget_runtime(std::string_view gone)
{
    // Collected before anything is released, because release_routed runs
    // on_disconnect and a script may unroute, close or remove, any of which
    // mutates the containers being walked.
    std::vector<conn_ref> incoming;
    for (const auto& [handle, fc] : m_forwarded)
    {
        (void)handle;
        if (fc.origin == gone)
            incoming.push_back(fc.ref);
    }
    for (const auto& ref : incoming)
        release_routed(ref);

    // The other direction, sent nowhere because there is nobody left to tell,
    // with the entry and the cached flag dropped together -- a set flag makes
    // the read path take the routed branch once per message forever.
    std::vector<uint64_t> outgoing;
    for (const auto& [serial, target] : m_routes)
        if (target == gone)
            outgoing.push_back(serial);
    for (uint64_t serial : outgoing)
        drop_route(conn_ref{owner_key(), serial});
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
    // Someone else's name for one of our connections, where three things have
    // to hold and the descriptor version checked none of them.
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
    // The owning overload: one recipient and a buffer this function already
    // holds, so wrapping it in a control block bought a second allocation and
    // an entry the queue may not coalesce.  The same shape queue_send's own
    // comment describes.
    queue_send(conn, std::move(buf));
    return true;
}

void server_instance::drop_route(const conn_ref& ref)
{
    if (ref.owner != owner_key())
        return;

    if (m_routes.erase(ref.serial) == 0)
        return;

    // And the cached flag on the connection, which the previous cleanup left
    // set, costing a lookup per message for a route that no longer existed.
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
    // Handles are 32-bit and start high, so a daemon that exhausts two billion
    // routes is still owed a correct answer rather than a negative handle.
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
    // connection, because a runtime's owner is a name and a worker now holds a
    // replica of every name.
    auto* parent = mgr->get(owner_name);
    if (!parent) return false;

    // In this process, and running: both still required, and the second is
    // still read locally because for an IN-PROCESS parent this map is the
    // authority rather than a copy of one.
    if (auto* srv = route_relay::local_server(mgr, owner_name))
    {
        if (parent->get_state() != runtime_running) return false;
        srv->broadcast(msg);
        return true;
    }

    // Out of process it addresses a runtime rather than a connection, and it
    // is a routing verb rather than a `deliver`, because deliver honours
    // `--mode in` and dropped it for an owner created that way.
    return route_relay::broadcast(mgr, owner_name, get_name(), msg);
}

static inline uint64_t udp_peer_key(const struct sockaddr_in& addr)
{
    return (static_cast<uint64_t>(addr.sin_addr.s_addr) << 16) |
            static_cast<uint64_t>(addr.sin_port);
}

void server_instance::drop_udp_peer(int idx)
{
    if (idx < 0 || static_cast<size_t>(idx) >= m_udp_peers.size())
        return;

    m_udp_peer_idx.erase(udp_peer_key(m_udp_peers[idx].addr));

    const int last = static_cast<int>(m_udp_peers.size()) - 1;
    if (idx != last)
    {
        // Swap and pop, so the element that moves has its own index rewritten
        // -- the map holds indices into this vector and a stale one would name
        // somebody else's address.
        m_udp_peers[idx] = m_udp_peers[last];
        m_udp_peer_idx[udp_peer_key(m_udp_peers[idx].addr)] = idx;
    }
    m_udp_peers.pop_back();
}

size_t server_instance::forget_idle_udp_peers(std::chrono::steady_clock::time_point now,
                                              std::chrono::seconds timeout)
{
    size_t gone = 0;
    for (int i = static_cast<int>(m_udp_peers.size()) - 1; i >= 0; --i)
    {
        // Backwards, because drop_udp_peer moves the LAST element into the
        // hole and walking forwards would skip whatever landed there.
        if (now - m_udp_peers[i].last_seen > timeout)
        {
            drop_udp_peer(i);
            ++gone;
        }
    }
    return gone;
}

// The timers this server armed, withdrawn because a timeout reaches no
// shutdown or cancel and left the instance in the graveyard for as long as
// thirty seconds -- decided by the armed flags rather than by a guess.
void server_instance::withdraw_timers(event_loop& loop)
{
    bool timers_withdrawn = true;

    if (m_idle_sweep_armed)
        timers_withdrawn &= loop.submit_timeout_remove(&m_idle_sweep_req);
    // 250 ms would end the retirement soon enough on its own, but a timer left
    // in the ring is a completion this owner is still owed however short its
    // fuse.
    if (m_relay_deadline_armed)
        timers_withdrawn &= loop.submit_timeout_remove(&m_relay_deadline_req);
    if (m_accept_backoff_armed)
        timers_withdrawn &= loop.submit_timeout_remove(&m_accept_backoff_req);
    loop.flush();

    if (SOCKETLEY_UNLIKELY(!timers_withdrawn))
        LOG_WARN("server: a timer withdrawal did not reach the ring — this instance "
                 "stays retired until the timer fires on its own");
}

// A timeout hangs off no fd, so the previous run's sweep is still counting down
// on this very request and arming another gives the server a second chain per
// restart.
// Dated from the first incomplete read and not renewed, which is the whole
// point: a deadline the next byte pushes out is a deadline the client owns.
// The same sentence arm_header_deadline() carries in the proxy, about the same
// trap -- and the one my TLS handshake deadline got wrong by reading
// last_activity.
void server_instance::arm_header_deadline(server_connection* conn)
{
    if (!conn || conn->awaiting_headers)
        return;

    conn->awaiting_headers = true;
    conn->header_deadline = std::chrono::steady_clock::now() +
                            std::chrono::seconds(http_header_deadline_secs);
    // Both callers are a head with no request line parsed out of it yet, so
    // the 408 the sweep answers owes a body whatever the LAST request on this
    // connection was -- and that is the one thing it cannot be asked.
    conn->http_head = false;
    m_headers_outstanding = true;
    arm_idle_sweep();
}

void server_instance::arm_idle_sweep()
{
    // Armed for any of four questions: the idle timeout if one was
    // configured, the handshake deadline on any TLS listener whether one was or
    // not, a head that has arrived in part, and a refused peer still draining.
    if (!m_loop || m_idle_sweep_armed ||
        (m_idle_timeout_cached <= 0 && !m_tls && !m_headers_outstanding && !m_drains_outstanding))
        return;

    m_idle_sweep_ts.tv_sec  = 30;
    m_idle_sweep_ts.tv_nsec = 0;
    m_idle_sweep_req = { this, nullptr, -1, 0, op_timeout };
    m_idle_sweep_armed = m_loop->submit_timeout(&m_idle_sweep_ts, &m_idle_sweep_req);
}

int server_instance::find_or_add_peer(const struct sockaddr_in& addr)
{
    const uint64_t key = udp_peer_key(addr);
    const auto now = std::chrono::steady_clock::now();

    auto it = m_udp_peer_idx.find(key);
    if (it != m_udp_peer_idx.end())
    {
        m_udp_peers[static_cast<size_t>(it->second)].last_seen = now;
        return it->second;
    }

    if (m_udp_peers.size() >= MAX_UDP_PEERS)
    {
        // The table used to be a wall: at MAX_UDP_PEERS every datagram from a
        // NEW address was dropped before process_message, silently and until
        // the runtime stopped -- and a peer was entered on its first datagram
        // and never removed, so ten thousand client restarts got there on
        // their own.  The oldest goes instead, because a sender heard from
        // longer ago than every other is the one a broadcast is least likely
        // to be for.
        int oldest = 0;
        for (size_t i = 1; i < m_udp_peers.size(); ++i)
            if (m_udp_peers[i].last_seen < m_udp_peers[oldest].last_seen)
                oldest = static_cast<int>(i);
        drop_udp_peer(oldest);
    }

    int idx = static_cast<int>(m_udp_peers.size());
    m_udp_peers.push_back({addr, now});
    m_udp_peer_idx[key] = idx;
    return idx;
}

// ─── Lua client enumeration ───

// Every client of this runtime and not of this process, with a sibling's
// client returned as a handle out of conn_identity.h's reserved range --
// minted once and kept, so the same client is the same number to a script that
// calls twice.
std::vector<int> server_instance::clients()
{
    if (!shard_clients_table().mapped())
        return m_active_fds;

    std::vector<conn_ref> foreign;
    const bool complete = shard_clients_table().read_others(foreign, shard_clients_table().index());
    if (!complete)
    {
        // A block that could not be read within its retry bound, said out
        // loud, because a script handed a short list with no indication is the
        // failure this step exists to remove.
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

    // Handles for siblings' connections that have gone, pruned here or
    // m_forwarded grows for the life of the runtime -- and only the ones
    // minted here, because route() owns its own lifetime.
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

// A stable local number for a connection a sibling shard owns, because a
// script that calls self.clients() twice and compares must get the same number
// for the same client.
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

// How many of the named connections the message was queued to, so the caller
// is told how many stale ids were skipped rather than having to assume none
// were.
size_t server_instance::multicast(const std::vector<int>& fds, std::string_view msg)
{
    if (!m_loop || m_udp) return 0;
    // The separator, on the same reasoning pipe() gives: every other send path
    // frames its message and this one did not, so two multicasts merged into
    // one unsplittable line.
    auto shared = std::make_shared<const std::string>(
        msg.empty() || msg.back() != '\n' ? std::string(msg) + "\n"
                                          : std::string(msg));
    // One frame for every websocket in the list; see queue_send's ws_cache.
    std::shared_ptr<const std::string> ws_msg;
    size_t sent = 0;
    for (int fd : fds)
    {
        if (fd < 0 || fd >= MAX_FDS) continue;
        auto* conn = m_conn_idx[fd];
        if (!conn || conn->closing) continue;
        queue_send(conn, shared, false, &ws_msg);
        ++sent;
    }
    return sent;
}

// ─── Lua per-connection metadata ───

bool server_instance::set_data(int fd, std::string_view key, std::string_view val)
{
    if (fd < 0 || fd >= MAX_FDS || !m_conn_idx[fd]) return false;
    m_conn_idx[fd]->meta[std::string(key)] = std::string(val);
    return true;
}

bool server_instance::del_data(int fd, std::string_view key)
{
    if (fd < 0 || fd >= MAX_FDS || !m_conn_idx[fd]) return false;
    m_conn_idx[fd]->meta.erase(std::string(key));
    return true;
}

std::string server_instance::get_data(int fd, std::string_view key) const
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

bool server_instance::join_group(int fd, std::string_view group)
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

bool server_instance::leave_group(int fd, std::string_view group)
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

// A count and not a bool, because the interesting failure is a group that
// exists and has nobody left in it, which is what a misspelled group name
// looks like.
size_t server_instance::group_send(std::string_view group, std::string_view msg)
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

    // One frame for every websocket in the group, built on the first one that
    // is a websocket and not at all if none is.
    std::shared_ptr<const std::string> ws_msg;
    size_t sent = 0;
    for (int fd : it->second)
    {
        auto* conn = (fd >= 0 && fd < MAX_FDS) ? m_conn_idx[fd] : nullptr;
        if (!conn || conn->closing) continue;
        if (conn->write_queue.bytes() >= write_buffer_bytes())
        {
            conn->closing = true;
            continue;
        }
        queue_send(conn, shared_msg, false, &ws_msg);
        ++sent;
    }
    return sent;
}

bool server_instance::pipe(int fd_a, int fd_b)
{
    if (!m_loop || fd_a == fd_b) return false;
    auto* a = (fd_a >= 0 && fd_a < MAX_FDS) ? m_conn_idx[fd_a] : nullptr;
    auto* b = (fd_b >= 0 && fd_b < MAX_FDS) ? m_conn_idx[fd_b] : nullptr;
    if (!a || !b || a->closing || b->closing) return false;

    // Unpipe any existing pairings first
    if (a->pipe_peer_fd >= 0) unpipe(fd_a);
    if (b->pipe_peer_fd >= 0) unpipe(fd_b);

    a->pipe_peer_fd = fd_b;
    b->pipe_peer_fd = fd_a;
    return true;
}

bool server_instance::unpipe(int fd)
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

    // Resolve the endpoint once and keep it, because a literal address needs
    // no resolver and a name looked up on every reconnect stalls everything
    // this runtime serves.
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

    // The callback does NOT fire here, and neither does `established`.  A
    // non-blocking connect() answers EINPROGRESS whenever the target is not
    // already there, so everything below this line used to be told the far end
    // had accepted before a single packet had crossed -- measured against a
    // port nobody held, `upstreams:1/1` for twenty-five of thirty seconds.
    // note_upstream_established() asks the kernel instead.
    uc->established = false;
    m_upstream_awaiting = true;

    return true;
}

// The upstream half of the client's note_connected(), and the same question:
// getpeername() is what an accept() answers on the other side, failing with
// ENOTCONN for as long as the handshake is out and never succeeding for a
// connect that was refused.
void server_instance::note_upstream_established()
{
    bool still_waiting = false;
    for (auto& [_, uc] : m_upstreams)
    {
        if (!uc->connected || uc->established || uc->fd < 0)
            continue;

        struct sockaddr_storage peer{};
        socklen_t len = sizeof(peer);
        if (getpeername(uc->fd, reinterpret_cast<struct sockaddr*>(&peer), &len) < 0)
        {
            still_waiting = true;      // handshake out, or refused and not yet reaped
            continue;
        }

        uc->established = true;
        invoke_on_upstream_connect(uc->conn_id);
    }
    m_upstream_awaiting = still_waiting;
}

void server_instance::upstream_schedule_reconnect(upstream_connection* uc)
{
    // Not while one is already counting down: the timer request is a single
    // slot on this struct, and re-arming it while the kernel still holds it
    // gives one upstream two reconnect chains.
    if (!m_loop || uc->timeout_pending)
        return;

    // Exponential backoff, 1, 2, 4, 8 and then 16 seconds, with up to half a
    // second of jitter.  SIXTEEN and not thirty: the shift is capped at four,
    // so base_sec never passes 16 and the std::min against 30 that used to sit
    // here could not fire.  The same dead pair stood in the client until it
    // was measured -- dials at 1, 2, 4, 8.1, 16.2, 32.7, 49.1 seconds, which
    // is 16 from the fifth on -- and the comment is corrected rather than the
    // code, because a thirty-second ceiling buys nothing sixteen does not and
    // costs fourteen more seconds of outage after the target comes back.
    int delay_sec = 1 << std::min(uc->reconnect_attempt, 4);
    int jitter_ms = (uc->reconnect_attempt * 137) % 500;

    // The address that just failed us goes with the attempt.  has_cached_addr
    // was set once and never cleared -- there was no path that cleared it at
    // all -- so a server with `-u app:9000` kept dialling the IP a recreated
    // container had already released, for the life of the runtime, and
    // on_upstream_connect never fired again.  Re-resolving costs a getaddrinfo
    // at most once per second of backoff, and a literal address never reaches
    // the resolver.
    uc->has_cached_addr = false;

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
    uc->established = false;
    uc->closing = false;
    uc->read_pending = false;
    uc->write_pending = false;
    uc->partial.clear();

    // Release write queue refs
    uc->write_queue.clear();
    for (size_t i = 0; i < uc->write_batch_count; i++)
        uc->write_batch[i].clear();
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

    if (uc->partial.size() > read_buffer_bytes())
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

// Upstreams are outside the reachability chokepoint deliberately, because an
// upstream read is single-shot on the descriptor and close_fd() can withdraw
// it -- but this rests on the structural argument alone and was never
// measured.
void server_instance::handle_upstream_write(struct io_uring_cqe* cqe, upstream_connection* uc)
{
    uc->write_pending = false;

    if (cqe->res <= 0)
    {
        for (uint32_t i = 0; i < uc->write_batch_count; i++)
            uc->write_batch[i].clear();
        uc->write_batch_count = 0;
        uc->closing = true;
        if (!uc->read_pending)
            upstream_disconnect(uc);
        return;
    }

    m_stat_bytes_out.fetch_add(static_cast<uint64_t>(cqe->res), std::memory_order_relaxed);

    // Short write handling, because releasing the batch on any positive result
    // dropped the rest and the upstream read a truncated message with the next
    // one appended.
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
                    uc->write_batch[i].clear();
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
                    uc->write_batch[i].clear();
                uc->write_batch_count = 0;
                uc->closing = true;
            }
            return;
        }
    }

    // Full write completed — release batch
    for (uint32_t i = 0; i < uc->write_batch_count; i++)
        uc->write_batch[i].clear();
    uc->write_batch_count = 0;

    // The queue has shrunk, so this is where the crossing can be seen.  Without
    // this the drain_wanted set one function down was a flag nothing read: an
    // upstream producer could ASK how deep its queue was and never be told when
    // there was room, which is the cliff without the slope that this whole
    // session has been closing.  Recorded and not called, for the reason the
    // client-facing dispatch gives at length: a script's callback sends.
    if (SOCKETLEY_UNLIKELY(uc->drain_wanted)
        && uc->write_queue.bytes() < write_watermark_bytes())
    {
        uc->drain_wanted = false;
        if (wants_on_upstream_writable())
            m_upstream_drain_pending.push_back(uc->conn_id);
    }

    if (!uc->write_queue.empty())
    {
        upstream_flush_write_queue(uc);
    }
    else if (uc->closing && !uc->read_pending)
    {
        upstream_disconnect(uc);
    }
}

bool server_instance::queue_upstream_send(upstream_connection* uc, const std::shared_ptr<const std::string>& msg)
{
    if (!m_loop || !uc->connected || uc->closing)
        return false;

    const size_t queued = uc->write_queue.bytes();
    if (queued >= write_buffer_bytes())
    {
        // Sticky, so the refusal one call later can say which of the reasons it
        // was.  The comment below already noted this door is "the same decision
        // queue_send() makes one function up" -- and that one was taught to
        // answer while this one was not, which is the whole of this change.
        uc->closed_for_backlog = true;
        uc->closing = true;
        return false;
    }
    if (queued + msg->size() >= write_watermark_bytes())
        uc->drain_wanted = true;

    // The same decision queue_send() makes one function up, because
    // upstream_broadcast() is the same shape pointed outwards: one payload,
    // every upstream connection, and a queue that only deepens when one of
    // them is not draining.
    uc->write_queue.push_shared(msg,
        upstream_connection::WRITE_COALESCE_LIMIT,
        upstream_connection::MAX_WRITE_BATCH);
    if (!uc->write_pending)
        upstream_flush_write_queue(uc);
    return true;
}

void server_instance::upstream_flush_write_queue(upstream_connection* uc)
{
    if (!m_loop || uc->write_queue.empty())
        return;

    uint32_t count = 0;
    while (!uc->write_queue.empty() && count < upstream_connection::MAX_WRITE_BATCH)
    {
        uc->write_batch[count] = uc->write_queue.take_front();
        uc->write_iovs[count].iov_base = const_cast<char*>(uc->write_batch[count].data());
        uc->write_iovs[count].iov_len = uc->write_batch[count].size();
        count++;
    }

    uc->write_batch_count = count;
    uc->write_pending = true;

    bool queued;
    if (count == 1)
    {
        uc->write_req.type = op_write;
        queued = m_loop->submit_write(uc->fd, uc->write_batch[0].data(),
            static_cast<uint32_t>(uc->write_batch[0].size()), &uc->write_req);
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
            uc->write_batch[i].clear();
        uc->write_batch_count = 0;
        uc->closing = true;
    }
}

// ─── Lua upstream actions ───

bool server_instance::upstream_send(int conn_id, std::string_view msg)
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
    // Answered rather than assumed: the old `return true` here is the same
    // defect send_to_client() carried, whose own comment admitted it -- "a
    // connection closed for exceeding the write-queue bound reported by the
    // connection going away".
    return queue_upstream_send(it->second.get(), std::move(shared));
}

server_instance::fanout_count server_instance::upstream_broadcast(std::string_view msg)
{
    fanout_count counted;
    std::string buf;
    buf.reserve(msg.size() + 1);
    buf.append(msg);
    if (buf.empty() || buf.back() != '\n')
        buf.push_back('\n');
    auto shared = std::make_shared<const std::string>(std::move(buf));
    for (auto& [cid, uc] : m_upstreams)
    {
        if (!uc->connected || uc->closing)
            continue;
        if (queue_upstream_send(uc.get(), shared))
            ++counted.taken;
        else
            ++counted.backlogged;
    }
    return counted;
}

long server_instance::upstream_pending(int conn_id) const
{
    auto it = m_upstreams.find(conn_id);
    if (it == m_upstreams.end())
        return -1;
    return static_cast<long>(it->second->write_queue.bytes());
}

bool server_instance::upstream_closed_for_backlog(int conn_id) const
{
    auto it = m_upstreams.find(conn_id);
    return it != m_upstreams.end() && it->second->closed_for_backlog;
}

std::vector<int> server_instance::upstreams() const
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
