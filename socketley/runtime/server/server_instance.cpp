#include "server_instance.h"
#include "../../shared/blocking_write.h"
#include "../../shared/event_loop.h"
#include "../../shared/runtime_manager.h"
#include "../../shared/lua_context.h"
#include "../../shared/ws_protocol.h"
#include "../../shared/invariants.h"
#include "../../cli/command_hashing.h"
#include "../cache/cache_instance.h"
#include "../cache/resp_parser.h"

#include <unistd.h>
#include <cstring>
#include <charconv>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <liburing.h>
#include <sstream>
#include <algorithm>
#include <fstream>
#include <filesystem>
#include <fcntl.h>
#include <sys/stat.h>

server_instance::server_instance(std::string_view name)
    : runtime_instance(runtime_server, name), m_mode(mode_inout), m_listen_fd(-1), m_loop(nullptr)
{
    std::memset(&m_accept_addr, 0, sizeof(m_accept_addr));
    m_accept_addrlen = sizeof(m_accept_addr);
    m_accept_req = { this, nullptr, -1, 0, op_accept };
}

server_instance::~server_instance()
{
    if (m_listen_fd >= 0)
        close(m_listen_fd);
    if (m_udp_fd >= 0)
        close(m_udp_fd);
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
    return conn;
}

bool server_instance::conn_ops_pending(const server_connection* conn) const
{
    return conn->read_pending || conn->write_pending || conn->zc_notif_pending
        || conn->file_read_pending || conn->splice_in_pending || conn->splice_out_pending;
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
    // Doing this while a request is still in flight is safe for the same reason
    // closing the socket is: the request took its own reference to the file when
    // it was issued and keeps it until it completes.  This is also what teardown
    // did before the retired list existed.
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
    for (uint32_t i = 0; i < conn->write_batch_count; i++) conn->write_batch[i].reset();
    conn->write_batch_count = 0;
    conn->ws_cookie.clear();
    conn->ws_origin.clear();
    conn->ws_protocol.clear();
    conn->ws_auth.clear();
    if (conn->file_fd >= 0) { close(conn->file_fd); conn->file_fd = -1; }
    if (conn->file_buf) { free(conn->file_buf); conn->file_buf = nullptr; }
    conn->file_size = 0;
    conn->file_content_type.clear();
    conn->file_is_html = false;
    conn->file_read_pending = false;
    conn->http_keep_alive = false;

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
    if (fd >= 0 && fd < MAX_FDS)
        m_conn_idx[fd] = nullptr;
    close(fd);

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
        close(conn->file_fd);
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

void server_instance::add_upstream_target(std::string_view addr)
{
    upstream_target t;
    t.address = std::string(addr);
    auto colon = addr.rfind(':');
    if (colon != std::string_view::npos)
    {
        t.resolved_host = std::string(addr.substr(0, colon));
        auto port_sv = addr.substr(colon + 1);
        std::from_chars(port_sv.data(), port_sv.data() + port_sv.size(), t.resolved_port);
    }
    else
    {
        t.resolved_host = std::string(addr);
        t.resolved_port = 0;
    }
    m_upstream_targets.push_back(std::move(t));
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

void server_instance::rebuild_http_cache()
{
    m_http_cache.clear();
    if (m_http_dir.empty())
        return;

    namespace fs = std::filesystem;
    std::error_code ec;

    // Resolve canonical base path (also cached for disk-mode serve_http)
    m_http_base = fs::canonical(m_http_dir, ec);
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

        // Store pre-built response as shared_ptr (zero-copy on cache hit)
        // Use keep-alive since 99%+ clients are HTTP/1.1
        m_http_cache[url_path] = {
            std::make_shared<const std::string>(build_http_response(ct, content, true))
        };
    }
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
            ? it->second.response : http_404_response(conn->http_keep_alive));

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

        fs::path file_path = m_http_base / url_path.substr(1); // strip leading /
        fs::path resolved = fs::canonical(file_path, ec);

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

        // Open file and get size
        int ffd = open(resolved.c_str(), O_RDONLY);
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
            close(ffd);
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

        // Splice path: zero-copy file→pipe→socket for non-HTML files
        if (!is_html && !m_splice_busy && m_splice_pipe[0] >= 0)
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
            close(ffd);
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

void server_instance::handle_http_request(server_connection* conn, const http_request& req, size_t total_consumed)
{
#ifndef SOCKETLEY_NO_LUA
    // Try Lua on_http_request callback
    if (lua() && lua()->has_on_http_request())
    {
        try
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

            sol::object result = lua()->on_http_request()(lua_req);

            if (result.is<sol::table>())
            {
                sol::table resp_tbl = result.as<sol::table>();
                int status = resp_tbl.get_or("status", 200);
                std::string body = resp_tbl.get_or<std::string>("body", "");
                std::string_view reason = http_reason(status);

                std::vector<std::pair<std::string, std::string>> resp_headers;
                sol::optional<sol::table> h = resp_tbl["headers"];
                if (h)
                {
                    h->for_each([&](sol::object key, sol::object val) {
                        if (key.is<std::string>() && val.is<std::string>())
                            resp_headers.emplace_back(key.as<std::string>(), val.as<std::string>());
                    });
                }

                // Determine keep-alive: HTTP/1.1 defaults to keep-alive
                bool keep_alive = (req.version.find("1.1") != std::string_view::npos);

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
        catch (const std::exception&)
        {
            // Lua error — fall through to static/404
        }
    }
#endif

    // Determine keep-alive: HTTP/1.1 defaults to keep-alive
    conn->http_keep_alive = (req.version.find("1.1") != std::string_view::npos);

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
    return m_active_fds.size() + m_forwarded_clients.size() + upstream_connected;
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

    m_loop = &loop;
    m_ring_loop = &loop;

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

    // Internal-only server (port=0, used for Lua-managed sub-servers)
    if (get_port() == 0 && !get_owner().empty())
        return true;

    uint16_t port = get_port();
    if (port == 0)
        port = 8000;

    if (m_udp)
    {
        m_udp_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
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
            close(m_udp_fd);
            m_udp_fd = -1;
            return false;
        }

        // Setup recvmsg structures
        std::memset(&m_udp_recv_addr, 0, sizeof(m_udp_recv_addr));
        m_udp_recv_iov.iov_base = m_udp_recv_buf;
        m_udp_recv_iov.iov_len = sizeof(m_udp_recv_buf);
        std::memset(&m_udp_recv_msg, 0, sizeof(m_udp_recv_msg));
        m_udp_recv_msg.msg_name = &m_udp_recv_addr;
        m_udp_recv_msg.msg_namelen = sizeof(m_udp_recv_addr);
        m_udp_recv_msg.msg_iov = &m_udp_recv_iov;
        m_udp_recv_msg.msg_iovlen = 1;

        // Only if the previous run's recvmsg has completed.  It reads into
        // m_udp_recv_buf and writes the sender into m_udp_recv_addr; a second
        // one armed on the same msghdr gives the kernel two writers into one
        // buffer and one sockaddr, and answers go to whichever peer landed
        // there last.  If one is still armed it re-arms itself on the new
        // socket when it completes.
        if (!m_udp_recv_armed)
        {
            m_udp_recv_req = { this, nullptr, m_udp_fd, 0, op_recvmsg };
            arm_udp_recv();
        }

        return true;
    }

    // TCP mode
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

    // Setup provided buffer ring for zero-copy reads
    m_use_provided_bufs = loop.setup_buf_ring(BUF_GROUP_ID, BUF_COUNT, BUF_SIZE);
    m_recv_multishot = m_use_provided_bufs && loop.recv_multishot_supported();
    m_send_zc = loop.send_zc_supported();

    // Use multishot accept if supported (kernel 5.19+)
    // Note: direct-descriptor accept (kernel 6.0+) is NOT used because
    // cqe->res returns a fixed file index, not a real fd — setsockopt,
    // getpeername, and other syscalls require a real fd.  Instead, we
    // register the accepted fd into the fixed file table post-accept.
    // The previous run's accept chain died with its listener: teardown()
    // shuts the socket down, which completes every accept it holds.  Arming a
    // fresh one here is therefore right; handle_accept() is what must not arm a
    // second when that dead chain's last completion finally arrives.
    m_direct_accept = false;
    if (event_loop::supports_multishot_accept())
    {
        m_accept_req.type = op_multishot_accept;
        m_accept_armed = loop.submit_multishot_accept(m_listen_fd, &m_accept_req);
        m_multishot_active = true;
    }
    else
    {
        m_accept_req.type = op_accept;
        m_accept_armed = loop.submit_accept(m_listen_fd, &m_accept_addr, &m_accept_addrlen, &m_accept_req);
        m_multishot_active = false;
    }

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
        if (pipe2(m_splice_pipe, O_NONBLOCK) == 0)
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
    if (m_udp)
    {
        if (m_udp_fd >= 0)
        {
            // The recvmsg holds a reference to the socket, so close() does not
            // end it — it stays armed on m_udp_recv_buf and m_udp_recv_addr.
            // SO_REUSEPORT then makes that matter: once a restart binds a new
            // socket to the same port the kernel delivers datagrams to the old
            // one as well, and the completion used to arm a second recvmsg on
            // the same msghdr.  Cancel first, close second — event_loop.h says
            // why that order and not the other one.
            loop.submit_cancel_fd(m_udp_fd);
            loop.flush();
            close(m_udp_fd);
            m_udp_fd = -1;
        }
        m_udp_peers.clear();
        m_udp_peer_idx.clear();
        m_loop = nullptr;
        return;
    }

    // Shutdown the listen socket before closing it.  This causes the kernel to
    // complete any pending io_uring accept ops immediately (via the socket wait
    // queue), placing their CQEs in the ring synchronously within the syscall.
    // Using shutdown() instead of a cancel SQE avoids the race where close(fd)
    // is called before the SQPOLL thread processes the cancel SQE: after close,
    // fget(fd) returns NULL so the cancel fails with ENOENT, leaving the accept
    // in-flight and its CQE arriving after server_instance is freed → SIGSEGV.
    if (m_listen_fd >= 0)
        shutdown(m_listen_fd, SHUT_RDWR);

    // Close listener to stop new connections
    if (m_listen_fd >= 0)
    {
        close(m_listen_fd);
        m_listen_fd = -1;
    }

    // Drain: flush pending write queues with blocking writes before closing
    if (get_drain())
    {
        for (auto& [fd, conn] : m_clients)
        {
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

    for (auto& [fd, conn] : m_clients)
    {
        if (fd >= 0 && fd < MAX_FDS)
            m_conn_idx[fd] = nullptr;

        conn->closing = true;

        // Shutdown the connection before closing it.  Like for the listen fd,
        // shutdown() completes any pending io_uring read/write ops synchronously
        // (the kernel wakes up the socket wait queue, completing the ops and
        // placing their CQEs in the ring before we return from shutdown()).
        // This avoids the cancel-SQE fd-closed race described above.
        shutdown(fd, SHUT_RDWR);
        close(fd);

        // The file read and the file→pipe splice target the file fd, not the
        // socket, so the shutdown above does not touch them.  Closing the file
        // ends them; the ops themselves keep the struct out of the pool until
        // their completions arrive, and file_buf stays allocated until then
        // because that is where the kernel is writing.
        if (conn->file_fd >= 0) { close(conn->file_fd); conn->file_fd = -1; }
        if (conn->splice_file_fd >= 0) { close(conn->splice_file_fd); conn->splice_file_fd = -1; }
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

    // Tear down upstream connections
    for (auto& [cid, uc] : m_upstreams)
    {
        if (uc->fd >= 0)
        {
            m_upstream_by_fd.erase(uc->fd);
            shutdown(uc->fd, SHUT_RDWR);
            close(uc->fd);
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
        if (uc->read_pending || uc->write_pending || uc->timeout_pending)
            m_upstream_retired.push_back(std::move(uc));
    }
    m_upstreams.clear();

    // Close splice pipe
    if (m_splice_pipe[0] >= 0) { close(m_splice_pipe[0]); m_splice_pipe[0] = -1; }
    if (m_splice_pipe[1] >= 0) { close(m_splice_pipe[1]); m_splice_pipe[1] = -1; }
    m_splice_busy = false;

    // m_idle_sweep_req keeps its owner.  Nulling it made the loop drop the
    // sweep's completion, which left m_idle_sweep_armed true for ever and the
    // next start() unable to tell an armed timer from a lost one.  The request
    // lives in this instance, and an instance that ever armed I/O is retired
    // rather than freed, so the loop reading it is reading valid memory.
    m_loop = nullptr;
    m_multishot_active = false;
    m_master_fd = -1;

    // Clean up forwarded client entries on parent servers
    for (auto& [fwd_fd, parent_name] : m_forwarded_clients)
    {
        auto* mgr = get_runtime_manager();
        if (mgr)
        {
            auto* parent = mgr->get(parent_name);
            if (parent && parent->get_type() == runtime_server)
            {
                auto* psrv = static_cast<server_instance*>(parent);
                psrv->m_routes.erase(fwd_fd);
            }
        }
    }
    m_forwarded_clients.clear();
    m_routes.clear();
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
        else if (req == &m_accept_backoff_req) m_accept_backoff_armed = false;
        else if (req == &m_udp_recv_req)       m_udp_recv_armed = false;
        else if (req == &m_accept_req)         m_accept_armed = false;
        return;
    }

#ifdef SOCKETLEY_INVARIANTS
    // Remembered before the dispatch, because the handler may release the
    // struct and the request with it.  Only per-connection operations are worth
    // asking about; an accept or a timer names no connection.
    const int inv_fd = (req->type == op_accept || req->type == op_multishot_accept ||
                        req->type == op_timeout || req->type == op_recvmsg)
                       ? -1 : req->fd;
#endif

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
        case op_write:
        case op_writev:
        case op_send_zc:
        case op_send_zc_notif:
        {
            const bool is_read = (req->type == op_read || req->type == op_read_provided
                                  || req->type == op_recv_multishot);

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
                        m_accept_armed = m_loop->submit_multishot_accept(m_listen_fd, &m_accept_req);
                    else
                    {
                        m_accept_addrlen = sizeof(m_accept_addr);
                        m_accept_armed = m_loop->submit_accept(m_listen_fd, &m_accept_addr,
                                                               &m_accept_addrlen, &m_accept_req);
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

#ifdef SOCKETLEY_INVARIANTS
    inv_check_reachable(inv_fd, "server::on_cqe");
#endif
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
        h.in_flight = c->read_pending || c->write_pending || c->zc_notif_pending ||
                      c->file_read_pending || c->splice_in_pending || c->splice_out_pending;
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
}

inline void server_instance::submit_conn_read(server_connection* conn)
{
    bool queued;
    if (conn->direct_fd)
    {
        if (m_recv_multishot)
            queued = m_loop->submit_recv_multishot_fixed_file(conn->fixed_idx, BUF_GROUP_ID, &conn->read_req);
        else if (m_use_provided_bufs)
            queued = m_loop->submit_read_provided_fixed_file(conn->fixed_idx, BUF_GROUP_ID, &conn->read_req);
        else
            queued = m_loop->submit_read_fixed_file(conn->fixed_idx, conn->read_buf, server_connection::READ_BUF_SIZE, &conn->read_req);
    }
    else
    {
        if (m_recv_multishot)
            queued = m_loop->submit_recv_multishot(conn->fd, BUF_GROUP_ID, &conn->read_req);
        else if (m_use_provided_bufs)
            queued = m_loop->submit_read_provided(conn->fd, BUF_GROUP_ID, &conn->read_req);
        else
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
            close(client_fd);
            goto resubmit_accept;
        }

        // Max connections check
        if (SOCKETLEY_UNLIKELY(m_max_conns_cached > 0 && m_clients.size() >= m_max_conns_cached))
        {
            close(client_fd);
            goto resubmit_accept;
        }

        int opt = 1;
        setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

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

        // Check per-IP auth failure rate (master mode only)
        // Use getpeername() instead of m_accept_addr because multishot accept
        // passes nullptr for addr — m_accept_addr is never populated per-connection.
        if (!m_master_pw.empty())
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
                m_accept_armed = m_loop->submit_multishot_accept(m_listen_fd, &m_accept_req);
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
                                                   &m_accept_addrlen, &m_accept_req);
        }
    }
}

void server_instance::handle_read(struct io_uring_cqe* cqe, io_request* req)
{
    int fd = req->fd;
    auto* conn = m_conn_idx[fd];
    if (SOCKETLEY_UNLIKELY(!conn))
        return;

    bool is_multishot_recv = (req->type == op_recv_multishot);
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

    if (is_provided)
    {
        // Extract buffer ID from CQE flags
        uint16_t buf_id = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
        char* buf_ptr = m_loop->get_buf_ptr(BUF_GROUP_ID, buf_id);
        if (SOCKETLEY_LIKELY(buf_ptr != nullptr))
        {
            conn->partial.append(buf_ptr, cqe->res);
            m_loop->return_buf(BUF_GROUP_ID, buf_id);
        }
    }
    else
    {
        conn->partial.append(conn->read_buf, cqe->res);
    }

    if (SOCKETLEY_UNLIKELY(conn->partial.size() > server_connection::MAX_PARTIAL_SIZE))
    {
        conn->closing = true;
        goto submit_next_read;
    }

    // Multi-protocol auto-detection
    if (conn->proto == proto_unknown)
    {
        if (conn->partial.size() < 4)
            goto submit_next_read;

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
                conn->proto = proto_http;
        }
        else
        {
            conn->proto = proto_tcp;
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
                goto submit_next_read;
            }
            goto submit_next_read; // Incomplete headers
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
                // Fall through to proto_http handler below
            }
            else
            {
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
        goto submit_next_read;
    }

    // proto_http: full HTTP request handling
    if (conn->proto == proto_http)
    {
        // Wait for complete headers
        auto hdr_end = conn->partial.find("\r\n\r\n");
        if (hdr_end == std::string::npos)
        {
            if (conn->partial.size() > 16384)
            {
                conn->closing = true;
                goto submit_next_read;
            }
            goto submit_next_read;
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
            goto submit_next_read;
        }

        http_request hreq;
        hreq.method = req_line.substr(0, sp1);
        std::string_view raw_path = req_line.substr(sp1 + 1, sp2 - sp1 - 1);
        hreq.version = req_line.substr(sp2 + 1);
        hreq.client_id = fd;

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

        // Parse headers + detect Content-Length
        size_t content_length = 0;
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
                    std::string_view name = line.substr(0, colon);
                    size_t vs = colon + 1;
                    while (vs < line.size() && line[vs] == ' ') ++vs;
                    std::string_view value = line.substr(vs);
                    hreq.headers.emplace_back(name, value);

                    if (fnv1a_lower(name) == fnv1a("content-length"))
                        std::from_chars(value.data(), value.data() + value.size(), content_length);
                }
                line_start = line_end + 2;
            }
        }

        size_t total_expected = hdr_end + 4 + content_length;
        if (conn->partial.size() < total_expected)
            goto submit_next_read;  // Need more body data

        hreq.body = full.substr(hdr_end + 4, content_length);

        handle_http_request(conn, hreq, total_expected);
        goto submit_next_read;
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
        goto submit_next_read;
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

submit_next_read:
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
        auto rit = m_routes.find(sender->fd);
        if (rit != m_routes.end())
        {
            auto* mgr = get_runtime_manager();
            if (mgr)
            {
                auto* target = mgr->get(rit->second);
                if (target && target->get_type() == runtime_server &&
                    target->get_state() == runtime_running)
                {
                    auto* sub = static_cast<server_instance*>(target);
                    sub->process_forwarded_message(sender->fd, msg, get_name());
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

    // Cache command interception: "cache <cmd>" → execute against linked cache, respond to sender only
    if (SOCKETLEY_UNLIKELY(sender && msg.size() > 6 && msg[0] == 'c' && msg.starts_with("cache ")))
    {
        auto cname = get_cache_name();
        if (!cname.empty() && get_runtime_manager())
        {
            auto* cache_rt = get_runtime_manager()->get(cname);
            if (cache_rt && cache_rt->get_type() == runtime_cache &&
                cache_rt->get_state() == runtime_running)
            {
                auto* cache = static_cast<cache_instance*>(cache_rt);
                std::string resp = cache->execute(msg.substr(6));
                if (!resp.empty())
                {
                    if (resp.back() != '\n')
                        resp += '\n';
                    auto resp_msg = std::make_shared<const std::string>(std::move(resp));
                    send_to(sender, resp_msg);
                }
            }
        }
        return; // Cache commands are never broadcast
    }

    // Store in cache if configured
    auto cache_name = get_cache_name();
    if (!cache_name.empty() && get_runtime_manager())
    {
        auto* cache_rt = get_runtime_manager()->get(cache_name);
        if (cache_rt && cache_rt->get_type() == runtime_cache &&
            cache_rt->get_state() == runtime_running)
        {
            auto* cache = static_cast<cache_instance*>(cache_rt);
            char key_buf[24];
            auto [key_end, key_ec] = std::to_chars(key_buf, key_buf + sizeof(key_buf), ++m_message_counter);
            cache->store_direct(std::string_view(key_buf, key_end - key_buf), msg);
        }
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

                // Try Lua on_master_auth callback first
                auto* lctx = lua();
                if (lctx && lctx->has_on_master_auth())
                {
#ifndef SOCKETLEY_NO_LUA
                    try {
                        sol::protected_function_result result =
                            lctx->on_master_auth()(sender->fd, pw);
                        if (result.valid())
                            auth_ok = result.get<bool>();
                    } catch (...) {}
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

    // Also send to forwarded clients through their parent servers
    for (auto& [fwd_fd, parent_name] : m_forwarded_clients)
    {
        auto* mgr = get_runtime_manager();
        if (mgr)
        {
            auto* parent = mgr->get(parent_name);
            if (parent && parent->get_type() == runtime_server &&
                parent->get_state() == runtime_running)
            {
                static_cast<server_instance*>(parent)->send_to_client(fwd_fd, msg);
            }
        }
    }
}

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

void server_instance::send_to(server_connection* conn, const std::shared_ptr<const std::string>& msg)
{
    if (SOCKETLEY_UNLIKELY(!m_loop || conn->closing))
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

void server_instance::flush_write_queue(server_connection* conn)
{
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

    // Check if more messages to send
    if (SOCKETLEY_LIKELY(!conn->write_queue.empty() && !conn->zc_notif_pending))
    {
        flush_write_queue(conn);
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
        if (conn->file_fd >= 0) { close(conn->file_fd); conn->file_fd = -1; }
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

    // Read error — send 404
    if (SOCKETLEY_UNLIKELY(cqe->res <= 0))
    {
        if (conn->file_fd >= 0) { close(conn->file_fd); conn->file_fd = -1; }
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
        }
        return;
    }

    // Close the file fd — we're done with it
    if (conn->file_fd >= 0)
    {
        close(conn->file_fd);
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

    conn->write_queue.push(
        std::make_shared<const std::string>(
            build_http_response(conn->file_content_type, resp_body, conn->http_keep_alive)));

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
        close(conn->splice_file_fd);
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
    }
    else
    {
        conn->proto = proto_unknown;
        if (!conn->read_pending)
            submit_conn_read(conn);
    }
}

// One recvmsg at a time, always.  It reads into m_udp_recv_buf and writes the
// sender into m_udp_recv_addr, both single-instance, so a second one armed
// beside it gives the kernel two writers into the same buffer and the same
// sockaddr: datagrams interleave and replies go to the wrong peer.
void server_instance::arm_udp_recv()
{
    if (!m_loop || m_udp_fd < 0)
    {
        m_udp_recv_armed = false;
        return;
    }
    m_udp_recv_msg.msg_namelen = sizeof(m_udp_recv_addr);
    m_udp_recv_armed = m_loop->submit_recvmsg(m_udp_fd, &m_udp_recv_msg, &m_udp_recv_req);
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
    if (find_or_add_peer(m_udp_recv_addr) < 0)
    {
        arm_udp_recv();
        return;
    }

    // Extract message — whole datagram = one message
    std::string_view msg(m_udp_recv_buf, static_cast<size_t>(cqe->res));

    // Strip trailing newline if present
    if (!msg.empty() && msg.back() == '\n')
    {
        msg.remove_suffix(1);
        if (!msg.empty() && msg.back() == '\r')
            msg.remove_suffix(1);
    }

    if (!msg.empty())
        process_message(nullptr, msg);

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

void server_instance::lua_disconnect(int client_fd)
{
    auto* conn = (client_fd >= 0 && client_fd < MAX_FDS)
                 ? m_conn_idx[client_fd] : nullptr;
    if (!conn || conn->closing) return;
    conn->closing = true;
    // SHUT_RD only: keeps the write side open so any queued message
    // (e.g. "AUTH FAIL" sent just before disconnect) still reaches the client.
    // If a pending read CQE exists, SHUT_RD triggers its EOF so handle_read
    // can clean up. If no ops are pending, handle_read's submit_next_read
    // branch handles the cleanup when it sees closing=true, write_pending=false.
    shutdown(client_fd, SHUT_RD);
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
    try {
        sol::table h = lctx->state().create_table();
        if (!conn->ws_cookie.empty())   h["cookie"]        = conn->ws_cookie;
        if (!conn->ws_origin.empty())   h["origin"]        = conn->ws_origin;
        if (!conn->ws_protocol.empty()) h["protocol"]      = conn->ws_protocol;
        if (!conn->ws_auth.empty())     h["authorization"] = conn->ws_auth;
        lctx->on_websocket()(fd, h);
    } catch (const sol::error& e) {
        fprintf(stderr, "[lua] on_websocket error: %s\n", e.what());
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

void server_instance::lua_send_to(int client_id, std::string_view msg)
{
    if (!m_loop || m_udp)
        return;

    // Check direct connection first
    if (client_id >= 0 && client_id < MAX_FDS && m_conn_idx[client_id])
    {
        auto* conn = m_conn_idx[client_id];
        if (conn->closing)
            return;

        std::string buf;
        buf.reserve(msg.size() + 1);
        buf.append(msg);
        if (buf.empty() || buf.back() != '\n')
            buf.push_back('\n');
        auto full_msg = std::make_shared<const std::string>(std::move(buf));
        send_to(conn, full_msg);
        return;
    }

    // Check forwarded clients (send through parent server)
    auto fit = m_forwarded_clients.find(client_id);
    if (fit != m_forwarded_clients.end())
    {
        auto* mgr = get_runtime_manager();
        if (mgr)
        {
            auto* parent = mgr->get(fit->second);
            if (parent && parent->get_type() == runtime_server &&
                parent->get_state() == runtime_running)
            {
                static_cast<server_instance*>(parent)->send_to_client(client_id, msg);
            }
        }
    }
}

std::string server_instance::get_stats() const
{
    std::string base = runtime_instance::get_stats();
    std::ostringstream out;
    out << base
        << "peak_connections:" << m_stat_peak_connections << "\n"
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
    return out.str();
}

// ─── Client Routing ───

bool server_instance::route_client(int client_fd, std::string_view target_name)
{
    auto* mgr = get_runtime_manager();
    if (!mgr) return false;

    auto* target = mgr->get(target_name);
    if (!target || target->get_type() != runtime_server) return false;

    auto* sub = static_cast<server_instance*>(target);
    m_routes[client_fd] = std::string(target_name);

    // Update cached route flag on connection
    if (client_fd >= 0 && client_fd < MAX_FDS && m_conn_idx[client_fd])
        m_conn_idx[client_fd]->routed = true;

    sub->m_forwarded_clients[client_fd] = std::string(get_name());
    sub->invoke_on_connect(client_fd);
    return true;
}

bool server_instance::unroute_client(int client_fd)
{
    auto it = m_routes.find(client_fd);
    if (it == m_routes.end()) return false;

    // Clear cached route flag on connection
    if (client_fd >= 0 && client_fd < MAX_FDS && m_conn_idx[client_fd])
        m_conn_idx[client_fd]->routed = false;

    auto* mgr = get_runtime_manager();
    if (mgr)
    {
        auto* target = mgr->get(it->second);
        if (target && target->get_type() == runtime_server)
        {
            auto* sub = static_cast<server_instance*>(target);
            sub->invoke_on_disconnect(client_fd);
            sub->m_forwarded_clients.erase(client_fd);
        }
    }
    m_routes.erase(it);
    return true;
}

std::string_view server_instance::get_client_route(int client_fd) const
{
    auto it = m_routes.find(client_fd);
    if (it == m_routes.end()) return {};
    return it->second;
}

void server_instance::process_forwarded_message(int client_fd, std::string_view msg,
                                                  std::string_view /*parent_name*/)
{
    m_stat_total_messages.fetch_add(1, std::memory_order_relaxed);
    invoke_on_client_message(client_fd, msg);
    invoke_on_message(msg);
}

void server_instance::remove_forwarded_client(int client_fd)
{
    m_forwarded_clients.erase(client_fd);
}

void server_instance::send_to_client(int client_fd, std::string_view msg)
{
    if (SOCKETLEY_UNLIKELY(client_fd < 0 || client_fd >= MAX_FDS || !m_conn_idx[client_fd])) return;
    auto* conn = m_conn_idx[client_fd];
    if (SOCKETLEY_UNLIKELY(conn->closing)) return;

    std::string buf;
    buf.reserve(msg.size() + 1);
    buf.append(msg);
    if (buf.empty() || buf.back() != '\n') buf.push_back('\n');
    auto shared = std::make_shared<const std::string>(std::move(buf));
    send_to(conn, shared);
}

bool server_instance::owner_send(int client_fd, std::string_view msg)
{
    auto owner_name = get_owner();
    if (owner_name.empty()) return false;

    auto* mgr = get_runtime_manager();
    if (!mgr) return false;

    auto* parent = mgr->get(owner_name);
    if (!parent || parent->get_type() != runtime_server ||
        parent->get_state() != runtime_running) return false;

    static_cast<server_instance*>(parent)->send_to_client(client_fd, msg);
    return true;
}

bool server_instance::owner_broadcast(std::string_view msg)
{
    auto owner_name = get_owner();
    if (owner_name.empty()) return false;

    auto* mgr = get_runtime_manager();
    if (!mgr) return false;

    auto* parent = mgr->get(owner_name);
    if (!parent || parent->get_type() != runtime_server ||
        parent->get_state() != runtime_running) return false;

    static_cast<server_instance*>(parent)->lua_broadcast(msg);
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

std::vector<int> server_instance::lua_clients() const
{
    return m_active_fds;
}

void server_instance::lua_multicast(const std::vector<int>& fds, std::string_view msg)
{
    if (!m_loop || m_udp) return;
    auto shared = std::make_shared<const std::string>(msg);
    for (int fd : fds)
    {
        if (fd < 0 || fd >= MAX_FDS) continue;
        auto* conn = m_conn_idx[fd];
        if (!conn || conn->closing) continue;
        send_to(conn, shared);
    }
}

// ─── Lua per-connection metadata ───

void server_instance::lua_set_data(int fd, std::string_view key, std::string_view val)
{
    if (fd < 0 || fd >= MAX_FDS || !m_conn_idx[fd]) return;
    m_conn_idx[fd]->meta[std::string(key)] = std::string(val);
}

void server_instance::lua_del_data(int fd, std::string_view key)
{
    if (fd < 0 || fd >= MAX_FDS || !m_conn_idx[fd]) return;
    m_conn_idx[fd]->meta.erase(std::string(key));
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

void server_instance::lua_join_group(int fd, std::string_view group)
{
    if (fd < 0 || fd >= MAX_FDS || !m_conn_idx[fd]) return;
    auto* conn = m_conn_idx[fd];
    std::string gname(group);

    // Check if already in group
    for (const auto& g : conn->groups)
        if (g == gname) return;

    conn->groups.push_back(gname);
    m_groups[gname].push_back(fd);
}

void server_instance::lua_leave_group(int fd, std::string_view group)
{
    if (fd < 0 || fd >= MAX_FDS || !m_conn_idx[fd]) return;
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
}

void server_instance::lua_group_send(std::string_view group, std::string_view msg)
{
    if (!m_loop) return;
    auto it = m_groups.find(std::string(group));
    if (it == m_groups.end()) return;

    // Build newline-terminated message (single allocation, shared across all recipients)
    std::string buf;
    buf.reserve(msg.size() + 1);
    buf.append(msg);
    if (buf.empty() || buf.back() != '\n')
        buf.push_back('\n');
    auto shared_msg = std::make_shared<const std::string>(std::move(buf));

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
    }
}

void server_instance::lua_pipe(int fd_a, int fd_b)
{
    if (!m_loop || fd_a == fd_b) return;
    auto* a = (fd_a >= 0 && fd_a < MAX_FDS) ? m_conn_idx[fd_a] : nullptr;
    auto* b = (fd_b >= 0 && fd_b < MAX_FDS) ? m_conn_idx[fd_b] : nullptr;
    if (!a || !b || a->closing || b->closing) return;

    // Unpipe any existing pairings first
    if (a->pipe_peer_fd >= 0) lua_unpipe(fd_a);
    if (b->pipe_peer_fd >= 0) lua_unpipe(fd_b);

    a->pipe_peer_fd = fd_b;
    b->pipe_peer_fd = fd_a;
}

void server_instance::lua_unpipe(int fd)
{
    auto* conn = (fd >= 0 && fd < MAX_FDS) ? m_conn_idx[fd] : nullptr;
    if (!conn || conn->pipe_peer_fd < 0) return;

    int peer_fd = conn->pipe_peer_fd;
    conn->pipe_peer_fd = -1;

    auto* peer = (peer_fd >= 0 && peer_fd < MAX_FDS) ? m_conn_idx[peer_fd] : nullptr;
    if (peer && peer->pipe_peer_fd == fd)
        peer->pipe_peer_fd = -1;
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

    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0)
        return false;

    int opt = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    if (connect(fd, reinterpret_cast<const struct sockaddr*>(&uc->cached_addr),
                sizeof(uc->cached_addr)) < 0 && errno != EINPROGRESS)
    {
        close(fd);
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
        close(uc->fd);
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

void server_instance::lua_upstream_send(int conn_id, std::string_view msg)
{
    auto it = m_upstreams.find(conn_id);
    if (it == m_upstreams.end() || !it->second->connected)
        return;

    std::string buf;
    buf.reserve(msg.size() + 1);
    buf.append(msg);
    if (buf.empty() || buf.back() != '\n')
        buf.push_back('\n');
    auto shared = std::make_shared<const std::string>(std::move(buf));
    upstream_send(it->second.get(), std::move(shared));
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
    try {
        lctx->on_upstream()(conn_id, data);
    } catch (const sol::error& e) {
        fprintf(stderr, "[lua] on_upstream error: %s\n", e.what());
    }
#endif
}

void server_instance::invoke_on_upstream_connect([[maybe_unused]] int conn_id)
{
#ifndef SOCKETLEY_NO_LUA
    auto* lctx = lua();
    if (!lctx || !lctx->has_on_upstream_connect()) return;
    try {
        lctx->on_upstream_connect()(conn_id);
    } catch (const sol::error& e) {
        fprintf(stderr, "[lua] on_upstream_connect error: %s\n", e.what());
    }
#endif
}

void server_instance::invoke_on_upstream_disconnect([[maybe_unused]] int conn_id)
{
#ifndef SOCKETLEY_NO_LUA
    auto* lctx = lua();
    if (!lctx || !lctx->has_on_upstream_disconnect()) return;
    try {
        lctx->on_upstream_disconnect()(conn_id);
    } catch (const sol::error& e) {
        fprintf(stderr, "[lua] on_upstream_disconnect error: %s\n", e.what());
    }
#endif
}
