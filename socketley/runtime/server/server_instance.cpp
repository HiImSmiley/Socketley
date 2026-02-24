#include "server_instance.h"
#include "../../shared/event_loop.h"
#include "../../shared/runtime_manager.h"
#include "../../shared/lua_context.h"
#include "../../shared/ws_protocol.h"
#include "../../cli/command_hashing.h"
#include "../cache/cache_instance.h"

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

server_instance::server_instance(std::string_view name)
    : runtime_instance(runtime_server, name), m_mode(mode_inout), m_listen_fd(-1), m_loop(nullptr)
{
    std::memset(&m_accept_addr, 0, sizeof(m_accept_addr));
    m_accept_addrlen = sizeof(m_accept_addr);
    m_accept_req = { op_accept, -1, nullptr, 0, this };
}

server_instance::~server_instance()
{
    if (m_listen_fd >= 0)
        close(m_listen_fd);
    if (m_udp_fd >= 0)
        close(m_udp_fd);
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

static std::string build_http_response(std::string_view content_type, std::string_view body)
{
    std::string resp;
    resp.reserve(128 + body.size());
    resp.append("HTTP/1.1 200 OK\r\nContent-Type: ");
    resp.append(content_type);
    resp.append("\r\nContent-Length: ");
    char len_buf[24];
    auto [len_end, len_ec] = std::to_chars(len_buf, len_buf + sizeof(len_buf), body.size());
    resp.append(len_buf, len_end - len_buf);
    resp.append("\r\nConnection: close\r\n\r\n");
    resp.append(body);
    return resp;
}

static const std::shared_ptr<const std::string>& http_404_response()
{
    static const auto resp = std::make_shared<const std::string>(
        "HTTP/1.1 404 Not Found\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 13\r\n"
        "Connection: close\r\n\r\n"
        "404 Not Found");
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
        m_http_cache[url_path] = {
            std::make_shared<const std::string>(build_http_response(ct, content))
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
        conn->write_queue.push(http_404_response());
        if (!conn->write_pending)
            flush_write_queue(conn);
        conn->closing = true;
        return;
    }

    // Strip query string
    auto qpos = url_path.find('?');
    if (qpos != std::string::npos)
        url_path.erase(qpos);

    if (m_http_cache_enabled && !m_http_cache.empty())
    {
        // Cached mode: zero-copy lookup — just bump shared_ptr refcount
        auto it = m_http_cache.find(url_path);
        conn->write_queue.push(it != m_http_cache.end()
            ? it->second.response : http_404_response());
    }
    else
    {
        // Disk mode: read file on each request
        namespace fs = std::filesystem;
        std::error_code ec;

        // Resolve base once if not yet done (dev mode, no rebuild_http_cache call)
        if (m_http_base.empty())
        {
            m_http_base = fs::canonical(m_http_dir, ec);
            if (ec)
            {
                conn->write_queue.push(http_404_response());
                if (!conn->write_pending)
                    flush_write_queue(conn);
                conn->closing = true;
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
            conn->write_queue.push(http_404_response());
            if (!conn->write_pending)
                flush_write_queue(conn);
            conn->closing = true;
            return;
        }

        std::ifstream f(resolved, std::ios::binary);
        if (!f.is_open())
        {
            conn->write_queue.push(http_404_response());
        }
        else
        {
            std::string content((std::istreambuf_iterator<char>(f)),
                                 std::istreambuf_iterator<char>());
            std::string ext = resolved.extension().string();
            for (auto& c : ext)
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            uint32_t ext_hash = fnv1a(ext);
            auto ct = http_content_type(ext);

            if (ext_hash == fnv1a(".html") || ext_hash == fnv1a(".htm"))
                content = inject_ws_script(content);

            conn->write_queue.push(
                std::make_shared<const std::string>(build_http_response(ct, content)));
        }
    }

    if (!conn->write_pending)
        flush_write_queue(conn);
    conn->closing = true;
}

size_t server_instance::get_connection_count() const
{
    if (m_udp)
        return m_udp_peers.size();
    size_t upstream_connected = 0;
    for (const auto& [_, uc] : m_upstreams)
        if (uc->connected) ++upstream_connected;
    return m_clients.size() + m_forwarded_clients.size() + upstream_connected;
}

bool server_instance::setup(event_loop& loop)
{
    // Clear any connections left over from a previous stop() — their fds are
    // already closed, but we deferred freeing them so that in-flight io_uring
    // CQEs could reference their io_request members safely.  Now that setup()
    // is starting a fresh run it is safe to destroy them.
    m_clients.clear();

    m_loop = &loop;

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

        m_udp_recv_req = { op_recvmsg, m_udp_fd, nullptr, 0, this };
        loop.submit_recvmsg(m_udp_fd, &m_udp_recv_msg, &m_udp_recv_req);

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

    // Use multishot accept if supported (kernel 5.19+)
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

    // Build HTTP file cache if enabled
    if (m_http_cache_enabled && !m_http_dir.empty())
        rebuild_http_cache();

    if (get_idle_timeout() > 0)
    {
        m_idle_sweep_ts.tv_sec = 30;
        m_idle_sweep_ts.tv_nsec = 0;
        m_idle_sweep_req = { op_timeout, -1, nullptr, 0, this };
        m_loop->submit_timeout(&m_idle_sweep_ts, &m_idle_sweep_req);
    }

    // Connect to upstreams
    // Clear stale upstream connections from a previous stop (deferred for CQE safety)
    m_upstreams.clear();
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
            close(m_udp_fd);
            m_udp_fd = -1;
        }
        m_udp_peers.clear();
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
                auto& msg = conn->write_queue.front();
                if (::write(fd, msg->data(), msg->size()) < 0) break;
                conn->write_queue.pop();
            }
        }
    }

    for (auto& [fd, conn] : m_clients)
    {
        if (fd >= 0 && fd < MAX_FDS)
            m_conn_idx[fd] = nullptr;

        // Shutdown the connection before closing it.  Like for the listen fd,
        // shutdown() completes any pending io_uring read/write ops synchronously
        // (the kernel wakes up the socket wait queue, completing the ops and
        // placing their CQEs in the ring before we return from shutdown()).
        // This avoids the cancel-SQE fd-closed race described above.
        shutdown(fd, SHUT_RDWR);
        close(fd);

        // Release shared_ptr message refs now so memory is freed promptly, but
        // keep the server_connection structs alive — their embedded io_request
        // members are still referenced by in-flight CQEs until the cancellations
        // complete and the deferred-delete timeout fires.
        while (!conn->write_queue.empty())
            conn->write_queue.pop();
        for (size_t i = 0; i < conn->write_batch_count; i++)
            conn->write_batch[i].reset();
        conn->write_batch_count = 0;
    }

    // Tear down upstream connections
    for (auto& [cid, uc] : m_upstreams)
    {
        // Null timeout owner to prevent stale CQE dispatch
        uc->timeout_req.owner = nullptr;

        if (uc->fd >= 0)
        {
            m_upstream_by_fd.erase(uc->fd);
            shutdown(uc->fd, SHUT_RDWR);
            close(uc->fd);
            uc->fd = -1;
        }
        uc->connected = false;
        // Release write queue refs
        while (!uc->write_queue.empty())
            uc->write_queue.pop();
        for (size_t j = 0; j < uc->write_batch_count; j++)
            uc->write_batch[j].reset();
        uc->write_batch_count = 0;
    }
    // Do NOT clear m_upstreams here — keep structs alive for pending CQEs.
    // They are freed in the next setup() call.

    // Do NOT call m_clients.clear() here.  The server_connection objects must
    // stay alive until the server_instance itself is destroyed (see setup() for
    // when they are freed on a restart, or the destructor for the remove case).
    m_idle_sweep_req.owner = nullptr;
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
    if (!req || !m_loop)
        return;

    switch (req->type)
    {
        case op_accept:
        case op_multishot_accept:
            handle_accept(cqe);
            break;
        case op_recvmsg:
            handle_udp_read(cqe);
            break;
        case op_read:
        case op_read_provided:
        case op_write:
        case op_writev:
        {
            if (req->fd >= 0 && req->fd < MAX_FDS && m_conn_idx[req->fd])
            {
                // Client connection (fast path)
                if (req->type == op_read || req->type == op_read_provided)
                    handle_read(cqe, req);
                else
                    handle_write(cqe, req);
            }
            else
            {
                // Check upstream connections
                auto uit = m_upstream_by_fd.find(req->fd);
                if (uit != m_upstream_by_fd.end())
                {
                    if (req->type == op_read || req->type == op_read_provided)
                        handle_upstream_read(cqe, uit->second);
                    else
                        handle_upstream_write(cqe, uit->second);
                }
            }
            break;
        }
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
            else
            {
                // Upstream reconnect timers
                for (auto& [cid, uc] : m_upstreams)
                {
                    if (req == &uc->timeout_req)
                    {
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
}

void server_instance::handle_accept(struct io_uring_cqe* cqe)
{
    int client_fd = cqe->res;

    if (client_fd >= 0)
    {
        // Reject fds beyond our O(1) lookup table — they'd become zombie connections
        if (client_fd >= MAX_FDS)
        {
            close(client_fd);
            goto resubmit_accept;
        }

        // Max connections check
        if (get_max_connections() > 0 && m_clients.size() >= get_max_connections())
        {
            close(client_fd);
            goto resubmit_accept;
        }

        int opt = 1;
        setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

        auto conn = std::make_unique<server_connection>();
        conn->fd = client_fd;
        conn->partial.reserve(8192);
        conn->read_req = { op_read, client_fd, conn->read_buf, sizeof(conn->read_buf), this };
        conn->write_req = { op_write, client_fd, nullptr, 0, this };

        auto* ptr = conn.get();
        m_clients[client_fd] = std::move(conn);
        if (client_fd < MAX_FDS)
            m_conn_idx[client_fd] = ptr;

        ptr->last_activity = std::chrono::steady_clock::now();

        m_stat_total_connections.fetch_add(1, std::memory_order_relaxed);
        if (m_clients.size() > m_stat_peak_connections)
            m_stat_peak_connections = static_cast<uint32_t>(m_clients.size());

        // Initialize rate limiting
        double rl = get_rate_limit();
        if (rl > 0)
        {
            ptr->rl_max = rl;
            ptr->rl_tokens = rl;
            ptr->rl_last = std::chrono::steady_clock::now();
        }

        // Check per-IP auth failure rate (master mode only)
        if (!m_master_pw.empty())
        {
            uint32_t ip = m_accept_addr.sin_addr.s_addr;
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
                    if (client_fd < MAX_FDS) m_conn_idx[client_fd] = nullptr;
                    m_clients.erase(client_fd);
                    shutdown(client_fd, SHUT_RDWR);
                    close(client_fd);
                    goto resubmit_accept;
                }
            }
        }

        // on_auth fires before on_connect; a rejected client never triggers on_connect
        if (!invoke_on_auth(client_fd))
        {
            if (client_fd < MAX_FDS) m_conn_idx[client_fd] = nullptr;
            m_clients.erase(client_fd);
            shutdown(client_fd, SHUT_RDWR);
            close(client_fd);
            goto resubmit_accept;
        }

        invoke_on_connect(client_fd);

        ptr->read_pending = true;
        if (m_use_provided_bufs)
            m_loop->submit_read_provided(client_fd, BUF_GROUP_ID, &ptr->read_req);
        else
            m_loop->submit_read(client_fd, ptr->read_buf, sizeof(ptr->read_buf), &ptr->read_req);
    }

    // EMFILE/ENFILE: backoff 100ms to avoid CPU spin when fd limit is hit
    if (client_fd == -EMFILE || client_fd == -ENFILE)
    {
        m_accept_backoff_ts.tv_sec = 0;
        m_accept_backoff_ts.tv_nsec = 100000000LL;
        m_accept_backoff_req = { op_timeout, -1, nullptr, 0, this };
        m_loop->submit_timeout(&m_accept_backoff_ts, &m_accept_backoff_req);
        return;
    }

resubmit_accept:
    // Resubmit accept if needed
    if (m_multishot_active)
    {
        // Multishot: only resubmit if IORING_CQE_F_MORE is NOT set
        if (!(cqe->flags & IORING_CQE_F_MORE))
        {
            if (m_listen_fd >= 0)
                m_loop->submit_multishot_accept(m_listen_fd, &m_accept_req);
        }
    }
    else
    {
        // Regular accept: always resubmit
        if (m_listen_fd >= 0)
        {
            m_accept_addrlen = sizeof(m_accept_addr);
            m_loop->submit_accept(m_listen_fd, &m_accept_addr, &m_accept_addrlen, &m_accept_req);
        }
    }
}

void server_instance::handle_read(struct io_uring_cqe* cqe, io_request* req)
{
    int fd = req->fd;
    auto* conn = m_conn_idx[fd];
    if (!conn)
        return;

    conn->read_pending = false;  // Read operation completed

    bool is_provided = (req->type == op_read_provided);

    if (cqe->res <= 0)
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

        // Connection closed or error
        if (fd == m_master_fd)
            m_master_fd = -1;
        if (conn->write_pending)
        {
            conn->closing = true;
        }
        else
        {
            unroute_client(fd);
            invoke_on_disconnect(fd);
            m_conn_idx[fd] = nullptr;
            close(fd);
            m_clients.erase(fd);
        }
        return;
    }

    conn->last_activity = std::chrono::steady_clock::now();
    m_stat_bytes_in.fetch_add(static_cast<uint64_t>(cqe->res), std::memory_order_relaxed);

    if (is_provided)
    {
        // Extract buffer ID from CQE flags
        uint16_t buf_id = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
        char* buf_ptr = m_loop->get_buf_ptr(BUF_GROUP_ID, buf_id);
        if (buf_ptr)
        {
            conn->partial.append(buf_ptr, cqe->res);
            m_loop->return_buf(BUF_GROUP_ID, buf_id);
        }
    }
    else
    {
        conn->partial.append(conn->read_buf, cqe->res);
    }

    if (conn->partial.size() > server_connection::MAX_PARTIAL_SIZE)
    {
        conn->closing = true;
        goto submit_next_read;
    }

    // WebSocket auto-detection
    if (conn->ws == ws_unknown)
    {
        if (conn->partial.size() < 4)
            goto submit_next_read;
        if (conn->partial[0] == 'G' && conn->partial[1] == 'E' &&
            conn->partial[2] == 'T' && conn->partial[3] == ' ')
            conn->ws = ws_upgrading;
        else
            conn->ws = ws_tcp;
    }

    if (conn->ws == ws_upgrading)
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
                if (!m_http_dir.empty())
                {
                    // Extract request path from "GET /path HTTP/1.1"
                    std::string_view req_line(conn->partial.data(),
                        std::min(conn->partial.find("\r\n"), conn->partial.size()));
                    auto sp1 = req_line.find(' ');
                    auto sp2 = (sp1 != std::string_view::npos)
                                ? req_line.find(' ', sp1 + 1) : std::string_view::npos;
                    if (sp1 != std::string_view::npos && sp2 != std::string_view::npos)
                    {
                        std::string_view path = req_line.substr(sp1 + 1, sp2 - sp1 - 1);
                        conn->partial.clear();
                        serve_http(conn, path);
                        goto submit_next_read;
                    }
                }
                conn->ws = ws_tcp;
                conn->partial.clear();
                goto submit_next_read;
            }

            std::string_view ws_key = hdrs.substr(ws_key_pos, ws_key_end - ws_key_pos);

            // Send 101 response
            std::string response = ws_handshake_response(ws_key);
            auto resp_msg = std::make_shared<const std::string>(std::move(response));
            conn->write_queue.push(resp_msg);
            if (!conn->write_pending)
                flush_write_queue(conn);

            conn->ws = ws_active;
            invoke_on_websocket(conn->fd);
            conn->partial.erase(0, hdr_end + 4);
        }
    }

    if (conn->ws == ws_active)
    {
        // Parse WebSocket frames
        ws_frame frame;
        while (ws_parse_frame(conn->partial.data(), conn->partial.size(), frame))
        {
            conn->partial.erase(0, frame.consumed);
            switch (frame.opcode)
            {
                case WS_OP_TEXT:
                    if (!frame.payload.empty())
                        process_message(conn, frame.payload);
                    break;
                case WS_OP_PING:
                {
                    auto pong = std::make_shared<const std::string>(ws_frame_pong(frame.payload));
                    conn->write_queue.push(pong);
                    if (!conn->write_pending)
                        flush_write_queue(conn);
                    break;
                }
                case WS_OP_CLOSE:
                {
                    auto close_frame = std::make_shared<const std::string>(ws_frame_close());
                    conn->write_queue.push(close_frame);
                    if (!conn->write_pending)
                        flush_write_queue(conn);
                    conn->closing = true;
                    break;
                }
                default:
                    break;
            }
        }
        goto submit_next_read;
    }

    // ws_tcp: existing newline-delimited parsing
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
    // Only submit next read if connection is not closing
    if (m_loop && !conn->closing)
    {
        conn->read_pending = true;
        if (m_use_provided_bufs)
            m_loop->submit_read_provided(fd, BUF_GROUP_ID, &conn->read_req);
        else
            m_loop->submit_read(fd, conn->read_buf, sizeof(conn->read_buf), &conn->read_req);
    }
    else if (conn->closing && !conn->write_pending)
    {
        // No write in flight and closing — clean up now.
        // (If write_pending, handle_write will clean up when write completes.)
        unroute_client(fd);
        invoke_on_disconnect(fd);
        if (fd >= 0 && fd < MAX_FDS) m_conn_idx[fd] = nullptr;
        close(fd);
        m_clients.erase(fd);
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

static bool check_rate_limit(server_connection* conn)
{
    if (conn->rl_max <= 0)
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

    // Check if this client is routed to a sub-server
    if (sender)
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
    if (sender && msg.size() > 6 && msg.starts_with("cache "))
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
                std::string relay_str;
                relay_str.reserve(msg.size() + 1);
                relay_str.append(msg.data(), msg.size());
                relay_str += '\n';
                auto relay_msg = std::make_shared<const std::string>(std::move(relay_str));
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
                            lctx->on_master_auth()(sender->fd, std::string(pw));
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
                    std::string relay_str;
                    relay_str.reserve(msg.size() + 1);
                    relay_str.append(msg.data(), msg.size());
                    relay_str += '\n';
                    auto relay_msg = std::make_shared<const std::string>(std::move(relay_str));
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
                auto fwd_msg = std::make_shared<std::string>();
                fwd_msg->reserve(msg.size() + 16);
                fwd_msg->push_back('[');
                fwd_msg->append(fd_buf, fd_end - fd_buf);
                fwd_msg->append("] ", 2);
                fwd_msg->append(msg.data(), msg.size());
                fwd_msg->push_back('\n');
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
    if (!m_loop)
        return;

    invoke_on_send(msg);

    if (m_udp)
    {
        udp_broadcast(msg, nullptr);
        return;
    }

    std::string full_str;
    full_str.reserve(msg.size() + 1);
    full_str.append(msg.data(), msg.size());
    if (full_str.empty() || full_str.back() != '\n')
        full_str += '\n';

    auto full_msg = std::make_shared<const std::string>(std::move(full_str));
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
    if (!m_loop)
        return;

    std::shared_ptr<const std::string> ws_msg; // Lazy WS frame creation

    for (auto& [fd, conn] : m_clients)
    {
        if (fd == exclude_fd || conn->closing)
            continue;

        if (conn->write_queue.size() >= server_connection::MAX_WRITE_QUEUE)
        {
            conn->closing = true;
            continue;
        }

        if (conn->ws == ws_active)
        {
            if (!ws_msg)
            {
                // Strip trailing newline for WS frame (WS messages are not newline-delimited)
                std::string_view payload(*msg);
                if (!payload.empty() && payload.back() == '\n')
                    payload.remove_suffix(1);
                ws_msg = std::make_shared<const std::string>(ws_frame_text(payload));
            }
            conn->write_queue.push(ws_msg);
            if (!conn->write_pending)
                flush_write_queue(conn.get());
        }
        else
        {
            conn->write_queue.push(msg);
            if (!conn->write_pending)
                flush_write_queue(conn.get());
        }
    }
}

void server_instance::send_to(server_connection* conn, const std::shared_ptr<const std::string>& msg)
{
    if (!m_loop || conn->closing)
        return;

    if (conn->write_queue.size() >= server_connection::MAX_WRITE_QUEUE)
    {
        conn->closing = true;
        return;
    }

    if (conn->ws == ws_active)
    {
        // Strip trailing newline for WS frame
        std::string_view payload(*msg);
        if (!payload.empty() && payload.back() == '\n')
            payload.remove_suffix(1);
        auto framed = std::make_shared<const std::string>(ws_frame_text(payload));
        conn->write_queue.push(framed);
    }
    else
    {
        conn->write_queue.push(msg);
    }

    if (!conn->write_pending)
        flush_write_queue(conn);
}

void server_instance::flush_write_queue(server_connection* conn)
{
    if (!m_loop || conn->write_queue.empty())
        return;

    // Coalesce up to MAX_WRITE_BATCH messages into a single writev
    uint32_t count = 0;
    while (!conn->write_queue.empty() && count < server_connection::MAX_WRITE_BATCH)
    {
        conn->write_batch[count] = std::move(conn->write_queue.front());
        conn->write_queue.pop();

        conn->write_iovs[count].iov_base = const_cast<char*>(conn->write_batch[count]->data());
        conn->write_iovs[count].iov_len = conn->write_batch[count]->size();
        count++;
    }

    conn->write_batch_count = count;
    conn->write_pending = true;

    if (count == 1)
    {
        // Single message — use plain write (lower overhead than writev)
        conn->write_req.type = op_write;
        m_loop->submit_write(conn->fd, conn->write_batch[0]->data(),
            static_cast<uint32_t>(conn->write_batch[0]->size()), &conn->write_req);
    }
    else
    {
        conn->write_req.type = op_writev;
        m_loop->submit_writev(conn->fd, conn->write_iovs, count, &conn->write_req);
    }
}

void server_instance::handle_write(struct io_uring_cqe* cqe, io_request* req)
{
    int fd = req->fd;
    auto* conn = m_conn_idx[fd];
    if (!conn)
        return;

    conn->write_pending = false;

    // Release batch references
    for (uint32_t i = 0; i < conn->write_batch_count; i++)
        conn->write_batch[i].reset();
    conn->write_batch_count = 0;

    if (cqe->res <= 0)
    {
        if (fd == m_master_fd)
            m_master_fd = -1;
        conn->closing = true;
        if (!conn->read_pending)
        {
            unroute_client(fd);
            invoke_on_disconnect(fd);
            m_conn_idx[fd] = nullptr;
            close(fd);
            m_clients.erase(fd);
        }
        return;
    }

    m_stat_bytes_out.fetch_add(static_cast<uint64_t>(cqe->res), std::memory_order_relaxed);

    // Check if more messages to send
    if (!conn->write_queue.empty())
    {
        flush_write_queue(conn);
    }
    else
    {
        if (conn->closing && !conn->read_pending)
        {
            if (fd == m_master_fd)
                m_master_fd = -1;
            unroute_client(fd);
            invoke_on_disconnect(fd);
            m_conn_idx[fd] = nullptr;
            close(fd);
            m_clients.erase(fd);
        }
    }
}

void server_instance::handle_udp_read(struct io_uring_cqe* cqe)
{
    if (cqe->res <= 0)
    {
        // Resubmit on error
        if (m_loop && m_udp_fd >= 0)
            m_loop->submit_recvmsg(m_udp_fd, &m_udp_recv_msg, &m_udp_recv_req);
        return;
    }

    // Register peer if new; skip processing if peer list is full
    if (find_or_add_peer(m_udp_recv_addr) < 0)
    {
        m_udp_recv_msg.msg_namelen = sizeof(m_udp_recv_addr);
        if (m_loop && m_udp_fd >= 0)
            m_loop->submit_recvmsg(m_udp_fd, &m_udp_recv_msg, &m_udp_recv_req);
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
    m_udp_recv_msg.msg_namelen = sizeof(m_udp_recv_addr);
    if (m_loop && m_udp_fd >= 0)
        m_loop->submit_recvmsg(m_udp_fd, &m_udp_recv_msg, &m_udp_recv_req);
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
    if (!conn || conn->ws != ws_active) return {};
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

        std::string full_str;
        full_str.reserve(msg.size() + 1);
        full_str.append(msg.data(), msg.size());
        if (full_str.empty() || full_str.back() != '\n')
            full_str += '\n';

        auto full_msg = std::make_shared<const std::string>(std::move(full_str));
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
    sub->m_forwarded_clients[client_fd] = std::string(get_name());
    sub->invoke_on_connect(client_fd);
    return true;
}

bool server_instance::unroute_client(int client_fd)
{
    auto it = m_routes.find(client_fd);
    if (it == m_routes.end()) return false;

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
                                                  std::string_view parent_name)
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
    if (client_fd < 0 || client_fd >= MAX_FDS || !m_conn_idx[client_fd]) return;
    auto* conn = m_conn_idx[client_fd];
    if (conn->closing) return;

    std::string full(msg);
    if (full.empty() || full.back() != '\n') full += '\n';
    auto shared = std::make_shared<const std::string>(std::move(full));
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
    for (size_t i = 0; i < m_udp_peers.size(); i++)
    {
        if (m_udp_peers[i].addr.sin_addr.s_addr == addr.sin_addr.s_addr &&
            m_udp_peers[i].addr.sin_port == addr.sin_port)
            return static_cast<int>(i);
    }

    if (m_udp_peers.size() >= MAX_UDP_PEERS)
        return -1;

    m_udp_peers.push_back({addr});
    return static_cast<int>(m_udp_peers.size() - 1);
}

// ─── Lua client enumeration ───

std::vector<int> server_instance::lua_clients() const
{
    std::vector<int> result;
    result.reserve(m_clients.size());
    for (const auto& [fd, _] : m_clients)
        result.push_back(fd);
    return result;
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

// ─── Upstream Connections ───

bool server_instance::upstream_try_connect(upstream_connection* uc)
{
    if (!m_loop)
        return false;

    const auto& host = uc->target.resolved_host;
    uint16_t port = uc->target.resolved_port;
    if (host.empty() || port == 0)
        return false;

    // DNS resolve
    struct addrinfo hints{}, *addrs = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char port_buf[8];
    auto [pe, pec] = std::to_chars(port_buf, port_buf + sizeof(port_buf), port);
    *pe = '\0';
    if (getaddrinfo(host.c_str(), port_buf, &hints, &addrs) != 0 || !addrs)
        return false;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        freeaddrinfo(addrs);
        return false;
    }

    int opt = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    if (connect(fd, addrs->ai_addr, addrs->ai_addrlen) < 0)
    {
        freeaddrinfo(addrs);
        close(fd);
        return false;
    }
    freeaddrinfo(addrs);

    uc->fd = fd;
    uc->connected = true;
    uc->closing = false;
    uc->reconnect_attempt = 0;
    uc->partial.clear();
    uc->partial.reserve(4096);
    uc->read_pending = false;
    uc->write_pending = false;

    m_upstream_by_fd[fd] = uc;

    uc->read_req = { op_read, fd, uc->read_buf, sizeof(uc->read_buf), this };
    uc->write_req = { op_write, fd, nullptr, 0, this };

    // Submit first read
    uc->read_pending = true;
    m_loop->submit_read(fd, uc->read_buf, sizeof(uc->read_buf), &uc->read_req);

    // Fire on_upstream_connect callback
    invoke_on_upstream_connect(uc->conn_id);

    return true;
}

void server_instance::upstream_schedule_reconnect(upstream_connection* uc)
{
    if (!m_loop)
        return;

    // Exponential backoff: min(1s * 2^attempt, 30s) with jitter
    int base_sec = 1 << std::min(uc->reconnect_attempt, 4); // 1,2,4,8,16
    int delay_sec = std::min(base_sec, 30);
    int jitter_ms = (uc->reconnect_attempt * 137) % 500;

    uc->timeout_ts.tv_sec = delay_sec;
    uc->timeout_ts.tv_nsec = jitter_ms * 1000000LL;
    uc->timeout_req = { op_timeout, -1, nullptr, 0, this };
    m_loop->submit_timeout(&uc->timeout_ts, &uc->timeout_req);
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
    while (!uc->write_queue.empty())
        uc->write_queue.pop();
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
        m_loop->submit_read(uc->fd, uc->read_buf, sizeof(uc->read_buf), &uc->read_req);
    }
    else if (uc->closing && !uc->write_pending)
    {
        upstream_disconnect(uc);
    }
}

void server_instance::handle_upstream_write(struct io_uring_cqe* cqe, upstream_connection* uc)
{
    uc->write_pending = false;

    // Release batch references
    for (uint32_t i = 0; i < uc->write_batch_count; i++)
        uc->write_batch[i].reset();
    uc->write_batch_count = 0;

    if (cqe->res <= 0)
    {
        uc->closing = true;
        if (!uc->read_pending)
            upstream_disconnect(uc);
        return;
    }

    m_stat_bytes_out.fetch_add(static_cast<uint64_t>(cqe->res), std::memory_order_relaxed);

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

    if (uc->write_queue.size() >= upstream_connection::MAX_WRITE_QUEUE)
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
        uc->write_batch[count] = std::move(uc->write_queue.front());
        uc->write_queue.pop();
        uc->write_iovs[count].iov_base = const_cast<char*>(uc->write_batch[count]->data());
        uc->write_iovs[count].iov_len = uc->write_batch[count]->size();
        count++;
    }

    uc->write_batch_count = count;
    uc->write_pending = true;

    if (count == 1)
    {
        uc->write_req.type = op_write;
        m_loop->submit_write(uc->fd, uc->write_batch[0]->data(),
            static_cast<uint32_t>(uc->write_batch[0]->size()), &uc->write_req);
    }
    else
    {
        uc->write_req.type = op_writev;
        m_loop->submit_writev(uc->fd, uc->write_iovs, count, &uc->write_req);
    }
}

// ─── Lua upstream actions ───

void server_instance::lua_upstream_send(int conn_id, std::string_view msg)
{
    auto it = m_upstreams.find(conn_id);
    if (it == m_upstreams.end() || !it->second->connected)
        return;

    std::string full;
    full.reserve(msg.size() + 1);
    full.append(msg.data(), msg.size());
    if (full.empty() || full.back() != '\n')
        full += '\n';
    upstream_send(it->second.get(), std::make_shared<const std::string>(std::move(full)));
}

void server_instance::lua_upstream_broadcast(std::string_view msg)
{
    std::string full;
    full.reserve(msg.size() + 1);
    full.append(msg.data(), msg.size());
    if (full.empty() || full.back() != '\n')
        full += '\n';
    auto shared = std::make_shared<const std::string>(std::move(full));
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

void server_instance::invoke_on_upstream(int conn_id, std::string_view data)
{
#ifndef SOCKETLEY_NO_LUA
    auto* lctx = lua();
    if (!lctx || !lctx->has_on_upstream()) return;
    try {
        lctx->on_upstream()(conn_id, std::string(data));
    } catch (const sol::error& e) {
        fprintf(stderr, "[lua] on_upstream error: %s\n", e.what());
    }
#endif
}

void server_instance::invoke_on_upstream_connect(int conn_id)
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

void server_instance::invoke_on_upstream_disconnect(int conn_id)
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
