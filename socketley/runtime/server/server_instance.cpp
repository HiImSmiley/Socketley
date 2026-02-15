#include "server_instance.h"
#include "../../shared/event_loop.h"
#include "../../shared/runtime_manager.h"
#include "../../shared/lua_context.h"
#include "../../shared/ws_protocol.h"
#include "../../cli/command_hashing.h"
#include "../cache/cache_instance.h"

#include <unistd.h>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <liburing.h>
#include <sstream>

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

void server_instance::set_runtime_manager(runtime_manager* mgr)
{
    m_runtime_manager = mgr;
}

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

size_t server_instance::get_connection_count() const
{
    if (m_udp)
        return m_udp_peers.size();
    return m_clients.size();
}

bool server_instance::setup(event_loop& loop)
{
    m_loop = &loop;

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

    // Close listener first to stop new connections
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
        close(fd);
    }

    m_clients.clear();
    m_loop = nullptr;
    m_multishot_active = false;
    m_master_fd = -1;
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
            if (req->fd < 0 || req->fd >= MAX_FDS || !m_conn_idx[req->fd])
                return;
            if (req->type == op_read || req->type == op_read_provided)
                handle_read(cqe, req);
            else
                handle_write(cqe, req);
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

        invoke_on_connect(client_fd);

        ptr->read_pending = true;
        if (m_use_provided_bufs)
            m_loop->submit_read_provided(client_fd, BUF_GROUP_ID, &ptr->read_req);
        else
            m_loop->submit_read(client_fd, ptr->read_buf, sizeof(ptr->read_buf), &ptr->read_req);
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
            invoke_on_disconnect(fd);
            m_conn_idx[fd] = nullptr;
            close(fd);
            m_clients.erase(fd);
        }
        return;
    }

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
            goto submit_next_read; // Incomplete headers

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
                    }
                }

                line_start = line_end + 2;
            }

            if (!has_upgrade || ws_key_pos == std::string_view::npos)
            {
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
                conn->partial = conn->partial.substr(scan_from);
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
}

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
    // Rate limit check
    if (sender && !check_rate_limit(sender))
        return;

    m_stat_total_messages.fetch_add(1, std::memory_order_relaxed);
    print_bash_message(msg);
    notify_interactive(msg);

    // Cache command interception: "cache <cmd>" → execute against linked cache, respond to sender only
    if (sender && msg.size() > 6 && msg.starts_with("cache "))
    {
        auto cname = get_cache_name();
        if (!cname.empty() && m_runtime_manager)
        {
            auto* cache_rt = m_runtime_manager->get(cname);
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
    if (!cache_name.empty() && m_runtime_manager)
    {
        auto* cache_rt = m_runtime_manager->get(cache_name);
        if (cache_rt && cache_rt->get_type() == runtime_cache &&
            cache_rt->get_state() == runtime_running)
        {
            auto* cache = static_cast<cache_instance*>(cache_rt);
            std::string key = std::to_string(++m_message_counter);
            cache->store_direct(key, msg);
        }
    }

    switch (m_mode)
    {
        case mode_inout:
        {
            invoke_on_message(msg);

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
                std::string_view pw = msg.substr(7);
                bool auth_ok = false;

                // Try Lua on_master_auth callback first
                auto* lctx = lua();
                if (lctx && lctx->has_on_master_auth())
                {
                    try {
                        sol::protected_function_result result =
                            lctx->on_master_auth()(sender->fd, std::string(pw));
                        if (result.valid())
                            auth_ok = result.get<bool>();
                    } catch (...) {}
                }
                else if (!m_master_pw.empty())
                {
                    // Static password check
                    auth_ok = (pw == m_master_pw);
                }

                if (auth_ok)
                {
                    m_master_fd = sender->fd;
                    auto ok_msg = std::make_shared<const std::string>("master: ok\n");
                    send_to(sender, ok_msg);
                }
                else
                {
                    auto deny_msg = std::make_shared<const std::string>("master: denied\n");
                    send_to(sender, deny_msg);
                }
                break;
            }

            // If sender is master: broadcast to all except sender
            if (sender && sender->fd == m_master_fd)
            {
                invoke_on_message(msg);

                std::string relay_str;
                relay_str.reserve(msg.size() + 1);
                relay_str.append(msg.data(), msg.size());
                relay_str += '\n';
                auto relay_msg = std::make_shared<const std::string>(std::move(relay_str));
                broadcast(relay_msg, sender->fd);
                break;
            }

            // Non-master: forward to master if master_forward is set
            if (sender && m_master_forward && m_master_fd >= 0 &&
                m_master_fd < MAX_FDS && m_conn_idx[m_master_fd])
            {
                std::string fwd_str;
                fwd_str.reserve(msg.size() + 16);
                fwd_str += '[';
                fwd_str += std::to_string(sender->fd);
                fwd_str += "] ";
                fwd_str.append(msg.data(), msg.size());
                fwd_str += '\n';
                auto fwd_msg = std::make_shared<const std::string>(std::move(fwd_str));
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

    // Register peer if new
    find_or_add_peer(m_udp_recv_addr);

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

void server_instance::lua_send_to(int client_id, std::string_view msg)
{
    if (!m_loop || m_udp)
        return;

    if (client_id < 0 || client_id >= MAX_FDS || !m_conn_idx[client_id])
        return;

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
    return out.str();
}

int server_instance::find_or_add_peer(const struct sockaddr_in& addr)
{
    for (size_t i = 0; i < m_udp_peers.size(); i++)
    {
        if (m_udp_peers[i].addr.sin_addr.s_addr == addr.sin_addr.s_addr &&
            m_udp_peers[i].addr.sin_port == addr.sin_port)
            return static_cast<int>(i);
    }

    m_udp_peers.push_back({addr});
    return static_cast<int>(m_udp_peers.size() - 1);
}
