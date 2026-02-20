#include "proxy_instance.h"
#include "../../shared/event_loop.h"
#include "../../shared/runtime_manager.h"
#include "../../shared/lua_context.h"

#include <unistd.h>
#include <cstring>
#include <charconv>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <algorithm>
#include <liburing.h>
#include <sstream>

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

size_t proxy_instance::get_connection_count() const
{
    return m_clients.size();
}

bool proxy_instance::resolve_backend(backend_info& b)
{
    auto colon = b.address.find(':');
    if (colon != std::string::npos)
    {
        b.resolved_host = b.address.substr(0, colon);
        auto port_str = b.address.data() + colon + 1;
        auto port_end = b.address.data() + b.address.size();
        std::from_chars(port_str, port_end, b.resolved_port);
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
    return true;
}

bool proxy_instance::setup(event_loop& loop)
{
    m_loop = &loop;

    for (auto& b : m_backends)
    {
        if (!resolve_backend(b))
            return false;
    }

    if (m_backends.empty())
        return false;

    m_use_provided_bufs = loop.setup_buf_ring(BUF_GROUP_ID, BUF_COUNT, BUF_SIZE);

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

    return true;
}

void proxy_instance::teardown(event_loop& loop)
{
    // Close listener first
    if (m_listen_fd >= 0)
    {
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
                if (::write(fd, msg->data(), msg->size()) < 0) break;
                conn->write_queue.pop();
            }
        }
    }

    for (auto& [fd, conn] : m_backend_conns)
        close(fd);
    m_backend_conns.clear();

    for (auto& [fd, conn] : m_clients)
    {
        if (conn->backend_fd >= 0)
            close(conn->backend_fd);
        close(fd);
    }
    m_clients.clear();

    m_loop = nullptr;
    m_multishot_active = false;
}

void proxy_instance::on_cqe(struct io_uring_cqe* cqe)
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
        case op_read:
        case op_read_provided:
        {
            if (m_clients.count(req->fd))
                handle_client_read(cqe, req);
            else if (m_backend_conns.count(req->fd))
                handle_backend_read(cqe, req);
            break;
        }
        case op_write:
        case op_writev:
        {
            if (m_clients.count(req->fd))
                handle_client_write(cqe, req);
            else if (m_backend_conns.count(req->fd))
                handle_backend_write(cqe, req);
            break;
        }
        default:
            break;
    }
}

void proxy_instance::handle_accept(struct io_uring_cqe* cqe)
{
    int client_fd = cqe->res;

    if (client_fd >= 0)
    {
        if (get_max_connections() > 0 && m_clients.size() >= get_max_connections())
        {
            close(client_fd);
            goto proxy_resubmit_accept;
        }

        int opt = 1;
        setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

        m_stat_total_connections.fetch_add(1, std::memory_order_relaxed);

        auto conn = std::make_unique<proxy_client_connection>();
        conn->fd = client_fd;
        conn->partial.reserve(8192);
        conn->read_req = { op_read, client_fd, conn->read_buf, sizeof(conn->read_buf), this };
        conn->write_req = { op_write, client_fd, nullptr, 0, this };

        auto* ptr = conn.get();
        m_clients[client_fd] = std::move(conn);

        ptr->read_pending = true;
        if (m_use_provided_bufs)
            m_loop->submit_read_provided(client_fd, BUF_GROUP_ID, &ptr->read_req);
        else
            m_loop->submit_read(client_fd, ptr->read_buf, sizeof(ptr->read_buf), &ptr->read_req);
    }

proxy_resubmit_accept:
    if (m_multishot_active)
    {
        if (!(cqe->flags & IORING_CQE_F_MORE))
        {
            if (m_listen_fd >= 0)
                m_loop->submit_multishot_accept(m_listen_fd, &m_accept_req);
        }
    }
    else
    {
        if (m_listen_fd >= 0)
        {
            m_accept_addrlen = sizeof(m_accept_addr);
            m_loop->submit_accept(m_listen_fd, &m_accept_addr, &m_accept_addrlen, &m_accept_req);
        }
    }
}

void proxy_instance::handle_client_read(struct io_uring_cqe* cqe, io_request* req)
{
    int fd = req->fd;
    auto it = m_clients.find(fd);
    if (it == m_clients.end())
        return;

    auto* conn = it->second.get();
    conn->read_pending = false;

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
        if (!read_data)
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
        if (conn->backend_fd < 0)
        {
            size_t idx = select_backend(conn);
            if (!connect_to_backend(conn, idx))
            {
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

        if (!conn->closing)
        {
            conn->read_pending = true;
            if (m_use_provided_bufs)
                m_loop->submit_read_provided(fd, BUF_GROUP_ID, &conn->read_req);
            else
                m_loop->submit_read(fd, conn->read_buf, sizeof(conn->read_buf), &conn->read_req);
        }
        return;
    }

    // HTTP mode
    conn->partial.append(read_data, cqe->res);
    if (is_provided)
        m_loop->return_buf(BUF_GROUP_ID, buf_id);

    if (!conn->header_parsed)
    {
        if (!parse_http_request_line(conn))
        {
            // Need more data
            conn->read_pending = true;
            if (m_use_provided_bufs)
                m_loop->submit_read_provided(fd, BUF_GROUP_ID, &conn->read_req);
            else
                m_loop->submit_read(fd, conn->read_buf, sizeof(conn->read_buf), &conn->read_req);
            return;
        }

        conn->header_parsed = true;

        // Check path prefix
        std::string prefix = "/" + std::string(get_name()) + "/";
        if (!conn->path.starts_with(prefix) && conn->path != "/" + std::string(get_name()))
        {
            send_error(conn, "404 Not Found", "Not Found\n");
            return;
        }

        // Strip prefix
        std::string new_path;
        if (conn->path == "/" + std::string(get_name()))
            new_path = "/";
        else
            new_path = conn->path.substr(prefix.size() - 1); // Keep leading /

        // Select and connect to backend
        size_t idx = select_backend(conn);
        if (!connect_to_backend(conn, idx))
        {
            send_error(conn, "502 Bad Gateway", "Bad Gateway\n");
            return;
        }

        // Rewrite request and forward
        std::string rewritten = rewrite_http_request(conn, new_path);
        forward_to_backend(conn, rewritten);
    }
    else
    {
        // Subsequent data (request body) — forward as-is
        forward_to_backend(conn, conn->partial);
        conn->partial.clear();
    }

    if (!conn->closing)
    {
        conn->read_pending = true;
        if (m_use_provided_bufs)
            m_loop->submit_read_provided(fd, BUF_GROUP_ID, &conn->read_req);
        else
            m_loop->submit_read(fd, conn->read_buf, sizeof(conn->read_buf), &conn->read_req);
    }
}

void proxy_instance::handle_backend_read(struct io_uring_cqe* cqe, io_request* req)
{
    int fd = req->fd;
    auto it = m_backend_conns.find(fd);
    if (it == m_backend_conns.end())
        return;

    auto* conn = it->second.get();
    conn->read_pending = false;

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

        close_pair(conn->client_fd, fd);
        return;
    }

    if (is_provided)
    {
        uint16_t buf_id = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
        char* buf_ptr = m_loop->get_buf_ptr(BUF_GROUP_ID, buf_id);
        if (buf_ptr)
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

    if (!conn->closing)
    {
        conn->read_pending = true;
        if (m_use_provided_bufs)
            m_loop->submit_read_provided(fd, BUF_GROUP_ID, &conn->read_req);
        else
            m_loop->submit_read(fd, conn->read_buf, sizeof(conn->read_buf), &conn->read_req);
    }
}

bool proxy_instance::parse_http_request_line(proxy_client_connection* conn)
{
    auto pos = conn->partial.find("\r\n");
    if (pos == std::string::npos)
        return false;

    std::string line = conn->partial.substr(0, pos);

    // Parse: METHOD SP PATH SP VERSION
    auto sp1 = line.find(' ');
    if (sp1 == std::string::npos)
        return false;

    auto sp2 = line.find(' ', sp1 + 1);
    if (sp2 == std::string::npos)
        return false;

    conn->method = line.substr(0, sp1);
    conn->path = line.substr(sp1 + 1, sp2 - sp1 - 1);
    conn->version = line.substr(sp2 + 1);

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
    result += conn->partial.substr(pos); // includes \r\n and rest of headers+body
    conn->partial.clear();
    return result;
}

size_t proxy_instance::select_backend(proxy_client_connection* conn)
{
    if (m_backends.size() == 1)
        return 0;

    if (m_strategy == strategy_lua && lua() && lua()->has_on_route())
    {
        sol::object result;
        if (m_protocol == protocol_http)
            result = lua()->on_route()(conn->method, conn->path);
        else
            result = lua()->on_route()();

        if (result.is<int>())
        {
            int idx = result.as<int>();
            if (idx >= 0 && static_cast<size_t>(idx) < m_backends.size())
                return static_cast<size_t>(idx);
        }
        // Fallback to round-robin
    }

    if (m_strategy == strategy_random)
    {
        std::uniform_int_distribution<size_t> dist(0, m_backends.size() - 1);
        return dist(m_rng);
    }

    // round-robin (default, also fallback for lua)
    size_t idx = m_rr_index % m_backends.size();
    ++m_rr_index;
    return idx;
}

bool proxy_instance::connect_to_backend(proxy_client_connection* conn, size_t idx)
{
    if (idx >= m_backends.size())
        return false;

    auto& backend = m_backends[idx];

    int bfd = socket(AF_INET, SOCK_STREAM, 0);
    if (bfd < 0)
        return false;

    int opt = 1;
    setsockopt(bfd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(backend.resolved_port);

    if (inet_pton(AF_INET, backend.resolved_host.c_str(), &addr.sin_addr) <= 0)
    {
        close(bfd);
        return false;
    }

    if (::connect(bfd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
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

    auto* ptr = bconn.get();
    m_backend_conns[bfd] = std::move(bconn);

    ptr->read_pending = true;
    if (m_use_provided_bufs)
        m_loop->submit_read_provided(bfd, BUF_GROUP_ID, &ptr->read_req);
    else
        m_loop->submit_read(bfd, ptr->read_buf, sizeof(ptr->read_buf), &ptr->read_req);

    return true;
}

void proxy_instance::close_pair(int client_fd, int backend_fd)
{
    if (backend_fd >= 0)
    {
        auto bit = m_backend_conns.find(backend_fd);
        if (bit != m_backend_conns.end())
        {
            auto* bconn = bit->second.get();
            if (bconn->read_pending || bconn->write_pending)
            {
                bconn->closing = true;
            }
            else
            {
                close(backend_fd);
                m_backend_conns.erase(bit);
            }
        }
        else
        {
            close(backend_fd);
        }
    }

    if (client_fd >= 0)
    {
        auto it = m_clients.find(client_fd);
        if (it != m_clients.end())
        {
            auto* conn = it->second.get();

            // Also close the other side of the pair
            if (conn->backend_fd >= 0 && conn->backend_fd != backend_fd)
            {
                auto bit2 = m_backend_conns.find(conn->backend_fd);
                if (bit2 != m_backend_conns.end())
                {
                    auto* bconn2 = bit2->second.get();
                    if (bconn2->read_pending || bconn2->write_pending)
                    {
                        bconn2->closing = true;
                    }
                    else
                    {
                        close(conn->backend_fd);
                        m_backend_conns.erase(bit2);
                    }
                }
                else
                {
                    close(conn->backend_fd);
                }
            }

            if (conn->read_pending || conn->write_pending)
            {
                conn->closing = true;
            }
            else
            {
                close(client_fd);
                m_clients.erase(it);
            }
        }
        else
        {
            close(client_fd);
        }
    }
}

std::string proxy_instance::get_stats() const
{
    std::string base = runtime_instance::get_stats();
    std::ostringstream out;
    out << base
        << "backend_connections:" << m_backend_conns.size() << "\n"
        << "protocol:" << (m_protocol == protocol_http ? "http" : "tcp") << "\n"
        << "backends:" << m_backends.size() << "\n";
    return out.str();
}

void proxy_instance::forward_to_backend(proxy_client_connection* conn, std::string_view data)
{
    if (conn->backend_fd < 0 || !m_loop)
        return;

    auto it = m_backend_conns.find(conn->backend_fd);
    if (it == m_backend_conns.end())
        return;

    auto* bconn = it->second.get();
    if (bconn->closing)
        return;

    auto msg = std::make_shared<const std::string>(data);
    bconn->write_queue.push(msg);

    if (!bconn->write_pending)
        flush_backend_write_queue(bconn);
}

void proxy_instance::forward_to_client(proxy_backend_connection* conn, std::string_view data)
{
    if (!m_loop)
        return;

    auto it = m_clients.find(conn->client_fd);
    if (it == m_clients.end())
        return;

    auto* cconn = it->second.get();
    if (cconn->closing)
        return;

    auto msg = std::make_shared<const std::string>(data);
    cconn->write_queue.push(msg);

    if (!cconn->write_pending)
        flush_client_write_queue(cconn);
}

void proxy_instance::send_error(proxy_client_connection* conn, std::string_view status, std::string_view body)
{
    if (!m_loop || conn->closing)
        return;

    std::string response;
    response.reserve(9 + status.size() + 18 + 8 + 23 + body.size());
    response += "HTTP/1.1 ";
    response += status;
    response += "\r\nContent-Length: ";
    response += std::to_string(body.size());
    response += "\r\nConnection: close\r\n\r\n";
    response += body;

    auto msg = std::make_shared<const std::string>(std::move(response));
    conn->write_queue.push(msg);
    conn->closing = true;

    if (!conn->write_pending)
        flush_client_write_queue(conn);
}

void proxy_instance::flush_client_write_queue(proxy_client_connection* conn)
{
    if (!m_loop || conn->write_queue.empty())
        return;

    uint32_t count = 0;
    while (!conn->write_queue.empty() && count < proxy_client_connection::MAX_WRITE_BATCH)
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

void proxy_instance::flush_backend_write_queue(proxy_backend_connection* conn)
{
    if (!m_loop || conn->write_queue.empty())
        return;

    uint32_t count = 0;
    while (!conn->write_queue.empty() && count < proxy_backend_connection::MAX_WRITE_BATCH)
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

void proxy_instance::handle_client_write(struct io_uring_cqe* cqe, io_request* req)
{
    int fd = req->fd;
    auto it = m_clients.find(fd);
    if (it == m_clients.end())
        return;

    auto* conn = it->second.get();
    conn->write_pending = false;

    // Release batch references
    for (uint32_t i = 0; i < conn->write_batch_count; i++)
        conn->write_batch[i].reset();
    conn->write_batch_count = 0;

    if (cqe->res <= 0)
    {
        close_pair(fd, conn->backend_fd);
        return;
    }

    if (!conn->write_queue.empty())
    {
        flush_client_write_queue(conn);
    }
    else if (conn->closing && !conn->read_pending)
    {
        close_pair(fd, conn->backend_fd);
    }
}

void proxy_instance::handle_backend_write(struct io_uring_cqe* cqe, io_request* req)
{
    int fd = req->fd;
    auto it = m_backend_conns.find(fd);
    if (it == m_backend_conns.end())
        return;

    auto* conn = it->second.get();
    conn->write_pending = false;

    // Release batch references
    for (uint32_t i = 0; i < conn->write_batch_count; i++)
        conn->write_batch[i].reset();
    conn->write_batch_count = 0;

    if (cqe->res <= 0)
    {
        close_pair(conn->client_fd, fd);
        return;
    }

    if (!conn->write_queue.empty())
    {
        flush_backend_write_queue(conn);
    }
    else if (conn->closing && !conn->read_pending)
    {
        close_pair(conn->client_fd, fd);
    }
}
