#include "client_instance.h"
#include "../../shared/event_loop.h"

#include <unistd.h>
#include <cstring>
#include <charconv>
#include <chrono>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <algorithm>

client_instance::client_instance(std::string_view name)
    : runtime_instance(runtime_client, name), m_mode(client_mode_inout), m_loop(nullptr), m_connected(false)
{
    m_conn.fd = -1;
    std::memset(&m_conn.read_req, 0, sizeof(m_conn.read_req));
    std::memset(&m_conn.write_req, 0, sizeof(m_conn.write_req));
}

client_instance::~client_instance()
{
    if (m_conn.fd >= 0)
    {
        shutdown(m_conn.fd, SHUT_RDWR);
        close(m_conn.fd);
    }
}

void client_instance::set_mode(client_mode mode)
{
    m_mode = mode;
}

client_mode client_instance::get_mode() const
{
    return m_mode;
}

void client_instance::set_udp(bool udp)
{
    m_udp = udp;
}

bool client_instance::is_udp() const
{
    return m_udp;
}

size_t client_instance::get_connection_count() const
{
    return m_connected ? 1 : 0;
}

bool client_instance::try_connect()
{
    std::string host = "127.0.0.1";
    uint16_t port = get_port();
    if (port == 0)
        port = 8000;

    auto target = get_target();
    if (!target.empty())
    {
        auto colon = target.rfind(':');
        if (colon != std::string_view::npos)
        {
            host = std::string(target.substr(0, colon));
            auto port_sv = target.substr(colon + 1);
            uint32_t parsed_port = 0;
            auto [ptr, ec] = std::from_chars(port_sv.data(), port_sv.data() + port_sv.size(), parsed_port);
            if (ec == std::errc{} && parsed_port > 0 && parsed_port <= 65535)
                port = static_cast<uint16_t>(parsed_port);
        }
    }

    m_conn.fd = socket(AF_INET, m_udp ? (SOCK_DGRAM | SOCK_NONBLOCK) : (SOCK_STREAM | SOCK_NONBLOCK), 0);
    if (m_conn.fd < 0)
        return false;

    if (!m_udp)
    {
        int opt = 1;
        setsockopt(m_conn.fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
    }

    // Try cached DNS result first (same host:port)
    if (m_has_cached_addr && m_cached_host == host && m_cached_port == port)
    {
        int connect_ret = connect(m_conn.fd, reinterpret_cast<struct sockaddr*>(&m_cached_addr), sizeof(m_cached_addr));
        if (connect_ret == 0 || errno == EINPROGRESS)
            goto connected;

        // Cached address failed — clear cache, fall through to fresh resolve
        m_has_cached_addr = false;
        m_cached_host.clear();
        m_cached_port = 0;

        // Need a new socket since connect() may have tainted the old one
        close(m_conn.fd);
        m_conn.fd = socket(AF_INET, m_udp ? (SOCK_DGRAM | SOCK_NONBLOCK) : (SOCK_STREAM | SOCK_NONBLOCK), 0);
        if (m_conn.fd < 0)
            return false;
        if (!m_udp)
        {
            int opt2 = 1;
            setsockopt(m_conn.fd, IPPROTO_TCP, TCP_NODELAY, &opt2, sizeof(opt2));
        }
    }

    {
    // Resolve hostname (supports both IPs and DNS names like Docker hostnames)
    char port_str[8];
    auto [pend, pec] = std::to_chars(port_str, port_str + sizeof(port_str), port);
    *pend = '\0';

    struct addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = m_udp ? SOCK_DGRAM : SOCK_STREAM;

    struct addrinfo* result = nullptr;
    if (getaddrinfo(host.c_str(), port_str, &hints, &result) != 0 || !result)
    {
        close(m_conn.fd);
        m_conn.fd = -1;
        return false;
    }

    int connect_ret = connect(m_conn.fd, result->ai_addr, result->ai_addrlen);

    // Cache the resolved address for future reconnects
    if (result->ai_addrlen == sizeof(struct sockaddr_in))
    {
        std::memcpy(&m_cached_addr, result->ai_addr, sizeof(m_cached_addr));
        m_cached_host = host;
        m_cached_port = port;
        m_has_cached_addr = true;
    }

    freeaddrinfo(result);

    if (connect_ret < 0 && errno != EINPROGRESS)
    {
        close(m_conn.fd);
        m_conn.fd = -1;
        return false;
    }
    }

connected:
    m_connected = true;
    m_reconnect_attempt = 0;
    m_stat_total_connections.fetch_add(1, std::memory_order_relaxed);
    invoke_on_connect(m_conn.fd);
    m_conn.partial.clear();
    m_conn.partial.reserve(65536);
    m_conn.closing = false;
    m_conn.read_pending = false;
    m_conn.write_pending = false;

    m_conn.read_req = { this, m_conn.read_buf, m_conn.fd, sizeof(m_conn.read_buf), op_read };
    m_conn.write_req = { this, nullptr, m_conn.fd, 0, op_write };

    if (m_mode != client_mode_out)
    {
        m_conn.read_pending = true;
        if (m_use_provided_bufs)
            m_loop->submit_read_provided(m_conn.fd, BUF_GROUP_ID, &m_conn.read_req);
        else
            m_loop->submit_read(m_conn.fd, m_conn.read_buf, sizeof(m_conn.read_buf), &m_conn.read_req);
    }

    return true;
}

void client_instance::schedule_reconnect()
{
    int max = get_reconnect();
    if (max < 0 || !m_loop)
        return; // Reconnect disabled

    if (max > 0 && m_reconnect_attempt >= max)
        return; // Max attempts reached

    // Exponential backoff: min(1s * 2^attempt, 30s) with jitter
    int base_sec = 1 << std::min(m_reconnect_attempt, 4); // 1,2,4,8,16
    int delay_sec = std::min(base_sec, 30);
    // Time-based jitter: 0-499ms (avoids thundering herd with deterministic values)
    auto ns = std::chrono::steady_clock::now().time_since_epoch().count();
    int jitter_ms = static_cast<int>((ns ^ (ns >> 17)) % 500);

    m_timeout_ts.tv_sec = delay_sec;
    m_timeout_ts.tv_nsec = jitter_ms * 1000000LL;

    m_timeout_req = { this, nullptr, -1, 0, op_timeout };
    m_reconnect_pending = true;
    m_loop->submit_timeout(&m_timeout_ts, &m_timeout_req);
}

bool client_instance::setup(event_loop& loop)
{
    m_loop = &loop;

    m_use_provided_bufs = loop.setup_buf_ring(BUF_GROUP_ID, BUF_COUNT, BUF_SIZE);

    if (!try_connect())
    {
        // If reconnect enabled, schedule first attempt
        if (get_reconnect() >= 0)
        {
            schedule_reconnect();
            return true; // Setup "succeeds" — we'll connect later
        }
        return false;
    }

    return true;
}

void client_instance::teardown(event_loop& loop)
{
    // Drain write queue
    while (!m_write_queue.empty())
        m_write_queue.pop();

    if (m_conn.fd >= 0)
    {
        shutdown(m_conn.fd, SHUT_RDWR);
        close(m_conn.fd);
        m_conn.fd = -1;
    }

    m_connected = false;
    m_conn.partial.clear();
    m_loop = nullptr;
}

void client_instance::on_cqe(struct io_uring_cqe* cqe)
{
    auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
    if (!req || !m_loop)
        return;

    switch (req->type)
    {
        case op_read:
        case op_read_provided:
            handle_read(cqe);
            break;
        case op_write:
            handle_write(cqe);
            break;
        case op_timeout:
            handle_timeout(cqe);
            break;
        default:
            break;
    }
}

void client_instance::handle_read(struct io_uring_cqe* cqe)
{
    m_conn.read_pending = false;

    bool is_provided = (m_conn.read_req.type == op_read_provided);

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
            m_conn.read_pending = true;
            m_loop->submit_read(m_conn.fd, m_conn.read_buf, sizeof(m_conn.read_buf), &m_conn.read_req);
            return;
        }

        // Connection closed or error — defer if write pending
        if (m_conn.write_pending)
        {
            m_conn.closing = true;
        }
        else
        {
            invoke_on_disconnect(m_conn.fd);
            shutdown(m_conn.fd, SHUT_RDWR);
            close(m_conn.fd);
            m_conn.fd = -1;
            m_connected = false;
            schedule_reconnect();
        }
        return;
    }

    m_stat_bytes_in.fetch_add(static_cast<uint64_t>(cqe->res), std::memory_order_relaxed);

    if (m_udp)
    {
        // UDP: whole datagram = one message, no line parsing
        const char* buf_data = m_conn.read_buf;
        size_t buf_len = static_cast<size_t>(cqe->res);

        if (is_provided)
        {
            uint16_t buf_id = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
            buf_data = m_loop->get_buf_ptr(BUF_GROUP_ID, buf_id);
            if (!buf_data)
                goto resubmit;

            std::string_view msg(buf_data, buf_len);
            if (!msg.empty() && msg.back() == '\n')
            {
                msg.remove_suffix(1);
                if (!msg.empty() && msg.back() == '\r')
                    msg.remove_suffix(1);
            }
            if (!msg.empty())
                process_message(msg);

            m_loop->return_buf(BUF_GROUP_ID, buf_id);
        }
        else
        {
            std::string_view msg(buf_data, buf_len);
            if (!msg.empty() && msg.back() == '\n')
            {
                msg.remove_suffix(1);
                if (!msg.empty() && msg.back() == '\r')
                    msg.remove_suffix(1);
            }
            if (!msg.empty())
                process_message(msg);
        }
        goto resubmit;
    }

    if (is_provided)
    {
        uint16_t buf_id = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
        char* buf_ptr = m_loop->get_buf_ptr(BUF_GROUP_ID, buf_id);
        if (buf_ptr)
        {
            m_conn.partial.append(buf_ptr, cqe->res);
            m_loop->return_buf(BUF_GROUP_ID, buf_id);
        }
    }
    else
    {
        m_conn.partial.append(m_conn.read_buf, cqe->res);
    }

    if (m_conn.partial.size() > client_tcp_connection::MAX_PARTIAL_SIZE)
    {
        m_conn.closing = true;
        goto resubmit;
    }

    {
    size_t scan_from = 0;
    size_t pos;
    while ((pos = m_conn.partial.find('\n', scan_from)) != std::string::npos)
    {
        std::string_view line(m_conn.partial.data() + scan_from, pos - scan_from);

        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);

        if (!line.empty())
            process_message(line);

        scan_from = pos + 1;
    }

    if (scan_from > 0)
    {
        if (scan_from >= m_conn.partial.size())
            m_conn.partial.clear();
        else
            m_conn.partial.erase(0, scan_from);
    }
    }

resubmit:
    if (m_loop && m_connected && !m_conn.closing)
    {
        m_conn.read_pending = true;
        if (m_use_provided_bufs)
            m_loop->submit_read_provided(m_conn.fd, BUF_GROUP_ID, &m_conn.read_req);
        else
            m_loop->submit_read(m_conn.fd, m_conn.read_buf, sizeof(m_conn.read_buf), &m_conn.read_req);
    }
}

void client_instance::handle_write(struct io_uring_cqe* cqe)
{
    m_conn.write_pending = false;

    if (cqe->res <= 0)
    {
        m_conn.closing = true;
        if (!m_conn.read_pending)
        {
            invoke_on_disconnect(m_conn.fd);
            shutdown(m_conn.fd, SHUT_RDWR);
            close(m_conn.fd);
            m_conn.fd = -1;
            m_connected = false;
            schedule_reconnect();
        }
        return;
    }

    m_stat_bytes_out.fetch_add(static_cast<uint64_t>(cqe->res), std::memory_order_relaxed);

    // Flush queued writes before checking closing state
    if (!m_write_queue.empty() && !m_conn.closing)
    {
        m_conn.write_buf = std::move(m_write_queue.front());
        m_write_queue.pop();
        m_conn.write_pending = true;
        m_loop->submit_write(m_conn.fd, m_conn.write_buf.data(),
            static_cast<uint32_t>(m_conn.write_buf.size()), &m_conn.write_req);
        return;
    }

    if (m_conn.closing && !m_conn.read_pending)
    {
        invoke_on_disconnect(m_conn.fd);
        shutdown(m_conn.fd, SHUT_RDWR);
        close(m_conn.fd);
        m_conn.fd = -1;
        m_connected = false;
        schedule_reconnect();
    }
}

void client_instance::handle_timeout(struct io_uring_cqe* cqe)
{
    m_reconnect_pending = false;

    // io_uring timeout fires with -ETIME on expiration
    if (cqe->res != -ETIME && cqe->res != 0)
        return;

    m_reconnect_attempt++;

    if (try_connect())
        return; // Reconnected successfully

    // Failed — schedule another attempt
    schedule_reconnect();
}

void client_instance::process_message(std::string_view msg)
{
    m_stat_total_messages.fetch_add(1, std::memory_order_relaxed);
    print_bash_message(msg);
    notify_interactive(msg);

    switch (m_mode)
    {
        case client_mode_inout:
        case client_mode_in:
        {
            invoke_on_message(msg);
            break;
        }
        case client_mode_out:
            break;
        default:
            break;
    }
}

void client_instance::lua_send(std::string_view msg)
{
    if (!m_loop || !m_connected || m_mode == client_mode_in)
        return;

    invoke_on_send(msg);

    if (m_udp)
    {
        // UDP: send as-is, no newline needed
        send_to_server(msg);
        return;
    }

    // Queue message if a write is already in flight
    if (m_conn.write_pending || m_conn.closing)
    {
        if (!m_conn.closing && m_write_queue.size() < MAX_WRITE_QUEUE)
        {
            std::string out(msg.data(), msg.size());
            if (out.empty() || out.back() != '\n')
                out.push_back('\n');
            m_write_queue.push(std::move(out));
        }
        return;
    }

    m_conn.write_buf.assign(msg.data(), msg.size());
    if (m_conn.write_buf.empty() || m_conn.write_buf.back() != '\n')
        m_conn.write_buf.push_back('\n');

    m_conn.write_pending = true;
    m_loop->submit_write(m_conn.fd, m_conn.write_buf.data(),
        static_cast<uint32_t>(m_conn.write_buf.size()), &m_conn.write_req);
}

void client_instance::send_to_server(std::string_view msg)
{
    if (!m_loop || !m_connected || m_mode == client_mode_in || m_conn.write_pending || m_conn.closing)
        return;

    m_conn.write_buf.assign(msg.data(), msg.size());
    m_conn.write_req.buffer = m_conn.write_buf.data();
    m_conn.write_req.length = static_cast<uint32_t>(m_conn.write_buf.size());

    m_conn.write_pending = true;
    m_loop->submit_write(m_conn.fd, m_conn.write_buf.data(),
        static_cast<uint32_t>(m_conn.write_buf.size()), &m_conn.write_req);
}
