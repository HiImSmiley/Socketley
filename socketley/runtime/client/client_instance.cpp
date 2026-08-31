#include "client_instance.h"
#include "../../shared/unix_listener.h"
#include "../../shared/event_loop.h"
#include "../../shared/logging.h"
#include "../../shared/tls_context.h"

#include <unistd.h>
#include <cstring>
#include <iostream>
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
    m_conn = std::make_unique<client_tcp_connection>();
}

client_instance::~client_instance()
{
    if (m_conn->fd >= 0)
    {
        shutdown(m_conn->fd, SHUT_RDWR);
        close_tracked(m_conn->fd);
    }
}

void client_instance::close_tracked(int fd)
{
    if (fd < 0)
        return;
    event_loop* lp = m_loop ? m_loop : m_ring_loop;
    if (SOCKETLEY_LIKELY(lp != nullptr))
        lp->close_fd(fd);
    else
        close(fd);
}

void client_instance::set_mode(client_mode mode)
{
    const client_mode was = m_mode;
    m_mode = mode;

    // Switching a running client out of send-only mode has to start it
    // reading, because arm_read() declines in client_mode_out and every read
    // comes from a completion, so with none in flight there are none.
    if (was == client_mode_out && mode != client_mode_out)
        arm_read();
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

// Everything a client's socket needs in one place, TCP_NODELAY and
// SO_KEEPALIVE at 60/10/3 -- because a peer that loses power sends nothing, an
// idle client never writes, and --reconnect's promise is then never kept.
static void tune_client_socket(int fd, bool udp)
{
    if (udp)
        return;   // no connection to keep alive, and no Nagle to turn off

    int opt = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) < 0) {}

    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) < 0) {}
    int idle = 60, intvl = 10, cnt = 3;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE,  &idle,  sizeof(idle))  < 0) {}
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl)) < 0) {}
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT,   &cnt,   sizeof(cnt))   < 0) {}
}

bool client_instance::try_connect()
{
    std::string host = "127.0.0.1";
    uint16_t port = get_port();
    if (port == 0)
        port = 8000;

    auto target = get_target();

    // `-t unix:/path` needs no resolver and no tune_client_socket, because the
    // path is the address and a unix peer that goes away is reported by the
    // socket rather than probed for.
    if (target.starts_with("unix:"))
    {
        const std::string_view upath = target.substr(5);
        m_conn->fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (m_conn->fd < 0)
            return false;

        struct sockaddr_un uaddr{};
        const socklen_t ulen = socketley::unix_sock::fill_addr(upath, uaddr);
        // A non-blocking AF_UNIX connect either completes now or fails now,
        // EAGAIN included, because unlike EINPROGRESS nothing will finish it
        // later.
        if (connect(m_conn->fd, reinterpret_cast<struct sockaddr*>(&uaddr), ulen) < 0)
        {
            close_tracked(m_conn->fd);
            m_conn->fd = -1;
            return false;
        }
        goto connected;
    }

    if (!target.empty())
    {
        auto colon = target.rfind(':');
        if (colon != std::string_view::npos)
        {
            host = std::string(target.substr(0, colon));
            auto port_sv = target.substr(colon + 1);
            uint32_t parsed_port = 0;
            // The whole of it: `host:8080x` took the 8080 and connected there.
            auto [ptr, ec] = std::from_chars(port_sv.data(), port_sv.data() + port_sv.size(), parsed_port);
            if (ec == std::errc{} && ptr == port_sv.data() + port_sv.size()
                && parsed_port > 0 && parsed_port <= 65535)
                port = static_cast<uint16_t>(parsed_port);
        }
    }

    // The name a TLS peer's certificate has to be valid for, taken before the
    // resolver runs, because a name read back from DNS or the certificate
    // would verify the peer against its own claim.
    m_tls_peer_name = host;

    m_conn->fd = socket(AF_INET,
                        (m_udp ? SOCK_DGRAM : SOCK_STREAM) | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (m_conn->fd < 0)
        return false;

    tune_client_socket(m_conn->fd, m_udp);

    // Try cached DNS result first (same host:port)
    if (m_has_cached_addr && m_cached_host == host && m_cached_port == port)
    {
        int connect_ret = connect(m_conn->fd, reinterpret_cast<struct sockaddr*>(&m_cached_addr), sizeof(m_cached_addr));
        if (connect_ret == 0 || errno == EINPROGRESS)
            goto connected;

        // Cached address failed — clear cache, fall through to fresh resolve
        m_has_cached_addr = false;
        m_cached_host.clear();
        m_cached_port = 0;

        // Need a new socket since connect() may have tainted the old one
        close_tracked(m_conn->fd);
        m_conn->fd = socket(AF_INET,
                        (m_udp ? SOCK_DGRAM : SOCK_STREAM) | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (m_conn->fd < 0)
            return false;
        tune_client_socket(m_conn->fd, m_udp);
    }

    {
    // A literal address needs no resolver, because getaddrinfo runs on the
    // event loop thread and stalls every other connection for as long as it
    // takes.
    {
        struct sockaddr_in lit{};
        lit.sin_family = AF_INET;
        lit.sin_port = htons(port);
        if (inet_pton(AF_INET, host.c_str(), &lit.sin_addr) == 1)
        {
            m_cached_addr = lit;
            m_cached_host = host;
            m_cached_port = port;
            m_has_cached_addr = true;

            int connect_ret = connect(m_conn->fd, reinterpret_cast<struct sockaddr*>(&lit), sizeof(lit));
            if (connect_ret < 0 && errno != EINPROGRESS)
            {
                close_tracked(m_conn->fd);
                m_conn->fd = -1;
                return false;
            }
            goto connected;
        }
    }

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
        close_tracked(m_conn->fd);
        m_conn->fd = -1;
        return false;
    }

    int connect_ret = connect(m_conn->fd, result->ai_addr, result->ai_addrlen);

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
        close_tracked(m_conn->fd);
        m_conn->fd = -1;
        return false;
    }
    }

connected:
    m_connected = true;
    // Everything armed from here on says it belongs to this socket.
    m_conn_generation = next_io_generation();
    m_reconnect_attempt = 0;
    m_stat_total_connections.fetch_add(1, std::memory_order_relaxed);
    invoke_on_connect(m_conn->fd);
    m_conn->partial.clear();
    m_conn->partial.reserve(65536);
    m_conn->closing = false;

    // The session goes on the socket before anything is read from it, and a
    // failure costs the socket -- there is deliberately no path from a refused
    // session to a cleartext dial.
    if (m_tls && !start_tls())
    {
        drop_connection();
        return false;
    }

    // read_pending and write_pending are deliberately left alone, because a
    // previous socket's operation can still hold one of the two requests and
    // arming again would point a second kernel read at the same buffer.
    arm_read();
    flush_queued_write();

    return m_connected;
}

// The one place a read is armed, never while one already is, because both
// would write into m_conn->read_buf.
void client_instance::arm_read()
{
    if (!m_loop || !m_connected || m_conn->closing || m_conn->fd < 0)
        return;
    if (m_conn->read_pending)
        return;
    // A TLS connection always reads even in `--mode out`, because the
    // handshake, alerts and session tickets arrive on this socket, and
    // handle_read drops the plaintext instead.
    if (m_mode == client_mode_out && !m_conn->ssl)
        return;

    m_conn->read_req = { this, m_conn->read_buf, m_conn->fd, sizeof(m_conn->read_buf), op_read,
                        m_conn_generation };
    if (m_use_provided_bufs)
        m_conn->read_pending = m_loop->submit_read_provided(m_conn->fd, BUF_GROUP_ID, &m_conn->read_req);
    else
        m_conn->read_pending = m_loop->submit_read(m_conn->fd, m_conn->read_buf,
                                                  sizeof(m_conn->read_buf), &m_conn->read_req);

    // Nothing reached the ring, so no completion will arrive for this socket and
    // nothing would ever wake this client again; it would sit connected and deaf
    // until the runtime stopped.
    if (!m_conn->read_pending)
        drop_connection();
}

// The one place a write is armed, stamped with the socket it belongs to so a
// completion from a lost socket cannot push that conversation into the current
// one.
void client_instance::arm_write(const char* data, uint32_t len)
{
    m_conn->write_req = { this, const_cast<char*>(data), m_conn->fd, len, op_write,
                         m_conn_generation };
    m_conn->write_pending = m_loop->submit_write(m_conn->fd, data, len, &m_conn->write_req);

    // Nothing reached the ring: no completion will come, so nothing would ever
    // drain what is queued behind this message.
    if (!m_conn->write_pending)
        drop_connection();
}

void client_instance::flush_queued_write()
{
    if (!m_loop || !m_connected || m_conn->write_pending)
        return;

    // A TLS connection's bytes go through the record layer, checked ahead of
    // `closing` because a session on its way down still owes the peer the
    // alert that says why.
    if (m_conn->ssl)
    {
        tls_flush();
        return;
    }

    if (m_conn->closing || m_write_queue.empty())
        return;

    m_conn->write_buf = m_write_queue.take_front();
    // Once there is room again, a later stall is worth reporting afresh.
    if (m_write_queue.bytes() < socketley::write_queue_backpressure_bytes)
        m_write_queue_full = false;
    m_conn->write_off = 0;
    arm_write(m_conn->write_buf.data(), static_cast<uint32_t>(m_conn->write_buf.size()));
}

// Losing the socket: one teardown, reached from every path that loses it.
void client_instance::drop_connection()
{
    if (m_conn->fd >= 0)
    {
        invoke_on_disconnect(m_conn->fd);
        shutdown(m_conn->fd, SHUT_RDWR);
        close_tracked(m_conn->fd);
        m_conn->fd = -1;
    }
    tls_release();
    m_connected = false;
    // A refused timer has nowhere to recover to, and mark_failed() is
    // authoritative in the daemon and worker-local everywhere else -- so out
    // here the log is the report, which is a gap named rather than closed.
    if (!schedule_reconnect())
        mark_failed();
}

// A session belongs to one socket and dies with it, safe to release with a
// write in flight because the ciphertext lives in write_buf and nothing inside
// the SSL is ever named by an SQE.
void client_instance::tls_release()
{
    if (m_conn->ssl)
    {
        tls_context::free_ssl(m_conn->ssl);
        m_conn->ssl = nullptr;
    }
    m_conn->tls_state = tls_conn_none;
    m_conn->tls_peer_closed = false;
}

void client_instance::return_provided_buf(struct io_uring_cqe* cqe)
{
    if (!(cqe->flags & IORING_CQE_F_BUFFER) || !m_ring_loop)
        return;
    m_ring_loop->return_buf(BUF_GROUP_ID,
        static_cast<uint16_t>(cqe->flags >> IORING_CQE_BUFFER_SHIFT));
}

// A completion for a socket we no longer have, not acted on but settled, so
// the buffer goes back and the request becomes free to arm again.
void client_instance::settle_stale(struct io_uring_cqe* cqe, io_request* req)
{
    return_provided_buf(cqe);

    if (req == &m_conn->read_req)
    {
        if (!(cqe->flags & IORING_CQE_F_MORE))
            m_conn->read_pending = false;
    }
    else if (req == &m_conn->write_req)
    {
        m_conn->write_pending = false;
    }
    else if (req == &m_conn->timeout_req)
    {
        m_reconnect_pending = false;
    }
}

// True means something will bring this client back rather than that a timer
// was submitted, because three of the four exits owe nothing and only a
// refused submission means nothing will ever run again.
bool client_instance::schedule_reconnect()
{
    int max = get_reconnect();
    if (max < 0 || !m_loop)
        return true; // Reconnect disabled: nothing to arm, nothing wrong

    if (max > 0 && m_reconnect_attempt >= max)
        return true; // The configured limit, reached as asked

    // One timer and one request slot, because arming it again while the kernel
    // holds it races two reconnect chains and leaks the loser's fd.
    if (m_reconnect_pending)
        return true; // Already armed — that IS the clock running

    // Exponential backoff: min(1s * 2^attempt, 30s) with jitter
    int base_sec = 1 << std::min(m_reconnect_attempt, 4); // 1,2,4,8,16
    int delay_sec = std::min(base_sec, 30);
    // Time-based jitter: 0-499ms (avoids thundering herd with deterministic values)
    auto ns = std::chrono::steady_clock::now().time_since_epoch().count();
    int jitter_ms = static_cast<int>((ns ^ (ns >> 17)) % 500);

    m_conn->timeout_ts.tv_sec = delay_sec;
    m_conn->timeout_ts.tv_nsec = jitter_ms * 1000000LL;

    m_conn->timeout_req = { this, nullptr, -1, 0, op_timeout, m_conn_generation };
    m_reconnect_pending = m_loop->submit_timeout(&m_conn->timeout_ts, &m_conn->timeout_req);

    // A refused timer here is the end of this client, because all three
    // callers are fire-and-forget, and it is said in words rather than as a
    // code the operator cannot see.
    if (!m_reconnect_pending)
        LOG_ERROR("client: the reconnect timer could not be submitted — this "
                  "client is disconnected and will not dial again on its own; "
                  "restart the runtime");

    return m_reconnect_pending;
}

bool client_instance::setup(event_loop& loop)
{
    m_loop = &loop;
    m_ring_loop = &loop;

    // The three occupied flags survive a stop, because a deregistered owner's
    // completions are dropped and never lower them, so this asks the loop --
    // zero frees the old struct, non-zero takes a fresh one, and a full owner
    // table takes the conservative branch.
    if (loop.owner_inflight(this) == 0 && !loop.owner_table_full())
    {
        m_conn->read_pending  = false;
        m_conn->write_pending = false;
        m_reconnect_pending   = false;
        m_conn_spent.clear();
    }
    else if (m_conn->read_pending || m_conn->write_pending || m_reconnect_pending)
    {
        m_conn_spent.push_back(std::move(m_conn));
        m_conn = std::make_unique<client_tcp_connection>();
        m_reconnect_pending = false;
    }

    // ── TLS ─────────────────────────────────────────────────────────────────
    // The CA file and client certificate are read here, at setup, because that
    // is blocking file I/O and the handshake itself touches neither file nor
    // socket -- and every refusal returns false rather than falling through to
    // a cleartext dial, which `inspect` would still report as TLS.
    if (const std::string_view target = get_target(); target.starts_with("unix:"))
    {
        if (const std::string why =
                socketley::unix_sock::path_refusal(target.substr(5));
            !why.empty())
        {
            LOG_ERROR(("client: -t: " + why).c_str());
            return false;
        }
        if (m_udp)
        {
            LOG_ERROR("client: -t unix: names a stream socket and --udp asks "
                      "for datagrams -- a unix datagram dial is a different "
                      "thing and this is not it");
            return false;
        }
        if (get_tls())
        {
            LOG_ERROR("client: --tls encrypts a dial against the network, and "
                      "a unix socket is not on one -- the permissions on the "
                      "socket node are what restrict it.  Refusing rather than "
                      "spending a handshake on a peer that cannot be anywhere "
                      "else");
            return false;
        }
    }

    m_tls.reset();
    if (get_tls())
    {
        auto ctx = std::make_unique<tls_context>();
        // --ca is this client's trust store and the system store is used
        // without one, with the chain and the peer's name always checked;
        // --cert/--key are what this client presents.
        if (!ctx->init_client(get_ca_path(), get_cert_path(), get_key_path()))
        {
            // init_client has already said which file and what OpenSSL made of
            // it, so this says what it cost.
            LOG_ERROR("client: TLS not started -- the CA file or the client "
                      "certificate could not be loaded");
            return false;
        }
        m_tls = std::move(ctx);
    }

    m_use_provided_bufs = loop.setup_buf_ring(BUF_GROUP_ID, BUF_COUNT, BUF_SIZE);

    if (!try_connect())
    {
        // Checked, because "we'll connect later" is only true if the clock
        // that makes it later was actually armed.
        if (get_reconnect() >= 0)
            return schedule_reconnect();
        return false;
    }

    return true;
}

void client_instance::teardown(event_loop& loop)
{
    // Drain write queue
    m_write_queue.clear();
    m_write_queue_full = false;

    if (m_conn->fd >= 0)
    {
        // close_fd submits the cancel and holds the number until both
        // operations report, because this runtime reuses one read and one
        // write request and the kernel hands the socket number straight back
        // on the next connect.
        shutdown(m_conn->fd, SHUT_RDWR);
        close_tracked(m_conn->fd);
        m_conn->fd = -1;
    }

    // The socket is gone so the session is finished, released here because
    // this struct can outlive the stop and a session held across a start is a
    // handshake the next peer never heard of.
    tls_release();

    // The reconnect timer is attached to no fd, so the cancel could not reach
    // it and the ring would owe this owner a completion for up to thirty
    // seconds -- during which a removed runtime is never freed.
    if (m_reconnect_pending)
    {
        if (!loop.submit_timeout_remove(&m_conn->timeout_req))
            LOG_WARN("client: the reconnect timer withdrawal did not reach the ring — "
                     "this instance stays retired until the timer fires on its own");
        loop.flush();
    }

    // Its request keeps its owner, because the loop reads the request when the
    // completion lands, and the pending flags are left standing since a
    // withdrawn timeout is still owed exactly one.
    m_connected = false;
    m_conn->closing = false;
    m_conn->partial.clear();
    // Nothing armed before this stop belongs to anything that comes after it,
    // including a start() that fails to connect and so never stamps a new
    // socket of its own.
    m_conn_generation = next_io_generation();
    m_loop = nullptr;
}

void client_instance::on_cqe(struct io_uring_cqe* cqe)
{
    auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
    if (!req)
        return;

    // Stopped, or belonging to a socket already lost: not acted on but
    // settled, because the descriptor number alone cannot tell the two apart.
    if (!m_loop || req->generation != m_conn_generation)
    {
        settle_stale(cqe, req);
        // Whatever that completion was occupying is free now, and the current
        // socket may have been waiting on exactly that.
        arm_read();
        flush_queued_write();
        return;
    }

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
    m_conn->read_pending = false;

    bool is_provided = (m_conn->read_req.type == op_read_provided);

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
            m_conn->read_pending = true;
            // Reset the request type, because leaving it as a provided-buffer
            // type makes the handler append ring buffer 0's contents and
            // return a buffer it never took.
            m_conn->read_req.type = op_read;
            m_conn->read_pending = m_loop->submit_read(m_conn->fd, m_conn->read_buf,
                                                      sizeof(m_conn->read_buf), &m_conn->read_req);
            if (!m_conn->read_pending)
                drop_connection();
            return;
        }

        // Connection closed or error — defer if write pending
        if (m_conn->write_pending)
            m_conn->closing = true;
        else
            drop_connection();
        return;
    }

    m_stat_bytes_in.fetch_add(static_cast<uint64_t>(cqe->res), std::memory_order_relaxed);

    if (m_udp)
    {
        // UDP: whole datagram = one message, no line parsing
        const char* buf_data = m_conn->read_buf;
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

    // On a TLS connection these bytes are ciphertext and tls_feed is what puts
    // plaintext into partial; everything below this point reads exactly the
    // same buffer it always did and knows nothing about TLS.
    if (is_provided)
    {
        uint16_t buf_id = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
        char* buf_ptr = m_loop->get_buf_ptr(BUF_GROUP_ID, buf_id);
        if (buf_ptr)
        {
            if (m_conn->ssl)
                tls_feed(buf_ptr, static_cast<size_t>(cqe->res));
            else
                m_conn->partial.append(buf_ptr, cqe->res);
            // Back to the group whatever the session made of it: the group is
            // shared with every other client on this loop, and one failed
            // handshake is no reason to starve them.
            m_loop->return_buf(BUF_GROUP_ID, buf_id);
        }
    }
    else if (m_conn->ssl)
    {
        tls_feed(m_conn->read_buf, static_cast<size_t>(cqe->res));
    }
    else
    {
        m_conn->partial.append(m_conn->read_buf, cqe->res);
    }

    // A send-only TLS client reads because the record layer has to, so the
    // application data is dropped here rather than parsed -- otherwise --tls
    // would quietly start delivering what `--mode out` says no to.
    if (m_conn->ssl && m_mode == client_mode_out)
        m_conn->partial.clear();

    if (m_conn->partial.size() > client_tcp_connection::MAX_PARTIAL_SIZE)
    {
        m_conn->closing = true;
        goto resubmit;
    }

    {
    size_t scan_from = 0;
    size_t pos;
    while ((pos = m_conn->partial.find('\n', scan_from)) != std::string::npos)
    {
        std::string_view line(m_conn->partial.data() + scan_from, pos - scan_from);

        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);

        if (!line.empty())
            process_message(line);

        scan_from = pos + 1;
    }

    if (scan_from > 0)
    {
        if (scan_from >= m_conn->partial.size())
            m_conn->partial.clear();
        else
            m_conn->partial.erase(0, scan_from);
    }
    }

resubmit:
    // close_notify is applied here rather than where it was read, because the
    // same read can carry a last line ahead of it, and one flush then covers
    // everything the record layer owes the wire.
    if (m_conn->ssl)
    {
        if (m_conn->tls_peer_closed)
            m_conn->closing = true;
        tls_flush();
    }

    // A connection marked closing with nothing in flight has nobody to notice
    // it, because arm_read() declines while closing, so the client sat
    // connected and deaf and never dialled again.
    if (m_conn->closing && !m_conn->write_pending && m_connected)
    {
        drop_connection();
        return;
    }

    arm_read();
}

// The two read_pending guards defer a teardown to an armed read, which
// conn_reachability.h refuses, and are left alone because the read is
// single-shot and armed on the descriptor -- 109 resets reproduced no
// stranding, which is a weaker measurement than the other two and is named as
// one.
void client_instance::handle_write(struct io_uring_cqe* cqe)
{
    m_conn->write_pending = false;

    if (cqe->res <= 0)
    {
        m_conn->closing = true;
        if (!m_conn->read_pending)
            drop_connection();
        return;
    }

    m_stat_bytes_out.fetch_add(static_cast<uint64_t>(cqe->res), std::memory_order_relaxed);

    // Resume a short write before moving on to the next message.
    m_conn->write_off += static_cast<size_t>(cqe->res);
    if (m_conn->write_off < m_conn->write_buf.size())
    {
        arm_write(m_conn->write_buf.data() + m_conn->write_off,
                  static_cast<uint32_t>(m_conn->write_buf.size() - m_conn->write_off));
        return;
    }
    m_conn->write_off = 0;

    // Flush queued writes before checking closing state, because
    // flush_queued_write is what turns this completion into the next handshake
    // flight.
    flush_queued_write();
    if (m_conn->write_pending)
        return;

    if (m_conn->closing && !m_conn->read_pending && m_connected)
        drop_connection();
}

void client_instance::handle_timeout(struct io_uring_cqe* cqe)
{
    m_reconnect_pending = false;

    // io_uring timeout fires with -ETIME on expiration
    if (cqe->res != -ETIME && cqe->res != 0)
        return;

    // A timer that outlived what it was waiting for, since dialling again here
    // would overwrite m_conn->fd and leak the one it replaced.
    if (m_connected)
        return;

    m_reconnect_attempt++;

    if (try_connect())
        return; // Reconnected successfully

    // Failed, so schedule another attempt, because if the clock cannot be
    // re-armed there is no later attempt to wait for.
    if (!schedule_reconnect())
        mark_failed();
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

// Whether the message was written or queued, which was void, so self.send()
// reported none of the three ordinary refusals.
bool client_instance::lua_send(std::string_view msg)
{
    if (!m_loop || !m_connected || m_mode == client_mode_in)
        return false;

    invoke_on_send(msg);

    if (m_udp)
    {
        // UDP: send as-is, no newline needed
        send_to_server(msg);
        return true;
    }

    // Queued when a write is in flight, or always on a TLS connection, because
    // tls_flush is the only thing allowed to put a record on the wire and an
    // SSL asked to write mid-handshake answers WANT_READ.
    if (m_conn->ssl || m_conn->write_pending || m_conn->closing)
    {
        if (!m_conn->closing)
        {
            // The bound is memory and not entries, because an entry cap
            // dropped 20-byte lines after 80 KB and let megabyte payloads
            // queue gigabytes.
            if (m_write_queue.bytes() >= socketley::write_queue_max_bytes)
            {
                if (!m_write_queue_full)
                {
                    m_write_queue_full = true;
                    std::cerr << "[client] server is not reading ("
                              << m_write_queue.bytes()
                              << " bytes queued), dropping messages\n";
                }
                return false;
            }
            std::string out(msg.data(), msg.size());
            if (out.empty() || out.back() != '\n')
                out.push_back('\n');
            m_write_queue.push(std::move(out));
        }
        // Nothing else will come back for this message on its own, so the
        // record layer is driven from here or the line sits in the queue.
        if (m_conn->ssl)
            tls_flush();
        // Queued, or dropped because the connection is already closing.
        return !m_conn->closing;
    }

    m_conn->write_buf.assign(msg.data(), msg.size());
    if (m_conn->write_buf.empty() || m_conn->write_buf.back() != '\n')
        m_conn->write_buf.push_back('\n');

    m_conn->write_off = 0;
    arm_write(m_conn->write_buf.data(), static_cast<uint32_t>(m_conn->write_buf.size()));
    return true;
}

// The datagram path, which knows nothing about the record layer because
// setup() refuses --tls on a UDP client rather than dialling in the clear.
void client_instance::send_to_server(std::string_view msg)
{
    if (!m_loop || !m_connected || m_mode == client_mode_in || m_conn->write_pending || m_conn->closing)
        return;

    m_conn->write_buf.assign(msg.data(), msg.size());
    m_conn->write_off = 0;
    arm_write(m_conn->write_buf.data(), static_cast<uint32_t>(m_conn->write_buf.size()));
}

// ─── TLS record layer ───────────────────────────────────────────────────────
// Give this connection its session and put the ClientHello on the wire, pinned
// to the host from `-t` and never to a name read back from the certificate, so
// this can only fail closed.
bool client_instance::start_tls()
{
    if (SOCKETLEY_UNLIKELY(!m_tls))
        return false;

    if (SOCKETLEY_UNLIKELY(m_tls_peer_name.empty()))
    {
        LOG_ERROR("client: TLS connection refused -- the target has no host to verify "
                  "the peer's certificate against");
        return false;
    }

    m_conn->ssl = m_tls->create_ssl_client(m_tls_peer_name);
    if (SOCKETLEY_UNLIKELY(!m_conn->ssl))
        return false;
    m_conn->tls_state = tls_conn_handshake;
    m_conn->tls_peer_closed = false;

    // One turn of the handshake, which produces the ClientHello, where a
    // negative is a local failure rather than a rejection because nothing is
    // on the wire yet.
    if (SOCKETLEY_UNLIKELY(tls_context::do_handshake(m_conn->ssl) < 0))
        return false;

    tls_flush();
    return true;
}

// Ciphertext in and plaintext into m_conn->partial, one call per read
// completion, which is what makes the handshake asynchronous with nothing
// blocking the event loop.
void client_instance::tls_feed(const char* data, size_t len)
{
    // Inbound ciphertext into the read BIO, whose refusal is fatal by contract
    // because there is nowhere to hold what was not taken.
    size_t off = 0;
    while (off < len)
    {
        const int n = tls_context::bio_write_in(m_conn->ssl, data + off,
                                                static_cast<int>(len - off));
        if (SOCKETLEY_UNLIKELY(n <= 0))
        {
            m_conn->closing = true;
            return;
        }
        off += static_cast<size_t>(n);
    }

    if (m_conn->tls_state == tls_conn_handshake)
    {
        const int r = tls_context::do_handshake(m_conn->ssl);
        if (SOCKETLEY_UNLIKELY(r < 0))
        {
            // Where a server's certificate is rejected, closing but not
            // silently, because the alert OpenSSL produced tells the peer why
            // and the tls_flush at the end of handle_read puts it on the wire.
            m_conn->closing = true;
            return;
        }
        if (r == 0)
            return;   // another round; its records go out with that flush

        m_conn->tls_state = tls_conn_ready;
        // Deliberately falling through rather than returning, because under
        // TLS 1.3 a peer's Finished and its first message routinely arrive in
        // one packet.
    }

    char plain[16384];
    for (;;)
    {
        const int n = tls_context::ssl_read(m_conn->ssl, plain, sizeof(plain));
        if (SOCKETLEY_LIKELY(n > 0))
        {
            m_conn->partial.append(plain, static_cast<size_t>(n));
            // The same ceiling the cleartext path applies, checked inside the
            // loop, because one read completion can decrypt everything the
            // inbound BIO had buffered.
            if (SOCKETLEY_UNLIKELY(m_conn->partial.size() >
                                   client_tcp_connection::MAX_PARTIAL_SIZE))
            {
                m_conn->closing = true;
                break;
            }
            continue;
        }
        if (n < 0)
        {
            // Either the peer's close_notify or an unusable record, both
            // recorded and applied by the caller because the bytes decrypted
            // above may be a complete line.
            m_conn->tls_peer_closed = true;
        }
        break;
    }
}

// Every byte this connection sends is a TLS record, including the ones nobody
// queued, and there is no other way onto the wire for a connection with a
// session.
void client_instance::tls_flush()
{
    if (SOCKETLEY_UNLIKELY(!m_loop || !m_conn->ssl))
        return;

    // One write in flight at a time, because a second submission would need a
    // second buffer and would interleave two record streams on one socket.
    if (m_conn->write_pending)
        return;

    // Application data only once the handshake is done, so a message queued by
    // on_connect waits rather than being handed to an SSL that would answer
    // WANT_READ.
    if (m_conn->tls_state == tls_conn_ready)
    {
        while (!m_write_queue.empty())
        {
            const std::string& msg = m_write_queue.front();
            const int n = tls_context::ssl_write(m_conn->ssl, msg.data(),
                                                 static_cast<int>(msg.size()));
            if (n <= 0)
            {
                // 0 is backpressure and the same buffer is offered again once
                // the write BIO drains, which leaving the message at the front
                // of the queue arranges; -1 is fatal.
                if (n < 0)
                    m_conn->closing = true;
                break;
            }
            // Partial writes are not enabled on this context, so a short count
            // would mean the record layer and this queue disagree about what
            // has been sent.
            if (SOCKETLEY_UNLIKELY(static_cast<size_t>(n) != msg.size()))
            {
                m_conn->closing = true;
                break;
            }
            m_write_queue.pop();
        }
        // Once there is room again, a later stall is worth reporting afresh —
        // the same latch the cleartext path lowers in flush_queued_write.
        if (m_write_queue.bytes() < socketley::write_queue_backpressure_bytes)
            m_write_queue_full = false;
    }

    if (!tls_context::has_pending_out(m_conn->ssl))
        return;

    // Ciphertext copied out of the write BIO into write_buf rather than
    // pointed at, because the BIO's storage moves as OpenSSL writes the next
    // record -- and the copy is what keeps the SSL free of anything the ring
    // can name.
    std::string cipher;
    char buf[16384];
    for (;;)
    {
        const int n = tls_context::bio_read_out(m_conn->ssl, buf, sizeof(buf));
        if (n <= 0)
            break;
        cipher.append(buf, static_cast<size_t>(n));
    }
    if (SOCKETLEY_UNLIKELY(cipher.empty()))
        return;

    // Nothing is in flight (checked above), so write_buf is this function's to
    // take: whatever was in it belongs to a write that has already completed.
    m_conn->write_buf = std::move(cipher);
    m_conn->write_off = 0;
    arm_write(m_conn->write_buf.data(), static_cast<uint32_t>(m_conn->write_buf.size()));
}
