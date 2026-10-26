#include "../../shared/net/socket_tuning.h"
#include "client_instance.h"
#include "../../shared/net/unix_listener.h"
#include "../../shared/net/dial_address.h"
#include "../../shared/loop/event_loop.h"
#include "../../shared/util/logging.h"
#include "../../shared/crypto/tls_context.h"
#include "../../shared/loop/line_framing.h"

#include <unistd.h>
#include <cstring>
#include <iostream>
#include <chrono>
#include <arpa/inet.h>
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

// Beside total_connections and not folded into it: that one counts connections
// the kernel confirmed, this one counts the dials it took, and the two pulling
// apart is what a flapping target looks like from here.
std::string client_instance::stats_lines() const
{
    return "dial_attempts:"
         + std::to_string(m_stat_dial_attempts.load(std::memory_order_relaxed))
         + "\n";
}

// Everything a client's socket needs in one place: TCP_NODELAY, and the
// keepalive every listener in this tree shares -- an idle client never writes,
// so without it --reconnect's promise is never kept.
static void tune_client_socket(int fd, bool udp)
{
    if (udp)
        return;   // no connection to keep alive, and no Nagle to turn off

    int opt = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) < 0) {}

    socket_tuning::keepalive_dead_peer(fd);
}

bool client_instance::try_connect(bool at_start)
{
    m_resolving = false;
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
        socketley::unix_sock::tune_stream(m_conn->fd);

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
        // Judged here and not only at the flag, because a target reaches a
        // runtime four other ways -- a config file, an import, a Lua create,
        // the API -- and a port that cannot work used to become whichever port
        // -p had set instead.
        if (const std::string why = socketley::dial_addr::refusal(target, host, port);
            !why.empty())
        {
            LOG_ERROR(("client target \"" + std::string(target) + "\": " + why).c_str());
            return false;
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
    std::vector<socketley::async_resolver::address> found;
    // At start the dial is waited for anyway, and a name that cannot resolve is a start that fails.
    const auto st = at_start ? m_resolver.lookup_now(host, AF_INET, found)
                             : m_resolver.lookup(host, AF_INET, found);
    m_resolving = st == socketley::async_resolver::state::pending;
    if (st != socketley::async_resolver::state::ready || found.empty() ||
        found.front().len != sizeof(struct sockaddr_in))
    {
        close_tracked(m_conn->fd);
        m_conn->fd = -1;
        return false;
    }

    std::memcpy(&m_cached_addr, &found.front().addr, sizeof(m_cached_addr));
    m_cached_addr.sin_port = htons(port);
    m_cached_host = host;
    m_cached_port = port;
    m_has_cached_addr = true;

    int connect_ret = connect(m_conn->fd, reinterpret_cast<struct sockaddr*>(&m_cached_addr), sizeof(m_cached_addr));

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
    // The attempt counter is NOT reset here.  A non-blocking connect answers
    // EINPROGRESS and falls straight through to this label, so zeroing it here
    // zeroed it on every dial -- and `--reconnect N`, documented as a limit,
    // could never reach one.  Measured with `-t 127.0.0.1:1 --reconnect 2`:
    // still `Up` after twelve seconds, dialling for ever.  It is reset where a
    // peer has actually answered, in note_established().

    // A dial and not a connection, for the same reason the paragraph above
    // gives: total_connections is counted where the kernel confirms one, in
    // note_connected().
    stat_add(m_stat_dial_attempts, 1);
    m_conn_counted = false;
    m_conn->partial.clear();
    m_conn->partial.reserve(65536);
    // Before the callback and not after it, because on_connect sends and
    // lua_send refuses on `closing` -- which drop_connection() never lowers.
    // The first reconnect after a failed write therefore ran the callback with
    // the dead socket's flag still up, queued nothing, and answered the script
    // "not connected" on a connection that was up; one line later it was false
    // and every later send worked.
    m_conn->closing = false;
    invoke_on_connect(m_conn->fd);

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
void client_instance::arm_read(bool poll_first)
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
    // One submission for a stream of messages rather than one per message.
    // Measured on a server's read path, which has the same shape, driven by a
    // single pipelined connection: 7 of 7 interleaved passes with the order
    // rotated, spread [1.024, 1.051] against a noise floor of [0.998, 0.999].
    if (m_recv_multishot)
        m_conn->read_pending = m_loop->submit_recv_multishot(m_conn->fd, BUF_GROUP_ID, &m_conn->read_req);
    if (!m_conn->read_pending && m_use_provided_bufs)
        m_conn->read_pending = m_loop->submit_read_provided(m_conn->fd, BUF_GROUP_ID, &m_conn->read_req,
                                                            poll_first);

    // A refused submission is the ring being momentarily full, not the peer
    // being gone -- and the arm below is the one the cache and the server fall
    // back to for exactly that.  Without it a busy ring cost the whole
    // connection: socket closed, on_disconnect fired, and at least a second of
    // backoff before the client tried again.  read_buf is already here for the
    // case where no ring exists at all, and handle_read's own ENOBUFS path
    // takes this same arm with this same reset.
    //
    // The type goes back to op_read first, because leaving it as a
    // provided-buffer type makes the handler append ring buffer 0's contents
    // and return a buffer it never took.
    if (!m_conn->read_pending)
    {
        m_conn->read_req.type = op_read;
        m_conn->read_pending = m_loop->submit_read(m_conn->fd, m_conn->read_buf,
                                                  sizeof(m_conn->read_buf), &m_conn->read_req,
                                                  poll_first);
    }

    // Nothing reached the ring at all, so no completion will arrive for this
    // socket and nothing would ever wake this client again; it would sit
    // connected and deaf until the runtime stopped.
    if (!m_conn->read_pending)
        drop_connection();
}

// The one place a write is armed, stamped with the socket it belongs to so a
// completion from a lost socket cannot push that conversation into the current
// one.
//
// One buffer per write, where the server, the cache and the proxy gather up to
// MAX_WRITE_BATCH into a writev, and that is the right answer here rather than
// the missing one.  A callback cannot be interrupted by a completion, so a
// script sending several lines at once is the ordinary case -- and lua_send
// puts them through push_coalesced, which appends them into one buffer up to
// WRITE_COALESCE_LIMIT.  Sixteen short lines are therefore one contiguous
// write, which beats a sixteen-element iovec rather than falling short of it.
// Above the limit the queue stops merging, and by then each entry is 64 KiB or
// more, which amortises a submission on its own.
//
// Measured, one line answered with a burst of K and the next burst sent only
// after K replies: 7.65 us of CPU per message at K=1, 4.29 at K=4 and 1.28 at
// K=16, spreads of 1 to 2 per cent.  A client that armed one write per message
// could not fall like that.
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
    if (m_write_queue.bytes() < write_watermark_bytes())
    {
        m_write_queue_full = false;
        // The same crossing, read for the other purpose: a producer that
        // stopped at the watermark is owed a call.
        if (m_drain_wanted) { m_drain_wanted = false; m_drain_due = true; }
    }
    m_conn->write_off = 0;
    arm_write(m_conn->write_buf.data(), static_cast<uint32_t>(m_conn->write_buf.size()));
}

long client_instance::pending_bytes() const
{
    return static_cast<long>(m_write_queue.bytes());
}

bool client_instance::write_backlogged() const
{
    return m_write_queue_full && m_connected;
}

void client_instance::on_loop_turn()
{
    // A connection that is up and silent is still a connection, and no
    // completion will ever report one -- so the kernel is asked here, which is
    // also the last thing that runs before a turn publishes its figures.
    if (SOCKETLEY_UNLIKELY(m_connected && !m_conn_counted))
        note_connected();

    if (SOCKETLEY_UNLIKELY(m_drain_due))
    {
        m_drain_due = false;
        // No id: a client has one connection, and inventing a number for it
        // would be a fiction a script could try to use.  The argument is
        // passed as 0 so the binding is one function for both runtimes; a
        // client's on_writable() simply takes none, which Lua allows.
        invoke_on_writable(0);
    }
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
        // What the socket leaves behind: the context keeps this session so the
        // next dial resumes instead of paying a second full handshake.  Only
        // from a connection that reached tls_conn_ready, because a handshake
        // that never finished verified nobody.
        if (m_tls && m_conn->tls_state == tls_conn_ready)
            m_tls->remember_session(m_tls_peer_name, m_conn->ssl);
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
    else if (req == &m_conn->hs_req)
    {
        m_conn->hs_armed = false;
        // The deadline an earlier socket left standing kept this one from arming its own.
        if (m_connected && m_conn->tls_state == tls_conn_handshake)
            arm_handshake_deadline();
    }
}

// One connection, counted once, where the kernel says there is one.
//
// getpeername() is the question an accept() answers on the other side: it
// fails with ENOTCONN for as long as the handshake is out, and a connect that
// is refused never reaches a state where it succeeds.  The count used to sit
// at the dial instead, which a non-blocking connect() answers EINPROGRESS for
// whenever the target is not already there -- measured against a port nobody
// held, `connections:0` beside `total_connections:5`.
void client_instance::note_connected()
{
    struct sockaddr_storage peer{};
    socklen_t len = sizeof(peer);
    if (m_conn->fd < 0
        || getpeername(m_conn->fd, reinterpret_cast<struct sockaddr*>(&peer), &len) < 0)
        return;

    // Per socket, because this runs every turn until it is true and a client
    // that reconnects all day must count connections and not turns.
    m_conn_counted = true;
    stat_add(m_stat_total_connections, 1);
}

// A completion carrying bytes is the first thing that proves the peer accepted
// the connection rather than that the kernel accepted the SQE, and it is where
// the backoff and the --reconnect limit start counting from again.
void client_instance::note_established()
{
    // Not while the handshake is still in progress.  The bytes crossing then
    // are handshake records, and one of the two callers is a WRITE completion
    // -- which means the local kernel took them, the one thing the sentence
    // above says this is not.  A target that accepts and never handshakes
    // wrote its ClientHello successfully on every re-dial and zeroed the
    // counter each time, so `--reconnect N` was never reached: measured, six
    // deadlines in three minutes and not one refusal.
    //
    // A plaintext client is unaffected, its tls_state being tls_conn_none.
    if (m_conn && m_conn->tls_state == tls_conn_handshake)
        return;

    m_reconnect_attempt = 0;
}

// True means something will bring this client back rather than that a timer
// was submitted, because three of the four exits owe nothing and only a
// refused submission means nothing will ever run again.
bool client_instance::schedule_reconnect()
{
    // A name still being looked up is asked again shortly, whatever --reconnect says, since no dial has failed yet.
    if (m_resolving && m_loop)
    {
        if (m_reconnect_pending)
            return true;
        m_conn->timeout_ts.tv_sec = 0;
        m_conn->timeout_ts.tv_nsec = 100000000LL;
        m_conn->timeout_req = { this, nullptr, -1, 0, op_timeout, m_conn_generation };
        m_reconnect_pending = m_loop->submit_timeout(&m_conn->timeout_ts, &m_conn->timeout_req);
        if (!m_reconnect_pending)
            LOG_ERROR("client: the timer that waits for the target's name could not be submitted");
        return m_reconnect_pending;
    }

    int max = get_reconnect();
    if (max < 0 || !m_loop)
        return true; // Reconnect disabled: nothing to arm, nothing wrong

    if (max > 0 && m_reconnect_attempt >= max)
    {
        // Reached as asked -- and nothing will ever wake this client again, so
        // it is not a success.  Answering true here left `ps` reporting
        // `running` with no socket and zero connections, and was_running
        // brought it back into the same state at the next daemon start.  The
        // contract of this function is "something will bring this client
        // back", and at the limit nothing will, so drop_connection()'s
        // mark_failed() is the honest end.
        LOG_ERROR("client: the --reconnect limit was reached and this client "
                  "will not dial again; it is left failed");
        return false;
    }

    // One timer and one request slot, because arming it again while the kernel
    // holds it races two reconnect chains and leaks the loser's fd.
    if (m_reconnect_pending)
        return true; // Already armed — that IS the clock running

    // Exponential backoff: 1, 2, 4, 8 and then 16 seconds for ever, plus up to
    // half a second of jitter -- the shift's own cap is the ceiling, and the
    // std::min(base, 30) that used to stand beside it could never bind.
    int delay_sec = 1 << std::min(m_reconnect_attempt, 4);
    // Time-based jitter: 0-499ms (avoids thundering herd with deterministic values)
    auto ns = std::chrono::steady_clock::now().time_since_epoch().count();
    int jitter_ms = static_cast<int>((ns ^ (ns >> 17)) % 500);

    m_conn->timeout_ts.tv_sec = delay_sec;
    m_conn->timeout_ts.tv_nsec = jitter_ms * 1000000LL;

    // The cached address goes with the attempt that just ended.  It was only
    // ever cleared when connect() failed SYNCHRONOUSLY, and a non-blocking
    // connect to a remote address answers EINPROGRESS -- the refusal arrives
    // later as -ECONNREFUSED on a CQE, down a path that never touched the
    // cache.  So a client dialling `app:9000` kept an address the container
    // had already given up, for as long as the runtime lived, while the manual
    // promises automatic reconnection for exactly that case.  Re-resolving is
    // affordable here and nowhere else: the backoff is at least a second, and
    // a literal address never reaches the resolver at all.
    m_has_cached_addr = false;
    if (!m_cached_host.empty())
        m_resolver.forget(m_cached_host);
    m_cached_host.clear();
    m_cached_port = 0;

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
    if (loop.owner_drained(this))
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

    // A start is a new --reconnect budget.
    m_reconnect_attempt = 0;

    m_use_provided_bufs = loop.setup_buf_ring(BUF_GROUP_ID, BUF_COUNT, BUF_SIZE);
    // Needs the ring, because a multishot recv selects its buffer from one.
    m_recv_multishot = m_use_provided_bufs && loop.recv_multishot_enabled();

    if (!try_connect(/*at_start=*/true))
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
    m_drain_wanted = false;
    m_drain_due = false;

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

    // The same reasoning for the handshake deadline, which hangs off no
    // descriptor either.
    if (m_conn->hs_armed)
    {
        if (!loop.submit_timeout_remove(&m_conn->hs_req))
            LOG_WARN("client: the handshake deadline withdrawal did not reach the ring — "
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
        case op_recv_multishot:
            handle_read(cqe);
            break;
        case op_write:
            handle_write(cqe);
            break;
        case op_timeout:
            handle_timeout(cqe, req);
            break;
        default:
            break;
    }
}

void client_instance::handle_read(struct io_uring_cqe* cqe)
{
    // A multishot arm still standing is NOT a re-arm this client owes: the
    // kernel delivers again without being asked, and clearing the flag here
    // would let arm_read() put a second recv on the same socket and the same
    // buffer.  arm_read() at the bottom of this function then declines on its
    // own, which is how one path serves both.
    const bool multishot = is_multishot_recv_op(m_conn->read_req.type);
    const bool more      = multishot && (cqe->flags & IORING_CQE_F_MORE);
    if (!more)
        m_conn->read_pending = false;

    bool is_provided = (m_conn->read_req.type == op_read_provided || multishot);

    // res == 0 is an end of stream on TCP and a legitimate empty datagram on
    // UDP, and testing `<= 0` before the m_udp branch below made the second
    // one a disconnect: a peer sending nothing, or a server's own
    // broadcast(""), put every UDP client through drop_connection and a
    // reconnect round -- or killed it outright without --reconnect.
    if (cqe->res < 0 || (cqe->res == 0 && !m_udp))
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
            // The kernel ends a multishot recv it cannot find a buffer for, so
            // MORE is expected to be clear here; asserted rather than assumed
            // because arming a second read while the first still stands splits
            // the stream between two arms and neither sees a whole message.
            if (more)
                return;
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

    note_established();
    stat_add(m_stat_bytes_in, static_cast<uint64_t>(cqe->res));

    if (m_udp)
    {
        // UDP: whole datagram = one message, no line parsing
        const char* buf_data = m_conn->read_buf;
        size_t buf_len = static_cast<size_t>(cqe->res);

        if (is_provided)
        {
            // Kept apart from m_loop, which a stop inside on_message nulls while the buffer is still owed to the
            // group, as the stream path below keeps it.
            event_loop* const ring = m_loop;
            uint16_t buf_id = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
            buf_data = ring->get_buf_ptr(BUF_GROUP_ID, buf_id);
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

            ring->return_buf(BUF_GROUP_ID, buf_id);
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

    {
    // Kept apart from m_loop, which a stop inside a callback below nulls
    // while the buffer this read holds is still owed to the group.
    event_loop* const ring = m_loop;
    const size_t len = static_cast<size_t>(cqe->res);
    const uint16_t buf_id = static_cast<uint16_t>(cqe->flags >> IORING_CQE_BUFFER_SHIFT);
    const char* data = is_provided ? ring->get_buf_ptr(BUF_GROUP_ID, buf_id)
                                   : m_conn->read_buf;
    if (data)
    {
        // Only a provided buffer is read in place, because nothing can point
        // the kernel at it again before return_buf, while read_buf is re-armed
        // by whatever calls arm_read().
        if (m_conn->ssl)
            read_tls(data, len);
        else if (is_provided)
            read_in_place(data, len);
        else
            read_through_partial(data, len);

        // Back to the group only after the last line in it was delivered, and
        // whatever the session made of it, because every client on this loop
        // shares the group.
        if (is_provided)
            ring->return_buf(BUF_GROUP_ID, buf_id);
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

    // A datagram socket never reports what it still holds, so there the flag's
    // absence says nothing.
    arm_read(!m_udp && event_loop::recv_drained(cqe));
}

// Whether the socket a read belongs to is still the one being read, asked
// after every delivered line because a script can stop this runtime from
// on_message and every later line of that read was meant for nobody.
bool client_instance::still_reading(const client_tcp_connection* conn,
                                    uint32_t generation, int fd) const
{
    return m_conn.get() == conn && m_conn_generation == generation && conn->fd == fd;
}

size_t client_instance::deliver_lines(const char* data, size_t len, size_t search_from)
{
    const client_tcp_connection* const conn = m_conn.get();
    const uint32_t generation = m_conn_generation;
    const int fd = conn->fd;
    const size_t used = socketley::for_each_line(data, len, search_from,
        [&](std::string_view line)
        {
            process_message(line);
            return still_reading(conn, generation, fd);
        });

    // The socket went and its unfinished line with it, unless a stop or a
    // dial already gave this struct a new generation and cleared it itself.
    if (used == socketley::line_framing_stopped
        && m_conn.get() == conn && m_conn_generation == generation)
        m_conn->partial.clear();
    return used;
}

// The complete lines partial holds, where `scanned` is how much of it an
// earlier read already searched, and a partial over the bound is refused.
void client_instance::deliver_partial(size_t scanned)
{
    std::string& partial = m_conn->partial;
    if (partial.size() > read_buffer_bytes())
    {
        m_conn->closing = true;
        return;
    }

    const size_t used = deliver_lines(partial.data(), partial.size(), scanned);
    if (used == socketley::line_framing_stopped || used == 0)
        return;
    if (used >= partial.size())
        partial.clear();
    else
        partial.erase(0, used);
}

// Lines straight out of a provided buffer, with partial holding only the
// unfinished line on either side of it.
void client_instance::read_in_place(const char* data, size_t len)
{
    std::string& partial = m_conn->partial;

    // Over the bound the copying path refuses it, bytes kept, so every later
    // read on this closing connection is refused too.
    if (partial.size() + len > read_buffer_bytes())
    {
        read_through_partial(data, len);
        return;
    }

    size_t from = 0;
    if (!partial.empty())
    {
        const void* nl = std::memchr(data, '\n', len);
        if (!nl)
        {
            partial.append(data, len);
            return;
        }
        from = static_cast<size_t>(static_cast<const char*>(nl) - data) + 1;
        partial.append(data, from);
        if (deliver_lines(partial.data(), partial.size(), partial.size() - 1)
            == socketley::line_framing_stopped)
            return;
        partial.clear();
    }

    const size_t used = deliver_lines(data + from, len - from, 0);
    if (used == socketley::line_framing_stopped)
        return;
    partial.append(data + from + used, len - from - used);
}

// Bytes copied into partial before any callback runs, for read_buf, which a
// callback may arm the next read into.
void client_instance::read_through_partial(const char* data, size_t len)
{
    const size_t scanned = m_conn->partial.size();
    m_conn->partial.append(data, len);
    deliver_partial(scanned);
}

// Ciphertext in, and whatever plaintext tls_feed put into partial framed as
// the copying path frames it.
void client_instance::read_tls(const char* data, size_t len)
{
    const size_t scanned = m_conn->partial.size();
    tls_feed(data, len);

    // A send-only TLS client reads because the record layer has to, so the
    // application data is dropped here rather than parsed -- otherwise --tls
    // would quietly start delivering what `--mode out` says no to.
    if (m_mode == client_mode_out)
    {
        m_conn->partial.clear();
        return;
    }
    deliver_partial(scanned);
}

// The two read_pending guards defer a teardown to an armed read, which
// conn_reachability.h refuses.  They were left alone on the read being
// single-shot; it is multishot now, so that premise is gone and this is what
// replaced it.  read_pending is true in both designs whenever this function
// runs -- the only window where a single-shot read clears it is inside
// handle_read, and no completion interleaves on one thread -- and the teardown
// a closing connection depends on is in handle_read's tail, which asks about
// write_pending rather than read_pending.  Measured under the shape the
// single-shot commit predicted would strand: a peer that RSTs every dial, 45
// seconds, 37 dials on each arm and the runtime answering the daemon on both.
void client_instance::handle_write(struct io_uring_cqe* cqe)
{
    m_conn->write_pending = false;

    // A zero-length datagram reports 0 written and that is the whole message,
    // so `self.send("")` on a UDP client used to close its own socket.
    const bool empty_datagram_sent =
        (cqe->res == 0 && m_udp && m_conn->write_buf.empty());

    if (cqe->res < 0 || (cqe->res == 0 && !empty_datagram_sent))
    {
        // Said, because a connection this runtime drops must not vanish quietly:
        // test_client_can_pace_its_sends.sh lost one here about one run in six and
        // the daemon log carried nothing at all -- the callback it was waiting for
        // could not fire because there was nothing left to drain, and stats read
        // connections:0 with no reason anywhere.
        char why[128];
        std::snprintf(why, sizeof why,
                      "client: write failed (%s), dropping the connection with "
                      "%zu bytes still queued",
                      cqe->res < 0 ? std::strerror(-cqe->res) : "peer closed",
                      m_write_queue.bytes());
        LOG_WARN(why);
        m_conn->closing = true;
        if (!m_conn->read_pending)
            drop_connection();
        return;
    }

    note_established();
    stat_add(m_stat_bytes_out, static_cast<uint64_t>(cqe->res));

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

void client_instance::handle_timeout(struct io_uring_cqe* cqe, io_request* req)
{
    // Told apart by the request the ring names rather than by state: the
    // handshake deadline fires while m_connected is true, and the reconnect
    // clock's own guard below reads that as a timer to ignore.
    if (m_conn && req == &m_conn->hs_req)
    {
        m_conn->hs_armed = false;
        if (cqe->res != -ETIME && cqe->res != 0)
            return;
        // Finished, or the socket went while this was in flight.
        if (m_conn->tls_state != tls_conn_handshake)
            return;
        LOG_ERROR("client: the target accepted the connection and did not finish the "
                  "TLS handshake — dropped, so --reconnect applies to it");
        drop_connection();
        return;
    }

    m_reconnect_pending = false;

    // io_uring timeout fires with -ETIME on expiration
    if (cqe->res != -ETIME && cqe->res != 0)
        return;

    // A timer that outlived what it was waiting for, since dialling again here
    // would overwrite m_conn->fd and leak the one it replaced.
    if (m_connected)
        return;

    // A poll for a name is no attempt, so it spends none of --reconnect.
    if (!m_resolving)
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
    stat_add(m_stat_total_messages, 1);
    print_bash_message(msg);
    write_received_message(msg);
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
        // The same queue the TCP arm below uses, minus the newline, because a
        // datagram frames itself.  Without a queue every send made while a
        // write was in flight was dropped and still answered true -- and no
        // CQE can arrive during a callback, so "a second message in the same
        // callback" was the ordinary case rather than the exception: a script
        // sending ten lines from on_connect delivered one.
        if (m_conn->closing)
            return false;

        if (m_conn->write_pending)
        {
            // The bound is memory and not entries, on the same reasoning the
            // TCP arm gives below.
            if (m_write_queue.bytes() >= write_buffer_bytes())
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
            // push and not push_coalesced, which the TCP arm below uses: an
            // entry here is a datagram, so merging two of them delivers one
            // message where the script sent two.  Caught by
            // test_udp_client_sends.sh at 2 of 10 -- and the same fact is
            // written three functions away in udp_broadcast(), which has no
            // queue at all for exactly this reason.
            if (m_write_queue.bytes() + msg.size()
                >= write_watermark_bytes())
                m_drain_wanted = true;
            m_write_queue.push(std::string(msg.data(), msg.size()));
            return true;
        }

        m_conn->write_buf.assign(msg.data(), msg.size());
        m_conn->write_off = 0;
        arm_write(m_conn->write_buf.data(),
                  static_cast<uint32_t>(m_conn->write_buf.size()));
        return true;
    }

    // Queued when a write is in flight, or always on a TLS connection, because
    // tls_flush is the only thing allowed to put a record on the wire and an
    // SSL asked to write mid-handshake answers WANT_READ.
    //
    // Asked of m_tls and not of m_conn->ssl: the two disagree for exactly one
    // window, between try_connect() reaching `connected:` and start_tls()
    // creating the SSL, and on_connect runs inside it.  A script sending from
    // there took the plain arm and put its payload on the wire in the clear,
    // ahead of the ClientHello -- which the peer reads as a record content
    // type of 'S' and aborts, so the handshake never completed either.
    // tls_flush() already holds what is queued until the handshake is done.
    if (m_tls || m_conn->ssl || m_conn->write_pending || m_conn->closing)
    {
        if (!m_conn->closing)
        {
            // The bound is memory and not entries, because an entry cap
            // dropped 20-byte lines after 80 KB and let megabyte payloads
            // queue gigabytes.
            if (m_write_queue.bytes() >= write_buffer_bytes())
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
            // Judged on the size the message leaves behind, not the one it
            // arrived to: a producer pacing on self.pending() stops on this
            // same number, so arming on the size before the push arms one send
            // too late and that send never comes.
            if (m_write_queue.bytes() + msg.size()
                >= write_watermark_bytes())
                m_drain_wanted = true;
            // The string that was built only to be thrown away: when the
            // tail takes the bytes, push_coalesced appends them and discards
            // what it was handed, so a copy per send bought a newline.  The
            // terminator is still only added when the caller left one off,
            // which push_coalesced_line cannot decide for itself.
            if (!msg.empty() && msg.back() == '\n')
                m_write_queue.push_coalesced(msg, WRITE_COALESCE_LIMIT);
            else
                m_write_queue.push_coalesced_line(msg, WRITE_COALESCE_LIMIT);
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
    arm_handshake_deadline();
    return true;
}

// A flat deadline and not a progress one.  The dump a follower takes can
// legitimately run for minutes, so that deadline had to measure bytes; a
// handshake is bounded by round trips rather than by data, and no real peer
// spends half a minute on one.
void client_instance::arm_handshake_deadline()
{
    if (!m_loop || !m_conn)
        return;
    if (m_conn->hs_armed)
    {
        // An earlier socket's deadline is withdrawn, and its settling arms this one's.
        if (m_conn->hs_req.generation != m_conn_generation && !m_loop->submit_timeout_remove(&m_conn->hs_req))
            LOG_WARN("client: an earlier handshake deadline could not be withdrawn — this "
                     "connection's own is armed when that one fires");
        return;
    }

    m_conn->hs_ts.tv_sec  = tls_handshake_deadline_secs;
    m_conn->hs_ts.tv_nsec = 0;
    m_conn->hs_req = { this, nullptr, -1, 0, op_timeout, m_conn_generation };
    m_conn->hs_armed = m_loop->submit_timeout(&m_conn->hs_ts, &m_conn->hs_req);
    if (SOCKETLEY_UNLIKELY(!m_conn->hs_armed))
        LOG_ERROR("client: the handshake deadline could not be submitted — a target that "
                  "accepts and never handshakes will not be dropped");
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
                                   read_buffer_bytes()))
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
        // Room for the records of what is queued, as the proxy reserves it, so the write BIO does not regrow from empty.
        if (!m_write_queue.empty())
        {
            const size_t plain = std::min<size_t>(m_write_queue.bytes(),
                                                  tls_context::max_bio_buffered + m_write_queue.front().size());
            tls_context::reserve_out(m_conn->ssl, plain + plain / 16384 * 22 + 64);
        }
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
        // the same latch the cleartext path lowers in flush_queued_write, and
        // the same crossing noted for on_writable.
        if (m_write_queue.bytes() < write_watermark_bytes())
        {
            m_write_queue_full = false;
            if (m_drain_wanted) { m_drain_wanted = false; m_drain_due = true; }
        }
    }

    if (!tls_context::has_pending_out(m_conn->ssl))
        return;

    // Ciphertext taken out of the write BIO into write_buf rather than
    // pointed at, because the BIO's storage moves as OpenSSL writes the next
    // record -- and taking it is what keeps the SSL free of anything the ring
    // can name.
    std::string cipher;
    if (SOCKETLEY_UNLIKELY(tls_context::take_out(m_conn->ssl, cipher) == 0))
        return;

    // Nothing is in flight (checked above), so write_buf is this function's to
    // take: whatever was in it belongs to a write that has already completed.
    m_conn->write_buf = std::move(cipher);
    m_conn->write_off = 0;
    arm_write(m_conn->write_buf.data(), static_cast<uint32_t>(m_conn->write_buf.size()));
}
