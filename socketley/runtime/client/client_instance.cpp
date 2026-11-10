#include "../../shared/net/socket_tuning.h"
#include "client_instance.h"
#include "../../shared/net/unix_listener.h"
#include "../../shared/net/dial_address.h"
#include "../../shared/loop/event_loop.h"
#include "../../shared/util/logging.h"
#include "../../shared/crypto/tls_context.h"
#include "../../shared/loop/line_framing.h"
#include "../../shared/lua/lua_context.h"

#include <unistd.h>
#include <cstring>
#include <iostream>
#include <chrono>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <algorithm>

client_instance::client_instance(std::string_view name)
    : runtime_instance(runtime_client, name), m_mode(client_mode_inout), m_loop(nullptr)
{
    m_slots.push_back(std::make_unique<conn_t>());
}

client_instance::~client_instance()
{
    for (auto& conn : m_slots)
    {
        if (conn->fd >= 0)
        {
            shutdown(conn->fd, SHUT_RDWR);
            close_tracked(conn->fd);
        }
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
        for (auto& conn : m_slots)
            arm_read(conn.get());
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
    return m_up;
}

size_t client_instance::total_queued_bytes() const
{
    size_t sum = 0;
    for (const auto& conn : m_slots)
        sum += conn->write_queue.bytes();
    return sum;
}

void client_instance::set_connections(uint32_t n)
{
    m_connections = std::clamp<uint32_t>(n, 1, max_connections_held);
    // Stopped, the slots follow at the next setup.
    if (!m_loop)
        return;
    // m_loop asked each time round, because an on_disconnect the closing runs may stop this runtime.
    while (m_loop && m_slots.size() > m_connections)
    {
        close_slot(m_slots.back().get());
        retire(std::move(m_slots.back()));
        m_slots.pop_back();
    }
    while (m_loop && m_slots.size() < m_connections)
        open_slot();
}

void client_instance::open_slot()
{
    auto fresh = std::make_unique<conn_t>();
    fresh->slot = static_cast<uint32_t>(m_slots.size());
    fresh->generation = next_io_generation();
    conn_t* conn = fresh.get();
    m_slots.push_back(std::move(fresh));
    // A dial refused on the spot is retried on the backoff, as a reconnect is.
    if (!try_connect(conn) && !schedule_reconnect(conn))
        give_up(conn);
}

// The callback runs while the slot is still in m_slots, so a send from it still finds its connection.
void client_instance::close_slot(conn_t* conn)
{
    if (conn->fd >= 0)
    {
        {
            current_scope cs(*this, conn);
            invoke_on_disconnect(conn->fd, id_of(conn));
        }
        // Stopped from the callback: teardown() has closed the socket and withdrawn the clocks with a loop to do it on.
        if (!m_loop)
            return;
        shutdown(conn->fd, SHUT_RDWR);
        close_tracked(conn->fd);
        conn->fd = -1;
    }
    tls_release(conn);
    mark_down(conn);
    if (conn->gave_up)
    {
        conn->gave_up = false;
        --m_gave_up;
    }
    // Neither clock hangs off a descriptor, so the close above does not reach them.
    if (conn->reconnect_pending && !m_loop->submit_timeout_remove(&conn->timeout_req))
        LOG_WARN("client: a closed connection's reconnect timer could not be withdrawn; it is dropped when it fires");
    if (conn->hs_armed && !m_loop->submit_timeout_remove(&conn->hs_req))
        LOG_WARN("client: a closed connection's handshake deadline could not be withdrawn; it is dropped when it fires");
    conn->write_queue.clear();
    conn->partial.clear();
    conn->closing = false;
    conn->drain_due = false;
    conn->drain_wanted = false;
    conn->generation = next_io_generation();
}

void client_instance::retire(std::unique_ptr<conn_t> conn)
{
    if (conn && owes_completions(conn.get()))
        keep_spent(std::move(conn));
}

// Each spent struct knows its place, so its last completion takes it out in constant time however many a shrink left.
void client_instance::keep_spent(std::unique_ptr<conn_t> conn)
{
    conn->spent_at = static_cast<uint32_t>(m_conn_spent.size());
    m_conn_spent.push_back(std::move(conn));
}

void client_instance::drop_spent(conn_t* conn)
{
    const uint32_t at = conn->spent_at;
    if (at >= m_conn_spent.size() || m_conn_spent[at].get() != conn)
        return;
    if (at + 1 != m_conn_spent.size())
    {
        m_conn_spent[at] = std::move(m_conn_spent.back());
        m_conn_spent[at]->spent_at = at;
    }
    m_conn_spent.pop_back();
}

void client_instance::mark_dialled(conn_t* conn)
{
    if (!conn->connected)
    {
        conn->connected = true;
        ++m_up;
    }
    conn->counted = false;
    m_count_due = true;
}

void client_instance::mark_down(conn_t* conn)
{
    if (conn->connected)
    {
        conn->connected = false;
        --m_up;
    }
}

// mark_failed() only once no slot is left that would ever dial again, which for one connection is the first to give up.
void client_instance::give_up(conn_t* conn)
{
    if (!conn->gave_up)
    {
        conn->gave_up = true;
        ++m_gave_up;
    }
    if (m_gave_up >= m_slots.size())
        mark_failed();
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

bool client_instance::try_connect(conn_t* conn, bool at_start)
{
    conn->resolving = false;
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
        conn->fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (conn->fd < 0)
            return false;
        socketley::unix_sock::tune_stream(conn->fd);

        struct sockaddr_un uaddr{};
        const socklen_t ulen = socketley::unix_sock::fill_addr(upath, uaddr);
        // A non-blocking AF_UNIX connect either completes now or fails now,
        // EAGAIN included, because unlike EINPROGRESS nothing will finish it
        // later.
        if (connect(conn->fd, reinterpret_cast<struct sockaddr*>(&uaddr), ulen) < 0)
        {
            close_tracked(conn->fd);
            conn->fd = -1;
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

    conn->fd = socket(AF_INET,
                      (m_udp ? SOCK_DGRAM : SOCK_STREAM) | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (conn->fd < 0)
        return false;

    tune_client_socket(conn->fd, m_udp);

    // Try cached DNS result first (same host:port)
    if (m_has_cached_addr && m_cached_host == host && m_cached_port == port)
    {
        int connect_ret = connect(conn->fd, reinterpret_cast<struct sockaddr*>(&m_cached_addr), sizeof(m_cached_addr));
        if (connect_ret == 0 || errno == EINPROGRESS)
            goto connected;

        // Cached address failed — clear cache, fall through to fresh resolve
        m_has_cached_addr = false;
        m_cached_host.clear();
        m_cached_port = 0;

        // Need a new socket since connect() may have tainted the old one
        close_tracked(conn->fd);
        conn->fd = socket(AF_INET,
                      (m_udp ? SOCK_DGRAM : SOCK_STREAM) | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (conn->fd < 0)
            return false;
        tune_client_socket(conn->fd, m_udp);
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

            int connect_ret = connect(conn->fd, reinterpret_cast<struct sockaddr*>(&lit), sizeof(lit));
            if (connect_ret < 0 && errno != EINPROGRESS)
            {
                close_tracked(conn->fd);
                conn->fd = -1;
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
    conn->resolving = st == socketley::async_resolver::state::pending;
    if (st != socketley::async_resolver::state::ready || found.empty() ||
        found.front().len != sizeof(struct sockaddr_in))
    {
        close_tracked(conn->fd);
        conn->fd = -1;
        return false;
    }

    std::memcpy(&m_cached_addr, &found.front().addr, sizeof(m_cached_addr));
    m_cached_addr.sin_port = htons(port);
    m_cached_host = host;
    m_cached_port = port;
    m_has_cached_addr = true;

    int connect_ret = connect(conn->fd, reinterpret_cast<struct sockaddr*>(&m_cached_addr), sizeof(m_cached_addr));

    if (connect_ret < 0 && errno != EINPROGRESS)
    {
        close_tracked(conn->fd);
        conn->fd = -1;
        return false;
    }
    }

connected:
    mark_dialled(conn);
    // Everything armed from here on says it belongs to this socket.
    conn->generation = next_io_generation();
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
    conn->partial.clear();
    // Not with --connections, where it would be 64 KB a connection held for a line that is usually never split.
    if (m_connections == 1)
        conn->partial.reserve(65536);
    // Before the callback and not after it, because on_connect sends and
    // lua_send refuses on `closing` -- which drop_connection() never lowers.
    // The first reconnect after a failed write therefore ran the callback with
    // the dead socket's flag still up, queued nothing, and answered the script
    // "not connected" on a connection that was up; one line later it was false
    // and every later send worked.
    conn->closing = false;
    {
        current_scope cs(*this, conn);
        invoke_on_connect(conn->fd, id_of(conn));
    }

    // The session goes on the socket before anything is read from it, and a
    // failure costs the socket -- there is deliberately no path from a refused
    // session to a cleartext dial.
    if (m_tls && !start_tls(conn))
    {
        drop_connection(conn);
        return false;
    }

    // read_pending and write_pending are deliberately left alone, because a
    // previous socket's operation can still hold one of the two requests and
    // arming again would point a second kernel read at the same buffer.
    arm_read(conn);
    flush_queued_write(conn);

    return conn->connected;
}

// The one place a read is armed, never while one already is, because both
// would write into conn->read_buf.
void client_instance::arm_read(conn_t* conn, bool poll_first)
{
    if (!m_loop || !conn->connected || conn->closing || conn->fd < 0)
        return;
    if (conn->read_pending)
        return;
    // A TLS connection always reads even in `--mode out`, because the
    // handshake, alerts and session tickets arrive on this socket, and
    // handle_read drops the plaintext instead.
    if (m_mode == client_mode_out && !conn->ssl)
        return;

    conn->read_req = { this, reinterpret_cast<char*>(conn), conn->fd, conn_t::READ_BUF_SIZE, op_read,
                       conn->generation };
    // One submission for a stream of messages rather than one per message.
    // Measured on a server's read path, which has the same shape, driven by a
    // single pipelined connection: 7 of 7 interleaved passes with the order
    // rotated, spread [1.024, 1.051] against a noise floor of [0.998, 0.999].
    if (m_recv_multishot)
        conn->read_pending = m_loop->submit_recv_multishot(conn->fd, BUF_GROUP_ID, &conn->read_req);
    if (!conn->read_pending && m_use_provided_bufs)
        conn->read_pending = m_loop->submit_read_provided(conn->fd, BUF_GROUP_ID, &conn->read_req,
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
    if (!conn->read_pending)
        submit_plain_read(conn, poll_first);

    // Nothing reached the ring at all, so no completion will arrive for this
    // socket and nothing would ever wake this client again; it would sit
    // connected and deaf until the runtime stopped.
    if (!conn->read_pending)
        drop_connection(conn);
}

bool client_instance::submit_plain_read(conn_t* conn, bool poll_first)
{
    if (!conn->read_buf)
        conn->read_buf = std::make_unique_for_overwrite<char[]>(conn_t::READ_BUF_SIZE);
    conn->read_req.type = op_read;
    conn->read_pending = m_loop->submit_read(conn->fd, conn->read_buf.get(), conn_t::READ_BUF_SIZE,
                                             &conn->read_req, poll_first);
    return conn->read_pending;
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
// Above the limit the queue stops merging, and by then each entry is 1 MiB or
// more, which amortises a submission on its own.
//
// Measured, one line answered with a burst of K and the next burst sent only
// after K replies: 7.65 us of CPU per message at K=1, 4.29 at K=4 and 1.28 at
// K=16, spreads of 1 to 2 per cent.  A client that armed one write per message
// could not fall like that.
void client_instance::arm_write(conn_t* conn, const char* data, uint32_t len)
{
    conn->write_req = { this, reinterpret_cast<char*>(conn), conn->fd, len, op_write,
                        conn->generation };
    conn->write_pending = m_loop->submit_write(conn->fd, data, len, &conn->write_req);

    // Nothing reached the ring: no completion will come, so nothing would ever
    // drain what is queued behind this message.
    if (!conn->write_pending)
        drop_connection(conn);
}

void client_instance::flush_queued_write(conn_t* conn)
{
    if (!m_loop || !conn->connected || conn->write_pending)
        return;

    // A TLS connection's bytes go through the record layer, checked ahead of
    // `closing` because a session on its way down still owes the peer the
    // alert that says why.
    if (conn->ssl)
    {
        tls_flush(conn);
        return;
    }

    if (conn->closing || conn->write_queue.empty())
        return;

    m_direct_gate.admit(conn->fd);
    conn->write_buf = conn->write_queue.take_front();
    // Once there is room again, a later stall is worth reporting afresh.
    if (conn->write_queue.bytes() < write_watermark_bytes())
    {
        conn->queue_full = false;
        // The same crossing, read for the other purpose: a producer that
        // stopped at the watermark is owed a call.
        if (conn->drain_wanted) { conn->drain_wanted = false; conn->drain_due = true; m_drain_any = true; }
    }
    conn->write_off = 0;
    arm_write(conn, conn->write_buf.data(), static_cast<uint32_t>(conn->write_buf.size()));
}

long client_instance::pending_bytes() const
{
    if (m_cur >= 0 && static_cast<size_t>(m_cur) < m_slots.size())
        return static_cast<long>(m_slots[static_cast<size_t>(m_cur)]->write_queue.bytes());
    return static_cast<long>(total_queued_bytes());
}

long client_instance::pending_bytes_of(int id) const
{
    const conn_t* conn = slot_of_id(id);
    return conn ? static_cast<long>(conn->write_queue.bytes()) : -1;
}

void client_instance::on_loop_turn()
{
    // A connection that is up and silent is still a connection, and no
    // completion will ever report one -- so the kernel is asked here, which is
    // also the last thing that runs before a turn publishes its figures.
    if (SOCKETLEY_UNLIKELY(m_count_due))
    {
        bool still = false;
        for (auto& conn : m_slots)
        {
            if (conn->connected && !conn->counted)
            {
                note_connected(conn.get());
                still |= !conn->counted;
            }
        }
        m_count_due = still;
    }

    if (SOCKETLEY_UNLIKELY(m_drain_any))
    {
        m_drain_any = false;
        // By index, because the callback may send and a send never adds or removes a slot.
        for (size_t i = 0; i < m_slots.size(); ++i)
        {
            conn_t* conn = m_slots[i].get();
            if (!conn->drain_due)
                continue;
            conn->drain_due = false;
            current_scope cs(*this, conn);
            invoke_on_writable(id_of(conn));
        }
    }
    m_direct_gate.next_turn();
}

// Losing the socket: one teardown, reached from every path that loses it.
void client_instance::drop_connection(conn_t* conn)
{
    if (conn->fd >= 0)
    {
        {
            current_scope cs(*this, conn);
            invoke_on_disconnect(conn->fd, id_of(conn));
        }
        // close_slot()'s reason: a stop from the callback has done the rest, and there is no loop to reconnect on.
        if (!m_loop)
            return;
        shutdown(conn->fd, SHUT_RDWR);
        close_tracked(conn->fd);
        conn->fd = -1;
    }
    tls_release(conn);
    mark_down(conn);
    // A refused timer has nowhere to recover to, and mark_failed() is
    // authoritative in the daemon and worker-local everywhere else -- so out
    // here the log is the report, which is a gap named rather than closed.
    if (!schedule_reconnect(conn))
        give_up(conn);
}

// A session belongs to one socket and dies with it, safe to release with a
// write in flight because the ciphertext lives in write_buf and nothing inside
// the SSL is ever named by an SQE.
void client_instance::tls_release(conn_t* conn)
{
    if (conn->ssl)
    {
        // What the socket leaves behind: the context keeps this session so the
        // next dial resumes instead of paying a second full handshake.  Only
        // from a connection that reached tls_conn_ready, because a handshake
        // that never finished verified nobody.
        if (m_tls && conn->tls_state == tls_conn_ready)
            m_tls->remember_session(m_tls_peer_name, conn->ssl);
        tls_context::free_ssl(conn->ssl);
        conn->ssl = nullptr;
    }
    conn->tls_state = tls_conn_none;
    conn->tls_peer_closed = false;
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
void client_instance::settle_stale(conn_t* conn, struct io_uring_cqe* cqe, io_request* req)
{
    return_provided_buf(cqe);

    if (req == &conn->read_req)
    {
        if (!(cqe->flags & IORING_CQE_F_MORE))
            conn->read_pending = false;
    }
    else if (req == &conn->write_req)
    {
        conn->write_pending = false;
    }
    else if (req == &conn->timeout_req)
    {
        conn->reconnect_pending = false;
    }
    else if (req == &conn->hs_req)
    {
        conn->hs_armed = false;
        // The deadline an earlier socket left standing kept this one from arming its own.
        if (is_current(conn) && conn->connected && conn->tls_state == tls_conn_handshake)
            arm_handshake_deadline(conn);
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
void client_instance::note_connected(conn_t* conn)
{
    struct sockaddr_storage peer{};
    socklen_t len = sizeof(peer);
    if (conn->fd < 0
        || getpeername(conn->fd, reinterpret_cast<struct sockaddr*>(&peer), &len) < 0)
        return;

    // Per socket, because this runs every turn until it is true and a client
    // that reconnects all day must count connections and not turns.
    conn->counted = true;
    stat_add(m_stat_total_connections, 1);
}

// A completion carrying bytes is the first thing that proves the peer accepted
// the connection rather than that the kernel accepted the SQE, and it is where
// the backoff and the --reconnect limit start counting from again.
void client_instance::note_established(conn_t* conn)
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
    if (conn->tls_state == tls_conn_handshake)
        return;

    conn->reconnect_attempt = 0;
}

// True means something will bring this client back rather than that a timer
// was submitted, because three of the four exits owe nothing and only a
// refused submission means nothing will ever run again.
bool client_instance::schedule_reconnect(conn_t* conn)
{
    // A name still being looked up is asked again shortly, whatever --reconnect says, since no dial has failed yet.
    if (conn->resolving && m_loop)
    {
        if (conn->reconnect_pending)
            return true;
        conn->timeout_ts.tv_sec = 0;
        conn->timeout_ts.tv_nsec = 100000000LL;
        conn->timeout_req = { this, reinterpret_cast<char*>(conn), -1, 0, op_timeout, conn->generation };
        conn->reconnect_pending = m_loop->submit_timeout(&conn->timeout_ts, &conn->timeout_req);
        if (!conn->reconnect_pending)
            LOG_ERROR("client: the timer that waits for the target's name could not be submitted");
        return conn->reconnect_pending;
    }

    int max = get_reconnect();
    if (max < 0 || !m_loop)
        return true; // Reconnect disabled: nothing to arm, nothing wrong

    if (max > 0 && conn->reconnect_attempt >= max)
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
    if (conn->reconnect_pending)
        return true; // Already armed — that IS the clock running

    // Exponential backoff: 1, 2, 4, 8 and then 16 seconds for ever, plus up to
    // half a second of jitter -- the shift's own cap is the ceiling, and the
    // std::min(base, 30) that used to stand beside it could never bind.
    int delay_sec = 1 << std::min(conn->reconnect_attempt, 4);
    // Time-based jitter: 0-499ms (avoids thundering herd with deterministic values)
    auto ns = std::chrono::steady_clock::now().time_since_epoch().count();
    int jitter_ms = static_cast<int>((ns ^ (ns >> 17)) % 500);

    conn->timeout_ts.tv_sec = delay_sec;
    conn->timeout_ts.tv_nsec = jitter_ms * 1000000LL;

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

    conn->timeout_req = { this, reinterpret_cast<char*>(conn), -1, 0, op_timeout, conn->generation };
    conn->reconnect_pending = m_loop->submit_timeout(&conn->timeout_ts, &conn->timeout_req);

    // A refused timer here is the end of this client, because all three
    // callers are fire-and-forget, and it is said in words rather than as a
    // code the operator cannot see.
    if (!conn->reconnect_pending)
        LOG_ERROR("client: the reconnect timer could not be submitted — this "
                  "client is disconnected and will not dial again on its own; "
                  "restart the runtime");

    return conn->reconnect_pending;
}

bool client_instance::setup(event_loop& loop)
{
    m_loop = &loop;
    m_ring_loop = &loop;
    // Clients are made one per connection and many share a core, where a spin only takes the core from the others.
    loop.set_busy_spin(false);

    // The occupied flags survive a stop, because a deregistered owner's
    // completions are dropped and never lower them, so this asks the loop --
    // zero frees the old structs, non-zero takes a fresh one for each slot
    // still occupied, and a full owner table takes the conservative branch.
    const bool drained = loop.owner_drained(this);
    if (drained)
        m_conn_spent.clear();
    for (auto& conn : m_slots)
    {
        if (drained)
        {
            conn->read_pending      = false;
            conn->write_pending     = false;
            conn->reconnect_pending = false;
            // Nothing is owed, so a deadline still marked armed is one whose completion was dropped.
            conn->hs_armed          = false;
        }
        else if (conn->read_pending || conn->write_pending || conn->reconnect_pending)
        {
            const uint32_t slot = conn->slot;
            keep_spent(std::move(conn));
            conn = std::make_unique<conn_t>();
            conn->slot = slot;
        }
    }
    while (m_slots.size() > m_connections)
    {
        retire(std::move(m_slots.back()));
        m_slots.pop_back();
    }
    while (m_slots.size() < m_connections)
    {
        m_slots.push_back(std::make_unique<conn_t>());
        m_slots.back()->slot = static_cast<uint32_t>(m_slots.size() - 1);
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

    // A start is a new --reconnect budget, for every slot.
    m_gave_up = 0;
    m_cur = -1;
    m_rr = 0;
    for (auto& conn : m_slots)
    {
        conn->reconnect_attempt = 0;
        conn->gave_up = false;
    }

    if (m_connections == 1)
        m_use_provided_bufs = loop.setup_buf_ring(BUF_GROUP_ID, BUF_COUNT, BUF_SIZE, BUF_SIZE / BUF_HEADROOM_SHARE);
    else
    {
        // A power of two, as the ring requires, of at least one buffer a connection, smaller as there are more so
        // the pool stays under the 2 MB at which the loop asks for huge pages and every page of it is resident.
        uint32_t count = BUF_COUNT;
        while (count < m_connections && count < MULTI_BUF_MAX)
            count <<= 1;
        const uint32_t size = std::clamp<uint32_t>(MULTI_BUF_POOL / count, MULTI_BUF_MIN, MULTI_BUF_SIZE);
        m_use_provided_bufs = loop.setup_buf_ring(BUF_GROUP_ID, count, size, size / BUF_HEADROOM_SHARE);
    }
    // Needs the ring, because a multishot recv selects its buffer from one.
    m_recv_multishot = m_use_provided_bufs && loop.recv_multishot_enabled();

    // The first connection decides whether the start succeeded, as the only one always has; a later one refused on
    // the spot is retried on the backoff.
    conn_t* const first = m_slots.front().get();
    if (!try_connect(first, /*at_start=*/true))
    {
        // Checked, because "we'll connect later" is only true if the clock
        // that makes it later was actually armed.
        if (get_reconnect() < 0 || !schedule_reconnect(first))
            return false;
    }
    for (size_t i = 1; i < m_slots.size() && m_loop; ++i)
    {
        conn_t* conn = m_slots[i].get();
        if (!try_connect(conn, /*at_start=*/true) && !schedule_reconnect(conn))
            give_up(conn);
    }

    return true;
}

void client_instance::teardown(event_loop& loop)
{
    bool withdrew = false;
    for (auto& owned : m_slots)
    {
        conn_t* conn = owned.get();
        // Drain write queue
        conn->write_queue.clear();
        conn->queue_full = false;
        conn->drain_wanted = false;
        conn->drain_due = false;

        if (conn->fd >= 0)
        {
            // close_fd submits the cancel and holds the number until both
            // operations report, because this runtime reuses one read and one
            // write request and the kernel hands the socket number straight back
            // on the next connect.
            shutdown(conn->fd, SHUT_RDWR);
            close_tracked(conn->fd);
            conn->fd = -1;
        }

        // The socket is gone so the session is finished, released here because
        // this struct can outlive the stop and a session held across a start is a
        // handshake the next peer never heard of.
        tls_release(conn);

        // The reconnect timer is attached to no fd, so the cancel could not reach
        // it and the ring would owe this owner a completion for up to thirty
        // seconds -- during which a removed runtime is never freed.
        if (conn->reconnect_pending)
        {
            if (!loop.submit_timeout_remove(&conn->timeout_req))
                LOG_WARN("client: the reconnect timer withdrawal did not reach the ring — "
                         "this instance stays retired until the timer fires on its own");
            withdrew = true;
        }

        // The same reasoning for the handshake deadline, which hangs off no
        // descriptor either.
        if (conn->hs_armed)
        {
            if (!loop.submit_timeout_remove(&conn->hs_req))
                LOG_WARN("client: the handshake deadline withdrawal did not reach the ring — "
                         "this instance stays retired until the timer fires on its own");
            withdrew = true;
        }

        // Its request keeps its owner, because the loop reads the request when the
        // completion lands, and the pending flags are left standing since a
        // withdrawn timeout is still owed exactly one.
        mark_down(conn);
        conn->closing = false;
        conn->partial.clear();
        // Nothing armed before this stop belongs to anything that comes after it,
        // including a start() that fails to connect and so never stamps a new
        // socket of its own.
        conn->generation = next_io_generation();
    }
    if (withdrew)
        loop.flush();
    m_drain_any = false;
    m_count_due = false;
    m_loop = nullptr;
}

void client_instance::on_cqe(struct io_uring_cqe* cqe)
{
    auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
    if (!req || !req->buffer)
        return;
    conn_t* const conn = conn_of(req);

    // Stopped, belonging to a socket already lost, or to a struct a shrink or
    // a restart left behind: not acted on but settled, because the descriptor
    // number alone cannot tell these apart.
    if (!m_loop || req->generation != conn->generation || !is_current(conn))
    {
        settle_stale(conn, cqe, req);
        if (is_current(conn))
        {
            // Whatever that completion was occupying is free now, and the current
            // socket may have been waiting on exactly that.
            arm_read(conn);
            flush_queued_write(conn);
        }
        else if (!owes_completions(conn))
        {
            // Its last completion, so nothing names it any more.
            drop_spent(conn);
        }
        return;
    }

    switch (req->type)
    {
        case op_read:
        case op_read_provided:
        case op_recv_multishot:
            handle_read(conn, cqe);
            break;
        case op_write:
            handle_write(conn, cqe);
            break;
        case op_timeout:
            handle_timeout(conn, cqe, req);
            break;
        default:
            break;
    }
}

void client_instance::handle_read(conn_t* conn, struct io_uring_cqe* cqe)
{
    // Every callback this read reaches runs for this connection.
    current_scope cs(*this, conn);

    // A multishot arm still standing is NOT a re-arm this client owes: the
    // kernel delivers again without being asked, and clearing the flag here
    // would let arm_read() put a second recv on the same socket and the same
    // buffer.  arm_read() at the bottom of this function then declines on its
    // own, which is how one path serves both.
    const bool multishot = is_multishot_recv_op(conn->read_req.type);
    const bool more      = multishot && (cqe->flags & IORING_CQE_F_MORE);
    if (!more)
        conn->read_pending = false;

    bool is_provided = (conn->read_req.type == op_read_provided || multishot);

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
            if (!submit_plain_read(conn, false))
                drop_connection(conn);
            return;
        }

        // Connection closed or error — defer if write pending
        if (conn->write_pending)
            conn->closing = true;
        else
            drop_connection(conn);
        return;
    }

    note_established(conn);
    stat_add(m_stat_bytes_in, static_cast<uint64_t>(cqe->res));

    if (m_udp)
    {
        // UDP: whole datagram = one message, no line parsing
        const char* buf_data = conn->read_buf.get();
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
                process_message(msg, id_of(conn));

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
                process_message(msg, id_of(conn));
        }
        goto resubmit;
    }

    {
    // Kept apart from m_loop, which a stop inside a callback below nulls
    // while the buffer this read holds is still owed to the group.
    event_loop* const ring = m_loop;
    const size_t len = static_cast<size_t>(cqe->res);
    const uint16_t buf_id = static_cast<uint16_t>(cqe->flags >> IORING_CQE_BUFFER_SHIFT);
    char* data = is_provided ? ring->get_buf_ptr(BUF_GROUP_ID, buf_id)
                                   : conn->read_buf.get();
    if (data)
    {
        // Only a provided buffer is read in place, because nothing can point
        // the kernel at it again before return_buf, while read_buf is re-armed
        // by whatever calls arm_read().
        if (conn->ssl)
            read_tls(conn, data, len);
        else if (is_provided)
            read_in_place(conn, data, len);
        else
            read_through_partial(conn, data, len);

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
    if (conn->ssl)
    {
        if (conn->tls_peer_closed)
            conn->closing = true;
        tls_flush(conn);
    }

    // A connection marked closing with nothing in flight has nobody to notice
    // it, because arm_read() declines while closing, so the client sat
    // connected and deaf and never dialled again.
    if (conn->closing && !conn->write_pending && conn->connected)
    {
        drop_connection(conn);
        return;
    }

    // A datagram socket never reports what it still holds, so there the flag's
    // absence says nothing.
    arm_read(conn, !m_udp && event_loop::recv_drained(cqe));
}

// Whether the socket a read belongs to is still the one being read, asked
// after every delivered line because a script can stop this runtime from
// on_message and every later line of that read was meant for nobody.
// The slot is passed by value and compared before conn is read, because a
// restart from a callback may have retired conn to another list.
bool client_instance::still_reading(const conn_t* conn, uint32_t slot,
                                    uint32_t generation, int fd) const
{
    return slot < m_slots.size() && m_slots[slot].get() == conn && conn->generation == generation
        && conn->fd == fd;
}

bool client_instance::batches_lines() const
{
    return m_mode != client_mode_out && (wants_on_read() || wants_on_messages());
}

size_t client_instance::deliver_chunk(conn_t* conn, const char* data, size_t len, size_t search_from)
{
    const void* nl = search_from < len ? memrchr(data + search_from, '\n', len - search_from) : nullptr;
    if (!nl)
        return 0;
    const size_t end = static_cast<size_t>(static_cast<const char*>(nl) - data) + 1;
    const std::string_view chunk(data, end);

    // Counted and observed before the script runs, so -w, bash output and interactive see what they would see with
    // on_message, even when the script stops this runtime, and counted in one pass where nothing observes.
    // The lines on_message would have been handed, the blank ones it skips left out, so the count does not depend on
    // which of the two the script defines.
    // For on_read the count comes with an index of the lines, which the view then walks without searching, unless
    // a view opened further up the stack is still reading the index.
    const bool view = wants_on_read();
    const bool indexed = view && !m_viewing;
    uint64_t lines = indexed ? socketley::index_lines(data, end, m_line_ends) : 0;
    if (SOCKETLEY_UNLIKELY(observes_messages()))
    {
        uint64_t seen = 0;
        socketley::for_each_line(data, end, 0, [&](std::string_view line)
        {
            ++seen;
            print_bash_message(line);
            write_received_message(line);
            notify_interactive(line);
            return true;
        });
        lines = seen;
    }
    else if (!indexed)
        lines = socketley::count_lines(data, end);
    stat_add(m_stat_total_messages, lines);

    const uint32_t slot = conn->slot;
    const uint32_t generation = conn->generation;
    const int fd = conn->fd;
    {
        current_scope cs(*this, conn);
        // The view reads the bytes where they lie, which stay put until this returns: a provided buffer goes back
        // to its group after the read, and partial is only appended to by a read.
        if (view)
        {
            const bool was_viewing = m_viewing;
            m_viewing = true;
            invoke_on_read(chunk, indexed ? &m_line_ends : nullptr, id_of(conn));
            m_viewing = was_viewing;
        }
        else
            invoke_on_messages(chunk, id_of(conn));
    }
    if (still_reading(conn, slot, generation, fd))
        return end;
    // The same rule deliver_lines() gives for a socket that went under the callback.
    if (slot < m_slots.size() && m_slots[slot].get() == conn && conn->generation == generation)
        conn->partial.clear();
    return socketley::line_framing_stopped;
}

size_t client_instance::deliver_lines(conn_t* conn, const char* data, size_t len, size_t search_from)
{
    if (batches_lines())
        return deliver_chunk(conn, data, len, search_from);

    const uint32_t slot = conn->slot;
    const uint32_t generation = conn->generation;
    const int fd = conn->fd;
    const int id = id_of(conn);
    const size_t used = socketley::for_each_line(data, len, search_from,
        [&](std::string_view line)
        {
            process_message(line, id);
            return still_reading(conn, slot, generation, fd);
        });

    // The socket went and its unfinished line with it, unless a stop or a
    // dial already gave this struct a new generation and cleared it itself.
    if (used == socketley::line_framing_stopped
        && slot < m_slots.size() && m_slots[slot].get() == conn && conn->generation == generation)
        conn->partial.clear();
    return used;
}

// Whether every line in `s`, with its newline, and its unfinished tail fit in `limit` bytes.
static bool lines_fit(std::string_view s, size_t limit)
{
    for (size_t start = 0;;)
    {
        const void* nl = std::memchr(s.data() + start, '\n', s.size() - start);
        if (!nl)
            return s.size() - start <= limit;
        const size_t end = static_cast<size_t>(static_cast<const char*>(nl) - s.data()) + 1;
        if (end - start > limit)
            return false;
        start = end;
    }
}

// The complete lines partial holds, where `scanned` is how much of it an earlier read already searched, and a line or
// an unfinished one over the bound is refused -- not the read that brought it, which may hold many whole lines.
void client_instance::deliver_partial(conn_t* conn, size_t scanned)
{
    std::string& partial = conn->partial;
    if (partial.size() > read_buffer_bytes() && !lines_fit(partial, read_buffer_bytes()))
    {
        conn->closing = true;
        return;
    }

    const size_t used = deliver_lines(conn, partial.data(), partial.size(), scanned);
    if (used == socketley::line_framing_stopped || used == 0)
        return;
    if (used >= partial.size())
        partial.clear();
    else
        partial.erase(0, used);
}

// Lines straight out of a provided buffer, with partial holding only the
// unfinished line on either side of it.
void client_instance::read_in_place(conn_t* conn, char* data, size_t len)
{
    std::string& partial = conn->partial;
    const uint32_t headroom = m_loop ? m_loop->buf_ring_headroom(BUF_GROUP_ID) : 0;

    // Over the bound the copying path refuses it, bytes kept, so every later
    // read on this closing connection is refused too.
    if (partial.size() + len > read_buffer_bytes())
    {
        read_through_partial(conn, data, len);
        return;
    }

    size_t from = 0;
    if (!partial.empty())
    {
        // Through the last newline for on_read and on_messages, so a read is one call however its first line began.
        const bool batch = batches_lines();
        const void* nl = batch ? memrchr(data, '\n', len) : std::memchr(data, '\n', len);
        if (!nl)
        {
            partial.append(data, len);
            return;
        }
        // A batch reader's leftover goes into the free bytes before this buffer, so the read is still one view and
        // only the leftover is copied: the whole read appended behind it was 7% of a client taking 4 KiB lines.
        if (batch && partial.size() <= headroom)
        {
            const size_t kept = partial.size();
            char* const front = data - kept;
            std::memcpy(front, partial.data(), kept);
            partial.clear();
            const size_t used = deliver_lines(conn, front, kept + len, kept);
            if (used != socketley::line_framing_stopped)
                partial.append(front + used, kept + len - used);
            return;
        }
        from = static_cast<size_t>(static_cast<const char*>(nl) - data) + 1;
        const size_t scanned = partial.size();
        partial.append(data, from);
        if (deliver_lines(conn, partial.data(), partial.size(), batch ? scanned : partial.size() - 1)
            == socketley::line_framing_stopped)
            return;
        partial.clear();
    }

    const size_t used = deliver_lines(conn, data + from, len - from, 0);
    if (used == socketley::line_framing_stopped)
        return;
    partial.append(data + from + used, len - from - used);
}

// Bytes copied into partial before any callback runs, for read_buf, which a
// callback may arm the next read into.
void client_instance::read_through_partial(conn_t* conn, const char* data, size_t len)
{
    const size_t scanned = conn->partial.size();
    conn->partial.append(data, len);
    deliver_partial(conn, scanned);
}

// Ciphertext in, and whatever plaintext tls_feed put into partial framed as
// the copying path frames it.
void client_instance::read_tls(conn_t* conn, const char* data, size_t len)
{
    const size_t scanned = conn->partial.size();
    tls_feed(conn, data, len);

    // A send-only TLS client reads because the record layer has to, so the
    // application data is dropped here rather than parsed -- otherwise --tls
    // would quietly start delivering what `--mode out` says no to.
    if (m_mode == client_mode_out)
    {
        conn->partial.clear();
        return;
    }
    deliver_partial(conn, scanned);
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
void client_instance::handle_write(conn_t* conn, struct io_uring_cqe* cqe)
{
    conn->write_pending = false;

    // A zero-length datagram reports 0 written and that is the whole message,
    // so `self.send("")` on a UDP client used to close its own socket.
    const bool empty_datagram_sent =
        (cqe->res == 0 && m_udp && conn->write_buf.empty());

    if (cqe->res < 0 || (cqe->res == 0 && !empty_datagram_sent))
    {
        // Said, because a connection this runtime drops must not vanish quietly:
        // test_client_can_pace_its_sends.sh lost one here about one run in six and
        // the daemon log carried nothing at all -- the callback it was waiting for
        // could not fire because there was nothing left to drain, and stats read
        // connections:0 with no reason anywhere.
        char why[160];
        std::snprintf(why, sizeof why,
                      "client: write failed (%s), dropping the connection%s with "
                      "%zu bytes still queued",
                      cqe->res < 0 ? std::strerror(-cqe->res) : "peer closed",
                      m_slots.size() > 1 ? (" " + std::to_string(id_of(conn))).c_str() : "",
                      conn->write_queue.bytes());
        LOG_WARN(why);
        conn->closing = true;
        if (!conn->read_pending)
            drop_connection(conn);
        return;
    }

    note_established(conn);
    stat_add(m_stat_bytes_out, static_cast<uint64_t>(cqe->res));

    // Resume a short write before moving on to the next message.
    conn->write_off += static_cast<size_t>(cqe->res);
    if (conn->write_off < conn->write_buf.size())
    {
        arm_write(conn, conn->write_buf.data() + conn->write_off,
                  static_cast<uint32_t>(conn->write_buf.size() - conn->write_off));
        return;
    }
    conn->write_off = 0;

    // Flush queued writes before checking closing state, because
    // flush_queued_write is what turns this completion into the next handshake
    // flight.
    flush_queued_write(conn);
    if (conn->write_pending)
        return;

    if (conn->closing && !conn->read_pending && conn->connected)
        drop_connection(conn);
}

void client_instance::handle_timeout(conn_t* conn, struct io_uring_cqe* cqe, io_request* req)
{
    // Told apart by the request the ring names rather than by state: the
    // handshake deadline fires while `connected` is true, and the reconnect
    // clock's own guard below reads that as a timer to ignore.
    if (req == &conn->hs_req)
    {
        conn->hs_armed = false;
        if (cqe->res != -ETIME && cqe->res != 0)
            return;
        // Finished, or the socket went while this was in flight.
        if (conn->tls_state != tls_conn_handshake)
            return;
        LOG_ERROR("client: the target accepted the connection and did not finish the "
                  "TLS handshake — dropped, so --reconnect applies to it");
        drop_connection(conn);
        return;
    }

    conn->reconnect_pending = false;

    // io_uring timeout fires with -ETIME on expiration
    if (cqe->res != -ETIME && cqe->res != 0)
        return;

    // A timer that outlived what it was waiting for, since dialling again here
    // would overwrite conn->fd and leak the one it replaced.
    if (conn->connected)
        return;

    // A poll for a name is no attempt, so it spends none of --reconnect.
    if (!conn->resolving)
        conn->reconnect_attempt++;

    if (try_connect(conn))
        return; // Reconnected successfully

    // Failed, so schedule another attempt, because if the clock cannot be
    // re-armed there is no later attempt to wait for.
    if (!schedule_reconnect(conn))
        give_up(conn);
}

void client_instance::process_message(std::string_view msg, int id)
{
    stat_add(m_stat_total_messages, 1);
    if (SOCKETLEY_UNLIKELY(observes_messages()))
    {
        print_bash_message(msg);
        write_received_message(msg);
        notify_interactive(msg);
    }

    switch (m_mode)
    {
        case client_mode_inout:
        case client_mode_in:
        {
            // A datagram has no read to batch, so on_read and on_messages take it as a chunk of one line.
            if (SOCKETLEY_UNLIKELY(wants_on_read()))
                invoke_on_read(one_line_chunk(msg), nullptr, id);
            else if (SOCKETLEY_UNLIKELY(wants_on_messages()))
                invoke_on_messages(one_line_chunk(msg), id);
            else
                invoke_on_message(msg, id);
            break;
        }
        case client_mode_out:
            break;
        default:
            break;
    }
}

// One connection, or the next connected one after the last this sent on, so
// `socketley send` spreads one message a call over every connection held.
bool client_instance::lua_send(std::string_view msg)
{
    const size_t n = m_slots.size();
    if (n == 1)
        return write_one(m_slots.front().get(), msg);
    for (size_t k = 0; k < n; ++k)
    {
        const size_t i = (m_rr + k) % n;
        if (!m_slots[i]->connected)
            continue;
        m_rr = static_cast<uint32_t>((i + 1) % n);
        return write_one(m_slots[i].get(), msg);
    }
    return false;
}

client_instance::conn_t* client_instance::current_or_only(send_answer& why) const
{
    if (m_cur >= 0 && static_cast<size_t>(m_cur) < m_slots.size())
        return m_slots[static_cast<size_t>(m_cur)].get();
    if (m_slots.size() == 1)
        return m_slots.front().get();
    why = send_answer::no_current;
    return nullptr;
}

client_instance::send_answer client_instance::script_send(std::string_view msg, int id)
{
    send_answer why = send_answer::no_such_id;
    conn_t* conn = id != 0 ? slot_of_id(id) : current_or_only(why);
    if (!conn)
        return why;
    if (write_one(conn, msg))
        return send_answer::sent;
    // The latch is guarded on being connected, so a stall left up is not
    // blamed for a disconnection that happened underneath it.
    return conn->queue_full && conn->connected ? send_answer::backlogged : send_answer::not_connected;
}

// Each condition rules out a step of write_one that can run Lua or answer with a
// sentence -- on_send, the direct send and arm_write whose failure drops the
// connection, a refusal and the bound's latch -- so what is left is the queue
// behind a write in flight, where tls_flush returns at once as well.
bool client_instance::send_if_queued(std::string_view msg, int id)
{
    send_answer why = send_answer::no_such_id;
    conn_t* conn = id != 0 ? slot_of_id(id) : current_or_only(why);
    if (!conn || !m_loop || !conn->connected || m_mode == client_mode_in || conn->closing
        || !conn->write_pending || (lua() && lua()->has_on_send())
        || conn->write_queue.bytes() >= write_buffer_bytes())
        return false;
    // The pushes and not write_one, whose checks this has already made.
    if (m_udp)
        enqueue_datagram(conn, msg);
    else
        enqueue_line(conn, msg);
    return true;
}

// The watermark is judged on the size the message leaves behind, not the one it
// arrived to: a producer pacing on self.pending() stops on this same number, so
// arming on the size before the push arms one send too late and that send never
// comes.
void client_instance::enqueue_line(conn_t* conn, std::string_view msg)
{
    if (conn->write_queue.bytes() + msg.size() >= write_watermark_bytes())
        conn->drain_wanted = true;
    // The string that was built only to be thrown away: when the tail takes
    // the bytes, push_coalesced appends them and discards what it was handed,
    // so a copy per send bought a newline.  The terminator is still only added
    // when the caller left one off, which push_coalesced_line cannot decide
    // for itself.
    if (!msg.empty() && msg.back() == '\n')
        conn->write_queue.push_coalesced(msg, WRITE_COALESCE_LIMIT);
    else
        conn->write_queue.push_coalesced_line(msg, WRITE_COALESCE_LIMIT);
}

// push and not push_coalesced, which the TCP arm uses: an entry here is a
// datagram, so merging two of them delivers one message where the script sent
// two.  Caught by test_udp_client_sends.sh at 2 of 10 -- and the same fact is
// written in udp_broadcast(), which has no queue at all for exactly this
// reason.
void client_instance::enqueue_datagram(conn_t* conn, std::string_view msg)
{
    if (conn->write_queue.bytes() + msg.size() >= write_watermark_bytes())
        conn->drain_wanted = true;
    conn->write_queue.push(std::string(msg.data(), msg.size()));
}

// Whether the message was written or queued, which was void, so self.send()
// reported none of the three ordinary refusals.
bool client_instance::write_one(conn_t* conn, std::string_view msg)
{
    if (!m_loop || !conn->connected || m_mode == client_mode_in)
        return false;

    invoke_on_send(msg, id_of(conn));

    if (m_udp)
    {
        // The same queue the TCP arm below uses, minus the newline, because a
        // datagram frames itself.  Without a queue every send made while a
        // write was in flight was dropped and still answered true -- and no
        // CQE can arrive during a callback, so "a second message in the same
        // callback" was the ordinary case rather than the exception: a script
        // sending ten lines from on_connect delivered one.
        if (conn->closing)
            return false;

        if (conn->write_pending)
        {
            // The bound is memory and not entries, on the same reasoning the
            // TCP arm gives below.
            if (conn->write_queue.bytes() >= write_buffer_bytes())
            {
                if (!conn->queue_full)
                {
                    conn->queue_full = true;
                    std::cerr << "[client] server is not reading ("
                              << conn->write_queue.bytes()
                              << " bytes queued), dropping messages\n";
                }
                return false;
            }
            enqueue_datagram(conn, msg);
            return true;
        }

        conn->write_buf.assign(msg.data(), msg.size());
        conn->write_off = 0;
        arm_write(conn, conn->write_buf.data(),
                  static_cast<uint32_t>(conn->write_buf.size()));
        return true;
    }

    // Queued when a write is in flight, or always on a TLS connection, because
    // tls_flush is the only thing allowed to put a record on the wire and an
    // SSL asked to write mid-handshake answers WANT_READ.
    //
    // Asked of m_tls and not of conn->ssl: the two disagree for exactly one
    // window, between try_connect() reaching `connected:` and start_tls()
    // creating the SSL, and on_connect runs inside it.  A script sending from
    // there took the plain arm and put its payload on the wire in the clear,
    // ahead of the ClientHello -- which the peer reads as a record content
    // type of 'S' and aborts, so the handshake never completed either.
    // tls_flush() already holds what is queued until the handshake is done.
    if (m_tls || conn->ssl || conn->write_pending || conn->closing)
    {
        if (!conn->closing)
        {
            // The bound is memory and not entries, because an entry cap
            // dropped 20-byte lines after 80 KB and let megabyte payloads
            // queue gigabytes.
            if (conn->write_queue.bytes() >= write_buffer_bytes())
            {
                if (!conn->queue_full)
                {
                    conn->queue_full = true;
                    std::cerr << "[client] server is not reading ("
                              << conn->write_queue.bytes()
                              << " bytes queued), dropping messages\n";
                }
                return false;
            }
            enqueue_line(conn, msg);
        }
        // Nothing else will come back for this message on its own, so the
        // record layer is driven from here or the line sits in the queue.
        if (conn->ssl)
            tls_flush(conn);
        // Queued, or dropped because the connection is already closing.
        return !conn->closing;
    }

    // Nothing in flight and the turn's one write, so the socket is tried at once, because through the ring the send's own
    // completion cost every request-answer message a second loop turn; what the socket does not take goes to the ring.
    // Not a second line of the turn: a producer sending in a loop paid a syscall a line and never filled its queue.
    const bool   has_nl = !msg.empty() && msg.back() == '\n';
    ssize_t sent = -1;
    if (m_direct_gate.admit(conn->fd))
    {
        const size_t total  = msg.size() + (has_nl ? 0 : 1);
        struct iovec iov[2] = { { const_cast<char*>(msg.data()), msg.size() },
                                { const_cast<char*>("\n"), 1 } };
        struct msghdr mh{};
        mh.msg_iov    = iov;
        mh.msg_iovlen = has_nl ? 1 : 2;
        sent = ::sendmsg(conn->fd, &mh, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (sent > 0)
        {
            note_established(conn);
            stat_add(m_stat_bytes_out, static_cast<uint64_t>(sent));
            if (static_cast<size_t>(sent) == total)
                return true;
        }
    }

    conn->write_buf.assign(msg.data(), msg.size());
    if (!has_nl)
        conn->write_buf.push_back('\n');

    conn->write_off = sent > 0 ? static_cast<size_t>(sent) : 0;
    arm_write(conn, conn->write_buf.data() + conn->write_off,
              static_cast<uint32_t>(conn->write_buf.size() - conn->write_off));
    return true;
}

// ─── TLS record layer ───────────────────────────────────────────────────────
// Give this connection its session and put the ClientHello on the wire, pinned
// to the host from `-t` and never to a name read back from the certificate, so
// this can only fail closed.
bool client_instance::start_tls(conn_t* conn)
{
    if (SOCKETLEY_UNLIKELY(!m_tls))
        return false;

    if (SOCKETLEY_UNLIKELY(m_tls_peer_name.empty()))
    {
        LOG_ERROR("client: TLS connection refused -- the target has no host to verify "
                  "the peer's certificate against");
        return false;
    }

    conn->ssl = m_tls->create_ssl_client(m_tls_peer_name);
    if (SOCKETLEY_UNLIKELY(!conn->ssl))
        return false;
    conn->tls_state = tls_conn_handshake;
    conn->tls_peer_closed = false;

    // One turn of the handshake, which produces the ClientHello, where a
    // negative is a local failure rather than a rejection because nothing is
    // on the wire yet.
    if (SOCKETLEY_UNLIKELY(tls_context::do_handshake(conn->ssl) < 0))
        return false;

    tls_flush(conn);
    arm_handshake_deadline(conn);
    return true;
}

// A flat deadline and not a progress one.  The dump a follower takes can
// legitimately run for minutes, so that deadline had to measure bytes; a
// handshake is bounded by round trips rather than by data, and no real peer
// spends half a minute on one.
void client_instance::arm_handshake_deadline(conn_t* conn)
{
    if (!m_loop)
        return;
    if (conn->hs_armed)
    {
        // An earlier socket's deadline is withdrawn, and its settling arms this one's.
        if (conn->hs_req.generation != conn->generation && !m_loop->submit_timeout_remove(&conn->hs_req))
            LOG_WARN("client: an earlier handshake deadline could not be withdrawn — this "
                     "connection's own is armed when that one fires");
        return;
    }

    conn->hs_ts.tv_sec  = tls_handshake_deadline_secs;
    conn->hs_ts.tv_nsec = 0;
    conn->hs_req = { this, reinterpret_cast<char*>(conn), -1, 0, op_timeout, conn->generation };
    conn->hs_armed = m_loop->submit_timeout(&conn->hs_ts, &conn->hs_req);
    if (SOCKETLEY_UNLIKELY(!conn->hs_armed))
        LOG_ERROR("client: the handshake deadline could not be submitted — a target that "
                  "accepts and never handshakes will not be dropped");
}

// Ciphertext in and plaintext into conn->partial, one call per read
// completion, which is what makes the handshake asynchronous with nothing
// blocking the event loop.
void client_instance::tls_feed(conn_t* conn, const char* data, size_t len)
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
            // Where a server's certificate is rejected, closing but not
            // silently, because the alert OpenSSL produced tells the peer why
            // and the tls_flush at the end of handle_read puts it on the wire.
            conn->closing = true;
            return;
        }
        if (r == 0)
            return;   // another round; its records go out with that flush

        conn->tls_state = tls_conn_ready;
        // Deliberately falling through rather than returning, because under
        // TLS 1.3 a peer's Finished and its first message routinely arrive in
        // one packet.
    }

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
            if (SOCKETLEY_UNLIKELY(read_overflows(conn->partial.size(), len)))
            {
                conn->closing = true;
                break;
            }
            continue;
        }
        if (n < 0)
        {
            // Either the peer's close_notify or an unusable record, both
            // recorded and applied by the caller because the bytes decrypted
            // above may be a complete line.
            conn->tls_peer_closed = true;
        }
        break;
    }
}

// Every byte this connection sends is a TLS record, including the ones nobody
// queued, and there is no other way onto the wire for a connection with a
// session.
void client_instance::tls_flush(conn_t* conn)
{
    if (SOCKETLEY_UNLIKELY(!m_loop || !conn->ssl))
        return;

    // One write in flight at a time, because a second submission would need a
    // second buffer and would interleave two record streams on one socket.
    if (conn->write_pending)
        return;

    // Application data only once the handshake is done, so a message queued by
    // on_connect waits rather than being handed to an SSL that would answer
    // WANT_READ.
    if (conn->tls_state == tls_conn_ready)
    {
        // Room for the records of what is queued, as the proxy reserves it, so the write BIO does not regrow from empty.
        if (!conn->write_queue.empty())
        {
            const size_t plain = std::min<size_t>(conn->write_queue.bytes(),
                                                  tls_context::max_bio_buffered + conn->write_queue.front().size());
            tls_context::reserve_out(conn->ssl, plain + plain / 16384 * 22 + 64);
        }
        while (!conn->write_queue.empty())
        {
            const std::string& msg = conn->write_queue.front();
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
        // Once there is room again, a later stall is worth reporting afresh —
        // the same latch the cleartext path lowers in flush_queued_write, and
        // the same crossing noted for on_writable.
        if (conn->write_queue.bytes() < write_watermark_bytes())
        {
            conn->queue_full = false;
            if (conn->drain_wanted) { conn->drain_wanted = false; conn->drain_due = true; m_drain_any = true; }
        }
    }

    if (!tls_context::has_pending_out(conn->ssl))
        return;

    // Ciphertext taken out of the write BIO into write_buf rather than
    // pointed at, because the BIO's storage moves as OpenSSL writes the next
    // record -- and taking it is what keeps the SSL free of anything the ring
    // can name.
    std::string cipher;
    if (SOCKETLEY_UNLIKELY(tls_context::take_out(conn->ssl, cipher) == 0))
        return;

    // Nothing is in flight (checked above), so write_buf is this function's to
    // take: whatever was in it belongs to a write that has already completed.
    conn->write_buf = std::move(cipher);
    conn->write_off = 0;
    arm_write(conn, conn->write_buf.data(), static_cast<uint32_t>(conn->write_buf.size()));
}
