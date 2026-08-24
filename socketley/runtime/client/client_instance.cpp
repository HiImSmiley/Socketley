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

    // Switching a running client out of send-only mode has to start it reading.
    //
    // arm_read() declines while the mode is client_mode_out, so a client started
    // that way has never had a read armed and nothing else ever arms one: every
    // read this runtime submits comes from a completion, and with none in flight
    // there are no completions.  `socketley edit <name> --mode in` is allowed on
    // a running client — it is one of the few edit flags with no "cannot change
    // while running" guard — so before this it changed the field, reported
    // success, and left the client connected and receiving nothing until it lost
    // the connection and dialled again.
    //
    // The other direction needs nothing: a read already in the ring completes as
    // it always would, and arm_read() simply declines to replace it.
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

// ─── EVERYTHING A CLIENT'S SOCKET NEEDS, IN ONE PLACE ───────────────────────
//
// try_connect() creates the socket twice -- once, and again after a cached DNS
// answer turns out to be stale -- and each copy set TCP_NODELAY for itself.
// Two is how three starts, and the option below is exactly the kind that gets
// added to one of them: the second socket is on the *reconnect* path, which is
// the path that needs it most.
//
// SO_KEEPALIVE, because a peer can go away without saying so.  A FIN or an RST
// is a message, and a client acts on either the moment it arrives; a machine
// that loses power, a link that partitions, a firewall that forgets an idle
// flow -- none of those send anything.  The socket then stays ESTABLISHED
// against nothing, and an idle client never writes, so it never finds out.
// With --reconnect that is the worse half: the runtime believes it is connected
// and therefore never reconnects, which is the documented promise not kept.
//
// The kernel's own default idle is two hours.  60s idle, 10s between probes,
// 3 probes puts detection at about 90 seconds -- one packet every 60s per idle
// connection, which is nothing, against a promise that otherwise waits until
// after lunch.  No flag: a knob here would be a number nobody has a reason to
// pick, and the failure it guards is not one an operator can see coming.
//
// This is the client's own outbound socket.  A server's accepted connections
// are covered by --idle-timeout, which is a different question -- "this peer
// has nothing to say" rather than "this peer is gone".
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

    // ─── -t unix:/path — the connect side of --listen unix: ─────────────────
    //
    // The address rules are shared/unix_listener.h's, the same ones the
    // listener binds with; setup() has already refused a path that fails them
    // and the --udp/--tls pairs.  No resolver, no cached-address dance: the
    // path IS the address.  No tune_client_socket either — everything it sets
    // is a TCP-level option or a TCP keepalive timer, and a unix peer that
    // goes away is reported by the socket itself, not probed for.
    if (target.starts_with("unix:"))
    {
        const std::string_view upath = target.substr(5);
        m_conn->fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (m_conn->fd < 0)
            return false;

        struct sockaddr_un uaddr{};
        const socklen_t ulen = socketley::unix_sock::fill_addr(upath, uaddr);
        // A non-blocking AF_UNIX connect is not TCP's: it either completes
        // now or fails now — EAGAIN (a full backlog) included, since unlike
        // EINPROGRESS nothing will finish it later.  A failure here is what
        // the reconnect machinery exists for.
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
            auto [ptr, ec] = std::from_chars(port_sv.data(), port_sv.data() + port_sv.size(), parsed_port);
            if (ec == std::errc{} && parsed_port > 0 && parsed_port <= 65535)
                port = static_cast<uint16_t>(parsed_port);
        }
    }

    // The name a TLS peer's certificate has to be valid for, taken here because
    // this is the only place the host is known and taken *before* the resolver
    // runs.  It is what the operator typed, never what DNS answered and never
    // what the certificate says about itself: a name read back out of either
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
    // A literal address needs no resolver.  getaddrinfo runs on the event loop
    // thread and stalls every other connection this runtime serves for as long
    // as it takes, so the common case — a configured IP — must not enter it.
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

    // The session goes on the socket before anything is read from it, and the
    // ClientHello is the first thing this connection sends.  A failure here is
    // local — no session could be built, or the first flight did not reach the
    // ring — and it costs the socket: there is deliberately no path from a
    // refused session to a cleartext dial, which is the whole point of --tls.
    //
    // The connect may still be in flight at this point; that is as true of the
    // read and the queued write below, and the ring holds a submission on a
    // connecting socket until it is writable exactly as it always has.
    if (m_tls && !start_tls())
    {
        drop_connection();
        return false;
    }

    // read_pending and write_pending are deliberately left alone.  There is one
    // read request and one write request in this struct, and a previous socket's
    // operation can still be holding one of them, since a request is occupied
    // until its completion arrives and no earlier.  Clearing the flags here and
    // arming again would point a second kernel read at m_conn->read_buf while
    // the first is still writing into it.  Across a stop it is setup() that
    // settles this, by asking the loop rather than guessing — see there.
    arm_read();
    flush_queued_write();

    return m_connected;
}

// The one place a read is armed.  Never while one is already armed: both would
// be writing into m_conn->read_buf, and the second's bytes would land in the
// middle of the first's.
void client_instance::arm_read()
{
    if (!m_loop || !m_connected || m_conn->closing || m_conn->fd < 0)
        return;
    if (m_conn->read_pending)
        return;
    // `--mode out` says this runtime delivers no application data, and on a
    // cleartext socket that means it never reads at all.  A TLS session cannot
    // be run that way: the handshake, the peer's alerts and its session tickets
    // all arrive on this socket, and a client that never reads would send its
    // ClientHello and wait forever for a ServerHello nothing was going to
    // collect.  So a TLS connection always reads, and handle_read drops the
    // plaintext instead — the mode is honoured where the data would be
    // delivered, not by refusing to run the transport.
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

// The one place a write is armed.  Stamped like the read with the socket it
// belongs to, so a completion left over from a socket this client has already
// lost cannot push the remains of that conversation into the current one.
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

    // A TLS connection's bytes go through the record layer, which is the only
    // thing allowed to put one on the wire.  Checked ahead of `closing` and not
    // after it: a session that is on its way down still owes the peer the alert
    // that says why, and that alert is sitting in the write BIO with an empty
    // queue in front of it.
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
    // A refusal here has nowhere to recover to: the socket is already gone and
    // nothing else re-drives the clock.
    //
    // mark_failed() is authoritative for an in-daemon client and WORKER-LOCAL
    // for every other one, and the difference is measured rather than assumed.
    // Same probe build, timer submission forced to fail:
    //
    //   --daemon-process   start refused, `ls` reads Failed, 2 log lines
    //   worker-backed      start reports success, `ls` reads Up, 1 log line
    //   worker, healthy    start reports success, `ls` reads Up, 0 log lines
    //
    // So in a worker the log IS the report, and it is the only one, because a
    // worker's state does not reach the daemon's placeholder.  That gap is
    // bigger than this fix and is not closed here — it is named so the next
    // reader does not mistake the call for something it does in every case.
    if (!schedule_reconnect())
        mark_failed();
}

// A session belongs to one socket and dies with it.  Carrying one across a
// reconnect would leave the record layer half a handshake ahead of a peer that
// has never heard from us, and every byte after that undecryptable.
//
// Safe to do with a write still in flight: the ciphertext the kernel is reading
// lives in m_conn->write_buf, which this struct owns, and nothing inside the
// SSL is ever named by an SQE.  That is what the memory BIO pair buys.
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

// A completion that belongs to a socket we no longer have, or that arrived
// while the runtime is stopped.  It is not acted on, but it is not nothing
// either: the buffer it carries belongs to the shared group, and the request it
// names is free to be armed again only once this has arrived.
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

// ─── WHAT true MEANS HERE, BECAUSE THREE OF THE RETURNS ARE NOT SUBMISSIONS ──
//
// The question a caller asks is not "did you submit a timer?" but "is there
// anything left that will bring this client back, or should I stop claiming
// there is?".  Three of the four exits answer yes without submitting anything,
// and answering them `false` would mark a healthy runtime failed:
//
//   reconnect disabled   -- nothing is owed; drop_connection() calls this on
//                           every client, including the ones that never retry
//   attempts exhausted   -- the operator's own limit, reached as configured
//   already pending      -- the clock is armed; this call is the no-op that
//                           keeps two reconnect chains from racing
//
// Only a refused submission is false, and that is the one case where nothing
// will ever run again.
bool client_instance::schedule_reconnect()
{
    int max = get_reconnect();
    if (max < 0 || !m_loop)
        return true; // Reconnect disabled: nothing to arm, nothing wrong

    if (max > 0 && m_reconnect_attempt >= max)
        return true; // The configured limit, reached as asked

    // One timer, one request slot.  Arming it again while the kernel still
    // holds it gives the client two reconnect chains racing to open a socket,
    // and the loser's fd is leaked when the winner overwrites m_conn->fd.
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

    // ─── A refused timer here is the end of this client, not a hiccup ────────
    //
    // Nothing else re-drives the reconnect clock: the three callers are
    // drop_connection(), setup() and handle_timeout(), and every one of them
    // is fire-and-forget.  So a refusal leaves a runtime that reports
    // `running`, holds no connection, and will never dial again — silently.
    //
    // Said in words rather than as a code, the way the proxy states its own
    // timer refusals and the way teardown() below already states the
    // withdrawal: the operator can see a log line, and cannot see a bool that
    // was dropped on the floor.
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

    // ── what an earlier run armed and never saw the end of ──────────────────
    //
    // This runtime has one read request, one write request and one reconnect
    // timer, all living in m_conn and all reused for as long as that struct
    // does.  The three flags below say "this one is occupied, do not arm it
    // again"; they are raised when it is armed and lowered by its completion.
    //
    // Only by a completion the loop *delivers*, though.  stop() deregisters this
    // owner, and from that moment the loop drops this instance's completions
    // instead of dispatching them — so neither on_cqe nor settle_stale runs, and
    // the flag is never lowered.  It then survives into the next run, where
    // arm_read() declines to arm a read it believes is already in flight: the
    // client connects and is deaf for the rest of the process.  Same for the
    // write request, whose queue is then never flushed, and for the reconnect
    // timer, which can never be scheduled again.  A stop followed by a start was
    // all it took.
    //
    // Clearing the flags is not on its own an answer — the kernel really may
    // still be writing into read_buf and reading out of write_buf, which is why
    // teardown leaves them standing.  So this asks the loop, which is the only
    // thing that knows: owner_inflight() counts what is still in the ring for
    // this handler over every registration it has ever held, whatever became of
    // the completions.
    //
    //   zero      — every request in m_conn is free.  Lower the flags, and
    //               release the structs earlier runs left behind.
    //   non-zero  — something really is still in the ring.  The old struct keeps
    //               it and this run takes a fresh one; the old one is not freed,
    //               because the loop reads the request inside it to drop its
    //               completion.  This is the `restart` path: stop() and start()
    //               in one loop iteration, with nothing reaping the ring in
    //               between.
    //
    // owner_table_full() is the case owner_inflight() cannot answer: a handler
    // that never got a slot reads zero whatever it has outstanding, so a full
    // table takes the conservative branch rather than acting on a zero that
    // means "unknown".
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
    //
    // The CA file and the client certificate are read and parsed here, at
    // setup, before a single completion is armed.  That is file I/O and it
    // blocks, which is exactly why it happens here and nowhere near the event
    // loop: the handshake itself never touches a file and never touches a
    // socket — see tls_feed/tls_flush.
    //
    // Rebuilt on every start, which is what makes `reload` — a stop followed by
    // a start — the way a renewed certificate is installed, exactly as it is on
    // a server.
    //
    // Every refusal below returns false, which puts the runtime in the failed
    // state.  None of them may fall through to a cleartext dial: a client that
    // asked for encryption and connected in the clear is the one outcome the
    // operator cannot see, because `inspect` would go on reporting TLS.
    // ─── -t unix:/path — the connect side of --listen unix: ─────────────────
    //
    // Judged here rather than only in the flag parser, for the listener's
    // reason: setup() is on the restore and import paths the parser never
    // sees.  Before the TLS block, so a doomed configuration is refused
    // without loading certificates it may not use.
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
        // --ca is this client's trust store; without one the system store is
        // used.  Either way the chain is verified and the peer's name is
        // checked per connection (see start_tls) -- there is deliberately no
        // way to turn either off.  --cert/--key are the certificate this client
        // presents when the peer asks for one.
        if (!ctx->init_client(get_ca_path(), get_cert_path(), get_key_path()))
        {
            // init_client has already said which file and what OpenSSL made of
            // it.  This says what it cost.
            LOG_ERROR("client: TLS not started -- the CA file or the client "
                      "certificate could not be loaded");
            return false;
        }
        m_tls = std::move(ctx);
    }

    m_use_provided_bufs = loop.setup_buf_ring(BUF_GROUP_ID, BUF_COUNT, BUF_SIZE);

    if (!try_connect())
    {
        // If reconnect enabled, schedule first attempt.
        //
        // Checked, because "we'll connect later" is only true if the clock that
        // makes it later was actually armed.  Returning true on a refused
        // submission is the shape of the defect this tree has already had once:
        // a start that failed, recorded as running, answering nothing.
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
        // A read and a write can both be in flight on this socket, and closing
        // alone leaves them armed on m_conn->read_buf and m_conn->write_buf,
        // which the next start() would hand straight to a new socket.
        //
        // Cancelling first was the old defence and it was half of one: flush()
        // hands the SQE to the ring and returns, so nothing here waited for the
        // kernel to look at either the cancel or the read.  This runtime is the
        // clearest case of why that matters — one read request and one write
        // request reused across reconnects, and a socket number the kernel
        // hands straight back on the next connect(), so an unconsumed read
        // resolved after the reconnect reads the *new* connection's bytes into
        // a buffer the old completion still owns.  close_fd submits the cancel
        // and holds the number until both have reported.
        shutdown(m_conn->fd, SHUT_RDWR);
        close_tracked(m_conn->fd);
        m_conn->fd = -1;
    }

    // The socket is gone, so the session is finished whatever it was doing.
    // Released here rather than left for the destructor because this struct can
    // outlive the stop — see the comment on m_conn_spent in setup() — and a
    // session held across a start would be a handshake this client believes it
    // is halfway through and the next peer has never heard of.
    tls_release();

    // The reconnect timer is attached to no fd: the cancel above could not reach
    // it, and it can be up to thirty seconds from firing.  Thirty seconds during
    // which the ring still owes this owner a completion, which is what the
    // manager waits on before it frees a removed runtime — so a client removed
    // while backing off was never freed at all on any reap that ran in between,
    // and the whole instance stayed in the graveyard.  Withdraw it instead: the
    // timeout still reports, with -ECANCELED, only now rather than later.
    if (m_reconnect_pending)
    {
        if (!loop.submit_timeout_remove(&m_conn->timeout_req))
            LOG_WARN("client: the reconnect timer withdrawal did not reach the ring — "
                     "this instance stays retired until the timer fires on its own");
        loop.flush();
    }

    // Its request keeps its owner all the same.  The loop reads the request
    // when that completion lands — to decide whether to deliver it, and to count
    // it off this owner's tally — so it has to go on pointing at memory that is
    // there, which retirement guarantees and a null does not.
    //
    // The pending flags are left standing for the same reason they are in
    // try_connect: the request stays occupied until its completion arrives, and
    // a withdrawn timeout is still owed exactly one.  Clearing m_reconnect_pending
    // here would let a start() in this same loop iteration arm a second timeout
    // on a request the kernel is still carrying one for.
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

    // Stopped, or the completion belongs to a socket we have already lost: not
    // acted on, but settled, so the buffer goes back and the request it names
    // becomes free to arm again.  Acting on it instead would put the tail of a
    // finished conversation into the current one — the descriptor number alone
    // cannot tell the two apart, because the kernel hands the closed one
    // straight back to the next connect.
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
            // Reset the request type: the fallback is a plain read into the
            // connection's own buffer, not a provided-buffer one.  Leaving it
            // as a recv/provided type makes the completion handler treat the
            // result as a buffer-ring delivery — it then appends whatever sits
            // in ring buffer 0 instead of the bytes just read, discards those
            // bytes, and returns a buffer it never took, corrupting the ring's
            // free list.
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

    // A send-only TLS client reads because the record layer has to (see
    // arm_read), and what comes out the far side is application data this mode
    // says the runtime does not deliver.  Dropped here rather than parsed:
    // otherwise turning on --tls would quietly start printing and dispatching
    // messages that `--mode out` exists to say no to.
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
    // ── the TLS half of the same idea ──
    // The peer's close_notify is applied here rather than where it was read:
    // the read that carried it can carry a last line ahead of it, and marking
    // the connection closing any earlier would have thrown that line away.
    //
    // Then one flush for everything the record layer owes the wire — the next
    // handshake flight, an alert explaining a handshake that just failed, a
    // session ticket, and whatever lua_send queued while the handshake was
    // still running.  Every path through this function reaches this label, so
    // nothing is left sitting in a BIO waiting for a completion that has no
    // reason to come.
    if (m_conn->ssl)
    {
        if (m_conn->tls_peer_closed)
            m_conn->closing = true;
        tls_flush();
    }

    // A connection marked closing with nothing left in flight has nobody to
    // notice it.  arm_read() declines while closing, so no completion is
    // coming; the client sat connected and deaf, on an open socket, until the
    // runtime was stopped — and with reconnect configured it never dialled
    // again either, because nothing had told it the connection was gone.  Two
    // paths reach that state: a line longer than MAX_PARTIAL_SIZE, and now a
    // handshake or a record the session refused.  Every other way of losing the
    // socket goes through drop_connection; this one used to just stop.
    if (m_conn->closing && !m_conn->write_pending && m_connected)
    {
        drop_connection();
        return;
    }

    arm_read();
}

// ─── THE TWO read_pending GUARDS BELOW, AND WHY THEY STAY ───────────────────
//
// Both of them defer a teardown to an armed read, which is the shape
// shared/conn_reachability.h exists to refuse: an armed read is ended by the
// peer sending something or by the socket ending, and a connection that is
// `closing` is one whose peer has already gone.  It cost the cache a stranded
// connection (78c9ecc) and the server one too, and here the stakes are higher
// per occurrence rather than lower — a client has exactly one connection, so a
// stranded one means the whole runtime sits connected and deaf and, with
// --reconnect configured, never dials again, because drop_connection() is the
// only thing that would tell it the connection was gone.
//
// It is nevertheless left alone, for the same reason as the proxy and with the
// same two properties named:
//
//   * the read is SINGLE-SHOT (op_read / op_read_provided), never multishot, so
//     it is re-armed per completion rather than parked in the kernel across
//     them, and arm_read() is the one place that does it;
//   * it is armed on the DESCRIPTOR, never on a fixed-file index — this file
//     mentions neither multishot nor fixed files anywhere — so close_fd() can
//     withdraw it, which free_fixed_file_slot() explains is exactly what a
//     fixed-index submission does not allow.
//
// MEASURED, and it is a weaker measurement than the other two.  A client in
// --mode inout with a 60 KB write in flight, reset by its peer with
// SO_LINGER (on, 0): 109 consecutive resets, 109 reconnects, no stranding.  109 is
// not 15,000, and "not reproduced in 109 trials" is not "it is not there" — what
// makes this a decision rather than a gap is the two properties above, not the
// run length.  A reproducer would move it, and it would move it here.
//
// One shape is immune by construction and worth knowing: in --mode out on a
// cleartext socket arm_read() declines outright, so read_pending is false for
// the life of the connection and both guards always fire.
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

    // Flush queued writes before checking closing state.  flush_queued_write
    // routes a TLS connection through the record layer, which is what turns
    // this completion into the next handshake flight or the next batch of
    // encrypted messages — the session makes no progress on its own.
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

    // A timer that outlived what it was waiting for.  The socket is already up,
    // and dialling again here would overwrite m_conn->fd and leak the one it
    // replaced.
    if (m_connected)
        return;

    m_reconnect_attempt++;

    if (try_connect())
        return; // Reconnected successfully

    // Failed — schedule another attempt.  Same reasoning as drop_connection():
    // if the clock cannot be re-armed there is no later attempt to wait for.
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

// Whether the message was written or queued.
//
// It was void, and the three conditions below are the ordinary ones: a client
// that has not connected yet, one whose server dropped it, and one created
// --mode in, which does not send at all.  self.send() reported none of them.
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

    // Queue message if a write is already in flight — or always, on a TLS
    // connection.  There every byte has to be turned into a record first, and
    // tls_flush is the only thing allowed to do that and put the result on the
    // wire; there is no "connected with nothing in flight" case that can write
    // straight out, because the handshake may not have finished and an SSL
    // asked to write before it has would answer WANT_READ and leave this
    // function unsure what it had consumed.
    if (m_conn->ssl || m_conn->write_pending || m_conn->closing)
    {
        if (!m_conn->closing)
        {
            // The bound is memory, not entries: a client sending 20-byte lines
            // hit a 4096-entry cap after 80 KB and every message past it was
            // dropped without a word, while one sending megabyte payloads could
            // queue gigabytes before the same cap noticed.
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
        // Nothing else will come back for this message on its own: with no
        // write in flight there is no completion due, so the record layer has
        // to be driven from here or the line sits in the queue until something
        // unrelated happens to arrive.
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

// The datagram path.  Reached only from lua_send's UDP branch, and a UDP client
// never has a session — setup() refuses --tls on one rather than dial in the
// clear — so this deliberately knows nothing about the record layer.
void client_instance::send_to_server(std::string_view msg)
{
    if (!m_loop || !m_connected || m_mode == client_mode_in || m_conn->write_pending || m_conn->closing)
        return;

    m_conn->write_buf.assign(msg.data(), msg.size());
    m_conn->write_off = 0;
    arm_write(m_conn->write_buf.data(), static_cast<uint32_t>(m_conn->write_buf.size()));
}

// ─── TLS record layer ───────────────────────────────────────────────────────
//
// Give this connection its session and put the ClientHello on the wire.
//
// The name pinned to the session is the host from `-t` — what the operator
// meant to reach — and never one read back out of the certificate that turns
// up.  create_ssl_client refuses to build a session without one and there is no
// way to ask it not to check, which is what makes this able to fail only
// closed: a false return costs the socket and the reconnect clock starts, and
// nothing is ever retried in cleartext.
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

    // One turn of the handshake, which produces the ClientHello; the peer
    // speaks next and the read armed on this socket carries the answer.  A
    // negative here is a local failure — no memory, no usable cipher — rather
    // than a rejection: there is nothing on the wire yet to be rejected.
    if (SOCKETLEY_UNLIKELY(tls_context::do_handshake(m_conn->ssl) < 0))
        return false;

    tls_flush();
    return true;
}

// Ciphertext in, plaintext into m_conn->partial.  One call per read completion,
// which is what makes the handshake asynchronous: OpenSSL is handed the bytes
// that have arrived and asked what it makes of them, and whatever it wants to
// say back is drained by the tls_flush at the end of handle_read.  Several
// rounds of that is a handshake; there is no loop here waiting for one, and
// nothing blocks the event loop.
void client_instance::tls_feed(const char* data, size_t len)
{
    // Inbound ciphertext into the read BIO.  A refusal is fatal by contract —
    // the peer is over the per-connection buffer cap, or the BIO failed — and
    // it has to be: there is nowhere to hold what was not taken, and handing a
    // record layer a stream with a hole in it is worse than closing.
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
            // This is where a server's certificate is rejected: an unknown CA,
            // an expired chain, a name that does not match the host in `-t`.
            // do_handshake has already logged which.  Closing, but not
            // silently — what OpenSSL produced on its way to failing is the
            // alert that tells the peer why, and the tls_flush at the end of
            // handle_read puts it on the wire before the connection goes.
            m_conn->closing = true;
            return;
        }
        if (r == 0)
            return;   // another round; its records go out with that flush

        m_conn->tls_state = tls_conn_ready;
        // Deliberately falling through rather than returning: the same read can
        // already carry application data behind the handshake's last flight —
        // under TLS 1.3 a peer's Finished and its first message routinely
        // arrive in one packet, and returning here would leave that message
        // sitting in the BIO until something else was sent.
    }

    char plain[16384];
    for (;;)
    {
        const int n = tls_context::ssl_read(m_conn->ssl, plain, sizeof(plain));
        if (SOCKETLEY_LIKELY(n > 0))
        {
            m_conn->partial.append(plain, static_cast<size_t>(n));
            // The same ceiling the cleartext path applies, checked inside the
            // loop rather than after it: one read completion can decrypt
            // everything the inbound BIO had buffered, so "one read cannot
            // produce more than one buffer's worth" is not true here.
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
            // Either the peer's close_notify or a record we cannot use.  Both
            // end the connection, and neither ends it here: the bytes decrypted
            // above may be a complete line that deserves to be delivered, so
            // this is recorded and applied by the caller once it has been.
            m_conn->tls_peer_closed = true;
        }
        break;
    }
}

// Every byte this connection sends is a TLS record, including the ones nobody
// queued: a handshake flight, an alert, a session ticket.  There is no other
// way onto the wire for a connection that has a session.
void client_instance::tls_flush()
{
    if (SOCKETLEY_UNLIKELY(!m_loop || !m_conn->ssl))
        return;

    // One write in flight at a time, exactly as the cleartext path does — the
    // ciphertext buffer built below is what the kernel reads out of, and a
    // second submission would need a second buffer and would interleave two
    // record streams on one socket.  Whatever does not go now stays in the
    // queue or in the write BIO; the write completion comes back through
    // handle_write and lands here again.
    if (m_conn->write_pending)
        return;

    // Application data only once the handshake is done.  A message queued by
    // on_connect — which fires when the socket is dialled, before a single
    // record has crossed — waits here rather than being handed to an SSL that
    // would answer WANT_READ and leave the caller unsure what was consumed.
    if (m_conn->tls_state == tls_conn_ready)
    {
        while (!m_write_queue.empty())
        {
            const std::string& msg = m_write_queue.front();
            const int n = tls_context::ssl_write(m_conn->ssl, msg.data(),
                                                 static_cast<int>(msg.size()));
            if (n <= 0)
            {
                // 0 is backpressure: the write BIO is at its cap, and OpenSSL's
                // contract is that the same buffer is offered again once it has
                // drained — which is what leaving this message at the front of
                // the queue arranges.  -1 is fatal for the session.
                if (n < 0)
                    m_conn->closing = true;
                break;
            }
            // Partial writes are not enabled on this context, so SSL_write is
            // all-or-nothing.  A short count would mean the record layer and
            // this queue disagree about what has been sent, and a stream with a
            // hole in it has no framing left to recover: close instead.
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

    // Ciphertext out of the write BIO and into a buffer this connection owns.
    // It has to be copied rather than pointed at: an SQE names an address the
    // kernel reads at its leisure, and the BIO's storage moves under it as
    // OpenSSL writes the next record.  Copying is also what keeps the SSL free
    // of anything the ring can name, which is what makes the session safe to
    // release the moment the connection is lost — see tls_release.
    //
    // The buffer is write_buf, the same one a cleartext message rides in, so
    // the short-write resume in handle_write needs no TLS-specific case at all.
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
