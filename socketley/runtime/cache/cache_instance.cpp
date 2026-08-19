#include "cache_instance.h"
#include "../../shared/blocking_write.h"
#include "../../shared/ipc_framing.h"
#include "../../shared/trace.h"
#include "resp_parser.h"
#include "../../shared/event_loop.h"
#include "../../shared/runtime_manager.h"
#include "../../shared/lua_context.h"
#include "../../shared/logging.h"
#include "../../shared/invariants.h"
#include "../../cli/command_hashing.h"

#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <charconv>
#include <iostream>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <liburing.h>
#include <sstream>
#include <sys/stat.h>
#include <poll.h>

cache_instance::cache_instance(std::string_view name)
    : runtime_instance(runtime_cache, name), m_listen_fd(-1), m_loop(nullptr)
{
}

cache_instance::~cache_instance()
{
    // Normally already gone: the manager rebuilds the whole sink table on every
    // membership change, and removing a runtime is one.  This is the case that
    // does not go through the manager — an instance built and dropped by a
    // test, or one whose removal raced a rebuild — where a stale entry would be
    // a pointer into this object after it is freed.
    if (auto* mgr = get_runtime_manager())
        mgr->requests().drop_sink(this);

    close_tracked(m_listen_fd);
}

void cache_instance::close_tracked(int fd)
{
    if (fd < 0)
        return;
    // m_loop while running, m_retired_loop once teardown has cleared it — the
    // descriptors closed after a stop are exactly the ones the ring is most
    // likely to still be naming, so falling back to plain close() there would
    // leave the hazard open on the worst case.
    event_loop* lp = m_loop ? m_loop : m_retired_loop;
    if (SOCKETLEY_LIKELY(lp != nullptr))
        lp->close_fd(fd);
    else
        close(fd);
}

void cache_instance::retire(std::shared_ptr<void> storage, io_request* const* owed, size_t count)
{
    // Nothing outstanding: the ring has no way to reach this object again, so
    // holding on to it would only leak.
    if (count == 0)
        return;

    if (m_loop)
        m_retired_loop = m_loop;

    retired_op op;
    op.storage = std::move(storage);
    constexpr size_t max_waiting = sizeof(op.waiting) / sizeof(op.waiting[0]);
    for (size_t i = 0; i < count && op.count < max_waiting; i++)
        op.waiting[op.count++] = owed[i];
    m_retired.push_back(std::move(op));
}

bool cache_instance::absorb_retired(io_request* req, struct io_uring_cqe* cqe)
{
    for (size_t i = 0; i < m_retired.size(); i++)
    {
        auto& op = m_retired[i];
        for (uint8_t k = 0; k < op.count; k++)
        {
            if (op.waiting[k] != req)
                continue;

            // A read that came out of the provided-buffer ring still holds one
            // even when it is only reporting its own cancellation.  Hand it
            // back, or every restart costs the ring a few buffers for good.
            if ((cqe->flags & IORING_CQE_F_BUFFER) && m_retired_loop)
                m_retired_loop->return_buf(BUF_GROUP_ID,
                                           static_cast<uint16_t>(cqe->flags >> IORING_CQE_BUFFER_SHIFT));

            // More to come: a multishot read keeps delivering until it reports
            // without this flag, and a zero-copy send answers twice — once for
            // the write and once to say the kernel is done reading the buffer.
            // The memory stays where it is until that last word.
            if (cqe->flags & IORING_CQE_F_MORE)
                return true;

            op.waiting[k] = op.waiting[op.count - 1];
            op.count--;
            if (op.count == 0)
            {
                if (i + 1 != m_retired.size())
                    m_retired[i] = std::move(m_retired.back());
                m_retired.pop_back();
            }
            return true;
        }
    }
    return false;
}

std::unique_ptr<client_connection> cache_instance::pool_acquire(int fd)
{
    std::unique_ptr<client_connection> conn;
    if (!m_conn_pool.empty())
    {
        conn = std::move(m_conn_pool.back());
        m_conn_pool.pop_back();
        conn->reset(fd);
    }
    else
    {
        conn = std::make_unique<client_connection>();
        conn->fd = fd;
    }
    return conn;
}

void cache_instance::pool_release(std::unique_ptr<client_connection> conn)
{
    // Release fixed file slot
    if (conn->direct_fd && conn->fixed_idx >= 0 && m_loop)
    {
        m_loop->free_fixed_file_slot(static_cast<uint32_t>(conn->fixed_idx));
        conn->fixed_idx = -1;
        conn->direct_fd = false;
    }

    // The TLS session dies with the connection that owned it, here rather than
    // in reset(), so that a struct being *retired* below — one the ring still
    // owes a completion — does not hold an OpenSSL session and two memory BIOs
    // for however long that takes.  No completion can name the session:
    // everything the kernel reads or writes was copied into or out of a buffer
    // this struct owns before the SQE was built, which is why this needs none
    // of the "wait until the ring is finished" care write_batch does.
    if (SOCKETLEY_UNLIKELY(conn->ssl != nullptr))
    {
        tls_context::free_ssl(conn->ssl);
        conn->ssl = nullptr;
    }
    conn->tls_state = tls_conn_none;
    conn->tls_peer_closed = false;

    // A struct only goes back into the pool once the ring is finished with it.
    // The pool hands its structs to the very next accepted connection, and a
    // completion landing on one that has already been reissued is charged to a
    // connection it has nothing to do with — while the kernel is still reading
    // out of write_batch[0], which reset() clears.  Anything still owed is
    // retired instead, requests included, so its completion comes back to
    // absorb_retired() and the memory is released only then.
    {
        io_request* owed[2];
        size_t n = 0;
        if (conn->read_pending)
            owed[n++] = &conn->read_req;
        // A zero-copy send clears write_pending on its first completion and
        // still owes the notification that says the kernel has stopped reading
        // the buffer, so the two flags together are the condition.
        if (conn->write_pending || conn->zc_notif_pending)
            owed[n++] = &conn->write_req;
        if (n > 0)
        {
            retire(std::shared_ptr<void>(std::move(conn)), owed, n);
            return;
        }
    }

    // Nothing is owed, so nothing can arrive: clear the owners anyway, because
    // that is the only protection a struct sitting in the pool has if this
    // reasoning is ever wrong.
    conn->read_req.owner = nullptr;
    conn->write_req.owner = nullptr;
    conn->partial.clear();
    conn->response_buf.clear();
    conn->write_queue.clear();
    for (uint32_t i = 0; i < conn->write_batch_count; i++) conn->write_batch[i].clear();
    conn->write_batch_count = 0;

    SKL_INV_POOLABLE("cache::pool_release", conn->fd,
        conn->read_pending || conn->write_pending || conn->zc_notif_pending,
        conn->read_req.owner || conn->write_req.owner);

    conn->fd = -1;
    m_conn_pool.push_back(std::move(conn));
}

void cache_instance::close_client([[maybe_unused]] client_connection* conn, int fd,
                                  [[maybe_unused]] const char* reason)
{
    m_store.unsubscribe_all(fd);
    // A follower registered on this descriptor has to go with it.  It holds no
    // reference of its own — the socket is this client's — so leaving it behind
    // pointed replication at a number the kernel was free to hand to the next
    // connection that came in.
    detach_follower(fd);
    SKL_TRACE_CLOSE(conn, fd, reason);
    close_tracked(fd);
    if (fd >= 0 && fd < MAX_FDS) m_conn_idx[fd] = nullptr;
    auto it = m_clients.find(fd);
    if (it != m_clients.end())
    {
        pool_release(std::move(it->second));
        m_clients.erase(it);
    }
}

void cache_instance::set_persistent(std::string_view path)
{
    // Validate parent directory exists
    std::string p(path);
    auto slash = p.rfind('/');
    if (slash != std::string::npos && slash > 0)
    {
        std::string parent = p.substr(0, slash);
        struct stat st;
        if (stat(parent.c_str(), &st) != 0 || !S_ISDIR(st.st_mode))
            return; // Silent reject — parent dir doesn't exist
    }
    m_persistent_path = path;
}

std::string_view cache_instance::get_persistent() const
{
    return m_persistent_path;
}

void cache_instance::set_mode(cache_mode mode)
{
    m_mode = mode;
}

cache_mode cache_instance::get_mode() const
{
    return m_mode;
}

size_t cache_instance::get_connection_count() const
{
    return m_clients.size();
}

bool cache_instance::setup(event_loop& loop)
{
    // Nothing from the previous run is cleaned up here any more.  teardown()
    // hands everything it cannot free to retire(), which owns it for as long as
    // the ring might still touch it; freeing it here instead was the crash —
    // the event loop went on to read req->owner out of a connection that had
    // just been deleted, and a follower write was still reading out of a string
    // that no longer existed.
    //
    // What can go is whatever the loop confirms is finished with.  A completion
    // from a previous registration is dropped rather than delivered, so
    // absorb_retired() never hears about those and this is the only thing that
    // releases them.
    if (!m_retired.empty() && loop.owner_inflight(this) == 0)
        m_retired.clear();

    // Pre-allocate connection pool
    if (m_conn_pool.empty())
    {
        m_conn_pool.reserve(CONN_POOL_INIT);
        for (size_t i = 0; i < CONN_POOL_INIT; i++)
            m_conn_pool.push_back(std::make_unique<client_connection>());
    }

    m_loop = &loop;
    // Kept across teardown: a descriptor closed after a stop still has to be
    // checked against the ring, and m_loop is null exactly then.
    m_retired_loop = &loop;

    // ── TLS listener ────────────────────────────────────────────────────────
    //
    // Certificates are read and parsed here, at setup, before a single
    // completion is armed.  That is file I/O and it blocks, which is exactly
    // why it happens here and nowhere near the event loop: the handshake
    // itself never touches a file, and never touches a socket either — see
    // tls_feed/tls_flush.
    //
    // Every refusal below returns false, which puts the runtime in the failed
    // state.  None of them may fall through to a plaintext listener: a cache
    // that asked for encryption and got a cleartext port is the one outcome
    // the operator cannot see, because `inspect` reports what was configured.
    m_tls.reset();
    if (get_tls())
    {
        // The configuration gate in runtime_instance::start() has already
        // refused --replicate here, on every path including the restore.  This
        // is the belt to that braces: setup() is what actually dials the
        // leader a few lines below, and the cost of the two disagreeing is the
        // dataset going out in the clear.
        if (m_repl_role == repl_follower && !m_replicate_target.empty())
        {
            LOG_ERROR("cache: --tls encrypts this cache's own listener, and the "
                      "replication link to its leader is dialled in cleartext -- "
                      "refusing rather than streaming the dataset off an encrypted "
                      "port unencrypted");
            return false;
        }
        auto ctx = std::make_unique<tls_context>();
        if (!ctx->init_server(get_cert_path(), get_key_path(), get_ca_path()))
        {
            // init_server has already said which file and what OpenSSL made of
            // it.  This says what it cost.
            LOG_ERROR("cache: TLS listener not started -- the certificate, key or "
                      "client CA could not be loaded");
            return false;
        }
        m_tls = std::move(ctx);
    }

    uint16_t port = get_port();
    if (port == 0)
        port = 9000;

    // SOCK_CLOEXEC, same reasoning as the server and proxy listeners: a cache
    // lives in the daemon, and the daemon forks proxy workers that have no use
    // for this port and every opportunity to keep it bound after the cache is
    // gone.
    m_listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (m_listen_fd < 0)
        return false;

    int opt = 1;
    setsockopt(m_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(m_listen_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    setsockopt(m_listen_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    // ─── NO TCP_DEFER_ACCEPT, FOR THE SERVER'S REASONS ──────────────────────
    //
    // This set it with a one-second timeout.  setup_tcp_listener in
    // server_instance.cpp carries the full argument; what follows is what is
    // different about a cache, because a cache is the case where the usual
    // defence of this option is actually true.
    //
    // RESP is request/response and nothing greets, so a cache client speaks
    // first by definition and the DELAY the option introduces costs a real one
    // nothing.  Measured here and stated plainly:
    //
    //     connect storm      (`server burst`, no client ever speaks)
    //         with 106,456/s   without 73,448/s   -25.8%  +/-13.9% CI95
    //     client speaks first (connect, SET, read the answer, close)
    //         with  28,708/s   without 30,887/s    +7.9%  +/-10.3% CI95
    //
    // Fifteen pairs each, interleaved, gated on the port pool; the method and
    // why the paired median is the statistic are written out once, next to the
    // same measurement in proxy_instance.cpp.
    //
    // So the intuition holds and is now a number: on the only shape a cache
    // client has, this option is worth nothing that can be told from zero.  The
    // -26% is a storm of connections that never send a command, which is not a
    // cache workload -- it is the case the deferral was written for.
    //
    // It is removed anyway, and not for the delay.  A connection still in
    // SYN-RECV is a request sock rather than a socket, and when the listener
    // closes the kernel drops it with no FIN and no RST — the client keeps an
    // ESTABLISHED socket against a peer that no longer exists, and nothing on an
    // accepted cache connection sets SO_KEEPALIVE.  "Until it next writes" is
    // the whole problem for this runtime in particular: a cache client library
    // holds a POOL of idle connections and hands one out on demand, so a
    // connection killed while idle is not noticed at the moment it dies but at
    // the moment somebody's request is written into it.  Idle is the normal
    // state of most of that pool, and the window is every connection between
    // the handshake and the first command.
    //
    // Nor is it only the delay that the deferral hides: a connection in
    // SYN-RECV is in no count, no stats figure and no listing this runtime can
    // produce, so an operator asking how many clients a cache has is told a
    // number the kernel disagrees with.
    //
    int rcvbuf = 131072;
    setsockopt(m_listen_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    setsockopt(m_listen_fd, SOL_SOCKET, SO_SNDBUF, &rcvbuf, sizeof(rcvbuf));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(m_listen_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        close_tracked(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }

    if (listen(m_listen_fd, 4096) < 0)
    {
        close_tracked(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }

    if (!m_persistent_path.empty())
        m_store.load(m_persistent_path);

    // Cache config values to avoid virtual calls on hot paths
    m_idle_timeout_cached = get_idle_timeout();
    m_max_conns_cached = get_max_connections();
    m_rate_limit_cached = get_rate_limit();
    // Seed from the store rather than clearing: load() above restores expiry
    // timestamps from the persistence file, and this flag gates both the
    // periodic sweep and every lazy check_expiry() call.  Forcing it to false
    // here would leave keys restored with a TTL immortal until some unrelated
    // command set a new TTL and flipped the flag back on.
    m_has_ttl_keys = m_store.has_expiry_keys();

    // Connect to master if follower
    if (m_repl_role == repl_follower && !m_replicate_target.empty())
        connect_to_master();

    // Provided-buffer ring geometry.  Buffer size decides how many commands a
    // single read completion can carry: with 4 KB buffers a 4 KB value fills one
    // buffer per command, so every command costs its own completion.  Count
    // decides how much concurrent traffic fits before the pool runs dry and
    // reads fall back to a slower per-read path.  Both are tunable so the
    // trade-off against memory (count * size per cache runtime) can be measured
    // rather than guessed.
    uint32_t buf_count = BUF_COUNT;
    uint32_t buf_size  = BUF_SIZE;
    if (const char* e = getenv("SOCKETLEY_CACHE_BUF_COUNT"))
    {
        char* end; long v = strtol(e, &end, 10);
        if (end != e && v > 0) buf_count = static_cast<uint32_t>(v);
    }
    if (const char* e = getenv("SOCKETLEY_CACHE_BUF_SIZE"))
    {
        char* end; long v = strtol(e, &end, 10);
        if (end != e && v >= 1024) buf_size = static_cast<uint32_t>(v);
    }
    m_use_provided_bufs = loop.setup_buf_ring(BUF_GROUP_ID, buf_count, buf_size);
    m_recv_multishot = m_use_provided_bufs && loop.recv_multishot_supported();
    // Not send_zc_supported(): the kernel having the opcode is not the
    // question.  A pending zero-copy notification is not a cancellable request
    // and only the peer can release it, so it would hold this instance in
    // retire()'s graveyard for as long as one client declines to read.  See
    // event_loop::send_zc_enabled().
    m_send_zc = loop.send_zc_enabled();

    // A fresh accept request for this run.  The previous one may still be owed
    // a completion — a multishot accept stays armed until it reports without
    // IORING_CQE_F_MORE — and re-arming that same request would leave the
    // listener with two accept chains sharing one io_request and one address
    // buffer.
    m_accept = std::make_unique<accept_op>();
    m_accept->req = { this, nullptr, -1, 0, op_accept };
    if (event_loop::supports_multishot_accept())
    {
        m_accept->req.type = op_multishot_accept;
        m_multishot_active = true;
    }
    else
    {
        m_accept->req.type = op_accept;
        m_multishot_active = false;
    }
    rearm_accept();

    // Periodic TTL sweep, started only once a key actually carries an expiry —
    // a store loaded from disk may already contain some, otherwise the first
    // SETEX/EXPIRE arms it via mark_ttl_keys().  Arming unconditionally would
    // leave a timer running for the lifetime of every cache runtime, which is
    // enough to keep the SQPOLL kernel thread from ever sleeping.
    //
    // The interval trades memory against CPU, not correctness: an expired key is
    // never served regardless, because every read path checks the expiry itself.
    // The sweep only decides how quickly keys that nobody touches again release
    // their memory.  It also has to stay well above the SQPOLL idle timeout, or
    // the poller is re-armed before it can ever sleep.
    long sweep_ms = 500;
    const char* sweep_env = getenv("SOCKETLEY_CACHE_TTL_SWEEP_MS");
    if (sweep_env)
    {
        char* send;
        long v = strtol(sweep_env, &send, 10);
        if (send != sweep_env && v > 0)
            sweep_ms = v;
    }
    // Fresh timers for this run, for the reason spelled out on timer_op: the
    // sweep that was running when the runtime stopped is still on its way, and
    // it cannot be cancelled.  m_ttl_timer_armed cannot tell the difference
    // either — each sweep clears the flag and sets it again — so reusing the
    // request left two chains expiring keys on one timer.
    m_ttl_timer = std::make_unique<timer_op>();
    m_ttl_timer->ts = { sweep_ms / 1000, (sweep_ms % 1000) * 1'000'000 };
    m_ttl_timer->req = { this, nullptr, -1, 0, op_timeout };
    m_ttl_timer_armed = false;
    if (m_has_ttl_keys)
        arm_ttl_timer();

    if (m_idle_timeout_cached > 0)
    {
        m_idle_sweep_timer = std::make_unique<timer_op>();
        m_idle_sweep_timer->ts.tv_sec = 30;
        m_idle_sweep_timer->ts.tv_nsec = 0;
        m_idle_sweep_timer->req = { this, nullptr, -1, 0, op_timeout };
        if (SOCKETLEY_UNLIKELY(!m_loop->submit_timeout(&m_idle_sweep_timer->ts,
                                                       &m_idle_sweep_timer->req)))
            LOG_ERROR("cache: idle sweep timer refused — idle connections will not be reaped");
    }

    return true;
}

void cache_instance::teardown(event_loop& /*loop*/)
{
    if (!m_persistent_path.empty())
        m_store.save(m_persistent_path);

    // Shutdown before closing.  A multishot accept holds its own reference to
    // the socket, so close() does not end it and the terminating completion
    // never arrives — which leaves the loop counting one operation this owner
    // still owes, forever.  reap_retired waits for that count to reach zero, so
    // the whole instance was never freed: about 6 MB per removed runtime, held
    // until the daemon exited.  shutdown() also ends the listen state, which is
    // what takes the socket out of the SO_REUSEPORT group so a restart's bind
    // is not competing with it.
    //
    // The explicit cancel-and-flush that used to stand here is gone into
    // close_fd, which submits the same cancel and — unlike a flush, which under
    // SQPOLL does not even make a syscall — holds the descriptor number until
    // both the accept and the cancel have actually reported.  Flushing and
    // closing left both of them able to resolve the number after the next
    // accept had taken it.
    if (m_listen_fd >= 0)
    {
        shutdown(m_listen_fd, SHUT_RDWR);
        close_tracked(m_listen_fd);
        m_listen_fd = -1;
    }

    // Drain: flush pending write queues with blocking writes
    if (get_drain())
    {
        for (auto& [fd, conn] : m_clients)
        {
            // ── a session's bytes are records, drain or no drain ──
            //
            // These are blocking writes straight at the descriptor, and on a
            // TLS connection the buffers below are plaintext.  Writing them
            // here as-is would send the answers to a peer's last commands in
            // the clear, at shutdown, on the one port the operator encrypted —
            // a downgrade that only ever happens on the way out and is
            // therefore the one nobody would catch.
            //
            // So they go through the session: encrypted, then the ciphertext
            // the write BIO produced is what reaches the socket.  A session
            // that is not ready yet — a handshake still in flight — has no way
            // to encrypt anything, and the reply is dropped rather than
            // downgraded.  A lost reply on shutdown is recoverable; cleartext
            // is not.
            if (SOCKETLEY_UNLIKELY(conn->ssl != nullptr))
            {
                if (conn->tls_state != tls_conn_ready)
                    continue;

                if (!conn->response_buf.empty())
                {
                    conn->write_queue.push(std::move(conn->response_buf));
                    conn->response_buf.clear();
                }

                bool broken = false;
                while (!conn->write_queue.empty() && !broken)
                {
                    const std::string& msg = conn->write_queue.front();
                    const int n = tls_context::ssl_write(conn->ssl, msg.data(),
                                                         static_cast<int>(msg.size()));
                    // 0 is the write BIO at its cap and -1 is a dead session;
                    // neither recovers here, because nothing is going to drain
                    // it for us after this loop.
                    if (n <= 0 || static_cast<size_t>(n) != msg.size())
                        broken = true;
                    else
                        conn->write_queue.pop();

                    // Out of the BIO and onto the wire as we go, so one
                    // oversized queue cannot buffer past the cap that made
                    // ssl_write refuse in the first place.
                    char cbuf[16384];
                    for (;;)
                    {
                        const int c = tls_context::bio_read_out(conn->ssl, cbuf, sizeof(cbuf));
                        if (c <= 0)
                            break;
                        if (!socketley::write_all(fd, cbuf, static_cast<size_t>(c)))
                        {
                            broken = true;
                            break;
                        }
                    }
                }
                continue;
            }

            // Flush response_buf first.
            //
            // Giving up on this client must not give up on the rest: the break
            // below used to leave the enclosing for-loop, so one peer that had
            // already hung up cost every remaining client its pending replies.
            if (!conn->response_buf.empty())
            {
                if (!socketley::write_all(fd, conn->response_buf.data(),
                                          conn->response_buf.size()))
                    continue;
            }
            while (!conn->write_queue.empty())
            {
                const auto& msg = conn->write_queue.front();
                if (!socketley::write_all(fd, msg.data(), msg.size()))
                    break;
                conn->write_queue.pop();
            }
        }
    }

    std::memset(m_conn_idx, 0, sizeof(m_conn_idx));

    // The listener goes first, then everything that hangs off it.  Each object
    // is closed and then handed to pool_release()/retire(), which keeps it —
    // and its io_requests, still pointing here — until the ring has finished
    // with it.  The next setup() starts from nothing and touches none of this.
    for (auto& [fd, conn] : m_clients)
    {
        // Release fixed file slot before closing
        if (conn->direct_fd && conn->fixed_idx >= 0)
        {
            m_loop->free_fixed_file_slot(static_cast<uint32_t>(conn->fixed_idx));
            conn->fixed_idx = -1;
            conn->direct_fd = false;
        }
        // shutdown() before close() so an armed read or write is completed by
        // the kernel now rather than whenever the peer gets around to it.
        shutdown(fd, SHUT_RDWR);
        close_tracked(fd);
        // Drop the subscriptions with the socket.  Leaving them in the store
        // let a connection that later landed on the same fd number inherit the
        // dead client's channels.
        m_store.unsubscribe_all(fd);
        // A follower promoted from this connection must lose the descriptor
        // before the loop below sees it, or it would close the number a second
        // time.
        detach_follower(fd);
        pool_release(std::move(conn));
    }
    m_clients.clear();

    // Close replication connections
    if (m_master)
    {
        if (m_master->fd >= 0)
        {
            shutdown(m_master->fd, SHUT_RDWR);
            close_tracked(m_master->fd);
            m_master->fd = -1;
        }
        io_request* owed[1];
        size_t n = 0;
        if (m_master->read_pending)
            owed[n++] = &m_master->read_req;
        retire(std::shared_ptr<void>(std::move(m_master)), owed, n);
    }
    for (auto& f : m_followers)
    {
        // The socket belonged to the client connection above, which has already
        // closed it; only the buffers are ours to account for here.  The kernel
        // reads straight out of f->out for the duration of a write, which is
        // why this object cannot simply be dropped.
        f->fd = -1;
        f->dead = true;
        io_request* owed[1];
        size_t n = 0;
        if (f->write_pending)
            owed[n++] = &f->write_req;
        retire(std::shared_ptr<void>(std::move(f)), owed, n);
    }
    m_followers.clear();

    // Withdraw every timer this run armed, before they are retired below.
    //
    // Nothing above reached them: a timeout hangs off no descriptor, so the
    // shutdown()s and the cancel on the listen fd walked straight past, and the
    // ring went on owing this owner one completion per armed timer — half a
    // second for the TTL sweep, thirty for the idle sweep.  reap_retired() frees
    // a removed instance only once that count reaches zero, and with the TTL
    // sweep re-arming itself every half second it never did: the whole cache
    // stayed in the graveyard, about 6 MB, until the daemon exited.
    //
    // A withdrawal does not take the completion away, it brings it forward: the
    // timeout reports once more with -ECANCELED, which is the completion the
    // retire() below is already waiting for, so every `owed` count here stays
    // exactly as it was.  Withdrawing only where a completion is genuinely owed
    // matters for the same reason — the cancelled timeout is delivered carrying
    // the address of its request, and retire() with a count of zero would have
    // freed the storage that address points into.
    if (m_loop)
    {
        bool withdrawn = true;
        if (m_ttl_timer_armed && m_ttl_timer)
            withdrawn &= m_loop->submit_timeout_remove(&m_ttl_timer->req);
        if (m_idle_sweep_timer)
            withdrawn &= m_loop->submit_timeout_remove(&m_idle_sweep_timer->req);
        if (m_accept_backoff_timer)
            withdrawn &= m_loop->submit_timeout_remove(&m_accept_backoff_timer->req);
        m_loop->flush();

        if (SOCKETLEY_UNLIKELY(!withdrawn))
            LOG_WARN("cache: a timer withdrawal did not reach the ring — this instance "
                     "stays retired until the timer fires on its own");
    }

    // The timers and the listener, for the reason on timer_op: nothing cancels
    // an io_uring timeout, and the accept completion is still owed.  Retiring
    // them costs a few dozen bytes per stop; re-arming them cost a second timer
    // chain per restart, each one keeping the next alive.
    {
        io_request* owed[1];
        if (m_accept)
        {
            owed[0] = &m_accept->req;
            retire(std::shared_ptr<void>(std::move(m_accept)), owed, 1);
        }
        if (m_ttl_timer)
        {
            const size_t n = m_ttl_timer_armed ? 1 : 0;
            owed[0] = &m_ttl_timer->req;
            retire(std::shared_ptr<void>(std::move(m_ttl_timer)), owed, n);
        }
        if (m_idle_sweep_timer)
        {
            owed[0] = &m_idle_sweep_timer->req;
            retire(std::shared_ptr<void>(std::move(m_idle_sweep_timer)), owed, 1);
        }
        if (m_accept_backoff_timer)
        {
            owed[0] = &m_accept_backoff_timer->req;
            retire(std::shared_ptr<void>(std::move(m_accept_backoff_timer)), owed, 1);
        }
    }

    m_ttl_timer_armed = false;
    m_loop = nullptr;
    m_multishot_active = false;
}

void cache_instance::arm_ttl_timer()
{
    if (m_ttl_timer_armed || !m_loop || !m_ttl_timer)
        return;
    m_ttl_timer_armed = true;
    if (SOCKETLEY_UNLIKELY(!m_loop->submit_timeout(&m_ttl_timer->ts, &m_ttl_timer->req)))
    {
        // Clear the flag again.  Nothing else would ever retry: mark_ttl_keys()
        // only submits while the flag is unset, so a single refused timeout
        // would stop the sweep for the lifetime of the runtime and leave every
        // key with an expiry holding its memory until something touched it.
        m_ttl_timer_armed = false;
        LOG_WARN("cache: TTL sweep timer refused — expired keys keep their memory until touched");
    }
}

void cache_instance::mark_ttl_keys()
{
    m_has_ttl_keys = true;
    arm_ttl_timer();
}

void cache_instance::on_cqe(struct io_uring_cqe* cqe)
{
    auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
    if (!req)
        return;

    // Before anything else, and before the check below that gives up while the
    // runtime is stopped: this may be the completion a previous run is still
    // owed, and it is the one that lets the memory behind it go.
    if (SOCKETLEY_UNLIKELY(!m_retired.empty()) && absorb_retired(req, cqe))
        return;

    if (!m_loop)
        return;

    // Periodic TTL sweep timer
    if (m_ttl_timer && req == &m_ttl_timer->req)
    {
        m_ttl_timer_armed = false;
        if (!m_has_ttl_keys)
            return;    // nothing to expire: stay off until mark_ttl_keys()
        auto expired_keys = m_store.sweep_expired();
        m_has_ttl_keys = m_store.has_expiry_keys();
        m_stat_keys_expired += expired_keys.size();
#ifndef SOCKETLEY_NO_LUA
        if (lua() && lua()->has_on_expire() && !expired_keys.empty())
        {
            for (const auto& key : expired_keys)
            {
                {
                    sol::protected_function_result r = lua()->on_expire()(key);
                    if (SOCKETLEY_UNLIKELY(!r.valid()))
                    {
                        sol::error e = r;
                        std::cerr << lua_diag::tag(get_name()) << " on_expire error: " << e.what() << "\n";
                    }
                }
            }
        }
#endif
        // Only keep sweeping while keys with an expiry remain.  sweep_expired()
        // may have removed the last one, in which case the timer stops here.
        if (m_has_ttl_keys)
            arm_ttl_timer();
        return;
    }

    // Read from the master (replication), matched by request rather than by fd.
    // The link owns its request, so this cannot be confused with a client that
    // happens to sit on the same descriptor number.
    if (m_master && req == &m_master->read_req)
    {
        handle_master_read(cqe);
        return;
    }

    // Replication writes, matched by request pointer rather than by fd: a
    // follower reached the leader as an ordinary client, so its socket also has
    // a client_connection and the generic write handler would otherwise claim
    // these completions and look up the wrong state.
    for (auto& f : m_followers)
    {
        if (req == &f->write_req)
        {
            handle_follower_write(cqe, *f);
            reap_followers();
            return;
        }
    }

    // Remembered before the dispatch: the handler may release the struct and the
    // request along with it.  Only per-connection operations name a connection.
    const int cqe_fd = (req->type == op_accept || req->type == op_multishot_accept ||
                        req->type == op_timeout)
                       ? -1 : req->fd;

    switch (req->type)
    {
        case op_accept:
        case op_multishot_accept:
            handle_accept(cqe);
            break;
        case op_read:
        case op_read_provided:
        case op_recv_multishot:
            handle_read(cqe, req);
            break;
        case op_write:
        case op_writev:
        case op_send_zc:
        case op_send_zc_notif:
            handle_write(cqe, req);
            break;
        case op_timeout:
            if (m_idle_sweep_timer && req == &m_idle_sweep_timer->req)
            {
                auto now = std::chrono::steady_clock::now();
                auto timeout = std::chrono::seconds(m_idle_timeout_cached);
                for (auto& [cfd, cconn] : m_clients)
                {
                    // A replication follower is idle by definition: it may not
                    // send anything once promoted, and the stream it receives
                    // never touches last_activity.  Sweeping it would tear
                    // replication down on a timer for behaving correctly.
                    if (cconn->is_follower)
                        continue;
                    if (!cconn->closing && (now - cconn->last_activity) > timeout)
                    {
                        cconn->closing = true;
                        shutdown(cfd, SHUT_RD);
                    }
                }
                if (SOCKETLEY_UNLIKELY(!m_loop->submit_timeout(&m_idle_sweep_timer->ts,
                                                               &m_idle_sweep_timer->req)))
                    LOG_ERROR("cache: idle sweep timer refused — no further sweeps will run");
            }
            // Accept backoff expired — resubmit accept.  The timer has spoken,
            // so it owes nothing more and the next shortage may arm a new one.
            else if (m_accept_backoff_timer && req == &m_accept_backoff_timer->req)
            {
                m_accept_backoff_timer.reset();
                if (m_listen_fd >= 0)
                    rearm_accept();
            }
            break;
        default:
            break;
    }

    // ── The chokepoint ──────────────────────────────────────────────────────
    //
    // Every teardown in this runtime runs out of a completion handler, and
    // every completion handler runs from here.  The handlers each decide for
    // themselves whether the connection they just touched can be finished, and
    // seven of those decisions say a connection with a read armed cannot be —
    // "a completion is still owed, so the teardown will run when it lands".
    //
    // For a read that is not true, and it is the only one of the three flags
    // for which it is not.  A write and a zero-copy notification are requests
    // the ring answers whatever the socket does.  An armed read is finished by
    // the peer sending something, or by the socket ending — and a connection
    // that is closing is one whose peer has already gone.  free_fixed_file_slot()
    // records the same finding one level down: a multishot recv "could only ever
    // end by itself, and by itself means the peer or the socket".
    //
    // So this runs after the dispatch, for the connection the completion named,
    // and finishes it when nothing the ring owes can.  Taking the read back is
    // close_client()'s to do and it already does it: close_fd() cancels one
    // armed on a descriptor, free_fixed_file_slot() cancels one armed on a fixed
    // index, and retire() holds the struct until that -ECANCELED lands.
    finish_unreachable_client(cqe_fd);

#ifdef SOCKETLEY_INVARIANTS
    inv_check_reachable(cqe_fd, "cache::on_cqe");
#endif
}

// See the call site in on_cqe() for why this exists.  Everything here is a
// guard: a descriptor with no connection on it, or one that is not closing, or
// one the ring still owes an answer for, is somebody else's business.
void cache_instance::finish_unreachable_client(int fd)
{
    if (fd < 0 || fd >= MAX_FDS)
        return;
    auto* conn = m_conn_idx[fd];
    if (SOCKETLEY_LIKELY(conn == nullptr || !conn->closing))
        return;

    // The two the ring genuinely owes.  Their completion comes back here and
    // asks this question again.
    if (conn->write_pending || conn->zc_notif_pending)
        return;

    // Bytes the client already handed us and considers answered are not
    // "nothing left": push them out and let the write completion finish the
    // teardown, exactly as the closing block in handle_read does.  A flush can
    // legitimately submit nothing — a TLS session with a reply queued while the
    // handshake is still running has output and no way to send it — and that
    // leaves nothing to wake it either.
    if (conn_has_output(conn))
    {
        if (SOCKETLEY_UNLIKELY(!flush_write_queue(conn)))
        {
            close_client(conn, fd, "unreachable-write-submit-failed");
            return;
        }
        if (conn->write_pending || conn->zc_notif_pending)
            return;
        close_client(conn, fd, "unreachable-with-unsendable-output");
        return;
    }

    close_client(conn, fd, "unreachable-closing");
}

#ifdef SOCKETLEY_INVARIANTS
// Invariant (1) from invariants.h.  A cache client has no peer — it asks and is
// answered on the one socket — so the pair here is a single half, and the
// question is simply whether the ring still owes it anything.  If it does not,
// nothing will ever run the read that would take its next command, and whatever
// is in its write queue is an answer that will never be sent.
void cache_instance::inv_check_reachable(int fd, const char* where)
{
    if (fd < 0 || fd >= MAX_FDS)
        return;

    const auto* conn = m_conn_idx[fd];
    if (!conn)
        return;   // already torn down: nothing left that needs waking

    skl_inv::half c{};
    c.present   = true;
    c.in_flight = conn->read_pending || conn->write_pending || conn->zc_notif_pending;
    // response_buf counts as queued too: it is answers already built and not yet
    // handed to the write path, which is the same loss with one hop less.
    c.queued    = !conn->write_queue.empty() || !conn->response_buf.empty();
    c.closing   = conn->closing;
    c.fd        = conn->fd;

    SKL_INV_PAIR(where, c, skl_inv::half{});
}
#endif

void cache_instance::handle_accept(struct io_uring_cqe* cqe)
{
    int client_fd = cqe->res;

    if (client_fd >= 0)
    {
        // Reject fds beyond our O(1) lookup table — they'd become zombie connections
        if (client_fd >= MAX_FDS)
        {
            close_tracked(client_fd);
            goto cache_resubmit_accept;
        }

        if (m_max_conns_cached > 0 && m_clients.size() >= m_max_conns_cached)
        {
            close_tracked(client_fd);
            goto cache_resubmit_accept;
        }

        int opt = 1;
        setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

        m_stat_total_connections.fetch_add(1, std::memory_order_relaxed);

        auto conn = pool_acquire(client_fd);
        SKL_TRACE_SET(conn, opened_ms, ::skl_trace::now_ms());
        conn->partial.reserve(4096);
        conn->response_buf.reserve(4096);
        conn->read_req = { this, conn->read_buf, client_fd, sizeof(conn->read_buf), op_read };
        conn->write_req = { this, nullptr, client_fd, 0, op_write };

        // Register fd in fixed file table for fget/fput-free I/O
        int slot = m_loop->alloc_fixed_file_slot();
        if (slot >= 0 && m_loop->update_registered_file(static_cast<uint32_t>(slot), client_fd))
        {
            conn->fixed_idx = slot;
            conn->direct_fd = true;
        }

        auto* ptr = conn.get();
        m_clients[client_fd] = std::move(conn);
        if (client_fd < MAX_FDS)
            m_conn_idx[client_fd] = ptr;

        // A TLS listener gives every accepted socket a session before anything
        // else touches the connection.  The session is created here and the
        // handshake starts on the first read completion — nothing is written
        // yet, because the client speaks first.
        if (SOCKETLEY_UNLIKELY(m_tls != nullptr))
        {
            ptr->ssl = m_tls->create_ssl_server();
            if (SOCKETLEY_UNLIKELY(!ptr->ssl))
            {
                // No session, no encryption, so no connection.  Serving this
                // client in cleartext is the one alternative and it is worse
                // than dropping it.
                shutdown(client_fd, SHUT_RDWR);
                close_client(ptr, client_fd, "tls-session-alloc-failed");
                goto cache_resubmit_accept;
            }
            ptr->tls_state = tls_conn_handshake;
        }

        // Initialize rate limiting
        auto now_tp = std::chrono::steady_clock::now();
        if (m_rate_limit_cached > 0)
        {
            ptr->rl_max = m_rate_limit_cached;
            ptr->rl_tokens = m_rate_limit_cached;
            ptr->rl_last = now_tp;
        }

        ptr->last_activity = now_tp;

        // A connection whose very first read cannot be armed has no way to make
        // progress: the client would sit on an open socket that this side never
        // reads from.  Nothing else touches ptr after this, so the teardown is
        // safe here — the accept is still re-armed below.
        if (SOCKETLEY_UNLIKELY(!submit_client_read(ptr, client_fd)))
            close_client(ptr, client_fd, "read-submit-failed");
    }

    // EMFILE/ENFILE: backoff 100ms to avoid CPU spin when fd limit is hit
    if (client_fd == -EMFILE || client_fd == -ENFILE)
    {
        schedule_accept_backoff();
        return;
    }

cache_resubmit_accept:
    if (m_multishot_active)
    {
        if (!(cqe->flags & IORING_CQE_F_MORE))
            rearm_accept();
    }
    else
    {
        rearm_accept();
    }
}

bool cache_instance::submit_client_read(client_connection* conn, int fd)
{
    if (SOCKETLEY_UNLIKELY(!m_loop))
        return false;

    conn->read_pending = true;
    bool queued;
    if (conn->direct_fd)
    {
        if (m_recv_multishot)
            queued = m_loop->submit_recv_multishot_fixed_file(conn->fixed_idx, BUF_GROUP_ID, &conn->read_req);
        else if (m_use_provided_bufs)
            queued = m_loop->submit_read_provided_fixed_file(conn->fixed_idx, BUF_GROUP_ID, &conn->read_req);
        else
            queued = m_loop->submit_read_fixed_file(conn->fixed_idx, conn->read_buf, sizeof(conn->read_buf), &conn->read_req);
    }
    else
    {
        if (m_recv_multishot)
            queued = m_loop->submit_recv_multishot(fd, BUF_GROUP_ID, &conn->read_req);
        else if (m_use_provided_bufs)
            queued = m_loop->submit_read_provided(fd, BUF_GROUP_ID, &conn->read_req);
        else
            queued = m_loop->submit_read(fd, conn->read_buf, sizeof(conn->read_buf), &conn->read_req);
    }

    // Leaving the flag set after a refusal is what turns a busy ring into a hung
    // connection: every path here treats read_pending as "a completion is on its
    // way", and none is.
    if (SOCKETLEY_UNLIKELY(!queued))
        conn->read_pending = false;
    return queued;
}

void cache_instance::schedule_accept_backoff()
{
    if (SOCKETLEY_UNLIKELY(!m_loop))
        return;

    // One backoff timer at a time.  A second one on the same request would give
    // the listener two retry chains, and the earlier timeout cannot be taken
    // back — it is not attached to any descriptor.
    if (m_accept_backoff_timer)
        return;

    m_accept_backoff_timer = std::make_unique<timer_op>();
    m_accept_backoff_timer->ts.tv_sec = 0;
    m_accept_backoff_timer->ts.tv_nsec = 100000000LL;
    m_accept_backoff_timer->req = { this, nullptr, -1, 0, op_timeout };
    if (SOCKETLEY_UNLIKELY(!m_loop->submit_timeout(&m_accept_backoff_timer->ts,
                                                   &m_accept_backoff_timer->req)))
    {
        m_accept_backoff_timer.reset();
        LOG_ERROR("cache: accept could not be re-armed and the retry timer was refused too — "
                  "the listener has stopped taking connections");
    }
}

void cache_instance::rearm_accept()
{
    if (SOCKETLEY_UNLIKELY(!m_loop || m_listen_fd < 0 || !m_accept))
        return;

    bool queued;
    if (m_multishot_active)
    {
        queued = m_loop->submit_multishot_accept(m_listen_fd, &m_accept->req);
    }
    else
    {
        m_accept->addrlen = sizeof(m_accept->addr);
        queued = m_loop->submit_accept(m_listen_fd, &m_accept->addr, &m_accept->addrlen,
                                       &m_accept->req);
    }

    // The listener has no completion left to bring it back, so fall back to the
    // backoff timer rather than going deaf without a word.
    if (SOCKETLEY_UNLIKELY(!queued))
        schedule_accept_backoff();
}

// Ciphertext in, plaintext into conn->partial.  One call per read completion,
// which is what makes the handshake asynchronous: OpenSSL is handed the bytes
// that have arrived and asked what it makes of them, and whatever it wants to
// say back is drained by tls_flush at the end of handle_read.  Several rounds
// of that is a handshake; there is no loop here waiting for one.
//
// This is the server runtime's implementation over the cache's connection
// struct, and deliberately not a second design.  The two structs differ in what
// they queue — owned strings here, shared_ptr there — and in nothing this
// function touches.
void cache_instance::tls_feed(client_connection* conn, const char* data, size_t len)
{
    // Inbound ciphertext into the read BIO.  A refusal is fatal by contract —
    // the peer is over the per-connection buffer cap, or the BIO failed — and
    // it has to be: there is nowhere to hold what was not taken, and handing a
    // record layer a stream with a hole in it is worse than closing.
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
            // Closing, but not silently: what OpenSSL produced on its way to
            // failing is the alert that tells the peer why, and it is the only
            // diagnosis the other end will ever get.  tls_flush at the end of
            // handle_read puts it on the wire, and the connection is torn down
            // when that write completes.
            //
            // This is also the path a plaintext client takes.  A RESP command
            // or a bare line is not a TLS record, so the handshake fails here
            // and the connection is dropped — it is never parsed as a command,
            // which is the whole point of refusing rather than downgrading.
            conn->closing = true;
            return;
        }
        if (r == 0)
            return;   // another round; its records go out at the end of the read

        conn->tls_state = tls_conn_ready;
        // Deliberately falling through rather than returning: the same read can
        // already carry application data behind the handshake's last flight —
        // under TLS 1.3 a client's Finished and its first command routinely
        // arrive in one packet, and returning here would leave that command
        // sitting in the BIO until the client sent something else.
    }

    // Plaintext into partial, where RESP detection and the line parser read it.
    char plain[16384];
    for (;;)
    {
        const int n = tls_context::ssl_read(conn->ssl, plain, sizeof(plain));
        if (SOCKETLEY_LIKELY(n > 0))
        {
            conn->partial.append(plain, static_cast<size_t>(n));
            // The same ceiling the cleartext path applies, checked inside the
            // loop rather than after it: one read completion can decrypt
            // everything the inbound BIO had buffered, so "one read cannot
            // produce more than one buffer's worth" is not true here.
            if (SOCKETLEY_UNLIKELY(conn->partial.size() > client_connection::MAX_PARTIAL_SIZE))
            {
                conn->closing = true;
                break;
            }
            continue;
        }
        if (n < 0)
        {
            // Either the peer's close_notify or a record we cannot use.  Both
            // end the connection, and neither ends it here: the bytes decrypted
            // above may be a command that deserves an answer, so this is
            // recorded and applied once handle_read has parsed them.
            conn->tls_peer_closed = true;
        }
        break;
    }
}

void cache_instance::tls_close_when_read_is_all(client_connection* conn, int fd)
{
    // See the declaration for why this exists at all.  Everything here is a
    // guard: a connection that is not closing, or still owes a write, or has
    // no session, is somebody else's business.
    if (!conn->closing || conn->ssl == nullptr)
        return;
    if (conn->write_pending || conn->zc_notif_pending || !conn->read_pending)
        return;
    if (fd < 0)
        return;

    shutdown(fd, SHUT_RDWR);
}

bool cache_instance::conn_has_output(const client_connection* conn) const
{
    if (!conn->write_queue.empty())
        return true;
    // A TLS connection can owe the wire bytes with an empty queue: a handshake
    // flight, an alert, a session ticket, or ciphertext that did not fit in the
    // write that just completed.
    return conn->ssl != nullptr && tls_context::has_pending_out(conn->ssl);
}

// Every byte a TLS connection sends is a record, including the ones nobody
// queued.  Reached from flush_write_queue for a TLS connection and from the end
// of handle_read; there is no other way onto the wire.
bool cache_instance::tls_flush(client_connection* conn)
{
    if (SOCKETLEY_UNLIKELY(!m_loop || !conn->ssl))
        return true;

    // One write in flight at a time, exactly as the cleartext path does — the
    // ciphertext buffer built below is what the kernel reads out of, and a
    // second submission would need a second buffer and would interleave two
    // record streams on one socket.  Whatever does not go now stays in the
    // queue or in the write BIO; handle_write comes back here when this write
    // lands.
    if (conn->write_pending || conn->zc_notif_pending)
        return true;

    // Application data only once the handshake is done.  A reply queued before
    // a single record has crossed waits here rather than being handed to an SSL
    // that would answer WANT_READ and leave the caller unsure what was
    // consumed.
    if (conn->tls_state == tls_conn_ready)
    {
        while (!conn->write_queue.empty())
        {
            const std::string& msg = conn->write_queue.front();
            const int n = tls_context::ssl_write(conn->ssl, msg.data(),
                                                 static_cast<int>(msg.size()));
            if (n <= 0)
            {
                // 0 is backpressure: the write BIO is at its cap, and OpenSSL's
                // contract is that the same buffer is offered again once it has
                // drained — which is what leaving this message at the front of
                // the queue arranges.  -1 is fatal for the session.
                if (n < 0)
                    conn->closing = true;
                break;
            }
            // Partial writes are not enabled on this context, so SSL_write is
            // all-or-nothing.  A short count would mean the record layer and
            // this queue disagree about what has been sent, and a stream with a
            // hole in it has no framing left to recover: close instead.
            if (SOCKETLEY_UNLIKELY(static_cast<size_t>(n) != msg.size()))
            {
                conn->closing = true;
                break;
            }
            conn->write_queue.pop();
        }
    }

    if (!tls_context::has_pending_out(conn->ssl))
        return true;

    // Ciphertext out of the write BIO and into a buffer this connection owns.
    // It has to be copied rather than pointed at: an SQE names an address the
    // kernel reads at its leisure, and the BIO's storage moves under it as
    // OpenSSL writes the next record.  Copying is also what keeps the SSL free
    // of anything the ring can name, which is what makes the session safe to
    // release the moment the connection is torn down.
    //
    // The buffer then rides in write_batch[0] like any other message, so the
    // short-write retry and the batch release in handle_write need no
    // TLS-specific case at all.
    std::string cipher;
    char buf[16384];
    for (;;)
    {
        const int n = tls_context::bio_read_out(conn->ssl, buf, sizeof(buf));
        if (n <= 0)
            break;
        cipher.append(buf, static_cast<size_t>(n));
    }
    if (SOCKETLEY_UNLIKELY(cipher.empty()))
        return true;

    // Nothing is in flight (checked above), so any buffers still held are from
    // a completed write and are this function's to drop.
    for (uint32_t i = 0; i < conn->write_batch_count; i++)
        conn->write_batch[i].clear();

    conn->write_batch[0] = std::move(cipher);
    conn->write_iovs[0].iov_base = conn->write_batch[0].data();
    conn->write_iovs[0].iov_len  = conn->write_batch[0].size();
    conn->write_batch_count = 1;
    conn->write_pending = true;
    conn->write_req.type = op_write;

    // Plain op_write and never send_zc, unlike the cleartext path.  A zero-copy
    // send answers twice and keeps the kernel reading out of write_batch[0]
    // until the notification lands, and this buffer has to be refilled from the
    // BIO on the very next flush; the notification round trip also costs more
    // than it saves at the sizes a record layer produces.
    const auto len = static_cast<uint32_t>(conn->write_batch[0].size());
    const bool queued = conn->direct_fd
        ? m_loop->submit_write_fixed_file(conn->fixed_idx, conn->write_batch[0].data(),
                                          len, &conn->write_req)
        : m_loop->submit_write(conn->fd, conn->write_batch[0].data(), len, &conn->write_req);

    // Nothing reached the ring, so no completion will arrive.  Undo the
    // in-flight bookkeeping and report it, as the cleartext path does: a
    // write_pending that never clears keeps the teardown waiting for a
    // completion that cannot come.
    if (SOCKETLEY_UNLIKELY(!queued))
    {
        conn->write_pending = false;
        conn->write_batch[0].clear();
        conn->write_batch_count = 0;
        return false;
    }
    return true;
}

void cache_instance::handle_read(struct io_uring_cqe* cqe, io_request* req)
{
    int fd = req->fd;
    if (SOCKETLEY_UNLIKELY(fd < 0 || fd >= MAX_FDS || !m_conn_idx[fd]))
    {
        // Nobody owns this any more, but the buffer it carries belongs to the
        // ring.  Dropping it here leaked one per stale completion, and the group
        // is shared by every cache on this loop.
        if (m_loop) m_loop->return_cqe_buf(cqe, req);
        return;
    }
    auto* conn = m_conn_idx[fd];

    bool is_multishot_recv = (req->type == op_recv_multishot);
    bool multishot_more = is_multishot_recv && (cqe->flags & IORING_CQE_F_MORE);

    // For multishot recv, the read remains pending as long as MORE flag is set
    if (!is_multishot_recv)
        conn->read_pending = false;
    else if (!multishot_more)
    {
        conn->read_pending = false;
        SKL_TRACE_ADD(conn, multishot_ends, 1);
    }

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
            SKL_TRACE_ADD(conn, enobufs, 1);
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
                queued = m_loop->submit_read_fixed_file(conn->fixed_idx, conn->read_buf, sizeof(conn->read_buf), &conn->read_req);
            else
                queued = m_loop->submit_read(fd, conn->read_buf, sizeof(conn->read_buf), &conn->read_req);
            if (SOCKETLEY_UNLIKELY(!queued))
            {
                // The fallback is the only read left for this connection; with
                // it refused there is nothing to wake it again.
                conn->read_pending = false;
                conn->closing = true;
                if (!conn->write_pending && !conn->zc_notif_pending)
                    close_client(conn, fd, "read-submit-failed");
            }
            return;
        }

        // Connection closed or error — defer if a write is still owed.  Drop the
        // subscriptions right away even when deferring: the read side is
        // already gone, so a publish must not queue further writes to it.
        //
        // A zero-copy send answers twice and clears write_pending on the first
        // of them, so write_pending alone says "done" while the kernel is still
        // reading out of write_batch[0] — which the struct's reset() clears the
        // moment it is handed to the next connection.
        m_store.unsubscribe_all(fd);
        if (conn->write_pending || conn->zc_notif_pending)
        {
            conn->closing = true;
        }
        else
        {
            close_client(conn, fd, "read-error-or-eof");
        }
        return;
    }

    // Only update last_activity when idle timeout is configured (avoids clock_gettime syscall)
    if (SOCKETLEY_UNLIKELY(m_idle_timeout_cached > 0))
        conn->last_activity = std::chrono::steady_clock::now();

    // On a TLS connection these bytes are ciphertext and tls_feed is what puts
    // plaintext into partial; everything below this point — RESP detection, the
    // line parser, every command handler — reads exactly the same buffer it
    // always did and knows nothing about TLS.
    if (is_provided)
    {
        uint16_t buf_id = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
        char* buf_ptr = m_loop->get_buf_ptr(BUF_GROUP_ID, buf_id);
        if (buf_ptr)
        {
            if (SOCKETLEY_UNLIKELY(conn->ssl != nullptr))
                tls_feed(conn, buf_ptr, static_cast<size_t>(cqe->res));
            else
                conn->partial.append(buf_ptr, cqe->res);
            SKL_TRACE_ADD(conn, bytes_read, cqe->res);
            SKL_TRACE_ADD(conn, reads, 1);
            // Back to the group whatever the session made of it: the group is
            // shared with every other cache on this loop, and one failed
            // handshake is no reason to starve them.
            m_loop->return_buf(BUF_GROUP_ID, buf_id);
        }
    }
    else if (SOCKETLEY_UNLIKELY(conn->ssl != nullptr))
    {
        tls_feed(conn, conn->read_buf, static_cast<size_t>(cqe->res));
        SKL_TRACE_ADD(conn, bytes_read, cqe->res);
        SKL_TRACE_ADD(conn, reads, 1);
    }
    else
    {
        conn->partial.append(conn->read_buf, cqe->res);
        SKL_TRACE_ADD(conn, bytes_read, cqe->res);
        SKL_TRACE_ADD(conn, reads, 1);
    }

    if (conn->partial.size() > client_connection::MAX_PARTIAL_SIZE)
    {
        conn->closing = true;
        // Same as above: the notification of a zero-copy send is a completion
        // this connection still owes, whatever write_pending says.
        if (!conn->write_pending && !conn->zc_notif_pending)
        {
            close_client(conn, fd, "partial-overflow");
        }
        return;
    }

    // Auto-detect RESP mode on first data
    if (!conn->resp_detected && !conn->partial.empty())
    {
        conn->resp_detected = true;
        if (conn->partial[0] == '*' || m_resp_forced)
            conn->resp_mode = true;
    }

    // A connection that was promoted by REPLICATE is not a client any more: the
    // socket carries the replication stream and this runtime is its only writer.
    // Parsing what arrives on it would produce replies with nowhere to go —
    // handle_replicate_request() has the rule and the reasoning.
    if (SOCKETLEY_UNLIKELY(conn->is_follower))
    {
        refuse_follower_input(conn);
    }
    else if (conn->resp_mode)
    {
        process_resp(conn);
    }
    else
    {
        size_t scan_from = 0;
        size_t pos;
        while ((pos = conn->partial.find('\n', scan_from)) != std::string::npos)
        {
            std::string_view line(conn->partial.data() + scan_from, pos - scan_from);

            if (!line.empty() && line.back() == '\r')
                line.remove_suffix(1);

            SKL_TRACE_ADD(conn, commands_parsed, 1);
            const size_t rb_before = conn->response_buf.size();
            process_command(conn, line);
            if (conn->response_buf.size() != rb_before)
                SKL_TRACE_ADD(conn, responses_made, 1);

            scan_from = pos + 1;

            // REPLICATE takes effect on the line that carried it, so the rest of
            // the batch is already follower input.  Answering it would put a
            // second writer on the socket the dump is going out on.
            if (SOCKETLEY_UNLIKELY(conn->is_follower))
                break;
        }

        if (scan_from > 0)
        {
            if (scan_from >= conn->partial.size())
                conn->partial.clear();
            else
                conn->partial.erase(0, scan_from);
        }

        // Whatever was pipelined behind REPLICATE is refused, not executed.
        if (SOCKETLEY_UNLIKELY(conn->is_follower && !conn->partial.empty()))
            refuse_follower_input(conn);
    }

    // Flush accumulated responses as single write
    if (SOCKETLEY_UNLIKELY(!flush_responses(conn)))
        conn->closing = true;

    // ── the TLS half of the same idea ──
    //
    // The peer's close_notify is applied here rather than where it was read:
    // the read that carried it can carry the last command ahead of it, and
    // marking the connection closing any earlier would have made the parse
    // above throw that command away with the answer half computed.
    //
    // Then one flush for everything the record layer owes the wire — the next
    // handshake flight, the alert explaining a handshake that just failed, a
    // session ticket, and whatever flush_responses left in the queue because
    // the handshake was not finished when it ran.  It has to happen even when
    // the connection is already closing, which is why it is not inside
    // flush_responses: that returns early on a closing connection, and the
    // alert is the only diagnosis the other end will ever get.
    if (SOCKETLEY_UNLIKELY(conn->ssl != nullptr))
    {
        if (conn->tls_peer_closed)
            conn->closing = true;
        if (SOCKETLEY_UNLIKELY(!tls_flush(conn)))
            conn->closing = true;
    }

    if (m_loop && !conn->closing)
    {
        if (!conn->read_pending && SOCKETLEY_UNLIKELY(!submit_client_read(conn, fd)))
        {
            close_client(conn, fd, "read-submit-failed");
            return;
        }
        return;
    }

    // Closing with nothing left in flight.  Every teardown in this runtime used
    // to run out of a completion handler, which only works while a completion is
    // still owed: a connection marked closing after its last operation had
    // already finished sat here holding its fd and its subscriptions until the
    // runtime stopped.  A refused submission makes that the ordinary case rather
    // than a corner one, because the completion being waited on never existed.
    if (conn->closing && !conn->read_pending && !conn->write_pending && !conn->zc_notif_pending)
    {
        // A queue that still holds data is not "nothing in flight": those are
        // bytes the client already handed us and considers answered.  Push them
        // out and let the write completion finish the teardown; closing on top
        // of them discards a reply that was accepted.
        //
        // conn_has_output and not the queue alone, for the TLS case: a session
        // can owe the wire an alert or the tail of a record with an empty
        // queue, and that alert is what tells the peer why its handshake
        // failed.
        if (conn_has_output(conn))
        {
            if (SOCKETLEY_UNLIKELY(!flush_write_queue(conn)))
            {
                close_client(conn, fd, "write-submit-failed");
                return;
            }
            // A flush can legitimately submit nothing — a TLS connection with
            // a reply queued while the handshake is still running has output
            // and no way to send it.  Without this the connection would be
            // left closing with nothing in flight and nothing to wake it.
            if (SOCKETLEY_UNLIKELY(!conn->write_pending && !conn->zc_notif_pending))
                close_client(conn, fd, "closing-with-unsendable-output");
        }
        else
        {
            close_client(conn, fd, "closing-nothing-in-flight");
        }
        return;
    }

    // Closing, with the read as the only thing still outstanding.  A session
    // gets here after its alert has been queued; nothing will complete that
    // read unless the socket is moved.
    tls_close_when_read_is_all(conn, fd);
}

void cache_instance::handle_write(struct io_uring_cqe* cqe, io_request* req)
{
    int fd = req->fd;
    if (fd < 0 || fd >= MAX_FDS || !m_conn_idx[fd])
        return;
    auto* conn = m_conn_idx[fd];

    // Zero-copy send notification: buffer is now safe to release
    if (cqe->flags & IORING_CQE_F_NOTIF)
    {
        conn->zc_notif_pending = false;
        for (uint32_t i = 0; i < conn->write_batch_count; i++)
            conn->write_batch[i].clear();
        conn->write_batch_count = 0;

        // Drain queue if we were waiting for NOTIF
        if (!conn->write_queue.empty() && !conn->write_pending)
        {
            if (SOCKETLEY_UNLIKELY(!flush_write_queue(conn)))
            {
                conn->closing = true;
                if (!conn->read_pending)
                    close_client(conn, fd, "write-submit-failed");
            }
        }
        else if (conn->write_queue.empty() && !conn->write_pending &&
                 conn->closing && !conn->read_pending)
        {
            close_client(conn, fd, "write-failed");
        }
        return;
    }

    conn->write_pending = false;
    SKL_TRACE_ADD(conn, writes, 1);
    if (cqe->res > 0)
        SKL_TRACE_ADD(conn, bytes_written, cqe->res);

    if (cqe->res <= 0)
    {
        SKL_TRACE_LOG("write failed fd=%d res=%d", fd, cqe->res);
        if (!conn->zc_notif_pending)
        {
            for (uint32_t i = 0; i < conn->write_batch_count; i++)
                conn->write_batch[i].clear();
            conn->write_batch_count = 0;
        }
        conn->closing = true;
        if (!conn->read_pending && !conn->zc_notif_pending)
        {
            close_client(conn, fd, "write-drained-closing");
        }
        return;
    }

    // Short write handling: resubmit remaining bytes
    if (!conn->zc_notif_pending && conn->write_batch_count > 0)
    {
        size_t total_submitted = 0;
        for (uint32_t i = 0; i < conn->write_batch_count; i++)
            total_submitted += conn->write_iovs[i].iov_len;

        size_t written = static_cast<size_t>(cqe->res);
        if (written < total_submitted)
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

            uint32_t new_count = conn->write_batch_count - first_iov;
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

            conn->write_pending = true;
            bool queued;
            if (new_count == 1)
            {
                conn->write_req.type = op_write;
                if (conn->direct_fd)
                    queued = m_loop->submit_write_fixed_file(conn->fixed_idx,
                        static_cast<const char*>(conn->write_iovs[0].iov_base),
                        static_cast<uint32_t>(conn->write_iovs[0].iov_len),
                        &conn->write_req);
                else
                    queued = m_loop->submit_write(conn->fd,
                        static_cast<const char*>(conn->write_iovs[0].iov_base),
                        static_cast<uint32_t>(conn->write_iovs[0].iov_len),
                        &conn->write_req);
            }
            else
            {
                conn->write_msg.msg_iov = conn->write_iovs;
                conn->write_msg.msg_iovlen = new_count;
                conn->write_req.type = op_writev;
                if (conn->direct_fd)
                    queued = m_loop->submit_sendmsg_fixed_file(conn->fixed_idx, &conn->write_msg, &conn->write_req);
                else
                    queued = m_loop->submit_sendmsg(conn->fd, &conn->write_msg, &conn->write_req);
            }
            if (SOCKETLEY_UNLIKELY(!queued))
            {
                // The tail of a short write cannot be handed over.  Leaving
                // write_pending set strands the connection halfway through a
                // reply, and the client would keep waiting for the rest of a
                // response that no completion is left to finish.
                conn->write_pending = false;
                conn->closing = true;
                if (!conn->read_pending && !conn->zc_notif_pending)
                    close_client(conn, fd, "write-submit-failed");
            }
            return;
        }
    }

    // Full write completed — release batch
    if (!conn->zc_notif_pending)
    {
        for (uint32_t i = 0; i < conn->write_batch_count; i++)
            conn->write_batch[i].clear();
        conn->write_batch_count = 0;
    }

    // Flush whatever is still owed.  conn_has_output and not the queue alone:
    // a TLS connection owes the wire the next handshake flight, a session
    // ticket or the tail of a record with nothing queued at all, and asking
    // only about the queue is how a handshake stalls one round short of
    // finishing.
    if (conn_has_output(conn) && !conn->zc_notif_pending)
    {
        if (SOCKETLEY_UNLIKELY(!flush_write_queue(conn)))
        {
            conn->closing = true;
            if (!conn->read_pending && !conn->zc_notif_pending)
                close_client(conn, fd, "write-submit-failed");
            return;
        }
        // Same corner as in handle_read: a flush that submits nothing leaves a
        // closing connection with no completion left to finish it.
        if (SOCKETLEY_UNLIKELY(conn->closing && !conn->write_pending &&
                               !conn->zc_notif_pending && !conn->read_pending))
            close_client(conn, fd, "closing-with-unsendable-output");
    }
    else
    {
        if (conn->closing && !conn->read_pending && !conn->zc_notif_pending)
        {
            close_client(conn, fd, "idle-sweep");
        }
        else
        {
            // The alert this write just carried was the last thing owed; the
            // read is all that is left and no one is going to complete it.
            tls_close_when_read_is_all(conn, fd);
        }
    }
}

// ─── Helper: parse int from string_view ───

static bool parse_int_sv(std::string_view sv, int& out)
{
    auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), out);
    return ec == std::errc{} && ptr == sv.data() + sv.size();
}

// A request payload is a newline-delimited command stream, and not one command.
//
// That is what would arrive on this cache's own port, so it is what the request
// channel carries: the same framing, the same interpreter, the same answers
// concatenated in the same order.  A caller with one command sends one line and
// gets one answer, which is the whole of what `cache <cmd>` through a server
// needs.  A caller with a stream of them — the server's `--cache` auto-store,
// which produces one `set` per message a client sends — sends them together and
// pays for one queue entry instead of one per message.  Without that, a client
// pushing a megabyte down a socket in one write posts a request per line, and
// the queue's cap turns into dropped writes: measured at 88% loss on a 200 000
// message burst before this was batched.
// ─── One payload, split into lines or taken whole ───────────────────────────
//
// `split` is what separates a client socket from a replication frame.  A client
// sends a stream and every newline in it ends a command.  A frame is one
// command that CONTAINS a newline — that is the only reason it was framed — so
// splitting it again undoes the framing and applies half of it.
//
// The two share everything else: the same connection setup, the same
// re-entrancy guard, the same interpreter.  They are one function with a flag
// rather than two because the setup is the part that must not drift.
void cache_instance::serve_payload(std::string_view payload, std::string& out, bool split)
{
    // The re-entrant case: a command that publishes reaches Lua, and a Lua
    // callback can ask this cache another question from inside the first.  Rare
    // enough to pay full price for, and it must not share the buffer.
    if (SOCKETLEY_UNLIKELY(m_serving))
    {
        client_connection nested{};
        nested.fd = -1;
        nested.rl_max = 0;
        if (split) run_request_lines(&nested, payload);
        else if (!payload.empty()) process_command(&nested, payload);
        out.append(nested.response_buf);
        return;
    }

    if (!m_request_conn)
        m_request_conn = std::make_unique<client_connection>();

    struct serving_guard
    {
        bool& flag;
        ~serving_guard() { flag = false; }
    } guard{m_serving};
    m_serving = true;

    auto* conn = m_request_conn.get();
    conn->fd = -1;
    conn->rl_max = 0;
    conn->rl_tokens = 0.0;
    conn->response_buf.clear();
    if (split) run_request_lines(conn, payload);
    else if (!payload.empty()) process_command(conn, payload);
    out.append(conn->response_buf);
}

void cache_instance::serve_request(std::string_view payload, std::string& out)
{
    serve_payload(payload, out, true);
}

// One command, newlines and all — what a replication frame carries.
void cache_instance::serve_one_command(std::string_view line, std::string& out)
{
    serve_payload(line, out, false);
}

void cache_instance::run_request_lines(client_connection* conn, std::string_view payload)
{
    size_t start = 0;
    while (start <= payload.size())
    {
        size_t nl = payload.find('\n', start);
        std::string_view line = (nl == std::string_view::npos)
            ? payload.substr(start) : payload.substr(start, nl - start);

        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        if (!line.empty())
            process_command(conn, line);

        if (nl == std::string_view::npos)
            break;
        start = nl + 1;
    }
}

std::string cache_instance::execute(std::string_view line)
{
    std::string out;
    serve_request(line, out);
    return out;
}

// Zero-allocation integer append for text-mode responses
static inline void append_int_nl(std::string& buf, int64_t v)
{
    char tmp[24];
    auto [end, ec] = std::to_chars(tmp, tmp + sizeof(tmp), v);
    buf.append(tmp, static_cast<size_t>(end - tmp));
    buf.push_back('\n');
}

void cache_instance::process_command(client_connection* conn, std::string_view line)
{
    if (SOCKETLEY_UNLIKELY(line.empty()))
        return;

    // Global rate limit check (across all connections)
    if (SOCKETLEY_UNLIKELY(!check_global_rate_limit()))
    {
        conn->response_buf.append("error: rate limited\n", 20);
        return;
    }

    // Rate limit check (usually disabled)
    if (SOCKETLEY_UNLIKELY(conn->rl_max > 0))
    {
        auto now = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(now - conn->rl_last).count();
        conn->rl_last = now;
        conn->rl_tokens += elapsed * conn->rl_max;
        if (conn->rl_tokens > conn->rl_max)
            conn->rl_tokens = conn->rl_max;
        if (conn->rl_tokens < 1.0)
        {
            conn->response_buf.append("error: rate limited\n", 20);
            return;
        }
        conn->rl_tokens -= 1.0;
    }

    m_stat_commands++;
    m_stat_total_messages.fetch_add(1, std::memory_order_relaxed);

    size_t first_space = line.find(' ');
    std::string_view cmd = (first_space != std::string_view::npos)
        ? line.substr(0, first_space) : line;

    std::string_view args = (first_space != std::string_view::npos)
        ? line.substr(first_space + 1) : std::string_view{};

    auto& rb = conn->response_buf;

    // Extract key from args (up to first space)
    auto extract_key = [](std::string_view a) -> std::pair<std::string_view, std::string_view> {
        size_t sp = a.find(' ');
        if (sp == std::string_view::npos)
            return {a, {}};
        return {a.substr(0, sp), a.substr(sp + 1)};
    };

    switch (fnv1a_lower(cmd))
    {
        // ─── Strings ───

        case fnv1a("set"):
        {
            if (m_mode == cache_mode_readonly)
            {
                rb.append("denied: readonly mode\n", 22);
                return;
            }
            size_t space = args.find(' ');
            if (space == std::string_view::npos)
            {
                rb.append("usage: set key value\n", 21);
                return;
            }
            auto key = args.substr(0, space);
            auto value = args.substr(space + 1);
            if (!m_store.set(key, value))
            {
                m_store.check_expiry(key);
                if (!m_store.set(key, value))
                {
                    // set() refuses for two unrelated reasons; the key's own
                    // type says which, so the client stops being told a memory
                    // refusal was a type conflict.
                    auto t = m_store.type(key);
                    if (t == "none" || t == "string")
                        rb.append("error: out of memory\n", 21);
                    else
                        rb.append("error: type conflict\n", 21);
                    break;
                }
            }
            rb.append("ok\n", 3);
            replicate_command(line);
#ifndef SOCKETLEY_NO_LUA
            if (lua() && lua()->has_on_write())
            {
                {
                    sol::protected_function_result r = lua()->on_write()(key, value, 0);
                    if (SOCKETLEY_UNLIKELY(!r.valid()))
                    {
                        sol::error e = r;
                        std::cerr << lua_diag::tag(get_name()) << " on_write error: " << e.what() << "\n";
                    }
                }
            }
#endif
            break;
        }
        case fnv1a("get"):
        {
            // Combined check_expiry + get_ptr — one hash probe instead of two
            const std::string* val = m_store.check_expiry_and_get_ptr(args);
            if (val)
            {
                m_stat_get_hits++;
                rb.append(*val);
                rb.push_back('\n');
            }
            else
            {
#ifndef SOCKETLEY_NO_LUA
                if (lua() && lua()->has_on_miss())
                {
                    // Checked BEFORE the result is read, and that is not a formality:
                    // on a failed call the value at index 0 is the ERROR OBJECT, and
                    // reading it as an optional<string> would store a Lua error message
                    // in the cache and answer it to the client as the fetched value.
                    // A raise still means a miss, which is what the catch this replaces
                    // decided by falling through to the nil below.
                    sol::protected_function_result res = lua()->on_miss()(args);
                    if (SOCKETLEY_UNLIKELY(!res.valid()))
                    {
                        sol::error e = res;
                        std::cerr << lua_diag::tag(get_name()) << " on_miss error: " << e.what() << "\n";
                    }
                    else
                    {
                        sol::optional<std::string> fetched = res.get<sol::optional<std::string>>(0);
                        if (fetched && !fetched->empty())
                        {
                            int ttl = 0;
                            sol::optional<int> ttl_opt = res.get<sol::optional<int>>(1);
                            if (ttl_opt) ttl = *ttl_opt;
                            m_store.set(args, *fetched);
                            if (ttl > 0) { m_store.set_expiry(args, ttl); mark_ttl_keys(); }
                            m_stat_get_hits++;
                            rb.append(*fetched);
                            rb.push_back('\n');
                            break;
                        }
                    }
                }
#endif
                m_stat_get_misses++;
                rb.append("nil\n", 4);
            }
            break;
        }
        case fnv1a("del"):
        {
            if (m_mode == cache_mode_readonly)
            {
                rb.append("denied: readonly mode\n", 22);
                return;
            }
            // Unlike set/lpush/sadd, del() cannot detect a stale key by failing:
            // it happily removes one that has already expired and reports
            // success, so DEL on an expired key would answer "ok" instead of
            // "nil".  The expiry check has to happen up front.
            if (m_has_ttl_keys) m_store.check_expiry(args);
            if (m_store.del(args))
            {
                rb.append("ok\n", 3);
                replicate_command(line);
#ifndef SOCKETLEY_NO_LUA
                if (lua() && lua()->has_on_delete())
                {
                    {
                        sol::protected_function_result r = lua()->on_delete_cb()(args);
                        if (SOCKETLEY_UNLIKELY(!r.valid()))
                        {
                            sol::error e = r;
                            std::cerr << lua_diag::tag(get_name()) << " on_delete error: " << e.what() << "\n";
                        }
                    }
                }
#endif
            }
            else
                rb.append("nil\n", 4);
            break;
        }
        case fnv1a("exists"):
        {
            if (m_has_ttl_keys) m_store.check_expiry(args);
            rb.append(m_store.exists(args) ? "1\n" : "0\n");
            break;
        }
        case fnv1a("incr"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            if (args.empty()) { rb.append("usage: incr key\n", 17); return; }
            int64_t result = 0;
            if (!m_store.incr(args, 1, result))
                rb.append("error: not an integer\n", 22);
            else
            {
                append_int_nl(rb, result);
                replicate_command(line);
            }
            break;
        }
        case fnv1a("decr"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            if (args.empty()) { rb.append("usage: decr key\n", 17); return; }
            int64_t result = 0;
            if (!m_store.incr(args, -1, result))
                rb.append("error: not an integer\n", 22);
            else
            {
                append_int_nl(rb, result);
                replicate_command(line);
            }
            break;
        }
        case fnv1a("incrby"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            auto [key, delta_str] = extract_key(args);
            if (key.empty() || delta_str.empty()) { rb.append("usage: incrby key delta\n", 24); return; }
            int64_t delta = 0;
            auto [p, e] = std::from_chars(delta_str.data(), delta_str.data() + delta_str.size(), delta);
            if (e != std::errc{}) { rb.append("error: invalid delta\n", 21); return; }
            int64_t result = 0;
            if (!m_store.incr(key, delta, result))
                rb.append("error: not an integer\n", 22);
            else
            {
                append_int_nl(rb, result);
                replicate_command(line);
            }
            break;
        }
        case fnv1a("decrby"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            auto [key, delta_str] = extract_key(args);
            if (key.empty() || delta_str.empty()) { rb.append("usage: decrby key delta\n", 24); return; }
            int64_t delta = 0;
            auto [p2, e2] = std::from_chars(delta_str.data(), delta_str.data() + delta_str.size(), delta);
            if (e2 != std::errc{}) { rb.append("error: invalid delta\n", 21); return; }
            int64_t result = 0;
            if (!m_store.incr(key, -delta, result))
                rb.append("error: not an integer\n", 22);
            else
            {
                append_int_nl(rb, result);
                replicate_command(line);
            }
            break;
        }
        case fnv1a("append"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            auto [key, suffix] = extract_key(args);
            if (key.empty() || suffix.empty()) { rb.append("usage: append key value\n", 24); return; }
            size_t newlen = m_store.append(key, suffix);
            if (newlen == cache_store::append_wrong_type)
                rb.append("error: type conflict\n", 21);
            else if (newlen == cache_store::append_denied)
                rb.append("error: out of memory\n", 21);
            else
            {
                append_int_nl(rb, static_cast<int64_t>(newlen));
                replicate_command(line);
            }
            break;
        }
        case fnv1a("strlen"):
        {
            if (m_has_ttl_keys) m_store.check_expiry(args);
            append_int_nl(rb, static_cast<int64_t>(m_store.strlen_key(args)));
            break;
        }
        case fnv1a("getset"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            auto [key, newval] = extract_key(args);
            if (key.empty() || newval.empty()) { rb.append("usage: getset key newvalue\n", 27); return; }
            // getset() overwrites unconditionally, so an expired key would be
            // reported as present and its stale value returned as the old one.
            if (m_has_ttl_keys) m_store.check_expiry(key);
            bool had_key = m_store.exists(key);
            std::string oldval;
            if (!m_store.getset(key, newval, oldval))
                rb.append("error: type conflict\n", 21);
            else
            {
                if (had_key) { rb.append(oldval); rb.push_back('\n'); }
                else rb.append("nil\n", 4);
                replicate_command(line);
            }
            break;
        }
        case fnv1a("mget"):
        {
            // MGET key1 key2 ... → one value per line (nil if missing), then "end\n"
            std::string_view rest = args;
            while (!rest.empty())
            {
                size_t sp = rest.find(' ');
                std::string_view key = (sp == std::string_view::npos) ? rest : rest.substr(0, sp);
                if (m_has_ttl_keys) m_store.check_expiry(key);
                const std::string* val = m_store.get_ptr(key);
                if (val) { rb.append(*val); rb.push_back('\n'); }
                else rb.append("nil\n", 4);
                if (sp == std::string_view::npos) break;
                rest = rest.substr(sp + 1);
            }
            rb.append("end\n", 4);
            break;
        }
        case fnv1a("mset"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            // MSET key1 val1 key2 val2 ...
            std::string_view rest = args;
            while (!rest.empty())
            {
                size_t sp1 = rest.find(' ');
                if (sp1 == std::string_view::npos) break;
                std::string_view key = rest.substr(0, sp1);
                rest = rest.substr(sp1 + 1);
                size_t sp2 = rest.find(' ');
                std::string_view val = (sp2 == std::string_view::npos) ? rest : rest.substr(0, sp2);
                if (m_has_ttl_keys) m_store.check_expiry(key);
                m_store.set(key, val);
#ifndef SOCKETLEY_NO_LUA
                if (lua() && lua()->has_on_write())
                {
                    {
                        sol::protected_function_result r = lua()->on_write()(key, val, 0);
                        if (SOCKETLEY_UNLIKELY(!r.valid()))
                        {
                            sol::error e = r;
                            std::cerr << lua_diag::tag(get_name()) << " on_write error: " << e.what() << "\n";
                        }
                    }
                }
#endif
                if (sp2 == std::string_view::npos) break;
                rest = rest.substr(sp2 + 1);
            }
            rb.append("ok\n", 3);
            replicate_command(line);
            break;
        }
        case fnv1a("type"):
        {
            if (m_has_ttl_keys) m_store.check_expiry(args);
            rb.append(m_store.type(args));
            rb.push_back('\n');
            break;
        }
        case fnv1a("keys"):
        {
            std::string_view pattern = args.empty() ? std::string_view("*") : args;
            std::vector<std::string_view> result;
            m_store.keys(pattern, result);
            for (auto& k : result) { rb.append(k); rb.push_back('\n'); }
            rb.append("end\n", 4);
            break;
        }

        // ─── Lists ───

        case fnv1a("lpush"):
        {
            if (m_mode == cache_mode_readonly)
            {
                rb.append("denied: readonly mode\n", 22);
                return;
            }
            auto [key, val] = extract_key(args);
            if (key.empty() || val.empty())
            {
                rb.append("usage: lpush key value\n", 23);
                return;
            }
            if (!m_store.lpush(key, val))
            {
                m_store.check_expiry(key);
                if (!m_store.lpush(key, val))
                {
                    rb.append("error: type conflict\n", 21);
                    break;
                }
            }
            rb.append("ok\n", 3);
            replicate_command(line);
            break;
        }
        case fnv1a("rpush"):
        {
            if (m_mode == cache_mode_readonly)
            {
                rb.append("denied: readonly mode\n", 22);
                return;
            }
            auto [key, val] = extract_key(args);
            if (key.empty() || val.empty())
            {
                rb.append("usage: rpush key value\n", 23);
                return;
            }
            if (!m_store.rpush(key, val))
            {
                m_store.check_expiry(key);
                if (!m_store.rpush(key, val))
                {
                    rb.append("error: type conflict\n", 21);
                    break;
                }
            }
            rb.append("ok\n", 3);
            replicate_command(line);
            break;
        }
        case fnv1a("lpop"):
        {
            if (m_mode == cache_mode_readonly)
            {
                rb.append("denied: readonly mode\n", 22);
                return;
            }
            if (m_has_ttl_keys) m_store.check_expiry(args);
            std::string val;
            if (m_store.lpop(args, val))
            {
                rb.append(val);
                rb.push_back('\n');
                replicate_command(line);   // was not replicated at all
            }
            else
                rb.append("nil\n", 4);
            break;
        }
        case fnv1a("rpop"):
        {
            if (m_mode == cache_mode_readonly)
            {
                rb.append("denied: readonly mode\n", 22);
                return;
            }
            if (m_has_ttl_keys) m_store.check_expiry(args);
            std::string val;
            if (m_store.rpop(args, val))
            {
                rb.append(val);
                rb.push_back('\n');
                replicate_command(line);   // was not replicated at all
            }
            else
                rb.append("nil\n", 4);
            break;
        }
        case fnv1a("llen"):
        {
            if (m_has_ttl_keys) m_store.check_expiry(args);
            append_int_nl(rb, m_store.llen(args));
            break;
        }
        case fnv1a("lindex"):
        {
            auto [key, idx_str] = extract_key(args);
            if (key.empty() || idx_str.empty())
            {
                rb.append("usage: lindex key index\n", 24);
                return;
            }
            if (m_has_ttl_keys) m_store.check_expiry(key);
            int idx;
            if (!parse_int_sv(idx_str, idx))
            {
                rb.append("error: invalid index\n", 21);
                return;
            }
            const std::string* val = m_store.lindex(key, idx);
            if (val)
            {
                rb.append(*val);
                rb.push_back('\n');
            }
            else
                rb.append("nil\n", 4);
            break;
        }
        case fnv1a("lrange"):
        {
            auto [key, rest] = extract_key(args);
            if (key.empty() || rest.empty())
            {
                rb.append("usage: lrange key start stop\n", 29);
                return;
            }
            auto [start_str, stop_str] = extract_key(rest);
            if (start_str.empty() || stop_str.empty())
            {
                rb.append("usage: lrange key start stop\n", 29);
                return;
            }
            if (m_has_ttl_keys) m_store.check_expiry(key);
            int start, stop;
            if (!parse_int_sv(start_str, start) || !parse_int_sv(stop_str, stop))
            {
                rb.append("error: invalid index\n", 21);
                return;
            }
            const auto* deq = m_store.list_ptr(key);
            if (!deq || deq->empty())
            {
                rb.append("end\n", 4);
                return;
            }
            int len = static_cast<int>(deq->size());
            if (start < 0) start += len;
            if (stop < 0) stop += len;
            if (start < 0) start = 0;
            if (stop >= len) stop = len - 1;
            for (int i = start; i <= stop; i++)
            {
                rb.append((*deq)[static_cast<size_t>(i)]);
                rb.push_back('\n');
            }
            rb.append("end\n", 4);
            break;
        }

        // ─── Sets ───

        case fnv1a("sadd"):
        {
            if (m_mode == cache_mode_readonly)
            {
                rb.append("denied: readonly mode\n", 22);
                return;
            }
            auto [key, member] = extract_key(args);
            if (key.empty() || member.empty())
            {
                rb.append("usage: sadd key member\n", 23);
                return;
            }
            int result = m_store.sadd(key, member);
            if (result < 0)
            {
                m_store.check_expiry(key);
                result = m_store.sadd(key, member);
            }
            if (result < 0)
                rb.append("error: type conflict\n", 21);
            else if (result == 0)
                rb.append("exists\n", 7);
            else
            {
                rb.append("ok\n", 3);
                replicate_command(line);
            }
            break;
        }
        case fnv1a("srem"):
        {
            if (m_mode == cache_mode_readonly)
            {
                rb.append("denied: readonly mode\n", 22);
                return;
            }
            auto [key, member] = extract_key(args);
            if (key.empty() || member.empty())
            {
                rb.append("usage: srem key member\n", 23);
                return;
            }
            if (m_has_ttl_keys) m_store.check_expiry(key);
            if (m_store.srem(key, member))
            {
                rb.append("ok\n", 3);
                replicate_command(line);   // was not replicated at all
            }
            else
                rb.append("nil\n", 4);
            break;
        }
        case fnv1a("sismember"):
        {
            auto [key, member] = extract_key(args);
            if (key.empty() || member.empty())
            {
                rb.append("usage: sismember key member\n", 28);
                return;
            }
            if (m_has_ttl_keys) m_store.check_expiry(key);
            rb.append(m_store.sismember(key, member) ? "1\n" : "0\n");
            break;
        }
        case fnv1a("scard"):
        {
            if (m_has_ttl_keys) m_store.check_expiry(args);
            append_int_nl(rb, m_store.scard(args));
            break;
        }
        case fnv1a("smembers"):
        {
            if (m_has_ttl_keys) m_store.check_expiry(args);
            const auto* s = m_store.set_ptr(args);
            if (!s || s->empty())
            {
                rb.append("end\n", 4);
                return;
            }
            for (const auto& member : *s)
            {
                rb.append(member);
                rb.push_back('\n');
            }
            rb.append("end\n", 4);
            break;
        }

        // ─── Hashes ───

        case fnv1a("hset"):
        {
            if (m_mode == cache_mode_readonly)
            {
                rb.append("denied: readonly mode\n", 22);
                return;
            }
            auto [key, rest] = extract_key(args);
            if (key.empty() || rest.empty())
            {
                rb.append("usage: hset key field value\n", 28);
                return;
            }
            auto [field, val] = extract_key(rest);
            if (field.empty() || val.empty())
            {
                rb.append("usage: hset key field value\n", 28);
                return;
            }
            if (!m_store.hset(key, field, val))
            {
                m_store.check_expiry(key);
                if (!m_store.hset(key, field, val))
                {
                    // hset() refuses for two unrelated reasons now that
                    // overwriting a field is checked against maxmemory too; the
                    // key's own type says which, as it does for SET.
                    auto t = m_store.type(key);
                    if (t == "none" || t == "hash")
                        rb.append("error: out of memory\n", 21);
                    else
                        rb.append("error: type conflict\n", 21);
                    break;
                }
            }
            rb.append("ok\n", 3);
            replicate_command(line);
            break;
        }
        case fnv1a("hget"):
        {
            auto [key, field] = extract_key(args);
            if (key.empty() || field.empty())
            {
                rb.append("usage: hget key field\n", 22);
                return;
            }
            if (m_has_ttl_keys) m_store.check_expiry(key);
            const std::string* val = m_store.hget(key, field);
            if (val)
            {
                rb.append(*val);
                rb.push_back('\n');
            }
            else
                rb.append("nil\n", 4);
            break;
        }
        case fnv1a("hdel"):
        {
            if (m_mode == cache_mode_readonly)
            {
                rb.append("denied: readonly mode\n", 22);
                return;
            }
            auto [key, field] = extract_key(args);
            if (key.empty() || field.empty())
            {
                rb.append("usage: hdel key field\n", 22);
                return;
            }
            if (m_has_ttl_keys) m_store.check_expiry(key);
            if (m_store.hdel(key, field))
            {
                rb.append("ok\n", 3);
                replicate_command(line);   // was not replicated at all
            }
            else
                rb.append("nil\n", 4);
            break;
        }
        case fnv1a("hlen"):
        {
            if (m_has_ttl_keys) m_store.check_expiry(args);
            append_int_nl(rb, m_store.hlen(args));
            break;
        }
        case fnv1a("hgetall"):
        {
            if (m_has_ttl_keys) m_store.check_expiry(args);
            const auto* h = m_store.hash_ptr(args);
            if (!h || h->empty())
            {
                rb.append("end\n", 4);
                return;
            }
            for (const auto& [field, val] : *h)
            {
                rb.append(field);
                rb.push_back(' ');
                rb.append(val);
                rb.push_back('\n');
            }
            rb.append("end\n", 4);
            break;
        }

        // ─── TTL / Expiry ───

        case fnv1a("expire"):
        {
            if (m_mode == cache_mode_readonly)
            {
                rb.append("denied: readonly mode\n", 22);
                return;
            }
            auto [key, sec_str] = extract_key(args);
            if (key.empty() || sec_str.empty())
            {
                rb.append("usage: expire key seconds\n", 26);
                return;
            }
            int seconds;
            if (!parse_int_sv(sec_str, seconds) || seconds <= 0)
            {
                rb.append("error: invalid seconds\n", 23);
                return;
            }
            if (m_store.set_expiry(key, seconds))
            {
                mark_ttl_keys();
                rb.append("ok\n", 3);
                replicate_command(line);   // was not replicated at all
            }
            else
                rb.append("nil\n", 4);
            break;
        }
        case fnv1a("ttl"):
        {
            if (m_has_ttl_keys) m_store.check_expiry(args);
            int64_t ttl = m_store.get_ttl(args);
            append_int_nl(rb, ttl);
            break;
        }
        case fnv1a("persist"):
        {
            if (m_mode == cache_mode_readonly)
            {
                rb.append("denied: readonly mode\n", 22);
                return;
            }
            if (m_store.persist(args))
            {
                rb.append("ok\n", 3);
                replicate_command(line);   // was not replicated at all
            }
            else
                rb.append("nil\n", 4);
            break;
        }
        case fnv1a("setnx"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            auto [key, val] = extract_key(args);
            if (key.empty() || val.empty()) { rb.append("usage: setnx key value\n", 23); return; }
            bool did_set = m_store.setnx(key, val);
            rb.append(did_set ? "1\n" : "0\n");
            if (did_set)
            {
                replicate_command(line);
#ifndef SOCKETLEY_NO_LUA
                if (lua() && lua()->has_on_write())
                {
                    {
                        sol::protected_function_result r = lua()->on_write()(key, val, 0);
                        if (SOCKETLEY_UNLIKELY(!r.valid()))
                        {
                            sol::error e = r;
                            std::cerr << lua_diag::tag(get_name()) << " on_write error: " << e.what() << "\n";
                        }
                    }
                }
#endif
            }
            break;
        }
        case fnv1a("setex"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            auto [key, rest] = extract_key(args);
            auto [sec_str, val] = extract_key(rest);
            if (key.empty() || sec_str.empty() || val.empty()) { rb.append("usage: setex key seconds value\n", 31); return; }
            int sec = 0;
            if (!parse_int_sv(sec_str, sec) || sec <= 0) { rb.append("error: invalid seconds\n", 23); return; }
            if (!m_store.set(key, val))
            {
                m_store.check_expiry(key);
                if (!m_store.set(key, val)) { rb.append("error: type conflict\n", 21); return; }
            }
            m_store.set_expiry(key, sec);
            mark_ttl_keys();
            rb.append("ok\n", 3);
            replicate_command(line);
#ifndef SOCKETLEY_NO_LUA
            if (lua() && lua()->has_on_write())
            {
                {
                    sol::protected_function_result r = lua()->on_write()(key, val, sec);
                    if (SOCKETLEY_UNLIKELY(!r.valid()))
                    {
                        sol::error e = r;
                        std::cerr << lua_diag::tag(get_name()) << " on_write error: " << e.what() << "\n";
                    }
                }
            }
#endif
            break;
        }
        case fnv1a("psetex"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            auto [key, rest] = extract_key(args);
            auto [ms_str, val] = extract_key(rest);
            if (key.empty() || ms_str.empty() || val.empty()) { rb.append("usage: psetex key milliseconds value\n", 37); return; }
            int64_t ms = 0;
            {
                auto [p, e] = std::from_chars(ms_str.data(), ms_str.data() + ms_str.size(), ms);
                if (e != std::errc{} || ms <= 0) { rb.append("error: invalid milliseconds\n", 28); return; }
            }
            if (!m_store.set(key, val))
            {
                m_store.check_expiry(key);
                if (!m_store.set(key, val)) { rb.append("error: type conflict\n", 21); return; }
            }
            m_store.set_expiry_ms(key, ms);
            mark_ttl_keys();
            rb.append("ok\n", 3);
            replicate_command(line);
#ifndef SOCKETLEY_NO_LUA
            if (lua() && lua()->has_on_write())
            {
                {
                    sol::protected_function_result r = lua()->on_write()(key, val, 0);
                    if (SOCKETLEY_UNLIKELY(!r.valid()))
                    {
                        sol::error e = r;
                        std::cerr << lua_diag::tag(get_name()) << " on_write error: " << e.what() << "\n";
                    }
                }
            }
#endif
            break;
        }
        case fnv1a("pexpire"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            auto [key, ms_str] = extract_key(args);
            if (key.empty() || ms_str.empty()) { rb.append("usage: pexpire key ms\n", 22); return; }
            int64_t ms = 0;
            {
                auto [p, e] = std::from_chars(ms_str.data(), ms_str.data() + ms_str.size(), ms);
                if (e != std::errc{} || ms <= 0) { rb.append("error: invalid ms\n", 18); return; }
            }
            if (m_store.set_expiry_ms(key, ms))
            {
                mark_ttl_keys();
                rb.append("1\n", 2);
                replicate_command(line);   // was not replicated at all
            }
            else
                rb.append("0\n", 2);
            break;
        }
        case fnv1a("pttl"):
        {
            if (m_has_ttl_keys) m_store.check_expiry(args);
            append_int_nl(rb, m_store.get_pttl(args));
            break;
        }
        case fnv1a("expireat"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            auto [key, ts_str] = extract_key(args);
            if (key.empty() || ts_str.empty()) { rb.append("usage: expireat key unix_seconds\n", 33); return; }
            int64_t unix_s = 0;
            {
                auto [p, e] = std::from_chars(ts_str.data(), ts_str.data() + ts_str.size(), unix_s);
                if (e != std::errc{}) { rb.append("error: invalid timestamp\n", 25); return; }
            }
            {
                int64_t now_s = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                int64_t remaining = unix_s - now_s;
                // Replicated verbatim, which is the right form for this one:
                // the argument is an ABSOLUTE timestamp, so the follower
                // arrives at the same expiry however long the line took to get
                // there.  A relative `expire` would drift by the wire delay.
                if (remaining <= 0)
                {
                    m_store.del(key);
                    rb.append("1\n", 2);
                    replicate_command(line);   // was not replicated at all
                }
                else if (m_store.set_expiry(key, remaining))
                {
                    mark_ttl_keys();
                    rb.append("1\n", 2);
                    replicate_command(line);   // was not replicated at all
                }
                else rb.append("0\n", 2);
            }
            break;
        }
        case fnv1a("pexpireat"):
        {
            if (m_mode == cache_mode_readonly) { rb.append("denied: readonly mode\n", 22); return; }
            auto [key, ts_str] = extract_key(args);
            if (key.empty() || ts_str.empty()) { rb.append("usage: pexpireat key unix_ms\n", 29); return; }
            int64_t unix_ms = 0;
            {
                auto [p, e] = std::from_chars(ts_str.data(), ts_str.data() + ts_str.size(), unix_ms);
                if (e != std::errc{}) { rb.append("error: invalid timestamp\n", 25); return; }
            }
            {
                int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                int64_t remaining_ms = unix_ms - now_ms;
                if (remaining_ms <= 0) { m_store.del(key); rb.append("1\n", 2); }
                else if (m_store.set_expiry_ms(key, remaining_ms))
                { mark_ttl_keys(); rb.append("1\n", 2); }
                else rb.append("0\n", 2);
            }
            break;
        }
        case fnv1a("scan"):
        {
            // scan cursor [match pattern] [count n]
            size_t sp0 = args.find(' ');
            std::string_view cursor_str = (sp0 == std::string_view::npos) ? args : args.substr(0, sp0);
            std::string_view rest2 = (sp0 == std::string_view::npos) ? std::string_view{} : args.substr(sp0 + 1);
            uint64_t scan_cursor = 0;
            {
                auto [p, e] = std::from_chars(cursor_str.data(), cursor_str.data() + cursor_str.size(), scan_cursor);
                if (e != std::errc{}) { rb.append("error: invalid cursor\n", 22); return; }
            }
            std::string_view scan_pattern = "*";
            size_t scan_count = 10;
            while (!rest2.empty())
            {
                size_t sp2 = rest2.find(' ');
                std::string_view opt = (sp2 == std::string_view::npos) ? rest2 : rest2.substr(0, sp2);
                rest2 = (sp2 == std::string_view::npos) ? std::string_view{} : rest2.substr(sp2 + 1);
                if (fnv1a_lower(opt) == fnv1a("match") && !rest2.empty())
                {
                    sp2 = rest2.find(' ');
                    scan_pattern = (sp2 == std::string_view::npos) ? rest2 : rest2.substr(0, sp2);
                    rest2 = (sp2 == std::string_view::npos) ? std::string_view{} : rest2.substr(sp2 + 1);
                }
                else if (fnv1a_lower(opt) == fnv1a("count") && !rest2.empty())
                {
                    sp2 = rest2.find(' ');
                    std::string_view cnt_str = (sp2 == std::string_view::npos) ? rest2 : rest2.substr(0, sp2);
                    rest2 = (sp2 == std::string_view::npos) ? std::string_view{} : rest2.substr(sp2 + 1);
                    size_t cnt = 10;
                    auto [p2, e2] = std::from_chars(cnt_str.data(), cnt_str.data() + cnt_str.size(), cnt);
                    if (e2 == std::errc{}) scan_count = cnt;
                }
            }
            std::vector<std::string_view> scan_keys;
            uint64_t next_cursor = m_store.scan(scan_cursor, scan_pattern, scan_count, scan_keys);
            append_int_nl(rb, static_cast<int64_t>(next_cursor));
            for (auto& k : scan_keys) { rb.append(k); rb.push_back('\n'); }
            rb.append("end\n", 4);
            break;
        }

        // ─── Admin ───

        case fnv1a("flush"):
        {
            if (m_mode != cache_mode_admin)
            {
                rb.append("denied: admin mode required\n", 28);
                return;
            }
            std::string_view path = m_persistent_path;
            if (path.empty())
            {
                rb.append("failed: no persistent path set\n", 31);
                return;
            }
            rb.append(m_store.save(path) ? "ok\n" : "failed: flush failed\n");
            break;
        }
        case fnv1a("load"):
        {
            if (m_mode != cache_mode_admin)
            {
                rb.append("denied: admin mode required\n", 28);
                return;
            }
            std::string_view path = m_persistent_path;
            if (path.empty())
            {
                rb.append("failed: no persistent path set\n", 31);
                return;
            }
            rb.append(m_store.load(path) ? "ok\n" : "failed: load failed\n");
            break;
        }
        case fnv1a("size"):
        {
            append_int_nl(rb, m_store.size());
            break;
        }

        // ─── Pub/Sub ───

        case fnv1a("subscribe"):
        {
            if (args.empty())
            {
                rb.append("usage: subscribe channel\n", 25);
                return;
            }
            m_store.subscribe(conn->fd, args);
            rb.append("ok\n", 3);
            break;
        }
        case fnv1a("unsubscribe"):
        {
            if (args.empty())
            {
                rb.append("usage: unsubscribe channel\n", 27);
                return;
            }
            m_store.unsubscribe(conn->fd, args);
            rb.append("ok\n", 3);
            break;
        }
        case fnv1a("publish"):
        {
            if (m_mode == cache_mode_readonly)
            {
                rb.append("denied: readonly mode\n", 22);
                return;
            }
            auto [channel, message] = extract_key(args);
            if (channel.empty() || message.empty())
            {
                rb.append("usage: publish channel message\n", 31);
                return;
            }
            int count = publish(channel, message);
            append_int_nl(rb, count);
            break;
        }

        // ─── Memory / Maxmemory ───

        case fnv1a("maxmemory"):
        {
            append_int_nl(rb, m_store.get_max_memory());
            break;
        }
        case fnv1a("memory"):
        {
            append_int_nl(rb, m_store.get_memory_used());
            break;
        }
        case fnv1a("replicate"):
        {
            handle_replicate_request(conn);
            return;
        }
        default:
            rb.append("failed: unknown command\n", 24);
            break;
    }
}

// Returns false only when a submission was attempted and did not reach the
// ring.  A caller that leaves write_pending set after that waits for a
// completion that cannot come: the connection stops making progress and the
// client is left holding a request nobody will ever answer.  On failure the
// pending flags are cleared and the batch dropped — the bytes are
// undeliverable, and saying so is the difference between a closed connection
// and a hung one.
bool cache_instance::flush_responses(client_connection* conn)
{
    if (SOCKETLEY_UNLIKELY(conn->response_buf.empty() || !m_loop || conn->closing))
    {
        if (!conn->response_buf.empty() && (conn->closing || !m_loop))
            SKL_TRACE_LOG("flush skipped fd=%d bytes=%zu closing=%d loop=%d",
                          conn->fd, conn->response_buf.size(),
                          (int)conn->closing, (int)(m_loop != nullptr));
        return true;
    }
    SKL_TRACE_ADD(conn, bytes_queued, conn->response_buf.size());

    if (SOCKETLEY_UNLIKELY(conn->write_queue.bytes() >= socketley::write_queue_max_bytes))
    {
        // The peer has genuinely stopped reading while megabytes pile up.
        // Dropping the connection is the right answer, but it must not happen
        // quietly: everything still in flight for this client is lost with it.
        std::cerr << "[cache] client " << conn->fd << " is not draining its socket ("
                  << conn->write_queue.bytes() << " bytes in "
                  << conn->write_queue.size() << " queued buffers), closing\n";
        conn->closing = true;
        return true;
    }

    // Fast-path: if no write is pending and queue is empty, submit directly
    // from response_buf without the queue round-trip (saves move + pop).
    //
    // Never on a TLS connection: this path builds an SQE straight out of
    // response_buf, which is plaintext, and would put the answer to a command
    // on the wire in the clear on a port the operator encrypted.  Those bytes
    // go into the queue and out through the record layer below, which is the
    // only writer a session has.
    if (SOCKETLEY_LIKELY(!conn->write_pending && conn->write_queue.empty() &&
                         !conn->zc_notif_pending && conn->ssl == nullptr))
    {
        conn->write_batch[0] = std::move(conn->response_buf);
        conn->response_buf.reserve(4096);
        conn->write_iovs[0].iov_base = conn->write_batch[0].data();
        conn->write_iovs[0].iov_len  = conn->write_batch[0].size();
        conn->write_batch_count = 1;
        conn->write_pending = true;

        auto len = static_cast<uint32_t>(conn->write_batch[0].size());
        bool queued;
        if (m_send_zc && len >= (512u << 10))
        {
            conn->zc_notif_pending = true;
            conn->write_req.type = op_send_zc;
            if (conn->direct_fd)
                queued = m_loop->submit_send_zc_fixed_file(conn->fixed_idx, conn->write_batch[0].data(), len, &conn->write_req);
            else
                queued = m_loop->submit_send_zc(conn->fd, conn->write_batch[0].data(), len, &conn->write_req);
        }
        else
        {
            conn->write_req.type = op_write;
            if (conn->direct_fd)
                queued = m_loop->submit_write_fixed_file(conn->fixed_idx, conn->write_batch[0].data(), len, &conn->write_req);
            else
                queued = m_loop->submit_write(conn->fd, conn->write_batch[0].data(), len, &conn->write_req);
        }

        if (SOCKETLEY_UNLIKELY(!queued))
        {
            conn->write_batch[0].clear();
            conn->write_batch_count = 0;
            conn->write_pending = false;
            conn->zc_notif_pending = false;
            return false;
        }
        return true;
    }

    // Append to the tail entry instead of adding another one whenever that keeps
    // it a sensible size.  A pipelined client produces one tiny reply per
    // command — "ok\n" is three bytes — and one queue entry per flush turns a
    // few kilobytes of data into thousands of entries, each with its own node
    // and allocation.  Merging them costs a memcpy and saves all of that.
    //
    // Only the tail is touched: entries are moved out of the queue into
    // write_batch before submission, so nothing the kernel is reading gets
    // modified here.
    if (!conn->write_queue.empty() &&
        conn->write_queue.back().size() + conn->response_buf.size() <= client_connection::WRITE_COALESCE_LIMIT)
    {
        conn->write_queue.append_back(conn->response_buf);
        conn->response_buf.clear();
    }
    else
    {
        conn->write_queue.push(std::move(conn->response_buf));
    }
    conn->response_buf.reserve(4096);

    if (!conn->write_pending)
        return flush_write_queue(conn);
    return true;
}

// Same contract as flush_responses above: false means nothing reached the ring
// and no completion is owed, so the caller has to stop treating the connection
// as one that is still going to be written to.
bool cache_instance::flush_write_queue(client_connection* conn)
{
    // A TLS connection's bytes go through the record layer, which is the only
    // thing allowed to put them on the wire.  This branch is what keeps every
    // caller above — the command handlers, publish(), the closing paths — from
    // having to know which kind of connection it is holding.
    if (SOCKETLEY_UNLIKELY(conn->ssl != nullptr))
        return tls_flush(conn);

    if (!m_loop || conn->write_queue.empty() || conn->zc_notif_pending)
        return true;

    uint32_t count = 0;
    while (!conn->write_queue.empty() && count < client_connection::MAX_WRITE_BATCH)
    {
        conn->write_batch[count] = conn->write_queue.take_front();

        conn->write_iovs[count].iov_base = conn->write_batch[count].data();
        conn->write_iovs[count].iov_len  = conn->write_batch[count].size();
        count++;
    }

    conn->write_batch_count = count;
    conn->write_pending = true;

    bool queued;
    if (count == 1)
    {
        auto len = static_cast<uint32_t>(conn->write_batch[0].size());

        // Use zero-copy send only for very large buffers (>= 512KB);
        // the NOTIF CQE round-trip kills throughput for smaller writes
        if (m_send_zc && len >= (512u << 10))
        {
            conn->zc_notif_pending = true;
            conn->write_req.type = op_send_zc;
            if (conn->direct_fd)
                queued = m_loop->submit_send_zc_fixed_file(conn->fixed_idx, conn->write_batch[0].data(), len, &conn->write_req);
            else
                queued = m_loop->submit_send_zc(conn->fd, conn->write_batch[0].data(), len, &conn->write_req);
        }
        else
        {
            conn->write_req.type = op_write;
            if (conn->direct_fd)
                queued = m_loop->submit_write_fixed_file(conn->fixed_idx, conn->write_batch[0].data(), len, &conn->write_req);
            else
                queued = m_loop->submit_write(conn->fd, conn->write_batch[0].data(), len, &conn->write_req);
        }
    }
    else
    {
        conn->write_msg.msg_iov = conn->write_iovs;
        conn->write_msg.msg_iovlen = count;
        conn->write_req.type = op_writev;
        if (conn->direct_fd)
            queued = m_loop->submit_sendmsg_fixed_file(conn->fixed_idx, &conn->write_msg, &conn->write_req);
        else
            queued = m_loop->submit_sendmsg(conn->fd, &conn->write_msg, &conn->write_req);
    }

    if (SOCKETLEY_UNLIKELY(!queued))
    {
        for (uint32_t i = 0; i < conn->write_batch_count; i++)
            conn->write_batch[i].clear();
        conn->write_batch_count = 0;
        conn->write_pending = false;
        conn->zc_notif_pending = false;
        return false;
    }
    return true;
}

// ─── Lua accessor methods ───

std::string cache_instance::lua_get(std::string_view key)
{
    m_store.check_expiry(key);
    std::string value;
    if (m_store.get(key, value))
        return value;
    return "";
}

bool cache_instance::lua_set(std::string_view key, std::string_view value)
{
    if (m_mode == cache_mode_readonly)
        return false;
    m_store.check_expiry(key);
    return m_store.set(key, value);
}

bool cache_instance::lua_del(std::string_view key)
{
    if (m_mode == cache_mode_readonly)
        return false;
    return m_store.del(key);
}

bool cache_instance::lua_lpush(std::string_view key, std::string_view val)
{
    if (m_mode == cache_mode_readonly)
        return false;
    m_store.check_expiry(key);
    return m_store.lpush(key, val);
}

bool cache_instance::lua_rpush(std::string_view key, std::string_view val)
{
    if (m_mode == cache_mode_readonly)
        return false;
    m_store.check_expiry(key);
    return m_store.rpush(key, val);
}

std::string cache_instance::lua_lpop(std::string_view key)
{
    if (m_mode == cache_mode_readonly)
        return "";
    m_store.check_expiry(key);
    std::string val;
    if (m_store.lpop(key, val))
        return val;
    return "";
}

std::string cache_instance::lua_rpop(std::string_view key)
{
    if (m_mode == cache_mode_readonly)
        return "";
    m_store.check_expiry(key);
    std::string val;
    if (m_store.rpop(key, val))
        return val;
    return "";
}

int cache_instance::lua_llen(std::string_view key)
{
    m_store.check_expiry(key);
    return m_store.llen(key);
}

#ifndef SOCKETLEY_NO_LUA
sol::table cache_instance::lua_lrange(std::string_view key, int start, int stop)
{
    m_store.check_expiry(key);
    auto* ctx = lua();
    if (!ctx)
        return sol::table();

    sol::table result = ctx->state().create_table();
    const auto* deq = m_store.list_ptr(key);
    if (!deq || deq->empty())
        return result;

    int len = static_cast<int>(deq->size());
    if (start < 0) start += len;
    if (stop < 0) stop += len;
    if (start < 0) start = 0;
    if (stop >= len) stop = len - 1;

    int lua_idx = 1;
    for (int i = start; i <= stop; i++)
        result[lua_idx++] = (*deq)[static_cast<size_t>(i)];

    return result;
}
#endif

int cache_instance::lua_sadd(std::string_view key, std::string_view member)
{
    if (m_mode == cache_mode_readonly)
        return -1;
    m_store.check_expiry(key);
    return m_store.sadd(key, member);
}

bool cache_instance::lua_srem(std::string_view key, std::string_view member)
{
    if (m_mode == cache_mode_readonly)
        return false;
    m_store.check_expiry(key);
    return m_store.srem(key, member);
}

bool cache_instance::lua_sismember(std::string_view key, std::string_view member)
{
    m_store.check_expiry(key);
    return m_store.sismember(key, member);
}

int cache_instance::lua_scard(std::string_view key)
{
    m_store.check_expiry(key);
    return m_store.scard(key);
}

#ifndef SOCKETLEY_NO_LUA
sol::table cache_instance::lua_smembers(std::string_view key)
{
    m_store.check_expiry(key);
    auto* ctx = lua();
    if (!ctx)
        return sol::table();

    sol::table result = ctx->state().create_table();
    const auto* s = m_store.set_ptr(key);
    if (!s)
        return result;

    int lua_idx = 1;
    for (const auto& member : *s)
        result[lua_idx++] = member;

    return result;
}
#endif

bool cache_instance::lua_hset(std::string_view key, std::string_view field, std::string_view val)
{
    if (m_mode == cache_mode_readonly)
        return false;
    m_store.check_expiry(key);
    return m_store.hset(key, field, val);
}

std::string cache_instance::lua_hget(std::string_view key, std::string_view field)
{
    m_store.check_expiry(key);
    const std::string* val = m_store.hget(key, field);
    return val ? *val : "";
}

bool cache_instance::lua_hdel(std::string_view key, std::string_view field)
{
    if (m_mode == cache_mode_readonly)
        return false;
    m_store.check_expiry(key);
    return m_store.hdel(key, field);
}

int cache_instance::lua_hlen(std::string_view key)
{
    m_store.check_expiry(key);
    return m_store.hlen(key);
}

#ifndef SOCKETLEY_NO_LUA
sol::table cache_instance::lua_hgetall(std::string_view key)
{
    m_store.check_expiry(key);
    auto* ctx = lua();
    if (!ctx)
        return sol::table();

    sol::table result = ctx->state().create_table();
    const auto* h = m_store.hash_ptr(key);
    if (!h)
        return result;

    for (const auto& [field, val] : *h)
        result[field] = val;

    return result;
}
#endif

bool cache_instance::lua_expire(std::string_view key, int seconds)
{
    if (m_mode == cache_mode_readonly)
        return false;
    if (m_store.set_expiry(key, seconds))
    {
        mark_ttl_keys();
        return true;
    }
    return false;
}

int64_t cache_instance::lua_ttl(std::string_view key)
{
    m_store.check_expiry(key);
    return m_store.get_ttl(key);
}

bool cache_instance::lua_persist(std::string_view key)
{
    if (m_mode == cache_mode_readonly)
        return false;
    return m_store.persist(key);
}

uint32_t cache_instance::get_size() const
{
    return m_store.size();
}

size_t cache_instance::store_memory_used() const
{
    return m_store.get_memory_used();
}

bool cache_instance::flush_to(std::string_view path)
{
    if (m_mode != cache_mode_admin)
        return false;
    return m_store.save(path);
}

bool cache_instance::load_from(std::string_view path)
{
    if (m_mode != cache_mode_admin)
        return false;
    return m_store.load(path);
}

// ─── RESP protocol support ───

void cache_instance::process_resp(client_connection* conn)
{
    // Fixed-size string_view array — zero heap allocations per command
    static constexpr int MAX_RESP_ARGS = 64;
    std::string_view args[MAX_RESP_ARGS];
    int argc = 0;
    size_t consumed = 0;
    size_t offset = 0;

    while (offset < conn->partial.size())
    {
        std::string_view buf(conn->partial.data() + offset, conn->partial.size() - offset);
        auto result = resp::parse_message_views(buf, args, MAX_RESP_ARGS, argc, consumed);

        if (result == resp::parse_result::incomplete)
            break;

        if (result == resp::parse_result::error)
        {
            conn->response_buf.append("-ERR protocol error\r\n");
            conn->partial.clear();
            return;
        }

        // Advance offset; args[] point into conn->partial which stays valid
        offset += consumed;

        if (argc > 0)
        {
            SKL_TRACE_ADD(conn, commands_parsed, 1);
            const size_t rb_before = conn->response_buf.size();
            process_resp_command(conn, args, argc);
            if (conn->response_buf.size() != rb_before)
                SKL_TRACE_ADD(conn, responses_made, 1);
        }

        // Cap response_buf at 1 MiB during large pipelines to prevent OOM
        if (conn->response_buf.size() > (1 << 20))
        {
            if (SOCKETLEY_UNLIKELY(!flush_responses(conn)))
            {
                // Nothing more can be delivered to this client, so parsing the
                // rest of the pipeline only grows a reply buffer that will never
                // be written.  Marking it is all this may do — the caller is
                // still holding conn — and the tail of the read handler tears it
                // down once it sees closing with nothing in flight.
                conn->closing = true;
                break;
            }
            conn->response_buf.reserve(4096);
        }
    }

    // Single erase for entire batch — O(remaining) not O(n * commands)
    if (offset > 0)
    {
        if (offset >= conn->partial.size())
            conn->partial.clear();
        else
            conn->partial.erase(0, offset);
    }
}

void cache_instance::process_resp_command(client_connection* conn, std::string_view* args, int argc)
{
    if (SOCKETLEY_UNLIKELY(argc == 0))
        return;

    // Global rate limit check (across all connections)
    if (SOCKETLEY_UNLIKELY(!check_global_rate_limit()))
    {
        resp::encode_error_into(conn->response_buf, "rate limited");
        return;
    }

    // Rate limit check (usually disabled — rl_max == 0)
    if (SOCKETLEY_UNLIKELY(conn->rl_max > 0))
    {
        auto now = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(now - conn->rl_last).count();
        conn->rl_last = now;
        conn->rl_tokens += elapsed * conn->rl_max;
        if (conn->rl_tokens > conn->rl_max)
            conn->rl_tokens = conn->rl_max;
        if (conn->rl_tokens < 1.0)
        {
            resp::encode_error_into(conn->response_buf, "rate limited");
            return;
        }
        conn->rl_tokens -= 1.0;
    }

    m_stat_commands++;
    m_stat_total_messages.fetch_add(1, std::memory_order_relaxed);

    // Helper: build text command from RESP args for replication
    auto repl = [&](std::string_view* a, int n) {
        if (m_repl_role != repl_leader || m_followers.empty()) return;
        std::string cmd;
        for (int i = 0; i < n; i++) {
            if (i > 0) cmd += ' ';
            cmd.append(a[i].data(), a[i].size());
        }
        replicate_command(cmd);
    };

    // ─── SET IS THE ONE COMMAND repl() CANNOT FLATTEN ───────────────────────
    //
    // repl() joins the arguments with spaces and the follower reads the result
    // with the TEXT interpreter, which takes everything after the key as the
    // value.  That is correct for every command whose arguments end with the
    // value — including a value containing spaces — and wrong for the one whose
    // options come AFTER it.  Measured, leader and follower side by side:
    //
    //     RESP  SET rk rv EX 100
    //     leader    get rk -> 'rv'          ttl 96
    //     follower  get rk -> 'rv EX 100'   ttl -1
    //
    // Not a stale value: a different one, on a key the leader holds correctly,
    // with the expiry lost as well.  Neither side can tell.
    //
    // What is replicated is therefore the EFFECT rather than the command.  The
    // leader has already decided what NX and XX mean — the follower must not
    // re-evaluate them against its own copy — and `set` plus `pexpire` are two
    // commands the text interpreter expresses exactly.  pexpire rather than
    // expire because it is the finer unit and covers both spellings.
    auto repl_set_effect = [&](std::string_view key, std::string_view val,
                               int ex_sec, int64_t px_ms) {
        if (m_repl_role != repl_leader || m_followers.empty()) return;

        std::string cmd;
        cmd.reserve(5 + key.size() + val.size());
        cmd += "set ";
        cmd.append(key.data(), key.size());
        cmd += ' ';
        cmd.append(val.data(), val.size());
        replicate_command(cmd);

        const int64_t ms = px_ms > 0 ? px_ms
                         : (ex_sec > 0 ? static_cast<int64_t>(ex_sec) * 1000 : 0);
        if (ms > 0)
        {
            std::string ttl_cmd = "pexpire ";
            ttl_cmd.append(key.data(), key.size());
            ttl_cmd += ' ';
            ttl_cmd += std::to_string(ms);
            replicate_command(ttl_cmd);
        }
    };

    // Dispatch via case-insensitive FNV-1a — no string allocation
    auto& rb = conn->response_buf;

    switch (fnv1a_lower(args[0]))
    {
        case fnv1a("set"):
        {
            if (SOCKETLEY_UNLIKELY(argc < 3)) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (SOCKETLEY_UNLIKELY(m_mode == cache_mode_readonly)) { resp::encode_error_into(rb, "readonly mode"); return; }

            // Fast-path: plain SET key value (argc == 3, no options)
            // This is the overwhelmingly common case in benchmarks
            if (SOCKETLEY_LIKELY(argc == 3))
            {
                if (SOCKETLEY_UNLIKELY(!m_store.set(args[1], args[2])))
                {
                    m_store.check_expiry(args[1]);
                    if (!m_store.set(args[1], args[2]))
                    {
                        auto t = m_store.type(args[1]);
                        if (t == "none" || t == "string")
                            resp::encode_error_into(rb,
                                "OOM command not allowed when used memory > 'maxmemory'");
                        else
                            resp::encode_error_into(rb, "type conflict");
                        break;
                    }
                }
                rb.append(resp::RESP_OK, 5);
                repl(args, argc);
#ifndef SOCKETLEY_NO_LUA
                if (SOCKETLEY_UNLIKELY(lua() && lua()->has_on_write()))
                {
                    {
                        sol::protected_function_result r = lua()->on_write()(args[1], args[2], 0);
                        if (SOCKETLEY_UNLIKELY(!r.valid()))
                        {
                            sol::error e = r;
                            std::cerr << lua_diag::tag(get_name()) << " on_write error: " << e.what() << "\n";
                        }
                    }
                }
#endif
                break;
            }

            // Slow path: SET with NX/XX/EX/PX options
            bool nx = false, xx = false;
            int ex_sec = 0;
            int64_t px_ms = 0;
            for (int i = 3; i < argc; i++)
            {
                switch (fnv1a_lower(args[i]))
                {
                    case fnv1a("ex"):
                        if (i + 1 < argc)
                        {
                            auto [p, e] = std::from_chars(args[i+1].data(), args[i+1].data() + args[i+1].size(), ex_sec);
                            if (e == std::errc{}) i++;
                        }
                        break;
                    case fnv1a("px"):
                        if (i + 1 < argc)
                        {
                            auto [p, e] = std::from_chars(args[i+1].data(), args[i+1].data() + args[i+1].size(), px_ms);
                            if (e == std::errc{}) i++;
                        }
                        break;
                    case fnv1a("nx"): nx = true; break;
                    case fnv1a("xx"): xx = true; break;
                    default:
                        // Refused rather than ignored.  `SET k v FOO` matched no
                        // case, fell through here and the SET reported success —
                        // so a mistyped option silently became a plain SET, and
                        // a caller that wrote EXX instead of EX got a key with
                        // no expiry and an "+OK".  Redis answers a syntax error;
                        // so does this now.
                        resp::encode_error_into(rb, "syntax error");
                        return;
                }
            }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            bool key_exists = m_store.exists(args[1]);
            if (nx && key_exists)  { resp::encode_null_into(rb); break; }
            if (xx && !key_exists) { resp::encode_null_into(rb); break; }
            if (!m_store.set(args[1], args[2]))
            {
                resp::encode_error_into(rb, "type conflict");
                break;
            }
            if (ex_sec > 0) { m_store.set_expiry(args[1], ex_sec); mark_ttl_keys(); }
            else if (px_ms > 0) { m_store.set_expiry_ms(args[1], px_ms); mark_ttl_keys(); }
            resp::encode_ok_into(rb);
            repl_set_effect(args[1], args[2], ex_sec, px_ms);
#ifndef SOCKETLEY_NO_LUA
            if (lua() && lua()->has_on_write())
            {
                {
                    sol::protected_function_result r = lua()->on_write()(args[1], args[2], ex_sec);
                    if (SOCKETLEY_UNLIKELY(!r.valid()))
                    {
                        sol::error e = r;
                        std::cerr << lua_diag::tag(get_name()) << " on_write error: " << e.what() << "\n";
                    }
                }
            }
#endif
            break;
        }
        case fnv1a("get"):
        {
            if (SOCKETLEY_UNLIKELY(argc < 2)) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            // Combined expiry check + lookup — one hash probe instead of two
            const std::string* val = m_store.check_expiry_and_get_ptr(args[1]);
            if (SOCKETLEY_LIKELY(val != nullptr))
            {
                m_stat_get_hits++;
                resp::encode_bulk_into(rb, *val);
            }
            else
            {
#ifndef SOCKETLEY_NO_LUA
                if (SOCKETLEY_UNLIKELY(lua() && lua()->has_on_miss()))
                {
                    // Checked BEFORE the result is read, and that is not a formality:
                    // on a failed call the value at index 0 is the ERROR OBJECT, and
                    // reading it as an optional<string> would store a Lua error message
                    // in the cache and answer it to the client as the fetched value.
                    // A raise still means a miss, which is what the catch this replaces
                    // decided by falling through to the nil below.
                    sol::protected_function_result res = lua()->on_miss()(args[1]);
                    if (SOCKETLEY_UNLIKELY(!res.valid()))
                    {
                        sol::error e = res;
                        std::cerr << lua_diag::tag(get_name()) << " on_miss error: " << e.what() << "\n";
                    }
                    else
                    {
                        sol::optional<std::string> fetched = res.get<sol::optional<std::string>>(0);
                        if (fetched && !fetched->empty())
                        {
                            int ttl = 0;
                            sol::optional<int> ttl_opt = res.get<sol::optional<int>>(1);
                            if (ttl_opt) ttl = *ttl_opt;
                            m_store.set(args[1], *fetched);
                            if (ttl > 0) { m_store.set_expiry(args[1], ttl); mark_ttl_keys(); }
                            m_stat_get_hits++;
                            resp::encode_bulk_into(rb, *fetched);
                            break;
                        }
                    }
                }
#endif
                m_stat_get_misses++;
                rb.append(resp::RESP_NULL, 5);
            }
            break;
        }
        case fnv1a("del"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int deleted = 0;
            for (int i = 1; i < argc; i++)
            {
                // del() succeeds on an already-expired key, so without this the
                // reply would count keys that Redis reports as absent.
                if (m_has_ttl_keys) m_store.check_expiry(args[i]);
                if (m_store.del(args[i]))
                {
                    deleted++;
#ifndef SOCKETLEY_NO_LUA
                    if (lua() && lua()->has_on_delete())
                    {
                        {
                            sol::protected_function_result r = lua()->on_delete_cb()(args[i]);
                            if (SOCKETLEY_UNLIKELY(!r.valid()))
                            {
                                sol::error e = r;
                                std::cerr << lua_diag::tag(get_name()) << " on_delete error: " << e.what() << "\n";
                            }
                        }
                    }
#endif
                }
            }
            if (deleted > 0) repl(args, argc);
            resp::encode_integer_into(rb, deleted);
            break;
        }
        case fnv1a("exists"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            resp::encode_integer_into(rb, m_store.exists(args[1]) ? 1 : 0);
            break;
        }
        case fnv1a("incr"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int64_t result = 0;
            if (!m_store.incr(args[1], 1, result))
                resp::encode_error_into(rb, "ERR value is not an integer or out of range");
            else
            { resp::encode_integer_into(rb, result); repl(args, argc); }
            break;
        }
        case fnv1a("decr"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int64_t result = 0;
            if (!m_store.incr(args[1], -1, result))
                resp::encode_error_into(rb, "ERR value is not an integer or out of range");
            else
            { resp::encode_integer_into(rb, result); repl(args, argc); }
            break;
        }
        case fnv1a("incrby"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int64_t delta = 0;
            auto [p, e] = std::from_chars(args[2].data(), args[2].data() + args[2].size(), delta);
            if (e != std::errc{}) { resp::encode_error_into(rb, "ERR value is not an integer or out of range"); return; }
            int64_t result = 0;
            if (!m_store.incr(args[1], delta, result))
                resp::encode_error_into(rb, "ERR value is not an integer or out of range");
            else
            { resp::encode_integer_into(rb, result); repl(args, argc); }
            break;
        }
        case fnv1a("decrby"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int64_t delta = 0;
            auto [p2, e2] = std::from_chars(args[2].data(), args[2].data() + args[2].size(), delta);
            if (e2 != std::errc{}) { resp::encode_error_into(rb, "ERR value is not an integer or out of range"); return; }
            int64_t result = 0;
            if (!m_store.incr(args[1], -delta, result))
                resp::encode_error_into(rb, "ERR value is not an integer or out of range");
            else
            { resp::encode_integer_into(rb, result); repl(args, argc); }
            break;
        }
        case fnv1a("append"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            size_t newlen = m_store.append(args[1], args[2]);
            if (newlen == cache_store::append_wrong_type)
                resp::encode_error_into(rb, "WRONGTYPE");
            else if (newlen == cache_store::append_denied)
                resp::encode_error_into(rb, "OOM command not allowed when used memory > 'maxmemory'");
            else
            { resp::encode_integer_into(rb, static_cast<int64_t>(newlen)); repl(args, argc); }
            break;
        }
        case fnv1a("strlen"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            resp::encode_integer_into(rb, static_cast<int64_t>(m_store.strlen_key(args[1])));
            break;
        }
        case fnv1a("getset"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            // GETSET must return nil for an expired key, not its stale value.
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            bool had_key = m_store.exists(args[1]);
            std::string oldval;
            if (!m_store.getset(args[1], args[2], oldval))
                resp::encode_error_into(rb, "WRONGTYPE");
            else
            {
                if (!had_key) resp::encode_null_into(rb);
                else resp::encode_bulk_into(rb, oldval);
                repl(args, argc);
            }
            break;
        }
        case fnv1a("mget"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            resp::encode_array_header_into(rb, argc - 1);
            for (int i = 1; i < argc; i++)
            {
                if (m_has_ttl_keys) m_store.check_expiry(args[i]);
                const std::string* val = m_store.get_ptr(args[i]);
                if (val) resp::encode_bulk_into(rb, *val);
                else resp::encode_null_into(rb);
            }
            break;
        }
        case fnv1a("mset"):
        {
            if (argc < 3 || (argc - 1) % 2 != 0) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            for (int i = 1; i + 1 < argc; i += 2)
            {
                if (m_has_ttl_keys) m_store.check_expiry(args[i]);
                m_store.set(args[i], args[i+1]);
#ifndef SOCKETLEY_NO_LUA
                if (lua() && lua()->has_on_write())
                {
                    {
                        sol::protected_function_result r = lua()->on_write()(args[i], args[i+1], 0);
                        if (SOCKETLEY_UNLIKELY(!r.valid()))
                        {
                            sol::error e = r;
                            std::cerr << lua_diag::tag(get_name()) << " on_write error: " << e.what() << "\n";
                        }
                    }
                }
#endif
            }
            resp::encode_ok_into(rb);
            repl(args, argc);
            break;
        }
        case fnv1a("type"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            resp::encode_simple_into(rb, m_store.type(args[1]));
            break;
        }
        case fnv1a("keys"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            std::vector<std::string_view> result;
            m_store.keys(args[1], result);
            resp::encode_array_header_into(rb, static_cast<int>(result.size()));
            for (auto& k : result)
                resp::encode_bulk_into(rb, k);
            break;
        }
        case fnv1a("ping"):
        {
            if (SOCKETLEY_LIKELY(argc <= 1))
                rb.append(resp::RESP_PONG, 7);
            else
                resp::encode_bulk_into(rb, args[1]);
            break;
        }
        case fnv1a("dbsize"):
        {
            resp::encode_integer_into(rb, m_store.size());
            break;
        }
        case fnv1a("lpush"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            for (int i = 2; i < argc; i++)
            {
                if (!m_store.lpush(args[1], args[i]))
                {
                    m_store.check_expiry(args[1]);
                    if (!m_store.lpush(args[1], args[i]))
                    {
                        resp::encode_error_into(rb, "type conflict");
                        return;
                    }
                }
            }
            resp::encode_integer_into(rb, m_store.llen(args[1]));
            repl(args, argc);
            break;
        }
        case fnv1a("rpush"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            for (int i = 2; i < argc; i++)
            {
                if (!m_store.rpush(args[1], args[i]))
                {
                    m_store.check_expiry(args[1]);
                    if (!m_store.rpush(args[1], args[i]))
                    {
                        resp::encode_error_into(rb, "type conflict");
                        return;
                    }
                }
            }
            resp::encode_integer_into(rb, m_store.llen(args[1]));
            repl(args, argc);
            break;
        }
        case fnv1a("lpop"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            std::string val;
            if (m_store.lpop(args[1], val)) { resp::encode_bulk_into(rb, val); repl(args, argc); }
            else resp::encode_null_into(rb);
            break;
        }
        case fnv1a("rpop"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            std::string val;
            if (m_store.rpop(args[1], val)) { resp::encode_bulk_into(rb, val); repl(args, argc); }
            else resp::encode_null_into(rb);
            break;
        }
        case fnv1a("llen"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            resp::encode_integer_into(rb, m_store.llen(args[1]));
            break;
        }
        case fnv1a("lrange"):
        {
            if (argc < 4) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            int start = 0, stop = 0;
            auto [p1, e1] = std::from_chars(args[2].data(), args[2].data() + args[2].size(), start);
            auto [p2, e2] = std::from_chars(args[3].data(), args[3].data() + args[3].size(), stop);
            if (e1 != std::errc{} || e2 != std::errc{}) { resp::encode_error_into(rb, "ERR value is not an integer or out of range"); return; }
            const auto* deq = m_store.list_ptr(args[1]);
            if (!deq || deq->empty()) { resp::encode_array_header_into(rb, 0); break; }
            int len = static_cast<int>(deq->size());
            if (start < 0) start += len;
            if (stop < 0) stop += len;
            if (start < 0) start = 0;
            if (stop >= len) stop = len - 1;
            int result_len = (start > stop) ? 0 : (stop - start + 1);
            resp::encode_array_header_into(rb, result_len);
            for (int i = start; i <= stop; i++)
                resp::encode_bulk_into(rb, (*deq)[static_cast<size_t>(i)]);
            break;
        }
        case fnv1a("lindex"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            int idx = 0;
            auto [p, e] = std::from_chars(args[2].data(), args[2].data() + args[2].size(), idx);
            if (e != std::errc{}) { resp::encode_error_into(rb, "ERR value is not an integer or out of range"); return; }
            const std::string* val = m_store.lindex(args[1], idx);
            if (val) resp::encode_bulk_into(rb, *val);
            else resp::encode_null_into(rb);
            break;
        }
        case fnv1a("sadd"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int added = 0;
            for (int i = 2; i < argc; i++)
            {
                int r = m_store.sadd(args[1], args[i]);
                if (r < 0)
                {
                    m_store.check_expiry(args[1]);
                    r = m_store.sadd(args[1], args[i]);
                    if (r < 0) { resp::encode_error_into(rb, "type conflict"); return; }
                }
                added += r;
            }
            if (added > 0) repl(args, argc);
            resp::encode_integer_into(rb, added);
            break;
        }
        case fnv1a("srem"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            int removed = 0;
            for (int i = 2; i < argc; i++)
                if (m_store.srem(args[1], args[i])) removed++;
            if (removed > 0) repl(args, argc);
            resp::encode_integer_into(rb, removed);
            break;
        }
        case fnv1a("sismember"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            resp::encode_integer_into(rb, m_store.sismember(args[1], args[2]) ? 1 : 0);
            break;
        }
        case fnv1a("scard"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            resp::encode_integer_into(rb, m_store.scard(args[1]));
            break;
        }
        case fnv1a("smembers"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            const auto* s = m_store.set_ptr(args[1]);
            if (!s) { resp::encode_array_header_into(rb, 0); break; }
            resp::encode_array_header_into(rb, static_cast<int>(s->size()));
            for (const auto& member : *s)
                resp::encode_bulk_into(rb, member);
            break;
        }
        case fnv1a("hset"):
        {
            if (argc < 4 || (argc - 2) % 2 != 0)
            {
                resp::encode_error_into(rb, "wrong number of arguments");
                return;
            }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int added = 0;
            for (int i = 2; i + 1 < argc; i += 2)
            {
                if (!m_store.hset(args[1], args[i], args[i+1]))
                {
                    m_store.check_expiry(args[1]);
                    if (!m_store.hset(args[1], args[i], args[i+1]))
                    {
                        // Same as SET: a memory refusal is not a type conflict,
                        // and overwriting a field can now be refused for room.
                        auto t = m_store.type(args[1]);
                        if (t == "none" || t == "hash")
                            resp::encode_error_into(rb,
                                "OOM command not allowed when used memory > 'maxmemory'");
                        else
                            resp::encode_error_into(rb, "type conflict");
                        return;
                    }
                }
                added++;
            }
            repl(args, argc);
            resp::encode_integer_into(rb, added);
            break;
        }
        case fnv1a("hget"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            const std::string* val = m_store.hget(args[1], args[2]);
            if (val) resp::encode_bulk_into(rb, *val);
            else resp::encode_null_into(rb);
            break;
        }
        case fnv1a("hdel"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            int removed = 0;
            for (int i = 2; i < argc; i++)
                if (m_store.hdel(args[1], args[i])) removed++;
            if (removed > 0) repl(args, argc);
            resp::encode_integer_into(rb, removed);
            break;
        }
        case fnv1a("hlen"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            resp::encode_integer_into(rb, m_store.hlen(args[1]));
            break;
        }
        case fnv1a("hgetall"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            const auto* h = m_store.hash_ptr(args[1]);
            if (!h) { resp::encode_array_header_into(rb, 0); break; }
            resp::encode_array_header_into(rb, static_cast<int>(h->size() * 2));
            for (const auto& [field, val] : *h)
            {
                resp::encode_bulk_into(rb, field);
                resp::encode_bulk_into(rb, val);
            }
            break;
        }
        case fnv1a("expire"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int sec = 0;
            auto [p, e] = std::from_chars(args[2].data(), args[2].data() + args[2].size(), sec);
            if (e != std::errc{} || sec <= 0) { resp::encode_error_into(rb, "invalid seconds"); return; }
            if (m_store.set_expiry(args[1], sec))
            {
                mark_ttl_keys();
                repl(args, argc);
                resp::encode_integer_into(rb, 1);
            }
            else
                resp::encode_integer_into(rb, 0);
            break;
        }
        case fnv1a("ttl"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            resp::encode_integer_into(rb, m_store.get_ttl(args[1]));
            break;
        }
        case fnv1a("persist"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            if (m_store.persist(args[1]))
            { repl(args, argc); resp::encode_integer_into(rb, 1); }
            else
                resp::encode_integer_into(rb, 0);
            break;
        }
        case fnv1a("setnx"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            bool did_set = m_store.setnx(args[1], args[2]);
            if (did_set) repl(args, argc);
            resp::encode_integer_into(rb, did_set ? 1 : 0);
#ifndef SOCKETLEY_NO_LUA
            if (did_set && lua() && lua()->has_on_write())
            {
                {
                    sol::protected_function_result r = lua()->on_write()(args[1], args[2], 0);
                    if (SOCKETLEY_UNLIKELY(!r.valid()))
                    {
                        sol::error e = r;
                        std::cerr << lua_diag::tag(get_name()) << " on_write error: " << e.what() << "\n";
                    }
                }
            }
#endif
            break;
        }
        case fnv1a("setex"):
        {
            if (argc < 4) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int sec = 0;
            auto [p, e] = std::from_chars(args[2].data(), args[2].data() + args[2].size(), sec);
            if (e != std::errc{} || sec <= 0) { resp::encode_error_into(rb, "ERR invalid expire time in SETEX"); return; }
            if (!m_store.set(args[1], args[3]))
            {
                m_store.check_expiry(args[1]);
                if (!m_store.set(args[1], args[3])) { resp::encode_error_into(rb, "WRONGTYPE"); return; }
            }
            m_store.set_expiry(args[1], sec);
            mark_ttl_keys();
            resp::encode_ok_into(rb);
            repl(args, argc);
#ifndef SOCKETLEY_NO_LUA
            if (lua() && lua()->has_on_write())
            {
                {
                    sol::protected_function_result r = lua()->on_write()(args[1], args[3], sec);
                    if (SOCKETLEY_UNLIKELY(!r.valid()))
                    {
                        sol::error e = r;
                        std::cerr << lua_diag::tag(get_name()) << " on_write error: " << e.what() << "\n";
                    }
                }
            }
#endif
            break;
        }
        case fnv1a("psetex"):
        {
            if (argc < 4) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int64_t ms = 0;
            auto [p, e] = std::from_chars(args[2].data(), args[2].data() + args[2].size(), ms);
            if (e != std::errc{} || ms <= 0) { resp::encode_error_into(rb, "ERR invalid expire time in PSETEX"); return; }
            if (!m_store.set(args[1], args[3]))
            {
                m_store.check_expiry(args[1]);
                if (!m_store.set(args[1], args[3])) { resp::encode_error_into(rb, "WRONGTYPE"); return; }
            }
            m_store.set_expiry_ms(args[1], ms);
            mark_ttl_keys();
            resp::encode_ok_into(rb);
            repl(args, argc);
#ifndef SOCKETLEY_NO_LUA
            if (lua() && lua()->has_on_write())
            {
                {
                    sol::protected_function_result r = lua()->on_write()(args[1], args[3], 0);
                    if (SOCKETLEY_UNLIKELY(!r.valid()))
                    {
                        sol::error e = r;
                        std::cerr << lua_diag::tag(get_name()) << " on_write error: " << e.what() << "\n";
                    }
                }
            }
#endif
            break;
        }
        case fnv1a("pexpire"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int64_t ms = 0;
            auto [p, e] = std::from_chars(args[2].data(), args[2].data() + args[2].size(), ms);
            if (e != std::errc{} || ms <= 0) { resp::encode_error_into(rb, "ERR invalid expire time"); return; }
            if (m_store.set_expiry_ms(args[1], ms))
            {
                mark_ttl_keys();
                repl(args, argc);
                resp::encode_integer_into(rb, 1);
            }
            else
                resp::encode_integer_into(rb, 0);
            break;
        }
        case fnv1a("pttl"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_has_ttl_keys) m_store.check_expiry(args[1]);
            resp::encode_integer_into(rb, m_store.get_pttl(args[1]));
            break;
        }
        case fnv1a("expireat"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int64_t unix_s = 0;
            auto [p, e] = std::from_chars(args[2].data(), args[2].data() + args[2].size(), unix_s);
            if (e != std::errc{}) { resp::encode_error_into(rb, "ERR invalid timestamp"); return; }
            {
                int64_t now_s = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                int64_t remaining = unix_s - now_s;
                if (remaining <= 0) { m_store.del(args[1]); repl(args, argc); resp::encode_integer_into(rb, 1); }
                else if (m_store.set_expiry(args[1], remaining))
                { mark_ttl_keys(); repl(args, argc); resp::encode_integer_into(rb, 1); }
                else resp::encode_integer_into(rb, 0);
            }
            break;
        }
        case fnv1a("pexpireat"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            if (m_mode == cache_mode_readonly) { resp::encode_error_into(rb, "readonly mode"); return; }
            int64_t unix_ms = 0;
            auto [p, e] = std::from_chars(args[2].data(), args[2].data() + args[2].size(), unix_ms);
            if (e != std::errc{}) { resp::encode_error_into(rb, "ERR invalid timestamp"); return; }
            {
                int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                int64_t remaining_ms = unix_ms - now_ms;
                if (remaining_ms <= 0) { m_store.del(args[1]); repl(args, argc); resp::encode_integer_into(rb, 1); }
                else if (m_store.set_expiry_ms(args[1], remaining_ms))
                { mark_ttl_keys(); repl(args, argc); resp::encode_integer_into(rb, 1); }
                else resp::encode_integer_into(rb, 0);
            }
            break;
        }
        case fnv1a("scan"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            uint64_t scan_cursor = 0;
            {
                auto [p, e] = std::from_chars(args[1].data(), args[1].data() + args[1].size(), scan_cursor);
                if (e != std::errc{}) { resp::encode_error_into(rb, "ERR invalid cursor"); return; }
            }
            std::string_view scan_pattern = "*";
            size_t scan_count = 10;
            for (int i = 2; i < argc; i++)
            {
                if (fnv1a_lower(args[i]) == fnv1a("match") && i + 1 < argc)
                    scan_pattern = args[++i];
                else if (fnv1a_lower(args[i]) == fnv1a("count") && i + 1 < argc)
                {
                    size_t cnt = 10;
                    auto [p2, e2] = std::from_chars(args[i+1].data(), args[i+1].data() + args[i+1].size(), cnt);
                    if (e2 == std::errc{}) scan_count = cnt;
                    i++;
                }
            }
            std::vector<std::string_view> scan_keys;
            uint64_t next_cursor = m_store.scan(scan_cursor, scan_pattern, scan_count, scan_keys);
            // RESP: *2\r\n + bulk(next_cursor_str) + array(keys)
            rb.append("*2\r\n");
            char cur_buf[24];
            auto [end, ec] = std::to_chars(cur_buf, cur_buf + sizeof(cur_buf), next_cursor);
            resp::encode_bulk_into(rb, std::string_view(cur_buf, static_cast<size_t>(end - cur_buf)));
            resp::encode_array_header_into(rb, static_cast<int>(scan_keys.size()));
            for (auto& k : scan_keys)
                resp::encode_bulk_into(rb, k);
            break;
        }
        case fnv1a("subscribe"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            for (int i = 1; i < argc; i++)
                m_store.subscribe(conn->fd, args[i]);
            resp::encode_ok_into(rb);
            break;
        }
        case fnv1a("unsubscribe"):
        {
            if (argc < 2) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            for (int i = 1; i < argc; i++)
                m_store.unsubscribe(conn->fd, args[i]);
            resp::encode_ok_into(rb);
            break;
        }
        case fnv1a("publish"):
        {
            if (argc < 3) { resp::encode_error_into(rb, "wrong number of arguments"); return; }
            int count = publish(args[1], args[2]);
            resp::encode_integer_into(rb, count);
            break;
        }
        default:
        {
            rb.append("-ERR unknown command '", 22);
            rb.append(args[0].data(), args[0].size());
            rb.append("'\r\n", 3);
            break;
        }
    }
}

// ─── Pub/Sub publish ───

int cache_instance::publish(std::string_view channel, std::string_view message)
{
    const auto* subs = m_store.get_subscribers(channel);
    int count = 0;

    if (subs && !subs->empty())
    {
        // Lazily built per-format messages (avoid building both if only one type exists)
        std::string text_msg;
        std::string resp_msg;

        for (int fd : *subs)
        {
            if (fd < 0 || fd >= MAX_FDS || !m_conn_idx[fd])
                continue;

            auto* sub_conn = m_conn_idx[fd];
            // A promoted follower has had its subscriptions dropped, so it
            // should never appear here; the check stays because delivering to it
            // would mean a publish writing into the middle of the replication
            // stream, and that is not something to leave to one call site.
            if (sub_conn->closing || sub_conn->is_follower)
                continue;

            // A subscriber that has stopped reading must not be allowed to grow
            // the queue without limit, but the bound is memory: a slow reader on
            // 30-byte notifications was dropped after 123 KB when this counted
            // entries.
            if (sub_conn->write_queue.bytes() >= socketley::write_queue_max_bytes)
            {
                sub_conn->closing = true;
                continue;
            }

            if (sub_conn->resp_mode)
            {
                if (resp_msg.empty())
                {
                    // RESP pub/sub: *3\r\n$7\r\nmessage\r\n$<chanlen>\r\n<chan>\r\n$<msglen>\r\n<msg>\r\n
                    resp_msg.reserve(32 + channel.size() + message.size());
                    resp_msg.append("*3\r\n$7\r\nmessage\r\n");
                    resp::encode_bulk_into(resp_msg, channel);
                    resp::encode_bulk_into(resp_msg, message);
                }
                sub_conn->write_queue.push(resp_msg);
            }
            else
            {
                if (text_msg.empty())
                {
                    text_msg.reserve(8 + channel.size() + 1 + message.size() + 1);
                    text_msg.append("message ");
                    text_msg.append(channel.data(), channel.size());
                    text_msg.push_back(' ');
                    text_msg.append(message.data(), message.size());
                    text_msg.push_back('\n');
                }
                sub_conn->write_queue.push(text_msg);
            }

            if (!sub_conn->write_pending && SOCKETLEY_UNLIKELY(!flush_write_queue(sub_conn)))
            {
                // Marking it is all that is allowed here.  close_client() would
                // call unsubscribe_all() on the very subscriber set this loop is
                // walking, and publish() returns into a command handler that
                // goes on using its own connection.  The subscriber has a read
                // armed; its handler finishes the teardown.
                sub_conn->closing = true;
                continue;
            }
            count++;
        }
    }

    // Dispatch to Lua subscribers in other runtimes
    if (auto* mgr = get_runtime_manager())
        mgr->dispatch_publish(get_name(), channel, message);

    return count;
}

// ─── Maxmemory / Eviction ───

void cache_instance::set_max_memory(size_t bytes)
{
    m_store.set_max_memory(bytes);
}

size_t cache_instance::get_max_memory() const
{
    return m_store.get_max_memory();
}

void cache_instance::set_eviction(eviction_policy policy)
{
    m_store.set_eviction(policy);
}

eviction_policy cache_instance::get_eviction() const
{
    return m_store.get_eviction();
}

// ─── RESP mode ───

void cache_instance::set_resp_forced(bool enabled)
{
    m_resp_forced = enabled;
}

bool cache_instance::get_resp_forced() const
{
    return m_resp_forced;
}

// ─── Replication ───

void cache_instance::set_replicate_target(std::string_view host_port)
{
    m_replicate_target = host_port;

    // ─── What an empty target means ────────────────────────────────────────
    //
    // This setter names the leader this cache follows.  An empty string names
    // no leader, so it means "follows nobody" — not "follows something
    // unspecified", which is what assigning repl_follower unconditionally used
    // to make of it.
    //
    // That distinction is not academic, because every `import` and every `edit`
    // calls this with whatever the document holds, and a cache that was never
    // meant to replicate has no replicate_target field in its document at all.
    // So editing a plain cache — changing its eviction policy, say — turned it
    // into a follower of nothing.  From that point on it could never become a
    // leader either: handle_replicate_request() answers "error: this node is a
    // follower" before it looks at anything else, so a cache that had simply
    // been edited once refused to serve REPLICATE for the rest of its life.
    //
    // Two other sites had already met this state and papered over it locally —
    // setup() checks `repl_follower && !m_replicate_target.empty()` in both the
    // dial and the TLS refusal, because a follower with no leader to dial is
    // nonsense.  Those checks are the symptom.  This is where the state was
    // created.
    //
    // ─── Why a leader is left alone ────────────────────────────────────────
    //
    // repl_leader is not configuration.  It is established at runtime, when a
    // peer sends REPLICATE, and it owns live sockets: m_followers holds a
    // connection per follower and this runtime is the only writer on each.
    // Letting a config change revoke it silently is worse than the bug above.
    // It happened, too — an edit that touched only the eviction policy demoted a
    // leader with a follower attached, and because replicate_command() returns
    // early unless the role is repl_leader, every write after that stopped
    // reaching a follower whose socket was still open and still healthy from
    // both ends.  Neither side can detect that; the datasets simply drift.
    //
    // The target is still recorded, so an operator who genuinely wants this
    // cache to follow another gets what they asked for at the next restart —
    // which is when it would take effect in any case, since setup() is what
    // dials the leader and a fresh instance starts at repl_none.
    if (m_repl_role == repl_leader)
        return;

    m_repl_role = m_replicate_target.empty() ? repl_none : repl_follower;
}

std::string_view cache_instance::get_replicate_target() const
{
    return m_replicate_target;
}

cache_instance::repl_role cache_instance::get_repl_role() const
{
    return m_repl_role;
}

void cache_instance::follower_kick(follower_conn& f)
{
    // fd < 0 means the client this follower was promoted from has gone and
    // taken the socket with it.  Submitting against the number anyway is how
    // the whole replication stream — dump included — used to end up in an
    // unrelated client's socket the moment the kernel reissued it, with every
    // write reporting success so nothing ever noticed.
    if (f.write_pending || f.dead || f.fd < 0 || !m_loop)
        return;

    // Safe to touch `out` only now that nothing is in flight.
    if (f.out.empty() && !f.queued.empty())
        f.out.swap(f.queued);
    if (f.out.empty())
        return;

    f.in_flight = f.out.size();
    f.write_req = { this, nullptr, f.fd, static_cast<uint32_t>(f.in_flight), op_write };
    f.write_pending = true;
    if (SOCKETLEY_UNLIKELY(!m_loop->submit_write(f.fd, f.out.data(),
                                                 static_cast<uint32_t>(f.in_flight), &f.write_req)))
    {
        // Nothing restarts the stream after this: the write completion is what
        // kicks the next one, and there will not be one.  Replication would go
        // on looking healthy while the follower silently stopped advancing, so
        // the follower is dropped instead — that it reconnects and takes a fresh
        // dump is recoverable, a follower quietly stuck at an old snapshot is
        // not.
        f.write_pending = false;
        f.in_flight = 0;
        f.dead = true;
        LOG_WARN("cache: replication write refused by the ring, dropping the follower");
    }
}

bool cache_instance::follower_write(follower_conn& f, std::string_view data)
{
    if (f.dead || f.fd < 0)
        return false;

    f.queued.append(data.data(), data.size());

    if (f.backlog() > MAX_FOLLOWER_PENDING)
    {
        std::cerr << "[cache] follower too far behind ("
                  << f.backlog() << " bytes queued), dropping\n";
        return false;
    }

    // follower_kick() gives up on the follower when its write cannot be handed
    // to the ring; report that here rather than letting the caller believe the
    // data is on its way.
    follower_kick(f);
    return !f.dead;
}

void cache_instance::handle_follower_write(struct io_uring_cqe* cqe, follower_conn& f)
{
    f.write_pending = false;

    if (cqe->res <= 0)
    {
        f.dead = true;
        return;
    }

    // A short write is normal; only the acknowledged prefix may be dropped.
    size_t written = std::min(static_cast<size_t>(cqe->res), f.in_flight);
    f.out.erase(0, written);
    f.in_flight = 0;

    follower_kick(f);
}

void cache_instance::reap_followers()
{
    for (auto it = m_followers.begin(); it != m_followers.end(); )
    {
        // A follower with a write still in flight has to stay alive until its
        // completion arrives — the kernel still points at its buffer.
        if (!(*it)->dead || (*it)->write_pending)
        {
            ++it;
            continue;
        }

        // The socket is not ours to close: it belongs to the client_connection
        // this follower was promoted from, and close_client() is the only path
        // that also drops that client's subscriptions and hands its struct
        // back.  Ask for the connection to go instead of taking the descriptor
        // out from under it.
        //
        // Marking rather than closing, because this runs from inside command
        // handling — replicate_command() reaches here from process_command() —
        // and the connection being dropped may be the very one whose handler is
        // running.  The read completion that the shutdown produces finishes the
        // teardown from a place where freeing it is safe; a handler that is
        // already mid-close finishes it itself when it finds nothing in flight.
        const int fd = (*it)->fd;
        if (fd >= 0 && fd < MAX_FDS && m_conn_idx[fd])
        {
            m_conn_idx[fd]->closing = true;
            shutdown(fd, SHUT_RDWR);
        }
        it = m_followers.erase(it);
    }
}

void cache_instance::detach_follower(int fd)
{
    if (m_followers.empty() || fd < 0)
        return;

    for (auto& f : m_followers)
    {
        if (f->fd != fd)
            continue;
        // The descriptor goes back to the kernel with the client; everything
        // this follower still holds is buffers.  A write that is already in
        // flight keeps going to the socket it was submitted against — the
        // operation holds its own reference — so only new submissions have to
        // be stopped, which clearing the fd does.
        f->fd = -1;
        f->dead = true;
    }
    reap_followers();
}

cache_instance::follower_conn* cache_instance::follower_for_fd(int fd)
{
    if (fd < 0)
        return nullptr;
    for (auto& f : m_followers)
        if (f->fd == fd)
            return f.get();
    return nullptr;
}

void cache_instance::refuse_follower_input(client_connection* conn)
{
    // The bytes are dropped, not parsed.  Executing them would produce a
    // response, and there is nowhere to put a response: the follower buffer owns
    // this socket now.
    conn->partial.clear();

    if (conn->follower_refused)
        return;
    conn->follower_refused = true;

    LOG_WARN("cache: command received on a replication follower connection, ignoring");

    // Say so through the replication stream itself, so the socket keeps exactly
    // one writer.  A real follower drops any line it does not recognise —
    // handle_master_read() acts on a fixed set of commands and ignores the rest
    // — so this reaches a person watching the socket and nobody else.  Once per
    // connection: a client that keeps sending would otherwise be able to push
    // the follower past MAX_FOLLOWER_PENDING with error lines alone.
    follower_conn* f = follower_for_fd(conn->fd);
    if (!f)
        return;
    if (!follower_write(*f, "error: replication follower, commands are not accepted\n"))
    {
        f->dead = true;
        reap_followers();
    }
}

void cache_instance::replicate_command(std::string_view cmd)
{
    if (m_repl_role != repl_leader || m_followers.empty())
        return;

    // ─── A VALUE WITH A NEWLINE IN IT ───────────────────────────────────────
    //
    // The replication link is one command per line, and a cache value is
    // arbitrary bytes — a RESP bulk string may contain anything.  So a value
    // with a line break ended at the break on the follower, and the remainder
    // was interpreted as a command of its own.  Measured:
    //
    //     RESP  SET nk "a\nb"
    //     leader    get nk  ->  a<LF>b
    //     follower  get nk  ->  a
    //
    // The two stores then disagreed and neither side could tell: replication
    // reports no error, because from the link's point of view nothing failed.
    //
    // This is the same defect as the control socket's, which ipc_framing.h
    // fixed, so it is the same fix and literally the same framing — a second
    // format for one job in one tree is how the two drift apart.
    //
    // ─── AND THE OLD FOLLOWER, WHICH IS THE ONLY DECISION HERE ──────────────
    //
    // A frame is sent ONLY when the line protocol cannot carry the command, so
    // every value without a newline is byte-identical on the wire and an old
    // follower sees exactly what it always saw.  The one case that changes is
    // the case that was already broken: an old follower now receives a frame it
    // does not understand and stores nothing, instead of storing a truncated
    // value and executing the tail as a command.  Neither is replication, and
    // between them, not applying a command is the one that does not corrupt the
    // dataset or run something nobody sent.
    //
    // There is no negotiation on this link to do better with, and adding one to
    // hand back a truncated value is not worth a protocol version.
    std::string line;
    if (ipc_frame::needs_frame(cmd))
    {
        line = ipc_frame::encode(cmd);
    }
    else
    {
        line.reserve(cmd.size() + 1);
        line.append(cmd.data(), cmd.size());
        line.push_back('\n');
    }

    for (auto& f : m_followers)
    {
        if (!follower_write(*f, line))
            f->dead = true;
    }
    reap_followers();
}

void cache_instance::handle_replicate_request(client_connection* conn)
{
    // ─── A TLS cache is not a replication leader ───────────────────────────
    //
    // The other half of the refusal in tls_config_refusal, and the half no
    // configuration gate can make: this cache becomes a leader here, when a
    // client asks, long after `create` and `start` have had their say.
    //
    // What promotion would do on a TLS listener is put a *second writer* on
    // this socket — follower_conn submits raw bytes straight at the descriptor
    // (see follower_kick), around the record layer that owns it.  Every one of
    // them would be cleartext inside what the peer believes is an encrypted
    // session: unreadable to a real follower, and this cache's entire dataset
    // in the clear on the wire.  Routing it through the session instead is not
    // a smaller change than it looks — it would mean two independent writers
    // on one write BIO, which is the exact thing the promotion rules below
    // exist to prevent.
    //
    // So it is refused, and the refusal goes to conn->response_buf, which is
    // still the ordinary reply path because no promotion has happened.
    if (m_tls)
    {
        conn->response_buf.append(
            "error: this cache terminates TLS on its listener and replication is "
            "not encrypted -- the dump and the command stream would go out in "
            "cleartext\n", 143);
        return;
    }

    // Client sent "REPLICATE\n" — promote self to leader, send full dump
    if (m_repl_role == repl_follower)
    {
        conn->response_buf.append("error: this node is a follower\n", 31);
        return;
    }

    // A follower is a socket, and interactive execute() has none: it runs
    // commands through a connection with fd -1.  Registering one anyway put a
    // follower in the list that could never be written to and that the reaper
    // would then try to tie back to a client connection.
    if (conn->fd < 0)
    {
        conn->response_buf.append("error: replicate needs a connection\n", 36);
        return;
    }

    // ─── What REPLICATE promises ───────────────────────────────────────────
    //
    // The promotion makes this runtime the sole writer on the descriptor.  From
    // the moment it succeeds the socket carries one thing, leader to follower:
    // the "ok", the full dump, and then the replicated command stream, all out
    // of the follower's own buffer and therefore in that order.  A client may
    // read that stream or close the socket.  It may not send anything else —
    // any further command is dropped with a single error line and never
    // executed (see refuse_follower_input()).
    //
    // The alternative was to let the connection keep answering commands, which
    // is what it did: its client_connection is still there and still queues into
    // conn->response_buf, and flush_responses() then submits a second write on
    // the same fd.  io_uring orders nothing between two writes in flight, so
    // that reply lands wherever it lands — including inside a replicated
    // command, which the follower has no way to detect and no way to resync
    // from.  One socket, one writer, is the only version of this that can be
    // made to hold.
    //
    // Which is also why promotion is refused while the ordinary path still owes
    // this client bytes.  Those bytes were promised before REPLICATE and cannot
    // be moved into the replication stream — a GET reply is arbitrary data and a
    // follower would try to read it as commands — nor dropped, since the client
    // is waiting for them.  The one case that matters in practice, a client
    // whose first command is REPLICATE, passes straight through.
    if (!conn->response_buf.empty() || !conn->write_queue.empty() ||
        conn->write_pending || conn->zc_notif_pending)
    {
        conn->response_buf.append("error: replicate needs an idle connection\n", 42);
        return;
    }

    m_repl_role = repl_leader;
    // Ordinary command service on this connection ends here, not when the dump
    // finishes: the refusal in handle_read() has to cover anything the client
    // pipelined behind the REPLICATE line as well.
    conn->is_follower = true;

    // Any channel this connection had subscribed to goes with the promotion.
    // publish() writes straight into a subscriber's write queue, which is the
    // same second writer by another route, and the subscriber can no longer
    // unsubscribe itself.
    m_store.unsubscribe_all(conn->fd);

    // Register first, then queue the dump: both the dump and every command that
    // follows travel through the same buffer, which is what keeps them ordered.
    auto f = std::make_unique<follower_conn>();
    f->fd = conn->fd;
    follower_conn& fc = *f;
    m_followers.push_back(std::move(f));

    // The acknowledgement travels through the follower buffer too, ahead of the
    // dump.  Writing it to conn->response_buf instead would put a second,
    // independent writer on the same socket and let the two interleave.  The
    // follower ignores commands it does not recognise, so a leading "ok" is
    // harmless there.
    bool ok = follower_write(fc, "ok\n") && send_full_dump(fc);
    if (!ok)
    {
        std::cerr << "[cache] full sync to follower failed, dropping it\n";
        fc.dead = true;
        reap_followers();
    }
}

bool cache_instance::send_full_dump(follower_conn& f)
{
    std::string buf;
    buf.reserve(65536);
    m_store.dump_commands(buf);

    if (buf.empty())
        return true;

    // Queued rather than written synchronously.  A dataset of any size exceeds
    // the socket buffer, and the follower may be a runtime inside this very
    // daemon: waiting for it to drain would block the loop that has to feed it.
    return follower_write(f, buf);
}

bool cache_instance::connect_to_master()
{
    if (m_replicate_target.empty())
        return false;

    // Parse host:port
    size_t colon = m_replicate_target.rfind(':');
    if (colon == std::string::npos)
        return false;

    std::string host = m_replicate_target.substr(0, colon);
    uint16_t port = 0;
    auto port_sv = std::string_view(m_replicate_target).substr(colon + 1);
    auto [p, e] = std::from_chars(port_sv.data(), port_sv.data() + port_sv.size(), port);
    if (e != std::errc{})
        return false;

    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return false;

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1)
    {
        close_tracked(fd);
        return false;
    }

    if (connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        if (errno != EINPROGRESS)
        {
            close_tracked(fd);
            return false;
        }
        // Wait for non-blocking connect to complete (up to 5s)
        struct pollfd pfd{fd, POLLOUT, 0};
        if (poll(&pfd, 1, 5000) <= 0 || !(pfd.revents & POLLOUT))
        {
            close_tracked(fd);
            return false;
        }
        int sock_err = 0;
        socklen_t errlen = sizeof(sock_err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &sock_err, &errlen);
        if (sock_err != 0)
        {
            close_tracked(fd);
            return false;
        }
    }

    // Send REPLICATE command
    const char* cmd = "replicate\n";
    if (::write(fd, cmd, 10) < 0) { ::close(fd); return false; }

    // A link of its own, never the previous one reused.  The read armed on the
    // old link survives its socket being closed, and a reconnect usually lands
    // on the same fd number: two reads filling one buffer left the replication
    // stream with holes in it that neither side could see.
    auto link = std::make_unique<master_link>();
    link->fd = fd;
    link->read_req = { this, link->buf, fd, sizeof(link->buf), op_read };
    link->read_pending = true;

    if (m_loop && SOCKETLEY_UNLIKELY(!m_loop->submit_read(fd, link->buf,
                                                          sizeof(link->buf), &link->read_req)))
    {
        // Without this read the node is connected and deaf: the leader would
        // stream the full dump and every command after it into a socket nobody
        // drains.  Failing the connect outright keeps the follower visibly
        // unsynced rather than silently frozen at an empty dataset.
        LOG_ERROR("cache: read from master could not be armed — replication link not established");
        close_tracked(fd);
        return false;
    }
    if (!m_loop)
        link->read_pending = false;

    m_master = std::move(link);

    // Set mode to readonly as follower
    m_mode = cache_mode_readonly;

    return true;
}

void cache_instance::handle_master_read(struct io_uring_cqe* cqe)
{
    if (!m_master)
        return;

    auto& link = *m_master;
    link.read_pending = false;

    if (cqe->res <= 0)
    {
        // Master disconnected.  The link goes with it rather than being kept for
        // the next attempt: nothing is in flight on it any more, and a fresh one
        // is what connect_to_master() hands back.
        if (link.fd >= 0)
            close_tracked(link.fd);
        m_master.reset();
        return;
    }

    link.partial.append(link.buf, cqe->res);

    // ─── Framed or line, decided by the first byte ──────────────────────────
    //
    // 0x00 cannot begin a command in the line protocol — every one of them is
    // printable text starting with a letter — so the two forms travel on one
    // link and a leader that sends no frames is byte-identical to the one that
    // never could.  See replicate_command() for why only some commands are
    // framed and what an old peer makes of them.
    //
    // Scanned by offset with one erase at the end, rather than consumed per
    // command: a single read from a busy leader carries many commands, and
    // erasing the front for each would make the batch quadratic in its size.
    size_t scan_from = 0;
    bool   framing_broken = false;
    while (scan_from < link.partial.size())
    {
        std::string_view line;

        if (link.partial[scan_from] == ipc_frame::marker)
        {
            size_t next = 0;
            const auto r = ipc_frame::peek_frame(link.partial, scan_from, line, next);
            if (r == ipc_frame::take::need_more)
                break;
            if (r == ipc_frame::take::fatal)
            {
                framing_broken = true;
                break;
            }
            scan_from = next;
        }
        else
        {
            const size_t pos = link.partial.find('\n', scan_from);
            if (pos == std::string::npos)
                break;
            line = std::string_view(link.partial.data() + scan_from, pos - scan_from);
            if (!line.empty() && line.back() == '\r')
                line.remove_suffix(1);
            scan_from = pos + 1;
        }

        if (!line.empty())
        {
            // ─── THE SAME INTERPRETER THE LEADER RAN ────────────────────
            //
            // This used to be a hand-picked switch over six commands — set,
            // del, lpush, rpush, sadd, hset — with everything else falling into
            // `default: break`.  The leader replicates EVERY mutating command
            // verbatim, so an incr, a decr, an incrby, an append, a getset, a
            // setnx, an lpop, an srem, an hdel, an mset, an expire or a persist
            // reached the follower and was dropped on the floor.  Both sides
            // then believed they were in sync and neither could tell.  Measured
            // on the parent commit, one assertion per command family:
            //
            //     incr    follower 5,  leader 6
            //     append  follower "hello", leader "helloworld"
            //     lpop    follower llen 1, leader llen 0
            //     expire  follower ttl -1, leader ttl 100
            //     ... ten more of the same shape.
            //
            // The comment that stood here — "Actually, we can just call the
            // store methods directly" — is the shortcut that caused it, and it
            // could never have been complete: the set of mutating commands is
            // whatever the interpreter supports, and this was a copy of it that
            // stopped being true the moment one was added.
            //
            // serve_request() is that interpreter.  A follower cannot loop back
            // through it, because replicate_command() returns at once for any
            // role that is not leader.
            //
            // The response is built and dropped: nothing is listening on a
            // replication link, and it costs a string per command that the text
            // path was already building for its own clients.
            cache_mode saved = m_mode;
            m_mode = cache_mode_readwrite;

            std::string discard;
            serve_one_command(line, discard);

            m_mode = saved;
        }
    }

    // A length past max_payload means the stream's framing is wrong, and there
    // is no point in it that says where the next command starts.  Guessing
    // would apply whatever the bytes happened to spell to the dataset, so the
    // link goes instead — which surfaces as a master disconnect, the one
    // failure this side already knows how to report.
    if (framing_broken)
    {
        LOG_ERROR("cache: replication frame longer than the protocol allows — "
                  "the link is dropped rather than resynchronised");
        if (link.fd >= 0)
            close_tracked(link.fd);
        m_master.reset();
        return;
    }

    if (scan_from > 0)
    {
        if (scan_from >= link.partial.size())
            link.partial.clear();
        else
            link.partial.erase(0, scan_from);
    }

    // Re-submit read
    if (m_loop && link.fd >= 0)
    {
        link.read_pending = true;
        if (SOCKETLEY_UNLIKELY(!m_loop->submit_read(link.fd, link.buf,
                                                    sizeof(link.buf), &link.read_req)))
        {
            // This read is the only thing that ever re-arms itself, so a refusal
            // ends replication for good.  Dropping the socket makes the break
            // look like a master disconnect, which is at least visible, instead
            // of a follower that stays up serving a dataset that stopped
            // advancing.
            LOG_ERROR("cache: read from master refused — the replication link is dropped");
            link.read_pending = false;
            close_tracked(link.fd);
            m_master.reset();
        }
    }
}

// ─── Stats ───

std::string cache_instance::get_stats() const
{
    // Out-of-process: the text was built by the worker, walking a store that
    // only the worker's thread may walk.  Returning it verbatim is what makes
    // `stats` answer identically on both paths — rebuilding it here from this
    // placeholder's own empty store is the wrong answer, and a confident one:
    // it printed keys:0 and commands_processed:0 for a cache that had just
    // served five SETs.  Same reasoning, same two lines, as
    // proxy_instance::get_stats().
    if (worker_backed())
        return stat_detail_snapshot();

    std::string base = runtime_instance::get_stats();
    std::ostringstream out;
    out << base
        << "keys:" << m_store.size() << "\n"
        << "commands_processed:" << m_stat_commands << "\n"
        << "get_hits:" << m_stat_get_hits << "\n"
        << "get_misses:" << m_stat_get_misses << "\n"
        << "keys_expired:" << m_stat_keys_expired << "\n"
        << "mode:" << static_cast<int>(m_mode) << "\n"
        << "max_memory:" << m_store.get_max_memory() << "\n"
        << "memory_used:" << m_store.get_memory_used() << "\n"
        << "eviction:" << static_cast<int>(m_store.get_eviction()) << "\n"
        << "channels:" << m_store.channel_count() << "\n"
        << "repl_role:" << static_cast<int>(m_repl_role) << "\n"
        << "followers:" << m_followers.size() << "\n";
    return out.str();
}
