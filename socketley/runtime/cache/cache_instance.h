#pragma once
#include "../../shared/conn_reachability.h"
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <memory>
#include <queue>
#include <netinet/in.h>
#include <sys/uio.h>
#include <sys/socket.h>

#include "../../shared/runtime_instance.h"
#include "../../shared/event_loop_definitions.h"
#include "../../shared/request_channel.h"
#include "cache_store.h"
#include "../../shared/trace.h"
#include "../../shared/write_queue.h"
#include "../../shared/tls_context.h"

struct client_connection
{
    static constexpr size_t MAX_WRITE_BATCH = 16;
    // Upper size for merging consecutive responses into one queue entry.  Large
    // enough that thousands of small replies share a handful of entries, small
    // enough that a single entry stays a reasonable write.
    static constexpr size_t WRITE_COALESCE_LIMIT = 64 * 1024;
    static constexpr size_t MAX_PARTIAL_SIZE = 1 * 1024 * 1024;

    int fd;
    int fixed_idx{-1};
    bool direct_fd{false};
    io_request read_req;
    io_request write_req;
    char read_buf[4096];
    std::string partial;
    std::string response_buf;
    // write_queue holds owned strings — no shared_ptr overhead per flush
    socketley::byte_counted_queue<std::string> write_queue;

    std::string write_batch[MAX_WRITE_BATCH];
    struct iovec write_iovs[MAX_WRITE_BATCH];
    struct msghdr write_msg{};
    uint32_t write_batch_count{0};

    bool read_pending{false};
    bool write_pending{false};
    bool closing{false};
    bool zc_notif_pending{false};

    // RESP protocol mode (auto-detected or forced)
    bool resp_mode{false};
    bool resp_detected{false};  // true once first byte examined

    // Set by REPLICATE: this socket now carries the replication stream and
    // nothing else, and the follower buffer is its only writer.  Ordinary
    // commands are refused from here on — see handle_replicate_request() for the
    // rule and what a client is still allowed to do.  follower_refused keeps the
    // refusal to one line per connection, so a client that keeps talking cannot
    // grow the replication backlog until the follower is dropped for it.
    bool is_follower{false};
    bool follower_refused{false};

    // === TLS session ===
    // Non-null only on a listener created with --tls.  The design is the
    // server runtime's, deliberately unchanged: OpenSSL never sees this
    // socket, the session is fed ciphertext a read completion delivered and
    // drained of ciphertext a write submission carries, and every byte is
    // copied into or out of a buffer this struct owns before an SQE is built.
    // Nothing the kernel holds ever names the SSL or its memory BIOs.
    //
    // Who may free this: this struct, and nothing else.  pool_release() on the
    // way back to the pool, reset() as a second line of defence for a struct
    // coming back out, and ~client_connection for one that reaches neither
    // because it was retired with a completion still outstanding and the
    // runtime went away before it landed.  Because no completion can name the
    // session, freeing it never has to wait on the ring — unlike write_batch.
    SSL* ssl{nullptr};
    tls_conn_state tls_state{tls_conn_none};
    // The peer's close_notify, remembered rather than acted on.  The read that
    // carries it can carry the last command ahead of it, and marking the
    // connection closing before that command is parsed answers it with a
    // dropped connection; handle_read applies this once the parse is done.
    bool tls_peer_closed{false};

    // What this struct owns that no container releases for it.  Reached by a
    // connection that was retired — the ring still owed it a completion — and
    // whose completion was dropped rather than delivered because the runtime
    // stopped first, so absorb_retired() never ran.  Safe here for the same
    // reason it is safe anywhere: no submission ever named the session.
    ~client_connection()
    {
        tls_context::free_ssl(ssl);
    }

    client_connection() = default;
    client_connection(const client_connection&) = delete;
    client_connection& operator=(const client_connection&) = delete;

    // Rate limiting (token bucket)
    double rl_tokens{0.0};
    double rl_max{0.0};
    std::chrono::steady_clock::time_point rl_last{};

    // Idle connection tracking
    std::chrono::steady_clock::time_point last_activity{};

    SKL_TRACE_FIELD(tr)

    void reset(int new_fd)
    {
        fd = new_fd;
        fixed_idx = -1;
        direct_fd = false;
        partial.clear();
        response_buf.clear();
        write_queue.clear();
        for (uint32_t i = 0; i < write_batch_count; i++) write_batch[i].clear();
        write_batch_count = 0;
        read_pending = false;
        write_pending = false;
        closing = false;
        zc_notif_pending = false;
        resp_mode = false;
        resp_detected = false;
        is_follower = false;
        follower_refused = false;
        // pool_release() already did this; repeated here because a struct
        // leaving the pool must not carry the previous connection's session
        // under any circumstances, and this is the last point at which that
        // can still be true.
        tls_context::free_ssl(ssl);
        ssl = nullptr;
        tls_state = tls_conn_none;
        tls_peer_closed = false;
        rl_tokens = 0.0;
        rl_max = 0.0;
        SKL_TRACE_RESET(*this);
    }
};

enum cache_mode : uint8_t
{
    cache_mode_readonly  = 0,  // GET, SIZE
    cache_mode_readwrite = 1,  // GET, SET, DEL, SIZE (default)
    cache_mode_admin     = 2   // all incl. FLUSH, LOAD
};

class cache_instance : public runtime_instance, public request_sink
{
public:
    cache_instance(std::string_view name);
    ~cache_instance() override;

    void set_persistent(std::string_view path);
    std::string_view get_persistent() const;

    void set_mode(cache_mode mode);
    cache_mode get_mode() const;

    void on_cqe(struct io_uring_cqe* cqe) override;
    bool setup(event_loop& loop) override;
    void teardown(event_loop& loop) override;

    size_t get_connection_count() const override;

    // Lua cache access — strings
    std::string lua_get(std::string_view key);
    bool lua_set(std::string_view key, std::string_view value);
    bool lua_del(std::string_view key);

    // Lua cache access — lists
    bool lua_lpush(std::string_view key, std::string_view val);
    bool lua_rpush(std::string_view key, std::string_view val);
    std::string lua_lpop(std::string_view key);
    std::string lua_rpop(std::string_view key);
    int lua_llen(std::string_view key);
#ifndef SOCKETLEY_NO_LUA
    sol::table lua_lrange(std::string_view key, int start, int stop);
#endif

    // Lua cache access — sets
    int lua_sadd(std::string_view key, std::string_view member);
    bool lua_srem(std::string_view key, std::string_view member);
    bool lua_sismember(std::string_view key, std::string_view member);
    int lua_scard(std::string_view key);
#ifndef SOCKETLEY_NO_LUA
    sol::table lua_smembers(std::string_view key);
#endif

    // Lua cache access — hashes
    bool lua_hset(std::string_view key, std::string_view field, std::string_view val);
    std::string lua_hget(std::string_view key, std::string_view field);
    bool lua_hdel(std::string_view key, std::string_view field);
    int lua_hlen(std::string_view key);
#ifndef SOCKETLEY_NO_LUA
    sol::table lua_hgetall(std::string_view key);
#endif

    // Lua cache access — TTL
    bool lua_expire(std::string_view key, int seconds);
    int64_t lua_ttl(std::string_view key);
    bool lua_persist(std::string_view key);

    // Virtual overrides for Lua API
    std::string lua_cache_get(std::string_view key) override { return lua_get(key); }
    bool lua_cache_set(std::string_view key, std::string_view value) override { return lua_set(key, value); }
    bool lua_cache_del(std::string_view key) override { return lua_del(key); }
    bool lua_cache_lpush(std::string_view key, std::string_view val) override { return lua_lpush(key, val); }
    bool lua_cache_rpush(std::string_view key, std::string_view val) override { return lua_rpush(key, val); }
    std::string lua_cache_lpop(std::string_view key) override { return lua_lpop(key); }
    std::string lua_cache_rpop(std::string_view key) override { return lua_rpop(key); }
    int lua_cache_llen(std::string_view key) override { return lua_llen(key); }
    int lua_cache_sadd(std::string_view key, std::string_view member) override { return lua_sadd(key, member); }
    bool lua_cache_srem(std::string_view key, std::string_view member) override { return lua_srem(key, member); }
    bool lua_cache_sismember(std::string_view key, std::string_view member) override { return lua_sismember(key, member); }
    int lua_cache_scard(std::string_view key) override { return lua_scard(key); }
    bool lua_cache_hset(std::string_view key, std::string_view field, std::string_view val) override { return lua_hset(key, field, val); }
    std::string lua_cache_hget(std::string_view key, std::string_view field) override { return lua_hget(key, field); }
    bool lua_cache_hdel(std::string_view key, std::string_view field) override { return lua_hdel(key, field); }
    int lua_cache_hlen(std::string_view key) override { return lua_hlen(key); }
    bool lua_cache_expire(std::string_view key, int seconds) override { return lua_expire(key, seconds); }
    int64_t lua_cache_ttl(std::string_view key) override { return lua_ttl(key); }
    bool lua_cache_persist(std::string_view key) override { return lua_persist(key); }
    int lua_cache_publish(std::string_view channel, std::string_view message) override { return publish(channel, message); }

    // Interactive mode: execute a command and return response
    std::string execute(std::string_view line);

    // ── request_sink ────────────────────────────────────────────────────────
    // Answer a command that reached this cache from another runtime.  Same
    // interpreter as a socket client's, deliberately: a request that arrives
    // over the channel and the same request typed at the cache's own port have
    // to mean the same thing, mode checks and replication included.
    //
    // The caller is the request channel, never the runtime that asked — this
    // runs inside a completion the channel owns, so nothing here is on anybody
    // else's message path.  See shared/request_channel.h.
    void serve_request(std::string_view payload, std::string& out) override;
    // The same interpreter over a payload that is exactly one command, newlines
    // included.  A replication frame is framed BECAUSE the command contains a
    // newline, so running it through the line splitter would apply half of it —
    // which is the truncation the framing exists to stop.
    void serve_one_command(std::string_view line, std::string& out);
    // Shared body of the two above; `split` picks which one it is.
    void serve_payload(std::string_view payload, std::string& out, bool split);
    // Itself when it is here, and the daemon's override when it is not: the
    // placeholder for an out-of-process cache has an empty store, so answering
    // from it would be confidently wrong rather than merely absent.
    request_sink* as_request_sink() override
    {
        if (auto* o = runtime_instance::as_request_sink())
            return o;
        return this;
    }

    // Maxmemory / Eviction
    void set_max_memory(size_t bytes);
    size_t get_max_memory() const;
    void set_eviction(eviction_policy policy);
    eviction_policy get_eviction() const;

    // RESP mode
    void set_resp_forced(bool enabled);
    bool get_resp_forced() const;

    // Pub/Sub
    int publish(std::string_view channel, std::string_view message);

    // Replication
    enum repl_role : uint8_t { repl_none = 0, repl_leader = 1, repl_follower = 2 };
    void set_replicate_target(std::string_view host_port);
    std::string_view get_replicate_target() const;
    repl_role get_repl_role() const;

    // What the TLS gate asks this role for.  A cache that terminates TLS on
    // its listener and replicates out of it in cleartext is refused, at create
    // and at every start; see tls_config_refusal.
    std::string_view get_replication_target() const override { return m_replicate_target; }

    // Stats
    std::string get_stats() const override;
    uint64_t m_stat_commands{0};
    uint64_t m_stat_get_hits{0};
    uint64_t m_stat_get_misses{0};
    uint64_t m_stat_keys_expired{0};

    // Cache management (for cmd_action)
    uint32_t get_size() const;
    size_t store_memory_used() const;
    bool flush_to(std::string_view path);
    bool load_from(std::string_view path);

private:
    void handle_accept(struct io_uring_cqe* cqe);
    void handle_read(struct io_uring_cqe* cqe, io_request* req);
    void handle_write(struct io_uring_cqe* cqe, io_request* req);

#ifdef SOCKETLEY_INVARIANTS
    // Debug-only: see invariants.h.  Asserts that a connection the runtime still
    // has indexed still has something that will wake it.
    void inv_check_reachable(int fd, const char* where);
#endif

    void process_command(client_connection* conn, std::string_view line);
    // Run every line of a request payload through process_command, in order.
    // See serve_request() for why a payload is a stream and not a command.
    void run_request_lines(client_connection* conn, std::string_view payload);
    void process_resp(client_connection* conn);
    void process_resp_command(client_connection* conn, std::string_view* args, int argc);

    // Both report whether the submission reached the ring; see the definitions
    // for why a caller must not ignore that.
    bool flush_responses(client_connection* conn);
    bool flush_write_queue(client_connection* conn);

    // ── TLS record layer ────────────────────────────────────────────────────
    // OpenSSL does no I/O here.  These two move bytes between a connection's
    // memory BIO pair and the io_uring submissions that carry every other byte
    // in the daemon, which is what makes the handshake asynchronous: one call
    // per completion, several completions per handshake, nothing blocking and
    // nothing spinning.
    //
    // Ciphertext a read delivered → SSL → plaintext in conn->partial, where
    // RESP detection and the line parser already look for it.  A close_notify
    // lands in tls_peer_closed instead of closing here, so the command it
    // arrived with still gets an answer.
    void tls_feed(client_connection* conn, const char* data, size_t len);

    // Queued plaintext → SSL → one write submission of ciphertext, and the
    // only way a byte leaves a TLS connection.  Same contract as the two
    // flushes above: false means nothing reached the ring and no completion is
    // owed.  True with nothing submitted is legitimate and common — a
    // handshake still running, or a write already in flight.
    bool tls_flush(client_connection* conn);

    // Whether this connection still owes the wire anything.  On a TLS
    // connection the write queue is only half the answer — a handshake flight,
    // an alert or a session ticket is output with an empty queue, and asking
    // only about the queue is how a handshake stalls one round short.
    bool conn_has_output(const client_connection* conn) const;

    // A TLS connection that is closing, owes the wire nothing more, and is
    // waiting on nothing but its own read.
    //
    // The cleartext paths close such a connection the moment they mark it,
    // because they have nothing left to send.  A session does: the alert that
    // says why a handshake failed is the only diagnosis the peer will ever
    // get, so the close waits for that write to land — and by then the read is
    // the one operation still outstanding.  Nothing is going to complete it.
    // The peer here is the one being refused; it is sitting on an open socket
    // waiting for an answer that is never coming, and a multishot recv stays
    // armed until the socket itself moves.  That is a client that hangs
    // instead of being refused, which is the opposite of failing closed.
    //
    // shutdown() makes the read complete now, and the ordinary teardown runs
    // from that completion — where freeing the struct is safe, and where every
    // other close in this runtime already happens.
    void tls_close_when_read_is_all(client_connection* conn, int fd);

    // Arm the read that fits the configured mode.  Returns false when nothing
    // reached the ring, with read_pending left clear so no one waits on it.
    bool submit_client_read(client_connection* conn, int fd);

    // Re-arm the listener, falling back to the backoff timer when the
    // submission does not reach the ring.  Without that the cache stops taking
    // connections silently — there is no completion left to report it.
    void rearm_accept();
    void schedule_accept_backoff();

    // ─── Retired I/O ───────────────────────────────────────────────────────
    //
    // One rule, applied everywhere: nothing io_uring may still be reading from
    // or writing into is freed, reused or re-armed.  It is retired instead —
    // moved out of the running state into m_retired, which owns the memory and
    // leaves the io_requests inside it pointing at this instance, so the
    // completion that is still owed lands in absorb_retired() instead of on
    // whatever has taken the object's place.
    //
    // A stop/start cycle used to get this wrong in half a dozen places at once.
    // teardown() deliberately kept connections, followers and timers alive
    // because the kernel still held their addresses, and then setup() freed
    // them or armed a second operation on the very same request — a completion
    // arriving in that gap was dispatched through a pointer into memory that
    // had already been handed to somebody else.
    struct retired_op
    {
        // Released as soon as the last request below has completed; anything
        // that never completes is held until the instance itself is destroyed,
        // which the manager already delays past the last completion.
        std::shared_ptr<void> storage;
        io_request* waiting[4]{};
        uint8_t count{0};
    };
    std::vector<retired_op> m_retired;
    // The loop stays reachable after m_loop is cleared: a retired read may
    // still be holding a provided buffer that has to go back to the ring.
    event_loop* m_retired_loop{nullptr};

    // Every descriptor this runtime gives back to the kernel goes through here.
    // A close does not withdraw an SQE that already carries the number; it only
    // frees the number for the next accept, and the queued operation then lands
    // on that connection instead.  See event_loop::close_fd, which holds the
    // number until nothing in the ring still names it.
    //
    // m_retired_loop and not m_loop, for the same reason retire() uses it:
    // descriptors are still closed after teardown has cleared m_loop, and that
    // is exactly when the ring is most likely to be holding something.
    void close_tracked(int fd);

    // Retire `storage`, waiting for the `count` requests in `owed` whose
    // completions the ring still owes us.  With nothing owed the object is
    // released here and now.
    void retire(std::shared_ptr<void> storage, io_request* const* owed, size_t count);
    // Consume a completion that belongs to a retired object.  True means the
    // request was one of those, and the caller must not look at it again.
    bool absorb_retired(io_request* req, struct io_uring_cqe* cqe);

    // A timeout and the request that carries it, allocated per run.
    //
    // io_uring keeps both addresses for the life of the operation, and an
    // interval timer is nearly always in flight when a runtime stops — the TTL
    // sweep fires twice a second.  Timeouts are not attached to an fd either,
    // so no shutdown() or cancel reaches them.  Re-arming the same request on
    // restart therefore leaves two self-perpetuating chains driving one piece
    // of state; a fresh object per run keeps the old completion recognisable.
    struct timer_op
    {
        io_request req{};
        struct __kernel_timespec ts{};
    };

    // The accept request together with the address the kernel fills in through
    // it.  Same reasoning as timer_op: a stale accept completion landing on a
    // re-armed request arms the listener twice.
    struct accept_op
    {
        io_request req{};
        struct sockaddr_in addr{};
        socklen_t addrlen{sizeof(struct sockaddr_in)};
    };

    int m_listen_fd;
    std::unique_ptr<accept_op> m_accept;
    bool m_multishot_active{false};

    // The listener's TLS context, or null when this cache serves cleartext.
    // Rebuilt on every start rather than kept: `reload` is a stop followed by
    // a start, and it is how an operator installs a renewed certificate.
    // Sessions handed out by the previous context hold their own reference and
    // are unaffected.
    std::unique_ptr<tls_context> m_tls;

    cache_store m_store;
    std::unordered_map<int, std::unique_ptr<client_connection>> m_clients;

    // O(1) fd→connection lookup (avoids hash map on every CQE)
    static constexpr int MAX_FDS = 8192;
    client_connection* m_conn_idx[MAX_FDS]{};

    event_loop* m_loop;

    // EMFILE/ENFILE accept backoff
    std::unique_ptr<timer_op> m_accept_backoff_timer;

    // Idle connection sweep timer
    std::unique_ptr<timer_op> m_idle_sweep_timer;

    std::string m_persistent_path;
    cache_mode m_mode = cache_mode_readwrite;
    bool m_resp_forced{false};

    // Replication
    std::string m_replicate_target;
    repl_role m_repl_role{repl_none};

    // A follower socket plus whatever has not reached it yet.
    //
    // Replication output cannot be written synchronously.  A follower may live
    // in the same daemon as its leader, sharing this event loop, so blocking
    // until the socket drains deadlocks: the follower cannot read while the loop
    // is stuck inside the leader's write.  Everything therefore goes through an
    // io_uring write and the unsent tail waits here.
    //
    // Keeping the tail also protects the command stream.  A short write would
    // otherwise splice two commands together, which the follower has no way to
    // detect.
    //
    // This buffer is the *only* writer on the descriptor once the promotion has
    // happened — the acknowledgement, the dump and every replicated command
    // leave through it, in that order.  The client_connection the socket came
    // from stops answering commands at the same moment, because two writers on
    // one socket cannot be ordered against each other; see
    // handle_replicate_request() and client_connection::is_follower.
    struct follower_conn
    {
        // Borrowed, never owned.  A follower reaches the leader as an ordinary
        // client, so this descriptor belongs to that client_connection and is
        // closed by close_client() alone.  Closing it here as well handed the
        // number back to the kernel twice; worse, keeping it after the client
        // had gone meant the next accepted connection inherited it and received
        // the replication stream — dataset dump included — while the writes
        // succeeded, so the follower was never even noticed as gone.
        // close_client() sets this back to -1 as it goes.
        int fd{-1};
        // Two buffers, because the kernel reads directly out of `out` for the
        // duration of a write.  Appending to it meanwhile can reallocate the
        // string and leave the operation pointing at freed memory, so anything
        // produced while a write is in flight waits in `queued` and moves over
        // once `out` has drained.
        std::string out;            // kernel owns out[0..in_flight) while writing
        std::string queued;         // produced since the current write started
        size_t in_flight{0};
        io_request write_req{};
        bool write_pending{false};
        bool dead{false};

        size_t backlog() const { return out.size() + queued.size(); }
    };
    // Cap on buffered-but-unsent replication data per follower.  A follower that
    // falls this far behind is dropped: an explicit disconnect is recoverable,
    // an unbounded buffer or a corrupted command stream is not.
    static constexpr size_t MAX_FOLLOWER_PENDING = 8 * 1024 * 1024;

    // unique_ptr because the kernel holds a pointer to each write_req for the
    // lifetime of its operation; vector growth would move the elements.
    std::vector<std::unique_ptr<follower_conn>> m_followers;

    // The link to the leader, allocated per connect.
    //
    // The read armed on it is not cancelled by closing the socket — the
    // operation holds its own reference to the file and completes on its own
    // terms — so neither the request nor the buffer may be handed to the next
    // link.  Reconnecting usually lands on the same fd number, and two reads
    // into one buffer produce a replication stream with holes in it.
    struct master_link
    {
        io_request read_req{};
        char buf[4096]{};
        std::string partial;
        int fd{-1};
        bool read_pending{false};
    };
    std::unique_ptr<master_link> m_master;

    // Start a write if nothing is in flight, moving queued data into out.
    void follower_kick(follower_conn& f);
    // Queue data for a follower and start writing if nothing is in flight.
    // Returns false when the follower must be dropped.
    bool follower_write(follower_conn& f, std::string_view data);
    // Continue or finish a follower write after its completion arrives.
    void handle_follower_write(struct io_uring_cqe* cqe, follower_conn& f);
    // Drop followers marked dead and ask their client connections to close.
    void reap_followers();
    // Give up the follower that was promoted from this descriptor, if any.
    // Called from close_client(), which is the only owner of the socket.
    void detach_follower(int fd);

    // The follower promoted from this descriptor, or nullptr.
    follower_conn* follower_for_fd(int fd);

    // Drop input that arrived on a socket that is now a replication follower,
    // and tell the client once — through the replication stream, because that
    // buffer is the socket's only writer.
    void refuse_follower_input(client_connection* conn);

    void replicate_command(std::string_view cmd);
    void handle_replicate_request(client_connection* conn);
    bool send_full_dump(follower_conn& f);
    bool connect_to_master();
    void handle_master_read(struct io_uring_cqe* cqe);

    // Provided buffer ring
    static constexpr uint16_t BUF_GROUP_ID = 3;
    static constexpr uint32_t BUF_COUNT = 512;
    static constexpr uint32_t BUF_SIZE = 4096;
    bool m_use_provided_bufs{false};
    bool m_recv_multishot{false};
    bool m_send_zc{false};

    // Periodic TTL sweep timer
    std::unique_ptr<timer_op> m_ttl_timer;

    // Cached config values (read once in setup, avoid virtual calls on hot path)
    uint32_t m_idle_timeout_cached{0};
    uint32_t m_max_conns_cached{0};
    double m_rate_limit_cached{0.0};

    // TTL sweep short-circuit: skip m_expiry scan when no TTL keys exist
    bool m_has_ttl_keys{false};

    // Whether a TTL sweep timeout is currently outstanding.
    //
    // The sweep used to rearm itself unconditionally, so every cache runtime
    // kept submitting an SQE ten times a second whether or not a single key had
    // an expiry.  With io_uring in SQPOLL mode that is enough to keep the kernel
    // poller from ever reaching its idle timeout, which costs a full core at
    // zero traffic.  The timer now stops when there is nothing to expire and is
    // restarted by mark_ttl_keys() when a TTL first appears.
    bool m_ttl_timer_armed{false};

    // Submit the sweep timeout unless one is already pending.
    void arm_ttl_timer();

    // Record that at least one key now carries an expiry, restarting the sweep
    // if it had stopped.  Use this instead of assigning m_has_ttl_keys directly:
    // setting the flag without arming the timer leaves expired keys to be
    // reclaimed only when something happens to touch them.
    void mark_ttl_keys();

    // The connection serve_request() and execute() answer through.
    //
    // A client_connection carries a 4 KB read buffer and half a dozen strings,
    // and both of those entry points used to build one on the stack per call.
    // That was fine while the only caller was an interactive CLI command; the
    // server's `--cache` auto-store now comes through here once per message, so
    // the object is made once and reset instead.  m_serving is the re-entrancy
    // guard: a command that publishes reaches Lua, and Lua can ask this cache
    // another question from inside the first one, which would otherwise write
    // two answers into one buffer.
    std::unique_ptr<client_connection> m_request_conn;
    bool m_serving{false};

    // Connection struct pool — reuse allocations to avoid malloc/free per connect/disconnect
    static constexpr size_t CONN_POOL_INIT = 32;
    std::vector<std::unique_ptr<client_connection>> m_conn_pool;
    std::unique_ptr<client_connection> pool_acquire(int fd);
    // Hand a connection back for reuse — or retire it, when the ring still owes
    // it a completion.  The pool gives structs straight to the next accepted
    // connection, so this is the one place that has to decide, and every close
    // path goes through it.
    void pool_release(std::unique_ptr<client_connection> conn);

    // Full teardown of a client connection.  Every close path must go through
    // this rather than open-coding the steps: dropping the fd without clearing
    // its subscriptions leaves it in the store's channel map forever, and the
    // next connection that happens to get the same fd number inherits the dead
    // client's channels.
    void close_client(client_connection* conn, int fd, const char* reason);

    // The one place a connection nothing is going to finish is finished.
    // Called from on_cqe() after every completion, for the connection that
    // completion named; see the call site for the reasoning and for why an
    // armed read does not count as something that will finish it.
    void finish_unreachable_client(int fd);

    // The same flags, sorted by who is obliged to report them.  See
    // shared/conn_reachability.h; this function is the seam between that
    // classification and this runtime's connection struct.
    socketley::reach::owed conn_owed(const client_connection* conn) const;
};
