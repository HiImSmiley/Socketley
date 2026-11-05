#pragma once
#include "../../shared/loop/fd_table.h"
#include "../../shared/net/async_resolver.h"
#include "../../shared/net/conn_reachability.h"
#include <initializer_list>
#include <string>
#include <string_view>
#include <vector>
#include <unordered_set>
#include <chrono>
#include <list>
#include <unordered_map>
#include <memory>
#include <queue>
#include <netinet/in.h>
#include <sys/uio.h>
#include <sys/socket.h>

#include "../../shared/runtime/runtime_instance.h"
#include "../../shared/runtime/latency_histogram.h"
#include "../../shared/loop/event_loop_definitions.h"
#include "../../shared/ipc/request_channel.h"

#include <deque>
#include "../../shared/ipc/cache_shard_map.h"
#include "cache_store.h"
#include "cache_script.h"
#include "../../shared/persist/mutation_journal.h"
#include "../../shared/util/trace.h"
#include "../../shared/loop/write_queue.h"
#include "../../shared/net/direct_send.h"
#include "../../shared/crypto/tls_context.h"
#include "../../shared/net/unix_companion.h"
#include "../../shared/cluster/replica_role.h"

struct client_connection
{
    static constexpr size_t MAX_WRITE_BATCH = 16;
    // Upper size for merging consecutive responses into one queue entry, large
    // enough that thousands of small replies share a handful and small enough
    // that one entry stays a reasonable write.
    static constexpr size_t WRITE_COALESCE_LIMIT = 64 * 1024;
    static constexpr size_t MAX_PARTIAL_SIZE = 1 * 1024 * 1024;

    // How long a command may be half-arrived.  Not a flat figure: a client
    // writing a large value over a slow link is legitimate and a flat deadline
    // would cut it, while a peer dribbling to hold a slot delivers nothing and
    // must not be given the same patience.  So the allowance grows with what
    // has actually been delivered --
    //
    //     allowed = PARTIAL_BASE_SECS + partial.size() / PARTIAL_FLOOR_BPS
    //
    // which is a floor on the rate, expressed as time.  A client sustaining
    // the floor always has PARTIAL_BASE_SECS of slack; one below it falls
    // behind its own allowance and is dropped; one sending nothing gets the
    // base and no more.  10 KiB/s is about 82 kbit/s, which is far under
    // anything a real client runs on.
    //
    // Measured before this existed: two peers holding a half-command against
    // --max-connections 2 refused every real client and were never reclaimed.
    static constexpr uint32_t PARTIAL_BASE_SECS  = 10;
    static constexpr size_t   PARTIAL_FLOOR_BPS  = 10 * 1024;

    int fd{-1};
    int fixed_idx{-1};
    bool direct_fd{false};
    io_request read_req;
    io_request write_req;

    // The last resort, and only that.  A read is armed as a bundle, then as
    // plain multishot, then as a provided-buffer read, and only if the buffer
    // ring does not exist at all does anything land here -- so with a ring, and
    // that is every start that gets one, these four kilobytes were carried per
    // connection and never written to.  Measured: an idle connection cost 8.2
    // to 14.1 KB against Redis's 1.3, and this was the largest single piece of
    // it.  Held rather than freed once taken, so no read can ever be armed on
    // storage that has gone.
    static constexpr size_t   READ_BUF_BYTES = 4096;
    std::unique_ptr<char[]>   read_buf;
    std::string partial;
    // What the read being taken in brought, which read_overflows() allows on top of the bound.
    uint32_t read_arrived{0};
    // How much of `partial` the text protocol has searched for a newline and not found, so a long line is not
    // searched again from its start on every read; it holds only while `partial` is that long.
    size_t text_searched{0};
    std::string response_buf;
    // Owned replies, and slices of a published message's segment.
    socketley::byte_counted_queue<socketley::write_chunk> write_queue;

    std::string write_batch[MAX_WRITE_BATCH];
    // What keeps a published message's segment alive while the kernel sends a
    // slice of it, beside write_batch rather than in it, because every entry
    // of a batch array is paid by every connection, idle or not.
    std::shared_ptr<const std::string> write_batch_seg[MAX_WRITE_BATCH];
    struct iovec write_iovs[MAX_WRITE_BATCH];
    struct msghdr write_msg{};
    uint32_t write_batch_count{0};

    bool read_pending{false};
    bool write_pending{false};
    bool closing{false};

    // Which listener this connection came in on, recorded at accept, because a
    // client that chose this shard's own port has read CLUSTER SLOTS and a key
    // that is not ours is a routing mistake to report with -MOVED rather than
    // a crossing to run.
    bool cluster_port{false};

    // ── MULTI ───────────────────────────────────────────────────────────────
    // A transaction is a queue on the connection and nothing more: commands
    // are stored verbatim between MULTI and EXEC and run back to back on the
    // event loop, which is single-threaded, so nothing can interleave with
    // them.  What this is not is a rollback -- EXEC runs what it queued, and a
    // command that fails there fails alone, the way Redis has it.
    bool                     in_multi{false};
    // A command refused while queueing poisons the transaction, because
    // running the rest of it would be running something the caller did not
    // ask for.
    bool                     multi_broken{false};
    std::vector<std::string> multi_queue;
    size_t                   multi_bytes{0};
    // Set only while EXEC replays what it queued, or a script runs.  in_multi
    // is already false by then -- EXEC clears it before the loop -- so a
    // command that must answer at once, as a blocking pop must, has nothing
    // else to read.
    bool                     in_exec{false};
    // Enough for a batch worth queueing and small enough that a client cannot
    // park unbounded memory on a connection by never sending EXEC.
    static constexpr size_t  MULTI_MAX_BYTES = 8u << 20;
    static constexpr size_t  MULTI_MAX_CMDS  = 100000;

    // The crossings this connection is waiting on, oldest first, because a
    // client pipelining down one socket can only tell replies apart by order
    // -- ids and not pointers, since the struct may be pooled by the time a
    // reply lands.
    std::vector<uint64_t> batches;
    // The turn stamp of the first read whose replies are owed, 0 once they are out.
    uint64_t batch_ns{0};

    // What those crossings carried and have not answered, which is the one
    // thing that stops this connection being read.
    size_t crossing_bytes{0};

    // The read was withdrawn because crossing_bytes reached
    // read_buffer_bytes(), and comes back as the crossings are answered.
    bool read_paused{false};

    // The peer sent its FIN while a crossing was still owed, so the close is
    // held rather than taken, because a crossing is answered on a later turn
    // and closing would throw away an answer the client is reading.
    bool peer_gone{false};

    // The answer that ends a closing connection has left and its FIN with it,
    // and what the client is still sending is read and discarded until its own
    // EOF, so the close does not reset the answer out of its receive queue.
    bool wr_shutdown{false};
    size_t drained_bytes{0};

    // RESP protocol mode (auto-detected or forced)
    bool resp_mode{false};
    bool resp_detected{false};  // true once first byte examined

    // Set by REPLICATE, after which this socket carries the replication stream
    // and nothing else, with the refusal kept to one line per connection.
    bool is_follower{false};
    bool follower_refused{false};

    // The keys this connection asked WATCH about, and whether any of them has
    // been written since.  Kept on the connection so a disconnect takes them
    // with it, and named in m_watchers so a write can find the watcher.
    // QUIT is answered and THEN closed, in that order: a connection marked
    // closing has its response buffer dropped, so setting it here would throw
    // the +OK away -- the same shape that silenced every protocol error.
    bool                     quit_after_flush{false};
    std::vector<std::string> watched;
    bool watch_dirty{false};

    // Channels plus patterns this connection holds, which is the number Redis
    // puts in every subscribe confirmation -- a client counts down from it to
    // know when its own subscribe batch is complete.
    uint32_t sub_count{0};

    // Waiting on BLPOP or BRPOP, which is the one command here that answers on
    // a later turn than the one it arrived on.  Everything already pipelined
    // behind it stays in `partial` until the wait ends, or the second reply
    // would overtake the first.
    bool blocked{false};

    // ── SOCKETLEY_CACHE_HANDOFF ─────────────────────────────────────────────
    // Where this connection is in being given to the shard that owns its keys: its read being withdrawn, waiting
    // for the link's writer to drain, or sent and waiting for the sibling's answer.
    enum class handoff : uint8_t { none, withdrawing, waiting, sent };
    handoff  ho_state{handoff::none};
    // The last window of single-key commands named ho_target often enough, which the next quiet moment acts on.
    bool     ho_want{false};
    // Accepted off a unix socket, which is not handed on.
    bool     unix_peer{false};
    uint8_t  ho_hops{0};
    uint8_t  ho_tries{0};
    uint8_t  ho_win_n{0};
    uint8_t  ho_win_hits{0};
    uint32_t ho_cand{0};
    uint32_t ho_target{0};
    uint64_t ho_id{0};
    // Not handed on before this, which a move and a failed attempt both push out.
    uint64_t ho_not_before_ns{0};

    // Non-null only with --tls, on the server runtime's design deliberately
    // unchanged, and freed only by this struct -- which is what makes freeing
    // it never have to wait on the ring.
    SSL* ssl{nullptr};
    tls_conn_state tls_state{tls_conn_none};
    // The peer's close_notify, remembered rather than acted on, because the
    // read that carries it can carry the last command ahead of it.
    bool tls_peer_closed{false};
    // When the handshake began, which the deadline reads instead of
    // last_activity.  last_activity is refreshed on every read -- but only when
    // --idle-timeout is set, so the deadline silently changed meaning with a
    // flag that has nothing to do with it: measured, a peer dribbling one byte
    // every twenty seconds inside an unfinished record held its slot for ever
    // WITH --idle-timeout and lost it in 63 seconds without.  Flat, like the
    // client's, because a handshake is bounded by round trips and not by data.
    std::chrono::steady_clock::time_point handshake_since{};
    // When the bytes now sitting in `partial` stopped becoming commands.
    // Unset while nothing is half-arrived; dated from the first read that left
    // a remainder and re-dated whenever a command completes, because a client
    // pipelining steadily never empties this buffer and is making progress the
    // whole time.
    std::chrono::steady_clock::time_point partial_since{};


    // What this struct owns that no container releases for it, reached by a
    // retired connection whose completion was dropped when the runtime stopped
    // first.
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
        // A slot comes back from the pool for a new peer, and a clock left
        // running belongs to the last one.
        partial_since = {};
        partial.clear();
        response_buf.clear();
        write_queue.clear();
        for (uint32_t i = 0; i < write_batch_count; i++) write_batch[i].clear();
        write_batch_count = 0;
        read_pending = false;
        write_pending = false;
        closing = false;
        cluster_port = false;
        in_multi = false;
        in_exec = false;
        multi_broken = false;
        multi_queue.clear();
        multi_bytes = 0;
        batches.clear();
        crossing_bytes = 0;
        read_paused = false;
        peer_gone = false;
        wr_shutdown = false;
        drained_bytes = 0;
        resp_mode = false;
        resp_detected = false;
        is_follower = false;
        follower_refused = false;
        blocked = false;
        quit_after_flush = false;
        watched.clear();
        watch_dirty = false;
        sub_count = 0;
        ho_state = handoff::none;
        ho_want = false;
        unix_peer = false;
        ho_hops = 0;
        ho_tries = 0;
        ho_win_n = 0;
        ho_win_hits = 0;
        ho_cand = 0;
        ho_target = 0;
        ho_id = 0;
        ho_not_before_ns = 0;
        // pool_release() already did this, repeated because a struct leaving
        // the pool must not carry the previous connection's session.
        tls_context::free_ssl(ssl);
        ssl = nullptr;
        tls_state = tls_conn_none;
        tls_peer_closed = false;
        rl_tokens = 0.0;
        rl_max = 0.0;
        SKL_TRACE_RESET(*this);
    }
};

// The port a cache listens on when none was configured.  Named once because
// setup() and listen_addresses() have to answer with the same number, and the
// per-shard cluster ports are counted up from it in both.
inline constexpr uint16_t cache_default_port = 9000;

enum cache_mode : uint8_t
{
    cache_mode_readonly  = 0,  // GET, SIZE
    cache_mode_readwrite = 1,  // GET, SET, DEL, SIZE (default)
    cache_mode_admin     = 2   // all incl. FLUSH, LOAD
};

class cache_instance : public runtime_instance, public request_sink,
                      public request_origin
{
public:
    cache_instance(std::string_view name);
    ~cache_instance() override;

    void set_persistent(std::string_view path);
    std::string_view get_persistent() const;

    // Seconds between journal flushes, 0 meaning no journal at all, which is
    // exactly what every cache before this flag existed had.
    void set_persist_interval(uint32_t seconds);
    uint32_t get_persist_interval() const;

    void set_mode(cache_mode mode);
    cache_mode get_mode() const;

    // A replica of a cluster cache, which is what `--cluster-replica <incarnation>` makes: the process is that incarnation,
    // starts fenced so it answers no client and takes no `replicate`, and is told what to be by the daemon from then on.
    void set_cluster_replica(uint64_t incarnation) { m_cluster_incarnation = incarnation; }
    uint64_t get_cluster_replica() const { return m_cluster_incarnation; }
    void on_replica_order(std::string_view payload) override;

    void on_cqe(struct io_uring_cqe* cqe) override;
    bool setup(event_loop& loop) override;
    void teardown(event_loop& loop) override;
    void on_loop_turn() override;

    // The three values setup() copies out of the configuration and the hot
    // paths read instead of calling a virtual per accept and per message: the
    // accept guard reads m_max_conns_cached, the idle sweep reads
    // m_idle_timeout_cached, and every accepted connection is seeded from
    // m_rate_limit_cached.
    //
    // Missing, this class cached and never refreshed -- which is the one thing
    // the base class's comment says a caching type must not do: "made every
    // setter a lie for a runtime that was already running ... A type that
    // caches overrides this."  The server and the proxy had it; the cache is
    // the third and had the members without the override, so `edit <cache>
    // --max-connections 1` reached the worker, set the field, was reported by
    // `show`, and the accept path went on enforcing whatever setup() had read.
    void refresh_cached_limits() override
    {
        m_idle_timeout_cached = get_idle_timeout();
        m_max_conns_cached    = get_max_connections();
        m_rate_limit_cached   = get_rate_limit();
        // A client certificate the listener demands is a credential, so mutual
        // TLS opens the cache the way --public does.
        m_admits_remote       = m_public || (get_tls() && !get_ca_path().empty());
    }

    // What setup() will bind, answered without binding it; see the base class.
    void listen_addresses(std::vector<std::string>& out) const override;
    uint16_t effective_port() const override;

    size_t get_connection_count() const override;

    // Lua cache access — strings
    std::string lua_get(std::string_view key);
    bool        lua_exists(std::string_view key);
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
    bool        lua_hexists(std::string_view key, std::string_view field);
    bool lua_hdel(std::string_view key, std::string_view field);
    int lua_hlen(std::string_view key);
#ifndef SOCKETLEY_NO_LUA
    sol::table lua_hgetall(std::string_view key);
#endif

    // Lua cache access — TTL
    bool lua_expire(std::string_view key, int seconds);
    int64_t lua_ttl(std::string_view key);
    bool lua_persist(std::string_view key);

    // self.publish(), which is publish() plus the siblings; see the definition
    // for why the count it returns is this shard's alone.
    int lua_publish(std::string_view channel, std::string_view message);

    // ── the one place the Lua table asks who owns a key ─────────────────────
    // Every other door into the store asks before it touches it, and says so at
    // its own line: process_command() and apply_replicated().  This one did
    // not, and what that cost depends on which callback is running.  on_start
    // and a timer run in ALL N processes, so each wrote the whole keyspace into
    // its own slice and KEYS and DBSIZE reported it N times over; on_miss,
    // on_write and on_delete run in exactly ONE, so a key that shard does not
    // own went into a slice no read routes to.  The rule is the same for both:
    // act on the keys this shard owns and leave the rest to the sibling that
    // owns them.
    //
    // Not a crossing: the answer to self.set() is its return value, and a
    // crossing arrives on a later turn -- see can_cross(), which is why the
    // wire's own path needs a connection to come back to.
    bool lua_owns(std::string_view key) const
    {
        return m_shard_n <= 1 || cache_shard_of(key, m_shard_n) == m_shard_i;
    }

    // Virtual overrides for Lua API
    bool lua_cache_owns(std::string_view key) override { return lua_owns(key); }

    std::string lua_cache_get(std::string_view key) override { return lua_owns(key) ? lua_get(key) : std::string(); }
    bool lua_cache_exists(std::string_view key) override { return lua_owns(key) && lua_exists(key); }
    bool lua_cache_set(std::string_view key, std::string_view value) override { return lua_owns(key) && lua_set(key, value); }
    bool lua_cache_del(std::string_view key) override { return lua_owns(key) && lua_del(key); }
    bool lua_cache_lpush(std::string_view key, std::string_view val) override { return lua_owns(key) && lua_lpush(key, val); }
    bool lua_cache_rpush(std::string_view key, std::string_view val) override { return lua_owns(key) && lua_rpush(key, val); }
    std::string lua_cache_lpop(std::string_view key) override { return lua_owns(key) ? lua_lpop(key) : std::string(); }
    std::string lua_cache_rpop(std::string_view key) override { return lua_owns(key) ? lua_rpop(key) : std::string(); }
    int lua_cache_llen(std::string_view key) override { return lua_owns(key) ? lua_llen(key) : 0; }
    // The same three names the wire protocol, `show` and --mode all use, so a
    // script comparing against "readonly" is comparing against one vocabulary.
    std::string_view lua_cache_mode() const override
    {
        switch (m_mode)
        {
            case cache_mode_readonly:  return "readonly";
            case cache_mode_admin:     return "admin";
            default:                   return "readwrite";
        }
    }

    // A foreign key is -1 and not 0, because -1 is already this call's refusal
    // and 0 would say "the member was there", which no shard checked.
    int lua_cache_sadd(std::string_view key, std::string_view member) override { return lua_owns(key) ? lua_sadd(key, member) : -1; }
    bool lua_cache_srem(std::string_view key, std::string_view member) override { return lua_owns(key) && lua_srem(key, member); }
    bool lua_cache_sismember(std::string_view key, std::string_view member) override { return lua_owns(key) && lua_sismember(key, member); }
    int lua_cache_scard(std::string_view key) override { return lua_owns(key) ? lua_scard(key) : 0; }
    bool lua_cache_hset(std::string_view key, std::string_view field, std::string_view val) override { return lua_owns(key) && lua_hset(key, field, val); }
    std::string lua_cache_hget(std::string_view key, std::string_view field) override { return lua_owns(key) ? lua_hget(key, field) : std::string(); }
    bool lua_cache_hexists(std::string_view key, std::string_view field) override { return lua_owns(key) && lua_hexists(key, field); }
    bool lua_cache_hdel(std::string_view key, std::string_view field) override { return lua_owns(key) && lua_hdel(key, field); }
    int lua_cache_hlen(std::string_view key) override { return lua_owns(key) ? lua_hlen(key) : 0; }
    bool lua_cache_expire(std::string_view key, int seconds) override { return lua_owns(key) && lua_expire(key, seconds); }
    // -2 is the store's own "no such key", which is what a foreign key is here.
    int64_t lua_cache_ttl(std::string_view key) override { return lua_owns(key) ? lua_ttl(key) : -2; }
    bool lua_cache_persist(std::string_view key) override { return lua_owns(key) && lua_persist(key); }
    // publish() is this PROCESS's subscribers plus the cross-runtime half; on
    // more than one shard that is a quarter of the cache's subscribers, so a
    // script's publish takes the road the wire's PUBLISH takes as well.
    int lua_cache_publish(std::string_view channel, std::string_view message) override { return lua_publish(channel, message); }

    // Interactive mode: execute a command and return response
    std::string execute(std::string_view line);

    // ── request_sink ────────────────────────────────────────────────────────
    // Answer a command that reached this cache from another runtime, through
    // the same interpreter a socket client's uses, called by the request
    // channel inside a completion the channel owns.
    void serve_request(std::string_view payload, std::string& out) override;

    // The ticket half: a sharded cache answers a request on a later turn when
    // the key is another shard's, and an unsharded one answers inline exactly
    // as before.
    bool serves_inline() const override { return m_shard_n <= 1; }
    bool serve_deferred(uint64_t ticket, std::string_view target,
                        std::string_view payload) override;

    // ── request_origin ──────────────────────────────────────────────────────
    // The other half of the same channel: a shard asking a sibling for a key
    // it does not own, with the cookie naming the group of commands this reply
    // answers.
    void on_request_reply(uint64_t cookie, request_status st,
                          std::string_view reply) override;
    // The same interpreter over exactly one command, newlines included,
    // because a replication frame is framed precisely when the command
    // contains a newline.
    void serve_one_command(std::string_view line, std::string& out);
    // One command from a leader applied to this shard's slice; see the
    // definition for what a sharded follower may drop.
    void apply_replicated(std::string_view line);
    // Shared body of the two above; `split` picks which one it is.
    void serve_payload(std::string_view payload, std::string& out, bool split);
    // Itself when it is here, and the daemon's override when it is not: the
    // placeholder for an out-of-process cache has an empty store, so answering
    // from it would be confidently wrong rather than merely absent.
    request_sink* as_request_sink() override { return sink_or(this); }

    // Maxmemory / Eviction
    void set_max_memory(size_t bytes);
    size_t get_max_memory() const;
    void set_eviction(eviction_policy policy);
    eviction_policy get_eviction() const;

    // RESP mode
    void set_resp_forced(bool enabled);
    bool get_resp_forced() const;

    // Cluster mode is the default above one shard on a port, and --no-cluster
    // is the way out, because client-side routing gives up an enforcement
    // point: behind a proxy the advertised address either bypasses the
    // proxy's rules or cannot be reached at all.
    void set_cluster(bool enabled);
    bool get_cluster() const;
    void set_no_cluster(bool enabled);
    bool get_no_cluster() const;
    // Whether this cache publishes its per-shard map: --cluster, or the
    // default at more than one shard on a port, unless --no-cluster.
    bool cluster_mode() const;

    // --public: a peer that is not on this machine is served, where by default
    // it is refused, because this cache has no password and answers every
    // client with everything it holds -- so reaching it from the network is
    // something to say, the way Redis's protected mode makes you say it.
    void set_public(bool enabled);
    bool get_public() const;

    // Pub/Sub
    int publish(std::string_view channel, std::string_view message);

    // Replication
    enum repl_role : uint8_t { repl_none = 0, repl_leader = 1, repl_follower = 2 };
    void set_replicate_target(std::string_view host_port);
    std::string_view get_replicate_target() const;
    repl_role get_repl_role() const;

    // What the TLS gate asks this role for, since a cache that terminates TLS
    // and replicates out of it in cleartext is refused at create and at every
    // start.
    std::string_view get_replication_target() const override { return m_replicate_target; }

    // Stats
    std::string stats_lines() const override;
    uint64_t m_stat_commands{0};
    // Commands whose arguments a follower could not have re-split the way this
    // leader meant them -- see the faithfulness check in process_resp_command.
    uint64_t m_repl_unfaithful{0};
    uint64_t m_stat_get_hits{0};
    uint64_t m_stat_get_misses{0};
    uint64_t m_stat_keys_expired{0};
    // A read's commands to their replies handed on, per flush, in loop turns.
    socketley::latency_histogram m_lat_batch;

    // Cache management (for cmd_action)
    uint32_t get_size() const;
    size_t store_memory_used() const;
    bool flush_to(std::string_view path);
    bool load_from(std::string_view path);

private:
    void handle_accept(struct io_uring_cqe* cqe, io_request* req);
    // One accepted descriptor into a connection, from whichever listener
    // handed it over, where false means it was dealt with and is gone.
    bool adopt_client(int client_fd, bool from_cluster, bool from_unix, bool handed = false);

    // ── SOCKETLEY_CACHE_HANDOFF ─────────────────────────────────────────────
    // A window of this many single-key commands, of which this many naming one other shard hand the connection
    // there: 28 of 32 is a chance of about 1 in 100,000 per window for random keys over two shards.
    static constexpr uint8_t  HO_WINDOW = 32;
    static constexpr uint8_t  HO_NEED   = 28;
    // What a handoff carries of what was read and not yet run, past which it waits.
    static constexpr size_t   HO_MAX_BACKLOG = 64 * 1024;
    // Turns a busy link may hold a handoff before it is given up.
    static constexpr uint8_t  HO_MAX_TRIES = 64;
    static constexpr uint64_t HO_SECOND_NS = 1'000'000'000ull;
    bool m_handoff_on{false};
    uint64_t m_ho_next_id{1};
    struct ho_ref { int fd; uint64_t id; uint32_t shard; };
    std::vector<ho_ref> m_ho_waiting;
    std::vector<ho_ref> m_ho_sent;
    uint64_t m_stat_ho_out{0};
    uint64_t m_stat_ho_in{0};
    uint64_t m_stat_ho_aborted{0};
    uint64_t m_stat_ho_busy{0};

    // One single-key command's owner into the connection's window, at the one place each interpreter asks it.
    void note_key_owner(client_connection* c, uint32_t owner)
    {
        if (SOCKETLEY_LIKELY(!m_handoff_on) || c->cluster_port)
            return;
        if (c->ho_win_n == 0)
            c->ho_cand = owner;
        c->ho_win_hits = static_cast<uint8_t>(c->ho_win_hits + (owner == c->ho_cand));
        if (++c->ho_win_n < HO_WINDOW)
            return;
        c->ho_want   = c->ho_win_hits >= HO_NEED && c->ho_cand != m_shard_i;
        c->ho_target = c->ho_cand;
        c->ho_win_n = 0;
        c->ho_win_hits = 0;
    }
    void try_handoff(client_connection* conn, int fd);
    void handoff_read(client_connection* conn, int fd, struct io_uring_cqe* cqe, io_request* req);
    void handoff_send_now(client_connection* conn, int fd);
    void handoff_abort(client_connection* conn, int fd);
    void handoff_turn();
    void serve_buffered(client_connection* conn, int fd);
public:
    bool adopt_handoff(uint32_t from, std::string_view payload, int fd) override;
    void on_handoff_answer(uint32_t shard, uint64_t id, bool taken) override;
private:
    void handle_read(struct io_uring_cqe* cqe, io_request* req);
    void handle_write(struct io_uring_cqe* cqe, io_request* req);

#ifdef SOCKETLEY_INVARIANTS
    // Debug-only: asserts that a connection the runtime still has indexed
    // still has something that will wake it.
    void inv_check_reachable(int fd, const char* where);
#endif

    // The ownership question is asked at the two dispatches and nowhere else,
    // rather than in sixty-odd command handlers, with the `_local` halves the
    // interpreters as they were -- which is what the answering side of a
    // crossing needs.
    void process_command(client_connection* conn, std::string_view line);
    void process_command_local(client_connection* conn, std::string_view line);
    // Run every line of a request payload through process_command in order,
    // because a payload is a stream and not a command.
    void run_request_lines(client_connection* conn, std::string_view payload);
    bool process_resp(client_connection* conn);
    void process_resp_command(client_connection* conn, std::string_view* args, int argc);
    int  first_foreign_key(std::string_view* args, int from, int n, int step) const;
    int  resp_first_foreign_key(uint32_t h, std::string_view* args, int argc) const;
    void process_resp_command_local(client_connection* conn, std::string_view* args, int argc);
    void resp_unsubscribe(client_connection* conn, std::string_view* args, int argc,
                          bool patterns, std::string& rb);
    void resp_pop_count(client_connection* conn, std::string_view* args, int argc,
                        bool left, std::string& rb);
    void resp_spop_count(std::string_view* args, int argc, std::string& rb);
    void resp_srandmember_count(std::string_view* args, int argc, std::string& rb);

    // The text line splitter, lifted out of handle_read so that a connection
    // whose crossing has just come back can be driven from the reply handler
    // with the same code the read handler uses.
    bool parse_text_lines(client_connection* conn);
    // Called once after the parse loop, for both protocols, with what `partial`
    // held before it ran: one place decides whether this connection made
    // progress, rather than each parser reporting it.
    void note_partial_progress(client_connection* conn, size_t before);
    // Creates and arms the sweep chain if it is not already running.  A cache
    // with neither --idle-timeout nor TLS has no timer at all until a client
    // leaves a command half-arrived, so this is on demand rather than at
    // setup(): an idle cache pays for no wakeups it does not need.
    void arm_idle_sweep_if_needed();

    // ─── CROSS-SHARD ROUTING ────────────────────────────────────────────────
    // A pipeline is grouped by owner before anything is sent, so a run crosses
    // once per shard rather than once per command, and the two shards frame
    // their exchange as `<len>\n<bytes>` because replies are not
    // self-delimiting -- with one command's answer assembled in the caller's
    // order rather than the order shards answered.
    // The first element kept inline, because nearly every slot has one part and
    // two vectors each were most of what a crossed pipeline allocated.
    template <class T>
    struct first_inline
    {
        T              first{};
        std::vector<T> rest;
        uint32_t       n{0};

        size_t size() const { return n; }
        bool empty() const { return n == 0; }
        T&       operator[](size_t i)       { return i == 0 ? first : rest[i - 1]; }
        const T& operator[](size_t i) const { return i == 0 ? first : rest[i - 1]; }
        void assign(size_t count, const T& v)
        {
            n     = static_cast<uint32_t>(count);
            first = v;
            rest.assign(count > 1 ? count - 1 : 0, v);
        }
        void push_back(T v)
        {
            if (n == 0)
                first = std::move(v);
            else
                rest.push_back(std::move(v));
            ++n;
        }

        template <class Q, class E>
        struct iter
        {
            Q*     q;
            size_t i;
            E& operator*() const { return (*q)[i]; }
            iter& operator++() { ++i; return *this; }
            bool operator!=(const iter& o) const { return i != o.i; }
        };
        iter<first_inline, T>             begin()       { return {this, 0}; }
        iter<first_inline, T>             end()         { return {this, n}; }
        iter<const first_inline, const T> begin() const { return {this, 0}; }
        iter<const first_inline, const T> end()   const { return {this, n}; }
    };

    struct reply_slot
    {
        cache_merge               merge{cache_merge::single};
        first_inline<std::string> parts;
        first_inline<uint8_t>     part_filled;
        uint32_t                  parts_left{0};
    };

    struct shard_batch
    {
        // Which connection is waiting, as a descriptor checked against
        // m_conn_idx and the connection's own list, because the socket may
        // have closed and its number been reissued.
        int  fd{-1};
        bool resp{false};

        // Answered, but behind an older batch of the same connection whose
        // replies go first.
        bool done{false};

        // What it charged the connection's crossing_bytes.
        size_t bytes{0};

        // One per command since the batch opened, in the order the client gave
        // them.
        std::vector<reply_slot> slots;

        // Crossings still owed an answer, one per shard rather than one per
        // command or per part.
        uint32_t outstanding{0};

        // The ticket this batch answers to instead of a socket, and what the
        // scratch connection produced ahead of the crossing.
        uint64_t    ticket{0};
        std::string head;
    };

    // Where one framed reply belongs: which command's answer, and which piece
    // of it.
    struct fill_target
    {
        uint32_t slot{0};
        uint32_t part{0};
    };

    // Crossed for and unanswered, per connection, past which the read is
    // withdrawn and the kernel's socket buffer holds the client.  It has to be
    // the accumulation bound and not a literal beside it: the comment here
    // already said "the same figure as MAX_PARTIAL_SIZE because it bounds the
    // same client's memory", and leaving 1 MiB written down while --read-buffer
    // moved the other one would have made that sentence false without anything
    // saying so.

    // A batch that could grow without bound is a memory path a client
    // controls, so a run of routed commands is cut and the rest left in
    // `partial` -- nothing lost and nothing reordered.
    static constexpr size_t MAX_ROUTED_PER_BATCH = 8192;

    // Parse what a connection has buffered, send what belongs to somebody else,
    // and stop if a crossing is already in flight for it.
    void pump(client_connection* conn);

    // Post one request per owning shard and put the batch in flight, once at
    // the end of a parse, which is what makes the grouping worth anything.
    void route_flush(client_connection* conn);

    // Fill every slot a failed or missing crossing owed, so a batch cannot be
    // left one answer short of ever completing.
    void batch_fill_error(shard_batch& b, const std::vector<fill_target>& targets,
                          std::string_view why);

    // Reserve this command's place in the reply order, returning its slot
    // index, with `parts` the number of pieces its answer needs.
    void     open_collect(client_connection* conn, bool resp);
    uint32_t slot_open(client_connection* conn, bool resp, cache_merge merge,
                       uint32_t parts);

    // Hand one piece of a command to the shard that owns it or run it here,
    // where `raw` is a complete single-key command in the connection's
    // protocol.
    void route_part(client_connection* conn, uint32_t owner, uint32_t slot,
                    uint32_t part, std::string_view raw, bool resp);

    // Run one complete command out of this shard's store and hand back what it
    // wrote, in one function for the two callers that must not diverge.
    void run_local_raw(client_connection* conn, std::string_view raw, bool resp,
                       std::string& out);

    // Put a finished slot's pieces together under its merge rule, where false
    // means they did not have the shape the rule expects and is answered as an
    // error for that command.
    bool slot_render(const reply_slot& sl, bool resp, std::string& out) const;

    // True when no key names another shard, which is the case a hash tag is
    // written to produce.
    bool keys_all_local(const std::string_view* keys, size_t n) const;

    // The two multi-key spellings exploded into single-key commands, where
    // false is a usage error or a command every key of which is this shard's,
    // and the local interpreter answers both.
    bool explode_text_multi(client_connection* conn, uint32_t h,
                            std::string_view args);
    bool explode_resp_multi(client_connection* conn, uint32_t h,
                            std::string_view* args, int argc);

    // A keyspace-wide command: the same command to every shard, merged.
    // A publish, to the shards whose channel filter says they can hold a
    // subscriber of that channel, and always this one.
    void fan_publish(client_connection* conn, uint32_t h, std::string_view raw,
                     bool resp, std::string_view channel);
    // The same set of targets with no reply collected, for a publish that has
    // to answer on the turn it was called.
    void fan_publish_siblings(std::string_view channel, std::string_view message);
    // A script's publishes for each sibling, sent as one batch a turn rather than one crossing each, and the
    // count each batch carries until it is answered.
    std::vector<std::string> m_lua_pub;
    std::vector<uint32_t> m_lua_pub_count;
    std::unordered_map<uint64_t, uint32_t> m_lua_pub_posts;
    void flush_lua_publishes();
    void flush_lua_publish(uint32_t sh);
    static void on_channel_presence(void* ctx, std::string_view channel, bool present);
    void        channel_presence(std::string_view channel, bool present);
    // The one bit with no channel name behind it: patterns.
    void        channel_presence_bit(uint32_t bit, bool present);
    // Channels of this shard per filter bucket, so the bit clears with the
    // bucket's last channel and not its first.
    std::vector<uint32_t> m_chan_buckets;

    // DBSIZE, size, memory and maxmemory answered from what every shard published, with no crossing; false when the
    // table cannot answer, and the command fans out as before.
    bool answer_from_table(client_connection* conn, uint32_t h, bool bare, bool resp);
    // This shard's key count and memory, published before anything it answered can leave, so a DBSIZE on a sibling
    // sees a write whose reply the client already has.
    void publish_keyspace();
    uint64_t m_pub_keys{~uint64_t{0}};
    uint64_t m_pub_memory{~uint64_t{0}};
    void fan_all_shards(client_connection* conn, uint32_t h,
                        std::string_view raw, bool resp);

    // Which shard a SCAN call resumes in, and one page out of this one.
    uint32_t scan_cursor_owner(std::string_view cursor_arg) const;
    // `node_local` is set for a SCAN on the per-shard port, which walks this
    // shard's slice and ends rather than handing back a cursor naming the next
    // shard.
    bool     shard_scan(uint64_t cursor, std::string_view pattern, size_t count,
                        std::vector<std::string_view>& out, uint64_t& next,
                        bool node_local,
                        const cache_store::scan_filter& filter = {});

    // Append a finished batch's slots to the connection's reply buffer and let
    // the rest of its pipeline run.
    void batch_finish(uint64_t id);

    // Give up a batch a connection can no longer be told about.
    void batch_drop(client_connection* conn);

    // The answering side: run a framed run of commands out of this shard's
    // store and frame the replies back.
    bool serve_shard_batch(std::string_view payload, std::string& out);

    // What a command this build does not route yet is answered with, said out
    // loud per command rather than served out of a quarter of the keyspace as
    // a miss for data that was stored.
    void emit_unrouted(client_connection* conn, std::string_view cmd, bool resp,
                       std::string_view why);

    // Run one command's local execution so its reply lands where the reply
    // ORDER says it belongs: at the end of response_buf when nothing is
    // crossing, and in a slot of its own once something is.
    template <class Fn>
    void run_in_reply_order(client_connection* conn, Fn&& fn)
    {
        if (SOCKETLEY_LIKELY(!m_collect && conn->batches.empty()))
        {
            fn();
            return;
        }
        // Behind an older crossing the reply takes a slot even with nothing
        // crossing now, or it would overtake the answers still out.
        if (!m_collect)
            open_collect(conn, conn->resp_mode);
        std::string held;
        held.swap(conn->response_buf);
        fn();
        std::string produced;
        produced.swap(conn->response_buf);
        conn->response_buf.swap(held);
        reply_slot sl;
        sl.merge = cache_merge::single;
        sl.parts.push_back(std::move(produced));
        sl.part_filled.push_back(1);
        sl.parts_left = 0;
        m_collect->slots.push_back(std::move(sl));
    }

    // Batches waiting on a sibling, by the id their connection holds.
    std::unordered_map<uint64_t, shard_batch> m_batches;

    // One posted crossing -- which batch it belongs to and which slot it fills
    // -- keyed by the cookie the channel hands back.
    struct posted_group
    {
        uint64_t                 batch{0};
        std::vector<fill_target> targets;
    };
    std::unordered_map<uint64_t, posted_group> m_posts;
    // A single-key command bound for a sibling, rebuilt here so a crossing allocates no string of its own.
    std::string m_cross_scratch;
    // How many slots the last routed batch took, reserved up front for the next one, since a pipeline grown a slot at a
    // time moved every slot it had held several times over.
    uint32_t    m_collect_hint{0};

    // The batch being collected by the parse running right now, one at a time
    // because one connection is parsed at a time, and null inside
    // serve_request().
    std::unique_ptr<shard_batch> m_collect;
    int                          m_collect_fd{-1};

    // Per-owner accumulation for the parse in progress, sized once at setup
    // and cleared per flush, so a pipeline costs no allocation per command.
    std::vector<std::string>              m_route_payload;
    std::vector<std::vector<fill_target>> m_route_slots;

    uint64_t m_next_batch{1};
    uint64_t m_next_cookie{1};

    // This runtime's shard set read once at setup, because get_shards() is not
    // inline and this is asked per command, with 1 and 0 the unsharded
    // answers.
    std::string shard_dump_path(uint32_t index) const;
    bool        save_shard_dump() const;
    bool        load_shard_set();

    // ── The mutation journal ────────────────────────────────────────────────
    // Beside this shard's dump as `<dump>.journal`, holding every write the
    // dump has not absorbed, flushed on --persistent-interval and truncated by
    // the snapshot that supersedes it.
    std::string journal_path(uint32_t index) const;
    bool        journal_recover();                      // judge, replay, open
    void        journal_mutation(std::string_view cmd); // buffer one write
    void        journal_flush_now();                    // buffer to page cache
    void        journal_after_snapshot(bool saved);     // truncate or flush
    void        arm_journal_timer();

    // A burst must not turn the buffer into the leak the interval avoids, so
    // it reaches the disk early at this size.
    static constexpr size_t journal_flush_bytes = 64 * 1024;

    // Whether a mutation needs writing down at all, asked before the text of
    // the command is built, because most caches neither lead nor journal.
#ifndef SOCKETLEY_NO_LUA
    // EVAL's own Lua, built on first use and never the runtime's --lua state:
    // one is the operator's code and the other arrived over the network.
    socketley::cache_script_engine m_scripts;

    // Runs one command for a script and hands back its reply, which is
    // redis.call's only way into the cache.
    void script_command(client_connection* conn, std::span<std::string_view> args, std::string& reply);
    // Scripts running now, counting one that redis.call started inside another.
    uint32_t m_script_depth{0};
#endif

    // ─── BLPOP / BRPOP ──────────────────────────────────────────────────────
    //
    // A descriptor and not a pointer, which is how the subscriber set holds
    // its readers and for the same reason: a descriptor can be revalidated
    // through m_conn_idx and a stale pointer cannot be noticed at all.  The
    // entry is dropped in close_client(), beside unsubscribe_all(), which is
    // the one function every close goes through.
    struct blocked_pop
    {
        int                      fd{-1};
        std::vector<std::string> keys;
        bool                     from_head{true};   // BLPOP head, BRPOP tail
        bool                     resp{true};
        // Zero means "no timeout": BLPOP key 0 waits for ever, as Redis does.
        std::chrono::steady_clock::time_point deadline{};
        uint64_t                 seq{0};
        // Where this waiter sits in each of its keys' queues, so leaving one
        // is an erase at a known node and not a search through the queue.
        std::vector<std::list<uint64_t>::iterator> slots;

        // An XREAD or XREADGROUP parks here too, queued in m_stream_wait_key.
        bool                     stream{false};
        std::vector<stream_id>   after;             // per key, the id past which it reads
        std::string              group;             // empty for XREAD
        std::string              consumer;
        uint64_t                 count{0};
        bool                     noack{false};

        // What sweep_blocked() can end: a deadline, or a group its stream may lose.
        bool needs_tick() const
        {
            return deadline.time_since_epoch().count() != 0 || (stream && !group.empty());
        }
    };

    // It stopped being true.  The linear walk that used to live here compared
    // every waiter's key list against the pushed key on EVERY push, and a
    // thousand idle workers -- an ordinary queue, not an attack -- cost the
    // pushing client 74% of its throughput while Redis lost 11%.  Profiled at
    // that load: memcmp 35.4%, wake_one_waiter 23.4%, string_view::compare
    // 16.9%, together 80% of the worker's CPU.
    //
    // So: waiters by sequence, and per key the sequences waiting on it in
    // arrival order -- the front of that queue is the longest-waiting client,
    // which is the order Redis serves and the reason the seq exists at all.
    std::unordered_map<uint64_t, blocked_pop>             m_blocked;
    // Waiters the tick serves, one with a deadline or a group reader; zero-deadline pops leave the timer unarmed.
    size_t                                                 m_ticking_waiters{0};
    std::unordered_map<std::string, std::list<uint64_t>,
                       string_hash, string_equal>          m_wait_key;
    std::unordered_map<int, uint64_t>                     m_wait_fd;
    uint64_t                 m_block_seq{0};

    // ─── Streams ────────────────────────────────────────────────────────────
    // Stream readers by key in arrival order, apart from the list waiters so a
    // push never hands an element to a reader that wants entries.
    std::unordered_map<std::string, std::list<uint64_t>,
                       string_hash, string_equal>          m_stream_wait_key;
    // Keys an XADD or a group's destruction has touched this turn, served once
    // the turn's commands are done, as Redis serves them after the command.
    std::vector<std::string> m_stream_ready;
    // Set while a replication record is applied, the only door to the two
    // verbs that restore a group exactly.
    bool m_stream_internal{false};
    // Inside apply_replicated(): a line from the primary or the journal, not from a client.
    bool m_applying_replicated{false};
    // A reply's body built before its count is known, kept so a range reuses its room.
    std::string m_stream_scratch;

    friend struct stream_commands;
    // Every stream command, answered in RESP into `rb` whichever protocol asked.
    void stream_command(client_connection* conn, uint32_t h, std::string_view* args, int argc,
                        std::string& rb);
    // The line protocol's door to the same commands, answered in its words.
    void stream_text(client_connection* conn, std::string_view cmd, std::string_view args);
    // One stream write for the followers and the journal, as the record the
    // text interpreter replays.
    void stream_repl(std::string_view key, const std::string_view* a, size_t n);
    void stream_repl(std::string_view key, std::initializer_list<std::string_view> a)
    { stream_repl(key, a.begin(), a.size()); }
    // A key an XADD or XGROUP DESTROY changed, for the readers parked on it.
    void stream_signal(std::string_view key);
    void serve_stream_ready();
    void serve_stream_waiter(uint64_t seq, std::string_view key);
    bool block_stream(client_connection* conn, const std::string_view* keys, const stream_id* ids,
                      size_t n, std::string_view group, std::string_view consumer,
                      uint64_t count, bool noack, int64_t timeout_ms);
    // A reply that did not come from this connection's own command, put on its
    // wire, and what it pipelined behind the wait run.
    void deliver_late(client_connection* c, std::string_view resp_reply);
    // A write refused a place in the replication log, counted and said.
    void repl_unfaithful(std::string_view key);

    // Drops one waiter from all three, and is the only way any of them shrink.
    void forget_waiter(uint64_t seq);

    // ─── WATCH ──────────────────────────────────────────────────────────────
    // key -> the descriptors watching it, the shape the subscriber set has and
    // for the same reason.  Empty is the usual state and the fast path.
    // Transparent, so a write looks a key up as a view: the plain map made
    // note_write_for_watch build a std::string on every single write.
    std::unordered_map<std::string, std::unordered_set<int>,
                       string_hash, string_equal> m_watchers;

    // And the same thing the other way round: who is watching ANYTHING.  A
    // write that cannot name its keys has to tell every watcher, and walking
    // m_watchers to find them makes that cost the number of watched KEYS --
    // so one client holding sixty thousand of them slows down every other
    // client's EVAL and MSET.  This makes it cost the number of watching
    // CLIENTS instead, where that client is one entry.
    std::unordered_set<int> m_watching;

    void reset_connection_state(client_connection* conn);
    void watch_keys(client_connection* conn, std::string_view* args, int argc);
    void unwatch_all(client_connection* conn);
    void drop_watches(int fd);
    // A command that is not a read has run: whoever is watching what it may
    // have touched cannot commit any more.
    void note_write_for_watch(uint32_t h, std::string_view* args, int argc);

    // Park the caller; false when it could be answered at once after all.
    bool block_pop(client_connection* conn, std::string_view* args, int argc,
                   bool from_head);
    // A push landed on `key`: hand it to the longest-waiting client that asked
    // for it, if there is one.  True means the element is gone to a waiter.
    bool wake_one_waiter(std::string_view key);
    // Answer everyone whose deadline has passed, and re-arm while any remain.
    void sweep_blocked();
    void arm_block_timer();
    void drop_blocked(int fd);

    // The handful of INFO fields a client or a monitor actually reads back,
    // and nothing invented to fill a section out.
    void build_info_reply(std::string& out, bool whole) const;

    bool mutation_log_wanted() const
    {
        return (m_repl_role == repl_leader && !m_followers.empty())
            || (m_journal.is_open() && !m_journal_replaying)
            || m_leads_cluster;
    }

    // One Lua-facing mutation into the chokepoint, spelled as the text
    // command a client would have typed, because this API used to walk past
    // both the followers and the journal.
    void log_lua_mutation(std::initializer_list<std::string_view> parts);

    uint32_t m_shard_n{1};
    // What --maxmemory asked for, the whole runtime's; the store holds this shard's share.
    size_t m_max_memory{0};
    uint32_t m_shard_i{0};

    // True while this shard is answering a crossing from a sibling rather than
    // a client of its own, read by publish().
    bool m_serving_shard_batch{false};

    // Both report whether the submission reached the ring; see the definitions
    // for why a caller must not ignore that.
    bool flush_responses(client_connection* conn);
    void after_write(client_connection* conn, int fd);
    bool flush_write_queue(client_connection* conn);
    // Where a published message is written once for its subscribers, one
    // segment per wire format; see socketley::place_in_segment().
    std::shared_ptr<std::string> m_pub_seg_text;
    std::shared_ptr<std::string> m_pub_seg_resp;

    // ── TLS record layer ────────────────────────────────────────────────────
    // OpenSSL does no I/O here, so the handshake is one call per completion
    // with nothing blocking, and a close_notify lands in tls_peer_closed so
    // the command it arrived with still gets an answer.
    void tls_feed(client_connection* conn, const char* data, size_t len);

    // Queued plaintext to one write submission of ciphertext, the only way a
    // byte leaves a TLS connection, where true with nothing submitted is
    // legitimate and common.
    bool tls_flush(client_connection* conn);

    // Whether this connection still owes the wire anything, which for TLS the
    // queue only half answers, because asking only about it is how a handshake
    // stalls one round short.
    bool conn_has_output(const client_connection* conn) const;

    // A closing TLS connection waiting on nothing but its own read is shut
    // down so that read completes now, because the alert saying why a
    // handshake failed is the peer's only diagnosis and a multishot recv stays
    // armed until the socket moves.
    void tls_close_when_read_is_all(client_connection* conn, int fd);
    // A closing cleartext connection whose answer has left sends its FIN and
    // keeps reading, so the close waits for the client's EOF.
    void drain_before_close(client_connection* conn, int fd);
    // How much a draining connection may still send before it is closed anyway.
    static constexpr size_t DRAIN_LIMIT_BYTES = 64 * 1024 * 1024;

    // Arm the read that fits the configured mode, false when nothing reached
    // the ring, with read_pending left clear so no one waits on it.
    bool submit_client_read(client_connection* conn, int fd);
    void pause_read(client_connection* conn);
    bool resume_read(client_connection* conn, int fd);

    // Re-arm the listener, falling back to the backoff timer when the
    // submission does not reach the ring, or the cache stops taking
    // connections silently.
    void rearm_accept();
    void rearm_cluster_accept();
    void schedule_accept_backoff();

    // One listener opened and bound, as one function with two arguments
    // because the two differ only in the port and whether SO_REUSEPORT is set.
    bool open_listener(uint16_t port, bool reuseport, int& out_fd);

    // ─── The cluster view ───────────────────────────────────────────────────
    // Enough of Redis's CLUSTER surface for an off-the-shelf client to
    // bootstrap and route, derived from two numbers every shard already holds
    // so N processes publish the same map without speaking.
    void     emit_cluster(client_connection* conn, std::string_view sub,
                          std::string_view arg, bool resp);
    // 40 lowercase hex, stable across restarts and distinct per shard, derived
    // from the runtime name and shard index so a reconnecting client sees the
    // topology it knows.
    std::string cluster_node_id(uint32_t shard) const;
    // The address to tell a client to go to, taken from getsockname() on the
    // asking connection, so it is by construction an address that reached us.
    std::string cluster_host(const client_connection* conn) const;
    uint16_t cluster_port_of(uint32_t shard) const;
    // -MOVED, the answer that teaches a client to stop coming here for this
    // key, only ever sent on the per-shard port.
    void emit_moved(client_connection* conn, std::string_view key,
                    uint32_t owner, bool resp);
    // The verdict on a multi-key command that arrived on the per-shard port,
    // where true means it has been answered here and the caller must stop.
    // Pointer and count, because the RESP spelling already HAS the keys in a
    // row: EXISTS, DEL, MGET and TOUCH name them in args[1..n], so building a
    // vector to look at them was one heap allocation per command on the
    // cluster port -- which is the port every sharded client connects to.
    bool route_all_keys_one_shard(client_connection* conn,
                                  std::string_view* args, int argc,
                                  int key_first, int key_count);
    bool cluster_multi_verdict(client_connection* conn,
                               const std::string_view* keys, size_t n,
                               bool resp);
    // MSET's keys are every other argument, so that one still needs a buffer;
    // it is reused rather than rebuilt.
    std::vector<std::string_view> m_multi_keys;

    bool cluster_multi_verdict(client_connection* conn,
                               const std::vector<std::string_view>& keys,
                               bool resp);


    // ─── Retired I/O ───────────────────────────────────────────────────────
    // One rule everywhere: nothing io_uring may still be reading from is
    // freed, reused or re-armed, but retired into m_retired with its
    // io_requests still pointing here, so the completion lands in
    // absorb_retired().
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

    // Every descriptor this runtime gives back goes through here, because a
    // close does not withdraw an SQE that carries the number -- through
    // m_retired_loop, since descriptors are closed after teardown has cleared
    // m_loop.
    void close_tracked(int fd);

    // Retire `storage`, waiting for the `count` requests in `owed`, releasing
    // it here and now when nothing is owed.
    void retire(std::shared_ptr<void> storage, io_request* const* owed, size_t count);
    // Consume a completion belonging to a retired object, where true means the
    // caller must not look at the request again.
    bool absorb_retired(io_request* req, struct io_uring_cqe* cqe);

    // A timeout and its request allocated per run, because an interval timer
    // is nearly always in flight when a runtime stops and reaches no shutdown
    // or cancel, so re-arming the same request leaves two chains driving one
    // piece of state.
    struct timer_op
    {
        io_request req{};
        struct __kernel_timespec ts{};
    };

    // The accept request together with the address the kernel fills in, on the
    // same reasoning as timer_op: a stale accept completion on a re-armed
    // request arms the listener twice.
    struct accept_op
    {
        io_request req{};
        struct sockaddr_in addr{};
        socklen_t addrlen{sizeof(struct sockaddr_in)};
    };

    // Arm `op` on `fd`, choosing multishot the same way for both listeners,
    // with `multishot` written rather than read because it records what was
    // actually armed.
    void arm_listener(int fd, accept_op& op, bool& multishot);
    void rearm_accept_on(int fd, accept_op* op, bool multishot);

    int m_listen_fd;
    // The path the current listener actually bound, deliberately not
    // get_listen_path(), because the configuration may have been edited
    // between start and stop.
    std::string m_bound_listen_path;
    std::unique_ptr<accept_op> m_accept;
    bool m_multishot_active{false};

    // The node beside the port, kept for as long as this instance is; see
    // setup() for why it is never reset.
    std::unique_ptr<socketley::unix_companion> m_companion;

    // ── The port this shard alone binds ─────────────────────────────────────
    // `base + 1 + shard index`, bound only when sharded and deliberately
    // without SO_REUSEPORT, because with it a second process binding this port
    // would be accepted and answer -MOVED for keys it does not hold.
    int m_cluster_listen_fd{-1};
    std::unique_ptr<accept_op> m_cluster_accept;
    bool m_cluster_multishot_active{false};
    uint16_t m_cluster_port{0};
    // What --cluster and --no-cluster asked for, what cluster_mode() made of
    // them at setup, and what this run binds, which differ for a cluster of a
    // single shard: it publishes a map and binds no extra port.
    bool m_cluster_forced{false};
    bool m_no_cluster{false};
    bool m_cluster_on{false};
    bool m_cluster_ports{false};
    bool m_public{false};
    // Whether a TCP peer on another machine is served, fixed at setup().
    bool m_admits_remote{false};
    // The port the operator configured, from which every shard's own port is
    // derived, kept because get_port() is not inline and the answer has to be
    // identical in every shard.
    uint16_t m_base_port{0};

    // The listener's TLS context, rebuilt on every start so `reload` installs
    // a renewed certificate, with existing sessions holding their own
    // reference.
    std::unique_ptr<tls_context> m_tls;

    cache_store m_store;
    std::unordered_map<int, std::unique_ptr<client_connection>> m_clients;

    // O(1) fd→connection lookup (avoids hash map on every CQE)
    static constexpr int MAX_FDS = 8192;
    socketley::fd_table<client_connection*> m_conn_idx{MAX_FDS};

    event_loop* m_loop;

    // EMFILE/ENFILE accept backoff
    std::unique_ptr<timer_op> m_accept_backoff_timer;

    // The tick that answers a BLPOP whose timeout has passed, armed only while
    // somebody is waiting -- a cache nobody blocks on has no timer at all.
    std::unique_ptr<timer_op> m_block_timer;
    bool                      m_block_timer_armed{false};

    // Idle connection sweep timer
    std::unique_ptr<timer_op> m_idle_sweep_timer;

    socketley::direct_send_gate m_direct_gate;
    // The connection a direct send went out on this turn, -1 for none.
    int m_direct_fd{-1};

    std::string m_persistent_path;
    // 0 keeps exactly the behaviour every cache before the flag had: a dump at
    // stop and at `flush`, and nothing in between.
    uint32_t m_persist_interval{0};

    mutation_journal m_journal;
    std::unique_ptr<timer_op> m_journal_timer;
    bool m_journal_timer_armed{false};
    // Replayed commands go through the interpreter, whose write paths would
    // journal them a second time.
    bool m_journal_replaying{false};
    // Warned once per run, because a full disk would otherwise say so once per
    // interval for as long as the writes keep coming.
    bool m_journal_write_warned{false};

    cache_mode m_mode = cache_mode_readwrite;
    bool m_resp_forced{false};

    // ── A replica of a cluster cache ────────────────────────────────────────
    // Present once setup() has made this process a replica, whose part is only what the daemon's last order says:
    // fenced answers no client, a follower is read-only and dials its primary, and the primary takes writes and counts them.
    uint64_t m_cluster_incarnation{0};
    std::unique_ptr<socketley::cluster::replica_role> m_role;
    socketley::cluster::replica_mode m_role_mode{socketley::cluster::replica_mode::fenced};
    // The mode the flags asked for, which a primary returns to after a spell as a follower or fenced.
    cache_mode m_mode_asked{cache_mode_readwrite};
    bool m_fenced{false};
    bool m_leads_cluster{false};
    std::unique_ptr<timer_op> m_role_timer;
    bool m_role_timer_armed{false};
    void apply_role(socketley::cluster::replica_mode mode, bool retarget);
    void follow(const std::string& target, bool retarget);
    void drop_master();
    void arm_role_timer();
    void role_lapsed();
    // A client command that is refused because this replica holds no lease.
    static void refuse_fenced(client_connection* conn, bool resp);

    // Replication
    std::string m_replicate_target;
    repl_role m_repl_role{repl_none};
    // The leader's name, resolved off the loop.
    socketley::async_resolver m_resolver;

    // A follower socket plus whatever has not reached it yet, because a
    // follower sharing this event loop would deadlock a synchronous write and
    // a short write would splice two commands together -- and this buffer is
    // the only writer on the descriptor once promotion has happened.
    struct follower_conn
    {
        // Borrowed and never owned, because the descriptor belongs to the
        // client_connection the follower reached the leader as, and keeping it
        // after that client had gone gave the next accepted connection the
        // replication stream.
        int fd{-1};
        // Two buffers, because the kernel reads directly out of `out` for the
        // duration of a write and appending could reallocate it under the
        // operation.
        std::string out;            // kernel owns out[out_off..out_off+in_flight) while writing
        std::string queued;         // produced since the current write started
        // Advanced rather than erased, because a dump is written in many short
        // writes and erasing the front of it after each one is quadratic.
        size_t out_off{0};
        size_t in_flight{0};
        // Bytes of the full dump not yet taken by the kernel, which the lag cap
        // is measured above, because the dump is the dataset and not lag.
        size_t sync_left{0};
        io_request write_req{};
        bool write_pending{false};
        bool dead{false};

        size_t backlog() const { return out.size() - out_off + queued.size(); }
    };
    // Cap on buffered-but-unsent replication data per follower beyond its full
    // dump, past which it is dropped, because an explicit disconnect is
    // recoverable and a corrupted command stream is not.
    static constexpr size_t MAX_FOLLOWER_PENDING = 8 * 1024 * 1024;

    // unique_ptr because the kernel holds a pointer to each write_req for the
    // lifetime of its operation; vector growth would move the elements.
    std::vector<std::unique_ptr<follower_conn>> m_followers;
    // The line replicate_command sends, kept so a leader's write allocates nothing for it.
    std::string m_repl_line;

    // The link to the leader allocated per connect, because the read armed on
    // it is not cancelled by closing the socket and reconnecting usually lands
    // on the same fd number.
    struct master_link
    {
        io_request read_req{};
        // A read as large as a full sync can use, since the link is one per follower and allocated per connect.
        char buf[256 * 1024]{};
        std::string partial;
        int fd{-1};
        bool read_pending{false};
        // A socket is not a sync: the dump arrives after the read is armed, so
        // between the two the follower is connected and answering out of a
        // dataset that is on its way to being replaced.
        bool synced{false};
        // What the deadline below compares against, so a dump that is slow is
        // told apart from a leader that has stopped sending.
        uint64_t bytes_seen{0};
        // How much of the unfinished line at the front of `partial` is known to hold no newline, so a long one is
        // searched once across its reads rather than from its start at every one.
        size_t searched{0};
        uint64_t bytes_at_deadline{0};
    };
    std::unique_ptr<master_link> m_master;

    // A dial in flight, which is not a link yet.  The address lives here for as
    // long as the kernel is reading it -- the reason the proxy's health probe
    // keeps its own copy -- and an abandoned dial goes to retire() like every
    // other request the ring still owes.
    struct master_dial
    {
        io_request req{};
        struct sockaddr_in addr{};
        int fd{-1};
        // Who was dialled, so an answer that arrives after the target changed is not taken for the new one's.
        std::string target;
    };
    std::unique_ptr<master_dial> m_master_dial;
    // One retry chain at a time and the attempt it counts from, which is the
    // shape upstream_schedule_reconnect() uses one runtime over, for the reason
    // timer_op gives: re-arming a request the ring still holds leaves two
    // chains driving one piece of state.
    std::unique_ptr<timer_op> m_master_retry;
    uint32_t m_master_attempt{0};
    // A leader that accepts the connection and then says nothing leaves the
    // read armed forever, which the retry chain never sees because there was
    // no drop.  Measured against bytes rather than against the clock, so a
    // dump that takes longer than the window re-arms instead of being dropped.
    std::unique_ptr<timer_op> m_master_sync_deadline;
    // Set when a connection is left holding a half-arrived command, cleared by
    // the sweep that finds none, because the sweep decides whether to re-arm
    // and a walk it has already finished is the only place that knows.
    bool m_partials_outstanding{false};

    // Start a write if nothing is in flight, moving queued data into out.
    void follower_kick(follower_conn& f);
    // Queue data for a follower and start writing if nothing is in flight,
    // false when the follower must be dropped.
    bool follower_write(follower_conn& f, std::string_view data);
    bool follower_write_owned(follower_conn& f, std::string&& data);
    // Continue or finish a follower write after its completion arrives.
    void handle_follower_write(struct io_uring_cqe* cqe, follower_conn& f);
    // Drop followers marked dead and ask their client connections to close.
    void reap_followers();
    // Give up the follower promoted from this descriptor, called from
    // close_client(), which is the only owner of the socket.
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
    void handle_master_connect(struct io_uring_cqe* cqe, io_request* req);
    // Arm the next dial, or do nothing when this cache no longer follows
    // anybody.  Called from every path that ends a link, so there is one place
    // that decides whether a follower keeps trying.
    void schedule_master_retry();
    void arm_master_sync_deadline();
    void handle_master_read(struct io_uring_cqe* cqe);

    // Provided buffer ring
    static constexpr uint16_t BUF_GROUP_ID = 3;
    // What a ring costs is its footprint against the core's cache, not its
    // buffer size, so it holds 4 MiB in large buffers.
    static constexpr uint32_t BUF_COUNT = 64;
    static constexpr uint32_t BUF_SIZE = 65536;
    bool m_use_provided_bufs{false};
    bool m_recv_multishot{false};
    // Bundled multishot recv, one completion per burst instead of one per
    // buffer, and only a preference: a refused submit falls back to the plain
    // arm, which handle_read consumes identically.
    bool m_recv_bundle{false};

    // Periodic TTL sweep timer
    std::unique_ptr<timer_op> m_ttl_timer;
    // The interval between sweeps once one has reached the table's end.
    long m_ttl_sweep_ms{500};

    // Cached config values (read once in setup, avoid virtual calls on hot path)
    uint32_t m_idle_timeout_cached{0};
    uint32_t m_max_conns_cached{0};
    double m_rate_limit_cached{0.0};

    // TTL sweep short-circuit: skip m_expiry scan when no TTL keys exist
    bool m_has_ttl_keys{false};

    // Whether a TTL sweep timeout is outstanding, because rearming
    // unconditionally wakes an otherwise idle loop twice a second for a scan
    // that has nothing to find.
    bool m_ttl_timer_armed{false};

    // Submit the sweep timeout unless one is already pending.
    void arm_ttl_timer();

    // Record that at least one key now carries an expiry and restart the
    // sweep, because setting the flag without arming the timer leaves expired
    // keys until something touches them.
    void mark_ttl_keys();

    // The connection serve_request() and execute() answer through, made once
    // and reset because the server's --cache auto-store comes here per
    // message, with m_serving the re-entrancy guard for a command that
    // publishes into Lua.
    std::unique_ptr<client_connection> m_request_conn;
    bool m_serving{false};

    // A request answered by ticket rather than down a socket, run one at a
    // time in arrival order, because the asker pipelines by order.
    struct deferred_request
    {
        uint64_t    ticket{0};
        std::string payload;
    };
    std::deque<deferred_request> m_deferred_queue;
    uint64_t                     m_deferred_inflight{0};
    // Bounded like the channel's parked table, and past it a request is
    // refused rather than queued.
    static constexpr size_t MAX_DEFERRED_QUEUE = 4096;
    // The ticket the scratch connection is serving right now, which is what
    // lets it open a crossing.
    uint64_t m_serving_ticket{0};

    bool can_cross(const client_connection* conn) const;
    void run_deferred(uint64_t ticket, std::string_view payload);
    void complete_ticket(uint64_t ticket, request_status st,
                         std::string_view reply);
    void drain_deferred();

    // Connection struct pool — reuse allocations to avoid malloc/free per connect/disconnect
    static constexpr size_t CONN_POOL_INIT = 32;
    std::vector<std::unique_ptr<client_connection>> m_conn_pool;
    std::unique_ptr<client_connection> pool_acquire(int fd);
    // Hand a connection back for reuse, or retire it when the ring still owes
    // it a completion, in the one place every close path goes through.
    void pool_release(std::unique_ptr<client_connection> conn);

    // Full teardown of a client connection, which every close path must go
    // through, because dropping the fd without clearing its subscriptions
    // leaves it in the store's channel map forever.
    void close_client(client_connection* conn, int fd, const char* reason);

    // The one place a connection nothing is going to finish is finished,
    // called after every completion for the connection it named.
    void finish_unreachable_client(int fd);

    // The same flags sorted by who is obliged to report them, which is the
    // seam between conn_reachability.h and this runtime's connection struct.
    socketley::reach::owed conn_owed(const client_connection* conn) const;
};
