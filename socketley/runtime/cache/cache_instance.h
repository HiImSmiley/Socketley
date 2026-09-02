#pragma once
#include "../../shared/conn_reachability.h"
#include <initializer_list>
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

#include <deque>
#include "../../shared/cache_shard_map.h"
#include "cache_store.h"
#include "../../shared/mutation_journal.h"
#include "../../shared/trace.h"
#include "../../shared/write_queue.h"
#include "../../shared/tls_context.h"
#include "../../shared/unix_companion.h"

struct client_connection
{
    static constexpr size_t MAX_WRITE_BATCH = 16;
    // Upper size for merging consecutive responses into one queue entry, large
    // enough that thousands of small replies share a handful and small enough
    // that one entry stays a reasonable write.
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
    // Enough for a batch worth queueing and small enough that a client cannot
    // park unbounded memory on a connection by never sending EXEC.
    static constexpr size_t  MULTI_MAX_BYTES = 8u << 20;
    static constexpr size_t  MULTI_MAX_CMDS  = 100000;

    // A crossing this connection is waiting on, which stops the pipeline
    // because a client pipelining down one socket can only tell replies apart
    // by order -- an id and not a pointer, since the struct may be pooled by
    // the time the reply lands.
    uint64_t batch_id{0};

    // The peer sent its FIN while a crossing was still owed, so the close is
    // held rather than taken, because a crossing is answered on a later turn
    // and closing would throw away an answer the client is reading.
    bool peer_gone{false};

    // RESP protocol mode (auto-detected or forced)
    bool resp_mode{false};
    bool resp_detected{false};  // true once first byte examined

    // Set by REPLICATE, after which this socket carries the replication stream
    // and nothing else, with the refusal kept to one line per connection.
    bool is_follower{false};
    bool follower_refused{false};

    // Non-null only with --tls, on the server runtime's design deliberately
    // unchanged, and freed only by this struct -- which is what makes freeing
    // it never have to wait on the ring.
    SSL* ssl{nullptr};
    tls_conn_state tls_state{tls_conn_none};
    // The peer's close_notify, remembered rather than acted on, because the
    // read that carries it can carry the last command ahead of it.
    bool tls_peer_closed{false};

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
        partial.clear();
        response_buf.clear();
        write_queue.clear();
        for (uint32_t i = 0; i < write_batch_count; i++) write_batch[i].clear();
        write_batch_count = 0;
        read_pending = false;
        write_pending = false;
        closing = false;
        zc_notif_pending = false;
        cluster_port = false;
        in_multi = false;
        multi_broken = false;
        multi_queue.clear();
        multi_bytes = 0;
        batch_id = 0;
        peer_gone = false;
        resp_mode = false;
        resp_detected = false;
        is_follower = false;
        follower_refused = false;
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

    void on_cqe(struct io_uring_cqe* cqe) override;
    bool setup(event_loop& loop) override;
    void teardown(event_loop& loop) override;
    void on_loop_turn() override;

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

    // --cluster is a flag and not a consequence of --shards, because
    // client-side routing gives up an enforcement point: behind a proxy the
    // advertised address either bypasses the proxy's rules or cannot be
    // reached at all.
    void set_cluster(bool enabled);
    bool get_cluster() const;

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
    uint64_t m_stat_get_hits{0};
    uint64_t m_stat_get_misses{0};
    uint64_t m_stat_keys_expired{0};

    // Cache management (for cmd_action)
    uint32_t get_size() const;
    size_t store_memory_used() const;
    bool flush_to(std::string_view path);
    bool load_from(std::string_view path);

private:
    void handle_accept(struct io_uring_cqe* cqe, io_request* req);
    // One accepted descriptor into a connection, from whichever listener
    // handed it over, where false means it was dealt with and is gone.
    bool adopt_client(int client_fd, bool from_cluster, bool from_unix);
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
    void process_resp(client_connection* conn);
    void process_resp_command(client_connection* conn, std::string_view* args, int argc);
    void process_resp_command_local(client_connection* conn, std::string_view* args, int argc);

    // The text line splitter, lifted out of handle_read so that a connection
    // whose crossing has just come back can be driven from the reply handler
    // with the same code the read handler uses.
    void parse_text_lines(client_connection* conn);

    // ─── CROSS-SHARD ROUTING ────────────────────────────────────────────────
    // A pipeline is grouped by owner before anything is sent, so a run crosses
    // once per shard rather than once per command, and the two shards frame
    // their exchange as `<len>\n<bytes>` because replies are not
    // self-delimiting -- with one command's answer assembled in the caller's
    // order rather than the order shards answered.
    struct reply_slot
    {
        cache_merge              merge{cache_merge::single};
        std::vector<std::string> parts;
        std::vector<uint8_t>     part_filled;
        uint32_t                 parts_left{0};
    };

    struct shard_batch
    {
        // Which connection is waiting, as a descriptor checked against
        // m_conn_idx and the connection's batch_id, because the socket may
        // have closed and its number been reissued.
        int  fd{-1};
        bool resp{false};

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

    // The two multi-key spellings exploded into single-key commands, where
    // false is a usage error answered by the local interpreter as it always
    // was.
    bool explode_text_multi(client_connection* conn, uint32_t h,
                            std::string_view args);
    bool explode_resp_multi(client_connection* conn, uint32_t h,
                            std::string_view* args, int argc);

    // A keyspace-wide command: the same command to every shard, merged.
    void fan_all_shards(client_connection* conn, uint32_t h,
                        std::string_view raw, bool resp);

    // Which shard a SCAN call resumes in, and one page out of this one.
    uint32_t scan_cursor_owner(std::string_view cursor_arg) const;
    // `node_local` is set for a SCAN on the per-shard port, which walks this
    // shard's slice and ends rather than handing back a cursor naming the next
    // shard.
    bool     shard_scan(uint64_t cursor, std::string_view pattern, size_t count,
                        std::vector<std::string_view>& out, uint64_t& next,
                        bool node_local);

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
        if (SOCKETLEY_LIKELY(!m_collect))
        {
            fn();
            return;
        }
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
    bool mutation_log_wanted() const
    {
        return (m_repl_role == repl_leader && !m_followers.empty())
            || (m_journal.is_open() && !m_journal_replaying);
    }

    // One Lua-facing mutation into the chokepoint, spelled as the text
    // command a client would have typed, because this API used to walk past
    // both the followers and the journal.
    void log_lua_mutation(std::initializer_list<std::string_view> parts);

    uint32_t m_shard_n{1};
    uint32_t m_shard_i{0};

    // True while this shard is answering a crossing from a sibling rather than
    // a client of its own, read by publish().
    bool m_serving_shard_batch{false};

    // Both report whether the submission reached the ring; see the definitions
    // for why a caller must not ignore that.
    bool flush_responses(client_connection* conn);
    bool flush_write_queue(client_connection* conn);

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

    // Arm the read that fits the configured mode, false when nothing reached
    // the ring, with read_pending left clear so no one waits on it.
    bool submit_client_read(client_connection* conn, int fd);

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
    // What --cluster asked for and what this run does about it, which differ
    // for a cluster of a single shard: it publishes a map and binds no extra
    // port.
    bool m_cluster_forced{false};
    bool m_cluster_ports{false};
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
    client_connection* m_conn_idx[MAX_FDS]{};

    event_loop* m_loop;

    // EMFILE/ENFILE accept backoff
    std::unique_ptr<timer_op> m_accept_backoff_timer;

    // Idle connection sweep timer
    std::unique_ptr<timer_op> m_idle_sweep_timer;

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

    // Replication
    std::string m_replicate_target;
    repl_role m_repl_role{repl_none};

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
        std::string out;            // kernel owns out[0..in_flight) while writing
        std::string queued;         // produced since the current write started
        size_t in_flight{0};
        io_request write_req{};
        bool write_pending{false};
        bool dead{false};

        size_t backlog() const { return out.size() + queued.size(); }
    };
    // Cap on buffered-but-unsent replication data per follower, past which it
    // is dropped, because an explicit disconnect is recoverable and a
    // corrupted command stream is not.
    static constexpr size_t MAX_FOLLOWER_PENDING = 8 * 1024 * 1024;

    // unique_ptr because the kernel holds a pointer to each write_req for the
    // lifetime of its operation; vector growth would move the elements.
    std::vector<std::unique_ptr<follower_conn>> m_followers;

    // The link to the leader allocated per connect, because the read armed on
    // it is not cancelled by closing the socket and reconnecting usually lands
    // on the same fd number.
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
    // Queue data for a follower and start writing if nothing is in flight,
    // false when the follower must be dropped.
    bool follower_write(follower_conn& f, std::string_view data);
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
    void handle_master_read(struct io_uring_cqe* cqe);

    // Provided buffer ring
    static constexpr uint16_t BUF_GROUP_ID = 3;
    // 4096 is kept under protest rather than confirmed: measured across buffer
    // size, bundling and allocator, 1 KB is a real penalty, bundling's
    // clearest win is 2 KB, and bundle-on rises monotonically to 16 KB -- but
    // each step is inside a 14% self-noise band, and the allocator did not
    // matter.
    static constexpr uint32_t BUF_COUNT = 512;
    static constexpr uint32_t BUF_SIZE = 4096;
    bool m_use_provided_bufs{false};
    bool m_recv_multishot{false};
    // Bundled multishot recv, one completion per burst instead of one per
    // buffer, and only a preference: a refused submit falls back to the plain
    // arm, which handle_read consumes identically.
    bool m_recv_bundle{false};
    bool m_send_zc{false};

    // Periodic TTL sweep timer
    std::unique_ptr<timer_op> m_ttl_timer;

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
