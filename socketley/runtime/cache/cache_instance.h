#pragma once
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
#include "cache_store.h"
#include "../../shared/trace.h"
#include "../../shared/write_queue.h"

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

class cache_instance : public runtime_instance
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

    // Stats
    std::string get_stats() const override;
    uint64_t m_stat_commands{0};
    uint64_t m_stat_get_hits{0};
    uint64_t m_stat_get_misses{0};
    uint64_t m_stat_keys_expired{0};

    // Direct store access (for server --cache integration)
    bool store_direct(std::string_view key, std::string_view value);

    // Cache management (for cmd_action)
    uint32_t get_size() const;
    size_t store_memory_used() const;
    bool flush_to(std::string_view path);
    bool load_from(std::string_view path);

private:
    void handle_accept(struct io_uring_cqe* cqe);
    void handle_read(struct io_uring_cqe* cqe, io_request* req);
    void handle_write(struct io_uring_cqe* cqe, io_request* req);

    void process_command(client_connection* conn, std::string_view line);
    void process_resp(client_connection* conn);
    void process_resp_command(client_connection* conn, std::string_view* args, int argc);

    // Both report whether the submission reached the ring; see the definitions
    // for why a caller must not ignore that.
    bool flush_responses(client_connection* conn);
    bool flush_write_queue(client_connection* conn);

    // Arm the read that fits the configured mode.  Returns false when nothing
    // reached the ring, with read_pending left clear so no one waits on it.
    bool submit_client_read(client_connection* conn, int fd);

    // Re-arm the listener, falling back to the backoff timer when the
    // submission does not reach the ring.  Without that the cache stops taking
    // connections silently — there is no completion left to report it.
    void rearm_accept();
    void schedule_accept_backoff();

    int m_listen_fd;
    struct sockaddr_in m_accept_addr;
    socklen_t m_accept_addrlen;
    io_request m_accept_req;
    bool m_multishot_active{false};

    cache_store m_store;
    std::unordered_map<int, std::unique_ptr<client_connection>> m_clients;

    // O(1) fd→connection lookup (avoids hash map on every CQE)
    static constexpr int MAX_FDS = 8192;
    client_connection* m_conn_idx[MAX_FDS]{};

    event_loop* m_loop;

    // EMFILE/ENFILE accept backoff
    io_request m_accept_backoff_req{};
    struct __kernel_timespec m_accept_backoff_ts{};

    // Idle connection sweep timer
    io_request m_idle_sweep_req{};
    struct __kernel_timespec m_idle_sweep_ts{};

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
    struct follower_conn
    {
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
    int m_master_fd{-1};

    // Start a write if nothing is in flight, moving queued data into out.
    void follower_kick(follower_conn& f);
    // Queue data for a follower and start writing if nothing is in flight.
    // Returns false when the follower must be dropped.
    bool follower_write(follower_conn& f, std::string_view data);
    // Continue or finish a follower write after its completion arrives.
    void handle_follower_write(struct io_uring_cqe* cqe, follower_conn& f);
    // Drop followers marked dead, closing their sockets.
    void reap_followers();
    io_request m_master_read_req{};
    char m_master_read_buf[4096]{};
    std::string m_master_partial;

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
    io_request m_ttl_req{};
    struct __kernel_timespec m_ttl_ts{};

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

    // Connection struct pool — reuse allocations to avoid malloc/free per connect/disconnect
    static constexpr size_t CONN_POOL_INIT = 32;
    std::vector<std::unique_ptr<client_connection>> m_conn_pool;
    std::unique_ptr<client_connection> pool_acquire(int fd);
    void pool_release(std::unique_ptr<client_connection> conn);

    // Full teardown of a client connection.  Every close path must go through
    // this rather than open-coding the steps: dropping the fd without clearing
    // its subscriptions leaves it in the store's channel map forever, and the
    // next connection that happens to get the same fd number inherits the dead
    // client's channels.
    void close_client(client_connection* conn, int fd, const char* reason);
};
