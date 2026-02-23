#pragma once
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <memory>
#include <queue>
#include <netinet/in.h>
#include <sys/uio.h>

#include "../../shared/runtime_instance.h"
#include "../../shared/event_loop_definitions.h"
#include "cache_store.h"

struct client_connection
{
    static constexpr size_t MAX_WRITE_BATCH = 16;
    static constexpr size_t MAX_WRITE_QUEUE = 4096;
    static constexpr size_t MAX_PARTIAL_SIZE = 1 * 1024 * 1024;

    int fd;
    io_request read_req;
    io_request write_req;
    char read_buf[4096];
    std::string partial;
    std::string response_buf;
    // write_queue holds owned strings — no shared_ptr overhead per flush
    std::queue<std::string> write_queue;

    std::string write_batch[MAX_WRITE_BATCH];
    struct iovec write_iovs[MAX_WRITE_BATCH];
    uint32_t write_batch_count{0};

    bool read_pending{false};
    bool write_pending{false};
    bool closing{false};

    // RESP protocol mode (auto-detected or forced)
    bool resp_mode{false};
    bool resp_detected{false};  // true once first byte examined

    // Rate limiting (token bucket)
    double rl_tokens{0.0};
    double rl_max{0.0};
    std::chrono::steady_clock::time_point rl_last{};

    // Idle connection tracking
    std::chrono::steady_clock::time_point last_activity{};
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
    int lua_ttl(std::string_view key);
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
    int lua_cache_ttl(std::string_view key) override { return lua_ttl(key); }
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
    void flush_responses(client_connection* conn);
    void flush_write_queue(client_connection* conn);

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
    std::vector<int> m_follower_fds;
    int m_master_fd{-1};
    io_request m_master_read_req{};
    char m_master_read_buf[4096]{};
    std::string m_master_partial;

    void replicate_command(std::string_view cmd);
    void handle_replicate_request(client_connection* conn);
    void send_full_dump(int fd);
    bool connect_to_master();
    void handle_master_read(struct io_uring_cqe* cqe);

    // Provided buffer ring
    static constexpr uint16_t BUF_GROUP_ID = 3;
    static constexpr uint32_t BUF_COUNT = 512;
    static constexpr uint32_t BUF_SIZE = 4096;
    bool m_use_provided_bufs{false};

    // Periodic TTL sweep timer
    io_request m_ttl_req{};
    struct __kernel_timespec m_ttl_ts{};
};
