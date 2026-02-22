#pragma once
#include <string>
#include <string_view>
#include <atomic>
#include <cstdint>
#include <memory>
#include <chrono>
#include <sstream>
#include <vector>
#include <algorithm>
#include <functional>
#include <sys/types.h>

#ifndef SOCKETLEY_NO_LUA
#include <sol/sol.hpp>
#endif
#include <liburing.h>
#include "runtime_definitions.h"
#include "event_loop_definitions.h"

class event_loop;
class lua_context;
class runtime_manager;

class runtime_instance : public io_handler
{
public:
    runtime_instance(runtime_type type, std::string_view name);
    ~runtime_instance() override;

    bool start(event_loop& loop);
    bool stop(event_loop& loop);

    void on_cqe(struct io_uring_cqe* cqe) override = 0;
    virtual bool setup(event_loop& loop) = 0;
    virtual void teardown(event_loop& loop) = 0;

    runtime_state get_state() const;
    runtime_type get_type() const;
    std::string_view get_name() const;
    void set_name(std::string_view name);
    std::string_view get_id() const;
    void set_id(std::string_view id);

    std::chrono::system_clock::time_point get_created_time() const;
    std::chrono::system_clock::time_point get_start_time() const;

    void set_port(uint16_t port);
    uint16_t get_port() const;

    void set_log_file(std::string_view path);
    std::string_view get_log_file() const;

    void set_write_file(std::string_view path);
    std::string_view get_write_file() const;

    void set_test_mode(bool enabled);
    bool get_test_mode() const;

    void set_target(std::string_view target);
    std::string_view get_target() const;

    void set_cache_name(std::string_view name);
    std::string_view get_cache_name() const;

    // Bash output settings
    void set_bash_output(bool enabled);
    void set_bash_prefix(bool enabled);
    void set_bash_timestamp(bool enabled);
    bool get_bash_output() const;
    bool get_bash_prefix() const;
    bool get_bash_timestamp() const;

    // Connection count (virtual, implemented per runtime type)
    virtual size_t get_connection_count() const { return 0; }

    // Max connections
    void set_max_connections(uint32_t max);
    uint32_t get_max_connections() const;

    // Rate limiting (messages per second, 0 = unlimited)
    void set_rate_limit(double rate);
    double get_rate_limit() const;

    // Graceful shutdown
    void set_drain(bool enabled);
    bool get_drain() const;

    // Reconnect (client only)
    void set_reconnect(int max_attempts);
    int get_reconnect() const;

    // TLS
    void set_tls(bool enabled);
    bool get_tls() const;
    void set_cert_path(std::string_view path);
    std::string_view get_cert_path() const;
    void set_key_path(std::string_view path);
    std::string_view get_key_path() const;
    void set_ca_path(std::string_view path);
    std::string_view get_ca_path() const;

    // Stats
    virtual std::string get_stats() const;
    std::atomic<uint64_t> m_stat_total_connections{0};
    std::atomic<uint64_t> m_stat_total_messages{0};
    std::atomic<uint64_t> m_stat_bytes_in{0};
    std::atomic<uint64_t> m_stat_bytes_out{0};

    // Lua hot-reload
    bool reload_lua_script();
    std::string_view get_lua_script_path() const;

    // Interactive mode observer fds
    void add_interactive_fd(int fd);
    void remove_interactive_fd(int fd);
    void notify_interactive(std::string_view msg) const;

    // UDP mode (virtual, implemented by server/client)
    virtual bool is_udp() const { return false; }

    // Ownership system
    void set_owner(std::string_view owner_name);
    std::string_view get_owner() const;
    void set_lua_created(bool v);
    bool is_lua_created() const;

    // External (attach) mode — runtime is managed by another process
    void mark_external();
    bool is_external() const;
    void set_pid(pid_t pid);
    pid_t get_pid() const;

    enum class child_policy { stop, remove };
    void set_child_policy(child_policy p);
    child_policy get_child_policy() const;

    // Runtime manager / event loop (base class — used by Lua management API)
    void set_runtime_manager(runtime_manager* mgr);
    void set_event_loop(event_loop* loop);
    runtime_manager* get_runtime_manager() const;
    event_loop* get_event_loop() const;

    // Lua integration
    bool load_lua_script(std::string_view path);
    lua_context* lua() const { return m_lua.get(); }

    // ── C++ event callbacks (alternative to Lua) ─────────────────────────────
    // If set, the C++ callback is invoked *instead of* the Lua callback for that event.
    // Use set_tick_interval() to control the tick period when not using Lua.
    void set_on_start          (std::function<void()>                         cb);
    void set_on_stop           (std::function<void()>                         cb);
    void set_on_connect        (std::function<void(int fd)>                   cb);
    void set_on_disconnect     (std::function<void(int fd)>                   cb);
    void set_on_client_message (std::function<void(int fd, std::string_view)> cb);
    void set_on_message        (std::function<void(std::string_view)>         cb);
    void set_on_tick           (std::function<void(double dt_ms)>             cb);
    void set_tick_interval     (uint32_t ms);   // tick period in ms; 0 = use Lua value (default)

    // Cross-runtime pub/sub dispatch (called by runtime_manager on publish)
    virtual void on_publish_dispatch(std::string_view cache_name, std::string_view channel, std::string_view message);

    // Virtual methods for Lua actions (overridden by specific runtimes)
    virtual void lua_send(std::string_view msg) {}
    virtual void lua_broadcast(std::string_view msg) {}
    virtual void lua_send_to(int client_id, std::string_view msg) {}

    // Virtual methods for Lua cache access (overridden by cache_instance)
    virtual std::string lua_cache_get(std::string_view key) { return ""; }
    virtual bool lua_cache_set(std::string_view key, std::string_view value) { return false; }
    virtual bool lua_cache_del(std::string_view key) { return false; }

    // Lists
    virtual bool lua_cache_lpush(std::string_view key, std::string_view val) { return false; }
    virtual bool lua_cache_rpush(std::string_view key, std::string_view val) { return false; }
    virtual std::string lua_cache_lpop(std::string_view key) { return ""; }
    virtual std::string lua_cache_rpop(std::string_view key) { return ""; }
    virtual int lua_cache_llen(std::string_view key) { return 0; }

    // Sets
    virtual int lua_cache_sadd(std::string_view key, std::string_view member) { return -1; }
    virtual bool lua_cache_srem(std::string_view key, std::string_view member) { return false; }
    virtual bool lua_cache_sismember(std::string_view key, std::string_view member) { return false; }
    virtual int lua_cache_scard(std::string_view key) { return 0; }

    // Hashes
    virtual bool lua_cache_hset(std::string_view key, std::string_view field, std::string_view val) { return false; }
    virtual std::string lua_cache_hget(std::string_view key, std::string_view field) { return ""; }
    virtual bool lua_cache_hdel(std::string_view key, std::string_view field) { return false; }
    virtual int lua_cache_hlen(std::string_view key) { return 0; }

    // TTL
    virtual bool lua_cache_expire(std::string_view key, int seconds) { return false; }
    virtual int lua_cache_ttl(std::string_view key) { return -2; }
    virtual bool lua_cache_persist(std::string_view key) { return false; }

    // Pub/Sub
    virtual int lua_cache_publish(std::string_view channel, std::string_view message) { return 0; }

protected:
    // Invoke Lua callbacks safely
    void invoke_on_start();
    void invoke_on_stop();
    void invoke_on_message(std::string_view msg);
    void invoke_on_connect(int client_id);
    void invoke_on_disconnect(int client_id);
    bool invoke_on_auth(int client_id);
    void invoke_on_send(std::string_view msg);
    void invoke_on_client_message(int client_id, std::string_view msg);

    // Bash output helper
    void print_bash_message(std::string_view msg) const;

private:
    std::string m_name;
    std::string m_id;
    runtime_type m_type;
    std::atomic<runtime_state> m_state;
    uint16_t m_port = 0;
    bool m_test_mode = false;
    std::string m_log_file;
    std::string m_write_file;
    std::string m_target;
    std::string m_cache_name;
    std::unique_ptr<lua_context> m_lua;

    std::chrono::system_clock::time_point m_created_time;
    std::chrono::system_clock::time_point m_start_time;

    // Bash output settings
    bool m_bash_output = false;
    bool m_bash_prefix = false;
    bool m_bash_timestamp = false;

    // Resource limits
    uint32_t m_max_connections = 0;
    double m_rate_limit = 0.0;

    // Graceful shutdown
    bool m_drain = false;

    // Reconnect
    int m_reconnect = -1; // -1 = disabled, 0 = infinite, >0 = max attempts

    // TLS
    bool m_tls = false;
    std::string m_cert_path;
    std::string m_key_path;
    std::string m_ca_path;

    // Lua script path for hot-reload
    std::string m_lua_script_path;

    // C++ event callbacks
    std::function<void()>                        m_cb_on_start;
    std::function<void()>                        m_cb_on_stop;
    std::function<void(int)>                     m_cb_on_connect;
    std::function<void(int)>                     m_cb_on_disconnect;
    std::function<void(int, std::string_view)>   m_cb_on_client_message;
    std::function<void(std::string_view)>        m_cb_on_message;
    std::function<void(double)>                  m_cb_on_tick;
    uint32_t                                     m_cb_tick_ms = 0;

    // Interactive mode observer fds (IPC sockets)
    std::vector<int> m_interactive_fds;

    // Ownership
    std::string m_owner;
    bool m_lua_created = false;
    bool m_external = false;
    pid_t m_pid = 0;           // PID of external process (used by stop() to send SIGTERM)
    child_policy m_child_policy = child_policy::stop;

    // Runtime manager / event loop (base class)
    runtime_manager* m_runtime_manager = nullptr;
    event_loop* m_event_loop = nullptr;

    // Tick timer
    struct tick_handler : io_handler {
        runtime_instance* rt{nullptr};
        io_request req{};
        struct __kernel_timespec ts{};
        std::chrono::steady_clock::time_point last{};
        void on_cqe(struct io_uring_cqe* cqe) override;
    };
    tick_handler* m_tick{nullptr};
    void start_tick_timer();
    void fire_tick(int res);
};
