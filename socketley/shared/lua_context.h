#pragma once

#ifndef SOCKETLEY_NO_LUA

#include <sol/sol.hpp>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

class runtime_instance;

// Lua context for a runtime - manages state and bindings
class lua_context
{
public:
    lua_context();
    ~lua_context();

    // Load and execute a Lua script, registering callbacks
    bool load_script(std::string_view path, runtime_instance* owner);

    // Get the Lua state (for callback invocation)
    sol::state& state() { return m_lua; }

    // Update self.state to reflect current runtime state
    void update_self_state(const char* state_str);

    // Callback bitmask constants
    enum : uint32_t {
        CB_ON_START              = 1u << 0,
        CB_ON_STOP               = 1u << 1,
        CB_ON_MESSAGE            = 1u << 2,
        CB_ON_SEND               = 1u << 3,
        CB_ON_CONNECT            = 1u << 4,
        CB_ON_DISCONNECT         = 1u << 5,
        CB_ON_ROUTE              = 1u << 6,
        CB_ON_MASTER_AUTH        = 1u << 7,
        CB_ON_CLIENT_MESSAGE     = 1u << 8,
        CB_ON_TICK               = 1u << 9,
        CB_ON_MISS               = 1u << 10,
        CB_ON_WRITE              = 1u << 11,
        CB_ON_DELETE             = 1u << 12,
        CB_ON_EXPIRE             = 1u << 13,
        CB_ON_AUTH               = 1u << 14,
        CB_ON_WEBSOCKET          = 1u << 15,
        CB_ON_PROXY_REQUEST      = 1u << 16,
        CB_ON_PROXY_RESPONSE     = 1u << 17,
        CB_ON_CLUSTER_JOIN       = 1u << 18,
        CB_ON_CLUSTER_LEAVE      = 1u << 19,
        CB_ON_GROUP_CHANGE       = 1u << 20,
        CB_ON_UPSTREAM           = 1u << 21,
        CB_ON_UPSTREAM_CONNECT   = 1u << 22,
        CB_ON_UPSTREAM_DISCONNECT = 1u << 23,
        CB_ON_HTTP_REQUEST       = 1u << 24,
    };

    // Check if context has valid callbacks (bitmask lookup)
    bool has_on_start()              const { return m_callback_mask & CB_ON_START; }
    bool has_on_stop()               const { return m_callback_mask & CB_ON_STOP; }
    bool has_on_message()            const { return m_callback_mask & CB_ON_MESSAGE; }
    bool has_on_send()               const { return m_callback_mask & CB_ON_SEND; }
    bool has_on_connect()            const { return m_callback_mask & CB_ON_CONNECT; }
    bool has_on_disconnect()         const { return m_callback_mask & CB_ON_DISCONNECT; }
    bool has_on_route()              const { return m_callback_mask & CB_ON_ROUTE; }
    bool has_on_master_auth()        const { return m_callback_mask & CB_ON_MASTER_AUTH; }
    bool has_on_client_message()     const { return m_callback_mask & CB_ON_CLIENT_MESSAGE; }
    bool has_on_tick()               const { return m_callback_mask & CB_ON_TICK; }
    bool has_on_miss()               const { return m_callback_mask & CB_ON_MISS; }
    bool has_on_write()              const { return m_callback_mask & CB_ON_WRITE; }
    bool has_on_delete()             const { return m_callback_mask & CB_ON_DELETE; }
    bool has_on_expire()             const { return m_callback_mask & CB_ON_EXPIRE; }
    bool has_on_auth()               const { return m_callback_mask & CB_ON_AUTH; }
    bool has_on_websocket()          const { return m_callback_mask & CB_ON_WEBSOCKET; }
    bool has_on_proxy_request()      const { return m_callback_mask & CB_ON_PROXY_REQUEST; }
    bool has_on_proxy_response()     const { return m_callback_mask & CB_ON_PROXY_RESPONSE; }
    bool has_on_cluster_join()       const { return m_callback_mask & CB_ON_CLUSTER_JOIN; }
    bool has_on_cluster_leave()      const { return m_callback_mask & CB_ON_CLUSTER_LEAVE; }
    bool has_on_group_change()       const { return m_callback_mask & CB_ON_GROUP_CHANGE; }
    bool has_on_upstream()           const { return m_callback_mask & CB_ON_UPSTREAM; }
    bool has_on_upstream_connect()   const { return m_callback_mask & CB_ON_UPSTREAM_CONNECT; }
    bool has_on_upstream_disconnect() const { return m_callback_mask & CB_ON_UPSTREAM_DISCONNECT; }
    bool has_on_http_request()       const { return m_callback_mask & CB_ON_HTTP_REQUEST; }

    // Get callbacks
    sol::function& on_start() { return m_on_start; }
    sol::function& on_stop() { return m_on_stop; }
    sol::function& on_message() { return m_on_message; }
    sol::function& on_send() { return m_on_send; }
    sol::function& on_connect() { return m_on_connect; }
    sol::function& on_disconnect() { return m_on_disconnect; }
    sol::function& on_route() { return m_on_route; }
    sol::function& on_master_auth() { return m_on_master_auth; }
    sol::function& on_client_message() { return m_on_client_message; }
    sol::function& on_tick() { return m_on_tick; }
    sol::function& on_miss()      { return m_on_miss; }
    sol::function& on_write()     { return m_on_write; }
    sol::function& on_delete_cb() { return m_on_delete; }  // avoid clash with std::delete
    sol::function& on_expire()    { return m_on_expire; }
    sol::function& on_auth()        { return m_on_auth; }
    sol::function& on_websocket()   { return m_on_websocket; }
    sol::function& on_proxy_request()  { return m_on_proxy_request; }
    sol::function& on_proxy_response() { return m_on_proxy_response; }
    sol::function& on_cluster_join()   { return m_on_cluster_join; }
    sol::function& on_cluster_leave()  { return m_on_cluster_leave; }
    sol::function& on_group_change()   { return m_on_group_change; }
    sol::function& on_upstream()           { return m_on_upstream; }
    sol::function& on_upstream_connect()   { return m_on_upstream_connect; }
    sol::function& on_upstream_disconnect() { return m_on_upstream_disconnect; }
    sol::function& on_http_request()       { return m_on_http_request; }
    uint32_t get_tick_ms() const { return m_tick_ms; }

    // Cross-runtime pub/sub dispatch (called from runtime_instance)
    void dispatch_publish(std::string_view cache_name, std::string_view channel, std::string_view message);

private:
    void register_bindings(runtime_instance* owner);
    void register_server_table(runtime_instance* owner, sol::table& self);
    void register_client_table(runtime_instance* owner, sol::table& self);
    void register_cache_table(runtime_instance* owner, sol::table& self);
    void register_proxy_table(runtime_instance* owner, sol::table& self);

    sol::state m_lua;
    sol::function m_on_start;
    sol::function m_on_stop;
    sol::function m_on_message;
    sol::function m_on_send;
    sol::function m_on_connect;
    sol::function m_on_disconnect;
    sol::function m_on_route;
    sol::function m_on_master_auth;
    sol::function m_on_client_message;
    sol::function m_on_tick;
    sol::function m_on_miss;
    sol::function m_on_write;
    sol::function m_on_delete;
    sol::function m_on_expire;
    sol::function m_on_auth;
    sol::function m_on_websocket;
    sol::function m_on_proxy_request;
    sol::function m_on_proxy_response;
    sol::function m_on_cluster_join;
    sol::function m_on_cluster_leave;
    sol::function m_on_group_change;
    sol::function m_on_upstream;
    sol::function m_on_upstream_connect;
    sol::function m_on_upstream_disconnect;
    sol::function m_on_http_request;
    uint32_t m_tick_ms{0};
    uint32_t m_callback_mask{0};

    // Timer lifetime guard — set to false in destructor; timers check before firing
    std::shared_ptr<bool> m_alive{std::make_shared<bool>(true)};

    // Active timers — tracked so we can clear sol::function refs before Lua state closes
    std::vector<void*> m_active_timers;

public:
    void unregister_timer(void* t);
private:

    // Cross-runtime pub/sub: key = cache_name + '\0' + channel
    std::unordered_map<std::string, std::vector<sol::function>> m_subscriptions;

    // Timer cancellation: ID → timer* mapping
    int m_next_timer_id{0};
    std::unordered_map<int, void*> m_timer_map;

    // Timer pool to avoid per-timer heap allocation
    std::vector<void*> m_timer_pool;
public:
    void* timer_pool_acquire();
    void timer_pool_release(void* t);
private:
};

#else // SOCKETLEY_NO_LUA

#include <string>
#include <string_view>
#include <cstdint>

class runtime_instance;

// No-op stub — same public interface, no LuaJIT required
class lua_context
{
public:
    lua_context() = default;
    ~lua_context() = default;

    bool load_script(std::string_view, runtime_instance*) { return true; }
    void update_self_state(const char*) {}

    bool has_on_start()          const { return false; }
    bool has_on_stop()           const { return false; }
    bool has_on_message()        const { return false; }
    bool has_on_send()           const { return false; }
    bool has_on_connect()        const { return false; }
    bool has_on_disconnect()     const { return false; }
    bool has_on_route()          const { return false; }
    bool has_on_master_auth()    const { return false; }
    bool has_on_client_message() const { return false; }
    bool has_on_tick()           const { return false; }
    bool has_on_miss()           const { return false; }
    bool has_on_write()          const { return false; }
    bool has_on_delete()         const { return false; }
    bool has_on_expire()         const { return false; }
    bool has_on_auth()           const { return false; }
    bool has_on_websocket()      const { return false; }
    bool has_on_proxy_request()  const { return false; }
    bool has_on_proxy_response() const { return false; }
    bool has_on_cluster_join()   const { return false; }
    bool has_on_cluster_leave()  const { return false; }
    bool has_on_group_change()   const { return false; }
    bool has_on_upstream()           const { return false; }
    bool has_on_upstream_connect()   const { return false; }
    bool has_on_upstream_disconnect() const { return false; }
    bool has_on_http_request()       const { return false; }
    uint32_t get_tick_ms()       const { return 0; }
    void dispatch_publish(std::string_view, std::string_view, std::string_view) {}
    // on_*() callbacks omitted — only called when has_*() returns true,
    // and guarded by #ifndef SOCKETLEY_NO_LUA at each call site.
};

#endif // SOCKETLEY_NO_LUA
