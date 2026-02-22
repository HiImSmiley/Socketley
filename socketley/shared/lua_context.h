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

    // Check if context has valid callbacks
    bool has_on_start() const;
    bool has_on_stop() const;
    bool has_on_message() const;
    bool has_on_send() const;
    bool has_on_connect() const;
    bool has_on_disconnect() const;
    bool has_on_route() const;
    bool has_on_master_auth() const;
    bool has_on_client_message() const;
    bool has_on_tick() const;
    bool has_on_miss() const;
    bool has_on_write() const;
    bool has_on_delete() const;
    bool has_on_expire() const;
    bool has_on_auth() const;
    bool has_on_websocket() const;
    bool has_on_proxy_request()  const;
    bool has_on_proxy_response() const;

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
    uint32_t m_tick_ms{0};

    // Timer lifetime guard — set to false in destructor; timers check before firing
    std::shared_ptr<bool> m_alive{std::make_shared<bool>(true)};

    // Cross-runtime pub/sub: key = cache_name + '\0' + channel
    std::unordered_map<std::string, std::vector<sol::function>> m_subscriptions;
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
    uint32_t get_tick_ms()       const { return 0; }
    void dispatch_publish(std::string_view, std::string_view, std::string_view) {}
    // on_*() callbacks omitted — only called when has_*() returns true,
    // and guarded by #ifndef SOCKETLEY_NO_LUA at each call site.
};

#endif // SOCKETLEY_NO_LUA
