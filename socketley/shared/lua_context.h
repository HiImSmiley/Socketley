#pragma once
#include <sol/sol.hpp>
#include <memory>
#include <string>
#include <string_view>

class runtime_instance;

// Lua context for a runtime - manages state and bindings
class lua_context
{
public:
    lua_context();
    ~lua_context() = default;

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
    uint32_t get_tick_ms() const { return m_tick_ms; }

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
    uint32_t m_tick_ms{0};
};
