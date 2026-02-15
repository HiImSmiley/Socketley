#include "lua_context.h"
#include "runtime_instance.h"
#include "runtime_definitions.h"
#include <iostream>

lua_context::lua_context()
{
    m_lua.open_libraries(sol::lib::base, sol::lib::string, sol::lib::table, sol::lib::math, sol::lib::os);
}

static const char* type_to_string(runtime_type t)
{
    switch (t)
    {
        case runtime_server: return "server";
        case runtime_client: return "client";
        case runtime_proxy:  return "proxy";
        case runtime_cache:  return "cache";
    }
    return "unknown";
}

static const char* state_to_string(runtime_state s)
{
    switch (s)
    {
        case runtime_created: return "created";
        case runtime_running: return "running";
        case runtime_stopped: return "stopped";
        case runtime_failed:  return "failed";
    }
    return "unknown";
}

bool lua_context::load_script(std::string_view path, runtime_instance* owner)
{
    register_bindings(owner);

    auto result = m_lua.safe_script_file(std::string(path), sol::script_pass_on_error);
    if (!result.valid())
    {
        sol::error err = result;
        std::cerr << "[lua] script error: " << err.what() << std::endl;
        return false;
    }

    m_on_start = m_lua["on_start"];
    m_on_stop = m_lua["on_stop"];
    m_on_message = m_lua["on_message"];
    m_on_send = m_lua["on_send"];
    m_on_connect = m_lua["on_connect"];
    m_on_disconnect = m_lua["on_disconnect"];
    m_on_route = m_lua["on_route"];
    m_on_master_auth = m_lua["on_master_auth"];

    return true;
}

bool lua_context::has_on_start() const { return m_on_start.valid(); }
bool lua_context::has_on_stop() const { return m_on_stop.valid(); }
bool lua_context::has_on_message() const { return m_on_message.valid(); }
bool lua_context::has_on_send() const { return m_on_send.valid(); }
bool lua_context::has_on_connect() const { return m_on_connect.valid(); }
bool lua_context::has_on_disconnect() const { return m_on_disconnect.valid(); }
bool lua_context::has_on_route() const { return m_on_route.valid(); }
bool lua_context::has_on_master_auth() const { return m_on_master_auth.valid(); }

void lua_context::update_self_state(const char* state_str)
{
    sol::optional<sol::table> self = m_lua["self"];
    if (self)
        (*self)["state"] = state_str;
}

void lua_context::register_bindings(runtime_instance* owner)
{
    // Register socketley.log()
    sol::table sk = m_lua.create_table();
    sk["log"] = [](std::string msg) {
        std::cerr << "[lua] " << msg << std::endl;
    };
    m_lua["socketley"] = sk;

    // Register "self" table with runtime properties and actions
    sol::table self = m_lua.create_table();
    self["name"] = std::string(owner->get_name());
    self["port"] = owner->get_port();
    self["type"] = type_to_string(owner->get_type());
    self["state"] = state_to_string(owner->get_state());

    // Register type-specific action methods
    switch (owner->get_type())
    {
        case runtime_server:
            register_server_table(owner, self);
            break;
        case runtime_client:
            register_client_table(owner, self);
            break;
        case runtime_cache:
            register_cache_table(owner, self);
            break;
        case runtime_proxy:
            register_proxy_table(owner, self);
            break;
    }

    m_lua["self"] = self;

    // Also register type-specific alias (server/client/cache/proxy) pointing to same table
    m_lua[type_to_string(owner->get_type())] = self;
}

void lua_context::register_server_table(runtime_instance* owner, sol::table& self)
{
    self["broadcast"] = [owner](std::string msg) {
        owner->lua_broadcast(msg);
    };
    self["send"] = [owner](int client_id, std::string msg) {
        owner->lua_send_to(client_id, msg);
    };
    self["connections"] = [owner]() -> size_t {
        return owner->get_connection_count();
    };
    self["protocol"] = owner->is_udp() ? "udp" : "tcp";
}

void lua_context::register_client_table(runtime_instance* owner, sol::table& self)
{
    self["send"] = [owner](std::string msg) {
        owner->lua_send(msg);
    };
    self["connections"] = [owner]() -> size_t {
        return owner->get_connection_count();
    };
    self["protocol"] = owner->is_udp() ? "udp" : "tcp";
}

void lua_context::register_cache_table(runtime_instance* owner, sol::table& self)
{
    // Strings
    self["get"] = [owner](std::string key) -> std::string {
        return owner->lua_cache_get(key);
    };
    self["set"] = [owner](std::string key, std::string value) -> bool {
        return owner->lua_cache_set(key, value);
    };
    self["del"] = [owner](std::string key) -> bool {
        return owner->lua_cache_del(key);
    };

    // Lists
    self["lpush"] = [owner](std::string key, std::string val) -> bool {
        return owner->lua_cache_lpush(key, val);
    };
    self["rpush"] = [owner](std::string key, std::string val) -> bool {
        return owner->lua_cache_rpush(key, val);
    };
    self["lpop"] = [owner](std::string key) -> std::string {
        return owner->lua_cache_lpop(key);
    };
    self["rpop"] = [owner](std::string key) -> std::string {
        return owner->lua_cache_rpop(key);
    };
    self["llen"] = [owner](std::string key) -> int {
        return owner->lua_cache_llen(key);
    };

    // Sets
    self["sadd"] = [owner](std::string key, std::string member) -> int {
        return owner->lua_cache_sadd(key, member);
    };
    self["srem"] = [owner](std::string key, std::string member) -> bool {
        return owner->lua_cache_srem(key, member);
    };
    self["sismember"] = [owner](std::string key, std::string member) -> bool {
        return owner->lua_cache_sismember(key, member);
    };
    self["scard"] = [owner](std::string key) -> int {
        return owner->lua_cache_scard(key);
    };

    // Hashes
    self["hset"] = [owner](std::string key, std::string field, std::string val) -> bool {
        return owner->lua_cache_hset(key, field, val);
    };
    self["hget"] = [owner](std::string key, std::string field) -> std::string {
        return owner->lua_cache_hget(key, field);
    };
    self["hdel"] = [owner](std::string key, std::string field) -> bool {
        return owner->lua_cache_hdel(key, field);
    };
    self["hlen"] = [owner](std::string key) -> int {
        return owner->lua_cache_hlen(key);
    };

    // TTL
    self["expire"] = [owner](std::string key, int seconds) -> bool {
        return owner->lua_cache_expire(key, seconds);
    };
    self["ttl"] = [owner](std::string key) -> int {
        return owner->lua_cache_ttl(key);
    };
    self["persist"] = [owner](std::string key) -> bool {
        return owner->lua_cache_persist(key);
    };

    // Pub/Sub
    self["publish"] = [owner](std::string channel, std::string message) -> int {
        return owner->lua_cache_publish(channel, message);
    };

    self["connections"] = [owner]() -> size_t {
        return owner->get_connection_count();
    };
}

void lua_context::register_proxy_table(runtime_instance* owner, sol::table& self)
{
    self["connections"] = [owner]() -> size_t {
        return owner->get_connection_count();
    };
}
