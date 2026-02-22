#include "lua_context.h"

#ifndef SOCKETLEY_NO_LUA

#include "runtime_instance.h"
#include "runtime_definitions.h"
#include "runtime_manager.h"
#include "event_loop.h"
#include "../runtime/server/server_instance.h"
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
    m_on_client_message = m_lua["on_client_message"];
    m_on_tick = m_lua["on_tick"];
    if (m_on_tick.valid()) {
        sol::optional<int> tms = m_lua["tick_ms"];
        m_tick_ms = (tms && *tms >= 10) ? static_cast<uint32_t>(*tms) : 100;
    }
    m_on_miss   = m_lua["on_miss"];
    m_on_write  = m_lua["on_write"];
    m_on_delete = m_lua["on_delete"];
    m_on_expire = m_lua["on_expire"];

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
bool lua_context::has_on_client_message() const { return m_on_client_message.valid(); }
bool lua_context::has_on_tick() const { return m_on_tick.valid(); }
bool lua_context::has_on_miss()   const { return m_on_miss.valid(); }
bool lua_context::has_on_write()  const { return m_on_write.valid(); }
bool lua_context::has_on_delete() const { return m_on_delete.valid(); }
bool lua_context::has_on_expire() const { return m_on_expire.valid(); }

void lua_context::update_self_state(const char* state_str)
{
    sol::optional<sol::table> self = m_lua["self"];
    if (self)
        (*self)["state"] = state_str;
}

static bool parse_type_string(const std::string& s, runtime_type& t)
{
    if (s == "server") { t = runtime_server; return true; }
    if (s == "client") { t = runtime_client; return true; }
    if (s == "proxy")  { t = runtime_proxy;  return true; }
    if (s == "cache")  { t = runtime_cache;  return true; }
    return false;
}

void lua_context::register_bindings(runtime_instance* owner)
{
    // Register socketley.log() and management API
    sol::table sk = m_lua.create_table();
    sk["log"] = [](std::string msg) {
        std::cerr << "[lua] " << msg << std::endl;
    };

    // socketley.create(type, name, config_table) → bool
    sk["create"] = [owner, this](std::string type_str, std::string name, sol::optional<sol::table> config) -> bool {
        auto* mgr = owner->get_runtime_manager();
        auto* loop = owner->get_event_loop();
        if (!mgr || !loop) return false;

        runtime_type type;
        if (!parse_type_string(type_str, type)) return false;

        if (!mgr->create(type, name)) return false;

        auto* inst = mgr->get(name);
        if (!inst) return false;

        inst->set_runtime_manager(mgr);
        inst->set_event_loop(loop);
        inst->set_owner(owner->get_name());
        inst->set_lua_created(true);

        if (config) {
            sol::optional<int> port = (*config)["port"];
            if (port) inst->set_port(static_cast<uint16_t>(*port));

            sol::optional<std::string> lua_script = (*config)["config"];
            if (!lua_script) lua_script = (*config)["lua"];
            if (lua_script && !lua_script->empty())
                inst->load_lua_script(*lua_script);

            sol::optional<std::string> target = (*config)["target"];
            if (target) inst->set_target(*target);

            sol::optional<std::string> mode_str = (*config)["mode"];
            if (mode_str && type == runtime_server) {
                auto* srv = static_cast<server_instance*>(inst);
                if (*mode_str == "in") srv->set_mode(mode_in);
                else if (*mode_str == "out") srv->set_mode(mode_out);
                else if (*mode_str == "master") srv->set_mode(mode_master);
                else srv->set_mode(mode_inout);
            }

            sol::optional<std::string> on_stop_str = (*config)["on_parent_stop"];
            if (on_stop_str && *on_stop_str == "remove")
                inst->set_child_policy(runtime_instance::child_policy::remove);

            sol::optional<bool> autostart = (*config)["autostart"];
            if (autostart && *autostart)
                mgr->run(name, *loop);
        }

        return true;
    };

    // socketley.start(name) → bool
    sk["start"] = [owner](std::string name) -> bool {
        auto* mgr = owner->get_runtime_manager();
        auto* loop = owner->get_event_loop();
        if (!mgr || !loop) return false;
        return mgr->run(name, *loop);
    };

    // socketley.stop(name) → bool
    sk["stop"] = [owner](std::string name) -> bool {
        auto* mgr = owner->get_runtime_manager();
        auto* loop = owner->get_event_loop();
        if (!mgr || !loop) return false;
        return mgr->stop(name, *loop);
    };

    // socketley.remove(name) → bool
    sk["remove"] = [owner](std::string name) -> bool {
        auto* mgr = owner->get_runtime_manager();
        auto* loop = owner->get_event_loop();
        if (!mgr || !loop) return false;
        auto* inst = mgr->get(name);
        if (inst && inst->get_state() == runtime_running)
            mgr->stop(name, *loop);
        return mgr->remove(name);
    };

    // socketley.send(name, msg) → bool
    sk["send"] = [owner](std::string name, std::string msg) -> bool {
        auto* mgr = owner->get_runtime_manager();
        if (!mgr) return false;
        auto* inst = mgr->get(name);
        if (!inst || inst->get_state() != runtime_running) return false;
        if (inst->get_type() == runtime_server)
            inst->lua_broadcast(msg);
        else
            inst->lua_send(msg);
        return true;
    };

    // socketley.list() → table of names
    sk["list"] = [owner, this]() -> sol::table {
        sol::table result = m_lua.create_table();
        auto* mgr = owner->get_runtime_manager();
        if (!mgr) return result;
        std::shared_lock lock(mgr->mutex);
        int i = 1;
        for (const auto& [name, _] : mgr->list())
            result[i++] = name;
        return result;
    };

    // socketley.get(name) → table {name, type, state, port, connections, owner} or nil
    sk["get"] = [owner, this](std::string name) -> sol::object {
        auto* mgr = owner->get_runtime_manager();
        if (!mgr) return sol::nil;
        auto* inst = mgr->get(name);
        if (!inst) return sol::nil;
        sol::table info = m_lua.create_table();
        info["name"] = std::string(inst->get_name());
        info["type"] = type_to_string(inst->get_type());
        info["state"] = state_to_string(inst->get_state());
        info["port"] = inst->get_port();
        info["connections"] = inst->get_connection_count();
        auto ow = inst->get_owner();
        info["owner"] = ow.empty() ? sol::object(sol::nil) : sol::make_object(m_lua, std::string(ow));
        return info;
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

    // Client routing
    self["route"] = [owner](int client_id, std::string target) -> bool {
        return static_cast<server_instance*>(owner)->route_client(client_id, target);
    };
    self["unroute"] = [owner](int client_id) -> bool {
        return static_cast<server_instance*>(owner)->unroute_client(client_id);
    };
    self["get_route"] = [owner, this](int client_id) -> sol::object {
        auto route = static_cast<server_instance*>(owner)->get_client_route(client_id);
        if (route.empty()) return sol::nil;
        return sol::make_object(m_lua, std::string(route));
    };

    // Owner-targeted sending (sub-server → owner's clients)
    self["owner_send"] = [owner](int client_id, std::string msg) -> bool {
        return static_cast<server_instance*>(owner)->owner_send(client_id, msg);
    };
    self["owner_broadcast"] = [owner](std::string msg) -> bool {
        return static_cast<server_instance*>(owner)->owner_broadcast(msg);
    };
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

#endif // SOCKETLEY_NO_LUA
