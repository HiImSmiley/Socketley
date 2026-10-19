#include "mqtt_lua.h"

#include <iostream>

#include "mqtt_instance.h"
#include "mqtt_run.h"

#ifndef SOCKETLEY_NO_LUA
#include "mqtt_lua_table.h"
#include "../../shared/lua/lua_context.h"
#include "../../shared/lua/lua_suspend.h"
#endif

namespace socketley::mqtt
{

mqtt_lua::mqtt_lua(mqtt_instance& owner) : m_owner(owner) {}

#ifndef SOCKETLEY_NO_LUA

namespace
{

const char* version_text(uint8_t level)
{
    return level == level_5 ? "5.0" : level == level_311 ? "3.1.1" : "3.1";
}

sol::table client_table(sol::state& L, const client_info& c)
{
    sol::table t = L.create_table(0, 5);
    t["id"]       = c.client_id;
    t["username"] = c.username;
    t["peer"]     = c.peer;
    t["version"]  = version_text(c.level);
    return t;
}

// What a deciding hook returned: nil keeps the default, true allows and false refuses.
enum class word : uint8_t { keep, yes, no };

word verdict_of(lua_State* th, int n, const char* error, std::string_view hook, std::string_view owner)
{
    if (error)
    {
        std::cerr << lua_diag::tag(owner) << " " << hook << " " << error << " -- refused\n";
        return word::no;
    }
    if (n < 1 || lua_isnil(th, 1))
        return word::keep;
    if (lua_type(th, 1) == LUA_TBOOLEAN)
        return lua_toboolean(th, 1) ? word::yes : word::no;
    return word::keep;
}

}   // namespace

bool mqtt_lua::wants_auth() const
{
    const lua_context* lua = m_owner.lua();
    return lua && lua->has_on_auth();
}

bool mqtt_lua::wants_publish() const
{
    const lua_context* lua = m_owner.lua();
    return lua && lua->has_on_publish();
}

bool mqtt_lua::wants_subscribe() const
{
    const lua_context* lua = m_owner.lua();
    return lua && lua->has_on_subscribe();
}

void mqtt_lua::auth(const auth_ask& ask, bool verified, bool allowed, const std::string& username,
                    std::function<void(bool)> done)
{
    lua_context* lua = m_owner.lua();
    if (!lua || !lua->has_on_auth())
    {
        done(allowed);
        return;
    }
    sol::state& L = lua->state();
    sol::table t = L.create_table(0, 8);
    t["id"]            = ask.client_id;
    t["username"]      = ask.username.value_or("");
    if (ask.password)
        t["password"]  = *ask.password;
    t["peer"]          = ask.peer;
    t["certificate"]   = ask.cert_cn;
    t["authenticated"] = verified;
    t["account"]       = username;
    t["version"]       = version_text(ask.level);
    const std::string owner(m_owner.get_name());
    // Saying nothing keeps what the credentials and --anonymous decided.
    const bool by_default = allowed;
    auto& sus = lua->suspender();
    sus.set_next_result([done, owner, by_default](lua_State* th, int n, const char* error) {
        const word w = verdict_of(th, n, error, "on_auth", owner);
        done(w == word::yes || (w == word::keep && by_default));
    });
    lua_suspender::id_t id = 0;
    sus.start(lua->raw_on_auth(), "on_auth", lua->callback_timeout_ms(), id, t);
}

void mqtt_lua::publish(const client_info& c, const message_ptr& m, std::function<void(publish_verdict)> done)
{
    lua_context* lua = m_owner.lua();
    if (!lua || !lua->has_on_publish())
    {
        done({});
        return;
    }
    sol::state& L = lua->state();
    sol::table msg = L.create_table(0, 4);
    msg["topic"]   = m->topic;
    msg["payload"] = m->payload;
    msg["qos"]     = m->qos;
    msg["retain"]  = m->retain;
    const std::string owner(m_owner.get_name());
    auto& sus = lua->suspender();
    sus.set_next_result([done, owner, m](lua_State* th, int n, const char* error) {
        publish_verdict v;
        if (!error && n >= 1 && lua_type(th, 1) == LUA_TTABLE)
        {
            // A table is the message as it is to go on.
            auto out = std::make_shared<message>(*m);
            lua_getfield(th, 1, "topic");
            if (lua_type(th, -1) == LUA_TSTRING)
                out->topic = lua_tostring(th, -1);
            lua_pop(th, 1);
            lua_getfield(th, 1, "payload");
            if (lua_type(th, -1) == LUA_TSTRING || lua_type(th, -1) == LUA_TNUMBER)
            {
                size_t len = 0;
                const char* p = lua_tolstring(th, -1, &len);
                out->payload.assign(p, len);
            }
            lua_pop(th, 1);
            lua_getfield(th, 1, "qos");
            if (lua_type(th, -1) == LUA_TNUMBER)
            {
                const lua_Integer q = lua_tointeger(th, -1);
                if (q >= 0 && q <= 2)
                    out->qos = static_cast<uint8_t>(q);
            }
            lua_pop(th, 1);
            lua_getfield(th, 1, "retain");
            if (lua_type(th, -1) == LUA_TBOOLEAN)
                out->retain = lua_toboolean(th, -1) != 0;
            lua_pop(th, 1);
            v.replace = std::move(out);
            done(std::move(v));
            return;
        }
        v.allow = verdict_of(th, n, error, "on_publish", owner) != word::no;
        done(std::move(v));
    });
    lua_suspender::id_t id = 0;
    sus.start(lua->raw_on_publish(), "on_publish", lua->callback_timeout_ms(), id, client_table(L, c), msg);
}

void mqtt_lua::subscribe(const client_info& c, const std::string& filter, uint8_t qos, std::function<void(bool)> done)
{
    lua_context* lua = m_owner.lua();
    if (!lua || !lua->has_on_subscribe())
    {
        done(true);
        return;
    }
    sol::state& L = lua->state();
    const std::string owner(m_owner.get_name());
    auto& sus = lua->suspender();
    sus.set_next_result([done, owner](lua_State* th, int n, const char* error) {
        done(verdict_of(th, n, error, "on_subscribe", owner) != word::no);
    });
    lua_suspender::id_t id = 0;
    sus.start(lua->raw_on_subscribe(), "on_subscribe", lua->callback_timeout_ms(), id, client_table(L, c), filter,
              static_cast<int>(qos));
}

void mqtt_lua::connected(const client_info& c)
{
    lua_context* lua = m_owner.lua();
    if (!lua || !lua->has_on_connect())
        return;
    lua_suspender::id_t id = 0;
    lua->suspender().start(lua->raw_on_connect(), "on_connect", lua->callback_timeout_ms(), id,
                           client_table(lua->state(), c));
}

void mqtt_lua::disconnected(const client_info& c, std::string_view why)
{
    lua_context* lua = m_owner.lua();
    if (!lua || !lua->has_on_disconnect())
        return;
    lua_suspender::id_t id = 0;
    lua->suspender().start(lua->raw_on_disconnect(), "on_disconnect", lua->callback_timeout_ms(), id,
                           client_table(lua->state(), c), std::string(why));
}

void register_lua_table(runtime_instance* owner, sol::state& lua, sol::table& self)
{
    auto* rt = static_cast<mqtt_instance*>(owner);
    // self.publish(topic, payload [, {qos=, retain=}]) -- a message from the script, as the operator's own.
    self["publish"] = [rt](std::string topic, sol::object payload, sol::optional<sol::table> opts,
                           sol::this_state ts) -> std::tuple<sol::object, sol::object> {
        sol::state_view L(ts);
        auto* run = rt->run();
        if (!run)
            return {sol::make_object(L, sol::lua_nil), sol::make_object(L, "the broker is not running")};
        if (!valid_topic(topic) || topic.front() == '$')
            return {sol::make_object(L, sol::lua_nil),
                    sol::make_object(L, "`" + topic + "` is not a topic a message can be published to")};
        message m;
        m.topic = std::move(topic);
        if (payload.get_type() == sol::type::string || payload.get_type() == sol::type::number)
            m.payload = payload.as<std::string>();
        if (opts)
        {
            const int q = opts->get_or("qos", 0);
            m.qos = static_cast<uint8_t>(q < 0 ? 0 : q > 2 ? 2 : q);
            m.retain = opts->get_or("retain", false);
        }
        run->core().publish(std::move(m));
        return {sol::make_object(L, true), sol::make_object(L, sol::lua_nil)};
    };
    // self.retained(topic) -- the payload retained on a topic, nil when there is none.
    self["retained"] = [rt](std::string topic, sol::this_state ts) -> sol::object {
        sol::state_view L(ts);
        auto* run = rt->run();
        if (!run)
            return sol::make_object(L, sol::lua_nil);
        sol::object out = sol::make_object(L, sol::lua_nil);
        run->core().retained_each(topic, [&](const message_ptr& m) {
            if (m->topic == topic)
                out = sol::make_object(L, m->payload);
        });
        return out;
    };
    // self.sessions() -- every session this shard holds, connected or waiting for its client.
    self["sessions"] = [rt](sol::this_state ts) -> sol::table {
        sol::state_view L(ts);
        sol::table out = L.create_table();
        auto* run = rt->run();
        if (!run)
            return out;
        int i = 1;
        for (const auto& s : run->core().sessions())
        {
            sol::table t = L.create_table(0, 7);
            t["id"]            = s.client_id;
            t["username"]      = s.username;
            t["connected"]     = s.connected;
            t["subscriptions"] = static_cast<double>(s.subscriptions);
            t["queued"]        = static_cast<double>(s.queued);
            t["inflight"]      = static_cast<double>(s.inflight);
            t["peer"]          = s.peer;
            out[i++] = t;
        }
        return out;
    };
    // self.kick(client_id [, end_session]) -- the client disconnected, its session ended too when asked.
    self["kick"] = [rt](std::string id, sol::optional<bool> end) -> bool {
        auto* run = rt->run();
        return run && run->core().kick(id, end.value_or(false));
    };
    (void)lua;
}

#else   // SOCKETLEY_NO_LUA

bool mqtt_lua::wants_auth() const { return false; }
bool mqtt_lua::wants_publish() const { return false; }
bool mqtt_lua::wants_subscribe() const { return false; }
void mqtt_lua::auth(const auth_ask&, bool, bool allowed, const std::string&, std::function<void(bool)> done)
{
    done(allowed);
}
void mqtt_lua::publish(const client_info&, const message_ptr&, std::function<void(publish_verdict)> done) { done({}); }
void mqtt_lua::subscribe(const client_info&, const std::string&, uint8_t, std::function<void(bool)> done) { done(true); }
void mqtt_lua::connected(const client_info&) {}
void mqtt_lua::disconnected(const client_info&, std::string_view) {}

#endif

}   // namespace socketley::mqtt
