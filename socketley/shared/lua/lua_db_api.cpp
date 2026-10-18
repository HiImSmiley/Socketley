#ifndef SOCKETLEY_NO_LUA

#include "lua_db_api.h"

#include <iostream>

#include "db_call.h"
#include "lua_context.h"
#include "lua_json.h"
#include "lua_suspend.h"
#include "../runtime/runtime_instance.h"
#include "../runtime/runtime_manager.h"
#include "../json/json_escape.h"

namespace
{

using verb = lua_db_client::verb;

const char* usage(verb v)
{
    switch (v)
    {
        case verb::get:    return "socketley.db.get(runtime, collection, id [, callback])";
        case verb::put:    return "socketley.db.put(runtime, collection, id, doc [, {[\"if\"]=version, if_absent=true}] [, callback])";
        case verb::insert: return "socketley.db.insert(runtime, collection, doc [, callback])";
        case verb::patch:  return "socketley.db.patch(runtime, collection, id, changes [, {[\"if\"]=version}] [, callback])";
        case verb::del:    return "socketley.db.delete(runtime, collection, id [, {[\"if\"]=version}] [, callback])";
        case verb::query:  return "socketley.db.query(runtime, collection [, query] [, callback])";
        case verb::tx:     return "socketley.db.tx(runtime, ops [, callback])";
    }
    return "";
}

bool string_at(lua_State* L, int idx, std::string& out)
{
    if (lua_type(L, idx) != LUA_TSTRING)
        return false;
    size_t n = 0;
    const char* p = lua_tolstring(L, idx, &n);
    out.assign(p, n);
    return true;
}

void quoted(std::string& out, std::string_view s)
{
    socketley::json::quote_into(out, std::string(s));
}

int db_thunk(lua_State* L)
{
    auto* client = static_cast<lua_db_client*>(lua_touserdata(L, lua_upvalueindex(1)));
    const int v = static_cast<int>(lua_tointeger(L, lua_upvalueindex(2)));
    if (!client)
        return 0;
    return client->call(L, static_cast<verb>(v));
}

}   // namespace

lua_db_client::lua_db_client(lua_context& ctx, runtime_instance& owner) : m_ctx(ctx), m_owner(owner) {}

lua_db_client::~lua_db_client()
{
    cancel();
}

void lua_db_client::install(sol::state& lua, sol::table& sk)
{
    lua_State* L = lua.lua_state();
    sol::table t = lua.create_table();
    t.push();
    static constexpr std::pair<const char*, verb> fns[] = {
        {"get", verb::get},     {"put", verb::put},    {"insert", verb::insert}, {"patch", verb::patch},
        {"delete", verb::del},  {"query", verb::query}, {"tx", verb::tx},
    };
    for (const auto& [name, v] : fns)
    {
        lua_pushlightuserdata(L, this);
        lua_pushinteger(L, static_cast<lua_Integer>(v));
        lua_pushcclosure(L, &db_thunk, 2);
        lua_setfield(L, -2, name);
    }
    lua_pop(L, 1);
    sk["db"] = t;
}

void lua_db_client::cancel()
{
    if (auto* mgr = m_owner.get_runtime_manager())
        mgr->requests().drop_origin(this);
    lua_State* L = m_ctx.state().lua_state();
    for (auto& [cookie, p] : m_pending)
        if (p.ref != LUA_NOREF)
            luaL_unref(L, LUA_REGISTRYINDEX, p.ref);
    m_pending.clear();
}

int lua_db_client::call(lua_State* L, verb v)
{
    const mode m = begin(L, v);
    if (m == mode::refused)
    {
        lua_pushnil(L);
        lua_pushlstring(L, m_error.data(), m_error.size());
        return 2;
    }
    if (m == mode::callback)
    {
        lua_pushboolean(L, 1);
        return 1;
    }
    // Nothing is left on this frame that a longjmp would skip.
    return lua_yield(L, 0);
}

lua_db_client::mode lua_db_client::begin(lua_State* L, verb v)
{
    const auto refuse = [&](std::string msg) {
        m_error = std::move(msg);
        return mode::refused;
    };
    if (m_ctx.registrations_severed())
        return refuse("this runtime has been stopped, so it makes no more calls");

    const int nargs = lua_gettop(L);
    const bool has_cb = nargs >= 1 && lua_type(L, nargs) == LUA_TFUNCTION;
    const int logical = has_cb ? nargs - 1 : nargs;
    const auto shape = [&] { return refuse(std::string("usage: ") + usage(v)); };

    std::string target, coll, id;
    if (logical < 2 || !string_at(L, 1, target) || target.empty())
        return shape();
    // The value at `idx` as JSON, refused with the encoder's reason.
    std::string err;
    const auto encode = [&](int idx, std::string& out) {
        std::vector<const void*> path;
        return socketley::lua_json::json_encode_value(out, sol::object(L, idx), 0, path, err);
    };
    // The optional {["if"]=version, if_absent=true} at `idx`.
    std::string if_match, if_none_match;
    const auto options = [&](int idx) {
        if (idx > logical)
            return true;
        if (lua_type(L, idx) != LUA_TTABLE)
            return false;
        lua_getfield(L, idx, "if");
        if (lua_type(L, -1) == LUA_TNUMBER)
            if_match = std::to_string(static_cast<uint64_t>(lua_tonumber(L, -1)));
        lua_pop(L, 1);
        lua_getfield(L, idx, "if_absent");
        if (lua_toboolean(L, -1))
            if_none_match = "*";
        lua_pop(L, 1);
        return true;
    };

    std::string method, path, body;
    if (v == verb::tx)
    {
        if (logical != 2 || lua_type(L, 2) != LUA_TTABLE)
            return shape();
        std::string ops;
        if (!encode(2, ops))
            return refuse("the ops cannot be JSON: " + err);
        method = "POST";
        path = "/tx";
        body = "{\"ops\":" + ops + "}";
    }
    else
    {
        if (!string_at(L, 2, coll) || coll.empty())
            return shape();
        switch (v)
        {
            case verb::get:
                if (logical != 3 || !string_at(L, 3, id))
                    return shape();
                method = "GET";
                break;
            case verb::del:
                if (logical < 3 || logical > 4 || !string_at(L, 3, id) || !options(4))
                    return shape();
                method = "DELETE";
                break;
            case verb::put:
            case verb::patch:
                if (logical < 4 || logical > 5 || !string_at(L, 3, id) || lua_type(L, 4) != LUA_TTABLE || !options(5))
                    return shape();
                if (!encode(4, body))
                    return refuse("the document cannot be JSON: " + err);
                method = v == verb::put ? "PUT" : "PATCH";
                break;
            case verb::insert:
                if (logical != 3 || lua_type(L, 3) != LUA_TTABLE)
                    return shape();
                if (!encode(3, body))
                    return refuse("the document cannot be JSON: " + err);
                method = "POST";
                break;
            case verb::query:
                if (logical > 3 || (logical == 3 && lua_type(L, 3) != LUA_TTABLE))
                    return shape();
                if (logical == 3 && !encode(3, body))
                    return refuse("the query cannot be JSON: " + err);
                method = "POST";
                id = "_query";
                break;
            case verb::tx:
                break;
        }
        path = "/c/" + coll + (id.empty() ? "" : "/" + id);
    }

    std::string payload(socketley::db::call_marker);
    payload += "{\"method\":";
    quoted(payload, method);
    payload += ",\"path\":";
    quoted(payload, path);
    if (!body.empty())
        payload += ",\"body\":" + body;
    if (!if_match.empty())
    {
        payload += ",\"if_match\":";
        quoted(payload, if_match);
    }
    if (!if_none_match.empty())
    {
        payload += ",\"if_none_match\":";
        quoted(payload, if_none_match);
    }
    payload += '}';

    auto* mgr = m_owner.get_runtime_manager();
    if (!mgr)
        return refuse("this runtime has no runtime manager");
    if (m_pending.size() >= max_pending)
        return refuse("too many db calls are already waiting on this runtime");
    pending p;
    if (has_cb)
    {
        lua_pushvalue(L, nargs);
        p.ref = luaL_ref(L, LUA_REGISTRYINDEX);
    }
    else
    {
        p.await = m_ctx.suspender().enrol_await(L);
        if (p.await == 0)
            return refuse(std::string("socketley.db waits for an answer, so without a callback it may only be called "
                                      "from one that can wait (on_message, on_client_message, or a storage runtime's "
                                      "on_request, on_put and on_delete); pass a function as the last argument "
                                      "anywhere else"));
    }
    const uint64_t cookie = m_next++;
    if (!mgr->requests().post(this, cookie, target, payload, request_class::client))
    {
        if (p.ref != LUA_NOREF)
            luaL_unref(L, LUA_REGISTRYINDEX, p.ref);
        return refuse("the request channel is full");
    }
    if (!has_cb)
    {
        uint64_t held = 0;
        m_owner.hold_answering_connection(held);
        m_ctx.suspender().note_await(p.await, 0, held);
    }
    m_pending.emplace(cookie, p);
    return has_cb ? mode::callback : mode::wait;
}

int lua_db_client::push_values(lua_State* L, request_status st, std::string_view reply)
{
    if (st != request_status::ok)
    {
        lua_pushnil(L);
        lua_pushstring(L, st == request_status::no_target ? "no runtime of that name answers socketley.db"
                                                         : request_status_text(st));
        return 2;
    }
    sol::state_view lua(L);
    const char* p = reply.data();
    auto js = socketley::lua_json::json_status::ok;
    sol::state& whole = m_ctx.state();
    sol::object doc = socketley::lua_json::json_decode_value(whole, p, reply.data() + reply.size(), 0, js);
    if (js != socketley::lua_json::json_status::ok || doc.get_type() != sol::type::table)
    {
        lua_pushnil(L);
        lua_pushstring(L, "the database's answer could not be read; is the runtime a db?");
        return 2;
    }
    sol::table t = doc.as<sol::table>();
    const int status = t.get_or("status", 0);
    sol::object body = t["body"];
    if (status >= 200 && status < 300)
    {
        body.push(L);
        return 1;
    }
    lua_pushnil(L);
    if (body.get_type() == sol::type::table)
    {
        sol::table b = body.as<sol::table>();
        const std::string code = b.get_or<std::string>("error", "error");
        const std::string message = b.get_or<std::string>("message", "");
        lua_pushlstring(L, code.data(), code.size());
        lua_pushlstring(L, message.data(), message.size());
        return 3;
    }
    lua_pushstring(L, ("status " + std::to_string(status)).c_str());
    return 2;
}

void lua_db_client::on_request_reply(uint64_t cookie, request_status st, std::string_view reply)
{
    const auto it = m_pending.find(cookie);
    if (it == m_pending.end())
        return;
    const pending p = it->second;
    m_pending.erase(it);
    if (p.await != 0)
    {
        m_ctx.suspender().settle_with(p.await, [&](lua_State* th) { return push_values(th, st, reply); });
        return;
    }
    lua_State* L = m_ctx.state().lua_state();
    lua_deadline::scope guard("socketley.db callback", m_ctx.callback_timeout_ms(), m_ctx.owner_name().c_str());
    lua_rawgeti(L, LUA_REGISTRYINDEX, p.ref);
    luaL_unref(L, LUA_REGISTRYINDEX, p.ref);
    const int n = push_values(L, st, reply);
    if (lua_pcall(L, n, 0, 0) != 0)
    {
        const char* msg = lua_tostring(L, -1);
        std::cerr << lua_diag::tag(m_ctx.owner_name()) << " a socketley.db callback raised: "
                  << (msg ? msg : "(no message)") << std::endl;
        lua_pop(L, 1);
    }
}

#endif // SOCKETLEY_NO_LUA
