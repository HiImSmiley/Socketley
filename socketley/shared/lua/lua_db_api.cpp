#ifndef SOCKETLEY_NO_LUA

#include "lua_db_api.h"

#include "db_call.h"
#include "lua_context.h"
#include "lua_json.h"
#include "../json/json_escape.h"

#include <cmath>

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

}   // namespace

lua_db_client::lua_db_client(lua_context& ctx, runtime_instance& owner)
    : lua_request_client(ctx, owner, "socketley.db", "db")
{
}

void lua_db_client::install(sol::state& lua, sol::table& sk)
{
    static constexpr function fns[] = {
        {"get", int(verb::get)},       {"put", int(verb::put)},     {"insert", int(verb::insert)},
        {"patch", int(verb::patch)},   {"delete", int(verb::del)},  {"query", int(verb::query)},
        {"tx", int(verb::tx)},
    };
    install_table(lua, sk, "db", fns);
}

lua_db_client::mode lua_db_client::begin(lua_State* L, int tag)
{
    const verb v = static_cast<verb>(tag);
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
        // A version that is no whole count is refused, or the write would go through without its condition.
        lua_getfield(L, idx, "if");
        if (lua_type(L, -1) != LUA_TNIL)
        {
            const double d = lua_type(L, -1) == LUA_TNUMBER ? lua_tonumber(L, -1) : -1.0;
            if (!(d >= 0.0) || d != std::floor(d) || d >= 9007199254740992.0)
            {
                lua_pop(L, 1);
                return false;
            }
            if_match = std::to_string(static_cast<uint64_t>(d));
        }
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

    return send(L, tag, target, std::move(payload));
}

int lua_db_client::push_values(lua_State* L, int, request_status st, std::string_view reply)
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

#endif // SOCKETLEY_NO_LUA
