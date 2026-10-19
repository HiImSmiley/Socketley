#ifndef SOCKETLEY_NO_LUA

#include "lua_mqtt_api.h"

#include "lua_context.h"
#include "../../runtime/mqtt/mqtt_codec.h"
#include "../../runtime/mqtt/mqtt_command.h"

namespace
{

constexpr const char* publish_usage =
    "usage: socketley.mqtt.publish(runtime, topic, payload [, {qos=0|1|2, retain=true}] [, callback])";

bool string_at(lua_State* L, int idx, std::string& out)
{
    if (lua_type(L, idx) != LUA_TSTRING)
        return false;
    size_t n = 0;
    const char* p = lua_tolstring(L, idx, &n);
    out.assign(p, n);
    return true;
}

}   // namespace

lua_mqtt_client::lua_mqtt_client(lua_context& ctx, runtime_instance& owner)
    : lua_request_client(ctx, owner, "socketley.mqtt", "mqtt")
{
}

void lua_mqtt_client::install(sol::state& lua, sol::table& sk)
{
    static constexpr function fns[] = {{"publish", 0}};
    install_table(lua, sk, "mqtt", fns);
}

lua_mqtt_client::mode lua_mqtt_client::begin(lua_State* L, int)
{
    const int nargs = lua_gettop(L);
    const bool has_cb = nargs >= 1 && lua_type(L, nargs) == LUA_TFUNCTION;
    const int logical = has_cb ? nargs - 1 : nargs;
    std::string target, topic, payload;
    if (logical < 3 || logical > 4 || !string_at(L, 1, target) || !string_at(L, 2, topic))
        return refuse(publish_usage);
    // A payload is bytes; a number is taken as the text it prints as.
    if (lua_type(L, 3) == LUA_TNUMBER || lua_type(L, 3) == LUA_TSTRING)
    {
        size_t n = 0;
        const char* p = lua_tolstring(L, 3, &n);
        payload.assign(p, n);
    }
    else
        return refuse(publish_usage);
    uint8_t qos = 0;
    bool retain = false;
    if (logical == 4)
    {
        if (lua_type(L, 4) != LUA_TTABLE)
            return refuse(publish_usage);
        lua_getfield(L, 4, "qos");
        if (lua_type(L, -1) == LUA_TNUMBER)
        {
            const lua_Integer q = lua_tointeger(L, -1);
            if (q < 0 || q > 2)
            {
                lua_pop(L, 1);
                return refuse("socketley.mqtt.publish: qos is 0, 1 or 2");
            }
            qos = static_cast<uint8_t>(q);
        }
        lua_pop(L, 1);
        lua_getfield(L, 4, "retain");
        retain = lua_toboolean(L, -1) != 0;
        lua_pop(L, 1);
    }
    if (!socketley::mqtt::valid_topic(topic) || topic.front() == '$')
        return refuse("socketley.mqtt.publish: `" + topic + "` is not a topic a message can be published to");
    return send(L, 0, target, socketley::mqtt::command_publish(topic, payload, qos, retain));
}

int lua_mqtt_client::push_values(lua_State* L, int, request_status st, std::string_view reply)
{
    if (st != request_status::ok)
    {
        lua_pushnil(L);
        lua_pushstring(L, st == request_status::no_target ? "no runtime of that name answers socketley.mqtt"
                                                         : request_status_text(st));
        return 2;
    }
    if (reply == "ok")
    {
        lua_pushboolean(L, 1);
        return 1;
    }
    // The broker's refusal without its "error: ", which says only that it is one.
    if (reply.starts_with("error: "))
        reply.remove_prefix(7);
    lua_pushnil(L);
    lua_pushlstring(L, reply.data(), reply.size());
    return 2;
}

#endif // SOCKETLEY_NO_LUA
