#pragma once
// socketley.mqtt.publish(runtime, topic, payload [, {qos=, retain=}] [, callback]): a message handed to an mqtt
// runtime of this daemon, from any runtime that has a script, answered true once the broker took it.
#ifndef SOCKETLEY_NO_LUA

#include <cstdint>
#include <string>

#include "lua_request_client.h"

class lua_mqtt_client : public lua_request_client
{
public:
    lua_mqtt_client(lua_context& ctx, runtime_instance& owner);

    // Adds `mqtt` to the `socketley` table being built.
    void install(sol::state& lua, sol::table& sk);

private:
    mode        begin(lua_State* L, int tag) override;
    int         push_values(lua_State* L, int tag, request_status st, std::string_view reply) override;
    std::string waits_name(int) const override { return "socketley.mqtt"; }
};

#endif // SOCKETLEY_NO_LUA
