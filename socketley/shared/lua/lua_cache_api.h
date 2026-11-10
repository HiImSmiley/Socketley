#pragma once
// socketley.cache.command(runtime, line [, callback]): one command of a cache runtime's text protocol, answered with
// what the cache said, from any runtime that has a script, as a server's self.cache asks the cache it links.
#ifndef SOCKETLEY_NO_LUA

#include <string>

#include "lua_request_client.h"

class lua_cache_client : public lua_request_client
{
public:
    lua_cache_client(lua_context& ctx, runtime_instance& owner);

    // Adds `cache` to the `socketley` table being built.
    void install(sol::state& lua, sol::table& sk);

private:
    mode        begin(lua_State* L, int tag) override;
    int         push_values(lua_State* L, int tag, request_status st, std::string_view reply) override;
    std::string waits_name(int) const override { return "socketley.cache"; }
};

#endif // SOCKETLEY_NO_LUA
