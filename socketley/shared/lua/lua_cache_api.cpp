#ifndef SOCKETLEY_NO_LUA

#include "lua_cache_api.h"

namespace
{

constexpr const char* command_usage = "usage: socketley.cache.command(runtime, command [, callback])";

}   // namespace

lua_cache_client::lua_cache_client(lua_context& ctx, runtime_instance& owner)
    : lua_request_client(ctx, owner, "socketley.cache", "cache")
{
}

void lua_cache_client::install(sol::state& lua, sol::table& sk)
{
    static constexpr function fns[] = {{"command", 0}};
    install_table(lua, sk, "cache", fns);
}

lua_cache_client::mode lua_cache_client::begin(lua_State* L, int)
{
    const int nargs = lua_gettop(L);
    const bool has_cb = nargs >= 1 && lua_type(L, nargs) == LUA_TFUNCTION;
    const int logical = has_cb ? nargs - 1 : nargs;
    if (logical != 2 || lua_type(L, 1) != LUA_TSTRING || lua_type(L, 2) != LUA_TSTRING)
        return refuse(command_usage);
    size_t tn = 0, cn = 0;
    const char* t = lua_tolstring(L, 1, &tn);
    const char* c = lua_tolstring(L, 2, &cn);
    if (tn == 0 || cn == 0)
        return refuse(command_usage);
    return send(L, 0, std::string_view(t, tn), std::string(c, cn));
}

int lua_cache_client::push_values(lua_State* L, int, request_status st, std::string_view reply)
{
    if (st != request_status::ok)
    {
        lua_pushnil(L);
        lua_pushstring(L, st == request_status::no_target ? "no runtime of that name answers socketley.cache"
                                                         : request_status_text(st));
        return 2;
    }
    // The line end a reply on the cache's port carries is the protocol's, not the value's.
    if (reply.ends_with('\n'))
        reply.remove_suffix(1);
    if (reply.ends_with('\r'))
        reply.remove_suffix(1);
    lua_pushlstring(L, reply.data(), reply.size());
    return 1;
}

#endif // SOCKETLEY_NO_LUA
