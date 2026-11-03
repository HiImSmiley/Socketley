#pragma once
// mcp.tool, mcp.resource and mcp.prompt in an mcp runtime's script.
#ifndef SOCKETLEY_NO_LUA

#include <sol/sol.hpp>

class runtime_instance;

namespace socketley::mcp
{

void register_lua_table(runtime_instance* owner, sol::state& lua, sol::table& self);

}   // namespace socketley::mcp

#endif   // SOCKETLEY_NO_LUA
