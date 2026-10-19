#pragma once
// self.publish, self.retained, self.sessions and self.kick in an mqtt runtime's script.
#ifndef SOCKETLEY_NO_LUA

#include <sol/sol.hpp>

class runtime_instance;

namespace socketley::mqtt
{

void register_lua_table(runtime_instance* owner, sol::state& lua, sol::table& self);

}   // namespace socketley::mqtt

#endif   // SOCKETLEY_NO_LUA
