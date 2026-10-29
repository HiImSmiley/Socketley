#pragma once

// string.find, match, gmatch and gsub for a state whose scripts come from
// clients: Lua 5.1's matcher, which backtracks without bound inside one C call
// where no count hook fires, rebuilt to test the armed lua_deadline as it works.

#ifndef SOCKETLEY_NO_LUA

#include <sol/sol.hpp>

namespace lua_pattern
{
    // Replaces find, match, gmatch (and gfind, where present) and gsub in the
    // string library table at `idx`, with the semantics of Lua 5.1 and a
    // nesting limit of 200, as Lua 5.2 has.
    void install(lua_State* L, int idx);
}

#endif  // SOCKETLEY_NO_LUA
