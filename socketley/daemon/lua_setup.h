#pragma once
// A machine's setup as Lua: the runtimes a file and the files it includes describe, as the create commands that make
// them -- read by `socketley --lua` and by the daemon at its start, and written back by `socketley export`.
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "../shared/json/json_doc.h"
#include "../shared/runtime/runtime_definitions.h"

#ifndef SOCKETLEY_NO_LUA
#include <sol/sol.hpp>
#endif

namespace lua_setup
{

// One runtime a setup describes: the words of the create that makes it, or why it cannot be made.
struct runtime_entry
{
    std::string name, type;
    std::vector<std::string> create;
    std::string refused;
    // Running where 1, stopped where 0, left as it is where -1.
    int start = -1;
};

// What `show` writes of a runtime that is no setting of it: who it is, who made it, and how it was last left.
bool volatile_key(std::string_view key);

// A runtime's settings as a setup names them, in the order the table gives its flags: (Lua key, value) where the
// state's key has a flag, and the keys that have none in `unmapped`.
std::vector<std::pair<std::string, socketley::json::jvalue>> settings_of(const socketley::json::jvalue& state,
                                                                        runtime_type type,
                                                                        std::vector<std::string>& unmapped);

// A value as a Lua literal, a table on one line.
std::string lua_literal(const socketley::json::jvalue& v);

#ifndef SOCKETLEY_NO_LUA

// The libraries a setup is read with, and include(), which reads a file, or each .lua of a directory in name order,
// from beside `top`, the file the setup begins with.
void open(sol::state& lua, const std::string& top);

// The runtimes of the file's `runtimes`, nested lists of them flattened, each with the create that makes it; a relative
// path among their values is one beside `top`.
std::vector<runtime_entry> runtimes(sol::state& lua, const std::string& top, std::string& why);

#endif

}   // namespace lua_setup
