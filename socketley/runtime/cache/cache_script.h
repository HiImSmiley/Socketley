#pragma once

// EVAL, EVALSHA and SCRIPT: Lua that arrived over the network.
//
// ─── WHY THIS IS NOT lua_context ───────────────────────────────────────────
//
// shared/lua_context.h says of itself: "This is not a sandbox and says so:
// `io`, `package` and `base` are open, so a Lua handler runs with the daemon's
// full privileges."  That is the right trade for a script the operator wrote
// and pointed --lua at.  It is the wrong one for EVAL, where the script is
// whatever a client sent -- and under LuaJIT `require("ffi")` alone is
// arbitrary memory access.
//
// So this is a second state, built the other way round: nothing is open unless
// a script needs it.  The two never meet, which also means a client's script
// cannot read the globals of the operator's.
//
// What a script can still do is spend time and allocate, and the answer to
// both is the count hook shared/lua_context.h already carries -- the same
// deadline a callback gets, armed per EVAL.

// Compiled only where Lua is: this file IS the Lua, and the nolua SDK builds
// the same runtime sources with SOCKETLEY_NO_LUA set.
#ifndef SOCKETLEY_NO_LUA

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <sol/sol.hpp>

namespace socketley {

class cache_script_engine
{
public:
    // Runs one command already encoded as a RESP array and appends its RESP
    // reply.  This is `redis.call`'s whole contact with the cache: the engine
    // knows nothing about the store, the dispatch or the shard map.
    using command_fn = std::function<void(std::string_view raw_resp, std::string& reply)>;

    cache_script_engine() = default;

    // Evaluates `body` and appends the RESP form of its return value.  False
    // means `err` holds a message already shaped as a RESP error line's text.
    bool eval(std::string_view body,
              const std::vector<std::string_view>& keys,
              const std::vector<std::string_view>& argv,
              const command_fn& call,
              std::string& resp_out,
              std::string& err);

    // SCRIPT LOAD, which keeps the source under its own SHA1 so EVALSHA can
    // find it.  Lowercase hex, forty characters, as Redis spells it.
    std::string load(std::string_view body);
    bool               known(std::string_view sha) const;
    const std::string* body_of(std::string_view sha) const;
    void               flush();
    size_t             size() const { return m_scripts.size(); }

    // The hex SHA1 of a string, which is also `redis.sha1hex`.
    static std::string sha1_hex(std::string_view in);

private:
    // Built on the first EVAL and not before: a cache that is never scripted
    // pays nothing, and the state is the largest thing here.
    void ensure_state();

    bool                m_ready{false};
    sol::state          m_lua;
    std::unordered_map<std::string, std::string> m_scripts;
};

}  // namespace socketley

#endif  // SOCKETLEY_NO_LUA
