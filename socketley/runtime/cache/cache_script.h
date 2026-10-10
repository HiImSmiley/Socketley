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
#include <list>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <sol/sol.hpp>
#include "../../shared/transparent_string.h"

namespace socketley {

class cache_script_engine
{
public:
    // Runs one command, its arguments as views, and appends its RESP reply.
    // This is `redis.call`'s whole contact with the cache: the engine knows
    // nothing about the store, the dispatch or the shard map.
    using command_fn = std::function<void(std::span<std::string_view> args, std::string& reply)>;

    cache_script_engine() = default;

    // Evaluates `body`, loaded as SCRIPT LOAD would load it, and appends the
    // RESP form of its return value.  False means `err` holds a message
    // already shaped as a RESP error line's text.
    bool eval(std::string_view body,
              std::span<const std::string_view> keys,
              std::span<const std::string_view> argv,
              const command_fn& call,
              std::string& resp_out,
              std::string& err);

    // SCRIPT LOAD, which keeps the source under its own SHA1 so EVALSHA can
    // find it.  Lowercase hex, forty characters, as Redis spells it.
    std::string load(std::string_view body, std::string& err);

    // The scripts only EVAL made known that are kept, as Redis 7.4 keeps them: a client that sends a new body each
    // time would otherwise grow the cache for ever. The least recently run goes first, and EVALSHA of it answers
    // NOSCRIPT, after which a client sends EVAL again; SCRIPT LOAD's are kept until SCRIPT FLUSH.
    static constexpr size_t eval_kept = 500;
    size_t eval_held() const { return m_eval_lru.size(); }
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

    // redis.call and redis.pcall, on the Lua stack rather than through sol:
    // its registry references and argument checks were most of what a
    // one-command script cost.
    static int call_raising(lua_State* L);
    static int call_protected(lua_State* L);
    // Pushes the reply and answers 1, or pushes the error text and answers 0.
    int run_call(lua_State* L, bool raising);

    bool                m_ready{false};
    sol::state          m_lua;
    // Transparent too: known() and body_of() take a view and used to build a
    // std::string for every EVALSHA just to look it up.
    std::unordered_map<std::string, std::string,
                       string_hash, string_equal> m_scripts;

    // The same pair the other way round, so load() can answer without
    // digesting.  Kept in step with m_scripts: both are filled in load() and
    // both are cleared in flush().
    std::unordered_map<std::string, std::string,
                       string_hash, string_equal> m_sha_of;

    // The compiled chunk, kept under the same SHA as the source.  Compiling on
    // every call is what made EVAL five times slower than Redis at it: Redis
    // compiles once and calls thereafter, and measured here `EVAL return(1) 0`
    // ran at 160,452/s against 787,482.
    // Keyed by the BODY and not by its SHA.  Keying by SHA meant hashing the
    // script on every single EVAL -- EVP_MD_CTX_new allocates an OpenSSL
    // context, then forty characters go into a std::string one at a time,
    // which is why std::string::push_back was the top symbol in the profile.
    // The body is already in hand and a string_view hash of it costs nothing.
    // The SHA is still computed where it is actually wanted: SCRIPT LOAD, and
    // EVALSHA's lookup.
    std::unordered_map<std::string, sol::protected_function,
                       string_hash, string_equal> m_compiled;

    // Names a body without pinning or tracking it: the part SCRIPT LOAD and EVAL share.
    std::string remember(std::string_view body);
    // The body compiled into m_compiled, false with the compiler's answer in `err`.
    bool compile(std::string_view body, std::string& err);
    // Drops the least recently run of EVAL's scripts past eval_kept, never while a script runs.
    void trim_eval();
    std::list<std::string> m_eval_lru;
    std::unordered_map<std::string, std::list<std::string>::iterator,
                       string_hash, string_equal> m_eval_at;
    int m_depth{0};

    // Built once and refilled per call.  Two fresh Lua tables per EVAL is two
    // allocations and two global-table writes for something whose shape almost
    // never changes; `EVAL return(1) 0` created two empty ones every time.
    sol::table m_keys_tbl;
    sol::table m_argv_tbl;

    // What redis.call reaches, set for the duration of one eval.  A member
    // rather than a capture, so the `redis` table is built once at start-up
    // instead of once per call -- three tables and a dozen closures per EVAL
    // was the other half of the same cost.
    const command_fn*   m_call{nullptr};

    // redis.call's arguments and reply, kept between calls for their capacity.
    std::vector<std::string_view> m_args;
    std::string                   m_reply_buf;
};

}  // namespace socketley

#endif  // SOCKETLEY_NO_LUA
