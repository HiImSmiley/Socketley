#include "cache_script.h"

#ifndef SOCKETLEY_NO_LUA

#include "resp_parser.h"
#include "../../shared/lua/lua_context.h"

#include <openssl/evp.h>
#include <cstdio>

namespace socketley {

// ─── SHA1 ───────────────────────────────────────────────────────────────────

std::string cache_script_engine::sha1_hex(std::string_view in)
{
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int  len = 0;
    EVP_MD_CTX*   ctx = EVP_MD_CTX_new();
    if (!ctx) return {};
    std::string out;
    if (EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr) == 1
        && EVP_DigestUpdate(ctx, in.data(), in.size()) == 1
        && EVP_DigestFinal_ex(ctx, md, &len) == 1)
    {
        static const char hex[] = "0123456789abcdef";
        out.reserve(len * 2);
        for (unsigned i = 0; i < len; ++i)
        { out += hex[md[i] >> 4]; out += hex[md[i] & 0xF]; }
    }
    EVP_MD_CTX_free(ctx);
    return out;
}

static std::string shape_lua_error(const char* what);

bool cache_script_engine::compile(std::string_view body, std::string& err)
{
    if (m_compiled.find(body) != m_compiled.end())
        return true;
    ensure_state();
    // Named so a compile error points at "user_script" the way Redis's
    // does, rather than at the script's own first line quoted back.
    // Text only, because LuaJIT runs bytecode unverified and a crafted
    // chunk from any client that can reach the port is native code.
    sol::load_result lr = m_lua.load(std::string(body), "@user_script", sol::load_mode::text);
    if (!lr.valid())
    {
        sol::error e = lr;
        err = shape_lua_error(e.what());
        return false;
    }
    m_compiled.emplace(std::string(body), lr.get<sol::protected_function>());
    return true;
}

std::string cache_script_engine::load(std::string_view body, std::string& err)
{
    if (!compile(body, err))
        return {};
    std::string sha = remember(body);
    // Loaded by name, it is kept until SCRIPT FLUSH, whether or not EVAL had made it known first.
    if (const auto at = m_eval_at.find(body); at != m_eval_at.end())
    {
        m_eval_lru.erase(at->second);
        m_eval_at.erase(at);
    }
    return sha;
}

void cache_script_engine::trim_eval()
{
    while (m_depth == 0 && m_eval_lru.size() > eval_kept)
    {
        const std::string& body = m_eval_lru.back();
        if (const auto s = m_sha_of.find(body); s != m_sha_of.end())
        {
            m_scripts.erase(s->second);
            m_sha_of.erase(s);
        }
        m_compiled.erase(body);
        m_eval_at.erase(body);
        m_eval_lru.pop_back();
    }
}

std::string cache_script_engine::remember(std::string_view body)
{
    // A body that fails to compile is registered again by every EVAL of it,
    // and SCRIPT LOAD may be sent any number of times: each would be an
    // OpenSSL context and forty characters appended one at a time.
    //
    // The body is the thing we have; the digest is a name for it.  Naming it
    // twice gives the same answer, so the second time is a lookup.
    auto seen = m_sha_of.find(body);
    if (seen != m_sha_of.end())
        return seen->second;

    std::string sha = sha1_hex(body);
    if (!sha.empty())
    {
        m_scripts.emplace(sha, std::string(body));
        m_sha_of.emplace(std::string(body), sha);
    }
    return sha;
}

bool cache_script_engine::known(std::string_view sha) const
{
    return m_scripts.find(sha) != m_scripts.end();
}

const std::string* cache_script_engine::body_of(std::string_view sha) const
{
    auto it = m_scripts.find(sha);
    return it == m_scripts.end() ? nullptr : &it->second;
}

void cache_script_engine::flush()
{
    m_scripts.clear();
    // The reverse index goes with it, or SCRIPT FLUSH would leave load()
    // answering with the digest of a script the engine no longer holds.
    m_sha_of.clear();
    // And the compiled forms, or SCRIPT FLUSH would leave the memory it was
    // asked to release.
    m_compiled.clear();
    m_eval_lru.clear();
    m_eval_at.clear();
}

// ─── The reply, read back ───────────────────────────────────────────────────
//
// redis.call hands the command to the cache and gets RESP back, which has to
// become a Lua value under Redis's rules: an integer is a number, a bulk
// string is a string, a nil is `false` -- not nil, because a nil in a table
// ends the array -- a status is a table with `ok` and an error is one with
// `err`.

namespace {

// Consumes one reply from `p` and pushes the Lua value.  False means the reply
// was malformed, which is a bug here rather than something a script can cause.
bool push_reply(lua_State* L, std::string_view& p)
{
    if (p.empty() || !lua_checkstack(L, 3)) return false;
    const char t = p.front();
    const size_t nl = p.find("\r\n");
    if (nl == std::string_view::npos) return false;
    const std::string_view head = p.substr(1, nl - 1);
    p.remove_prefix(nl + 2);

    switch (t)
    {
        case '+':
        case '-':
            // A status is a table so a script can tell +OK from the string
            // "OK", which is what Redis's own contract promises.
            lua_createtable(L, 0, 1);
            lua_pushlstring(L, head.data(), head.size());
            lua_setfield(L, -2, t == '+' ? "ok" : "err");
            return true;
        case ':':
        {
            long long v = 0;
            std::from_chars(head.data(), head.data() + head.size(), v);
            lua_pushnumber(L, static_cast<lua_Number>(v));
            return true;
        }
        case '$':
        {
            long long n = -1;
            std::from_chars(head.data(), head.data() + head.size(), n);
            if (n < 0) { lua_pushboolean(L, 0); return true; }
            if (p.size() < static_cast<size_t>(n) + 2) return false;
            lua_pushlstring(L, p.data(), static_cast<size_t>(n));
            p.remove_prefix(static_cast<size_t>(n) + 2);
            return true;
        }
        case '*':
        {
            long long n = -1;
            std::from_chars(head.data(), head.data() + head.size(), n);
            if (n < 0) { lua_pushboolean(L, 0); return true; }
            lua_createtable(L, static_cast<int>(n), 0);
            for (long long i = 0; i < n; ++i)
            {
                if (!push_reply(L, p)) return false;
                lua_rawseti(L, -2, static_cast<int>(i + 1));
            }
            return true;
        }
        default: return false;
    }
}

// And the other direction, for what the script returns.  A table is an array
// up to its first hole, which is Lua's own idea of where an array ends -- and
// `err` and `ok` are checked first, because a table carrying either is a reply
// and not a list.
// Read raw, because this runs outside the script's pcall: a table whose
// __index raised ended the worker, from one EVAL any client could send.
void lua_to_resp(lua_State* L, int idx, std::string& out, int depth = 0)
{
    if (depth > 16 || !lua_checkstack(L, 2)) { resp::encode_null_into(out); return; }
    if (idx < 0) idx = lua_gettop(L) + idx + 1;

    size_t len = 0;
    switch (lua_type(L, idx))
    {
        case LUA_TBOOLEAN:
            // false is a nil reply and true is 1: Lua has no other way to say
            // "no value", and Redis chose these.
            if (lua_toboolean(L, idx)) resp::encode_integer_into(out, 1);
            else                       resp::encode_null_into(out);
            return;
        case LUA_TNUMBER:
            // Truncated towards zero, not rounded: a script returning 3.7 is
            // returning 3 on Redis, and a caller that wanted 3.7 has to return
            // a string.
        {
            // Saturated past int64's range and zero for NaN, where the plain cast is undefined.
            const double d = lua_tonumber(L, idx);
            const int64_t v = !(d == d) ? 0
                            : d >= 9223372036854775808.0  ? INT64_MAX
                            : d < -9223372036854775808.0  ? INT64_MIN
                                                          : static_cast<int64_t>(d);
            resp::encode_integer_into(out, v);
            return;
        }
        case LUA_TSTRING:
        {
            const char* s = lua_tolstring(L, idx, &len);
            resp::encode_bulk_into(out, std::string_view(s, len));
            return;
        }
        case LUA_TTABLE:
        {
            lua_pushliteral(L, "err");
            lua_rawget(L, idx);
            if (lua_type(L, -1) == LUA_TSTRING)
            {
                const char* s = lua_tolstring(L, -1, &len);
                resp::encode_error_code_into(out, std::string_view(s, len));
                lua_pop(L, 1);
                return;
            }
            lua_pop(L, 1);
            lua_pushliteral(L, "ok");
            lua_rawget(L, idx);
            if (lua_type(L, -1) == LUA_TSTRING)
            {
                const char* s = lua_tolstring(L, -1, &len);
                resp::encode_simple_into(out, std::string_view(s, len));
                lua_pop(L, 1);
                return;
            }
            lua_pop(L, 1);

            // The length is where the first hole is, so { 1, 2, nil, 4 } is
            // two elements -- Lua's rule, and Redis follows it.
            int n = 0;
            while (true)
            {
                lua_rawgeti(L, idx, n + 1);
                const bool hole = lua_isnil(L, -1);
                lua_pop(L, 1);
                if (hole) break;
                ++n;
            }
            resp::encode_array_header_into(out, n);
            for (int i = 1; i <= n; ++i)
            {
                lua_rawgeti(L, idx, i);
                lua_to_resp(L, -1, out, depth + 1);
                lua_pop(L, 1);
            }
            return;
        }
        default:
            resp::encode_null_into(out);
            return;
    }
}

}  // namespace

// One line, no traceback, no doubled prefix.  A RESP error is ONE line: a
// message carrying a newline -- which a traceback always does -- would end the
// reply early and leave the rest of it read as the next one.  Measured as
// exactly that: redis-cli answered "Bad simple string value" to a script whose
// redis.call had failed.
static std::string shape_lua_error(const char* what)
{
    std::string err(what ? what : "script failed");
    if (const size_t tb = err.find("stack traceback:"); tb != std::string::npos)
        err.resize(tb);
    for (const std::string_view lead : {"lua: ", "error: "})
        while (err.compare(0, lead.size(), lead) == 0) err.erase(0, lead.size());
    for (char& c : err) if (c == '\r' || c == '\n') c = ' ';
    while (!err.empty() && err.back() == ' ') err.pop_back();
    if (err.size() > 512) { err.resize(509); err += "..."; }
    return err;
}

// ─── redis.call ─────────────────────────────────────────────────────────────

int cache_script_engine::call_raising(lua_State* L)
{
    auto* self = static_cast<cache_script_engine*>(lua_touserdata(L, lua_upvalueindex(1)));
    // Raised here, where nothing is left to destroy, and not inside run_call.
    if (self->run_call(L, true)) return 1;
    return lua_error(L);
}

int cache_script_engine::call_protected(lua_State* L)
{
    auto* self = static_cast<cache_script_engine*>(lua_touserdata(L, lua_upvalueindex(1)));
    if (self->run_call(L, false)) return 1;
    lua_createtable(L, 0, 1);
    lua_insert(L, -2);
    lua_setfield(L, -2, "err");
    return 1;
}

int cache_script_engine::run_call(lua_State* L, bool raising)
{
    const int argc = lua_gettop(L);
    if (argc == 0 || !m_call)
    {
        lua_pushliteral(L, "Please specify at least one argument for redis.call()");
        return 0;
    }

    // Taken rather than borrowed, so nothing the command runs can write into them.
    std::vector<std::string_view> args;
    args.swap(m_args);
    args.clear();
    for (int i = 1; i <= argc; ++i)
    {
        const int t = lua_type(L, i);
        if (t == LUA_TNUMBER)
        {
            // An integer argument is spelled without a decimal point,
            // because `redis.call('expire', k, 60)` must not send "60.0".
            // The text replaces the number on the stack, which keeps it alive
            // for as long as the view below.
            const double d = lua_tonumber(L, i);
            char buf[40];
            int  n;
            if (d >= -9223372036854775808.0 && d < 9223372036854775808.0 &&
                d == static_cast<double>(static_cast<long long>(d)))
                n = std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(d));
            else
                n = std::snprintf(buf, sizeof(buf), "%.17g", d);
            lua_pushlstring(L, buf, static_cast<size_t>(n));
            lua_replace(L, i);
        }
        else if (t != LUA_TSTRING)
        {
            m_args.swap(args);
            lua_pushliteral(L, "Lua redis lib command arguments must be strings or integers");
            return 0;
        }
        size_t len = 0;
        const char* s = lua_tolstring(L, i, &len);
        args.emplace_back(s, len);
    }

    std::string reply;
    reply.swap(m_reply_buf);
    reply.clear();
    (*m_call)(args, reply);

    int ok = 1;
    std::string_view p(reply);
    // redis.call raises what redis.pcall returns, which is the whole
    // difference between them.
    if (raising && !p.empty() && p.front() == '-')
    {
        const size_t nl = p.find("\r\n");
        const std::string_view msg = p.substr(1, nl == std::string_view::npos ? p.size() - 1 : nl - 1);
        lua_pushlstring(L, msg.data(), msg.size());
        ok = 0;
    }
    else if (!push_reply(L, p))
    {
        lua_settop(L, argc);
        lua_pushliteral(L, "the cache answered something this cannot read");
        ok = 0;
    }

    m_args.swap(args);
    // Not a large one, which would stay held by a cache that scripted it once.
    if (reply.capacity() <= 64 * 1024) m_reply_buf.swap(reply);
    return ok;
}

// ─── The state ──────────────────────────────────────────────────────────────

void cache_script_engine::ensure_state()
{
    if (m_ready) return;
    m_ready = true;

    // Opened by name, and the list is the whole of the sandbox.  `io`, `os`,
    // `package`, `debug` and `ffi` are absent because a script here came from
    // a client: `io.open` is the filesystem, `os.execute` is the machine, and
    // `require("ffi")` under LuaJIT is arbitrary memory.
    m_lua.open_libraries(sol::lib::base, sol::lib::string,
                         sol::lib::table, sol::lib::math);

    // What `base` brings that a sandbox may not keep: every way to turn a
    // string into a function reaches outside what was opened, and every way to
    // reach a file does too.
    for (const char* gone : {"dofile", "loadfile", "load", "loadstring",
                             "require", "module", "print", "collectgarbage",
                             "newproxy", "getfenv", "setfenv"})
        m_lua[gone] = sol::nil;

    // The deadline the rest of the tree already uses, on this state too: a
    // script that loops is stopped by the same count hook a callback is, and
    // the trace compiler stays off for the same reason -- a compiled trace
    // calls no hook back.
    lua_deadline::install(m_lua.lua_state(), lua_deadline::default_ms());

    // Built ONCE.  These closures read m_call rather than capturing it, so the
    // table survives between evals -- rebuilding it per call cost as much as
    // the script did.
    sol::table redis = m_lua.create_table();
    lua_State* L = m_lua.lua_state();
    redis.push();
    lua_pushlightuserdata(L, this);
    lua_pushcclosure(L, &cache_script_engine::call_raising, 1);
    lua_setfield(L, -2, "call");
    lua_pushlightuserdata(L, this);
    lua_pushcclosure(L, &cache_script_engine::call_protected, 1);
    lua_setfield(L, -2, "pcall");
    lua_pop(L, 1);
    redis.set_function("error_reply", [this](std::string m) {
        sol::table t = m_lua.create_table(); t["err"] = std::move(m); return t; });
    redis.set_function("status_reply", [this](std::string m) {
        sol::table t = m_lua.create_table(); t["ok"] = std::move(m); return t; });
    redis.set_function("sha1hex", [](std::string x) { return sha1_hex(x); });
    // Named for what it is rather than left out, so a script that logs does not
    // fail on an unknown field -- and nothing is written anywhere.
    redis.set_function("log", [](sol::variadic_args) {});
    redis["LOG_DEBUG"] = 0; redis["LOG_VERBOSE"] = 1;
    redis["LOG_NOTICE"] = 2; redis["LOG_WARNING"] = 3;
    m_lua["redis"]  = redis;
    m_lua["server"] = redis;      // Redis 7's second name for the same table

    // KEYS and ARGV are bound HERE, before the globals are sealed below, and
    // refilled per call thereafter.  Binding them lazily would mean the first
    // eval writing a global into a table that no longer accepts one.
    m_keys_tbl = m_lua.create_table();
    m_argv_tbl = m_lua.create_table();
    m_lua["KEYS"] = m_keys_tbl;
    m_lua["ARGV"] = m_argv_tbl;

    // ─── AND THEN THE GLOBALS ARE SEALED ────────────────────────────────────
    //
    // One interpreter serves every script on this cache, so its global table
    // is shared: `x = 1` in one script was readable by the next one, and by
    // every script after it for the life of the process.  That is a channel
    // between two clients that neither asked for -- a script can leave a value
    // behind and another can find it -- and it is state that no FLUSH clears.
    //
    // Redis guards this with a metatable and so does this now: writing a
    // global raises, naming the variable.  Reads are left alone, because an
    // undefined global reading as nil is ordinary Lua and blocking the write
    // is what closes the channel.
    //
    // The cost is that `function f() end` at the top level of a script is a
    // global and now fails; `local function f() end` is the spelling, and it
    // is the spelling Redis requires too.
    // Two locks, because the metatable alone is not one.  rawset goes straight
    // past __newindex -- measured: `rawset(_G, "sneak", 1)` stored, and the
    // next script read it back -- and table.insert would reach the same table
    // by number.  Every one of those routes needs a REFERENCE to the globals
    // table, so the name is taken away first and the metatable then covers the
    // ordinary assignment that needs no name at all.
    //
    // getfenv and setfenv are already nil in this sandbox, and load, loadstring
    // and require with them, so there is no second way to name it.
    //
    // And the names that already exist are locked too, which the metatable
    // alone did not do: `redis.call = f` or `redis = nil` in one script held
    // for every later script from every client, so the globals move into a
    // backing table behind __index, the libraries behind read-only proxies,
    // the string metatable behind __metatable, and rawset out of reach.
    // KEYS and ARGV get a protected metatable, since one planted there by a script would answer every later script's reads.
    m_lua.script(
        "local g = _G\n"
        "local rawset, pairs, ipairs, setmetatable, getmetatable, type =\n"
        "      rawset, pairs, ipairs, setmetatable, getmetatable, type\n"
        "local ros = {}\n"
        "local function ro(t)\n"
        "  local p = setmetatable({}, { __index = t, __metatable = false,\n"
        "    __newindex = function() error('Attempt to modify a readonly table', 2) end })\n"
        "  ros[p] = true\n"
        "  return p\n"
        "end\n"
        "local tbl = g.table\n"
        "if type(tbl) == 'table' then\n"
        "  for _, n in ipairs({ 'insert', 'remove', 'sort' }) do\n"
        "    local f = tbl[n]\n"
        "    if type(f) == 'function' then\n"
        "      tbl[n] = function(t, ...)\n"
        "        if ros[t] then error('Attempt to modify a readonly table', 2) end\n"
        "        return f(t, ...)\n"
        "      end\n"
        "    end\n"
        "  end\n"
        "end\n"
        "getmetatable('').__metatable = false\n"
        "setmetatable(g.KEYS, { __metatable = false })\n"
        "setmetatable(g.ARGV, { __metatable = false })\n"
        "local backing = {}\n"
        "for k, v in pairs(g) do backing[k] = v end\n"
        "for _, n in ipairs({ 'string', 'table', 'math', 'redis' }) do\n"
        "  if type(backing[n]) == 'table' then backing[n] = ro(backing[n]) end\n"
        "end\n"
        "backing.server = backing.redis\n"
        "backing.rawset = nil\n"
        "backing._G = nil\n"
        "local names = {}\n"
        "for k in pairs(g) do names[#names + 1] = k end\n"
        "for _, k in ipairs(names) do rawset(g, k, nil) end\n"
        "setmetatable(g, { __index = backing, __metatable = false,\n"
        "  __newindex = function(_, n)\n"
        "    if backing[n] ~= nil then\n"
        "      error(\"Attempt to modify a readonly table: '\" .. tostring(n) .. \"'\", 2)\n"
        "    end\n"
        "    error(\"Script attempted to create global variable '\" ..\n"
        "          tostring(n) .. \"'\", 2)\n"
        "  end })\n");
}

bool cache_script_engine::eval(std::string_view body,
                               std::span<const std::string_view> keys,
                               std::span<const std::string_view> argv,
                               const command_fn& call,
                               std::string& resp_out,
                               std::string& err)
{
    ensure_state();

    // Refilled, not rebuilt.  The tables and their two global bindings are made
    // once; a call only writes the elements it needs and clears whatever the
    // previous script left past its own end.
    // Every other entry is walked out of the table, since a script may write KEYS[5] itself and no length finds it.
    // Written raw, and no script can give either table a metatable: ensure_state() protects both.
    lua_State* L = m_lua.lua_state();
    const auto refill = [L](const sol::table& t, std::span<const std::string_view> v)
    {
        t.push();
        for (size_t i = 0; i < v.size(); ++i)
        {
            lua_pushlstring(L, v[i].data(), v[i].size());
            lua_rawseti(L, -2, static_cast<int>(i + 1));
        }
        lua_pushnil(L);
        while (lua_next(L, -2) != 0)
        {
            lua_pop(L, 1);
            if (lua_type(L, -1) == LUA_TNUMBER)
            {
                const lua_Number d = lua_tonumber(L, -1);
                if (d >= 1 && d <= static_cast<lua_Number>(v.size()) && d == static_cast<lua_Number>(static_cast<int64_t>(d)))
                    continue;
            }
            lua_pushvalue(L, -1);
            lua_pushnil(L);
            lua_rawset(L, -4);
        }
        lua_pop(L, 1);
    };
    refill(m_keys_tbl, keys);
    refill(m_argv_tbl, argv);

    // For the duration of this call only: the closures in the `redis` table
    // read it, and what it held before is put back on the way out, so an eval
    // that redis.call started leaves the outer script its own.
    struct call_guard
    {
        const command_fn** slot; const command_fn* prev;
        ~call_guard() { *slot = prev; }
    } cg{ &m_call, m_call };
    m_call = &call;

    // Looked up by the body itself.  The SHA it used to be keyed by cost an
    // OpenSSL context allocation and a forty-character string build on every
    // call, to arrive at a name for something we were already holding.
    // Counted for this call, so trim_eval() never drops the chunk an outer script is still running.
    struct depth_guard
    {
        int& d;
        cache_script_engine* e;
        ~depth_guard() { if (--d == 0) e->trim_eval(); }
    } dg{ ++m_depth, this };
    // A script already at the front, the one a client runs over and over, skips the hash a move to the front would cost.
    if (m_eval_lru.empty() || m_eval_lru.front() != body)
        if (const auto at = m_eval_at.find(body); at != m_eval_at.end())
            m_eval_lru.splice(m_eval_lru.begin(), m_eval_lru, at->second);

    auto cached = m_compiled.find(body);
    if (cached == m_compiled.end())
    {
        // Compiled before it is made known, so a body that does not compile has no SHA, as on Redis.
        if (!compile(body, err))
            return false;
        cached = m_compiled.find(body);
        // EVAL loads as well as runs, so the SHA it would have under SCRIPT
        // LOAD works afterwards -- which is what lets a client try EVALSHA
        // first and fall back once.  Here and not per call: SCRIPT FLUSH empties
        // both maps, so a body compiled is a body loaded.
        // Made known by EVAL alone it is one of the scripts kept only while they are run often enough.
        const bool pinned = m_sha_of.find(body) != m_sha_of.end() && m_eval_at.find(body) == m_eval_at.end();
        remember(body);
        if (!pinned && m_eval_at.find(body) == m_eval_at.end())
        {
            m_eval_lru.emplace_front(body);
            m_eval_at.emplace(std::string(body), m_eval_lru.begin());
        }
    }

    // Armed for this call, and NOT hoisted out of it: this is what stops a
    // `while true do end` from holding the event loop for ever.  It was lost
    // once already when the compile moved into a cache -- the scope sat
    // between the lines that were replaced -- and the deadline test caught it
    // by running past its own timeout while the cache stopped answering.
    lua_deadline::scope deadline("a script", lua_deadline::default_ms(), "cache eval");

    sol::protected_function_result r = cached->second();
    if (!r.valid())
    {
        sol::error e = r;
        err = shape_lua_error(e.what());
        return false;
    }

    if (r.return_count() > 0) lua_to_resp(L, r.stack_index(), resp_out);
    else                      resp::encode_null_into(resp_out);
    return true;
}

}  // namespace socketley

#endif  // SOCKETLEY_NO_LUA
