#include "cache_script.h"

#ifndef SOCKETLEY_NO_LUA

#include "resp_parser.h"
#include "../../shared/lua_context.h"

#include <openssl/evp.h>
#include <cstdio>
#include <cstring>

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

std::string cache_script_engine::load(std::string_view body)
{
    // EVAL registers its body on every call, so a client that never uses
    // EVALSHA still paid for one SHA1 per command: an OpenSSL context
    // allocated and freed, then forty characters appended one at a time.  That
    // was 5% of the worker in the profile, under a name -- push_back -- that
    // says nothing about scripting at all.
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
bool reply_to_lua(sol::state& L, std::string_view& p, sol::object& out)
{
    if (p.empty()) return false;
    const char t = p.front();
    const size_t nl = p.find("\r\n");
    if (nl == std::string_view::npos) return false;
    const std::string_view head = p.substr(1, nl - 1);
    p.remove_prefix(nl + 2);

    switch (t)
    {
        case '+':
        {
            // A status is a table so a script can tell +OK from the string
            // "OK", which is what Redis's own contract promises.
            sol::table tb = L.create_table();
            tb["ok"] = std::string(head);
            out = tb;
            return true;
        }
        case '-':
        {
            sol::table tb = L.create_table();
            tb["err"] = std::string(head);
            out = tb;
            return true;
        }
        case ':':
        {
            long long v = 0;
            std::from_chars(head.data(), head.data() + head.size(), v);
            out = sol::make_object(L, static_cast<double>(v));
            return true;
        }
        case '$':
        {
            long long n = -1;
            std::from_chars(head.data(), head.data() + head.size(), n);
            if (n < 0) { out = sol::make_object(L, false); return true; }
            if (p.size() < static_cast<size_t>(n) + 2) return false;
            out = sol::make_object(L, std::string(p.substr(0, static_cast<size_t>(n))));
            p.remove_prefix(static_cast<size_t>(n) + 2);
            return true;
        }
        case '*':
        {
            long long n = -1;
            std::from_chars(head.data(), head.data() + head.size(), n);
            if (n < 0) { out = sol::make_object(L, false); return true; }
            sol::table tb = L.create_table(static_cast<int>(n), 0);
            for (long long i = 0; i < n; ++i)
            {
                sol::object e;
                if (!reply_to_lua(L, p, e)) return false;
                tb[i + 1] = e;
            }
            out = tb;
            return true;
        }
        default: return false;
    }
}

// And the other direction, for what the script returns.  A table is an array
// up to its first hole, which is Lua's own idea of where an array ends -- and
// `err` and `ok` are checked first, because a table carrying either is a reply
// and not a list.
void lua_to_resp(const sol::object& v, std::string& out, int depth = 0)
{
    if (depth > 16) { resp::encode_null_into(out); return; }

    switch (v.get_type())
    {
        case sol::type::nil:
        case sol::type::none:
            resp::encode_null_into(out);
            return;
        case sol::type::boolean:
            // false is a nil reply and true is 1: Lua has no other way to say
            // "no value", and Redis chose these.
            if (v.as<bool>()) resp::encode_integer_into(out, 1);
            else              resp::encode_null_into(out);
            return;
        case sol::type::number:
        {
            // Truncated towards zero, not rounded: a script returning 3.7 is
            // returning 3 on Redis, and a caller that wanted 3.7 has to return
            // a string.
            const double d = v.as<double>();
            resp::encode_integer_into(out, static_cast<int64_t>(d));
            return;
        }
        case sol::type::string:
            resp::encode_bulk_into(out, v.as<std::string>());
            return;
        case sol::type::table:
        {
            sol::table t = v.as<sol::table>();
            sol::object err = t["err"];
            if (err.valid() && err.get_type() == sol::type::string)
            { resp::encode_error_code_into(out, err.as<std::string>()); return; }
            sol::object ok = t["ok"];
            if (ok.valid() && ok.get_type() == sol::type::string)
            { resp::encode_simple_into(out, ok.as<std::string>()); return; }

            // The length is where the first hole is, so { 1, 2, nil, 4 } is
            // two elements -- Lua's rule, and Redis follows it.
            int n = 0;
            while (true)
            {
                sol::object e = t[n + 1];
                if (!e.valid() || e.get_type() == sol::type::nil) break;
                ++n;
            }
            resp::encode_array_header_into(out, n);
            for (int i = 1; i <= n; ++i)
                lua_to_resp(t[i], out, depth + 1);
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
    const auto run = [this](bool raising, sol::variadic_args va) -> sol::object
    {
        std::string raw;
        int n = 0;
        for (auto a : va)
        {
            std::string sv;
            if (a.get_type() == sol::type::number)
            {
                // An integer argument is spelled without a decimal point,
                // because `redis.call('expire', k, 60)` must not send "60.0".
                const double d = a.as<double>();
                char buf[40];
                if (d == static_cast<double>(static_cast<long long>(d)))
                    std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(d));
                else
                    std::snprintf(buf, sizeof(buf), "%.17g", d);
                sv = buf;
            }
            else if (a.get_type() == sol::type::string) sv = a.as<std::string>();
            else
            {
                if (raising)
                    throw sol::error("Lua redis lib command arguments must be strings or integers");
                sol::table e = m_lua.create_table();
                e["err"] = "Lua redis lib command arguments must be strings or integers";
                return e;
            }
            resp::encode_bulk_into(raw, sv);
            ++n;
        }
        if (n == 0 || !m_call)
        {
            if (raising) throw sol::error("Please specify at least one argument for redis.call()");
            sol::table e = m_lua.create_table();
            e["err"] = "Please specify at least one argument for redis.call()";
            return e;
        }

        std::string cmd;
        resp::encode_array_header_into(cmd, n);
        cmd += raw;

        std::string reply;
        (*m_call)(cmd, reply);

        std::string_view p(reply);
        sol::object out;
        if (!reply_to_lua(m_lua, p, out))
        {
            if (raising) throw sol::error("the cache answered something this cannot read");
            sol::table e = m_lua.create_table();
            e["err"] = "the cache answered something this cannot read";
            return e;
        }
        // redis.call raises what redis.pcall returns, which is the whole
        // difference between them.
        if (raising && out.get_type() == sol::type::table)
        {
            sol::object e = out.as<sol::table>()["err"];
            if (e.valid() && e.get_type() == sol::type::string)
                throw sol::error(e.as<std::string>());
        }
        return out;
    };

    sol::table redis = m_lua.create_table();
    redis.set_function("call",  [run](sol::variadic_args va) { return run(true,  va); });
    redis.set_function("pcall", [run](sol::variadic_args va) { return run(false, va); });
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
    m_lua.script(
        "local g = _G\n"
        "local rawset, pairs, ipairs, setmetatable, getmetatable, type =\n"
        "      rawset, pairs, ipairs, setmetatable, getmetatable, type\n"
        "local function ro(t)\n"
        "  return setmetatable({}, { __index = t, __metatable = false,\n"
        "    __newindex = function() error('Attempt to modify a readonly table', 2) end })\n"
        "end\n"
        "getmetatable('').__metatable = false\n"
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
                               const std::vector<std::string_view>& keys,
                               const std::vector<std::string_view>& argv,
                               const command_fn& call,
                               std::string& resp_out,
                               std::string& err)
{
    ensure_state();

    // Refilled, not rebuilt.  The tables and their two global bindings are made
    // once; a call only writes the elements it needs and clears whatever the
    // previous script left past its own end.  Views go in directly -- sol
    // pushes a Lua string of that length, so the std::string copy per key was
    // an allocation for nothing.
    // The tail is measured on the table and not remembered from last time: a
    // script may write KEYS[5] itself, and trusting our own count would leave
    // that entry visible to the next script.  Scripts already share globals
    // here -- there is no metatable guarding them, which Redis does have -- so
    // this does not close that door, it just does not open it wider.
    const size_t prev_k = m_keys_tbl.size();
    const size_t prev_a = m_argv_tbl.size();
    for (size_t i = 0; i < keys.size(); ++i) m_keys_tbl[i + 1] = keys[i];
    for (size_t i = keys.size(); i < prev_k; ++i) m_keys_tbl[i + 1] = sol::lua_nil;
    for (size_t i = 0; i < argv.size(); ++i) m_argv_tbl[i + 1] = argv[i];
    for (size_t i = argv.size(); i < prev_a; ++i) m_argv_tbl[i + 1] = sol::lua_nil;

    // For the duration of this call only: the closures in the `redis` table
    // read it, and it is cleared on the way out so a stale one cannot be used
    // by a script that somehow runs outside an eval.
    m_call = &call;
    struct call_guard { const command_fn** slot; ~call_guard() { *slot = nullptr; } }
        cg{ &m_call };

    // Looked up by the body itself.  The SHA it used to be keyed by cost an
    // OpenSSL context allocation and a forty-character string build on every
    // call, to arrive at a name for something we were already holding.
    auto cached = m_compiled.find(body);
    if (cached == m_compiled.end())
    {
        // Named so a compile error points at "user_script" the way Redis's
        // does, rather than at the script's own first line quoted back.
        // Text only, because LuaJIT runs bytecode unverified and a crafted
        // chunk from any client that can reach the port is native code.
        sol::load_result lr = m_lua.load(std::string(body), "@user_script",
                                         sol::load_mode::text);
        if (!lr.valid())
        {
            sol::error e = lr;
            err = shape_lua_error(e.what());
            return false;
        }
        cached = m_compiled.emplace(std::string(body),
                                    lr.get<sol::protected_function>()).first;
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

    sol::object v = r.get<sol::object>();
    lua_to_resp(v, resp_out);
    return true;
}

}  // namespace socketley

#endif  // SOCKETLEY_NO_LUA
