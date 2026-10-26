#include "mail_template.h"

#include <sol/sol.hpp>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <tuple>
#include <vector>

namespace socketley::mail
{

namespace
{

bool lua_name(std::string_view s)
{
    static constexpr std::string_view keywords[] = {"and",  "break", "do",     "else", "elseif", "end",   "false",
                                                    "for",  "function", "goto", "if",   "in",     "local", "nil",
                                                    "not",  "or",    "repeat", "return", "then",  "true",  "until",
                                                    "while"};
    if (s.empty() || std::isdigit(static_cast<unsigned char>(s[0])))
        return false;
    for (const char ch : s)
        if (!std::isalnum(static_cast<unsigned char>(ch)) && ch != '_')
            return false;
    return std::find(std::begin(keywords), std::end(keywords), s) == std::end(keywords);
}

// A Lua string literal of `s`, on one line whatever it holds.
std::string literal(std::string_view s)
{
    std::string out = "\"";
    for (const char ch : s)
    {
        const auto u = static_cast<unsigned char>(ch);
        if (ch == '"' || ch == '\\')
            out += {'\\', ch};
        else if (ch == '\n')
            out += "\\n";
        else if (u < 32 || u == 127)
        {
            out += '\\';
            out += static_cast<char>('0' + u / 100);
            out += static_cast<char>('0' + u / 10 % 10);
            out += static_cast<char>('0' + u % 10);
        }
        else
            out += ch;
    }
    return out + "\"";
}

size_t lines_in(std::string_view s)
{
    return static_cast<size_t>(std::count(s.begin(), s.end(), '\n'));
}

std::string_view stripped(std::string_view v)
{
    while (!v.empty() && std::isspace(static_cast<unsigned char>(v.front())))
        v.remove_prefix(1);
    while (!v.empty() && std::isspace(static_cast<unsigned char>(v.back())))
        v.remove_suffix(1);
    return v;
}

// Where a placeholder's default begins: its first bar outside a string, since Lua has no operator of that name.
size_t default_bar(std::string_view s)
{
    char quote = 0;
    for (size_t i = 0; i < s.size(); ++i)
    {
        if (quote && s[i] == '\\')
            ++i;
        else if (quote && s[i] == quote)
            quote = 0;
        else if (!quote && (s[i] == '"' || s[i] == '\''))
            quote = s[i];
        else if (!quote && s[i] == '|')
            return i;
    }
    return std::string_view::npos;
}

// A name, its parts after dots, looked up so that one missing anywhere is no value rather than an error; a part
// may hold a hyphen, as a field's name does. Anything else is a Lua expression.
std::string name_lookup(std::string_view e, bool& named)
{
    named = !e.empty() && !std::isdigit(static_cast<unsigned char>(e[0])) &&
            e.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-") == std::string_view::npos &&
            e.front() != '.' && e.back() != '.' && e.find("..") == std::string_view::npos;
    if (!named)
        return "(" + std::string(e) + ")";
    std::vector<std::string_view> parts;
    for (std::string_view rest = e; !rest.empty();)
    {
        const size_t dot = rest.find('.');
        parts.push_back(rest.substr(0, dot));
        rest = dot == std::string_view::npos ? std::string_view{} : rest.substr(dot + 1);
    }
    std::string code = lua_name(parts[0]) ? std::string(parts[0]) : "_E[" + literal(parts[0]) + "]";
    if (parts.size() == 1)
        return code;
    code = "_p(" + code;
    for (size_t i = 1; i < parts.size(); ++i)
        code += ", " + literal(parts[i]);
    return code + ")";
}

// What a template calls beyond its recipient's values and the script's: the runtime of {{ }}, include(), and how a
// recipient is filled. The script's globals reach all of Lua; a template reaches what the script defines and `lib`.
constexpr const char* prelude = R"lua(
local compile, dir = ...
local safe_mt = {}
local escapes = { ["&"] = "&amp;", ["<"] = "&lt;", [">"] = "&gt;", ['"'] = "&quot;", ["'"] = "&#39;" }
local function esc(s) return (s:gsub("[&<>\"']", escapes)) end
local entities = { amp = "&", lt = "<", gt = ">", quot = '"', ["#39"] = "'" }
local function unesc(s) return (s:gsub("&(#?%w+);", entities)) end

local lib = {
    assert = assert, error = error, ipairs = ipairs, next = next, pairs = pairs, pcall = pcall, select = select,
    tonumber = tonumber, tostring = tostring, type = type, unpack = unpack, xpcall = xpcall,
    string = string, table = table, math = math,
    os = { date = os.date, time = os.time, clock = os.clock, difftime = os.difftime },
}
function lib.raw(s) return setmetatable({ tostring(s) }, safe_mt) end
function lib.html(s) return lib.raw(esc(tostring(s))) end
function lib.url(s)
    return (tostring(s):gsub("[^%w%-%._~]", function(c) return string.format("%%%02X", c:byte()) end))
end
local G = setmetatable({}, { __index = function(_, k)
    local v = _G[k]
    if v ~= nil then return v end
    return lib[k]
end })

local function path_of(v, ...)
    for i = 1, select("#", ...) do
        if type(v) ~= "table" then return nil end
        v = v[(select(i, ...))]
    end
    return v
end

local cur, depth, cache = nil, 0, {}
local function render(chunk, env, ctx)
    local b = {}
    local function o(s) b[#b + 1] = s end
    local function v(x, src, dflt, raw, named)
        if type(x) == "table" and getmetatable(x) == safe_mt then
            b[#b + 1] = x[1]
            return
        end
        if type(x) == "table" then
            local words = {}
            for i, e in ipairs(x) do
                if type(e) ~= "string" and type(e) ~= "number" then
                    error("{{" .. src .. "}} is a list of tables, which {% for %} walks", 2)
                end
                words[i] = tostring(e)
            end
            if #words == 0 and next(x) ~= nil then error("{{" .. src .. "}} is a table, not a value", 2) end
            x = table.concat(words, ", ")
        end
        if x == nil or x == false or x == "" then
            if not dflt then
                if named and not ctx.missing then ctx.missing = src end
                return
            end
            x = dflt
        end
        x = tostring(x)
        b[#b + 1] = (ctx.html and not raw) and esc(x) or x
    end
    local was = cur
    cur = { env = env, ctx = ctx }
    setfenv(chunk, env)
    local ok, err = pcall(chunk, o, v, path_of, env)
    cur = was
    if not ok then error(err, 0) end
    return table.concat(b)
end

local function load_template(text, name)
    local code, why = compile(text, name)
    if not code then return nil, why end
    return loadstring(code, "@" .. name)
end

function lib.include(path)
    path = tostring(path)
    if not cur then error("include() is for a template", 2) end
    if depth >= 16 then error("include() goes deeper than 16 templates", 2) end
    -- A template reaches no file but those beside it.
    if path:sub(1, 1) == "/" or ("/" .. path .. "/"):find("/%.%./") then
        error("include() takes a template beside this one, not " .. path, 2)
    end
    path = dir .. "/" .. path
    local chunk = cache[path]
    if not chunk then
        local h, err = io.open(path, "rb")
        if not h then error(err, 2) end
        local text = h:read("*a")
        h:close()
        chunk, err = load_template(text, path)
        if not chunk then error(err, 2) end
        cache[path] = chunk
    end
    depth = depth + 1
    local ok, s = pcall(render, chunk, cur.env, cur.ctx)
    depth = depth - 1
    if not ok then error(s, 0) end
    return lib.raw(s)
end

local function env_for(r)
    return setmetatable({ recipient = r }, { __index = function(_, k)
        local v = r[k]
        if v ~= nil then return v end
        v = rawget(G, k)
        if v ~= nil then return v end
        return lib[k]
    end })
end

-- Each <a>'s href but the runtime's {{unsubscribe}} and a cid:, as on_link answers for it.
local function links(h, fn, r)
    return (h:gsub("<[aA]%s[^>]*>", function(tag)
        return (tag:gsub("(%s[hH][rR][eE][fF]%s*=%s*)([\"'])(.-)%2", function(pre, q, u)
            if u == "{{unsubscribe}}" or u:sub(1, 4):lower() == "cid:" then return nil end
            local to = fn(unesc(u), r)
            if to == nil then return nil end
            return pre .. q .. esc(tostring(to)) .. q
        end, 1))
    end))
end

local parts, api = {}, {}
function api.add(part, name, text)
    local chunk, why = load_template(text, name)
    if not chunk then return nil, why end
    parts[part] = chunk
    return true
end
function api.script(path)
    local chunk, why = loadfile(path)
    if not chunk then return nil, why end
    setfenv(chunk, G)
    local ok, err = pcall(chunk)
    if not ok then return nil, tostring(err) end
    return true
end
function api.fill(r, strict)
    local hook = rawget(G, "on_recipient")
    if type(hook) == "function" then
        local ok, keep, why = pcall(hook, r)
        if not ok then return "failed", tostring(keep) end
        if keep == false then return "skipped", why ~= nil and tostring(why) or "on_recipient left them out" end
    end
    local env, out = env_for(r), {}
    for _, p in ipairs({ "subject", "html", "text" }) do
        if parts[p] then
            local ctx = { html = p == "html" }
            local ok, s = pcall(render, parts[p], env, ctx)
            if not ok then return "failed", tostring(s) end
            if strict and ctx.missing then return "missing", ctx.missing end
            out[p] = s
        end
    end
    local link = rawget(G, "on_link")
    if out.html and type(link) == "function" then
        local ok, s = pcall(links, out.html, link, r)
        if not ok then return "failed", tostring(s) end
        out.html = s
    end
    local function text(v) return (type(v) == "string" or type(v) == "number") and tostring(v) or "" end
    out.email = text(r.email) ~= "" and text(r.email) or text(r.to)
    out.name = text(r.name)
    return "written", out
end
return api
)lua";

sol::object to_lua(sol::state& lua, const json::jvalue& v)
{
    using kind = json::jvalue::kind;
    switch (v.k)
    {
        case kind::boolean: return sol::make_object(lua, v.b);
        case kind::number: return sol::make_object(lua, std::strtod(v.s.c_str(), nullptr));
        case kind::string: return sol::make_object(lua, v.s);
        case kind::array:
        {
            sol::table t = lua.create_table(static_cast<int>(v.items.size()), 0);
            size_t at = 0;
            for (const auto& item : v.items)
                if (item.k != kind::null)
                    t[++at] = to_lua(lua, item);
            return t;
        }
        case kind::object:
        {
            sol::table t = lua.create_table(0, static_cast<int>(v.members.size()));
            for (const auto& [k, m] : v.members)
                if (m.k != kind::null)
                    t[k] = to_lua(lua, m);
            return t;
        }
        case kind::null: break;
    }
    return sol::make_object(lua, sol::lua_nil);
}

}   // namespace

bool compile_template(std::string_view t, std::string_view name, bool keep_unsubscribe, std::string& code,
                      std::string& why)
{
    code = "local _o, _v, _p, _E = ... ";
    std::string text;
    // The code keeps the template's line numbers, a line ahead where a comment had to be ended.
    size_t ahead = 0;
    const auto align = [&](size_t lines) {
        const size_t k = std::min(lines, ahead);
        ahead -= k;
        code.append(lines - k, '\n');
    };
    const auto flush = [&] {
        if (!text.empty())
            code += "_o(" + literal(text) + ") ";
        align(lines_in(text));
        text.clear();
    };
    size_t i = 0;
    while (i < t.size())
    {
        const size_t at = t.find('{', i);
        if (at == std::string_view::npos || at + 1 >= t.size())
        {
            text.append(t.substr(i));
            break;
        }
        text.append(t.substr(i, at - i));
        const char next = t[at + 1];
        if (next == '%')
        {
            const size_t close = t.find("%}", at + 2);
            if (close == std::string_view::npos)
            {
                why = std::string(name) + ":" + std::to_string(1 + lines_in(t.substr(0, at))) + ": {% is never closed by %}";
                return false;
            }
            size_t end = close + 2;
            // A tag alone on its line takes the line with it, so a loop writes no empty lines.
            const size_t nl = t.rfind('\n', at);
            const size_t line_start = nl == std::string_view::npos ? 0 : nl + 1;
            size_t after = end;
            while (after < t.size() && (t[after] == ' ' || t[after] == '\t' || t[after] == '\r'))
                ++after;
            bool ate_line = false;
            if (t.substr(line_start, at - line_start).find_first_not_of(" \t") == std::string_view::npos &&
                (after == t.size() || t[after] == '\n'))
            {
                text.resize(text.size() - (at - line_start));
                ate_line = after < t.size();
                end = after + (ate_line ? 1 : 0);
            }
            flush();
            const std::string_view body = t.substr(at + 2, close - at - 2);
            const bool comment = !ate_line && body.find("--") != std::string_view::npos;
            code += std::string(body) + (ate_line || comment ? "\n" : " ");
            ahead += comment;
            i = end;
            continue;
        }
        if (next != '{')
        {
            text += '{';
            i = at + 1;
            continue;
        }
        const bool raw = at + 2 < t.size() && t[at + 2] == '{';
        const std::string_view closer = raw ? "}}}" : "}}";
        const size_t from = at + (raw ? 3 : 2), close = t.find(closer, from);
        if (close == std::string_view::npos)
        {
            text.append(t.substr(at, from - at));
            i = from;
            continue;
        }
        const size_t end = close + closer.size();
        const std::string_view inner = t.substr(from, close - from);
        const size_t bar = default_bar(inner);
        const std::string_view expr = stripped(inner.substr(0, bar));
        // Braces that hold nothing are text, as in a style sheet's example.
        if (expr.empty())
        {
            text.append(t.substr(at, end - at));
            i = end;
            continue;
        }
        if (keep_unsubscribe && expr == "unsubscribe" && bar == std::string_view::npos)
        {
            text += "{{unsubscribe}}";
            i = end;
            continue;
        }
        flush();
        bool named = false;
        const std::string value = name_lookup(expr, named);
        code += "_v(" + value + ", " + literal(expr) + ", " +
                (bar == std::string_view::npos ? std::string("nil") : literal(stripped(inner.substr(bar + 1)))) + ", " +
                (raw ? "true" : "false") + ", " + (named ? "true" : "false") + ") ";
        align(lines_in(t.substr(at, end - at)) - lines_in(value));
        i = end;
    }
    flush();
    return true;
}

struct campaign::impl
{
    sol::state lua;
    sol::table api;
};

campaign::campaign(bool ad, std::string dir) : m(std::make_unique<impl>())
{
    m->lua.open_libraries(sol::lib::base, sol::lib::package, sol::lib::string, sol::lib::table, sol::lib::math,
                          sol::lib::os, sol::lib::io, sol::lib::bit32);
    const auto compile = [ad](const std::string& text, const std::string& name) {
        std::string code, why;
        const bool ok = compile_template(text, name, ad, code, why);
        return std::make_tuple(ok ? sol::optional<std::string>(std::move(code)) : sol::nullopt, why);
    };
    sol::load_result chunk = m->lua.load(prelude, "@campaign");
    sol::protected_function_result r = chunk.get<sol::protected_function>()(compile, dir.empty() ? "." : dir);
    m->api = r.get<sol::table>();
}

campaign::~campaign() = default;

namespace
{

// A call of the prelude's that answers true, or nil and why.
bool answered(sol::protected_function_result r, std::string& why)
{
    if (!r.valid())
    {
        const sol::error e = r;
        why = e.what();
        return false;
    }
    if (r.get<sol::object>(0).is<bool>() && r.get<bool>(0))
        return true;
    why = r.get<sol::object>(1).is<std::string>() ? r.get<std::string>(1) : "it does not load";
    return false;
}

}   // namespace

bool campaign::script(const std::string& path, std::string& why)
{
    return answered(m->api.get<sol::protected_function>("script")(path), why);
}

bool campaign::add(part p, std::string_view name, std::string_view text, std::string& why)
{
    const char* slot = p == part::subject ? "subject" : p == part::html ? "html" : "text";
    return answered(m->api.get<sol::protected_function>("add")(slot, std::string(name), std::string(text)), why);
}

campaign::result campaign::fill(const json::jvalue& recipient, bool strict, message& out, std::string& why)
{
    sol::protected_function_result r = m->api.get<sol::protected_function>("fill")(to_lua(m->lua, recipient), strict);
    if (!r.valid())
    {
        const sol::error e = r;
        why = e.what();
        return result::failed;
    }
    const std::string status = r.get<std::string>(0);
    if (status != "written")
    {
        why = r.get<std::string>(1);
        return status == "skipped" ? result::skipped : status == "missing" ? result::missing : result::failed;
    }
    const sol::table t = r.get<sol::table>(1);
    out.email = t.get_or<std::string>("email", "");
    out.name = t.get_or<std::string>("name", "");
    out.subject = t.get_or<std::string>("subject", "");
    out.html = t.get_or<std::string>("html", "");
    out.text = t.get_or<std::string>("text", "");
    return result::written;
}

}   // namespace socketley::mail
