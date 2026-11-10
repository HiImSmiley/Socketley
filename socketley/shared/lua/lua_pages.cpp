#include "lua_pages.h"

#ifndef SOCKETLEY_NO_LUA

#include "../http/site_path.h"
#include "lua_suspend.h"
#include "lua_template.h"

#include <fcntl.h>
#include <linux/openat2.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <iostream>

namespace socketley::lua_pages
{

namespace
{

// The frame every page runs in: an environment of its own a request, so a global one request sets is not the next
// one's, with the request (its query, form, files and cookies read the first time they are asked for) and the
// helpers a page answers with, and what it returns or echoed made into the table on_http_request returns.
static constexpr char k_frame[] = R"lua(
local html_escape, c_url_decode = ...
local setfenv, setmetatable, getmetatable, rawget, rawset, select, tostring, tonumber, type, next, pairs, ipairs =
  setfenv, setmetatable, getmetatable, rawget, rawset, select, tostring, tonumber, type, next, pairs, ipairs
local concat, gsub, char, byte, format, find, sub, lower, match, gmatch =
  table.concat, string.gsub, string.char, string.byte, string.format, string.find, string.sub, string.lower,
  string.match, string.gmatch
local json_encode, json_decode, random_hex = socketley.json_encode, socketley.json_decode, socketley.random_hex
local G = _G

-- In C for the reason escape is: a form's every name and value goes through it.
local function url_decode(s)
  if type(s) ~= "string" then s = tostring(s) end
  return c_url_decode(s)
end
local function url_encode(s)
  return (gsub(tostring(s), "[^%w%-%._~]", function(c) return format("%%%02X", byte(c)) end))
end
-- In C: gsub with a table is never compiled, and cost 0.28 us a call, half of a 50-item template's page.
local function escape(s)
  if type(s) ~= "string" then s = tostring(s) end
  return html_escape(s)
end

-- A name ending in [] gathers a list, as a form's repeated field does.
local function put(t, k, v)
  if sub(k, -2) == "[]" then
    k = sub(k, 1, -3)
    local l = t[k]
    if type(l) ~= "table" then l = {}; t[k] = l end
    l[#l + 1] = v
  else
    t[k] = v
  end
end
local function parse_form(s, t)
  t = t or {}
  if s == nil or s == "" then return t end
  for part in gmatch(s, "[^&]+") do
    local k, v = match(part, "^([^=]*)=?(.*)$")
    if k ~= "" then put(t, url_decode(k), url_decode(v)) end
  end
  return t
end
local function parse_cookies(s)
  local t = {}
  if s then
    for part in gmatch(s, "[^;]+") do
      local k, v = match(part, "^%s*([^=]-)%s*=%s*(.-)%s*$")
      if k and k ~= "" and t[k] == nil then t[k] = v end
    end
  end
  return t
end
local function header_of(req, name)
  local hs = rawget(req, "headers")
  local v = hs[name]
  if v ~= nil then return v end
  name = lower(name)
  for k, x in pairs(hs) do
    if lower(k) == name then return x end
  end
  return nil
end
local function parse_multipart(body, boundary, post, files)
  local delim = "--" .. boundary
  local pos = find(body, delim, 1, true)
  while pos do
    local start = pos + #delim
    if sub(body, start, start + 1) == "--" then break end
    start = start + 2
    local stop = find(body, "\r\n" .. delim, start, true)
    if not stop then break end
    local part = sub(body, start, stop - 1)
    local hend = find(part, "\r\n\r\n", 1, true)
    if hend then
      local head, data = sub(part, 1, hend - 1), sub(part, hend + 4)
      local disp = match(head, "[Cc]ontent%-[Dd]isposition:([^\r\n]*)") or ""
      local name, filename = match(disp, 'name="([^"]*)"'), match(disp, 'filename="([^"]*)"')
      if name then
        if filename then
          local ctype = match(head, "[Cc]ontent%-[Tt]ype:%s*([^\r\n]*)") or "application/octet-stream"
          put(files, name, { filename = filename, type = ctype, data = data, size = #data })
        else
          put(post, name, data)
        end
      end
    end
    pos = stop + 2
  end
end
local function body_fields(req)
  local post, files = {}, {}
  local ctype = header_of(req, "Content-Type") or ""
  local lc = lower(ctype)
  if find(lc, "application/x-www-form-urlencoded", 1, true) then
    parse_form(rawget(req, "body"), post)
  elseif find(lc, "multipart/form-data", 1, true) then
    local b = match(ctype, 'boundary="?([^";]+)"?')
    if b then parse_multipart(rawget(req, "body"), b, post, files) end
  end
  rawset(req, "post", post)
  rawset(req, "files", files)
end
-- What a page reads of the request, each made the first time it is read.
local req_mt = { __index = function(req, k)
  if k == "get" then
    local v = parse_form(rawget(req, "query")); rawset(req, k, v); return v
  elseif k == "cookies" then
    local v = parse_cookies(header_of(req, "Cookie")); rawset(req, k, v); return v
  elseif k == "post" or k == "files" then
    body_fields(req); return rawget(req, k)
  elseif k == "header" then
    return header_of
  end
end }

-- What render() writes a template's values with: escaped for HTML unless raw() marked one.
local safe_mt = {}
-- A name's parts, which the compiled template passes as strings, so the first missing one ends them; past four the
-- general walk.
local function path_of(v, a, b, c, d, ...)
  if type(v) ~= "table" then return nil end
  v = v[a]
  if b == nil then return v end
  if type(v) ~= "table" then return nil end
  v = v[b]
  if c == nil then return v end
  if type(v) ~= "table" then return nil end
  v = v[c]
  if d == nil then return v end
  if type(v) ~= "table" then return nil end
  v = v[d]
  for i = 1, select("#", ...) do
    if type(v) ~= "table" then return nil end
    v = v[(select(i, ...))]
  end
  return v
end

return function(factory, req, load, tload)
  setmetatable(req, req_mt)
  local out, n = {}, 0
  local res = { status = 200, headers = {} }
  local env = setmetatable({ req = req, escape = escape, url_encode = url_encode, url_decode = url_decode },
                           { __index = G })
  env.echo = function(...)
    for i = 1, select("#", ...) do
      n = n + 1
      out[n] = tostring((select(i, ...)))
    end
  end
  env.header = function(k, v) res.headers[k] = v end
  env.status = function(code) res.status = code end
  env.redirect = function(url, code)
    res.status = code or 302
    res.headers["Location"] = url
  end
  env.set_cookie = function(name, value, o)
    o = o or {}
    local c = { name .. "=" .. tostring(value), "Path=" .. (o.path or "/") }
    if o.max_age then c[#c + 1] = "Max-Age=" .. tostring(o.max_age) end
    if o.domain then c[#c + 1] = "Domain=" .. o.domain end
    if o.http_only ~= false then c[#c + 1] = "HttpOnly" end
    if o.secure then c[#c + 1] = "Secure" end
    c[#c + 1] = "SameSite=" .. (o.same_site or "Lax")
    local l = res.headers["Set-Cookie"]
    if type(l) ~= "table" then l = {}; res.headers["Set-Cookie"] = l end
    l[#l + 1] = concat(c, "; ")
  end
  -- A response of value as JSON, for `return json(t)`.
  env.json = function(v, code)
    local body, why = json_encode(v)
    if body == false then error("json: " .. tostring(why), 2) end
    res.headers["Content-Type"] = "application/json"
    return { status = code or res.status, headers = res.headers, body = body }
  end
  -- A session: a table kept in a cache runtime under the id its cookie carries, made anew for an id the cache
  -- does not hold, so a client can never pick its own.
  local ids = setmetatable({}, { __mode = "k" })
  local function ask(c, line)
    local v, why = socketley.cache.command(c, line)
    if v == nil then error("session: " .. tostring(why), 3) end
    return v
  end
  local function give(s, id, o)
    ids[s] = { cache = o.cache, id = id, o = o }
  end
  env.session = {
    open = function(cache, o)
      o = o or {}
      o.cache, o.cookie, o.ttl = cache, o.cookie or "sid", o.ttl or 86400
      local id = req.cookies[o.cookie]
      local data
      if type(id) == "string" and #id == 32 and match(id, "^%x+$") then
        local v = ask(cache, "get session:" .. id)
        if v ~= "nil" then data = json_decode(v) end
      end
      if type(data) ~= "table" then data, id = {}, nil end
      give(data, id, o)
      return data
    end,
    save = function(s)
      local k = ids[s]
      if not k then error("session.save: not a table session.open gave", 2) end
      k.id = k.id or random_hex(16)
      if not k.id then error("session.save: no random bytes for an id", 2) end
      local body, why = json_encode(s)
      if body == false then error("session.save: " .. tostring(why), 2) end
      ask(k.cache, "setex session:" .. k.id .. " " .. k.o.ttl .. " " .. body)
      env.set_cookie(k.o.cookie, k.id, { max_age = k.o.ttl, secure = k.o.secure, same_site = k.o.same_site })
    end,
    -- A new id for the same data, as a sign-in asks, so an id seen before it is worth nothing after.
    regenerate = function(s)
      local k = ids[s]
      if not k then error("session.regenerate: not a table session.open gave", 2) end
      if k.id then ask(k.cache, "del session:" .. k.id) end
      k.id = nil
      env.session.save(s)
    end,
    destroy = function(s)
      local k = ids[s]
      if not k then error("session.destroy: not a table session.open gave", 2) end
      if k.id then ask(k.cache, "del session:" .. k.id) end
      env.set_cookie(k.o.cookie, "", { max_age = 0, secure = k.o.secure, same_site = k.o.same_site })
      for key in pairs(s) do s[key] = nil end
      k.id = nil
    end,
  }
  -- A file under the root run in this request's environment, with what it returns, as a page's head and foot are.
  env.include = function(name, ...)
    local f = load(name)
    setfenv(f, env)
    return f()(...)
  end
  env.raw = function(s) return setmetatable({ tostring(s) }, safe_mt) end
  -- A template under the root filled with `values`, and the page's helpers beside them, as HTML.
  env.render = function(name, values)
    local f = tload(name)
    local b = {}
    local function o(s) b[#b + 1] = s end
    local function v(x, src, dflt, raw)
      if type(x) == "table" and getmetatable(x) == safe_mt then b[#b + 1] = x[1]; return end
      if type(x) == "table" then
        local words = {}
        for i, e in ipairs(x) do
          if type(e) ~= "string" and type(e) ~= "number" then
            error("{{" .. src .. "}} is a list of tables, which {% for %} walks", 2)
          end
          words[i] = tostring(e)
        end
        if #words == 0 and next(x) ~= nil then error("{{" .. src .. "}} is a table, not a value", 2) end
        x = concat(words, ", ")
      end
      if x == nil or x == false or x == "" then
        if not dflt then return end
        x = dflt
      end
      -- A number is never anything to escape.
      if raw or type(x) == "number" then b[#b + 1] = tostring(x) else b[#b + 1] = escape(x) end
    end
    local tenv = setmetatable(values or {}, { __index = env })
    setfenv(f, tenv)
    f()(o, v, path_of, tenv)
    return concat(b)
  end
  -- A closure takes the environment its maker has when it is made, so each request's page is a closure of its own
  -- over this request's env, which a second request setting the factory's env does not change.
  setfenv(factory, env)
  local page = factory()
  local r = page(req)
  if type(r) == "table" then
    -- What the table sets wins; a header() it does not set is still sent.
    if r ~= res and next(res.headers) ~= nil then
      r.headers = r.headers or {}
      for k, v in pairs(res.headers) do
        if r.headers[k] == nil then r.headers[k] = v end
      end
    end
    return r
  end
  if r ~= nil then res.body = tostring(r) else res.body = concat(out, "", 1, n) end
  if res.headers["Content-Type"] == nil then res.headers["Content-Type"] = "text/html; charset=utf-8" end
  return res
end
)lua";

bool field_present(const sol::object& v)
{
    return v.valid() && v != sol::nil;
}

const char* type_name(lua_context& ctx, const sol::object& v)
{
    return lua_typename(ctx.state().lua_state(), static_cast<int>(v.get_type()));
}

reply server_error()
{
    reply r;
    r.status = 500;
    r.body = "500 Internal Server Error";
    return r;
}

// Each segment of `path`, which site_path() gave with single slashes and no dot segment.
template <class F>
bool any_segment(std::string_view path, F&& f)
{
    for (std::string_view rest = path; !rest.empty();)
    {
        const size_t slash = rest.find('/');
        const std::string_view seg = rest.substr(0, slash);
        rest = slash == std::string_view::npos ? std::string_view{} : rest.substr(slash + 1);
        if (!seg.empty() && f(seg))
            return true;
    }
    return false;
}

}   // namespace

bool hidden_to_requests(std::string_view site_path)
{
    return any_segment(site_path, [](std::string_view seg) { return seg.front() == '_'; });
}

bool page_name(std::string_view site_path, std::string& rel)
{
    if (site_path.size() < 5 || site_path.front() != '/' || !site_path.ends_with(".lua") ||
        socketley::http::hidden_path(site_path) || hidden_to_requests(site_path))
        return false;
    rel.assign(site_path.substr(1));
    return true;
}

bool reply_from_lua(lua_context& ctx, std::string_view owner, std::string_view hook, const sol::object& result,
                    reply& out)
{
    if (result.is<sol::table>())
    {
        sol::table resp_tbl = result.as<sol::table>();

        // Absent and unreadable are different answers: a field the
        // script never set takes the documented default, one of the
        // wrong type is a response this end cannot build -- and
        // get_or() cannot tell them apart, so it substituted the
        // default for both and said nothing.
        sol::object status_obj = resp_tbl["status"];
        sol::object body_obj   = resp_tbl["body"];

        if (SOCKETLEY_UNLIKELY(field_present(status_obj) &&
                               status_obj.get_type() != sol::type::number))
        {
            std::cerr << lua_diag::tag(owner)
                      << " " << hook << " returned a table whose `status` is a "
                      << type_name(ctx, status_obj)
                      << "; expected a number — answering 500" << std::endl;
            out = server_error();
            return true;
        }

        if (SOCKETLEY_UNLIKELY(field_present(body_obj) &&
                               body_obj.get_type() != sol::type::string))
        {
            std::cerr << lua_diag::tag(owner)
                      << " " << hook << " returned a table whose `body` is a "
                      << type_name(ctx, body_obj)
                      << "; expected a string — answering 500" << std::endl;
            out = server_error();
            return true;
        }

        int status = resp_tbl.get_or("status", 200);
        // Clamped before the reason is looked up, so "500" is not sent with the text of a code that does not exist.
        if (status < 100 || status > 999)
            status = 500;
        // Read out of the string body_obj anchors in the registry, so
        // the response below is the only copy of it.
        const std::string_view body = field_present(body_obj)
            ? body_obj.as<std::string_view>() : std::string_view();

        // A header this end cannot read costs the client that header,
        // while a status or body it cannot read costs the whole
        // answer, which is why only these are named and skipped.
        std::vector<std::pair<std::string, std::string>> resp_headers;
        sol::object headers_obj = resp_tbl["headers"];
        if (SOCKETLEY_UNLIKELY(field_present(headers_obj) &&
                               !headers_obj.is<sol::table>()))
        {
            std::cerr << lua_diag::tag(owner)
                      << " " << hook << " returned a table whose `headers` is a "
                      << type_name(ctx, headers_obj)
                      << "; expected a table — sending none" << std::endl;
        }
        else if (headers_obj.is<sol::table>())
        {
            headers_obj.as<sol::table>().for_each([&](sol::object key, sol::object val) {
                if (key.is<std::string>() && val.is<std::string>())
                {
                    resp_headers.emplace_back(key.as<std::string>(), val.as<std::string>());
                    return;
                }
                // A list is a line each, for the header that cannot be joined with commas: Set-Cookie.
                if (key.is<std::string>() && val.is<sol::table>())
                {
                    const sol::table list = val.as<sol::table>();
                    for (size_t i = 1; i <= list.size(); ++i)
                        if (const sol::object one = list[i]; one.is<std::string>())
                            resp_headers.emplace_back(key.as<std::string>(), one.as<std::string>());
                    return;
                }
                std::cerr << lua_diag::tag(owner)
                          << " " << hook << " headers: a name and its value must both be"
                             " strings, and one pair was a "
                          << type_name(ctx, key) << " and a "
                          << type_name(ctx, val)
                          << " — dropped it" << std::endl;
            });
        }

        out.status = status;
        out.headers = std::move(resp_headers);
        out.body.assign(body);
        return true;
    }

    // Falling through to the static file or the 404 is what the manual
    // promises for this, so the client's answer does not change; said
    // out loud because only nil declines, and a script that returned a
    // string meant to answer with something this end cannot read.
    if (SOCKETLEY_UNLIKELY(field_present(result)))
    {
        std::cerr << lua_diag::tag(owner) << " " << hook << " returned a "
                  << type_name(ctx, result)
                  << "; expected a table or nil — falling through to the static file or"
                     " the 404" << std::endl;
    }
    return false;
    return false;
}

namespace
{

enum class loaded
{
    missing,   // no regular file at `rel` beneath the root
    failed,    // it did not compile; `why` says how
    ok,        // its factory is on the stack
};

// The factory of the file at `rel` beneath `root_fd` pushed onto `L`, from the registry while the file is the one it
// was compiled from.
loaded load_factory(lua_State* L, cache& c, int root_fd, const std::string& rel, std::string& why,
                    bool as_template = false)
{
    const char* const table = as_template ? "socketley.templates" : "socketley.pages";
    auto& known = as_template ? c.templates : c.compiled;
    // Found current since the site last changed: the compiled one, with nothing asked of the disk.
    if (c.site_gen != 0)
        if (const auto it = known.find(rel); it != known.end() && it->second.seen == c.site_gen)
        {
            lua_getfield(L, LUA_REGISTRYINDEX, table);
            if (lua_istable(L, -1))
            {
                lua_getfield(L, -1, rel.c_str());
                if (lua_isfunction(L, -1))
                {
                    lua_remove(L, -2);
                    return loaded::ok;
                }
                lua_pop(L, 1);
            }
            lua_pop(L, 1);
        }
    struct open_how how{};
    how.flags   = static_cast<uint64_t>(O_RDONLY | O_CLOEXEC);
    how.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS;
    const long r = ::syscall(__NR_openat2, root_fd, rel.c_str(), &how, sizeof(how));
    if (r < 0)
        return loaded::missing;
    const int fd = static_cast<int>(r);
    struct stat st{};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode))
    {
        ::close(fd);
        return loaded::missing;
    }

    lua_getfield(L, LUA_REGISTRYINDEX, table);
    if (!lua_istable(L, -1))
    {
        lua_pop(L, 1);
        lua_newtable(L);
        lua_pushvalue(L, -1);
        lua_setfield(L, LUA_REGISTRYINDEX, table);
    }
    const int pages = lua_gettop(L);

    const cache::version v{st.st_dev, st.st_ino, st.st_size, st.st_mtim.tv_sec, st.st_mtim.tv_nsec, c.site_gen};
    const auto it = known.find(rel);
    const bool fresh = it != known.end() && it->second.dev == v.dev && it->second.ino == v.ino &&
                       it->second.size == v.size && it->second.sec == v.sec && it->second.nsec == v.nsec;
    lua_getfield(L, pages, rel.c_str());
    if (fresh && lua_isfunction(L, -1))
        it->second.seen = c.site_gen;
    else
    {
        lua_pop(L, 1);
        // The file as the body of a function the factory returns, on its first line so the page's line numbers
        // are its own, with the end on a line of its own after a last line that may be a comment.
        std::string src = "return function(...) ";
        const size_t head = src.size();
        src.resize(head + static_cast<size_t>(st.st_size));
        size_t got = 0;
        while (got < static_cast<size_t>(st.st_size))
        {
            const ssize_t n = ::pread(fd, src.data() + head + got, static_cast<size_t>(st.st_size) - got,
                                      static_cast<off_t>(got));
            if (n <= 0)
                break;
            got += static_cast<size_t>(n);
        }
        src.resize(head + got);
        // A template's text becomes the Lua that writes it, the same factory around it.
        if (as_template)
        {
            std::string code;
            if (!socketley::lua_template::compile(std::string_view(src).substr(head), rel, false, code, why))
            {
                ::close(fd);
                lua_pop(L, 1);
                return loaded::failed;
            }
            src.resize(head);
            src.append(code);
        }
        src.append("\nend");
        const std::string chunk = "@" + rel;
        if (luaL_loadbuffer(L, src.data(), src.size(), chunk.c_str()) != 0)
        {
            ::close(fd);
            const char* m = lua_tostring(L, -1);
            why.assign(m ? m : "(no message)");
            lua_pop(L, 2);
            return loaded::failed;
        }
        lua_pushvalue(L, -1);
        lua_setfield(L, pages, rel.c_str());
        known[rel] = v;
    }
    ::close(fd);
    lua_remove(L, pages);
    return loaded::ok;
}

// include(name): the factory of a file under the root, by its path there, for the frame to run in the page's own
// environment; a name starting with _ may be included, as no request may name it.
int load_thunk(lua_State* L, bool as_template)
{
    const char* const fn = as_template ? "render" : "include";
    auto* c = static_cast<cache*>(lua_touserdata(L, lua_upvalueindex(1)));
    size_t n = 0;
    const char* name = luaL_checklstring(L, 1, &n);
    std::string path, rel;
    const std::string_view asked(name, n);
    if (!c || !c->root || asked.empty() || asked.front() == '/' || !asked.ends_with(as_template ? ".tpl" : ".lua") ||
        !socketley::http::site_path("/" + std::string(asked), path) || socketley::http::hidden_path(path) ||
        path.back() == '/')
        return luaL_error(L, "%s: %s is not the path of a %s file under the site's root", fn, name,
                          as_template ? ".tpl" : ".lua");
    rel = path.substr(1);
    std::string why;
    switch (load_factory(L, *c, *c->root, rel, why, as_template))
    {
        case loaded::missing:
            return luaL_error(L, "%s: no file %s under the site's root", fn, rel.c_str());
        case loaded::failed:
            return luaL_error(L, "%s: %s", fn, why.c_str());
        case loaded::ok:
            break;
    }
    return 1;
}

// s with & < > " ' as HTML entities, the same string when it holds none of them.
int html_escape(lua_State* L)
{
    size_t n = 0;
    const char* p = luaL_checklstring(L, 1, &n);
    size_t i = 0;
    while (i < n && p[i] != '&' && p[i] != '<' && p[i] != '>' && p[i] != '"' && p[i] != '\'')
        ++i;
    if (i == n)
    {
        lua_settop(L, 1);
        return 1;
    }
    luaL_Buffer b;
    luaL_buffinit(L, &b);
    luaL_addlstring(&b, p, i);
    for (; i < n; ++i)
        switch (p[i])
        {
            case '&': luaL_addlstring(&b, "&amp;", 5); break;
            case '<': luaL_addlstring(&b, "&lt;", 4); break;
            case '>': luaL_addlstring(&b, "&gt;", 4); break;
            case '"': luaL_addlstring(&b, "&quot;", 6); break;
            case '\'': luaL_addlstring(&b, "&#39;", 5); break;
            default: luaL_addchar(&b, p[i]); break;
        }
    luaL_pushresult(&b);
    return 1;
}

// s with + as a space and each %XX as its byte; a % not followed by two hex digits is left as it is.
int url_decode(lua_State* L)
{
    size_t n = 0;
    const char* p = luaL_checklstring(L, 1, &n);
    size_t i = 0;
    while (i < n && p[i] != '%' && p[i] != '+')
        ++i;
    if (i == n)
    {
        lua_settop(L, 1);
        return 1;
    }
    const auto hex = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    luaL_Buffer b;
    luaL_buffinit(L, &b);
    luaL_addlstring(&b, p, i);
    for (; i < n; ++i)
    {
        if (p[i] == '+')
            luaL_addchar(&b, ' ');
        else if (p[i] == '%' && i + 2 < n && hex(p[i + 1]) >= 0 && hex(p[i + 2]) >= 0)
        {
            luaL_addchar(&b, static_cast<char>(hex(p[i + 1]) * 16 + hex(p[i + 2])));
            i += 2;
        }
        else
            luaL_addchar(&b, p[i]);
    }
    luaL_pushresult(&b);
    return 1;
}

int include_thunk(lua_State* L)
{
    return load_thunk(L, false);
}

int template_thunk(lua_State* L)
{
    return load_thunk(L, true);
}

}   // namespace

outcome run(lua_context& ctx, cache& c, int root_fd, const std::string& rel, const request& req,
            std::string_view owner, done_fn done)
{
    if (c.ctx != &ctx)
    {
        c.compiled.clear();
        c.templates.clear();
        c.ctx = &ctx;
    }
    lua_State* L = ctx.state().lua_state();
    const int top = lua_gettop(L);
    const auto fail = [&](std::string_view what, const char* why) {
        std::cerr << lua_diag::tag(owner) << " page " << rel << ": " << what << (why ? why : "")
                  << " — answering 500" << std::endl;
        lua_settop(L, top);
        done(server_error());
        return outcome::started;
    };

    std::string why;
    switch (load_factory(L, c, root_fd, rel, why))
    {
        case loaded::missing:
            return outcome::not_a_page;
        case loaded::failed:
            return fail("", why.c_str());
        case loaded::ok:
            break;
    }
    const int factory = lua_gettop(L);

    lua_getfield(L, LUA_REGISTRYINDEX, "socketley.page_frame");
    if (!lua_isfunction(L, -1))
    {
        lua_pop(L, 1);
        if (luaL_loadbuffer(L, k_frame, sizeof(k_frame) - 1, "=socketley page") != 0 ||
            (lua_pushcfunction(L, &html_escape), lua_pushcfunction(L, &url_decode), lua_pcall(L, 2, 1, 0)) != 0)
            return fail("the page frame: ", lua_tostring(L, -1));
        lua_pushvalue(L, -1);
        lua_setfield(L, LUA_REGISTRYINDEX, "socketley.page_frame");
    }
    sol::protected_function frame(L, -1);
    sol::protected_function fn(L, factory);
    lua_pushlightuserdata(L, &c);
    lua_pushcclosure(L, &include_thunk, 1);
    sol::protected_function loader(L, -1);
    lua_pushlightuserdata(L, &c);
    lua_pushcclosure(L, &template_thunk, 1);
    sol::protected_function tloader(L, -1);
    lua_settop(L, top);

    sol::table t = ctx.state().create_table(0, 7);
    t["method"] = req.method;
    t["path"] = req.path;
    t["query"] = req.query;
    t["body"] = req.body;
    t["client_id"] = req.client_id;
    t["version"] = req.version;
    sol::table headers = ctx.state().create_table(0, static_cast<int>(req.headers.size()));
    for (const auto& [k, val] : req.headers)
    {
        // A field sent twice is one list, as RFC 9110 joins it, and the cookie lines of HTTP/2 are one Cookie.
        const sol::object prev = headers[k];
        if (prev.is<std::string_view>())
        {
            std::string joined(prev.as<std::string_view>());
            const bool cookie = k.size() == 6 && std::equal(k.begin(), k.end(), "cookie", [](char a, char b) {
                return (a | 0x20) == b;
            });
            joined.append(cookie ? "; " : ", ");
            joined.append(val);
            headers[k] = joined;
        }
        else
            headers[k] = val;
    }
    t["headers"] = headers;

    // On a coroutine, so a page that asks socketley.db or socketley.http lets the runtime serve on while it waits; a
    // raise is reported by the suspender with the page's file and line, which its chunk name carries.
    lua_context* const cp = &ctx;
    auto& sus = ctx.suspender();
    sus.set_next_result([cp, rel, runtime = std::string(owner), done = std::move(done)](lua_State* th, int n,
                                                                                         const char* error) {
        reply out;
        const std::string what = "page " + rel;
        if (error || n < 1 || !th ||
            !reply_from_lua(*cp, runtime, what, sol::stack::get<sol::object>(th, 1), out))
            out = server_error();
        done(std::move(out));
    });
    lua_suspender::id_t id = 0;
    sus.start(frame, "page", ctx.callback_timeout_ms(), id, fn, t, loader, tloader);
    return outcome::started;
}

}   // namespace socketley::lua_pages
#endif
