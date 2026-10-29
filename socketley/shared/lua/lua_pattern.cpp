#ifndef SOCKETLEY_NO_LUA

#include "lua_pattern.h"
#include "lua_context.h"

#include <cstddef>
#include <cstring>

// The matcher is Lua 5.1's lstrlib.c (MIT, PUC-Rio), with the pattern bounded
// by its length rather than its first NUL and the work it does metered.
namespace lua_pattern
{
namespace
{

constexpr int       max_captures   = 32;
constexpr int       max_depth      = 200;
constexpr ptrdiff_t cap_unfinished = -1;
constexpr ptrdiff_t cap_position   = -2;
constexpr char      esc            = '%';
// How much matching work passes between two looks at the clock.
constexpr size_t    check_every    = size_t{1} << 14;

struct match_state
{
    const char* src_init;
    const char* src_end;
    const char* p_end;
    lua_State*  L;
    int         level;
    int         depth;
    size_t      left;
    struct { const char* init; ptrdiff_t len; } capture[max_captures];
};

inline int uc(char c) { return static_cast<unsigned char>(c); }

// Counts `units` of work and asks the deadline each time check_every of them have passed.
void charge(lua_State* L, size_t& left, size_t units)
{
    if (units < left) { left -= units; return; }
    left = check_every;
    lua_deadline::check(L);
}

void prepare(match_state& ms, lua_State* L, const char* s, size_t ls, const char* p, size_t lp)
{
    ms.src_init = s;
    ms.src_end  = s + ls;
    ms.p_end    = p + lp;
    ms.L        = L;
    ms.level    = 0;
    ms.depth    = max_depth;
    ms.left     = check_every;
}

// ASCII only and independent of the locale, as LuaJIT's own classes are.
bool is_digit(int c) { return static_cast<unsigned>(c - '0') < 10u; }
bool is_lower(int c) { return static_cast<unsigned>(c - 'a') < 26u; }
bool is_upper(int c) { return static_cast<unsigned>(c - 'A') < 26u; }
bool is_alpha(int c) { return is_lower(c) || is_upper(c); }
bool is_alnum(int c) { return is_alpha(c) || is_digit(c); }
bool is_space(int c) { return c == ' ' || static_cast<unsigned>(c - '\t') < 5u; }
bool is_cntrl(int c) { return c < 32 || c == 127; }
bool is_punct(int c) { return c > 32 && c < 127 && !is_alnum(c); }
bool is_xdigit(int c) { return is_digit(c) || static_cast<unsigned>(c - 'a') < 6u || static_cast<unsigned>(c - 'A') < 6u; }

bool match_class(int c, int cl)
{
    bool res;
    switch (is_upper(cl) ? cl + 32 : cl)
    {
        case 'a': res = is_alpha(c);  break;
        case 'c': res = is_cntrl(c);  break;
        case 'd': res = is_digit(c);  break;
        case 'l': res = is_lower(c);  break;
        case 'p': res = is_punct(c);  break;
        case 's': res = is_space(c);  break;
        case 'u': res = is_upper(c);  break;
        case 'w': res = is_alnum(c);  break;
        case 'x': res = is_xdigit(c); break;
        case 'z': res = (c == 0);     break;
        default:  return cl == c;
    }
    return is_lower(cl) ? res : !res;
}

int check_capture(match_state* ms, int l)
{
    l -= '1';
    if (l < 0 || l >= ms->level || ms->capture[l].len == cap_unfinished)
        return luaL_error(ms->L, "invalid capture index");
    return l;
}

int capture_to_close(match_state* ms)
{
    for (int level = ms->level - 1; level >= 0; level--)
        if (ms->capture[level].len == cap_unfinished) return level;
    return luaL_error(ms->L, "invalid pattern capture");
}

const char* class_end(match_state* ms, const char* p)
{
    switch (*p++)
    {
        case esc:
            if (p >= ms->p_end)
                luaL_error(ms->L, "malformed pattern (ends with '%%')");
            return p + 1;
        case '[':
            if (p < ms->p_end && *p == '^') p++;
            // The first character is a member even when it is `]`, as in Lua.
            do
            {
                if (p >= ms->p_end)
                    luaL_error(ms->L, "malformed pattern (missing ']')");
                if (*(p++) == esc && p < ms->p_end) p++;
            } while (p >= ms->p_end || *p != ']');
            return p + 1;
        default:
            return p;
    }
}

// `p` is at the `[` and `ec` at the `]` that closes it.
bool match_bracket_class(int c, const char* p, const char* ec)
{
    bool sig = true;
    if (*(p + 1) == '^') { sig = false; p++; }
    while (++p < ec)
    {
        if (*p == esc)
        {
            p++;
            if (match_class(c, uc(*p))) return sig;
        }
        else if (*(p + 1) == '-' && p + 2 < ec)
        {
            p += 2;
            if (uc(*(p - 2)) <= c && c <= uc(*p)) return sig;
        }
        else if (uc(*p) == c) return sig;
    }
    return !sig;
}

bool single_match(match_state* ms, const char* s, const char* p, const char* ep)
{
    if (s >= ms->src_end) return false;
    const int c = uc(*s);
    switch (*p)
    {
        case '.': return true;
        case esc: return match_class(c, uc(*(p + 1)));
        case '[': return match_bracket_class(c, p, ep - 1);
        default:  return uc(*p) == c;
    }
}

const char* do_match(match_state* ms, const char* s, const char* p);

const char* match_balance(match_state* ms, const char* s, const char* p)
{
    if (p + 1 >= ms->p_end)
        luaL_error(ms->L, "malformed pattern (missing arguments to '%%b')");
    if (s >= ms->src_end || *s != *p) return nullptr;
    const char  open  = *p;
    const char  close = *(p + 1);
    const char* from  = s;
    int         cont  = 1;
    while (++s < ms->src_end)
    {
        if (*s == close)
        {
            if (--cont == 0)
            {
                charge(ms->L, ms->left, static_cast<size_t>(s - from));
                return s + 1;
            }
        }
        else if (*s == open) cont++;
    }
    charge(ms->L, ms->left, static_cast<size_t>(s - from));
    return nullptr;
}

const char* max_expand(match_state* ms, const char* s, const char* p, const char* ep)
{
    ptrdiff_t i = 0;
    while (single_match(ms, s + i, p, ep)) i++;
    charge(ms->L, ms->left, static_cast<size_t>(i));
    while (i >= 0)
    {
        if (const char* res = do_match(ms, s + i, ep + 1)) return res;
        i--;
    }
    return nullptr;
}

const char* min_expand(match_state* ms, const char* s, const char* p, const char* ep)
{
    for (;;)
    {
        if (const char* res = do_match(ms, s, ep + 1)) return res;
        if (!single_match(ms, s, p, ep)) return nullptr;
        s++;
    }
}

const char* start_capture(match_state* ms, const char* s, const char* p, ptrdiff_t what)
{
    const int level = ms->level;
    if (level >= max_captures) luaL_error(ms->L, "too many captures");
    ms->capture[level].init = s;
    ms->capture[level].len  = what;
    ms->level = level + 1;
    const char* res = do_match(ms, s, p);
    if (res == nullptr) ms->level--;
    return res;
}

const char* end_capture(match_state* ms, const char* s, const char* p)
{
    const int l = capture_to_close(ms);
    ms->capture[l].len = s - ms->capture[l].init;
    const char* res = do_match(ms, s, p);
    if (res == nullptr) ms->capture[l].len = cap_unfinished;
    return res;
}

const char* match_capture(match_state* ms, const char* s, int l)
{
    l = check_capture(ms, l);
    const size_t len = static_cast<size_t>(ms->capture[l].len);
    if (static_cast<size_t>(ms->src_end - s) < len) return nullptr;
    charge(ms->L, ms->left, len);
    return std::memcmp(ms->capture[l].init, s, len) == 0 ? s + len : nullptr;
}

const char* do_match(match_state* ms, const char* s, const char* p)
{
    if (ms->depth-- == 0)
        luaL_error(ms->L, "pattern too complex");
init:
    charge(ms->L, ms->left, 1);
    if (p != ms->p_end)
    {
        switch (*p)
        {
            case '(':
            {
                if (p + 1 < ms->p_end && *(p + 1) == ')')
                    s = start_capture(ms, s, p + 2, cap_position);
                else
                    s = start_capture(ms, s, p + 1, cap_unfinished);
                break;
            }
            case ')':
            {
                s = end_capture(ms, s, p + 1);
                break;
            }
            case '$':
            {
                if (p + 1 != ms->p_end) goto dflt;
                s = (s == ms->src_end) ? s : nullptr;
                break;
            }
            case esc:
            {
                switch (p + 1 < ms->p_end ? *(p + 1) : '\0')
                {
                    case 'b':
                    {
                        s = match_balance(ms, s, p + 2);
                        if (s != nullptr) { p += 4; goto init; }
                        break;
                    }
                    case 'f':
                    {
                        p += 2;
                        if (p >= ms->p_end || *p != '[')
                            luaL_error(ms->L, "missing '[' after '%%f' in pattern");
                        const char* ep = class_end(ms, p);
                        const int previous = (s == ms->src_init) ? 0 : uc(*(s - 1));
                        const int current  = (s < ms->src_end) ? uc(*s) : 0;
                        if (!match_bracket_class(previous, p, ep - 1) &&
                            match_bracket_class(current, p, ep - 1))
                        { p = ep; goto init; }
                        s = nullptr;
                        break;
                    }
                    case '0': case '1': case '2': case '3': case '4':
                    case '5': case '6': case '7': case '8': case '9':
                    {
                        s = match_capture(ms, s, uc(*(p + 1)));
                        if (s != nullptr) { p += 2; goto init; }
                        break;
                    }
                    default: goto dflt;
                }
                break;
            }
            default: dflt:
            {
                const char* ep = class_end(ms, p);
                const char suffix = ep < ms->p_end ? *ep : '\0';
                if (!single_match(ms, s, p, ep))
                {
                    if (suffix == '*' || suffix == '?' || suffix == '-') { p = ep + 1; goto init; }
                    s = nullptr;
                }
                else
                {
                    switch (suffix)
                    {
                        case '?':
                        {
                            const char* res = do_match(ms, s + 1, ep + 1);
                            if (res != nullptr) s = res;
                            else { p = ep + 1; goto init; }
                            break;
                        }
                        case '+':
                            s++;
                            [[fallthrough]];
                        case '*':
                            s = max_expand(ms, s, p, ep);
                            break;
                        case '-':
                            s = min_expand(ms, s, p, ep);
                            break;
                        default:
                            s++; p = ep; goto init;
                    }
                }
                break;
            }
        }
    }
    ms->depth++;
    return s;
}

void push_onecapture(match_state* ms, int i, const char* s, const char* e)
{
    if (i >= ms->level)
    {
        if (i == 0) lua_pushlstring(ms->L, s, static_cast<size_t>(e - s));
        else        luaL_error(ms->L, "invalid capture index");
        return;
    }
    const ptrdiff_t l = ms->capture[i].len;
    if (l == cap_unfinished) luaL_error(ms->L, "unfinished capture");
    if (l == cap_position)
        lua_pushinteger(ms->L, static_cast<lua_Integer>(ms->capture[i].init - ms->src_init + 1));
    else
        lua_pushlstring(ms->L, ms->capture[i].init, static_cast<size_t>(l));
}

int push_captures(match_state* ms, const char* s, const char* e)
{
    const int n = (ms->level == 0 && s) ? 1 : ms->level;
    luaL_checkstack(ms->L, n, "too many captures");
    for (int i = 0; i < n; i++) push_onecapture(ms, i, s, e);
    return n;
}

ptrdiff_t posrelat(lua_Integer pos, size_t len)
{
    if (pos < 0) pos += static_cast<lua_Integer>(len) + 1;
    return pos >= 0 ? static_cast<ptrdiff_t>(pos) : 0;
}

bool no_specials(const char* p, size_t lp)
{
    static constexpr char specials[] = "^$*+?.([%-";
    for (size_t i = 0; i < lp; i++)
        if (std::memchr(specials, p[i], sizeof(specials) - 1)) return false;
    return true;
}

// A plain search, metered too, since each candidate costs a compare of the whole needle.
const char* plain_find(lua_State* L, const char* s, size_t ls, const char* p, size_t lp)
{
    if (lp == 0) return s;
    if (lp > ls) return nullptr;
    size_t left = check_every;
    const char* const last = s + (ls - lp);
    for (const char* at = s; at <= last; at++)
    {
        at = static_cast<const char*>(std::memchr(at, *p, static_cast<size_t>(last - at) + 1));
        if (at == nullptr) return nullptr;
        if (std::memcmp(at + 1, p + 1, lp - 1) == 0) return at;
        charge(L, left, lp);
    }
    return nullptr;
}

int find_aux(lua_State* L, bool find)
{
    size_t ls = 0, lp = 0;
    const char* s = luaL_checklstring(L, 1, &ls);
    const char* p = luaL_checklstring(L, 2, &lp);
    ptrdiff_t init = posrelat(luaL_optinteger(L, 3, 1), ls) - 1;
    if (init < 0) init = 0;
    else if (static_cast<size_t>(init) > ls) init = static_cast<ptrdiff_t>(ls);
    if (find && (lua_toboolean(L, 4) || no_specials(p, lp)))
    {
        if (const char* hit = plain_find(L, s + init, ls - static_cast<size_t>(init), p, lp))
        {
            lua_pushinteger(L, static_cast<lua_Integer>(hit - s + 1));
            lua_pushinteger(L, static_cast<lua_Integer>(hit - s) + static_cast<lua_Integer>(lp));
            return 2;
        }
    }
    else
    {
        match_state ms;
        prepare(ms, L, s, ls, p, lp);
        const bool anchor = lp > 0 && *p == '^';
        if (anchor) p++;
        const char* s1 = s + init;
        do
        {
            ms.level = 0;
            ms.depth = max_depth;
            if (const char* res = do_match(&ms, s1, p))
            {
                if (find)
                {
                    lua_pushinteger(L, static_cast<lua_Integer>(s1 - s + 1));
                    lua_pushinteger(L, static_cast<lua_Integer>(res - s));
                    return push_captures(&ms, nullptr, nullptr) + 2;
                }
                return push_captures(&ms, s1, res);
            }
        } while (s1++ < ms.src_end && !anchor);
    }
    lua_pushnil(L);
    return 1;
}

int str_find(lua_State* L)  { return find_aux(L, true); }
int str_match(lua_State* L) { return find_aux(L, false); }

int gmatch_aux(lua_State* L)
{
    size_t ls = 0, lp = 0;
    const char* s = lua_tolstring(L, lua_upvalueindex(1), &ls);
    const char* p = lua_tolstring(L, lua_upvalueindex(2), &lp);
    const lua_Integer from = lua_tointeger(L, lua_upvalueindex(3));
    if (from < 0 || static_cast<size_t>(from) > ls) return 0;
    match_state ms;
    prepare(ms, L, s, ls, p, lp);
    for (const char* src = s + from; src <= ms.src_end; src++)
    {
        ms.level = 0;
        ms.depth = max_depth;
        if (const char* e = do_match(&ms, src, p))
        {
            lua_Integer next = e - s;
            if (e == src) next++;
            lua_pushinteger(L, next);
            lua_replace(L, lua_upvalueindex(3));
            return push_captures(&ms, src, e);
        }
    }
    return 0;
}

int str_gmatch(lua_State* L)
{
    luaL_checkstring(L, 1);
    luaL_checkstring(L, 2);
    lua_settop(L, 2);
    lua_pushinteger(L, 0);
    lua_pushcclosure(L, &gmatch_aux, 3);
    return 1;
}

void add_s(match_state* ms, luaL_Buffer* b, const char* s, const char* e)
{
    size_t l = 0;
    const char* news = lua_tolstring(ms->L, 3, &l);
    for (size_t i = 0; i < l; i++)
    {
        if (news[i] != esc)
            luaL_addchar(b, news[i]);
        else
        {
            i++;
            if (!is_digit(uc(news[i])))
                luaL_addchar(b, news[i]);
            else if (news[i] == '0')
                luaL_addlstring(b, s, static_cast<size_t>(e - s));
            else
            {
                push_onecapture(ms, news[i] - '1', s, e);
                luaL_addvalue(b);
            }
        }
    }
}

void add_value(match_state* ms, luaL_Buffer* b, const char* s, const char* e)
{
    lua_State* L = ms->L;
    switch (lua_type(L, 3))
    {
        case LUA_TNUMBER:
        case LUA_TSTRING:
            add_s(ms, b, s, e);
            return;
        case LUA_TFUNCTION:
        {
            lua_pushvalue(L, 3);
            const int n = push_captures(ms, s, e);
            lua_call(L, n, 1);
            break;
        }
        case LUA_TTABLE:
            push_onecapture(ms, 0, s, e);
            lua_gettable(L, 3);
            break;
        default:
            break;
    }
    if (!lua_toboolean(L, -1))
    {
        lua_pop(L, 1);
        lua_pushlstring(L, s, static_cast<size_t>(e - s));
    }
    else if (!lua_isstring(L, -1))
        luaL_error(L, "invalid replacement value (a %s)", luaL_typename(L, -1));
    luaL_addvalue(b);
}

int str_gsub(lua_State* L)
{
    size_t srcl = 0, lp = 0;
    const char* src = luaL_checklstring(L, 1, &srcl);
    const char* p   = luaL_checklstring(L, 2, &lp);
    const int   tr  = lua_type(L, 3);
    const lua_Integer max_s = luaL_optinteger(L, 4, static_cast<lua_Integer>(srcl) + 1);
    luaL_argcheck(L, tr == LUA_TNUMBER || tr == LUA_TSTRING ||
                     tr == LUA_TFUNCTION || tr == LUA_TTABLE, 3,
                  "string/function/table expected");
    match_state ms;
    prepare(ms, L, src, srcl, p, lp);
    const bool anchor = lp > 0 && *p == '^';
    if (anchor) p++;
    lua_Integer n = 0;
    luaL_Buffer b;
    luaL_buffinit(L, &b);
    while (n < max_s)
    {
        ms.level = 0;
        ms.depth = max_depth;
        const char* e = do_match(&ms, src, p);
        if (e)
        {
            n++;
            add_value(&ms, &b, src, e);
        }
        if (e && e > src) src = e;
        else if (src < ms.src_end) luaL_addchar(&b, *src++);
        else break;
        if (anchor) break;
    }
    luaL_addlstring(&b, src, static_cast<size_t>(ms.src_end - src));
    luaL_pushresult(&b);
    lua_pushinteger(L, n);
    return 2;
}

}  // namespace

void install(lua_State* L, int idx)
{
    if (idx < 0) idx = lua_gettop(L) + idx + 1;
    lua_pushcfunction(L, &str_find);
    lua_setfield(L, idx, "find");
    lua_pushcfunction(L, &str_match);
    lua_setfield(L, idx, "match");
    lua_pushcfunction(L, &str_gmatch);
    lua_setfield(L, idx, "gmatch");
    lua_getfield(L, idx, "gfind");
    const bool gfind = !lua_isnil(L, -1);
    lua_pop(L, 1);
    if (gfind)
    {
        lua_pushcfunction(L, &str_gmatch);
        lua_setfield(L, idx, "gfind");
    }
    lua_pushcfunction(L, &str_gsub);
    lua_setfield(L, idx, "gsub");
}

}  // namespace lua_pattern

#endif  // SOCKETLEY_NO_LUA
