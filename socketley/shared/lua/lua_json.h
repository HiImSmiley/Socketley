#pragma once
#include "../json/json_escape.h"
#include <cstdlib>
// JSON for socketley.json_encode and json_decode, a header rather than
// file-static so a parser pointed at network data can be reached by a test and
// a fuzz target.

#include <sol/sol.hpp>

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstdio>
#include <string>
#include <vector>

namespace socketley::lua_json {

// Both sides recurse in C++ over a structure the caller chooses, so both need a
// bottom; the callback deadline hooks Lua instructions, not the C stack.
inline constexpr int json_max_depth = 128;

// A decode says which of three things happened, and the object is the document
// only on `ok` -- otherwise a truncated body is indistinguishable from a whole
// one, and the script proceeds on data it believes is complete.
enum class json_status
{
    ok,          // the object is the document
    too_deep,    // nesting past json_max_depth; the object is nothing
    malformed,   // not a JSON document; the object is nothing
};

// `path` is an ancestor chain and not a visited set, because a table repeated
// as a sibling is ordinary and one repeated on a path is a cycle.
inline bool json_encode_value(std::string& out, const sol::object& val,
                              int depth, std::vector<const void*>& path,
                              std::string& err);

// The count when `t` is exactly {1..n}, else 0 meaning encode as an object,
// with keys collected because nothing promises lua_next arrives in index
// order.
inline int array_length(const sol::table& t)
{
    int    count = 0;
    double highest = 0;
    for (const auto& kv : t)
    {
        if (kv.first.get_type() != sol::type::number)
            return 0;
        const double d = kv.first.as<double>();
        // The magnitude is tested before the cast, because converting a double
        // that int64 cannot hold is undefined and `t[1/0] = 1` is a key LuaJIT
        // accepts.
        if (d < 1 || d > 1e15 || d != static_cast<double>(static_cast<int64_t>(d)))
            return 0;
        if (d > highest) highest = d;
        ++count;
    }
    // Dense means n keys whose largest is n, so {1,2,4} is sparse and encodes
    // as an object, the only thing JSON can express.
    return (count > 0 && highest == count) ? count : 0;
}

inline bool json_encode_value(std::string& out, const sol::object& val,
                              int depth, std::vector<const void*>& path,
                              std::string& err)
{
    switch (val.get_type())
    {
        case sol::type::nil:
        case sol::type::none:
            out += "null";
            break;
        case sol::type::boolean:
            out += val.as<bool>() ? "true" : "false";
            break;
        case sol::type::number:
        {
            const double d = val.as<double>();

            // JSON has no spelling for either, and %.14g writes `inf` or `nan`
            // -- which the decoder twenty lines below refuses, so the two
            // halves of one pair disagreed about their own grammar and the
            // script was handed a string it could not have parsed back.
            if (!std::isfinite(d))
            {
                char spelled[32];
                snprintf(spelled, sizeof(spelled), "%.14g", d);
                err = std::string("the number ") + spelled +
                      " has no JSON spelling: a document can hold neither an "
                      "infinity nor a NaN";
                return false;
            }

            // The range before the cast, for the reason array_length gives.
            if (d >= -1e15 && d <= 1e15 &&
                d == static_cast<double>(static_cast<int64_t>(d)))
            {
                char buf[24];
                auto r = std::to_chars(buf, buf + sizeof(buf),
                                       static_cast<int64_t>(d));
                out.append(buf, static_cast<size_t>(r.ptr - buf));
            }
            else
            {
                // The shortest text that decodes to the same double, where %.14g dropped the digits past fourteen.
                char buf[32];
                const auto r = std::to_chars(buf, buf + sizeof(buf), d);
                out.append(buf, static_cast<size_t>(r.ptr - buf));
            }
            break;
        }
        case sol::type::string:
            socketley::json::quote_into(out, val.as<std::string>());
            break;
        case sol::type::table:
        {
            sol::table t = val.as<sol::table>();

            // The cycle first: it is the case a script reaches by accident, and
            // naming it beats reporting a depth limit for a table that is two
            // levels deep and points at itself.
            const void* const id = t.pointer();
            for (const void* ancestor : path)
            {
                if (ancestor == id)
                {
                    err = "the table contains itself, so there is no end to "
                          "encode: a JSON document cannot hold a cycle";
                    return false;
                }
            }

            if (depth >= json_max_depth)
            {
                err = "the table is nested deeper than " +
                      std::to_string(json_max_depth) + " levels";
                return false;
            }

            path.push_back(id);
            // A path that grows on the way in and not back out reports a
            // cycle for the next sibling.
            struct pop_guard
            {
                std::vector<const void*>& p;
                ~pop_guard() { p.pop_back(); }
            } guard{ path };

            if (const int n = array_length(t); n > 0)
            {
                // By index: [1,2] and [2,1] are different documents.
                out += '[';
                for (int i = 1; i <= n; ++i)
                {
                    if (i > 1) out += ',';
                    if (!json_encode_value(out, sol::object(t[i]), depth + 1, path, err))
                        return false;
                }
                out += ']';
            }
            else
            {
                // Sorted, so the output is a function of the value: lua_next's
                // order is not stable even between equal tables.
                struct field { std::string key; sol::object val; };
                std::vector<field> fields;

                for (const auto& kv : t)
                {
                    std::string key_text;

                    // Formatted here rather than coerced: as<std::string>() on
                    // a number is lua_tolstring, which REPLACES the key in the
                    // table mid-traversal, which the Lua manual forbids.
                    if (kv.first.get_type() == sol::type::string)
                    {
                        key_text = kv.first.as<std::string>();
                    }
                    else
                    {
                        // Guarded anyway: a table key would hide a cycle.
                        if (!json_encode_value(key_text, kv.first, depth + 1, path, err))
                            return false;
                    }

                    fields.push_back({ std::move(key_text), kv.second });
                }

                std::sort(fields.begin(), fields.end(),
                          [](const field& a, const field& b) { return a.key < b.key; });

                out += '{';
                bool first = true;
                for (const auto& f : fields)
                {
                    if (!first) out += ',';
                    first = false;
                    socketley::json::quote_into(out, f.key);
                    out += ':';
                    if (!json_encode_value(out, f.val, depth + 1, path, err))
                        return false;
                }
                out += '}';
            }
            break;
        }
        default:
            out += "null";
            break;
    }
    return true;
}

// `st` is set only on failure and never cleared, so one deep in a container
// survives the unwinding; every return carries a lua_State, because get_type()
// on a free-standing sol::nil segfaults.
inline sol::object json_decode_value(sol::state& lua, const char*& p, const char* end,
                                     int depth, json_status& st);

inline void json_skip_ws(const char*& p, const char* end)
{
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
        ++p;
}

// False only for an incomplete string; escapes stay lenient and are kept
// verbatim, because structure is what can hand back a truncated value.
inline std::string json_decode_string(const char*& p, const char* end, bool& ok)
{
    if (p >= end || *p != '"') { ok = false; return {}; }
    ++p;
    std::string result;
    while (p < end && *p != '"')
    {
        // The run up to the next quote or backslash goes in one append, not a byte at a time.
        if (*p != '\\')
        {
            const char* q = p;
            while (q < end && *q != '"' && *q != '\\')
                ++q;
            result.append(p, static_cast<size_t>(q - p));
            p = q;
            continue;
        }
        if (*p == '\\' && p + 1 < end)
        {
            ++p;
            switch (*p)
            {
                case '"':  result += '"';  break;
                case '\\': result += '\\'; break;
                case '/':  result += '/';  break;
                case 'n':  result += '\n'; break;
                case 'r':  result += '\r'; break;
                case 't':  result += '\t'; break;
                case 'b':  result += '\b'; break;
                case 'f':  result += '\f'; break;
                case 'u':
                {
                    if (p + 4 < end)
                    {
                        // Checked, or a non-hex digit contributes a silent zero
                        // and `\uZZZZ` decodes to U+0000.
                        unsigned cp = 0;
                        bool hex_ok = true;
                        const char* const digits = p + 1;
                        for (int i = 0; i < 4; ++i)
                        {
                            const char d = digits[i];
                            cp <<= 4;
                            if (d >= '0' && d <= '9')      cp |= static_cast<unsigned>(d - '0');
                            else if (d >= 'a' && d <= 'f') cp |= static_cast<unsigned>(d - 'a' + 10);
                            else if (d >= 'A' && d <= 'F') cp |= static_cast<unsigned>(d - 'A' + 10);
                            else { hex_ok = false; break; }
                        }
                        if (!hex_ok)
                        {
                            result += '\\';
                            result += 'u';
                            break;
                        }
                        p += 4;

                        // A surrogate pair is one codepoint, so encoding each
                        // half alone is not valid UTF-8 and an unpaired one is
                        // U+FFFD.
                        if (cp >= 0xD800 && cp <= 0xDBFF)
                        {
                            unsigned lo = 0;
                            bool have_low = false;
                            if (p + 6 < end && p[1] == '\\' && p[2] == 'u')
                            {
                                have_low = true;
                                for (int i = 0; i < 4; ++i)
                                {
                                    const char d = p[3 + i];
                                    lo <<= 4;
                                    if (d >= '0' && d <= '9')      lo |= static_cast<unsigned>(d - '0');
                                    else if (d >= 'a' && d <= 'f') lo |= static_cast<unsigned>(d - 'a' + 10);
                                    else if (d >= 'A' && d <= 'F') lo |= static_cast<unsigned>(d - 'A' + 10);
                                    else { have_low = false; break; }
                                }
                            }
                            if (have_low && lo >= 0xDC00 && lo <= 0xDFFF)
                            {
                                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                                p += 6;   // the \uXXXX of the low half
                            }
                            else
                            {
                                cp = 0xFFFD;
                            }
                        }
                        else if (cp >= 0xDC00 && cp <= 0xDFFF)
                        {
                            cp = 0xFFFD;   // a low surrogate with no high one
                        }

                        if (cp < 0x80)
                            result += static_cast<char>(cp);
                        else if (cp < 0x800)
                        {
                            result += static_cast<char>(0xC0 | (cp >> 6));
                            result += static_cast<char>(0x80 | (cp & 0x3F));
                        }
                        else if (cp < 0x10000)
                        {
                            result += static_cast<char>(0xE0 | (cp >> 12));
                            result += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                            result += static_cast<char>(0x80 | (cp & 0x3F));
                        }
                        else
                        {
                            // Reachable only because the pair is joined above.
                            result += static_cast<char>(0xF0 | (cp >> 18));
                            result += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
                            result += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                            result += static_cast<char>(0x80 | (cp & 0x3F));
                        }
                    }
                    break;
                }
                default: result += *p; break;
            }
        }
        else
            result += *p;
        ++p;
    }
    // The loop ends on the closing quote or on running out of input, and only
    // the first is a string.
    if (p >= end) { ok = false; return result; }
    ++p;
    return result;
}

inline sol::object json_decode_value(sol::state& lua, const char*& p, const char* end,
                                     int depth, json_status& st)
{
    json_skip_ws(p, end);
    if (p >= end) { st = json_status::malformed; return sol::nil; }

    // Once, before the switch, so it covers every container added later; a
    // scalar cannot recurse and passes at any depth.
    if ((*p == '{' || *p == '[') && depth >= json_max_depth)
    {
        st = json_status::too_deep;
        return sol::nil;
    }

    switch (*p)
    {
        case '"':
        {
            bool ok = true;
            std::string s = json_decode_string(p, end, ok);
            if (!ok) { st = json_status::malformed; return sol::nil; }
            return sol::make_object(lua, s);
        }
        case '{':
        {
            ++p;
            sol::table t = lua.create_table();
            json_skip_ws(p, end);
            if (p < end && *p == '}') { ++p; return t; }
            while (p < end)
            {
                json_skip_ws(p, end);

                // A key must be a quoted string, or `{a:1}` and `{,,,}` both
                // produce a table with a "" field.
                bool key_ok = true;
                std::string key = json_decode_string(p, end, key_ok);
                if (!key_ok) { st = json_status::malformed; return sol::nil; }

                json_skip_ws(p, end);
                if (p >= end || *p != ':') { st = json_status::malformed; return sol::nil; }
                ++p;

                sol::object val = json_decode_value(lua, p, end, depth + 1, st);
                if (st != json_status::ok) return sol::nil;
                t[key] = val;

                json_skip_ws(p, end);
                if (p < end && *p == ',') { ++p; continue; }
                break;
            }
            json_skip_ws(p, end);
            if (p >= end || *p != '}') { st = json_status::malformed; return sol::nil; }
            ++p;
            return t;
        }
        case '[':
        {
            ++p;
            sol::table t = lua.create_table();
            json_skip_ws(p, end);
            if (p < end && *p == ']') { ++p; return t; }
            int idx = 1;
            while (p < end)
            {
                sol::object val = json_decode_value(lua, p, end, depth + 1, st);
                if (st != json_status::ok) return sol::nil;
                t[idx++] = val;

                json_skip_ws(p, end);
                if (p < end && *p == ',') { ++p; continue; }
                break;
            }
            // The closing bracket is required, or `[1,2` from a dropped
            // connection decodes to an ordinary two-element table.
            json_skip_ws(p, end);
            if (p >= end || *p != ']') { st = json_status::malformed; return sol::nil; }
            ++p;
            return t;
        }
        case 't':
            if (end - p >= 4 && p[1] == 'r' && p[2] == 'u' && p[3] == 'e')
            { p += 4; return sol::make_object(lua, true); }
            st = json_status::malformed;
            return sol::nil;
        case 'f':
            if (end - p >= 5 && p[1] == 'a' && p[2] == 'l' && p[3] == 's' && p[4] == 'e')
            { p += 5; return sol::make_object(lua, false); }
            st = json_status::malformed;
            return sol::nil;
        case 'n':
            // The one nil that is an answer rather than a failure, and the only
            // reason it carries `lua`: see the note on the declaration.
            if (end - p >= 4 && p[1] == 'u' && p[2] == 'l' && p[3] == 'l')
            { p += 4; return sol::make_object(lua, sol::lua_nil); }
            st = json_status::malformed;
            return sol::nil;
        default:
        {
            const char* start = p;
            if (*p == '-') ++p;

            // At least one digit, separately from `p == start`: a lone "-"
            // otherwise decodes to 0.
            const char* const int_digits = p;
            while (p < end && *p >= '0' && *p <= '9') ++p;
            if (p == int_digits) { st = json_status::malformed; return sol::nil; }

            bool is_float = false;
            if (p < end && *p == '.')
            { is_float = true; ++p; while (p < end && *p >= '0' && *p <= '9') ++p; }
            if (p < end && (*p == 'e' || *p == 'E'))
            { is_float = true; ++p; if (p < end && (*p == '+' || *p == '-')) ++p; while (p < end && *p >= '0' && *p <= '9') ++p; }

            // strtod and not stod, whose throw on a number past double's range made 1e400 a zero: past the range is
            // infinity, as the magnitude says, and below it is as near to zero as a double comes.
            if (is_float)
            {
                const std::string num_str(start, static_cast<size_t>(p - start));
                return sol::make_object(lua, std::strtod(num_str.c_str(), nullptr));
            }

            int64_t n = 0;
            const auto r = std::from_chars(start, p, n);
            if (r.ec != std::errc{})
            {
                // Out of int64 range is a large number, not a bad document:
                // fall back to the float parse, which keeps the magnitude.
                const std::string num_str(start, static_cast<size_t>(p - start));
                return sol::make_object(lua, std::strtod(num_str.c_str(), nullptr));
            }
            return sol::make_object(lua, static_cast<double>(n));
        }
    }
}
}   // namespace socketley::lua_json
