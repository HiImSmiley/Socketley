#pragma once
// JSON for the Lua API: socketley.json_encode and socketley.json_decode.
//
// ─── WHY THIS IS A HEADER AND NOT STILL IN lua_context.cpp ──────────────────
//
// It was file-static in lua_context.cpp, reachable only through
// register_bindings(), which is private and needs a live runtime_instance.  So
// the two functions could not be called from a test at all — no unit test, and
// no fuzz target, for the one binding in this API that is written to be pointed
// at data from the network.
//
// That mattered.  Neither had a depth limit: a cyclic table crashed the encoder
// and a few hundred kilobytes of `[[[[` crashed the decoder, taking the whole
// daemon with it.  Measured, 40 KB survived and 200 KB was a SIGSEGV with a
// core file.  Both are fixed and both are now reachable, which is the point of
// moving them: a defect in a parser that cannot be driven from a test is a
// defect that gets found in production.
//
// Header-only and templated on nothing: these need sol2 and the standard
// library, so a header costs the includers nothing they do not already have.
// resp_parser.h is the same arrangement for the same reason.

#include <sol/sol.hpp>

#include <algorithm>
#include <charconv>
#include <cstdio>
#include <string>
#include <vector>

namespace socketley::lua_json {

// ─── JSON encode/decode for Lua ───────────────────────────────────────────────
//
// ─── HOW DEEP EITHER SIDE MAY GO, AND WHY THERE IS A LIMIT AT ALL ────────────
//
// Both functions below are recursive, in C++, over a structure a script hands
// them — and until this constant existed neither had a bottom.
//
// The encoder's was reachable by accident.  `t.self = t` is a typo every
// scripting language forgives, and Lua forgives it too; this encoder followed
// the reference forever.  Measured, one runtime whose on_start built exactly
// that table:
//
//     [INFO] [lua jc] about to encode a cyclic table
//     Segmentation fault (core dumped)
//
// The decoder's was reachable on purpose, and from outside.  socketley.json_decode
// is written to be pointed at a request body — that is what the API is for — so
// the nesting depth is chosen by whoever sent the request.  Measured, a runtime
// decoding string.rep("[", n) .. string.rep("]", n):
//
//     n =   1000  (  2 KB)   survived
//     n =   5000  ( 10 KB)   survived
//     n =  20000  ( 40 KB)   survived
//     n = 100000  (200 KB)   Segmentation fault (core dumped)
//
// 200 KB is an ordinary request body.  That made every script calling
// json_decode on network input a way for an unauthenticated client to take the
// whole daemon down, which is the only such path anybody found in this tree.
//
// The callback deadline does not help and was never going to: it is a
// lua_sethook on Lua instructions plus a wall clock, and this recursion is C++
// frames on the C stack.  The stack is gone long before ten seconds are.
//
// 128 is Redis's limit for the same job.  A document nested deeper than that is
// not something a handler builds by hand, and the two failures above are both
// well past it.
inline constexpr int json_max_depth = 128;

// ─── WHAT A DECODE ANSWERS ───────────────────────────────────────────────────
//
// The decoder used to answer one thing — a sol::object — and there was no way
// to ask whether it had meant it.  `null`, an empty string, `nul`, `garbage`
// and a document exhausted mid-value all returned nil, and every structural
// mistake returned a value built out of the part it had understood:
//
//     json_decode('{{{{')       →  a table          (not JSON at all)
//     json_decode('[1,')        →  a table  {1}     (truncated mid-array)
//     json_decode('"x')         →  the string "x"   (unterminated)
//     json_decode('{"a":}')     →  a table  {}      (the field silently gone)
//     json_decode('nul')        →  nil              (indistinguishable from null)
//
// A handler doing `local body = socketley.json_decode(req.body)` therefore
// could not tell a truncated request body from a complete one, and got a table
// with the fields that happened to arrive before the truncation.  That is worse
// than an error: the script proceeds, on data it believes is whole.
//
// So a decode reports which of three things happened, and the returned object
// is the document only when it says `ok`.  Two of the three were already
// distinct in the binding's contract for the encoder and for the depth refusal
// — this makes the third one, by far the most common, distinct too.
enum class json_status
{
    ok,          // the object is the document
    too_deep,    // nesting past json_max_depth; the object is nothing
    malformed,   // not a JSON document; the object is nothing
};

// `path` holds the tables currently being encoded, innermost last — an
// ancestor chain, not a visited set.  The difference matters: a table that
// appears twice as a SIBLING is ordinary and must still encode (two fields
// pointing at one shared config table), while a table that appears twice on one
// path is a cycle and cannot terminate.
//
// False means nothing was appended for this value and `err` says why.
inline bool json_encode_value(std::string& out, const sol::object& val,
                              int depth, std::vector<const void*>& path,
                              std::string& err);

inline void json_encode_string(std::string& out, const std::string& s)
{
    out += '"';
    for (char c : s)
    {
        switch (c)
        {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20)
                {
                    char hex[8];
                    snprintf(hex, sizeof(hex), "\\u%04x", static_cast<unsigned char>(c));
                    out += hex;
                }
                else
                    out += c;
        }
    }
    out += '"';
}

// The element count when `t` is exactly the dense set {1..n}, and 0 otherwise —
// 0 meaning "encode this as an object", which is also the right answer for an
// empty table.
//
// The keys are collected rather than matched against a running counter.  The
// old version compared each key to `expected` as lua_next produced it, so it
// answered "array" only if the traversal happened to arrive in index order.
// LuaJIT's array part does arrive in order today; nothing promises it, and the
// consequence of it not doing so is not a wrong answer but a DIFFERENT answer
// between two runs over equal data — the same class of bug as the key order
// below, and invisible until it matters.
inline int array_length(const sol::table& t)
{
    int    count = 0;
    double highest = 0;
    for (const auto& kv : t)
    {
        if (kv.first.get_type() != sol::type::number)
            return 0;
        const double d = kv.first.as<double>();
        if (d < 1 || d != static_cast<double>(static_cast<int64_t>(d)))
            return 0;
        if (d > highest) highest = d;
        ++count;
    }
    // Dense: n keys and the largest is n.  {1,2,4} has three keys and a largest
    // of 4, so it is a sparse table and encodes as an object, which is what it
    // did before and the only thing JSON can express.
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
            double d = val.as<double>();
            auto i = static_cast<int64_t>(d);
            if (d == i && d >= -1e15 && d <= 1e15)
            {
                char buf[24];
                auto r = std::to_chars(buf, buf + sizeof(buf), i);
                out.append(buf, static_cast<size_t>(r.ptr - buf));
            }
            else
            {
                char buf[32];
                int n = snprintf(buf, sizeof(buf), "%.14g", d);
                out.append(buf, static_cast<size_t>(n));
            }
            break;
        }
        case sol::type::string:
            json_encode_string(out, val.as<std::string>());
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
            // Every `return false` below leaves the pop to this guard: the
            // early exits are the whole point of the ancestor chain, and a
            // path that grows on the way in and not back out would report a
            // cycle for the next sibling.
            struct pop_guard
            {
                std::vector<const void*>& p;
                ~pop_guard() { p.pop_back(); }
            } guard{ path };

            if (const int n = array_length(t); n > 0)
            {
                // By index, not by traversal.  An array's elements have an
                // order that is part of the value — [1,2] and [2,1] are
                // different documents — so it is read from the indices rather
                // than from whatever order lua_next hands them back.
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
                // ─── The keys are sorted, and that is a fix ─────────────────
                //
                // A Lua table has no order to preserve: measured, a table
                // filled alpha, beta, gamma, delta iterates beta, gamma, delta,
                // alpha.  So whatever order lua_next produces is arbitrary —
                // and it is not even the same arbitrary order for two tables
                // holding equal data.  The fuzz target found it as
                //
                //     once : {"b":[1,2,{"c":"x"}],"e":3}
                //     twice: {"e":3,"b":[1,2,{"c":"x"}]}
                //
                // — one table, encoded, decoded, encoded again, and the two
                // strings differ.  json_encode was therefore not a function of
                // its argument, which breaks every use that compares its
                // output: an ETag, a cache key, a signature, a dedup hash, a
                // diff of two logged documents, a script asserting that two
                // tables match.  None of those fail loudly; they just stop
                // being right, occasionally.
                //
                // Sorting by the rendered key makes the output a function of
                // the value, and costs a vector and a sort per object.  The one
                // case still unordered is two distinct keys that render to the
                // same text — t[1] and t["1"] — which produces a duplicate JSON
                // key whichever way round it goes, and was already not
                // expressible.
                struct field { std::string key; sol::object val; };
                std::vector<field> fields;

                for (const auto& kv : t)
                {
                    std::string key_text;

                    // ─── The key is not necessarily a string ────────────────
                    //
                    // This branch takes every table that is not a dense array,
                    // and the commonest of those is a SPARSE one — {[1]=1,
                    // [3]=3} — whose keys are numbers.  `as<std::string>()` on
                    // a number was two bugs at once.
                    //
                    // sol2's safety checks follow NDEBUG, so they are off in
                    // Release and on in every Debug and Sanitize build.  With
                    // them on, this does not convert: it throws, the throw
                    // leaves through sol2's handler as "[sol2] An exception
                    // occurred: caught (...) exception", and the callback that
                    // called json_encode never returns.  Measured, one script
                    // encoding {[1]=1,[3]=3} and replying with the result:
                    //
                    //     Release   ->  j={"3":3,"1":1}
                    //     Sanitize  ->  (no reply at all; connection times out)
                    //
                    // With them off it is worse than an error.  as<std::string>
                    // on a number is lua_tolstring, which does not read the
                    // value — it REPLACES it, in the table, in the middle of a
                    // lua_next traversal.  The Lua manual forbids exactly that:
                    // modifying a key during traversal is undefined, and the
                    // Release build has been doing it on every sparse table.
                    //
                    // So the key is formatted here and the table is not
                    // touched.  A JSON object's keys are strings, so a
                    // non-string key is rendered and then quoted, which is the
                    // same text Release produced by coercion.
                    if (kv.first.get_type() == sol::type::string)
                    {
                        key_text = kv.first.as<std::string>();
                    }
                    else
                    {
                        // A key is a scalar in every case this branch can see —
                        // a table key would be one more place a cycle could
                        // hide, so it goes through the same guarded call rather
                        // than a bare one.
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
                    json_encode_string(out, f.key);
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

// `st` is set only on failure, and never cleared: a caller passes one status in
// and reads it once at the end, so a failure deep inside a container survives
// the unwinding rather than being overwritten by the frames above it.
//
// Every successful return carries a lua_State — including `null`, which returns
// a nil made against `lua` rather than the free-standing sol::nil.  A
// free-standing one has no state, and get_type() on it dereferences a null
// lua_State*: harmless while the only caller handed the object straight back to
// Lua, and an immediate segfault for the first C++ caller that looked at it.
// That first caller was the fuzz target below this file's own tests.
inline sol::object json_decode_value(sol::state& lua, const char*& p, const char* end,
                                     int depth, json_status& st);

inline void json_skip_ws(const char*& p, const char* end)
{
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
        ++p;
}

// `ok` is false when the bytes are not a complete string: no opening quote, or
// no closing one before the input ran out.  The escapes stay deliberately
// lenient — an unknown one is kept verbatim, `\uZZZZ` too — because a decoder
// that rejects a document over one odd escape is less useful than one that
// carries it through, and neither can hand back a truncated value the way an
// unterminated string can.  Structure is what is strict here.
inline std::string json_decode_string(const char*& p, const char* end, bool& ok)
{
    if (p >= end || *p != '"') { ok = false; return {}; }
    ++p;
    std::string result;
    while (p < end && *p != '"')
    {
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
                        // The four digits are checked now.  A non-hex character
                        // matched none of the three branches and contributed a
                        // silent zero, so `\uZZZZ` decoded to U+0000 and
                        // `\u00g0` to something no reader intended.  Malformed
                        // input is kept verbatim instead, which is what the
                        // `default` arm of this switch already does for every
                        // other unknown escape.
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

                        // ─── A surrogate is half a character ────────────────
                        //
                        // JSON has no way to write a codepoint above the BMP
                        // except as a surrogate PAIR — \uD83D\uDE00 is one
                        // emoji, not two characters.  Encoding each half on its
                        // own produces bytes that are not valid UTF-8, and they
                        // went straight into a Lua string that a handler then
                        // wrote to a socket or a file.
                        //
                        // The pair is joined here.  A high surrogate with no low
                        // one behind it, or a lone low surrogate, is not
                        // repairable and becomes U+FFFD — the replacement
                        // character exists for exactly this and is what every
                        // other decoder answers.
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
                            // Four bytes, reachable only now that a surrogate
                            // pair is joined above.  Before that this branch
                            // could not be entered — cp came from four hex
                            // digits and stopped at 0xFFFF — which is why the
                            // three-byte form was the whole of it.
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
    // The loop ends either on the closing quote or on running out of input.
    // Only the first is a string.
    if (p >= end) { ok = false; return result; }
    ++p;
    return result;
}

inline sol::object json_decode_value(sol::state& lua, const char*& p, const char* end,
                                     int depth, json_status& st)
{
    json_skip_ws(p, end);
    if (p >= end) { st = json_status::malformed; return sol::nil; }

    // Checked once, before the switch, so it covers both containers and every
    // container added later.  A scalar cannot recurse and is let through
    // whatever the depth, which keeps the limit about nesting rather than about
    // where in a document a value happens to sit.
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

                // A key has to be a quoted string.  When it was not, the old
                // decoder took the empty string json_decode_string returns for
                // "this is not a string" and carried on, so `{a:1}` and `{,,,}`
                // both produced a table with a "" field.
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
            // The closing bracket is required.  Without this check `[1,2` — a
            // request body cut off by a dropped connection — decoded to a
            // perfectly ordinary two-element table.
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

            // At least one digit, checked separately from `p == start`.  A lone
            // "-" moved p without consuming a digit, so the old check passed and
            // from_chars then failed and left n at its initial 0: the document
            // "-" decoded to the number 0.
            const char* const int_digits = p;
            while (p < end && *p >= '0' && *p <= '9') ++p;
            if (p == int_digits) { st = json_status::malformed; return sol::nil; }

            bool is_float = false;
            if (p < end && *p == '.')
            { is_float = true; ++p; while (p < end && *p >= '0' && *p <= '9') ++p; }
            if (p < end && (*p == 'e' || *p == 'E'))
            { is_float = true; ++p; if (p < end && (*p == '+' || *p == '-')) ++p; while (p < end && *p >= '0' && *p <= '9') ++p; }

            if (is_float)
            {
                std::string num_str(start, static_cast<size_t>(p - start));
                double d = 0;
                try { d = std::stod(num_str); } catch (...) {}
                return sol::make_object(lua, d);
            }

            int64_t n = 0;
            const auto r = std::from_chars(start, p, n);
            if (r.ec != std::errc{})
            {
                // Out of int64 range — 20 digits is not a malformed document,
                // it is a large number.  The old code ignored this result and
                // returned the untouched 0, so a counter past 9.2e18 came back
                // as zero.  Lua numbers are doubles anyway, so the integer path
                // is only ever an exactness optimisation; falling back to the
                // float parse loses precision and keeps the magnitude, which is
                // the right way round.
                std::string num_str(start, static_cast<size_t>(p - start));
                double d = 0;
                try { d = std::stod(num_str); } catch (...) {}
                return sol::make_object(lua, d);
            }
            return sol::make_object(lua, static_cast<double>(n));
        }
    }
}
}   // namespace socketley::lua_json
