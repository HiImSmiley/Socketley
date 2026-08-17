// Fuzz target: the JSON pair behind socketley.json_decode / json_encode.
//
// ─── WHY THIS TARGET EXISTS ─────────────────────────────────────────────────
//
// json_decode is the one Lua binding written to be pointed at data from the
// network — a request body, a message payload — so its nesting depth, escapes
// and lengths are chosen by whoever sent the request rather than by the script
// author.
//
// It had no depth limit.  Unbounded native recursion over the input, and a few
// hundred kilobytes of `[[[[` took the daemon down: measured, 40 KB survived
// and 200 KB was a SIGSEGV with a core file.  No callback deadline covers it,
// because that hooks Lua instructions and this recursion is C++ frames.
//
// The eleven existing targets cover the protocol parsers — RESP, WebSocket,
// HTTP request and response — which is where a full review found nothing.  This
// covers the parser that was actually broken.
//
// It could not be written at all until the pair moved into lua_json.h: it was
// file-static in lua_context.cpp behind a private register_bindings(), so
// nothing outside that translation unit could call it.  A first attempt at this
// file drove the functions through a sol::state and quietly returned 0 for
// every input because the bindings were not there — a target that measures
// nothing, with a long comment about why it matters.  That version was deleted.
//
// ─── WHAT IS CHECKED ────────────────────────────────────────────────────────
//
// Not "does it crash": libFuzzer answers that by itself, and the depth limit is
// what makes the answer no.  The properties are:
//
//   * decode terminates and reports.  A value or a refusal, never a hang and
//     never a half-built table handed back as though it were whole.
//
//   * encode(decode(encode(x))) == encode(x).  Feeding the encoder's own output
//     back in must produce the same string.  Drift means the two sides disagree
//     about the format they share, which no crash would surface.
//
//   * a table that contains itself is refused rather than followed.  Built here
//     rather than decoded, because no JSON document can express a cycle —
//     `t.self = t` is a typo a script makes, and it used to be a stack overflow.
//
// WHAT THIS DOES NOT COVER: sol2 itself, the callback deadline, and whatever a
// handler does with the value afterwards.  It stops where the value is built.

#include "fuzz_common.h"
#include "../../socketley/shared/lua_json.h"

#include <cstdio>
#include <string>
#include <vector>

namespace {

// One interpreter for the whole run.  A sol::state per input would measure
// LuaJIT's startup rather than the parser, and neither function keeps state
// between calls.
sol::state& interpreter()
{
    static sol::state* lua = [] {
        auto* s = new sol::state();
        s->open_libraries(sol::lib::base, sol::lib::table);
        return s;
    }();
    return *lua;
}

std::string encode_or_empty(const sol::object& v, bool& refused)
{
    std::string out;
    std::vector<const void*> path;
    std::string err;
    refused = !socketley::lua_json::json_encode_value(out, v, 0, path, err);
    return out;
}

}   // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    data = ::fuzz::never_null(data);
    ::fuzz::set_current(data, size);
    sol::state& lua = interpreter();

    // ─── The cycle, once per run rather than per input ──────────────────────
    //
    // It does not depend on the bytes, and running it every time would spend
    // the whole campaign on one case.  It is here at all because it is the
    // encoder half of the defect and no input can express it.
    static const bool cycle_refused = [&] {
        sol::table t = lua.create_table();
        t["self"] = t;
        bool refused = false;
        encode_or_empty(sol::object(t), refused);
        return refused;
    }();
    FUZZ_CHECK(cycle_refused, "json_encode followed a table that contains itself");

    using socketley::lua_json::json_status;

    const char* p   = reinterpret_cast<const char*>(::fuzz::never_null(data));
    const char* end = p + size;

    auto        st = json_status::ok;
    sol::object v  = socketley::lua_json::json_decode_value(lua, p, end, 0, st);
    if (st != json_status::ok)
        return 0;   // a refusal is an answer — the point of the limit, and of the parser

    // Every object a successful decode hands back carries an interpreter.  A
    // free-standing sol::nil does not, and get_type() on one dereferences a null
    // lua_State*: this line is where that was found, because it is the first
    // caller in the tree that looks at the object instead of passing it to Lua.
    FUZZ_CHECK(v.lua_state() != nullptr, "json_decode returned an object with no lua_State");

    bool refused = false;
    const std::string once = encode_or_empty(v, refused);
    if (refused)
        return 0;   // likewise: a value the encoder will not write is answered, not crashed

    // ─── Stability ──────────────────────────────────────────────────────────
    //
    // The encoder's own output is a document the decoder must read back to
    // something the encoder writes identically.  Against a decoder that accepts
    // anything this checks little; against one that rejects a missing bracket it
    // says the two halves agree on the grammar, which is the property that broke
    // when only one of them was ever changed.
    const char* q  = once.data();
    const char* qe = once.data() + once.size();
    auto        st2 = json_status::ok;
    sol::object v2 = socketley::lua_json::json_decode_value(lua, q, qe, 0, st2);

    if (st2 == json_status::too_deep)
        FUZZ_CHECK(false, "json_decode called its own encoder's output too deep");
    if (st2 != json_status::ok)
        FUZZ_CHECK(false, "json_decode rejected a document json_encode produced");
    if (q != qe)
        FUZZ_CHECK(false, "json_decode left trailing bytes on its own encoder's output");

    bool refused2 = false;
    const std::string twice = encode_or_empty(v2, refused2);
    if (refused2)
        FUZZ_CHECK(false, "json_encode refused a value it produced itself");

    if (once != twice)
    {
        // Both strings, because the input bytes alone do not show this one: the
        // interesting part is which of the two encodings moved, and a hex dump
        // of the seed says nothing about that.
        fprintf(stderr, "  once : %s\n  twice: %s\n", once.c_str(), twice.c_str());
        FUZZ_CHECK(false, "encode(decode(encode(x))) differs from encode(x)");
    }

    return 0;
}
