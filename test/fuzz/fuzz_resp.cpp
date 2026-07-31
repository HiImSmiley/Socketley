// Fuzz target: RESP2 command parsing (socketley/runtime/cache/resp_parser.h).
//
// Reachable by any unauthenticated peer that can open a TCP connection to a
// cache runtime.  The cache read handler appends bytes to a per-connection
// buffer and calls into these two functions on every wakeup, so the exact
// shapes this target produces — truncated headers, absurd lengths, a message
// split across reads — are what the parser sees in production.
//
// Both entry points are covered:
//
//   resp::parse_message        allocating, fills std::vector<std::string>
//   resp::parse_message_views  zero-allocation, fills string_views into the
//                              caller's buffer, with hand-written fast paths
//                              for single-digit array counts and bulk lengths
//
// The interesting property is not "does it crash" — it is that the two must
// describe the same wire format.  parse_message is the older, straightforward
// one; parse_message_views is the optimised one that the hot path actually
// uses.  A divergence means a peer can make the fast parser see a different
// command than the reference parser does, which on a shared address space is
// exactly the class of defect this project keeps finding by hand.
//
// WHAT THIS TARGET DOES NOT COVER: command dispatch and cache_store mutation
// (resp_parser.h stops at argv), the RESP *encoder* (fuzzing it needs a
// generator, not a byte string), and the framing loop in cache_instance.cpp
// that decides how much of the buffer to hand over.  Feeding the parser
// prefixes below is a model of that loop, not the loop itself.

#include "fuzz_common.h"
#include "../../socketley/runtime/cache/resp_parser.h"

#include <vector>
#include <string>

namespace {

constexpr int MAX_VIEW_ARGS = 64;

// Every string_view an ok parse hands back must point inside the bytes the
// parse claims to have consumed.  A view that points past `consumed` is a view
// into data the caller is entitled to overwrite as soon as it advances the
// buffer, which is a use-after-free with extra steps.
void check_views_in_bounds(std::string_view buf, const std::string_view* args, int argc, size_t consumed)
{
    FUZZ_CHECK(consumed <= buf.size(), "parser consumed more bytes than it was given");
    const char* lo = buf.data();
    const char* hi = buf.data() + consumed;
    for (int i = 0; i < argc; i++)
    {
        FUZZ_CHECK(args[i].data() >= lo, "argument view starts before the input buffer");
        FUZZ_CHECK(args[i].data() + args[i].size() <= hi,
                   "argument view extends past the bytes the parser said it consumed");
    }
}

void one_buffer(std::string_view buf, const uint8_t* raw, size_t raw_size)
{
    // --- reference parser ---
    std::vector<std::string> args;
    size_t consumed_ref = 0;
    auto r_ref = resp::parse_message(buf, args, consumed_ref);
    FUZZ_CHECK(consumed_ref <= buf.size(), "parse_message consumed more bytes than it was given");
    if (r_ref == resp::parse_result::ok)
        FUZZ_CHECK(!args.empty() || consumed_ref > 0, "ok parse consumed nothing and produced nothing");

    // --- zero-allocation parser ---
    std::string_view views[MAX_VIEW_ARGS];
    int argc = 0;
    size_t consumed_fast = 0;
    auto r_fast = resp::parse_message_views(buf, views, MAX_VIEW_ARGS, argc, consumed_fast);
    FUZZ_CHECK(argc >= 0 && argc <= MAX_VIEW_ARGS, "parse_message_views reported an argc outside the array it was given");
    check_views_in_bounds(buf, views, argc, consumed_fast);

    // --- differential oracle ---
    //
    // The two parsers disagree on one thing by construction: parse_message_views
    // refuses an array whose element count exceeds the caller's array, where
    // parse_message has no such ceiling.  That is a deliberate difference, so
    // skip the comparison whenever the reference produced more arguments than
    // the view parser was allowed to.
    const bool count_capped = (args.size() > static_cast<size_t>(MAX_VIEW_ARGS));
    if (!count_capped)
    {
        if (r_ref == resp::parse_result::ok && r_fast == resp::parse_result::ok)
        {
            FUZZ_CHECK(static_cast<size_t>(argc) == args.size(),
                       "the two RESP parsers accepted the same bytes but produced a different argument count");
            FUZZ_CHECK(consumed_fast == consumed_ref,
                       "the two RESP parsers accepted the same bytes but consumed different amounts — "
                       "the next command would start at a different offset in each");
            for (int i = 0; i < argc; i++)
                FUZZ_CHECK(views[i] == std::string_view(args[static_cast<size_t>(i)]),
                           "the two RESP parsers accepted the same bytes but produced different arguments");
        }
        else if (r_ref == resp::parse_result::ok || r_fast == resp::parse_result::ok)
        {
            // One accepted, the other did not.  A peer that can make the hot
            // parser execute a command the reference parser rejects (or the
            // other way round) has found a real inconsistency.
            FUZZ_CHECK(false,
                       "one RESP parser accepted the message and the other did not");
        }
        else if (r_ref != r_fast)
        {
            // Both rejected, but one said "incomplete" (wait for more bytes)
            // and the other said "error" (close the connection).  Known to
            // differ for at least one shape: "*1\r\nX" is `error` to
            // parse_message — it checks the '$' before checking the length —
            // and `incomplete` to parse_message_views, which requires four
            // bytes of element header first.  Reported, not fatal, because the
            // cache only ever calls one of them: the consequence is a slow
            // connection close rather than a wrong command.  FUZZ_STRICT=1
            // makes it fatal if that ever stops being true.
            fuzz_observe("RESP parsers disagree on incomplete-vs-error for the same bytes", raw, raw_size);
        }
    }

    // A message that parses must keep parsing the same way when the bytes that
    // follow it change: the parser is handed a live socket buffer that always
    // has whatever arrived next appended to it.
    if (r_ref == resp::parse_result::ok && consumed_ref < buf.size())
    {
        std::vector<std::string> args2;
        size_t consumed2 = 0;
        auto r2 = resp::parse_message(buf.substr(0, consumed_ref), args2, consumed2);
        FUZZ_CHECK(r2 == resp::parse_result::ok,
                   "a message that parsed inside a longer buffer stopped parsing once the trailing bytes were removed");
        FUZZ_CHECK(consumed2 == consumed_ref && args2 == args,
                   "a message parsed differently depending on bytes that came after it");
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    data = ::fuzz::never_null(data);
    ::fuzz::set_current(data, size);

    // 1 MB is well past the cache's own read buffer; anything larger only slows
    // the fuzzer down without reaching new code.
    if (size > 1024 * 1024)
        return 0;

    std::string_view buf(reinterpret_cast<const char*>(data), size);
    one_buffer(buf, data, size);

    // Model the socket: the same command arriving as two reads.  A parser that
    // is only ever tested on whole messages will not be tested on the boundary
    // handling that a peer controls completely, simply by sending one byte at
    // a time.  The split point comes from the input so the fuzzer can steer it.
    if (size >= 2)
    {
        size_t split = static_cast<size_t>(::fuzz::byte_at(data, size, size - 1)) % size;
        one_buffer(buf.substr(0, split), data, size);
    }

    // Drain: keep parsing complete messages out of the front of the buffer the
    // way the cache read handler does.  This is where a `consumed` that is too
    // large or too small turns into reading someone else's bytes.
    {
        std::string_view rest = buf;
        int guard = 0;
        while (!rest.empty() && guard++ < 1024)
        {
            std::vector<std::string> args;
            size_t consumed = 0;
            if (resp::parse_message(rest, args, consumed) != resp::parse_result::ok)
                break;
            FUZZ_CHECK(consumed > 0, "an ok parse consumed zero bytes — the drain loop would spin forever");
            FUZZ_CHECK(consumed <= rest.size(), "an ok parse consumed past the end of the remaining buffer");
            rest.remove_prefix(consumed);
        }
    }

    ::fuzz::set_current(nullptr, 0);
    return 0;
}
