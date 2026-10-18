// Fuzz target: the tunnel half of proxy response framing
// (socketley/shared/http/http_framing.h).
//
// The relay is the one proxy path that had no fuzzer, and it is the path where
// a framing mistake is least likely to announce itself.  A tunnel that gets its
// framing wrong does not return a status and does not log: it relays the wrong
// bytes, or it stops.  Every other parser in this tree fails loudly by
// comparison.
//
// ─── WHAT A FUZZER CAN SEE HERE, WHICH IS EVERYTHING ────────────────────────
//
// Worth stating, because if it were not true this target would be theatre.  The
// tunnel is relayed by ordinary read and write, NOT by splice — deliberately,
// and the reasoning is in proxy_instance.cpp above the relay: a splice armed on
// an idle tunnel holds an io-wq kernel thread for as long as the peer is quiet
// (four such connections burned 95.7% of a core), it needs a pipe pair and
// 256 KB of pipe buffer per connection, and it cannot cross a TLS leg at all
// while a WebSocket over an https:// listener is an entirely ordinary thing to
// ask for.  A multishot recv is already a poll until data arrives, so it
// reaches the same idle cost with none of that.
//
// Structurally: setup_splice_pipes() is reached only in protocol_tcp and only
// when no request/response hook is set, and a tunnel is HTTP-mode by
// construction — it begins with an upgrade request.  So no byte of a tunnel
// ever bypasses userspace, and the state this target drives is the state the
// live path drives.
//
// ─── WHY THIS IS NOT COVERED BY fuzz_http_response ──────────────────────────
//
// That target drives the same scanner and is where general response framing
// belongs.  What it does not do is reach 101: nothing in it, and nothing in its
// corpus, pins a switch to a tunnel, so the post-switch state is explored only
// when a mutator happens to spell "HTTP/1.1 101" — which is not a coverage
// strategy.  Half of this target is therefore *directed*: it builds the switch
// itself, on every single input, and then attacks what comes after it.
//
// ─── THE PROPERTY THAT MATTERS, STATED AS ITS CONSEQUENCE ───────────────────
//
// A flag being set is not the harm.  The harm is a live tunnel socket reaching
// the backend connection pool, where the next request picks it up and its
// borrower reads WebSocket payload as the head of its own answer.
//
// So the assertion is made against the pool gate itself.  Both pooling paths in
// proxy_instance ask exactly one predicate — backend_response_complete(), which
// is http_response_frame_complete() and nothing else — and it was moved into
// this header precisely so a test could call it.
//
// The concrete shape that motivates it is in the scanner's own comment: a
// payload that happens to spell "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
// must not be read as a complete response.  Part B hands the scanner exactly
// that coincidence, on purpose, every run — and the control for it is real:
// those same bytes with no 101 in front of them ARE poolable, which is what
// makes "not poolable behind a 101" a statement about the tunnel rather than
// about the bytes.
//
// ─── WHAT HOLDS THAT INVARIANT TODAY, MEASURED RATHER THAN ASSUMED ──────────
//
// Worth writing down, because it decides what this target can actually catch,
// and the first draft of this comment was wrong about it.  Three independent
// mechanisms keep the gate shut behind a 101, and any ONE of them is sufficient:
//
//   1. the switched_protocols early return in http_response_scan_chunk;
//   2. headers_parsed being set true by the 101 branch, which sends everything
//      afterwards to the body countdown instead of to a header scan — and with
//      no declared length there is nothing for it to count;
//   3. response_bytes_seen marking a second header block `unknown`.
//
// Measured: removing (1) alone changes no field of the state and leaves the
// gate shut.  So does removing (2) alone.  Removing both moves `unknown` from
// 0 to 1 — caught by (3), gate still shut — and that is the first change this
// target can see.  A target whose headline assertion cannot fail is the thing
// this file exists to avoid being, so: the pool-gate check is a backstop that
// is currently redundant three ways, and the assertion that actually
// discriminates is the snapshot one below.
//
// Verified by breaking it rather than by argument: with (1) and (2) both
// removed the target aborts on a six-byte seed — `"\x02" "0\r\n\r\n"` — naming
// the moved field.  Restored, it is green over the corpus again.
//
// Properties checked:
//   * switched_protocols is monotonic — nothing clears it, ever;
//   * once switched, the pool gate is shut and STAYS shut, whatever follows.
//     Redundant today; it is the statement of the harm, and it is the one that
//     survives somebody deciding (2) or (3) is the redundant one;
//   * once switched, the scan does not move any framing field — not the status,
//     not the body countdown, not chunked, not unknown.  Tunnel bytes are not
//     HTTP and must not be counted as any part of one.  THIS is the live wire;
//   * a switch is reached at all on every input (part B), so the case cannot
//     silently stop being exercised.
//
// WHAT THIS TARGET DOES NOT COVER: the upgrade *request* half (fuzz_http_request
// owns request parsing), WebSocket frame decoding (fuzz_ws_frame owns it — the
// proxy deliberately does none), the live relay's socket bookkeeping in
// conn_tunnelled()/begin_tunnel(), which needs the ops-style harness in
// fuzz_proxy_ops.cpp rather than a byte parser, and the deadline behaviour a
// tunnel disarms.

#include "fuzz_common.h"
#include "shared/http/http_framing.h"

#include <string>
#include <vector>

namespace {

// Everything about the state except the flag under test, so "the scan did not
// move anything" can be one comparison rather than nine.
struct framing_snapshot
{
    bool     headers_parsed, has_content_length, conn_close, chunked;
    bool     no_body, transfer_encoding, unknown, response_bytes_seen;
    uint16_t status_code;
    size_t   body_remaining;
    uint8_t  interim_blocks;

    explicit framing_snapshot(const http_response_framing& st)
        : headers_parsed(st.headers_parsed)
        , has_content_length(st.has_content_length)
        , conn_close(st.conn_close)
        , chunked(st.chunked)
        , no_body(st.no_body)
        , transfer_encoding(st.transfer_encoding)
        , unknown(st.unknown)
        , response_bytes_seen(st.response_bytes_seen)
        , status_code(st.status_code)
        , body_remaining(st.body_remaining)
        , interim_blocks(st.interim_blocks)
    {}

    bool operator==(const framing_snapshot& o) const
    {
        return headers_parsed == o.headers_parsed &&
               has_content_length == o.has_content_length &&
               conn_close == o.conn_close && chunked == o.chunked &&
               no_body == o.no_body && transfer_encoding == o.transfer_encoding &&
               unknown == o.unknown && response_bytes_seen == o.response_bytes_seen &&
               status_code == o.status_code && body_remaining == o.body_remaining &&
               interim_blocks == o.interim_blocks;
    }
};

// One chunk into the state, with every post-switch property re-stated.  `was`
// is the state as it stood before this chunk.
void feed_and_check(http_response_framing& st, std::string_view chunk)
{
    const bool             was_switched = st.switched_protocols;
    const framing_snapshot before(st);

    http_response_scan_chunk(st, chunk);

    FUZZ_CHECK(!was_switched || st.switched_protocols,
               "switched_protocols was cleared — a stream that became a tunnel "
               "cannot go back to carrying HTTP messages");

    if (st.switched_protocols)
        FUZZ_CHECK(!http_response_frame_complete(st),
                   "the pool gate opened on a tunnelled connection — a live "
                   "tunnel socket would be filed in the backend pool and the "
                   "next borrower would read its payload as a response");

    if (was_switched)
    {
        const framing_snapshot after(st);
        FUZZ_CHECK(before == after,
                   "the scan moved a framing field after the switch — tunnel "
                   "bytes are not HTTP and must not be read as any part of a "
                   "message");
    }
}

// ── A. free-form: whatever the mutator makes of a response stream ───────────
//
// Chunk boundaries come out of the input too: a header block straddling one is
// the case the scanner marks `unknown` for, and it is a boundary the peer
// chooses in practice.
void stream(const uint8_t* data, size_t size)
{
    http_response_framing st{};
    size_t off = 0;
    int    guard = 0;
    while (off < size && guard++ < 512)
    {
        size_t take = static_cast<size_t>(::fuzz::byte_at(data, size, off, 1)) + 1;
        if (take > size - off)
            take = size - off;
        feed_and_check(st, std::string_view(reinterpret_cast<const char*>(data) + off, take));
        off += take;
    }
}

// ── B. directed: the switch is built here, so it happens every run ──────────
//
// The 101 is not left to the mutator.  It is synthesised, fed, asserted, and
// only then is the fuzz input handed over as tunnel payload — which is free to
// spell a complete HTTP response, and on a mutator with any luck at all
// eventually will.  That is the whole case: the gate must stay shut anyway.
void directed_tunnel(const uint8_t* data, size_t size)
{
    // Headers chosen from the input where it is harmless to, so the seed pins
    // the shape while the mutator still gets to vary it.
    const uint8_t style = ::fuzz::byte_at(data, size, 0, 0);

    std::string resp = "HTTP/1.1 101 Switching Protocols\r\n";
    resp += "Upgrade: websocket\r\n";
    resp += "Connection: Upgrade\r\n";
    // A 101 that also claims a body is self-contradictory and is exactly the
    // sort of thing a backend under test does; the scanner must still treat the
    // switch as final.
    if (style & 1) resp += "Content-Length: 5\r\n";
    if (style & 2) resp += "Transfer-Encoding: chunked\r\n";
    if (style & 4) resp += "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n";
    resp += "\r\n";

    http_response_framing st{};

    // Split the 101 itself across a boundary when the input says so: a status
    // line separated from its headers is the shape that leaves other responses
    // `unknown`, and it must not leave a 101 half-switched.
    if ((style & 8) && resp.size() > 20)
    {
        feed_and_check(st, std::string_view(resp).substr(0, 20));
        feed_and_check(st, std::string_view(resp).substr(20));
    }
    else
    {
        feed_and_check(st, resp);
    }

    // Whether the split form switched is the scanner's business — a block that
    // straddles a boundary is allowed to be judged unreadable.  What is not
    // allowed is being poolable, either way.
    FUZZ_CHECK(!http_response_frame_complete(st),
               "the pool gate is open on a connection whose backend answered 101");

    if (!st.switched_protocols)
        return;   // straddled and marked unknown; part A still covers it

    // Now the tunnel payload: the fuzz input verbatim, then the coincidence the
    // scanner's comment names, then the input again behind it.
    if (size)
        feed_and_check(st, std::string_view(reinterpret_cast<const char*>(data), size));

    static constexpr std::string_view kLooksLikeAResponse =
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    feed_and_check(st, kLooksLikeAResponse);

    if (size)
        feed_and_check(st, std::string_view(reinterpret_cast<const char*>(data), size));

    // Stated once more at the end, plainly, because this is the sentence the
    // whole target exists to be able to say.
    FUZZ_CHECK(st.switched_protocols,
               "a tunnelled connection stopped being tunnelled");
    FUZZ_CHECK(!http_response_frame_complete(st),
               "a tunnelled connection became poolable after being fed bytes "
               "that spell a complete HTTP response");
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    data = ::fuzz::never_null(data);
    ::fuzz::set_current(data, size);

    // Nothing here is quadratic, but a megabyte of chunking per input only
    // slows the corpus down; the interesting states are all small.
    if (size > 256 * 1024)
        return 0;

    stream(data, size);
    directed_tunnel(data, size);

    ::fuzz::set_current(nullptr, 0);
    return 0;
}
