// Fuzz target: WebSocket frame parsing and handshake key derivation
// (socketley/shared/ws_protocol.h).
//
// Reachable by any unauthenticated peer that completes a WebSocket upgrade
// against a server runtime, or that speaks WebSocket through the proxy.  Frame
// headers are the most attacker-shaped input in the project: the peer chooses
// the declared payload length (up to a 64-bit field), whether the frame is
// masked, and how much of it actually arrives — three numbers that the parser
// has to reconcile against the size of a buffer the peer does not control.
//
// Covered:
//   ws_parse_header        length/mask/opcode decoding and the RFC 6455 limits
//   ws_parse_frame         copying parse (allocates a payload string)
//   ws_parse_frame_inplace unmasks the caller's buffer and points into it
//   ws_unmask_payload      via both of the above — AVX2/SSE2/scalar tails
//   ws_accept_key          the stack-vs-heap split at 92 bytes of client key
//
// Properties checked, beyond "did it crash":
//   * a frame the parser accepts must fit entirely inside the bytes it was
//     given, and `consumed` must never exceed them;
//   * the copying parser and the in-place parser must agree — they are two
//     implementations of the same header decode plus the same unmask, and the
//     in-place one is what the hot path uses;
//   * encode-then-parse must round-trip a payload unchanged.
//
// WHAT THIS TARGET DOES NOT COVER: fragmentation across frames (continuation
// opcodes are decoded here but the reassembly that owns them lives in the
// server and proxy read handlers), UTF-8 validation of text payloads (the
// project does not do any), the HTTP half of the upgrade, and permessage
// deflate (not implemented).

#include "fuzz_common.h"
#include "shared/ws_protocol.h"

#include <string>
#include <vector>

namespace {

void one_frame(const uint8_t* data, size_t size)
{
    if (size < 2)
        return;

    // --- header decode ---
    ws_header hdr{};
    bool hdr_ok = ws_parse_header(reinterpret_cast<const char*>(data), size, hdr);

    if (hdr_ok)
    {
        size_t mask_size = hdr.masked ? 4u : 0u;
        FUZZ_CHECK(hdr.header_size == 2 || hdr.header_size == 4 || hdr.header_size == 10,
                   "header_size is not one of the three sizes RFC 6455 defines");
        FUZZ_CHECK(hdr.payload_len <= WS_MAX_PAYLOAD,
                   "an accepted frame declares a payload past the configured ceiling");
        FUZZ_CHECK(hdr.header_size + mask_size + hdr.payload_len <= size,
                   "an accepted frame claims more bytes than the buffer holds — "
                   "the payload read would run past the end of the input");
        if (hdr.opcode >= 0x8)
        {
            FUZZ_CHECK(hdr.payload_len <= 125, "an accepted control frame carries more than 125 bytes (RFC 6455 5.5)");
            FUZZ_CHECK(hdr.fin, "an accepted control frame is fragmented (RFC 6455 5.5)");
        }
    }

    // --- copying parse ---
    ws_frame copy_out;
    bool copy_ok = ws_parse_frame(reinterpret_cast<const char*>(data), size, copy_out);
    FUZZ_CHECK(copy_ok == hdr_ok, "ws_parse_frame and ws_parse_header disagree on whether the frame is complete");
    if (copy_ok)
    {
        FUZZ_CHECK(copy_out.consumed <= size, "ws_parse_frame consumed more bytes than it was given");
        FUZZ_CHECK(copy_out.payload.size() == hdr.payload_len, "payload length does not match the decoded header");
    }

    // --- in-place parse, on a private copy since it rewrites the buffer ---
    std::vector<char> scratch(data, data + size);
    ws_frame_view view{};
    bool inplace_ok = ws_parse_frame_inplace(scratch.data(), scratch.size(), view);
    FUZZ_CHECK(inplace_ok == copy_ok, "the copying and in-place frame parsers disagree on whether the frame is complete");

    if (inplace_ok)
    {
        FUZZ_CHECK(view.consumed == copy_out.consumed, "the two frame parsers consumed different amounts");
        FUZZ_CHECK(view.opcode == copy_out.opcode, "the two frame parsers decoded different opcodes");
        FUZZ_CHECK(view.payload_len == copy_out.payload.size(), "the two frame parsers decoded different payload lengths");
        FUZZ_CHECK(view.payload_ptr >= scratch.data(), "the in-place payload view starts before the buffer");
        FUZZ_CHECK(view.payload_ptr + view.payload_len <= scratch.data() + view.consumed,
                   "the in-place payload view extends past the bytes the parser said it consumed");
        FUZZ_CHECK(std::memcmp(view.payload_ptr, copy_out.payload.data(), view.payload_len) == 0,
                   "the two frame parsers unmasked the same payload differently");
    }
}

// Encode a payload, parse it back, and require the payload to survive.  This is
// the direction a peer does not control, but it is the direction every reply
// the daemon sends takes, and the header writer has three size branches with
// hand-rolled byte shuffling in each.
void round_trip(const uint8_t* data, size_t size)
{
    // Keep this cheap: a 16 MB round trip per input would dominate the run.
    if (size > 128 * 1024)
        return;

    std::string_view payload(reinterpret_cast<const char*>(data), size);

    std::string framed = ws_frame_text(payload);
    ws_frame out;
    FUZZ_CHECK(ws_parse_frame(framed.data(), framed.size(), out),
               "a frame produced by ws_frame_text did not parse back");
    FUZZ_CHECK(out.opcode == WS_OP_TEXT, "a text frame round-tripped to a different opcode");
    FUZZ_CHECK(out.consumed == framed.size(), "a round-tripped frame reported the wrong consumed length");
    FUZZ_CHECK(out.payload == payload, "a payload did not survive encode-then-parse");

    std::string pong = ws_frame_pong(payload);
    ws_frame pout;
    FUZZ_CHECK(ws_parse_frame(pong.data(), pong.size(), pout),
               "a frame produced by ws_frame_pong did not parse back");
    FUZZ_CHECK(pout.opcode == WS_OP_PONG, "a pong frame round-tripped to a different opcode");
    FUZZ_CHECK(pout.payload.size() <= 125, "ws_frame_pong emitted a control frame larger than RFC 6455 allows");
    FUZZ_CHECK(payload.substr(0, pout.payload.size()) == pout.payload,
               "ws_frame_pong truncated the payload to something other than its own prefix");

    // Same payload as an appended frame: the _into variants write through
    // resize() + memcpy rather than append(), which is a different set of
    // bounds to get wrong.
    std::string buf = "PREFIX";
    ws_frame_text_into(buf, payload);
    FUZZ_CHECK(buf.size() == 6 + framed.size(), "ws_frame_text_into wrote a different number of bytes than ws_frame_text");
    FUZZ_CHECK(std::memcmp(buf.data() + 6, framed.data(), framed.size()) == 0,
               "ws_frame_text_into and ws_frame_text produced different bytes");
}

// The handshake key path.  Bounded at 200 bytes so both the `char combined[128]`
// stack branch (key <= 92 bytes) and the heap branch above it are reached, and
// the boundary between them is hit often.
void accept_key(const uint8_t* data, size_t size)
{
    size_t n = size < 200 ? size : 200;
    std::string_view key(reinterpret_cast<const char*>(data), n);

    std::string a = ws_accept_key(key);
    std::string b;
    ws_accept_key_into(b, key);
    FUZZ_CHECK(a == b, "ws_accept_key and ws_accept_key_into produced different accept keys");
    FUZZ_CHECK(a.size() == 28, "an accept key is not the 28 characters base64 of a SHA-1 digest must be");

    std::string resp = ws_handshake_response(key);
    FUZZ_CHECK(resp.find("\r\n\r\n") != std::string::npos, "the handshake response has no header terminator");
    FUZZ_CHECK(resp.find(a) != std::string::npos, "the handshake response does not carry the accept key it derived");
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    data = ::fuzz::never_null(data);
    ::fuzz::set_current(data, size);

    // WS_MAX_PAYLOAD is 16 MB; there is no point handing the fuzzer more than
    // enough to cross it, and larger inputs only slow the corpus down.
    if (size > 1024 * 1024)
        return 0;

    one_frame(data, size);
    round_trip(data, size);
    accept_key(data, size);

    // Drain: consecutive frames out of one buffer, the way a server read
    // handler pulls them.  A `consumed` that is off by even one byte here
    // desynchronises the stream permanently.
    {
        std::vector<char> scratch(data, data + size);
        size_t off = 0;
        int guard = 0;
        while (off < scratch.size() && guard++ < 4096)
        {
            ws_frame_view v{};
            if (!ws_parse_frame_inplace(scratch.data() + off, scratch.size() - off, v))
                break;
            FUZZ_CHECK(v.consumed > 0, "an accepted frame consumed zero bytes — the drain loop would spin forever");
            FUZZ_CHECK(off + v.consumed <= scratch.size(), "a frame consumed past the end of the remaining buffer");
            off += v.consumed;
        }
    }

    ::fuzz::set_current(nullptr, 0);
    return 0;
}
