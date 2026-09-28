// Fuzz target: the Raft wire codec (socketley/shared/raft_codec.h) and the
// frame splitting in front of it.
//
// Reachable by anything that can open a TCP connection to a daemon's
// --raft-listen port and, under --raft-insecure, by anyone at all: the codec
// runs on every frame before the sender's identity is known to be a member.
//
// The first input byte picks the mode:
//   even  the rest is one payload handed to wire::decode
//   odd   the rest is a byte stream split with ipc_frame::peek_frame, each
//         frame decoded, as raft_host's read path does
//
// Properties checked, beyond "did it crash":
//   * the encoding is canonical: a payload decode accepts re-encodes to the
//     exact same bytes, so two nodes cannot disagree about what one frame said;
//   * decode(encode(x)) is x for every accepted message, hello and join;
//   * a decoded snapshot message carries a snapshot and nothing else does,
//     since the core dereferences it without asking;
//   * an append's entries continue its index, since the core appends them
//     where they say they go;
//   * no truncation of an accepted payload is accepted, so a torn frame is
//     never taken for a shorter one;
//   * the frame splitter never hands out a payload past its buffer or past
//     ipc_frame::max_payload.
//
// WHAT THIS TARGET DOES NOT COVER: what the core does with a well-formed but
// hostile message (a forged term, a vote from a non-member), TLS, and the
// hello's identity check against membership, which live in raft_host.

#include "fuzz_common.h"
#include "shared/ipc_framing.h"
#include "shared/raft_codec.h"

#include <string>
#include <string_view>

namespace wire = socketley::raft::wire;
namespace raft = socketley::raft;

namespace {

void one_payload(std::string_view p)
{
    wire::frame f;
    if (!wire::decode(p, f))
        return;

    std::string again;
    switch (f.kind)
    {
    case wire::kind::message:
    {
        const raft::message& m = f.msg;
        FUZZ_CHECK((m.type == raft::msg_type::snapshot) == static_cast<bool>(m.snap),
                   "a snapshot message decoded without a snapshot, or another message with one");
        for (size_t i = 0; i < m.entries.size(); ++i)
            FUZZ_CHECK(m.entries[i].index == m.index + 1 + i, "an append's entries do not continue its index");
        again = wire::encode(m);
        wire::frame g;
        FUZZ_CHECK(wire::decode(again, g), "a re-encoded message does not decode");
        FUZZ_CHECK(g.kind == wire::kind::message && wire::same(m, g.msg), "a message did not survive a round trip");
        break;
    }
    case wire::kind::hello:
    {
        again = wire::encode(f.hi);
        wire::frame g;
        FUZZ_CHECK(wire::decode(again, g) && g.kind == wire::kind::hello && g.hi == f.hi,
                   "a hello did not survive a round trip");
        break;
    }
    case wire::kind::join:
    {
        again = wire::encode(f.req);
        wire::frame g;
        FUZZ_CHECK(wire::decode(again, g) && g.kind == wire::kind::join && g.req == f.req,
                   "a join did not survive a round trip");
        break;
    }
    }

    FUZZ_CHECK(again == p, "an accepted payload does not re-encode to the same bytes");

    // Every shorter prefix is a torn frame, and none of them may pass for a whole one.
    for (size_t cut = p.size(); cut-- > 0;)
    {
        wire::frame t;
        FUZZ_CHECK(!wire::decode(p.substr(0, cut), t), "a truncated payload was accepted");
        if (p.size() - cut > 64)
            break;
    }
}

void stream(std::string_view s)
{
    size_t off = 0;
    for (int frames = 0; frames < 64; ++frames)
    {
        if (off >= s.size() || s[off] != ipc_frame::marker)
            return;
        std::string_view payload;
        size_t next = 0;
        const ipc_frame::take r = ipc_frame::peek_frame(s, off, payload, next);
        if (r != ipc_frame::take::ok)
            return;
        FUZZ_CHECK(payload.size() <= ipc_frame::max_payload, "a frame larger than max_payload was taken");
        FUZZ_CHECK(next <= s.size() && payload.data() + payload.size() <= s.data() + s.size(),
                   "a frame reaches past the bytes it was split from");
        one_payload(payload);
        off = next;
    }
}

}   // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    fuzz::set_current(data, size);
    if (size < 1)
        return 0;
    const std::string_view rest(reinterpret_cast<const char*>(data + 1), size - 1);
    if (data[0] & 1)
        stream(rest);
    else
        one_payload(rest);
    return 0;
}
