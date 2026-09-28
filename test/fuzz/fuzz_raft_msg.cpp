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
//   0x80  the rest is a cluster command (bit 1 clear) or a cluster snapshot
//         (bit 1 set), the two things a committed entry and a snapshot carry
//         into the state machine
//
// Properties checked, beyond "did it crash":
//   * a cluster command or snapshot that decodes re-encodes to the same bytes,
//     and a state that decodes is one plan() can walk without leaving the
//     invariants the state machine keeps;
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
#include "shared/cluster_state.h"
#include "shared/raft_codec.h"

#include <string>
#include <string_view>
#include <vector>

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
    case wire::kind::command:
    {
        again = wire::encode(f.cmd);
        wire::frame g;
        FUZZ_CHECK(wire::decode(again, g) && g.kind == wire::kind::command && g.cmd == f.cmd,
                   "a forwarded command did not survive a round trip");
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

// Whatever decodes is what encode would have written, and planning on it never breaks the rules apply() keeps.
void cluster_bytes(std::string_view p, bool snapshot)
{
    namespace cl = socketley::cluster;
    if (!snapshot)
    {
        cl::command c;
        if (cl::decode(p, c))
        {
            FUZZ_CHECK(cl::encode(c) == p, "a cluster command that decodes does not re-encode to the same bytes");
            FUZZ_CHECK(cl::refusal(c).empty(), "a cluster command was accepted that refusal() refuses");
        }
        return;
    }
    cl::state s;
    if (!cl::decode(p, s))
        return;
    FUZZ_CHECK(cl::encode(s) == p, "a cluster snapshot that decodes does not re-encode to the same bytes");
    cl::state t;
    FUZZ_CHECK(cl::decode(cl::encode(s), t) && t == s, "a cluster snapshot did not survive a round trip");
    std::vector<cl::node_id> live = {1, 2, 3};
    for (const auto& [name, held] : s.owners)
        for (cl::node_id n : held)
            live.push_back(n);
    for (const cl::command& c : cl::plan(s, live))
    {
        FUZZ_CHECK(cl::refusal(c).empty(), "plan() proposed a command that refusal() refuses");
        s.apply(c);
    }
    for (const auto& [name, sp] : s.specs)
        FUZZ_CHECK(s.placed(name) <= sp.replicas, "a plan left a runtime with more owners than it wants replicas");
}

}   // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    fuzz::set_current(data, size);
    if (size < 1)
        return 0;
    const std::string_view rest(reinterpret_cast<const char*>(data + 1), size - 1);
    if (data[0] & 0x80)
        cluster_bytes(rest, data[0] & 2);
    else if (data[0] & 1)
        stream(rest);
    else
        one_payload(rest);
    return 0;
}
