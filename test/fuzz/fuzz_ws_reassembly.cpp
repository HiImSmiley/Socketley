// Fuzz target: a server runtime's WebSocket reassembly (socketley/runtime/server/server_instance.cpp, the proto_ws
// arm of parse_partial()): fragments compacted in place, control frames taken between them, a text message judged
// UTF-8 whole, and the read buffer's bound on what is held.
//
// Reachable by anyone who can upgrade a connection to a server runtime's WebSocket, which is anyone who can reach
// it where no --origins or on_auth says otherwise: every frame is the client's.
//
// The runtime's own parse_partial() is driven on a connection with no socket, the bytes appended a read at a time
// and the read buffer's bound applied as handle_read applies it. Nothing is sent: the connection is marked as
// having a write in flight, so what it queues stays queued. fuzz_ws_frame covers the frame parser alone; this
// covers what is built from the frames.
//
// An input is: a byte for the size of a read, a byte for --read-buffer, then a byte per frame naming its kind
// (a whole text or binary message, a first fragment, a middle or a last one, a ping, a pong, a close, and four kinds
// the RFC refuses: unmasked, a reserved opcode, a reserved bit, a text message that is not UTF-8) and a byte or two
// for its length, its payload taken from the input.
//
// What must hold, beside no report from the sanitizers, against a model of RFC 6455 kept here:
//
//   * The messages the runtime hands on are the model's, in order, each the concatenation of its fragments, and no
//     empty one; control frames between fragments change none of them.
//   * Where the model fails the connection (a frame refused, a continuation with no message open, a message begun
//     inside another, text that is not UTF-8) or a close ends it, the runtime closes it after exactly the messages
//     before that frame; where nothing ends it, it stays open and has handed on every message.
//   * While the connection is open, it holds no more than --read-buffer and the read in hand; past that it is
//     closed and hands on only messages the model has, in order.

#include <string>
#include <string_view>
#include <vector>

#include "fuzz_common.h"

#include "shared/loop/event_loop.h"
#include "shared/loop/event_loop_definitions.h"
#include "shared/runtime/runtime_instance.h"
#include "shared/runtime/runtime_manager.h"
#include "shared/loop/conn_alloc.h"
#include "shared/loop/write_queue.h"

// Reaching inside the class, as fuzz_server_ops does: parse_partial() and the connection it reads are private.
#define private public
#include "runtime/server/server_instance.h"
#undef private

namespace
{

std::vector<std::string>* g_got = nullptr;

struct reader
{
    const uint8_t* p;
    size_t n, at{0};
    uint8_t byte() { return at < n ? p[at++] : 0; }
    bool done() const { return at >= n; }
};

enum kind : uint8_t { k_text, k_binary, k_first_text, k_first_binary, k_middle, k_last, k_ping, k_pong, k_close,
                      k_unmasked, k_reserved_op, k_reserved_bit, k_bad_text, k_count };

void frame(std::string& out, uint8_t b0, bool masked, std::string_view payload)
{
    out.push_back(static_cast<char>(b0));
    const uint8_t m = masked ? 0x80 : 0;
    if (payload.size() < 126)
        out.push_back(static_cast<char>(m | payload.size()));
    else
    {
        out.push_back(static_cast<char>(m | 126));
        out.push_back(static_cast<char>(payload.size() >> 8));
        out.push_back(static_cast<char>(payload.size() & 0xff));
    }
    const char key[4] = {0x11, 0x22, 0x44, static_cast<char>(0x88)};
    if (masked)
        out.append(key, 4);
    for (size_t i = 0; i < payload.size(); ++i)
        out.push_back(masked ? static_cast<char>(payload[i] ^ key[i % 4]) : payload[i]);
}

}   // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    fuzz::set_current(data, size);
    if (size < 3 || size > (64u << 10))
        return 0;
    static event_loop* loop = [] {
        auto* l = new event_loop(64);
        if (!l->init())
            std::abort();
        return l;
    }();
    static std::vector<std::string> got;
    g_got = &got;
    static server_instance* rt = [] {
        auto* s = new server_instance("fuzz-ws");
        // A loop, so that a pong is admitted as in a running server (admit_send() asks for one); it is never
        // polled, and nothing reaches it. It is the loop setup() would set, which is what start() calls.
        s->set_event_loop(loop);
        s->m_loop = loop;
        s->set_on_client_message([](int, std::string_view m) { g_got->emplace_back(m); });
        return s;
    }();
    got.clear();

    reader r{data, size};
    const size_t chunk = 1 + (r.byte() * 67u) % server_connection::READ_BUF_SIZE;
    // --read-buffer has a floor of 64 KiB, so the bound is asked of the runtime rather than assumed.
    rt->set_read_buffer((64u << 10) * (1 + r.byte() % 3));
    const size_t cap = rt->get_read_buffer();

    // The frames, and what the model says comes of them.
    std::string wire;
    std::vector<std::string> want;
    bool open = false, ended = false;
    std::string building;
    while (!r.done() && wire.size() < (256u << 10))
    {
        const uint8_t k = r.byte() % k_count;
        size_t len = r.byte();
        if (len >= 0xF0)
            len = 126 + (static_cast<size_t>(r.byte()) << 5);
        const bool control = k == k_ping || k == k_pong || k == k_close;
        if (control)
            len = std::min<size_t>(len, 125);
        std::string payload;
        for (size_t i = 0; i < len; ++i)
            payload.push_back(static_cast<char>('a' + (i + r.at) % 26));
        if (k == k_close)
            payload = len >= 2 ? std::string("\x03\xe8", 2) : std::string();
        if (k == k_bad_text)
            payload += '\xff';
        bool fail = false;
        switch (k)
        {
            case k_text: case k_binary: case k_bad_text:
                frame(wire, 0x80 | (k == k_binary ? 2 : 1), true, payload);
                fail = open || k == k_bad_text;
                if (!fail && !payload.empty())
                    want.push_back(payload);
                break;
            case k_first_text: case k_first_binary:
                frame(wire, k == k_first_text ? 1 : 2, true, payload);
                fail = open;
                open = true;
                building = payload;
                break;
            case k_middle: case k_last:
                frame(wire, k == k_last ? 0x80 : 0x00, true, payload);
                fail = !open;
                building += payload;
                if (!fail && k == k_last)
                {
                    open = false;
                    if (!building.empty())
                        want.push_back(building);
                }
                break;
            case k_ping: frame(wire, 0x89, true, payload); break;
            case k_pong: frame(wire, 0x8A, true, payload); break;
            case k_close: frame(wire, 0x88, true, payload); ended = true; break;
            case k_unmasked: frame(wire, 0x82, false, payload); fail = true; break;
            case k_reserved_op: frame(wire, 0x83, true, payload); fail = true; break;
            default: frame(wire, 0xC2, true, payload); fail = true; break;
        }
        if (fail || ended)
        {
            ended = true;
            break;
        }
    }

    auto conn = socketley::make_connection<server_connection>();
    conn->fd = -1;
    conn->proto = proto_ws;
    conn->write_pending = true;
    bool overflowed = false;
    for (size_t at = 0; at < wire.size() && !conn->closing; at += chunk)
    {
        const size_t n = std::min(chunk, wire.size() - at);
        conn->partial.append(wire, at, n);
        conn->read_arrived = static_cast<uint32_t>(n);
        if (rt->read_overflows(conn->partial.size(), conn->read_arrived))
        {
            overflowed = true;
            conn->closing = true;
            break;
        }
        rt->parse_partial(conn.get());
        if (!conn->closing)
            FUZZ_CHECK(conn->partial.size() <= cap + n, "an open connection holds more than its read buffer and a read");
    }

    FUZZ_CHECK(got.size() <= want.size(), "a message handed on that the frames did not make");
    for (size_t i = 0; i < got.size(); ++i)
    {
        if (got[i] != want[i])
            std::fprintf(stderr, "message %zu: got %zu bytes, want %zu\n", i, got[i].size(), want[i].size());
        FUZZ_CHECK(got[i] == want[i], "a message handed on is not the one its frames made");
    }
    if (!overflowed)
    {
        if (ended)
            FUZZ_CHECK(conn->closing, "a frame that ends the conversation left the connection open");
        else
            FUZZ_CHECK(!conn->closing, "a conversation the frames did not end was closed");
        FUZZ_CHECK(got.size() == want.size(), "a message the frames made was not handed on");
    }
    return 0;
}
