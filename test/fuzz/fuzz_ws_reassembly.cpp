// Fuzz target: WebSocket reassembly as two runtimes read it, against a model of RFC 6455 kept here.
//
//   * A server runtime (socketley/runtime/server/server_instance.cpp, the proto_ws arm of parse_partial()):
//     fragments compacted in place, control frames taken between them, a text message judged UTF-8 whole, the read
//     buffer's bound on what is held, and the Close it answers with.
//   * An mqtt runtime's WebSocket listener (socketley/runtime/mqtt/mqtt_run.cpp, ws_handshake() and ws_frames()):
//     the upgrade, then frames whose data payloads are one MQTT byte stream however they are cut, pings answered,
//     a Close answered, and an unfinished frame bounded by four of the largest packets.
//
// Reachable by anyone who can upgrade a connection to a server runtime's WebSocket, which is anyone who can reach
// it where no --origins or on_auth says otherwise, and by anyone who reaches an mqtt runtime's --ws-port: every frame
// is the client's.
//
// Each runtime's own code is driven on a connection with no socket, the bytes appended a read at a time. Nothing is
// sent: the connection is marked as having a write in flight, so what it queues stays queued, and what it queued is
// read back as the frames a client would get. fuzz_ws_frame covers the frame parser alone; this covers what is built
// from the frames.
//
// An input is: a byte for the size of a read, a byte for --read-buffer whose top bit chooses the mqtt runtime (and
// whose low bits its largest packet there), then a byte per frame naming its kind and a byte or two for its length:
//
//   kinds    a whole text or binary message, a first fragment, a middle or a last one, a ping, a pong, a close, four
//            kinds the RFC refuses (unmasked, a reserved opcode, a reserved bit, a text message that is not UTF-8),
//            a length past 16 MiB or with its top bit set, and (mqtt) a data frame of bytes that are no MQTT packet.
//   length   below 0xE0 itself; 0xE0-0xEF a short length written in the 16-bit (0xE0-0xE7) or the 64-bit (0xE8-0xEF)
//            form, which the RFC asks be minimal and neither runtime refuses; 0xF0 and up 126 + the next byte * 32,
//            in the 16-bit form below 0xF8 and the 64-bit form from it.
//   close    its length byte chooses the body: none, one byte, a code the RFC lets be sent or one it does not (1004,
//            1005, 1006, 1012, 2999, 5000), a reason in UTF-8 or not, or a code from the next two bytes.
//
// What must hold, beside no report from the sanitizers:
//
//   server   The messages handed on are the model's, in order, each the concatenation of its fragments, and no empty
//            one; control frames between fragments change none of them.  Where the model fails the connection or a
//            close ends it, the runtime closes it after exactly the messages before that frame, and the Close it
//            queues carries the model's code: the peer's own code echoed when that may be sent and its reason is
//            UTF-8, 1000 for an empty body, 1002 for a one-byte body, a code that may not be sent or a frame refused,
//            1007 for a reason or a text message that is not UTF-8.  Where nothing ends it, it stays open and has
//            handed on every message.  While open it holds no more than --read-buffer and the read in hand.
//   mqtt     The upgrade is answered 101.  What it queues after are whole frames: binary ones whose payloads are whole
//            MQTT packets, a pong per ping before the end with the ping's payload, in order, and a Close 1000 last
//            where the client sent one.  A frame refused ends the connection; a Close closes it; nothing else does
//            while the unfinished frame is within four of the largest packets.  Where the MQTT stream the data frames
//            carried is a CONNECT and PINGREQs, the broker answered a CONNACK and a PINGRESP per whole PINGREQ.

#include <string>
#include <string_view>
#include <vector>

#include <openssl/ssl.h>

#include "fuzz_common.h"

#include "shared/http/outbound_http.h"
#include "shared/ipc/request_channel.h"
#include "shared/loop/conn_alloc.h"
#include "shared/loop/event_loop.h"
#include "shared/loop/event_loop_definitions.h"
#include "shared/loop/file_io.h"
#include "shared/loop/hash_pool.h"
#include "shared/loop/ring_read.h"
#include "shared/loop/write_queue.h"
#include "shared/net/failure_bar.h"
#include "shared/runtime/retired_runs.h"
#include "shared/runtime/runtime_instance.h"
#include "shared/runtime/runtime_manager.h"
#include "shared/util/transparent_string.h"
#include "runtime/mqtt/mqtt_auth.h"
#include "runtime/mqtt/mqtt_broker.h"
#include "runtime/mqtt/mqtt_routes.h"

// Reaching inside the classes, as fuzz_server_ops does: parse_partial(), ws_frames() and the connections they read
// are private.
#define private public
#include "runtime/server/server_instance.h"
#include "runtime/mqtt/mqtt_instance.h"
#include "runtime/mqtt/mqtt_run.h"
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
                      k_unmasked, k_reserved_op, k_reserved_bit, k_bad_text, k_huge, k_junk, k_count };

// The length's form on the wire: as short as it can be, or the 16-bit or 64-bit one whatever the length.
enum class len_form : uint8_t { minimal, sixteen, sixty_four };

void frame(std::string& out, uint8_t b0, bool masked, std::string_view payload, len_form form = len_form::minimal)
{
    out.push_back(static_cast<char>(b0));
    const uint8_t m = masked ? 0x80 : 0;
    const size_t n = payload.size();
    if (form == len_form::sixty_four || n > 0xffff)
    {
        out.push_back(static_cast<char>(m | 127));
        for (int i = 7; i >= 0; --i)
            out.push_back(static_cast<char>((static_cast<uint64_t>(n) >> (8 * i)) & 0xff));
    }
    else if (form == len_form::sixteen || n >= 126)
    {
        out.push_back(static_cast<char>(m | 126));
        out.push_back(static_cast<char>(n >> 8));
        out.push_back(static_cast<char>(n & 0xff));
    }
    else
        out.push_back(static_cast<char>(m | n));
    const char key[4] = {0x11, 0x22, 0x44, static_cast<char>(0x88)};
    if (masked)
        out.append(key, 4);
    for (size_t i = 0; i < n; ++i)
        out.push_back(masked ? static_cast<char>(payload[i] ^ key[i % 4]) : payload[i]);
}

// A header naming a payload no runtime takes: past 16 MiB, or with the top bit the RFC keeps clear. The payload never
// follows; the header alone must end the connection.
void huge_frame(std::string& out, size_t pick)
{
    out.push_back(static_cast<char>(0x82));
    out.push_back(static_cast<char>(0x80 | 127));
    const uint64_t n = (pick & 1) ? (1ull << 63) | pick : (16ull << 20) + 1 + pick;
    for (int i = 7; i >= 0; --i)
        out.push_back(static_cast<char>((n >> (8 * i)) & 0xff));
    out.append("\x11\x22\x44\x88", 4);
}

// A Close's body, and the code RFC 6455 has the server answer it with -- the model's own reading of 5.5.1 and 7.4,
// not ws_protocol.h's.
struct close_body
{
    std::string payload;
    uint16_t answer;
};

close_body close_of(uint8_t pick, reader& r)
{
    auto code = [](uint16_t c, std::string_view reason = {}) {
        std::string s;
        s.push_back(static_cast<char>(c >> 8));
        s.push_back(static_cast<char>(c & 0xff));
        s.append(reason);
        return s;
    };
    auto sendable = [](uint16_t c) {
        return (c >= 1000 && c <= 1011 && c != 1004 && c != 1005 && c != 1006) || (c >= 3000 && c <= 4999);
    };
    switch (pick % 16)
    {
        case 0:  return {"", 1000};
        case 1:  return {"\x03", 1002};
        case 2:  return {code(1000), 1000};
        case 3:  return {code(1001), 1001};
        case 4:  return {code(1004), 1002};
        case 5:  return {code(1005), 1002};
        case 6:  return {code(1006), 1002};
        case 7:  return {code(1011, "over"), 1011};
        case 8:  return {code(1012), 1002};
        case 9:  return {code(2999), 1002};
        case 10: return {code(3000, "app"), 3000};
        case 11: return {code(4999), 4999};
        case 12: return {code(5000), 1002};
        case 13: return {code(1000, "bye \xe2\x9c\x93"), 1000};
        case 14: return {code(1001, "cut \xe2\x9c"), 1007};
        default:
        {
            // Two statements: in one expression the two reads may be taken in either order (GCC and clang differ).
            const uint8_t high = r.byte();
            const uint8_t low = r.byte();
            const uint16_t c = static_cast<uint16_t>(high << 8 | low);
            const bool bad_reason = c & 1;
            return {code(c, bad_reason ? "\xff" : "x"), !sendable(c) ? uint16_t(1002) : bad_reason ? uint16_t(1007) : c};
        }
    }
}

// What a runtime queued, read back as the server's frames a client would get: unmasked, each whole.
struct out_frame
{
    uint8_t b0;
    std::string payload;
};

bool read_frames(std::string_view in, std::vector<out_frame>& out)
{
    while (!in.empty())
    {
        if (in.size() < 2)
            return false;
        const uint8_t b0 = static_cast<uint8_t>(in[0]), b1 = static_cast<uint8_t>(in[1]);
        if (b1 & 0x80)
            return false;
        size_t at = 2, n = b1 & 0x7f;
        if (n == 126)
        {
            if (in.size() < 4)
                return false;
            n = static_cast<uint8_t>(in[2]) << 8 | static_cast<uint8_t>(in[3]);
            at = 4;
        }
        else if (n == 127)
        {
            if (in.size() < 10)
                return false;
            n = 0;
            for (int i = 0; i < 8; ++i)
                n = n << 8 | static_cast<uint8_t>(in[2 + i]);
            at = 10;
        }
        if (in.size() - at < n)
            return false;
        out.push_back({b0, std::string(in.substr(at, n))});
        in.remove_prefix(at + n);
    }
    return true;
}

// The length a kind's byte asks for, and its form.
size_t length_of(reader& r, len_form& form)
{
    size_t len = r.byte();
    form = len_form::minimal;
    if (len >= 0xF0)
    {
        form = len >= 0xF8 ? len_form::sixty_four : len_form::minimal;
        len = 126 + (static_cast<size_t>(r.byte()) << 5);
    }
    else if (len >= 0xE0)
    {
        form = len >= 0xE8 ? len_form::sixty_four : len_form::sixteen;
        len = (len & 7) * 17;
    }
    return len;
}

// ─── The server runtime ─────────────────────────────────────────────────────

int server_case(reader& r, size_t chunk, uint8_t cap_byte, event_loop* loop)
{
    static std::vector<std::string> got;
    g_got = &got;
    static server_instance* rt = [loop] {
        auto* s = new server_instance("fuzz-ws");
        // A loop, so that a pong is admitted as in a running server (admit_send() asks for one); it is never
        // polled, and nothing reaches it. It is the loop setup() would set, which is what start() calls.
        s->set_event_loop(loop);
        s->m_loop = loop;
        s->set_on_client_message([](int, std::string_view m) { g_got->emplace_back(m); });
        return s;
    }();
    got.clear();

    // --read-buffer has a floor of 64 KiB, so the bound is asked of the runtime rather than assumed.
    rt->set_read_buffer((64u << 10) * (1 + cap_byte % 3));
    const size_t cap = rt->get_read_buffer();

    // The frames, and what the model says comes of them.
    std::string wire;
    std::vector<std::string> want;
    bool open = false, ended = false;
    uint16_t answer = 0;
    std::string building;
    while (!r.done() && wire.size() < (256u << 10))
    {
        const uint8_t k = r.byte() % (k_count - 1);   // no k_junk: a server has no protocol inside its messages
        len_form form;
        const uint8_t len_byte = r.at < r.n ? r.p[r.at] : 0;
        size_t len = length_of(r, form);
        const bool control = k == k_ping || k == k_pong || k == k_close;
        if (control)
            len = std::min<size_t>(len, 125);
        std::string payload;
        for (size_t i = 0; i < len; ++i)
            payload.push_back(static_cast<char>('a' + (i + r.at) % 26));
        if (k == k_bad_text)
            payload += '\xff';
        bool fail = false;
        switch (k)
        {
            case k_text: case k_binary: case k_bad_text:
                frame(wire, 0x80 | (k == k_binary ? 2 : 1), true, payload, form);
                fail = open || k == k_bad_text;
                answer = open ? 1002 : 1007;
                if (!fail && !payload.empty())
                    want.push_back(payload);
                break;
            case k_first_text: case k_first_binary:
                frame(wire, k == k_first_text ? 1 : 2, true, payload, form);
                fail = open;
                answer = 1002;
                open = true;
                building = payload;
                break;
            case k_middle: case k_last:
                frame(wire, k == k_last ? 0x80 : 0x00, true, payload, form);
                fail = !open;
                answer = 1002;
                building += payload;
                if (!fail && k == k_last)
                {
                    open = false;
                    if (!building.empty())
                        want.push_back(building);
                }
                break;
            case k_ping: frame(wire, 0x89, true, payload, form); break;
            case k_pong: frame(wire, 0x8A, true, payload, form); break;
            case k_close:
            {
                const close_body c = close_of(len_byte, r);
                frame(wire, 0x88, true, c.payload, form);
                answer = c.answer;
                ended = true;
                break;
            }
            case k_unmasked: frame(wire, 0x82, false, payload, form); fail = true; answer = 1002; break;
            case k_reserved_op: frame(wire, 0x83, true, payload, form); fail = true; answer = 1002; break;
            case k_huge: huge_frame(wire, len); fail = true; answer = 1002; break;
            default: frame(wire, 0xC2, true, payload, form); fail = true; answer = 1002; break;
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

        // What was queued: pongs and, where it ended, one Close with the model's code.
        std::vector<out_frame> sent;
        bool whole = true;
        while (!conn->write_queue.empty())
        {
            const auto piece = conn->write_queue.take_front();
            whole &= read_frames(piece.view(), sent);
        }
        FUZZ_CHECK(whole, "what the server queued is not whole frames");
        size_t closes = 0;
        uint16_t code = 0;
        for (const auto& f : sent)
            if ((f.b0 & 0x0f) == 0x8)
            {
                ++closes;
                code = f.payload.size() >= 2
                    ? static_cast<uint16_t>(static_cast<uint8_t>(f.payload[0]) << 8 | static_cast<uint8_t>(f.payload[1]))
                    : 0;
            }
        if (ended)
        {
            if (closes != 1 || code != answer)
                std::fprintf(stderr, "closes %zu, code %u, model %u\n", closes, code, answer);
            FUZZ_CHECK(closes == 1 && code == answer, "the Close the server answered with is not the model's");
        }
        else
            FUZZ_CHECK(closes == 0, "a Close queued on a conversation the frames did not end");
    }
    return 0;
}

// ─── The mqtt runtime's WebSocket listener ──────────────────────────────────

using socketley::mqtt::mqtt_run;

int mqtt_case(reader& r, size_t chunk, uint8_t cap_byte, event_loop* loop)
{
    static mqtt_instance* owner = [] {
        auto* o = new mqtt_instance("fuzz-mqtt-ws");
        o->set_anonymous(true);
        return o;
    }();
    static mqtt_run* run = [loop] {
        auto* m = new mqtt_run(*owner, *loop);
        // What start() builds and this needs, without the listeners, the files and the ticks: the broker alone.
        socketley::mqtt::broker_config cfg;
        cfg.max_packet = 1u << 20;
        m->m_broker = std::make_unique<socketley::mqtt::broker>(cfg, *m, *m);
        return m;
    }();
    static uint64_t next_id = 1;
    // The unfinished frame is bounded by four of the largest packets; a small largest packet reaches the bound.
    owner->set_max_packet(1024u * (1 + (cap_byte & 0x3f)));
    const size_t bound = static_cast<size_t>(owner->get_max_packet()) * 4 + 14;

    // The MQTT stream the data frames carry, cut wherever their lengths fall: a CONNECT (3.1.1, clean, client "f"),
    // then PINGREQs for as long as frames take bytes.
    static const std::string connect("\x10\x0d\x00\x04MQTT\x04\x02\x00\x3c\x00\x01" "f", 15);
    size_t stream_at = 0;
    std::string delivered;
    bool junk = false;
    auto take_stream = [&](size_t n) {
        std::string s;
        for (size_t i = 0; i < n; ++i, ++stream_at)
            s.push_back(stream_at < connect.size() ? connect[stream_at]
                                                   : ((stream_at - connect.size()) % 2 ? '\x00' : '\xc0'));
        return s;
    };

    std::string wire = "GET /mqtt HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                       "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
                       "Sec-WebSocket-Protocol: mqtt\r\n\r\n";
    const size_t head = wire.size();
    std::vector<std::string> pings;
    // What the model says: the connection refused by a frame (dead), closed by a Close, or neither.
    bool refused = false, closed = false;
    while (!r.done() && wire.size() < (256u << 10))
    {
        const uint8_t k = r.byte() % k_count;
        len_form form;
        const uint8_t len_byte = r.at < r.n ? r.p[r.at] : 0;
        size_t len = length_of(r, form);
        const bool control = k == k_ping || k == k_pong || k == k_close;
        if (control)
            len = std::min<size_t>(len, 125);
        bool end = false;
        switch (k)
        {
            case k_text: case k_binary: case k_first_text: case k_first_binary: case k_middle: case k_last:
            {
                // MQTT frames itself, so every data opcode carries the stream, fragmented or not.
                static const uint8_t b0s[] = {0x81, 0x82, 0x01, 0x02, 0x00, 0x80};
                const std::string piece = take_stream(len);
                frame(wire, b0s[k], true, piece, form);
                delivered += piece;
                break;
            }
            case k_bad_text: case k_junk:
            {
                // Bytes that are no MQTT packet; what the broker makes of them is its own business.
                std::string piece;
                for (size_t i = 0; i < len && !r.done(); ++i)
                    piece.push_back(static_cast<char>(r.byte()));
                frame(wire, 0x82, true, piece, form);
                delivered += piece;
                junk = true;
                break;
            }
            case k_ping:
            {
                std::string payload;
                for (size_t i = 0; i < len; ++i)
                    payload.push_back(static_cast<char>('A' + (i + r.at) % 26));
                frame(wire, 0x89, true, payload, form);
                pings.push_back(payload);
                break;
            }
            case k_pong: frame(wire, 0x8A, true, std::string(len, 'p'), form); break;
            case k_close:
                frame(wire, 0x88, true, close_of(len_byte, r).payload, form);
                closed = end = true;
                break;
            case k_unmasked: frame(wire, 0x82, false, take_stream(len), form); refused = end = true; break;
            case k_reserved_op: frame(wire, 0x83, true, std::string(len, 'r'), form); refused = end = true; break;
            case k_reserved_bit: frame(wire, 0xC2, true, std::string(len, 'r'), form); refused = end = true; break;
            default: huge_frame(wire, len); refused = end = true; break;
        }
        if (end)
            break;
    }

    auto owned = std::make_unique<mqtt_run::conn>();
    mqtt_run::conn& c = *owned;
    c.id = next_id++;
    c.fd = -1;
    c.ws = true;
    // A write in flight, so what is queued stays queued and is read back below.
    c.wr_pending = true;
    run->m_conns.emplace(c.id, std::move(owned));

    bool overflowed = false;
    for (size_t at = 0; at < wire.size() && !c.dead; at += chunk)
    {
        const size_t n = std::min(chunk, wire.size() - at);
        run->plain_in(c, wire.data() + at, n);
        if (c.dead)
        {
            // Dead before its frames ended it only past the bound on an unfinished frame.
            overflowed = !refused || at + n < wire.size();
            break;
        }
        FUZZ_CHECK(c.ws_in.size() <= bound, "an unfinished frame held past four of the largest packets");
    }
    // A frame refused ends it by the bound if the bound came first; either way it is dead.
    if (refused)
        FUZZ_CHECK(c.dead, "a frame the RFC refuses left the connection up");
    else if (!overflowed)
    {
        FUZZ_CHECK(!c.dead, "a conversation no frame refused was ended");
        FUZZ_CHECK(c.ws_open, "a well-formed upgrade was not taken");
        FUZZ_CHECK(c.closing == closed || (!closed && junk), "a Close was not answered by closing, or one came unasked");
        if (closed)
            FUZZ_CHECK(c.ws_in.empty(), "frames after a Close were kept");
    }

    // What was queued, read back: the 101, then frames.
    std::string out;
    for (const auto& w : c.queue)
        out.append(w.view());
    if (c.ws_open)
    {
        FUZZ_CHECK(out.starts_with("HTTP/1.1 101 Switching Protocols\r\n"), "the upgrade was not answered 101");
        const size_t body = out.find("\r\n\r\n");
        FUZZ_CHECK(body != std::string::npos, "the 101 has no end");
        std::vector<out_frame> sent;
        FUZZ_CHECK(read_frames(std::string_view(out).substr(body + 4), sent), "what the runtime queued is not whole frames");
        std::string mqtt_out;
        std::vector<std::string> pongs;
        size_t closes = 0;
        for (size_t i = 0; i < sent.size(); ++i)
        {
            const uint8_t op = sent[i].b0 & 0x0f;
            FUZZ_CHECK(sent[i].b0 & 0x80, "a fragment sent");
            FUZZ_CHECK(op == 0x2 || op == 0x8 || op == 0xA, "a frame of a kind the runtime does not send");
            if (op == 0x2)
                mqtt_out += sent[i].payload;
            else if (op == 0xA)
                pongs.push_back(sent[i].payload);
            else
            {
                ++closes;
                FUZZ_CHECK(i + 1 == sent.size(), "a frame queued behind the Close");
                FUZZ_CHECK(sent[i].payload == std::string("\x03\xe8", 2), "the Close is not 1000");
            }
        }
        if (!overflowed && !refused)
        {
            FUZZ_CHECK(closes == (closed ? 1u : 0u), "a Close was not answered, or one came unasked");
            FUZZ_CHECK(pongs == pings, "the pongs are not the pings' payloads in order");
        }
        else
            FUZZ_CHECK(pongs.size() <= pings.size() &&
                           std::equal(pongs.begin(), pongs.end(), pings.begin()),
                       "a pong no ping asked for, or out of order");
        // The broker's packets, whole: a fixed header and a remaining length each, nothing cut.
        std::string_view rest = mqtt_out;
        while (!rest.empty())
        {
            size_t len = 0, at = 1, shift = 0;
            bool more = true;
            while (more && at < rest.size() && at <= 4)
            {
                const uint8_t b = static_cast<uint8_t>(rest[at++]);
                len |= static_cast<size_t>(b & 0x7f) << shift;
                shift += 7;
                more = b & 0x80;
            }
            FUZZ_CHECK(!more && rest.size() - at >= len, "an MQTT packet sent cut short");
            rest.remove_prefix(at + len);
        }
        // A CONNECT and PINGREQs, delivered before the end: a CONNACK and a PINGRESP per whole PINGREQ after it.
        if (!junk && !overflowed && delivered.size() >= connect.size())
        {
            const size_t pingreqs = (delivered.size() - connect.size()) / 2;
            std::string want("\x20\x02\x00\x00", 4);
            for (size_t i = 0; i < pingreqs; ++i)
                want.append("\xd0\x00", 2);
            if (mqtt_out != want)
                std::fprintf(stderr, "mqtt out %zu bytes, want %zu (%zu PINGREQs)\n", mqtt_out.size(), want.size(),
                             pingreqs);
            FUZZ_CHECK(mqtt_out == want, "the broker's answers are not a CONNACK and a PINGRESP per PINGREQ");
        }
        else if (!junk && !overflowed)
            FUZZ_CHECK(mqtt_out.empty(), "an answer before a whole CONNECT");
    }
    (void)head;

    // Gone, as a read's end would leave it, and nothing of it kept for the next input.
    run->close_conn(c);
    run->m_closing.clear();
    run->m_close_soon.clear();
    run->m_last_conn = nullptr;
    return 0;
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
    reader r{data, size};
    const size_t chunk = 1 + (r.byte() * 67u) % server_connection::READ_BUF_SIZE;
    const uint8_t cap_byte = r.byte();
    if (cap_byte & 0x80)
        return mqtt_case(r, chunk, cap_byte, loop);
    return server_case(r, chunk, cap_byte, loop);
}
