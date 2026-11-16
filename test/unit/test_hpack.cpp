// HPACK and HTTP/2's frames. HPACK: RFC 7541's own examples decoded in sequence with the dynamic table they leave, the encoder's blocks read
// back, and what is not HPACK -- a bad index, a size update past the settings, wrong padding, EOS -- refused.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <chrono>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include "shared/http/h2_driver.h"
#include "shared/util/build_cost.h"
#include "shared/http/h2_frame.h"
#include "shared/http/hpack.h"

using namespace socketley::hpack;

namespace
{

#include "hpack_rfc7541_cases.inc"

std::string unhex(const char* h)
{
    std::string o;
    for (size_t i = 0; h[i] && h[i + 1]; i += 2)
        o += static_cast<char>(std::stoi(std::string(h + i, 2), nullptr, 16));
    return o;
}

decoder::result decode(decoder& d, const std::string& block, std::vector<header>& out, size_t max_list = 1 << 20)
{
    out.clear();
    return d.decode(block, out, max_list);
}

}   // namespace

TEST_CASE("RFC 7541 Appendix C decodes as the RFC says, the table carried from block to block")
{
    for (const auto& seq : rfc7541_cases)
    {
        decoder d(seq.table);
        INFO(seq.name);
        REQUIRE(!seq.blocks.empty());
        for (const auto& b : seq.blocks)
        {
            std::vector<header> got;
            REQUIRE(decode(d, unhex(b.hex), got) == decoder::result::ok);
            REQUIRE(got.size() == b.fields.size());
            for (size_t i = 0; i < got.size(); ++i)
            {
                CHECK(got[i].name == b.fields[i].first);
                CHECK(got[i].value == b.fields[i].second);
            }
        }
    }
    // C.3.3 leaves 164 octets in the table, C.5.3 (256 octets, so entries were evicted) 215.
    decoder d(4096);
    std::vector<header> got;
    for (const auto& b : rfc7541_cases[0].blocks)
        decode(d, unhex(b.hex), got);
    CHECK(d.table_size() == 164);
    decoder r(256);
    for (const auto& b : rfc7541_cases[2].blocks)
        decode(r, unhex(b.hex), got);
    CHECK(r.table_size() == 215);
}

TEST_CASE("a block of two-byte literals naming a large table entry costs its bytes, not a copy each")
{
    decoder d;
    // A literal with incremental indexing of a new 4,064-byte name, empty value: the table's entry 62.
    std::string first = "\x40";
    first += static_cast<char>(0x7f);
    first += "\xe1\x1e";   // 127 + 3,937 = 4,064, the name's length as an HPACK integer
    first += std::string(4064, 'x');
    first += '\0';
    std::vector<header> got;
    REQUIRE(decode(d, first, got) == decoder::result::ok);
    REQUIRE(got.size() == 1);
    // 0x7e 0x00: insert entry 62's name again with an empty value, which copied 4 KiB for every two bytes.
    std::string flood;
    for (int i = 0; i < 40000; ++i)
        flood += std::string("\x7e\x00", 2);
    const auto t0 = std::chrono::steady_clock::now();
    CHECK(decode(d, flood, got, 64 * 1024) == decoder::result::error);
    CHECK(std::chrono::steady_clock::now() - t0 < std::chrono::milliseconds(200 * build_cpu_factor));
    // The same without indexing (0x0f 0x2f), past the list's limit: counted, not copied.
    decoder e;
    REQUIRE(decode(e, first, got) == decoder::result::ok);
    std::string plain;
    for (int i = 0; i < 26000; ++i)
        plain += std::string("\x0f\x2f\x00", 3);
    const auto t1 = std::chrono::steady_clock::now();
    CHECK(decode(e, plain, got, 64 * 1024) == decoder::result::too_large);
    CHECK(std::chrono::steady_clock::now() - t1 < std::chrono::milliseconds(200 * build_cpu_factor));
    // A block inserting a few hundred, as a client might, still decodes.
    decoder f;
    std::string some;
    for (int i = 0; i < 300; ++i)
        some += "\x40\x01" + std::string(1, static_cast<char>('a' + i % 26)) + "\x01v";
    CHECK(decode(f, some, got) == decoder::result::ok);
}

TEST_CASE("what the encoder writes reads back, indexed where the static table has it")
{
    std::string block;
    encode(block, ":status", "200");
    CHECK(block == "\x88");
    encode(block, ":status", "206");
    encode(block, "content-type", "video/mp4");
    encode(block, "x-amz-request-id", "ABC123");
    encode(block, "content-length", std::string(300, '9'));
    decoder d;
    std::vector<header> got;
    REQUIRE(decode(d, block, got) == decoder::result::ok);
    REQUIRE(got.size() == 5);
    CHECK(got[1].value == "206");
    CHECK(got[2].name == "content-type");
    CHECK(got[2].value == "video/mp4");
    CHECK(got[3].name == "x-amz-request-id");
    CHECK(got[4].value.size() == 300);
    // Nothing was indexed, so the block stands on its own.
    CHECK(d.table_size() == 0);
}

TEST_CASE("Huffman strings: padding of at most seven ones, and no EOS")
{
    std::string out;
    // "www.example.com" from C.4.1.
    CHECK(huffman_decode(unhex("f1e3c2e5f23a6ba0ab90f4ff"), out));
    CHECK(out == "www.example.com");
    out.clear();
    CHECK(huffman_decode("", out));
    // Eight bits of padding.
    CHECK_FALSE(huffman_decode(std::string("\xff", 1), out));
    // EOS is thirty ones.
    CHECK_FALSE(huffman_decode(std::string("\xff\xff\xff\xfc", 4), out));
    // 'a' (00011) padded with zeros.
    CHECK_FALSE(huffman_decode(std::string("\x18", 1), out));
    out.clear();
    CHECK(huffman_decode(std::string("\x1f", 1), out));
    CHECK(out == "a");
}

TEST_CASE("what is not HPACK is refused, and a long list is told apart from a broken one")
{
    decoder d(4096);
    std::vector<header> got;
    // Index 0, and an index past both tables.
    CHECK(decode(d, std::string("\x80", 1), got) == decoder::result::error);
    CHECK(decode(d, std::string("\xbe", 1), got) == decoder::result::error);
    // A size update past the settings, and one after a field.
    CHECK(decode(d, std::string("\x3f\xe2\x1f", 3), got) == decoder::result::error);
    CHECK(decode(d, std::string("\x82\x20", 2), got) == decoder::result::error);
    // A string longer than the block.
    CHECK(decode(d, std::string("\x40\x05" "ab", 4), got) == decoder::result::error);
    // An integer that never ends.
    CHECK(decode(d, std::string("\xff\xff\xff\xff\xff\xff\xff", 7), got) == decoder::result::error);

    // A list past the limit is decoded whole, so a field it indexed is still there for the next block.
    std::string big;
    big += "\x40";
    big += "\x01x";
    big += "\x7f\x81\x01" + std::string(256, 'v');   // 7-bit prefix full: 127 + 129 = 256
    CHECK(decode(d, big, got, 100) == decoder::result::too_large);
    CHECK(got.empty());
    CHECK(decode(d, std::string("\xbe", 1), got) == decoder::result::ok);
    REQUIRE(got.size() == 1);
    CHECK(got[0].value.size() == 256);
}

TEST_CASE("random blocks are refused or read, never read past")
{
    std::mt19937 rng(3);
    for (int k = 0; k < 20000; ++k)
    {
        decoder d(1 + rng() % 4096);
        std::string b(1 + rng() % 200, '\0');
        for (auto& c : b)
            c = static_cast<char>(rng() & 0xff);
        std::vector<header> got;
        d.decode(b, got, 1 + rng() % 8192);
        CHECK(d.table_size() <= 4096);
    }
}

TEST_CASE("a frame's head is read as written, its reserved bit dropped")
{
    std::string o;
    socketley::h2::put_head(o, 0x123456, socketley::h2::HEADERS, socketley::h2::END_HEADERS, 0x7fffffff);
    REQUIRE(o.size() == socketley::h2::head_len);
    o[5] = static_cast<char>(o[5] | 0x80);
    const auto h = socketley::h2::parse_head(o.data());
    CHECK(h.len == 0x123456);
    CHECK(h.type == socketley::h2::HEADERS);
    CHECK(h.flags == socketley::h2::END_HEADERS);
    CHECK(h.sid == 0x7fffffff);
}

TEST_CASE("a header block larger than a frame is HEADERS and CONTINUATIONs, END_STREAM on the first, END_HEADERS on the last")
{
    namespace h2 = socketley::h2;
    std::string block(40000, 'b'), o;
    h2::put_header_block(o, 5, block, true, 16384);
    std::string back;
    size_t at = 0;
    int frames = 0;
    while (at < o.size())
    {
        const auto h = h2::parse_head(o.data() + at);
        CHECK(h.sid == 5);
        CHECK(h.type == (frames == 0 ? h2::HEADERS : h2::CONTINUATION));
        CHECK(bool(h.flags & h2::END_STREAM) == (frames == 0));
        back.append(o, at + h2::head_len, h.len);
        at += h2::head_len + h.len;
        ++frames;
        CHECK(bool(h.flags & h2::END_HEADERS) == (at == o.size()));
    }
    CHECK(frames == 3);
    CHECK(back == block);
    o.clear();
    h2::put_header_block(o, 1, "", false, 16384);
    CHECK(o.size() == h2::head_len);
}

TEST_CASE("padding and priority fields are taken off, and padding past the frame refused")
{
    namespace h2 = socketley::h2;
    h2::frame_head h;
    h.type  = h2::HEADERS;
    h.flags = h2::PADDED | h2::PRIORITY_F;
    std::string p = std::string(1, '\x03') + "PPPPP" + "block" + "zzz";
    std::string_view v = p;
    REQUIRE(h2::unpad(h, v));
    CHECK(v == "block");
    p = std::string(1, '\x09') + "abc";
    v = p;
    h.flags = h2::PADDED;
    CHECK_FALSE(h2::unpad(h, v));
    v = {};
    CHECK_FALSE(h2::unpad(h, v));
}

TEST_CASE("the frames a server writes")
{
    namespace h2 = socketley::h2;
    std::string o;
    h2::put_settings(o, {{h2::MAX_CONCURRENT_STREAMS, 128}, {h2::INITIAL_WINDOW_SIZE, 1 << 21}});
    auto h = h2::parse_head(o.data());
    CHECK(h.type == h2::SETTINGS);
    CHECK(h.len == 12);
    CHECK(h2::rd32(o.data() + 9 + 2) == 128);
    o.clear();
    h2::put_window_update(o, 3, 1000);
    CHECK(h2::rd32(o.data() + 9) == 1000);
    o.clear();
    h2::put_goaway(o, 7, h2::ENHANCE_YOUR_CALM);
    CHECK(h2::rd32(o.data() + 9) == 7);
    CHECK(h2::rd32(o.data() + 13) == h2::ENHANCE_YOUR_CALM);
    o.clear();
    h2::put_ping_ack(o, "12345678");
    h = h2::parse_head(o.data());
    CHECK((h.type == h2::PING && h.flags == h2::ACK && o.substr(9) == "12345678"));
}

TEST_CASE("Huffman strings: the table decoder says what the bit-by-bit definition says, for any bytes")
{
    // The definition: a bit at a time, a symbol wherever a code ends, padding of under eight ones at the end.
    auto reference = [](std::string_view in, std::string& out) {
        uint32_t code = 0;
        unsigned len  = 0;
        for (const char ch : in)
            for (int bit = 7; bit >= 0; --bit)
            {
                code = (code << 1) | ((static_cast<uint8_t>(ch) >> bit) & 1u);
                if (++len > 30)
                    return false;
                for (unsigned s = 0; s < 257; ++s)
                {
                    unsigned l = 0;
                    if (huffman_code(s, l) == code && l == len)
                    {
                        if (s == 256)
                            return false;
                        out += static_cast<char>(s);
                        code = 0;
                        len  = 0;
                        break;
                    }
                }
            }
        return len < 8 && code == (1u << len) - 1;
    };
    auto encode = [](std::string_view s) {
        std::string out;
        uint64_t acc = 0;
        unsigned nb  = 0;
        for (const char ch : s)
        {
            unsigned l = 0;
            const uint32_t c = huffman_code(static_cast<uint8_t>(ch), l);
            acc = (acc << l) | c;
            nb += l;
            while (nb >= 8) { out += static_cast<char>(acc >> (nb - 8)); nb -= 8; }
        }
        if (nb)
            out += static_cast<char>((acc << (8 - nb)) | ((1u << (8 - nb)) - 1));
        return out;
    };

    std::mt19937 rng(7541);
    for (int round = 0; round < 3000; ++round)
    {
        // Every byte value, through codes of every length from five to thirty.
        std::string plain;
        const int n = static_cast<int>(rng() % 64);
        for (int i = 0; i < n; ++i)
            plain += static_cast<char>(round % 3 == 0 ? rng() % 256 : 32 + rng() % 95);
        const std::string coded = encode(plain);
        std::string got;
        REQUIRE(huffman_decode(coded, got));
        CHECK(got == plain);

        // And bytes that are not a string at all, which both must refuse or read alike.
        std::string noise;
        const int m = static_cast<int>(rng() % 12);
        for (int i = 0; i < m; ++i)
            noise += static_cast<char>(rng() % 4 == 0 ? 0xff : rng() % 256);
        std::string a, b;
        const bool ra = huffman_decode(noise, a);
        const bool rb = reference(noise, b);
        CHECK(ra == rb);
        if (ra && rb)
            CHECK(a == b);
    }
}

namespace
{
namespace h2 = socketley::h2;

struct h2_node
{
    std::unique_ptr<h2::stream> h2s{new h2::stream};
};
}   // namespace

// Found by fuzz_h2_session under libFuzzer: a WINDOW_UPDATE on a stream, then SETTINGS INITIAL_WINDOW_SIZE 0x7fff0000.
TEST_CASE("a SETTINGS that would take one stream's window past 2^31-1 is refused whole, and moves nothing")
{
    using handle = std::shared_ptr<h2_node>;
    h2::session<handle> s;
    // One stream with a body waiting at the default window, one the client already widened by 0x01780000.
    auto quiet = std::make_shared<h2_node>();
    quiet->h2s->sid = 1;
    quiet->h2s->tx = "body";
    auto wide = std::make_shared<h2_node>();
    wide->h2s->sid = 3;
    wide->h2s->send_win = h2::default_window + 0x01780000;
    s.streams.emplace(1, quiet);
    s.streams.emplace(3, wide);

    std::string frame;
    h2::put_settings(frame, {{h2::MAX_FRAME_SIZE, 32768}, {h2::INITIAL_WINDOW_SIZE, 0x7fff0000u}});
    const h2::outcome got = h2::settings_in(s, std::string_view(frame).substr(h2::head_len));

    CHECK(got.kind == h2::outcome::what::conn_error);
    CHECK(got.code == h2::FLOW_CONTROL_ERROR);
    CHECK(wide->h2s->send_win == h2::default_window + 0x01780000);
    CHECK(quiet->h2s->send_win == h2::default_window);
    CHECK(s.rr.empty());
    CHECK(s.peer_init_win == h2::default_window);
    CHECK(s.peer_max_frame == h2::default_frame);
    CHECK(s.ctl.empty());
    CHECK_FALSE(s.got_settings);

    // The same frame with room on every stream is taken whole: both windows move, the waiting body is queued.
    wide->h2s->send_win = h2::default_window;
    const h2::outcome ok = h2::settings_in(s, std::string_view(frame).substr(h2::head_len));
    CHECK(ok.kind == h2::outcome::what::taken);
    CHECK(wide->h2s->send_win == 0x7fff0000);
    CHECK(quiet->h2s->send_win == 0x7fff0000);
    CHECK(s.rr.size() == 1);
    CHECK(s.peer_max_frame == 32768);
    CHECK(s.got_settings);
}

namespace
{
// A handle whose stream is reached through a state_of() of its own, so a test can count how often the driver walks.
struct counted_node
{
    std::unique_ptr<h2::stream> h2s{new h2::stream};
};
size_t walks = 0;
h2::stream& state_of(const std::shared_ptr<counted_node>& h)
{
    ++walks;
    return *h->h2s;
}
}   // namespace

// HAProxy's CVE-2026-49975 class: a frame cheap to send and dear to take.  A WINDOW_UPDATE of 1 on the connection walked
// every stream, 128 at the storage, so a flood of them cost 27 times the loop time of any other frame.
TEST_CASE("a WINDOW_UPDATE on the connection walks the streams only when the connection window was used up")
{
    using handle = std::shared_ptr<counted_node>;
    h2::session<handle> s;
    s.send_win = 0;
    for (uint32_t i = 0; i < 128; ++i)
    {
        auto n = std::make_shared<counted_node>();
        n->h2s->sid = 1 + 2 * i;
        n->h2s->tx = "body";
        s.streams.emplace(n->h2s->sid, n);
    }
    s.last_sid = 255;

    std::string frame;
    h2::put_window_update(frame, 0, 1);
    const std::string_view pl = std::string_view(frame).substr(h2::head_len);
    h2::frame_head h{};
    h.type = h2::WINDOW_UPDATE;
    h.len = 4;
    h.sid = 0;

    // The window was shut, so the first update lets every waiting stream go.
    walks = 0;
    CHECK(h2::window_update_in(s, h, pl).kind == h2::outcome::what::taken);
    CHECK(s.rr.size() == 128);
    CHECK(walks == 128);

    // While it stays open, ten thousand more walk nothing, and the window still grows by each.
    walks = 0;
    for (int i = 0; i < 10000; ++i)
        REQUIRE(h2::window_update_in(s, h, pl).kind == h2::outcome::what::taken);
    CHECK(walks == 0);
    CHECK(s.send_win == 10001);

    // Used up by a turn, it walks again on the next update, and the streams the turn left out are queued again.
    std::string out;
    h2::drain(s, out, 0, size_t(1) << 30, [](const handle&) {}, [](const handle&) {}, [](const handle&) {});
    CHECK(s.send_win == 10001 - 128 * 4);
    s.send_win = 0;
    for (auto& [sid, n] : s.streams)
    {
        n->h2s->tx = "more";
        n->h2s->tx_off = 0;
    }
    CHECK(s.rr.empty());
    walks = 0;
    CHECK(h2::window_update_in(s, h, pl).kind == h2::outcome::what::taken);
    CHECK(walks == 128);
    CHECK(s.rr.size() == 128);
}
