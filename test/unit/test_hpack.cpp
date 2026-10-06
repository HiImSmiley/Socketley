// HPACK and HTTP/2's frames. HPACK: RFC 7541's own examples decoded in sequence with the dynamic table they leave, the encoder's blocks read
// back, and what is not HPACK -- a bad index, a size update past the settings, wrong padding, EOS -- refused.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <random>
#include <string>
#include <vector>

#include "shared/h2_frame.h"
#include "shared/hpack.h"

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
