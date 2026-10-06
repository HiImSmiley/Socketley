// HPACK: RFC 7541's own examples decoded in sequence with the dynamic table they leave, the encoder's blocks read
// back, and what is not HPACK -- a bad index, a size update past the settings, wrong padding, EOS -- refused.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <random>
#include <string>
#include <vector>

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
