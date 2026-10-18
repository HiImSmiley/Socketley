// The cache's mutation journal: what is appended is what a replay hands back, whatever its length.
//
// A record longer than the replay would read was written whole and then taken for damage: the replay stopped at it,
// and the next open cut it and every record after it off the file. A runtime with a --read-buffer above that length
// took such a command and lost what followed it at the next start.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <string>
#include <unistd.h>
#include <vector>

#include "shared/persist/mutation_journal.h"

namespace
{

std::string temp_path()
{
    static int n = 0;
    return "/tmp/skl-mutation-journal-" + std::to_string(::getpid()) + "-" + std::to_string(++n);
}

}   // namespace

TEST_CASE("a record longer than 64 MiB is replayed, and so is every record after it")
{
    const std::string p = temp_path();
    const std::string big(70u << 20, 'v');
    {
        mutation_journal j;
        REQUIRE(j.open_append(p, "owner"));
        j.append("set a 1");
        j.append(big);
        j.append("set b 2");
        REQUIRE(j.flush());
    }
    std::vector<size_t> sizes;
    std::string last;
    mutation_journal::replay_stats st;
    REQUIRE(mutation_journal::replay(p, [&](std::string_view r) { sizes.push_back(r.size()); last.assign(r); }, st));
    CHECK(st.records == 3);
    REQUIRE(sizes.size() == 3);
    CHECK(sizes[1] == big.size());
    CHECK(last == "set b 2");
    CHECK_FALSE(st.torn);
    ::unlink(p.c_str());
}

TEST_CASE("a record whose bytes do not match its checksum still ends the replay")
{
    const std::string p = temp_path();
    {
        mutation_journal j;
        REQUIRE(j.open_append(p, "owner"));
        j.append("set a 1");
        j.append("set b 2");
        REQUIRE(j.flush());
    }
    // The last byte of the file belongs to the second record.
    FILE* f = std::fopen(p.c_str(), "r+b");
    REQUIRE(f);
    std::fseek(f, -1, SEEK_END);
    std::fputc('X', f);
    std::fclose(f);
    std::vector<std::string> got;
    mutation_journal::replay_stats st;
    REQUIRE(mutation_journal::replay(p, [&](std::string_view r) { got.emplace_back(r); }, st));
    REQUIRE(got.size() == 1);
    CHECK(got[0] == "set a 1");
    ::unlink(p.c_str());
}

TEST_CASE("the record checksum is CRC-32 at every length and alignment")
{
    // The bitwise definition the table form must agree with, so a slip in the eight-byte fold shows here and not as a journal the next build cannot replay.
    auto bitwise = [](std::string_view s) {
        uint32_t c = 0xFFFFFFFFu;
        for (const unsigned char b : s)
        {
            c ^= b;
            for (int k = 0; k < 8; ++k)
                c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        }
        return c ^ 0xFFFFFFFFu;
    };
    CHECK(socketley::crc::crc32("123456789") == 0xCBF43926u);
    std::string buf;
    uint32_t    x = 0x12345678u;
    for (int i = 0; i < 300; ++i)
    {
        x = x * 1664525u + 1013904223u;
        buf.push_back(static_cast<char>(x >> 24));
    }
    for (size_t off = 0; off < 8; ++off)
        for (size_t len = 0; len + off <= 140; ++len)
            CHECK(socketley::crc::crc32(std::string_view(buf).substr(off, len))
                  == bitwise(std::string_view(buf).substr(off, len)));
}
