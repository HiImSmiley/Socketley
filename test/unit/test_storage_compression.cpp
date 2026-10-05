// The LZ4 block codec and the compressed body's chunks: round trips, refusals of what is not a block, the format
// read by the system's liblz4 and liblz4's read by ours, and the record and table a compressed object keeps.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <cstring>
#include <random>
#include <string>

#include <dlfcn.h>

#include "runtime/storage/compression.h"
#include "runtime/storage/lz4_block.h"

using namespace socketley::storage;

namespace
{

std::string round_trip(const std::string& in)
{
    std::string packed(lz4_bound(in.size()), '\0');
    packed.resize(lz4_compress(reinterpret_cast<const uint8_t*>(in.data()), in.size(),
                               reinterpret_cast<uint8_t*>(packed.data())));
    std::string out(in.size(), '\0');
    const long n = lz4_decompress(reinterpret_cast<const uint8_t*>(packed.data()), packed.size(),
                                  reinterpret_cast<uint8_t*>(out.data()), out.size());
    if (n < 0)
        return "<refused>";
    out.resize(static_cast<size_t>(n));
    return out;
}

std::string random_bytes(size_t n, uint32_t seed)
{
    std::mt19937 g(seed);
    std::string s(n, '\0');
    for (char& c : s)
        c = static_cast<char>(g());
    return s;
}

std::string text(size_t n)
{
    std::string s;
    for (size_t i = 0; s.size() < n; ++i)
        s += "{\"id\":" + std::to_string(i) + ",\"name\":\"item\",\"tags\":[\"a\",\"b\"]}\n";
    s.resize(n);
    return s;
}

// The system's liblz4, when it is installed, to read and write the format with another implementation.
struct system_lz4
{
    using compress_fn   = int (*)(const char*, char*, int, int);
    using decompress_fn = int (*)(const char*, char*, int, int);
    void*         lib{dlopen("liblz4.so.1", RTLD_NOW)};
    compress_fn   compress{lib ? reinterpret_cast<compress_fn>(dlsym(lib, "LZ4_compress_default")) : nullptr};
    decompress_fn decompress{lib ? reinterpret_cast<decompress_fn>(dlsym(lib, "LZ4_decompress_safe")) : nullptr};
    ~system_lz4()
    {
        if (lib)
            dlclose(lib);
    }
};

}   // namespace

TEST_CASE("blocks round-trip whatever their bytes")
{
    for (const std::string& s : {std::string(), std::string("a"), std::string(12, 'x'), std::string(13, 'x'),
                                 std::string("abcabcabcabcabcabcabcabc"), std::string(70000, 'z'),
                                 random_bytes(65536, 1), text(65536), text(200000) + random_bytes(5000, 2)})
        CHECK(round_trip(s) == s);
    // A repeat 60000 bytes back, near the farthest an offset reaches.
    const std::string far = random_bytes(60000, 3);
    CHECK(round_trip(far + far + far) == far + far + far);
}

TEST_CASE("text gets much shorter and noise no longer than its bound")
{
    const std::string t = text(65536);
    std::string packed(lz4_bound(t.size()), '\0');
    CHECK(lz4_compress(reinterpret_cast<const uint8_t*>(t.data()), t.size(),
                       reinterpret_cast<uint8_t*>(packed.data())) < t.size() / 3);
    const std::string r = random_bytes(65536, 4);
    std::string rp(lz4_bound(r.size()), '\0');
    CHECK(lz4_compress(reinterpret_cast<const uint8_t*>(r.data()), r.size(), reinterpret_cast<uint8_t*>(rp.data())) <=
          lz4_bound(r.size()));
}

TEST_CASE("a block made by hand to the format's description opens")
{
    // Three literals, a match of nine at offset three, then five literals that end the block.
    const uint8_t block[] = {0x35, 'a', 'b', 'c', 0x03, 0x00, 0x50, 'a', 'b', 'c', 'd', 'e'};
    char out[32];
    const long n = lz4_decompress(block, sizeof block, reinterpret_cast<uint8_t*>(out), sizeof out);
    REQUIRE(n == 17);
    CHECK(std::string(out, 17) == "abcabcabcabcabcde");
}

TEST_CASE("what is not a block, or does not fit, is refused rather than read past")
{
    const std::string t = text(20000);
    std::string packed(lz4_bound(t.size()), '\0');
    packed.resize(lz4_compress(reinterpret_cast<const uint8_t*>(t.data()), t.size(),
                               reinterpret_cast<uint8_t*>(packed.data())));
    std::string out(t.size(), '\0');
    // Every cut opens to less than the whole, or not at all.
    for (size_t cut = 0; cut + 1 < packed.size(); ++cut)
    {
        const long n = lz4_decompress(reinterpret_cast<const uint8_t*>(packed.data()), cut,
                                      reinterpret_cast<uint8_t*>(out.data()), out.size());
        CHECK(n != static_cast<long>(t.size()));
    }
    CHECK(lz4_decompress(reinterpret_cast<const uint8_t*>(packed.data()), packed.size(),
                         reinterpret_cast<uint8_t*>(out.data()), t.size() - 1) == -1);
    const uint8_t zero_offset[] = {0x10, 'a', 0x00, 0x00, 0x50, 'a', 'b', 'c', 'd', 'e'};
    const uint8_t before_start[] = {0x10, 'a', 0x05, 0x00, 0x50, 'a', 'b', 'c', 'd', 'e'};
    const uint8_t long_literals[] = {0xF0, 0xFF, 0xFF};
    char small[64];
    CHECK(lz4_decompress(zero_offset, sizeof zero_offset, reinterpret_cast<uint8_t*>(small), sizeof small) == -1);
    CHECK(lz4_decompress(before_start, sizeof before_start, reinterpret_cast<uint8_t*>(small), sizeof small) == -1);
    CHECK(lz4_decompress(long_literals, sizeof long_literals, reinterpret_cast<uint8_t*>(small), sizeof small) == -1);
}

TEST_CASE("the system's liblz4 reads our blocks and we read its")
{
    system_lz4 sys;
    if (!sys.compress || !sys.decompress)
    {
        MESSAGE("liblz4.so.1 is not installed; the format is checked against the hand-made block alone");
        return;
    }
    for (const std::string& s : {text(65536), random_bytes(65536, 5), std::string(65536, 'q'), text(1000) +
                                 random_bytes(3000, 6) + text(60000)})
    {
        std::string ours(lz4_bound(s.size()), '\0');
        ours.resize(lz4_compress(reinterpret_cast<const uint8_t*>(s.data()), s.size(),
                                 reinterpret_cast<uint8_t*>(ours.data())));
        std::string back(s.size(), '\0');
        CHECK(sys.decompress(ours.data(), back.data(), static_cast<int>(ours.size()), static_cast<int>(back.size())) ==
              static_cast<int>(s.size()));
        CHECK(back == s);

        std::string theirs(lz4_bound(s.size()) + 64, '\0');
        const int tn = sys.compress(s.data(), theirs.data(), static_cast<int>(s.size()), static_cast<int>(theirs.size()));
        REQUIRE(tn > 0);
        std::string mine(s.size(), '\0');
        CHECK(lz4_decompress(reinterpret_cast<const uint8_t*>(theirs.data()), static_cast<size_t>(tn),
                             reinterpret_cast<uint8_t*>(mine.data()), mine.size()) == static_cast<long>(s.size()));
        CHECK(mine == s);
    }
}

TEST_CASE("a compressed body's record, table and chunks")
{
    // The third chunk is noise, kept as it is.
    const std::string body = text(2 * lz4_chunk) + random_bytes(lz4_chunk, 7) + text(30000);
    std::string out, table;
    lz4_squeeze(body.data(), body.size(), out, table);
    object_meta m;
    m.size = body.size();
    const lz4_record r{out.size(), lz4_chunks_of(body.size())};
    set_lz4_record(m, &r);
    CHECK(is_compressed(m));
    lz4_record back;
    REQUIRE(lz4_record_of(m, back));
    CHECK((back.table_at == r.table_at && back.chunks == 4));
    // The numbers are written at a fixed width, so a header made with a placeholder is as long as the last one.
    CHECK(encode_lz4_record({0, 1}).size() == encode_lz4_record({UINT32_MAX, 99999}).size());

    lz4_table t;
    REQUIRE(lz4_table_decode(table, m, back, t));
    CHECK(t.raw[2]);
    CHECK(!t.raw[0]);
    std::string plain;
    REQUIRE(lz4_open_body(m, out + table, plain));
    CHECK(plain == body);
    // Any run of chunks opens on its own.
    std::string part(2 * lz4_chunk, '\0');
    REQUIRE(lz4_open_chunks(t, 1, 2, out.data() + t.at[1], part.data()));
    CHECK(part == body.substr(lz4_chunk, 2 * lz4_chunk));

    // A table that does not add up, a body cut short and a record that does not fit its size are refused.
    std::string bad = table;
    bad[0] = static_cast<char>(bad[0] + 1);
    CHECK_FALSE(lz4_table_decode(bad, m, back, t));
    CHECK_FALSE(lz4_open_body(m, (out + table).substr(0, out.size()), plain));
    object_meta other = m;
    other.size = 10;
    CHECK_FALSE(lz4_record_of(other, back));
    other = m;
    other.parts = 2;
    CHECK_FALSE(lz4_record_of(other, back));
    set_lz4_record(m, nullptr);
    CHECK_FALSE(is_compressed(m));
}
