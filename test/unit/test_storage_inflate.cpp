// DEFLATE opened: streams written by the system's zlib at every level (stored, fixed and dynamic blocks) read back
// byte for byte however their input is cut and their output bounded, and what is not DEFLATE, or ends inside it,
// refused rather than taken for something.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <random>
#include <string>

#include <dlfcn.h>

#include "runtime/storage/inflate.h"

using namespace socketley::storage;

namespace
{

// zlib's compress2 writes a two-byte header, raw DEFLATE, and an Adler-32: the middle is what a ZIP entry holds.
struct zlib
{
    using compress2_fn = int (*)(uint8_t*, unsigned long*, const uint8_t*, unsigned long, int);
    void*        lib{dlopen("libz.so.1", RTLD_NOW)};
    compress2_fn compress2{lib ? reinterpret_cast<compress2_fn>(dlsym(lib, "compress2")) : nullptr};

    std::string deflate(const std::string& in, int level) const
    {
        unsigned long n = in.size() + in.size() / 1000 + 64;
        std::string out(n, '\0');
        if (compress2(reinterpret_cast<uint8_t*>(out.data()), &n, reinterpret_cast<const uint8_t*>(in.data()),
                      in.size(), level) != 0)
            return {};
        return out.substr(2, n - 6);
    }
};

// Feeds `raw` `step` bytes at a time and takes at most `cap` bytes a run, as a reader of a stored entry would.
std::string open(const std::string& raw, size_t step, size_t cap, inflater::result* last = nullptr)
{
    inflater z;
    std::string out;
    size_t at = 0;
    for (;;)
    {
        const auto r = z.run(out, cap);
        if (r == inflater::result::output_full)
            continue;
        if (r == inflater::result::need_input)
        {
            if (at >= raw.size())
            {
                z.end();
                continue;
            }
            const size_t n = std::min(step, raw.size() - at);
            z.feed(reinterpret_cast<const uint8_t*>(raw.data()) + at, n);
            at += n;
            continue;
        }
        if (last)
            *last = r;
        return r == inflater::result::done ? out : "<refused>";
    }
}

std::string sample(size_t n, unsigned seed)
{
    // Text-like: words repeated at distances near and far, so matches of every length and distance occur.
    std::mt19937 rng(seed);
    static const char* words[] = {"film ", "song ", "picture ", "folder ", "storage ", "socketley ", "\n", "0123456789"};
    std::string s;
    while (s.size() < n)
    {
        if (rng() % 7 == 0)
            s += static_cast<char>(rng() & 0xff);
        else
            s += words[rng() % 8];
    }
    s.resize(n);
    return s;
}

}   // namespace

TEST_CASE("zlib's streams at every level open byte for byte")
{
    zlib z;
    if (!z.compress2)
    {
        MESSAGE("libz.so.1 is not installed here, skipped");
        return;
    }
    std::mt19937 rng(7);
    std::string noise(300000, '\0');
    for (auto& c : noise)
        c = static_cast<char>(rng() & 0xff);
    const std::string inputs[] = {"", "a", std::string(100000, 'x'), sample(1 << 20, 1), noise, sample(70000, 2) + noise};
    for (const auto& in : inputs)
        for (const int level : {0, 1, 6, 9})
        {
            const std::string raw = z.deflate(in, level);
            REQUIRE(!raw.empty());
            CHECK(open(raw, raw.size() + 1, 1 << 20) == in);
            CHECK(open(raw, 1, 1 << 20) == in);
            CHECK(open(raw, 4093, 1) == in);
            CHECK(open(raw, 65536, 7919) == in);
        }
}

TEST_CASE("a stream ends at its final block, and what follows it is not read as more")
{
    zlib z;
    if (!z.compress2)
        return;
    const std::string in  = sample(50000, 3);
    const std::string raw = z.deflate(in, 6) + "trailing bytes of the next entry";
    CHECK(open(raw, 1000, 1 << 16) == in);
}

TEST_CASE("what is not DEFLATE, or ends inside it, is refused")
{
    zlib z;
    inflater::result r{};
    // Block type 3 does not exist.
    CHECK(open(std::string(1, '\x07'), 1, 1024, &r) == "<refused>");
    CHECK(r == inflater::result::bad);
    // A stored block whose length's complement is wrong.
    CHECK(open(std::string("\x01\x05\x00\x00\x00hello", 10), 3, 1024, &r) == "<refused>");
    // A stored block that is right.
    CHECK(open(std::string("\x01\x05\x00\xfa\xffhello", 10), 3, 1024) == "hello");
    // A distance back before the first byte: fixed block, length 3 at distance 1 with nothing yet written.
    CHECK(open(std::string("\x03\x02\x00", 3), 1, 1024, &r) == "<refused>");
    if (z.compress2)
    {
        const std::string raw = z.deflate(sample(200000, 4), 9);
        CHECK(open(raw.substr(0, raw.size() / 2), 777, 1 << 16, &r) == "<refused>");
        CHECK(r == inflater::result::bad);
    }
    // Random bytes are refused or opened, never read past or hung on.
    std::mt19937 rng(11);
    for (int k = 0; k < 2000; ++k)
    {
        std::string junk(1 + rng() % 600, '\0');
        for (auto& c : junk)
            c = static_cast<char>(rng() & 0xff);
        open(junk, 1 + rng() % 64, 1 + rng() % 4096);
    }
}

TEST_CASE("a small stream that opens to much is given out a bounded amount at a time")
{
    zlib z;
    if (!z.compress2)
        return;
    const std::string raw = z.deflate(std::string(64 << 20, '\0'), 9);
    CHECK(raw.size() < 100000);
    inflater f;
    f.feed(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
    f.end();
    std::string out;
    CHECK(f.run(out, 1 << 16) == inflater::result::output_full);
    CHECK(out.size() == 1 << 16);
    size_t total = out.size();
    for (;;)
    {
        out.clear();
        const auto r = f.run(out, 1 << 20);
        total += out.size();
        CHECK(out.size() <= 1 << 20);
        if (r != inflater::result::output_full)
        {
            CHECK(r == inflater::result::done);
            break;
        }
    }
    CHECK(total == 64u << 20);
}
