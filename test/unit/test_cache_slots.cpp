#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include "../../socketley/shared/ipc/cache_shard_map.h"

#include <cstring>
#include <set>
#include <string>
#include <vector>

// What this file is for.
//
// cache_shard_of() stopped being ours.  Its whole value is now that a stranger
// computes the same number from the same bytes without ever talking to us —
// redis-cli -c, redis-benchmark --cluster, go-redis, lettuce — so the thing
// under test is not "does it spread keys", it is "is it EXACTLY Redis's
// function".  A test that only checked our own consistency would stay green
// through the one change that matters: a mixing step that is a little different
// from CRC16/XMODEM's, which spreads just as well and routes every key of every
// real client to the wrong shard.
//
// So the constants below are external.  0x31C3 is the published CRC16/XMODEM
// check value for "123456789"; the slot numbers are the ones Redis's own
// documentation and test suite state.  They were not read out of this build.

TEST_CASE("CRC16/XMODEM matches its published check value")
{
    CHECK(cache_crc16("123456789") == 0x31C3);

    // The empty string is the identity of the initial value, which is 0 here
    // (no 0xFFFF init, no final xor) — the two most common ways to get a
    // CRC16 variant wrong both show up in this one case.
    CHECK(cache_crc16("") == 0x0000);
}

TEST_CASE("slots match the numbers Redis states")
{
    CHECK(cache_slot_of("foo")   == 12182);
    CHECK(cache_slot_of("bar")   == 5061);
    CHECK(cache_slot_of("hello") == 866);
    CHECK(cache_slot_of("key1")  == 9189);
}

TEST_CASE("hash tags follow Redis's rule, including its corner cases")
{
    // The point of the feature: two keys a client deliberately tied together.
    CHECK(cache_slot_of("{user1000}.following")
          == cache_slot_of("{user1000}.followers"));
    CHECK(cache_slot_of("{user1000}.following") == cache_slot_of("user1000"));

    // An empty pair is NOT a tag — the whole key is hashed.
    CHECK(cache_slot_of("foo{}{bar}") == cache_crc16("foo{}{bar}") % 16384);
    CHECK(cache_slot_of("foo{}{bar}") != cache_slot_of("bar"));

    // First '{' and the first '}' after it: "foo{{bar}}zap" hashes "{bar".
    CHECK(cache_slot_of("foo{{bar}}zap") == cache_slot_of("{bar"));

    // A second tag is ignored.
    CHECK(cache_slot_of("foo{bar}{zap}") == cache_slot_of("bar"));

    // No closing brace at all: the whole key.
    CHECK(cache_slot_of("foo{bar") == cache_crc16("foo{bar") % 16384);

    // A key that is nothing but a tag.
    CHECK(cache_slot_of("{bar}") == cache_slot_of("bar"));

    CHECK(cache_hash_tag("{a}b") == std::string_view("a"));
    CHECK(cache_hash_tag("ab")   == std::string_view("ab"));
    CHECK(cache_hash_tag("{}ab") == std::string_view("{}ab"));
}

TEST_CASE("bytes above 0x7f are hashed as unsigned")
{
    // char is signed on this toolchain.  A sign-extended byte fed to the table
    // index would run off the front of the array — UB that ASan catches, and
    // that a release build would answer with a plausible wrong slot.
    CHECK(cache_slot_of("\xff\xfe\x80") < 16384);
    CHECK(cache_crc16("\xff") == cache_crc16_bitwise(0, 0xFF));
}

TEST_CASE("the table agrees with the bitwise definition it was generated from")
{
    for (int i = 0; i < 256; ++i)
        CHECK(cache_crc16_tab.v[i]
              == cache_crc16_bitwise(0, static_cast<uint8_t>(i)));
}

TEST_CASE("eight bytes at a time is the bitwise CRC, for every length, every byte and a key fed in pieces")
{
    auto bitwise = [](std::string_view s)
    {
        uint16_t crc = 0;
        for (const char c : s)
            crc = cache_crc16_bitwise(crc, static_cast<uint8_t>(c));
        return crc;
    };
    static_assert(cache_crc16("123456789") == 0x31C3);

    uint64_t x = 0x9E3779B97F4A7C15ull;
    auto next = [&x]() { x ^= x << 13; x ^= x >> 7; x ^= x << 17; return x; };
    std::vector<std::string> inputs;
    // Every length across several blocks and tails, of random bytes, of all zeros and of all ones.
    for (size_t len = 0; len <= 70; ++len)
    {
        std::string r(len, '\0');
        for (auto& c : r)
            c = static_cast<char>(next());
        inputs.push_back(r);
        inputs.push_back(std::string(len, '\0'));
        inputs.push_back(std::string(len, '\xff'));
    }
    // Every byte value in every position of a block.
    for (int pos = 0; pos < 9; ++pos)
        for (int b = 0; b < 256; ++b)
        {
            std::string s(9, 'k');
            s[static_cast<size_t>(pos)] = static_cast<char>(b);
            inputs.push_back(s);
        }
    for (int i = 0; i < 2000; ++i)
    {
        std::string r(next() % 300, '\0');
        for (auto& c : r)
            c = static_cast<char>(next());
        inputs.push_back(r);
    }

    for (const std::string& s : inputs)
    {
        REQUIRE(cache_crc16(s) == bitwise(s));
        // Split anywhere and fed in two pieces, as a storage key is fed as bucket, "/" and key.
        const size_t cut = s.empty() ? 0 : next() % (s.size() + 1);
        const std::string_view v(s);
        CHECK(cache_crc16_update(cache_crc16_update(0, v.substr(0, cut)), v.substr(cut)) == bitwise(s));
    }
}

TEST_CASE("an unsharded cache is shard 0 of one, not a special case")
{
    CHECK(cache_shard_of("anything", 0) == 0);
    CHECK(cache_shard_of("anything", 1) == 0);
    CHECK(cache_shard_slot_first(0, 1) == 0);
    CHECK(cache_shard_slot_last(0, 1)  == 16383);
}

TEST_CASE("slot ranges are contiguous, complete and disjoint")
{
    for (uint32_t n : {2u, 3u, 4u, 5u, 6u, 7u, 8u, 16u, 64u})
    {
        CHECK(cache_shard_slot_first(0, n) == 0);
        CHECK(cache_shard_slot_last(n - 1, n) == 16383);

        uint32_t covered = 0;
        for (uint32_t s = 0; s < n; ++s)
        {
            const uint32_t lo = cache_shard_slot_first(s, n);
            const uint32_t hi = cache_shard_slot_last(s, n);
            REQUIRE(lo <= hi);                    // no empty range below N=16384
            if (s > 0)
                CHECK(lo == cache_shard_slot_last(s - 1, n) + 1);   // no gap
            covered += hi - lo + 1;
        }
        CHECK(covered == 16384);
    }
}

TEST_CASE("the range a shard advertises is the range it is actually given")
{
    // The two directions are computed by different expressions, and CLUSTER
    // SLOTS publishes one while routing uses the other.  A client that trusted
    // a range the router disagreed with would be sent -MOVED forever, in a
    // loop, and every cluster client has a retry limit it would hit instead.
    for (uint32_t n : {2u, 3u, 4u, 5u, 7u, 8u, 64u})
        for (uint32_t slot = 0; slot < 16384; ++slot)
        {
            const uint32_t owner = cache_shard_of_slot(slot, n);
            REQUIRE(owner < n);
            REQUIRE(slot >= cache_shard_slot_first(owner, n));
            REQUIRE(slot <= cache_shard_slot_last(owner, n));
        }
}

TEST_CASE("cache_shard_of routes a key to the owner of its slot")
{
    const char* keys[] = {"foo", "bar", "hello", "key1", "", "{a}b",
                          "a longer key with spaces", "\xff\xfe"};
    for (uint32_t n : {2u, 3u, 4u, 8u})
        for (const char* k : keys)
            CHECK(cache_shard_of(k, n) == cache_shard_of_slot(cache_slot_of(k), n));
}

TEST_CASE("the fingerprint moves when the ownership function moves")
{
    // cache_shard_map.h's own claim: a dump written under one ownership
    // function and loaded under another takes the filter path rather than the
    // fast one, because the fingerprint differs.  This pins the CURRENT
    // fingerprint against the FNV-1a one this build replaced, which is the
    // exact transition a dump on disk right now will make.
    unsigned char now[cache_fingerprint_len];
    cache_shard_fingerprint(now);

    const auto fnv_shard_of = [](std::string_view key, uint32_t n) -> unsigned char {
        uint64_t h = 1469598103934665603ull;
        for (const char c : key)
        {
            h ^= static_cast<uint8_t>(c);
            h *= 1099511628211ull;
        }
        return static_cast<unsigned char>(h % n);
    };

    bool differs = false;
    for (size_t i = 0; i < cache_fingerprint_len; ++i)
        if (now[i] != fnv_shard_of(cache_fingerprint_probes[i],
                                   cache_fingerprint_count))
            differs = true;
    CHECK(differs);

    // And it is a function of the function, not of the split: taking it twice
    // gives the same bytes, so a load under the same build takes the fast path.
    unsigned char again[cache_fingerprint_len];
    cache_shard_fingerprint(again);
    CHECK(std::memcmp(now, again, cache_fingerprint_len) == 0);
}

TEST_CASE("the split is not so lopsided that a shard is starved")
{
    // Not a quality claim — CRC16 is not chosen for its mixing and this test
    // cannot be allowed to fail for a reason nobody may fix.  It is a floor: a
    // 4-shard split of 20000 sequential keys where any shard held under half
    // its share would mean the slot-to-shard arithmetic is broken, not that the
    // hash is mediocre.
    for (uint32_t n : {2u, 4u, 8u})
    {
        std::vector<int> count(n, 0);
        for (int i = 0; i < 20000; ++i)
        {
            std::string key("key:");
            key += std::to_string(i);
            count[cache_shard_of(key, n)]++;
        }
        const int fair = 20000 / static_cast<int>(n);
        for (uint32_t s = 0; s < n; ++s)
            CHECK(count[s] > fair / 2);
    }
}
