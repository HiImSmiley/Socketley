#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <cstring>
#include <algorithm>
#include "doctest.h"
#include "../../socketley/runtime/cache/cache_store.h"
#include <deque>
#include <map>
#include <limits>
#include <set>
#include <thread>
#include <malloc.h>
#include <unistd.h>

TEST_CASE("cache_store string operations")
{
    cache_store store;

    SUBCASE("set and get")
    {
        CHECK(store.set("key1", "value1"));
        std::string out;
        CHECK(store.get("key1", out));
        CHECK(out == "value1");
    }

    SUBCASE("get nonexistent")
    {
        std::string out;
        CHECK_FALSE(store.get("nokey", out));
    }

    SUBCASE("overwrite")
    {
        store.set("k", "v1");
        store.set("k", "v2");
        std::string out;
        store.get("k", out);
        CHECK(out == "v2");
    }

    SUBCASE("del")
    {
        store.set("k", "v");
        CHECK(store.del("k"));
        CHECK_FALSE(store.del("k"));
    }

    SUBCASE("exists")
    {
        CHECK_FALSE(store.exists("k"));
        store.set("k", "v");
        CHECK(store.exists("k"));
    }

    SUBCASE("size")
    {
        CHECK(store.size() == 0);
        store.set("a", "1");
        store.set("b", "2");
        CHECK(store.size() == 2);
    }
}

TEST_CASE("cache_store type conflicts")
{
    cache_store store;

    SUBCASE("set on list key fails")
    {
        store.lpush("k", "v");
        CHECK_FALSE(store.set("k", "val"));
    }

    SUBCASE("lpush on string key fails")
    {
        store.set("k", "v");
        CHECK_FALSE(store.lpush("k", "val"));
    }

    SUBCASE("sadd on string key fails")
    {
        store.set("k", "v");
        CHECK(store.sadd("k", "m") == -1);
    }

    SUBCASE("hset on list key fails")
    {
        store.lpush("k", "v");
        CHECK_FALSE(store.hset("k", "f", "v"));
    }

    SUBCASE("del removes any type")
    {
        store.lpush("list", "v");
        CHECK(store.del("list"));
        CHECK_FALSE(store.exists("list"));

        store.sadd("set", "m");
        CHECK(store.del("set"));

        store.hset("hash", "f", "v");
        CHECK(store.del("hash"));
    }
}

TEST_CASE("cache_store list operations")
{
    cache_store store;

    SUBCASE("lpush and lpop")
    {
        store.lpush("q", "a");
        store.lpush("q", "b");
        std::string out;
        CHECK(store.lpop("q", out));
        CHECK(out == "b");
        CHECK(store.lpop("q", out));
        CHECK(out == "a");
        CHECK_FALSE(store.lpop("q", out));
    }

    SUBCASE("rpush and rpop")
    {
        store.rpush("q", "a");
        store.rpush("q", "b");
        std::string out;
        CHECK(store.rpop("q", out));
        CHECK(out == "b");
        CHECK(store.rpop("q", out));
        CHECK(out == "a");
    }

    SUBCASE("llen")
    {
        CHECK(store.llen("q") == 0);
        store.rpush("q", "a");
        store.rpush("q", "b");
        CHECK(store.llen("q") == 2);
    }

    SUBCASE("lindex")
    {
        store.rpush("q", "a");
        store.rpush("q", "b");
        store.rpush("q", "c");

        auto val = store.lindex("q", 0);
        REQUIRE(val.has_value());
        CHECK(*val == "a");

        val = store.lindex("q", -1);
        REQUIRE(val.has_value());
        CHECK(*val == "c");

        CHECK_FALSE(store.lindex("q", 10).has_value());
    }
}

TEST_CASE("cache_store set operations")
{
    cache_store store;

    SUBCASE("sadd and sismember")
    {
        CHECK(store.sadd("s", "a") == 1);
        CHECK(store.sadd("s", "b") == 1);
        CHECK(store.sadd("s", "a") == 0);  // already exists
        CHECK(store.sismember("s", "a"));
        CHECK_FALSE(store.sismember("s", "c"));
    }

    SUBCASE("srem")
    {
        store.sadd("s", "a");
        CHECK(store.srem("s", "a"));
        CHECK_FALSE(store.srem("s", "a"));
    }

    SUBCASE("scard")
    {
        CHECK(store.scard("s") == 0);
        store.sadd("s", "a");
        store.sadd("s", "b");
        CHECK(store.scard("s") == 2);
    }
}

TEST_CASE("cache_store hash operations")
{
    cache_store store;

    SUBCASE("hset and hget")
    {
        CHECK(store.hset("h", "f1", "v1"));
        auto val = store.hget("h", "f1");
        REQUIRE(val.has_value());
        CHECK(*val == "v1");
    }

    SUBCASE("hget nonexistent")
    {
        CHECK(store.hget("h", "f") == std::nullopt);
        store.hset("h", "f1", "v1");
        CHECK(store.hget("h", "f2") == std::nullopt);
    }

    SUBCASE("hdel")
    {
        store.hset("h", "f1", "v1");
        CHECK(store.hdel("h", "f1"));
        CHECK_FALSE(store.hdel("h", "f1"));
    }

    SUBCASE("hlen")
    {
        CHECK(store.hlen("h") == 0);
        store.hset("h", "f1", "v1");
        store.hset("h", "f2", "v2");
        CHECK(store.hlen("h") == 2);
    }
}

TEST_CASE("cache_store TTL")
{
    cache_store store;

    SUBCASE("expire and ttl")
    {
        store.set("k", "v");
        CHECK(store.set_expiry("k", 100));
        int ttl = store.get_ttl("k");
        CHECK(ttl > 0);
        CHECK(ttl <= 100);
    }

    SUBCASE("ttl on nonexistent key")
    {
        CHECK(store.get_ttl("nokey") == -2);
    }

    SUBCASE("ttl on key without expiry")
    {
        store.set("k", "v");
        CHECK(store.get_ttl("k") == -1);
    }

    SUBCASE("persist")
    {
        store.set("k", "v");
        store.set_expiry("k", 100);
        CHECK(store.persist("k"));
        CHECK(store.get_ttl("k") == -1);
    }

    SUBCASE("expire on nonexistent key")
    {
        CHECK_FALSE(store.set_expiry("nokey", 100));
    }

    // The single-probe form TTL and PTTL answer from has to say what the two
    // calls it replaced said, including removing a key whose deadline passed.
    SUBCASE("expire_then_pttl answers as check_expiry then get_pttl")
    {
        CHECK(store.expire_then_pttl("nokey") == -2);
        store.set("plain", "v");
        CHECK(store.expire_then_pttl("plain") == -1);
        store.set("k", "v");
        REQUIRE(store.set_expiry("k", 100));
        const int64_t ms = store.expire_then_pttl("k");
        CHECK(ms > 99000);
        CHECK(ms <= 100000);
        store.set("gone", "v");
        REQUIRE(store.set_expiry_ms("gone", 1));
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        CHECK(store.expire_then_pttl("gone") == -2);
        CHECK_FALSE(store.exists("gone"));
    }
}

TEST_CASE("cache_store eviction")
{
    cache_store store;
    // The limit counts the containers, not just the payload: a key costs what
    // its strings allocate plus ~74 for the map node and, while a limit is
    // configured, ~139 more for the LRU bookkeeping.  A 40-byte value is past
    // the small-string limit and takes a 64-byte heap block of its own, so an
    // entry below is ~279 bytes: 600 holds two of them and evicts on the third.
    store.set_max_memory(600);
    store.set_eviction(evict_allkeys_lru);

    SUBCASE("basic eviction")
    {
        // Fill up memory
        store.set("k1", std::string(40, 'a'));
        store.set("k2", std::string(40, 'b'));

        // This should trigger eviction of k1 (LRU)
        bool ok = store.set("k3", std::string(40, 'c'));
        CHECK(ok);
        CHECK_FALSE(store.exists("k1"));
    }

    SUBCASE("noeviction rejects writes")
    {
        store.set_eviction(evict_none);
        store.set_max_memory(500);
        store.set("k1", std::string(90, 'a'));
        CHECK_FALSE(store.set("k2", std::string(20, 'b')));
    }

    SUBCASE("growing an existing value is checked against the limit")
    {
        store.set_eviction(evict_none);
        store.set_max_memory(500);
        CHECK(store.set("k", std::string(90, 'a')));

        // Overwriting upward used to skip check_memory altogether, so a small
        // value could be replaced by an arbitrarily large one with the limit
        // never consulted.  It has to be refused, not silently accepted.
        CHECK_FALSE(store.set("k", std::string(5000, 'b')));

        std::string out;
        CHECK(store.get("k", out));
        CHECK(out.size() == 90);
    }

    SUBCASE("a refused append says so instead of reporting success")
    {
        store.set_eviction(evict_none);
        store.set_max_memory(500);
        CHECK(store.set("k", std::string(90, 'a')));

        // The refusal used to come back as the unchanged length, which reads
        // exactly like a successful append of nothing.
        CHECK(store.append("k", std::string(5000, 'b')) == cache_store::append_denied);
        std::string out;
        CHECK(store.get("k", out));
        CHECK(out.size() == 90);

        // Same for a key that does not exist yet, where the refusal used to be
        // reported as a new length of 0.
        CHECK(store.append("brandnew", std::string(5000, 'c')) == cache_store::append_denied);
        CHECK_FALSE(store.exists("brandnew"));
    }

    SUBCASE("a collection write does not evict the collection it is writing")
    {
        // sadd held an iterator into m_sets across check_memory(), and
        // try_evict was free to pick the very set that iterator named: the
        // emplace below then went through a freed node.  Two commands under
        // --maxmemory are the whole reproducer, and it is reachable by any
        // client that can write.  lpush, rpush and hset held theirs the same
        // way.
        REQUIRE(store.sadd("s", std::string(40, 'm')) == 1);
        store.sadd("s", std::string(400, 'n'));   // was a use-after-free here

        // Whatever the answer, the set that was written to has to still be the
        // set that was there.
        CHECK(store.sismember("s", std::string(40, 'm')));

        std::string out;
        REQUIRE(store.rpush("l", std::string(40, 'e')));
        store.rpush("l", std::string(400, 'f'));
        CHECK(store.llen("l") >= 1);
        CHECK(store.lindex("l", 0).has_value());

        REQUIRE(store.hset("h", "f", std::string(40, 'v')));
        store.hset("h", "g", std::string(400, 'w'));
        CHECK(store.hget("h", "f") != std::nullopt);
    }

    SUBCASE("a refused write leaves the key it refused to write alone")
    {
        REQUIRE(store.set("cfg", std::string(300, 'a')));

        // try_evict chose "cfg" itself as the victim, and the write was refused
        // anyway: the caller got an error *and* the value it already had was
        // deleted, to make room for a write that never landed.
        CHECK_FALSE(store.set("cfg", std::string(5000, 'b')));

        std::string out;
        REQUIRE(store.get("cfg", out));
        CHECK(out.size() == 300);
    }

    SUBCASE("a refused APPEND does not take the value it was appending to")
    {
        REQUIRE(store.set("log", std::string(300, 'a')));
        REQUIRE(store.set_expiry("log", 3600));

        // This evicted "log", fell through to the create branch, stored the
        // suffix on its own and returned 200 — a number the caller cannot tell
        // from a successful append.  The 300 bytes that were there and the TTL
        // went with it, and nothing said so.
        CHECK(store.append("log", std::string(200, 'b')) == cache_store::append_denied);

        std::string out;
        REQUIRE(store.get("log", out));
        CHECK(out.size() == 300);
        CHECK(store.get_ttl("log") > 0);
    }

    SUBCASE("overwriting a hash field is checked against the limit")
    {
        store.set_eviction(evict_none);
        store.set_max_memory(1200);
        REQUIRE(store.hset("h", "f", "v"));
        const size_t before = store.get_memory_used();

        // Overwriting an existing field called check_memory nowhere at all, so
        // this went straight in: 294 bytes in use before it, 100305 after,
        // against a ceiling of 1200.  Adding a *new* field was checked; the
        // same hole was closed for SET long ago.
        CHECK_FALSE(store.hset("h", "f", std::string(100000, 'x')));

        auto got = store.hget("h", "f");
        REQUIRE(got.has_value());
        CHECK(*got == "v");
        CHECK(store.get_memory_used() == before);
        CHECK(store.get_memory_used() <= 1200);
    }

    SUBCASE("an APPEND is charged for the buffer it actually buys")
    {
        store.set_eviction(evict_none);
        store.set_max_memory(1600);
        REQUIRE(store.set("k", std::string(1300, 'a')));

        // libstdc++ reallocates to twice the old capacity rather than to fit,
        // so a 32-byte suffix on a 1300-byte value buys a 2600-byte buffer.
        // Admission asked for what the new *length* needs — 32 bytes — and the
        // accepted write left the store at 2838 bytes against a 1600-byte
        // ceiling.  What has to be asked for is the allocation.
        CHECK(store.append("k", std::string(32, 'b')) == cache_store::append_denied);
        CHECK(store.strlen_key("k") == 1300);
        CHECK(store.get_memory_used() <= 1600);

        // And the other side of it: an append that really does fit is still
        // taken.  A refusal that is always right for the wrong reason is not a
        // fix.
        store.set_max_memory(100000);
        CHECK(store.append("k", std::string(32, 'b')) == 1332);
        CHECK(store.get_memory_used() <= 100000);
    }

    SUBCASE("emptying a collection does not corrupt LRU order")
    {
        // Draining a list deletes the key.  That path used to erase the key
        // from m_lru_map while leaving its m_lru_order node behind, so when the
        // key came back touch_lru appended a *second* node.  Eviction then
        // walked the stale node and deleted the key it named — the live one,
        // even though it was the most recently used.
        std::string out;
        store.rpush("a", "x");
        CHECK(store.lpop("a", out));
        CHECK_FALSE(store.exists("a"));

        store.set("a", std::string(45, 'a'));
        store.set("b", std::string(45, 'b'));

        // Touch "a" so "b" is unambiguously the least recently used.
        // get_ptr is what the command path uses; plain get() is const and does
        // not update the LRU.
        CHECK(store.get_ptr("a") != nullptr);

        // Adding "c" has to evict exactly one key, and it must be "b"
        CHECK(store.set("c", std::string(45, 'c')));
        CHECK(store.exists("a"));
        CHECK_FALSE(store.exists("b"));
    }
}

TEST_CASE("cache_store a refused SET leaves the key's TTL alone")
{
    // set() erased the key's expiry as its very first act — before the
    // type-conflict check and before check_memory — so a SET that was then
    // refused had still stripped the TTL off a key it never wrote.  The client
    // is told the write failed and has every reason to believe nothing
    // happened; the key it was told about now never expires.  Reachable through
    // SET and GETSET.
    SUBCASE("refused on the key's type")
    {
        cache_store store;
        REQUIRE(store.hset("sess", "f", "v"));
        REQUIRE(store.set_expiry("sess", 3600));

        CHECK_FALSE(store.set("sess", "v"));
        CHECK(store.get_ttl("sess") > 0);

        std::string oldval;
        CHECK_FALSE(store.getset("sess", "v", oldval));
        CHECK(store.get_ttl("sess") > 0);
    }

    SUBCASE("refused for want of room")
    {
        cache_store store;
        store.set_max_memory(600);
        store.set_eviction(evict_none);
        REQUIRE(store.set("k", std::string(100, 'a')));
        REQUIRE(store.set_expiry("k", 3600));

        CHECK_FALSE(store.set("k", std::string(5000, 'b')));
        CHECK(store.get_ttl("k") > 0);

        // ...and a SET that goes through still drops it, which is what SET
        // without KEEPTTL means.
        CHECK(store.set("k", std::string(100, 'c')));
        CHECK(store.get_ttl("k") == -1);
    }
}

TEST_CASE("cache_store load restores accounting and eviction order")
{
    const std::string path = "/tmp/socketley-unit-load-" + std::to_string(::getpid()) + ".bin";
    size_t expected = 0;

    {
        cache_store src;
        src.set_max_memory(1000000);
        src.set_eviction(evict_allkeys_lru);
        for (int i = 0; i < 20; i++)
            src.set("k" + std::to_string(i), std::string(50, 'v'));
        src.rpush("l", std::string(40, 'e'));
        src.sadd("s", std::string(40, 'm'));
        src.hset("h", "f", std::string(40, 'x'));
        // 16..29 bytes is the one range where load() used to hand back a string
        // that costs more than the one saved: it built them with assign() onto
        // a fresh std::string, and libstdc++ rounds a request under twice the
        // old capacity up to twice it, so 20 bytes came back holding 30.  The
        // equality below is what caught it; every other length in this case
        // round-trips exactly.
        src.set(std::string(20, 'p'), std::string(20, 'q'));
        expected = src.get_memory_used();
        CHECK(src.save(path));
    }

    cache_store dst;
    dst.set_max_memory(1000000);          // limit is configured before the load, as the runtime does
    dst.set_eviction(evict_allkeys_lru);
    CHECK(dst.load(path));
    CHECK(dst.size() == 24);

    // load() inserted straight into the containers, so the restored data was
    // invisible to the accounting: same bytes resident, but reported as nothing.
    CHECK(dst.get_memory_used() == expected);

    // And the eviction order has to come back too.  With an empty LRU try_evict
    // has nothing to walk, so a write that needs room fails instead of making it.
    dst.set_max_memory(dst.get_memory_used() + 200);
    CHECK(dst.set("fresh", std::string(400, 'z')));

    ::unlink(path.c_str());
}

TEST_CASE("cache_store memory accounting")
{
    cache_store store;
    const size_t empty = store.get_memory_used();

    SUBCASE("reports the cost of the containers, not just the payload")
    {
        store.set("k", std::string(10, 'v'));
        // 11 bytes of payload live in a map node that costs several times that
        CHECK(store.get_memory_used() - empty > 50);
    }

    SUBCASE("returns to baseline once every key is gone")
    {
        for (int i = 0; i < 50; i++)
        {
            std::string n = std::to_string(i);
            store.set("k" + n, "value");
            store.rpush("list", "element");
            store.sadd("set", "member" + n);
            store.hset("hash", "field" + n, "v");
        }
        CHECK(store.get_memory_used() > empty);

        for (int i = 0; i < 50; i++)
            CHECK(store.del("k" + std::to_string(i)));
        CHECK(store.del("list"));
        CHECK(store.del("set"));
        CHECK(store.del("hash"));

        // A missed decrement anywhere leaves the cache permanently believing it
        // holds memory it does not — and that error only ever accumulates.
        CHECK(store.get_memory_used() == empty);
    }

    SUBCASE("draining collections element by element balances too")
    {
        std::string out;
        for (int i = 0; i < 20; i++) store.rpush("l", "e");
        for (int i = 0; i < 20; i++) CHECK(store.lpop("l", out));
        for (int i = 0; i < 20; i++) store.sadd("s", "m" + std::to_string(i));
        for (int i = 0; i < 20; i++) CHECK(store.srem("s", "m" + std::to_string(i)));
        for (int i = 0; i < 20; i++) store.hset("h", "f" + std::to_string(i), "v");
        for (int i = 0; i < 20; i++) CHECK(store.hdel("h", "f" + std::to_string(i)));
        CHECK(store.get_memory_used() == empty);
    }
}

// An independent model of what libstdc++ and glibc actually spend on one stored
// string — deliberately not the one cache_store uses, so that a formula that
// drifts is caught rather than confirmed.  It is a *lower* bound: a store
// reporting less than this is reporting less memory than it is holding, which is
// the direction that lets --maxmemory be exceeded.
namespace
{
    // libstdc++ keeps up to 15 bytes inside the string object itself.
    constexpr size_t sso_limit = 15;

    // glibc rounds an allocation up to a 16-byte chunk with an 8-byte header,
    // and never hands out less than 32 bytes.  A string of `len` asks for
    // len + 1 (the terminator).
    size_t heap_block(size_t len)
    {
        if (len <= sso_limit)
            return 0;
        size_t chunk = (len + 1 + 8 + 15) & ~static_cast<size_t>(15);
        return chunk < 32 ? 32 : chunk;
    }

    // Reported cost of a single string key, over an empty store.
    size_t reported_cost(const std::string& key, const std::string& val, bool with_limit)
    {
        cache_store store;
        if (with_limit)
        {
            // Far above anything these cases store, so nothing is ever evicted;
            // the point of the limit is that it switches the LRU on.
            store.set_max_memory(size_t(1) << 30);
            store.set_eviction(evict_allkeys_lru);
        }
        const size_t empty = store.get_memory_used();
        REQUIRE(store.set(key, val));
        return store.get_memory_used() - empty;
    }
}

TEST_CASE("cache_store memory accounting past the small-string limit")
{
    // Everything a key costs that does not depend on its length: map node,
    // bucket slot and LRU bookkeeping.  Taken from the store itself with a key
    // and value that both fit inside their string objects, which is the one
    // shape the reported figure was measured to match RSS on exactly (234 B/key
    // at 500k keys).  Deriving it here rather than writing the constants down
    // keeps this test about the part that was wrong: the string allocations.
    const std::string tiny_key(11, 'k');
    const std::string tiny_val(10, 'v');
    const size_t fixed = reported_cost(tiny_key, tiny_val, true)
                       - tiny_key.size() - tiny_val.size();

    SUBCASE("a key and value past the limit are charged for their heap blocks")
    {
        // The shape that used to read 1.4x low: 26-byte key, 100-byte value.
        // The key exists three times over — once in the map node, once in the
        // LRU list node, once as the LRU map's key — and each copy owns a block.
        const std::string key(26, 'k');
        const std::string val(100, 'v');

        const size_t floor_ = fixed + 3 * heap_block(key.size()) + heap_block(val.size());
        CHECK(reported_cost(key, val, true) >= floor_);
    }

    SUBCASE("one byte over the limit buys a whole block")
    {
        const size_t at_limit = reported_cost("k", std::string(sso_limit, 'v'), true);
        const size_t over     = reported_cost("k", std::string(sso_limit + 1, 'v'), true);

        // 15 bytes live in the string object; 16 take a 32-byte chunk of their
        // own and leave the inline buffer behind, unused.  The step is real and
        // has to show up as one.
        CHECK(over >= at_limit + heap_block(sso_limit + 1) - sso_limit);
    }

    SUBCASE("the LRU's own copies of a long key are charged")
    {
        const std::string val(4, 'v');
        const std::string short_key(sso_limit, 'k');
        const std::string long_key(sso_limit + 1, 'k');

        // What the LRU costs for a key that needs no allocation: bookkeeping only.
        const size_t lru_fixed = reported_cost(short_key, val, true)
                               - reported_cost(short_key, val, false);

        // For a longer key it is that plus the two extra copies of the key.
        // Their bytes were counted nowhere — the map node's copy was counted
        // once and stood in for all three.
        const size_t lru_long = reported_cost(long_key, val, true)
                              - reported_cost(long_key, val, false);
        CHECK(lru_long >= lru_fixed + 2 * heap_block(long_key.size()));
    }

    SUBCASE("with no limit configured there is no LRU to charge for")
    {
        const std::string key(26, 'k');
        const std::string val(100, 'v');
        const size_t reported = reported_cost(key, val, false);

        // Still the two blocks the map node's own strings need...
        CHECK(reported >= heap_block(key.size()) + heap_block(val.size()));
        // ...and not the LRU's, which do not exist while touch_lru is a no-op.
        CHECK(reported < fixed + 3 * heap_block(key.size()) + heap_block(val.size()));
    }

    SUBCASE("500 keys never report below what their strings allocate")
    {
        cache_store store;
        store.set_max_memory(size_t(1) << 30);
        store.set_eviction(evict_allkeys_lru);
        const size_t empty = store.get_memory_used();

        const std::string val(100, 'v');
        constexpr int n = 500;
        for (int i = 0; i < n; i++)
        {
            std::string key = std::to_string(1000 + i);   // 4 bytes
            key.append(22, 'k');                          // 26 in total
            REQUIRE(store.set(key, val));
        }

        // 234 B/key was right and 340 B/key was not; the difference is entirely
        // in these blocks.  Reading low is what lets a cache with --maxmemory
        // 256M settle well above 256 MB, so the check is one-sided on purpose.
        const size_t floor_ = size_t(n) * (fixed + 3 * heap_block(26) + heap_block(val.size()));
        CHECK(store.get_memory_used() - empty >= floor_);
    }

    SUBCASE("a value that shrinks in place is still charged for its buffer")
    {
        cache_store store;
        const size_t empty = store.get_memory_used();
        REQUIRE(store.set("k", std::string(1000, 'v')));
        REQUIRE(store.set("k", std::string(4, 'v')));

        // assign() never gives a buffer back, so the key still owns the
        // kilobyte it was given.  Charging the new length instead would report
        // four bytes for a kilobyte of resident memory.
        CHECK(store.get_memory_used() - empty >= heap_block(1000));
    }

    SUBCASE("a value grown by APPEND is charged for its buffer")
    {
        cache_store store;
        const size_t empty = store.get_memory_used();
        const std::string chunk(1000, 'x');
        REQUIRE(store.set("k", "seed"));
        for (int i = 0; i < 5; i++)
            REQUIRE(store.append("k", chunk) != cache_store::append_denied);

        // libstdc++ doubles the buffer rather than growing it to fit, so the
        // real allocation is larger than this; the length is the safe bound.
        CHECK(store.get_memory_used() - empty >= heap_block(4 + 5 * chunk.size()));
    }

    SUBCASE("long keys of every type balance back to the baseline")
    {
        // The LRU's copies are added by touch_lru and given back by drop_lru,
        // which is a second pair of books to get wrong.  Once with a limit
        // configured and once without, because only the first has an LRU.
        for (int with_limit = 0; with_limit < 2; with_limit++)
        {
            cache_store store;
            if (with_limit)
            {
                store.set_max_memory(size_t(1) << 30);
                store.set_eviction(evict_allkeys_lru);
            }
            const size_t empty = store.get_memory_used();

            const std::string elem(80, 'e');
            for (int i = 0; i < 20; i++)
            {
                const std::string n = std::to_string(i);
                REQUIRE(store.set("string:key:padding:" + n, elem));
                REQUIRE(store.rpush("list:key:padding:" + n, elem));
                REQUIRE(store.sadd("set:key:padding:" + n, elem) == 1);
                REQUIRE(store.hset("hash:key:padding:" + n, "field:padding:" + n, elem));
            }
            CHECK(store.get_memory_used() > empty);

            for (int i = 0; i < 20; i++)
            {
                const std::string n = std::to_string(i);
                CHECK(store.del("string:key:padding:" + n));
                CHECK(store.del("list:key:padding:" + n));
                CHECK(store.del("set:key:padding:" + n));
                CHECK(store.del("hash:key:padding:" + n));
            }
            CHECK(store.get_memory_used() == empty);
        }
    }

    SUBCASE("draining long-keyed collections element by element balances too")
    {
        cache_store store;
        store.set_max_memory(size_t(1) << 30);
        store.set_eviction(evict_allkeys_lru);
        const size_t empty = store.get_memory_used();

        const std::string list_key(30, 'l');
        const std::string set_key(30, 's');
        const std::string hash_key(30, 'h');
        std::string out;

        for (int i = 0; i < 20; i++)
            REQUIRE(store.rpush(list_key, std::string(40, 'e')));
        for (int i = 0; i < 20; i++)
            CHECK(store.lpop(list_key, out));

        for (int i = 0; i < 20; i++)
            REQUIRE(store.sadd(set_key, "member:padding:" + std::to_string(i)) == 1);
        for (int i = 0; i < 20; i++)
            CHECK(store.srem(set_key, "member:padding:" + std::to_string(i)));

        for (int i = 0; i < 20; i++)
            REQUIRE(store.hset(hash_key, "field:padding:" + std::to_string(i), std::string(40, 'v')));
        for (int i = 0; i < 20; i++)
            CHECK(store.hdel(hash_key, "field:padding:" + std::to_string(i)));

        CHECK(store.get_memory_used() == empty);
    }
}

TEST_CASE("cache_store pub/sub")
{
    cache_store store;

    SUBCASE("subscribe and get_subscribers")
    {
        store.subscribe(10, "ch1");
        store.subscribe(20, "ch1");
        store.subscribe(10, "ch2");

        const auto* subs = store.get_subscribers("ch1");
        REQUIRE(subs != nullptr);
        CHECK(subs->size() == 2);
        CHECK(subs->count(10) == 1);
        CHECK(subs->count(20) == 1);
    }

    SUBCASE("unsubscribe")
    {
        store.subscribe(10, "ch1");
        store.unsubscribe(10, "ch1");
        CHECK(store.get_subscribers("ch1") == nullptr);
    }

    SUBCASE("unsubscribe_all")
    {
        store.subscribe(10, "ch1");
        store.subscribe(10, "ch2");
        store.unsubscribe_all(10);
        CHECK(store.get_subscribers("ch1") == nullptr);
        CHECK(store.get_subscribers("ch2") == nullptr);
    }

    SUBCASE("channel_count")
    {
        CHECK(store.channel_count() == 0);
        store.subscribe(10, "ch1");
        store.subscribe(20, "ch2");
        CHECK(store.channel_count() == 2);
    }
}

TEST_CASE("cache_store new methods")
{
    cache_store store;

    SUBCASE("incr creates key")
    {
        int64_t result = 0;
        CHECK(store.incr("counter", 1, result) == cache_store::incr_result::ok);
        CHECK(result == 1);
        std::string out;
        CHECK(store.get("counter", out));
        CHECK(out == "1");
    }

    SUBCASE("incr existing integer")
    {
        store.set("counter", "10");
        int64_t result = 0;
        CHECK(store.incr("counter", 5, result) == cache_store::incr_result::ok);
        CHECK(result == 15);
    }

    SUBCASE("incr non-integer fails")
    {
        store.set("k", "abc");
        int64_t result = 0;
        CHECK(store.incr("k", 1, result) == cache_store::incr_result::not_an_integer);
    }

    SUBCASE("decr")
    {
        store.set("k", "10");
        int64_t result = 0;
        CHECK(store.incr("k", -1, result) == cache_store::incr_result::ok);
        CHECK(result == 9);
    }

    // The sum that leaves int64 is refused, and -- the half of it a test that
    // only reads the return value would miss -- the stored value is the one
    // that was there before.
    SUBCASE("incr past INT64_MAX is refused and writes nothing")
    {
        store.set("k", "9223372036854775807");
        int64_t result = 0;
        CHECK(store.incr("k", 1, result) == cache_store::incr_result::would_overflow);
        std::string out;
        CHECK(store.get("k", out));
        CHECK(out == "9223372036854775807");
    }

    SUBCASE("incr past INT64_MIN is refused and writes nothing")
    {
        store.set("k", "-9223372036854775808");
        int64_t result = 0;
        CHECK(store.incr("k", -1, result) == cache_store::incr_result::would_overflow);
        std::string out;
        CHECK(store.get("k", out));
        CHECK(out == "-9223372036854775808");
    }

    SUBCASE("hincrby past INT64_MAX is refused and leaves the field")
    {
        store.hset("h", "f", "9223372036854775807");
        int64_t result = 0;
        CHECK(store.hincrby("h", "f", 1, result) == cache_store::incr_result::would_overflow);
        auto held = store.hget("h", "f");
        REQUIRE(held.has_value());
        CHECK(*held == "9223372036854775807");
    }

    // expire_in is the one decision behind EXPIRE, PEXPIRE, EXPIREAT,
    // PEXPIREAT and a script's self.expire.  Three answers, and the third is
    // the one no bool could carry.
    SUBCASE("expire_in answers about the key, not about the call")
    {
        int64_t unused = 0;
        (void)unused;
        CHECK(store.expire_in("nosuch", 600, false) == cache_store::expire_result::no_such_key);

        store.set("a", "v");
        CHECK(store.expire_in("a", 600, false) == cache_store::expire_result::armed);
        CHECK(store.get_ttl("a") > 0);

        // Zero and below delete, and the deadline goes with the value -- a
        // name left in m_expiry answers to nothing.
        store.set("b", "v");
        CHECK(store.expire_in("b", 0, false) == cache_store::expire_result::deleted);
        std::string out;
        CHECK_FALSE(store.get("b", out));
        CHECK(store.get_pttl("b") == -2);

        store.set("c", "v");
        CHECK(store.expire_in("c", -1, true) == cache_store::expire_result::deleted);
        CHECK_FALSE(store.get("c", out));
    }

    // A key past its deadline that the sweep has not reached yet is not there
    // to be given a new one: without the check, EXPIRE erased the deadline,
    // kept the value and the key was back for good.  The deadline is put one
    // millisecond in the PAST rather than waiting for one to pass, so this
    // says the same thing on every machine.
    SUBCASE("expire_in does not revive a key whose deadline has passed")
    {
        store.set("k", "v");
        CHECK(store.set_expiry_ms("k", -1));
        CHECK(store.expire_in("k", 600, false) == cache_store::expire_result::no_such_key);
        std::string out;
        CHECK_FALSE(store.get("k", out));
    }

    // The deadline an absurd TTL means is "never", and the two readers agree
    // with it: an overflow here wrapped into the past and the key was gone on
    // the next touch.
    SUBCASE("a TTL past the clock's range saturates rather than wrapping")
    {
        store.set("k", "v");
        CHECK(store.set_expiry_ms("k", 9223372036854775807LL));
        CHECK(store.get_pttl("k") > 0);
        CHECK(store.get_ttl("k") > 0);
        CHECK(store.expire_time("k", true) > 0);
        store.check_expiry("k");
        std::string out;
        CHECK(store.get("k", out));

        store.set("k2", "v");
        CHECK(store.set_expiry("k2", 9223372036854775807LL));
        CHECK(store.get_ttl("k2") > 0);
        store.check_expiry("k2");
        CHECK(store.get("k2", out));
    }

    SUBCASE("append creates key")
    {
        size_t len = store.append("k", "hello");
        CHECK(len == 5);
        std::string out;
        CHECK(store.get("k", out));
        CHECK(out == "hello");
    }

    SUBCASE("append existing")
    {
        store.set("k", "hello");
        size_t len = store.append("k", " world");
        CHECK(len == 11);
        std::string out;
        store.get("k", out);
        CHECK(out == "hello world");
    }

    SUBCASE("strlen")
    {
        store.set("k", "hello");
        CHECK(store.strlen_key("k") == 5);
        CHECK(store.strlen_key("missing") == 0);
    }

    SUBCASE("getset returns old value")
    {
        store.set("k", "old");
        std::string oldval;
        CHECK(store.getset("k", "new", oldval));
        CHECK(oldval == "old");
        std::string cur;
        store.get("k", cur);
        CHECK(cur == "new");
    }

    SUBCASE("getset on missing key")
    {
        std::string oldval = "nonempty";
        CHECK(store.getset("missing", "new", oldval));
        CHECK(oldval == "");
        CHECK(store.exists("missing"));
    }

    SUBCASE("type")
    {
        store.set("s", "val");
        CHECK(store.type("s") == "string");
        store.lpush("l", "a");
        CHECK(store.type("l") == "list");
        store.sadd("st", "m");
        CHECK(store.type("st") == "set");
        store.hset("h", "f", "v");
        CHECK(store.type("h") == "hash");
        CHECK(store.type("none") == "none");
    }

    SUBCASE("keys wildcard")
    {
        store.set("foo:1", "a");
        store.set("foo:2", "b");
        store.set("bar:1", "c");
        std::vector<std::string_view> out;
        store.keys("foo:*", out);
        CHECK(out.size() == 2);
        out.clear();
        store.keys("*", out);
        CHECK(out.size() == 3);
    }

    SUBCASE("setnx new key")
    {
        CHECK(store.setnx("k", "val"));
        std::string out;
        CHECK(store.get("k", out));
        CHECK(out == "val");
    }

    SUBCASE("setnx existing key")
    {
        store.set("k", "original");
        CHECK_FALSE(store.setnx("k", "new"));
        std::string out;
        store.get("k", out);
        CHECK(out == "original");
    }

    SUBCASE("set_expiry_ms and get_pttl")
    {
        store.set("k", "v");
        CHECK(store.set_expiry_ms("k", 5000));
        int64_t pttl = store.get_pttl("k");
        CHECK(pttl > 4000);
        CHECK(pttl <= 5000);
    }

    SUBCASE("pttl nonexistent")
    {
        CHECK(store.get_pttl("missing") == -2);
    }

    SUBCASE("pttl no expiry")
    {
        store.set("k", "v");
        CHECK(store.get_pttl("k") == -1);
    }

    SUBCASE("sweep_expired ms")
    {
        store.set("k", "v");
        CHECK(store.set_expiry_ms("k", 1));
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        store.sweep_expired();
        CHECK_FALSE(store.exists("k"));
    }

    SUBCASE("scan all keys")
    {
        store.set("a", "1");
        store.set("b", "2");
        store.set("c", "3");
        std::vector<std::string_view> out;
        uint64_t next = store.scan(0, "*", 10, out);
        CHECK(next == 0);
        CHECK(out.size() == 3);
    }

    SUBCASE("scan pagination")
    {
        store.set("k1", "v");
        store.set("k2", "v");
        store.set("k3", "v");
        store.set("k4", "v");
        store.set("k5", "v");
        std::vector<std::string_view> all;
        uint64_t cursor = 0;
        do {
            std::vector<std::string_view> batch;
            cursor = store.scan(cursor, "*", 2, batch);
            all.insert(all.end(), batch.begin(), batch.end());
        } while (cursor != 0);
        CHECK(all.size() == 5);
    }

    SUBCASE("scan pattern")
    {
        store.set("foo:1", "v");
        store.set("foo:2", "v");
        store.set("bar:1", "v");
        std::vector<std::string_view> out;
        uint64_t next = store.scan(0, "foo:*", 10, out);
        CHECK(next == 0);
        CHECK(out.size() == 2);
        for (auto& k : out)
            CHECK(k.substr(0, 4) == "foo:");
    }
}

TEST_CASE("accounted memory tracks contents, not deletion history")
{
    // Found by fuzz_cache_ops (corpus: erase_reuse_accounting-56f01737) against
    // an open-addressing m_data: erase left the dead entry's heap buffers in
    // the slot — libstdc++ string move-assignment from a small-string source
    // keeps the destination's allocation — and a later insert that reused the
    // slot inherited a 192-byte capacity it never asked for.  stored_string()
    // reads capacity, deliberately, so the recycled buffer was CHARGED to the
    // new key: the store stood at 421 bytes under maxmemory 400 after a write
    // admission had approved at size zero.
    //
    // The property, container-independent: what a store reports after
    // create-delete-create must equal what it reports holding the same final
    // contents with no history.  If it does not, eviction under --maxmemory is
    // driven by deletion history rather than by what is resident, and the
    // cache evicts keys it could have kept.
    //
    // 500 large-value keys deleted, then 500 fresh empty-value keys: enough
    // that fresh keys land on previously-occupied slots in any open-addressed
    // layout of this size, and a no-op for any node-based one.
    cache_store with_history;
    for (int i = 0; i < 500; i++)
        CHECK(with_history.set("old:" + std::to_string(i), std::string(192, 'v')));
    const size_t loaded = with_history.get_memory_used();
    for (int i = 0; i < 500; i++)
        CHECK(with_history.del("old:" + std::to_string(i)));
    for (int i = 0; i < 500; i++)
        CHECK(with_history.set("new:" + std::to_string(i), ""));

    cache_store fresh;
    for (int i = 0; i < 500; i++)
        CHECK(fresh.set("new:" + std::to_string(i), ""));

    // The identity check below passes trivially if the two histories never
    // differed, so first pin that they did: the large values must have been
    // accounted while they were resident.
    CHECK(loaded > fresh.get_memory_used() + 500 * 192);

    CHECK(with_history.get_memory_used() == fresh.get_memory_used());
    CHECK(with_history.size() == fresh.size());
}

// A value predicate is answered out of the string map alone, and it shares its
// cursor with the ordinary scan -- which packs a map index beside a bucket
// index, so a cursor handed over from a walk that had already moved on carries
// a bucket number belonging to a different table.
TEST_CASE("cache_store scan filtering on the value")
{
    cache_store store;
    std::string_view berlin = "*berlin*";

    SUBCASE("only a string key holds a value")
    {
        store.set("s:hit",  "wohnt in berlin");
        store.set("s:miss", "wohnt in hamburg");
        store.rpush("l:1", "berlin");
        store.sadd("t:1", "berlin");
        store.hset("h:1", "city", "berlin");
        store.zadd("z:1", 1.0, "berlin");

        std::vector<std::string_view> out;
        CHECK(store.scan(0, "*", 100000, out, cache_store::scan_filter::one(&berlin)) == 0);
        REQUIRE(out.size() == 1);
        CHECK(out[0] == "s:hit");
    }

    SUBCASE("absent is not empty")
    {
        store.set("e:1", "");
        store.set("e:2", "not empty");

        std::vector<std::string_view> out;
        std::string_view none = "";
        CHECK(store.scan(0, "*", 100000, out, cache_store::scan_filter::one(&none)) == 0);
        REQUIRE(out.size() == 1);
        CHECK(out[0] == "e:1");

        // And without the predicate the same call answers both.
        std::vector<std::string_view> all;
        CHECK(store.scan(0, "*", 100000, all) == 0);
        CHECK(all.size() == 2);
    }

    SUBCASE("the key pattern and the value pattern are both required")
    {
        store.set("u:1", "berlin");
        store.set("u:2", "hamburg");
        store.set("x:1", "berlin");

        std::vector<std::string_view> out;
        CHECK(store.scan(0, "u:*", 100000, out, cache_store::scan_filter::one(&berlin)) == 0);
        REQUIRE(out.size() == 1);
        CHECK(out[0] == "u:1");
    }

    SUBCASE("count bounds the keys examined, not the keys returned")
    {
        for (int i = 0; i < 400; i++)
            store.set("k:" + std::to_string(i), "hamburg");

        // Nothing matches, so a page bounded by results would run to the end of
        // the map in one call and answer 0.  Bounded by keys examined it stops
        // early and hands back a cursor.
        std::vector<std::string_view> out;
        const uint64_t next = store.scan(0, "*", 8, out, cache_store::scan_filter::one(&berlin));
        CHECK(out.empty());
        CHECK(next != 0);
    }

    SUBCASE("a cursor naming another map restarts rather than skipping")
    {
        for (int i = 0; i < 300; i++)
            store.set("v:" + std::to_string(i), "berlin");

        // The store does not publish its bucket count and guessing it is how this
        // subcase first passed against the defect it is for.  A real cursor
        // carries it: one page of an ordinary scan comes back with the string
        // map's own bucket count packed into bits 32..54.
        std::vector<std::string_view> probe;
        const uint64_t real = store.scan(0, "*", 1, probe);
        REQUIRE(real != 0);
        const uint64_t buckets = (real >> 32) & 0x7FFFFFull;

        // Same bucket count, different map -- the one shape the rehash guard
        // cannot tell from a legitimate resume.  Taken at face value it starts
        // the walk at bucket five and the keys before it are returned by no call
        // of the iteration at all.
        const uint64_t foreign = (1ull << 55) | (buckets << 32) | 5ull;
        std::vector<std::string_view> out;
        CHECK(store.scan(foreign, "*", 100000, out, cache_store::scan_filter::one(&berlin)) == 0);
        CHECK(out.size() == 300);
    }
}

// The type of a key is the map it lives in, so a type filter is a restriction
// on which of the five the walk visits -- which makes the scan cheaper rather
// than dearer, the same way the value predicate does.
TEST_CASE("cache_store scan restricted to one type")
{
    cache_store store;
    store.set("s:1", "v");
    store.set("s:2", "v");
    store.rpush("l:1", "e");
    store.sadd("t:1", "m");
    store.hset("h:1", "f", "v");
    store.zadd("z:1", 1.0, "m");

    SUBCASE("a name maps to its map, and a name no type has to nothing")
    {
        CHECK(cache_store::scan_map_of_type("string") == 0);
        CHECK(cache_store::scan_map_of_type("list")   == 1);
        CHECK(cache_store::scan_map_of_type("set")    == 2);
        CHECK(cache_store::scan_map_of_type("hash")   == 3);
        CHECK(cache_store::scan_map_of_type("zset")   == 4);
        // Spelled however the caller likes, because the names are all letters.
        CHECK(cache_store::scan_map_of_type("HASH")   == 3);
        CHECK(cache_store::scan_map_of_type("ZSet")   == 4);
        CHECK(cache_store::scan_map_of_type("stream") == 5);
        CHECK(cache_store::scan_map_of_type("STREAM") == 5);
        CHECK(cache_store::scan_map_of_type("module") == -1);
        CHECK(cache_store::scan_map_of_type("")       == -1);
    }

    SUBCASE("each restriction returns its own map and nothing else")
    {
        // The prefix each map's keys were seeded with, so "it returned two
        // things" cannot pass for "it returned the right two things".
        struct { int map; size_t n; char prefix; } want[] = {
            {0, 2, 's'}, {1, 1, 'l'}, {2, 1, 't'}, {3, 1, 'h'}, {4, 1, 'z'},
        };
        for (const auto& w : want)
        {
            std::vector<std::string_view> out;
            CHECK(store.scan(0, "*", 100000, out, cache_store::scan_filter::one(nullptr, w.map)) == 0);
            REQUIRE(out.size() == w.n);
            for (auto k : out)
            {
                REQUIRE(k.size() >= 2);
                CHECK(k[0] == w.prefix);
                CHECK(k[1] == ':');
            }
        }
    }

    SUBCASE("the whole keyspace is still the default")
    {
        std::vector<std::string_view> out;
        CHECK(store.scan(0, "*", 100000, out) == 0);
        CHECK(out.size() == 6);
    }

    SUBCASE("a cursor already past the one map has nothing left to do")
    {
        // Restricted to the string map, resumed with a cursor naming the hash
        // map: under this restriction that iteration is over, and walking the
        // string map again would only repeat what the client already has.
        const uint64_t past = (3ull << 55);
        std::vector<std::string_view> out;
        CHECK(store.scan(past, "*", 100000, out, cache_store::scan_filter::one(nullptr, 0)) == 0);
        CHECK(out.empty());
    }

    SUBCASE("a cursor naming an earlier map starts the restricted one at its top")
    {
        for (int i = 0; i < 300; i++)
            store.hset("big:" + std::to_string(i), "f", "v");

        // Bits that name the string map, fed to a walk restricted to hashes.
        std::vector<std::string_view> probe;
        const uint64_t real = store.scan(0, "*", 1, probe);
        REQUIRE(real != 0);
        const uint64_t earlier = (real >> 32) << 32 | 7ull;   // map 0, bucket 7

        std::vector<std::string_view> out;
        CHECK(store.scan(earlier, "*", 1000000, out, cache_store::scan_filter::one(nullptr, 3)) == 0);
        CHECK(out.size() == 301);       // the 300 plus h:1
    }
}

// What the store says this key holds, so a pair can be checked against the
// store rather than against the other half of the same reply.
static std::string store_value_of(const cache_store& st, std::string_view key)
{
    std::string out;
    const_cast<cache_store&>(st).get(key, out);
    return out;
}

// The value is in the walker's hand when it matches a key, and throwing it away
// only to have the client ask for it again is the round trip this removes.
TEST_CASE("cache_store scan returning values beside keys")
{
    cache_store store;
    store.set("u:1", "berlin");
    store.set("u:2", "hamburg");
    store.set("e:1", "");
    store.hset("h:1", "f", "berlin");

    SUBCASE("key and value, interleaved, strings only")
    {
        std::vector<std::string_view> out;
        CHECK(store.scan(0, "*", 100000, out, cache_store::scan_filter::one(nullptr, -1, /*with_values=*/true)) == 0);
        REQUIRE(out.size() == 6);          // three pairs, and not the hash
        std::map<std::string, std::string> got;
        for (size_t i = 0; i < out.size(); i += 2)
            got[std::string(out[i])] = std::string(out[i + 1]);
        CHECK(got.size() == 3);
        CHECK(got["u:1"] == "berlin");
        CHECK(got["u:2"] == "hamburg");
        // Present with an empty value, which is a different answer from absent.
        REQUIRE(got.count("e:1") == 1);
        CHECK(got["e:1"] == "");
        CHECK(got.count("h:1") == 0);
    }

    SUBCASE("with a predicate it is the matches and their values")
    {
        std::string_view berlin = "*berlin*";
        std::vector<std::string_view> out;
        CHECK(store.scan(0, "*", 100000, out, cache_store::scan_filter::one(&berlin, -1, true)) == 0);
        REQUIRE(out.size() == 2);
        CHECK(out[0] == "u:1");
        CHECK(out[1] == "berlin");
    }

    SUBCASE("a page never ends between a key and its value")
    {
        for (int i = 0; i < 300; i++)
            store.set("v:" + std::to_string(i), "value-" + std::to_string(i));

        uint64_t cur = 0;
        size_t pairs = 0;
        int guard = 0;
        do {
            std::vector<std::string_view> page;
            cur = store.scan(cur, "*", 4, page, cache_store::scan_filter::one(nullptr, -1, true));
            // The one property that makes the reply parseable at all: a client
            // reading two at a time must never be handed an odd page.
            REQUIRE(page.size() % 2 == 0);
            for (size_t i = 0; i < page.size(); i += 2)
                CHECK(page[i + 1] == store_value_of(store, page[i]));
            pairs += page.size() / 2;
            REQUIRE(++guard < 10000);
        } while (cur != 0);
        CHECK(pairs == 303);               // 300 plus u:1, u:2 and e:1
    }
}

// How many keys of a type there are is a question the maps answer by existing,
// and counting the same thing with a scan is the whole map walked.
TEST_CASE("cache_store counts one type without walking it")
{
    cache_store store;
    for (int i = 0; i < 7; i++)  store.set("s:" + std::to_string(i), "v");
    for (int i = 0; i < 3; i++)  store.rpush("l:" + std::to_string(i), "e");
    for (int i = 0; i < 2; i++)  store.sadd("t:" + std::to_string(i), "m");
    for (int i = 0; i < 11; i++) store.hset("h:" + std::to_string(i), "f", "v");
    for (int i = 0; i < 5; i++)  store.zadd("z:" + std::to_string(i), 1.0, "m");
    for (int i = 0; i < 4; i++)  REQUIRE(store.stream_make("x:" + std::to_string(i), 0));

    SUBCASE("each map is counted on its own")
    {
        CHECK(store.size_of_type(0) == 7);
        CHECK(store.size_of_type(1) == 3);
        CHECK(store.size_of_type(2) == 2);
        CHECK(store.size_of_type(3) == 11);
        CHECK(store.size_of_type(4) == 5);
        CHECK(store.size_of_type(5) == 4);
    }

    SUBCASE("a map no type names counts nothing")
    {
        CHECK(store.size_of_type(-1) == 0);
        CHECK(store.size_of_type(6)  == 0);
        CHECK(store.size_of_type(99) == 0);
    }

    SUBCASE("and the six of them are the whole keyspace")
    {
        // The invariant that makes the six answers trustworthy together: a map
        // counted twice or missed entirely shows up here and nowhere else.
        uint32_t sum = 0;
        for (int m = 0; m <= 5; m++) sum += store.size_of_type(m);
        CHECK(sum == store.size());
        CHECK(sum == 32);
    }

    SUBCASE("it agrees with what a walk of the same map returns")
    {
        for (int m = 0; m <= 5; m++)
        {
            std::vector<std::string_view> out;
            CHECK(store.scan(0, "*", 1000000, out, cache_store::scan_filter::one(nullptr, m)) == 0);
            CHECK(out.size() == store.size_of_type(m));
        }
    }
}

// The database question for the layout records are usually stored in: which
// hashes have city = berlin.  From outside it is an HGET per hash key.
TEST_CASE("cache_store scan filtering on a hash field")
{
    cache_store store;
    store.hset("u:1", "city", "berlin");
    store.hset("u:2", "city", "hamburg");
    store.hset("u:3", "city", "berlin");
    store.hset("u:4", "name", "no city at all");
    store.hset("u:5", "city", "");
    store.set("plain", "berlin");
    store.rpush("l:1", "berlin");

    std::string_view field_city = "city";
    auto walk = [&](cache_store::scan_filter f, std::string_view pat = "*") {
        std::vector<std::string_view> out;
        CHECK(store.scan(0, pat, 100000, out, f) == 0);
        return out;
    };

    SUBCASE("having the field is not the same as the field being empty")
    {
        auto has = walk(cache_store::scan_filter::one(nullptr, -1, false, &field_city));
        CHECK(has.size() == 4);                       // u:4 has no city
        std::string_view empty = "";
        auto is_empty = walk(cache_store::scan_filter::one(&empty, -1, false, &field_city));
        REQUIRE(is_empty.size() == 1);
        CHECK(is_empty[0] == "u:5");                  // and u:5's city IS empty
    }

    SUBCASE("the predicate is matched against the field, not against the key")
    {
        std::string_view berlin = "berlin";
        auto got = walk(cache_store::scan_filter::one(&berlin, -1, false, &field_city));
        REQUIRE(got.size() == 2);
        std::set<std::string_view> s(got.begin(), got.end());
        CHECK(s.count("u:1") == 1);
        CHECK(s.count("u:3") == 1);
        // The string and the list hold "berlin" too, and neither is a hash with
        // a city field, so neither is an answer to this question.
        CHECK(s.count("plain") == 0);
        CHECK(s.count("l:1") == 0);
    }

    SUBCASE("the key pattern still applies")
    {
        std::string_view berlin = "berlin";
        auto got = walk(cache_store::scan_filter::one(&berlin, -1, false, &field_city), "u:1*");
        REQUIRE(got.size() == 1);
        CHECK(got[0] == "u:1");
    }

    SUBCASE("with values it is the field's value that comes back")
    {
        auto got = walk(cache_store::scan_filter::one(nullptr, -1, true, &field_city));
        REQUIRE(got.size() == 8);                     // four pairs
        std::map<std::string, std::string> m;
        for (size_t i = 0; i < got.size(); i += 2)
            m[std::string(got[i])] = std::string(got[i + 1]);
        CHECK(m["u:1"] == "berlin");
        CHECK(m["u:2"] == "hamburg");
        CHECK(m["u:5"] == "");
        CHECK(m.count("u:4") == 0);
    }

    SUBCASE("count bounds the keys examined, not the keys returned")
    {
        for (int i = 0; i < 400; i++)
            store.hset("h:" + std::to_string(i), "city", "hamburg");
        std::string_view nowhere = "atlantis";
        std::vector<std::string_view> out;
        const uint64_t next = store.scan(0, "*", 8, out, cache_store::scan_filter::one(&nowhere, -1, false, &field_city));
        CHECK(out.empty());
        CHECK(next != 0);
    }

    SUBCASE("a cursor naming another map starts the hash map at its top")
    {
        for (int i = 0; i < 300; i++)
            store.hset("h:" + std::to_string(i), "city", "berlin");

        std::vector<std::string_view> probe;
        const uint64_t real = store.scan(0, "*", 1, probe);
        REQUIRE(real != 0);
        const uint64_t buckets = (real >> 32) & 0x7FFFFFull;
        const uint64_t foreign = (0ull << 55) | (buckets << 32) | 5ull;   // the string map

        std::string_view berlin = "berlin";
        std::vector<std::string_view> out;
        CHECK(store.scan(foreign, "*", 1000000, out, cache_store::scan_filter::one(&berlin, -1, false, &field_city)) == 0);
        CHECK(out.size() == 302);                     // the 300 plus u:1 and u:3
    }
}

// hscan's pattern matches what a field is CALLED; this is what it holds.  A
// hash used as a table has the interesting part in the value, and transferring
// every value to compare them in the client is the round trip being removed.
TEST_CASE("cache_store hscan filtering on the field's value")
{
    cache_store store;
    store.hset("t", "f1", "berlin");
    store.hset("t", "f2", "hamburg");
    store.hset("t", "f3", "berlin");
    store.hset("t", "f4", "");

    using pairs = std::vector<std::pair<std::string_view, std::string_view>>;
    auto names = [](const pairs& p) {
        std::set<std::string_view> s;
        for (auto& [f, v] : p) s.insert(f);
        return s;
    };

    SUBCASE("without a predicate it is every field, as before")
    {
        pairs got;
        CHECK(store.hscan("t", 0, "*", 100000, got) == 0);
        CHECK(got.size() == 4);
    }

    SUBCASE("with one it is the fields holding that value")
    {
        std::string_view berlin = "berlin";
        pairs got;
        CHECK(store.hscan("t", 0, "*", 100000, got, &berlin) == 0);
        auto n = names(got);
        CHECK(n.size() == 2);
        CHECK(n.count("f1") == 1);
        CHECK(n.count("f3") == 1);
    }

    SUBCASE("absent is not empty here either")
    {
        std::string_view empty = "";
        pairs got;
        CHECK(store.hscan("t", 0, "*", 100000, got, &empty) == 0);
        REQUIRE(got.size() == 1);
        CHECK(got[0].first == "f4");
    }

    SUBCASE("the field pattern and the value predicate are both required")
    {
        std::string_view berlin = "berlin";
        pairs got;
        CHECK(store.hscan("t", 0, "f1*", 100000, got, &berlin) == 0);
        REQUIRE(got.size() == 1);
        CHECK(got[0].first == "f1");
    }

    SUBCASE("count bounds the fields examined once there is a predicate")
    {
        for (int i = 0; i < 400; i++)
            store.hset("t", "g" + std::to_string(i), "hamburg");
        std::string_view nowhere = "atlantis";
        pairs got;
        const uint64_t next = store.hscan("t", 0, "*", 4, got, &nowhere);
        CHECK(got.empty());
        CHECK(next != 0);
    }

    SUBCASE("and a whole paged round still finds every match")
    {
        for (int i = 0; i < 400; i++)
            store.hset("t", "g" + std::to_string(i), i % 5 == 0 ? "berlin" : "hamburg");
        std::string_view berlin = "berlin";
        std::set<std::string_view> seen;
        uint64_t cur = 0;
        int guard = 0;
        do {
            pairs page;
            cur = store.hscan("t", cur, "*", 8, page, &berlin);
            for (auto& [f, v] : page) { CHECK(v == "berlin"); seen.insert(f); }
            REQUIRE(++guard < 10000);
        } while (cur != 0);
        CHECK(seen.size() == 82);          // 80 of the g's, plus f1 and f3
    }
}

// A glob cannot say "between 20 and 30", and that is the one question a store
// full of records is asked that none of the other filters can answer.
TEST_CASE("cache_store scan filtering on a numeric range")
{
    using vr = cache_store::scan_filter::value_range;
    cache_store store;
    store.set("n:10", "10");
    store.set("n:20", "20");
    store.set("n:30", "30");
    store.set("n:f",  "25.5");
    store.set("n:na", "30kg");
    store.set("n:e",  "");
    // from_chars reads all three of these as numbers.  Two of them are numbers.
    store.set("n:nan", "nan");
    store.set("n:NAN", "NaN");
    store.set("n:inf", "inf");
    store.hset("u:1", "age", "30");
    store.hset("u:2", "age", "22");
    store.hset("u:3", "age", "older than that");

    auto names = [&](cache_store::scan_filter f) {
        std::vector<std::string_view> out;
        CHECK(store.scan(0, "*", 100000, out, f) == 0);
        return std::set<std::string_view>(out.begin(), out.end());
    };

    SUBCASE("the bounds are inclusive unless asked otherwise")
    {
        vr inc{10, 30, true, true};
        auto a = names(cache_store::scan_filter::one(nullptr, -1, false, nullptr, &inc));
        CHECK(a == std::set<std::string_view>{"n:10", "n:20", "n:30", "n:f"});

        vr exc{10, 30, false, false};
        auto b = names(cache_store::scan_filter::one(nullptr, -1, false, nullptr, &exc));
        CHECK(b == std::set<std::string_view>{"n:20", "n:f"});
    }

    SUBCASE("a value that is not a number matches no range at all")
    {
        // Not even this one, which every number matches.  from_chars would
        // happily read the 30 out of "30kg" and stop; the whole of the value has
        // to be the number or it is not one.
        vr all{-std::numeric_limits<double>::infinity(),
                std::numeric_limits<double>::infinity(), true, true};
        auto got = names(cache_store::scan_filter::one(nullptr, -1, false, nullptr, &all));
        CHECK(got.count("n:na") == 0);
        CHECK(got.count("n:e")  == 0);
        CHECK(got.count("n:10") == 1);
        CHECK(got.count("n:f")  == 1);
        // An infinity IS a number and belongs in the range that spans
        // everything; a NaN is not, and belongs in none.
        CHECK(got.count("n:inf") == 1);
        CHECK(got.count("n:nan") == 0);
        CHECK(got.count("n:NAN") == 0);
    }

    SUBCASE("and NaN is in no range at all, not even one it is nowhere near")
    {
        // This is the one the comparisons cannot catch by themselves: every
        // comparison against NaN is false, so a range that only asks "not below
        // and not above" contains it.  Measured before the guard: a valuerange
        // of 100 to 200 answered with a value of "nan".
        for (auto [lo, hi] : { std::pair{100.0, 200.0}, std::pair{-1.0, 0.0},
                               std::pair{0.0, 0.0} })
        {
            vr r{lo, hi, true, true};
            auto got = names(cache_store::scan_filter::one(nullptr, -1, false, nullptr, &r));
            CHECK(got.count("n:nan") == 0);
            CHECK(got.count("n:NAN") == 0);
        }
    }

    SUBCASE("a range and a glob are both required")
    {
        std::string_view two = "2*";
        vr r{10, 30, true, true};
        auto got = names(cache_store::scan_filter::one(&two, -1, false, nullptr, &r));
        CHECK(got == std::set<std::string_view>{"n:20", "n:f"});
    }

    SUBCASE("with a field it is the field that has to be in range")
    {
        std::string_view age = "age";
        vr r{25, 40, true, true};
        auto got = names(cache_store::scan_filter::one(nullptr, -1, false, &age, &r));
        REQUIRE(got.size() == 1);
        CHECK(got.count("u:1") == 1);
    }

    SUBCASE("a field whose value is not a number is not in any range either")
    {
        std::string_view age = "age";
        vr all{-std::numeric_limits<double>::infinity(),
                std::numeric_limits<double>::infinity(), true, true};
        auto got = names(cache_store::scan_filter::one(nullptr, -1, false, &age, &all));
        CHECK(got == std::set<std::string_view>{"u:1", "u:2"});
    }
}

// inf plus -inf is NaN, and a NaN score is in every range and in none.  It also
// broke the store's own "did that work" check, which compares the score it read
// back against the one it wrote -- and NaN equals nothing, including itself.
TEST_CASE("cache_store zincrby refuses a result that is not a number")
{
    using zr = cache_store::zincr_result;
    cache_store store;

    SUBCASE("an ordinary increment still works")
    {
        double out = 0;
        CHECK(store.zincrby("z", 5.0, "m", out) == zr::ok);
        CHECK(out == 5.0);
        CHECK(store.zincrby("z", 2.5, "m", out) == zr::ok);
        CHECK(out == 7.5);
        double sc = 0;
        CHECK(store.zscore("z", "m", sc));
        CHECK(sc == 7.5);
    }

    SUBCASE("an infinite score is allowed, because a zset may hold one")
    {
        double out = 0;
        CHECK(store.zincrby("z", std::numeric_limits<double>::infinity(), "m", out) == zr::ok);
        CHECK(std::isinf(out));
        double sc = 0;
        CHECK(store.zscore("z", "m", sc));
        CHECK(std::isinf(sc));
    }

    SUBCASE("but an increment that would make it NaN is refused")
    {
        double out = 0;
        REQUIRE(store.zincrby("z", std::numeric_limits<double>::infinity(), "m", out) == zr::ok);
        CHECK(store.zincrby("z", -std::numeric_limits<double>::infinity(), "m", out)
              == zr::not_a_number);

        // And refused BEFORE the write: the member still holds what it held.
        double sc = 0;
        REQUIRE(store.zscore("z", "m", sc));
        CHECK(std::isinf(sc));
        CHECK(sc > 0);
    }

    SUBCASE("a type conflict is still its own answer")
    {
        store.set("s", "not a zset");
        double out = 0;
        CHECK(store.zincrby("s", 1.0, "m", out) == zr::type_conflict);
    }

    SUBCASE("a member that moves is found at its new rank, small and big")
    {
        for (const int n : { 10, static_cast<int>(zskiplist::SMALL_MAX) + 20 })
        {
            const std::string key = "r" + std::to_string(n);
            for (int i = 0; i < n; ++i) store.zadd(key, i, "m" + std::to_string(i));
            double out = 0;
            CHECK(store.zincrby(key, n + 0.5, "m0", out) == zr::ok);     // first to last
            CHECK(out == n + 0.5);
            CHECK(store.zincrby(key, 0.0, "m1", out) == zr::ok);         // no move at all
            CHECK(out == 1.0);
            size_t rank = 0;
            REQUIRE(store.zrank(key, "m0", rank, false));
            CHECK(rank == static_cast<size_t>(n - 1));
            REQUIRE(store.zrank(key, "m1", rank, false));
            CHECK(rank == 0);
            CHECK(store.zcard(key) == static_cast<size_t>(n));
            double sc = 0;
            REQUIRE(store.zscore(key, "m0", sc));
            CHECK(sc == n + 0.5);
        }
    }
}

// Two things asked of one key at once, which is the question a store full of
// records is asked and the one a single predicate cannot express.
TEST_CASE("cache_store scan with more than one predicate")
{
    using vr = cache_store::scan_filter::value_range;
    cache_store store;
    store.hset("u:1", "city", "berlin");  store.hset("u:1", "age", "30");
    store.hset("u:2", "city", "berlin");  store.hset("u:2", "age", "55");
    store.hset("u:3", "city", "hamburg"); store.hset("u:3", "age", "30");
    store.hset("u:4", "city", "berlin");
    store.set("plain", "berlin");

    std::string_view f_city = "city", f_age = "age", berlin = "berlin";
    vr r25_40{25, 40, true, true};

    auto run = [&](cache_store::scan_filter f) {
        std::vector<std::string_view> out;
        CHECK(store.scan(0, "*", 100000, out, f) == 0);
        return std::set<std::string_view>(out.begin(), out.end());
    };

    SUBCASE("each on its own, so the conjunction has something to be between")
    {
        CHECK(run(cache_store::scan_filter::one(&berlin, -1, false, &f_city))
              == std::set<std::string_view>{"u:1", "u:2", "u:4"});
        CHECK(run(cache_store::scan_filter::one(nullptr, -1, false, &f_age, &r25_40))
              == std::set<std::string_view>{"u:1", "u:3"});
    }

    SUBCASE("and together they are the intersection, not the union")
    {
        cache_store::scan_filter f;
        f.preds[0] = { &f_city, &berlin, nullptr };
        f.preds[1] = { &f_age,  nullptr, &r25_40 };
        f.pred_count = 2;
        CHECK(run(f) == std::set<std::string_view>{"u:1"});

        // Order is not part of the answer: a conjunction commutes and a walk
        // that let the last predicate win would not.
        cache_store::scan_filter g;
        g.preds[0] = { &f_age,  nullptr, &r25_40 };
        g.preds[1] = { &f_city, &berlin, nullptr };
        g.pred_count = 2;
        CHECK(run(g) == run(f));
    }

    SUBCASE("a field a hash does not have fails the conjunction")
    {
        // u:4 has city=berlin and no age at all, so it answers the first
        // predicate and cannot answer the second.
        std::string_view nowhere = "*";
        cache_store::scan_filter f;
        f.preds[0] = { &f_city, &berlin, nullptr };
        f.preds[1] = { &f_age,  &nowhere, nullptr };
        f.pred_count = 2;
        CHECK(run(f) == std::set<std::string_view>{"u:1", "u:2"});
    }

    SUBCASE("two predicates on the key's own value are two tests of one string")
    {
        std::string_view ber = "*berlin*", star_n = "*n";
        cache_store::scan_filter f;
        f.preds[0] = { nullptr, &ber,    nullptr };
        f.preds[1] = { nullptr, &star_n, nullptr };
        f.pred_count = 2;
        CHECK(run(f) == std::set<std::string_view>{"plain"});

        std::string_view star_z = "*z";
        cache_store::scan_filter g;
        g.preds[0] = { nullptr, &ber,    nullptr };
        g.preds[1] = { nullptr, &star_z, nullptr };
        g.pred_count = 2;
        CHECK(run(g).empty());
    }
}

// string_equal compares short keys with overlapping word loads rather than a
// call into libc, which is worth 3.9 per cent of a pipelined cache and is the
// one shape of code that can read past a string without any test noticing.
// Every length from zero to forty, every position of a differing byte, and
// every mismatched pair of lengths.
TEST_CASE("string_equal agrees with == at every length and every difference")
{
    string_equal eq;

    for (size_t n = 0; n <= 40; ++n)
    {
        std::string a(n, 'x');
        for (size_t i = 0; i < n; ++i)
            a[i] = static_cast<char>('a' + (i % 26));

        CHECK(eq(std::string_view(a), std::string_view(a)) == true);

        const std::string same = a;
        CHECK(eq(std::string_view(a), std::string_view(same)) == (a == same));

        for (size_t i = 0; i < n; ++i)
        {
            // Two different single-byte edits, because one of them lands on a
            // byte whose case flip is a no-op for some alphabets.
            std::string c = a;
            c[i] = static_cast<char>(c[i] ^ 0x20);
            CHECK(eq(std::string_view(a), std::string_view(c)) == (a == c));

            std::string d = a;
            d[i] = static_cast<char>(d[i] ^ 0x01);
            CHECK(eq(std::string_view(a), std::string_view(d)) == (a == d));
        }

        for (size_t m = 0; m <= 40; ++m)
        {
            if (m == n)
                continue;
            const std::string e(m, 'a');
            CHECK(eq(std::string_view(a), std::string_view(e)) == (a == e));
        }
    }
}

// The same key looked up through a string_view must land on the entry a
// std::string put there, which is the whole point of the transparent pair and
// what a hand-written comparison could break without any store test noticing.
TEST_CASE("a hand-written comparison still finds what the store put there")
{
    cache_store store;

    const char* shapes[] = { "", "a", "ab", "abc", "abcd", "abcdefg", "abcdefgh",
                             "abcdefghi", "k:000000000123", "abcdefghijklmnop",
                             "abcdefghijklmnopq",
                             "a-considerably-longer-key-than-sixteen-bytes" };
    for (const char* s : shapes)
    {
        CHECK(store.set(s, std::string("v") + s));
        std::string out;
        CHECK(store.get(std::string_view(s), out));
        CHECK(out == std::string("v") + s);
    }

    // And a near miss at every one of those lengths is still a miss.
    for (const char* s : shapes)
    {
        std::string near = s;
        if (near.empty())
            continue;
        near.back() = static_cast<char>(near.back() ^ 0x01);
        std::string out;
        CHECK_FALSE(store.get(std::string_view(near), out));
    }
}

// ─── key_table: the keyspace's own hash table ───

TEST_CASE("key_table finds what it holds and nothing else")
{
    key_table<std::string> t;
    CHECK(t.empty());
    CHECK(t.find("a") == t.end());
    for (int i = 0; i < 10000; ++i)
        CHECK(t.try_emplace("key:" + std::to_string(i), std::to_string(i)).second);
    CHECK(t.size() == 10000);
    CHECK_FALSE(t.try_emplace("key:17", "x").second);
    for (int i = 0; i < 10000; ++i)
    {
        auto it = t.find("key:" + std::to_string(i));
        REQUIRE(it != t.end());
        CHECK(it->first == "key:" + std::to_string(i));
        CHECK(it->second == std::to_string(i));
    }
    CHECK(t.find("key:10000") == t.end());
    CHECK(t.count("") == 0);
    t.try_emplace("", "empty key");
    CHECK(t.find("")->second == "empty key");
}

TEST_CASE("key_table erase leaves every other key reachable")
{
    key_table<int> t;
    std::set<int> live;
    for (int i = 0; i < 5000; ++i) { t.try_emplace(std::to_string(i), i); live.insert(i); }
    // Every third key out, then half of them back, so probes cross tombstones.
    for (int i = 0; i < 5000; i += 3) { CHECK(t.erase(std::to_string(i)) == 1); live.erase(i); }
    for (int i = 0; i < 5000; i += 6) { t.try_emplace(std::to_string(i), i); live.insert(i); }
    CHECK(t.size() == live.size());
    for (int i = 0; i < 5000; ++i)
        CHECK((t.find(std::to_string(i)) != t.end()) == (live.count(i) == 1));
    size_t walked = 0;
    for (const auto& [k, v] : t) { CHECK(k == std::to_string(v)); ++walked; }
    CHECK(walked == live.size());
}

TEST_CASE("key_table erase while iterating visits each entry once")
{
    key_table<int> t;
    for (int i = 0; i < 1000; ++i) t.try_emplace(std::to_string(i), i);
    std::set<int> seen;
    for (auto it = t.begin(); it != t.end();)
    {
        CHECK(seen.insert(it->second).second);
        if (it->second % 2) it = t.erase(it); else ++it;
    }
    CHECK(seen.size() == 1000);
    CHECK(t.size() == 500);
}

TEST_CASE("key_table churn at a steady size does not grow the table without end")
{
    key_table<int> t;
    for (int i = 0; i < 100; ++i) t.try_emplace(std::to_string(i), i);
    const size_t cap = t.bucket_count();
    for (int i = 100; i < 200000; ++i)
    {
        t.try_emplace(std::to_string(i), i);
        CHECK(t.erase(std::to_string(i - 100)) == 1);
    }
    CHECK(t.size() == 100);
    CHECK(t.bucket_count() <= cap * 2);
    for (int i = 200000 - 100; i < 200000; ++i) CHECK(t.count(std::to_string(i)) == 1);
}

TEST_CASE("key_table insert_or_assign, operator[] and clear")
{
    key_table<std::string> t;
    CHECK(t.insert_or_assign(std::string("k"), std::string("1")).second);
    CHECK_FALSE(t.insert_or_assign(std::string("k"), std::string("2")).second);
    CHECK(t.find("k")->second == "2");
    t["n"] += "x";
    CHECK(t.find("n")->second == "x");
    const uint32_t before = t.scan_epoch();
    t.clear();
    CHECK(t.empty());
    CHECK(t.bucket_count() == 0);
    CHECK(t.scan_epoch() != before);
    CHECK(t.find("k") == t.end());
}

TEST_CASE("key_table values keep their address across growth")
{
    key_table<std::string> t;
    t.try_emplace("anchor", "value");
    const std::string* p = &t.find("anchor")->second;
    for (int i = 0; i < 50000; ++i) t.try_emplace(std::to_string(i), "v");
    CHECK(&t.find("anchor")->second == p);
}

TEST_CASE("SCAN over a keyspace with deletes between pages returns every key that stayed")
{
    cache_store store;
    for (int i = 0; i < 20000; ++i) store.set("k" + std::to_string(i), "v");
    std::set<std::string> got;
    uint64_t cursor = 0;
    int page = 0;
    do
    {
        std::vector<std::string_view> out;
        cursor = store.scan(cursor, "*", 100, out);
        for (auto k : out) got.insert(std::string(k));
        // Deleting between pages leaves tombstones, which must not move anyone.
        if (++page % 3 == 0)
            for (int j = 0; j < 20; ++j) store.del("k" + std::to_string((page * 20 + j) % 20000));
    } while (cursor != 0);
    for (int i = 0; i < 20000; ++i)
    {
        const std::string k = "k" + std::to_string(i);
        if (store.exists(k)) CHECK(got.count(k) == 1);
    }
}


// A skiplist entry against the model's pair: the list answers the member as a
// view, and std::pair compares only like with like.
static bool same_entry(const zskiplist::entry& a, const std::pair<double, std::string>& b)
{
    return a.first == b.first && a.second == b.second;
}

TEST_CASE("zskiplist agrees with an ordered set through inserts, moves and removals")
{
    zskiplist z;
    std::set<std::pair<double, std::string>> ref;
    std::map<std::string, double> score;
    uint32_t r = 12345;
    auto rnd = [&] { r ^= r << 13; r ^= r >> 17; r ^= r << 5; return r; };
    for (int step = 0; step < 60000; ++step)
    {
        // Long names too, so the member lives outside the string object.
        const std::string m = (rnd() % 3 ? "m" : "a-member-name-past-sso-") + std::to_string(rnd() % 2000);
        const double sc = static_cast<double>(rnd() % 500);
        auto it = score.find(m);
        if (rnd() % 4 == 0)
        {
            if (it != score.end())
            {
                CHECK(z.erase(it->second, m) == 1);
                ref.erase({ it->second, m });
                score.erase(it);
            }
            else
                CHECK(z.erase(sc, m) == 0);
        }
        else if (it != score.end())
        {
            REQUIRE(z.rescore(it->second, m, sc));
            ref.erase({ it->second, m });
            ref.insert({ sc, m });
            it->second = sc;
        }
        else
        {
            z.emplace(sc, m);
            ref.insert({ sc, m });
            score[m] = sc;
        }
        if (step % 5000 == 0 || step == 59999)
        {
            REQUIRE(z.size() == ref.size());
            size_t i = 0;
            for (auto zit = z.begin(); zit != z.end(); ++zit, ++i)
            {
                auto rit = std::next(ref.begin(), static_cast<long>(i));
                CHECK(same_entry(*zit, *rit));
                CHECK(z.rank(rit->first, rit->second) == i);
                CHECK(same_entry(*z.at(i), *rit));
            }
            if (!ref.empty())
                CHECK(same_entry(*std::prev(z.end()), *ref.rbegin()));
            // Backwards too, and every member found by name at its score:
            // a moved node keeps its back link and its index slot.
            if (!ref.empty())
            {
                auto zit = z.last();
                for (auto rit = ref.rbegin();; --zit)
                {
                    REQUIRE(same_entry(*zit, *rit));
                    if (++rit == ref.rend()) break;
                }
            }
            for (const auto& [name, sc] : score)
            {
                double got = -1.0;
                REQUIRE(z.score_of(name, got));
                CHECK(got == sc);
            }
        }
    }
    zskiplist copy(z);
    CHECK(copy.size() == z.size());
    zskiplist moved(std::move(copy));
    CHECK(moved.size() == z.size());
}

TEST_CASE("field_map agrees with a map, packed and after it moves to the table")
{
    uint32_t r = 777;
    auto rnd = [&] { r ^= r << 13; r ^= r >> 17; r ^= r << 5; return r; };
    for (int round = 0; round < 40; ++round)
    {
        field_map fm;
        std::map<std::string, std::string> ref;
        // Most rounds stay small and packed; some grow past either bound.
        const int fields = (round % 4 == 0) ? 300 : 12;
        const bool long_values = (round % 5 == 0);
        for (int step = 0; step < 2000; ++step)
        {
            const std::string f = "f" + std::to_string(rnd() % fields);
            const size_t vlen = long_values ? rnd() % 100 : rnd() % 20;
            const std::string v(vlen, static_cast<char>('a' + rnd() % 26));
            switch (rnd() % 4)
            {
                case 0:
                    CHECK(fm.erase(f) == (ref.erase(f) == 1));
                    break;
                default:
                {
                    const bool is_new = ref.find(f) == ref.end();
                    CHECK(fm.set(f, v) == is_new);
                    ref[f] = v;
                    break;
                }
            }
            REQUIRE(fm.size() == ref.size());
        }
        for (const auto& [f, v] : ref)
        {
            std::string_view got;
            REQUIRE(fm.get(f, got));
            CHECK(got == v);
        }
        std::map<std::string, std::string> walked;
        for (const auto& [f, v] : fm) walked.emplace(std::string(f), std::string(v));
        CHECK(walked == ref);
        // HSCAN's walk: every bucket, every entry once.
        std::map<std::string, std::string> scanned;
        for (size_t b = 0; b < fm.bucket_count(); ++b)
            for (auto it = fm.begin(b); it != fm.end(b); ++it)
                CHECK(scanned.emplace(std::string((*it).first), std::string((*it).second)).second);
        CHECK(scanned == ref);
        field_map copy(fm);
        CHECK(copy.size() == fm.size());
        if (fields == 12 && !long_values) CHECK(fm.packed());
        if (fields == 300) CHECK_FALSE(fm.packed());
    }
}

TEST_CASE("a small hash is packed and a large one is not, through the store")
{
    cache_store store;
    for (int i = 0; i < 5; ++i) store.hset("small", "field" + std::to_string(i), "value");
    CHECK(store.hash_ptr("small")->packed());
    for (int i = 0; i < 200; ++i) store.hset("large", "field" + std::to_string(i), "value");
    CHECK_FALSE(store.hash_ptr("large")->packed());
    store.hset("longval", "f", std::string(100, 'x'));
    CHECK_FALSE(store.hash_ptr("longval")->packed());
    CHECK(store.hget("longval", "f") == std::string(100, 'x'));
    CHECK(store.hlen("large") == 200);
    CHECK(store.hdel("small", "field2"));
    CHECK(store.hlen("small") == 4);
    CHECK_FALSE(store.hget("small", "field2").has_value());
}

TEST_CASE("zset_inner agrees with a model, small and after the skiplist takes over")
{
    uint32_t r = 4242;
    auto rnd = [&] { r ^= r << 13; r ^= r >> 17; r ^= r << 5; return r; };
    for (int round = 0; round < 30; ++round)
    {
        zset_inner z;
        std::map<std::string, double> score;
        std::set<std::pair<double, std::string>> ord;
        const int universe = (round % 3 == 0) ? 400 : 60;   // 400 crosses SMALL_MAX
        for (int step = 0; step < 3000; ++step)
        {
            const std::string m = (rnd() % 2 ? "m" : "a-long-member-name-") + std::to_string(rnd() % universe);
            const double sc = static_cast<double>(rnd() % 50);
            auto it = score.find(m);
            if (rnd() % 5 == 0)
            {
                if (it != score.end())
                {
                    z.remove(m, it->second);
                    ord.erase({ it->second, m });
                    score.erase(it);
                }
            }
            else if (it != score.end())
            {
                z.rescore(m, it->second, sc);
                ord.erase({ it->second, m });
                ord.insert({ sc, m });
                it->second = sc;
            }
            else
            {
                z.add(sc, m);
                ord.insert({ sc, m });
                score[m] = sc;
            }
            REQUIRE(z.size() == score.size());
        }
        size_t i = 0;
        for (auto it = z.order.begin(); it != z.order.end(); ++it, ++i)
        {
            const auto& want = *std::next(ord.begin(), static_cast<long>(i));
            CHECK(same_entry(*it, want));
            CHECK(z.order.rank(want.first, want.second) == i);
            CHECK(same_entry(*z.order.at(i), want));
        }
        CHECK(i == ord.size());
        for (const auto& [m, sc] : score)
        {
            double got = -1;
            REQUIRE(z.score_of(m, got));
            CHECK(got == sc);
        }
        double none = 0;
        CHECK_FALSE(z.score_of("absent", none));
        // The first member at or past 25, as ZRANGEBYSCORE finds it.
        auto lb = z.order.lower_bound_score(25.0, true);
        auto rl = std::find_if(ord.begin(), ord.end(), [](const auto& e) { return e.first >= 25.0; });
        CHECK((lb == z.order.end()) == (rl == ord.end()));
        if (rl != ord.end()) CHECK(same_entry(*lb, *rl));
        if (!ord.empty()) CHECK(same_entry(*std::prev(z.order.end()), *ord.rbegin()));
        // ZSCAN's walk visits every member once with its score.
        std::map<std::string, double> scanned;
        for (size_t b = 0; b < z.bucket_count(); ++b)
            for (auto it = z.begin(b); it != z.end(b); ++it)
                CHECK(scanned.emplace(std::string((*it).first), (*it).second).second);
        CHECK(scanned == score);
        zset_inner copy(z);
        CHECK(copy.size() == z.size());
        // Sixty members never outgrow the vector; four hundred always did.
        if (universe == 60) CHECK_FALSE(z.order.big());
        else                CHECK(z.order.big());
    }
}

TEST_CASE("seg_list agrees with a deque through both ends and the middle")
{
    uint32_t r = 99;
    auto rnd = [&] { r ^= r << 13; r ^= r >> 17; r ^= r << 5; return r; };
  // Kept under 100 the whole run, and left to grow into thousands of blocks
  // with the map ring wrapping at both ends.
  for (const size_t cap : { size_t{100}, size_t{1} << 30 })
  {
    seg_list ring;
    std::deque<std::string> ref;
    for (int step = 0; step < 50000; ++step)
    {
        while (ref.size() >= cap) { ring.pop_back(); ref.pop_back(); }
        // Past SSO now and then, so a move that loses the heap block shows.
        const std::string v = (rnd() % 3 ? "v" : std::string(40, 'L')) + std::to_string(step);
        switch (rnd() % 8)
        {
            case 0: ring.push_front(v); ref.push_front(v); break;
            case 1: ring.emplace_back(v); ref.emplace_back(v); break;
            case 2: if (!ref.empty()) { ring.pop_front(); ref.pop_front(); } break;
            case 3: if (!ref.empty()) { ring.pop_back(); ref.pop_back(); } break;
            case 4:
            {
                const size_t i = ref.empty() ? 0 : rnd() % (ref.size() + 1);
                ring.insert(ring.begin() + static_cast<long>(i), v);
                ref.insert(ref.begin() + static_cast<long>(i), v);
                break;
            }
            case 5:
                if (!ref.empty())
                {
                    const size_t i = rnd() % ref.size();
                    ring.erase(ring.begin() + static_cast<long>(i));
                    ref.erase(ref.begin() + static_cast<long>(i));
                }
                break;
            case 6: if (!ref.empty()) { const size_t i = rnd() % ref.size(); ring[i] = v; ref[i] = v; } break;
            default: ring.push_back(v); ref.push_back(v); break;
        }
        REQUIRE(ring.size() == ref.size());
        if (step % 997 == 0)
        {
            for (size_t i = 0; i < ref.size(); ++i) REQUIRE(ring[i] == ref[i]);
            if (!ref.empty()) { CHECK(ring.front() == ref.front()); CHECK(ring.back() == ref.back()); }
            seg_list copy(ring);
            CHECK(copy == ring);
            seg_list moved(std::move(copy));
            CHECK(moved == ring);
        }
    }
    size_t i = 0;
    for (const auto& s : ring) CHECK(s == ref[i++]);
    // Backwards from end(), as LREM with a negative count walks it.
    auto e = ring.end();
    size_t j = ref.size();
    while (e != ring.begin()) { --e; CHECK(*e == ref[--j]); }
    ring.clear();
    CHECK(ring.empty());
  }
}

TEST_CASE("seg_list taken from one end only, emptied and refilled")
{
    seg_list l;
    std::deque<std::string> ref;
    for (int round = 0; round < 3; ++round)
    {
        // LPUSH only: every eighth push takes a block in front, and the map
        // ring wraps backwards.
        for (int i = 0; i < 1000; ++i) { l.push_front(std::to_string(i)); ref.push_front(std::to_string(i)); }
        for (size_t i = 0; i < ref.size(); ++i) REQUIRE(l[i] == ref[i]);
        // RPOP to empty, then LPOP from a list refilled from the back.
        while (!ref.empty()) { REQUIRE(l.back() == ref.back()); l.pop_back(); ref.pop_back(); }
        CHECK(l.empty());
        for (int i = 0; i < 20; ++i) { l.push_back("x" + std::to_string(i)); ref.push_back("x" + std::to_string(i)); }
        while (!ref.empty()) { REQUIRE(l.front() == ref.front()); l.pop_front(); ref.pop_front(); }
        CHECK(l.empty());
    }
}

TEST_CASE("list_items agrees with a deque, packed and after it moves to the seg_list")
{
    uint32_t r = 31337;
    auto rnd = [&] { r ^= r << 13; r ^= r >> 17; r ^= r << 5; return r; };
    for (int round = 0; round < 60; ++round)
    {
        list_items l;
        std::deque<std::string> ref;
        const size_t cap = (round % 3 == 0) ? 200 : 20;      // 200 crosses PACK_MAX_ITEMS
        const bool long_values = (round % 5 == 0);           // and 100 bytes crosses PACK_MAX_LEN
        for (int step = 0; step < 1500; ++step)
        {
            const size_t vlen = long_values ? rnd() % 100 : rnd() % 20;
            const std::string v(vlen, static_cast<char>('a' + rnd() % 26));
            switch (rnd() % 9)
            {
                case 0: if (ref.size() < cap) { l.push_front(v); ref.push_front(v); } break;
                case 1: if (ref.size() < cap) { l.push_back(v); ref.push_back(v); } break;
                case 2: if (!ref.empty()) { std::string o; l.pop_front(o); CHECK(o == ref.front()); ref.pop_front(); } break;
                case 3: if (!ref.empty()) { std::string o; l.pop_back(o); CHECK(o == ref.back()); ref.pop_back(); } break;
                case 4: if (!ref.empty()) { const size_t i = rnd() % ref.size(); l.set(i, v); ref[i] = v; } break;
                case 5: if (!ref.empty()) { const size_t i = rnd() % ref.size(); l.erase(i); ref.erase(ref.begin() + static_cast<long>(i)); } break;
                case 6: if (ref.size() < cap) { const size_t i = rnd() % (ref.size() + 1); l.insert(i, v); ref.insert(ref.begin() + static_cast<long>(i), v); } break;
                default: if (ref.size() < cap) { l.push_back(v); ref.push_back(v); } break;
            }
            REQUIRE(l.size() == ref.size());
            if (!ref.empty()) { REQUIRE(l.front() == ref.front()); REQUIRE(l.back() == ref.back()); }
        }
        size_t i = 0;
        for (auto e = l.begin(); e != l.end(); ++e, ++i) CHECK(*e == ref[i]);
        CHECK(i == ref.size());
        size_t j = ref.size();
        for (auto e = l.end(); e != l.begin(); ) { --e; CHECK(*e == ref[--j]); }
        for (size_t k = 0; k < ref.size(); ++k) CHECK(l.at(k) == ref[k]);
        if (!ref.empty())
        {
            const size_t s = rnd() % ref.size();
            auto e = l.iterator_at(s);
            for (size_t k = s; k < ref.size(); ++k, ++e) CHECK(*e == ref[k]);
        }
        list_items copy(l);
        CHECK(copy == l);
        if (cap == 20 && !long_values) CHECK(l.packed());
    }
}

TEST_CASE("a sorted set moves to the skiplist for a long member and stays ordered")
{
    zset_inner z;
    for (int i = 0; i < 10; ++i) z.add(static_cast<double>(i), "m" + std::to_string(i));
    CHECK_FALSE(z.order.big());
    const std::string long_name(100, 'L');
    z.add(4.5, long_name);
    CHECK(z.order.big());
    REQUIRE(z.size() == 11);
    double sc = 0;
    REQUIRE(z.score_of(long_name, sc));
    CHECK(sc == 4.5);
    CHECK(z.order.rank(4.5, long_name) == 5);
    CHECK((*z.order.at(5)).second == long_name);
    z.rescore("m0", 0.0, 99.0);
    CHECK((*std::prev(z.order.end())).second == "m0");
    z.remove(long_name, 4.5);
    CHECK(z.size() == 10);
    CHECK_FALSE(z.score_of(long_name, sc));
}

// Both flavours, because the one with room of its own moves its bytes rather
// than its pointer, and a move that forgot to was a view into the source.
template <class Buf>
static void pack_buf_agrees_with_a_string(uint32_t seed)
{
    uint32_t r = seed;
    auto rnd = [&] { r ^= r << 13; r ^= r >> 17; r ^= r << 5; return r; };
    Buf b;
    std::string ref;
    auto same = [&](const Buf& x, const std::string& s) {
        REQUIRE(x.size() == s.size());
        CHECK(std::string_view(x.data(), x.size()) == s);
    };
    for (int step = 0; step < 20000; ++step)
    {
        const std::string v(rnd() % 40, static_cast<char>('a' + rnd() % 26));
        switch (rnd() % 10)
        {
            case 0: case 1: case 2:
            {
                const size_t off = ref.empty() ? 0 : rnd() % (ref.size() + 1);
                b.insert(off, v.data(), v.size()); ref.insert(off, v);
                break;
            }
            case 3: if (!ref.empty()) { const size_t off = rnd() % ref.size(), n = rnd() % (ref.size() - off + 1);
                                        b.erase(off, n); ref.erase(off, n); } break;
            case 4: if (!ref.empty()) { const size_t off = rnd() % ref.size(), n = rnd() % (ref.size() - off + 1);
                                        b.replace(off, n, v.data(), v.size()); ref.replace(off, n, v); } break;
            case 5: if (!ref.empty()) { const size_t off = rnd() % (ref.size() + 1); b.truncate(off); ref.resize(off); } break;
            case 6: { Buf c(b); same(c, ref); Buf m(std::move(c)); same(m, ref); CHECK(c.size() == 0);
                      b = std::move(m); same(b, ref); } break;
            case 7: { Buf o; o.insert(0, v.data(), v.size()); b.swap(o); same(b, v); same(o, ref);
                      b.swap(o); same(b, ref); same(o, v); } break;
            case 8: { Buf c; c = b; same(c, ref); c.release(); CHECK(c.size() == 0); } break;
            default: if (ref.size() > 4000) { b.release(); ref.clear(); } break;
        }
        same(b, ref);
    }
}

TEST_CASE("pack_buf agrees with a string, with and without room of its own")
{
    pack_buf_agrees_with_a_string<basic_pack_buf<0>>(4242);
    pack_buf_agrees_with_a_string<basic_pack_buf<24>>(2424);
}

TEST_CASE("zskiplist moves and copies between its small and big forms")
{
    auto filled = [](int n, int name_len) {
        zskiplist z;
        for (int i = 0; i < n; ++i)
            z.emplace(static_cast<double>(i % 7), std::string(static_cast<size_t>(name_len), 'm') + std::to_string(i));
        return z;
    };
    auto listing = [](const zskiplist& z) {
        std::vector<std::pair<double, std::string>> v;
        for (auto e : z) v.emplace_back(e.first, std::string(e.second));
        return v;
    };
    for (const int n_a : { 0, 5, 300 })
        for (const int n_b : { 0, 5, 300 })
        {
            const zskiplist a0 = filled(n_a, 3), b0 = filled(n_b, 9);
            const auto la = listing(a0), lb = listing(b0);
            zskiplist a(a0), b(b0);
            CHECK(listing(a) == la);
            a = std::move(b);                       // either form over either form
            CHECK(listing(a) == lb);
            CHECK(b.empty());
            b.emplace(1.0, "after");                // a moved-from set is a usable empty one
            CHECK(b.size() == 1);
            b = a0;
            CHECK(listing(b) == la);
            zskiplist c(std::move(b));
            CHECK(listing(c) == la);
            c.clear();
            CHECK(c.empty());
            CHECK_FALSE(c.big());
            c.emplace(2.0, "x");
            CHECK(c.rank(2.0, "x") == 0);
        }
}

TEST_CASE("a small zskiplist keeps every score exactly through its compact widths")
{
    // Each side of every width's edge, the signs, the non-integers and the
    // values no integer holds; -0.0 last-but-not-least, since it compares equal
    // to 0 and an integer encoding would bring it back positive.
    const double scores[] = {
        0.0, -0.0, 1.0, -1.0, 127.0, 128.0, -128.0, -129.0,
        32767.0, 32768.0, -32768.0, -32769.0,
        2147483647.0, 2147483648.0, -2147483648.0, -2147483649.0,
        0.5, -2.25, 1e300, -1e300, 4503599627370497.0,
        std::numeric_limits<double>::infinity(), -std::numeric_limits<double>::infinity(),
        std::numeric_limits<double>::denorm_min() };
    auto same_bits = [](double a, double b) { return std::memcmp(&a, &b, sizeof a) == 0; };

    zskiplist z;
    std::vector<std::pair<double, std::string>> ref;
    int i = 0;
    for (const double sc : scores)
    {
        std::string m = "m" + std::to_string(i++);
        z.emplace(sc, m);
        ref.emplace_back(sc, std::move(m));
    }
    std::sort(ref.begin(), ref.end());
    REQUIRE_FALSE(z.big());
    REQUIRE(z.size() == ref.size());

    auto check_all = [&](const zskiplist& zz) {
        size_t k = 0;
        for (auto e : zz)
        {
            REQUIRE(k < ref.size());
            // Which of 0.0 and -0.0 sorts first is a matter of member name,
            // so the member decides which reference the score is checked on.
            const auto rit = std::find_if(ref.begin(), ref.end(), [&](const auto& r) { return r.second == e.second; });
            REQUIRE(rit != ref.end());
            CHECK(same_bits(e.first, rit->first));
            CHECK(zz.rank(rit->first, rit->second) == k);
            ++k;
        }
        CHECK(k == ref.size());
    };
    check_all(z);

    // Backwards over the same entries, which walks the trailing size byte.
    std::vector<std::string> back;
    for (auto it = z.last();; --it)
    {
        back.emplace_back((*it).second);
        if (it == z.begin()) break;
    }
    std::vector<std::string> fwd;
    for (auto e : z) fwd.emplace_back(e.second);
    std::reverse(back.begin(), back.end());
    CHECK(back == fwd);

    // Removing from the middle keeps the neighbours' encodings readable.
    for (const auto& r : std::vector<std::pair<double, std::string>>(ref))
        if (r.first == 32768.0 || r.first == 0.5)
        {
            CHECK(z.erase(r.first, r.second) == 1);
            ref.erase(std::find(ref.begin(), ref.end(), r));
        }
    check_all(z);

    // And through the move to the skiplist, scores still bit for bit.
    for (int j = 0; j < static_cast<int>(zskiplist::SMALL_MAX) + 10; ++j)
    {
        std::string m = "fill" + std::to_string(j);
        z.emplace(1000.0 + j, m);
        ref.emplace_back(1000.0 + j, std::move(m));
    }
    std::sort(ref.begin(), ref.end());
    REQUIRE(z.big());
    check_all(z);
}

TEST_CASE("zset_inner's member index follows its skiplist through copies and moves")
{
    auto filled = [](int n) {
        zset_inner z;
        for (int i = 0; i < n; ++i) z.add(i * 0.5, "m" + std::to_string(i));
        return z;
    };
    auto scores_ok = [](const zset_inner& z, int n) {
        for (int i = 0; i < n; ++i)
        {
            double sc = -1;
            if (!z.score_of("m" + std::to_string(i), sc) || sc != i * 0.5) return false;
        }
        double sc;
        return !z.score_of("absent", sc);
    };
    const int big = static_cast<int>(zskiplist::SMALL_MAX) + 50;
    for (const int n_a : { 0, 5, big })
        for (const int n_b : { 0, 5, big })
        {
            zset_inner a = filled(n_a), b = filled(n_b);
            zset_inner a2(a);                       // a copy builds its own index
            CHECK(scores_ok(a2, n_a));
            a = std::move(b);                       // the old index goes, b's moves in
            CHECK(scores_ok(a, n_b));
            CHECK(b.size() == 0);
            b = a2;                                 // copy-assign over an emptied one
            CHECK(scores_ok(b, n_a));
            zset_inner c(std::move(b));
            CHECK(scores_ok(c, n_a));
            c.add(99999.0, "late");
            double sc;
            CHECK((c.score_of("late", sc) && sc == 99999.0));
            c.remove("late", 99999.0);
            CHECK_FALSE(c.score_of("late", sc));
        }
}

TEST_CASE("zskiplist at() lands on the same entry from either end")
{
    // at() walks a small set from whichever end is nearer, so every index is
    // checked against the forward walk, across the move to the big form.
    for (const int n : { 0, 1, 2, 3, 7, 64, 127, 128, 129, 200 })
    {
        zskiplist z;
        for (int i = 0; i < n; ++i) z.emplace((i * 7919) % 101 - 50.5, "m" + std::to_string(i));
        std::vector<std::pair<double, std::string>> fwd;
        for (auto e : z) fwd.emplace_back(e.first, std::string(e.second));
        REQUIRE(fwd.size() == static_cast<size_t>(n));
        for (int i = 0; i < n; ++i)
        {
            auto it = z.at(static_cast<size_t>(i));
            REQUIRE(it != z.end());
            CHECK((*it).first == fwd[static_cast<size_t>(i)].first);
            CHECK((*it).second == fwd[static_cast<size_t>(i)].second);
            // And iterating on from there reaches the end in the right number of steps.
            size_t left = 0;
            for (auto j = it; j != z.end(); ++j) ++left;
            CHECK(left == static_cast<size_t>(n - i));
        }
        CHECK(z.at(static_cast<size_t>(n)) == z.end());
    }
}

TEST_CASE("a big zskiplist keeps member bytes exactly, the empty one and NULs included")
{
    // A member over SMALL_MAX_LEN makes the set big at once, so every name
    // below lives in a node's own block.
    const std::string long_name(100, 'L');
    const std::vector<std::string> names = {
        long_name, std::string(), std::string("\0a", 2), std::string("a\0", 2),
        std::string(15, 's'), std::string(16, 's'), std::string(1000, '\xff') };
    zskiplist z;
    std::vector<std::pair<double, std::string>> ref;
    for (size_t i = 0; i < names.size(); ++i)
    {
        z.emplace(static_cast<double>(i % 3), names[i]);
        ref.emplace_back(static_cast<double>(i % 3), names[i]);
    }
    REQUIRE(z.big());
    std::sort(ref.begin(), ref.end());
    size_t k = 0;
    for (auto e : z)
    {
        REQUIRE(k < ref.size());
        CHECK(e.first == ref[k].first);
        CHECK(e.second == ref[k].second);
        ++k;
    }
    CHECK(k == ref.size());

    // A member moved to the far end keeps its bytes, and a copy and a move keep them.
    REQUIRE(z.rescore(ref[2].first, ref[2].second, 1e9));
    ref.push_back({ 1e9, ref[2].second });
    ref.erase(ref.begin() + 2);
    {
        double sc = 0.0;
        REQUIRE(z.score_of(ref.back().second, sc));
        CHECK(sc == 1e9);
        CHECK((*z.last()).second == ref.back().second);
    }
    zskiplist c(z);
    zskiplist m(std::move(z));
    for (const zskiplist* zz : { &c, &m })
    {
        size_t j = 0;
        for (auto e : *zz) { CHECK(e.second == ref[j].second); ++j; }
        CHECK(j == ref.size());
    }
}

TEST_CASE("ZSCAN over a big sorted set returns every member, across a rebuild too")
{
    cache_store store;
    const int n = static_cast<int>(zskiplist::SMALL_MAX) * 4;
    for (int i = 0; i < n; ++i) store.zadd("z", i * 0.25, "member:" + std::to_string(i));

    auto scan_all = [&](int grow_after_pages) {
        std::map<std::string, double> seen;
        uint64_t cursor = 0;
        int pages = 0, added = 0;
        do
        {
            std::vector<std::pair<std::string_view, double>> page;
            cursor = store.zscan("z", cursor, "*", 10, page);
            for (const auto& [m, sc] : page) seen[std::string(m)] = sc;
            // Members added mid-scan force the index to rebuild under the cursor.
            if (++pages == grow_after_pages)
                for (; added < n; ++added)
                    store.zadd("z", -1.0, "late:" + std::to_string(added));
        } while (cursor != 0 && pages < 100000);
        return seen;
    };

    const auto seen = scan_all(-1);
    REQUIRE(seen.size() == static_cast<size_t>(n));
    for (int i = 0; i < n; ++i)
    {
        const auto it = seen.find("member:" + std::to_string(i));
        REQUIRE(it != seen.end());
        CHECK(it->second == i * 0.25);
    }

    // Every member that was there for the whole scan is returned at least once.
    const auto seen2 = scan_all(3);
    for (int i = 0; i < n; ++i)
        CHECK(seen2.count("member:" + std::to_string(i)) == 1);

    double sc = 0;
    CHECK(store.zscore("z", "late:7", sc));
    CHECK(sc == -1.0);
    CHECK_FALSE(store.zscore("z", "nobody", sc));
}

TEST_CASE("a packed list short enough to sit in place survives being moved")
{
    list_items a;
    a.push_back("one");
    a.push_back("two");
    REQUIRE(a.packed());
    list_items b(std::move(a));
    CHECK(b.size() == 2);
    CHECK(b.at(0) == "one");
    CHECK(b.at(1) == "two");
    list_items c;
    c.push_back("gone");
    c = std::move(b);
    CHECK(c.at(1) == "two");
    for (int i = 0; i < 20; ++i) c.push_back("more-than-fits-in-place");
    CHECK(c.at(0) == "one");
    CHECK(c.back() == "more-than-fits-in-place");
}

// What glibc's heap holds in use, arenas and mmapped blocks both, which is the
// resident memory the reported figure is a bound on.
namespace
{
    size_t heap_in_use()
    {
        const struct mallinfo2 m = mallinfo2();
        return m.uordblks + m.hblkhd;
    }

    // Under ASan the allocator is not glibc's and the figure above never moves.
    bool heap_is_visible()
    {
        const size_t before = heap_in_use();
        void* volatile p = std::malloc(size_t(1) << 20);
        const bool seen = heap_in_use() >= before + (size_t(1) << 20);
        std::free(p);
        return seen;
    }

    // The heap `grow` leaves held must not exceed what the store reports for
    // it, give or take `slack` and a sixteenth for what neither side sees
    // exactly: freed chunks glibc keeps in its thread cache, the split
    // remainders it hands out whole, and the key tables' own rounding.
    template <class F>
    void check_charged(cache_store& store, F&& grow, size_t slack = 32768)
    {
        if (!heap_is_visible())
        {
            MESSAGE("glibc's heap is not the allocator here, so there is nothing to measure");
            return;
        }
        const size_t real_before = heap_in_use();
        const size_t used_before = store.get_memory_used();
        grow();
        const int64_t real = static_cast<int64_t>(heap_in_use()) - static_cast<int64_t>(real_before);
        const int64_t used = static_cast<int64_t>(store.get_memory_used()) - static_cast<int64_t>(used_before);
        CAPTURE(real);
        CAPTURE(used);
        CHECK(real <= used + used / 16 + static_cast<int64_t>(slack));
    }
}

TEST_CASE("a value overwritten with less keeps no buffer the store does not charge")
{
    // assign() keeps the buffer it has, so a field set to 100 KB and then to
    // one byte went on holding the 100 KB while the store charged one byte, as
    // many times over as there were fields.
    const std::string big(100000, 'v');

    SUBCASE("a hash field in the table form")
    {
        cache_store store;
        check_charged(store, [&] {
            REQUIRE(store.hset("h", "long", std::string(100, 'l')));
            REQUIRE_FALSE(store.hash_ptr("h")->packed());
            for (int i = 0; i < 64; ++i)
            {
                const std::string f = "f" + std::to_string(i);
                REQUIRE(store.hset("h", f, big));
                REQUIRE(store.hset("h", f, "x"));
            }
        });
    }

    SUBCASE("a list element set by LSET")
    {
        cache_store store;
        check_charged(store, [&] {
            REQUIRE(store.rpush("l", std::string(100, 'l')));
            REQUIRE_FALSE(store.list_ptr("l")->packed());
            for (int i = 0; i < 64; ++i) REQUIRE(store.rpush("l", "s"));
            for (int i = 1; i <= 64; ++i)
            {
                REQUIRE(store.lset("l", i, big) == 0);
                REQUIRE(store.lset("l", i, "x") == 0);
            }
        });
    }

    SUBCASE("a list element that LREM shifts into a removed element's place")
    {
        // The shift move-assigns each element over the one before it, and a
        // short element moved over a long one is copied into the long one's
        // buffer rather than taking its own.
        cache_store store;
        check_charged(store, [&] {
            REQUIRE(store.rpush("l", std::string(100, 'l')));
            for (int i = 0; i < 64; ++i) REQUIRE(store.rpush("l", "s"));
            for (int i = 0; i < 64; ++i)
            {
                REQUIRE(store.lpush("l", big));
                REQUIRE(store.lrem("l", 1, big) == 1);
            }
        });
    }
}

TEST_CASE("a list past its packed form is charged for its blocks and map")
{
    SUBCASE("a first element over the packed limit")
    {
        cache_store store;
        check_charged(store, [&] {
            for (int i = 0; i < 2000; ++i)
                REQUIRE(store.rpush("l" + std::to_string(i), std::string(100, 'e')));
        });
    }

    SUBCASE("a list grown long and popped back to one")
    {
        cache_store store;
        std::string out;
        check_charged(store, [&] {
            for (int k = 0; k < 20; ++k)
            {
                const std::string key = "l" + std::to_string(k);
                for (int i = 0; i < 20000; ++i) REQUIRE(store.rpush(key, "e"));
                for (int i = 1; i < 20000; ++i) REQUIRE(store.lpop(key, out));
            }
        });
    }
}

TEST_CASE("a sorted set in its big form is charged for its head and member index")
{
    SUBCASE("a first member over the packed limit")
    {
        cache_store store;
        check_charged(store, [&] {
            for (int i = 0; i < 2000; ++i)
                REQUIRE(store.zadd("z" + std::to_string(i), 1, std::string(65, 'm')) == 1);
        });
    }

    SUBCASE("a set grown big and removed back to one")
    {
        cache_store store;
        check_charged(store, [&] {
            for (int i = 0; i < 100000; ++i)
                REQUIRE(store.zadd("z", i, "m" + std::to_string(i)) == 1);
            for (int i = 1; i < 100000; ++i)
                REQUIRE(store.zrem("z", "m" + std::to_string(i)));
        });
    }
}

TEST_CASE("a hash in its table form is charged for the table and its slots")
{
    SUBCASE("moved there by one long value")
    {
        cache_store store;
        check_charged(store, [&] {
            for (int i = 0; i < 4000; ++i)
                REQUIRE(store.hset("h" + std::to_string(i), "f", std::string(100, 'v')));
        });
    }

    SUBCASE("grown big and deleted back to one field")
    {
        cache_store store;
        check_charged(store, [&] {
            for (int i = 0; i < 100000; ++i)
                REQUIRE(store.hset("h", "f" + std::to_string(i), "v"));
            for (int i = 1; i < 100000; ++i)
                REQUIRE(store.hdel("h", "f" + std::to_string(i)));
        });
    }
}

TEST_CASE("a set grown big and removed back to one is charged for its slots")
{
    cache_store store;
    check_charged(store, [&] {
        for (int i = 0; i < 100000; ++i)
            REQUIRE(store.sadd("s", "m" + std::to_string(i)) == 1);
        for (int i = 1; i < 100000; ++i)
            REQUIRE(store.srem("s", "m" + std::to_string(i)));
    });
}

TEST_CASE("a packed collection is charged for the room its buffer keeps")
{
    SUBCASE("a hash whose fields are gone")
    {
        cache_store store;
        check_charged(store, [&] {
            for (int k = 0; k < 200; ++k)
            {
                const std::string key = "h" + std::to_string(k);
                for (int i = 0; i < 128; ++i)
                    REQUIRE(store.hset(key, std::string(60, 'f') + std::to_string(i), std::string(64, 'v')));
                REQUIRE(store.hash_ptr(key)->packed());
                for (int i = 1; i < 128; ++i)
                    REQUIRE(store.hdel(key, std::string(60, 'f') + std::to_string(i)));
            }
        });
    }

    SUBCASE("a list whose elements are gone")
    {
        cache_store store;
        std::string out;
        check_charged(store, [&] {
            for (int k = 0; k < 200; ++k)
            {
                const std::string key = "l" + std::to_string(k);
                for (int i = 0; i < 128; ++i) REQUIRE(store.rpush(key, std::string(64, 'e')));
                REQUIRE(store.list_ptr(key)->packed());
                for (int i = 1; i < 128; ++i) REQUIRE(store.rpop(key, out));
            }
        });
    }

    SUBCASE("a sorted set whose members are gone")
    {
        cache_store store;
        check_charged(store, [&] {
            for (int k = 0; k < 200; ++k)
            {
                const std::string key = "z" + std::to_string(k);
                for (int i = 0; i < 128; ++i)
                    REQUIRE(store.zadd(key, 0.5 + i, std::string(60, 'm') + std::to_string(i)) == 1);
                for (int i = 1; i < 128; ++i)
                    REQUIRE(store.zrem(key, std::string(60, 'm') + std::to_string(i)));
            }
        });
    }
}

TEST_CASE("a memory limit holds against the heap a collection takes")
{
    // Admission has to count what the write will make the collection hold,
    // or the limit is passed by everything that is not counted.
    constexpr size_t room = size_t(1) << 20;
    auto fill = [&](auto&& write) {
        cache_store store;
        store.set_eviction(evict_none);
        store.set_max_memory(store.get_memory_used() + room);
        check_charged(store, [&] {
            int i = 0;
            while (write(store, std::to_string(i))) ++i;
            CHECK(i > 100);
            CHECK(store.get_memory_used() <= store.get_max_memory());
        }, 65536);
    };

    SUBCASE("lists of one long element")
    {
        fill([](cache_store& s, const std::string& n) { return s.rpush("l" + n, std::string(100, 'e')); });
    }
    SUBCASE("sorted sets of one long member")
    {
        fill([](cache_store& s, const std::string& n) { return s.zadd("z" + n, 1, std::string(65, 'm')) == 1; });
    }
    SUBCASE("hashes of one long value")
    {
        fill([](cache_store& s, const std::string& n) { return s.hset("h" + n, "f", std::string(100, 'v')); });
    }
}

TEST_CASE("a collection's key is charged for its name when the write creates it")
{
    // Charged nowhere and given back when the collection emptied, so every
    // round trip took the name's bytes off what the store believed it held.
    cache_store store;
    std::string out;
    REQUIRE(store.set("base", std::string(5000, 'b')));
    const size_t before = store.get_memory_used();
    const std::string name(1000, 'k');

    REQUIRE(store.zadd(name, 1, "m") == 1);
    CHECK(store.get_memory_used() >= before + 1000);
    REQUIRE(store.zrem(name, "m"));
    CHECK(store.get_memory_used() == before);

    REQUIRE(store.rpush("src", "e"));
    const size_t with_src = store.get_memory_used();
    REQUIRE(store.lmove("src", name, true, true, out));
    CHECK(store.get_memory_used() >= with_src + 1000 - 200);
    REQUIRE(store.lpop(name, out));
    CHECK(store.get_memory_used() == before);
}

TEST_CASE("a collection's predicted shape is the shape it takes")
{
    // Admission is asked against these predictions, so one that falls short
    // lets a write past the limit by the difference.
    auto same_list = [](const list_items::footprint& a, const list_items::footprint& b) {
        return a.n == b.n && a.packed == b.packed && a.pack_size == b.pack_size && a.pack_heap == b.pack_heap
            && a.seg.blocks == b.seg.blocks && a.seg.map_cap == b.seg.map_cap
            && a.seg.off == b.seg.off && a.seg.size == b.seg.size && a.spare == b.spare;
    };

    SUBCASE("a list pushed at either end, across the packed limits and block edges")
    {
        for (int front = 0; front < 2; ++front)
            for (size_t len : {size_t(0), size_t(5), size_t(22), size_t(64), size_t(65), size_t(100)})
            {
                list_items l;
                for (int i = 0; i < 300; ++i)
                {
                    const std::string v(i % 7 == 3 ? len : size_t(i % 30), 'x');
                    const auto want = l.after_push(v.size(), front != 0);
                    if (front) l.push_front(v); else l.push_back(v);
                    REQUIRE(same_list(want, l.now()));
                }
                std::string out;
                for (int i = 0; i < 150; ++i) { if (front) l.pop_back(out); else l.pop_front(out); }
                const std::string v(len, 'y');
                const auto want = l.after_push(v.size(), front != 0);
                if (front) l.push_front(v); else l.push_back(v);
                CHECK(same_list(want, l.now()));
            }
    }

    SUBCASE("a list element set longer or shorter, and one inserted in the middle")
    {
        for (size_t len : {size_t(1), size_t(30), size_t(64), size_t(65)})
        {
            list_items l;
            for (int i = 0; i < 10; ++i) l.push_back(std::string(20, 'x'));
            const auto want = l.after_set(4, len);
            l.set(4, std::string(len, 's'));
            CHECK(same_list(want, l.now()));

            const auto ins = l.after_push(len, false);
            l.insert(3, std::string(len, 'i'));
            CHECK(same_list(ins, l.now()));
        }

        // Past the packed form, where an element keeps or refits its block.
        list_items l;
        for (int i = 0; i < 40; ++i) l.push_back(std::string(100, 'x'));
        for (size_t k = 0; k < 400; ++k)
        {
            const size_t i   = (k * 7) % 40;
            const size_t len = (k * 37) % 300;
            const auto want = l.after_set(i, len);
            l.set(i, std::string(len, 's'));
            REQUIRE(same_list(want, l.now()));
            if (k % 50 == 0) { l.erase(i); l.insert(i / 2, std::string(len, 'i')); }
        }
    }

    SUBCASE("a hash set field by field, overwritten, and moved to its table")
    {
        auto same = [](const field_map::footprint& a, const field_map::footprint& b) {
            return a.n == b.n && a.packed == b.packed && a.pack_size == b.pack_size
                && a.pack_heap == b.pack_heap && a.slots == b.slots && a.spare == b.spare;
        };
        for (size_t len : {size_t(3), size_t(64), size_t(65)})
        {
            field_map h;
            for (int i = 0; i < 200; ++i)
            {
                const std::string f = "f" + std::to_string(i % 150);
                const std::string v(i == 140 ? len : size_t(i % 40), 'v');
                std::string_view old;
                const bool had = h.get(f, old);
                const auto want = h.after_set(f, v.size(), had ? &old : nullptr);
                h.set(f, v);
                REQUIRE(same(want, h.now()));
            }
        }
    }

    SUBCASE("a sorted set filled small, promoted by a long member or by count, and big")
    {
        auto same = [](const zskiplist::footprint& a, const zskiplist::footprint& b) {
            return a.n == b.n && a.big == b.big && a.pack_size == b.pack_size
                && a.pack_heap == b.pack_heap && a.index_slots == b.index_slots;
        };
        for (size_t at : {size_t(0), size_t(7), size_t(127), size_t(1000)})
        {
            zskiplist z;
            for (size_t i = 0; i < 300; ++i)
            {
                const std::string m = (i == at ? std::string(70, 'l') : "m") + std::to_string(i);
                const double score = i % 3 == 0 ? double(i) : i % 3 == 1 ? i + 0.5 : 70000.0 * double(i);
                const auto want = z.after_insert(score, m.size());
                z.insert(score, m);
                REQUIRE(same(want, z.now()));
            }
        }
    }

    SUBCASE("a set's slots after one more member")
    {
        key_set s;
        for (int i = 0; i < 1000; ++i)
        {
            const size_t want = s.capacity_after_insert();
            s.insert("m" + std::to_string(i));
            REQUIRE(want == s.bucket_count());
            if (i % 3 == 0) s.erase("m" + std::to_string(i / 2));
        }
    }
}

TEST_CASE("a key copied, renamed or stored is charged while it is there and given back once")
{
    // Each of these put a key in place without charging or counting it, and
    // deleting it took back what had never been added: COPY and DEL of the
    // copy, repeated, wore the figure down to nothing.
    cache_store store;
    REQUIRE(store.set("base", std::string(5000, 'b')));
    const size_t base = store.get_memory_used();
    std::string out;

    auto fill = [&](std::string_view key, int type) {
        for (int i = 0; i < 40; ++i)
        {
            const std::string e = std::string(70, 'e') + std::to_string(i);
            switch (type)
            {
                case 0: REQUIRE(store.set(key, e)); return;
                case 1: REQUIRE(store.rpush(key, e)); break;
                case 2: REQUIRE(store.sadd(key, e) == 1); break;
                case 3: REQUIRE(store.hset(key, e, e)); break;
                default: REQUIRE(store.zadd(key, i, e) == 1); break;
            }
        }
    };

    SUBCASE("COPY, of every type")
    {
        for (int type = 0; type < 5; ++type)
        {
            CAPTURE(type);
            fill("k", type);
            const size_t one = store.get_memory_used() - base;
            REQUIRE(store.copy_key("k", "k2", false) == 1);
            CHECK(store.get_memory_used() >= base + 2 * one - 64);
            REQUIRE(store.del("k2"));
            CHECK(store.get_memory_used() == base + one);
            REQUIRE(store.del("k"));
            CHECK(store.get_memory_used() == base);
        }
    }

    SUBCASE("RENAME to a longer name, of every type")
    {
        const std::string name(1000, 'n');
        for (int type = 0; type < 5; ++type)
        {
            CAPTURE(type);
            fill("k", type);
            const size_t one = store.get_memory_used() - base;
            REQUIRE(store.rename_key("k", name, false) == 1);
            CHECK(store.get_memory_used() >= base + one + 1000);
            REQUIRE(store.del(name));
            CHECK(store.get_memory_used() == base);
        }
    }

    SUBCASE("the STORE forms of set algebra")
    {
        fill("s1", 2);
        const size_t one = store.get_memory_used() - base;
        std::vector<std::string> members;
        const std::string_view keys[] = {"s1"};
        REQUIRE(store.sunion(keys, 1, members) == 0);
        REQUIRE(store.sreplace("d", std::move(members)) == 40);
        CHECK(store.get_memory_used() >= base + 2 * one - 64);
        REQUIRE(store.del("d"));
        CHECK(store.get_memory_used() == base + one);
    }

    SUBCASE("SMOVE, and SMOVE of the last member")
    {
        fill("s", 2);
        const std::string first = std::string(70, 'e') + "0";
        REQUIRE(store.smove("s", "d", first) == 1);
        for (int i = 1; i < 40; ++i)
            REQUIRE(store.smove("s", "d", std::string(70, 'e') + std::to_string(i)) == 1);
        CHECK_FALSE(store.exists("s"));
        REQUIRE(store.del("d"));
        CHECK(store.get_memory_used() == base);
    }

    SUBCASE("SMOVE onto its own set leaves the member where it is")
    {
        fill("s", 2);
        const std::string first = std::string(70, 'e') + "0";
        CHECK(store.smove("s", "s", first) == 1);
        CHECK(store.sismember("s", first));
    }

    SUBCASE("LTRIM to nothing")
    {
        fill("l", 1);
        REQUIRE(store.ltrim("l", 5, 2));
        CHECK_FALSE(store.exists("l"));
        CHECK(store.get_memory_used() == base);
    }
}

TEST_CASE("a renamed key can still be evicted, and a refused COPY copies nothing")
{
    cache_store store;
    store.set_max_memory(size_t(1) << 20);
    store.set_eviction(evict_allkeys_lru);

    SUBCASE("RENAME")
    {
        // The rename took the key out of the eviction order and never put
        // it back, so it outlived every key written after it.
        REQUIRE(store.set("old", std::string(1000, 'o')));
        REQUIRE(store.rename_key("old", "renamed", false) == 1);
        for (int i = 0; i < 2000 && store.exists("renamed"); ++i)
            REQUIRE(store.set("fill" + std::to_string(i), std::string(1000, 'f')));
        CHECK_FALSE(store.exists("renamed"));
    }

    SUBCASE("COPY past the limit")
    {
        store.set_eviction(evict_none);
        REQUIRE(store.set("k", std::string(600000, 'v')));
        CHECK(store.copy_key("k", "k2", false) == 0);
        CHECK_FALSE(store.exists("k2"));
        CHECK(store.get_memory_used() <= store.get_max_memory());
    }

    SUBCASE("COPY REPLACE onto a larger destination, which it frees")
    {
        // Admitted as if the destination stayed, this answered 0 where Redis
        // copies: 700 KB and 200 KB fit a megabyte, and so do 200 KB twice.
        store.set_eviction(evict_none);
        REQUIRE(store.set("k2", std::string(700000, 'd')));
        REQUIRE(store.set("k", std::string(200000, 'v')));
        CHECK(store.copy_key("k", "k2", true) == 1);
        CHECK(store.strlen_key("k2") == 200000);
        CHECK(store.get_memory_used() <= store.get_max_memory());
    }

    SUBCASE("a refused COPY REPLACE leaves the destination alone")
    {
        store.set_eviction(evict_none);
        REQUIRE(store.set("k2", std::string(100000, 'd')));
        REQUIRE(store.set("k", std::string(600000, 'v')));
        CHECK(store.copy_key("k", "k2", true) == 0);
        CHECK(store.strlen_key("k2") == 100000);
        CHECK(store.get_memory_used() <= store.get_max_memory());
    }
}

TEST_CASE("a renamed key is charged as the same key made under its new name")
{
    // RENAME moves the value whole, so only the name's cost may change.
    const std::string name(1000, 'n');
    for (int limit = 0; limit < 2; ++limit)
        for (int type = 0; type < 5; ++type)
        {
            CAPTURE(limit);
            CAPTURE(type);
            auto fill = [&](cache_store& s, const std::string& key) {
                if (limit) { s.set_max_memory(size_t(1) << 30); s.set_eviction(evict_allkeys_lru); }
                for (int i = 0; i < 300; ++i)
                {
                    const std::string e = std::string(i % 90, 'e') + std::to_string(i);
                    switch (type)
                    {
                        case 0: REQUIRE(s.set(key, e)); break;
                        case 1: REQUIRE(s.rpush(key, e)); break;
                        case 2: REQUIRE(s.sadd(key, e) == 1); break;
                        case 3: REQUIRE(s.hset(key, e, e)); break;
                        default: REQUIRE(s.zadd(key, i, e) == 1); break;
                    }
                }
            };
            cache_store renamed, made;
            fill(renamed, "k");
            REQUIRE(renamed.rename_key("k", name, false) == 1);
            fill(made, name);
            CHECK(renamed.get_memory_used() == made.get_memory_used());
        }
}

TEST_CASE("a value that churns keeps its block, and one that shrinks a lot gives it back")
{
    // A 100/90/110 byte churn allocated on every write while each write fitted
    // its block exactly; the block is kept while it is at most twice the need.
    SUBCASE("the string itself")
    {
        std::string s(100, 'a');
        assign_fitted(s, std::string(90, 'b'));
        CHECK(s.capacity() == 100);
        assign_fitted(s, std::string(110, 'c'));
        CHECK(s.capacity() == fitted_capacity(100, 110));
        const char* block = s.data();
        for (int i = 0; i < 1000; ++i)
        {
            const size_t len = i % 3 == 0 ? 100 : i % 3 == 1 ? 90 : 110;
            const size_t want = fitted_capacity(s.capacity(), len);
            assign_fitted(s, std::string(len, 'd'));
            REQUIRE(s.capacity() == want);
            REQUIRE(s.data() == block);
        }
        assign_fitted(s, std::string(40, 'e'));      // more than twice the need and 32
        CHECK(s.capacity() == 40);
        assign_fitted(s, std::string(1000000, 'f'));
        assign_fitted(s, "g");
        CHECK(s.capacity() == std::string().capacity());
    }

    // What a kept block holds past the value is charged, or a field set to
    // 1000 bytes and then 600 held 400 more than it was charged.
    SUBCASE("a hash field in the table form, charged for the block it keeps")
    {
        cache_store store;
        check_charged(store, [&] {
            for (int i = 0; i < 1000; ++i)
                REQUIRE(store.hset("h", "f" + std::to_string(i), std::string(1000, 'v')));
            for (int i = 0; i < 1000; ++i)
                REQUIRE(store.hset("h", "f" + std::to_string(i), std::string(600, 'w')));
        });
    }

    SUBCASE("a list element, charged for the block it keeps")
    {
        cache_store store;
        check_charged(store, [&] {
            for (int i = 0; i < 1000; ++i) REQUIRE(store.rpush("l", std::string(1000, 'v')));
            for (int i = 0; i < 1000; ++i) REQUIRE(store.lset("l", i, std::string(600, 'w')) == 0);
        });
    }
}

TEST_CASE("SMOVE the destination has no room for leaves the member in the source")
{
    cache_store store;
    store.set_eviction(evict_none);
    REQUIRE(store.sadd("s", std::string(100, 'm')) == 1);
    REQUIRE(store.sadd("s", "other") == 1);
    store.set_max_memory(store.get_memory_used() + 100);
    CHECK(store.smove("s", "d", std::string(100, 'm')) == 0);
    CHECK(store.sismember("s", std::string(100, 'm')));
    CHECK_FALSE(store.exists("d"));
}

TEST_CASE("every change to a collection is given back exactly when the key goes")
{
    // A figure that drifts by a few bytes a write is a limit that drifts with
    // it, so each round trip has to land on the byte it started from.
    for (int limit = 0; limit < 2; ++limit)
    {
        CAPTURE(limit);
        cache_store store;
        if (limit) { store.set_max_memory(size_t(1) << 30); store.set_eviction(evict_allkeys_lru); }
        REQUIRE(store.set("base", std::string(5000, 'b')));
        const size_t base = store.get_memory_used();
        std::string out;
        double sc = 0;

        SUBCASE("ZADD and ZINCRBY moving scores, small and big")
        {
            for (int n : {5, 300})
            {
                for (int i = 0; i < n; ++i) REQUIRE(store.zadd("z", i, "m" + std::to_string(i)) == 1);
                for (int r = 0; r < 3 * n; ++r)
                {
                    const std::string m = "m" + std::to_string(r % n);
                    REQUIRE(store.zadd("z", r % 7 == 0 ? 70000.25 * r : r * 0.5, m) == 0);
                    REQUIRE(store.zincrby("z", r % 2 ? 1.5 : -100000.0, m, sc) == cache_store::zincr_result::ok);
                }
                REQUIRE(store.del("z"));
                CHECK(store.get_memory_used() == base);
                for (int i = 0; i < n; ++i) REQUIRE(store.zadd("z", i, "m" + std::to_string(i)) == 1);
                for (int r = 0; r < n; ++r) REQUIRE(store.zincrby("z", 0.25, "m" + std::to_string(r), sc) == cache_store::zincr_result::ok);
                for (int i = 0; i < n; ++i) REQUIRE(store.zrem("z", "m" + std::to_string(i)));
                CHECK(store.get_memory_used() == base);
            }
        }

        SUBCASE("LSET, LREM, LINSERT and pops, packed and not")
        {
            for (size_t len : {size_t(10), size_t(100)})
            {
                for (int i = 0; i < 60; ++i) REQUIRE(store.rpush("l", std::string(len, char('a' + i % 5))));
                for (int i = 0; i < 200; ++i)
                    REQUIRE(store.lset("l", i % 60, std::string((i * 37) % 250, 'x')) == 0);
                CHECK(store.lrem("l", 2, std::string((37 * 7) % 250, 'x')) >= 0);
                CHECK(store.lrem("l", -3, std::string(len, 'a')) >= 0);
                for (int i = 0; i < 20; ++i)
                    CHECK(store.linsert("l", i % 2 == 0, std::string(len, 'b'), std::string(i * 9, 'i')) != 0);
                REQUIRE(store.del("l"));
                CHECK(store.get_memory_used() == base);

                for (int i = 0; i < 60; ++i) REQUIRE(store.rpush("l", std::string(len, 'p')));
                for (int i = 0; i < 30; ++i) REQUIRE(store.lset("l", i, std::string(len / 2, 'q')) == 0);
                for (int i = 0; i < 30; ++i) REQUIRE(store.lpop("l", out));
                for (int i = 0; i < 30; ++i) REQUIRE(store.rpop("l", out));
                CHECK_FALSE(store.exists("l"));
                CHECK(store.get_memory_used() == base);
            }
        }

        SUBCASE("HSET overwriting, packed and in the table")
        {
            for (size_t len : {size_t(10), size_t(100)})
            {
                for (int i = 0; i < 60; ++i) REQUIRE(store.hset("h", "f" + std::to_string(i), std::string(len, 'v')));
                for (int i = 0; i < 300; ++i)
                    REQUIRE(store.hset("h", "f" + std::to_string(i % 60), std::string((i * 37) % 250, 'w')));
                REQUIRE(store.del("h"));
                CHECK(store.get_memory_used() == base);

                for (int i = 0; i < 60; ++i) REQUIRE(store.hset("h", "f" + std::to_string(i), std::string(len, 'v')));
                for (int i = 0; i < 60; ++i) REQUIRE(store.hset("h", "f" + std::to_string(i), std::string(len + 7, 'w')));
                for (int i = 0; i < 60; ++i) REQUIRE(store.hdel("h", "f" + std::to_string(i)));
                CHECK(store.get_memory_used() == base);
            }
        }
    }
}

// ─── Streams ────────────────────────────────────────────────────────────────

namespace
{
    // An XADD the way the command layer makes one: a stream found or made,
    // room admitted for what the append will grow it by, the change charged.
    bool store_xadd(cache_store& st, std::string_view key, stream_id id,
                    const std::vector<std::string>& fv)
    {
        std::vector<std::string_view> v(fv.begin(), fv.end());
        stream_inner* s = st.stream_find(key);
        const size_t pairs = v.size() / 2;
        const size_t growth = s ? s->append_growth(id, v.data(), pairs)
                                : stream_inner{}.append_growth(id, v.data(), pairs);
        if (!s) s = st.stream_make(key, growth);
        else if (st.stream_admit(key, growth)) s = st.stream_find(key);
        else s = nullptr;
        if (!s) return false;
        st.stream_change(key, *s, [&](stream_inner& x) { x.append(id, v.data(), pairs); });
        return true;
    }

    using model_entry = std::pair<stream_id, std::vector<std::string>>;

    std::vector<model_entry> read_all(const stream_log& s, stream_id lo = {},
                                      stream_id hi = stream_id::max(), bool rev = false)
    {
        std::vector<model_entry> out;
        s.walk(lo, hi, rev, [&](const stream_log::entry& e) {
            std::vector<std::string> fv;
            e.each([&](std::string_view f, std::string_view v) { fv.emplace_back(f); fv.emplace_back(v); });
            out.emplace_back(e.id, std::move(fv));
            return true;
        });
        return out;
    }

    std::string serialized(const stream_log& s)
    {
        std::string out;
        s.serialize(out);
        return out;
    }
}

TEST_CASE("stream ids parse as Redis parses them and print as it prints them")
{
    stream_id id;
    bool given = true;
    CHECK(stream_parse_id("5-3", id, 0, true, nullptr));
    CHECK(id == stream_id{5, 3});
    CHECK(stream_parse_id("5", id, 7, true, nullptr));
    CHECK(id == stream_id{5, 7});
    CHECK(stream_parse_id("-", id, 0, false, nullptr));
    CHECK(id == stream_id{});
    CHECK(stream_parse_id("+", id, 0, false, nullptr));
    CHECK(id == stream_id::max());
    CHECK_FALSE(stream_parse_id("-", id, 0, true, nullptr));
    CHECK_FALSE(stream_parse_id("+", id, 0, true, nullptr));
    CHECK(stream_parse_id("9-*", id, 0, true, &given));
    CHECK_FALSE(given);
    CHECK(id == stream_id{9, 0});
    CHECK(stream_parse_id("9-1", id, 0, true, &given));
    CHECK(given);
    CHECK_FALSE(stream_parse_id("9-*", id, 0, true, nullptr));
    // strtoull's reading after the strict one, as string2ull has it.
    CHECK(stream_parse_id("007", id, 0, true, nullptr));
    CHECK(id.ms == 7);
    CHECK(stream_parse_id("18446744073709551615-18446744073709551615", id, 0, true, nullptr));
    CHECK(id == stream_id::max());
    CHECK_FALSE(stream_parse_id("18446744073709551616", id, 0, true, nullptr));
    CHECK_FALSE(stream_parse_id("-5", id, 0, true, nullptr));
    CHECK_FALSE(stream_parse_id("", id, 0, true, nullptr));
    CHECK_FALSE(stream_parse_id("1-", id, 0, true, nullptr));
    CHECK_FALSE(stream_parse_id("1-x", id, 0, true, nullptr));
    CHECK_FALSE(stream_parse_id("abc", id, 0, true, nullptr));
    CHECK_FALSE(stream_parse_id(std::string(128, '1'), id, 0, true, nullptr));
    CHECK(stream_parse_id(std::string_view("4-2\0junk", 8), id, 0, true, nullptr));
    CHECK(id == stream_id{4, 2});

    stream_id top = stream_id::max();
    CHECK_FALSE(top.incr());
    CHECK(top == stream_id{});
    CHECK_FALSE(top.decr());
    CHECK(top == stream_id::max());
    stream_id a{3, UINT64_MAX};
    CHECK(a.incr());
    CHECK(a == stream_id{4, 0});
    CHECK(a.decr());
    CHECK(a == stream_id{3, UINT64_MAX});
    CHECK(stream_id{12, 0}.str() == "12-0");
    CHECK(stream_id::max().str() == "18446744073709551615-18446744073709551615");
    CHECK(stream_id{1, 2} < stream_id{2, 0});
    CHECK(stream_id{2, 1} > stream_id{2, 0});
}

TEST_CASE("a stream record's arguments come back as they went in, spaces and newlines included")
{
    const std::string_view in[] = { "XADD", "k y", "1-1", "", "a\r\nb", std::string_view("\0:3", 3) };
    std::string rec;
    stream_args_encode(rec, in, std::size(in));
    std::vector<std::string_view> out;
    REQUIRE(stream_args_decode(rec, out));
    REQUIRE(out.size() == std::size(in));
    for (size_t i = 0; i < out.size(); ++i) CHECK(out[i] == in[i]);
    out.clear();
    CHECK_FALSE(stream_args_decode("3:ab", out));
    out.clear();
    CHECK_FALSE(stream_args_decode("x:ab", out));
    out.clear();
    CHECK_FALSE(stream_args_decode("3", out));
}

TEST_CASE("stream_log agrees with a model through appends, deletions and trims")
{
    uint32_t r = 4242;
    auto rnd = [&] { r ^= r << 13; r ^= r >> 17; r ^= r << 5; return r; };
    const std::vector<std::vector<std::string>> shapes = {
        { "f", "v" }, { "name", "", "age", "" }, { "a", "", "b", "", "c", "" }, { "payload", "" },
    };
    for (int round = 0; round < 6; ++round)
    {
        CAPTURE(round);
        stream_log s;
        std::map<stream_id, std::vector<std::string>> model;
        stream_id last;
        stream_id maxdel;
        uint64_t added = 0;
        for (int step = 0; step < 4000; ++step)
        {
            const uint32_t op = rnd() % 100;
            if (op < 60)
            {
                // Same millisecond now and then, a jump now and then.
                stream_id id = last;
                if (rnd() % 3 == 0) id.seq += 1 + rnd() % 3;
                else { id.ms += 1 + rnd() % (rnd() % 10 == 0 ? 100000 : 3); id.seq = rnd() % 2; }
                if (id <= last) id = { last.ms, last.seq + 1 };
                std::vector<std::string> fv = shapes[rnd() % shapes.size()];
                for (size_t i = 1; i < fv.size(); i += 2)
                    fv[i] = std::string(rnd() % 7 == 0 ? 300 + rnd() % 900 : rnd() % 20, char('a' + rnd() % 26));
                if (rnd() % 11 == 0) fv[0] = "odd" + std::to_string(rnd() % 3);
                std::vector<std::string_view> v(fv.begin(), fv.end());
                const size_t before = s.heap_bytes();
                const size_t predicted = s.append_growth(id, v.data(), v.size() / 2);
                s.append(id, v.data(), v.size() / 2);
                CHECK(s.heap_bytes() <= before + predicted);
                model[id] = fv;
                last = id;
                ++added;
            }
            else if (op < 75 && !model.empty())
            {
                auto it = std::next(model.begin(), static_cast<long>(rnd() % model.size()));
                const stream_id id = rnd() % 5 ? it->first : stream_id{ it->first.ms, it->first.seq + 1 };
                const bool had = model.erase(id) > 0;
                CHECK(s.erase(id) == had);
                if (had && id > maxdel) maxdel = id;
            }
            else if (op < 85)
            {
                stream_log::trim_spec t;
                t.by = stream_log::trim_by::maxlen;
                t.approx = rnd() % 2;
                t.maxlen = model.size() > 3 ? rnd() % model.size() : 0;
                t.limit = t.approx && rnd() % 2 ? static_cast<int64_t>(rnd() % 300) : 0;
                const uint64_t gone = s.trim(t);
                // Whatever went is the oldest `gone`, never more than was asked.
                CHECK(gone <= (model.size() > t.maxlen ? model.size() - t.maxlen : 0));
                for (uint64_t i = 0; i < gone; ++i) model.erase(model.begin());
                if (!t.approx && !t.limit) CHECK(model.size() <= std::max<uint64_t>(t.maxlen, 0));
            }
            else if (op < 92 && !model.empty())
            {
                stream_log::trim_spec t;
                t.by = stream_log::trim_by::minid;
                t.approx = rnd() % 2;
                t.minid = std::next(model.begin(), static_cast<long>(rnd() % model.size()))->first;
                const uint64_t gone = s.trim(t);
                uint64_t below = 0;
                for (const auto& [id, fv] : model) if (id < t.minid) ++below;
                CHECK(gone <= below);
                for (uint64_t i = 0; i < gone; ++i) model.erase(model.begin());
                if (!t.approx) CHECK(gone == below);
            }
            else
            {
                // A range read, forwards and backwards, against the model.
                if (model.empty()) continue;
                auto a = std::next(model.begin(), static_cast<long>(rnd() % model.size()))->first;
                auto b = std::next(model.begin(), static_cast<long>(rnd() % model.size()))->first;
                if (b < a) std::swap(a, b);
                if (rnd() % 2) a.seq = a.seq ? a.seq - 1 : 0;
                std::vector<model_entry> want(model.lower_bound(a), model.upper_bound(b));
                CHECK(read_all(s, a, b) == want);
                std::reverse(want.begin(), want.end());
                CHECK(read_all(s, a, b, true) == want);
            }

            REQUIRE(s.size() == model.size());
            CHECK(s.entries_added() == added);
            CHECK(s.last_id() == last);
            CHECK(s.max_deleted() == maxdel);
            if (!model.empty())
            {
                CHECK(s.first_id() == model.begin()->first);
                CHECK(s.last_live() == model.rbegin()->first);
            }
            else
                CHECK(s.first_id() == stream_id{});
            if (step % 500 == 0 || step == 3999)
            {
                const std::vector<model_entry> all(model.begin(), model.end());
                REQUIRE(read_all(s) == all);
                for (const auto& [id, fv] : model)
                    CHECK(s.contains(id));
                // The persisted form and a copy both hold the same stream.
                stream_log back;
                REQUIRE(back.deserialize(serialized(s)));
                CHECK(serialized(back) == serialized(s));
                CHECK(read_all(back) == all);
                stream_log copy(s);
                CHECK(serialized(copy) == serialized(s));
                stream_log moved(std::move(copy));
                CHECK(read_all(moved) == all);
                CHECK(copy.size() == 0);
            }
        }
    }
}

TEST_CASE("a stream is cut into blocks where Redis cuts its nodes")
{
    stream_log s;
    const std::string_view fv[] = { "f", "v" };
    for (uint64_t i = 1; i <= 250; ++i) s.append({ i, 1 }, fv, 1);
    CHECK(s.block_count() == 3);

    // MAXLEN ~ takes whole blocks only, and LIMIT stops before a block that
    // would cross it.
    stream_log::trim_spec t;
    t.by = stream_log::trim_by::maxlen;
    t.approx = true;
    t.maxlen = 120;
    t.limit = 10000;
    CHECK(s.trim(t) == 100);
    CHECK(s.size() == 150);
    t.maxlen = 0;
    t.limit = 50;
    CHECK(s.trim(t) == 0);

    // An exact trim leaves the tail block's slots taken, so the next block
    // opens where Redis's next node would.
    t.approx = false;
    t.limit = 0;
    t.maxlen = 10;
    CHECK(s.trim(t) == 140);
    CHECK(s.block_count() == 1);
    for (uint64_t i = 251; i <= 300; ++i) s.append({ i, 1 }, fv, 1);
    CHECK(s.block_count() == 1);
    s.append({ 301, 1 }, fv, 1);
    CHECK(s.block_count() == 2);

    // A node's byte bound cuts a stream of large entries before its count
    // does, at four of a thousand bytes as Redis's listpack does.
    stream_log big;
    const std::string v(1000, 'x');
    const std::string_view bfv[] = { "f", v };
    for (uint64_t i = 1; i <= 12; ++i) big.append({ i, 0 }, bfv, 1);
    CHECK(big.block_count() == 3);

    // An XDEL that empties a block takes the block with it.
    stream_log d;
    for (uint64_t i = 1; i <= 150; ++i) d.append({ i, 0 }, fv, 1);
    for (uint64_t i = 1; i <= 100; ++i) REQUIRE(d.erase({ i, 0 }));
    CHECK(d.block_count() == 1);
    CHECK(d.first_id() == stream_id{ 101, 0 });
    CHECK(d.max_deleted() == stream_id{ 100, 0 });
}

TEST_CASE("a group's pending entries agree with a model through deliveries, claims and acks")
{
    uint32_t r = 99;
    auto rnd = [&] { r ^= r << 13; r ^= r >> 17; r ^= r << 5; return r; };
    stream_log s;
    const std::string_view fv[] = { "f", "v" };
    for (uint64_t i = 1; i <= 300; ++i) s.append({ i, 0 }, fv, 1);
    REQUIRE(s.create_group("g", {}, 0));
    CHECK_FALSE(s.create_group("g", {}, 0));
    stream_log::group* g = s.find_group("g");
    REQUIRE(g);

    struct pend { std::string owner; int64_t when; uint64_t count; };
    std::map<stream_id, pend> model;
    std::set<std::string> consumers;
    const auto consumer = [&](const std::string& n) {
        stream_log::consumer* c = s.find_consumer(*g, n);
        if (!c) { c = s.create_consumer(*g, n, 1); consumers.insert(n); }
        return c;
    };
    for (int step = 0; step < 20000; ++step)
    {
        const std::string who = "c" + std::to_string(rnd() % 6) + (rnd() % 4 ? "" : std::string(20, 'x'));
        const stream_id id{ 1 + rnd() % 300, 0 };
        const uint32_t op = rnd() % 10;
        if (op < 4)
        {
            stream_log::nack& n = s.deliver(*g, id, *consumer(who), step);
            CHECK(n.count == 1);
            model[id] = { who, step, 1 };
        }
        else if (op < 6)
        {
            CHECK(s.ack(*g, id) == (model.erase(id) > 0));
        }
        else if (op < 8)
        {
            // A claim: an entry already pending moves to another consumer.
            stream_log::nack* n = s.find_nack(*g, id);
            CHECK((n != nullptr) == (model.count(id) > 0));
            if (n)
            {
                s.move_nack(id, *n, *consumer(who));
                ++n->count;
                model[id].owner = who;
                ++model[id].count;
            }
        }
        else if (op < 9)
        {
            const int64_t had = s.delete_consumer(*g, who);
            uint64_t owned = 0;
            for (auto it = model.begin(); it != model.end();)
                if (it->second.owner == who) { ++owned; it = model.erase(it); } else ++it;
            CHECK(had == (consumers.erase(who) ? static_cast<int64_t>(owned) : -1));
        }
        else
        {
            stream_log::nack& n = s.force_nack(*g, id, 5);
            if (!model.count(id)) { CHECK(n.count == 1); CHECK(n.delivery_ms == 5); }
            s.move_nack(id, n, *consumer(who));
            model[id] = { who, n.delivery_ms, n.count };
        }

        if (step % 1000 == 0)
        {
            REQUIRE(g->pel.size() == model.size());
            size_t viewed = 0;
            for (const auto& [id, n] : g->pel)
            {
                REQUIRE(model.count(id));
                REQUIRE(n.owner);
                CHECK(std::string(n.owner->name) == model[id].owner);
                CHECK(n.count == model[id].count);
                CHECK(n.owner->pel.count(id) == 1);
            }
            for (const auto& [name, c] : g->consumers)
            {
                CHECK(consumers.count(name) == 1);
                CHECK(c.name == name);
                viewed += c.pel.size();
            }
            CHECK(viewed == model.size());
            CHECK(g->consumers.size() == consumers.size());
            // The persisted form carries every pending entry and its owner.
            stream_log back;
            REQUIRE(back.deserialize(serialized(s)));
            CHECK(serialized(back) == serialized(s));
            CHECK(back.heap_bytes() - back.pending_index_bytes() == s.heap_bytes() - s.pending_index_bytes());
            CHECK(back.pending_index_bytes() <= s.pending_index_bytes());
        }
    }
    // Destroying the group gives every byte its entries held back.
    const size_t with = s.heap_bytes();
    REQUIRE(s.destroy_group("g"));
    CHECK(s.heap_bytes() < with);
    stream_log bare;
    for (uint64_t i = 1; i <= 300; ++i) bare.append({ i, 0 }, fv, 1);
    CHECK(s.heap_bytes() == bare.heap_bytes());
}

TEST_CASE("a group's lag and read counter follow Redis's rules")
{
    stream_log s;
    const std::string_view fv[] = { "f", "v" };
    for (uint64_t i = 1; i <= 5; ++i) s.append({ i, 1 }, fv, 1);
    stream_log::group* g = s.create_group("g", {}, 0);
    int64_t lag = -1;
    CHECK(s.lag(*g, lag));
    CHECK(lag == 5);
    s.advance(*g, { 1, 1 });
    s.advance(*g, { 2, 1 });
    CHECK(g->entries_read == 2);
    CHECK(s.lag(*g, lag));
    CHECK(lag == 3);
    // A hole ahead of the group makes the counter unknowable.
    REQUIRE(s.erase({ 4, 1 }));
    CHECK_FALSE(s.lag(*g, lag));
    s.advance(*g, { 3, 1 });
    CHECK(g->entries_read == -1);
    s.advance(*g, { 5, 1 });
    CHECK(g->entries_read == 5);
    CHECK(s.lag(*g, lag));
    CHECK(lag == 0);
    stream_log::group* h = s.create_group("h", { 5, 1 }, -1);
    CHECK(s.lag(*h, lag));
    CHECK(lag == 0);
    CHECK(s.estimate_read({ 0, 1 }) == -1);
    stream_log e;
    CHECK(e.estimate_read({ 7, 7 }) == 0);
}

TEST_CASE("a stream is one more type to the store")
{
    cache_store store;
    REQUIRE(store_xadd(store, "x", { 1, 1 }, { "f", "v" }));
    CHECK(store.type("x") == "stream");
    CHECK(store.exists("x"));
    CHECK(store.holds_other_type("x", 's'));
    CHECK_FALSE(store.holds_other_type("x", 'x'));
    CHECK_FALSE(store.set("x", "v"));
    CHECK_FALSE(store.lpush("x", "v"));
    CHECK(store.sadd("x", "m") < 0);
    CHECK_FALSE(store.hset("x", "f", "v"));
    CHECK(store.zadd("x", 1, "m") < 0);
    REQUIRE(store.set("str", "v"));
    CHECK(store.stream_make("str", 0) == nullptr);
    CHECK(store.size() == 2);

    std::vector<std::string_view> ks;
    store.keys("*", ks);
    CHECK(ks.size() == 2);
    ks.clear();
    CHECK(store.scan(0, "*", 100, ks, cache_store::scan_filter::one(nullptr, 5)) == 0);
    REQUIRE(ks.size() == 1);
    CHECK(ks[0] == "x");

    CHECK(store.copy_key("x", "y", false) == 1);
    CHECK(serialized(*store.stream_get("y")) == serialized(*store.stream_get("x")));
    CHECK(store.rename_key("y", "z", false) == 1);
    CHECK(store.type("z") == "stream");
    CHECK_FALSE(store.exists("y"));
    CHECK(store.set_expiry_ms("z", 1));
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    store.check_expiry("z");
    CHECK_FALSE(store.exists("z"));
    CHECK(store.del("x"));
    CHECK(store.type("x") == "none");
}

TEST_CASE("a stream survives save and load, and a dump names it as records")
{
    cache_store store;
    for (uint64_t i = 1; i <= 150; ++i)
        REQUIRE(store_xadd(store, "s", { i, 0 }, { "n", std::to_string(i), "sp", "a b\r\nc" }));
    stream_inner* s = store.stream_find("s");
    store.stream_change("s", *s, [](stream_inner& x) {
        stream_log::group* g = x.create_group("g", {}, -1);
        stream_log::consumer* c = x.create_consumer(*g, "alice", 77);
        for (uint64_t i = 1; i <= 20; ++i) x.deliver(*g, { i, 0 }, *c, 1000 + static_cast<int64_t>(i));
        x.erase({ 5, 0 });
    });
    REQUIRE(store.stream_make("empty", 0));

    char path[] = "/tmp/socketley-stream-XXXXXX";
    const int fd = mkstemp(path);
    REQUIRE(fd >= 0);
    close(fd);
    REQUIRE(store.save(path));
    cache_store back;
    REQUIRE(back.load(path));
    unlink(path);
    REQUIRE(back.stream_get("s"));
    CHECK(serialized(*back.stream_get("s")) == serialized(*store.stream_get("s")));
    CHECK(back.type("empty") == "stream");
    CHECK(back.get_memory_used() == store.get_memory_used());

    std::string dump;
    store.dump_commands(dump);
    size_t records = 0;
    for (size_t at = dump.find("xapply s "); at != std::string::npos; at = dump.find("xapply s ", at + 1))
        ++records;
    // 149 entries, the counters, the group, its consumer and 20 pending, the
    // deleted entry's among them.
    CHECK(records == 149 + 1 + 1 + 1 + 20);
    CHECK(dump.find("xapply empty ") != std::string::npos);
}

TEST_CASE("a stream is charged for what it holds and gives it all back")
{
    const std::string v(200, 'v');
    SUBCASE("entries, trims and groups against the heap")
    {
        cache_store store;
        check_charged(store, [&] {
            for (uint64_t i = 1; i <= 5000; ++i)
                REQUIRE(store_xadd(store, "big", { i, 0 }, { "field", v }));
            stream_inner* s = store.stream_find("big");
            store.stream_change("big", *s, [&](stream_inner& x) {
                stream_log::group* g = x.create_group("g", {}, 0);
                for (int c = 0; c < 50; ++c)
                {
                    stream_log::consumer* k = x.create_consumer(*g, "consumer-with-a-long-name-" + std::to_string(c), 1);
                    for (uint64_t i = 1; i <= 40; ++i) x.deliver(*g, { static_cast<uint64_t>(c) * 40 + i, 0 }, *k, 1);
                }
            });
        });
    }

    for (int limit = 0; limit < 2; ++limit)
    {
        CAPTURE(limit);
        cache_store store;
        if (limit) { store.set_max_memory(size_t(1) << 30); store.set_eviction(evict_allkeys_lru); }
        REQUIRE(store.set("base", std::string(5000, 'b')));
        const size_t base = store.get_memory_used();
        for (uint64_t i = 1; i <= 700; ++i)
            REQUIRE(store_xadd(store, "s", { i, i % 3 }, { i % 5 ? "a" : "b", std::string(i % 60, 'x') }));
        stream_inner* s = store.stream_find("s");
        store.stream_change("s", *s, [&](stream_inner& x) {
            stream_log::group* g = x.create_group("g", {}, 0);
            stream_log::consumer* c = x.create_consumer(*g, std::string(40, 'c'), 1);
            for (uint64_t i = 1; i <= 300; ++i) x.deliver(*g, { i, i % 3 }, *c, 1);
            for (uint64_t i = 1; i <= 100; ++i) x.ack(*g, { i, i % 3 });
            for (uint64_t i = 200; i <= 260; ++i) x.erase({ i, i % 3 });
            stream_log::trim_spec t;
            t.by = stream_log::trim_by::maxlen;
            t.maxlen = 333;
            x.trim(t);
        });
        CHECK(store.copy_key("s", "t", false) == 1);
        CHECK(store.rename_key("t", "u", false) == 1);
        REQUIRE(store.del("u"));
        REQUIRE(store.del("s"));
        CHECK(store.get_memory_used() == base);
    }
}

TEST_CASE("a stream write refused for room leaves the stream as it was")
{
    cache_store store;
    for (uint64_t i = 1; i <= 50; ++i) REQUIRE(store_xadd(store, "s", { i, 0 }, { "f", "v" }));
    const std::string before = serialized(*store.stream_get("s"));
    // The limit switched on first, because doing so charges the eviction order.
    store.set_max_memory(size_t(1) << 30);
    store.set_max_memory(store.get_memory_used() + 64);
    size_t refused = 0;
    for (uint64_t i = 51; i <= 400; ++i)
        if (!store_xadd(store, "s", { i, 0 }, { "f", std::string(100, 'z') })) ++refused;
    CHECK(refused > 0);
    CHECK(store.get_memory_used() <= store.get_max_memory());
    CHECK(serialized(*store.stream_get("s")).size() >= before.size());
    CHECK_FALSE(store_xadd(store, "fresh", { 1, 0 }, { "f", std::string(1000, 'z') }));
    CHECK_FALSE(store.exists("fresh"));

    // Under LRU the stream being written is never what is evicted for it.
    cache_store lru;
    lru.set_max_memory(size_t(1) << 20);
    lru.set_eviction(evict_allkeys_lru);
    for (int i = 0; i < 200; ++i) REQUIRE(lru.set("k" + std::to_string(i), std::string(2000, 'v')));
    for (uint64_t i = 1; i <= 3000; ++i)
        REQUIRE(store_xadd(lru, "s", { i, 0 }, { "f", std::string(300, 'y') }));
    CHECK(lru.stream_get("s")->size() == 3000);
    CHECK(lru.get_memory_used() <= lru.get_max_memory());
}
