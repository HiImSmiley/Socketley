#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include "../../socketley/runtime/cache/cache_store.h"
#include <thread>
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

        const std::string* val = store.lindex("q", 0);
        REQUIRE(val != nullptr);
        CHECK(*val == "a");

        val = store.lindex("q", -1);
        REQUIRE(val != nullptr);
        CHECK(*val == "c");

        CHECK(store.lindex("q", 10) == nullptr);
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
        const std::string* val = store.hget("h", "f1");
        REQUIRE(val != nullptr);
        CHECK(*val == "v1");
    }

    SUBCASE("hget nonexistent")
    {
        CHECK(store.hget("h", "f") == nullptr);
        store.hset("h", "f1", "v1");
        CHECK(store.hget("h", "f2") == nullptr);
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
        expected = src.get_memory_used();
        CHECK(src.save(path));
    }

    cache_store dst;
    dst.set_max_memory(1000000);          // limit is configured before the load, as the runtime does
    dst.set_eviction(evict_allkeys_lru);
    CHECK(dst.load(path));
    CHECK(dst.size() == 23);

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
        CHECK(store.incr("counter", 1, result));
        CHECK(result == 1);
        std::string out;
        CHECK(store.get("counter", out));
        CHECK(out == "1");
    }

    SUBCASE("incr existing integer")
    {
        store.set("counter", "10");
        int64_t result = 0;
        CHECK(store.incr("counter", 5, result));
        CHECK(result == 15);
    }

    SUBCASE("incr non-integer fails")
    {
        store.set("k", "abc");
        int64_t result = 0;
        CHECK_FALSE(store.incr("k", 1, result));
    }

    SUBCASE("decr")
    {
        store.set("k", "10");
        int64_t result = 0;
        CHECK(store.incr("k", -1, result));
        CHECK(result == 9);
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
