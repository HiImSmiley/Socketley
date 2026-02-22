#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include "../../socketley/runtime/cache/cache_store.h"
#include <thread>

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
    store.set_max_memory(100);
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
        store.set("k1", std::string(90, 'a'));
        CHECK_FALSE(store.set("k2", std::string(20, 'b')));
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
