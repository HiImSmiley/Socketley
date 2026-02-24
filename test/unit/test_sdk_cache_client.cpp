// SDK compile test + unit tests for cache_client.h
#include "socketley/cache_client.h"
#include <cassert>

// ── cache_result tests ──────────────────────────────────────────

static void test_result_default()
{
    socketley::cache_result r;
    assert(!r.ok);
    assert(r.value.empty());
    assert(r.values.empty());
    assert(r.integer == 0);
    assert(!r.is_nil());
    assert(!static_cast<bool>(r));
}

static void test_result_ok()
{
    socketley::cache_result r;
    r.ok = true;
    r.value = "hello";
    assert(static_cast<bool>(r));
    assert(!r.is_nil());
}

static void test_result_nil()
{
    socketley::cache_result r;
    r.ok = true;
    r.value = "nil";
    assert(r.is_nil());
    assert(static_cast<bool>(r));
}

static void test_result_integer()
{
    socketley::cache_result r;
    r.ok = true;
    r.value = "42";
    r.integer = 42;
    assert(r.integer == 42);
}

static void test_result_multi()
{
    socketley::cache_result r;
    r.ok = true;
    r.values.push_back("a");
    r.values.push_back("b");
    r.values.push_back("c");
    assert(r.values.size() == 3);
    assert(r.values[0] == "a");
    assert(r.values[2] == "c");
}

// ── Compile verification ────────────────────────────────────────

static void verify_cache_client_api()
{
    if (false)
    {
        socketley::cache_client c;
        bool ok = c.connect("localhost", 9000);
        c.close();
        ok = c.reconnect();
        ok = c.is_connected();
        c.set_recv_timeout(5000);
        const std::string& h = c.host();
        uint16_t p = c.port();

        // Strings
        socketley::cache_result r = c.get("k");
        r = c.set("k", "v");
        r = c.del("k");
        r = c.exists("k");
        r = c.incr("k");
        r = c.decr("k");
        r = c.incrby("k", 5);
        r = c.decrby("k", 3);
        r = c.append("k", "v");
        r = c.strlen("k");
        r = c.getset("k", "v");
        r = c.setnx("k", "v");
        r = c.setex("k", 60, "v");
        r = c.psetex("k", 60000, "v");
        r = c.type("k");

        // Multi-key
        r = c.mget({"k1", "k2"});
        r = c.mset({{"k1", "v1"}, {"k2", "v2"}});

        // Lists
        r = c.lpush("k", "v");
        r = c.rpush("k", "v");
        r = c.lpop("k");
        r = c.rpop("k");
        r = c.llen("k");
        r = c.lindex("k", 0);
        r = c.lrange("k", 0, -1);

        // Sets
        r = c.sadd("k", "m");
        r = c.srem("k", "m");
        r = c.sismember("k", "m");
        r = c.scard("k");
        r = c.smembers("k");

        // Hashes
        r = c.hset("k", "f", "v");
        r = c.hget("k", "f");
        r = c.hdel("k", "f");
        r = c.hlen("k");
        r = c.hgetall("k");

        // TTL
        r = c.expire("k", 60);
        r = c.pexpire("k", 60000);
        r = c.ttl("k");
        r = c.pttl("k");
        r = c.persist("k");
        r = c.expireat("k", 1700000000);
        r = c.pexpireat("k", 1700000000000);

        // Pub/Sub
        r = c.publish("ch", "msg");
        r = c.subscribe("ch");
        r = c.unsubscribe("ch");
        r = c.recv_message();

        // Admin
        r = c.size();
        r = c.memory();
        r = c.maxmemory();
        r = c.keys("*");
        r = c.scan(0, "*", 10);
        r = c.flush();
        r = c.load();

        // Raw
        r = c.execute("ping");

        (void)ok; (void)r; (void)h; (void)p;
    }
}

int main()
{
    test_result_default();
    test_result_ok();
    test_result_nil();
    test_result_integer();
    test_result_multi();

    verify_cache_client_api();

    return 0;
}
