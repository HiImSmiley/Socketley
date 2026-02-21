#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include "../../socketley/cli/command_hashing.h"

TEST_CASE("FNV-1a basic correctness")
{
    CHECK(fnv1a("") != 0);
    CHECK(fnv1a("get") != fnv1a("set"));
    CHECK(fnv1a("get") != fnv1a("GET"));
    CHECK(fnv1a("create") != fnv1a("remove"));
}

TEST_CASE("FNV-1a deterministic")
{
    CHECK(fnv1a("hello") == fnv1a("hello"));
    CHECK(fnv1a("set") == fnv1a("set"));
    CHECK(fnv1a("lpush") == fnv1a("lpush"));
}

TEST_CASE("FNV-1a case-insensitive variant")
{
    CHECK(fnv1a_lower("GET") == fnv1a("get"));
    CHECK(fnv1a_lower("SET") == fnv1a("set"));
    CHECK(fnv1a_lower("Del") == fnv1a("del"));
    CHECK(fnv1a_lower("LPUSH") == fnv1a("lpush"));
    CHECK(fnv1a_lower("HGETALL") == fnv1a("hgetall"));
}

TEST_CASE("FNV-1a all cache commands unique")
{
    // Verify no hash collisions among cache commands
    uint32_t hashes[] = {
        fnv1a("set"), fnv1a("get"), fnv1a("del"), fnv1a("exists"),
        fnv1a("lpush"), fnv1a("rpush"), fnv1a("lpop"), fnv1a("rpop"),
        fnv1a("llen"), fnv1a("lindex"), fnv1a("lrange"),
        fnv1a("sadd"), fnv1a("srem"), fnv1a("sismember"), fnv1a("scard"), fnv1a("smembers"),
        fnv1a("hset"), fnv1a("hget"), fnv1a("hdel"), fnv1a("hlen"), fnv1a("hgetall"),
        fnv1a("expire"), fnv1a("ttl"), fnv1a("persist"),
        fnv1a("flush"), fnv1a("load"), fnv1a("size"),
        fnv1a("subscribe"), fnv1a("unsubscribe"), fnv1a("publish"),
        fnv1a("maxmemory"), fnv1a("memory"), fnv1a("replicate")
    };

    size_t count = sizeof(hashes) / sizeof(hashes[0]);
    for (size_t i = 0; i < count; i++)
        for (size_t j = i + 1; j < count; j++)
            CHECK(hashes[i] != hashes[j]);
}

TEST_CASE("FNV-1a CLI commands unique")
{
    uint32_t hashes[] = {
        fnv1a("daemon"), fnv1a("ls"), fnv1a("ps"),
        fnv1a("create"), fnv1a("run"), fnv1a("stop"), fnv1a("remove"),
        fnv1a("send"), fnv1a("edit"), fnv1a("stats"), fnv1a("reload"),
        fnv1a("--lua")
    };

    size_t count = sizeof(hashes) / sizeof(hashes[0]);
    for (size_t i = 0; i < count; i++)
        for (size_t j = i + 1; j < count; j++)
            CHECK(hashes[i] != hashes[j]);
}
