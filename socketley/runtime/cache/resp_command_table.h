#pragma once
// What COMMAND answers: every command the RESP side of this cache serves, with
// Redis 7's arity, flags and key positions for it, because a cluster client
// builds its key routing from this reply and an empty one left redis-py's
// RedisCluster unable to send any command that names a key.
//
// Arity counts the command name; negative means "at least".  Key positions
// are first, last (-1 the last argument, -2 the one before it) and step, and
// 0 0 0 is a command with no key.  EVAL and EVALSHA carry 0 0 0 without
// movablekeys, as every cluster client reads their keys from numkeys itself.
#include <cstdint>
#include <string_view>

struct resp_command_info
{
    std::string_view name;
    int32_t          arity;
    std::string_view flags;   // space-separated, as the reply lists them
    int32_t          first_key;
    int32_t          last_key;
    int32_t          step;
};

inline constexpr resp_command_info resp_command_table[] = {
    // strings
    {"get",          2, "readonly fast",              1,  1, 1},
    {"set",         -3, "write denyoom",              1,  1, 1},
    {"setnx",        3, "write denyoom fast",         1,  1, 1},
    {"setex",        4, "write denyoom",              1,  1, 1},
    {"psetex",       4, "write denyoom",              1,  1, 1},
    {"getset",       3, "write denyoom fast",         1,  1, 1},
    {"getdel",       2, "write fast",                 1,  1, 1},
    {"append",       3, "write denyoom fast",         1,  1, 1},
    {"strlen",       2, "readonly fast",              1,  1, 1},
    {"getrange",     4, "readonly",                   1,  1, 1},
    {"substr",       4, "readonly",                   1,  1, 1},
    {"setrange",     4, "write denyoom",              1,  1, 1},
    {"incr",         2, "write denyoom fast",         1,  1, 1},
    {"decr",         2, "write denyoom fast",         1,  1, 1},
    {"incrby",       3, "write denyoom fast",         1,  1, 1},
    {"decrby",       3, "write denyoom fast",         1,  1, 1},
    {"incrbyfloat",  3, "write denyoom fast",         1,  1, 1},
    {"mget",        -2, "readonly fast",              1, -1, 1},
    {"mset",        -3, "write denyoom",              1, -1, 2},
    // keys
    {"del",         -2, "write",                      1, -1, 1},
    {"unlink",      -2, "write fast",                 1, -1, 1},
    {"exists",      -2, "readonly fast",              1, -1, 1},
    {"touch",       -2, "readonly fast",              1, -1, 1},
    {"type",         2, "readonly fast",              1,  1, 1},
    {"expire",      -3, "write fast",                 1,  1, 1},
    {"pexpire",     -3, "write fast",                 1,  1, 1},
    {"expireat",    -3, "write fast",                 1,  1, 1},
    {"pexpireat",   -3, "write fast",                 1,  1, 1},
    {"ttl",          2, "readonly fast",              1,  1, 1},
    {"pttl",         2, "readonly fast",              1,  1, 1},
    {"expiretime",   2, "readonly fast",              1,  1, 1},
    {"pexpiretime",  2, "readonly fast",              1,  1, 1},
    {"persist",      2, "write fast",                 1,  1, 1},
    {"rename",       3, "write",                      1,  2, 1},
    {"renamenx",     3, "write fast",                 1,  2, 1},
    {"copy",        -3, "write denyoom",              1,  2, 1},
    {"keys",         2, "readonly",                   0,  0, 0},
    {"scan",        -2, "readonly",                   0,  0, 0},
    {"randomkey",    1, "readonly",                   0,  0, 0},
    {"dbsize",       1, "readonly fast",              0,  0, 0},
    {"flushall",    -1, "write",                      0,  0, 0},
    {"flushdb",     -1, "write",                      0,  0, 0},
    // lists
    {"lpush",       -3, "write denyoom fast",         1,  1, 1},
    {"rpush",       -3, "write denyoom fast",         1,  1, 1},
    {"lpop",        -2, "write fast",                 1,  1, 1},
    {"rpop",        -2, "write fast",                 1,  1, 1},
    {"llen",         2, "readonly fast",              1,  1, 1},
    {"lrange",       4, "readonly",                   1,  1, 1},
    {"lindex",       3, "readonly",                   1,  1, 1},
    {"lset",         4, "write denyoom",              1,  1, 1},
    {"lrem",         4, "write",                      1,  1, 1},
    {"ltrim",        4, "write",                      1,  1, 1},
    {"linsert",      5, "write denyoom",              1,  1, 1},
    {"lmove",        5, "write denyoom",              1,  2, 1},
    {"rpoplpush",    3, "write denyoom",              1,  2, 1},
    {"blpop",       -3, "write noscript blocking",    1, -2, 1},
    {"brpop",       -3, "write noscript blocking",    1, -2, 1},
    // sets
    {"sadd",        -3, "write denyoom fast",         1,  1, 1},
    {"srem",        -3, "write fast",                 1,  1, 1},
    {"scard",        2, "readonly fast",              1,  1, 1},
    {"smembers",     2, "readonly",                   1,  1, 1},
    {"sismember",    3, "readonly fast",              1,  1, 1},
    {"smismember",  -3, "readonly fast",              1,  1, 1},
    {"spop",        -2, "write fast",                 1,  1, 1},
    {"srandmember", -2, "readonly",                   1,  1, 1},
    {"smove",        4, "write fast",                 1,  2, 1},
    {"sinter",      -2, "readonly",                   1, -1, 1},
    {"sunion",      -2, "readonly",                   1, -1, 1},
    {"sdiff",       -2, "readonly",                   1, -1, 1},
    {"sinterstore", -3, "write denyoom",              1, -1, 1},
    {"sunionstore", -3, "write denyoom",              1, -1, 1},
    {"sdiffstore",  -3, "write denyoom",              1, -1, 1},
    {"sscan",       -3, "readonly",                   1,  1, 1},
    // hashes
    {"hset",        -4, "write denyoom fast",         1,  1, 1},
    {"hmset",       -4, "write denyoom fast",         1,  1, 1},
    {"hsetnx",       4, "write denyoom fast",         1,  1, 1},
    {"hget",         3, "readonly fast",              1,  1, 1},
    {"hmget",       -3, "readonly fast",              1,  1, 1},
    {"hdel",        -3, "write fast",                 1,  1, 1},
    {"hgetall",      2, "readonly",                   1,  1, 1},
    {"hkeys",        2, "readonly",                   1,  1, 1},
    {"hvals",        2, "readonly",                   1,  1, 1},
    {"hlen",         2, "readonly fast",              1,  1, 1},
    {"hexists",      3, "readonly fast",              1,  1, 1},
    {"hstrlen",      3, "readonly fast",              1,  1, 1},
    {"hincrby",      4, "write denyoom fast",         1,  1, 1},
    {"hscan",       -3, "readonly",                   1,  1, 1},
    // sorted sets
    {"zadd",        -4, "write denyoom fast",         1,  1, 1},
    {"zrem",        -3, "write fast",                 1,  1, 1},
    {"zscore",       3, "readonly fast",              1,  1, 1},
    {"zincrby",      4, "write denyoom fast",         1,  1, 1},
    {"zcard",        2, "readonly fast",              1,  1, 1},
    {"zcount",       4, "readonly fast",              1,  1, 1},
    {"zrank",       -3, "readonly fast",              1,  1, 1},
    {"zrevrank",    -3, "readonly fast",              1,  1, 1},
    {"zrange",      -4, "readonly",                   1,  1, 1},
    {"zrevrange",   -4, "readonly",                   1,  1, 1},
    {"zrangebyscore",    -4, "readonly",              1,  1, 1},
    {"zrevrangebyscore", -4, "readonly",              1,  1, 1},
    {"zremrangebyrank",   4, "write",                 1,  1, 1},
    {"zremrangebyscore",  4, "write",                 1,  1, 1},
    {"zpopmin",     -2, "write fast",                 1,  1, 1},
    {"zpopmax",     -2, "write fast",                 1,  1, 1},
    {"zscan",       -3, "readonly",                   1,  1, 1},
    // pub/sub
    {"publish",      3, "pubsub loading stale fast",  0,  0, 0},
    {"subscribe",   -2, "pubsub noscript loading stale", 0, 0, 0},
    {"unsubscribe", -1, "pubsub noscript loading stale", 0, 0, 0},
    {"psubscribe",  -2, "pubsub noscript loading stale", 0, 0, 0},
    {"punsubscribe",-1, "pubsub noscript loading stale", 0, 0, 0},
    // transactions and scripts
    {"multi",        1, "noscript loading stale fast",   0,  0, 0},
    {"exec",         1, "noscript loading stale",        0,  0, 0},
    {"discard",      1, "noscript loading stale fast",   0,  0, 0},
    {"watch",       -2, "noscript loading stale fast",   1, -1, 1},
    {"unwatch",      1, "noscript loading stale fast",   0,  0, 0},
    {"eval",        -3, "noscript stale",                0,  0, 0},
    {"evalsha",     -3, "noscript stale",                0,  0, 0},
    {"script",      -2, "noscript",                      0,  0, 0},
    // connection and server
    {"ping",        -1, "fast",                          0,  0, 0},
    {"echo",         2, "fast",                          0,  0, 0},
    {"select",       2, "loading stale fast",            0,  0, 0},
    {"auth",        -2, "noscript loading stale fast",   0,  0, 0},
    {"hello",       -1, "noscript loading stale fast",   0,  0, 0},
    {"client",      -2, "noscript loading stale",        0,  0, 0},
    {"reset",        1, "noscript loading stale fast",   0,  0, 0},
    {"quit",        -1, "noscript loading stale fast",   0,  0, 0},
    {"readonly",     1, "loading stale fast",            0,  0, 0},
    {"readwrite",    1, "loading stale fast",            0,  0, 0},
    {"asking",       1, "fast",                          0,  0, 0},
    {"info",        -1, "loading stale",                 0,  0, 0},
    {"config",      -2, "admin noscript loading stale",  0,  0, 0},
    {"cluster",     -2, "",                              0,  0, 0},
    {"command",     -1, "loading stale",                 0,  0, 0},
};
