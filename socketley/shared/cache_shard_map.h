#pragma once
// Which shard of a cache owns a key, and which commands that question applies
// to.
//
// ─── WHY THIS IS A HEADER AND NOT A METHOD ──────────────────────────────────
//
// Ownership by key hash is what keeps `cache_store` lock-free: each shard is
// the sole reader AND the sole writer of its own slice, so nothing is shared
// and nothing needs a lock.  That property holds only while every shard agrees
// about who owns what, and "agree" here means N separate processes computing
// the same answer from the same bytes with no way to compare notes.
//
// So the answer is a pure function of the key and the shard count, stated once,
// in a header both the asking side and the answering side include.  A shard
// that computed it differently would not fail loudly — it would serve a miss
// for data that was stored, which is the exact failure the cache's --shards
// refusal names.  The verdict is `constexpr` over plain arguments for the same
// reason conn_reachability.h is: there is nowhere for a caller to put a
// disagreement.
//
// This is the shape shared/ asks for — the DECISION extracted, not the
// function.  The four runtimes' event loops differ; a rule about which process
// owns a name does not, and when the server or the proxy grows a keyed
// partition it will ask this rather than write a second one.
//
// ─── THE HASH ───────────────────────────────────────────────────────────────
//
// FNV-1a, 64-bit, over the key's bytes, modulo the shard count.  Not the
// 32-bit fnv1a() the command dispatch uses: that one is a switch label over a
// dozen literals, where a collision is caught by reading the file.  This one
// runs over arbitrary client-supplied keys and its only job is to spread them,
// so the wider mix is worth the nothing it costs.
//
// Modulo rather than a power-of-two mask, because the shard count is whatever
// the operator typed and 3, 5 and 6 are all legal.  One divide per command
// against a ~150 us cache operation.
//
// NOT stable across a change of N.  `shard_of(k, 4) != shard_of(k, 3)` for most
// keys, and that is the whole of the persistence hazard: N dumps written under
// one N and loaded under another put keys in slices that will never be asked
// for them.  Redistribution is that step's job; this header's job is to make
// the dependence on N impossible to miss, which is why N is a parameter and
// never a member.
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "../cli/command_hashing.h"

// Which of `shard_count` shards owns `key`.  Always 0 for an unsharded cache,
// which is shard 0 of one and not a special case.
inline uint32_t cache_shard_of(std::string_view key, uint32_t shard_count)
{
    if (shard_count <= 1)
        return 0;

    uint64_t h = 1469598103934665603ull;
    for (const char c : key)
    {
        h ^= static_cast<uint8_t>(c);
        h *= 1099511628211ull;
    }
    return static_cast<uint32_t>(h % shard_count);
}

// ─── WHAT A COMMAND ASKS OF THE KEYSPACE ────────────────────────────────────
//
// Five answers, and every command in both interpreters has exactly one of them.
// A command this table does not name reads `unknown`, which is served where it
// was asked — correct, because the interpreters answer an unknown command with
// "unknown command" and that answer is the same in every process.
enum class cache_cmd_class : uint8_t
{
    single_key,   // one key, in the first argument: route to its owner
    multi_key,    // several keys, possibly several owners
    keyspace,     // every shard's slice at once — keys, scan, dbsize, flush
    fanout,       // no key, but every shard has subscribers: publish
    connection,   // answered by whoever holds the socket; no key at all
    stateful,     // attaches a stream to one shard: replicate
    unknown       // not a command; the local dispatch says so
};

// The command alone, without its arguments.
//
// `del` and `exists` answer multi_key here because the RESP spelling takes
// several keys.  The TEXT interpreter's does not — process_command() splits at
// the first space and hands the whole remainder to the store as one key — so
// the text reading narrows them below.  One table, two readings, rather than
// two tables that can disagree.
constexpr cache_cmd_class cache_classify(uint32_t h)
{
    switch (h)
    {
        // ── strings ──
        case fnv1a("set"):        case fnv1a("get"):
        case fnv1a("incr"):       case fnv1a("decr"):
        case fnv1a("incrby"):     case fnv1a("decrby"):
        case fnv1a("append"):     case fnv1a("strlen"):
        case fnv1a("getset"):     case fnv1a("type"):
        case fnv1a("setnx"):      case fnv1a("setex"):
        case fnv1a("psetex"):
        // ── expiry ──
        case fnv1a("expire"):     case fnv1a("pexpire"):
        case fnv1a("expireat"):   case fnv1a("pexpireat"):
        case fnv1a("ttl"):        case fnv1a("pttl"):
        case fnv1a("persist"):
        // ── lists ──
        case fnv1a("lpush"):      case fnv1a("rpush"):
        case fnv1a("lpop"):       case fnv1a("rpop"):
        case fnv1a("llen"):       case fnv1a("lindex"):
        case fnv1a("lrange"):
        // ── sets ──
        case fnv1a("sadd"):       case fnv1a("srem"):
        case fnv1a("sismember"):  case fnv1a("scard"):
        case fnv1a("smembers"):
        // ── hashes ──
        case fnv1a("hset"):       case fnv1a("hget"):
        case fnv1a("hdel"):       case fnv1a("hlen"):
        case fnv1a("hgetall"):
            return cache_cmd_class::single_key;

        case fnv1a("del"):        case fnv1a("exists"):
        case fnv1a("mget"):       case fnv1a("mset"):
            return cache_cmd_class::multi_key;

        case fnv1a("keys"):       case fnv1a("scan"):
        case fnv1a("dbsize"):     case fnv1a("size"):
        case fnv1a("flush"):      case fnv1a("load"):
        case fnv1a("memory"):     case fnv1a("maxmemory"):
            return cache_cmd_class::keyspace;

        case fnv1a("publish"):
            return cache_cmd_class::fanout;

        case fnv1a("ping"):
        case fnv1a("subscribe"):  case fnv1a("unsubscribe"):
            return cache_cmd_class::connection;

        case fnv1a("replicate"):
            return cache_cmd_class::stateful;

        default:
            return cache_cmd_class::unknown;
    }
}

// The text interpreter's reading.  `del k` and `exists k` are one key by
// construction there — the multi-key spelling does not exist in that protocol,
// so refusing it as multi_key would refuse a command that has one owner.
constexpr cache_cmd_class cache_classify_text(uint32_t h)
{
    if (h == fnv1a("del") || h == fnv1a("exists"))
        return cache_cmd_class::single_key;
    return cache_classify(h);
}

// And RESP's, which does allow several.  `DEL k` with exactly one key is one
// owner; `DEL a b` is not.  `EXISTS` reads only args[1] whatever it is given,
// so it is one key at any arity — the narrowing follows the implementation
// rather than the protocol, deliberately: the class has to describe what this
// build does, not what Redis does.
constexpr cache_cmd_class cache_classify_resp(uint32_t h, int argc)
{
    if (h == fnv1a("exists"))
        return cache_cmd_class::single_key;
    if (h == fnv1a("del"))
        return argc == 2 ? cache_cmd_class::single_key
                         : cache_cmd_class::multi_key;
    return cache_classify(h);
}

// ─── SPLITTING A TEXT COMMAND ───────────────────────────────────────────────
//
// The same positional split process_command() makes, in one place so the router
// and the interpreter cannot read a line differently.  Command to the first
// space; the key is the rest up to the next one.
//
// `del` and `exists` are the exception this cannot express: their key is the
// WHOLE remainder, spaces included.  That is not a difference the router cares
// about — a key with a space in it hashes to one shard either way only if both
// sides agree — so cache_text_key() takes the command hash and applies the same
// rule the interpreter does.
struct cache_text_parts
{
    std::string_view cmd;
    std::string_view args;
};

constexpr cache_text_parts cache_split_text(std::string_view line)
{
    const size_t sp = line.find(' ');
    if (sp == std::string_view::npos)
        return {line, {}};
    return {line.substr(0, sp), line.substr(sp + 1)};
}

// ─── WHERE A TEXT COMMAND'S KEY IS ─────────────────────────────────────────
//
// Not one rule, and this is the trap.  process_command() splits the LINE at the
// first space into command and arguments, and then each handler reads its key
// out of the arguments in one of two ways:
//
//   * seventeen of them pass `args` STRAIGHT THROUGH to the store, so the key is
//     everything after the command, spaces included;
//   * the rest take the first token and leave the value behind it.
//
// A router that assumed the second rule everywhere would hash a different
// string than the store looks up, for any key with a space in it — and RESP can
// store one, so `SET "a b" v` over RESP followed by `get a b` in text would be
// routed on "a" and read on "a b".  A miss for data that was stored, which is
// the failure this whole arrangement exists to remove, reintroduced by the
// thing removing it.
//
// So the rule is read off the handlers rather than guessed, and it lives here
// because it has to be the SAME rule on the shard that routes and the shard
// that answers.  Verified against both switches at the time of writing: 17
// whole-argument commands, all listed.
constexpr bool cache_text_key_is_whole_args(uint32_t h)
{
    switch (h)
    {
        case fnv1a("get"):      case fnv1a("del"):     case fnv1a("exists"):
        case fnv1a("incr"):     case fnv1a("decr"):    case fnv1a("strlen"):
        case fnv1a("type"):     case fnv1a("lpop"):    case fnv1a("rpop"):
        case fnv1a("llen"):     case fnv1a("scard"):   case fnv1a("smembers"):
        case fnv1a("hlen"):     case fnv1a("hgetall"): case fnv1a("ttl"):
        case fnv1a("pttl"):     case fnv1a("persist"):
            return true;
        default:
            return false;
    }
}

// The key a single-key text command names, read exactly as the interpreter
// reads it.  Empty when the command has no arguments, which the interpreter
// answers with a usage line — served locally, because "usage" is the same
// answer in every process.
constexpr std::string_view cache_text_key(uint32_t h, std::string_view args)
{
    if (cache_text_key_is_whole_args(h))
        return args;
    const size_t sp = args.find(' ');
    return sp == std::string_view::npos ? args : args.substr(0, sp);
}
