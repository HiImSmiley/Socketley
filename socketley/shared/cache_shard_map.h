#pragma once
// Which shard owns a key, as Redis's keyHashSlot() exactly, so N processes
// agree and a client can compute it without asking.
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "../cli/command_hashing.h"

// CRC16/XMODEM, built at compile time from the bitwise definition rather than
// pasted as 256 constants; test_cache_slots.cpp pins it to Redis's own values.
inline constexpr uint16_t cache_crc16_bitwise(uint16_t crc, uint8_t byte)
{
    crc ^= static_cast<uint16_t>(static_cast<uint16_t>(byte) << 8);
    for (int i = 0; i < 8; ++i)
        crc = (crc & 0x8000u)
            ? static_cast<uint16_t>(static_cast<uint16_t>(crc << 1) ^ 0x1021u)
            : static_cast<uint16_t>(crc << 1);
    return crc;
}

struct cache_crc16_table
{
    uint16_t v[256];
};

inline constexpr cache_crc16_table cache_make_crc16_table()
{
    cache_crc16_table t{};
    for (int i = 0; i < 256; ++i)
        t.v[i] = cache_crc16_bitwise(0, static_cast<uint8_t>(i));
    return t;
}

inline constexpr cache_crc16_table cache_crc16_tab = cache_make_crc16_table();

inline constexpr uint16_t cache_crc16(std::string_view s)
{
    uint16_t crc = 0;
    for (const char c : s)
        crc = static_cast<uint16_t>(
            static_cast<uint16_t>(crc << 8)
            ^ cache_crc16_tab.v[((crc >> 8) ^ static_cast<uint8_t>(c)) & 0xFFu]);
    return crc;
}

// The number of hash slots, fixed at Redis's 16384 because the clients that
// make this worth doing have that number compiled in.
inline constexpr uint32_t cache_slot_count = 16384;

// The whole key unless it carries a non-empty `{...}`: first `{`, first `}`
// after it, Redis's rule to the letter.
constexpr std::string_view cache_hash_tag(std::string_view key)
{
    const size_t open = key.find('{');
    if (open == std::string_view::npos)
        return key;
    const size_t close = key.find('}', open + 1);
    if (close == std::string_view::npos || close == open + 1)
        return key;
    return key.substr(open + 1, close - open - 1);
}

// The hash slot a key belongs to, 0..16383 and independent of the shard count,
// which is what lets a client cache a slot per key across a resize.
constexpr uint32_t cache_slot_of(std::string_view key)
{
    return cache_crc16(cache_hash_tag(key)) & (cache_slot_count - 1);
}

// Which of `shard_count` shards owns `slot`.
constexpr uint32_t cache_shard_of_slot(uint32_t slot, uint32_t shard_count)
{
    if (shard_count <= 1)
        return 0;
    return (slot * shard_count) / cache_slot_count;
}

// The inverse, for CLUSTER SLOTS: the first and last slot of a shard's range.
constexpr uint32_t cache_shard_slot_first(uint32_t shard, uint32_t shard_count)
{
    if (shard_count <= 1)
        return 0;
    return (shard * cache_slot_count + shard_count - 1) / shard_count;
}

constexpr uint32_t cache_shard_slot_last(uint32_t shard, uint32_t shard_count)
{
    if (shard_count <= 1)
        return cache_slot_count - 1;
    return cache_shard_slot_first(shard + 1, shard_count) - 1;
}

// Which of `shard_count` shards owns `key`, always 0 for an unsharded cache,
// which is shard 0 of one and not a special case.
inline uint32_t cache_shard_of(std::string_view key, uint32_t shard_count)
{
    if (shard_count <= 1)
        return 0;
    return cache_shard_of_slot(cache_slot_of(key), shard_count);
}

// What a command asks of the keyspace; an unnamed one reads `unknown` and is
// served where it was asked, because that answer is the same everywhere.
enum class cache_cmd_class : uint8_t
{
    single_key,   // one key, in the first argument: route to its owner
    multi_key,    // several keys, possibly several owners
    keyspace,     // every shard's slice at once — keys, dbsize, memory
    cursor_scan,  // one shard per call, named by the cursor; see below
    fanout,       // no key, but every shard has its own subscribers: publish
    connection,   // answered by whoever holds the socket; no key at all
    stateful,     // attaches a stream to one shard: replicate
    unknown       // not a command; the local dispatch says so
};

// A multi-key command is EXPLODED into one per key, so reassembly is
// concatenation; splitting per shard would need a reply-shape table.
// Commands that name several keys and cannot be split between shards.  Set
// algebra because an intersection computed on two shards separately is not an
// intersection; RENAME and COPY because a key cannot be half-moved.  Every key
// must belong to one shard, and keys that do not are refused with -CROSSSLOT.
//
// Named for the ROUTING RULE and not for sets: the first version of this was
// called cache_is_set_algebra and RENAME wanted the same decision two hours
// later.
constexpr bool cache_needs_one_shard(uint32_t h)
{
    switch (h)
    {
        case fnv1a("sinter"):      case fnv1a("sunion"):      case fnv1a("sdiff"):
        case fnv1a("sinterstore"): case fnv1a("sunionstore"): case fnv1a("sdiffstore"):
        case fnv1a("smove"):
        case fnv1a("rename"):      case fnv1a("renamenx"):    case fnv1a("copy"):
            return true;
        default:
            return false;
    }
}

enum class cache_merge : uint8_t
{
    single,     // one part, verbatim.  Every command routed by step one.
    elements,   // mget: one `get` reply per key, in the caller's order
    all_ok,     // mset: every `set` must have said ok
    sum,        // dbsize/size/memory/publish/multi-del: integers added
    key_list    // keys: the per-shard lists concatenated
};

// What a command's parts are merged with, `single` for everything that has one
// part.
constexpr cache_merge cache_merge_for(uint32_t h)
{
    switch (h)
    {
        case fnv1a("mget"):   return cache_merge::elements;
        case fnv1a("mset"):   return cache_merge::all_ok;
        case fnv1a("del"):    case fnv1a("unlink"):
        case fnv1a("touch"):  case fnv1a("exists"):
            return cache_merge::sum;     // the RESP spellings, counted
        case fnv1a("keys"):   return cache_merge::key_list;
        case fnv1a("flush"):  case fnv1a("load"):
        case fnv1a("flushall"): case fnv1a("flushdb"):
            return cache_merge::all_ok;

        case fnv1a("dbsize"): case fnv1a("size"):
        case fnv1a("memory"): case fnv1a("maxmemory"):
        // publish answers how many subscribers it REACHED, and every shard
        // holds its own; the runtime's answer is the total.
        case fnv1a("publish"):
            return cache_merge::sum;
        default:              return cache_merge::single;
    }
}

// The command alone, with `del` and `exists` multi_key for RESP and narrowed
// for the text reading below -- one table, two readings.
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
        case fnv1a("getrange"):   case fnv1a("setrange"):
        case fnv1a("incrbyfloat"): case fnv1a("getdel"):
        case fnv1a("getex"):      case fnv1a("substr"):
        // ── expiry ──
        case fnv1a("expire"):     case fnv1a("pexpire"):
        case fnv1a("expireat"):   case fnv1a("pexpireat"):
        case fnv1a("ttl"):        case fnv1a("pttl"):
        case fnv1a("persist"):
        // ── lists ──
        case fnv1a("lpush"):      case fnv1a("rpush"):
        case fnv1a("lpop"):       case fnv1a("rpop"):
        case fnv1a("llen"):       case fnv1a("lindex"):
        case fnv1a("lrange"):     case fnv1a("lset"):
        case fnv1a("lrem"):       case fnv1a("ltrim"):
        case fnv1a("linsert"):
        // Two keys, routed on the first.  The shard that owns it answers
        // -CROSSSLOT when the second is a sibling's, which is what Redis says
        // for a pair that does not hash together -- moving it would be a
        // crossing that has to be undone if the far side refuses.
        case fnv1a("rpoplpush"):  case fnv1a("lmove"):
        // Refused on a sharded cache by the handler, and single-key here so an
        // unsharded one routes it like every other list command.
        case fnv1a("blpop"):      case fnv1a("brpop"):
        // ── sets ──
        case fnv1a("sadd"):       case fnv1a("srem"):
        case fnv1a("sismember"):  case fnv1a("scard"):
        case fnv1a("smembers"):   case fnv1a("spop"):
        case fnv1a("srandmember"): case fnv1a("smismember"):
        // ── hashes ──
        case fnv1a("hset"):       case fnv1a("hget"):
        case fnv1a("hdel"):       case fnv1a("hlen"):
        case fnv1a("hgetall"):    case fnv1a("hexists"):
        case fnv1a("hincrby"):    case fnv1a("hsetnx"):
        case fnv1a("hmget"):      case fnv1a("hmset"):
        case fnv1a("hkeys"):      case fnv1a("hvals"):
        case fnv1a("hstrlen"):
        // A cursor over ONE key's collection, so it routes to that key's owner
        // like any other single-key command -- unlike SCAN, whose cursor names
        // a shard because the keyspace is spread over all of them.
        case fnv1a("hscan"):      case fnv1a("sscan"):
        case fnv1a("zscan"):
        // ── sorted sets ──
        case fnv1a("zadd"):       case fnv1a("zrem"):
        case fnv1a("zscore"):     case fnv1a("zcard"):
        case fnv1a("zrank"):      case fnv1a("zrevrank"):
        case fnv1a("zrange"):     case fnv1a("zrevrange"):
        case fnv1a("zincrby"):
        case fnv1a("zrangebyscore"):    case fnv1a("zrevrangebyscore"):
        case fnv1a("zcount"):          case fnv1a("zpopmin"):
        case fnv1a("zpopmax"):         case fnv1a("zremrangebyrank"):
        case fnv1a("zremrangebyscore"):
        // ── streams, with XGROUP and XINFO naming theirs second; see cache_key_arg ──
        case fnv1a("xadd"):       case fnv1a("xlen"):
        case fnv1a("xrange"):     case fnv1a("xrevrange"):
        case fnv1a("xdel"):       case fnv1a("xtrim"):
        case fnv1a("xack"):       case fnv1a("xpending"):
        case fnv1a("xclaim"):     case fnv1a("xautoclaim"):
        case fnv1a("xsetid"):     case fnv1a("xgroup"):
        case fnv1a("xinfo"):
        // A stream write as the replication log carries it, keyed first.
        case fnv1a("xapply"):
            return cache_cmd_class::single_key;

        case fnv1a("del"):        case fnv1a("exists"):
        case fnv1a("mget"):       case fnv1a("mset"):
        case fnv1a("unlink"):     case fnv1a("touch"):
            return cache_cmd_class::multi_key;

        case fnv1a("keys"):
        case fnv1a("dbsize"):     case fnv1a("size"):
        case fnv1a("memory"):     case fnv1a("maxmemory"):
            return cache_cmd_class::keyspace;

        case fnv1a("scan"):
            return cache_cmd_class::cursor_scan;

        // These touch the dump file, and each shard now writes its own, so
        // they fan out -- with `all_ok`, because a partial flush must be
        // visible as a failure rather than averaged into a number.
        case fnv1a("flush"):      case fnv1a("load"):
        // The RESP spellings of the same thing, which ran on whichever shard
        // the connection landed on and left the others' keys standing.
        case fnv1a("flushall"):   case fnv1a("flushdb"):
            return cache_cmd_class::keyspace;

        case fnv1a("publish"):
            return cache_cmd_class::fanout;

        // subscribe records a DESCRIPTOR, so whoever holds the socket answers:
        // delivery crosses, registration does not.
        case fnv1a("ping"):
        case fnv1a("subscribe"):  case fnv1a("unsubscribe"):
        case fnv1a("hello"):      case fnv1a("echo"):
        case fnv1a("select"):     case fnv1a("auth"):
        case fnv1a("client"):     case fnv1a("command"):
        case fnv1a("config"):     case fnv1a("info"):
        // SCRIPT keeps its table in the process that was asked, and EVAL is
        // routed ahead of this switch by the keys it declares -- neither is a
        // single-key command, and args[1] of an EVAL is the script.
        case fnv1a("script"):
        // Every field is derived from the shard count and base port, which
        // each shard holds, so whoever has the socket answers for the map.
        case fnv1a("cluster"):
        case fnv1a("readonly"):   case fnv1a("readwrite"):
        case fnv1a("asking"):
            return cache_cmd_class::connection;

        case fnv1a("replicate"):
            return cache_cmd_class::stateful;

        default:
            return cache_cmd_class::unknown;
    }
}

// Where XREAD's and XREADGROUP's keys are, the first half of what follows
// STREAMS, and whether the call blocks.
struct stream_read_keys
{
    int  first{0};
    int  count{0};
    bool blocks{false};
};

constexpr stream_read_keys find_stream_read_keys(const std::string_view* a, int argc)
{
    stream_read_keys k;
    for (int i = 1; i < argc; ++i)
    {
        const uint32_t w = fnv1a_lower(a[i]);
        if (w == fnv1a("block") && i + 1 < argc) { k.blocks = true; ++i; }
        else if (w == fnv1a("count") && i + 1 < argc) ++i;
        else if (w == fnv1a("group") && i + 2 < argc) i += 2;
        else if (w == fnv1a("streams"))
        {
            const int rest = argc - i - 1;
            if (rest > 0 && rest % 2 == 0) { k.first = i + 1; k.count = rest / 2; }
            return k;
        }
    }
    return k;
}

// Which argument holds a single-key command's key: the first, except where a
// subcommand comes before it.
constexpr int cache_key_arg(uint32_t h)
{
    return (h == fnv1a("xgroup") || h == fnv1a("xinfo")) ? 2 : 1;
}

// Whether a command can be trusted not to change anything, asked by WATCH and
// by nothing else.
//
// The list is of READS and not of writes, deliberately.  A write missing from
// a list of writes is a transaction that commits over somebody else's change
// and never notices -- silent, and the exact failure WATCH exists to prevent.
// A read missing from this list is a transaction that retries once for no
// reason.  So anything not named here counts as a write.
constexpr bool cache_is_read_only(uint32_t h)
{
    switch (h)
    {
        case fnv1a("get"):        case fnv1a("mget"):
        case fnv1a("expiretime"): case fnv1a("pexpiretime"):
        case fnv1a("strlen"):     case fnv1a("getrange"):
        case fnv1a("substr"):     case fnv1a("exists"):
        case fnv1a("touch"):      case fnv1a("type"):
        case fnv1a("ttl"):        case fnv1a("pttl"):
        case fnv1a("llen"):       case fnv1a("lrange"):
        case fnv1a("lindex"):
        case fnv1a("scard"):      case fnv1a("smembers"):
        case fnv1a("sismember"):  case fnv1a("smismember"):
        case fnv1a("srandmember"):
        case fnv1a("hget"):       case fnv1a("hgetall"):
        case fnv1a("hlen"):       case fnv1a("hkeys"):
        case fnv1a("hvals"):      case fnv1a("hmget"):
        case fnv1a("hexists"):    case fnv1a("hstrlen"):
        case fnv1a("zscore"):     case fnv1a("zcard"):
        case fnv1a("zrank"):      case fnv1a("zrevrank"):
        case fnv1a("zrange"):     case fnv1a("zrevrange"):
        case fnv1a("zrangebyscore"): case fnv1a("zrevrangebyscore"):
        case fnv1a("zcount"):
        case fnv1a("xrange"):     case fnv1a("xrevrange"):
        case fnv1a("xlen"):       case fnv1a("xread"):
        case fnv1a("xpending"):   case fnv1a("xinfo"):
        case fnv1a("scan"):       case fnv1a("hscan"):
        case fnv1a("sscan"):      case fnv1a("zscan"):
        case fnv1a("keys"):       case fnv1a("dbsize"):
        case fnv1a("size"):       case fnv1a("memory"):
        case fnv1a("ping"):       case fnv1a("echo"):
        case fnv1a("info"):       case fnv1a("config"):
        case fnv1a("command"):    case fnv1a("cluster"):
        case fnv1a("select"):     case fnv1a("hello"):
        case fnv1a("client"):     case fnv1a("auth"):
        case fnv1a("readonly"):   case fnv1a("readwrite"):
        case fnv1a("asking"):
        // publish changes no key; subscribe records a descriptor.
        case fnv1a("publish"):    case fnv1a("subscribe"):
        case fnv1a("unsubscribe"):
        // The transaction verbs themselves, and SCRIPT, which only touches
        // the script table -- EVAL is a write, because it can be.
        case fnv1a("multi"):      case fnv1a("exec"):
        case fnv1a("discard"):    case fnv1a("watch"):
        case fnv1a("unwatch"):    case fnv1a("script"):
            return true;
        default:
            return false;
    }
}

// The text interpreter's reading, where `del k` and `exists k` are one key by
// construction because the multi-key spelling does not exist in that protocol.
constexpr cache_cmd_class cache_classify_text(uint32_t h)
{
    if (h == fnv1a("del")    || h == fnv1a("exists")
     || h == fnv1a("unlink") || h == fnv1a("touch"))
        return cache_cmd_class::single_key;
    return cache_classify(h);
}

// RESP's reading, which allows several, narrowed to follow this build's
// implementation rather than the protocol.
constexpr cache_cmd_class cache_classify_resp(uint32_t h, int argc)
{
    // EXISTS counts every key it is given, so more than one of them routes the
    // way DEL's do; narrowing it unconditionally answered for the first alone.
    if (h == fnv1a("exists") || h == fnv1a("touch")
     || h == fnv1a("del")    || h == fnv1a("unlink"))
        return argc == 2 ? cache_cmd_class::single_key
                         : cache_cmd_class::multi_key;
    return cache_classify(h);
}

// process_command()'s own positional split, here so the router and the
// interpreter cannot read a line differently.
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

// Two rules, because seventeen commands take the whole remainder as the key
// and the rest take the first token, and assuming either everywhere misroutes
// a key with a space in it.
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

// The key as the interpreter reads it; empty means no arguments, answered
// locally because "usage" is the same everywhere.
constexpr std::string_view cache_text_key(uint32_t h, std::string_view args)
{
    if (cache_text_key_is_whole_args(h))
        return args;
    if (cache_key_arg(h) == 2)
    {
        const size_t sub = args.find(' ');
        args = sub == std::string_view::npos ? std::string_view{} : args.substr(sub + 1);
    }
    const size_t sp = args.find(' ');
    return sp == std::string_view::npos ? args : args.substr(0, sp);
}

// SCAN walks shard by shard with the shard in the top six bits, so a change of
// N must refuse an old cursor rather than follow it.
inline constexpr int      cache_scan_shard_bits  = 6;          // max_shards == 64
inline constexpr int      cache_scan_shard_shift = 64 - cache_scan_shard_bits;
inline constexpr uint64_t cache_scan_store_mask  =
    (1ull << cache_scan_shard_shift) - 1ull;

// Which shard a cursor is a position in, 0 for every cursor an unsharded cache
// issues.
constexpr uint32_t cache_scan_cursor_shard(uint64_t cursor)
{
    return static_cast<uint32_t>(cursor >> cache_scan_shard_shift);
}

// That shard's own cursor, as cache_store::scan() would recognise it.
constexpr uint64_t cache_scan_cursor_store(uint64_t cursor)
{
    return cursor & cache_scan_store_mask;
}

constexpr uint64_t cache_scan_cursor_make(uint32_t shard, uint64_t store_cursor)
{
    return (static_cast<uint64_t>(shard) << cache_scan_shard_shift)
         | (store_cursor & cache_scan_store_mask);
}

// The ownership function fingerprinted over sixteen fixed probes always, so a
// changed hash takes the filter path instead of misplacing every key.
inline constexpr uint32_t cache_fingerprint_count = 16;

inline constexpr std::string_view cache_fingerprint_probes[] = {
    "", "a", "key", "socketley", "0123456789",
    "\xff\xfe", "a longer key with spaces", "\x01\x02\x03\x04",
};

inline constexpr size_t cache_fingerprint_len =
    sizeof(cache_fingerprint_probes) / sizeof(cache_fingerprint_probes[0]);

// Eight bytes, one shard index per probe, written into every dump header and
// compared on load.
inline void cache_shard_fingerprint(unsigned char out[cache_fingerprint_len])
{
    for (size_t i = 0; i < cache_fingerprint_len; ++i)
        out[i] = static_cast<unsigned char>(
            cache_shard_of(cache_fingerprint_probes[i], cache_fingerprint_count));
}
