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
// CRC16/XMODEM over the key, modulo 16384, and then a CONTIGUOUS range of those
// slots per shard:
//
//     slot  = crc16(hash_tag_or_key) & 16383
//     shard = slot * N / 16384
//
// This is Redis's keyHashSlot() exactly, `{hash tag}` rule included, and the
// reason it is Redis's and not ours is the only reason that matters here: a
// client has to be able to compute it WITHOUT ASKING US.  redis-cli -c,
// redis-benchmark --cluster, redis-py, go-redis, lettuce and node-redis all
// already do — they read the slot map once from CLUSTER SLOTS and then open one
// connection per shard and send each key to its owner.  A key that arrives at
// its owner costs no crossing at all, and with N shards a random key is foreign
// (N-1)/N of the time, so this is the difference between paying for a crossing
// on three quarters of requests and paying for it on none.
//
// Measured on this tree, 8 client processes x 50 connections, three interleaved
// passes per arm, medians, rps per SERVER core:
//
//     four shards, clients on the shared port     63,849   15.66 us/req
//     the same runtime, clients routed to the
//       per-shard ports (zero crossings)          87,401   11.44 us/req
//     four independent single-shard caches        87,663   11.40 us/req
//
// +36.9%, and the routed arm lands within 0.3% of four separate caches.  That
// second comparison is the one that matters: the whole gap between a sharded
// runtime and N unsharded ones was the crossing, and routing removes all of it
// rather than some of it.
//
// WHAT A CROSSING COSTS, said correctly.  15.66 - 11.44 = 4.22 us is per
// REQUEST, and at four shards only (N-1)/N = 75% of requests cross -- the
// counter says so directly, 9.0 M crossings for 12 M requests.  Per crossing
// it is 4.22 / 0.75 = ~5.6 us.  Quoting the per-request difference as the
// price of a crossing understates it by a quarter, and the mistake survives
// because both numbers are in microseconds and neither is obviously wrong.
//
// Absolutes are not portable between machines or sessions: utime is time, not
// cycles, so a shift in effective clock scales both arms of a sweep alike and
// leaves the ratio intact while moving every absolute.  The ratio within one
// interleaved sweep is what is claimed here; the levels are not.
//
// Our own FNV-1a mixed better and spread more evenly and was worth nothing,
// because no off-the-shelf client can compute it.  A non-standard hash forces a
// -MOVED on every single key, which is slower than the crossing it replaces.
// Distribution quality was never the constraint; agreement with strangers is.
//
// ─── WHY CONTIGUOUS RANGES AND NOT slot % N ─────────────────────────────────
//
// Because CLUSTER SLOTS is a list of RANGES.  `slot % N` would need 16384/N
// entries per shard — 4096 ranges at N=4 — which every client would then hold
// and search per key.  `slot * N / 16384` gives each shard exactly one range,
// which is one line of the reply and a binary search over N.
//
// The ranges are not exactly equal when N does not divide 16384: at N=3 the
// shards get 5462/5461/5461 slots.  That is a 0.02% imbalance, and it is
// declared in CLUSTER SLOTS rather than hidden, which is what a client expects.
//
// ─── THE HASH TAG, AND WHY IT IS NOT OPTIONAL ───────────────────────────────
//
// `{...}` in a key means: hash only what is between the first `{` and the first
// `}` after it, provided there is something between them.  It is how a client
// puts several keys on one shard on purpose, and every cluster client emits it.
// Leaving it out would not be a smaller feature — it would be a DIFFERENT hash
// from the client's for exactly the keys where the client took care, so
// `{user:1}:name` and `{user:1}:age` would land on two shards after the client
// had guaranteed itself they would not.
//
// ─── STILL NOT STABLE ACROSS A CHANGE OF N ──────────────────────────────────
//
// Unchanged, and for the same reason: `shard_of(k, 4) != shard_of(k, 3)` for
// most keys.  The SLOT is now stable across N — that is what makes a resharding
// expressible at all — but the shard a slot lands in is not, so dumps written
// under one N and loaded under another still put keys in slices that will never
// be asked for them.  Redistribution is that step's job; N stays a parameter
// and never a member.
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "../cli/command_hashing.h"

// ─── CRC16/XMODEM ───────────────────────────────────────────────────────────
//
// Polynomial 0x1021, initial value 0, no reflection, no final xor.  The table
// is built at compile time out of the bitwise definition rather than pasted in
// as 256 magic numbers, so there is no transcription to get wrong and nothing
// that has to be checked by eye.  test_cache_slots.cpp pins it to the published
// check value and to slots Redis itself documents.
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

// What of `key` is actually hashed.  The whole key, unless it carries a
// non-empty `{...}`, in which case only what is inside.  Redis's rule to the
// letter: the FIRST `{`, the first `}` AFTER it, and an empty pair or a missing
// `}` means the whole key.
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

// The hash slot a key belongs to: 0..16383, and the same number Redis would
// give it.  Independent of the shard count, which is what lets a client cache
// a slot per key and a client library share one slot table across a resize.
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
// An empty range would need shard_count > 16384 and max_shards is 64.
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

// Which of `shard_count` shards owns `key`.  Always 0 for an unsharded cache,
// which is shard 0 of one and not a special case.
inline uint32_t cache_shard_of(std::string_view key, uint32_t shard_count)
{
    if (shard_count <= 1)
        return 0;
    return cache_shard_of_slot(cache_slot_of(key), shard_count);
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
    keyspace,     // every shard's slice at once — keys, dbsize, memory
    cursor_scan,  // one shard per call, named by the cursor; see below
    fanout,       // no key, but every shard has its own subscribers: publish
    connection,   // answered by whoever holds the socket; no key at all
    stateful,     // attaches a stream to one shard: replicate
    unknown       // not a command; the local dispatch says so
};

// ─── HOW THE PIECES OF ONE ANSWER ARE PUT BACK TOGETHER ─────────────────────
//
// A command with several keys is not sent as one command to several shards.
// It is EXPLODED into one single-key command per key -- `mget a b c` becomes
// three `get`s -- each routed to its own owner, and the replies are reassembled
// here.
//
// That is the choice that keeps this out of the trap request_channel.h names.
// Sending `mget a c` to one shard and `mget b` to another would come back as
// two multi-value replies which have to be TAKEN APART again before they can be
// interleaved, and taking them apart needs a table of reply shapes per command
// -- "the same duplication by another route".  One key in, one reply out: the
// pieces arrive already separated, and reassembly is concatenation in the order
// the caller wrote the keys.
//
// It costs nothing in crossings.  A crossing is one queue entry per SHARD per
// pipeline, and the exploded sub-commands are grouped by owner exactly like any
// others -- `mget` over 100 keys on 4 shards is still 3 crossings, carrying 25
// framed commands each.
//
// The merge rules below therefore only ever read replies to commands THIS file
// chose to send.  That is a narrower dependence than a general reply-shape
// table, and it is still a dependence: each rule names the exact command whose
// reply it reads.
enum class cache_merge : uint8_t
{
    single,     // one part, verbatim.  Every command routed by step one.
    elements,   // mget: one `get` reply per key, in the caller's order
    all_ok,     // mset: every `set` must have said ok
    sum,        // dbsize/size/memory/publish/multi-del: integers added
    key_list    // keys: the per-shard lists concatenated
};

// What a command's parts are merged with.  `single` for everything that has one
// part, which is every command step one routes.
constexpr cache_merge cache_merge_for(uint32_t h)
{
    switch (h)
    {
        case fnv1a("mget"):   return cache_merge::elements;
        case fnv1a("mset"):   return cache_merge::all_ok;
        case fnv1a("del"):    return cache_merge::sum;     // the RESP spelling
        case fnv1a("keys"):   return cache_merge::key_list;
        case fnv1a("flush"):  case fnv1a("load"):
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

        case fnv1a("keys"):
        case fnv1a("dbsize"):     case fnv1a("size"):
        case fnv1a("memory"):     case fnv1a("maxmemory"):
            return cache_cmd_class::keyspace;

        case fnv1a("scan"):
            return cache_cmd_class::cursor_scan;

        // `flush` and `load` touch the DUMP FILE rather than the keyspace, and
        // that is why they were refused on a sharded cache: fanned out, N
        // shards wrote N different slices over ONE path, last writer won, and
        // the next start loaded one shard's share.
        //
        // Each shard now writes its OWN file, and the set says what split it
        // holds, so the collision that made this dangerous no longer exists.
        // They fan out like a keyspace read, with `all_ok` rather than a sum —
        // a partial flush has to be visible as the failure it is, not averaged
        // into a number.
        case fnv1a("flush"):      case fnv1a("load"):
            return cache_cmd_class::keyspace;

        case fnv1a("publish"):
            return cache_cmd_class::fanout;

        // ─── AND THE TWO THAT MUST NOT BE FANNED OUT ────────────────────────
        //
        // subscribe and unsubscribe are answered by whoever holds the socket,
        // and that is not a gap in the fan-out — it is what a subscription IS.
        // m_store.subscribe() records a DESCRIPTOR, which means nothing in
        // another process; sending one to every shard would have N-1 of them
        // register a number belonging to whatever they happen to hold at that
        // index, and a later publish would write this client's messages into a
        // stranger's socket.
        //
        // The client is still reached by a publish on any shard, because
        // publish fans out to the shards rather than subscriptions being
        // gathered onto one.  Delivery crosses; registration does not.
        case fnv1a("ping"):
        case fnv1a("subscribe"):  case fnv1a("unsubscribe"):
        // CLUSTER names no key and needs no crossing: every field of every
        // reply is derived from the shard count and the base port, and each
        // shard holds both.  Whoever holds the socket answers for the whole
        // map — which is what lets the map be published on the shared port as
        // well as on the per-shard ones.
        case fnv1a("cluster"):
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

// ─── SCAN ACROSS N SHARDS ───────────────────────────────────────────────────
//
// SCAN is the one command here whose contract is a PROMISE ABOUT SUCCESSIVE
// CALLS, so it cannot be answered by fanning out and merging: the caller holds
// a cursor between calls and there is one integer to put it in.
//
// What is NOT possible, said plainly rather than worked around: N independent
// positions cannot be carried in one 64-bit cursor that also has to carry the
// store's own position.  Anything claiming otherwise is either widening the
// wire format or keeping per-client state on the server, and the cursor is
// documented as stateless.
//
// So the iteration is SEQUENTIAL: shard 0 to exhaustion, then shard 1, and so
// on.  One crossing per call, not N -- cheaper than a fan-out, not more
// expensive.  The cursor names the shard it belongs to.
//
//   bits 58..63   the shard whose slice this cursor is a position in
//   bits  0..57   that shard's own cursor, exactly as cache_store issues it
//
// Six bits because max_shards is 64.  They come out of the top of the store's
// cursor, whose layout is [map index : 8][bucket count : 24][bucket index : 32]
// and whose map index only ever holds 0..3 -- four maps, fixed order.  That
// leaves the top six bits genuinely unused rather than merely usually zero, and
// cache_instance.cpp static_asserts the map count against this so that a fifth
// map is a build failure and not a cursor that silently names another shard.
//
// ─── WHAT A CALLER IS PROMISED, AND WHAT IT IS NOT ──────────────────────────
//
// Unchanged from the single-store contract: a key present for the whole
// iteration is returned at least once, and a key added or removed during it may
// or may not appear.
//
// Added by sharding, and it is a real condition rather than a formality: the
// cursor is only meaningful for the shard set that issued it.  This build
// cannot violate it -- reconcile_proxy_workers() refuses to change a running
// runtime's shard count, so N is fixed for the life of a run, and a restart
// invalidates a cursor exactly as it already invalidates an unsharded one.  If
// that ever stops being true, a cursor from the old N has to be REFUSED here
// rather than followed into a shard that is not the one it meant.
//
// One visible consequence, which is a property of sequential iteration and not
// a defect: a page never mixes shards, and the call that finishes a shard
// returns an empty page carrying the next shard's opening cursor.  Redis's own
// SCAN is allowed to return an empty page with a non-zero cursor and every
// client handles it; COUNT is a hint on both.
inline constexpr int      cache_scan_shard_bits  = 6;          // max_shards == 64
inline constexpr int      cache_scan_shard_shift = 64 - cache_scan_shard_bits;
inline constexpr uint64_t cache_scan_store_mask  =
    (1ull << cache_scan_shard_shift) - 1ull;

// Which shard a cursor is a position in.  0 for every cursor an unsharded cache
// ever issues, which is what makes this a no-op there.
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

// ─── A FINGERPRINT OF THE OWNERSHIP FUNCTION ────────────────────────────────
//
// A dump written under one hash and loaded under another puts every key in the
// wrong slice.  The fast path — each shard loads its own dump and trusts the
// split — is then silently wrong, which is the failure persistence exists to
// avoid rather than to introduce.
//
// The obvious guard is a version integer in the header, bumped whenever
// cache_shard_of() changes.  That is a rule somebody has to remember, and this
// file's whole argument is that a rule call sites must remember is one the next
// change will not know about.  So there is no version to bump.
//
// Instead the dump records what the function DOES: cache_shard_of() evaluated
// over a fixed probe set at a fixed count, packed one shard index per byte.  At
// load the probes are recomputed and compared.
//
//   same function      identical fingerprint   -> the fast path is safe
//   any change to the hash, the mixing, the modulo or the character handling
//                      different fingerprint   -> the filter path, where every
//                                                 shard reads every dump and
//                                                 keeps what hashes to it
//
// It is self-verifying: nothing has to be remembered, and it cannot be wrong in
// the direction that loses data.  An unnecessary filter pass is slow; a wrongly
// trusted fast path is silent loss.
//
// ─── THE COUNT IS FIXED, AND THAT IS LOAD-BEARING ───────────────────────────
//
// Sixteen, always — never the dump's own shard count.  A fingerprint taken
// modulo the set's count would differ between a set written at N=4 and one
// written at N=8 for a function that never changed, and every cross-N load
// would take the filter path believing the hash had changed.  The fingerprint
// answers "is this the same function", not "is this the same split"; the split
// is the count and index in the header, which are recorded separately.
//
// The probes live here, beside the function they fingerprint, so the two cannot
// drift apart.
inline constexpr uint32_t cache_fingerprint_count = 16;

inline constexpr std::string_view cache_fingerprint_probes[] = {
    "", "a", "key", "socketley", "0123456789",
    "\xff\xfe", "a longer key with spaces", "\x01\x02\x03\x04",
};

inline constexpr size_t cache_fingerprint_len =
    sizeof(cache_fingerprint_probes) / sizeof(cache_fingerprint_probes[0]);

// Eight bytes, one shard index per probe.  Written into every dump header and
// compared on load.
inline void cache_shard_fingerprint(unsigned char out[cache_fingerprint_len])
{
    for (size_t i = 0; i < cache_fingerprint_len; ++i)
        out[i] = static_cast<unsigned char>(
            cache_shard_of(cache_fingerprint_probes[i], cache_fingerprint_count));
}
