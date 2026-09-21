// Fuzz target: cache_store (socketley/runtime/cache/cache_store.{h,cpp}) driven
// as a *sequence of operations* rather than as a byte string.
//
// ─── WHY A DIFFERENT SHAPE OF TARGET ────────────────────────────────────────
//
// The three targets next to this one (fuzz_resp, fuzz_ws_frame,
// fuzz_http_request) throw bytes at a parser.  That found a remote crash in the
// proxy on the first run, and it is the right tool for a parser — but this
// project's defects are not parser defects.  The ones found by hand were:
//
//   * eviction deleted a key that was still live, because a drained collection
//     left an orphaned node in m_lru_order while erasing its m_lru_map entry;
//   * get_memory_used() read ~11x low, so --maxmemory 256M let the process
//     settle at 2.8 GB;
//   * SET over an existing key skipped check_memory entirely, so a 10-byte
//     value could be replaced by a 100 MB one with the limit never consulted;
//   * APPEND reported a refusal as a successful append of nothing.
//
// None of those is reachable by mutating a byte buffer.  Every one of them
// needs a *history*: a particular sequence of writes, reads, drains and limit
// changes, with the state checked after each step.  So this target decodes the
// fuzzer's bytes into a program — four bytes per operation — runs it against a
// real cache_store, and checks a fixed set of invariants after every single
// step.  The bug is not the crash; the bug is the step where an invariant
// stopped holding, and the report below names that step.
//
// ─── THE INVARIANTS ─────────────────────────────────────────────────────────
//
//  1. AGREEMENT WITH A MODEL.  A shadow model of the store is kept alongside
//     it.  A key the model holds must be readable with exactly the value the
//     model has; a key the model does not hold must not be in the store.  The
//     one tolerated deviation is a key that *disappeared*, and only on a step
//     that could have evicted (a write, with a limit configured and an
//     eviction policy set).  Everywhere else — reads, any step with no limit,
//     any step with eviction off — a key that vanishes is a failure.  Seen from
//     outside, the eviction bug looked exactly like this.  Its sharpest form:
//     a write that reported success must leave its key readable.
//
//  2. THE REPORTED MEMORY IS NOT AN UNDERSTATEMENT.  An independent allocation
//     model (the one in test/unit/test_cache_store.cpp, deliberately *not*
//     cache_store's own arithmetic — reusing that would make the check
//     circular) gives a lower bound on what the stored strings must cost.
//     m_current_memory may never fall below it.  Reading low is the dangerous
//     direction: it is what lets a configured ceiling be exceeded.
//     Its counterpart: an empty store must report exactly zero, or a missed
//     decrement is accumulating silently.
//
//  3. THE LIMIT HOLDS.  After a write that reported success, with a limit
//     configured, usage must be at or under the limit — unless it was already
//     over before the step, which a limit lowered after the fact can produce.
//     Setting a TTL is the one exemption, and it is a deliberate one: EXPIRE
//     may carry usage past the ceiling, by the single expiry node it adds and
//     not a byte more.  The reasoning is at OP_EXPIRE, where it is enforced.
//
//  4. THE LRU AND THE KEY MAPS AGREE.  m_lru_order and m_lru_map must be a
//     bijection: same size, no key twice, and every map iterator must still
//     point at the node holding its own key.  Every key in the LRU must be a
//     live key, and while a limit is configured every live key must be in the
//     LRU.  This is the invariant the orphaned-node bug broke, and it is
//     invisible from outside the class until eviction drops a live key — which
//     is why this target reaches inside (see the note on access below).
//     Alongside it: with an LRU policy, a key evicted on a step must have been
//     *older* in the pre-step LRU order than every key that survived it.
//
//  5. SAVE/LOAD IS A ROUND TRIP.  Saving and loading into a fresh store
//     configured the same way must reproduce the keys, the values and the
//     TTLs, must satisfy every structural invariant above, and must not report
//     more memory than the original (a loaded string is exactly sized, so it
//     can cost less, never more).
//
// ─── ON REACHING INSIDE THE CLASS ───────────────────────────────────────────
//
// Invariants 2 and 4 are about m_lru_order, m_lru_map, m_current_memory and the
// element counters, all private.  There are three ways to get at them: add a
// friend declaration to cache_store.h, add a test-only accessor, or redefine
// the access specifier for this translation unit.  The first two change
// socketley/ to suit a test; the third does not, so that is what is done here.
// It is confined to the include below and undone immediately after, and the
// standard headers cache_store.h needs are pulled in *before* it so the macro
// never reaches libstdc++.  cache_store.cpp is compiled normally and linked in;
// member access affects neither layout nor mangling, so the two translation
// units agree on the object.
//
// ─── WHAT THIS TARGET DOES NOT COVER ────────────────────────────────────────
//
// The RESP command layer above cache_store (fuzz_resp covers the parser, and
// nothing covers dispatch), pub/sub, dump_commands and the replication path,
// concurrent access (cache_store is used from one thread and has no locking),
// and load() over a *corrupted* file — this target only ever loads a file that
// save() wrote.  A file-format fuzzer is a separate target and a separate
// corpus; it is the obvious next one to write.
//
// ─── TRIAGE ─────────────────────────────────────────────────────────────────
//
// On a violation the raw bytes are useless, so the failure report prints the
// decoded program as compilable C++ — paste it into test/unit/test_cache_store.cpp
// and it reproduces.  FUZZ_CACHE_SKIP=id1,id2 demotes named findings to a
// printed observation so a run can continue past a known one and look for the
// next; the ids are the first argument of each CACHE_FINDING below.  Nothing is
// skipped unless the variable names it, so CI still fails on the first one.

#include <algorithm>
#include <cerrno>
#include <cstdarg>
#include <chrono>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <functional>
#include <list>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <unistd.h>

#include "fuzz_common.h"

// See "ON REACHING INSIDE THE CLASS" above.  Every header cache_store.h needs
// is already included, so this macro is never in effect over libstdc++.
#define private public
#include "../../socketley/runtime/cache/cache_store.h"
#undef private

namespace {

// ─────────────────────────── the alphabet of a program ──────────────────────
//
// Keys, values and members come from small fixed tables rather than from
// arbitrary bytes.  Two reasons.  A decoded program has to be readable — a key
// that prints as std::string(16,'f') is a key a person can retype — and the
// invariants above are all *relational*, so they need the same key to be
// revisited over and over.  A 2^64 key space would make every operation touch a
// fresh key and no history would ever build up.
//
// The lengths are chosen around the boundaries the accounting turns on: 15 is
// the last length libstdc++ keeps inside the string object, 16 is the first
// that buys a heap block, and the rest span the malloc size classes above it.

constexpr int NKEYS = 12;

struct sized_string
{
    size_t len;
    char   ch;
};

// Distinct fill characters, so a key can be identified from its first byte.
// 'a'..'k' are keys and nothing else uses them.
constexpr sized_string KEY_SPEC[NKEYS] = {
    { 0,  '\0'},   // the empty key — legal, and nothing else in the tree tries it
    { 1,  'a'},
    { 2,  'b'},
    { 7,  'c'},
    {14,  'd'},
    {15,  'e'},    // exactly the small-string limit
    {16,  'f'},    // one past it: first heap block
    {17,  'g'},
    {26,  'h'},    // the shape get_memory_used() used to read 1.4x low on
    {31,  'i'},
    {32,  'j'},
    {63,  'k'}
};

// Values: length crosses the same boundaries; the fill characters are digits so
// that INCR sometimes lands on a value it can actually parse.  Every repeated
// digit that fits in these lengths also fits in an int64, so the model can
// predict INCR without risking an overflow of its own.
constexpr size_t VAL_LEN[] = {0, 1, 5, 15, 16, 17, 32, 64, 100, 192};
constexpr int    NVAL_LEN  = static_cast<int>(sizeof(VAL_LEN) / sizeof(VAL_LEN[0]));
constexpr char   VAL_CH[]  = {'0', '1', '5', '9', 'V', 'W', 'X', 'Y'};
constexpr int    NVAL_CH   = static_cast<int>(sizeof(VAL_CH) / sizeof(VAL_CH[0]));

// Members and hash fields share a table.  Eight of them, which is also the cap
// on how large one collection is allowed to get — see MAX_ELEMS.
constexpr int NMEM = 8;
constexpr sized_string MEM_SPEC[NMEM] = {
    { 1, 'm'}, { 5, 'n'}, {15, 'o'}, {16, 'p'},
    {20, 'q'}, { 2, 'r'}, {33, 's'}, { 9, 't'}
};

// A collection is not allowed past this many elements.  Not a property of the
// store — a harness bound, so that the O(elements) invariant walk below stays
// cheap enough to run after every step and a runaway program cannot exhaust a
// 3 GB box.  A push past the cap is recorded in the program as skipped.
constexpr size_t MAX_ELEMS = 8;

// Memory limits the program can select.  0 means "no limit", which is the
// configuration where invariant 1 is at its strongest: nothing may vanish.
constexpr size_t MEM_LIMIT[] = {0, 400, 800, 1600, 4000, 10000, 40000, 200000};
constexpr int    NMEM_LIMIT  = static_cast<int>(sizeof(MEM_LIMIT) / sizeof(MEM_LIMIT[0]));

// TTLs are one of two values on purpose: 3600s never elapses inside a fuzz
// input, and 0 has already elapsed by the time anything looks at it.  Anything
// in between would make the model's expectations depend on wall-clock timing,
// and a fuzz target that fails on a slow machine teaches nobody anything.
constexpr int64_t TTL_LONG_S  = 3600;
constexpr int64_t TTL_LONG_MS = 3600 * 1000;

const std::string& key_str(int i)
{
    static const std::vector<std::string> table = [] {
        std::vector<std::string> v;
        v.reserve(NKEYS);
        for (const auto& k : KEY_SPEC)
            v.emplace_back(k.len, k.ch);
        return v;
    }();
    return table[static_cast<size_t>(i)];
}

const std::string& val_str(int len_idx, int ch_idx)
{
    static const std::vector<std::string> table = [] {
        std::vector<std::string> v;
        v.reserve(static_cast<size_t>(NVAL_LEN * NVAL_CH));
        for (int l = 0; l < NVAL_LEN; l++)
            for (int c = 0; c < NVAL_CH; c++)
                v.emplace_back(VAL_LEN[l], VAL_CH[c]);
        return v;
    }();
    return table[static_cast<size_t>(len_idx * NVAL_CH + ch_idx)];
}

const std::string& mem_str(int i)
{
    static const std::vector<std::string> table = [] {
        std::vector<std::string> v;
        v.reserve(NMEM);
        for (const auto& m : MEM_SPEC)
            v.emplace_back(m.len, m.ch);
        return v;
    }();
    return table[static_cast<size_t>(i)];
}

// Which table entry a key belongs to.  Every key in the store came from
// KEY_SPEC, so this is a first-byte lookup; -1 means the store is holding a key
// nobody wrote, which is itself a finding.
int key_index(std::string_view k)
{
    if (k.empty())
        return 0;
    const int i = static_cast<int>(k[0]) - 'a' + 1;
    if (i < 1 || i >= NKEYS)
        return -1;
    return (k.size() == KEY_SPEC[i].len) ? i : -1;
}

// ─────────────────────────── the program ────────────────────────────────────

enum op_code : uint8_t
{
    OP_SET, OP_SETNX, OP_GETSET, OP_APPEND, OP_INCR,
    OP_GET, OP_GETPTR, OP_EXPGET,
    OP_DEL,
    OP_EXPIRE, OP_PEXPIRE, OP_PERSIST, OP_TTL,
    OP_LPUSH, OP_RPUSH, OP_LPOP, OP_RPOP, OP_LINDEX,
    OP_SADD, OP_SREM, OP_SISMEMBER,
    OP_HSET, OP_HGET, OP_HDEL,
    OP_MAXMEM, OP_EVICTION, OP_SWEEP, OP_SAVELOAD, OP_SCAN, OP_KEYS,
    OP_COUNT
};

struct step
{
    uint8_t op      = 0;
    uint8_t key     = 0;
    uint8_t a       = 0;
    uint8_t b       = 0;
    uint8_t skipped = 0;   // the harness declined to run it (collection at cap)
};

constexpr size_t MAX_STEPS = 8192;
step   g_prog[MAX_STEPS];
size_t g_steps = 0;

void print_program()
{
    std::fprintf(stderr,
        "\n--- decoded operation sequence (%zu steps) ---\n"
        "// Compilable against test/unit/test_cache_store.cpp:\n"
        "cache_store store;\n"
        "std::string out, oldval; int64_t result = 0;\n", g_steps);

    for (size_t i = 0; i < g_steps; i++)
    {
        const step& s = g_prog[i];
        const int   k = s.key % NKEYS;

        char keybuf[64];
        if (KEY_SPEC[k].len == 0)
            std::snprintf(keybuf, sizeof(keybuf), "std::string()");
        else
            std::snprintf(keybuf, sizeof(keybuf), "std::string(%zu,'%c')",
                          KEY_SPEC[k].len, KEY_SPEC[k].ch);

        char valbuf[64];
        std::snprintf(valbuf, sizeof(valbuf), "std::string(%zu,'%c')",
                      VAL_LEN[s.a % NVAL_LEN], VAL_CH[s.b % NVAL_CH]);

        char membuf[64];
        std::snprintf(membuf, sizeof(membuf), "std::string(%zu,'%c')",
                      MEM_SPEC[s.a % NMEM].len, MEM_SPEC[s.a % NMEM].ch);

        std::fprintf(stderr, "  /* %4zu */ ", i);
        if (s.skipped)
            std::fputs("// NOT RUN — harness declined it (collection at MAX_ELEMS, or "
                       "FUZZ_CACHE_SKIP names uaf-collection-evict): ", stderr);

        switch (s.op)
        {
            case OP_SET:       std::fprintf(stderr, "store.set(%s, %s);\n", keybuf, valbuf); break;
            case OP_SETNX:     std::fprintf(stderr, "store.setnx(%s, %s);\n", keybuf, valbuf); break;
            case OP_GETSET:    std::fprintf(stderr, "store.getset(%s, %s, oldval);\n", keybuf, valbuf); break;
            case OP_APPEND:    std::fprintf(stderr, "store.append(%s, %s);\n", keybuf, valbuf); break;
            case OP_INCR:      std::fprintf(stderr, "store.incr(%s, %d, result);\n", keybuf,
                                            static_cast<int>(static_cast<int8_t>(s.a))); break;
            case OP_GET:       std::fprintf(stderr, "store.get(%s, out);\n", keybuf); break;
            case OP_GETPTR:    std::fprintf(stderr, "store.get_ptr(%s);\n", keybuf); break;
            case OP_EXPGET:    std::fprintf(stderr, "store.check_expiry_and_get_ptr(%s);\n", keybuf); break;
            case OP_DEL:       std::fprintf(stderr, "store.del(%s);\n", keybuf); break;
            case OP_EXPIRE:    std::fprintf(stderr, "store.set_expiry(%s, %lld);\n", keybuf,
                                            static_cast<long long>((s.a & 1) ? 0 : TTL_LONG_S)); break;
            case OP_PEXPIRE:   std::fprintf(stderr, "store.set_expiry_ms(%s, %lld);\n", keybuf,
                                            static_cast<long long>((s.a & 1) ? 0 : TTL_LONG_MS)); break;
            case OP_PERSIST:   std::fprintf(stderr, "store.persist(%s);\n", keybuf); break;
            case OP_TTL:       std::fprintf(stderr, "store.get_ttl(%s); store.get_pttl(%s);\n", keybuf, keybuf); break;
            case OP_LPUSH:     std::fprintf(stderr, "store.lpush(%s, %s);\n", keybuf, valbuf); break;
            case OP_RPUSH:     std::fprintf(stderr, "store.rpush(%s, %s);\n", keybuf, valbuf); break;
            case OP_LPOP:      std::fprintf(stderr, "store.lpop(%s, out);\n", keybuf); break;
            case OP_RPOP:      std::fprintf(stderr, "store.rpop(%s, out);\n", keybuf); break;
            case OP_LINDEX:    std::fprintf(stderr, "store.lindex(%s, %d);\n", keybuf,
                                            static_cast<int>(static_cast<int8_t>(s.a))); break;
            case OP_SADD:      std::fprintf(stderr, "store.sadd(%s, %s);\n", keybuf, membuf); break;
            case OP_SREM:      std::fprintf(stderr, "store.srem(%s, %s);\n", keybuf, membuf); break;
            case OP_SISMEMBER: std::fprintf(stderr, "store.sismember(%s, %s);\n", keybuf, membuf); break;
            case OP_HSET:      std::fprintf(stderr, "store.hset(%s, %s, %s);\n", keybuf, membuf, valbuf); break;
            case OP_HGET:      std::fprintf(stderr, "store.hget(%s, %s);\n", keybuf, membuf); break;
            case OP_HDEL:      std::fprintf(stderr, "store.hdel(%s, %s);\n", keybuf, membuf); break;
            case OP_MAXMEM:    std::fprintf(stderr, "store.set_max_memory(%zu);\n",
                                            MEM_LIMIT[s.a % NMEM_LIMIT]); break;
            case OP_EVICTION:  std::fprintf(stderr, "store.set_eviction(%s);\n",
                                            (s.a % 3) == 0 ? "evict_none"
                                          : (s.a % 3) == 1 ? "evict_allkeys_lru"
                                                           : "evict_allkeys_random"); break;
            case OP_SWEEP:     std::fputs("store.sweep_expired();\n", stderr); break;
            case OP_SAVELOAD:  std::fputs("/* save() to a temp file, load() into a fresh store, compare */\n", stderr); break;
            case OP_SCAN:      std::fputs("/* full store.scan() walk */\n", stderr); break;
            case OP_KEYS:      std::fputs("/* store.keys(\"*\", out) */\n", stderr); break;
            default:           std::fprintf(stderr, "/* op %u */\n", s.op); break;
        }
    }
    std::fputs("--- end of sequence ---\n", stderr);
}

// Numbers a violated check wants to show — reported figure against limit,
// reported against floor.  "Over the limit" is a claim; "1712 bytes used
// against a limit of 1600, up from 1408" is a diagnosis.  Filled in by the
// check about to run and cleared afterwards.
char g_detail[512] = {0};

void set_detail(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
void set_detail(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(g_detail, sizeof(g_detail), fmt, ap);
    va_end(ap);
}

[[noreturn]] void cache_fail(const char* expr, const char* file, int line, const char* what)
{
    if (g_detail[0])
        std::fprintf(stderr, "\n--- measurements ---\n  %s\n", g_detail);
    print_program();
    ::fuzz::fail(expr, file, line, what);
}

#define CACHE_CHECK(expr, what) \
    do { if (!(expr)) cache_fail(#expr, __FILE__, __LINE__, (what)); } while (0)

// A named check that can be demoted to a printed observation with
// FUZZ_CACHE_SKIP=<id>[,<id>...].  This exists so that one known defect does not
// stop the fuzzer at step 12 of every input and hide the next one behind it.
bool finding_suppressed(const char* id)
{
    static const char* const env = [] {
        const char* e = std::getenv("FUZZ_CACHE_SKIP");
        return (e && *e) ? e : nullptr;
    }();
    if (!env)
        return false;
    const size_t n = std::strlen(id);
    for (const char* p = env; *p; )
    {
        const char* e   = std::strchr(p, ',');
        const char* end = e ? e : p + std::strlen(p);
        // Trim: a YAML folded scalar in a workflow file joins its lines with a
        // space, so an id can arrive with whitespace glued to the front of it.
        while (p < end && (*p == ' ' || *p == '\t' || *p == '\n')) p++;
        while (end > p && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\n')) end--;
        if (static_cast<size_t>(end - p) == n && std::strncmp(p, id, n) == 0)
            return true;
        if (!e)
            break;
        p = e + 1;
    }
    return false;
}

// Deliberately allocation-free, and so is everything else this file does
// outside the per-input `world`.  libFuzzer counts mallocs against frees for
// each input and runs a full LeakSanitizer scan whenever they do not match; a
// harness that grows a static buffer as it goes triggers that scan over and
// over, and a forked heap walk per input turned a 0.35 s run into 90 s.  Ids
// are string literals, so pointer identity is enough to count them.
void observe_once(const char* id, const char* what)
{
    static const char* ids[16] = {nullptr};
    static int         hits[16] = {0};
    for (int i = 0; i < 16; i++)
    {
        if (ids[i] == nullptr)
            ids[i] = id;
        if (ids[i] == id)
        {
            if (hits[i]++ < 3)
                std::fprintf(stderr, "[fuzz-cache] suppressed finding '%s': %s\n", id, what);
            return;
        }
    }
}

#define CACHE_FINDING(id, expr, what)                                        \
    do {                                                                     \
        if (!(expr))                                                         \
        {                                                                    \
            if (finding_suppressed(id)) observe_once(id, what);              \
            else cache_fail(#expr, __FILE__, __LINE__, (what));              \
        }                                                                    \
    } while (0)

// ─────────────────── the independent allocation model ───────────────────────
//
// Taken from test/unit/test_cache_store.cpp and deliberately NOT derived from
// cache_store's own constants: a floor computed with the same arithmetic the
// store uses would confirm the store rather than check it.
//
// libstdc++ keeps up to 15 bytes inside the string object; past that the string
// owns a heap block, and glibc rounds an allocation up to a 16-byte chunk with
// an 8-byte header and never hands out less than 32 bytes.  Both terms are
// *lower* bounds — the store charges by capacity, which is at least the length —
// so a store reporting less than this is reporting less memory than it holds.

constexpr size_t SSO_LIMIT = 15;

constexpr size_t heap_block(size_t len)
{
    if (len <= SSO_LIMIT)
        return 0;
    const size_t chunk = (len + 1 + 8 + 15) & ~static_cast<size_t>(15);
    return chunk < 32 ? 32 : chunk;
}

// What one stored string must cost at minimum: inside the small-string limit the
// bytes live in the node and the length is all there is; past it, the block.
constexpr size_t string_floor(size_t len)
{
    return len <= SSO_LIMIT ? len : heap_block(len);
}

// ─────────────────────────── the shadow model ───────────────────────────────

enum val_type { T_NONE = 0, T_STRING, T_LIST, T_SET, T_HASH };
enum ttl_state { TTL_NONE = 0, TTL_LONG, TTL_ELAPSED };

struct shadow_entry
{
    val_type                           type = T_NONE;
    std::string                        str;
    std::deque<std::string>            list;
    std::set<std::string>              members;
    std::map<std::string, std::string> fields;
    ttl_state                          ttl = TTL_NONE;

    void clear()
    {
        type = T_NONE;
        ttl  = TTL_NONE;
        str.clear();
        list.clear();
        members.clear();
        fields.clear();
    }
};

struct world
{
    cache_store     store;
    shadow_entry    sh[NKEYS];
    size_t          max_mem    = 0;
    eviction_policy evic       = evict_none;
    int             saves_left = 2;
    std::string     tmp_path;
    // Reused by verify_model() so that reading a value back is not one
    // allocation per key per step.  It lives here rather than in a function
    // static so that it is created and destroyed with the input, which keeps
    // libFuzzer's malloc/free counts balanced — see observe_once().
    std::string     scratch;

    // Filled by verify_model() for the step it is checking: the keys the model
    // still held that the store no longer has.  Reset per step, judged by
    // check_evictable().
    size_t          victims = 0;
    int             victim_idx[NKEYS] = {};
};

bool eviction_active(const world& w)
{
    return w.max_mem != 0 && w.evic != evict_none;
}

// Triage escape hatch for one specific defect.
//
// lpush/rpush/sadd/hset all hold an iterator into their container across
// check_memory(), which may evict — and the victim can be the very key the
// iterator names.  set() and append() re-acquire their iterator for exactly
// this reason; the four collection writers do not, so the write dereferences a
// freed node.  That is an ASan abort rather than a CACHE_FINDING, so
// FUZZ_CACHE_SKIP cannot demote it.  Naming `uaf-collection-evict` there
// instead makes the harness decline the writes that reach it, so a run can get
// past it and go on testing the other invariants.  It costs coverage of
// collections under eviction, which is why it is off by default.
bool avoid_collection_uaf(const world& w)
{
    return eviction_active(w) && finding_suppressed("uaf-collection-evict");
}

// ───────────────────── structural invariants (2 and 4) ──────────────────────

void check_structure(cache_store& s)
{
    // --- 4a: the LRU list and the LRU map are a bijection ---
    //
    // Dereferencing the map's iterator is the check that matters: if the node it
    // names was erased while the map entry stayed, this read is a
    // use-after-free and ASan says so.  That is precisely the orphan the
    // drained-collection bug produced.
    int lru_count[NKEYS];
    for (int& c : lru_count) c = 0;

    size_t order_n = 0;
    for (const std::string& k : s.m_lru_order)
    {
        const int i = key_index(k);
        CACHE_CHECK(i >= 0, "the LRU order holds a key that no operation ever wrote");
        lru_count[i]++;
        CACHE_CHECK(lru_count[i] == 1,
                    "the same key appears twice in the LRU order — eviction will walk the stale "
                    "node and delete the live key it names");
        order_n++;
    }
    CACHE_CHECK(s.m_lru_map.size() == order_n,
                "the LRU map and the LRU order hold different numbers of keys");

    for (const auto& entry : s.m_lru_map)
    {
        const int i = key_index(entry.first);
        CACHE_CHECK(i >= 0, "the LRU map holds a key that no operation ever wrote");
        CACHE_CHECK(lru_count[i] == 1, "an LRU map entry names a key that is not in the LRU order");
        CACHE_CHECK(*entry.second == entry.first,
                    "an LRU map iterator does not point at the node holding its own key");
    }

    // --- 4b: an LRU entry names a live key, and (with a limit) every live key
    //         is in the LRU ---
    //
    // The first direction: a stale entry makes eviction walk a key that no
    // longer exists.  The second: a live key outside the LRU can never be
    // evicted, so try_evict runs out of candidates while memory it could have
    // freed is still resident, and writes start failing for no visible reason.
    int live_count[NKEYS];
    for (int& c : live_count) c = 0;

    auto count_live = [&](const std::string& k) {
        const int i = key_index(k);
        CACHE_CHECK(i >= 0, "the store holds a key that no operation ever wrote");
        live_count[i]++;
    };
    for (const auto& e : s.m_data)   count_live(e.first);
    for (const auto& e : s.m_lists)  count_live(e.first);
    for (const auto& e : s.m_sets)   count_live(e.first);
    for (const auto& e : s.m_hashes) count_live(e.first);

    for (int i = 0; i < NKEYS; i++)
    {
        CACHE_CHECK(live_count[i] <= 1,
                    "one key is present under two different types at the same time");
        if (lru_count[i])
            CACHE_CHECK(live_count[i] == 1,
                        "the LRU holds a key that is in none of the data maps");
        if (s.m_max_memory != 0 && live_count[i])
            CACHE_CHECK(lru_count[i] == 1,
                        "a live key is absent from the LRU while a memory limit is configured — "
                        "it can never be evicted");
    }

    // --- the element counters feed structural_overhead(); a drifted one
    //     corrupts the reported figure permanently ---
    size_t list_elems = 0, set_elems = 0, hash_fields = 0;
    for (const auto& e : s.m_lists)  list_elems  += e.second.size();
    for (const auto& e : s.m_sets)   set_elems   += e.second.size();
    for (const auto& e : s.m_hashes) hash_fields += e.second.size();
    CACHE_CHECK(s.m_list_elems  == list_elems,  "m_list_elems has drifted from the deques it counts");
    CACHE_CHECK(s.m_set_elems   == set_elems,   "m_set_elems has drifted from the sets it counts");
    CACHE_CHECK(s.m_hash_fields == hash_fields, "m_hash_fields has drifted from the hashes it counts");

    // --- 2: the reported payload is never below what the strings must allocate ---
    //
    // A key's block is counted once for the map node, and twice more when the
    // key is in the LRU (the m_lru_order node and the m_lru_map key own a copy
    // each).  Whether it is in the LRU is *observed* rather than derived from
    // the limit, so this stays a statement about bytes and not about
    // cache_store's own rules.
    auto key_floor = [&](const std::string& k) {
        size_t bytes = string_floor(k.size());
        if (s.m_lru_map.count(k))
            bytes += 2 * heap_block(k.size());
        return bytes;
    };

    size_t floor_bytes = 0;
    for (const auto& e : s.m_data)
        floor_bytes += key_floor(e.first) + string_floor(e.second.size());
    for (const auto& e : s.m_lists)
    {
        floor_bytes += key_floor(e.first);
        for (const auto& x : e.second) floor_bytes += string_floor(x.size());
    }
    for (const auto& e : s.m_sets)
    {
        floor_bytes += key_floor(e.first);
        for (const auto& x : e.second) floor_bytes += string_floor(x.size());
    }
    for (const auto& e : s.m_hashes)
    {
        floor_bytes += key_floor(e.first);
        for (const auto& f : e.second)
            floor_bytes += string_floor(f.first.size()) + string_floor(f.second.size());
    }

    // set_detail() runs vsnprintf, so it is only reached on the failing branch:
    // this walk happens after every step and formatting a message nobody reads
    // costs more than the whole rest of the check.
    if (s.m_current_memory < floor_bytes || s.get_memory_used() < floor_bytes)
    {
        set_detail("independent floor for the strings resident is %zu bytes; the store's own "
                   "m_current_memory is %zu, get_memory_used() is %zu",
                   floor_bytes, s.m_current_memory, s.get_memory_used());
        CACHE_FINDING("mem-floor", s.m_current_memory >= floor_bytes,
                      "the store reports less memory than its own strings must have allocated — "
                      "a configured maxmemory can be exceeded by the difference");
        CACHE_CHECK(s.get_memory_used() >= floor_bytes,
                    "get_memory_used() is below what the stored strings must have allocated");
        g_detail[0] = 0;
    }

    // --- 2b: an empty store owes nothing ---
    if (s.m_data.empty() && s.m_lists.empty() && s.m_sets.empty() && s.m_hashes.empty()
        && s.m_lru_map.empty())
    {
        CACHE_FINDING("mem-baseline", s.m_current_memory == 0,
                      "every key is gone but the store still believes it holds payload — "
                      "a missed decrement, and the error only ever accumulates");
    }
}

// ───────────────────── model agreement (invariant 1) ────────────────────────

// `evict_possible` is true only on a step that could legitimately have removed
// a key the model still holds: a write, with a limit configured and a policy
// set.  On every other step a key that vanished is a defect.
void verify_model(world& w, bool evict_possible)
{
    cache_store& s = w.store;
    size_t model_keys = 0;

    w.victims = 0;

    for (int i = 0; i < NKEYS; i++)
    {
        shadow_entry&          e  = w.sh[i];
        const std::string&     k  = key_str(i);
        const std::string_view t  = s.type(k);
        const bool st_present     = (t != "none");

        CACHE_CHECK(s.exists(k) == st_present,
                    "exists() and type() disagree about whether a key is in the store");

        if (e.type == T_NONE)
        {
            CACHE_CHECK(!st_present,
                        "the store holds a key the model does not — a delete, a drain or an "
                        "expiry did not remove everything it should have");
            continue;
        }

        if (!st_present)
        {
            CACHE_FINDING("key-vanished", evict_possible,
                          "a key disappeared on a step that cannot evict — with no memory limit "
                          "(or no eviction policy) nothing may silently remove a live key");

            // Remember which key went, for check_evictable() after the step.
            // `evict_possible` on its own says only that eviction was *allowed*
            // on this step; it says nothing about which keys it was allowed to
            // take, so a store that discarded a key eviction could never have
            // chosen satisfied this check as readily as one that behaved.
            if (w.victims < NKEYS)
                w.victim_idx[w.victims++] = i;

            e.clear();
            continue;
        }

        model_keys++;

        switch (e.type)
        {
            case T_STRING:
            {
                CACHE_CHECK(t == "string", "a key the model wrote as a string has another type");
                // w.scratch is reused across steps: get() assigns into the
                // caller's buffer, so a fresh string here would be one
                // allocation per key per step, and this walk runs after every
                // step of every input.
                CACHE_CHECK(s.get(k, w.scratch), "type() says string but get() cannot read the key");
                CACHE_CHECK(w.scratch == e.str, "the stored value is not the value that was written");
                CACHE_CHECK(s.strlen_key(k) == e.str.size(), "strlen_key disagrees with the value");
                break;
            }
            case T_LIST:
            {
                CACHE_CHECK(t == "list", "a key the model wrote as a list has another type");
                const auto* d = s.list_ptr(k);
                CACHE_CHECK(d != nullptr, "type() says list but list_ptr() returns nothing");
                CACHE_CHECK(d->size() == e.list.size(), "the list has a different length than was written");
                for (size_t j = 0; j < e.list.size(); j++)
                    CACHE_CHECK((*d)[j] == e.list[j], "a list element is not what was pushed");
                CACHE_CHECK(static_cast<size_t>(s.llen(k)) == e.list.size(), "llen disagrees with the list");
                break;
            }
            case T_SET:
            {
                CACHE_CHECK(t == "set", "a key the model wrote as a set has another type");
                const auto* m = s.set_ptr(k);
                CACHE_CHECK(m != nullptr, "type() says set but set_ptr() returns nothing");
                CACHE_CHECK(m->size() == e.members.size(), "the set has a different size than was written");
                for (const auto& mem : e.members)
                    CACHE_CHECK(s.sismember(k, mem), "a member that was added is not in the set");
                CACHE_CHECK(static_cast<size_t>(s.scard(k)) == e.members.size(), "scard disagrees with the set");
                break;
            }
            case T_HASH:
            {
                CACHE_CHECK(t == "hash", "a key the model wrote as a hash has another type");
                const auto* h = s.hash_ptr(k);
                CACHE_CHECK(h != nullptr, "type() says hash but hash_ptr() returns nothing");
                CACHE_CHECK(h->size() == e.fields.size(), "the hash has a different size than was written");
                for (const auto& f : e.fields)
                {
                    const std::string* got = s.hget(k, f.first);
                    CACHE_CHECK(got != nullptr, "a field that was written is not in the hash");
                    CACHE_CHECK(*got == f.second, "a hash field holds a value that was never written to it");
                }
                CACHE_CHECK(static_cast<size_t>(s.hlen(k)) == e.fields.size(), "hlen disagrees with the hash");
                break;
            }
            default: break;
        }

        // TTL.  The two settings are far apart on purpose (see TTL_LONG_S), so
        // this needs no timing tolerance beyond a sanity band.
        const int64_t ttl  = s.get_ttl(k);
        const int64_t pttl = s.get_pttl(k);
        const bool ttl_ok = (e.ttl == TTL_NONE)  ? (ttl == -1 && pttl == -1)
                          : (e.ttl == TTL_LONG)  ? (ttl > 0 && ttl <= TTL_LONG_S
                                                    && pttl > 0 && pttl <= TTL_LONG_MS)
                                                 : (ttl <= 0);
        if (!ttl_ok)
        {
            set_detail("key %d (%zu bytes of '%c'), type %.*s: the model set %s, the store reports "
                       "ttl=%lld pttl=%lld",
                       i, KEY_SPEC[i].len, KEY_SPEC[i].len ? KEY_SPEC[i].ch : '-',
                       static_cast<int>(t.size()), t.data(),
                       e.ttl == TTL_NONE ? "no expiry"
                     : e.ttl == TTL_LONG ? "an expiry an hour out" : "an expiry that has elapsed",
                       static_cast<long long>(ttl), static_cast<long long>(pttl));
            if (e.ttl == TTL_NONE)
                CACHE_CHECK(false, "a key with no expiry reports one");
            else if (e.ttl == TTL_LONG)
                CACHE_CHECK(false, "an expiry an hour out is not there any more, or is not what it was set to");
            else
                CACHE_CHECK(false, "a TTL that has already elapsed reports as still running");
        }
    }

    CACHE_CHECK(s.size() == model_keys,
                "size() does not match the number of keys the model expects to be present");

    // ── eviction had to be necessary, key by key ──
    //
    // "key-vanished" above asks only whether eviction was *permitted* on this
    // step.  That is one bit for the whole step, so once a limit and a policy
    // were configured, a store that evicted a single key and one that emptied
    // itself were indistinguishable to it — and over-eviction is not a
    // theoretical worry here, it is how a cache turns into a slow database
    // under load.
    //
    // The stronger statement: eviction runs until the store is back under its
    // limit and stops.  So the last key it took had to be needed, and putting
    // the cheapest victim back must leave the store over the limit.  Measured
    // with the model's floor, which is a *lower* bound on what that key cost —
    // so the real key was at least this big, and if even this much would not
    // have fitted, none of it would have.  One-sided on purpose: the check can
    // only fire when the store freed more than any accounting of its own could
    // justify.
    // The victims themselves are judged by the caller, which has the LRU
    // snapshot taken before the step — see the note at check_evictable() for
    // why that is the sharp question and how much memory the store used is not.
}

// ───────────────── eviction order (the other half of invariant 4) ───────────

struct lru_snapshot
{
    int  pos[NKEYS];       // position in the LRU order before the step, -1 = absent
    bool present[NKEYS];   // key was live before the step
};

void snapshot_lru(world& w, lru_snapshot& snap)
{
    for (int i = 0; i < NKEYS; i++)
    {
        snap.pos[i]     = -1;
        snap.present[i] = (w.sh[i].type != T_NONE);
    }
    int p = 0;
    for (const std::string& k : w.store.m_lru_order)
    {
        const int i = key_index(k);
        if (i >= 0)
            snap.pos[i] = p;
        p++;
    }
}

// Which keys eviction was allowed to take, as opposed to how many.
//
// "key-vanished" in verify_model() asks only whether eviction was *permitted*
// on this step — one bit for the whole step.  Once a limit and a policy were
// configured it accepted any key disappearing, from anywhere, which is a good
// deal weaker than the property it stands for.  The two sharp statements, both
// of them free of arithmetic:
//
//   * Eviction takes from m_lru_order and nowhere else.  A key that was live
//     but *not in that order* is one try_evict() could not have reached, so if
//     it is gone, something else dropped it — and the store has no other
//     mechanism that may.  This is the shape of the defect that once left an
//     orphaned LRU node behind: order and map coming apart, in the other
//     direction.
//   * The key the step is writing is protected: check_memory() passes it to
//     try_evict() precisely so that it cannot be chosen, which is what stopped
//     the collection writers from working through a freed node.  If it went
//     anyway, that protection is not holding.
//
// Deliberately not phrased in bytes.  The obvious "it should have stopped once
// it was back under the limit" cannot be checked from out here: the store evicts
// against an *estimate* of what the write will cost, and the model's floor is a
// lower bound on what a key cost, so the two disagree by margins wide enough to
// swallow the property.  These two do not depend on either number.
void check_evictable(world& w, const lru_snapshot& snap, int wrote_key)
{
    for (size_t v = 0; v < w.victims; v++)
    {
        const int i = w.victim_idx[v];

        CACHE_FINDING("evict-not-candidate", !(snap.present[i] && snap.pos[i] < 0),
                      "a key vanished that was not in the eviction order — try_evict() takes "
                      "from m_lru_order and nothing else may remove a live key, so the order "
                      "and the map have come apart");

        CACHE_FINDING("evict-wrote-key", i != wrote_key,
                      "eviction took the very key the step was writing, although check_memory() "
                      "names it precisely so that try_evict() will not choose it — the write "
                      "then works through storage that has been freed");
    }
}

// After an LRU-policy step: everything that was evicted must have been older
// than everything that survived.  try_evict takes from the front of
// m_lru_order, so this holds by construction — unless the order and the map
// have come apart, which is exactly the bug that dropped a live,
// most-recently-used key.  The key the step itself wrote is excluded: it is
// touched to the back after eviction runs, so its own position says nothing.
void check_eviction_order(world& w, const lru_snapshot& snap, int wrote_key)
{
    int newest_victim   = -1;
    int oldest_survivor = INT_MAX;

    for (int i = 0; i < NKEYS; i++)
    {
        if (!snap.present[i] || i == wrote_key || snap.pos[i] < 0)
            continue;
        if (w.store.type(key_str(i)) != "none")
            oldest_survivor = std::min(oldest_survivor, snap.pos[i]);
        else
            newest_victim = std::max(newest_victim, snap.pos[i]);
    }

    if (newest_victim >= 0 && oldest_survivor != INT_MAX)
        CACHE_FINDING("lru-order", newest_victim < oldest_survivor,
                      "LRU eviction removed a key that was more recently used than one it left "
                      "behind — the eviction order and the key map have come apart");
}

// ───────────────────── save/load round trip (invariant 5) ───────────────────

void check_save_load(world& w)
{
    cache_store& src = w.store;

    // A key whose TTL has already elapsed is handled asymmetrically by the file
    // format (see the report), so the value comparison below is only run when
    // nothing is mid-expiry.  Those shapes still reach save() and load(); they
    // are just not compared field by field.
    bool any_elapsed = false;
    for (int i = 0; i < NKEYS; i++)
        if (w.sh[i].type != T_NONE && w.sh[i].ttl == TTL_ELAPSED)
            any_elapsed = true;

    if (!src.save(w.tmp_path))
        return;   // a full /dev/shm is the machine's problem, not the store's

    cache_store dst;
    dst.set_max_memory(src.m_max_memory);
    dst.set_eviction(src.m_eviction);
    CACHE_CHECK(dst.load(w.tmp_path), "load() rejected a file that save() had just written");

    // The loaded store has to satisfy every structural invariant on its own.
    // load() once inserted straight into the containers, leaving the accounting
    // at zero and the LRU empty — which makes the configured limit
    // unenforceable for everything that came off disk.
    check_structure(dst);

    if (any_elapsed)
        return;

    for (int i = 0; i < NKEYS; i++)
    {
        const std::string& k = key_str(i);
        CACHE_CHECK(src.type(k) == dst.type(k),
                    "a key came back from save/load with a different type, or did not come back");

        const std::string_view t = src.type(k);
        if (t == "string")
        {
            std::string a, b;
            src.get(k, a);
            dst.get(k, b);
            CACHE_CHECK(a == b, "a string value did not survive save/load intact");
        }
        else if (t == "list")
        {
            const auto* a = src.list_ptr(k);
            const auto* b = dst.list_ptr(k);
            CACHE_CHECK(a && b && *a == *b, "a list did not survive save/load intact (contents or order)");
        }
        else if (t == "set")
        {
            const auto* a = src.set_ptr(k);
            const auto* b = dst.set_ptr(k);
            CACHE_CHECK(a && b && a->size() == b->size(), "a set changed size across save/load");
            for (const auto& m : *a)
                CACHE_CHECK(b->count(m) == 1, "a set member did not survive save/load");
        }
        else if (t == "hash")
        {
            const auto* a = src.hash_ptr(k);
            const auto* b = dst.hash_ptr(k);
            CACHE_CHECK(a && b && a->size() == b->size(), "a hash changed size across save/load");
            for (const auto& f : *a)
            {
                const std::string* got = dst.hget(k, f.first);
                CACHE_CHECK(got && *got == f.second, "a hash field did not survive save/load");
            }
        }

        // TTLs are serialised as a remaining-milliseconds delta rather than as
        // a deadline, which is the right choice — steady_clock has no meaning
        // across a restart — but it means the round trip *extends* the deadline
        // by however long the save and the load took.  So the tolerance is
        // two-sided.  It was one-sided at first, and 1.6 million executions in,
        // a loaded machine took long enough between save() and load() for the
        // extension to show: a real property of the format, not a defect, and
        // worth having stated here rather than rediscovered.
        const int64_t pa = src.get_pttl(k);
        const int64_t pb = dst.get_pttl(k);
        if (pa < 0 || pb < 0 || pa - pb > 5000 || pb - pa > 5000)
        {
            set_detail("key %d (%zu bytes of '%c'), type %.*s: pttl was %lld before save and "
                       "%lld after load",
                       i, KEY_SPEC[i].len, KEY_SPEC[i].len ? KEY_SPEC[i].ch : '-',
                       static_cast<int>(t.size()), t.data(),
                       static_cast<long long>(pa), static_cast<long long>(pb));
            if (pa < 0 || pb < 0)
                CACHE_CHECK(pa == pb, "a TTL turned into a non-TTL (or the reverse) across save/load");
            else
                CACHE_CHECK(false, "a TTL came back from save/load with a wildly different deadline");
            g_detail[0] = 0;
        }
    }

    // Usage across the round trip.  It is NOT equality, and the reason is worth
    // stating because it is itself a (small) finding:
    //
    //   load_v2 builds every string with `out.assign(p, len)` on a fresh
    //   std::string, and libstdc++'s _M_create doubles the old capacity when
    //   the request is under twice it — so a fresh string asked for 16..29
    //   bytes comes back with capacity 30, where the std::string(string_view)
    //   the live write paths use gives exactly `len`.  For lengths 16..23 that
    //   is one whole malloc size class, 16 bytes, per string.  A cache that
    //   reloads its own dump therefore occupies slightly *more* than the one
    //   that wrote it, and get_memory_used() correctly reports the growth.
    //
    // So the check is one class per string in either direction: below the floor
    // (checked by check_structure(dst) above) means load() lost track of bytes
    // it is holding — the defect that once left a reloaded store reporting
    // zero; more than one class per string above the original means it is
    // charging for something twice.
    size_t loaded_strings = dst.m_data.size() * 2 + dst.m_lists.size()
                          + dst.m_sets.size() + dst.m_hashes.size()
                          + dst.m_list_elems + dst.m_set_elems + dst.m_hash_fields * 2;
    CACHE_FINDING("load-usage",
                  dst.get_memory_used() <= src.get_memory_used() + 16 * loaded_strings,
                  "a store reports far more memory after save/load than the store it was written "
                  "from — more than one malloc size class per restored string");
}

// ───────────────────────────── the interpreter ──────────────────────────────

// Apply the expiry the store is about to apply.  A TTL of 0 has elapsed by the
// time anything looks at it, so this is deterministic rather than a race: every
// entry point that calls check_expiry() removes the key.
void model_expire(world& w, int i)
{
    if (w.sh[i].type != T_NONE && w.sh[i].ttl == TTL_ELAPSED)
        w.sh[i].clear();
}

// Called on the failure path of every entry point that goes through set().
//
// set() drops the key's expiry as its very first act — before the type-conflict
// check and before check_memory — so a SET that is *refused* still strips the
// TTL off the key it refused to write.  The client sees an error and has every
// reason to believe nothing happened; the key it was told about now never
// expires.  Raised here rather than in verify_model() so the message names the
// step, and the model is resynchronised afterwards so that a suppressed run can
// keep looking for the next thing.
void check_failed_write_kept_ttl(world& w, int ki, const char* what)
{
    shadow_entry& e = w.sh[ki];
    if (e.type == T_NONE)
        return;
    const int64_t ttl = w.store.get_ttl(key_str(ki));
    CACHE_FINDING("failed-set-drops-ttl",
                  !(e.ttl != TTL_NONE && ttl == -1), what);
    if (ttl == -1)
        e.ttl = TTL_NONE;   // resync, so the generic TTL check does not re-fire
}

// Returns true when the harness declined to run the step (see MAX_ELEMS).
bool run_step(world& w, const step& s)
{
    const int          ki  = s.key % NKEYS;
    const std::string& k   = key_str(ki);
    shadow_entry&      e   = w.sh[ki];
    const std::string& val = val_str(s.a % NVAL_LEN, s.b % NVAL_CH);
    const std::string& mem = mem_str(s.a % NMEM);

    const bool   had_limit    = (w.max_mem != 0);
    const bool   can_evict    = eviction_active(w);
    const size_t usage_before = w.store.get_memory_used();

    // Is a refusal excusable at all?  "A limit is configured" was the old
    // answer, and it is far too generous: with an eviction policy set, a store
    // refuses a write only when eviction cannot make room for it.  Redis
    // returns OOM on that condition and no other.
    //
    // Evaluated after the write returned, and deliberately not in bytes.  Two
    // attempts at this were written in bytes first and both had to be thrown
    // away, because they called correct refusals defects: the store admits
    // against an *estimate* of what a write will cost, the model knows only a
    // lower bound on what it did cost, and the gap between them is wider than
    // the property.  hset() pays for a field, a value and a node; the model
    // counted a key and a value.
    //
    // The arithmetic-free statement is exact.  try_evict() loops until the
    // store is back under its limit — in which case the write is admitted, not
    // refused — or until it has no candidate left.  The key being written is
    // never a candidate: check_memory() names it precisely so that eviction
    // cannot choose it, which is what stopped the collection writers from
    // working through a freed node.  So a refusal under an active policy means
    // the eviction order held nothing but that key; anything else still in it
    // is room the store was allowed to take and did not.
    auto refusal_excusable = [&]() -> bool {
        if (!had_limit)  return false;   // nothing may be refused for memory at all
        if (!can_evict)  return true;    // nothing may be freed to make room
        for (const std::string& lk : w.store.m_lru_order)
            if (lk != k)
                return false;            // a candidate was still standing there
        return true;
    };

    lru_snapshot snap{};
    const bool lru_policy = (w.max_mem != 0 && w.evic == evict_allkeys_lru);
    if (lru_policy)
        snapshot_lru(w, snap);

    // Set by the write handlers: the key this step wrote, and whether the store
    // reported the write as accepted.
    int  wrote_key       = -1;
    bool wrote_ok        = false;
    bool is_memory_write = false;
    bool evict_possible  = false;

    // Whether the key the write targets was there before the write, read after
    // any expiry the op itself applies.  A write that is *refused* must leave
    // that key exactly as it found it — the caller was told no.
    bool target_existed  = false;
    ttl_state target_ttl_before = TTL_NONE;

    // With no limit configured, no write may be refused for any reason other
    // than a type conflict.  A refusal there means the store invented a reason
    // to drop a client's data.
    auto type_conflicts = [&](val_type want) {
        return e.type != T_NONE && e.type != want;
    };

    switch (s.op)
    {
        case OP_SET:
        {
            // set() does not call check_expiry(): it erases the key's expiry
            // outright and overwrites in place, so an elapsed TTL neither
            // removes the key first nor changes the type conflict.
            wrote_key       = ki;
            is_memory_write = true;
            evict_possible  = can_evict;
            target_existed  = (e.type != T_NONE);
            target_ttl_before = e.ttl;
            const bool conflict = type_conflicts(T_STRING);
            const bool ok = w.store.set(k, val);
            wrote_ok = ok;
            if (ok)
            {
                CACHE_CHECK(!conflict, "set() overwrote a key that is not a string");
                e.type = T_STRING;
                e.str  = val;
                e.ttl  = TTL_NONE;    // a plain SET drops the expiry
            }
            else
            {
                CACHE_FINDING("write-refused", conflict || refusal_excusable(),
                              "set() refused a write that it had room for after eviction, with no type conflict");
                check_failed_write_kept_ttl(w, ki,
                    "a SET that was refused (wrong type, or no room under maxmemory) still erased "
                    "the key's expiry — the caller got an error and the key it named is now immortal");
            }
            break;
        }
        case OP_SETNX:
        {
            model_expire(w, ki);   // setnx() calls check_expiry() first
            wrote_key       = ki;
            is_memory_write = true;
            evict_possible  = can_evict;
            target_existed  = (e.type != T_NONE);
            target_ttl_before = e.ttl;
            const bool existed  = (e.type != T_NONE);
            const bool conflict = type_conflicts(T_STRING);
            const bool ok = w.store.setnx(k, val);
            wrote_ok = ok;
            if (ok)
            {
                CACHE_CHECK(!existed, "setnx() overwrote a key that already existed");
                e.type = T_STRING;
                e.str  = val;
                e.ttl  = TTL_NONE;
            }
            else
            {
                CACHE_FINDING("write-refused", existed || conflict || refusal_excusable(),
                              "setnx() refused to create a key that did not exist, and had room for it after eviction");
            }
            break;
        }
        case OP_GETSET:
        {
            model_expire(w, ki);   // getset() calls check_expiry() first
            wrote_key       = ki;
            is_memory_write = true;
            evict_possible  = can_evict;
            target_existed  = (e.type != T_NONE);
            target_ttl_before = e.ttl;
            const bool        conflict   = type_conflicts(T_STRING);
            const std::string expect_old = (e.type == T_STRING) ? e.str : std::string();
            std::string oldval = "sentinel";
            const bool ok = w.store.getset(k, val, oldval);
            wrote_ok = ok;
            if (ok)
            {
                CACHE_CHECK(!conflict, "getset() overwrote a key that is not a string");
                CACHE_CHECK(oldval == expect_old, "getset() returned a value the key never held");
                e.type = T_STRING;
                e.str  = val;
                e.ttl  = TTL_NONE;
            }
            else
            {
                CACHE_FINDING("write-refused", conflict || refusal_excusable(),
                              "getset() refused a write that it had room for after eviction, with no type conflict");
                check_failed_write_kept_ttl(w, ki,
                    "a GETSET that was refused still erased the key's expiry — it forwards to set(), "
                    "which drops the TTL before it can fail");
            }
            break;
        }
        case OP_APPEND:
        {
            model_expire(w, ki);   // append() calls check_expiry() first
            wrote_key       = ki;
            is_memory_write = true;
            evict_possible  = can_evict;
            target_existed  = (e.type != T_NONE);
            target_ttl_before = e.ttl;
            const bool conflict = type_conflicts(T_STRING);
            const size_t r = w.store.append(k, val);
            if (r == cache_store::append_wrong_type)
            {
                CACHE_CHECK(conflict, "append() reported a type conflict on a key that is a string or absent");
            }
            else if (r == cache_store::append_denied)
            {
                CACHE_FINDING("write-refused", refusal_excusable(),
                              "append() reported a memory refusal for a write it had room for after eviction");
            }
            else
            {
                CACHE_CHECK(!conflict, "append() wrote to a key that is not a string");
                const std::string prev = (e.type == T_STRING) ? e.str : std::string();
                e.type = T_STRING;
                e.str  = prev + val;
                wrote_ok = true;

                if (r != e.str.size())
                {
                    // The one legitimate-looking way this happens: check_memory
                    // evicted the very key being appended to, and append() then
                    // fell through to its create branch, storing the suffix
                    // alone.  It still returns a length and still reports
                    // success, so a client building a value with APPEND gets it
                    // silently truncated to the last chunk it sent — the same
                    // class of defect as the refusal that used to be reported as
                    // a successful append of nothing.
                    set_detail("APPEND returned %zu; the value before it was %zu bytes and the "
                               "suffix %zu, so the result should be %zu",
                               r, prev.size(), val.size(), e.str.size());
                    CACHE_FINDING("append-self-evict", !(can_evict && r == val.size()),
                                  "APPEND evicted the key it was appending to, then reported "
                                  "success after storing only the suffix — the value that was "
                                  "there is gone and the caller was not told");
                    CACHE_CHECK(can_evict && r == val.size(),
                                "append() returned a length that is not the length of the "
                                "resulting value");
                    g_detail[0] = 0;
                    // Resync to what the store actually holds.  The eviction
                    // took the key's expiry with it, so the recreated key has
                    // none — that is part of the same loss.
                    e.str = val;
                    e.ttl = TTL_NONE;
                }
                else if (target_ttl_before == TTL_LONG && w.store.get_ttl(k) == -1)
                {
                    // The same self-eviction, in the one shape the returned
                    // length cannot show: when the value was empty, "the suffix
                    // alone" and "the old value plus the suffix" are the same
                    // number of bytes.  The vanished TTL is what gives it away.
                    CACHE_FINDING("append-self-evict", false,
                                  "APPEND evicted the key it was appending to and recreated it, "
                                  "so the key silently lost its expiry");
                    e.ttl = TTL_NONE;
                }
            }
            break;
        }
        case OP_INCR:
        {
            model_expire(w, ki);   // incr() calls check_expiry() first
            wrote_key       = ki;
            is_memory_write = true;
            evict_possible  = can_evict;
            target_existed  = (e.type != T_NONE);
            target_ttl_before = e.ttl;
            const int64_t delta    = static_cast<int8_t>(s.a);
            const bool    conflict = type_conflicts(T_STRING);

            // Is the current value one std::from_chars accepts whole?  The model
            // has to know, because incr() returning false is legitimate for a
            // value that is not an integer.
            bool      numeric = true;
            long long cur     = 0;
            if (e.type == T_STRING)
            {
                if (e.str.empty())
                    numeric = false;
                else
                {
                    errno = 0;
                    char* endp = nullptr;
                    cur = std::strtoll(e.str.c_str(), &endp, 10);
                    if (errno != 0 || endp != e.str.c_str() + e.str.size())
                        numeric = false;
                }
            }
            else if (e.type != T_NONE)
            {
                numeric = false;
            }

            // The model's own sum, computed the way the store has to compute
            // it: `cur + delta` is undefined when it leaves int64, so the
            // model cannot form it and then ask whether it fits.
            int64_t    sum      = 0;
            const bool sum_fits = !__builtin_add_overflow(static_cast<int64_t>(cur), delta, &sum);

            int64_t result = 0;
            const auto st  = w.store.incr(k, delta, result);
            const bool ok  = (st == cache_store::incr_result::ok);
            wrote_ok = ok;
            if (ok)
            {
                CACHE_CHECK(!conflict, "incr() wrote to a key that is not a string");
                CACHE_CHECK(numeric, "incr() accepted a value that is not an integer");
                CACHE_CHECK(sum_fits, "incr() wrote a sum int64 cannot hold");
                CACHE_CHECK(result == sum, "incr() produced the wrong sum");
                char buf[32];
                std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(result));
                e.type = T_STRING;
                e.str  = buf;
            }
            else if (st == cache_store::incr_result::would_overflow)
            {
                CACHE_CHECK(numeric && !sum_fits,
                            "incr() called a sum an overflow when the model's own sum fits");
            }
            else
            {
                CACHE_FINDING("write-refused", conflict || !numeric || refusal_excusable(),
                              "incr() refused an integer value it had room for after eviction");
            }
            break;
        }

        case OP_GET:
        {
            std::string out = "sentinel";
            const bool ok = w.store.get(k, out);
            CACHE_CHECK(ok == (e.type == T_STRING), "get() disagrees with the model about a key");
            if (ok)
                CACHE_CHECK(out == e.str, "get() returned a value that was never written");
            break;
        }
        case OP_GETPTR:
        {
            const std::string* p = w.store.get_ptr(k);
            CACHE_CHECK((p != nullptr) == (e.type == T_STRING), "get_ptr() disagrees with the model");
            if (p)
                CACHE_CHECK(*p == e.str, "get_ptr() returned a value that was never written");
            break;
        }
        case OP_EXPGET:
        {
            const bool expect_drop = (e.type != T_NONE && e.ttl == TTL_ELAPSED);
            model_expire(w, ki);
            const std::string* p = w.store.check_expiry_and_get_ptr(k);
            if (expect_drop)
                CACHE_CHECK(p == nullptr, "check_expiry_and_get_ptr() returned a value for an expired key");
            CACHE_CHECK((p != nullptr) == (e.type == T_STRING),
                        "check_expiry_and_get_ptr() disagrees with the model");
            if (p)
                CACHE_CHECK(*p == e.str, "check_expiry_and_get_ptr() returned a value that was never written");
            break;
        }

        case OP_DEL:
        {
            const bool existed = (e.type != T_NONE);
            const bool ok = w.store.del(k);
            CACHE_CHECK(ok == existed, "del() disagrees with the model about whether the key existed");
            e.clear();
            break;
        }

        case OP_EXPIRE:
        case OP_PEXPIRE:
        {
            const bool elapsed = (s.a & 1) != 0;
            const bool existed = (e.type != T_NONE);
            // Read before the call: the exemption below is expressed in nodes
            // the store actually added, not in a number written out here.
            const size_t nodes_before = w.store.m_expiry.size();
            const bool ok = (s.op == OP_EXPIRE)
                          ? w.store.set_expiry(k, elapsed ? 0 : TTL_LONG_S)
                          : w.store.set_expiry_ms(k, elapsed ? 0 : TTL_LONG_MS);
            CACHE_CHECK(ok == existed, "set_expiry() disagrees with the model about whether the key existed");
            if (ok)
                e.ttl = elapsed ? TTL_ELAPSED : TTL_LONG;

            // ── invariant 3 is deliberately relaxed here ────────────────────
            //
            // Setting a TTL adds one m_expiry node, which structural_overhead()
            // prices at expiry_entry_overhead bytes, and set_expiry() never
            // consults max_memory.  This target used to call that a defect.  It
            // is not one; the oracle was wrong.
            //
            // Redis classifies EXPIRE as not a denyoom command, and the reason
            // is worth stating rather than citing: a command whose whole purpose
            // is to let data *expire* must not fail because there is too much
            // data.  Setting a TTL is how a caller reduces pressure — it hands
            // the store standing permission to drop that key unasked.  Refusing
            // it at the ceiling is backwards: it would lock a full cache into a
            // state whose only exit is an explicit DEL, and it would do so at
            // the exact moment the caller was trying to give memory back.
            //
            // Both alternatives were tried against this target and both cost
            // more than they bought.  EXPIRE must return true exactly when the
            // key exists (the check above), must remove no key (`key-vanished`,
            // and see the note on evict_possible below), and — as this used to
            // demand — must stay under the ceiling.  A 64-byte node cannot
            // satisfy all three: evicting to make room breaks the second,
            // refusing breaks the first.  The ceiling is the one that gives.
            //
            // What is NOT forgiven is a byte beyond that one node.  The
            // exemption is bounded per step by the node the store actually
            // added, and bounded in total because there is at most one expiry
            // node per key — del(), check_expiry() and try_evict() all erase the
            // node with the key, so orphans cannot accumulate.  Nor does the
            // overshoot compound: get_memory_used() counts these nodes, so the
            // next write either evicts back down past them or is refused.  This
            // path offsets the ceiling by a bounded cost per expiring key; it
            // does not creep past it.  A TTL that moved the figure by more than
            // its own node is charging for payload on a path that stores none,
            // and that is still a finding.
            const size_t used_after   = w.store.get_memory_used();
            const size_t nodes_after  = w.store.m_expiry.size();
            const size_t nodes_added  = nodes_after > nodes_before ? nodes_after - nodes_before : 0;
            const size_t allowance    = nodes_added * cache_store::expiry_entry_overhead;

            if (ok && had_limit && usage_before <= w.max_mem
                && used_after > w.max_mem + allowance)
            {
                set_detail("maxmemory %zu, used %zu before the EXPIRE and %zu after (+%zu); "
                           "the step added %zu expiry node(s), worth %zu bytes, and that is the "
                           "whole of what this path is allowed to add",
                           w.max_mem, usage_before, used_after, used_after - usage_before,
                           nodes_added, allowance);
                CACHE_FINDING("expire-over-limit", false,
                              "setting a TTL took the store further past its configured maxmemory "
                              "than the expiry node it added accounts for — the expiry path is "
                              "charging for something it does not store");
                g_detail[0] = 0;
            }

            // evict_possible stays false for this step, and the exemption does
            // not change that.  set_expiry()/set_expiry_ms() call exists() and
            // then emplace into m_expiry; neither exists() nor emplace has a
            // removal path, and with the limit out of the picture there is no
            // check_memory() call to reach try_evict() either.  So an EXPIRE
            // that loses a key is a genuine defect and `key-vanished` should
            // still fire on it — which is precisely the check that would catch a
            // future set_expiry() that decided to evict its way under the limit.
            break;
        }
        case OP_PERSIST:
        {
            const bool had = (e.type != T_NONE && e.ttl != TTL_NONE);
            const bool ok  = w.store.persist(k);
            CACHE_CHECK(ok == had, "persist() disagrees with the model about whether a TTL was set");
            if (ok)
                e.ttl = TTL_NONE;
            break;
        }
        case OP_TTL:
            // verify_model() checks get_ttl/get_pttl for every key on every step
            // anyway; this op exists so the fuzzer can spend a step doing
            // nothing, which is a useful shape to have between two writes.
            if (w.store.get_ttl(k) == INT64_MIN) {}
            if (w.store.get_pttl(k) == INT64_MIN) {}
            break;

        case OP_LPUSH:
        case OP_RPUSH:
        {
            if ((e.type == T_LIST && e.list.size() >= MAX_ELEMS) || avoid_collection_uaf(w))
                return true;
            wrote_key       = ki;
            is_memory_write = true;
            evict_possible  = can_evict;
            target_existed  = (e.type != T_NONE);
            target_ttl_before = e.ttl;
            const bool conflict = type_conflicts(T_LIST);
            const bool ok = (s.op == OP_LPUSH) ? w.store.lpush(k, val) : w.store.rpush(k, val);
            wrote_ok = ok;
            if (ok)
            {
                CACHE_CHECK(!conflict, "a push wrote to a key that is not a list");
                e.type = T_LIST;
                if (s.op == OP_LPUSH) e.list.push_front(val);
                else                  e.list.push_back(val);
            }
            else
            {
                CACHE_FINDING("write-refused", conflict || refusal_excusable(),
                              "a push was refused that it had room for after eviction, with no type conflict");
            }
            break;
        }
        case OP_LPOP:
        case OP_RPOP:
        {
            const bool expect = (e.type == T_LIST && !e.list.empty());
            std::string out = "sentinel";
            const bool ok = (s.op == OP_LPOP) ? w.store.lpop(k, out) : w.store.rpop(k, out);
            CACHE_CHECK(ok == expect, "a pop disagrees with the model about whether the list had elements");
            if (ok)
            {
                const std::string want = (s.op == OP_LPOP) ? e.list.front() : e.list.back();
                CACHE_CHECK(out == want, "a pop returned an element that was never pushed");
                if (s.op == OP_LPOP) e.list.pop_front();
                else                 e.list.pop_back();
                if (e.list.empty())
                    e.clear();   // draining a list deletes the key, TTL and all
            }
            break;
        }
        case OP_LINDEX:
        {
            const int  idx = static_cast<int8_t>(s.a);
            const std::string* p = w.store.lindex(k, idx);
            long j = idx;
            if (e.type == T_LIST && j < 0)
                j += static_cast<long>(e.list.size());
            const bool in_range = (e.type == T_LIST && j >= 0 && j < static_cast<long>(e.list.size()));
            CACHE_CHECK((p != nullptr) == in_range, "lindex() disagrees with the model about the range");
            if (p)
                CACHE_CHECK(*p == e.list[static_cast<size_t>(j)], "lindex() returned the wrong element");
            break;
        }

        case OP_SADD:
        {
            if ((e.type == T_SET && e.members.size() >= MAX_ELEMS && e.members.count(mem) == 0)
                || avoid_collection_uaf(w))
                return true;
            wrote_key       = ki;
            is_memory_write = true;
            evict_possible  = can_evict;
            target_existed  = (e.type != T_NONE);
            target_ttl_before = e.ttl;
            const bool conflict = type_conflicts(T_SET);
            const bool already  = (e.type == T_SET && e.members.count(mem) != 0);
            const int  r = w.store.sadd(k, mem);
            wrote_ok = (r >= 0);
            if (r == 1)
            {
                CACHE_CHECK(!conflict, "sadd() wrote to a key that is not a set");
                CACHE_CHECK(!already, "sadd() reported a member as new that was already there");
                e.type = T_SET;
                e.members.insert(mem);
            }
            else if (r == 0)
            {
                CACHE_CHECK(already, "sadd() reported a member as present that was never added");
            }
            else
            {
                // -1 is both "wrong type" and "no room": the same conflation
                // append() used to have between a refusal and a success.
                CACHE_FINDING("write-refused", conflict || refusal_excusable(),
                              "sadd() returned -1 that it had room for after eviction, with no type conflict");
            }
            break;
        }
        case OP_SREM:
        {
            const bool expect = (e.type == T_SET && e.members.count(mem) != 0);
            const bool ok = w.store.srem(k, mem);
            CACHE_CHECK(ok == expect, "srem() disagrees with the model about membership");
            if (ok)
            {
                e.members.erase(mem);
                if (e.members.empty())
                    e.clear();
            }
            break;
        }
        case OP_SISMEMBER:
        {
            const bool expect = (e.type == T_SET && e.members.count(mem) != 0);
            CACHE_CHECK(w.store.sismember(k, mem) == expect, "sismember() disagrees with the model");
            break;
        }

        case OP_HSET:
        {
            if ((e.type == T_HASH && e.fields.size() >= MAX_ELEMS && e.fields.count(mem) == 0)
                || avoid_collection_uaf(w))
                return true;
            wrote_key       = ki;
            is_memory_write = true;
            evict_possible  = can_evict;
            target_existed  = (e.type != T_NONE);
            target_ttl_before = e.ttl;
            const bool conflict = type_conflicts(T_HASH);
            const bool ok = w.store.hset(k, mem, val);
            wrote_ok = ok;
            if (ok)
            {
                CACHE_CHECK(!conflict, "hset() wrote to a key that is not a hash");
                e.type = T_HASH;
                e.fields[mem] = val;
            }
            else
            {
                CACHE_FINDING("write-refused", conflict || refusal_excusable(),
                              "hset() was refused that it had room for after eviction, with no type conflict");
            }
            break;
        }
        case OP_HGET:
        {
            const bool have = (e.type == T_HASH && e.fields.count(mem) != 0);
            const std::string* p = w.store.hget(k, mem);
            CACHE_CHECK((p != nullptr) == have, "hget() disagrees with the model about a field");
            if (p)
                CACHE_CHECK(*p == e.fields[mem], "hget() returned a value that was never written");
            break;
        }
        case OP_HDEL:
        {
            const bool have = (e.type == T_HASH && e.fields.count(mem) != 0);
            const bool ok = w.store.hdel(k, mem);
            CACHE_CHECK(ok == have, "hdel() disagrees with the model about a field");
            if (ok)
            {
                e.fields.erase(mem);
                if (e.fields.empty())
                    e.clear();
            }
            break;
        }

        case OP_MAXMEM:
            w.max_mem = MEM_LIMIT[s.a % NMEM_LIMIT];
            w.store.set_max_memory(w.max_mem);
            break;
        case OP_EVICTION:
            w.evic = (s.a % 3) == 0 ? evict_none
                   : (s.a % 3) == 1 ? evict_allkeys_lru
                                    : evict_allkeys_random;
            w.store.set_eviction(w.evic);
            break;

        case OP_SWEEP:
        {
            std::set<std::string> expect;
            for (int i = 0; i < NKEYS; i++)
                if (w.sh[i].type != T_NONE && w.sh[i].ttl == TTL_ELAPSED)
                    expect.insert(key_str(i));

            const std::vector<std::string> got = w.store.sweep_expired();
            CACHE_CHECK(got.size() == expect.size(),
                        "sweep_expired() returned a different number of keys than have elapsed TTLs");
            for (const auto& g : got)
                CACHE_CHECK(expect.count(g) == 1,
                            "sweep_expired() removed a key whose TTL had not elapsed");
            for (int i = 0; i < NKEYS; i++)
                if (w.sh[i].type != T_NONE && w.sh[i].ttl == TTL_ELAPSED)
                    w.sh[i].clear();
            break;
        }

        case OP_SAVELOAD:
            if (w.saves_left > 0)
            {
                w.saves_left--;
                check_save_load(w);
            }
            break;

        case OP_SCAN:
        {
            // Every key must come back from a full cursor walk exactly once.  A
            // cursor that skips a key hides it from a SCAN client even though it
            // is resident.
            std::vector<std::string> seen;
            uint64_t cursor = 0;
            int      guard  = 0;
            do {
                std::vector<std::string_view> batch;
                cursor = w.store.scan(cursor, "*", 1 + (s.a % 4), batch);
                for (const auto& sv : batch)
                    seen.emplace_back(sv);
            } while (cursor != 0 && ++guard < 4 * NKEYS + 8);

            CACHE_CHECK(cursor == 0, "a full SCAN never returned a zero cursor");
            std::sort(seen.begin(), seen.end());
            CACHE_CHECK(std::adjacent_find(seen.begin(), seen.end()) == seen.end(),
                        "a full SCAN returned the same key twice");
            CACHE_CHECK(seen.size() == w.store.size(),
                        "a full SCAN did not return every key in the store");
            break;
        }
        case OP_KEYS:
        {
            std::vector<std::string_view> out;
            w.store.keys("*", out);
            CACHE_CHECK(out.size() == w.store.size(), "keys(\"*\") did not return every key");
            break;
        }

        default:
            break;
    }

    // ── invariant 1, the sharp edge: a write that said yes ──
    if (wrote_key >= 0 && wrote_ok)
        CACHE_FINDING("write-vanished", w.store.type(key_str(wrote_key)) != "none",
                      "a write reported success and the key was not in the store immediately "
                      "afterwards — the shape the eviction bug took from outside");

    // ── and its mirror image: a write that said no ──
    //
    // check_memory() runs before the store has decided it can go ahead, and
    // try_evict() is free to choose the very key being written as its victim.
    // When the write is then refused anyway, the key it refused to write is
    // gone — along with the value that was already there and its TTL.  The
    // caller was told the write did not happen; what it was not told is that
    // its data was deleted to make room for a write that never landed.
    // test/unit/test_cache_store.cpp already asserts this for evict_none
    // ("growing an existing value is checked against the limit"); it stops
    // holding the moment an eviction policy is configured.
    if (is_memory_write && !wrote_ok && target_existed && wrote_key >= 0)
        CACHE_FINDING("refused-write-destroys-key",
                      w.store.type(key_str(wrote_key)) != "none",
                      "a write that was refused deleted the key it refused to write — the caller "
                      "got an error and its existing value is gone");

    // ── invariant 3: the limit holds after an accepted write ──
    //
    // Writes only: is_memory_write is set by the handlers that store payload,
    // so EXPIRE never reaches this check.  It carries its own, relaxed version
    // of the same rule — see the reasoning at OP_EXPIRE.
    if (is_memory_write && w.max_mem != 0 && usage_before <= w.max_mem
        && w.store.get_memory_used() > w.max_mem)
    {
        set_detail("maxmemory %zu, used %zu before this write and %zu after (+%zu)",
                   w.max_mem, usage_before, w.store.get_memory_used(),
                   w.store.get_memory_used() - usage_before);
        CACHE_FINDING("over-limit", false,
                      "the store is over its configured maxmemory after a write that started "
                      "under it — the write path did not consult the limit");
        g_detail[0] = 0;
    }

    // ── invariant 4, second half ──
    if (lru_policy && is_memory_write)
        check_eviction_order(w, snap, wrote_key);

    // ── invariants 1, 2 and 4 ──
    verify_model(w, evict_possible);
    if (lru_policy)
        check_evictable(w, snap, wrote_key);
    check_structure(w.store);
    return false;
}

} // namespace

// libFuzzer calls this once, before any input.  Its only job is to build the
// three lookup tables and read the environment while nobody is counting, so
// that no input is charged with the allocations they make on first use.  The
// GCC replay driver does not call it; it does not need to, having no leak
// detector to confuse.
extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    (void)key_str(0);
    (void)val_str(0, 0);
    (void)mem_str(0);
    (void)finding_suppressed("");
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    data = ::fuzz::never_null(data);
    ::fuzz::set_current(data, size);
    g_steps = 0;

    // Four bytes per operation.  A longer input only buys more steps, and the
    // invariant walk after each one is what costs time, so the ceiling is on
    // steps rather than on bytes.
    if (size < 4)
        return 0;

    world w;
    {
        // /dev/shm keeps save()/load() off the disk; the pid keeps two
        // concurrent fuzzer workers from writing the same file.
        char buf[128];
        std::snprintf(buf, sizeof(buf), "/dev/shm/socketley-fuzz-cache-%d.bin",
                      static_cast<int>(::getpid()));
        w.tmp_path = buf;
    }

    size_t off = 0;
    while (off + 4 <= size && g_steps < MAX_STEPS)
    {
        step s;
        s.op  = static_cast<uint8_t>(data[off + 0] % OP_COUNT);
        s.key = data[off + 1];
        s.a   = data[off + 2];
        s.b   = data[off + 3];
        off += 4;

        const size_t idx = g_steps;
        g_prog[g_steps++] = s;
        g_prog[idx].skipped = run_step(w, s) ? 1u : 0u;
    }

    if (::unlink(w.tmp_path.c_str()) < 0) {}
    ::fuzz::set_current(nullptr, 0);
    return 0;
}
