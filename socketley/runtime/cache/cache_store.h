#pragma once
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <deque>
#include <list>
#include <vector>
#include <cstdint>
#include <functional>
#include <chrono>
#include "zskiplist.h"

#include "../../shared/transparent_string.h"

using string_map = std::unordered_map<std::string, std::string, string_hash, string_equal>;
using list_map = std::unordered_map<std::string, std::deque<std::string>, string_hash, string_equal>;
using set_inner = std::unordered_set<std::string, string_hash, string_equal>;
using set_map = std::unordered_map<std::string, set_inner, string_hash, string_equal>;
using hash_inner = std::unordered_map<std::string, std::string, string_hash, string_equal>;
using hash_map = std::unordered_map<std::string, hash_inner, string_hash, string_equal>;

// A sorted set is two views of one thing: scores by member, and members in
// score order.  The ordered half is a skiplist carrying spans, because the
// std::set it used to be had the right order and no way to ask WHERE a member
// sits -- see zskiplist.h for the sweep that settled it.
struct zset_inner
{
    std::unordered_map<std::string, double, string_hash, string_equal> score;
    zskiplist                                                          order;

    size_t size() const { return score.size(); }
    bool   empty() const { return score.empty(); }
};
using zset_map = std::unordered_map<std::string, zset_inner, string_hash, string_equal>;
using expiry_map = std::unordered_map<std::string, std::chrono::steady_clock::time_point, string_hash, string_equal>;
using channel_map = std::unordered_map<std::string, std::unordered_set<int>, string_hash, string_equal>;

enum eviction_policy : uint8_t
{
    evict_none           = 0,
    evict_allkeys_lru    = 1,
    evict_allkeys_random = 2
};

class cache_store
{
public:
    cache_store()
    {
        // Pre-allocate hash buckets to avoid rehashing during the initial
        // load.
        //
        // max_load_factor is deliberately left at libstdc++'s 1.0, and the
        // curve below is why -- measured on pipelined GET at about 173,000
        // keys, nine passes per arm, interleaved with the order reversed:
        //
        //     0.5   0.663    (-34%)   0 of 8 passes favoured it
        //     1.0   1.000    baseline
        //     2.0   1.051 / 1.032     7 of 8, then 6 of 8 on a repeat
        //     4.0   1.034    (+3.4%)  4 of 6, which is nothing
        //     8.0   0.765    (-24%)   0 of 6
        //
        // The shape is the finding, not the peak.  Halving the load factor
        // DOUBLES the bucket array -- 1.4 MB to 2.8 MB at this key count --
        // and costs a third of the throughput, while shortening every chain.
        // So what this table pays for is not collisions: it is whether the
        // bucket array stays resident.  That is also why a better hash was
        // measured and refused (wyhash, chi2/df 1.035 against 1.000, 0.975x
        // throughput): fewer collisions buy nothing when the cost is a miss.
        //
        // 2.0 is left unset because the win is 3 to 5 per cent on a path whose
        // noise floor is 5, it reads -0.5% at depth 1 where the kernel holds
        // 86% of the time, and the peak moves with the key count -- so it
        // would be tuning this constant for one table size.  The direction
        // that does follow from the curve is a more COMPACT table: open
        // addressing, or smaller nodes, not a cleverer hash.
        m_data.reserve(1024);
    }

    // --- Strings (existing) ---
    bool set(std::string_view key, std::string_view value);
    bool get(std::string_view key, std::string& out) const;
    const std::string* get_ptr(std::string_view key) const;

    // Combined check_expiry and get_ptr in a single probe sequence, which
    // avoids two lookups on the hot GET path.
    const std::string* check_expiry_and_get_ptr(std::string_view key);

    // --- Lists ---
    bool lpush(std::string_view key, std::string_view val);
    bool rpush(std::string_view key, std::string_view val);
    bool lpop(std::string_view key, std::string& out);
    bool rpop(std::string_view key, std::string& out);
    int llen(std::string_view key) const;
    const std::deque<std::string>* list_ptr(std::string_view key) const;
    const std::string* lindex(std::string_view key, int idx) const;

    // --- Sets ---
    // Returns: 1 = added, 0 = already exists, -1 = type conflict
    int sadd(std::string_view key, std::string_view member);
    bool srem(std::string_view key, std::string_view member);
    bool sismember(std::string_view key, std::string_view member) const;
    int scard(std::string_view key) const;
    const set_inner* set_ptr(std::string_view key) const;

    // ─── Set algebra ────────────────────────────────────────────────────────
    //
    // The result is materialised as owned strings and not as views into the
    // sets, because the STORE forms write their answer back and the
    // destination is allowed to BE one of the sources: SINTERSTORE s s t is
    // legal, and a view into `s` would dangle the moment `s` is replaced.
    //
    // -1 back means a key held something that is not a set; the caller turns
    // that into WRONGTYPE, which is what a client switches on.
    int sinter(const std::string_view* keys, size_t n, std::vector<std::string>& out) const;
    int sunion(const std::string_view* keys, size_t n, std::vector<std::string>& out) const;
    int sdiff (const std::string_view* keys, size_t n, std::vector<std::string>& out) const;

    // Replaces dest outright, as Redis does: an empty result DELETES it rather
    // than leaving an empty set behind, because an empty set is not a thing
    // Redis keeps and EXISTS would disagree with the store otherwise.
    size_t sreplace(std::string_view dest, std::vector<std::string>&& members);

    // 1 moved, 0 not a member, -1 type conflict.
    int smove(std::string_view src, std::string_view dst, std::string_view member);

    // ─── Whole-key operations ───────────────────────────────────────────────
    //
    // A key lives in exactly one of the five containers and may carry an entry
    // in the expiry map, so moving or copying one has to find it first and
    // take its deadline with it -- Redis carries the TTL through RENAME and,
    // for COPY, does not.
    //
    // 1 done, 0 refused because the destination exists (the NX forms), -2 the
    // source is not there.
    int rename_key(std::string_view src, std::string_view dst, bool nx);
    int copy_key(std::string_view src, std::string_view dst, bool replace);

    // Any key at all, empty when the store is.  One container is picked and
    // then one entry inside it, which is not uniform across containers -- and
    // neither is Redis, which samples its own table.
    std::string_view random_key() const;

    // The absolute deadline in seconds or milliseconds since the epoch: -1 for
    // a key with no expiry, -2 for a key that is not there, which is TTL's own
    // pair of answers and what a client already switches on.
    int64_t expire_time(std::string_view key, bool millis) const;

    // Empties the store and its counters.  FLUSHALL and FLUSHDB are the same
    // thing here because there is one keyspace: this cache has no SELECT-able
    // databases, so there is no second one to leave behind.
    void flush_all();

    // --- Hashes ---
    // `created` is told whether the field is new, which is what HSET counts.
    bool hset(std::string_view key, std::string_view field, std::string_view val,
              bool* created = nullptr);
    const std::string* hget(std::string_view key, std::string_view field) const;
    bool hdel(std::string_view key, std::string_view field);
    int hlen(std::string_view key) const;
    const hash_inner* hash_ptr(std::string_view key) const;

    // --- TTL / Expiry ---
    // Both of these saturate: the deadline an absurd TTL means is "never" or
    // "long gone", never a signed overflow, and the two interpreters hand them
    // a client's number unchecked.
    bool set_expiry(std::string_view key, int64_t seconds);
    // EXPIRE, PEXPIRE, EXPIREAT and PEXPIREAT are one decision with four
    // spellings, so it is made here rather than four times over two
    // interpreters: a deadline that has already passed is a DELETION, and the
    // answer is about whether the key was there to be given one at all.
    // Redis's three answers, and it cannot be a bool -- "I deleted it" and "I
    // armed it" are both 1 to the client and only one of them arms a timer.
    enum class expire_result { no_such_key, armed, deleted };
    expire_result expire_in(std::string_view key, int64_t n, bool millis);
    int64_t get_ttl(std::string_view key) const;    // -1 = no ttl, -2 = key not found
    bool persist(std::string_view key);
    void check_expiry(std::string_view key);
    std::vector<std::string> sweep_expired();  // removes expired keys, returns their names
    bool has_expiry_keys() const { return !m_expiry.empty(); }

    // --- Millisecond-precision TTL ---
    bool set_expiry_ms(std::string_view key, int64_t ms);
    int64_t get_pttl(std::string_view key) const;  // ms; -1=no ttl, -2=not found
    // get_pttl() after check_expiry(), in one probe of the expiry map.
    int64_t expire_then_pttl(std::string_view key);

    // --- Set if not exists ---
    bool setnx(std::string_view key, std::string_view value);

    // The cursor packs [map index : 8][bucket count : 24][bucket index : 32],
    // and the top six bits are free for a shard tag only while the map index
    // fits in the two below them.
    static constexpr uint8_t scan_last_map = 4;   // m_data, m_lists, m_sets, m_hashes, m_zsets
    // `value_pattern` is a pointer and not an empty string_view because absent
    // and empty are different requests, the same distinction MATCH "" makes.
    // What one scan call was asked for, beside the cursor and the page size.
    //
    // A struct and not six more parameters, because `scan(0, "*", n, out,
    // nullptr, -1, true)` does not say at the call site which of those is the
    // type and which the values.
    struct scan_filter
    {
        // A numeric range on the value a glob would be matched against.  A value
        // that is not a number matches no range at all, which is a different
        // answer from matching every range -- "30kg" is not thirty.
        struct value_range { double lo, hi; bool lo_inclusive, hi_inclusive; };

        // One thing a key has to satisfy.  `field` names where the value comes
        // from -- a hash field, or the key's own value when it is absent -- and
        // `value` and `range` are what that value has to be.  Both are pointers
        // and not empty values because absent and empty are different requests,
        // the same distinction MATCH "" makes.
        struct predicate
        {
            const std::string_view* field = nullptr;
            const std::string_view* value = nullptr;
            const value_range*      range = nullptr;
        };

        // Four, and a caller asking for a fifth is refused rather than served
        // from the heap: this is built on the stack for every call of a command
        // on the hot path, and four field predicates in one scan is already past
        // what anybody has asked for.
        static constexpr size_t MAX_PREDICATES = 4;
        predicate preds[MAX_PREDICATES]{};
        size_t    pred_count = 0;

        // Which of the five maps to walk, which is what a type filter IS here:
        // the type of a key is the map it lives in.  -1 walks all five, and a
        // name no type has never reaches this -- the caller answers an empty
        // page for that rather than asking for a walk of nothing.
        int  type_map = -1;
        // Put the value after each key, interleaved the way hscan returns field
        // and value.  Restricts to strings unless a field says otherwise, for
        // the reason a value predicate does: nothing else holds one value.
        bool with_values = false;

        // Whether any predicate names a field, which is what decides the map.
        bool wants_hashes() const
        {
            for (size_t i = 0; i < pred_count; i++)
                if (preds[i].field) return true;
            return false;
        }
        bool any_predicate() const { return pred_count != 0; }

        // The one-predicate case, which is most of them, spelled so a call site
        // does not have to build a list to ask one question.
        static scan_filter one(const std::string_view* value = nullptr,
                               int type_map = -1, bool with_values = false,
                               const std::string_view* field = nullptr,
                               const value_range* range = nullptr)
        {
            scan_filter f;
            f.type_map = type_map;
            f.with_values = with_values;
            if (value || field || range)
            {
                f.preds[0] = { field, value, range };
                f.pred_count = 1;
            }
            return f;
        }
    };

    uint64_t scan(uint64_t cursor, std::string_view pattern,
                  size_t count, std::vector<std::string_view>& out,
                  const scan_filter& filter) const;

    // The unfiltered walk, spelled as an overload rather than a default
    // argument: the class is still incomplete where the default would sit, so
    // scan_filter{} cannot be written there.
    uint64_t scan(uint64_t cursor, std::string_view pattern,
                  size_t count, std::vector<std::string_view>& out) const
    { return scan(cursor, pattern, count, out, scan_filter{}); }

    // The map a type name names, or -1 for a name no type has.
    static int scan_map_of_type(std::string_view name);

    // How many keys one map holds, which is O(1) where counting the same thing
    // with a scan is the whole map walked and every key name sent back.
    uint32_t size_of_type(int map) const;

    // The string map alone, which is the only one a value predicate can be
    // answered from, with the page bounded by keys examined rather than keys
    // returned -- see the definition for why those are not the same contract.
    uint64_t scan_values(uint64_t cursor, std::string_view pattern, size_t count,
                         std::vector<std::string_view>& out,
                         const scan_filter& filter) const;

    // The hash map, filtered on what a named field of each hash holds.
    uint64_t scan_hash_field(uint64_t cursor, std::string_view pattern, size_t count,
                             std::vector<std::string_view>& out,
                             const scan_filter& filter) const;

    // --- Atomic increment ---
    // An increment can be refused for two different reasons and the caller has
    // to tell them apart, exactly as zincrby's does: a value that is not a
    // number is about the client's KEY, a sum past int64 is about its
    // arithmetic, and Redis names the second one separately.  not_an_integer
    // carries the memory refusal too, as the `false` it replaces did -- folding
    // that one is an older imprecision and not this enum's.
    enum class incr_result { ok, not_an_integer, would_overflow };
    incr_result incr(std::string_view key, int64_t delta, int64_t& result);

    // append() sentinels, where npos means the wrong type, because a memory
    // refusal reported as the unchanged length was indistinguishable from a
    // successful append of nothing.
    static constexpr size_t append_wrong_type = std::string::npos;
    static constexpr size_t append_denied     = std::string::npos - 1;
    // A length no std::string can represent, which is a refusal and not a
    // memory verdict: setrange() is the only command whose result length is
    // computed from an argument rather than read off one.
    static constexpr size_t append_too_long   = std::string::npos - 2;
    // The largest string one SETRANGE may build.  The guard used to compare
    // against std::string::max_size(), about 4.6e18, which is what the type
    // can represent and not what a machine can hold -- so every length between
    // the two was accepted and the allocation behind it ended the worker,
    // there being no catch for std::bad_alloc anywhere between cache_store and
    // main().  512 MiB is the ceiling Redis puts on one string, and this cache
    // answers INFO with that dialect.
    static constexpr size_t setrange_max_bytes = 512u * 1024 * 1024;

    size_t append(std::string_view key, std::string_view suffix);  // returns new length
    size_t strlen_key(std::string_view key) const;                  // 0 if missing
    bool getset(std::string_view key, std::string_view newval, std::string& oldval);

    // --- Sorted sets ---
    // 1 added, 0 already there, -1 type conflict -- sadd's answers, and for
    // sadd's reason: a bare false meant either "already there" or "not a
    // sorted set", and every caller had to ask type() to tell them apart.
    // type() walks all five containers, so the ambiguity cost five hash
    // lookups on every update, which is the whole of what ZADD does when a
    // member's score has not moved.
    int    zadd(std::string_view key, double score, std::string_view member);
    bool   zrem(std::string_view key, std::string_view member);
    bool   zscore(std::string_view key, std::string_view member, double& out) const;
    size_t zcard(std::string_view key) const;
    // The rank a member holds counting from the low score, and false when the
    // key or the member is not there -- the two the callers answer alike.
    bool   zrank(std::string_view key, std::string_view member, size_t& out,
                 bool reverse = false) const;
    // Inclusive ends, negative counting from the last, empty when the range is
    // inverted -- the same rules lrange has here.
    void   zrange(std::string_view key, int64_t start, int64_t stop,
                  std::vector<std::pair<std::string_view, double>>& out,
                  bool reverse = false) const;
    // An increment can be refused for two different reasons and the caller has
    // to tell them apart: a type conflict is about the client's KEY, a NaN
    // result is about its arithmetic, and Redis names the second one separately
    // rather than reporting the first.
    enum class zincr_result { ok, type_conflict, not_a_number };
    zincr_result zincrby(std::string_view key, double delta, std::string_view member,
                         double& out);

    // --- Strings, the range and float spellings ---
    // Inclusive ends, negative counting from the last, empty when inverted --
    // the same rules lrange and zrange follow here.
    bool   getrange(std::string_view key, int64_t start, int64_t end, std::string& out) const;
    size_t setrange(std::string_view key, size_t offset, std::string_view value);
    bool   incrbyfloat(std::string_view key, double delta, double& result);
    bool   getdel(std::string_view key, std::string& out);

    // --- Lists, the positional spellings ---
    // 0 ok, -1 no such key, -2 index past the end.
    int  lset(std::string_view key, int64_t idx, std::string_view val);
    // Removes count occurrences from the head, or from the tail when negative,
    // or every one when zero, and answers how many went.
    int  lrem(std::string_view key, int64_t count, std::string_view val);
    bool ltrim(std::string_view key, int64_t start, int64_t stop);
    // The new length, 0 when the key is absent and -1 when the pivot is not.
    int  linsert(std::string_view key, bool before, std::string_view pivot,
                 std::string_view val);

    // One element from one end of `src` to one end of `dst`, which is the
    // reliable-queue move: the job is never in neither list.  Answers false
    // when src is empty or either key is not a list; src == dst rotates.
    bool lmove(std::string_view src, std::string_view dst,
               bool from_head, bool to_head, std::string& out);

    // --- Sets, the sampling spellings ---
    bool spop(std::string_view key, std::string& out);
    bool srandmember(std::string_view key, std::string& out) const;

    // One collection walked in whole buckets, cursor 0 to start and 0 again
    // when it is done -- SCAN's contract, over one key instead of the
    // keyspace.  A missing key is an immediate 0 with nothing emitted, which
    // is what Redis answers rather than an error.
    // `value_pattern` filters on what each field HOLDS, where `pattern` matches
    // what it is called; absent and empty are different requests, as elsewhere.
    uint64_t hscan(std::string_view key, uint64_t cursor, std::string_view pattern,
                   size_t count,
                   std::vector<std::pair<std::string_view, std::string_view>>& out,
                   const std::string_view* value_pattern = nullptr) const;
    uint64_t sscan(std::string_view key, uint64_t cursor, std::string_view pattern,
                   size_t count, std::vector<std::string_view>& out) const;
    uint64_t zscan(std::string_view key, uint64_t cursor, std::string_view pattern,
                   size_t count,
                   std::vector<std::pair<std::string_view, double>>& out) const;

    // --- Hashes, the field spellings ---
    bool hexists(std::string_view key, std::string_view field) const;
    incr_result hincrby(std::string_view key, std::string_view field, int64_t delta,
                        int64_t& result);
    // 1 set, 0 already there, -1 type conflict -- sadd's answers.
    int  hsetnx(std::string_view key, std::string_view field, std::string_view val);

    // --- Sorted sets, by score rather than by rank ---
    // A score range with its two ends each open or closed, walked from the low
    // end or the high one.
    void zrangebyscore(std::string_view key, double min, double max,
                       bool min_incl, bool max_incl, bool reverse,
                       std::vector<std::pair<std::string_view, double>>& out) const;
    size_t zcount(std::string_view key, double min, double max,
                  bool min_incl, bool max_incl) const;
    // The lowest-scoring member, or the highest, removed and handed back.
    bool   zpop(std::string_view key, bool highest, std::string& member, double& score);
    size_t zremrangebyrank(std::string_view key, int64_t start, int64_t stop);
    size_t zremrangebyscore(std::string_view key, double min, double max,
                            bool min_incl, bool max_incl);

    // The difference between "not there" and "there as something else", asked
    // only when a read has already MISSED its own container -- so a hit pays
    // nothing and a pure single-type store pays four empty() tests.
    //
    // `expect` is the container the caller looked in: 's' string, 'l' list,
    // 't' set, 'h' hash, 'z' sorted set.
    bool holds_other_type(std::string_view key, char expect) const;

    // --- Type / Keys ---
    std::string_view type(std::string_view key) const;
    // returns "string", "list", "set", "hash", or "none"
    void keys(std::string_view pattern, std::vector<std::string_view>& out) const;

    // --- General ---
    bool del(std::string_view key);

    // Remove a key from whichever container holds it, with the element
    // counters and the memory tally, and nothing else -- the caller owns the
    // expiry entry and the LRU.  One chain, because three copies of it left
    // two without m_zsets.
    bool drop_value(std::string_view key);
    uint32_t size() const;
    bool exists(std::string_view key) const;

    // `prefix` is written ahead of the dump's magic and `offset` skipped on
    // the way in, both defaulting to nothing -- and take_owned() moves every
    // key this shard owns out of a dump just read, deadline included, so a key
    // five seconds from expiring stays five seconds from expiring.
    void adopt_owned(cache_store& other, uint32_t shard_index, uint32_t shard_count);

    bool save(std::string_view path, std::string_view prefix = {}) const;
    bool load(std::string_view path, size_t offset = 0);

    // --- Eviction / Memory ---
    void set_max_memory(size_t bytes);
    size_t get_max_memory() const { return m_max_memory; }
    // Payload plus the cost of the containers holding it, because counting
    // payload alone read 10 MB where the process had grown by 111 MB.
    size_t get_memory_used() const { return m_current_memory + structural_overhead(); }
    void set_eviction(eviction_policy policy);
    eviction_policy get_eviction() const { return m_eviction; }
    // Inline fast-path: most configs have no memory limit
    bool check_memory(size_t needed)
    {
        if (__builtin_expect(m_max_memory == 0, 1))
            return true;
        if (__builtin_expect(get_memory_used() + needed <= m_max_memory, 1))
            return true;
        return try_evict(needed, nullptr);
    }

    // The same admission check on behalf of a named key try_evict() may not
    // take, because eviction of the key being written invalidated held
    // iterators, destroyed values for writes that were then refused, and
    // turned APPEND into a silent truncation.
    bool check_memory(size_t needed, std::string_view key)
    {
        if (__builtin_expect(m_max_memory == 0, 1))
            return true;
        if (__builtin_expect(get_memory_used() + needed <= m_max_memory, 1))
            return true;
        return try_evict(needed, &key);
    }

    // Serialize all data as text commands into buf, for the initial full sync
    // when a follower connects.
    void dump_commands(std::string& buf) const;

    // --- Pub/Sub ---
    // Each says whether the subscription set changed, because the count a
    // client is answered with must not move for a repeat or a stranger.
    bool subscribe(int fd, std::string_view channel);
    bool unsubscribe(int fd, std::string_view channel);
    void unsubscribe_all(int fd);

    // Pattern subscriptions, kept apart from the exact ones because they are
    // matched and not looked up: every publish walks this map, and nothing
    // walks the other.
    bool psubscribe(int fd, std::string_view pattern);
    bool punsubscribe(int fd, std::string_view pattern);
    void punsubscribe_all(int fd);

    // What `fd` holds in one of the two maps, for an UNSUBSCRIBE that names
    // nothing and so means all of them.
    std::vector<std::string> subscriptions_of(int fd, bool patterns) const;
    bool has_patterns() const { return !m_patterns.empty(); }
    const channel_map& patterns() const { return m_patterns; }

    // Told when a channel gains its first subscriber here or loses its last,
    // which is what a shard's channel filter is kept from.
    using channel_observer = void (*)(void* ctx, std::string_view channel, bool present);
    void set_channel_observer(channel_observer fn, void* ctx)
    {
        m_chan_observer     = fn;
        m_chan_observer_ctx = ctx;
    }
    const std::unordered_set<int>* get_subscribers(std::string_view channel) const;
    size_t channel_count() const { return m_channels.size(); }

private:
    bool has_type_conflict_for_string(std::string_view key) const;
    bool has_type_conflict_for_list(std::string_view key) const;
    bool has_type_conflict_for_set(std::string_view key) const;
    bool has_type_conflict_for_hash(std::string_view key) const;
    bool has_type_conflict_for_zset(std::string_view key) const;

    bool save_v2(std::string_view path, std::string_view prefix) const;
    bool load_v2(const char* data, size_t size);
    bool load_v2_stream(std::ifstream& file);  // legacy fallback
    bool load_v1(std::ifstream& file, uint32_t first_key_len);

    // Take ownership of one entry restored by load() with the bookkeeping a
    // live write would have done, because inserting straight into the
    // containers left an empty LRU and an unenforceable maxmemory.
    void adopt_loaded_string(std::string&& key, std::string&& value);
    void adopt_loaded_list(std::string&& key, std::deque<std::string>&& deq);
    void adopt_loaded_set(std::string&& key, set_inner&& members);
    void adopt_loaded_hash(std::string&& key, hash_inner&& fields);
    void adopt_loaded_zset(std::string&& key, zset_inner&& members);

    // Populate the eviction order from data already resident, needed when a
    // limit is switched on after the fact.
    void rebuild_lru();

    void touch_lru(std::string_view key);

    // Remove a key from both LRU structures together, because erasing only
    // from m_lru_map orphans the node and touch_lru then appends a second one.
    void drop_lru(std::string_view key);

    // `protect`, when not null, names the key try_evict() may not take -- the
    // one the calling write is about to touch.
    bool try_evict(size_t needed, const std::string_view* protect);

    // Drop the key's expiry, as Redis specifies for SET without KEEPTTL,
    // called at the point a write is known to be going ahead -- doing it on
    // the way in stripped the TTL off keys whose write was then refused.
    void drop_expiry(std::string_view key);

    // Structural cost of the containers in bytes per entry, measured on this
    // toolchain and covering the fixed part only, because the heap block a
    // string takes past its SSO buffer depends on the length and is charged at
    // the payload sites.
    static constexpr size_t key_entry_overhead    = 74;
    static constexpr size_t lru_entry_overhead    = 139;
    static constexpr size_t expiry_entry_overhead = 64;
    static constexpr size_t list_elem_overhead    = 32;
    static constexpr size_t set_elem_overhead     = 64;
    static constexpr size_t hash_field_overhead   = 74;
    // A member sits in two containers: an unordered_map node and a skiplist
    // node in the ordered view, whose entry also carries a copy of the name.
    static constexpr size_t zset_member_overhead  = 74 + 64;

    // Longest string libstdc++ keeps inside the string object, derived rather
    // than written as 15, so a different layout moves this number instead of
    // silently invalidating it.
    static constexpr size_t sso_capacity =
        sizeof(std::string) - sizeof(char*) - sizeof(size_t) - 1;
    static_assert(sso_capacity >= 7 && sso_capacity < sizeof(std::string),
                  "std::string is not laid out the way this accounting assumes");

    // Bytes glibc malloc actually spends on a request, header and rounding
    // included, because those are resident memory like any other.
    static constexpr size_t malloc_chunk(size_t request)
    {
        constexpr size_t header = 8, align = 16, min_chunk = 32;
        const size_t chunk = (request + header + align - 1) & ~(align - 1);
        return chunk < min_chunk ? min_chunk : chunk;
    }

    // What one stored string costs given its length, where inside the SSO
    // limit only the length is added and past it the separate block is the
    // whole cost -- assuming capacity equals size, which is true of every
    // string this class creates.
    static constexpr size_t stored_string(size_t len)
    {
        return len <= sso_capacity ? len : malloc_chunk(len + 1);
    }

    // The same cost read off a string that exists, using capacity rather than
    // length, because assign() never hands a buffer back and APPEND doubles
    // rather than fitting.
    static size_t stored_string(const std::string& s)
    {
        return s.capacity() <= sso_capacity ? s.size() : malloc_chunk(s.capacity() + 1);
    }

    // What an existing string will cost once it holds `new_len` bytes, which
    // is the figure a write over an existing value is admitted against,
    // because libstdc++ reallocates to twice the old capacity and keeps the
    // buffer when it does not.
    static size_t rewritten_string(const std::string& s, size_t new_len)
    {
        const size_t cap = s.capacity();
        if (new_len <= cap)                   // the buffer already paid for is kept
            return cap <= sso_capacity ? new_len : malloc_chunk(cap + 1);
        return malloc_chunk((new_len < 2 * cap ? 2 * cap : new_len) + 1);
    }

    // The LRU keeps two further copies of the key and nothing else counts
    // their bytes, tracked by touch_lru/drop_lru because those two decide
    // whether a key is in the LRU at all.
    static constexpr size_t lru_key_copies(size_t key_len)
    {
        return key_len <= sso_capacity ? 0 : 2 * malloc_chunk(key_len + 1);
    }

    // What a brand new key costs, added by callers to what they pass
    // check_memory so admission and the limit are measured the same way, and
    // taking the length because both the key's block and the LRU's copies turn
    // on it.
    size_t new_key_cost(size_t key_len) const
    {
        return stored_string(key_len) + key_entry_overhead
             + (m_max_memory != 0 ? lru_entry_overhead + lru_key_copies(key_len) : 0);
    }

    // Accounted payload of one whole key for the removal paths, in one place,
    // because five hand-written copies of this loop is a permanent error in
    // the reported figure waiting to happen.
    static size_t entry_cost(const std::string& key, const std::string& val);
    static size_t entry_cost(const std::string& key, const std::deque<std::string>& deq);
    static size_t entry_cost(const std::string& key, const set_inner& members);
    static size_t entry_cost(const std::string& key, const hash_inner& fields);
    static size_t entry_cost(const std::string& key, const zset_inner& members);

    // Derived from live container sizes rather than tracked incrementally, so
    // it cannot drift, with every term O(1).
    size_t structural_overhead() const
    {
        return (m_data.size() + m_lists.size() + m_sets.size() + m_hashes.size()
                + m_zsets.size()) * key_entry_overhead
             + m_lru_map.size() * lru_entry_overhead
             + m_expiry.size()  * expiry_entry_overhead
             + m_list_elems     * list_elem_overhead
             + m_set_elems      * set_elem_overhead
             + m_hash_fields    * hash_field_overhead
             + m_zset_members   * zset_member_overhead;
    }

    // Inline memory tracking — called on every set/del, must be fast
    void track_add(size_t bytes) { m_current_memory += bytes; }
    void track_sub(size_t bytes)
    {
        if (__builtin_expect(bytes > m_current_memory, 0))
            m_current_memory = 0;
        else
            m_current_memory -= bytes;
    }

    string_map m_data;
    list_map m_lists;
    set_map m_sets;
    hash_map m_hashes;
    zset_map m_zsets;
    expiry_map m_expiry;

    // Eviction / Memory
    size_t m_max_memory = 0;
    // Payload: every stored string charged through stored_string(), plus the
    // LRU's own copies of the keys.
    size_t m_current_memory = 0;

    // Element counts for the collection types, where the number of keys is
    // O(1) from the maps and the number of members inside them is not.
    size_t m_list_elems = 0;
    size_t m_set_elems = 0;
    size_t m_hash_fields = 0;
    size_t m_zset_members = 0;
    eviction_policy m_eviction = evict_none;
    std::list<std::string> m_lru_order;
    std::unordered_map<std::string, std::list<std::string>::iterator, string_hash, string_equal> m_lru_map;

    // Pub/Sub
    channel_map m_channels;
    channel_map m_patterns;
    channel_observer m_chan_observer{nullptr};
    void*            m_chan_observer_ctx{nullptr};
};
