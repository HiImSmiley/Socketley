#pragma once
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <deque>
#include <list>
#include <vector>
#include <cstdint>
#include <functional>
#include <chrono>

// Transparent hash for heterogeneous lookup (avoids string copies on find/erase)
struct string_hash
{
    using is_transparent = void;

    size_t operator()(std::string_view sv) const noexcept
    {
        return std::hash<std::string_view>{}(sv);
    }

    size_t operator()(const std::string& s) const noexcept
    {
        return std::hash<std::string_view>{}(s);
    }
};

struct string_equal
{
    using is_transparent = void;

    bool operator()(std::string_view lhs, std::string_view rhs) const noexcept
    {
        return lhs == rhs;
    }
};

using string_map = std::unordered_map<std::string, std::string, string_hash, string_equal>;
using list_map = std::unordered_map<std::string, std::deque<std::string>, string_hash, string_equal>;
using set_inner = std::unordered_set<std::string, string_hash, string_equal>;
using set_map = std::unordered_map<std::string, set_inner, string_hash, string_equal>;
using hash_inner = std::unordered_map<std::string, std::string, string_hash, string_equal>;
using hash_map = std::unordered_map<std::string, hash_inner, string_hash, string_equal>;
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
        // Pre-allocate hash buckets to avoid rehashing during initial load.
        // 1024 is a reasonable starting point for most workloads.
        m_data.reserve(1024);
    }

    // --- Strings (existing) ---
    bool set(std::string_view key, std::string_view value);
    bool get(std::string_view key, std::string& out) const;
    const std::string* get_ptr(std::string_view key) const;

    // Combined check_expiry + get_ptr in a single hash probe sequence.
    // Avoids the cost of two separate lookups on the hot GET path.
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

    // --- Hashes ---
    bool hset(std::string_view key, std::string_view field, std::string_view val);
    const std::string* hget(std::string_view key, std::string_view field) const;
    bool hdel(std::string_view key, std::string_view field);
    int hlen(std::string_view key) const;
    const hash_inner* hash_ptr(std::string_view key) const;

    // --- TTL / Expiry ---
    bool set_expiry(std::string_view key, int seconds);
    int get_ttl(std::string_view key) const;    // -1 = no ttl, -2 = key not found
    bool persist(std::string_view key);
    void check_expiry(std::string_view key);
    std::vector<std::string> sweep_expired();  // removes expired keys, returns their names

    // --- Millisecond-precision TTL ---
    bool set_expiry_ms(std::string_view key, int64_t ms);
    int64_t get_pttl(std::string_view key) const;  // ms; -1=no ttl, -2=not found

    // --- Set if not exists ---
    bool setnx(std::string_view key, std::string_view value);

    // --- Cursor scan (stateless offset cursor; returns next cursor, 0=done) ---
    uint64_t scan(uint64_t cursor, std::string_view pattern,
                  size_t count, std::vector<std::string_view>& out) const;

    // --- Atomic increment ---
    bool incr(std::string_view key, int64_t delta, int64_t& result);

    // --- String extras ---
    size_t append(std::string_view key, std::string_view suffix);  // returns new length
    size_t strlen_key(std::string_view key) const;                  // 0 if missing
    bool getset(std::string_view key, std::string_view newval, std::string& oldval);

    // --- Type / Keys ---
    std::string_view type(std::string_view key) const;
    // returns "string", "list", "set", "hash", or "none"
    void keys(std::string_view pattern, std::vector<std::string_view>& out) const;

    // --- General ---
    bool del(std::string_view key);
    uint32_t size() const;
    bool exists(std::string_view key) const;

    bool save(std::string_view path) const;
    bool load(std::string_view path);

    // --- Eviction / Memory ---
    void set_max_memory(size_t bytes);
    size_t get_max_memory() const { return m_max_memory; }
    size_t get_memory_used() const { return m_current_memory; }
    void set_eviction(eviction_policy policy);
    eviction_policy get_eviction() const { return m_eviction; }
    // Inline fast-path: most configs have no memory limit
    bool check_memory(size_t needed)
    {
        if (__builtin_expect(m_max_memory == 0, 1))
            return true;
        if (__builtin_expect(m_current_memory + needed <= m_max_memory, 1))
            return true;
        return try_evict(needed);
    }

    // --- Pub/Sub ---
    void subscribe(int fd, std::string_view channel);
    void unsubscribe(int fd, std::string_view channel);
    void unsubscribe_all(int fd);
    const std::unordered_set<int>* get_subscribers(std::string_view channel) const;
    size_t channel_count() const { return m_channels.size(); }

private:
    bool has_type_conflict_for_string(std::string_view key) const;
    bool has_type_conflict_for_list(std::string_view key) const;
    bool has_type_conflict_for_set(std::string_view key) const;
    bool has_type_conflict_for_hash(std::string_view key) const;

    bool save_v2(std::string_view path) const;
    bool load_v2(std::ifstream& file);
    bool load_v1(std::ifstream& file, uint32_t first_key_len);

    void touch_lru(std::string_view key);
    bool try_evict(size_t needed);

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
    expiry_map m_expiry;

    // Eviction / Memory
    size_t m_max_memory = 0;
    size_t m_current_memory = 0;
    eviction_policy m_eviction = evict_none;
    std::list<std::string> m_lru_order;
    std::unordered_map<std::string, std::list<std::string>::iterator, string_hash, string_equal> m_lru_map;

    // Pub/Sub
    channel_map m_channels;
};
