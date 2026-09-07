#include "cache_store.h"
#include "../../shared/cache_shard_map.h"
#include "../../shared/ipc_framing.h"
#include "../../shared/logging.h"
#include <fstream>
#include <cstring>
#include <random>
#include <charconv>
#include <cmath>
#include <cerrno>
#include <cstdlib>
#include <cstdio>
#include <algorithm>
#include <fnmatch.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

// ─── Per-entry cost (see the constants in cache_store.h) ───

size_t cache_store::entry_cost(const std::string& key, const std::string& val)
{
    return stored_string(key) + stored_string(val);
}

size_t cache_store::entry_cost(const std::string& key, const std::deque<std::string>& deq)
{
    size_t bytes = stored_string(key);
    for (const auto& e : deq) bytes += stored_string(e);
    return bytes;
}

size_t cache_store::entry_cost(const std::string& key, const set_inner& members)
{
    size_t bytes = stored_string(key);
    for (const auto& e : members) bytes += stored_string(e);
    return bytes;
}

// ─── Sorted sets ────────────────────────────────────────────────────────────

size_t cache_store::entry_cost(const std::string& key, const zset_inner& members)
{
    size_t bytes = stored_string(key);
    // Twice per member, because the ordered view holds a copy of the name.
    for (const auto& [m, sc] : members.score) bytes += 2 * stored_string(m);
    return bytes;
}

int cache_store::zadd(std::string_view key, double score, std::string_view member)
{
    check_expiry(key);

    // A key found here is a sorted set, so the four cross-map probes are owed
    // only when it is not -- the shortcut lpush, rpush, sadd and hset already
    // take, and the one this function was the last to be without.
    auto it = m_zsets.find(key);
    if (it != m_zsets.end())
    {
        auto sit = it->second.score.find(member);
        if (sit != it->second.score.end())
        {
            // A score that moves is a move in the ordered view too, and the
            // old pair has to go before the new one arrives or the member is
            // in there twice.
            if (sit->second != score)
            {
                it->second.order.erase({sit->second, sit->first});
                it->second.order.emplace(score, sit->first);
                sit->second = score;
            }
            touch_lru(key);
            return 0;
        }
    }

    if (it == m_zsets.end() && has_type_conflict_for_zset(key))
        return -1;

    if (!check_memory(2 * stored_string(member.size()) + new_key_cost(key.size())
                      + zset_member_overhead, key))
        return -1;

    if (it == m_zsets.end())
        it = m_zsets.emplace(std::string(key), zset_inner{}).first;

    const size_t before = entry_cost(it->first, it->second);
    it->second.score.emplace(std::string(member), score);
    it->second.order.emplace(score, std::string(member));
    ++m_zset_members;
    track_add(entry_cost(it->first, it->second) - before);
    touch_lru(key);
    return 1;
}

bool cache_store::zrem(std::string_view key, std::string_view member)
{
    check_expiry(key);
    auto it = m_zsets.find(key);
    if (it == m_zsets.end())
        return false;
    auto sit = it->second.score.find(member);
    if (sit == it->second.score.end())
        return false;

    const size_t before = entry_cost(it->first, it->second);
    it->second.order.erase({sit->second, sit->first});
    it->second.score.erase(sit);
    --m_zset_members;
    track_sub(before - entry_cost(it->first, it->second));

    // An empty sorted set is not a key, the way an empty list is not one here.
    if (it->second.empty())
    {
        track_sub(entry_cost(it->first, it->second));
        m_zsets.erase(it);
        m_expiry.erase(std::string(key));
        drop_lru(key);
    }
    return true;
}

bool cache_store::zscore(std::string_view key, std::string_view member, double& out) const
{
    auto it = m_zsets.find(key);
    if (it == m_zsets.end())
        return false;
    auto sit = it->second.score.find(member);
    if (sit == it->second.score.end())
        return false;
    out = sit->second;
    return true;
}

size_t cache_store::zcard(std::string_view key) const
{
    auto it = m_zsets.find(key);
    return it == m_zsets.end() ? 0 : it->second.size();
}

bool cache_store::zrank(std::string_view key, std::string_view member, size_t& out,
                        bool reverse) const
{
    auto it = m_zsets.find(key);
    if (it == m_zsets.end())
        return false;
    auto sit = it->second.score.find(member);
    if (sit == it->second.score.end())
        return false;

    // Walked rather than indexed, because std::set has no order statistic and
    // a second structure to carry one would be a second thing to keep true.
    size_t rank = 0;
    for (const auto& e : it->second.order)
    {
        if (e.first == sit->second && e.second == sit->first)
            break;
        ++rank;
    }
    out = reverse ? it->second.size() - 1 - rank : rank;
    return true;
}

void cache_store::zrange(std::string_view key, int64_t start, int64_t stop,
                         std::vector<std::pair<std::string_view, double>>& out,
                         bool reverse) const
{
    auto it = m_zsets.find(key);
    if (it == m_zsets.end())
        return;

    const int64_t n = static_cast<int64_t>(it->second.size());
    if (start < 0) start += n;
    if (stop  < 0) stop  += n;
    if (start < 0) start = 0;
    if (stop >= n) stop = n - 1;
    if (start > stop || start >= n)
        return;

    out.reserve(out.size() + static_cast<size_t>(stop - start + 1));
    int64_t i = 0;
    if (!reverse)
    {
        for (const auto& e : it->second.order)
        {
            if (i > stop) break;
            if (i >= start) out.emplace_back(std::string_view(e.second), e.first);
            ++i;
        }
    }
    else
    {
        for (auto rit = it->second.order.rbegin(); rit != it->second.order.rend(); ++rit)
        {
            if (i > stop) break;
            if (i >= start) out.emplace_back(std::string_view(rit->second), rit->first);
            ++i;
        }
    }
}

bool cache_store::zincrby(std::string_view key, double delta, std::string_view member,
                          double& out)
{
    double current = 0.0;
    if (zscore(key, member, current))
        out = current + delta;
    else
        out = delta;

    // zadd carries the type check and the memory refusal, and answers `new`
    // rather than `stored`, so the score is what says this worked.
    zadd(key, out, member);
    double check = 0.0;
    return zscore(key, member, check) && check == out;
}

size_t cache_store::entry_cost(const std::string& key, const hash_inner& fields)
{
    size_t bytes = stored_string(key);
    for (const auto& [f, v] : fields) bytes += stored_string(f) + stored_string(v);
    return bytes;
}

// ─── Type conflict checks (fast-path: empty() avoids hash lookups) ───

bool cache_store::has_type_conflict_for_string(std::string_view key) const
{
    // Lists, sets and hashes are usually empty or unconflicting, and the
    // empty() checks are O(1) fast paths.
    if (__builtin_expect(!m_lists.empty() && m_lists.count(key), 0)) return true;
    if (__builtin_expect(!m_sets.empty() && m_sets.count(key), 0)) return true;
    if (__builtin_expect(!m_hashes.empty() && m_hashes.count(key), 0)) return true;
    if (__builtin_expect(!m_zsets.empty() && m_zsets.count(key), 0)) return true;
    return false;
}

bool cache_store::has_type_conflict_for_list(std::string_view key) const
{
    if (!m_data.empty() && m_data.count(key)) return true;
    if (!m_sets.empty() && m_sets.count(key)) return true;
    if (!m_hashes.empty() && m_hashes.count(key)) return true;
    if (!m_zsets.empty() && m_zsets.count(key)) return true;
    return false;
}

bool cache_store::has_type_conflict_for_set(std::string_view key) const
{
    if (!m_data.empty() && m_data.count(key)) return true;
    if (!m_lists.empty() && m_lists.count(key)) return true;
    if (!m_hashes.empty() && m_hashes.count(key)) return true;
    if (!m_zsets.empty() && m_zsets.count(key)) return true;
    return false;
}

bool cache_store::has_type_conflict_for_hash(std::string_view key) const
{
    if (!m_data.empty() && m_data.count(key)) return true;
    if (!m_lists.empty() && m_lists.count(key)) return true;
    if (!m_sets.empty() && m_sets.count(key)) return true;
    if (!m_zsets.empty() && m_zsets.count(key)) return true;
    return false;
}

// The fifth type asks the same question the other four do, which is why this
// is a fifth copy and not a loop: each one names the maps that are NOT its own.
bool cache_store::has_type_conflict_for_zset(std::string_view key) const
{
    if (!m_data.empty()   && m_data.count(key))   return true;
    if (!m_lists.empty()  && m_lists.count(key))  return true;
    if (!m_sets.empty()   && m_sets.count(key))   return true;
    if (!m_hashes.empty() && m_hashes.count(key)) return true;
    return false;
}

// ─── Strings ───

void cache_store::drop_expiry(std::string_view key)
{
    // Guarded on empty() to keep a cache with no TTLs free of the lookup, and
    // taken through the iterator because erase() does not accept a
    // string_view.
    if (m_expiry.empty())
        return;
    auto eit = m_expiry.find(key);
    if (eit != m_expiry.end())
        m_expiry.erase(eit);
}

bool cache_store::set(std::string_view key, std::string_view value)
{
    // Fast path for a key that already exists as a string, which avoids the
    // type-conflict cross-map lookups.
    auto it = m_data.find(key);
    if (__builtin_expect(it != m_data.end(), 1))
    {
        // Growing an existing value has to clear the same bar as creating one,
        // which this path skipped, so a 10-byte value could be replaced by a
        // 100 MB one without maxmemory being consulted.
        if (__builtin_expect(m_max_memory != 0 && value.size() > it->second.size(), 0))
        {
            // The delta is between what the two values cost and not their
            // lengths, because assign() reallocates to twice the old capacity
            // rather than to fit.
            const size_t held = stored_string(it->second);
            const size_t want = rewritten_string(it->second, value.size());
            if (want > held && !check_memory(want - held, key))
                return false;
            // check_memory() will not take the key it was named, so `it` is
            // still live, and re-acquired anyway because that guarantee
            // belongs to another function.
            it = m_data.find(key);
        }

        if (__builtin_expect(it != m_data.end(), 1))
        {
            // Past the last refusal, so the write is going ahead and the key's
            // old deadline goes.
            drop_expiry(key);
            track_sub(stored_string(it->second));
            // Use assign() instead of operator= to potentially reuse existing allocation
            it->second.assign(value.data(), value.size());
            track_add(stored_string(it->second));
            touch_lru(key);
            return true;
        }
        // Unreachable while check_memory() honours the key it is named — but if
        // it ever stops doing so, insert the key as a new one rather than write
        // through a node that is gone.
    }

    // Slow path: new key — check type conflicts
    if (__builtin_expect(has_type_conflict_for_string(key), 0))
        return false;

    if (__builtin_expect(!check_memory(stored_string(value.size()) + new_key_cost(key.size()), key), 0))
        return false;

    drop_expiry(key);
    auto [it2, inserted] = m_data.try_emplace(std::string(key), std::string(value));
    if (!inserted)
        it2->second = std::string(value);
    track_add(entry_cost(it2->first, it2->second));
    touch_lru(key);
    return true;
}

bool cache_store::get(std::string_view key, std::string& out) const
{
    auto it = m_data.find(key);
    if (it == m_data.end())
        return false;

    out = it->second;
    return true;
}

const std::string* cache_store::get_ptr(std::string_view key) const
{
    auto it = m_data.find(key);
    if (__builtin_expect(it == m_data.end(), 0))
        return nullptr;
    // Prefetch the value string data — it's likely about to be read by encode_bulk_into
    __builtin_prefetch(it->second.data(), 0, 1);
    const_cast<cache_store*>(this)->touch_lru(key);
    return &it->second;
}

const std::string* cache_store::check_expiry_and_get_ptr(std::string_view key)
{
    // Combined expiry check and get in minimal probes, which for the common
    // case is one empty() test and one find() rather than two find() probes.

    if (__builtin_expect(!m_expiry.empty(), 0))
    {
        auto eit = m_expiry.find(key);
        if (eit != m_expiry.end())
        {
            if (std::chrono::steady_clock::now() >= eit->second)
            {
                // Expired — remove
                m_expiry.erase(eit);
                drop_lru(key);
                drop_value(key);
                return nullptr;
            }
        }
    }

    auto it = m_data.find(key);
    if (__builtin_expect(it == m_data.end(), 0))
        return nullptr;
    // Prefetch the value string data for encode_bulk_into
    __builtin_prefetch(it->second.data(), 0, 1);
    touch_lru(key);
    return &it->second;
}

// ─── Lists ───

bool cache_store::lpush(std::string_view key, std::string_view val)
{
    auto it = m_lists.find(key);
    if (it != m_lists.end())
    {
        // The key is named to check_memory() so eviction cannot take it,
        // because `it` has to survive the call and the emplace below went
        // through a freed node.
        if (!check_memory(stored_string(val.size()) + list_elem_overhead, key))
            return false;
        // Measured after it has been constructed in place, like every other add
        // here: what it costs is the buffer it ended up with.
        const std::string& elem = it->second.emplace_front(val);
        ++m_list_elems;
        track_add(stored_string(elem));
        touch_lru(key);
        return true;
    }

    if (has_type_conflict_for_list(key))
        return false;

    if (!check_memory(stored_string(val.size()) + new_key_cost(key.size()) + list_elem_overhead, key))
        return false;

    auto nit = m_lists.emplace(std::string(key), std::deque<std::string>{}).first;
    nit->second.emplace_front(val);
    ++m_list_elems;
    track_add(entry_cost(nit->first, nit->second));
    touch_lru(key);
    return true;
}

bool cache_store::rpush(std::string_view key, std::string_view val)
{
    auto it = m_lists.find(key);
    if (it != m_lists.end())
    {
        // Named for the same reason as in lpush(): `it` must survive the call.
        if (!check_memory(stored_string(val.size()) + list_elem_overhead, key))
            return false;
        // Same as lpush(): measured once it exists.
        const std::string& elem = it->second.emplace_back(val);
        ++m_list_elems;
        track_add(stored_string(elem));
        touch_lru(key);
        return true;
    }

    if (has_type_conflict_for_list(key))
        return false;

    if (!check_memory(stored_string(val.size()) + new_key_cost(key.size()) + list_elem_overhead, key))
        return false;

    auto nit = m_lists.emplace(std::string(key), std::deque<std::string>{}).first;
    nit->second.emplace_back(val);
    ++m_list_elems;
    track_add(entry_cost(nit->first, nit->second));
    touch_lru(key);
    return true;
}

bool cache_store::lpop(std::string_view key, std::string& out)
{
    auto it = m_lists.find(key);
    if (it == m_lists.end() || it->second.empty())
        return false;

    // Measured before the move: `out` belongs to the caller and is reused across
    // calls, so its capacity afterwards is its own history, not the element's.
    const size_t elem_cost = stored_string(it->second.front());
    out = std::move(it->second.front());
    it->second.pop_front();
    --m_list_elems;
    track_sub(elem_cost);

    if (it->second.empty())
    {
        track_sub(stored_string(it->first));
        m_list_elems -= it->second.size();
        m_lists.erase(it);
        m_expiry.erase(std::string(key));
        drop_lru(key);
    }
    return true;
}

bool cache_store::rpop(std::string_view key, std::string& out)
{
    auto it = m_lists.find(key);
    if (it == m_lists.end() || it->second.empty())
        return false;

    // Same as lpop(): the element is measured while it is still the deque's.
    const size_t elem_cost = stored_string(it->second.back());
    out = std::move(it->second.back());
    it->second.pop_back();
    --m_list_elems;
    track_sub(elem_cost);

    if (it->second.empty())
    {
        track_sub(stored_string(it->first));
        m_list_elems -= it->second.size();
        m_lists.erase(it);
        m_expiry.erase(std::string(key));
        drop_lru(key);
    }
    return true;
}

int cache_store::llen(std::string_view key) const
{
    auto it = m_lists.find(key);
    if (it == m_lists.end())
        return 0;
    return static_cast<int>(it->second.size());
}

const std::deque<std::string>* cache_store::list_ptr(std::string_view key) const
{
    auto it = m_lists.find(key);
    if (it == m_lists.end())
        return nullptr;
    return &it->second;
}

const std::string* cache_store::lindex(std::string_view key, int idx) const
{
    auto it = m_lists.find(key);
    if (it == m_lists.end())
        return nullptr;

    const auto& deq = it->second;
    int len = static_cast<int>(deq.size());

    if (idx < 0)
        idx += len;
    if (idx < 0 || idx >= len)
        return nullptr;

    return &deq[static_cast<size_t>(idx)];
}

// ─── Sets ───

int cache_store::sadd(std::string_view key, std::string_view member)
{
    auto it = m_sets.find(key);
    if (it != m_sets.end())
    {
        // Named for the same reason as in lpush(): `it` must survive the call.
        if (!check_memory(stored_string(member.size()) + set_elem_overhead, key))
            return -1;
        auto [mit, inserted] = it->second.emplace(member);
        if (inserted)
        {
            ++m_set_elems;
            track_add(stored_string(*mit));
            touch_lru(key);
        }
        return inserted ? 1 : 0;
    }

    if (has_type_conflict_for_set(key))
        return -1;

    if (!check_memory(stored_string(member.size()) + new_key_cost(key.size()) + set_elem_overhead, key))
        return -1;

    auto nit = m_sets.emplace(std::string(key), set_inner{}).first;
    nit->second.emplace(member);
    ++m_set_elems;
    track_add(entry_cost(nit->first, nit->second));
    touch_lru(key);
    return 1;
}

bool cache_store::srem(std::string_view key, std::string_view member)
{
    auto it = m_sets.find(key);
    if (it == m_sets.end())
        return false;

    auto mit = it->second.find(member);
    if (mit == it->second.end())
        return false;

    track_sub(stored_string(*mit));
    it->second.erase(mit);
    --m_set_elems;

    if (it->second.empty())
    {
        track_sub(stored_string(it->first));
        m_set_elems -= it->second.size();
        m_sets.erase(it);
        m_expiry.erase(std::string(key));
        drop_lru(key);
    }
    return true;
}

bool cache_store::sismember(std::string_view key, std::string_view member) const
{
    auto it = m_sets.find(key);
    if (it == m_sets.end())
        return false;
    return it->second.count(member) > 0;
}

int cache_store::scard(std::string_view key) const
{
    auto it = m_sets.find(key);
    if (it == m_sets.end())
        return 0;
    return static_cast<int>(it->second.size());
}

const set_inner* cache_store::set_ptr(std::string_view key) const
{
    auto it = m_sets.find(key);
    if (it == m_sets.end())
        return nullptr;
    return &it->second;
}

// ─── Hashes ───

bool cache_store::hset(std::string_view key, std::string_view field, std::string_view val)
{
    auto it = m_hashes.find(key);
    if (it != m_hashes.end())
    {
        auto fit = it->second.find(field);
        if (fit != it->second.end())
        {
            // Overwriting a field has to clear the same bar as adding one,
            // which this path did not, so a 5-byte value could become 100 KB
            // against a configured 1200.
            if (__builtin_expect(m_max_memory != 0 && val.size() > fit->second.size(), 0))
            {
                const size_t held = stored_string(fit->second);
                const size_t want = rewritten_string(fit->second, val.size());
                if (want > held && !check_memory(want - held, key))
                    return false;
            }
            track_sub(stored_string(fit->second));
            fit->second = val;
            track_add(stored_string(fit->second));
        }
        else
        {
            // Named so that eviction cannot take this hash, because `it` is
            // held across the call and the emplace below writes through it.
            if (!check_memory(stored_string(field.size()) + stored_string(val.size()) + hash_field_overhead, key))
                return false;
            auto nfit = it->second.emplace(std::string(field), std::string(val)).first;
            ++m_hash_fields;
            track_add(stored_string(nfit->first) + stored_string(nfit->second));
        }
        touch_lru(key);
        return true;
    }

    if (has_type_conflict_for_hash(key))
        return false;

    if (!check_memory(stored_string(field.size()) + stored_string(val.size())
                      + new_key_cost(key.size()) + hash_field_overhead, key))
        return false;

    auto nit = m_hashes.emplace(std::string(key), hash_inner{}).first;
    nit->second.emplace(std::string(field), std::string(val));
    ++m_hash_fields;
    track_add(entry_cost(nit->first, nit->second));
    touch_lru(key);
    return true;
}

const std::string* cache_store::hget(std::string_view key, std::string_view field) const
{
    auto it = m_hashes.find(key);
    if (it == m_hashes.end())
        return nullptr;

    auto fit = it->second.find(field);
    if (fit == it->second.end())
        return nullptr;

    return &fit->second;
}

bool cache_store::hdel(std::string_view key, std::string_view field)
{
    auto it = m_hashes.find(key);
    if (it == m_hashes.end())
        return false;

    auto fit = it->second.find(field);
    if (fit == it->second.end())
        return false;

    track_sub(stored_string(fit->first) + stored_string(fit->second));
    it->second.erase(fit);
    --m_hash_fields;

    if (it->second.empty())
    {
        track_sub(stored_string(it->first));
        m_hash_fields -= it->second.size();
        m_hashes.erase(it);
        m_expiry.erase(std::string(key));
        drop_lru(key);
    }
    return true;
}

int cache_store::hlen(std::string_view key) const
{
    auto it = m_hashes.find(key);
    if (it == m_hashes.end())
        return 0;
    return static_cast<int>(it->second.size());
}

const hash_inner* cache_store::hash_ptr(std::string_view key) const
{
    auto it = m_hashes.find(key);
    if (it == m_hashes.end())
        return nullptr;
    return &it->second;
}

// ─── TTL / Expiry ───

bool cache_store::set_expiry(std::string_view key, int64_t seconds)
{
    if (!exists(key))
        return false;

    auto tp = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    auto it = m_expiry.find(key);
    if (it != m_expiry.end())
        it->second = tp;
    else
        m_expiry.emplace(std::string(key), tp);
    return true;
}

int64_t cache_store::get_ttl(std::string_view key) const
{
    if (!exists(key))
        return -2;

    auto it = m_expiry.find(key);
    if (it == m_expiry.end())
        return -1;

    // Rounded, not truncated: duration_cast goes towards zero, so `SET k v EX
    // 1` answered 0 immediately and `EX 10` read as 9 after one millisecond.
    // Redis computes (ms + 500) / 1000, and a client treating TTL == 0 as
    // "expiring now" acted a whole second early against the old answer.
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        it->second - std::chrono::steady_clock::now()).count();
    return (ms + 500) / 1000;
}

bool cache_store::persist(std::string_view key)
{
    auto it = m_expiry.find(key);
    if (it == m_expiry.end())
        return false;
    m_expiry.erase(it);
    return true;
}

void cache_store::check_expiry(std::string_view key)
{
    // Fast early-out: most workloads have no TTLs at all
    if (__builtin_expect(m_expiry.empty(), 1))
        return;

    auto it = m_expiry.find(key);
    if (__builtin_expect(it == m_expiry.end(), 1))
        return;

    if (__builtin_expect(std::chrono::steady_clock::now() < it->second, 1))
        return;

    // Expired — remove from all containers
    m_expiry.erase(it);
    drop_lru(key);
    drop_value(key);
}

std::vector<std::string> cache_store::sweep_expired()
{
    std::vector<std::string> expired;
    if (__builtin_expect(m_expiry.empty(), 1))
        return expired;

    auto now = std::chrono::steady_clock::now();
    for (const auto& [key, tp] : m_expiry)
    {
        if (now >= tp)
            expired.push_back(key);
    }
    for (const auto& key : expired)
        del(key);
    return expired;
}

bool cache_store::set_expiry_ms(std::string_view key, int64_t ms)
{
    if (!exists(key))
        return false;

    auto tp = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
    auto it = m_expiry.find(key);
    if (it != m_expiry.end())
        it->second = tp;
    else
        m_expiry.emplace(std::string(key), tp);
    return true;
}

int64_t cache_store::get_pttl(std::string_view key) const
{
    if (!exists(key))
        return -2;

    auto it = m_expiry.find(key);
    if (it == m_expiry.end())
        return -1;

    auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        it->second - std::chrono::steady_clock::now());
    return remaining.count();
}

bool cache_store::setnx(std::string_view key, std::string_view value)
{
    check_expiry(key);
    if (exists(key))
        return false;
    return set(key, value);
}

// A cursor over buckets rather than an offset, because an offset into an
// unordered_map both skips and duplicates and made a full scan quadratic --
// and what is still not guaranteed is a rehash mid-iteration, which restarts
// the map being walked and trades duplicates, which the contract allows, for a
// skip, which it does not.
uint64_t cache_store::scan(uint64_t cursor, std::string_view pattern,
                            size_t count, std::vector<std::string_view>& out) const
{
    bool match_all = (pattern.empty() || pattern == "*");
    auto match = [&](std::string_view k) -> bool {
        if (match_all) return true;
        return fnmatch(std::string(pattern).c_str(), std::string(k).c_str(), 0) == 0;
    };

    // The bucket count rides in the cursor so the next call can tell whether
    // the table it is resuming into is the one it left, truncated to 24 bits,
    // where a collision only misses a rehash.
    // Three bits for the map, not two: the fifth map needed one and the only
    // field with a bit to give is this bucket count, whose truncation is
    // already a tolerated approximation -- a collision here misses a rehash,
    // which is the same miss one bit fewer makes twice as often.
    const uint8_t  in_map     = static_cast<uint8_t>((cursor >> 55) & 0x7u);
    const uint32_t in_buckets = static_cast<uint32_t>((cursor >> 32) & 0x7FFFFFu);
    uint64_t       in_bucket  = cursor & 0xFFFFFFFFu;

    auto pack = [](uint8_t map, size_t buckets, size_t bucket) -> uint64_t {
        return (static_cast<uint64_t>(map & 0x7u) << 55)
             | ((static_cast<uint64_t>(buckets) & 0x7FFFFF) << 32)
             | (static_cast<uint64_t>(bucket) & 0xFFFFFFFFu);
    };

    // One map from `first_bucket` on, returning the cursor to resume with or 0
    // when this map is exhausted.
    auto walk = [&](const auto& map, uint8_t idx, size_t first_bucket) -> uint64_t {
        const size_t nbuckets = map.bucket_count();
        for (size_t b = first_bucket; b < nbuckets; ++b)
        {
            for (auto it = map.begin(b); it != map.end(b); ++it)
                if (match(it->first))
                    out.push_back(it->first);

            // Whole buckets and never half of one, because a page boundary
            // inside a bucket would need the element index this is replacing.
            if (out.size() >= count && b + 1 < nbuckets)
                return pack(idx, nbuckets, b + 1);
        }
        return 0;
    };

    // The five in a fixed order, so a cursor names the same map on every call.
    const uint8_t last_map = scan_last_map;
    for (uint8_t idx = in_map; idx <= last_map; ++idx)
    {
        size_t start = 0;
        if (idx == in_map && cursor != 0)
        {
            // A rehash between calls invalidates the bucket index, so this map
            // restarts -- the answer that cannot skip, and may repeat, which
            // the contract allows.
            const size_t now = (idx == 0 ? m_data.bucket_count()
                              : idx == 1 ? m_lists.bucket_count()
                              : idx == 2 ? m_sets.bucket_count()
                              : idx == 3 ? m_hashes.bucket_count()
                                         : m_zsets.bucket_count());
            start = (in_buckets == (now & 0x7FFFFF)) ? in_bucket : 0;
        }

        uint64_t next = 0;
        switch (idx)
        {
            case 0:  next = walk(m_data,   0, start); break;
            case 1:  next = walk(m_lists,  1, start); break;
            case 2:  next = walk(m_sets,   2, start); break;
            case 3:  next = walk(m_hashes, 3, start); break;
            default: next = walk(m_zsets,  4, start); break;
        }
        if (next != 0)
            return next;

        // This map is done, and a full page resumes at the next map rather
        // than walking into it now.
        if (out.size() >= count && idx < last_map)
            return pack(static_cast<uint8_t>(idx + 1), 0, 0);
    }

    return 0;  // exhausted all keys
}

bool cache_store::incr(std::string_view key, int64_t delta, int64_t& result)
{
    check_expiry(key);

    // A key found here is a string, so the four cross-map probes are owed only
    // when it is not -- the shortcut set() already takes.
    int64_t val = 0;
    auto it = m_data.find(key);
    if (it != m_data.end())
    {
        auto [ptr, ec] = std::from_chars(it->second.data(), it->second.data() + it->second.size(), val);
        if (ec != std::errc{} || ptr != it->second.data() + it->second.size())
            return false;  // not an integer
    }
    else if (has_type_conflict_for_string(key))
        return false;

    val += delta;
    result = val;

    char buf[24];
    auto [end, ec2] = std::to_chars(buf, buf + sizeof(buf), val);
    std::string_view sv(buf, static_cast<size_t>(end - buf));

    if (it != m_data.end() && __builtin_expect(m_max_memory != 0 && sv.size() > it->second.size(), 0))
    {
        // The same bar SET has to clear, because a counter crossing the
        // small-string limit takes a 48-byte buffer rather than growing by a
        // digit.
        const size_t held = stored_string(it->second);
        const size_t want = rewritten_string(it->second, sv.size());
        if (want > held && !check_memory(want - held, key))
            return false;
        it = m_data.find(key);   // see set(): named to check_memory, but not trusted here
    }

    if (it != m_data.end())
    {
        track_sub(stored_string(it->second));
        it->second.assign(sv.data(), sv.size());
        track_add(stored_string(it->second));
    }
    else
    {
        if (!check_memory(stored_string(sv.size()) + new_key_cost(key.size()), key))
            return false;
        auto nit = m_data.emplace(std::string(key), std::string(sv)).first;
        track_add(entry_cost(nit->first, nit->second));
    }
    touch_lru(key);
    return true;
}

size_t cache_store::append(std::string_view key, std::string_view suffix)
{
    check_expiry(key);

    auto it = m_data.find(key);
    if (it != m_data.end())
    {
        if (__builtin_expect(m_max_memory != 0, 0))
        {
            // Refusing has to be visible, and what is asked for is the growth
            // of the allocation rather than the length of the suffix, because
            // libstdc++ doubles the buffer.
            const size_t held = stored_string(it->second);
            const size_t want = rewritten_string(it->second, it->second.size() + suffix.size());
            if (want > held && !check_memory(want - held, key))
                return append_denied;
            // check_memory() will not take the key it was named, so `it` is
            // still live, and re-acquired anyway.
            it = m_data.find(key);
        }

        if (it != m_data.end())
        {
            // Measured on both sides of the append rather than added as the
            // suffix length, because a string appended to in a loop holds up
            // to twice what its length says.
            track_sub(stored_string(it->second));
            it->second.append(suffix.data(), suffix.size());
            track_add(stored_string(it->second));
            touch_lru(key);
            return it->second.size();
        }
        // Unreachable while check_memory() honours the key it is named, which
        // it did not: the append evicted the key it was appending to and
        // returned the suffix's length as success.
    }

    // Reached only with the key absent from m_data, which is the one case the
    // cross-map probes can still refuse.
    if (has_type_conflict_for_string(key))
        return append_wrong_type;

    if (!check_memory(stored_string(suffix.size()) + new_key_cost(key.size()), key))
        return append_denied;
    auto nit = m_data.emplace(std::string(key), std::string(suffix)).first;
    track_add(entry_cost(nit->first, nit->second));
    touch_lru(key);
    return nit->second.size();
}

size_t cache_store::strlen_key(std::string_view key) const
{
    auto it = m_data.find(key);
    if (it == m_data.end())
        return 0;
    return it->second.size();
}

bool cache_store::getset(std::string_view key, std::string_view newval, std::string& oldval)
{
    check_expiry(key);

    // Same shortcut, and set() below finds the key a second time rather than
    // being handed an iterator it would have to trust across an eviction.
    auto it = m_data.find(key);
    if (it != m_data.end())
        oldval.assign(it->second);
    else
    {
        if (has_type_conflict_for_string(key))
            return false;
        oldval.clear();
    }
    return set(key, newval);
}

// ─── Strings, the range and float spellings ───

// The two ends resolved the way lrange resolves them, so one reading of a
// negative index serves every range command here.
static bool resolve_range(int64_t len, int64_t& start, int64_t& stop)
{
    if (start < 0) start += len;
    if (stop  < 0) stop  += len;
    if (start < 0) start = 0;
    if (stop >= len) stop = len - 1;
    return start <= stop && start < len && len > 0;
}

bool cache_store::getrange(std::string_view key, int64_t start, int64_t end,
                           std::string& out) const
{
    auto it = m_data.find(key);
    if (it == m_data.end())
        return false;
    int64_t s = start, e = end;
    if (!resolve_range(static_cast<int64_t>(it->second.size()), s, e))
    {
        out.clear();
        return true;    // an empty range over a key that exists is still ""
    }
    out.assign(it->second, static_cast<size_t>(s), static_cast<size_t>(e - s + 1));
    return true;
}

size_t cache_store::setrange(std::string_view key, size_t offset, std::string_view value)
{
    check_expiry(key);

    const size_t need = offset + value.size();
    auto it = m_data.find(key);
    if (it == m_data.end())
    {
        if (has_type_conflict_for_string(key))
            return append_wrong_type;
        if (value.empty())
            return 0;   // Redis creates nothing for an empty write
        if (!check_memory(stored_string(need) + new_key_cost(key.size()), key))
            return append_denied;
        auto nit = m_data.emplace(std::string(key), std::string(need, '\0')).first;
        nit->second.replace(offset, value.size(), value);
        track_add(entry_cost(nit->first, nit->second));
        touch_lru(key);
        return nit->second.size();
    }

    if (value.empty())
        return it->second.size();

    if (__builtin_expect(m_max_memory != 0 && need > it->second.size(), 0))
    {
        const size_t held = stored_string(it->second);
        const size_t want = rewritten_string(it->second, need);
        if (want > held && !check_memory(want - held, key))
            return append_denied;
        it = m_data.find(key);      // see set(): re-acquired rather than trusted
        if (it == m_data.end())
            return append_denied;
    }

    track_sub(stored_string(it->second));
    if (it->second.size() < need)
        it->second.resize(need, '\0');
    it->second.replace(offset, value.size(), value);
    track_add(stored_string(it->second));
    touch_lru(key);
    return it->second.size();
}

bool cache_store::incrbyfloat(std::string_view key, double delta, double& result)
{
    check_expiry(key);

    // The same shortcut incr() takes, and for the same reason.
    double val = 0;
    auto it = m_data.find(key);
    if (it != m_data.end())
    {
        const std::string& cur = it->second;
        char* end = nullptr;
        errno = 0;
        val = std::strtod(cur.c_str(), &end);
        if (end != cur.c_str() + cur.size() || cur.empty() || errno == ERANGE)
            return false;
    }
    else if (has_type_conflict_for_string(key))
        return false;

    val += delta;
    if (!std::isfinite(val))
        return false;   // Redis refuses NaN and infinity rather than storing them

    result = val;

    // Redis prints a float with up to seventeen significant digits and no
    // trailing zeros, which is what round-trips through strtod.
    char buf[40];
    int n = std::snprintf(buf, sizeof(buf), "%.17g", val);
    if (n <= 0 || static_cast<size_t>(n) >= sizeof(buf))
        return false;
    return set(key, std::string_view(buf, static_cast<size_t>(n)));
}

bool cache_store::getdel(std::string_view key, std::string& out)
{
    check_expiry(key);
    auto it = m_data.find(key);
    if (it == m_data.end())
        return false;
    out = it->second;
    track_sub(entry_cost(it->first, it->second));
    m_data.erase(it);
    m_expiry.erase(std::string(key));
    drop_lru(key);
    return true;
}

// ─── Lists, the positional spellings ───

int cache_store::lset(std::string_view key, int64_t idx, std::string_view val)
{
    check_expiry(key);
    auto it = m_lists.find(key);
    if (it == m_lists.end())
        return -1;
    auto& dq = it->second;
    if (idx < 0) idx += static_cast<int64_t>(dq.size());
    if (idx < 0 || idx >= static_cast<int64_t>(dq.size()))
        return -2;

    auto& slot = dq[static_cast<size_t>(idx)];
    if (__builtin_expect(m_max_memory != 0 && val.size() > slot.size(), 0))
    {
        const size_t held = stored_string(slot);
        const size_t want = rewritten_string(slot, val.size());
        if (want > held && !check_memory(want - held, key))
            return -2;
        it = m_lists.find(key);
        if (it == m_lists.end() || idx >= static_cast<int64_t>(it->second.size()))
            return -1;
    }
    auto& target = it->second[static_cast<size_t>(idx)];
    track_sub(stored_string(target));
    target.assign(val.data(), val.size());
    track_add(stored_string(target));
    touch_lru(key);
    return 0;
}

int cache_store::lrem(std::string_view key, int64_t count, std::string_view val)
{
    check_expiry(key);
    auto it = m_lists.find(key);
    if (it == m_lists.end())
        return 0;
    auto& dq = it->second;

    int removed = 0;
    const size_t want = (count == 0) ? dq.size()
                                     : static_cast<size_t>(count < 0 ? -count : count);
    if (count >= 0)
    {
        for (auto e = dq.begin(); e != dq.end() && static_cast<size_t>(removed) < want; )
        {
            if (*e == val) { track_sub(stored_string(*e)); e = dq.erase(e); ++removed; --m_list_elems; }
            else ++e;
        }
    }
    else
    {
        for (auto e = dq.end(); e != dq.begin() && static_cast<size_t>(removed) < want; )
        {
            --e;
            if (*e == val) { track_sub(stored_string(*e)); e = dq.erase(e); ++removed; --m_list_elems; }
        }
    }

    // An empty list is not a key, the way an empty sorted set is not one here.
    if (dq.empty())
    {
        track_sub(entry_cost(it->first, it->second));
        m_lists.erase(it);
        m_expiry.erase(std::string(key));
        drop_lru(key);
    }
    else if (removed > 0)
        touch_lru(key);
    return removed;
}

bool cache_store::ltrim(std::string_view key, int64_t start, int64_t stop)
{
    check_expiry(key);
    auto it = m_lists.find(key);
    if (it == m_lists.end())
        return true;     // trimming what is not there is not a failure
    auto& dq = it->second;

    int64_t s = start, e = stop;
    const bool keep = resolve_range(static_cast<int64_t>(dq.size()), s, e);
    if (!keep)
    {
        for (const auto& v : dq) { track_sub(stored_string(v)); --m_list_elems; }
        track_sub(entry_cost(it->first, it->second));
        m_lists.erase(it);
        m_expiry.erase(std::string(key));
        drop_lru(key);
        return true;
    }

    while (static_cast<int64_t>(dq.size()) > e + 1)
    { track_sub(stored_string(dq.back())); dq.pop_back(); --m_list_elems; }
    for (int64_t i = 0; i < s; ++i)
    { track_sub(stored_string(dq.front())); dq.pop_front(); --m_list_elems; }
    touch_lru(key);
    return true;
}

int cache_store::linsert(std::string_view key, bool before, std::string_view pivot,
                         std::string_view val)
{
    check_expiry(key);
    auto it = m_lists.find(key);
    if (it == m_lists.end())
        return 0;

    if (!check_memory(stored_string(val.size()) + list_elem_overhead, key))
        return -1;
    it = m_lists.find(key);
    if (it == m_lists.end())
        return 0;

    auto& dq = it->second;
    auto at = std::find(dq.begin(), dq.end(), pivot);
    if (at == dq.end())
        return -1;
    dq.insert(before ? at : std::next(at), std::string(val));
    ++m_list_elems;
    track_add(stored_string(val.size()));
    touch_lru(key);
    return static_cast<int>(dq.size());
}

bool cache_store::lmove(std::string_view src, std::string_view dst,
                        bool from_head, bool to_head, std::string& out)
{
    check_expiry(src);
    if (src != dst) check_expiry(dst);

    auto sit = m_lists.find(src);
    if (sit == m_lists.end() || sit->second.empty())
        return false;

    // The destination must be a list or absent; a string there is a refusal
    // and NOT a pop, or the element would be gone with nowhere to be.
    if (m_lists.find(dst) == m_lists.end() && has_type_conflict_for_list(dst))
        return false;

    // Charged before the pop, for the same reason: a refusal after it would
    // have taken the element out of the queue and dropped it.
    const std::string& head = from_head ? sit->second.front() : sit->second.back();
    if (src != dst && !check_memory(stored_string(head.size())
                                    + new_key_cost(dst.size()) + list_elem_overhead, dst))
        return false;
    sit = m_lists.find(src);
    if (sit == m_lists.end() || sit->second.empty())
        return false;

    if (from_head) { out = std::move(sit->second.front()); sit->second.pop_front(); }
    else           { out = std::move(sit->second.back());  sit->second.pop_back();  }
    track_sub(stored_string(out));
    --m_list_elems;

    // src == dst is a rotation, and the deque above is the one below: taken
    // before the source can be erased for being empty, which it is not.
    if (src == dst)
    {
        if (to_head) sit->second.push_front(out); else sit->second.push_back(out);
        ++m_list_elems;
        track_add(stored_string(out));
        touch_lru(src);
        return true;
    }

    if (sit->second.empty())
    {
        track_sub(entry_cost(sit->first, sit->second));
        m_lists.erase(sit);
        m_expiry.erase(std::string(src));
        drop_lru(src);
    }

    auto dit = m_lists.find(dst);
    if (dit == m_lists.end())
        dit = m_lists.emplace(std::string(dst), std::deque<std::string>{}).first;
    if (to_head) dit->second.push_front(out); else dit->second.push_back(out);
    ++m_list_elems;
    track_add(stored_string(out));
    touch_lru(dst);
    return true;
}

// ─── Sets, the sampling spellings ───

bool cache_store::spop(std::string_view key, std::string& out)
{
    check_expiry(key);
    auto it = m_sets.find(key);
    if (it == m_sets.end() || it->second.empty())
        return false;

    auto mit = it->second.begin();
    out = *mit;
    track_sub(stored_string(*mit));
    it->second.erase(mit);
    --m_set_elems;

    if (it->second.empty())
    {
        track_sub(stored_string(it->first));
        m_sets.erase(it);
        m_expiry.erase(std::string(key));
        drop_lru(key);
    }
    else
        touch_lru(key);
    return true;
}

bool cache_store::srandmember(std::string_view key, std::string& out) const
{
    auto it = m_sets.find(key);
    if (it == m_sets.end() || it->second.empty())
        return false;
    out = *it->second.begin();
    return true;
}

// What a pattern is matched against, which is the element itself in a set and
// the field or member name in the other two.
static inline std::string_view scan_key_of(const std::string& s) { return s; }
template <typename A, typename B>
static inline std::string_view scan_key_of(const std::pair<A, B>& p) { return p.first; }

// ─── One collection, scanned ───
//
// The keyspace SCAN packs a map index beside the bucket count because it walks
// five maps; over one key there is no index, so the whole 24 bits of bucket
// count and 32 of bucket index are this collection's.  The count rides along
// for the same reason it does there: a resume can tell whether the table it is
// going back into is the one it left, and a rehash restarts rather than
// silently skipping half the elements.
template <typename Map, typename Emit>
static uint64_t scan_one_collection(const Map& map, uint64_t cursor,
                                    std::string_view pattern, size_t count, Emit emit)
{
    const bool match_all = (pattern.empty() || pattern == "*");
    const auto match = [&](std::string_view k) {
        return match_all
            || fnmatch(std::string(pattern).c_str(), std::string(k).c_str(), 0) == 0;
    };

    const uint32_t was_buckets = static_cast<uint32_t>((cursor >> 32) & 0xFFFFFFu);
    size_t         bucket      = static_cast<size_t>(cursor & 0xFFFFFFFFu);
    const size_t   nbuckets    = map.bucket_count();

    // A table that has been rehashed under the caller is one this cursor
    // cannot resume into, so it starts again rather than reporting a slice.
    if (was_buckets != 0 && was_buckets != (nbuckets & 0xFFFFFFu))
        bucket = 0;

    size_t emitted = 0;
    for (size_t b = bucket; b < nbuckets; ++b)
    {
        for (auto it = map.begin(b); it != map.end(b); ++it)
            if (match(scan_key_of(*it))) { emit(*it); ++emitted; }

        // Whole buckets only: half of one would need an element index the
        // cursor has no room for.
        if (emitted >= count && b + 1 < nbuckets)
            return ((static_cast<uint64_t>(nbuckets) & 0xFFFFFFu) << 32)
                 | (static_cast<uint64_t>(b + 1) & 0xFFFFFFFFu);
    }
    return 0;
}

uint64_t cache_store::hscan(std::string_view key, uint64_t cursor,
                            std::string_view pattern, size_t count,
                            std::vector<std::pair<std::string_view, std::string_view>>& out) const
{
    auto it = m_hashes.find(key);
    if (it == m_hashes.end()) return 0;
    return scan_one_collection(it->second, cursor, pattern, count,
        [&out](const auto& e) { out.emplace_back(std::string_view(e.first),
                                                 std::string_view(e.second)); });
}

uint64_t cache_store::sscan(std::string_view key, uint64_t cursor,
                            std::string_view pattern, size_t count,
                            std::vector<std::string_view>& out) const
{
    auto it = m_sets.find(key);
    if (it == m_sets.end()) return 0;
    return scan_one_collection(it->second, cursor, pattern, count,
        [&out](const auto& e) { out.emplace_back(std::string_view(e)); });
}

uint64_t cache_store::zscan(std::string_view key, uint64_t cursor,
                            std::string_view pattern, size_t count,
                            std::vector<std::pair<std::string_view, double>>& out) const
{
    auto it = m_zsets.find(key);
    if (it == m_zsets.end()) return 0;
    return scan_one_collection(it->second.score, cursor, pattern, count,
        [&out](const auto& e) { out.emplace_back(std::string_view(e.first), e.second); });
}

// ─── Hashes, the field spellings ───

bool cache_store::hexists(std::string_view key, std::string_view field) const
{
    auto it = m_hashes.find(key);
    return it != m_hashes.end() && it->second.count(field) > 0;
}

bool cache_store::hincrby(std::string_view key, std::string_view field,
                          int64_t delta, int64_t& result)
{
    check_expiry(key);

    int64_t val = 0;
    auto it = m_hashes.find(key);
    if (it != m_hashes.end())
    {
        auto fit = it->second.find(field);
        if (fit != it->second.end())
        {
            auto [ptr, ec] = std::from_chars(fit->second.data(),
                                             fit->second.data() + fit->second.size(), val);
            if (ec != std::errc{} || ptr != fit->second.data() + fit->second.size())
                return false;
        }
    }

    val += delta;
    result = val;

    char buf[24];
    auto [end, ec2] = std::to_chars(buf, buf + sizeof(buf), val);
    (void)ec2;
    return hset(key, field, std::string_view(buf, static_cast<size_t>(end - buf)));
}

int cache_store::hsetnx(std::string_view key, std::string_view field, std::string_view val)
{
    check_expiry(key);
    auto it = m_hashes.find(key);
    if (it != m_hashes.end() && it->second.count(field))
        return 0;
    return hset(key, field, val) ? 1 : -1;
}

// ─── Sorted sets, by score rather than by rank ───

// Where a score range starts in the ordered view: the pair's second element
// orders equal scores, so an inclusive low end must sit before every member
// holding it and an exclusive one after all of them.
static std::set<std::pair<double, std::string>>::const_iterator
score_lower(const std::set<std::pair<double, std::string>>& ord, double min, bool incl)
{
    return incl ? ord.lower_bound({min, std::string{}})
                : ord.upper_bound({min, std::string(1, '\xff')});
}

void cache_store::zrangebyscore(std::string_view key, double min, double max,
                                bool min_incl, bool max_incl, bool reverse,
                                std::vector<std::pair<std::string_view, double>>& out) const
{
    auto it = m_zsets.find(key);
    if (it == m_zsets.end())
        return;
    const auto& ord = it->second.order;

    for (auto e = score_lower(ord, min, min_incl); e != ord.end(); ++e)
    {
        if (e->first > max || (!max_incl && e->first == max))
            break;
        out.emplace_back(std::string_view(e->second), e->first);
    }
    if (reverse)
        std::reverse(out.begin(), out.end());
}

size_t cache_store::zcount(std::string_view key, double min, double max,
                           bool min_incl, bool max_incl) const
{
    auto it = m_zsets.find(key);
    if (it == m_zsets.end())
        return 0;
    const auto& ord = it->second.order;
    size_t n = 0;
    for (auto e = score_lower(ord, min, min_incl); e != ord.end(); ++e)
    {
        if (e->first > max || (!max_incl && e->first == max))
            break;
        ++n;
    }
    return n;
}

bool cache_store::zpop(std::string_view key, bool highest, std::string& member, double& score)
{
    check_expiry(key);
    auto it = m_zsets.find(key);
    if (it == m_zsets.end() || it->second.empty())
        return false;

    auto e = highest ? std::prev(it->second.order.end()) : it->second.order.begin();
    score  = e->first;
    member = e->second;
    zrem(key, member);      // one removal path, so the empty-key rule lives once
    return true;
}

size_t cache_store::zremrangebyrank(std::string_view key, int64_t start, int64_t stop)
{
    check_expiry(key);
    auto it = m_zsets.find(key);
    if (it == m_zsets.end())
        return 0;

    int64_t s = start, e = stop;
    if (!resolve_range(static_cast<int64_t>(it->second.order.size()), s, e))
        return 0;

    std::vector<std::string> doomed;
    int64_t i = 0;
    for (const auto& m : it->second.order)
    {
        if (i > e) break;
        if (i >= s) doomed.push_back(m.second);
        ++i;
    }
    for (const auto& m : doomed)
        zrem(key, m);
    return doomed.size();
}

size_t cache_store::zremrangebyscore(std::string_view key, double min, double max,
                                     bool min_incl, bool max_incl)
{
    check_expiry(key);
    auto it = m_zsets.find(key);
    if (it == m_zsets.end())
        return 0;

    std::vector<std::string> doomed;
    for (auto e = score_lower(it->second.order, min, min_incl);
         e != it->second.order.end(); ++e)
    {
        if (e->first > max || (!max_incl && e->first == max))
            break;
        doomed.push_back(e->second);
    }
    for (const auto& m : doomed)
        zrem(key, m);
    return doomed.size();
}

std::string_view cache_store::type(std::string_view key) const
{
    if (m_data.count(key)) return "string";
    if (!m_lists.empty() && m_lists.count(key)) return "list";
    if (!m_sets.empty() && m_sets.count(key)) return "set";
    if (!m_hashes.empty() && m_hashes.count(key)) return "hash";
    if (!m_zsets.empty()  && m_zsets.count(key))  return "zset";
    return "none";
}

void cache_store::keys(std::string_view pattern, std::vector<std::string_view>& out) const
{
    bool match_all = (pattern == "*");
    auto match = [&](std::string_view key) -> bool {
        if (match_all) return true;
        // fnmatch requires null-terminated strings
        std::string key_str(key);
        std::string pat_str(pattern);
        return fnmatch(pat_str.c_str(), key_str.c_str(), 0) == 0;
    };

    for (const auto& [key, _] : m_data)
        if (match(key)) out.push_back(key);
    for (const auto& [key, _] : m_lists)
        if (match(key)) out.push_back(key);
    for (const auto& [key, _] : m_sets)
        if (match(key)) out.push_back(key);
    for (const auto& [key, _] : m_zsets)
        if (match(key)) out.push_back(key);
    for (const auto& [key, _] : m_hashes)
        if (match(key)) out.push_back(key);
}

// ─── General ───

// The one place that knows every container a key can live in, and the one
// place that keeps the element counters straight while removing it.
//
// Three callers used to spell this chain out and TWO of them stopped at
// m_hashes.  A sorted set therefore survived its own expiry -- the deadline
// erased, the members kept, and TTL answering -1 for ever afterwards -- as
// soon as any read path reached the key before the 500 ms sweep did.
bool cache_store::drop_value(std::string_view key)
{
    // Use transparent find + erase-by-iterator to avoid allocating std::string(key)
    if (auto it = m_data.find(key); it != m_data.end())
    {
        track_sub(entry_cost(it->first, it->second));
        m_data.erase(it);
        return true;
    }
    if (auto it = m_lists.find(key); it != m_lists.end())
    {
        track_sub(entry_cost(it->first, it->second));
        m_list_elems -= it->second.size();
        m_lists.erase(it);
        return true;
    }
    if (auto it = m_sets.find(key); it != m_sets.end())
    {
        track_sub(entry_cost(it->first, it->second));
        m_set_elems -= it->second.size();
        m_sets.erase(it);
        return true;
    }
    if (auto it = m_hashes.find(key); it != m_hashes.end())
    {
        track_sub(entry_cost(it->first, it->second));
        m_hash_fields -= it->second.size();
        m_hashes.erase(it);
        return true;
    }
    if (auto it = m_zsets.find(key); it != m_zsets.end())
    {
        track_sub(entry_cost(it->first, it->second));
        m_zset_members -= it->second.size();
        m_zsets.erase(it);
        return true;
    }
    return false;
}

bool cache_store::del(std::string_view key)
{
    if (auto eit = m_expiry.find(key); eit != m_expiry.end())
        m_expiry.erase(eit);

    drop_lru(key);
    return drop_value(key);
}

uint32_t cache_store::size() const
{
    return static_cast<uint32_t>(m_data.size() + m_lists.size() + m_sets.size()
                              + m_hashes.size() + m_zsets.size());
}

bool cache_store::exists(std::string_view key) const
{
    // Check m_data first — most keys are strings in typical workloads
    if (__builtin_expect(m_data.count(key) != 0, 1)) return true;
    if (!m_lists.empty() && m_lists.count(key)) return true;
    if (!m_sets.empty() && m_sets.count(key)) return true;
    if (!m_hashes.empty() && m_hashes.count(key)) return true;
    if (!m_zsets.empty() && m_zsets.count(key)) return true;
    return false;
}

// ─── Persistence ───

void cache_store::dump_commands(std::string& buf) const
{
    // ─── A VALUE MAY CONTAIN THE SEPARATOR ──────────────────────────────────
    // Framed by the same rule as the live replication path, so a value with a
    // newline in it does not end the command -- and a dataset without newlines
    // produces a byte-for-byte identical stream.
    std::string cmd;
    const auto emit = [&buf, &cmd]() {
        if (ipc_frame::needs_frame(cmd))
            buf += ipc_frame::encode(cmd);
        else
        {
            buf.append(cmd);
            buf.push_back('\n');
        }
        cmd.clear();
    };

    // Strings
    for (const auto& [key, val] : m_data)
    {
        cmd.append("set ");
        cmd.append(key);
        cmd.push_back(' ');
        cmd.append(val);
        emit();
    }

    // Lists (emit rpush to preserve order)
    for (const auto& [key, deq] : m_lists)
    {
        for (const auto& val : deq)
        {
            cmd.append("rpush ");
            cmd.append(key);
            cmd.push_back(' ');
            cmd.append(val);
            emit();
        }
    }

    // Sets
    for (const auto& [key, members] : m_sets)
    {
        for (const auto& member : members)
        {
            cmd.append("sadd ");
            cmd.append(key);
            cmd.push_back(' ');
            cmd.append(member);
            emit();
        }
    }

    // Hashes
    for (const auto& [key, fields] : m_hashes)
    {
        for (const auto& [field, val] : fields)
        {
            cmd.append("hset ");
            cmd.append(key);
            cmd.push_back(' ');
            cmd.append(field);
            cmd.push_back(' ');
            cmd.append(val);
            emit();
        }
    }

    // Sorted sets, which this walk did not have and every follower therefore
    // started without -- silently, because the live stream carried the zadds
    // that came after and only the leader's existing ones went missing.
    for (const auto& [key, z] : m_zsets)
    {
        for (const auto& [score, member] : z.order)
        {
            cmd.append("zadd ");
            cmd.append(key);
            cmd.push_back(' ');
            // Whole scores print as integers, which is what the text
            // interpreter reads back without a rounding step.
            if (score == static_cast<double>(static_cast<int64_t>(score))
                && score < 9.2e18 && score > -9.2e18)
                cmd.append(std::to_string(static_cast<int64_t>(score)));
            else
            {
                char sb[40];
                const int n = std::snprintf(sb, sizeof(sb), "%.17g", score);
                if (n > 0) cmd.append(sb, static_cast<size_t>(n));
            }
            cmd.push_back(' ');
            cmd.append(member);
            emit();
        }
    }

    // ─── TTLs, in milliseconds ──────────────────────────────────────────────
    // pexpire rather than expire, because the cast truncated a key with 500 ms
    // left to `expire key 0`, which the `> 0` test then dropped and the key
    // came back immortal.
    auto now = std::chrono::steady_clock::now();
    for (const auto& [key, tp] : m_expiry)
    {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(tp - now).count();
        if (ms > 0)
        {
            cmd.append("pexpire ");
            cmd.append(key);
            cmd.push_back(' ');
            cmd.append(std::to_string(ms));
            emit();
        }
    }
}

static constexpr char MAGIC_V2[4] = {'S', 'K', 'V', '2'};

// Append-only: an older build reads a dump it does not know the types in,
// which is why a new one goes on the end and never in the middle.
enum : uint8_t { TYPE_STRING = 0, TYPE_LIST = 1, TYPE_SET = 2, TYPE_HASH = 3,
                 TYPE_ZSET = 4 };

void cache_store::adopt_owned(cache_store& other, uint32_t shard_index,
                              uint32_t shard_count)
{
    const auto mine = [&](const std::string& k) {
        return cache_shard_of(k, shard_count) == shard_index;
    };

    // The deadline moves with the key, and it is read BEFORE the key is moved
    // out of `other` — after the move the string is gone and the lookup would
    // be against an empty key.
    const auto carry_expiry = [&](const std::string& k) {
        const auto e = other.m_expiry.find(k);
        if (e != other.m_expiry.end())
            m_expiry[k] = e->second;
    };

    for (auto it = other.m_data.begin(); it != other.m_data.end(); ++it)
        if (mine(it->first))
        {
            carry_expiry(it->first);
            adopt_loaded_string(std::string(it->first), std::move(it->second));
        }

    for (auto it = other.m_lists.begin(); it != other.m_lists.end(); ++it)
        if (mine(it->first))
        {
            carry_expiry(it->first);
            adopt_loaded_list(std::string(it->first), std::move(it->second));
        }

    for (auto it = other.m_sets.begin(); it != other.m_sets.end(); ++it)
        if (mine(it->first))
        {
            carry_expiry(it->first);
            adopt_loaded_set(std::string(it->first), std::move(it->second));
        }

    for (auto it = other.m_hashes.begin(); it != other.m_hashes.end(); ++it)
        if (mine(it->first))
        {
            carry_expiry(it->first);
            adopt_loaded_hash(std::string(it->first), std::move(it->second));
        }

    for (auto it = other.m_zsets.begin(); it != other.m_zsets.end(); ++it)
        if (mine(it->first))
        {
            carry_expiry(it->first);
            adopt_loaded_zset(std::string(it->first), std::move(it->second));
        }
}

bool cache_store::save(std::string_view path, std::string_view prefix) const
{
    return save_v2(path, prefix);
}

bool cache_store::save_v2(std::string_view path, std::string_view prefix) const
{
    std::string tmp_path = std::string(path) + ".tmp";

    // Phase 1: Calculate total file size
    size_t total_size = prefix.size() + 4;  // caller's header, then MAGIC_V2

    auto entry_overhead = [&](std::string_view key) -> size_t {
        // type(1) + key_len(4) + key + expiry_flag(1) [+ remaining_ms(8)]
        size_t sz = 1 + 4 + key.size() + 1;
        auto eit = m_expiry.find(key);
        if (eit != m_expiry.end()) sz += 8;
        return sz;
    };

    auto string_size = [](std::string_view s) -> size_t { return 4 + s.size(); };

    for (const auto& [key, value] : m_data)
        total_size += entry_overhead(key) + string_size(value);

    for (const auto& [key, deq] : m_lists)
    {
        total_size += entry_overhead(key) + 4;
        for (const auto& elem : deq) total_size += string_size(elem);
    }

    for (const auto& [key, s] : m_sets)
    {
        total_size += entry_overhead(key) + 4;
        for (const auto& member : s) total_size += string_size(member);
    }

    for (const auto& [key, h] : m_hashes)
    {
        total_size += entry_overhead(key) + 4;
        for (const auto& [field, val] : h) total_size += string_size(field) + string_size(val);
    }

    // A score rides as its eight raw bytes, like every u32 in this file: the
    // dump is native and carries a fingerprint that says so.
    for (const auto& [key, z] : m_zsets)
    {
        total_size += entry_overhead(key) + 4;
        for (const auto& [member, sc] : z.score) total_size += string_size(member) + 8;
    }

    // Phase 2: mmap temp file and serialize directly into mapped region
    //
    // ─── 0600, AND CREATED THAT WAY ─────────────────────────────────────────
    // 0600 rather than the literal 0644 a dump was written at, created O_EXCL
    // after an unlink because O_CREAT does not touch an existing file's mode
    // and this .tmp name is deterministic -- and cache_instance::start() loads
    // this path, so it is what the cache will hold rather than a report of
    // what it held.
    unlink(tmp_path.c_str());
    int fd_raw = open(tmp_path.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd_raw < 0) return false;

    if (ftruncate(fd_raw, static_cast<off_t>(total_size)) < 0)
    {
        close(fd_raw);
        return false;
    }

    void* map = mmap(nullptr, total_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd_raw, 0);
    if (map == MAP_FAILED)
    {
        close(fd_raw);
        return false;
    }

    char* p = static_cast<char*>(map);
    auto now = std::chrono::steady_clock::now();

    auto emit = [&](const void* src, size_t n) { std::memcpy(p, src, n); p += n; };
    auto emit_u8  = [&](uint8_t v)  { *p++ = static_cast<char>(v); };
    auto emit_u32 = [&](uint32_t v) { std::memcpy(p, &v, 4); p += 4; };
    auto emit_i64 = [&](int64_t v)  { std::memcpy(p, &v, 8); p += 8; };

    auto emit_string = [&](std::string_view s) {
        emit_u32(static_cast<uint32_t>(s.size()));
        emit(s.data(), s.size());
    };

    auto emit_key = [&](uint8_t type, std::string_view key) {
        emit_u8(type);
        emit_string(key);
    };

    auto emit_expiry = [&](std::string_view key) {
        auto eit = m_expiry.find(key);
        if (eit == m_expiry.end())
        {
            emit_u8(0);
        }
        else
        {
            emit_u8(1);
            int64_t remaining_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                eit->second - now).count();
            if (remaining_ms < 0) remaining_ms = 0;
            emit_i64(remaining_ms);
        }
    };

    if (!prefix.empty())
        emit(prefix.data(), prefix.size());
    emit(MAGIC_V2, 4);

    for (const auto& [key, value] : m_data)
    {
        emit_key(TYPE_STRING, key);
        emit_string(value);
        emit_expiry(key);
    }

    for (const auto& [key, deq] : m_lists)
    {
        emit_key(TYPE_LIST, key);
        emit_u32(static_cast<uint32_t>(deq.size()));
        for (const auto& elem : deq) emit_string(elem);
        emit_expiry(key);
    }

    for (const auto& [key, s] : m_sets)
    {
        emit_key(TYPE_SET, key);
        emit_u32(static_cast<uint32_t>(s.size()));
        for (const auto& member : s) emit_string(member);
        emit_expiry(key);
    }

    for (const auto& [key, h] : m_hashes)
    {
        emit_key(TYPE_HASH, key);
        emit_u32(static_cast<uint32_t>(h.size()));
        for (const auto& [field, val] : h)
        {
            emit_string(field);
            emit_string(val);
        }
        emit_expiry(key);
    }

    for (const auto& [key, z] : m_zsets)
    {
        emit_key(TYPE_ZSET, key);
        emit_u32(static_cast<uint32_t>(z.score.size()));
        for (const auto& [member, sc] : z.score)
        {
            emit_string(member);
            std::memcpy(p, &sc, 8); p += 8;
        }
        emit_expiry(key);
    }

    if (msync(map, total_size, MS_SYNC) < 0) {}
    munmap(map, total_size);
    fsync(fd_raw);
    close(fd_raw);

    return rename(tmp_path.c_str(), std::string(path).c_str()) == 0;
}

bool cache_store::load(std::string_view path, size_t offset)
{
    // mmap path: zero-copy read from page cache
    int fd_raw = open(std::string(path).c_str(), O_RDONLY | O_CLOEXEC);
    if (fd_raw < 0)
        return false;

    struct stat st;
    if (fstat(fd_raw, &st) < 0
        || st.st_size < 4
        || static_cast<size_t>(st.st_size) < offset + 4)
    {
        close(fd_raw);
        return false;
    }

    // ─── THE DUMPS THAT ARE ALREADY ON DISK ─────────────────────────────────
    // The same repair state_persistence makes to the runtime records, through
    // fchmod on the descriptor already opened so it cannot be pointed at a
    // different file, narrowing only.
    if ((st.st_mode & 0077) != 0)
    {
        if (fchmod(fd_raw, 0600) == 0)
            LOG_INFO(("cache: tightened " + std::string(path) +
                      " to 0600 — a persistence dump holds whatever was cached "
                      "and was readable by other users on this machine").c_str());
    }

    auto file_size = static_cast<size_t>(st.st_size);
    void* map = mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE, fd_raw, 0);
    close(fd_raw);

    if (map == MAP_FAILED)
    {
        // Fallback to ifstream
        std::ifstream file(std::string(path), std::ios::binary);
        if (!file) return false;
        if (offset > 0) file.seekg(static_cast<std::streamoff>(offset));
        char header[4]{};
        file.read(header, 4);
        if (!file) return false;
        if (std::memcmp(header, MAGIC_V2, 4) == 0)
            return load_v2_stream(file);
        uint32_t first_key_len;
        std::memcpy(&first_key_len, header, sizeof(first_key_len));
        return load_v1(file, first_key_len);
    }

    // The caller's header, if it wrote one, is skipped here and nowhere else:
    // everything below this line reads exactly the bytes it always read.
    const char* data = static_cast<const char*>(map) + offset;
    file_size -= offset;

    if (std::memcmp(data, MAGIC_V2, 4) == 0)
    {
        bool ok = load_v2(data + 4, file_size - 4);
        munmap(map, file_size + offset);
        return ok;
    }

    // v1 format — fall back to stream parser
    munmap(map, file_size + offset);
    std::ifstream file(std::string(path), std::ios::binary);
    if (!file) return false;
    if (offset > 0) file.seekg(static_cast<std::streamoff>(offset));
    char header[4]{};
    file.read(header, 4);
    if (!file) return false;
    uint32_t first_key_len;
    std::memcpy(&first_key_len, header, sizeof(first_key_len));
    return load_v1(file, first_key_len);
}

bool cache_store::load_v2(const char* data, size_t size)
{
    m_data.clear();
    m_lists.clear();
    m_sets.clear();
    m_hashes.clear();
    m_zsets.clear();
    m_list_elems = 0;
    m_set_elems = 0;
    m_hash_fields = 0;
    m_expiry.clear();
    m_current_memory = 0;
    m_lru_order.clear();
    m_lru_map.clear();

    auto now = std::chrono::steady_clock::now();
    const char* p = data;
    const char* end = data + size;

    auto remaining = [&]() -> size_t { return static_cast<size_t>(end - p); };

    auto read_u8 = [&](uint8_t& v) -> bool {
        if (remaining() < 1) return false;
        v = static_cast<uint8_t>(*p++);
        return true;
    };

    auto read_u32 = [&](uint32_t& v) -> bool {
        if (remaining() < 4) return false;
        std::memcpy(&v, p, 4); p += 4;
        return true;
    };

    auto read_i64 = [&](int64_t& v) -> bool {
        if (remaining() < 8) return false;
        std::memcpy(&v, p, 8); p += 8;
        return true;
    };

    auto read_string = [&](std::string& out) -> bool {
        uint32_t len = 0;
        if (!read_u32(len)) return false;
        if (remaining() < len) return false;
        // Constructed and not assign()ed into, because assign() rounds up to
        // twice the old capacity and a cache reloading its own dump occupied
        // more than the one that wrote it.
        out = std::string(p, len);
        p += len;
        return true;
    };

    auto read_expiry = [&](const std::string& key) {
        uint8_t has = 0;
        if (!read_u8(has)) return;
        if (has)
        {
            int64_t remaining_ms = 0;
            if (!read_i64(remaining_ms)) return;
            if (remaining_ms > 0)
                m_expiry[key] = now + std::chrono::milliseconds(remaining_ms);
        }
    };

    while (p < end)
    {
        uint8_t type = 0;
        if (!read_u8(type)) break;

        std::string key;
        if (!read_string(key)) break;

        bool expired = false;

        switch (type)
        {
            case TYPE_STRING:
            {
                std::string value;
                if (!read_string(value)) return false;
                uint8_t has = 0;
                if (!read_u8(has)) return false;
                if (has)
                {
                    int64_t remaining_ms = 0;
                    if (!read_i64(remaining_ms)) return false;
                    if (remaining_ms > 0)
                        m_expiry[key] = now + std::chrono::milliseconds(remaining_ms);
                    else
                        expired = true;
                }
                if (!expired)
                    adopt_loaded_string(std::move(key), std::move(value));
                break;
            }
            case TYPE_LIST:
            {
                uint32_t count = 0;
                if (!read_u32(count)) return false;
                std::deque<std::string> deq;
                for (uint32_t i = 0; i < count; i++)
                {
                    std::string elem;
                    if (!read_string(elem)) return false;
                    deq.push_back(std::move(elem));
                }
                read_expiry(key);
                if (!m_expiry.count(key) || m_expiry[key] > now)
                    adopt_loaded_list(std::move(key), std::move(deq));
                break;
            }
            case TYPE_SET:
            {
                uint32_t count = 0;
                if (!read_u32(count)) return false;
                set_inner s;
                for (uint32_t i = 0; i < count; i++)
                {
                    std::string member;
                    if (!read_string(member)) return false;
                    s.insert(std::move(member));
                }
                read_expiry(key);
                if (!m_expiry.count(key) || m_expiry[key] > now)
                    adopt_loaded_set(std::move(key), std::move(s));
                break;
            }
            case TYPE_HASH:
            {
                uint32_t count = 0;
                if (!read_u32(count)) return false;
                hash_inner h;
                for (uint32_t i = 0; i < count; i++)
                {
                    std::string field, val;
                    if (!read_string(field)) return false;
                    if (!read_string(val)) return false;
                    h[std::move(field)] = std::move(val);
                }
                read_expiry(key);
                if (!m_expiry.count(key) || m_expiry[key] > now)
                    adopt_loaded_hash(std::move(key), std::move(h));
                break;
            }
            case TYPE_ZSET:
            {
                uint32_t count = 0;
                if (!read_u32(count)) return false;
                zset_inner z;
                for (uint32_t i = 0; i < count; i++)
                {
                    std::string member;
                    double      sc = 0.0;
                    if (!read_string(member)) return false;
                    if (remaining() < 8) return false;
                    std::memcpy(&sc, p, 8); p += 8;
                    z.order.emplace(sc, member);
                    z.score.emplace(std::move(member), sc);
                }
                read_expiry(key);
                if (!m_expiry.count(key) || m_expiry[key] > now)
                    adopt_loaded_zset(std::move(key), std::move(z));
                break;
            }
            default:
                return false;
        }
    }

    return true;
}

bool cache_store::load_v2_stream(std::ifstream& file)
{
    // Legacy ifstream-based parser (fallback when mmap fails)
    m_data.clear();
    m_lists.clear();
    m_sets.clear();
    m_hashes.clear();
    m_zsets.clear();
    m_list_elems = 0;
    m_set_elems = 0;
    m_hash_fields = 0;
    m_expiry.clear();
    m_current_memory = 0;
    m_lru_order.clear();
    m_lru_map.clear();

    auto now = std::chrono::steady_clock::now();

    auto read_string = [&](std::string& out) -> bool {
        uint32_t len = 0;
        file.read(reinterpret_cast<char*>(&len), sizeof(len));
        if (!file) return false;
        // Sized on construction rather than resize()d into, for the reason
        // given in load_v2(): growing a fresh string to 16..29 bytes buys 30.
        std::string buf(len, '\0');
        file.read(buf.data(), len);
        out = std::move(buf);
        return file.good() || file.eof();
    };

    auto read_expiry = [&](const std::string& key) {
        uint8_t has = 0;
        file.read(reinterpret_cast<char*>(&has), 1);
        if (has)
        {
            int64_t remaining_ms = 0;
            file.read(reinterpret_cast<char*>(&remaining_ms), sizeof(remaining_ms));
            if (remaining_ms > 0)
                m_expiry[key] = now + std::chrono::milliseconds(remaining_ms);
        }
    };

    while (file)
    {
        uint8_t type = 0;
        file.read(reinterpret_cast<char*>(&type), 1);
        if (!file) break;

        std::string key;
        if (!read_string(key)) break;

        bool expired = false;

        switch (type)
        {
            case TYPE_STRING:
            {
                std::string value;
                if (!read_string(value)) return false;
                uint8_t has = 0;
                file.read(reinterpret_cast<char*>(&has), 1);
                if (has)
                {
                    int64_t remaining_ms = 0;
                    file.read(reinterpret_cast<char*>(&remaining_ms), sizeof(remaining_ms));
                    if (remaining_ms > 0)
                        m_expiry[key] = now + std::chrono::milliseconds(remaining_ms);
                    else
                        expired = true;
                }
                if (!expired)
                    adopt_loaded_string(std::move(key), std::move(value));
                break;
            }
            case TYPE_LIST:
            {
                uint32_t count = 0;
                file.read(reinterpret_cast<char*>(&count), sizeof(count));
                if (!file) return false;
                std::deque<std::string> deq;
                for (uint32_t i = 0; i < count; i++)
                {
                    std::string elem;
                    if (!read_string(elem)) return false;
                    deq.push_back(std::move(elem));
                }
                read_expiry(key);
                if (!m_expiry.count(key) || m_expiry[key] > now)
                    adopt_loaded_list(std::move(key), std::move(deq));
                break;
            }
            case TYPE_SET:
            {
                uint32_t count = 0;
                file.read(reinterpret_cast<char*>(&count), sizeof(count));
                if (!file) return false;
                set_inner s;
                for (uint32_t i = 0; i < count; i++)
                {
                    std::string member;
                    if (!read_string(member)) return false;
                    s.insert(std::move(member));
                }
                read_expiry(key);
                if (!m_expiry.count(key) || m_expiry[key] > now)
                    adopt_loaded_set(std::move(key), std::move(s));
                break;
            }
            case TYPE_HASH:
            {
                uint32_t count = 0;
                file.read(reinterpret_cast<char*>(&count), sizeof(count));
                if (!file) return false;
                hash_inner h;
                for (uint32_t i = 0; i < count; i++)
                {
                    std::string field, val;
                    if (!read_string(field)) return false;
                    if (!read_string(val)) return false;
                    h[std::move(field)] = std::move(val);
                }
                read_expiry(key);
                if (!m_expiry.count(key) || m_expiry[key] > now)
                    adopt_loaded_hash(std::move(key), std::move(h));
                break;
            }
            case TYPE_ZSET:
            {
                uint32_t count = 0;
                file.read(reinterpret_cast<char*>(&count), sizeof(count));
                if (!file) return false;
                zset_inner z;
                for (uint32_t i = 0; i < count; i++)
                {
                    std::string member;
                    double      sc = 0.0;
                    if (!read_string(member)) return false;
                    file.read(reinterpret_cast<char*>(&sc), sizeof(sc));
                    if (!file) return false;
                    z.order.emplace(sc, member);
                    z.score.emplace(std::move(member), sc);
                }
                read_expiry(key);
                if (!m_expiry.count(key) || m_expiry[key] > now)
                    adopt_loaded_zset(std::move(key), std::move(z));
                break;
            }
            default:
                return false;
        }
    }

    return true;
}

bool cache_store::load_v1(std::ifstream& file, uint32_t first_key_len)
{
    m_data.clear();
    m_lists.clear();
    m_sets.clear();
    m_hashes.clear();
    m_zsets.clear();
    m_list_elems = 0;
    m_set_elems = 0;
    m_hash_fields = 0;
    m_expiry.clear();
    m_current_memory = 0;
    m_lru_order.clear();
    m_lru_map.clear();

    // Process the first entry (key_len already read)
    uint32_t key_len = first_key_len;

    while (true)
    {
        std::string key(key_len, '\0');
        file.read(key.data(), key_len);
        if (!file) break;

        uint32_t val_len = 0;
        file.read(reinterpret_cast<char*>(&val_len), sizeof(val_len));
        if (!file) break;

        std::string value(val_len, '\0');
        file.read(value.data(), val_len);
        if (!file) break;

        adopt_loaded_string(std::move(key), std::move(value));

        // Try reading next key_len
        file.read(reinterpret_cast<char*>(&key_len), sizeof(key_len));
        if (!file) break;
    }

    return true;
}

// ─── Eviction / Memory ───

void cache_store::set_max_memory(size_t bytes)
{
    // touch_lru is a no-op while there is no limit, so switching one on over
    // existing data would otherwise leave try_evict an empty list.
    const bool enabling = (m_max_memory == 0 && bytes != 0);
    m_max_memory = bytes;
    if (enabling)
        rebuild_lru();
}

void cache_store::set_eviction(eviction_policy policy)
{
    m_eviction = policy;
}

// Each of these measures the entry after it has been moved into place, for the
// same reason the live writes do: what a restored string costs is whatever
// buffer it arrived with, not the sum of the lengths that were on disk.
void cache_store::adopt_loaded_string(std::string&& key, std::string&& value)
{
    auto it = m_data.insert_or_assign(std::move(key), std::move(value)).first;
    track_add(entry_cost(it->first, it->second));
    touch_lru(it->first);
}

void cache_store::adopt_loaded_list(std::string&& key, std::deque<std::string>&& deq)
{
    m_list_elems += deq.size();
    auto it = m_lists.insert_or_assign(std::move(key), std::move(deq)).first;
    track_add(entry_cost(it->first, it->second));
    touch_lru(it->first);
}

void cache_store::adopt_loaded_set(std::string&& key, set_inner&& members)
{
    m_set_elems += members.size();
    auto it = m_sets.insert_or_assign(std::move(key), std::move(members)).first;
    track_add(entry_cost(it->first, it->second));
    touch_lru(it->first);
}

void cache_store::adopt_loaded_hash(std::string&& key, hash_inner&& fields)
{
    m_hash_fields += fields.size();
    auto it = m_hashes.insert_or_assign(std::move(key), std::move(fields)).first;
    track_add(entry_cost(it->first, it->second));
    touch_lru(it->first);
}

void cache_store::adopt_loaded_zset(std::string&& key, zset_inner&& members)
{
    m_zset_members += members.size();
    auto it = m_zsets.insert_or_assign(std::move(key), std::move(members)).first;
    track_add(entry_cost(it->first, it->second));
    touch_lru(it->first);
}

void cache_store::rebuild_lru()
{
    for (const auto& e : m_data)   touch_lru(e.first);
    for (const auto& e : m_lists)  touch_lru(e.first);
    for (const auto& e : m_sets)   touch_lru(e.first);
    for (const auto& e : m_hashes) touch_lru(e.first);
    // The same omission as the expiry chain: without this a maxmemory set
    // after the fact could never evict a sorted set, because nothing had put
    // one in the LRU.
    for (const auto& e : m_zsets)  touch_lru(e.first);
}

void cache_store::drop_lru(std::string_view key)
{
    // Transparent find — no std::string allocation for the lookup.
    auto it = m_lru_map.find(key);
    if (it == m_lru_map.end())
        return;
    m_lru_order.erase(it->second);
    m_lru_map.erase(it);
    // The two copies of the key go with them, counted here because entering
    // and leaving the LRU is the only thing that creates or destroys them.
    track_sub(lru_key_copies(key.size()));
}

void cache_store::touch_lru(std::string_view key)
{
    if (__builtin_expect(m_max_memory == 0, 1))
        return;  // No memory limit, skip LRU tracking

    // Use transparent lookup (string_view) to avoid string allocation on find()
    auto it = m_lru_map.find(key);
    if (it != m_lru_map.end())
    {
        // Relink the existing node rather than destroying and rebuilding it,
        // because erase plus push_back copies the key string again on every
        // cache hit.
        m_lru_order.splice(m_lru_order.end(), m_lru_order, it->second);
    }
    else
    {
        std::string k(key);
        m_lru_order.push_back(k);
        m_lru_map[std::move(k)] = std::prev(m_lru_order.end());
        // Two more copies of the key now exist and nothing else counts them,
        // while the splice branch allocates nothing.
        track_add(lru_key_copies(key.size()));
    }
}

bool cache_store::try_evict(size_t needed, const std::string_view* protect)
{
    if (m_eviction == evict_none)
        return false;

    // Same measure check_memory uses — evicting against payload alone would
    // stop far short of the limit the caller actually set.
    while (get_memory_used() + needed > m_max_memory && !m_lru_order.empty())
    {
        // The key the caller is writing is not a candidate, so when it is the
        // only thing left the write is refused rather than paid for with its
        // own data.
        const bool protect_resident = (protect != nullptr && m_lru_map.count(*protect) != 0);
        const size_t candidates = m_lru_order.size() - (protect_resident ? 1 : 0);
        if (candidates == 0)
            break;

        // Both branches go through drop_lru(), which is the one place that
        // knows what leaving the LRU costs, so an eviction path that skipped
        // it would leak those bytes into the reported figure.
        size_t skip = 0;
        if (m_eviction != evict_allkeys_lru)   // evict_allkeys_random
        {
            static thread_local std::mt19937 rng(std::random_device{}());
            skip = std::uniform_int_distribution<size_t>(0, candidates - 1)(rng);
        }

        // The LRU policy takes the front of the order and the random one the
        // skip'th candidate, both stepping over the protected key if it is in
        // their path.
        auto node = m_lru_order.end();
        for (auto n = m_lru_order.begin(); n != m_lru_order.end(); ++n)
        {
            if (protect_resident && std::string_view(*n) == *protect)
                continue;
            if (skip == 0)
            {
                node = n;
                break;
            }
            --skip;
        }
        if (node == m_lru_order.end())
            break;
        std::string victim = *node;

        const size_t order_before = m_lru_order.size();
        drop_lru(victim);
        if (m_lru_order.size() == order_before)
        {
            // The map held no entry for this node, which cannot happen while
            // the two stay in step, and leaving it in place would spin here
            // forever.
            m_lru_order.erase(node);
        }
        m_expiry.erase(victim);

        // Delete from whichever container holds it
        if (auto it = m_data.find(victim); it != m_data.end())
        {
            track_sub(entry_cost(it->first, it->second));
            m_data.erase(it);
        }
        else if (auto it = m_lists.find(victim); it != m_lists.end())
        {
            track_sub(entry_cost(it->first, it->second));
            m_list_elems -= it->second.size();
            m_lists.erase(it);
        }
        else if (auto it = m_sets.find(victim); it != m_sets.end())
        {
            track_sub(entry_cost(it->first, it->second));
            m_set_elems -= it->second.size();
            m_sets.erase(it);
        }
        else if (auto it = m_hashes.find(victim); it != m_hashes.end())
        {
            track_sub(entry_cost(it->first, it->second));
            m_hash_fields -= it->second.size();
            m_hashes.erase(it);
        }
        else if (auto it = m_zsets.find(victim); it != m_zsets.end())
        {
            track_sub(entry_cost(it->first, it->second));
            m_zset_members -= it->second.size();
            m_zsets.erase(it);
        }
    }

    return get_memory_used() + needed <= m_max_memory;
}

// ─── Pub/Sub ───

void cache_store::subscribe(int fd, std::string_view channel)
{
    const auto [it, fresh] = m_channels.try_emplace(std::string(channel));
    it->second.insert(fd);
    if (fresh && m_chan_observer)
        m_chan_observer(m_chan_observer_ctx, it->first, true);
}

void cache_store::unsubscribe(int fd, std::string_view channel)
{
    auto it = m_channels.find(channel);
    if (it != m_channels.end())
    {
        it->second.erase(fd);
        if (it->second.empty())
        {
            if (m_chan_observer)
                m_chan_observer(m_chan_observer_ctx, it->first, false);
            m_channels.erase(it);
        }
    }
}

void cache_store::unsubscribe_all(int fd)
{
    for (auto it = m_channels.begin(); it != m_channels.end(); )
    {
        it->second.erase(fd);
        if (it->second.empty())
        {
            if (m_chan_observer)
                m_chan_observer(m_chan_observer_ctx, it->first, false);
            it = m_channels.erase(it);
        }
        else
            ++it;
    }
}

const std::unordered_set<int>* cache_store::get_subscribers(std::string_view channel) const
{
    auto it = m_channels.find(channel);
    if (it == m_channels.end())
        return nullptr;
    return &it->second;
}
