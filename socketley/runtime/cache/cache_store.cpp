#include "cache_store.h"
#include "../../shared/cache_shard_map.h"
#include "../../shared/ipc_framing.h"
#include "../../shared/logging.h"
#include <fstream>
#include <cstring>
#include <random>
#include <charconv>
#include <cmath>
#include <limits>
#include <cerrno>
#include <cstdlib>
#include <cstdio>
#include <algorithm>
#include "../../shared/glob_match.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

// ─── Per-entry cost (see the constants in cache_store.h) ───

size_t cache_store::entry_cost(std::string_view key, const std::string& val)
{
    return stored_string(key) + stored_string(val);
}

size_t cache_store::entry_cost(std::string_view key, const list_inner& deq)
{
    size_t bytes = stored_string(key) + shape_cost(deq);
    for (const auto& e : deq) bytes += stored_string(e);
    return bytes;
}

size_t cache_store::entry_cost(std::string_view key, const set_inner& members)
{
    size_t bytes = stored_string(key) + shape_cost(members);
    for (const auto& e : members) bytes += stored_string(e);
    return bytes;
}

// ─── Sorted sets ────────────────────────────────────────────────────────────

size_t cache_store::entry_cost(std::string_view key, const zset_inner& members)
{
    size_t bytes = stored_string(key) + shape_cost(members);
    // Twice per member, because the ordered view holds a copy of the name.
    for (const auto& [sc, m] : members.order) bytes += 2 * stored_string(m);
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
        double old = 0.0;
        if (it->second.score_of(member, old))
        {
            // A score that moves is a move in the ordered view too, and the
            // old pair has to go before the new one arrives or the member is
            // in there twice.
            if (old != score)
                rescore(it->second, member, old, score);
            touch_lru(key);
            return 0;
        }
    }

    if (it == m_zsets.end() && has_type_conflict_for_zset(key))
        return -1;

    const zset_inner* had = it == m_zsets.end() ? nullptr : &it->second;
    if (!check_memory(2 * stored_string(member.size()) + new_key_cost(key.size())
                      + zset_member_overhead + member_growth(had, score, member.size()), key))
        return -1;

    if (it == m_zsets.end())
    {
        it = m_zsets.emplace(std::string(key), zset_inner{}).first;
        it->second.add(score, member);
        ++m_zset_members;
        // The key's own bytes with it, which a new sorted set was never charged.
        track_add(entry_cost(it->first, it->second));
        touch_lru(key);
        return 1;
    }

    const size_t shape = shape_cost(it->second);
    it->second.add(score, member);
    ++m_zset_members;
    // The delta and not two full walks: entry_cost() sums every member, so
    // every zadd was O(n) in the set's size and filling one was O(n squared).
    // The number is the same one those two walks produced -- a member costs
    // its name twice, because the ordered view holds a copy.
    track_add(2 * stored_string(member.size()));
    reshape(shape, shape_cost(it->second));
    touch_lru(key);
    return 1;
}

void cache_store::rescore(zset_inner& z, std::string_view member, double old, double score)
{
    // Not refused for room: the member is already paid for, and what can grow
    // is the packed buffer by a wider score or the index by a rebuild.
    const size_t shape = shape_cost(z);
    z.rescore(member, old, score);
    reshape(shape, shape_cost(z));
}

bool cache_store::zrem(std::string_view key, std::string_view member)
{
    check_expiry(key);
    auto it = m_zsets.find(key);
    if (it == m_zsets.end())
        return false;
    double old = 0.0;
    if (!it->second.score_of(member, old))
        return false;

    const size_t shape = shape_cost(it->second);
    it->second.remove(member, old);
    --m_zset_members;
    // The same delta zadd charges, for the same reason.
    track_sub(2 * stored_string(member.size()));
    reshape(shape, shape_cost(it->second));

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
    return it->second.score_of(member, out);
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
    double sc = 0.0;
    if (!it->second.score_of(member, sc))
        return false;

    // The spans crossed on the way down are the rank, so this is O(log n) and
    // not a walk.  It was a walk, and at fifty thousand members that was
    // thirty-three times slower than Redis.
    const size_t rank = it->second.order.rank(sc, member);
    if (rank == zskiplist::npos)
        return false;
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
    const auto& ord = it->second.order;
    // Sought rather than counted to.  ZRANGE z 9000 9010 used to walk nine
    // thousand nodes before emitting anything; at() lands on the first one.
    if (!reverse)
    {
        auto e = ord.at(static_cast<size_t>(start));
        for (int64_t i = start; i <= stop && e != ord.end(); ++i, ++e)
            out.emplace_back(std::string_view(e->second), e->first);
    }
    else
    {
        // Index i from the back is index n-1-i from the front.
        auto e = ord.at(static_cast<size_t>(n - 1 - start));
        for (int64_t i = start; i <= stop; ++i)
        {
            if (e == ord.end()) break;
            out.emplace_back(std::string_view(e->second), e->first);
            if (e == ord.begin()) { ++i; break; }
            --e;
        }
    }
}

cache_store::zincr_result
cache_store::zincrby(std::string_view key, double delta, std::string_view member,
                     double& out)
{
    // One lookup and one walk for a member that is there, where going through
    // zscore, zadd and a zscore to check was three lookups and five walks of
    // a small set -- ZINCRBY read 1.15x Redis beside ZADD's 1.75x.
    check_expiry(key);
    auto it = m_zsets.find(key);
    double current = 0.0;
    const bool had = it != m_zsets.end() && it->second.score_of(member, current);
    out = had ? current + delta : delta;

    // inf plus -inf is NaN, and a NaN score is in every range and in none: it
    // compares false against both bounds, so `zrangebyscore k 0 1` answered with
    // a member whose score was NaN.  Refused BEFORE anything is written, which
    // is what leaves the set as it was -- incrbyfloat one screen up refuses the
    // same way and for the same reason.
    //
    // It also broke the check below, which is how this surfaced: NaN == NaN is
    // false, so the store reported a failure for a write it had just made and
    // the door turned that into a type conflict.
    //
    // An INFINITE score is fine and stays allowed: a zset may hold one, and
    // Redis refuses only the NaN here.
    if (std::isnan(out))
        return zincr_result::not_a_number;

    if (had)
    {
        if (out != current)
            rescore(it->second, member, current, out);
        touch_lru(key);
        return zincr_result::ok;
    }

    // A new member: zadd carries the type check and the memory refusal, and
    // either is the one answer this door has for a write that did not happen.
    return zadd(key, out, member) == 1 ? zincr_result::ok : zincr_result::type_conflict;
}

size_t cache_store::entry_cost(std::string_view key, const hash_inner& fields)
{
    size_t bytes = stored_string(key) + shape_cost(fields);
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
    if (__builtin_expect(!m_streams.empty() && m_streams.count(key), 0)) return true;
    return false;
}

bool cache_store::has_type_conflict_for_list(std::string_view key) const
{
    if (!m_data.empty() && m_data.count(key)) return true;
    if (!m_sets.empty() && m_sets.count(key)) return true;
    if (!m_hashes.empty() && m_hashes.count(key)) return true;
    if (!m_zsets.empty() && m_zsets.count(key)) return true;
    if (!m_streams.empty() && m_streams.count(key)) return true;
    return false;
}

bool cache_store::has_type_conflict_for_set(std::string_view key) const
{
    if (!m_data.empty() && m_data.count(key)) return true;
    if (!m_lists.empty() && m_lists.count(key)) return true;
    if (!m_hashes.empty() && m_hashes.count(key)) return true;
    if (!m_zsets.empty() && m_zsets.count(key)) return true;
    if (!m_streams.empty() && m_streams.count(key)) return true;
    return false;
}

bool cache_store::has_type_conflict_for_hash(std::string_view key) const
{
    if (!m_data.empty() && m_data.count(key)) return true;
    if (!m_lists.empty() && m_lists.count(key)) return true;
    if (!m_sets.empty() && m_sets.count(key)) return true;
    if (!m_zsets.empty() && m_zsets.count(key)) return true;
    if (!m_streams.empty() && m_streams.count(key)) return true;
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
    if (!m_streams.empty() && m_streams.count(key)) return true;
    return false;
}

bool cache_store::has_type_conflict_for_stream(std::string_view key) const
{
    return holds_other_type(key, 'x');
}

// ─── Streams ────────────────────────────────────────────────────────────────

const stream_inner* cache_store::stream_get(std::string_view key) const
{
    auto it = m_streams.find(key);
    if (it == m_streams.end())
        return nullptr;
    const_cast<cache_store*>(this)->touch_lru(key);
    return &it->second;
}

stream_inner* cache_store::stream_find(std::string_view key)
{
    auto it = m_streams.find(key);
    return it == m_streams.end() ? nullptr : &it->second;
}

stream_inner* cache_store::stream_make(std::string_view key, size_t growth)
{
    if (has_type_conflict_for_stream(key))
        return nullptr;
    if (!check_memory(new_key_cost(key.size()) + stream_entry_extra + growth, key))
        return nullptr;
    auto it = m_streams.emplace(std::string(key), stream_inner{}).first;
    track_add(entry_cost(it->first, it->second));
    touch_lru(key);
    return &it->second;
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
    return push(key, val, true);
}

bool cache_store::rpush(std::string_view key, std::string_view val)
{
    return push(key, val, false);
}

bool cache_store::push(std::string_view key, std::string_view val, bool front)
{
    // A key past its deadline but not yet swept would take the element and lose it with the sweep.
    check_expiry(key);
    auto it = m_lists.find(key);
    if (it != m_lists.end())
    {
        // The key is named to check_memory() so eviction cannot take it,
        // because `it` has to survive the call and the emplace below went
        // through a freed node.
        if (!check_memory(stored_string(val.size()) + list_elem_overhead
                          + push_growth(&it->second, val.size(), front), key))
            return false;
        const size_t shape = shape_cost(it->second);
        if (front) it->second.push_front(val); else it->second.push_back(val);
        ++m_list_elems;
        track_add(stored_string(val.size()));
        reshape(shape, shape_cost(it->second));
        touch_lru(key);
        return true;
    }

    if (has_type_conflict_for_list(key))
        return false;

    if (!check_memory(stored_string(val.size()) + new_key_cost(key.size()) + list_elem_overhead
                      + push_growth(nullptr, val.size(), front), key))
        return false;

    auto nit = m_lists.emplace(std::string(key), list_inner{}).first;
    if (front) nit->second.push_front(val); else nit->second.push_back(val);
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

    // Charged by length, as the push was: an element may be bytes in a packed
    // buffer and have no capacity of its own.
    const size_t shape = shape_cost(it->second);
    it->second.pop_front(out);
    after_pop(it, key, stored_string(out.size()), shape);
    return true;
}

bool cache_store::rpop(std::string_view key, std::string& out)
{
    auto it = m_lists.find(key);
    if (it == m_lists.end() || it->second.empty())
        return false;

    const size_t shape = shape_cost(it->second);
    it->second.pop_back(out);
    after_pop(it, key, stored_string(out.size()), shape);
    return true;
}

void cache_store::after_pop(list_map::iterator it, std::string_view key, size_t elem_cost,
                            size_t shape_before)
{
    --m_list_elems;
    track_sub(elem_cost);
    reshape(shape_before, shape_cost(it->second));

    // An empty list is not a key.
    if (it->second.empty())
    {
        track_sub(entry_cost(it->first, it->second));
        m_list_elems -= it->second.size();
        m_lists.erase(it);
        m_expiry.erase(std::string(key));
        drop_lru(key);
    }
}

int cache_store::llen(std::string_view key) const
{
    auto it = m_lists.find(key);
    if (it == m_lists.end())
        return 0;
    return static_cast<int>(it->second.size());
}

const list_inner* cache_store::list_ptr(std::string_view key) const
{
    auto it = m_lists.find(key);
    if (it == m_lists.end())
        return nullptr;
    return &it->second;
}

std::optional<std::string_view> cache_store::lindex(std::string_view key, int idx) const
{
    auto it = m_lists.find(key);
    if (it == m_lists.end())
        return std::nullopt;

    const auto& deq = it->second;
    int len = static_cast<int>(deq.size());

    if (idx < 0)
        idx += len;
    if (idx < 0 || idx >= len)
        return std::nullopt;

    return deq.at(static_cast<size_t>(idx));
}

// ─── Sets ───

int cache_store::sadd(std::string_view key, std::string_view member)
{
    check_expiry(key);
    auto it = m_sets.find(key);
    if (it != m_sets.end())
    {
        // Named for the same reason as in lpush(): `it` must survive the call.
        if (!check_memory(stored_string(member.size()) + set_elem_overhead
                          + set_growth(&it->second), key))
            return -1;
        const size_t shape = shape_cost(it->second);
        auto [mit, inserted] = it->second.emplace(member);
        if (inserted)
        {
            ++m_set_elems;
            track_add(stored_string(*mit));
            reshape(shape, shape_cost(it->second));
            touch_lru(key);
        }
        return inserted ? 1 : 0;
    }

    if (has_type_conflict_for_set(key))
        return -1;

    if (!check_memory(stored_string(member.size()) + new_key_cost(key.size()) + set_elem_overhead
                      + set_growth(nullptr), key))
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

    const size_t shape = shape_cost(it->second);
    track_sub(stored_string(*mit));
    it->second.erase(mit);
    --m_set_elems;
    reshape(shape, shape_cost(it->second));

    if (it->second.empty())
    {
        track_sub(entry_cost(it->first, it->second));
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

// ─── Set algebra ───

// Shared shape: every key must be a set or absent, and a key that is neither
// stops the whole command.  Checked BEFORE any work, so a WRONGTYPE never
// arrives after a partial answer.
int cache_store::sinter(const std::string_view* keys, size_t n,
                        std::vector<std::string>& out) const
{
    if (n == 0) return 0;
    // Every key's type first, as Redis does: an absent set ahead of a string still answers WRONGTYPE.
    for (size_t i = 0; i < n; ++i)
        if (holds_other_type(keys[i], 't')) return -1;
    std::vector<const set_inner*> sets;
    sets.reserve(n);
    for (size_t i = 0; i < n; ++i)
    {
        const set_inner* sp = set_ptr(keys[i]);
        if (!sp || sp->empty()) return 0;      // one empty set empties the lot
        sets.push_back(sp);
    }
    // Walk the smallest, probe the rest: the cost is then the smallest set
    // times the number of sets, not the first one named.
    size_t smallest = 0;
    for (size_t i = 1; i < sets.size(); ++i)
        if (sets[i]->size() < sets[smallest]->size()) smallest = i;
    for (const auto& m : *sets[smallest])
    {
        bool in_all = true;
        for (size_t i = 0; i < sets.size() && in_all; ++i)
            if (i != smallest && sets[i]->find(m) == sets[i]->end()) in_all = false;
        if (in_all) out.emplace_back(m);
    }
    return 0;
}

int cache_store::sunion(const std::string_view* keys, size_t n,
                        std::vector<std::string>& out) const
{
    set_inner seen;
    for (size_t i = 0; i < n; ++i)
    {
        if (holds_other_type(keys[i], 't')) return -1;
        const set_inner* sp = set_ptr(keys[i]);
        if (!sp) continue;
        for (const auto& m : *sp)
            if (seen.insert(m).second) out.emplace_back(m);
    }
    return 0;
}

int cache_store::sdiff(const std::string_view* keys, size_t n,
                       std::vector<std::string>& out) const
{
    if (n == 0) return 0;
    for (size_t i = 0; i < n; ++i)
        if (holds_other_type(keys[i], 't')) return -1;
    const set_inner* first = set_ptr(keys[0]);
    if (!first) return 0;
    for (const auto& m : *first)
    {
        bool elsewhere = false;
        for (size_t i = 1; i < n && !elsewhere; ++i)
        {
            const set_inner* sp = set_ptr(keys[i]);
            if (sp && sp->find(m) != sp->end()) elsewhere = true;
        }
        if (!elsewhere) out.emplace_back(m);
    }
    return 0;
}

size_t cache_store::sreplace(std::string_view dest, std::vector<std::string>&& members)
{
    if (members.empty())
    {
        del(dest);
        return 0;                       // an empty result leaves no key behind
    }
    set_inner s;
    s.reserve(members.size());
    for (auto& m : members) s.insert(std::move(m));
    const size_t n = s.size();
    // Admitted before the destination goes, as COPY is: the result is a new
    // copy of its members, so a union of two large sets doubles them, and
    // Redis refuses the STORE forms with -OOM.
    if (m_max_memory != 0)
    {
        const size_t need  = new_key_cost(dest.size()) + entry_cost(dest, s) + n * set_elem_overhead;
        const bool   taken = exists(dest);
        const size_t freed = taken ? key_cost(dest) : 0;   // what replacing dest gives back
        if (need > freed && !check_memory(need - freed, dest))
            return sreplace_refused;
        // Eviction may have taken the destination, whose room was then counted twice.
        if (taken && !exists(dest) && !check_memory(need, dest))
            return sreplace_refused;
    }
    // Gone first, so a destination that was a string or a list stops being one
    // -- Redis replaces the key outright and does not answer WRONGTYPE here.
    del(dest);
    auto it = m_sets.emplace(std::string(dest), std::move(s)).first;
    m_set_elems += n;
    track_add(entry_cost(it->first, it->second));
    touch_lru(dest);
    return n;
}

int cache_store::smove(std::string_view src, std::string_view dst,
                       std::string_view member)
{
    if (holds_other_type(src, 't') || holds_other_type(dst, 't')) return -1;
    auto it = m_sets.find(src);
    if (it == m_sets.end()) return 0;
    if (it->second.find(member) == it->second.end()) return 0;
    if (src == dst) return 1;     // Redis's no-op, where the removal below took it out
    // Taken from the source only once the destination has it, so a failure
    // between the two cannot lose the member.
    const pin_source keep(*this, src);
    if (sadd(dst, member) < 0) return 0;
    srem(src, member);
    return 1;
}

// ─── Whole-key operations ───

// Written once as a template because doing it five times by hand is five
// chances to forget one container -- which has already happened twice in this
// file, to dump_commands and to holds_other_type.
template <typename Map>
bool cache_store::move_one(Map& m, size_t* elems, std::string_view src, std::string_view dst,
                           bool keep)
{
    auto it = m.find(src);
    if (it == m.end())
        return false;
    if (keep)
    {
        auto copy = it->second;                 // before the insert can rehash
        auto nit = m.insert_or_assign(std::string(dst), std::move(copy)).first;
        if (elems) *elems += nit->second.size();
        track_add(entry_cost(nit->first, nit->second));
    }
    else
    {
        // The value moves whole, its blocks and capacities with it, so only
        // the name's cost changes and a rename stays O(1).
        track_sub(stored_string(it->first));
        auto held = std::move(it->second);
        m.erase(it);
        m.insert_or_assign(std::string(dst), std::move(held));
        track_add(stored_string(dst));
    }
    touch_lru(dst);
    return true;
}

size_t cache_store::value_cost(std::string_view key) const
{
    const auto value = [&](const auto& it, size_t elem_overhead) {
        return entry_cost(it->first, it->second) - stored_string(it->first)
             + it->second.size() * elem_overhead;
    };
    if (auto it = m_data.find(key);   it != m_data.end())   return value(it, 0);
    if (auto it = m_lists.find(key);  it != m_lists.end())  return value(it, list_elem_overhead);
    if (auto it = m_sets.find(key);   it != m_sets.end())   return value(it, set_elem_overhead);
    if (auto it = m_hashes.find(key); it != m_hashes.end()) return value(it, hash_field_overhead);
    if (auto it = m_zsets.find(key);  it != m_zsets.end())  return value(it, zset_member_overhead);
    if (auto it = m_streams.find(key); it != m_streams.end()) return value(it, 0);
    return 0;
}

size_t cache_store::key_cost(std::string_view key) const
{
    return stored_string(key) + key_entry_overhead + value_cost(key)
         + (m_lru_map.count(key) ? lru_entry_overhead + lru_key_copies(key.size()) : 0)
         + (m_expiry.count(key) ? expiry_entry_overhead : 0);
}

int cache_store::rename_key(std::string_view src, std::string_view dst, bool nx)
{
    if (!exists(src))
        return -2;
    if (src == dst)
        return nx ? 0 : 1;      // Redis answers OK and changes nothing
    if (nx && exists(dst))
        return 0;

    // The destination goes first whatever it held: RENAME replaces it outright
    // and does not answer WRONGTYPE for a destination of another type.
    del(dst);

    int64_t deadline_ms = -1;
    if (auto e = m_expiry.find(src); e != m_expiry.end())
    {
        deadline_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          e->second.time_since_epoch()).count();
        m_expiry.erase(e);
    }
    drop_lru(src);

    // Not refused for room, since RENAME has no answer for it: what grows is
    // the name, and it is charged.
    if (!move_one(m_data,   nullptr,         src, dst, false)
     && !move_one(m_lists,  &m_list_elems,   src, dst, false)
     && !move_one(m_sets,   &m_set_elems,    src, dst, false)
     && !move_one(m_hashes, &m_hash_fields,  src, dst, false)
     && !move_one(m_zsets,  &m_zset_members, src, dst, false)
     && !move_one(m_streams, nullptr,        src, dst, false))
        return -2;

    // The deadline travels with the key, which is what Redis does: renaming is
    // not a way to make an expiring key permanent.
    if (deadline_ms >= 0)
        m_expiry.insert_or_assign(std::string(dst),
            std::chrono::steady_clock::time_point(std::chrono::milliseconds(deadline_ms)));
    return 1;
}

int cache_store::copy_key(std::string_view src, std::string_view dst, bool replace)
{
    if (!exists(src))
        return -2;
    if (src == dst)
        return 0;
    const bool taken = exists(dst);
    if (taken && !replace)
        return 0;
    // Refused for room before REPLACE deletes anything, answered apart from a
    // destination in the way because Redis refuses COPY with -OOM.
    if (m_max_memory != 0)
    {
        const size_t need  = new_key_cost(dst.size()) + value_cost(src)
                           + (m_expiry.count(src) ? expiry_entry_overhead : 0);
        const size_t freed = taken ? key_cost(dst) : 0;   // what REPLACE gives back
        if (need > freed && !check_memory(need - freed, src))
            return -3;
        // Eviction may have taken the destination, whose room was then counted twice.
        if (taken && !exists(dst) && !check_memory(need, src))
            return -3;
    }
    if (taken)
        del(dst);
    if (!move_one(m_data,   nullptr,         src, dst, true)
     && !move_one(m_lists,  &m_list_elems,   src, dst, true)
     && !move_one(m_sets,   &m_set_elems,    src, dst, true)
     && !move_one(m_hashes, &m_hash_fields,  src, dst, true)
     && !move_one(m_zsets,  &m_zset_members, src, dst, true)
     && !move_one(m_streams, nullptr,        src, dst, true))
        return -2;
    // The deadline is copied too.  This first read "COPY copies the value, not
    // the deadline", which sounded right and is not what redis-server does --
    // the comparison in the test caught it: the copy came back with TTL -1
    // there and 500 in Redis.  A copy that outlives its original is a key that
    // never goes away.
    if (auto e = m_expiry.find(src); e != m_expiry.end())
        m_expiry.insert_or_assign(std::string(dst), e->second);
    return 1;
}

std::string_view cache_store::random_key() const
{
    if (!m_data.empty())   return m_data.begin()->first;
    if (!m_lists.empty())  return m_lists.begin()->first;
    if (!m_sets.empty())   return m_sets.begin()->first;
    if (!m_hashes.empty()) return m_hashes.begin()->first;
    if (!m_zsets.empty())  return m_zsets.begin()->first;
    if (!m_streams.empty()) return m_streams.begin()->first;
    return {};
}

int64_t cache_store::expire_time(std::string_view key, bool millis) const
{
    if (!exists(key))
        return -2;
    auto e = m_expiry.find(key);
    if (e == m_expiry.end())
        return -1;
    // m_expiry holds a steady_clock point, which has no epoch a client could
    // use, so it is turned back into wall time through the offset between the
    // two clocks measured now.
    const auto now_steady = std::chrono::steady_clock::now();
    const auto now_wall   = std::chrono::system_clock::now();
    // Narrowed to milliseconds BEFORE the two clocks are added: a saturated
    // deadline is most of int64 in NANOseconds, and adding the wall clock's
    // own nanoseconds to it left int64 and answered a date in 1734.  The
    // narrowing is what fixes that; the guard behind it is about the clock's
    // period, which this file reads rather than assumes -- on a coarser
    // steady_clock the milliseconds would be most of int64 again.
    const auto delta_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                              e->second - now_steady).count();
    const auto now_ms   = std::chrono::duration_cast<std::chrono::milliseconds>(
                              now_wall.time_since_epoch()).count();
    int64_t ms = 0;
    if (__builtin_expect(__builtin_add_overflow(now_ms, delta_ms, &ms), 0))
        ms = std::numeric_limits<int64_t>::max();
    return millis ? ms : ms / 1000;
}

// ─── Hashes ───

bool cache_store::hset(std::string_view key, std::string_view field, std::string_view val,
                       bool* created)
{
    if (created) *created = false;
    check_expiry(key);
    auto it = m_hashes.find(key);
    if (it != m_hashes.end())
    {
        const size_t shape = shape_cost(it->second);
        std::string_view old;
        if (it->second.get(field, old))
        {
            // Overwriting a field has to clear the same bar as adding one,
            // which this path did not, so a 5-byte value could become 100 KB
            // against a configured 1200.
            if (__builtin_expect(m_max_memory != 0, 0))
            {
                const size_t held = stored_string(old.size()) + shape;
                const size_t want = stored_string(val.size()) + shape
                                  + field_growth(&it->second, field, val.size(), &old);
                if (want > held && !check_memory(want - held, key))
                    return false;
            }
            track_sub(stored_string(old.size()));
            it->second.set(field, val);
            track_add(stored_string(val.size()));
        }
        else
        {
            // Named so that eviction cannot take this hash, because `it` is
            // held across the call and the set below writes through it.
            if (!check_memory(stored_string(field.size()) + stored_string(val.size()) + hash_field_overhead
                              + field_growth(&it->second, field, val.size(), nullptr), key))
                return false;
            it->second.set(field, val);
            ++m_hash_fields;
            if (created) *created = true;
            track_add(stored_string(field.size()) + stored_string(val.size()));
        }
        reshape(shape, shape_cost(it->second));
        touch_lru(key);
        return true;
    }

    if (has_type_conflict_for_hash(key))
        return false;

    if (!check_memory(stored_string(field.size()) + stored_string(val.size())
                      + new_key_cost(key.size()) + hash_field_overhead
                      + field_growth(nullptr, field, val.size(), nullptr), key))
        return false;

    auto nit = m_hashes.emplace(std::string(key), hash_inner{}).first;
    nit->second.set(field, val);
    ++m_hash_fields;
    if (created) *created = true;
    track_add(entry_cost(nit->first, nit->second));
    touch_lru(key);
    return true;
}

std::optional<std::string_view> cache_store::hget(std::string_view key, std::string_view field) const
{
    auto it = m_hashes.find(key);
    std::string_view out;
    if (it == m_hashes.end() || !it->second.get(field, out))
        return std::nullopt;
    return out;
}

bool cache_store::hdel(std::string_view key, std::string_view field)
{
    auto it = m_hashes.find(key);
    if (it == m_hashes.end())
        return false;

    std::string_view old;
    if (!it->second.get(field, old))
        return false;

    const size_t shape = shape_cost(it->second);
    track_sub(stored_string(field.size()) + stored_string(old.size()));
    it->second.erase(field);
    --m_hash_fields;
    reshape(shape, shape_cost(it->second));

    if (it->second.empty())
    {
        track_sub(entry_cost(it->first, it->second));
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

// The deadline an absurd TTL means is "never" or "long gone", not a signed
// overflow -- the same saturation journal_mutation's deadline_of already does,
// moved to where the two interpreters actually arrive.  This clock counts
// nanoseconds, so `seconds(n)` multiplies by a billion: every TTL past ~9.2e9 s
// (or ~9.2e12 ms) wrapped the deadline into the PAST, and the key a client had
// just asked to keep longest was deleted on the spot.
static std::chrono::steady_clock::time_point saturating_deadline(int64_t n, int64_t ticks_per_unit)
{
    using clock = std::chrono::steady_clock;
    int64_t ticks = 0;
    int64_t at    = 0;
    const int64_t now = clock::now().time_since_epoch().count();
    if (__builtin_expect(__builtin_mul_overflow(n, ticks_per_unit, &ticks) ||
                         __builtin_add_overflow(now, ticks, &at), 0))
    {
        // "Never" is the clock's own far end, but "long gone" is one tick ago
        // rather than time_point::min(): the readers subtract this point from
        // now(), and min() would only move the overflow into get_pttl() and
        // expire_time().
        return n > 0 ? clock::time_point::max()
                     : clock::time_point(clock::duration(now)) - clock::duration(1);
    }
    return clock::time_point(clock::duration(at));
}

// Ticks of this clock in one second, read off the clock rather than assumed.
static_assert(std::chrono::steady_clock::duration::period::num == 1,
              "saturating_deadline computes ticks per second as the period's denominator");
static constexpr int64_t ticks_per_second = std::chrono::steady_clock::duration::period::den;
static constexpr int64_t ticks_per_milli  = ticks_per_second / 1000;

bool cache_store::set_expiry(std::string_view key, int64_t seconds)
{
    if (!exists(key))
        return false;

    auto tp = saturating_deadline(seconds, ticks_per_second);
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
            expired.emplace_back(key);
    }
    for (const auto& key : expired)
        del(key);
    return expired;
}

bool cache_store::set_expiry_ms(std::string_view key, int64_t ms)
{
    if (!exists(key))
        return false;

    auto tp = saturating_deadline(ms, ticks_per_milli);
    auto it = m_expiry.find(key);
    if (it != m_expiry.end())
        it->second = tp;
    else
        m_expiry.emplace(std::string(key), tp);
    return true;
}

cache_store::expire_result cache_store::expire_in(std::string_view key, int64_t n, bool millis)
{
    // An expired key does not exist, so it cannot be given a new deadline --
    // without this, EXPIRE on a key past its deadline but not yet swept
    // overwrote the deadline and brought the key back.
    check_expiry(key);
    if (!exists(key))
        return expire_result::no_such_key;

    // Redis deletes rather than refusing, and it is the same command either
    // way: `EXPIRE k 0` and `EXPIREAT k <yesterday>` differ only in who did
    // the subtraction.  del() takes the deadline with the value, which is what
    // keeps m_expiry from holding a name nothing answers to.
    if (n <= 0)
    {
        del(key);
        return expire_result::deleted;
    }

    if (millis) set_expiry_ms(key, n);
    else        set_expiry(key, n);
    return expire_result::armed;
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

// TTL asked check_expiry() and then get_ttl(), which probed the expiry map
// twice and the keyspace once and read the clock twice, on the one command a
// client polls.
int64_t cache_store::expire_then_pttl(std::string_view key)
{
    if (!m_expiry.empty())
    {
        auto it = m_expiry.find(key);
        if (it != m_expiry.end())
        {
            const auto now = std::chrono::steady_clock::now();
            if (now >= it->second)
            {
                m_expiry.erase(it);
                drop_lru(key);
                drop_value(key);
                return -2;
            }
            if (!exists(key))
                return -2;
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                it->second - now).count();
        }
    }
    return exists(key) ? -1 : -2;
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
// The cursor layout, in one place, because scan() and scan_values() hand each
// other cursors and two copies of a bit layout is two chances to disagree.
static inline uint64_t scan_cursor_pack(uint8_t map, size_t buckets, size_t bucket)
{
    return (static_cast<uint64_t>(map & 0x7u) << 55)
         | ((static_cast<uint64_t>(buckets) & 0x7FFFFF) << 32)
         | (static_cast<uint64_t>(bucket) & 0xFFFFFFFFu);
}

// One page of the string map, filtered on the VALUE a key holds.
//
// Only this map, because the other four hold no single value to match against:
// a list, set, hash or zset key can never satisfy a value predicate, so walking
// them is time spent to return nothing.
//
// And the page ends on keys EXAMINED where scan() ends on keys returned, which
// is the contract that matters here.  scan() can afford its rule because MATCH
// is usually broad; a value predicate is selective by construction, so under
// scan()'s rule one call would walk the whole map -- measured at 74 ms over
// 632,331 keys, and that is 74 ms with this shard answering nobody.
// A stored value read as a number, with the whole of it consumed.  "30" is
// thirty and "30kg" is not a number at all: from_chars would happily stop after
// the digits, and a range that matched "30kg" would be answering a question
// nobody asked.
static bool value_in_range(std::string_view sv,
                           const cache_store::scan_filter::value_range& r)
{
    if (sv.empty()) return false;
    double v = 0;
    const auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), v);
    if (ec != std::errc{} || ptr != sv.data() + sv.size())
        return false;
    // from_chars reads "nan" as a number too, and NaN is false against every
    // comparison below -- so without this a value of "nan" falls inside every
    // range, including ones it is nowhere near.  Measured: `valuerange 100 200`
    // answered with it, and so did a FIELD query on an age of "nan".
    if (std::isnan(v))
        return false;
    if (r.lo_inclusive ? (v < r.lo) : (v <= r.lo)) return false;
    if (r.hi_inclusive ? (v > r.hi) : (v >= r.hi)) return false;
    return true;
}

// One page of a bucket-walked map, which is the shape all three scans have.
//
// `visit` is handed each entry; `page_full` is asked after each whole bucket and
// says whether this page has done enough.  What "enough" means is the caller's,
// and the two answers are not interchangeable: the plain walk ends on entries
// RETURNED, which is right while the pattern is broad, and the filtered walks end
// on entries EXAMINED, because a selective predicate under the other rule walks
// the whole map in one call -- 74 ms over 632,331 keys with the shard answering
// nobody.  Written once here because it had been written three times.
// What a cursor records of the table it walked, so a table whose entries have
// moved since is walked again; a key_table can move them and keep its size.
template <class Map>
static size_t scan_shape(const Map& map)
{
    if constexpr (requires { map.scan_epoch(); })
        return map.bucket_count() ^ (static_cast<size_t>(map.scan_epoch()) * 0x9E3779B1u);
    else
        return map.bucket_count();
}

template <class Map, class Visit, class Full>
static uint64_t walk_buckets(const Map& map, uint8_t map_index, size_t first_bucket,
                             Visit visit, Full page_full)
{
    const size_t nbuckets = map.bucket_count();
    size_t examined = 0;
    for (size_t b = first_bucket; b < nbuckets; ++b)
    {
        for (auto it = map.begin(b); it != map.end(b); ++it)
        {
            ++examined;
            visit(*it);
        }
        // Whole buckets and never half of one: a page boundary inside a bucket
        // would need an element index the cursor has no room for.
        if (page_full(examined) && b + 1 < nbuckets)
            return scan_cursor_pack(map_index, scan_shape(map), b + 1);
    }
    return 0;
}

// Where a walk of one map resumes, given a cursor that may name another map or a
// table that has been rehashed since.  Both answers are "start again": repeating
// keys is allowed by the contract and skipping them is not.
static size_t resume_bucket(uint64_t cursor, uint8_t want_map, size_t shape)
{
    if (cursor == 0) return 0;
    const uint8_t  in_map     = static_cast<uint8_t>((cursor >> 55) & 0x7u);
    const uint32_t in_buckets = static_cast<uint32_t>((cursor >> 32) & 0x7FFFFFu);
    const uint64_t in_bucket  = cursor & 0xFFFFFFFFu;
    if (in_map != want_map) return 0;
    return (in_buckets == (shape & 0x7FFFFF)) ? static_cast<size_t>(in_bucket) : 0;
}

// Whether one value satisfies one predicate's value tests.  The field is not
// looked at here: which value this is was decided by the caller, which is the
// only part the two walks disagree about.
static bool value_satisfies(std::string_view v,
                            const cache_store::scan_filter::predicate& p)
{
    if (p.value && *p.value != "*" && !socketley::glob_match(*p.value, v))
        return false;
    if (p.range && !value_in_range(v, *p.range))
        return false;
    return true;
}

// One page of the hash map, filtered on what named fields of each hash hold.
//
// This is the database question -- "which records have city = berlin" -- for the
// layout most records are actually stored in.  Answered from outside it is an
// HGET per hash key; answered here it is one probe of that hash's own field map,
// where the walk already is, and no round trip at all.
//
// The page is bounded by keys examined rather than keys returned, for the reason
// scan_values() gives: the predicate is selective by construction.
uint64_t cache_store::scan_hash_field(uint64_t cursor, std::string_view pattern,
                                      size_t count, std::vector<std::string_view>& out,
                                      const scan_filter& filter) const
{
    const bool match_all_keys = (pattern == "*");

    // Map three is the hash map; a cursor naming another one carries a bucket
    // index belonging to a different table.
    return walk_buckets(m_hashes, 3, resume_bucket(cursor, 3, scan_shape(m_hashes)),
        [&](const auto& e) {
            if (!match_all_keys && !socketley::glob_match(pattern, e.first))
                return;
            // EVERY predicate, which is what makes two of them a conjunction and
            // not a choice.  The first that fails ends it.
            std::string_view shown;
            for (size_t i = 0; i < filter.pred_count; i++)
            {
                const auto& p = filter.preds[i];
                // A hash without the field is not a hash whose field is empty,
                // so it does not match even a predicate that matches everything.
                std::string_view fv;
                if (!e.second.get(p.field ? *p.field : std::string_view{}, fv))
                    return;
                if (!value_satisfies(fv, p))
                    return;
                if (i == 0) shown = fv;
            }
            out.push_back(e.first);
            // The FIRST predicate's field, because that is the one the caller
            // named first and a reply cannot carry four values per key.
            if (filter.with_values)
                out.push_back(shown);
        },
        [&](size_t examined) { return examined >= count; });
}

uint64_t cache_store::scan_values(uint64_t cursor, std::string_view pattern,
                                  size_t count, std::vector<std::string_view>& out,
                                  const scan_filter& filter) const
{
    const bool match_all_keys = (pattern == "*");

    // A cursor naming another map came from a walk that was not this one -- an
    // iteration that changed its options midway -- and its bucket index means
    // nothing here.
    return walk_buckets(m_data, 0, resume_bucket(cursor, 0, scan_shape(m_data)),
        [&](const auto& e) {
            if (!match_all_keys && !socketley::glob_match(pattern, e.first))
                return;
            // A key has one value of its own, so more than one predicate on it
            // is more than one test of the same string.
            for (size_t i = 0; i < filter.pred_count; i++)
                if (!value_satisfies(e.second, filter.preds[i]))
                    return;
            out.push_back(e.first);
            if (filter.with_values)
                out.push_back(e.second);
        },
        [&](size_t examined) { return examined >= count; });
}

uint64_t cache_store::scan(uint64_t cursor, std::string_view pattern,
                            size_t count, std::vector<std::string_view>& out,
                            const scan_filter& filter) const
{
    // A field names the hash map, and a predicate or WITHVALUES without one
    // names the string map.  Either way a type filter that agrees adds nothing,
    // and one that disagrees was answered empty by the caller before it got here.
    if (filter.wants_hashes())
        return scan_hash_field(cursor, pattern, count, out, filter);
    if (filter.any_predicate() || filter.with_values)
        return scan_values(cursor, pattern, count, out, filter);

    // Not `pattern.empty() ||`: MATCH "" asks for the key that has no name,
    // and answering it with the whole keyspace is the opposite of the request.
    // Callers spell an absent MATCH as "*".
    bool match_all = (pattern == "*");
    auto match = [&](std::string_view k) -> bool {
        if (match_all) return true;
        return socketley::glob_match(pattern, k);
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

    auto pack = scan_cursor_pack;

    // One map from `first_bucket` on, returning the cursor to resume with or 0
    // when this map is exhausted.
    // Ends on keys RETURNED and across the five maps together: `out` is what the
    // whole page has so far, not what this one map contributed.
    // A key past its deadline is gone to every reader, the sweep only not having reached it yet.
    const bool any_ttl = !m_expiry.empty();
    const auto now = any_ttl ? std::chrono::steady_clock::now() : std::chrono::steady_clock::time_point{};
    auto live = [&](std::string_view k) -> bool {
        if (!any_ttl) return true;
        const auto e = m_expiry.find(k);
        return e == m_expiry.end() || now < e->second;
    };
    auto walk = [&](const auto& map, uint8_t idx, size_t first_bucket) -> uint64_t {
        return walk_buckets(map, idx, first_bucket,
            [&](const auto& e) { if (match(e.first) && live(e.first)) out.push_back(e.first); },
            [&](size_t) { return out.size() >= count; });
    };

    // The five in a fixed order, so a cursor names the same map on every call --
    // or exactly one of them when a type was asked for, because the type of a
    // key is the map it is in.
    const int type_map = filter.type_map;
    const uint8_t first_map = (type_map >= 0) ? static_cast<uint8_t>(type_map) : in_map;
    const uint8_t last_map  = (type_map >= 0) ? static_cast<uint8_t>(type_map) : scan_last_map;

    // A cursor already past the single map this walk may visit has nothing left
    // to do.  Without this the walk below would start that map again from the
    // top, which repeats keys -- allowed, but pointlessly.
    if (type_map >= 0 && in_map > static_cast<uint8_t>(type_map))
        return 0;

    for (uint8_t idx = first_map; idx <= last_map; ++idx)
    {
        size_t start = 0;
        if (idx == in_map && cursor != 0)
        {
            // A rehash between calls invalidates the bucket index, so this map
            // restarts -- the answer that cannot skip, and may repeat, which
            // the contract allows.
            const size_t now = (idx == 0 ? scan_shape(m_data)
                              : idx == 1 ? scan_shape(m_lists)
                              : idx == 2 ? scan_shape(m_sets)
                              : idx == 3 ? scan_shape(m_hashes)
                              : idx == 4 ? scan_shape(m_zsets)
                                         : scan_shape(m_streams));
            start = (in_buckets == (now & 0x7FFFFF)) ? in_bucket : 0;
        }

        uint64_t next = 0;
        switch (idx)
        {
            case 0:  next = walk(m_data,   0, start); break;
            case 1:  next = walk(m_lists,  1, start); break;
            case 2:  next = walk(m_sets,   2, start); break;
            case 3:  next = walk(m_hashes, 3, start); break;
            case 4:  next = walk(m_zsets,  4, start); break;
            default: next = walk(m_streams, 5, start); break;
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

cache_store::incr_result cache_store::incr(std::string_view key, int64_t delta, int64_t& result)
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
            return incr_result::not_an_integer;
    }
    else if (has_type_conflict_for_string(key))
        return incr_result::wrong_type;

    // Checked before the sum and not after it, because signed overflow is
    // undefined and there is no "after" to inspect: two INCRBY INT64_MAX in a
    // row answered -2, which is a counter a client believes.  incrbyfloat and
    // zincrby both refuse their own unrepresentable result already; this was
    // the arithmetic that did not.
    if (__builtin_expect(__builtin_add_overflow(val, delta, &val), 0))
        return incr_result::would_overflow;
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
            return incr_result::out_of_memory;
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
            return incr_result::out_of_memory;
        auto nit = m_data.emplace(std::string(key), std::string(sv)).first;
        track_add(entry_cost(nit->first, nit->second));
    }
    touch_lru(key);
    return incr_result::ok;
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

    // The offset is a client's number and this is the only place a result
    // length is computed from one.  Both writes below -- the construction and
    // the resize -- raise std::length_error above max_size(), nothing between
    // here and main() catches it, and the worker died: one command, no
    // password (this cache has no such mechanism), every connection on that
    // process gone with it.  `offset > need` is the wrap.
    //
    // max_size() was the wrong ceiling for the same sentence: it bounds what
    // the type can represent, so a length the type accepts and the machine
    // cannot raised std::bad_alloc instead of std::length_error and ended the
    // worker exactly as before.  Measured: `SETRANGE k 1000000000000000 x` on
    // an idle cache closed the connection and left the port refusing.
    if (__builtin_expect(offset > need || need > setrange_max_bytes, 0))
        return append_too_long;

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

    const std::string txt = cache_float_text(val);
    if (txt.empty())
        return false;
    return set(key, txt);
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

    const size_t old_len = dq.at(static_cast<size_t>(idx)).size();
    const size_t shape   = shape_cost(dq);
    if (__builtin_expect(m_max_memory != 0, 0))
    {
        const size_t held = stored_string(old_len) + shape;
        const size_t want = stored_string(val.size())
                          + std::max(shape, shape_cost(dq.after_set(static_cast<size_t>(idx), val.size())));
        if (want > held && !check_memory(want - held, key))
            return -3;
        it = m_lists.find(key);
        if (it == m_lists.end() || idx >= static_cast<int64_t>(it->second.size()))
            return -1;
    }
    track_sub(stored_string(old_len));
    it->second.set(static_cast<size_t>(idx), val);
    track_add(stored_string(val.size()));
    reshape(shape, shape_cost(it->second));
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
    // Negated unsigned, since -INT64_MIN has no signed value.
    const size_t want = (count == 0) ? dq.size()
                                     : static_cast<size_t>(count < 0 ? 0 - static_cast<uint64_t>(count)
                                                                     : static_cast<uint64_t>(count));
    const size_t shape = shape_cost(dq);
    // By position, since an erase in a packed list moves the bytes behind it
    // and an iterator carrying their offset would name the wrong element.
    if (count >= 0)
    {
        for (size_t i = 0; i < dq.size() && static_cast<size_t>(removed) < want; )
        {
            if (dq.at(i) == val) { track_sub(stored_string(val.size())); dq.erase(i); ++removed; --m_list_elems; }
            else ++i;
        }
    }
    else
    {
        for (size_t i = dq.size(); i > 0 && static_cast<size_t>(removed) < want; )
        {
            --i;
            if (dq.at(i) == val) { track_sub(stored_string(val.size())); dq.erase(i); ++removed; --m_list_elems; }
        }
    }
    reshape(shape, shape_cost(dq));

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
        // entry_cost() is the elements too, which were once taken off here first.
        m_list_elems -= dq.size();
        track_sub(entry_cost(it->first, it->second));
        m_lists.erase(it);
        m_expiry.erase(std::string(key));
        drop_lru(key);
        return true;
    }

    const size_t shape = shape_cost(dq);
    while (static_cast<int64_t>(dq.size()) > e + 1)
    { track_sub(stored_string(dq.back())); dq.pop_back(); --m_list_elems; }
    for (int64_t i = 0; i < s; ++i)
    { track_sub(stored_string(dq.front())); dq.pop_front(); --m_list_elems; }
    reshape(shape, shape_cost(dq));
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
    // The pivot first, so a list without it costs no other key its place, and room after.
    if (std::find(it->second.begin(), it->second.end(), pivot) == it->second.end())
        return -1;

    if (!check_memory(stored_string(val.size()) + list_elem_overhead
                      + push_growth(&it->second, val.size(), false), key))
        return linsert_refused;
    it = m_lists.find(key);
    if (it == m_lists.end())
        return 0;

    auto& dq = it->second;
    auto at = std::find(dq.begin(), dq.end(), pivot);
    if (at == dq.end())
        return -1;
    const size_t shape = shape_cost(dq);
    dq.insert(at.index() + (before ? 0 : 1), val);
    ++m_list_elems;
    track_add(stored_string(val.size()));
    reshape(shape, shape_cost(dq));
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
    const auto dfound = m_lists.find(dst);
    if (dfound == m_lists.end() && has_type_conflict_for_list(dst))
        return false;

    // Charged before the pop, for the same reason: a refusal after it would
    // have taken the element out of the queue and dropped it.
    const size_t head_len = (from_head ? sit->second.front() : sit->second.back()).size();
    const pin_source keep(*this, src);
    if (src != dst && !check_memory(stored_string(head_len) + new_key_cost(dst.size()) + list_elem_overhead
                                    + push_growth(dfound == m_lists.end() ? nullptr : &dfound->second,
                                                  head_len, to_head), dst))
        return false;
    sit = m_lists.find(src);
    if (sit == m_lists.end() || sit->second.empty())
        return false;

    const size_t shape = shape_cost(sit->second);
    if (from_head) sit->second.pop_front(out); else sit->second.pop_back(out);
    track_sub(stored_string(out.size()));
    --m_list_elems;
    reshape(shape, shape_cost(sit->second));

    // src == dst is a rotation, and the deque above is the one below: taken
    // before the source can be erased for being empty, which it is not.
    if (src == dst)
    {
        // Not refused for room, since the list holds no more than it did.
        const size_t turned = shape_cost(sit->second);
        if (to_head) sit->second.push_front(out); else sit->second.push_back(out);
        ++m_list_elems;
        track_add(stored_string(out.size()));
        reshape(turned, shape_cost(sit->second));
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
    {
        dit = m_lists.emplace(std::string(dst), list_inner{}).first;
        if (to_head) dit->second.push_front(out); else dit->second.push_back(out);
        ++m_list_elems;
        // The key's own bytes with it, which a new destination was never charged.
        track_add(entry_cost(dit->first, dit->second));
        touch_lru(dst);
        return true;
    }
    const size_t dshape = shape_cost(dit->second);
    if (to_head) dit->second.push_front(out); else dit->second.push_back(out);
    ++m_list_elems;
    track_add(stored_string(out.size()));
    reshape(dshape, shape_cost(dit->second));
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
    const size_t shape = shape_cost(it->second);
    track_sub(stored_string(*mit));
    it->second.erase(mit);
    --m_set_elems;
    reshape(shape, shape_cost(it->second));

    if (it->second.empty())
    {
        track_sub(entry_cost(it->first, it->second));
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
static inline std::string_view scan_key_of(std::string_view s) { return s; }
template <typename E>
static inline std::string_view scan_key_of(const E& e) { return e.first; }

// ─── One collection, scanned ───
//
// The keyspace SCAN packs a map index beside the bucket count because it walks
// five maps; over one key there is no index, so the whole 24 bits of bucket
// count and 32 of bucket index are this collection's.  The count rides along
// for the same reason it does there: a resume can tell whether the table it is
// going back into is the one it left, and a rehash restarts rather than
// silently skipping half the elements.
template <typename Map, typename Emit>
// `emit` answers whether it kept the entry, which is what lets a caller filter
// on something the pattern cannot see -- a hash field's VALUE, where the pattern
// matches its name.  A page then ends on entries EXAMINED rather than kept, for
// the reason walk_buckets() gives: a selective predicate under the other rule
// walks the whole collection in one call.
static uint64_t scan_one_collection(const Map& map, uint64_t cursor,
                                    std::string_view pattern, size_t count, Emit emit,
                                    bool bound_by_examined = false)
{
    const bool match_all = (pattern == "*");   // see scan(): "" is a pattern
    const auto match = [&](std::string_view k) {
        return match_all
            || socketley::glob_match(pattern, k);
    };

    const uint32_t was_buckets = static_cast<uint32_t>((cursor >> 32) & 0xFFFFFFu);
    size_t         bucket      = static_cast<size_t>(cursor & 0xFFFFFFFFu);
    const size_t   nbuckets    = map.bucket_count();
    const size_t   shape       = scan_shape(map);

    // A table that has been rehashed under the caller is one this cursor
    // cannot resume into, so it starts again rather than reporting a slice.
    if (was_buckets != 0 && was_buckets != (shape & 0xFFFFFFu))
        bucket = 0;

    size_t emitted = 0, examined = 0;
    for (size_t b = bucket; b < nbuckets; ++b)
    {
        for (auto it = map.begin(b); it != map.end(b); ++it)
        {
            ++examined;
            if (match(scan_key_of(*it)) && emit(*it)) ++emitted;
        }

        // Whole buckets only: half of one would need an element index the
        // cursor has no room for.
        if ((bound_by_examined ? examined : emitted) >= count && b + 1 < nbuckets)
            return ((static_cast<uint64_t>(shape) & 0xFFFFFFu) << 32)
                 | (static_cast<uint64_t>(b + 1) & 0xFFFFFFFFu);
    }
    return 0;
}

uint64_t cache_store::hscan(std::string_view key, uint64_t cursor,
                            std::string_view pattern, size_t count,
                            std::vector<std::pair<std::string_view, std::string_view>>& out,
                            const std::string_view* value_pattern) const
{
    auto it = m_hashes.find(key);
    if (it == m_hashes.end()) return 0;
    const bool match_all_vals = (!value_pattern || *value_pattern == "*");
    return scan_one_collection(it->second, cursor, pattern, count,
        [&](const auto& e) {
            if (!match_all_vals && !socketley::glob_match(*value_pattern, e.second))
                return false;
            out.emplace_back(std::string_view(e.first), std::string_view(e.second));
            return true;
        },
        /*bound_by_examined=*/value_pattern != nullptr);
}

uint64_t cache_store::sscan(std::string_view key, uint64_t cursor,
                            std::string_view pattern, size_t count,
                            std::vector<std::string_view>& out) const
{
    auto it = m_sets.find(key);
    if (it == m_sets.end()) return 0;
    return scan_one_collection(it->second, cursor, pattern, count,
        [&out](const auto& e) { out.emplace_back(std::string_view(e)); return true; });
}

uint64_t cache_store::zscan(std::string_view key, uint64_t cursor,
                            std::string_view pattern, size_t count,
                            std::vector<std::pair<std::string_view, double>>& out) const
{
    auto it = m_zsets.find(key);
    if (it == m_zsets.end()) return 0;
    return scan_one_collection(it->second, cursor, pattern, count,
        [&out](const auto& e) { out.emplace_back(std::string_view(e.first), e.second); return true; });
}

// ─── Hashes, the field spellings ───

bool cache_store::hexists(std::string_view key, std::string_view field) const
{
    auto it = m_hashes.find(key);
    return it != m_hashes.end() && it->second.count(field) > 0;
}

cache_store::incr_result cache_store::hincrby(std::string_view key, std::string_view field,
                                              int64_t delta, int64_t& result)
{
    check_expiry(key);

    int64_t val = 0;
    auto it = m_hashes.find(key);
    if (it != m_hashes.end())
    {
        std::string_view cur;
        if (it->second.get(field, cur))
        {
            auto [ptr, ec] = std::from_chars(cur.data(), cur.data() + cur.size(), val);
            if (ec != std::errc{} || ptr != cur.data() + cur.size())
                return incr_result::not_an_integer;
        }
    }

    // The same guard incr() carries, and refused before the write for the same
    // reason: the field must be left as it was.
    if (__builtin_expect(__builtin_add_overflow(val, delta, &val), 0))
        return incr_result::would_overflow;
    result = val;

    char buf[24];
    auto [end, ec2] = std::to_chars(buf, buf + sizeof(buf), val);
    (void)ec2;
    if (hset(key, field, std::string_view(buf, static_cast<size_t>(end - buf))))
        return incr_result::ok;
    // hset() refuses for room or for a key of another kind, which the key itself tells apart.
    const std::string_view held = type(key);
    return held == "none" || held == "hash" ? incr_result::out_of_memory : incr_result::wrong_type;
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
static zskiplist::const_iterator
score_lower(const zskiplist& ord, double min, bool incl)
{
    // The exclusive case used to be upper_bound({min, "\xff"}), which is only
    // right while no member begins with that byte.  Asking the list to skip a
    // SCORE cannot be fooled by a member's spelling.
    return ord.lower_bound_score(min, incl);
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
        if (i >= s) doomed.emplace_back(m.second);
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
        doomed.emplace_back(e->second);
    }
    for (const auto& m : doomed)
        zrem(key, m);
    return doomed.size();
}

// A read that missed its own container has two possible answers, and until
// this existed every one of them gave the wrong one: GET on a list replied nil,
// which a caller reads as "not cached" and acts on.  Redis answers WRONGTYPE.
//
// The order is the cheap tests first, and every one is guarded by empty() --
// a cache holding only strings never touches the other four maps.
bool cache_store::holds_other_type(std::string_view key, char expect) const
{
    if (expect != 's' && !m_data.empty()   && m_data.count(key))   return true;
    if (expect != 'l' && !m_lists.empty()  && m_lists.count(key))  return true;
    if (expect != 't' && !m_sets.empty()   && m_sets.count(key))   return true;
    if (expect != 'h' && !m_hashes.empty() && m_hashes.count(key)) return true;
    if (expect != 'z' && !m_zsets.empty()  && m_zsets.count(key))  return true;
    if (expect != 'x' && !m_streams.empty() && m_streams.count(key)) return true;
    return false;
}

// Beside type() deliberately: the two share a vocabulary, and a reader who
// changes one has to have the other on the same screen.
int cache_store::scan_map_of_type(std::string_view name)
{
    // The names are all letters, so ORing in 0x20 lowercases them and a caller
    // may spell the type however it likes.
    auto eq = [](std::string_view a, std::string_view lower) {
        if (a.size() != lower.size()) return false;
        for (size_t i = 0; i < a.size(); ++i)
            if (static_cast<char>(a[i] | 0x20) != lower[i]) return false;
        return true;
    };
    if (eq(name, "string")) return 0;
    if (eq(name, "list"))   return 1;
    if (eq(name, "set"))    return 2;
    if (eq(name, "hash"))   return 3;
    if (eq(name, "zset"))   return 4;
    if (eq(name, "stream")) return 5;
    return -1;
}

std::string_view cache_store::type(std::string_view key) const
{
    if (m_data.count(key)) return "string";
    if (!m_lists.empty() && m_lists.count(key)) return "list";
    if (!m_sets.empty() && m_sets.count(key)) return "set";
    if (!m_hashes.empty() && m_hashes.count(key)) return "hash";
    if (!m_zsets.empty()  && m_zsets.count(key))  return "zset";
    if (!m_streams.empty() && m_streams.count(key)) return "stream";
    return "none";
}

void cache_store::keys(std::string_view pattern, std::vector<std::string_view>& out) const
{
    bool match_all = (pattern == "*");
    // As in scan(): a key past its deadline is listed by nobody.
    const bool any_ttl = !m_expiry.empty();
    const auto now = any_ttl ? std::chrono::steady_clock::now() : std::chrono::steady_clock::time_point{};
    auto match = [&](std::string_view key) -> bool {
        if (any_ttl)
            if (const auto e = m_expiry.find(key); e != m_expiry.end() && now >= e->second)
                return false;
        if (match_all) return true;
        return socketley::glob_match(pattern, key);
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
    for (const auto& [key, _] : m_streams)
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
    if (auto it = m_streams.find(key); it != m_streams.end())
    {
        track_sub(entry_cost(it->first, it->second));
        m_streams.erase(it);
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

uint32_t cache_store::size_of_type(int map) const
{
    switch (map)
    {
        case 0:  return static_cast<uint32_t>(m_data.size());
        case 1:  return static_cast<uint32_t>(m_lists.size());
        case 2:  return static_cast<uint32_t>(m_sets.size());
        case 3:  return static_cast<uint32_t>(m_hashes.size());
        case 4:  return static_cast<uint32_t>(m_zsets.size());
        case 5:  return static_cast<uint32_t>(m_streams.size());
        default: return 0;          // a name no type has holds no keys
    }
}

uint32_t cache_store::size() const
{
    return static_cast<uint32_t>(m_data.size() + m_lists.size() + m_sets.size()
                              + m_hashes.size() + m_zsets.size() + m_streams.size());
}

bool cache_store::exists(std::string_view key) const
{
    // Check m_data first — most keys are strings in typical workloads
    if (__builtin_expect(m_data.count(key) != 0, 1)) return true;
    if (!m_lists.empty() && m_lists.count(key)) return true;
    if (!m_sets.empty() && m_sets.count(key)) return true;
    if (!m_hashes.empty() && m_hashes.count(key)) return true;
    if (!m_zsets.empty() && m_zsets.count(key)) return true;
    if (!m_streams.empty() && m_streams.count(key)) return true;
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

    // Streams, as the records their writes replicate as: the entries, the
    // counters XSETID carries, and every group with its consumers and pending
    // entries, with the empty stream made by XADD MAXLEN 0 as Redis's own
    // rewrite makes it.
    for (const auto& [key, st] : m_streams)
    {
        const auto record = [&](std::initializer_list<std::string_view> a) {
            cmd.append("xapply ");
            cmd.append(key);
            cmd.push_back(' ');
            stream_args_encode(cmd, a.begin(), a.size());
            emit();
        };
        std::vector<std::string_view> xa;
        std::string ids;
        st.walk({}, stream_id::max(), false, [&](const stream_inner::entry& e) {
            xa.assign({ "XADD", std::string_view(key) });
            ids = e.id.str();
            xa.push_back(ids);
            e.each([&](std::string_view f, std::string_view v) { xa.push_back(f); xa.push_back(v); });
            cmd.append("xapply ");
            cmd.append(key);
            cmd.push_back(' ');
            stream_args_encode(cmd, xa.data(), xa.size());
            emit();
            return true;
        });
        if (st.empty())
            record({ "XADD", key, "MAXLEN", "0", "0-1", "x", "y" });
        const std::string last = st.last_id().str(), maxdel = st.max_deleted().str(),
                          added = std::to_string(st.entries_added());
        record({ "XSETID", key, last, "ENTRIESADDED", added, "MAXDELETEDID", maxdel });
        if (!st.groups()) continue;
        for (const auto& [gname, g] : *st.groups())
        {
            const std::string gl = g.last.str(), er = std::to_string(g.entries_read);
            record({ "XGROUP", "CREATE", key, gname, gl, "ENTRIESREAD", er });
            for (const auto& [cname, c] : g.consumers)
            {
                const std::string seen = std::to_string(c.seen_ms), active = std::to_string(c.active_ms);
                record({ "XCONSUMER", key, gname, cname, seen, active });
            }
            for (const auto& [id, n] : g.pel)
            {
                if (!n.owner) continue;
                const std::string idt = id.str(), when = std::to_string(n.delivery_ms),
                                  count = std::to_string(n.count);
                record({ "XNACK", key, gname, n.owner->name, idt, when, count });
            }
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

// An expiry flag of 1 is the remaining time at the save, which is what every
// dump before this one wrote; 2 is the deadline in wall-clock milliseconds.
static constexpr uint8_t expiry_absolute = 2;

static int64_t expiry_left_ms(uint8_t flag, int64_t v, int64_t wall_now_ms)
{
    return flag == expiry_absolute ? v - wall_now_ms : v;
}

static int64_t wall_clock_ms()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// Append-only: an older build reads a dump it does not know the types in,
// which is why a new one goes on the end and never in the middle.
enum : uint8_t { TYPE_STRING = 0, TYPE_LIST = 1, TYPE_SET = 2, TYPE_HASH = 3,
                 TYPE_ZSET = 4, TYPE_STREAM = 5 };

void cache_store::adopt_owned(cache_store& other, uint32_t shard_index,
                              uint32_t shard_count)
{
    const auto mine = [&](std::string_view k) {
        return cache_shard_of(k, shard_count) == shard_index;
    };

    // The deadline moves with the key, and it is read BEFORE the key is moved
    // out of `other` — after the move the string is gone and the lookup would
    // be against an empty key.
    const auto carry_expiry = [&](std::string_view k) {
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

    for (auto it = other.m_streams.begin(); it != other.m_streams.end(); ++it)
        if (mine(it->first))
        {
            carry_expiry(it->first);
            adopt_loaded_stream(std::string(it->first), std::move(it->second));
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
        // type(1) + key_len(4) + key + expiry_flag(1) [+ deadline_ms(8)]
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
        for (const auto& [sc, member] : z.order) total_size += string_size(member) + 8;
    }

    // A stream is its own serialisation behind a u64 length, made here once
    // because its size is only known by making it.
    std::vector<std::string> stream_blobs;
    stream_blobs.reserve(m_streams.size());
    for (const auto& [key, st] : m_streams)
    {
        stream_blobs.emplace_back();
        st.serialize(stream_blobs.back());
        total_size += entry_overhead(key) + 8 + stream_blobs.back().size();
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

    // Blocks reserved, not a sparse file: a store into a mapping the disk has
    // no room behind raises SIGBUS rather than an error, so a full disk ended
    // the worker in the middle of a stop instead of failing the dump.
    // ftruncate stays the fallback only where fallocate is not supported.
    int rc = ::fallocate(fd_raw, 0, 0, static_cast<off_t>(total_size));
    if (rc != 0 && (errno == EOPNOTSUPP || errno == ENOSYS))
        rc = ftruncate(fd_raw, static_cast<off_t>(total_size));
    if (rc != 0)
    {
        close(fd_raw);
        unlink(tmp_path.c_str());
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
    const int64_t wall_now_ms = wall_clock_ms();

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
            // A wall-clock deadline, because a remaining time restored a week
            // later grants the whole of it again.
            emit_u8(expiry_absolute);
            emit_i64(wall_now_ms + std::chrono::duration_cast<std::chrono::milliseconds>(
                eit->second - now).count());
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
        emit_u32(static_cast<uint32_t>(z.size()));
        for (const auto& [sc, member] : z.order)
        {
            emit_string(member);
            std::memcpy(p, &sc, 8); p += 8;
        }
        emit_expiry(key);
    }

    size_t blob_i = 0;
    for (const auto& [key, st] : m_streams)
    {
        const std::string& blob = stream_blobs[blob_i++];
        emit_key(TYPE_STREAM, key);
        emit_i64(static_cast<int64_t>(blob.size()));
        emit(blob.data(), blob.size());
        emit_expiry(key);
    }

    // A dump the disk could not take is no dump, and the one before it stays in place.
    const bool synced = msync(map, total_size, MS_SYNC) == 0;
    munmap(map, total_size);
    const bool flushed = synced && fsync(fd_raw) == 0;
    close(fd_raw);
    if (!flushed)
    {
        unlink(tmp_path.c_str());
        return false;
    }

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

// Everything, including the counters.  Extracted from load_v2, which had the
// only copy: a second hand-written clear is a second chance to leave
// m_list_elems standing while the lists it counts are gone, and the memory
// figure would then never come back to zero.
void cache_store::flush_all()
{
    m_data.clear();
    m_lists.clear();
    m_sets.clear();
    m_hashes.clear();
    m_zsets.clear();
    m_streams.clear();
    m_list_elems   = 0;
    m_set_elems    = 0;
    m_hash_fields  = 0;
    m_zset_members = 0;
    m_expiry.clear();
    m_current_memory = 0;
    m_lru_order.clear();
    m_lru_map.clear();
}

bool cache_store::load_v2(const char* data, size_t size)
{
    flush_all();

    auto now = std::chrono::steady_clock::now();
    const int64_t wall_now_ms = wall_clock_ms();
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

    // False on a short read, and `expired` set for a deadline already past, so
    // every type is dropped alike rather than restored with no deadline at all.
    auto read_expiry = [&](const std::string& key, bool& expired) -> bool {
        uint8_t has = 0;
        if (!read_u8(has)) return false;
        if (has == 0) return true;
        int64_t v = 0;
        if (!read_i64(v)) return false;
        const int64_t left = expiry_left_ms(has, v, wall_now_ms);
        if (left > 0) m_expiry[key] = now + std::chrono::milliseconds(left);
        else          expired = true;
        return true;
    };

    while (p < end)
    {
        uint8_t type = 0;
        if (!read_u8(type)) return false;

        // A dump cut inside a key's header is as short as one cut inside its value, and loads as nothing.
        std::string key;
        if (!read_string(key)) return false;

        bool expired = false;

        switch (type)
        {
            case TYPE_STRING:
            {
                std::string value;
                if (!read_string(value)) return false;
                if (!read_expiry(key, expired)) return false;
                if (!expired)
                    adopt_loaded_string(std::move(key), std::move(value));
                break;
            }
            case TYPE_LIST:
            {
                uint32_t count = 0;
                if (!read_u32(count)) return false;
                list_inner deq;
                for (uint32_t i = 0; i < count; i++)
                {
                    std::string elem;
                    if (!read_string(elem)) return false;
                    deq.push_back(std::move(elem));
                }
                if (!read_expiry(key, expired)) return false;
                if (!expired)
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
                if (!read_expiry(key, expired)) return false;
                if (!expired)
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
                    h.set(field, val);
                }
                if (!read_expiry(key, expired)) return false;
                if (!expired)
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
                    z.add(sc, member);
                }
                if (!read_expiry(key, expired)) return false;
                if (!expired)
                    adopt_loaded_zset(std::move(key), std::move(z));
                break;
            }
            case TYPE_STREAM:
            {
                int64_t len = 0;
                if (!read_i64(len) || len < 0 || remaining() < static_cast<size_t>(len)) return false;
                stream_inner st;
                if (!st.deserialize(std::string_view(p, static_cast<size_t>(len)))) return false;
                p += len;
                if (!read_expiry(key, expired)) return false;
                if (!expired)
                    adopt_loaded_stream(std::move(key), std::move(st));
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
    flush_all();

    auto now = std::chrono::steady_clock::now();
    const int64_t wall_now_ms = wall_clock_ms();

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

    // The same rule as load_v2's, over a stream.
    auto read_expiry = [&](const std::string& key, bool& expired) -> bool {
        uint8_t has = 0;
        file.read(reinterpret_cast<char*>(&has), 1);
        if (!file) return false;
        if (has == 0) return true;
        int64_t v = 0;
        file.read(reinterpret_cast<char*>(&v), sizeof(v));
        if (!file) return false;
        const int64_t left = expiry_left_ms(has, v, wall_now_ms);
        if (left > 0) m_expiry[key] = now + std::chrono::milliseconds(left);
        else          expired = true;
        return true;
    };

    while (file)
    {
        uint8_t type = 0;
        file.read(reinterpret_cast<char*>(&type), 1);
        if (!file) break;

        // Cut inside a key's header is a cut dump, as load_v2 says.
        std::string key;
        if (!read_string(key)) return false;

        bool expired = false;

        switch (type)
        {
            case TYPE_STRING:
            {
                std::string value;
                if (!read_string(value)) return false;
                if (!read_expiry(key, expired)) return false;
                if (!expired)
                    adopt_loaded_string(std::move(key), std::move(value));
                break;
            }
            case TYPE_LIST:
            {
                uint32_t count = 0;
                file.read(reinterpret_cast<char*>(&count), sizeof(count));
                if (!file) return false;
                list_inner deq;
                for (uint32_t i = 0; i < count; i++)
                {
                    std::string elem;
                    if (!read_string(elem)) return false;
                    deq.push_back(std::move(elem));
                }
                if (!read_expiry(key, expired)) return false;
                if (!expired)
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
                if (!read_expiry(key, expired)) return false;
                if (!expired)
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
                    h.set(field, val);
                }
                if (!read_expiry(key, expired)) return false;
                if (!expired)
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
                    z.add(sc, member);
                }
                if (!read_expiry(key, expired)) return false;
                if (!expired)
                    adopt_loaded_zset(std::move(key), std::move(z));
                break;
            }
            case TYPE_STREAM:
            {
                int64_t len = 0;
                file.read(reinterpret_cast<char*>(&len), sizeof(len));
                if (!file || len < 0 || len > (int64_t{1} << 40)) return false;
                std::string blob(static_cast<size_t>(len), '\0');
                file.read(blob.data(), len);
                if (!file) return false;
                stream_inner st;
                if (!st.deserialize(blob)) return false;
                if (!read_expiry(key, expired)) return false;
                if (!expired)
                    adopt_loaded_stream(std::move(key), std::move(st));
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
    flush_all();

    // Process the first entry (key_len already read)
    uint32_t key_len = first_key_len;

    while (true)
    {
        // Short anywhere inside an entry is a cut dump; only the end of the file between entries is its end.
        std::string key(key_len, '\0');
        file.read(key.data(), key_len);
        if (!file) return false;

        uint32_t val_len = 0;
        file.read(reinterpret_cast<char*>(&val_len), sizeof(val_len));
        if (!file) return false;

        std::string value(val_len, '\0');
        file.read(value.data(), val_len);
        if (!file) return false;

        adopt_loaded_string(std::move(key), std::move(value));

        // Try reading next key_len
        file.read(reinterpret_cast<char*>(&key_len), sizeof(key_len));
        if (!file)
            return file.gcount() == 0;
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

void cache_store::adopt_loaded_list(std::string&& key, list_inner&& deq)
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

void cache_store::adopt_loaded_stream(std::string&& key, stream_inner&& s)
{
    auto it = m_streams.insert_or_assign(std::move(key), std::move(s)).first;
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
    for (const auto& e : m_streams) touch_lru(e.first);
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
        const bool pinned_resident  = (m_pinned != nullptr && m_lru_map.count(*m_pinned) != 0
                                       && !(protect_resident && *m_pinned == *protect));
        const size_t candidates = m_lru_order.size() - (protect_resident ? 1 : 0)
                                                     - (pinned_resident ? 1 : 0);
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
        // skip'th candidate, both stepping over the protected keys if they are
        // in their path.
        auto node = m_lru_order.end();
        for (auto n = m_lru_order.begin(); n != m_lru_order.end(); ++n)
        {
            if ((protect_resident && std::string_view(*n) == *protect)
             || (pinned_resident && std::string_view(*n) == *m_pinned))
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
        else if (auto it = m_streams.find(victim); it != m_streams.end())
        {
            track_sub(entry_cost(it->first, it->second));
            m_streams.erase(it);
        }
    }

    return get_memory_used() + needed <= m_max_memory;
}

// ─── Pub/Sub ───

bool cache_store::subscribe(int fd, std::string_view channel)
{
    const auto [it, fresh] = m_channels.try_emplace(std::string(channel));
    const bool added = it->second.insert(fd).second;
    if (fresh && m_chan_observer)
        m_chan_observer(m_chan_observer_ctx, it->first, true);
    return added;
}

bool cache_store::unsubscribe(int fd, std::string_view channel)
{
    auto it = m_channels.find(channel);
    if (it == m_channels.end())
        return false;
    const bool removed = it->second.erase(fd) > 0;
    if (it->second.empty())
    {
        if (m_chan_observer)
            m_chan_observer(m_chan_observer_ctx, it->first, false);
        m_channels.erase(it);
    }
    return removed;
}

// A pattern has no bit to look up, so these are walked and matched on every
// publish -- which is why they are a separate map: the exact channels stay a
// hash lookup and pay nothing for a feature they are not using.
bool cache_store::psubscribe(int fd, std::string_view pattern)
{
    return m_patterns[std::string(pattern)].insert(fd).second;
}

bool cache_store::punsubscribe(int fd, std::string_view pattern)
{
    auto it = m_patterns.find(pattern);
    if (it == m_patterns.end()) return false;
    const bool removed = it->second.erase(fd) > 0;
    if (it->second.empty()) m_patterns.erase(it);
    return removed;
}

std::vector<std::string> cache_store::subscriptions_of(int fd, bool patterns) const
{
    std::vector<std::string> out;
    for (const auto& [name, fds] : patterns ? m_patterns : m_channels)
        if (fds.count(fd))
            out.push_back(name);
    return out;
}

void cache_store::punsubscribe_all(int fd)
{
    for (auto it = m_patterns.begin(); it != m_patterns.end(); )
    {
        it->second.erase(fd);
        if (it->second.empty()) it = m_patterns.erase(it); else ++it;
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
