#pragma once
#include <cstdint>
#include <cstddef>
#include <algorithm>
#include <string>
#include <string_view>
#include <functional>
#include <type_traits>
#include <utility>
#include <vector>

// Open-addressing hash table for the cache store's hot maps, replacing
// std::unordered_map where the profile said the money was: the bucket-chain
// walk (_M_find_before_node_tr) was ~1.9% of total CPU on a GET/SET workload,
// with another ~1.8% in the node dereference and key compare behind it, because
// every probe of a node-based map is a pointer chase into memory nothing else
// has touched.  Here a probe walks a contiguous byte array of 7-bit hash
// fragments and touches an entry only on a fragment match, and the entry it
// touches holds the key AND the value inline — for m_data that is two
// std::string objects, 64 bytes, exactly one cache line, so a GET's key compare
// and its value read (SSO values) are the same line.
//
// This lives in runtime/cache/ and not shared/ deliberately: the cache is the
// only runtime with a keyed store on its request path.  The other three keep
// their tables keyed by fd or looked up per-config, not per-request.
//
// The part callers lean on — the invalidation contract, which is NOT
// std::unordered_map's:
//
//   * erase never moves an entry.  A deleted slot becomes a tombstone (or
//     empty, when nothing probes past it), so iterators and pointers to OTHER
//     entries survive every erase.  cache_store holds iterators into m_data
//     across check_memory(), whose eviction erases other keys; tombstone
//     deletion is what makes that legal, so backward-shift deletion must not
//     be introduced here.
//   * insert may rehash, and a rehash moves every entry: ALL iterators,
//     pointers and string_views into the table die.  Callers that return a
//     value pointer (get_ptr and friends) rely on nothing inserting between
//     lookup and use — true of every site today, each of which encodes the
//     value into its reply buffer before the next store call.
//
// Growth: capacity is a power of two; a rehash is triggered when full+tombstone
// slots would pass 7/8 of capacity, and rehashes to the smallest capacity that
// holds the live entries under 5/8 load (tombstones do not survive a rehash).
// At the 7/8 trigger a 65-byte slot (64B entry + 1B metadata) amortizes to
// ~74 B per key — the same figure cache_store::key_entry_overhead was measured
// at for the map this replaces, which is why the memory accounting keeps its
// constants (see the note there).
template <typename V>
class flat_map
{
public:
    struct entry
    {
        std::string first;
        V second;
    };

private:
    static constexpr uint8_t meta_empty = 0x00;
    static constexpr uint8_t meta_tomb  = 0x01;
    static constexpr size_t  npos       = static_cast<size_t>(-1);

    // Full slots carry 0x80 | (top 7 bits of the hash): the high bit is what
    // distinguishes "full" from the two sentinels, and the fragment is what
    // lets a probe reject a slot without touching the entry at all.
    static size_t hash_key(std::string_view k) noexcept
    {
        return std::hash<std::string_view>{}(k);
    }
    static uint8_t h2_of(size_t h) noexcept
    {
        return static_cast<uint8_t>(0x80u | (h >> 57));
    }

    std::vector<uint8_t> m_meta;   // capacity bytes, one per slot
    std::vector<entry>   m_slots;  // capacity entries, parallel to m_meta
    size_t m_size = 0;             // full slots
    size_t m_used = 0;             // full + tombstone slots

    size_t mask() const noexcept { return m_meta.size() - 1; }
    bool is_full(size_t i) const noexcept { return (m_meta[i] & 0x80u) != 0; }

    template <bool Const>
    class iter
    {
        using E = std::conditional_t<Const, const entry, entry>;
        E* m_p = nullptr;
        E* m_end = nullptr;
        const uint8_t* m_m = nullptr;

        friend class flat_map;
        template <bool> friend class iter;

    public:
        iter() = default;
        iter(E* p, E* end, const uint8_t* m) noexcept : m_p(p), m_end(end), m_m(m) { }

        // iterator -> const_iterator, matching the standard containers.
        template <bool C = Const, typename = std::enable_if_t<C>>
        iter(const iter<false>& o) noexcept : m_p(o.m_p), m_end(o.m_end), m_m(o.m_m) { }

        E& operator*() const noexcept { return *m_p; }
        E* operator->() const noexcept { return m_p; }

        iter& operator++() noexcept
        {
            do { ++m_p; ++m_m; } while (m_p != m_end && (*m_m & 0x80u) == 0);
            return *this;
        }

        template <bool C>
        bool operator==(const iter<C>& o) const noexcept { return m_p == o.m_p; }
        template <bool C>
        bool operator!=(const iter<C>& o) const noexcept { return m_p != o.m_p; }
    };

    iter<false> make_iter(size_t i) noexcept
    {
        return { m_slots.data() + i, m_slots.data() + m_slots.size(), m_meta.data() + i };
    }
    iter<true> make_iter(size_t i) const noexcept
    {
        return { m_slots.data() + i, m_slots.data() + m_slots.size(), m_meta.data() + i };
    }

    size_t find_index(std::string_view k) const noexcept
    {
        if (m_meta.empty())
            return npos;
        const size_t h = hash_key(k);
        const uint8_t h2 = h2_of(h);
        const size_t msk = mask();
        size_t i = h & msk;
        for (;;)
        {
            const uint8_t m = m_meta[i];
            if (m == h2 && m_slots[i].first == k)
                return i;
            if (m == meta_empty)
                return npos;
            i = (i + 1) & msk;
        }
    }

    // Rehash to the smallest power-of-two capacity holding `need` entries under
    // 5/8 load.  Never shrinks: scan() cursors tolerate a capacity change, but
    // a table that bounces between sizes under churn would repay nothing.
    void rehash_to(size_t need)
    {
        size_t cap = 16;
        while (need * 8 > cap * 5)
            cap <<= 1;
        if (cap < m_meta.size())
            cap = m_meta.size();

        std::vector<uint8_t> nmeta(cap, meta_empty);
        std::vector<entry>   nslots(cap);
        const size_t msk = cap - 1;
        for (size_t s = 0; s < m_meta.size(); ++s)
        {
            if (!is_full(s))
                continue;
            const size_t h = hash_key(m_slots[s].first);
            size_t i = h & msk;
            while (nmeta[i] != meta_empty)          // keys are unique: no compares
                i = (i + 1) & msk;
            nmeta[i] = h2_of(h);
            nslots[i] = std::move(m_slots[s]);
        }
        m_meta.swap(nmeta);
        m_slots.swap(nslots);
        m_used = m_size;
    }

    // Find the slot for an insert of `k` (hash `h`), reusing the first
    // tombstone on the probe path.  Returns {index, found}.
    std::pair<size_t, bool> insert_slot(std::string_view k, size_t h)
    {
        const uint8_t h2 = h2_of(h);
        const size_t msk = mask();
        size_t i = h & msk;
        size_t tomb = npos;
        for (;;)
        {
            const uint8_t m = m_meta[i];
            if (m == h2 && m_slots[i].first == k)
                return { i, true };
            if (m == meta_empty)
                break;
            if (m == meta_tomb && tomb == npos)
                tomb = i;
            i = (i + 1) & msk;
        }
        if (tomb != npos)
            i = tomb;
        else
            ++m_used;
        m_meta[i] = h2;
        ++m_size;
        return { i, false };
    }

    void maybe_grow()
    {
        if (m_meta.empty() || (m_used + 1) * 8 > m_meta.size() * 7)
            rehash_to(m_size + 1);
    }

public:
    using iterator = iter<false>;
    using const_iterator = iter<true>;

    flat_map() = default;

    void reserve(size_t n)
    {
        if (m_meta.empty() || n * 8 > m_meta.size() * 5)
            rehash_to(n < m_size ? m_size : n);
    }

    size_t size() const noexcept { return m_size; }
    bool empty() const noexcept { return m_size == 0; }

    iterator begin() noexcept
    {
        size_t i = 0;
        while (i < m_meta.size() && !is_full(i))
            ++i;
        return make_iter(i);
    }
    iterator end() noexcept { return make_iter(m_meta.size()); }
    const_iterator begin() const noexcept
    {
        size_t i = 0;
        while (i < m_meta.size() && !is_full(i))
            ++i;
        return make_iter(i);
    }
    const_iterator end() const noexcept { return make_iter(m_meta.size()); }

    iterator find(std::string_view k) noexcept
    {
        const size_t i = find_index(k);
        return i == npos ? end() : make_iter(i);
    }
    const_iterator find(std::string_view k) const noexcept
    {
        const size_t i = find_index(k);
        return i == npos ? end() : make_iter(i);
    }
    size_t count(std::string_view k) const noexcept
    {
        return find_index(k) == npos ? 0 : 1;
    }

    template <typename... Args>
    std::pair<iterator, bool> try_emplace(std::string&& key, Args&&... args)
    {
        maybe_grow();
        const auto [i, found] = insert_slot(key, hash_key(key));
        if (found)
            return { make_iter(i), false };
        m_slots[i].first = std::move(key);
        m_slots[i].second = V(std::forward<Args>(args)...);
        return { make_iter(i), true };
    }

    // Same as try_emplace for our purposes: on an existing key neither
    // overwrites, exactly as std::unordered_map::emplace does not.
    std::pair<iterator, bool> emplace(std::string&& key, V&& value)
    {
        return try_emplace(std::move(key), std::move(value));
    }

    std::pair<iterator, bool> insert_or_assign(std::string&& key, V&& value)
    {
        auto [it, inserted] = try_emplace(std::move(key), std::move(value));
        if (!inserted)
            it->second = std::move(value);
        return { it, inserted };
    }

    // Tombstone deletion: the entry is destroyed in place and nothing moves —
    // see the contract at the top.  When nothing can be probing past this slot
    // (the next slot is empty), it and any run of tombstones behind it become
    // empty instead: a probe path is a contiguous run of non-empty slots, so a
    // slot cyclically followed by an empty one is on nobody's path.
    void erase(const_iterator it)
    {
        const size_t i = static_cast<size_t>(it.operator->() - m_slots.data());
        // Destroy by moving OUT, not by assigning an empty entry in: libstdc++'s
        // string move-assignment from an SSO source keeps the destination's
        // heap buffer, so `m_slots[i] = entry{}` retained the erased value's
        // allocation inside the slot.  The fuzzer caught what that does next:
        // try_emplace reused the slot, the new value inherited the old 192-byte
        // capacity, and the capacity-based memory accounting charged a recycled
        // buffer to a write that was admitted at size zero -- landing the store
        // over its configured maxmemory.  Moving out steals the buffers into a
        // temporary whose destructor frees them.
        { entry dead(std::move(m_slots[i])); (void)dead; }
        m_slots[i].first.clear();
        --m_size;
        const size_t msk = mask();
        if (m_meta[(i + 1) & msk] == meta_empty)
        {
            m_meta[i] = meta_empty;
            --m_used;
            for (size_t j = (i + msk) & msk; m_meta[j] == meta_tomb; j = (j + msk) & msk)
            {
                m_meta[j] = meta_empty;
                --m_used;
            }
        }
        else
        {
            m_meta[i] = meta_tomb;
        }
    }

    void clear()
    {
        std::fill(m_meta.begin(), m_meta.end(), meta_empty);
        // clear-then-resize, not assignment: destroying the entries is the only
        // way to actually free their buffers (see erase()).  The vector keeps
        // its own capacity, so this allocates nothing.
        const size_t cap = m_slots.size();
        m_slots.clear();
        m_slots.resize(cap);
        m_size = 0;
        m_used = 0;
    }

    // Slot-granularity access for scan(): a "bucket" is one slot holding zero
    // or one entries, so SCAN's whole-buckets-only cursor works unchanged, and
    // its rehash detection (bucket_count changed -> restart the map) covers
    // this table's growth the same way it covered unordered_map's.
    size_t bucket_count() const noexcept { return m_meta.size(); }
    const entry* begin(size_t b) const noexcept { return m_slots.data() + b; }
    const entry* end(size_t b) const noexcept
    {
        return m_slots.data() + b + (is_full(b) ? 1 : 0);
    }
};
