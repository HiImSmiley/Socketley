#pragma once
// The cache's keyspace table: string keys to V, open-addressed over slots that
// carry the whole hash, each pointing at one allocation holding the value and
// the key bytes behind it.
//
// std::unordered_map reached a key through the bucket, the node BEFORE the
// match, the match, and a heap block for any key past 15 bytes -- three or four
// dependent misses a lookup once the keyspace is out of cache.  Here it is the
// slot line and the entry, and the slot line can be fetched ahead.
//
// Entries never move once placed, except when the whole table is rebuilt: an
// erase leaves a tombstone rather than shifting a neighbour back, so a SCAN
// walking slot order sees every key that stayed, and scan_epoch() changes on
// every rebuild so a cursor from before one starts again.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iterator>
#include <new>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

#include "../../shared/transparent_string.h"

template <class V>
class key_table
{
public:
    // Two members only, so `auto& [key, value] = *it` binds as it did for a
    // std::pair; the key's bytes follow the struct in the same block.
    struct entry
    {
        std::string_view first;
        V                second;
    };

private:
    static constexpr uint64_t EMPTY = 0;
    static constexpr uint64_t TOMB  = 1;
    // Set on every live hash, so no live slot reads as EMPTY or TOMB.
    static constexpr uint64_t LIVE  = uint64_t{1} << 63;

    struct slot
    {
        uint64_t h;
        entry*   e;
    };

    static uint64_t hash_of(std::string_view k) { return string_hash{}(k) | LIVE; }

    template <class... A>
    static entry* make_entry(std::string_view k, A&&... a)
    {
        void* mem = ::operator new(sizeof(entry) + (k.empty() ? 1 : k.size()));
        char* kb  = static_cast<char*>(mem) + sizeof(entry);
        if (!k.empty()) std::memcpy(kb, k.data(), k.size());
        try
        {
            return ::new (mem) entry{ std::string_view(kb, k.size()), V(std::forward<A>(a)...) };
        }
        catch (...)
        {
            ::operator delete(mem);
            throw;
        }
    }

    static void drop_entry(entry* e)
    {
        e->~entry();
        ::operator delete(static_cast<void*>(e));
    }

public:
    template <bool Const>
    class basic_iterator
    {
        using table_ptr = std::conditional_t<Const, const key_table*, key_table*>;
        table_ptr m_t{nullptr};
        size_t    m_i{0};
        friend class key_table;

        basic_iterator(table_ptr t, size_t i) : m_t(t), m_i(i) { skip(); }
        void skip()
        {
            while (m_i < m_t->m_cap && m_t->m_slots[m_i].e == nullptr) ++m_i;
        }

    public:
        using iterator_category = std::forward_iterator_tag;
        using value_type        = entry;
        using difference_type   = std::ptrdiff_t;
        using reference         = std::conditional_t<Const, const entry&, entry&>;
        using pointer           = std::conditional_t<Const, const entry*, entry*>;

        basic_iterator() = default;
        // A mutable iterator is usable wherever a const one is asked for.
        template <bool C = Const, class = std::enable_if_t<C>>
        basic_iterator(const basic_iterator<false>& o) : m_t(o.m_t), m_i(o.m_i) {}

        reference operator*()  const { return *m_t->m_slots[m_i].e; }
        pointer   operator->() const { return m_t->m_slots[m_i].e; }
        basic_iterator& operator++() { ++m_i; skip(); return *this; }
        basic_iterator  operator++(int) { auto c = *this; ++*this; return c; }
        friend bool operator==(const basic_iterator& a, const basic_iterator& b) { return a.m_i == b.m_i; }
        friend bool operator!=(const basic_iterator& a, const basic_iterator& b) { return a.m_i != b.m_i; }

        template <bool> friend class basic_iterator;
    };

    using iterator       = basic_iterator<false>;
    using const_iterator = basic_iterator<true>;

    // What walk_buckets() iterates: one slot, holding one entry or none.
    template <bool Const>
    class basic_local_iterator
    {
        using ptr = std::conditional_t<Const, const entry*, entry*>;
        ptr m_e{nullptr};

    public:
        basic_local_iterator() = default;
        explicit basic_local_iterator(ptr e) : m_e(e) {}
        std::conditional_t<Const, const entry&, entry&> operator*() const { return *m_e; }
        ptr operator->() const { return m_e; }
        basic_local_iterator& operator++() { m_e = nullptr; return *this; }
        friend bool operator==(const basic_local_iterator& a, const basic_local_iterator& b) { return a.m_e == b.m_e; }
        friend bool operator!=(const basic_local_iterator& a, const basic_local_iterator& b) { return a.m_e != b.m_e; }
    };

    using local_iterator       = basic_local_iterator<false>;
    using const_local_iterator = basic_local_iterator<true>;

    key_table() = default;
    key_table(const key_table&) = delete;
    key_table& operator=(const key_table&) = delete;
    key_table(key_table&& o) noexcept { steal(o); }
    key_table& operator=(key_table&& o) noexcept
    {
        if (this != &o) { release(); steal(o); }
        return *this;
    }
    ~key_table() { release(); }

    size_t size()  const { return m_size; }
    bool   empty() const { return m_size == 0; }

    iterator       begin()       { return iterator(this, 0); }
    iterator       end()         { return iterator(this, m_cap); }
    const_iterator begin() const { return const_iterator(this, 0); }
    const_iterator end()   const { return const_iterator(this, m_cap); }

    size_t               bucket_count() const { return m_cap; }
    local_iterator       begin(size_t b)       { return local_iterator(m_slots[b].e); }
    local_iterator       end(size_t)           { return local_iterator(); }
    const_local_iterator begin(size_t b) const { return const_local_iterator(m_slots[b].e); }
    const_local_iterator end(size_t)   const { return const_local_iterator(); }

    // Changes whenever entries change slots, which bucket_count() alone does
    // not say when a rebuild keeps the capacity.
    uint32_t scan_epoch() const { return m_epoch; }

    iterator find(std::string_view k)
    {
        const size_t i = locate(k, hash_of(k));
        return iterator(this, i == NPOS ? m_cap : i);
    }
    const_iterator find(std::string_view k) const
    {
        const size_t i = locate(k, hash_of(k));
        return const_iterator(this, i == NPOS ? m_cap : i);
    }
    size_t count(std::string_view k) const { return locate(k, hash_of(k)) == NPOS ? 0 : 1; }
    bool   contains(std::string_view k) const { return count(k) != 0; }

    // Room for n entries without a rebuild.
    void reserve(size_t n)
    {
        size_t want = MIN_CAP;
        while (want < n * 2) want <<= 1;
        if (want > m_cap) rebuild(want);
    }

    // The slot's line, ahead of the find() that will need it.
    void prefetch(std::string_view k) const
    {
        if (m_cap) __builtin_prefetch(&m_slots[hash_of(k) & (m_cap - 1)]);
    }

    template <class... A>
    std::pair<iterator, bool> try_emplace(std::string_view k, A&&... a)
    {
        const uint64_t h = hash_of(k);
        size_t i = locate(k, h);
        if (i != NPOS)
            return { iterator(this, i), false };
        reserve_one();
        i = free_slot(h);
        entry* e = make_entry(k, std::forward<A>(a)...);
        occupy(i, h, e);
        return { iterator(this, i), true };
    }

    template <class... A>
    std::pair<iterator, bool> emplace(std::string_view k, A&&... a)
    {
        return try_emplace(k, std::forward<A>(a)...);
    }

    template <class M>
    std::pair<iterator, bool> insert_or_assign(std::string_view k, M&& v)
    {
        auto r = try_emplace(k, std::forward<M>(v));
        if (!r.second)
            r.first->second = std::forward<M>(v);
        return r;
    }

    V& operator[](std::string_view k) { return try_emplace(k).first->second; }

    iterator erase(const_iterator pos)
    {
        const size_t i = pos.m_i;
        vacate(i);
        return iterator(this, i + 1);
    }
    iterator erase(iterator pos) { return erase(const_iterator(pos)); }

    size_t erase(std::string_view k)
    {
        const size_t i = locate(k, hash_of(k));
        if (i == NPOS)
            return 0;
        vacate(i);
        return 1;
    }

    // Back to no table at all, so a FLUSHALL returns the slots as well.
    void clear() { release(); ++m_epoch; }

private:
    static constexpr size_t NPOS = ~size_t{0};
    static constexpr size_t MIN_CAP = 16;

    slot*    m_slots{nullptr};
    size_t   m_cap{0};
    size_t   m_size{0};
    size_t   m_tombs{0};
    uint32_t m_epoch{0};

    size_t locate(std::string_view k, uint64_t h) const
    {
        if (m_size == 0)
            return NPOS;
        const size_t mask = m_cap - 1;
        for (size_t i = h & mask;; i = (i + 1) & mask)
        {
            const slot& s = m_slots[i];
            if (s.h == h && string_equal{}(s.e->first, k))
                return i;
            if (s.h == EMPTY)
                return NPOS;
        }
    }

    // The first tombstone or empty slot on h's probe path; room is certain
    // after reserve_one().
    size_t free_slot(uint64_t h) const
    {
        const size_t mask = m_cap - 1;
        for (size_t i = h & mask;; i = (i + 1) & mask)
            if (m_slots[i].h == EMPTY || m_slots[i].h == TOMB)
                return i;
    }

    void occupy(size_t i, uint64_t h, entry* e)
    {
        if (m_slots[i].h == TOMB) --m_tombs;
        m_slots[i] = { h, e };
        ++m_size;
    }

    void vacate(size_t i)
    {
        drop_entry(m_slots[i].e);
        --m_size;
        const size_t mask = m_cap - 1;
        // A tombstone is only needed where a probe might have to pass it, so
        // one followed by an empty slot is empty, and so are the tombstones
        // that only it was holding up.
        if (m_slots[(i + 1) & mask].h == EMPTY)
        {
            m_slots[i] = { EMPTY, nullptr };
            for (size_t j = (i - 1) & mask; m_slots[j].h == TOMB; j = (j - 1) & mask)
            {
                m_slots[j] = { EMPTY, nullptr };
                --m_tombs;
            }
        }
        else
        {
            m_slots[i] = { TOMB, nullptr };
            ++m_tombs;
        }
    }

    // Keeps live and dead slots under three quarters, past which linear
    // probing's runs grow faster than the table does.
    void reserve_one()
    {
        if (m_cap && (m_size + m_tombs + 1) * 4 <= m_cap * 3)
            return;
        size_t want = MIN_CAP;
        while (want < (m_size + 1) * 2) want <<= 1;   // at most half full after
        rebuild(want < m_cap ? m_cap : want);
    }

    void rebuild(size_t cap)
    {
        slot* fresh = static_cast<slot*>(std::calloc(cap, sizeof(slot)));
        if (!fresh)
            throw std::bad_alloc();
        const size_t mask = cap - 1;
        for (size_t i = 0; i < m_cap; ++i)
        {
            const slot& s = m_slots[i];
            if (s.e == nullptr)
                continue;
            size_t j = s.h & mask;
            while (fresh[j].h != EMPTY) j = (j + 1) & mask;
            fresh[j] = s;
        }
        std::free(m_slots);
        m_slots = fresh;
        m_cap   = cap;
        m_tombs = 0;
        ++m_epoch;
    }

    void release()
    {
        for (size_t i = 0; i < m_cap; ++i)
            if (m_slots[i].e) drop_entry(m_slots[i].e);
        std::free(m_slots);
        m_slots = nullptr;
        m_cap = m_size = m_tombs = 0;
    }

    void steal(key_table& o)
    {
        m_slots = o.m_slots; m_cap = o.m_cap; m_size = o.m_size;
        m_tombs = o.m_tombs; m_epoch = o.m_epoch + 1;
        o.m_slots = nullptr; o.m_cap = o.m_size = o.m_tombs = 0;
    }
};
