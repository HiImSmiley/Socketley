#pragma once
// A hash's fields: packed into one buffer while the hash is small, a
// key_table once it is not.
//
// Most hashes are a handful of short fields -- a user record, a session -- and
// as a table each field was an allocation of its own plus a slot: 632 bytes
// for five six-byte fields, where Redis's listpack holds the same in 170.
// Packed, a field is its two lengths and its bytes, found by a walk that at
// this size touches one or two cache lines.  Past PACK_MAX_FIELDS fields, or a
// field or value past PACK_MAX_LEN bytes, the walk stops being cheap and the
// map moves to the table for good.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include "key_table.h"
#include "pack_buf.h"

class field_map
{
public:
    static constexpr size_t PACK_MAX_FIELDS = 128;
    static constexpr size_t PACK_MAX_LEN    = 64;

    // The table form, with what its values' blocks hold past their lengths.
    class table : public key_table<std::string>
    {
    public:
        size_t spare = 0;
        table() = default;
        // A copy's strings are made at their length and hold nothing spare.
        table(const table& o) : key_table<std::string>(o) {}
        table& operator=(const table&) = delete;
    };
    using value_type = std::pair<std::string_view, std::string_view>;

    field_map() = default;
    field_map(const field_map& o)
        : m_pack(o.m_pack), m_count(o.m_count),
          m_table(o.m_table ? std::make_unique<table>(*o.m_table) : nullptr) {}
    field_map& operator=(const field_map& o)
    {
        if (this != &o)
        {
            field_map copy(o);
            *this = std::move(copy);
        }
        return *this;
    }
    field_map(field_map&&) noexcept = default;
    field_map& operator=(field_map&&) noexcept = default;

    size_t size()  const { return m_table ? m_table->size() : m_count; }
    bool   empty() const { return size() == 0; }
    bool   packed() const { return !m_table; }

    // What the map's own blocks are: its packed buffer, or its table and the
    // table's slots, beside the fields they hold.
    struct footprint
    {
        size_t n{0};
        size_t pack_size{0};
        size_t pack_heap{0};    // the packed buffer's heap block
        size_t slots{0};        // the table's, 0 while packed
        size_t spare{0};        // the table's values' blocks past their lengths
        bool   packed{true};
    };
    footprint now() const
    {
        if (m_table) return { m_table->size(), 0, 0, m_table->bucket_count(), m_table->spare, false };
        return { m_count, m_pack.size(), m_pack.heap_capacity(), 0, 0, true };
    }
    // After field `f` is set to `vlen` bytes, `old` being the value it holds
    // now, or null for a new field.
    footprint after_set(std::string_view f, size_t vlen, const std::string_view* old) const
    {
        const size_t n = size() + (old ? 0 : 1);
        if (m_table)
        {
            if (!old) return { n, 0, 0, m_table->capacity_after_insert(), m_table->spare, false };
            const std::string& s = m_table->find(f)->second;
            return { n, 0, 0, m_table->bucket_count(),
                     m_table->spare - spare_bytes(s.capacity(), s.size())
                     + spare_bytes(fitted_capacity(s.capacity(), vlen), vlen), false };
        }
        if (!packs(f.size(), vlen) || (!old && m_count + 1 > PACK_MAX_FIELDS))
            return { n, 0, 0, table::capacity_for(m_count + 1), 0, false };
        const size_t more = old ? (vlen > old->size() ? vlen - old->size() : 0) : 2 + f.size() + vlen;
        const size_t bytes = old ? m_pack.size() - old->size() + vlen : m_pack.size() + 2 + f.size() + vlen;
        return { n, bytes, m_pack.heap_part(m_pack.capacity_for(more)), 0, 0, true };
    }

    // The value of `f`, or false.
    bool get(std::string_view f, std::string_view& out) const
    {
        if (m_table)
        {
            auto it = m_table->find(f);
            if (it == m_table->end()) return false;
            out = it->second;
            return true;
        }
        size_t at = 0;
        if (!find_packed(f, at, nullptr)) return false;
        out = value_at(at);
        return true;
    }
    bool   contains(std::string_view f) const { std::string_view v; return get(f, v); }
    size_t count(std::string_view f)    const { return contains(f) ? 1 : 0; }

    // Stores `v` under `f`; answers whether the field is new.
    bool set(std::string_view f, std::string_view v)
    {
        if (!m_table && !packs(f.size(), v.size()))
            unpack();
        if (m_table)
        {
            auto [it, inserted] = m_table->try_emplace(f, v);
            if (!inserted)
            {
                std::string& s = it->second;
                m_table->spare -= spare_bytes(s.capacity(), s.size());
                assign_fitted(s, v);
                m_table->spare += spare_bytes(s.capacity(), s.size());
            }
            return inserted;
        }
        size_t at = 0;
        if (find_packed(f, at, nullptr))
        {
            // The value is the entry's tail; the bytes behind it move by the
            // difference in length.
            const size_t lpos = at + 1 + f.size();
            m_pack.replace(lpos + 1, len_at(lpos), v.data(), v.size());
            m_pack[lpos] = static_cast<char>(v.size());
            return false;
        }
        if (m_count + 1 > PACK_MAX_FIELDS)
        {
            unpack();
            return m_table->try_emplace(f, v).second;
        }
        char e[2 + 2 * PACK_MAX_LEN];
        e[0] = static_cast<char>(f.size());
        std::memcpy(e + 1, f.data(), f.size());
        e[1 + f.size()] = static_cast<char>(v.size());
        std::memcpy(e + 2 + f.size(), v.data(), v.size());
        m_pack.insert(m_pack.size(), e, 2 + f.size() + v.size());
        ++m_count;
        return true;
    }

    bool erase(std::string_view f)
    {
        if (m_table)
        {
            auto it = m_table->find(f);
            if (it == m_table->end()) return false;
            m_table->spare -= spare_bytes(it->second.capacity(), it->second.size());
            m_table->erase(it);
            return true;
        }
        size_t at = 0, end = 0;
        if (!find_packed(f, at, &end)) return false;
        m_pack.erase(at, end - at);
        --m_count;
        if (m_count == 0) m_pack.release();
        return true;
    }

    void clear() { m_pack.release(); m_count = 0; m_table.reset(); ++m_epoch; }

    // ─── Walking it ───

    class const_iterator
    {
        friend class field_map;
        const field_map*     m_m{nullptr};
        size_t               m_at{0};           // packed: byte offset
        table::const_iterator m_it{};           // table
        mutable value_type   m_cur{};

        const_iterator(const field_map* m, size_t at) : m_m(m), m_at(at) {}
        const_iterator(const field_map* m, table::const_iterator it) : m_m(m), m_it(it) {}

    public:
        using iterator_category = std::forward_iterator_tag;
        using difference_type   = std::ptrdiff_t;
        using reference         = const value_type&;
        using pointer           = const value_type*;

        const_iterator() = default;
        reference operator*() const
        {
            if (m_m->m_table) m_cur = { m_it->first, m_it->second };
            else              m_cur = { m_m->field_at(m_at), m_m->value_at(m_at) };
            return m_cur;
        }
        pointer operator->() const { return &**this; }
        const_iterator& operator++()
        {
            if (m_m->m_table) ++m_it;
            else              m_at = m_m->next_at(m_at);
            return *this;
        }
        friend bool operator==(const const_iterator& a, const const_iterator& b)
        {
            // A friend of the iterator is no member of field_map, so it asks through the public packed().
            return a.m_m->packed() ? a.m_at == b.m_at : a.m_it == b.m_it;
        }
        friend bool operator!=(const const_iterator& a, const const_iterator& b) { return !(a == b); }
    };
    using iterator = const_iterator;

    const_iterator begin() const
    {
        return m_table ? const_iterator(this, std::as_const(*m_table).begin()) : const_iterator(this, size_t{0});
    }
    const_iterator end() const
    {
        return m_table ? const_iterator(this, std::as_const(*m_table).end()) : const_iterator(this, m_pack.size());
    }

    // What HSCAN walks: a packed map is one bucket holding every field, so a
    // small hash is answered in one page, as Redis answers a listpack.
    class const_local_iterator
    {
        const_iterator              m_whole;
        table::const_local_iterator m_slot;
        bool                        m_packed;

    public:
        const_local_iterator(const_iterator w) : m_whole(w), m_slot(), m_packed(true) {}
        const_local_iterator(table::const_local_iterator s) : m_whole(), m_slot(s), m_packed(false) {}
        value_type operator*() const
        {
            if (m_packed) return *m_whole;
            return { m_slot->first, m_slot->second };
        }
        const_local_iterator& operator++()
        {
            if (m_packed) ++m_whole; else ++m_slot;
            return *this;
        }
        friend bool operator==(const const_local_iterator& a, const const_local_iterator& b)
        {
            return a.m_packed ? a.m_whole == b.m_whole : a.m_slot == b.m_slot;
        }
        friend bool operator!=(const const_local_iterator& a, const const_local_iterator& b) { return !(a == b); }
    };

    size_t bucket_count() const { return m_table ? m_table->bucket_count() : 1; }
    const_local_iterator begin(size_t b) const
    {
        return m_table ? const_local_iterator(std::as_const(*m_table).begin(b)) : const_local_iterator(begin());
    }
    const_local_iterator end(size_t b) const
    {
        return m_table ? const_local_iterator(std::as_const(*m_table).end(b)) : const_local_iterator(end());
    }
    uint32_t scan_epoch() const { return m_table ? m_table->scan_epoch() + m_epoch : m_epoch; }

private:
    pack_buf               m_pack;
    uint32_t               m_count{0};
    // Moved to the table and back to empty count as changes of shape, so a
    // cursor into the one is never read against the other.
    uint32_t               m_epoch{0};
    std::unique_ptr<table> m_table;

    // Whether a field and value of these lengths may be packed at all.
    static bool packs(size_t flen, size_t vlen) { return flen <= PACK_MAX_LEN && vlen <= PACK_MAX_LEN; }

    size_t len_at(size_t pos) const { return static_cast<unsigned char>(m_pack[pos]); }

    std::string_view field_at(size_t at) const { return { m_pack.data() + at + 1, len_at(at) }; }
    std::string_view value_at(size_t at) const
    {
        const size_t v = at + 1 + len_at(at);
        return { m_pack.data() + v + 1, len_at(v) };
    }
    size_t next_at(size_t at) const
    {
        const size_t v = at + 1 + len_at(at);
        return v + 1 + len_at(v);
    }

    bool find_packed(std::string_view f, size_t& at, size_t* end) const
    {
        for (size_t p = 0; p < m_pack.size(); p = next_at(p))
        {
            if (len_at(p) == f.size() && string_equal{}(field_at(p), f))
            {
                at = p;
                if (end) *end = next_at(p);
                return true;
            }
        }
        return false;
    }

    void unpack()
    {
        auto t = std::make_unique<table>();
        t->reserve(m_count + 1);
        for (size_t p = 0; p < m_pack.size(); p = next_at(p))
            t->try_emplace(field_at(p), value_at(p));
        m_table = std::move(t);
        m_pack.release();
        m_count = 0;
        ++m_epoch;
    }
};
