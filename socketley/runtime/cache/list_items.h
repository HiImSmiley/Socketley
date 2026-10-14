#pragma once
// A list's elements: packed into one buffer while the list is short, a
// seg_list once it is not.
//
// A seg_list holds a short list well -- no map or block until the first
// element -- but a block is sixteen 32-byte string objects, 726 bytes for a
// one-element list where Redis's listpack holds it in 185.  Packed, an element
// is its bytes between two length bytes: the one in front walks forward, the
// one behind walks back, so both ends are O(1) and an index is a walk over at
// most PACK_MAX_ITEMS entries.  Past that, or past an element of PACK_MAX_LEN
// bytes, the list moves to the seg_list for good.
//
// Reads answer views, because a packed element is bytes and no std::string;
// changes go through the calls, which keep either form's invariants.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

#include "pack_buf.h"
#include "seg_list.h"

// A packed list's bytes and count, outside the class so the variant below can
// default-construct it while list_items is still incomplete.  The seg_list
// sets the variant's size, so the bytes up to it hold a short list in place.
struct list_items_packed
{
    basic_pack_buf<24> buf;
    uint32_t           n = 0;
};

class list_items
{
public:
    static constexpr size_t PACK_MAX_ITEMS = 128;
    static constexpr size_t PACK_MAX_LEN   = 64;

    size_t size()   const { return is_packed() ? packed_ref().n : seg_ref().size(); }
    bool   empty()  const { return size() == 0; }
    bool   packed() const { return is_packed(); }

    // What the list's own blocks are: its packed buffer, or its segment
    // blocks and map, beside the elements they hold.
    struct footprint
    {
        size_t          n{0};
        size_t          pack_size{0};
        size_t          pack_heap{0};    // the packed buffer's heap block, 0 while in place
        seg_list::shape seg{};
        size_t          spare{0};        // the elements' blocks past their lengths
        bool            packed{true};
    };
    footprint now() const
    {
        if (!is_packed()) return { size(), 0, 0, seg_ref().now(), seg_ref().spare(), false };
        const auto& p = packed_ref();
        return { p.n, p.buf.size(), p.buf.heap_capacity(), {}, 0, true };
    }
    // After one more element of `len` bytes at an end; an insert grows the
    // list as one at the back does.
    footprint after_push(size_t len, bool front) const
    {
        if (!is_packed())
            return { size() + 1, 0, 0, seg_ref().now().pushed(front), seg_ref().spare(), false };
        const auto& p = packed_ref();
        if (packs(len, p.n))
            return { p.n + 1, p.buf.size() + len + 2, p.buf.heap_part(p.buf.capacity_for(len + 2)), {}, 0, true };
        return { p.n + 1, 0, 0, seg_list::built(p.n).pushed(front), 0, false };
    }
    // After element `i` becomes `len` bytes long.
    footprint after_set(size_t i, size_t len) const
    {
        if (!is_packed())
            return { size(), 0, 0, seg_ref().now(), seg_ref().spare_after_assign(i, len), false };
        const auto& p = packed_ref();
        if (len > PACK_MAX_LEN) return { p.n, 0, 0, seg_list::built(p.n), 0, false };
        const size_t old = item(offset_of(i)).size();
        return { p.n, p.buf.size() - old + len,
                 p.buf.heap_part(p.buf.capacity_for(len > old ? len - old : 0)), {}, 0, true };
    }

    std::string_view at(size_t i) const
    {
        if (!is_packed()) return seg_ref()[i];
        size_t off = 0;
        for (size_t k = 0; k < i; ++k) off = next(off);
        return item(off);
    }
    std::string_view front() const { return is_packed() ? item(0) : std::string_view(seg_ref().front()); }
    std::string_view back() const
    {
        if (!is_packed()) return seg_ref().back();
        return item(prev(packed_ref().buf.size()));
    }

    // The seg_list asked for first and once: a long list is the one pushed
    // and popped at millions a second, and each variant test was a share of it.
    void push_back(std::string_view v)
    {
        if (seg_list* s = std::get_if<1>(&m_v)) { s->emplace_back(v); return; }
        if (fits(v)) { place(packed_ref().buf.size(), v); return; }
        seg_ref().emplace_back(v);
    }
    void push_front(std::string_view v)
    {
        if (seg_list* s = std::get_if<1>(&m_v)) { s->emplace_front(v); return; }
        if (fits(v)) { place(0, v); return; }
        seg_ref().emplace_front(v);
    }

    // Into the caller's string, once: returning it by value moved every
    // element twice, the second move where two return paths defeat NRVO, and
    // LPOP on a long list read 16 ns an element slower than the deque for it.
    void pop_front(std::string& out)
    {
        if (seg_list* s = std::get_if<1>(&m_v)) { s->take_front(out); return; }
        auto& p = packed_ref();
        out.assign(item(0));
        p.buf.erase(0, next(0));
        --p.n;
    }
    void pop_back(std::string& out)
    {
        if (seg_list* s = std::get_if<1>(&m_v)) { s->take_back(out); return; }
        auto& p = packed_ref();
        const size_t off = prev(p.buf.size());
        out.assign(item(off));
        p.buf.truncate(off);
        --p.n;
    }
    // And without a caller to hand the element to.
    void pop_front()
    {
        if (seg_list* s = std::get_if<1>(&m_v)) { s->pop_front(); return; }
        auto& p = packed_ref();
        p.buf.erase(0, next(0));
        --p.n;
    }
    void pop_back()
    {
        if (seg_list* s = std::get_if<1>(&m_v)) { s->pop_back(); return; }
        auto& p = packed_ref();
        p.buf.truncate(prev(p.buf.size()));
        --p.n;
    }

    void set(size_t i, std::string_view v)
    {
        if (is_packed() && v.size() > PACK_MAX_LEN) unpack();
        if (!is_packed()) { seg().assign(i, v); return; }
        const size_t off = offset_of(i);
        auto& p = packed_ref();
        char f[2 + PACK_MAX_LEN];
        p.buf.replace(off, next(off) - off, f, frame(f, v));
    }

    void erase(size_t i)
    {
        if (!is_packed()) { seg().erase(seg().begin() + static_cast<std::ptrdiff_t>(i)); return; }
        const size_t off = offset_of(i);
        auto& p = packed_ref();
        p.buf.erase(off, next(off) - off);
        --p.n;
    }

    // LREM in one walk: up to `limit` elements equal to `v`, from the front or the back, answering how many went.
    size_t remove_matching(std::string_view v, size_t limit, bool from_back)
    {
        size_t removed = 0;
        if (!is_packed())
        {
            auto& s = seg_ref();
            if (!from_back)
            {
                for (size_t i = 0; i < s.size() && removed < limit; )
                    if (s[i] == v) { s.erase(s.begin() + static_cast<std::ptrdiff_t>(i)); ++removed; }
                    else ++i;
            }
            else
            {
                for (size_t i = s.size(); i > 0 && removed < limit; )
                    if (s[--i] == v) { s.erase(s.begin() + static_cast<std::ptrdiff_t>(i)); ++removed; }
            }
            return removed;
        }
        // By offset: an erase moves only the bytes behind it, which a forward walk has not reached and a backward one has passed.
        auto& p = packed_ref();
        if (!from_back)
        {
            for (size_t off = 0; off < p.buf.size() && removed < limit; )
                if (item(off) == v) { p.buf.erase(off, next(off) - off); --p.n; ++removed; }
                else off = next(off);
        }
        else
        {
            for (size_t end = p.buf.size(); end > 0 && removed < limit; )
            {
                const size_t off = prev(end);
                if (item(off) == v) { p.buf.erase(off, end - off); --p.n; ++removed; }
                end = off;
            }
        }
        return removed;
    }

    void insert(size_t i, std::string_view v)
    {
        if (fits(v)) { place(offset_of(i), v); return; }
        seg().insert(seg().begin() + static_cast<std::ptrdiff_t>(i), std::string(v));
    }

    void clear() { m_v = packed_t{}; }

    // ─── Walking it, in either direction, as views ───

    class const_iterator
    {
        friend class list_items;
        const list_items* m_l{nullptr};
        size_t            m_i{0};     // position
        size_t            m_off{0};   // packed: byte offset of that position

        const_iterator(const list_items* l, size_t i, size_t off) : m_l(l), m_i(i), m_off(off) {}

    public:
        using iterator_category = std::bidirectional_iterator_tag;
        using value_type        = std::string_view;
        using difference_type   = std::ptrdiff_t;
        using reference         = std::string_view;
        using pointer           = void;

        const_iterator() = default;
        std::string_view operator*() const
        {
            return m_l->is_packed() ? m_l->item(m_off) : std::string_view(m_l->seg_ref()[m_i]);
        }
        const_iterator& operator++()
        {
            if (m_l->is_packed()) m_off = m_l->next(m_off);
            ++m_i;
            return *this;
        }
        const_iterator& operator--()
        {
            if (m_l->is_packed()) m_off = m_l->prev(m_off);
            --m_i;
            return *this;
        }
        const_iterator operator++(int) { auto c = *this; ++*this; return c; }
        const_iterator operator--(int) { auto c = *this; --*this; return c; }
        size_t index() const { return m_i; }
        friend bool operator==(const const_iterator& a, const const_iterator& b) { return a.m_i == b.m_i; }
        friend bool operator!=(const const_iterator& a, const const_iterator& b) { return a.m_i != b.m_i; }
    };
    using iterator = const_iterator;

    const_iterator begin() const { return { this, 0, 0 }; }
    const_iterator end() const
    {
        return { this, size(), is_packed() ? packed_ref().buf.size() : 0 };
    }
    // The position `i`, in one walk rather than i increments.
    const_iterator iterator_at(size_t i) const { return { this, i, is_packed() ? offset_of(i) : 0 }; }

    friend bool operator==(const list_items& a, const list_items& b)
    {
        if (a.size() != b.size()) return false;
        auto x = a.begin(), y = b.begin();
        for (; x != a.end(); ++x, ++y)
            if (*x != *y) return false;
        return true;
    }

private:
    using packed_t = list_items_packed;
    std::variant<packed_t, seg_list> m_v;

    bool is_packed() const { return m_v.index() == 0; }
    // Unchecked: every caller has asked which form it holds.
    packed_t&       packed_ref()       { return *std::get_if<0>(&m_v); }
    const packed_t& packed_ref() const { return *std::get_if<0>(&m_v); }
    seg_list&       seg_ref()          { return *std::get_if<1>(&m_v); }
    const seg_list& seg_ref()    const { return *std::get_if<1>(&m_v); }
    // The seg_list, moving to it first if the list is still packed.
    seg_list& seg() { if (is_packed()) unpack(); return seg_ref(); }

    size_t len_at(size_t pos) const { return static_cast<unsigned char>(packed_ref().buf[pos]); }
    std::string_view item(size_t off) const
    {
        return { packed_ref().buf.data() + off + 1, len_at(off) };
    }
    size_t next(size_t off) const { return off + len_at(off) + 2; }
    size_t prev(size_t end) const { return end - len_at(end - 1) - 2; }
    size_t offset_of(size_t i) const
    {
        size_t off = 0;
        for (size_t k = 0; k < i; ++k) off = next(off);
        return off;
    }

    // Whether an element of `len` bytes joins `n` in the packed form.
    static bool packs(size_t len, size_t n) { return len <= PACK_MAX_LEN && n < PACK_MAX_ITEMS; }

    // Whether `v` goes into the packed form, moving to the seg_list if not.
    bool fits(std::string_view v)
    {
        if (!is_packed()) return false;
        if (packs(v.size(), packed_ref().n)) return true;
        unpack();
        return false;
    }

    // `v` between its two length bytes, into `f`; answers the bytes written.
    static size_t frame(char* f, std::string_view v)
    {
        f[0] = static_cast<char>(v.size());
        std::memcpy(f + 1, v.data(), v.size());
        f[1 + v.size()] = static_cast<char>(v.size());
        return v.size() + 2;
    }

    void place(size_t off, std::string_view v)
    {
        auto& p = packed_ref();
        char f[2 + PACK_MAX_LEN];
        p.buf.insert(off, f, frame(f, v));
        ++p.n;
    }

    void unpack()
    {
        seg_list s;
        const auto& p = packed_ref();
        for (size_t off = 0; off < p.buf.size(); off = next(off))
            s.emplace_back(item(off));
        m_v = std::move(s);
    }
};
