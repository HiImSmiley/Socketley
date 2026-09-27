#pragma once
// A list's elements, as a deque of eight-string blocks.
//
// std::deque was the right shape and the wrong size: libstdc++ builds its map
// and a 512-byte block before the first element, 806 bytes for a one-element
// list against Redis's 185.  A ring of strings in one block was small, but it
// moved every string each time it grew and its block left the neighbourhood of
// the table entry, and RPUSH/LPOP on fifty-element lists read 26% slower.
// This keeps what made the deque fast -- blocks that never move, the first one
// allocated with the list -- at a block size a short list does not waste.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iterator>
#include <new>
#include <string>
#include <type_traits>
#include <utility>

#include "pack_buf.h"

class seg_list
{
public:
    static constexpr uint32_t B = 16;  // strings a block

    seg_list() = default;
    seg_list(const seg_list& o)
    {
        try { for (size_t i = 0; i < o.m_size; ++i) emplace_back(o[i]); }
        catch (...) { release(); throw; }
    }
    seg_list& operator=(const seg_list& o)
    {
        if (this != &o) { seg_list copy(o); release(); steal(copy); }
        return *this;
    }
    seg_list(seg_list&& o) noexcept { steal(o); }
    seg_list& operator=(seg_list&& o) noexcept
    {
        if (this != &o) { release(); steal(o); }
        return *this;
    }
    ~seg_list() { release(); }

    size_t size()  const { return m_size; }
    bool   empty() const { return m_size == 0; }

    // The blocks and map slots a list holds with where its elements sit in
    // them, and what one more element at either end makes of those.
    struct shape
    {
        uint32_t blocks{0}, map_cap{0}, off{0}, size{0};

        // Whether an element going in at that end needs a block first.
        bool full_at(bool front) const { return front ? off == 0 : off + size == blocks * B; }
        shape pushed(bool front) const
        {
            shape s = *this;
            if (full_at(front))
            {
                if (s.blocks == s.map_cap) s.map_cap = grown_map(s.map_cap);
                ++s.blocks;
                if (front) s.off = B;
            }
            if (front) --s.off;
            ++s.size;
            return s;
        }
    };
    shape now() const { return { m_blocks, m_map_cap, m_off, m_size }; }
    // A list of `n` pushed at the back, which is how a packed one is unpacked.
    static shape built(size_t n)
    {
        shape s;
        while (n--) s = s.pushed(false);
        return s;
    }

    // What the elements' blocks hold past their lengths (see spare_bytes()).
    size_t spare() const { return size_t{m_spare} * 16; }
    // The same after element `i` is set to `len` bytes by assign().
    size_t spare_after_assign(size_t i, size_t len) const
    {
        const std::string& s = (*this)[i];
        return spare() - size_t{units(s)} * 16
             + size_t{units(fitted_capacity(s.capacity(), len), len)} * 16;
    }
    void assign(size_t i, std::string_view v)
    {
        std::string& s = (*this)[i];
        m_spare -= units(s);
        assign_fitted(s, v);
        m_spare += units(s);
    }
    // The end element moved into `out` and gone, its spare with it.
    void take_front(std::string& out) { m_spare -= units(front()); out = std::move(front()); pop_front(); }
    void take_back(std::string& out)  { m_spare -= units(back());  out = std::move(back());  pop_back(); }

    std::string&       operator[](size_t i)       { return slot_at(m_off + i); }
    const std::string& operator[](size_t i) const { return slot_at(m_off + i); }
    std::string&       front()       { return (*this)[0]; }
    const std::string& front() const { return (*this)[0]; }
    std::string&       back()        { return (*this)[m_size - 1]; }
    const std::string& back()  const { return (*this)[m_size - 1]; }

    // Built in place: a block is raw storage, and only [front, back] holds
    // live strings.  Blocks never move, so an argument naming an element of
    // this list is still that element after a block is added.
    template <class... A>
    std::string& emplace_back(A&&... a)
    {
        if (now().full_at(false))
            add_block_back();
        std::string* slot = ::new (&raw_at(m_off + m_size)) std::string(std::forward<A>(a)...);
        ++m_size;
        m_spare += units(*slot);
        return *slot;
    }
    template <class... A>
    std::string& emplace_front(A&&... a)
    {
        if (now().full_at(true))
        {
            add_block_front();
            m_off = B;
        }
        std::string* slot = ::new (&raw_at(m_off - 1)) std::string(std::forward<A>(a)...);
        --m_off;
        ++m_size;
        m_spare += units(*slot);
        return *slot;
    }
    void push_back(std::string v)  { emplace_back(std::move(v)); }
    void push_front(std::string v) { emplace_front(std::move(v)); }

    void pop_front()
    {
        m_spare -= units(front());
        front().~basic_string();
        ++m_off;
        if (--m_size == 0) { release(); return; }
        if (m_off == B)
        {
            drop_block(0);
            m_head = (m_head + 1 == m_map_cap) ? 0 : m_head + 1;
            --m_blocks;
            m_off = 0;
            m_front_blk = block(0);
        }
    }
    void pop_back()
    {
        m_spare -= units(back());
        back().~basic_string();
        if (--m_size == 0) { release(); return; }
        if (m_off + m_size <= size_t{m_blocks - 1} * B)
        {
            drop_block(m_blocks - 1);
            --m_blocks;
            m_back_blk = block(m_blocks - 1);
        }
    }

    void clear() { release(); }

    friend bool operator==(const seg_list& a, const seg_list& b)
    {
        if (a.m_size != b.m_size) return false;
        for (size_t k = 0; k < a.m_size; ++k)
            if (a[k] != b[k]) return false;
        return true;
    }

    // ─── Iterators by position, so an insert or erase leaves them naming the
    //     position they named, as the deque's callers here expect ───

    template <bool Const>
    class basic_iterator
    {
        using owner_t = std::conditional_t<Const, const seg_list, seg_list>;
        owner_t* m_r{nullptr};
        size_t   m_i{0};
        friend class seg_list;

    public:
        using iterator_category = std::random_access_iterator_tag;
        using value_type        = std::string;
        using difference_type   = std::ptrdiff_t;
        using reference         = std::conditional_t<Const, const std::string&, std::string&>;
        using pointer           = std::conditional_t<Const, const std::string*, std::string*>;

        basic_iterator() = default;
        basic_iterator(owner_t* r, size_t i) : m_r(r), m_i(i) {}
        template <bool C = Const, class = std::enable_if_t<C>>
        basic_iterator(const basic_iterator<false>& o) : m_r(o.m_r), m_i(o.m_i) {}

        reference operator*()  const { return (*m_r)[m_i]; }
        pointer   operator->() const { return &(*m_r)[m_i]; }
        reference operator[](difference_type n) const { return (*m_r)[m_i + n]; }
        basic_iterator& operator++() { ++m_i; return *this; }
        basic_iterator& operator--() { --m_i; return *this; }
        basic_iterator  operator++(int) { auto c = *this; ++m_i; return c; }
        basic_iterator  operator--(int) { auto c = *this; --m_i; return c; }
        basic_iterator& operator+=(difference_type n) { m_i += n; return *this; }
        basic_iterator& operator-=(difference_type n) { m_i -= n; return *this; }
        basic_iterator  operator+(difference_type n) const { return { m_r, m_i + n }; }
        basic_iterator  operator-(difference_type n) const { return { m_r, m_i - n }; }
        difference_type operator-(const basic_iterator& o) const
        {
            return static_cast<difference_type>(m_i) - static_cast<difference_type>(o.m_i);
        }
        friend bool operator==(const basic_iterator& a, const basic_iterator& b) { return a.m_i == b.m_i; }
        friend bool operator!=(const basic_iterator& a, const basic_iterator& b) { return a.m_i != b.m_i; }
        friend bool operator<(const basic_iterator& a, const basic_iterator& b)  { return a.m_i < b.m_i; }

        template <bool> friend class basic_iterator;
    };
    using iterator       = basic_iterator<false>;
    using const_iterator = basic_iterator<true>;

    iterator       begin()       { return { this, 0 }; }
    iterator       end()         { return { this, m_size }; }
    const_iterator begin() const { return { this, 0 }; }
    const_iterator end()   const { return { this, m_size }; }

    // What was behind `pos` moves up one; answers the position it named.
    // Swapped rather than moved, since a short string moved over a long one is
    // copied into the long one's block and would keep it.
    iterator erase(const_iterator pos)
    {
        const size_t i = pos.m_i;
        for (size_t k = i; k + 1 < m_size; ++k)
            (*this)[k].swap((*this)[k + 1]);
        pop_back();
        return { this, i };
    }

    // `v` goes in at `pos`, and what was there moves back one.  Blocks never
    // move, so back() is still the string it was after emplace_back grows.
    iterator insert(const_iterator pos, std::string v)
    {
        const size_t i = pos.m_i;
        if (i == m_size) { emplace_back(std::move(v)); return { this, i }; }
        // Every block moves whole to a string left empty, so only `v` adds spare.
        const uint32_t spare = m_spare;
        emplace_back(std::move(back()));
        for (size_t k = m_size - 2; k > i; --k)
            (*this)[k] = std::move((*this)[k - 1]);
        (*this)[i] = std::move(v);
        m_spare = spare + units((*this)[i]);
        return { this, i };
    }

private:
    // The two end blocks, kept here as the deque keeps its start and finish:
    // a push, a pop or an index near either end reads no map, and without
    // them RPUSH and LPOP read 27-31% slower than the deque.
    std::string*  m_front_blk{nullptr};
    std::string*  m_back_blk{nullptr};
    // A ring of block pointers, so either end takes a block in O(1).
    std::string** m_map{nullptr};
    uint32_t      m_map_cap{0};
    uint32_t      m_head{0};      // map slot of the first block
    uint32_t      m_blocks{0};
    uint32_t      m_off{0};       // first element's place in the first block
    uint32_t      m_size{0};
    // spare() in 16-byte units, in what was padding: 64 GiB before it wraps.
    uint32_t      m_spare{0};

    static uint32_t units(size_t cap, size_t len)
    {
        return static_cast<uint32_t>((spare_bytes(cap, len) + 15) / 16);
    }
    static uint32_t units(const std::string& s) { return units(s.capacity(), s.size()); }

    std::string& slot_at(size_t p) const
    {
        const size_t b = p / B;
        if (b == 0)              return m_front_blk[p];
        if (b + 1 == m_blocks)   return m_back_blk[p % B];
        return block(b)[p % B];
    }
    // The same place, before a string lives there.
    std::string& raw_at(size_t p) const { return slot_at(p); }

    std::string* block(size_t b) const
    {
        const size_t s = m_head + b;
        return m_map[s >= m_map_cap ? s - m_map_cap : s];
    }

    static std::string* new_block()
    {
        return static_cast<std::string*>(::operator new(sizeof(std::string) * B));
    }

    static uint32_t grown_map(uint32_t cap) { return cap ? cap * 2 : 2; }

    void grow_map()
    {
        const uint32_t cap = grown_map(m_map_cap);
        auto** fresh = static_cast<std::string**>(std::malloc(sizeof(std::string*) * cap));
        if (!fresh) throw std::bad_alloc();
        for (uint32_t b = 0; b < m_blocks; ++b)
            fresh[b] = block(b);
        std::free(m_map);
        m_map = fresh;
        m_map_cap = cap;
        m_head = 0;
    }

    void add_block_back()
    {
        std::string* blk = new_block();
        if (m_blocks == m_map_cap)
        {
            try { grow_map(); } catch (...) { ::operator delete(static_cast<void*>(blk)); throw; }
        }
        const size_t s = m_head + m_blocks;
        m_map[s >= m_map_cap ? s - m_map_cap : s] = blk;
        ++m_blocks;
        m_back_blk = blk;
        if (m_blocks == 1) m_front_blk = blk;
    }

    void add_block_front()
    {
        std::string* blk = new_block();
        if (m_blocks == m_map_cap)
        {
            try { grow_map(); } catch (...) { ::operator delete(static_cast<void*>(blk)); throw; }
        }
        m_head = (m_head == 0) ? m_map_cap - 1 : m_head - 1;
        m_map[m_head] = blk;
        ++m_blocks;
        m_front_blk = blk;
        if (m_blocks == 1) m_back_blk = blk;
    }

    void drop_block(uint32_t b) { ::operator delete(static_cast<void*>(block(b))); }

    void release()
    {
        for (size_t i = 0; i < m_size; ++i)
            (*this)[i].~basic_string();
        for (uint32_t b = 0; b < m_blocks; ++b)
            ::operator delete(static_cast<void*>(block(b)));
        std::free(m_map);
        m_map = nullptr;
        m_front_blk = m_back_blk = nullptr;
        m_map_cap = m_head = m_blocks = m_off = m_size = m_spare = 0;
    }

    void steal(seg_list& o) noexcept
    {
        m_front_blk = o.m_front_blk; m_back_blk = o.m_back_blk;
        o.m_front_blk = o.m_back_blk = nullptr;
        m_map = o.m_map; m_map_cap = o.m_map_cap; m_head = o.m_head;
        m_blocks = o.m_blocks; m_off = o.m_off; m_size = o.m_size; m_spare = o.m_spare;
        o.m_map = nullptr; o.m_map_cap = o.m_head = o.m_blocks = o.m_off = o.m_size = o.m_spare = 0;
    }
};
static_assert(sizeof(seg_list) == 48, "the spare count lives in what was padding");
