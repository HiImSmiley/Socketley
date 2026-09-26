#pragma once
// A list's elements: a ring of strings in one block while the list is small,
// where std::deque was a map array and a 512-byte block before its first
// element -- 807 bytes for a five-element list, against Redis's 217.  Past
// BIG_AT elements the list moves to a std::deque for good, because a ring
// moves every string each time it grows and a long list pushed at one end paid
// that: LPUSH into one list read 13.5% slower.  Both ends are O(1), an index is
// O(1), and the middle is a shift, as the deque's middle was.

#include <cstddef>
#include <deque>
#include <memory>
#include <cstdint>
#include <iterator>
#include <new>
#include <string>
#include <type_traits>
#include <utility>

class string_ring
{
public:
    static constexpr size_t BIG_AT = 128;

    string_ring() = default;
    string_ring(const string_ring& o) { copy_from(o); }
    string_ring& operator=(const string_ring& o)
    {
        if (this != &o) { string_ring copy(o); release(); steal(copy); }
        return *this;
    }
    string_ring(string_ring&& o) noexcept { steal(o); }
    string_ring& operator=(string_ring&& o) noexcept
    {
        if (this != &o) { release(); steal(o); }
        return *this;
    }
    ~string_ring() { release(); }

    size_t size()  const { return m_big ? dq().size() : m_size; }
    bool   empty() const { return size() == 0; }
    bool   big()   const { return m_big != nullptr; }

    std::string&       operator[](size_t i)       { return m_big ? dq()[i] : m_buf[slot(i)]; }
    const std::string& operator[](size_t i) const { return m_big ? dq()[i] : m_buf[slot(i)]; }
    std::string&       front()       { return (*this)[0]; }
    const std::string& front() const { return (*this)[0]; }
    std::string&       back()        { return (*this)[size() - 1]; }
    const std::string& back()  const { return (*this)[size() - 1]; }

    template <class... A>
    std::string& emplace_back(A&&... a)
    {
        if (m_big || grow_big()) return dq().emplace_back(std::forward<A>(a)...);
        reserve_one();
        std::string* p = ::new (&m_buf[slot(m_size)]) std::string(std::forward<A>(a)...);
        ++m_size;
        return *p;
    }
    template <class... A>
    std::string& emplace_front(A&&... a)
    {
        if (m_big || grow_big()) return dq().emplace_front(std::forward<A>(a)...);
        reserve_one();
        const uint32_t h = m_head == 0 ? m_cap - 1 : m_head - 1;
        std::string* p = ::new (&m_buf[h]) std::string(std::forward<A>(a)...);
        m_head = h;
        ++m_size;
        return *p;
    }
    void push_back(std::string v)  { emplace_back(std::move(v)); }
    void push_front(std::string v) { emplace_front(std::move(v)); }

    void pop_front()
    {
        if (m_big) { dq().pop_front(); return; }
        m_buf[m_head].~basic_string();
        m_head = (m_head + 1 == m_cap) ? 0 : m_head + 1;
        if (--m_size == 0) m_head = 0;
    }
    void pop_back()
    {
        if (m_big) { dq().pop_back(); return; }
        m_buf[slot(m_size - 1)].~basic_string();
        if (--m_size == 0) m_head = 0;
    }

    void clear() { release(); }

    friend bool operator==(const string_ring& a, const string_ring& b)
    {
        if (a.size() != b.size()) return false;
        for (size_t k = 0; k < a.size(); ++k)
            if (a[k] != b[k]) return false;
        return true;
    }

    // ─── Iterators, by position, so an insert or erase leaves them meaning
    //     the position they name, as the deque's callers here expect ───

    template <bool Const>
    class basic_iterator
    {
        using owner_t = std::conditional_t<Const, const string_ring, string_ring>;
        owner_t* m_r{nullptr};
        size_t   m_i{0};
        friend class string_ring;

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
    iterator       end()         { return { this, size() }; }
    const_iterator begin() const { return { this, 0 }; }
    const_iterator end()   const { return { this, size() }; }

    // What was behind `pos` moves up one; answers the position it named.
    iterator erase(const_iterator pos)
    {
        const size_t i = pos.m_i;
        if (m_big) { dq().erase(dq().begin() + static_cast<std::ptrdiff_t>(i)); return { this, i }; }
        for (size_t k = i; k + 1 < m_size; ++k)
            (*this)[k] = std::move((*this)[k + 1]);
        pop_back();
        return { this, i };
    }

    // `v` goes in at `pos`, and what was there moves back one.
    iterator insert(const_iterator pos, std::string v)
    {
        const size_t i = pos.m_i;
        if (m_big || grow_big())
        {
            dq().insert(dq().begin() + static_cast<std::ptrdiff_t>(i), std::move(v));
            return { this, i };
        }
        if (i == m_size) { emplace_back(std::move(v)); return { this, i }; }
        // Grown first, because growing moves every element and back() would
        // name a moved-from string.
        reserve_one();
        emplace_back(std::move(back()));
        for (size_t k = m_size - 2; k > i; --k)
            (*this)[k] = std::move((*this)[k - 1]);
        (*this)[i] = std::move(v);
        return { this, i };
    }

private:
    std::string* m_buf{nullptr};
    uint32_t     m_cap{0};
    uint32_t     m_head{0};
    uint32_t     m_size{0};
    // Behind a pointer, because a deque in the object cost every small list
    // eighty bytes to spare the few long ones a miss.
    using deque_t = std::deque<std::string>;
    std::unique_ptr<deque_t> m_big;

    deque_t&       dq()       { return *m_big; }
    const deque_t& dq() const { return *m_big; }
    void make_big(deque_t&& d) { m_big = std::make_unique<deque_t>(std::move(d)); }
    void drop_big() { m_big.reset(); }

    // At BIG_AT the ring's strings move into a deque, which then holds them.
    bool grow_big()
    {
        if (m_size < BIG_AT)
            return false;
        deque_t d;
        for (uint32_t k = 0; k < m_size; ++k)
            d.push_back(std::move(m_buf[slot(k)]));
        release();
        make_big(std::move(d));
        return true;
    }

    size_t slot(size_t i) const
    {
        const size_t s = m_head + i;
        return s >= m_cap ? s - m_cap : s;
    }

    // Eight to start, so a short list never moves: its block is allocated
    // beside its table entry and stays there, which is what kept the deque's
    // first block fast -- a ring regrown at the fifth element read LINDEX 22%
    // slower for landing elsewhere.  By half again after that.
    void reserve_one()
    {
        if (m_size < m_cap)
            return;
        const uint32_t cap = m_cap ? m_cap + m_cap / 2 + 1 : 8;
        auto* fresh = static_cast<std::string*>(::operator new(sizeof(std::string) * cap));
        for (uint32_t k = 0; k < m_size; ++k)
        {
            std::string& old = m_buf[slot(k)];
            ::new (&fresh[k]) std::string(std::move(old));
            old.~basic_string();
        }
        ::operator delete(static_cast<void*>(m_buf));
        m_buf = fresh;
        m_cap = cap;
        m_head = 0;
    }

    void release()
    {
        drop_big();
        for (uint32_t k = 0; k < m_size; ++k)
            m_buf[slot(k)].~basic_string();
        ::operator delete(static_cast<void*>(m_buf));
        m_buf = nullptr;
        m_cap = m_head = m_size = 0;
    }

    void steal(string_ring& o) noexcept
    {
        m_buf = o.m_buf; m_cap = o.m_cap; m_head = o.m_head; m_size = o.m_size;
        o.m_buf = nullptr; o.m_cap = o.m_head = o.m_size = 0;
        if (o.m_big) { make_big(std::move(o.dq())); o.drop_big(); }
    }

    void copy_from(const string_ring& o)
    {
        if (o.m_big) { make_big(deque_t(o.dq())); return; }
        if (o.m_size == 0) return;
        m_buf = static_cast<std::string*>(::operator new(sizeof(std::string) * o.m_size));
        m_cap = o.m_size;
        try
        {
            for (uint32_t k = 0; k < o.m_size; ++k)
            {
                ::new (&m_buf[k]) std::string(o[k]);
                m_size = k + 1;
            }
        }
        catch (...)
        {
            release();
            throw;
        }
    }
};
