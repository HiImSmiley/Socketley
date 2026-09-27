#pragma once
// The bytes of a small hash, list or sorted set's packed form.
//
// A std::string was 32 bytes of object for a buffer that is rarely a short
// string: its fifteen bytes of room held a one-element list and nothing larger,
// so a sorted set or a hash paid for them and allocated anyway.  This is a
// pointer and two lengths, with `Local` bytes of its own only where the owner
// has them spare, and it grows by a quarter where libstdc++ doubles.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <new>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

// `v` into `s` in the block a fresh string of its length would take, because
// a collection charges a value by its length and assign() keeps a larger block
// or grows one to twice its size.
inline void assign_fitted(std::string& s, std::string_view v)
{
    if (s.capacity() == std::max(v.size(), std::string().capacity()))
        s.assign(v.data(), v.size());
    else
        std::string(v).swap(s);
}

template <uint32_t Local = 0>
class basic_pack_buf
{
public:
    basic_pack_buf() noexcept : m_p(local()), m_cap(Local) {}
    ~basic_pack_buf() { if (!is_local()) std::free(m_p); }

    basic_pack_buf(const basic_pack_buf& o) : basic_pack_buf()
    {
        if (o.m_size > m_cap) reserve_exact(o.m_size);
        if (o.m_size) std::memcpy(m_p, o.m_p, o.m_size);
        m_size = o.m_size;
    }
    basic_pack_buf& operator=(const basic_pack_buf& o)
    {
        if (this != &o) { basic_pack_buf copy(o); *this = std::move(copy); }
        return *this;
    }
    basic_pack_buf(basic_pack_buf&& o) noexcept : m_p(local()), m_size(o.m_size), m_cap(Local)
    {
        if (o.is_local())
        {
            if (o.m_size) std::memcpy(m_p, o.m_p, o.m_size);
        }
        else
        {
            m_p = o.m_p; m_cap = o.m_cap;
            o.m_p = o.local(); o.m_cap = Local;
        }
        o.m_size = 0;
    }
    basic_pack_buf& operator=(basic_pack_buf&& o) noexcept
    {
        if (this != &o) { this->~basic_pack_buf(); ::new (this) basic_pack_buf(std::move(o)); }
        return *this;
    }
    void swap(basic_pack_buf& o) noexcept
    {
        basic_pack_buf t(std::move(o));
        o = std::move(*this);
        *this = std::move(t);
    }

    const char* data() const { return m_p; }
    char*       data()       { return m_p; }
    size_t size()     const { return m_size; }
    size_t capacity() const { return m_cap; }
    bool   empty()    const { return m_size == 0; }
    char  operator[](size_t i) const { return m_p[i]; }
    char& operator[](size_t i)       { return m_p[i]; }

    // `n` bytes in at `off`, the rest moving back.
    void insert(size_t off, const char* s, size_t n)
    {
        if (n == 0) return;
        grow_for(n);
        std::memmove(m_p + off + n, m_p + off, m_size - off);
        std::memcpy(m_p + off, s, n);
        m_size += static_cast<uint32_t>(n);
    }

    // `n` bytes out at `off`; the block keeps its size, as a string's does.
    void erase(size_t off, size_t n)
    {
        std::memmove(m_p + off, m_p + off + n, m_size - off - n);
        m_size -= static_cast<uint32_t>(n);
    }
    void truncate(size_t off) { m_size = static_cast<uint32_t>(off); }

    // The `n` bytes at `off` become `s`.
    void replace(size_t off, size_t n, const char* s, size_t len)
    {
        if (n == 0 && len == 0) return;
        if (len > n) grow_for(len - n);
        std::memmove(m_p + off + len, m_p + off + n, m_size - off - n);
        std::memcpy(m_p + off, s, len);
        m_size = static_cast<uint32_t>(m_size - n + len);
    }

    // Empty and holding no block.
    void release() { *this = basic_pack_buf(); }

private:
    struct none {};
    char*    m_p;
    uint32_t m_size{0};
    uint32_t m_cap;
    [[no_unique_address]] std::conditional_t<(Local > 0), char[(Local > 0 ? Local : 1)], none> m_local;

    char* local()
    {
        if constexpr (Local > 0) return m_local;
        else                     return nullptr;
    }
    bool is_local() const
    {
        if constexpr (Local > 0) return m_p == m_local;
        else                     return false;
    }

    void grow_for(size_t more)
    {
        const size_t need = m_size + more;
        if (need > m_cap) reserve_exact(need + need / 4);
    }
    void reserve_exact(size_t cap)
    {
        void* p = is_local() ? std::malloc(cap) : std::realloc(m_p, cap);
        if (!p) throw std::bad_alloc();
        if (is_local() && m_size) std::memcpy(p, m_p, m_size);
        m_p = static_cast<char*>(p);
        m_cap = static_cast<uint32_t>(cap);
    }
};

using pack_buf = basic_pack_buf<>;
