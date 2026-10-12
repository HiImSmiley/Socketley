#pragma once

// A table with one entry per descriptor, which the kernel fills in as it is used.
//
// A runtime indexes its connections by descriptor, and the array is sized for the most a process may hold.  As a
// member it is a megabyte or two of zeroes written at construction -- so every instance pays it in full the moment it
// exists, including the placeholder the daemon keeps for a runtime whose worker is the one serving.  Measured, before
// this: a proxy cost its daemon 2,068 kB whether it had one shard or four, and a worker serving nothing paid the same
// again.
//
// calloc of a block this size comes from mmap, which the kernel hands over already zero and does not make resident
// until a page is written.  A table of 65,536 entries is then a megabyte of address space and as many pages as the
// descriptors in use touch -- descriptors being handed out from zero upwards, that is the first page or two.
//
// Only for a type whose zero bytes are its empty value: a raw pointer, or a struct of those and integers.

#include <cstdlib>
#include <cstring>
#include <new>
#include <type_traits>

namespace socketley
{

template <typename T>
class fd_table
{
    // An implicit-lifetime type, which calloc creates by allocating it: anything with a constructor to run would
    // have to be built entry by entry, and building 65,536 of them is the writing this exists to avoid.
    static_assert(std::is_trivially_default_constructible_v<T> && std::is_trivially_destructible_v<T>,
                  "an entry the kernel may hand over as zeroes");

public:
    explicit fd_table(size_t entries) : m_entries(entries), m_data(static_cast<T*>(std::calloc(entries, sizeof(T))))
    {
        if (!m_data)
            throw std::bad_alloc();
    }
    ~fd_table() { std::free(m_data); }
    // Empty again, and its pages back to the kernel, rather than a write over every one of them.
    void clear()
    {
        T* fresh = static_cast<T*>(std::calloc(m_entries, sizeof(T)));
        if (!fresh)
        {
            std::memset(m_data, 0, m_entries * sizeof(T));
            return;
        }
        std::free(m_data);
        m_data = fresh;
    }
    fd_table(const fd_table&) = delete;
    fd_table& operator=(const fd_table&) = delete;

    T&       operator[](size_t i)       { return m_data[i]; }
    const T& operator[](size_t i) const { return m_data[i]; }
    size_t   size() const { return m_entries; }

private:
    size_t m_entries;
    T*     m_data;
};

}   // namespace socketley
