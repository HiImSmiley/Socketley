#pragma once
// How much one read off a connection takes: little for one that asks small things, four times more each time a read
// came back full, up to a bound, and little again once it has been quiet a while.  A connection carrying a stream is
// woken a sixteenth as often as at 16 KiB a read, which on the tunnel was 649 against 1,602 MiB/s; one that only ever
// asks small things never holds more than its first size.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>

namespace socketley
{

class read_size
{
public:
    constexpr read_size(uint32_t first, uint32_t max) : m_first(first), m_max(max), m_size(first) {}

    uint32_t next() const { return m_size; }
    uint32_t first() const { return m_first; }
    void reset()
    {
        m_size = m_first;
        m_small = 0;
    }

    // After a read that took `n` of next(): a full one grows the next, and a long run of small ones goes back to the
    // first size, so a connection that streamed once does not keep its large buffer for the rest of its life.
    void took(size_t n)
    {
        if (n >= m_size && m_size < m_max)
        {
            m_size = std::min(m_size * 4, m_max);
            m_small = 0;
        }
        else if (m_size > m_first && n < m_first && ++m_small >= quiet_reads)
        {
            m_size = m_first;
            m_small = 0;
        }
        else if (n >= m_first)
            m_small = 0;
    }

private:
    // Small reads in a row that a large size goes back down after.
    static constexpr uint16_t quiet_reads = 64;
    uint32_t m_first, m_max, m_size;
    uint16_t m_small{0};
};

// A read_size with the bytes it reads into: the first size inline, the larger ones on the heap, kept while they are
// asked for.  Only for a caller that changes it with no read in flight, which is when took() is called.
template <uint32_t First, uint32_t Max = 256 * 1024>
class read_buffer
{
public:
    // The first size is made at the first read, so a holder that never reads -- a storage connection without TLS
    // keeps one for its bodies -- costs a pointer and not First bytes.
    char* data()
    {
        if (m_size.next() != First)
            return m_big.get();
        if (!m_small)
            m_small = std::make_unique_for_overwrite<char[]>(First);
        return m_small.get();
    }
    uint32_t size() const { return m_size.next(); }

    // Back to the first size and its heap given back, for a connection gone quiet; only with no read in flight.
    void reset()
    {
        m_size.reset();
        m_big.reset();
        m_big_size = 0;
    }

    void took(size_t n)
    {
        m_size.took(n);
        if (m_size.next() == First)
        {
            m_big.reset();
            m_big_size = 0;
        }
        else if (m_size.next() != m_big_size)
        {
            m_big = std::make_unique_for_overwrite<char[]>(m_size.next());
            m_big_size = m_size.next();
        }
    }

private:
    read_size m_size{First, Max};
    std::unique_ptr<char[]> m_small;
    std::unique_ptr<char[]> m_big;
    uint32_t m_big_size{0};
};

}   // namespace socketley
