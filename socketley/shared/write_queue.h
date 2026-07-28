#pragma once

// A pending-write queue bounded by the memory it holds, not by the number of
// entries it holds.
//
// Every runtime capped its write queue at 4096 entries and closed the
// connection on reaching the cap. An entry is one message, and messages are not
// one size, so that cap meant two different things depending on the traffic:
//
//   4096 pending 1 MB responses is four gigabytes of resident memory, and the
//   cap does nothing about it — the limit it was written to enforce is exactly
//   the one it misses
//
//   4096 pending 30-byte pub/sub notifications is 123 KB, and the cap drops the
//   subscriber over it
//
// Counting bytes makes the bound mean what it was meant to mean. Each entry is
// additionally charged a fixed overhead so that a flood of empty messages is
// bounded too — the queue node and its allocation are real memory even when the
// payload is not.

#include <cstddef>
#include <memory>
#include <queue>
#include <string>
#include <string_view>
#include <utility>

namespace socketley
{

// Per-entry bookkeeping charged on top of the payload: the queue node, the
// string header, and allocator rounding. The exact figure matters less than
// that it is nonzero.
inline constexpr size_t write_queue_entry_overhead = 64;

// Closing threshold. A connection holding more than this in unsent data is not
// going to catch up, and keeping the memory helps nobody.
inline constexpr size_t write_queue_max_bytes = 8u * 1024 * 1024;

// Stop reading from the peer at this point, while there is still room to absorb
// what is already in flight.
inline constexpr size_t write_queue_backpressure_bytes = 4u * 1024 * 1024;

inline size_t write_queue_size_of(const std::string& s)
{
    return s.size() + write_queue_entry_overhead;
}

inline size_t write_queue_size_of(const std::shared_ptr<const std::string>& p)
{
    return (p ? p->size() : 0) + write_queue_entry_overhead;
}

template <typename T>
class byte_counted_queue
{
public:
    bool   empty() const noexcept { return m_queue.empty(); }
    size_t size()  const noexcept { return m_queue.size(); }
    size_t bytes() const noexcept { return m_bytes; }

    // Read-only, deliberately: taking a mutable reference and moving out of it
    // would leave pop() subtracting the size of an emptied string, and the
    // counter would drift upward until the connection was closed for a backlog
    // it no longer had. Call sites that need to move use take_front().
    const T& front() const { return m_queue.front(); }
    const T& back()  const { return m_queue.back(); }

    // Grow the tail entry in place. Only the tail may be grown — entries ahead
    // of it may already have been handed to the kernel — and going through the
    // queue is what keeps the byte count honest while doing it.
    void append_back(std::string_view extra)
    {
        m_queue.back().append(extra);
        m_bytes += extra.size();
    }

    void push(const T& value)
    {
        m_bytes += write_queue_size_of(value);
        m_queue.push(value);
    }

    void push(T&& value)
    {
        m_bytes += write_queue_size_of(value);
        m_queue.push(std::move(value));
    }

    template <typename... Args>
    void emplace(Args&&... args)
    {
        m_queue.emplace(std::forward<Args>(args)...);
        m_bytes += write_queue_size_of(m_queue.back());
    }

    void pop()
    {
        if (m_queue.empty())
            return;
        charge_back(write_queue_size_of(m_queue.front()));
        m_queue.pop();
    }

    // Hand the front entry to the caller and drop it, accounting for its size
    // before the move empties it.
    T take_front()
    {
        const size_t n = write_queue_size_of(m_queue.front());
        T value = std::move(m_queue.front());
        m_queue.pop();
        charge_back(n);
        return value;
    }

    void clear()
    {
        m_queue = std::queue<T>{};
        m_bytes = 0;
    }

private:
    void charge_back(size_t n) noexcept
    {
        m_bytes = (m_bytes >= n) ? m_bytes - n : 0;
    }

    std::queue<T> m_queue;
    size_t        m_bytes{0};
};

}  // namespace socketley
