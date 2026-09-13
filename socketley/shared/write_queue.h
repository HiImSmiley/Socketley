#pragma once

// Bounded by the memory it holds rather than the entries, each charged a fixed
// overhead so empty messages are bounded too.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <queue>
#include <string>
#include <string_view>
#include <utility>

namespace socketley
{

// Per-entry bookkeeping charged on top of the payload: the queue node, the
// string header, and allocator rounding.
inline constexpr size_t write_queue_entry_overhead = 64;

// Closing threshold, past which a connection is not going to catch up.
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

// Bytes on loan from a pool that wants them back by number once the write that
// used them has completed, which is what a provided-buffer ring is.
struct borrowed_bytes
{
    const char* data{nullptr};
    size_t      size{0};
    void      (*give_back)(void* pool, uint16_t id){nullptr};
    void*       pool{nullptr};
    uint16_t    id{0};
};

// One queued write: bytes this connection owns, a reference to bytes several
// connections are sending, or bytes on loan from the buffer a read delivered
// them in.
//
// The first two halves are the two things a write queue can be good at and
// neither is free.  Sharing is what makes a broadcast to N connections cost
// one copy instead of N -- the server's queue held shared_ptr for that reason
// and could not coalesce, because appending to a payload would change it for
// everybody else holding it.  Owning is what lets a backlog become fewer,
// larger writes -- the cache's queue held strings for that reason and pays N
// copies on a fan-out.  Holding both is not a compromise between them: a
// connection that is keeping up has nothing to coalesce into, and one that is
// behind has already been copied to once, so the two cases never want the same
// entry.
//
// Borrowing is the third: a relay that forwards what it read has nothing to
// add and nobody to share with, so the copy into an owned string bought only
// the right to return the read's buffer early.  A borrowed entry gives that
// buffer back itself, when it is dropped, moved over or cleared, which is the
// one place a queue entry's life ends -- so no path that drops an entry has
// to remember the buffer.
class write_chunk
{
public:
    write_chunk() = default;
    write_chunk(std::string s) : m_owned(std::move(s)) {}
    write_chunk(std::shared_ptr<const std::string> p) : m_shared(std::move(p)) {}
    write_chunk(borrowed_bytes b) : m_borrowed(b) {}
    ~write_chunk() { give_back(); }

    // A copy of a loan is bytes this copy owns, so one buffer is never given
    // back twice.
    write_chunk(const write_chunk& o)
        : m_owned(o.m_borrowed.data ? std::string(o.m_borrowed.data, o.m_borrowed.size)
                                    : o.m_owned),
          m_shared(o.m_shared)
    {
    }
    write_chunk& operator=(const write_chunk& o)
    {
        if (this != &o)
        {
            give_back();
            m_owned  = o.m_borrowed.data ? std::string(o.m_borrowed.data, o.m_borrowed.size)
                                         : o.m_owned;
            m_shared = o.m_shared;
        }
        return *this;
    }
    write_chunk(write_chunk&& o) noexcept
        : m_owned(std::move(o.m_owned)), m_shared(std::move(o.m_shared)),
          m_borrowed(o.m_borrowed)
    {
        o.m_borrowed = {};
    }
    write_chunk& operator=(write_chunk&& o) noexcept
    {
        if (this != &o)
        {
            give_back();
            m_owned    = std::move(o.m_owned);
            m_shared   = std::move(o.m_shared);
            m_borrowed = o.m_borrowed;
            o.m_borrowed = {};
        }
        return *this;
    }

    const char* data() const
    {
        return m_borrowed.data ? m_borrowed.data
             : m_shared        ? m_shared->data()
                               : m_owned.data();
    }
    size_t size() const
    {
        return m_borrowed.data ? m_borrowed.size
             : m_shared        ? m_shared->size()
                               : m_owned.size();
    }
    bool        empty() const { return size() == 0; }
    std::string_view view() const { return { data(), size() }; }

    // Whether this entry may still grow, which a shared or a borrowed one may
    // not: those bytes are in somebody else's queue, or somebody else's pool.
    bool owns() const { return !m_shared && !m_borrowed.data; }
    void append(std::string_view extra) { m_owned.append(extra); }

    void clear() { m_owned.clear(); m_shared.reset(); give_back(); }

private:
    void give_back()
    {
        if (m_borrowed.give_back)
            m_borrowed.give_back(m_borrowed.pool, m_borrowed.id);
        m_borrowed = {};
    }

    std::string                        m_owned;
    std::shared_ptr<const std::string> m_shared;
    borrowed_bytes                     m_borrowed;
};

inline size_t write_queue_size_of(const write_chunk& c)
{
    return c.size() + write_queue_entry_overhead;
}

// Whether the tail entry may still be appended to.  An owned string always
// may; anything holding bytes on somebody else's behalf never may, and says so
// through its own overload rather than by being special-cased here.
inline bool write_queue_can_grow(const std::string&) { return true; }
inline bool write_queue_can_grow(const write_chunk& c) { return c.owns(); }

template <typename T>
class byte_counted_queue
{
public:
    bool   empty() const noexcept { return m_queue.empty(); }
    size_t size()  const noexcept { return m_queue.size(); }
    size_t bytes() const noexcept { return m_bytes; }

    // Read-only, because moving out of it leaves pop() subtracting an emptied
    // string; use take_front().
    const T& front() const { return m_queue.front(); }
    const T& back()  const { return m_queue.back(); }

    // Grow the tail entry in place, only the tail, since entries ahead of it
    // may already have been handed to the kernel.
    void append_back(std::string_view extra)
    {
        m_queue.back().append(extra);
        m_bytes += extra.size();
    }

    // Grow the tail while that keeps it under `limit`, and queue a new entry
    // otherwise.
    //
    // The decision and not the function: two call sites in the cache had
    // worked out the same thing from opposite ends -- a pipelined client's
    // three-byte replies, and a subscriber falling behind a busy channel --
    // and both are one fact about this queue.  A stream of small messages to
    // one connection becomes thousands of entries, of which only
    // MAX_WRITE_BATCH reach the kernel per submission, so the cost is paid in
    // segments rather than in bytes.  Measured on the second of those sites:
    // 0.149 TCP segments per delivery against 0.036.
    //
    // `limit` belongs to the caller because it is a memory bound on one
    // connection, not a property of the queue.
    void push_coalesced(std::string_view value, size_t limit)
    {
        if (fits_in_tail(value.size(), limit))
        {
            append_back(value);
            return;
        }
        push(T(std::string(value)));
    }

    // A payload several connections are sending, which is the same decision
    // read from the other side.
    //
    // The threshold is what keeps this from being a loss.  For a queue of
    // owned strings the choice is between copying into the tail and copying
    // into a fresh entry, so coalescing is strictly cheaper and needs no
    // condition.  Here the alternative costs nothing at all -- a refcount --
    // so a copy has to buy something, and below `batch` entries it buys
    // nothing: the whole queue leaves in one submission whatever its shape.
    // At or above it, entries are what the kernel is charging for.
    //
    // The seeding push at the end is why the middle case is ever reached: a
    // tail that is shared cannot grow, so the first message past the threshold
    // queues a copy that the ones after it can append to.
    void push_shared(const std::shared_ptr<const std::string>& value,
                     size_t limit, size_t batch)
    {
        if (!value)
            return;
        if (m_queue.size() < batch)
        {
            push(T(value));
            return;
        }
        if (fits_in_tail(value->size(), limit))
        {
            append_back(*value);
            return;
        }
        // The copy below is a seed: it buys the NEXT message an appendable tail.
        // A payload already at the limit cannot pay for that, because
        // fits_in_tail would then fail on its size alone whatever arrives after
        // it -- so the copy is the whole cost and none of the benefit.  Every
        // chunk of a 64 KiB streamed response is this shape, and so is a kept
        // --http response of any size once the queue is deep.
        if (value->size() >= limit)
        {
            push(T(value));
            return;
        }
        push(T(std::string(*value)));
    }

    // The same decision for a caller that owns the bytes, which is not a
    // convenience: the response path reached this queue through
    // push(std::move(buf)) and routing it through the copying form above would
    // have put an allocation and a copy on the hottest path in the runtime for
    // the sake of one shared implementation.
    void push_coalesced(std::string&& value, size_t limit)
    {
        if (fits_in_tail(value.size(), limit))
        {
            append_back(value);
            return;
        }
        push(T(std::move(value)));
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
    bool fits_in_tail(size_t n, size_t limit) const
    {
        return !m_queue.empty() && write_queue_can_grow(m_queue.back()) &&
               m_queue.back().size() + n <= limit;
    }

    void charge_back(size_t n) noexcept
    {
        m_bytes = (m_bytes >= n) ? m_bytes - n : 0;
    }

    std::queue<T> m_queue;
    size_t        m_bytes{0};
};

}  // namespace socketley
