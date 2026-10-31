#pragma once

// Bounded by the memory it holds rather than the entries, each charged a fixed
// overhead so empty messages are bounded too.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <queue>
#include <string>
#include <string_view>
#include <utility>
#include <sys/uio.h>

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

// How much one runtime is willing to owe in TOTAL before it starts telling
// producers to pace, which is a different question from how much it will owe ONE
// connection.  The second is a memory bound and is set per connection; the first
// is a cache question, because the bytes are written by this process and then
// read again by the kernel copying them into a socket.  L3 on the box this was
// measured on is 16 MiB shared and L2 is 4 MiB per core; at 64 streams a fixed
// half-of-8-MiB pacing point owes about 69 MB at once and both copies cost about
// 2.4x what they cost when the same work is paced to fit -- measured 315 us of
// CPU per MiB against 254, with memmove falling from 103 to 40 and the kernel's
// own copy from 87 to 43.
inline constexpr size_t write_pacing_budget = 8u * 1024 * 1024;

// And the smallest pacing point, which is the largest single entry these queues
// build: below it a producer would be told to stop before it could send one
// message.
inline constexpr size_t write_pacing_floor = 64u * 1024;

// The largest tail still grown in place once it is full, because past it a
// reallocation copies more than a new entry costs the kernel.
inline constexpr size_t write_queue_regrow_max = 4u * 1024;

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
    // A slice of a segment several connections send from, which a broadcast
    // grows in place rather than copying into every queue.
    // Held as a loan with nobody to give it back to, the segment kept alive by
    // the reference beside it.
    write_chunk(std::shared_ptr<const std::string> seg, uint32_t off, uint32_t len)
        : m_shared(std::move(seg)), m_borrowed{ m_shared->data() + off, len, nullptr, nullptr, 0 } {}
    ~write_chunk() { give_back(); }

    // A copy of a loan is bytes this copy owns, so one buffer is never given
    // back twice.
    write_chunk(const write_chunk& o)
        : m_owned(o.is_loan() ? std::string(o.m_borrowed.data, o.m_borrowed.size) : o.m_owned),
          m_shared(o.m_shared), m_borrowed(o.is_slice() ? o.m_borrowed : borrowed_bytes{})
    {
    }
    write_chunk& operator=(const write_chunk& o)
    {
        if (this != &o)
        {
            give_back();
            m_owned  = o.is_loan() ? std::string(o.m_borrowed.data, o.m_borrowed.size) : o.m_owned;
            m_shared = o.m_shared;
            m_borrowed = o.is_slice() ? o.m_borrowed : borrowed_bytes{};
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
    size_t room() const { return owns() ? m_owned.capacity() - m_owned.size() : 0; }

    void clear() { m_owned.clear(); m_shared.reset(); give_back(); }

    // For a queue that sends from an array of strings: the owned bytes, and
    // the reference that keeps a slice's segment alive while it is sent.
    std::string take_owned() { return std::move(m_owned); }
    std::shared_ptr<const std::string> take_shared() { return std::move(m_shared); }

    // Whether the bytes at `off` in `seg` follow this slice's last byte, so
    // the slice can take them by growing.
    bool continues_at(const std::string* seg, uint32_t off) const
    {
        return is_slice() && m_shared.get() == seg &&
               m_borrowed.data + m_borrowed.size == seg->data() + off;
    }
    void grow_slice(uint32_t len) { m_borrowed.size += len; }

private:
    bool is_slice() const { return m_borrowed.data && !m_borrowed.give_back; }
    bool is_loan() const { return m_borrowed.data && m_borrowed.give_back; }

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

// Where a message several connections send is written once: appended to `seg`,
// or to a fresh one when it would not fit, since a segment that grew past its
// reserve would move under the slices queues already hold -- the offset back.
constexpr size_t write_segment_bytes = 64 * 1024;
inline uint32_t place_in_segment(std::shared_ptr<std::string>& seg, std::string_view bytes)
{
    if (!seg || seg->capacity() - seg->size() < bytes.size())
    {
        seg = std::make_shared<std::string>();
        seg->reserve(bytes.size() > write_segment_bytes ? bytes.size() : write_segment_bytes);
    }
    const auto off = static_cast<uint32_t>(seg->size());
    seg->append(bytes);
    return off;
}

// place_in_segment for bytes `fill` appends, exactly `n` of them, so a frame is built where it is sent from.
template <class Fill>
inline uint32_t place_in_segment_with(std::shared_ptr<std::string>& seg, size_t n, Fill&& fill)
{
    if (!seg || seg->capacity() - seg->size() < n)
    {
        seg = std::make_shared<std::string>();
        seg->reserve(n > write_segment_bytes ? n : write_segment_bytes);
    }
    const auto off = static_cast<uint32_t>(seg->size());
    fill(*seg);
    return off;
}

inline size_t write_queue_size_of(const write_chunk& c)
{
    return c.size() + write_queue_entry_overhead;
}

// Whether the tail entry may still be appended to.  An owned string always
// may; anything holding bytes on somebody else's behalf never may, and says so
// through its own overload rather than by being special-cased here.
inline bool write_queue_can_grow(const std::string&) { return true; }
inline bool write_queue_can_grow(const write_chunk& c) { return c.owns(); }

inline size_t write_queue_room_of(const std::string& s) { return s.capacity() - s.size(); }
inline size_t write_queue_room_of(const write_chunk& c) { return c.room(); }

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
        push(T(seed(value, limit)));
    }

    // Bytes of a broadcast segment, taken by the tail slice when they follow
    // it -- a subscriber behind a busy channel then holds one entry per flush
    // and no copy at all.
    void push_slice(const std::shared_ptr<const std::string>& seg, uint32_t off, uint32_t len)
    {
        if (!m_queue.empty() && m_queue.back().continues_at(seg.get(), off))
        {
            m_queue.back().grow_slice(len);
            m_bytes += len;
            return;
        }
        push(T(seg, off, len));
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
        push(T(seed(*value, limit)));
    }

    // The same decision for a caller that owns the bytes, which is not a
    // convenience: the response path reached this queue through
    // push(std::move(buf)) and routing it through the copying form above would
    // have put an allocation and a copy on the hottest path in the runtime for
    // the sake of one shared implementation.
    // A payload and the newline that terminates it, without building the two
    // into a string first.
    //
    // The caller's alternative is a temporary whose entire allocation is
    // thrown away the moment append_back() copies out of it: malloc, one copy
    // in, one copy out, free -- for a line an echo server sends millions of
    // times a second.  Profiled on `--send-to sender` at pipeline depth 400,
    // 64-byte messages: malloc and _int_free together held 4.5 per cent of the
    // worker and string::append and push_back another 4.3.  Worth +12.5 per
    // cent of the message rate, 3.93 to 4.43 M/s, six runs per arm with the
    // ranges not overlapping -- measured over 2.5 seconds per run after a
    // warm-up, because a fixed round count finished in 0.16 s and was mostly
    // timing the ramp.
    //
    // The fallback is the same string the caller would have built, so nothing
    // changes for a payload the tail cannot take.
    void push_coalesced_line(std::string_view value, size_t limit)
    {
        if (fits_in_tail(value.size() + 1, limit))
        {
            append_back(value);
            append_back(std::string_view("\n", 1));
            return;
        }
        std::string built = seed(value, limit, 1);
        built.push_back('\n');
        push(T(std::move(built)));
    }

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
    // A new tail is sized for the backlog it joins, because a connection that
    // far behind is about to take that much again and a string grown by
    // doubling copies everything it holds at every step.
    std::string seed(std::string_view first, size_t limit, size_t extra = 0) const
    {
        std::string s;
        s.reserve(std::max(first.size() + extra, std::min(limit, m_bytes)));
        s.append(first);
        return s;
    }

    bool fits_in_tail(size_t n, size_t limit) const
    {
        if (m_queue.empty() || !write_queue_can_grow(m_queue.back()))
            return false;
        const T& tail = m_queue.back();
        return tail.size() + n <= limit &&
               (n <= write_queue_room_of(tail) || tail.size() < write_queue_regrow_max);
    }

    void charge_back(size_t n) noexcept
    {
        m_bytes = (m_bytes >= n) ? m_bytes - n : 0;
    }

    std::queue<T> m_queue;
    size_t        m_bytes{0};
};

// After a short write of `written` bytes, less than the batch holds: drops the entries sent whole and the front of the
// next, moves what is left to the front with `move_entry(to, from)`, and returns how many entries are left.  Each iovec is
// re-pointed through `bytes_of(i)`, the address entry i's bytes start at or nullptr where they do not live in the entry,
// because a string of up to 15 bytes keeps its bytes inside itself and takes them along when it moves.
template <class Move, class Bytes>
uint32_t drop_written(struct iovec* iovs, uint32_t count, size_t written, Move&& move_entry, Bytes&& bytes_of)
{
    uint32_t first = 0;
    while (first < count && written >= iovs[first].iov_len)
        written -= iovs[first++].iov_len;
    const uint32_t left = count - first;
    for (uint32_t i = 0; i < left; ++i)
    {
        const uint32_t from = first + i;
        const size_t   skip = i == 0 ? written : 0;
        char* const    at   = static_cast<char*>(iovs[from].iov_base) + skip;
        const size_t   len  = iovs[from].iov_len - skip;
        const char*    old  = bytes_of(from);
        const size_t   off  = old ? static_cast<size_t>(at - old) : 0;
        if (from != i)
            move_entry(i, from);
        // Only bytes that lived in their entry move with it; any other iovec stays where it pointed.
        const char* now = bytes_of(i);
        iovs[i].iov_base = old && now ? const_cast<char*>(now) + off : at;
        iovs[i].iov_len  = len;
    }
    return left;
}

// The same for a batch of write_chunks, whose slots past what is left are cleared so a borrowed one gives its buffer back.
inline uint32_t drop_written(write_chunk* batch, struct iovec* iovs, uint32_t count, size_t written)
{
    const uint32_t left = drop_written(
        iovs, count, written, [&](uint32_t to, uint32_t from) { batch[to] = std::move(batch[from]); },
        // An empty slot holds no bytes, and its data() is a buffer inside the slot that moves with it.
        [&](uint32_t i) -> const char* { return batch[i].size() ? batch[i].data() : nullptr; });
    for (uint32_t i = left; i < count; ++i)
        batch[i].clear();
    return left;
}

}  // namespace socketley
