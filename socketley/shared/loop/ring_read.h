#pragma once
// A connection's reads off the ring, decided in one place: a multishot recv lent its buffers by the loop's buffer
// ring, a single provided-buffer recv where the multishot cannot be armed, and a single read into the owner's own
// buffer where the ring has none to lend; the owner arms it, takes each completion, and asks a standing one to end.
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

#include "event_loop.h"

namespace socketley
{

// The loop's buffer group a runtime type reads from, one per type in a process, and its geometry.
struct ring_group
{
    uint16_t id;
    uint32_t bufs;
    uint32_t bytes;
};

// One connection's read: its request and how it stands.
struct ring_read
{
    io_request req{};
    bool pending{false};
    // A multishot recv stands, and its withdrawal has been asked for.
    bool multi{false}, cancel{false};
    // The ring had no buffer to lend, so the next read brings the owner's own.
    bool own_next{false};
    // The owner's buffer a single read is reading into.
    char* own{nullptr};
};

// What one completion brought, with the ring's buffer it lent given back when this goes.
class ring_bytes
{
public:
    enum class kind : uint8_t
    {
        data,
        // The far side wrote its last.
        eof,
        failed,
        // Ended by a withdrawal, to be armed again when a read is wanted.
        withdrawn,
        // The ring had no buffer to lend; the next arm reads into the owner's own.
        no_buffer,
    };

    ring_bytes() = default;
    ring_bytes(const ring_bytes&) = delete;
    ring_bytes& operator=(const ring_bytes&) = delete;
    ring_bytes(ring_bytes&& o) noexcept { *this = std::move(o); }
    ring_bytes& operator=(ring_bytes&& o) noexcept
    {
        if (this != &o)
        {
            give_back();
            m_loop = std::exchange(o.m_loop, nullptr);
            m_group = o.m_group;
            m_bid = o.m_bid;
            m_p = o.m_p;
            m_n = o.m_n;
            what = o.what;
            res = o.res;
            more = o.more;
        }
        return *this;
    }
    ~ring_bytes() { give_back(); }

    kind what{kind::failed};
    int res{0};
    // The multishot recv still stands and brings more.
    bool more{false};

    const char* data() const { return m_p; }
    size_t size() const { return m_n; }
    std::string_view view() const { return {m_p, m_n}; }

    // The buffer back to the ring now, for an owner that has taken the bytes and goes on to work that may arm again.
    void give_back()
    {
        if (m_loop)
            m_loop->return_buf(m_group, m_bid);
        m_loop = nullptr;
        m_p = nullptr;
        m_n = 0;
    }

private:
    friend class ring_reader;
    event_loop* m_loop{nullptr};
    uint16_t m_group{0};
    uint16_t m_bid{0};
    const char* m_p{nullptr};
    size_t m_n{0};
};

// How the owner wants this read armed.
struct ring_arm
{
    // From the ring, when it lends; false for a read that must land in a buffer of the owner's.
    bool ring{true};
    // A standing multishot recv; false for a single recv, as for a connection that may ask once and close.
    bool multishot{true};
    // The last read left the socket empty (event_loop::recv_drained), so a single recv waits for data first.
    bool poll_first{false};
};

// A runtime's reads: its loop, its buffer group, and whether the loop lends from it.
class ring_reader
{
public:
    ring_reader(event_loop& loop, ring_group g) : m_loop(loop), m_g(g) {}
    // A reader that never lends: every read lands in the owner's own buffer.
    explicit ring_reader(event_loop& loop) : m_loop(loop), m_g{0, 0, 0} {}

    // The group set up on this loop, once per process for the type; false leaves every read on the owner's buffers.
    bool setup()
    {
        m_lends = m_g.bufs != 0 && m_loop.setup_buf_ring(m_g.id, m_g.bufs, m_g.bytes);
        return m_lends;
    }
    // The same with `bufs` buffers in place of the group's own count, zero taking the ring away.
    bool setup(uint32_t bufs)
    {
        m_g.bufs = bufs;
        return setup();
    }
    bool lends() const { return m_lends; }
    const ring_group& group() const { return m_g; }

    // A read armed on `fd` for `owner`, with `tag` as the request's buffer for the owner to find its connection by;
    // `own()` gives {buffer, length} for a read into the owner's own, called only when one is armed, and may give
    // {nullptr, 0} for an owner that has none.  False when the ring had no room, with nothing armed.
    template <class Own>
    bool arm(ring_read& r, io_handler* owner, void* tag, int fd, const ring_arm& how, Own&& own)
    {
        r.req = io_request{};
        r.req.owner = owner;
        r.req.buffer = static_cast<char*>(tag);
        r.req.fd = fd;
        r.req.type = op_read;
        r.multi = r.cancel = false;
        r.own = nullptr;
        const bool ring = m_lends && how.ring;
        bool queued = ring && !r.own_next && lend(r, fd, how);
        if (!queued)
        {
            const auto [p, n] = own();
            if (p)
            {
                r.req.type = op_read;
                r.req.buf_group = NO_BUF_GROUP;
                r.own = p;
                queued = m_loop.submit_read(fd, p, static_cast<uint32_t>(n), &r.req, how.poll_first);
            }
        }
        // An owner with no buffer of its own after the ring ran dry asks the ring again.
        if (!queued && ring && r.own_next)
            queued = lend(r, fd, how);
        r.own_next = false;
        r.pending = queued;
        return queued;
    }

    // The completion of `r`'s read, its buffer given back on every way out unless the owner keeps the result.
    ring_bytes take(ring_read& r, const struct io_uring_cqe* cqe)
    {
        ring_bytes b;
        const bool lent = r.req.type != op_read;
        b.more = lent && (cqe->flags & IORING_CQE_F_MORE) != 0;
        b.res = cqe->res;
        if (!b.more)
        {
            r.pending = false;
            r.multi = false;
            r.cancel = false;
        }
        if (lent && (cqe->flags & IORING_CQE_F_BUFFER))
        {
            b.m_loop = &m_loop;
            b.m_group = r.req.buf_group;
            b.m_bid = static_cast<uint16_t>(cqe->flags >> IORING_CQE_BUFFER_SHIFT);
        }
        if (b.res > 0)
        {
            b.what = ring_bytes::kind::data;
            b.m_p = lent ? (b.m_loop ? m_loop.get_buf_ptr(b.m_group, b.m_bid) : nullptr) : r.own;
            b.m_n = b.m_p ? static_cast<size_t>(b.res) : 0;
            // A lent recv that named no buffer the pool has cannot be read, and is a failure rather than lost bytes.
            if (!b.m_p)
                b.what = ring_bytes::kind::failed;
        }
        else if (b.res == 0)
            b.what = ring_bytes::kind::eof;
        else if (b.res == -ENOBUFS && lent && !b.more)
        {
            b.what = ring_bytes::kind::no_buffer;
            r.own_next = true;
        }
        else if (b.res == -ECANCELED && !b.more)
            b.what = ring_bytes::kind::withdrawn;
        else
            b.what = ring_bytes::kind::failed;
        return b;
    }

    // A standing multishot recv asked to end; a single read ends by itself.  Asked again at the next completion
    // when the ring has no room for the withdrawal.
    bool withdraw(ring_read& r)
    {
        if (r.pending && r.multi && !r.cancel && m_loop.submit_cancel_request(&r.req))
            r.cancel = true;
        return r.cancel;
    }

private:
    bool lend(ring_read& r, int fd, const ring_arm& how)
    {
        bool queued = false;
        // Asked of the loop each time, because a kernel that refuses the flag turns it off after start.
        if (how.multishot && m_loop.recv_multishot_enabled())
            queued = r.multi = m_loop.submit_recv_multishot(fd, m_g.id, &r.req);
        if (!queued)
            queued = m_loop.submit_read_provided(fd, m_g.id, &r.req, how.poll_first);
        return queued;
    }

    event_loop& m_loop;
    ring_group m_g;
    bool m_lends{false};
};

// The bytes a completion brought, parsed where they lie when nothing is left over from before, so only what a
// message spanning completions needs is copied into `in`; `parse(view)` answers how much of the view it used, and is
// called once, on the bytes or on `in` with them appended.
template <class Parse>
void take_into(std::string& in, std::string_view got, Parse&& parse)
{
    if (in.empty())
    {
        const size_t used = parse(got);
        if (used < got.size())
            in.append(got.data() + used, got.size() - used);
        return;
    }
    in.append(got.data(), got.size());
    const size_t used = parse(std::string_view(in));
    in.erase(0, used);
}

}   // namespace socketley
