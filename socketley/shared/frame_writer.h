#pragma once
// Frames out of a process, queued behind a cap so a peer that stopped reading
// cannot grow it; past the cap write() refuses and the caller must act on that.
#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <unistd.h>

#include "backlog_gate.h"
#include "event_loop.h"
#include "event_loop_definitions.h"
#include "logging.h"

class frame_writer
{
public:
    static constexpr size_t MAX_BACKLOG = 4u << 20;

    // Caps the 32-bit SQE length against an unbounded backlog.
    static constexpr size_t MAX_SEND = 1u << 20;

    explicit frame_writer(int fd) : m_fd(fd) {}

    void set_fd(int fd) { m_fd = fd; }
    int  fd() const     { return m_fd; }

    // Only after register_owner(), after which the owner must flush() once per
    // turn because write() only queues.
    void use_ring(event_loop* loop, io_handler* owner)
    {
        if (!loop || !owner || m_loop)
            return;
        m_loop  = loop;
        m_owner = owner;
        flush();
    }

    // An in-flight send is abandoned rather than rewritten, since a duplicated
    // prefix is a malformed frame.
    void leave_ring()
    {
        if (!m_loop)
            return;
        if (m_send_armed)
            m_dead = true;
        else if (m_wire_off < m_wire.size())
            m_out.insert(m_off, m_wire, m_wire_off, std::string::npos);
        m_wire.clear();
        m_wire_off = 0;
        m_loop  = nullptr;
        m_owner = nullptr;
    }

    bool on_ring()        const { return m_loop != nullptr; }
    bool send_in_flight() const { return m_send_armed; }

    // Is this completion the one this writer submitted, asked instead of
    // dispatching on the op type, which the owner's own submissions would also
    // match.
    bool owns_request(const io_request* r) const { return r == &m_send_req; }

    // `res` is a count, not a verdict: short sends are ordinary here.
    void on_send_cqe(int res)
    {
        m_send_armed = false;

        // A completion for a send abandoned by leave_ring(); m_wire is gone.
        if (!m_loop)
            return;

        if (res > 0)
        {
            m_wire_off += static_cast<size_t>(res);
            flush();                 // the rest of it, or the next batch
            return;
        }

        // Retried from the loop's next flush(): -EAGAIN is the socket being
        // full and -ECANCELED is this ring going down.
        if (res == -EAGAIN || res == -EWOULDBLOCK || res == -EINTR ||
            res == -ENOBUFS || res == -ECANCELED)
            return;

        // Everything else, including a zero-length send of a non-empty buffer,
        // is the peer being gone.
        m_dead = true;
    }

    bool write(std::string_view framed)
    {
        if (!m_gate.admit(pending(), framed.size(), MAX_BACKLOG,
                          "frame writer: backlog full; the peer is not reading"))
            return false;
        m_out.append(framed);

        // Queue only: submitting per frame ends the ring's wait for a
        // completion nobody needed, and the loop stops batching.
        if (!m_loop)
            blocking_flush();
        return true;
    }

    // write() for a frame built straight into the queue: `fill` appends
    // exactly `size` bytes, and is not called for a frame the cap refuses.
    template <class Fill>
    bool write_with(size_t size, Fill&& fill)
    {
        if (!m_gate.admit(pending(), size, MAX_BACKLOG,
                          "frame writer: backlog full; the peer is not reading"))
            return false;
        fill(m_out);
        if (!m_loop)
            blocking_flush();
        return true;
    }

    void flush()
    {
        if (m_loop)
            ring_flush();
        else
            blocking_flush();
    }

    // Everything this writer still owes the wire, in both buffers, so a byte
    // sitting in an in-flight send counts.
    size_t pending() const
    {
        return (m_out.size() - m_off) + (m_wire.size() - m_wire_off);
    }

    // Queued with nothing in the ring to move it; what a loop clamps its wait
    // on, because a refused submission is the only case needing a timeout.
    bool needs_retry() const
    {
        return m_loop && !m_send_armed && !m_dead && pending() > 0;
    }

    bool   dead()    const { return m_dead; }
    void   mark_dead()     { m_dead = true; }

private:
    void ring_flush()
    {
        // One send at a time, because two outstanding on one stream socket is
        // not a faster writer but an unordered one.
        if (m_dead || m_send_armed)
            return;

        if (m_wire_off >= m_wire.size())
        {
            m_wire.clear();
            m_wire_off = 0;
            if (m_off >= m_out.size())
            {
                m_out.clear();
                m_off = 0;
                return;                       // nothing owed
            }
            m_wire.assign(m_out, m_off, std::string::npos);
            m_out.clear();
            m_off = 0;
        }

        const size_t   left = m_wire.size() - m_wire_off;
        const uint32_t len  = static_cast<uint32_t>(std::min(left, MAX_SEND));

        m_send_req = { m_owner, nullptr, m_fd, len, op_write };
        if (!m_loop->submit_write(m_fd, m_wire.data() + m_wire_off, len, &m_send_req))
            return;   // the submission queue had nothing to give; needs_retry()

        m_send_armed = true;
    }

    void blocking_flush()
    {
        while (m_off < m_out.size())
        {
            const ssize_t n = ::write(m_fd, m_out.data() + m_off, m_out.size() - m_off);
            if (n > 0) { m_off += static_cast<size_t>(n); continue; }
            if (n < 0 && errno == EINTR)
                continue;
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                break;
            m_dead = true;          // the peer is gone; the read side ends it
            return;
        }

        // Compacted in one move: erasing the written prefix on every pass is
        // quadratic in exactly the backlog this exists to hold.
        if (m_off >= m_out.size())      { m_out.clear(); m_off = 0; }
        else if (m_off >= 64 * 1024)    { m_out.erase(0, m_off); m_off = 0; }
    }

    int          m_fd;
    std::string  m_out;
    size_t       m_off{0};
    backlog_gate m_gate;
    bool         m_dead{false};

    // Null until use_ring(); everything above works without it.
    event_loop* m_loop{nullptr};
    io_handler* m_owner{nullptr};
    io_request  m_send_req{};
    bool        m_send_armed{false};

    // What a submitted send is reading from, never touched while m_send_armed.
    std::string m_wire;
    size_t      m_wire_off{0};
};
