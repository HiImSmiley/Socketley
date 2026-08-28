#pragma once
// Frames on their way out of a process, and what happens when the far side is
// not reading.
//
// Queued and flushed as the socket takes them, with a cap so a peer that has
// stopped reading cannot grow this process without limit.  Beyond the cap
// write() refuses, and a refusal is a fact the caller must act on -- on the
// mesh it is what makes a crossing fall back to the relay instead of vanishing.
//
// use_ring() puts the send on the ring; everything above is unchanged, and a
// writer with no ring behaves exactly as before.
//
// Two buffers, not one: an SQE holds a pointer the kernel reads later, so
// `m_wire` is never touched while a send is armed and `m_out` is what write()
// appends to.
#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <unistd.h>

#include "event_loop.h"
#include "event_loop_definitions.h"
#include "logging.h"

class frame_writer
{
public:
    static constexpr size_t MAX_BACKLOG = 4u << 20;

    // The largest single send this will submit.  A cap at all because the
    // length field of an SQE is 32 bits and the backlog is not, and this one
    // because it is far above any frame this socket carries — it bounds nothing
    // in practice and is here so the cast below cannot be the thing that is
    // wrong.
    static constexpr size_t MAX_SEND = 1u << 20;

    explicit frame_writer(int fd) : m_fd(fd) {}

    void set_fd(int fd) { m_fd = fd; }
    int  fd() const     { return m_fd; }

    // Put the send on the ring.  Only after register_owner(), or the completion
    // is dropped rather than delivered.
    //
    // AFTERWARDS THE OWNER MUST CALL flush() ONCE PER TURN of its loop: from
    // here write() queues and does not submit.  Forgetting leaves the frame
    // until the next flush, which on a control socket is a reply someone waits
    // for.
    void use_ring(event_loop* loop, io_handler* owner)
    {
        if (!loop || !owner || m_loop)
            return;
        m_loop  = loop;
        m_owner = owner;
        flush();
    }

    // Take the send off the ring on the way down.  A send already in flight is
    // abandoned rather than rewritten: how much the kernel took is unknowable
    // until its completion lands, and a duplicated prefix is a malformed frame.
    // Queued-but-unsubmitted bytes go back to the front of m_out.
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

    // Is this completion the one this writer submitted?  The owner dispatches
    // on it rather than on the op type: the same handler has other submissions
    // of its own and they must not be confused for a send that finished.
    bool owns_request(const io_request* r) const { return r == &m_send_req; }

    // ── A send that finished ────────────────────────────────────────────────
    //
    // Short sends are ordinary on a stream socket, so `res` is a count and not
    // a verdict: what it did not take stays at the front of m_wire and the next
    // submission continues from there.
    void on_send_cqe(int res)
    {
        m_send_armed = false;

        // The completion of a send this writer has already given up on, in the
        // window between leave_ring() and the ring closing.  m_wire is gone and
        // the verdict was taken there; advancing an offset into a cleared
        // buffer here would take pending() below zero.
        if (!m_loop)
            return;

        if (res > 0)
        {
            m_wire_off += static_cast<size_t>(res);
            flush();                 // the rest of it, or the next batch
            return;
        }

        // Retried from the loop's next flush().  -EAGAIN is the socket being
        // full, which is the case the backlog above exists for; -ECANCELED is
        // this ring going down, and there is no next flush to do it any harm.
        if (res == -EAGAIN || res == -EWOULDBLOCK || res == -EINTR ||
            res == -ENOBUFS || res == -ECANCELED)
            return;

        // Everything else — including a zero-length send of a non-empty buffer
        // — is the peer being gone.  The read side is what acts on it.
        m_dead = true;
    }

    bool write(std::string_view framed)
    {
        if (pending() + framed.size() > MAX_BACKLOG)
        {
            if (!m_full)
            {
                LOG_WARN("frame writer: backlog full; the peer is not reading");
                m_full = true;
            }
            return false;
        }
        m_full = false;
        m_out.append(framed);

        // A ring writer queues and does not submit: submitting per frame ends
        // the ring's wait for a completion nobody needed, so the loop stops
        // batching.  flush() sends one turn's frames in one send; see
        // use_ring() for the contract that makes it safe.
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

    // Everything this writer still owes the wire, in both buffers.  The caller
    // uses it to decide whether its loop may sleep, so a byte sitting in an
    // in-flight send counts: it has not been handed over yet.
    size_t pending() const
    {
        return (m_out.size() - m_off) + (m_wire.size() - m_wire_off);
    }

    // Queued, and nothing in the ring will move it on its own.  This is what a
    // loop clamps its wait on: an in-flight send ends with a completion, so it
    // needs no timeout, and a submission that get_sqe() refused needs exactly
    // one.
    bool needs_retry() const
    {
        return m_loop && !m_send_armed && !m_dead && pending() > 0;
    }

    bool   dead()    const { return m_dead; }
    void   mark_dead()     { m_dead = true; }

private:
    void ring_flush()
    {
        // One send at a time.  Two outstanding on one stream socket is not a
        // faster writer, it is an unordered one: the kernel may take them in
        // either order and the far side reads the frames interleaved.
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

    int         m_fd;
    std::string m_out;
    size_t      m_off{0};
    bool        m_full{false};
    bool        m_dead{false};

    // Null until use_ring(); everything above works without it.
    event_loop* m_loop{nullptr};
    io_handler* m_owner{nullptr};
    io_request  m_send_req{};
    bool        m_send_armed{false};

    // What a submitted send is reading from.  Never touched while m_send_armed
    // — see the note at the top about a pointer the kernel reads through.
    std::string m_wire;
    size_t      m_wire_off{0};
};
