#pragma once
// Frames on their way out of a process, and what happens when the far side is
// not reading.
//
// ─── WHY THIS IS SHARED AND NOT ONE MORE COPY ───────────────────────────────
//
// Written for the worker's control socket to the daemon, and lifted here whole
// when the shard mesh needed the same thing for a link to a sibling.  The two
// carry the same frames in the same direction problem: a request or a reply
// that does not fit must not be dropped silently, and a peer that has stopped
// reading must not be able to grow this process without limit.
//
// This is the rule in this tree — a second runtime needing the same behaviour
// gets a helper, not a copy — and the cost of ignoring it is countable: a
// bounded-backlog writer with a drop policy has two places to get the EAGAIN
// case wrong, and the second one is always found months later.
//
// ─── THE POLICY, WHICH IS THE PART THAT MATTERS ─────────────────────────────
//
// This was a straight write that dropped the frame on EAGAIN, which was right
// while the socket carried stats: the next push supersedes the one that did not
// fit.  It is wrong for a request or a reply.  A dropped request is answered
// "no such runtime" by the asking side — for a target that exists — and a
// dropped reply is an answer that never comes, so the origin waits until its
// client gives up.
//
// Queued and flushed as the socket takes them, with a cap so a peer that has
// stopped reading cannot grow this process without limit.  Beyond the cap
// write() refuses, and a refusal is a fact the caller has to act on rather than
// a number to log: on the mesh it is what makes a crossing fall back to the
// relay instead of vanishing.
//
// ─── AND WHY THE SEND CAN BE ON THE RING ────────────────────────────────────
//
// The policy above is unchanged.  What changed is the one line that used to put
// the bytes on the wire: a blocking ::write() from inside an event loop that
// has a ring standing right next to it.
//
// It was measured, on a cache shard answering GETs for keys another shard owns.
// One shard, 200,000 GETs over four shards, strace -f -c: 50,600 write() and
// 14,984 read() against 5,920 io_uring_enter — 1.31 blocking syscalls per GET
// that do not exist at one shard, where the same run costs 7 and 9.  Every one
// of them is a crossing: a shard's control socket carries nothing else under
// load.  The ring was already there and was carrying 0.118 entries per GET.
//
// So `use_ring()` moves the send onto it.  Nothing above this line moves: the
// cap, the refusal and what a refusal means to the caller are the same, and a
// writer that has not been given a ring behaves exactly as it did before —
// which is what the worker needs, because it sends its hello frame before there
// is a ring to send it on.
//
// ─── THE ONE THING A RING SEND MAKES HARDER, AND HOW IT IS HELD ─────────────
//
// An SQE holds a *pointer*, and the kernel reads through it at a moment this
// process does not choose.  A single std::string that is appended to while a
// send is in flight can reallocate under that pointer, and the failure is a
// send of freed memory rather than anything the caller would see.
//
// So there are two buffers and not one.  `m_wire` is what a send is reading
// from and is never touched while `m_send_armed`; `m_out` is where write()
// appends, and it is moved into m_wire only when nothing is in flight.  That
// also disposes of the compaction the blocking path needs: m_wire is consumed
// whole and then cleared.
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

    // ── Put the send on the ring ────────────────────────────────────────────
    //
    // Called once the ring exists and the owner is registered with it, and not
    // before: a submission carries its owner's token, and one made before
    // register_owner() would have its completion dropped rather than delivered.
    //
    // Whatever is already queued goes out on the ring from here.  Order is
    // preserved because m_out is drained into m_wire in one move.
    //
    // ── THE ONE THING THE CALLER OWES AFTERWARDS ────────────────────────────
    //
    // From here, write() queues and does not submit — see the note there for
    // the measurement that decided it.  So the owner must call flush() once per
    // turn of its loop, and a frame written by a turn goes out at the end of
    // that turn.  Not calling it does not lose the frame; it leaves it until
    // the next flush, which for a control socket is a reply somebody is waiting
    // for.  The worker's loop calls it unconditionally, one line after the
    // control frames are dispatched, which is where it already was.
    void use_ring(event_loop* loop, io_handler* owner)
    {
        if (!loop || !owner || m_loop)
            return;
        m_loop  = loop;
        m_owner = owner;
        flush();
    }

    // ── And take it off again, on the way down ──────────────────────────────
    //
    // The ring is about to close, and anything still queued has to travel on
    // the descriptor itself or not at all.
    //
    // A send that is in flight is the case that cannot be recovered: how much
    // of it the kernel took is not knowable until its completion lands, and
    // writing those bytes again would put a duplicated prefix into a framed
    // stream — which the far side reads as a malformed frame and treats as
    // fatal.  So the writer goes quiet instead of guessing.  A dropped frame is
    // what a full socket already costs here; a corrupted one is not, and the
    // difference is the daemon killing this worker's supervisor state versus
    // losing one frame it was about to stop caring about.
    //
    // Bytes that were queued but never submitted are put back at the front of
    // m_out, where the blocking path finds them in the order they were written.
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

        // ── Why a ring writer does NOT submit here, and a blocking one does ─
        //
        // The blocking path writes now because there is nothing else to write
        // it: the caller is the only thing that runs.
        //
        // On the ring, submitting per frame is what it looks like and is not
        // what it costs.  A send produces a completion, a completion arriving
        // on its own ends the ring's wait, and the loop then takes a whole turn
        // — and one io_uring_enter — to learn that a send it did not need an
        // answer to has finished.  Measured, four-shard cache, one shard,
        // 200,000 GETs: submitting per frame turned 5,920 entries into 61,221,
        // about one per crossing, because the loop stopped batching.  The 65,584
        // blocking syscalls it removed were paid for twice over in wakeups.
        //
        // So the send is submitted once per turn instead, by the owner's own
        // flush() — which the loop already called, for the EAGAIN backlog this
        // class has always had.  Frames written during one turn go out in ONE
        // send, which is the collapsing this change was predicted to produce
        // and did not until the submission moved.
        //
        // The contract that makes it safe is stated rather than assumed: an
        // owner that has called use_ring() MUST call flush() once per turn of
        // its loop.  Nothing here can enforce it, and what it costs to forget
        // is a frame that sits until the next write — so it is written down at
        // use_ring(), which is the only place it can be got wrong.
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
