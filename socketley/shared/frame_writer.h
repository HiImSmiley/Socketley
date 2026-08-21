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
#include <cerrno>
#include <cstddef>
#include <string>
#include <string_view>
#include <unistd.h>

#include "logging.h"

class frame_writer
{
public:
    static constexpr size_t MAX_BACKLOG = 4u << 20;

    explicit frame_writer(int fd) : m_fd(fd) {}

    void set_fd(int fd) { m_fd = fd; }
    int  fd() const     { return m_fd; }

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
        flush();
        return true;
    }

    void flush()
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

    size_t pending() const { return m_out.size() - m_off; }
    bool   dead()    const { return m_dead; }
    void   mark_dead()     { m_dead = true; }

private:
    int         m_fd;
    std::string m_out;
    size_t      m_off{0};
    bool        m_full{false};
    bool        m_dead{false};
};
