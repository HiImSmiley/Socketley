#include "conn_transfer.h"

#include <cerrno>
#include <cstring>
#include <sys/socket.h>
#include <unistd.h>

#include "event_loop.h"
#include "logging.h"

namespace conn_transfer
{

namespace
{

// The handover's own payload, ahead of any backlog:
//   [conn_ref][u32 origin_len][origin][u32 backlog_len][backlog]
//
// Sent as one sendmsg with the descriptor attached, so a receiver either has
// the whole thing and the descriptor or has neither.  Splitting it would open a
// window where the descriptor has arrived and the name of what it is has not,
// and there is nothing useful a receiver could do with that.
void put_u32(std::string& out, uint32_t v)
{
    for (int i = 0; i < 4; ++i)
        out.push_back(static_cast<char>((v >> (8 * i)) & 0xFF));
}

bool take_u32(const char*& p, const char* end, uint32_t& out)
{
    if (end - p < 4) return false;
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i)
        v |= static_cast<uint32_t>(static_cast<uint8_t>(p[i])) << (8 * i);
    p += 4;
    out = v;
    return true;
}

// A handover message is a name, a runtime name and one socket read.  Anything
// larger is not one.
constexpr size_t max_handover_message = 2u * 1024u * 1024u;

}   // namespace

bool send_handover(int channel_fd, const handover& h, int payload_fd)
{
    if (channel_fd < 0 || payload_fd < 0 || !h.ref.valid())
        return false;

    std::string body;
    body.reserve(conn_ref_wire_size + 8 + h.origin.size() + h.backlog.size());
    put_conn_ref(body, h.ref);
    put_u32(body, static_cast<uint32_t>(h.origin.size()));
    body.append(h.origin);
    put_u32(body, static_cast<uint32_t>(h.backlog.size()));
    body.append(h.backlog);

    if (body.size() > max_handover_message)
    {
        LOG_ERROR("conn transfer: handover body too large to send");
        return false;
    }

    // Length-prefixed on the wire as well, because a stream socket may coalesce
    // two handovers into one read even though each was one sendmsg.  The
    // control message is not coalesced — the kernel truncates a read at the
    // boundary of a message carrying one — but the receiver still has to know
    // where the body ends before it can trust the next descriptor it sees.
    std::string framed;
    framed.reserve(4 + body.size());
    put_u32(framed, static_cast<uint32_t>(body.size()));
    framed.append(body);

    struct iovec iov{};
    iov.iov_base = const_cast<char*>(framed.data());
    iov.iov_len  = framed.size();

    union {
        struct cmsghdr align;
        char buf[CMSG_SPACE(sizeof(int))];
    } control{};

    struct msghdr msg{};
    msg.msg_iov        = &iov;
    msg.msg_iovlen     = 1;
    msg.msg_control    = control.buf;
    msg.msg_controllen = sizeof(control.buf);

    struct cmsghdr* cm = CMSG_FIRSTHDR(&msg);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type  = SCM_RIGHTS;
    cm->cmsg_len   = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cm), &payload_fd, sizeof(int));

    // One sendmsg, retried only on EINTR.  A short write here would split the
    // body from its descriptor, so a partial send is treated as a failed
    // handover and the caller keeps the connection it still owns — which is the
    // safe direction to fail in: a connection served by the wrong runtime is
    // recoverable, a connection served by neither is not.
    for (;;)
    {
        const ssize_t n = ::sendmsg(channel_fd, &msg, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0)
            return false;
        if (static_cast<size_t>(n) != framed.size())
        {
            LOG_WARN("conn transfer: handover was sent short, keeping the connection");
            return false;
        }
        return true;
    }
}

bool recv_handover(int channel_fd, handover& h, int& out_fd)
{
    out_fd = -1;
    if (channel_fd < 0)
        return false;

    // Read the length first, without the control message, so the body can be
    // sized before it is taken.  MSG_PEEK is what makes that possible without a
    // buffer that has to survive between calls: the descriptor stays queued
    // with its message until the real recvmsg below.
    uint32_t body_len = 0;
    {
        char lenbuf[4];
        struct iovec iov{lenbuf, sizeof(lenbuf)};
        struct msghdr msg{};
        msg.msg_iov    = &iov;
        msg.msg_iovlen = 1;

        ssize_t n;
        for (;;)
        {
            n = ::recvmsg(channel_fd, &msg, MSG_PEEK | MSG_CMSG_CLOEXEC);
            if (n < 0 && errno == EINTR) continue;
            break;
        }
        if (n != 4)
            return false;

        const char* p = lenbuf;
        if (!take_u32(p, lenbuf + 4, body_len))
            return false;
        if (body_len > max_handover_message)
        {
            LOG_ERROR("conn transfer: refusing a handover that claims an impossible size");
            return false;
        }
    }

    std::string frame_buf;
    frame_buf.resize(4 + body_len);

    struct iovec iov{};
    iov.iov_base = frame_buf.data();
    iov.iov_len  = frame_buf.size();

    union {
        struct cmsghdr align;
        char buf[CMSG_SPACE(sizeof(int))];
    } control{};

    struct msghdr msg{};
    msg.msg_iov        = &iov;
    msg.msg_iovlen     = 1;
    msg.msg_control    = control.buf;
    msg.msg_controllen = sizeof(control.buf);

    ssize_t n;
    for (;;)
    {
        // MSG_CMSG_CLOEXEC on the way in, always.  A descriptor received here
        // and then inherited by a fork/exec is a socket the child holds open
        // for ever, and the peer's close never becomes an EOF for anybody.
        n = ::recvmsg(channel_fd, &msg, MSG_CMSG_CLOEXEC);
        if (n < 0 && errno == EINTR) continue;
        break;
    }
    if (n <= 0 || static_cast<size_t>(n) != frame_buf.size())
        return false;

    int fd = -1;
    for (struct cmsghdr* cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm))
    {
        if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS &&
            cm->cmsg_len == CMSG_LEN(sizeof(int)))
        {
            memcpy(&fd, CMSG_DATA(cm), sizeof(int));
            break;
        }
    }
    if (fd < 0)
        return false;

    const char* p   = frame_buf.data() + 4;
    const char* end = frame_buf.data() + frame_buf.size();

    conn_ref ref{};
    uint32_t origin_len = 0, backlog_len = 0;
    if (!take_conn_ref(p, end, ref) || !take_u32(p, end, origin_len) ||
        static_cast<size_t>(end - p) < origin_len)
    {
        ::close(fd);
        return false;
    }
    std::string origin(p, origin_len);
    p += origin_len;

    if (!take_u32(p, end, backlog_len) || static_cast<size_t>(end - p) < backlog_len)
    {
        ::close(fd);
        return false;
    }

    if (!ref.valid())
    {
        // A descriptor with no name is a descriptor nothing can ever route to
        // or close on purpose.  Closing it is the only answer that does not
        // leak it.
        LOG_WARN("conn transfer: handover carried no connection name, dropping it");
        ::close(fd);
        return false;
    }

    h.ref     = ref;
    h.origin  = std::move(origin);
    h.backlog.assign(p, backlog_len);
    out_fd    = fd;
    return true;
}

void withdraw(event_loop* loop, int fd)
{
    if (!loop || fd < 0)
        return;
    if (loop->fd_inflight(fd) == 0)
        return;

    // Once.  See the header: a cancel submitted every turn is the completion
    // the next drain consumes, so the read being cancelled is never given a
    // turn to report and the descriptor is never released.  That was measured
    // rather than reasoned — fifty drains, fifty cancel completions, the read
    // still armed at the end of them.
    loop->submit_cancel_fd(fd);
}

bool relinquish(event_loop* loop, int fd)
{
    if (fd < 0)
        return true;

    if (loop)
    {
        // The whole reason this is not just close().  An SQE holds the
        // descriptor NUMBER and the kernel resolves it when it consumes the
        // SQE; closing before that happens does not cancel the operation, it
        // aims it at whatever takes the number next.  After a handover the
        // receiver is writing to this socket, so a read still armed here would
        // also be stealing bytes that belong to it.
        //
        // No cancel is submitted here.  Withdrawing is the caller's decision
        // and has to happen exactly once; this only reports whether it has
        // taken effect yet.
        if (loop->fd_inflight(fd) > 0)
            return false;

        loop->close_fd(fd);
        return true;
    }

    ::close(fd);
    return true;
}

// ── Relay ───────────────────────────────────────────────────────────────────

std::string relay_frame(relay_op op, const conn_ref& ref, std::string_view payload)
{
    std::string out;
    out.reserve(relay_header_size + payload.size());
    put_u32(out, static_cast<uint32_t>(payload.size()));
    out.push_back(static_cast<char>(op));
    put_conn_ref(out, ref);
    out.append(payload);
    return out;
}

bool take_relay_frame(std::string& buf, relay_op& op, conn_ref& ref,
                      std::string& payload, bool& fatal)
{
    fatal = false;
    if (buf.size() < relay_header_size)
        return false;

    const char* p   = buf.data();
    const char* end = buf.data() + buf.size();

    uint32_t len = 0;
    if (!take_u32(p, end, len))
        return false;

    if (len > relay_max_payload)
    {
        fatal = true;
        return false;
    }

    op = static_cast<relay_op>(static_cast<uint8_t>(*p));
    ++p;

    if (!take_conn_ref(p, end, ref))
        return false;

    if (buf.size() < relay_header_size + len)
        return false;

    payload.assign(buf, relay_header_size, len);
    buf.erase(0, relay_header_size + len);
    return true;
}

}   // namespace conn_transfer
