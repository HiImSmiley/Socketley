#pragma once
// How one runtime's process is handed a socket to another's: one SEQPACKET
// socketpair per worker whose only cargo is the end of a link, because the
// control socket's reads are a standing recv and a recv with no control buffer
// drops the ancillary data a descriptor travels in.
//
// SEQPACKET and not SOCK_STREAM: two grants on a stream may coalesce into one
// read, and only the first one's descriptor arrives with it.
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <functional>
#include <string>
#include <string_view>

#include "event_loop.h"
#include "event_loop_definitions.h"
#include "logging.h"

namespace socketley::peer_link
{

// A runtime name is the whole message, so this is the message limit too.
inline constexpr size_t max_name = 128;

// The one cargo on this channel that is not a peer: the descriptor of an
// operator's interactive session, handed to the worker so notify_interactive()
// can write to their terminal directly.  A marker rather than a second channel
// because the mechanism is identical -- one descriptor, one short message --
// and '@' is what makes it unambiguous: runtime_manager::valid_name() allows
// only [alnum], '-', '_' and '.', so no runtime can ever be called this.
inline constexpr std::string_view interactive_marker = "@i";

// The daemon's side.  Never blocking: this runs on the daemon's event-loop
// thread, and a worker that has stopped reading its grant channel must cost a
// refused introduction rather than the whole daemon.  A refusal leaves the two
// runtimes relaying, which is where they already were.
inline bool grant(int chan_fd, std::string_view peer, int link_fd)
{
    if (chan_fd < 0 || link_fd < 0 || peer.empty() || peer.size() >= max_name)
        return false;

    struct iovec iov{};
    iov.iov_base = const_cast<char*>(peer.data());
    iov.iov_len  = peer.size();

    // alignas, because CMSG_FIRSTHDR reads a struct cmsghdr out of this buffer
    // and a plain char array is aligned to 1.  The sanitizer catches it; a
    // release build reads a misaligned struct and gets away with it on x86.
    alignas(struct cmsghdr) char ctl[CMSG_SPACE(sizeof(int))]{};
    struct msghdr msg{};
    msg.msg_iov        = &iov;
    msg.msg_iovlen     = 1;
    msg.msg_control    = ctl;
    msg.msg_controllen = sizeof ctl;

    struct cmsghdr* c = CMSG_FIRSTHDR(&msg);
    if (!c)
        return false;
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type  = SCM_RIGHTS;
    c->cmsg_len   = CMSG_LEN(sizeof(int));
    std::memcpy(CMSG_DATA(c), &link_fd, sizeof(int));

    ssize_t n;
    do { n = ::sendmsg(chan_fd, &msg, MSG_NOSIGNAL | MSG_DONTWAIT); }
    while (n < 0 && errno == EINTR);

    return n == static_cast<ssize_t>(peer.size());
}

// The worker's side: a standing recvmsg on the ring, one grant at a time.
// Re-armed after each, and a grant that arrives while none is armed waits in
// the socket rather than being lost.
class receiver : public io_handler
{
public:
    // What to do with one grant; the descriptor is the callee's from here.
    using on_grant = std::function<void(std::string peer, int fd)>;

    receiver(int fd, on_grant cb) : m_fd(fd), m_cb(std::move(cb)) {}

    ~receiver() override
    {
        if (m_fd >= 0 && !m_loop)
            ::close(m_fd);
    }

    receiver(const receiver&)            = delete;
    receiver& operator=(const receiver&) = delete;

    // register_owner() before the submission, because a submission whose owner
    // is unset has its completion dropped and this channel would then be deaf
    // for the life of the process.
    bool attach(event_loop& loop)
    {
        m_loop = &loop;
        loop.register_owner(this);
        arm();
        return m_armed;
    }

    bool armed() const { return m_armed; }

    // A refused submission is not a dead channel, so the worker's loop calls
    // this on the turns it clamps its wait.
    void pump()
    {
        if (!m_armed)
            arm();
    }

    void on_cqe(struct io_uring_cqe* cqe) override
    {
        auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
        if (req != &m_req)
            return;

        m_armed = false;
        const int res = cqe->res;

        // The daemon closed its end, which happens when this worker is being
        // torn down; nothing to say and nothing to re-arm.
        if (res == 0 || res == -ECANCELED || res == -EBADF)
            return;

        if (res < 0)
        {
            if (res != -EINTR && res != -EAGAIN)
                LOG_WARN(("peer links: the grant channel failed ("
                          + std::string(std::strerror(-res)) + ")").c_str());
            arm();
            return;
        }

        std::string peer;
        const int fd = take(res, peer);
        arm();
        if (fd >= 0 && m_cb)
            m_cb(std::move(peer), fd);
    }

private:
    void arm()
    {
        if (!m_loop || m_armed || m_fd < 0 || !m_loop->ring_open())
            return;

        m_iov.iov_base        = m_name;
        m_iov.iov_len         = sizeof m_name;
        m_msg                 = {};
        m_msg.msg_iov         = &m_iov;
        m_msg.msg_iovlen      = 1;
        m_msg.msg_control     = m_ctl;
        m_msg.msg_controllen  = sizeof m_ctl;

        m_req   = { this, nullptr, m_fd, 0, op_recvmsg };
        m_armed = m_loop->submit_recvmsg(m_fd, &m_msg, &m_req);
    }

    // The descriptor out of one completed grant, or -1 with nothing left open.
    int take(int res, std::string& peer)
    {
        int fd = -1;
        for (struct cmsghdr* c = CMSG_FIRSTHDR(&m_msg); c;
             c = CMSG_NXTHDR(&m_msg, c))
        {
            if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS
                && c->cmsg_len == CMSG_LEN(sizeof(int)))
                std::memcpy(&fd, CMSG_DATA(c), sizeof fd);
        }

        // MSG_CTRUNC says the kernel dropped what it could not fit, and a
        // half-taken grant is a descriptor nobody closes.
        const bool truncated = (m_msg.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) != 0;
        if (truncated || res <= 0 || res >= static_cast<int>(sizeof m_name))
        {
            if (fd >= 0)
                ::close(fd);
            LOG_WARN("peer links: a grant arrived truncated and was refused");
            return -1;
        }

        peer.assign(m_name, static_cast<size_t>(res));
        if (peer.empty() && fd >= 0)
        {
            ::close(fd);
            return -1;
        }
        return fd;
    }

    int         m_fd{-1};
    on_grant    m_cb;
    event_loop* m_loop{nullptr};
    io_request  m_req{};
    bool        m_armed{false};

    char           m_name[max_name]{};
    alignas(struct cmsghdr) char m_ctl[CMSG_SPACE(sizeof(int))]{};
    struct iovec   m_iov{};
    struct msghdr  m_msg{};
};

}   // namespace socketley::peer_link
