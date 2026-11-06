#include "orderly_close.h"

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstring>

#include <linux/sockios.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../loop/event_loop.h"

namespace socketley
{

namespace
{
// Where the kernel's struct tcp_info keeps tcpi_state and tcpi_last_data_sent, its ABI.
constexpr size_t TCPI_STATE_AT          = 0;
constexpr size_t TCPI_LAST_DATA_SENT_AT = 44;
static_assert(offsetof(struct tcp_info, tcpi_last_data_sent) == TCPI_LAST_DATA_SENT_AT,
              "tcpi_last_data_sent is at 44 in the kernel's struct tcp_info");
}

send_look look_at_send(int fd)
{
    send_look l;
    unsigned char ti[TCPI_LAST_DATA_SENT_AT + sizeof(uint32_t)]{};
    socklen_t     n = sizeof(ti);
    if (::getsockopt(fd, IPPROTO_TCP, TCP_INFO, ti, &n) < 0 || n < sizeof(ti))
        return l;
    int owed = 0;
    if (::ioctl(fd, SIOCOUTQ, &owed) < 0)
        return l;
    l.tcp   = true;
    l.owed  = owed > 0 ? static_cast<uint32_t>(owed) : 0;
    l.state = ti[TCPI_STATE_AT];
    std::memcpy(&l.idle_ms, ti + TCPI_LAST_DATA_SENT_AT, sizeof(l.idle_ms));
    return l;
}

bool send_stalled(int fd, std::chrono::milliseconds bound)
{
    int owed = 0;
    // The cheap question first, since a connection with nothing owed is most of those asked.
    if (fd < 0 || ::ioctl(fd, SIOCOUTQ, &owed) < 0 || owed <= 0)
        return false;
    return send_stalled(look_at_send(fd), bound);
}

bool peer_has_closed(uint8_t s)
{
    return s == TCP_CLOSE_WAIT || s == TCP_LAST_ACK || s == TCP_CLOSING || s == TCP_TIME_WAIT || s == TCP_CLOSE;
}

orderly_close::~orderly_close()
{
    for (auto& e : m_held)
        if (e->fd >= 0)
            ::close(e->fd);
}

void orderly_close::take(int fd, bool kernel_tls)
{
    if (fd < 0)
        return;
    ++m_taken;
    auto e = std::make_unique<entry>();
    e->fd         = fd;
    e->kernel_tls = kernel_tls;
    e->since      = e->heard = std::chrono::steady_clock::now();
    if (advance(*e))
        return;
    // Nothing to wait with, or too many waiting: closed as before, its tail at the kernel's mercy.
    if (m_held.size() >= max_held || !arm(*e))
    {
        ::close(fd);
        return;
    }
    ++m_waited;
    e->index = m_held.size();
    m_held.push_back(std::move(e));
}

bool orderly_close::advance(entry& e)
{
    const auto now = std::chrono::steady_clock::now();
    // What the peer sends is read away, so none is left unread for the close to answer with a reset.
    bool drained = false, eof = false;
    for (int i = 0; i < 64; ++i)
    {
        static thread_local char sink[16384];
        const ssize_t n = ::recv(e.fd, sink, sizeof(sink), MSG_DONTWAIT);
        if (n > 0)
        {
            e.drained += static_cast<uint64_t>(n);
            e.heard    = now;
            if (e.drained > drain_limit)
                break;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        // An error is a connection the kernel has ended already, and nothing is left to keep.
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
        {
            ::close(e.fd);
            e.fd = -1;
            return true;
        }
        drained = true;
        eof     = n == 0;
        break;
    }
    e.input_left = !drained;

    if (!e.write_shut)
    {
        // Under kernel TLS the FIN waits until the kernel has handed TCP every record it took.
        if (e.kernel_tls)
        {
            const send_look l = look_at_send(e.fd);
            if (l.tcp && l.owed > 0 && !send_stalled(l, stall) && e.drained <= drain_limit)
                return false;
        }
        if (::shutdown(e.fd, SHUT_WR) < 0) {}
        e.write_shut = true;
    }

    // The peer has closed and all it sent is read: nothing more can arrive for the close to answer with a reset.
    bool done = drained && eof;
    bool give_up = false;
    if (!done)
    {
        const send_look l = look_at_send(e.fd);
        // A unix socket's bytes are in its peer's queue already, and nothing it sends later resets anything.
        done = !l.tcp || (drained && peer_has_closed(l.state)) ||
               // All it was sent is acknowledged, and it has been quiet long enough to be read as done sending.
               (l.owed == 0 && drained && now - e.heard >= quiet);
        give_up = !done && (send_stalled(l, stall) || e.drained > drain_limit ||
                            (l.owed == 0 && now - e.since >= linger_most));
    }
    if (!done && !give_up)
        return false;
    // Reset, so the peer learns of the end and the kernel keeps no orphan sending what it will not take.
    if (give_up)
    {
        const linger now_reset{1, 0};
        if (::setsockopt(e.fd, SOL_SOCKET, SO_LINGER, &now_reset, sizeof now_reset) < 0) {}
    }
    ::close(e.fd);
    e.fd = -1;
    return true;
}

bool orderly_close::arm(entry& e)
{
    const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(e.wait).count();
    e.ts.tv_sec  = ns / 1000000000;
    e.ts.tv_nsec = ns % 1000000000;
    e.req        = io_request{};
    e.req.owner  = this;
    e.req.type   = op_timeout;
    return m_loop.submit_timeout(&e.ts, &e.req);
}

void orderly_close::on_cqe(struct io_uring_cqe* cqe)
{
    auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
    if (!req)
        return;
    // req is the first member, so this is the entry it belongs to.
    auto* e = reinterpret_cast<entry*>(req);
    if (e->index >= m_held.size() || m_held[e->index].get() != e)
        return;
    if (advance(*e))
    {
        drop(e);
        return;
    }
    // A peer still sending is read again soon, so it is not held back; a quiet one is looked at less and less often.
    e->wait = e->input_left ? std::chrono::milliseconds(10) : std::min(e->wait * 2, std::chrono::milliseconds(1000));
    if (!arm(*e))
    {
        ::close(e->fd);
        e->fd = -1;
        drop(e);
    }
}

void orderly_close::drop(entry* e)
{
    const size_t i = e->index;
    if (i + 1 != m_held.size())
    {
        m_held[i] = std::move(m_held.back());
        m_held[i]->index = i;
    }
    m_held.pop_back();
}

}   // namespace socketley
