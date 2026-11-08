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
#include "../util/settings.h"
#include "../util/thread_buffer.h"

namespace socketley
{

namespace
{
// Where the kernel's struct tcp_info keeps what is read here, its ABI.
constexpr size_t TCPI_STATE_AT          = 0;
constexpr size_t TCPI_UNACKED_AT        = 24;
constexpr size_t TCPI_LAST_DATA_SENT_AT = 44;
constexpr size_t TCPI_NOTSENT_BYTES_AT  = 144;
static_assert(offsetof(struct tcp_info, tcpi_unacked) == TCPI_UNACKED_AT, "tcpi_unacked is at 24");
static_assert(offsetof(struct tcp_info, tcpi_last_data_sent) == TCPI_LAST_DATA_SENT_AT, "tcpi_last_data_sent is at 44");

uint32_t u32_at(const unsigned char* ti, size_t at)
{
    uint32_t v = 0;
    std::memcpy(&v, ti + at, sizeof(v));
    return v;
}
}

send_look look_at_send(int fd)
{
    send_look l;
    unsigned char ti[TCPI_NOTSENT_BYTES_AT + sizeof(uint32_t)]{};
    socklen_t     n = sizeof(ti);
    if (::getsockopt(fd, IPPROTO_TCP, TCP_INFO, ti, &n) < 0 || n < TCPI_LAST_DATA_SENT_AT + sizeof(uint32_t))
        return l;
    l.tcp     = true;
    l.state   = ti[TCPI_STATE_AT];
    l.idle_ms = u32_at(ti, TCPI_LAST_DATA_SENT_AT);
    // Segments in flight and bytes not yet sent, in one call; a kernel too old to say the second is asked the queue.
    if (n >= sizeof(ti))
        l.owed = u32_at(ti, TCPI_UNACKED_AT) + u32_at(ti, TCPI_NOTSENT_BYTES_AT);
    else if (int q = 0; ::ioctl(fd, SIOCOUTQ, &q) == 0)
        l.owed = q > 0 ? static_cast<uint32_t>(q) : 0;
    else
        l.tcp = false;
    return l;
}

std::chrono::seconds write_stall()
{
    static const auto secs =
        std::chrono::seconds(socketley::settings::number<uint64_t>("SOCKETLEY_WRITE_STALL_SECS").value_or(120));
    return secs;
}

bool send_stalled(int fd, std::chrono::milliseconds bound)
{
    return fd >= 0 && send_stalled(look_at_send(fd), bound);
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
        struct sink_site;
        constexpr size_t sink_bytes = 16384;
        char* const sink = thread_buffer<char, sink_bytes, sink_site>();
        const ssize_t n = ::recv(e.fd, sink, sink_bytes, MSG_DONTWAIT);
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

    // The peer has closed and all it sent is read, so nothing can arrive for the close to answer with a reset, and
    // the close sends the FIN itself; under kernel TLS a close still throws away what the kernel holds.
    if (drained && eof && !e.kernel_tls)
    {
        ::close(e.fd);
        e.fd = -1;
        return true;
    }

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
