#pragma once
// Keepalive as this tree tunes it, in one place because a peer that loses power
// sends nothing and every listener owes the same answer to that.
#include <cerrno>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string_view>
#include <sys/socket.h>

namespace socket_tuning {

// 60/10/3: silence for a minute, then three probes ten seconds apart.  This
// reaps a connection whose peer is gone and leaves one that is merely quiet,
// which is the distinction --idle-timeout cannot make and the reason it is not
// a substitute.
//
// Every failure is ignored on purpose: a kernel without one of the TCP_KEEP*
// knobs still keeps the connection alive on its own defaults, and there is
// nothing useful to do about it on an accept path.
inline void keepalive_dead_peer(int fd)
{
    int on = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on)) < 0) {}

    int idle = 60, intvl = 10, cnt = 3;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE,  &idle,  sizeof(idle))  < 0) {}
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl)) < 0) {}
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT,   &cnt,   sizeof(cnt))   < 0) {}
}

// The options an accepted TCP socket takes from its listener, set once there
// instead of once per connection.  Linux clones the listener's `sock` on
// accept, so nonagle, SOCK_KEEPOPEN with its three timers and both buffer
// sizes are already on every child.
//
// Verified on this kernel rather than assumed: a listener carrying all of them
// hands each accepted socket exactly those values, while a plain listener's
// children get the defaults (nodelay off, keepalive off, 7200/75/9).
//
// AF_UNIX is NOT the same, and that is why this is named for TCP: an accepted
// unix socket takes the default receive buffer whatever its listener holds, so
// a unix accept path still sets its own.
//
// Fixing the buffer sizes turns off TCP autotuning by setting SOCK_*BUF_LOCK.
// That is unchanged by moving it here -- every accepted socket was locked
// individually before -- but it is a decision, and it now sits in one place
// where it can be revisited.
inline void tcp_listener_defaults(int fd, int rcvbuf, int sndbuf)
{
    int on = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) < 0) {}

    keepalive_dead_peer(fd);

    if (rcvbuf > 0)
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {}
    if (sndbuf > 0)
        if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) < 0) {}
}

// The round trip the kernel has measured on a connection, in microseconds, 0 before it has one.
inline uint32_t rtt_us(int fd)
{
    struct tcp_info ti{};
    socklen_t n = sizeof(ti);
    return getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &n) == 0 ? ti.tcpi_rtt : 0;
}

// On a path with a round trip, what a connection has framed waits in its own queue, where a frame made later may go
// ahead of it, and not in the kernel's buffer behind it; on a LAN that buffer drains as fast as it fills, and holding
// it short would only cap the rate. True where it was held short, which is when the caller bounds its writes too.
inline bool fit_to_path(int fd)
{
    if (rtt_us(fd) < 1000)
        return false;
    const int lowat = 16 * 1024;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, &lowat, sizeof(lowat)) < 0) {}
    return true;
}

// The congestion control a listener's accepted sockets run, which they take from it as they take the options above:
// 0, or the errno the kernel refused it with -- EPERM for one not in net.ipv4.tcp_allowed_congestion_control to a
// process without CAP_NET_ADMIN, ENOENT for one this kernel does not have.
inline int congestion(int fd, std::string_view name)
{
    if (name.empty())
        return 0;
    return setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, name.data(), static_cast<socklen_t>(name.size())) < 0 ? errno : 0;
}

}  // namespace socket_tuning
