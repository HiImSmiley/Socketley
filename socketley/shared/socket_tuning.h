#pragma once
// Keepalive as this tree tunes it, in one place because a peer that loses power
// sends nothing and every listener owes the same answer to that.
#include <netinet/in.h>
#include <netinet/tcp.h>
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

}  // namespace socket_tuning
