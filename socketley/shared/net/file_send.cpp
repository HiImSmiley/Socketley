#include "file_send.h"

#include <algorithm>
#include <cerrno>

#include <fcntl.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/uio.h>

namespace socketley::file_send
{

bool cold(int file_fd, uint64_t off, uint64_t left)
{
    if (left == 0)
        return false;
    char probe = 0;
    iovec v{&probe, 1};
    const auto last = static_cast<off_t>(off + std::min(left, burst_max) - 1);
    return ::preadv2(file_fd, &v, 1, last, RWF_NOWAIT) < 0 && errno == EAGAIN;
}

burst send(int sock, int& sock_flags, int file_fd, uint64_t& off, uint64_t& left, uint64_t& sent)
{
    if (sock_flags < 0)
        sock_flags = ::fcntl(sock, F_GETFL);
    if (sock_flags < 0 || ::fcntl(sock, F_SETFL, sock_flags | O_NONBLOCK) < 0)
        return burst::failed;
    bool failed = false;
    for (uint64_t budget = burst_max; left > 0 && budget > 0;)
    {
        auto at = static_cast<off_t>(off);
        const ssize_t n = ::sendfile(sock, file_fd, &at, static_cast<size_t>(std::min(left, budget)));
        if (n > 0)
        {
            const auto took = static_cast<uint64_t>(n);
            off += took;
            left -= std::min(left, took);
            budget -= std::min(budget, took);
            sent += took;
            continue;
        }
        failed = n == 0 || errno != EAGAIN;
        break;
    }
    if (::fcntl(sock, F_SETFL, sock_flags) < 0)
        failed = true;
    if (failed)
        return burst::failed;
    return left == 0 ? burst::done : burst::more;
}

ssize_t send_head(int sock, std::string_view head)
{
    const ssize_t n = ::send(sock, head.data(), head.size(), MSG_DONTWAIT | MSG_NOSIGNAL | MSG_MORE);
    if (n >= 0)
        return n;
    return errno == EAGAIN ? 0 : -1;
}


}   // namespace socketley::file_send
