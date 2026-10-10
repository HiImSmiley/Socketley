#pragma once

// Write a whole buffer to a blocking fd or report how far it got, because a
// short write treated as complete misframes every message after it.

#include <chrono>
#include <cerrno>
#include <cstddef>
#include <poll.h>
#include <unistd.h>
#include <sys/socket.h>

namespace socketley
{

// True when the entire buffer was written; `written`, if given, receives the
// byte count even on failure.
inline bool write_all(int fd, const char* data, size_t len, size_t* written = nullptr)
{
    size_t off = 0;
    while (off < len)
    {
        const ssize_t n = ::write(fd, data + off, len - off);
        if (n > 0)
        {
            off += static_cast<size_t>(n);
            continue;
        }
        // A signal between two chunks is not a failure to deliver.
        if (n < 0 && errno == EINTR)
            continue;
        break;
    }
    if (written)
        *written = off;
    return off == len;
}


// write_all() for a socket that must never stop the caller: a viewer that does not read loses what would not fit
// rather than holding an event loop until it does. False, with what went in `written`, when not all of it did.
inline bool send_all_nowait(int fd, const char* data, size_t len, size_t* written = nullptr)
{
    size_t off = 0;
    while (off < len)
    {
        const ssize_t n = ::send(fd, data + off, len - off, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (n > 0)
        {
            off += static_cast<size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        break;
    }
    if (written)
        *written = off;
    return off == len;
}

// write_all() for a socket with an end to the wait: a peer that stops reading holds the caller until `deadline` and
// no longer, which is what a drain on stop owes every other connection and the operator waiting on it.
inline bool write_all_until(int fd, const char* data, size_t len, std::chrono::steady_clock::time_point deadline)
{
    size_t off = 0;
    while (off < len)
    {
        const ssize_t n = ::send(fd, data + off, len - off, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (n > 0)
        {
            off += static_cast<size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        {
            const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now()).count();
            if (left <= 0)
                return false;
            struct pollfd p{fd, POLLOUT, 0};
            if (::poll(&p, 1, static_cast<int>(left)) < 0 && errno != EINTR)
                return false;
            continue;
        }
        return false;
    }
    return true;
}

// How long a drain on stop may spend on all its connections together.
inline constexpr std::chrono::seconds drain_budget{5};

}  // namespace socketley
