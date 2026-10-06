#pragma once
// Descriptors put on the fixed numbers a forked child hands its exec, with nothing but fcntl and dup2, so it is safe
// between fork and exec.
#include <cstddef>
#include <fcntl.h>
#include <unistd.h>

namespace socketley
{

// One descriptor and the number it is to have; a negative src is nothing to place.
struct fd_move
{
    int src;
    int dst;
};

// Puts every src on its dst with the close-on-exec flag cleared, false when a descriptor could not be had. dup2
// destroys its destination, so every source sitting on any destination is lifted above them all, close-on-exec, before
// the first is placed.
inline bool place_descriptors(fd_move* moves, size_t n)
{
    int top = 0;
    for (size_t i = 0; i < n; ++i)
        if (moves[i].src >= 0 && moves[i].dst >= top)
            top = moves[i].dst + 1;
    for (size_t i = 0; i < n; ++i)
    {
        if (moves[i].src < 0)
            continue;
        bool on_a_destination = false;
        for (size_t j = 0; j < n; ++j)
            on_a_destination = on_a_destination || (moves[j].src >= 0 && moves[j].dst == moves[i].src);
        if (!on_a_destination)
            continue;
        const int up = ::fcntl(moves[i].src, F_DUPFD_CLOEXEC, top);
        if (up < 0)
            return false;
        moves[i].src = up;
    }
    for (size_t i = 0; i < n; ++i)
    {
        if (moves[i].src < 0)
            continue;
        if (::dup2(moves[i].src, moves[i].dst) < 0)
            return false;
        // dup2 onto itself leaves the flag as it was, and the worker must keep what it is given.
        const int fl = ::fcntl(moves[i].dst, F_GETFD, 0);
        if (fl >= 0 && (fl & FD_CLOEXEC))
            if (::fcntl(moves[i].dst, F_SETFD, fl & ~FD_CLOEXEC) < 0)
                return false;
    }
    return true;
}

} // namespace socketley
