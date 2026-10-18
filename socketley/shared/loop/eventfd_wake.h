#pragma once

#include <cstdint>

#include <unistd.h>

namespace socketley
{

// Adds one to an eventfd's counter, which wakes whoever waits on it; a failed write is a counter already full, so
// already a wake, and a bare write(2) keeps it safe in a signal handler.
inline void eventfd_bump(int fd)
{
    const uint64_t one = 1;
    if (::write(fd, &one, sizeof one) < 0) {}
}

} // namespace socketley
