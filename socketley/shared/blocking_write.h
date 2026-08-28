#pragma once

// Write a whole buffer to a blocking fd, or report how far it got: a short
// write is ordinary, and treating it as complete misframes every message after.
// "Nothing written" can be retried; "some of it" has already broken the stream.

#include <cerrno>
#include <cstddef>
#include <unistd.h>

namespace socketley
{

// Returns true when the entire buffer was written. `written`, if given, receives
// the number of bytes that made it out — including on failure.
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

}  // namespace socketley
