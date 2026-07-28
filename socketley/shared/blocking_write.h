#pragma once

// Write a whole buffer to a blocking fd, or report how far it got.
//
// write() and writev() returning fewer bytes than they were given is ordinary
// behaviour, not an error, and every caller that checked only for a negative
// return treated a short write as a complete one. On a message stream that is
// not a lost byte or two — the reader sees the tail of one message glued to the
// head of the next, and every message after it is misframed.
//
// The distinction between "nothing was written" and "some of it was" is the one
// callers act on: the first can be retried or skipped, the second has already
// put a fragment on the wire and left the stream unusable.

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
