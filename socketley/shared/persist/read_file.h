#pragma once
// A whole file read into a string, the one loop every runtime, the daemon and the CLI read their files with: what a
// missing file means, a cap on its size and whether a link is followed said by the caller.
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace socketley
{

struct read_options
{
    // A file that is not there read as empty rather than refused.
    bool missing_ok{false};
    // Refused past this many bytes, so a file nobody meant to be large cannot fill memory.
    size_t max_bytes{SIZE_MAX};
    // Refused when the name is a symbolic link.
    bool no_follow{false};
};

// The whole of `path` in `out`; false with `why` ("<path>: <reason>") when it cannot be read whole.
inline bool read_file(const std::string& path, std::string& out, const read_options& o = {}, std::string* why = nullptr)
{
    out.clear();
    const auto refuse = [&](const char* reason) {
        if (why)
            *why = path + ": " + reason;
        out.clear();
        return false;
    };
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | (o.no_follow ? O_NOFOLLOW : 0));
    if (fd < 0)
        return errno == ENOENT && o.missing_ok ? true : refuse(std::strerror(errno));
    char buf[65536];
    for (;;)
    {
        const ssize_t n = ::read(fd, buf, sizeof buf);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0)
        {
            const int err = errno;
            ::close(fd);
            return refuse(std::strerror(err));
        }
        if (n == 0)
            break;
        if (out.size() + static_cast<size_t>(n) > o.max_bytes)
        {
            ::close(fd);
            return refuse("larger than it may be");
        }
        out.append(buf, static_cast<size_t>(n));
    }
    ::close(fd);
    return true;
}

inline bool read_whole_file(const std::string& path, std::string& out)
{
    return read_file(path, out);
}

}   // namespace socketley
