#pragma once

// A small file a runtime keeps beside its data, read whole and written whole:
// the new content goes to a file beside it and is renamed over it, so a reader
// in any process sees the old content or the new and never part of either.
//
// The storage runtime keeps three kinds of these (its share links, its media
// marks, and the web interface's watch positions) and had two copies of this
// before the third.

#include "blocking_write.h"

#include <cerrno>
#include <fcntl.h>
#include <string>
#include <string_view>
#include <unistd.h>

namespace socketley
{

inline bool read_whole_file(const std::string& path, std::string& out)
{
    out.clear();
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    char buf[8192];
    for (;;)
    {
        const ssize_t n = ::read(fd, buf, sizeof buf);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
        {
            ::close(fd);
            return n == 0;
        }
        out.append(buf, static_cast<size_t>(n));
    }
}

// `durable` syncs the new file before the rename, for content a crash must not
// take back once it was answered for.
inline bool replace_file(const std::string& path, std::string_view data, bool durable)
{
    const std::string tmp = path + ".tmp." + std::to_string(::getpid());
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return false;
    bool ok = write_all(fd, data.data(), data.size());
    if (durable)
        ok = ::fsync(fd) == 0 && ok;
    ok = ::close(fd) == 0 && ok;
    if (!ok || ::rename(tmp.c_str(), path.c_str()) < 0)
    {
        ::unlink(tmp.c_str());
        return false;
    }
    // And the rename itself, which lives in the directory: without its sync a crash could bring the old file back.
    if (durable)
    {
        const size_t slash = path.rfind('/');
        const std::string dir = slash == std::string::npos ? std::string(".") : path.substr(0, slash ? slash : 1);
        const int dfd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dfd < 0)
            return false;
        const bool synced = ::fsync(dfd) == 0;
        ::close(dfd);
        return synced;
    }
    return true;
}

}   // namespace socketley
