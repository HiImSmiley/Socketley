#pragma once

// A small file a runtime keeps beside its data, read whole and written whole:
// the new content goes to a file beside it and is renamed over it, so a reader
// in any process sees the old content or the new and never part of either.
//
// Every runtime, the daemon and the CLI write their whole files here, at a
// durability each call names.

#include "../loop/blocking_write.h"

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <string_view>
#include <sys/stat.h>
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

// How far a replaced file is on the disk when replace_file() returns, said at every call.
enum class durability : uint8_t
{
    none,           // the page cache: a dead process keeps it, a dead machine may not
    data,           // the new bytes synced before the rename
    data_and_dir,   // and the rename synced into the directory, so a crash brings neither the old file back nor half
};

// `data` as the whole of `path`, written beside it under a name no other writer uses and renamed over it, so a reader
// in any process sees the old content or the new; false with `why` at the step that failed. With data_and_dir a
// failed directory sync is false after the new content is already in place.
inline bool replace_file(const std::string& path, std::string_view data, durability sync, std::string* why = nullptr,
                         mode_t mode = 0600)
{
    static std::atomic<uint64_t> next{0};
    // Ending in .tmp, which is how a start that finds one a crash left recognises it.
    const std::string tmp = path + "." + std::to_string(::getpid()) + "." +
                            std::to_string(next.fetch_add(1, std::memory_order_relaxed)) + ".tmp";
    const auto failed = [&](const char* step) {
        if (why)
            *why = std::string(step) + " failed for " + tmp + ": " + std::strerror(errno);
        return false;
    };
    // Made new, never through a link someone left at the name, at the mode said rather than the umask's.
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode);
    if (fd < 0)
        return failed("open");
    if (::fchmod(fd, mode) != 0 || !write_all(fd, data.data(), data.size()) ||
        (sync != durability::none && ::fsync(fd) != 0))
    {
        const int err = errno;
        ::close(fd);
        ::unlink(tmp.c_str());
        errno = err;
        return failed("write");
    }
    if (::close(fd) != 0)
    {
        const int err = errno;
        ::unlink(tmp.c_str());
        errno = err;
        return failed("close");
    }
    if (::rename(tmp.c_str(), path.c_str()) != 0)
    {
        const int err = errno;
        ::unlink(tmp.c_str());
        errno = err;
        if (why)
            *why = "rename failed for " + tmp + " to " + path + ": " + std::strerror(err);
        return false;
    }
    if (sync != durability::data_and_dir)
        return true;
    const size_t slash = path.rfind('/');
    const std::string dir = slash == std::string::npos ? std::string(".") : path.substr(0, slash ? slash : 1);
    const int dfd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    const bool synced = dfd >= 0 && ::fsync(dfd) == 0;
    const int err = errno;
    if (dfd >= 0)
        ::close(dfd);
    if (!synced && why)
        *why = "sync failed for the directory " + dir + ": " + std::strerror(err);
    return synced;
}

}   // namespace socketley
