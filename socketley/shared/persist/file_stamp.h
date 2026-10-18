#pragma once
// What a file is now, as one read again when it changes compares it: its modification to the nanosecond, its size
// and its inode, so a file replaced by a rename, rewritten in place or touched is told from the one before -- as
// three fields compared, never a sum two different files can share.
#include <cstdint>
#include <string>

#include <sys/stat.h>

namespace socketley
{

struct file_stamp
{
    int64_t mtime_ns{0};
    // -1 for a file that is not there, which no file that is ever equals.
    int64_t size{-1};
    uint64_t ino{0};

    bool operator==(const file_stamp&) const = default;
    bool exists() const { return size >= 0; }

    static file_stamp of(const struct stat& st)
    {
        return {static_cast<int64_t>(st.st_mtim.tv_sec) * 1000000000 + st.st_mtim.tv_nsec,
                static_cast<int64_t>(st.st_size), static_cast<uint64_t>(st.st_ino)};
    }

    static file_stamp of(const std::string& path)
    {
        struct stat st{};
        return ::stat(path.c_str(), &st) == 0 ? of(st) : file_stamp{};
    }
};

}   // namespace socketley
