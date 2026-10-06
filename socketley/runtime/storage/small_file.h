#pragma once
// The small files the runtime keeps beside its buckets -- links, media marks, the web interface's watch positions --
// read whole, and written aside and renamed in, so that a reader on any shard sees the old content or the new and never
// part of either; and the HMAC their signatures are made with.
#include <cerrno>
#include <string>
#include <string_view>

#include <fcntl.h>
#include <unistd.h>

#include <openssl/hmac.h>

#include "digest.h"

namespace socketley::storage
{

inline bool read_small_file(const std::string& path, std::string& out)
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

// `durable` syncs the file before it is renamed in, for what a crash must not take back once it was answered for.
inline bool write_small_file(const std::string& path, std::string_view data, bool durable)
{
    const std::string tmp = path + ".tmp." + std::to_string(::getpid());
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return false;
    bool ok = ::write(fd, data.data(), data.size()) == static_cast<ssize_t>(data.size());
    if (durable)
        ok = ::fsync(fd) == 0 && ok;
    ok = ::close(fd) == 0 && ok;
    if (!ok || ::rename(tmp.c_str(), path.c_str()) < 0)
    {
        ::unlink(tmp.c_str());
        return false;
    }
    return true;
}

inline std::string hmac_sha256_hex(std::string_view key, std::string_view msg)
{
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int  n = 0;
    if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), reinterpret_cast<const unsigned char*>(msg.data()),
              msg.size(), out, &n))
        return {};
    return hex(out, n);
}

}   // namespace socketley::storage
