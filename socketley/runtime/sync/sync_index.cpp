#include "sync_index.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

namespace socketley::sync
{

namespace
{

constexpr std::string_view magic = "SKLSYNC1";
// A record is kept small enough that a truncated tail is the only way to lose one.
constexpr size_t max_path = 4096;

void put_u16(std::string& o, uint16_t v) { o.append(reinterpret_cast<const char*>(&v), 2); }
void put_u64(std::string& o, uint64_t v) { o.append(reinterpret_cast<const char*>(&v), 8); }

// Reads `n` bytes at `at` of `s` into `out`, false when the record runs past the end.
bool take(std::string_view s, size_t& at, void* out, size_t n)
{
    if (at + n > s.size())
        return false;
    std::memcpy(out, s.data() + at, n);
    at += n;
    return true;
}

bool take_str(std::string_view s, size_t& at, size_t n, std::string& out)
{
    if (at + n > s.size())
        return false;
    out.assign(s.substr(at, n));
    at += n;
    return true;
}

bool read_whole(const std::string& path, std::string& out, std::string& why)
{
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
    {
        if (errno == ENOENT)
            return true;
        why = path + ": " + std::strerror(errno);
        return false;
    }
    char buf[65536];
    for (ssize_t n; (n = ::read(fd, buf, sizeof buf)) > 0;)
        out.append(buf, static_cast<size_t>(n));
    ::close(fd);
    return true;
}

}   // namespace

bool sync_index::open(std::string path, std::string& why)
{
    m_path = std::move(path);
    m_live.clear();
    m_records = 0;

    std::string text;
    if (!read_whole(m_path, text, why))
        return false;
    if (text.empty())
        return true;
    if (!std::string_view(text).starts_with(magic))
    {
        why = m_path + " is not a sync index";
        return false;
    }

    size_t at = magic.size();
    while (at < text.size())
    {
        // A record cut short is the tail a crash left; what came before it still counts.
        const size_t start = at;
        char kind = 0;
        uint16_t tlen = 0, plen = 0;
        uint64_t size = 0;
        int64_t mtime = 0;
        uint8_t elen = 0;
        index_key key;
        index_entry e;
        if (!take(text, at, &kind, 1) || !take(text, at, &tlen, 2) || !take_str(text, at, tlen, key.target) ||
            !take(text, at, &plen, 2) || plen > max_path || !take_str(text, at, plen, key.path) ||
            !take(text, at, &size, 8) || !take(text, at, &mtime, 8) || !take(text, at, &elen, 1) ||
            !take_str(text, at, elen, e.etag))
        {
            at = start;
            break;
        }
        e.size = size;
        e.mtime_ns = mtime;
        ++m_records;
        if (kind == 'p')
            m_live[key] = std::move(e);
        else
            m_live.erase(key);
    }
    // A tail no record could be read from is cut off, so the next append is not written behind rubbish.
    if (at != text.size())
    {
        if (::truncate(m_path.c_str(), static_cast<off_t>(at)) != 0)
        {
            why = m_path + ": " + std::strerror(errno);
            return false;
        }
    }
    return true;
}

const index_entry* sync_index::find(std::string_view target, std::string_view path) const
{
    const auto it = m_live.find(index_key{std::string(target), std::string(path)});
    return it == m_live.end() ? nullptr : &it->second;
}

bool sync_index::append(char kind, std::string_view target, std::string_view path, const index_entry& e,
                        std::string& why)
{
    std::string rec(1, kind);
    put_u16(rec, static_cast<uint16_t>(target.size()));
    rec.append(target);
    put_u16(rec, static_cast<uint16_t>(path.size()));
    rec.append(path);
    put_u64(rec, e.size);
    put_u64(rec, static_cast<uint64_t>(e.mtime_ns));
    rec.push_back(static_cast<char>(e.etag.size()));
    rec.append(e.etag);

    const bool fresh = ::access(m_path.c_str(), F_OK) != 0;
    const int fd = ::open(m_path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0)
    {
        why = m_path + ": " + std::strerror(errno);
        return false;
    }
    std::string out;
    if (fresh)
        out.append(magic);
    out.append(rec);
    const ssize_t n = ::write(fd, out.data(), out.size());
    // The record reaches the disk before the change it records is called done, or a crash forgets what it carried.
    if (n == static_cast<ssize_t>(out.size()))
        ::fdatasync(fd);
    ::close(fd);
    if (n != static_cast<ssize_t>(out.size()))
    {
        why = m_path + ": the record was not written whole";
        return false;
    }
    ++m_records;
    return true;
}

bool sync_index::carried(std::string_view target, std::string_view path, const index_entry& e, std::string& why)
{
    if (path.size() > max_path)
    {
        why = "a path of " + std::to_string(path.size()) + " bytes is longer than an index record holds";
        return false;
    }
    if (!append('p', target, path, e, why))
        return false;
    m_live[index_key{std::string(target), std::string(path)}] = e;
    return true;
}

bool sync_index::gone(std::string_view target, std::string_view path, std::string& why)
{
    if (!append('d', target, path, index_entry{}, why))
        return false;
    m_live.erase(index_key{std::string(target), std::string(path)});
    return true;
}

bool sync_index::compact(std::string& why)
{
    // Twice the live set is where the dead records cost more to read than the rewrite costs to make.
    if (m_records < 64 || m_records < m_live.size() * 2)
        return true;
    std::string out(magic);
    for (const auto& [k, e] : m_live)
    {
        out.push_back('p');
        put_u16(out, static_cast<uint16_t>(k.target.size()));
        out.append(k.target);
        put_u16(out, static_cast<uint16_t>(k.path.size()));
        out.append(k.path);
        put_u64(out, e.size);
        put_u64(out, static_cast<uint64_t>(e.mtime_ns));
        out.push_back(static_cast<char>(e.etag.size()));
        out.append(e.etag);
    }
    // Written beside and renamed, so a crash during the rewrite leaves the old whole file and not half a new one.
    const std::string tmp = m_path + ".new";
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
    {
        why = tmp + ": " + std::strerror(errno);
        return false;
    }
    const ssize_t n = ::write(fd, out.data(), out.size());
    if (n == static_cast<ssize_t>(out.size()))
        ::fdatasync(fd);
    ::close(fd);
    if (n != static_cast<ssize_t>(out.size()) || ::rename(tmp.c_str(), m_path.c_str()) != 0)
    {
        ::unlink(tmp.c_str());
        why = m_path + ": the index could not be written again";
        return false;
    }
    m_records = m_live.size();
    return true;
}

}   // namespace socketley::sync
