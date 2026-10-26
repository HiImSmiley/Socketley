#include "sync_index.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

#include "../../shared/persist/mutation_journal.h"
#include "../../shared/persist/read_file.h"

namespace socketley::sync
{

namespace
{

constexpr std::string_view magic = "SKLSYNC2";
constexpr size_t record_head = 8;
// No body is near this; a larger length is rubbish, not a record.
constexpr size_t max_body = 1 + 2 + 65535 + 2 + sync_index::max_path + 8 + 8 + 1 + 255;

void put_u16(std::string& o, uint16_t v) { o.append(reinterpret_cast<const char*>(&v), 2); }
void put_u32(std::string& o, uint32_t v) { o.append(reinterpret_cast<const char*>(&v), 4); }
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

std::string body_of(char kind, std::string_view target, std::string_view path, const index_entry& e)
{
    std::string b(1, kind);
    put_u16(b, static_cast<uint16_t>(target.size()));
    b.append(target);
    put_u16(b, static_cast<uint16_t>(path.size()));
    b.append(path);
    put_u64(b, e.size);
    put_u64(b, static_cast<uint64_t>(e.mtime_ns));
    // An etag is a few dozen bytes; a host that sends a longer one is remembered by its first 255.
    const size_t elen = std::min<size_t>(e.etag.size(), 255);
    b.push_back(static_cast<char>(elen));
    b.append(e.etag, 0, elen);
    return b;
}

std::string framed(std::string_view body)
{
    std::string out;
    put_u32(out, static_cast<uint32_t>(body.size()));
    put_u32(out, crc::crc32(body));
    out.append(body);
    return out;
}

bool write_all(int fd, std::string_view s)
{
    while (!s.empty())
    {
        const ssize_t n = ::write(fd, s.data(), s.size());
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        s.remove_prefix(static_cast<size_t>(n));
    }
    return true;
}

}   // namespace

sync_index::~sync_index()
{
    if (m_fd >= 0)
        ::close(m_fd);
}

bool sync_index::open(std::string path, std::string_view scope, std::string& why)
{
    if (scope.size() > 65535)
    {
        why = "the sync scope is too long to index";
        return false;
    }
    if (m_fd >= 0)
        ::close(m_fd);
    m_fd = -1;
    m_path = std::move(path);
    m_scope.assign(scope);
    m_live.clear();
    m_records = 0;
    m_stale = false;

    std::string text;
    if (!socketley::read_file(m_path, text, {.missing_ok = true, .no_follow = true}, &why))
        return false;
    // Empty, or the magic cut short by a crash before anything was recorded.
    if (text.size() <= magic.size() && magic.starts_with(text))
        return write_fresh(why);
    if (!std::string_view(text).starts_with(magic))
    {
        why = m_path + " is not a sync index";
        return false;
    }

    size_t at = magic.size();
    bool scoped = false;
    while (at < text.size())
    {
        // A record cut short, or one its checksum disowns, is where the file ends; what came before it still counts.
        const size_t start = at;
        uint32_t len = 0, crc = 0;
        if (!take(text, at, &len, 4) || !take(text, at, &crc, 4) || len > max_body || at + len > text.size())
        {
            at = start;
            break;
        }
        const std::string_view body(text.data() + at, len);
        if (crc::crc32(body) != crc)
        {
            at = start;
            break;
        }
        at += len;

        size_t b = 0;
        char kind = 0;
        uint16_t tlen = 0, plen = 0;
        uint64_t size = 0;
        int64_t mtime = 0;
        uint8_t elen = 0;
        index_key key;
        index_entry e;
        if (!take(body, b, &kind, 1) || !take(body, b, &tlen, 2) || !take_str(body, b, tlen, key.target) ||
            !take(body, b, &plen, 2) || !take_str(body, b, plen, key.path) || !take(body, b, &size, 8) ||
            !take(body, b, &mtime, 8) || !take(body, b, &elen, 1) || !take_str(body, b, elen, e.etag) ||
            b != body.size())
        {
            at = start;
            break;
        }
        ++m_records;
        if (kind == 's')
        {
            // The records of another directory or prefix name other objects, so they are not read as this job's.
            if (key.path != m_scope)
                return write_fresh(why);
            scoped = true;
            continue;
        }
        if (!scoped)
            return write_fresh(why);
        e.size = size;
        e.mtime_ns = mtime;
        if (kind == 'p')
            m_live[key] = std::move(e);
        else
            m_live.erase(key);
    }
    if (!scoped)
        return write_fresh(why);

    m_fd = ::open(m_path.c_str(), O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (m_fd < 0)
    {
        why = m_path + ": " + std::strerror(errno);
        return false;
    }
    // A tail no record could be read from is cut off, so the next append is not written behind rubbish.
    if (at != text.size() && ::ftruncate(m_fd, static_cast<off_t>(at)) != 0)
    {
        why = m_path + ": " + std::strerror(errno);
        return false;
    }
    m_size = at;
    return true;
}

bool sync_index::write_fresh(std::string& why)
{
    m_live.clear();
    m_records = 0;
    return compact(why, true);
}

const index_entry* sync_index::find(std::string_view target, std::string_view path) const
{
    const auto it = m_live.find(index_key{std::string(target), std::string(path)});
    return it == m_live.end() ? nullptr : &it->second;
}

bool sync_index::append(std::string_view body, std::string& why)
{
    if (m_fd < 0)
    {
        why = m_path + ": the index is not open";
        return false;
    }
    if (::lseek(m_fd, static_cast<off_t>(m_size), SEEK_SET) < 0 || !write_all(m_fd, framed(body)))
    {
        why = m_path + ": " + std::strerror(errno);
        // What went in short is cut back, or the next record would be written behind half of this one.
        if (::ftruncate(m_fd, static_cast<off_t>(m_size)) != 0) {}
        return false;
    }
    m_size += record_head + body.size();
    ++m_records;
    return true;
}

bool sync_index::carried(std::string_view target, std::string_view path, const index_entry& e, std::string& why)
{
    if (path.size() > max_path || target.size() > 65535)
    {
        why = "a path of " + std::to_string(path.size()) + " bytes is longer than an index record holds";
        return false;
    }
    if (!append(body_of('p', target, path, e), why))
        return false;
    index_entry& kept = m_live[index_key{std::string(target), std::string(path)}];
    kept = e;
    if (kept.etag.size() > 255)
        kept.etag.resize(255);
    return true;
}

bool sync_index::gone(std::string_view target, std::string_view path, std::string& why)
{
    if (path.size() > max_path || target.size() > 65535)
    {
        why = "a path of " + std::to_string(path.size()) + " bytes is longer than an index record holds";
        return false;
    }
    if (!append(body_of('d', target, path, index_entry{}), why))
        return false;
    m_live.erase(index_key{std::string(target), std::string(path)});
    return true;
}

void sync_index::retain(const std::vector<std::string>& targets)
{
    const size_t before = m_live.size();
    std::erase_if(m_live, [&](const auto& kv) {
        return std::find(targets.begin(), targets.end(), kv.first.target) == targets.end();
    });
    if (m_live.size() != before)
        m_stale = true;
}

void sync_index::flush()
{
    if (m_fd >= 0)
        ::fdatasync(m_fd);
}

bool sync_index::compact(std::string& why, bool force)
{
    // Twice the live set is where the dead records cost more to read than the rewrite costs to make.
    if (!force && !m_stale && (m_records < 64 || m_records < m_live.size() * 2))
        return true;
    std::string out(magic);
    out += framed(body_of('s', {}, m_scope, index_entry{}));
    for (const auto& [k, e] : m_live)
        out += framed(body_of('p', k.target, k.path, e));
    // Written beside and renamed, so a crash during the rewrite leaves the old whole file and not half a new one.
    const std::string tmp = m_path + ".new";
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0)
    {
        why = tmp + ": " + std::strerror(errno);
        return false;
    }
    const bool whole = write_all(fd, out) && ::fdatasync(fd) == 0;
    if (!whole || ::rename(tmp.c_str(), m_path.c_str()) != 0)
    {
        ::close(fd);
        ::unlink(tmp.c_str());
        why = m_path + ": the index could not be written again";
        return false;
    }
    if (m_fd >= 0)
        ::close(m_fd);
    m_fd = fd;
    m_size = out.size();
    m_records = 1 + m_live.size();
    m_stale = false;
    return true;
}

}   // namespace socketley::sync
