#include "db_log.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../shared/loop/blocking_write.h"
#include "../../shared/persist/mutation_journal.h"

namespace socketley::db
{

namespace
{

void put32(char* at, uint32_t v)
{
    for (int i = 0; i < 4; ++i)
        at[i] = static_cast<char>((v >> (8 * i)) & 0xFF);
}

uint32_t get32(const char* at)
{
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i)
        v |= static_cast<uint32_t>(static_cast<unsigned char>(at[i])) << (8 * i);
    return v;
}

std::string head_of()
{
    std::string h(seglog::magic, sizeof seglog::magic);
    h.append(seglog::header_bytes - sizeof seglog::magic, '\0');
    return h;
}

bool sync_dir(const std::string& dir)
{
    const int dfd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0)
        return false;
    const bool ok = ::fsync(dfd) == 0;
    ::close(dfd);
    return ok;
}

// What a room is written from.
const char zeros[64 << 10] = {};
// How far past the records a room begins when none is ready, so the loop's next records stay below it.
constexpr uint64_t room_lead = 512u << 10;

bool pread_all(int fd, char* buf, size_t n, uint64_t off)
{
    size_t got = 0;
    while (got < n)
    {
        const ssize_t r = ::pread(fd, buf + got, n - got, static_cast<off_t>(off + got));
        if (r < 0 && errno == EINTR)
            continue;
        if (r <= 0)
            return false;
        got += static_cast<size_t>(r);
    }
    return true;
}

}   // namespace

std::string seglog::path_of(uint32_t seg) const
{
    char name[32];
    std::snprintf(name, sizeof name, "/seg-%08u.log", seg);
    return m_dir + name;
}

bool seglog::scan_file(const std::string& path, const visitor& each, bool cut_torn_tail, std::string& why)
{
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
    {
        why = path + " cannot be read";
        return false;
    }
    struct stat st{};
    if (::fstat(fd, &st) != 0)
    {
        ::close(fd);
        why = path + " cannot be read";
        return false;
    }
    const uint64_t size = static_cast<uint64_t>(st.st_size);
    char head[header_bytes];
    if (size < header_bytes || !pread_all(fd, head, header_bytes, 0) || std::memcmp(head, magic, sizeof magic) != 0)
    {
        ::close(fd);
        why = path + " is not a segment of a db runtime";
        return false;
    }
    // Read a window at a time, so a segment is never held whole.
    std::string buf;
    uint64_t base = header_bytes;
    uint64_t at = header_bytes;
    bool ok = true;
    while (at < size)
    {
        if (size - at < record_head)
            break;
        // The window holds [base, base + buf.size()).
        if (at + record_head > base + buf.size())
        {
            buf.erase(0, static_cast<size_t>(at - base));
            base = at;
            const size_t want = static_cast<size_t>(std::min<uint64_t>(size - base, 4u << 20));
            const size_t had = buf.size();
            if (want > had)
            {
                buf.resize(want);
                if (!pread_all(fd, buf.data() + had, want - had, base + had))
                {
                    ok = false;
                    break;
                }
            }
        }
        const char* h = buf.data() + (at - base);
        const uint32_t len = get32(h);
        const uint32_t crc = get32(h + 4);
        // No record is empty, so a length of 0 is the room past the last one.
        if (len == 0 || len > max_record || at + record_head + len > size)
            break;
        if (at + record_head + len > base + buf.size())
        {
            buf.erase(0, static_cast<size_t>(at - base));
            base = at;
            const size_t had = buf.size();
            buf.resize(record_head + len);
            if (!pread_all(fd, buf.data() + had, buf.size() - had, base + had))
            {
                ok = false;
                break;
            }
        }
        const std::string_view payload(buf.data() + (at - base) + record_head, len);
        if (journal_detail::crc32(payload) != crc)
            break;
        if (!each(0, at + record_head, payload))
        {
            ::close(fd);
            why = path + " holds a record this build cannot read";
            return false;
        }
        at += record_head + len;
    }
    ::close(fd);
    if (!ok)
    {
        why = path + " cannot be read";
        return false;
    }
    if (at < size)
    {
        if (!cut_torn_tail)
        {
            why = path + " is damaged at byte " + std::to_string(at) + "; restore a backup";
            return false;
        }
        // A record the crash cut short is no record: the file ends where the last whole one does.
        if (::truncate(path.c_str(), static_cast<off_t>(at)) != 0)
        {
            why = path + " has a torn tail that cannot be cut";
            return false;
        }
    }
    return true;
}

bool seglog::open(const std::string& dir, const visitor& each, std::string& why)
{
    close();
    m_dir = dir;
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (!std::filesystem::is_directory(dir, ec))
    {
        why = "the data directory " + dir + " cannot be made";
        return false;
    }
    if (::chmod(dir.c_str(), 0700) != 0) {}
    std::vector<uint32_t> found;
    for (const auto& e : std::filesystem::directory_iterator(dir, ec))
    {
        const std::string name = e.path().filename().string();
        // A file a merge or a backup was writing when the process died is no segment.
        if (name.ends_with(".tmp"))
        {
            std::filesystem::remove(e.path(), ec);
            continue;
        }
        unsigned n = 0;
        if (std::sscanf(name.c_str(), "seg-%08u.log", &n) == 1 && name.size() == 16)
            found.push_back(n);
    }
    std::sort(found.begin(), found.end());
    for (size_t i = 0; i < found.size(); ++i)
    {
        const uint32_t seg = found[i];
        const bool last = i + 1 == found.size();
        if (!scan_file(path_of(seg), [&](uint32_t, uint64_t off, std::string_view p) { return each(seg, off, p); }, last,
                       why))
            return false;
        struct stat st{};
        if (::stat(path_of(seg).c_str(), &st) != 0)
        {
            why = path_of(seg) + " cannot be read";
            return false;
        }
        m_segs[seg].size = static_cast<uint64_t>(st.st_size);
        m_highest = std::max(m_highest, seg);
    }
    if (found.empty())
        return begin(1, why);
    m_active = found.back();
    m_fd = ::open(path_of(m_active).c_str(), O_RDWR | O_CLOEXEC);
    if (m_fd < 0)
    {
        why = path_of(m_active) + " cannot be opened to write";
        return false;
    }
    m_written = m_alloc = m_segs[m_active].size;
    return true;
}

bool seglog::begin(uint32_t seg, std::string& why)
{
    end_room();
    const std::string path = path_of(seg);
    const int fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    const std::string head = head_of();
    if (fd < 0 || !write_all(fd, head.data(), head.size()) || ::fdatasync(fd) != 0 || !sync_dir(m_dir))
    {
        if (fd >= 0)
            ::close(fd);
        why = path + " cannot be written";
        return false;
    }
    if (m_fd >= 0)
        ::close(m_fd);
    m_fd = fd;
    m_active = seg;
    m_highest = std::max(m_highest, seg);
    m_segs[seg].size = header_bytes;
    ++m_layout;
    m_written = m_alloc = header_bytes;
    m_room_failed = false;
    m_pending.clear();
    return true;
}

void seglog::close()
{
    end_room();
    // A file stopped cleanly ends at its last record, the room this log made cut; one a crash left with its room is cut
    // by the next open.
    if (m_fd >= 0 && !m_failed && m_alloc > m_written && ::ftruncate(m_fd, static_cast<off_t>(m_written)) != 0) {}
    if (m_fd >= 0)
        ::close(m_fd);
    m_fd = -1;
    for (auto& [n, s] : m_segs)
        if (s.fd >= 0)
            ::close(s.fd);
    m_segs.clear();
    m_pending.clear();
    m_active = m_highest = 0;
    m_written = m_alloc = 0;
    m_failed = m_room_failed = m_follow = false;
}

location seglog::append(std::string_view payload)
{
    char head[record_head];
    put32(head, static_cast<uint32_t>(payload.size()));
    put32(head + 4, journal_detail::crc32(payload));
    m_pending.append(head, record_head);
    const uint64_t off = m_written + m_pending.size();
    m_pending.append(payload);
    m_segs[m_active].size = m_written + m_pending.size();
    return location{m_active, off, static_cast<uint32_t>(payload.size())};
}

bool seglog::flush()
{
    if (m_failed)
        return false;
    if (m_pending.empty())
        return true;
    // Records never land where zeros are still being written.
    if (m_room && (m_room->done.load(std::memory_order_acquire) || m_written + m_pending.size() > m_room->from))
        end_room();
    // At the end the bytes before it name, so a write cut short and tried again cannot land twice.
    size_t done = 0;
    while (done < m_pending.size())
    {
        const ssize_t n = ::pwrite(m_fd, m_pending.data() + done, m_pending.size() - done,
                                   static_cast<off_t>(m_written + done));
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
        {
            m_failed = true;
            return false;
        }
        done += static_cast<size_t>(n);
    }
    m_written += m_pending.size();
    m_pending.clear();
    plan_room();
    return true;
}

void seglog::plan_room()
{
    if (m_room || m_room_failed || m_fd < 0 || m_alloc >= segment_bytes || m_alloc >= m_written + room_bytes / 2)
        return;
    auto job = std::make_unique<room_job>();
    job->from = std::max(m_alloc, (m_written + room_lead + 4095) / 4096 * 4096);
    job->to = job->from + room_bytes;
    room_job* j = job.get();
    const int fd = m_fd;
    j->th = std::thread([j, fd] {
        bool ok = true;
        for (uint64_t at = j->from; ok && at < j->to;)
        {
            const ssize_t n = ::pwrite(fd, zeros, static_cast<size_t>(std::min<uint64_t>(sizeof zeros, j->to - at)),
                                       static_cast<off_t>(at));
            if (n < 0 && errno == EINTR)
                continue;
            ok = n > 0;
            at += ok ? static_cast<uint64_t>(n) : 0;
        }
        j->ok = ok && ::fdatasync(fd) == 0;
        j->done.store(true, std::memory_order_release);
    });
    m_room = std::move(job);
}

void seglog::end_room()
{
    if (!m_room)
        return;
    m_room->th.join();
    if (m_room->ok)
        m_alloc = std::max(m_alloc, m_room->to);
    m_room_failed = !m_room->ok;
    m_room.reset();
}

bool seglog::sync()
{
    return flush() && m_fd >= 0 && ::fdatasync(m_fd) == 0;
}

int seglog::fd_of(uint32_t seg)
{
    if (seg == m_active)
        return m_fd;
    const auto it = m_segs.find(seg);
    if (it == m_segs.end())
    {
        // A reader of another's log takes a segment it had not seen the first time it is asked for, and keeps it.
        if (!m_follow)
            return -1;
        const int fd = ::open(path_of(seg).c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0)
            return -1;
        m_segs[seg].fd = fd;
        m_highest = std::max(m_highest, seg);
        return fd;
    }
    if (it->second.fd < 0)
        it->second.fd = ::open(path_of(seg).c_str(), O_RDONLY | O_CLOEXEC);
    return it->second.fd;
}

bool seglog::read(const location& at, std::string& out)
{
    out.resize(at.len);
    if (at.seg == m_active && at.off >= m_written)
    {
        const uint64_t from = at.off - m_written;
        if (from + at.len > m_pending.size())
            return false;
        std::memcpy(out.data(), m_pending.data() + from, at.len);
        return true;
    }
    const int fd = fd_of(at.seg);
    return fd >= 0 && pread_all(fd, out.data(), at.len, at.off);
}

bool seglog::roll_if_full(std::string& why)
{
    if (m_segs[m_active].size < segment_bytes)
        return true;
    // The sealed segment's records, and its end at the last of them, are on the disk before a newer one seals it.
    const bool synced = sync();
    // Zeros a room wrote after the cut would lengthen it again.
    end_room();
    if (!synced || ::ftruncate(m_fd, static_cast<off_t>(m_written)) != 0 || ::fsync(m_fd) != 0)
    {
        why = "the segment could not be written to the disk";
        return false;
    }
    const uint32_t sealed = m_active;
    const int fd = m_fd;
    m_fd = -1;
    if (!begin(reserve(), why))
    {
        m_fd = fd;
        m_active = sealed;
        return false;
    }
    m_segs[sealed].fd = fd;
    return true;
}

std::vector<uint32_t> seglog::sealed() const
{
    std::vector<uint32_t> out;
    for (const auto& [n, s] : m_segs)
        if (n != m_active)
            out.push_back(n);
    return out;
}

uint64_t seglog::size_of(uint32_t seg) const
{
    const auto it = m_segs.find(seg);
    return it == m_segs.end() ? 0 : it->second.size;
}

uint64_t seglog::total_bytes() const
{
    uint64_t t = 0;
    for (const auto& [n, s] : m_segs)
        t += s.size;
    return t;
}

bool seglog::adopt(uint32_t seg, std::string& why)
{
    struct stat st{};
    if (::stat(path_of(seg).c_str(), &st) != 0)
    {
        why = path_of(seg) + " is not there";
        return false;
    }
    m_segs[seg].size = static_cast<uint64_t>(st.st_size);
    m_highest = std::max(m_highest, seg);
    ++m_layout;
    return true;
}

void seglog::remove(uint32_t seg)
{
    const auto it = m_segs.find(seg);
    if (it == m_segs.end() || seg == m_active)
        return;
    if (it->second.fd >= 0)
        ::close(it->second.fd);
    ::unlink(path_of(seg).c_str());
    m_segs.erase(it);
    ++m_layout;
}

bool seglog::clear(std::string& why)
{
    const std::vector<uint32_t> all = [&] {
        std::vector<uint32_t> v;
        for (const auto& [n, s] : m_segs)
            v.push_back(n);
        return v;
    }();
    const uint32_t next = reserve();
    if (!begin(next, why))
        return false;
    for (const uint32_t n : all)
        remove(n);
    sync_dir(m_dir);
    return true;
}

bool seglog::follow_open(const std::string& dir, std::string& why)
{
    close();
    m_dir = dir;
    m_follow = true;
    for (const uint32_t n : listed())
    {
        const int fd = ::open(path_of(n).c_str(), O_RDONLY | O_CLOEXEC);
        char head[header_bytes];
        if (fd < 0 || !pread_all(fd, head, header_bytes, 0) || std::memcmp(head, magic, sizeof magic) != 0)
        {
            if (fd >= 0)
                ::close(fd);
            why = path_of(n) + " is not a segment of a db runtime";
            return false;
        }
        m_segs[n].fd = fd;
        m_highest = std::max(m_highest, n);
    }
    return true;
}

std::vector<uint32_t> seglog::listed() const
{
    std::vector<uint32_t> out;
    std::error_code ec;
    for (const auto& e : std::filesystem::directory_iterator(m_dir, ec))
    {
        const std::string name = e.path().filename().string();
        unsigned n = 0;
        if (name.size() == 16 && std::sscanf(name.c_str(), "seg-%08u.log", &n) == 1)
            out.push_back(n);
    }
    std::sort(out.begin(), out.end());
    return out;
}

uint64_t seglog::read_records(uint32_t seg, uint64_t off,
                              const std::function<bool(uint64_t payload_off, std::string_view payload)>& each)
{
    const int fd = fd_of(seg);
    struct stat st{};
    if (fd < 0 || ::fstat(fd, &st) != 0)
        return off;
    const uint64_t size = static_cast<uint64_t>(st.st_size);
    // A window at a time, as a scan reads, so a long tail is not one read a record.
    std::string buf;
    uint64_t base = off;
    while (off + record_head <= size)
    {
        if (off + record_head > base + buf.size())
        {
            buf.erase(0, static_cast<size_t>(std::min<uint64_t>(off - base, buf.size())));
            base = off;
            const size_t want = static_cast<size_t>(std::min<uint64_t>(size - base, 1u << 20));
            const size_t had = buf.size();
            if (want > had)
            {
                buf.resize(want);
                if (!pread_all(fd, buf.data() + had, want - had, base + had))
                    break;
            }
        }
        const char* h = buf.data() + (off - base);
        const uint32_t len = get32(h);
        const uint32_t crc = get32(h + 4);
        if (len == 0 || len > max_record || off + record_head + len > size)
            break;
        if (off + record_head + len > base + buf.size())
        {
            buf.erase(0, static_cast<size_t>(off - base));
            base = off;
            const size_t had = buf.size();
            buf.resize(record_head + len);
            if (!pread_all(fd, buf.data() + had, buf.size() - had, base + had))
                break;
        }
        const std::string_view payload(buf.data() + (off - base) + record_head, len);
        if (journal_detail::crc32(payload) != crc || !each(off + record_head, payload))
            break;
        off += record_head + len;
    }
    m_segs[seg].size = std::max(m_segs[seg].size, off);
    return off;
}

void seglog::forget(uint32_t seg)
{
    const auto it = m_segs.find(seg);
    if (it == m_segs.end())
        return;
    if (it->second.fd >= 0)
        ::close(it->second.fd);
    m_segs.erase(it);
}

bool seglog::write_file(const std::string& path, const std::vector<std::string>& payloads, std::vector<uint64_t>& offs,
                        std::string& why)
{
    const std::string tmp = path + ".tmp";
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
    {
        why = tmp + " cannot be written";
        return false;
    }
    std::string buf = head_of();
    uint64_t at = 0;
    bool ok = true;
    offs.clear();
    offs.reserve(payloads.size());
    for (const auto& p : payloads)
    {
        char head[record_head];
        put32(head, static_cast<uint32_t>(p.size()));
        put32(head + 4, journal_detail::crc32(p));
        buf.append(head, record_head);
        offs.push_back(at + buf.size());
        buf.append(p);
        if (buf.size() >= (1u << 20))
        {
            ok = ok && write_all(fd, buf.data(), buf.size());
            at += buf.size();
            buf.clear();
        }
    }
    ok = ok && write_all(fd, buf.data(), buf.size()) && ::fsync(fd) == 0;
    ::close(fd);
    const std::string dir = std::filesystem::path(path).parent_path().string();
    if (!ok || ::rename(tmp.c_str(), path.c_str()) != 0 || !sync_dir(dir))
    {
        ::unlink(tmp.c_str());
        why = path + " could not be written to the disk";
        return false;
    }
    return true;
}

}   // namespace socketley::db
