#pragma once
// An append-only journal of mutations between two snapshots, so a process
// killed mid-run loses at most one flush interval rather than everything
// since the last dump.
//
// Layout: a fixed magic, then an owner blob the caller supplies and judges,
// then records framed `u32 length | u32 crc32 | payload` -- length-prefixed
// because payloads carry newlines, and checksummed because a torn write must
// end the replay rather than replay garbage as a command.
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <functional>

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "blocking_write.h"

// CRC-32 (IEEE), table built at compile time like cache_shard_map's CRC-16,
// because pasting 256 constants is how a table acquires a typo.
namespace journal_detail
{
// Slicing-by-8: row k is the CRC of a byte followed by k zero bytes, so eight
// bytes fold in one step of eight independent lookups.
struct crc32_table
{
    uint32_t v[8][256];
};

inline constexpr crc32_table make_crc32_table()
{
    crc32_table t{};
    for (uint32_t i = 0; i < 256; ++i)
    {
        uint32_t c = i;
        for (int k = 0; k < 8; ++k)
            c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        t.v[0][i] = c;
    }
    for (uint32_t i = 0; i < 256; ++i)
        for (int k = 1; k < 8; ++k)
            t.v[k][i] = t.v[0][t.v[k - 1][i] & 0xFFu] ^ (t.v[k - 1][i] >> 8);
    return t;
}

inline constexpr crc32_table crc32_tab = make_crc32_table();

inline uint32_t crc32(std::string_view s)
{
    const auto* p = reinterpret_cast<const unsigned char*>(s.data());
    size_t      n = s.size();
    uint32_t    c = 0xFFFFFFFFu;
    const auto& t = crc32_tab.v;
    while (n >= 8)
    {
        const uint32_t lo = c ^ (uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16
                                 | uint32_t(p[3]) << 24);
        c = t[7][lo & 0xFFu] ^ t[6][(lo >> 8) & 0xFFu] ^ t[5][(lo >> 16) & 0xFFu] ^ t[4][lo >> 24]
          ^ t[3][p[4]] ^ t[2][p[5]] ^ t[1][p[6]] ^ t[0][p[7]];
        p += 8;
        n -= 8;
    }
    while (n--)
        c = t[0][(c ^ *p++) & 0xFFu] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}
} // namespace journal_detail

class mutation_journal
{
public:
    static constexpr char   magic[8]      = { 'S','K','L','J','R','N','L','1' };
    static constexpr size_t record_head   = 8;             // u32 length + u32 crc
    // Any length the head can state is data: a command is as long as the runtime's --read-buffer allows, and the CRC
    // and the file's end are what tell damage. A cap below that refused a long MSET on replay and cut every record
    // after it away.
    static constexpr size_t max_record    = UINT32_MAX;
    // What is held for a disk that takes nothing before the journal stops.
    static constexpr size_t max_pending   = size_t{256} << 20;

    // What a file at the journal's name turned out to be, judged before this
    // run writes a byte of its own.
    enum class probe_result : uint8_t
    {
        absent,        // no file, which is not an error
        empty,         // a journal with no complete record, whoever wrote it
        has_records,   // a journal with at least one complete record
        not_a_journal, // some other file at the journal's name
        unreadable,    // open or read failed
    };

    struct replay_stats
    {
        uint64_t records{0};
        uint64_t dropped_bytes{0};  // everything after the last complete record
        bool     torn{false};
    };

    // Read the head and count complete records, filling `owner` with the blob
    // the writer stamped, so the caller can tell its own journal from one a
    // differently-sharded run left behind.
    static probe_result probe(const std::string& path, std::string& owner)
    {
        owner.clear();
        std::string data;
        if (!slurp(path, data))
            return ::access(path.c_str(), F_OK) == 0 ? probe_result::unreadable
                                                     : probe_result::absent;
        // A file of no bytes holds no records, which is what `empty` means,
        // and open_append writes the head over it.  Judging it not-a-journal
        // refused the start: creat(2) makes the file before the head is
        // written, so a full disk leaves exactly this and a cache that will
        // not come back until someone deletes an empty file.
        if (data.empty())
            return probe_result::empty;

        size_t off = 0;
        if (!take_header(data, off, owner))
            return probe_result::not_a_journal;

        replay_stats st;
        walk(data, off, nullptr, st);
        return st.records > 0 ? probe_result::has_records : probe_result::empty;
    }

    // Hand every complete record to `apply` in write order and stop at the
    // first torn or corrupt frame, because everything after it is a tail the
    // crash already took.
    static bool replay(const std::string& path,
                       const std::function<void(std::string_view)>& apply,
                       replay_stats& out)
    {
        out = replay_stats{};
        std::string data;
        if (!slurp(path, data))
            return false;
        size_t off = 0;
        std::string owner;
        if (!take_header(data, off, owner))
            return false;
        walk(data, off, &apply, out);
        return true;
    }

    // replay() of a journal another process writes, open at `fd`, with the offset after its last complete record,
    // which tail() goes on from.
    static bool replay_fd(int fd, std::string& owner,
                          const std::function<void(std::string_view)>& apply,
                          uint64_t& end)
    {
        std::string data;
        size_t off = 0;
        if (!slurp_fd(fd, data) || !take_header(data, off, owner))
            return false;
        replay_stats st;
        walk(data, off, &apply, st);
        end = data.size() - st.dropped_bytes;
        return true;
    }

    // The complete records between `from`, where one begins, and `to`, in order; the offset after the last of them.
    static uint64_t tail(int fd, uint64_t from, uint64_t to,
                         const std::function<void(std::string_view)>& apply)
    {
        if (to <= from)
            return from;
        std::string data(static_cast<size_t>(to - from), '\0');
        size_t got = 0;
        while (got < data.size())
        {
            const ssize_t n = ::pread(fd, data.data() + got, data.size() - got,
                                      static_cast<off_t>(from + got));
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0)
                break;
            got += static_cast<size_t>(n);
        }
        data.resize(got);
        replay_stats st;
        walk(data, 0, &apply, st);
        return from + (data.size() - st.dropped_bytes);
    }

    // Open for appending, writing the head when the file is new or empty; an
    // existing head that does not match `owner` is refused here as well,
    // because the caller's probe and this open race nothing but a mistake.
    bool open_append(const std::string& path, std::string_view owner)
    {
        close();
        const int fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_APPEND, 0600);
        if (fd < 0)
            return false;

        struct stat st{};
        if (::fstat(fd, &st) != 0)
        {
            ::close(fd);
            return false;
        }

        const size_t head = sizeof(magic) + 4 + owner.size();
        if (st.st_size == 0)
        {
            std::string h;
            h.reserve(head);
            h.append(magic, sizeof(magic));
            char len4[4];
            put32(len4, static_cast<uint32_t>(owner.size()));
            h.append(len4, 4);
            h.append(owner.data(), owner.size());
            if (!socketley::write_all(fd, h.data(), h.size()))
            {
                // Back to empty, or the next start finds a part of a header and refuses the journal for good.
                if (::ftruncate(fd, 0) != 0) {}
                ::close(fd);
                return false;
            }
        }
        else
        {
            std::string data;
            if (!slurp_fd(fd, data))
            {
                ::close(fd);
                return false;
            }
            size_t off = 0;
            std::string found;
            if (!take_header(data, off, found) || found != owner)
            {
                ::close(fd);
                return false;
            }
            // A torn tail is cut here, because replay stops at the first bad
            // frame and a record appended behind it could never be read back.
            replay_stats st;
            walk(data, off, nullptr, st);
            if (st.torn &&
                ::ftruncate(fd, static_cast<off_t>(data.size() - st.dropped_bytes)) != 0)
            {
                ::close(fd);
                return false;
            }
        }

        m_fd = fd;
        m_head = head;
        m_pending.clear();
        m_given_up = false;
        return true;
    }

    void append(std::string_view record)
    {
        // A length the head cannot carry would be written short and read as damage; such a record is not kept.
        if (record.size() > max_record)
            return;
        // Bounded while the disk takes nothing: past it the journal stops, and the dump is the record from then on.
        if (m_given_up || m_pending.size() > max_pending)
        {
            m_given_up = true;
            m_pending.clear();
            return;
        }
        char head[record_head];
        put32(head,     static_cast<uint32_t>(record.size()));
        put32(head + 4, journal_detail::crc32(record));
        m_pending.append(head, record_head);
        m_pending.append(record.data(), record.size());
    }

    // One write of whatever accumulated and no fsync: the page cache is the
    // promise, which covers a dead process but not a dead machine.  What was
    // delivered leaves the buffer even on a short write, so a retry cannot
    // append the same bytes twice.
    bool flush()
    {
        if (m_given_up)
            return false;
        if (m_fd < 0 || m_pending.empty())
            return true;
        size_t written = 0;
        const bool ok = socketley::write_all(m_fd, m_pending.data(),
                                             m_pending.size(), &written);
        m_pending.erase(0, written);
        return ok;
    }

    // flush() and then the disk's own promise, for a record that must outlive a dead machine.
    bool sync()
    {
        return flush() && m_fd >= 0 && ::fdatasync(m_fd) == 0;
    }

    // Cut the records off behind a snapshot that now contains their effects,
    // buffer included, because both describe state the dump has absorbed.
    bool reset()
    {
        m_pending.clear();
        if (m_fd < 0)
            return true;
        return ::ftruncate(m_fd, static_cast<off_t>(m_head)) == 0;
    }

    void close()
    {
        if (m_fd >= 0)
            ::close(m_fd);
        m_fd = -1;
        m_pending.clear();
    }

    bool   is_open() const       { return m_fd >= 0; }
    // The descriptor, for a caller that syncs it off its loop after flush().
    int    fd() const            { return m_fd; }
    size_t pending_bytes() const { return m_pending.size(); }

    ~mutation_journal() { close(); }

    mutation_journal() = default;
    mutation_journal(const mutation_journal&) = delete;
    mutation_journal& operator=(const mutation_journal&) = delete;

private:
    static void put32(char* at, uint32_t v)
    {
        for (int i = 0; i < 4; ++i)
            at[i] = static_cast<char>((v >> (8 * i)) & 0xFF);
    }

    static uint32_t get32(const char* at)
    {
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i)
            v |= static_cast<uint32_t>(static_cast<unsigned char>(at[i])) << (8 * i);
        return v;
    }

    static bool slurp(const std::string& path, std::string& out)
    {
        const int fd = ::open(path.c_str(), O_RDONLY);
        if (fd < 0)
            return false;
        const bool ok = slurp_fd(fd, out);
        ::close(fd);
        return ok;
    }

    static bool slurp_fd(int fd, std::string& out)
    {
        struct stat st{};
        if (::fstat(fd, &st) != 0 || st.st_size < 0)
            return false;
        out.resize(static_cast<size_t>(st.st_size));
        size_t got = 0;
        while (got < out.size())
        {
            const ssize_t n = ::pread(fd, out.data() + got, out.size() - got,
                                      static_cast<off_t>(got));
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0)
                return false;
            got += static_cast<size_t>(n);
        }
        return true;
    }

    static bool take_header(const std::string& data, size_t& off, std::string& owner)
    {
        if (data.size() < sizeof(magic) + 4
            || std::memcmp(data.data(), magic, sizeof(magic)) != 0)
            return false;
        const uint32_t olen = get32(data.data() + sizeof(magic));
        if (data.size() < sizeof(magic) + 4 + olen)
            return false;
        owner.assign(data.data() + sizeof(magic) + 4, olen);
        off = sizeof(magic) + 4 + olen;
        return true;
    }

    // The one frame walk both probe and replay use, so they cannot disagree
    // about where the last complete record ends.
    static void walk(const std::string& data, size_t off,
                     const std::function<void(std::string_view)>* apply,
                     replay_stats& st)
    {
        size_t p = off;
        while (data.size() - p >= record_head)
        {
            const uint32_t len = get32(data.data() + p);
            const uint32_t crc = get32(data.data() + p + 4);
            if (data.size() - p - record_head < len)
                break;
            const std::string_view rec(data.data() + p + record_head, len);
            if (journal_detail::crc32(rec) != crc)
                break;
            if (apply)
                (*apply)(rec);
            ++st.records;
            p += record_head + len;
        }
        st.dropped_bytes = data.size() - p;
        st.torn          = st.dropped_bytes > 0;
    }

    int         m_fd{-1};
    size_t      m_head{0};
    std::string m_pending;
    // Set when m_pending outgrew max_pending with nothing written; cleared by the next open.
    bool m_given_up{false};
};
