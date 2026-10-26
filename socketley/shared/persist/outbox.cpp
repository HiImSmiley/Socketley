#include "outbox.h"

#include <algorithm>
#include <cerrno>
#include <cstring>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../loop/blocking_write.h"
#include "../util/byte_codec.h"
#include "../util/logging.h"
#include "../persist/mutation_journal.h"

namespace socketley
{

namespace
{

// The file is written again empty once nothing in it is owed and it has grown past this.
constexpr uint64_t rotate_bytes = 1u << 20;

}   // namespace

outbox::outbox(event_loop& loop, file_io& io, std::string what) : m_loop(loop), m_io(io), m_what(std::move(what)) {}

outbox::~outbox()
{
    *m_alive = false;
}

bool outbox::open(const std::string& dir, std::string_view sub, uint32_t shard, const change_made& made,
                  const keeper& keep, std::string& err)
{
    const std::string nd = dir + "/" + std::string(sub);
    if (::mkdir(nd.c_str(), 0755) < 0 && errno != EEXIST)
    {
        err = "cannot create " + nd + ": " + std::strerror(errno);
        return false;
    }
    m_dir_fd = ::open(nd.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (m_dir_fd < 0)
    {
        err = "cannot open " + nd + ": " + std::strerror(errno);
        return false;
    }
    m_name = "outbox." + std::to_string(shard);

    std::string text;
    if (const int fd = ::openat(m_dir_fd, m_name.c_str(), O_RDONLY | O_CLOEXEC); fd >= 0)
    {
        char buf[65536];
        for (;;)
        {
            const ssize_t n = ::read(fd, buf, sizeof(buf));
            if (n < 0 && errno == EINTR)
                continue;
            if (n < 0)
            {
                // A prefix taken as the whole would be written back without the entries still owed after it.
                err = "cannot read " + nd + "/" + m_name + ": " + std::strerror(errno);
                ::close(fd);
                return false;
            }
            if (n == 0)
                break;
            text.append(buf, static_cast<size_t>(n));
        }
        ::close(fd);
    }
    else if (errno != ENOENT)
    {
        err = "cannot open " + nd + "/" + m_name + ": " + std::strerror(errno);
        return false;
    }

    // Every entry with no delivery record, in the order they were made; a torn tail is a change never answered.
    struct held
    {
        uint64_t         id;
        std::string_view payload;
        // The staged change the entry is of, 0 for one that was made before its entry was written.
        uint64_t         change{0};
    };
    // A staged change's check, and what the file says of its end: 'C', 'X', or 0 for nothing.
    struct staged_end
    {
        std::string_view check;
        char             end{0};
    };
    std::vector<held> entries;
    std::vector<uint64_t> delivered;
    std::unordered_map<uint64_t, staged_end> changes;
    size_t pos = 0;
    while (text.size() - pos >= 8)
    {
        bytes::reader h(std::string_view(text).substr(pos, 8));
        uint32_t len = 0, crc = 0;
        // Any length append_record wrote is read back; one past the end of the file is a torn tail.
        if (!h.u32(len) || !h.u32(crc) || text.size() - pos - 8 < len)
            break;
        const std::string_view payload = std::string_view(text).substr(pos + 8, len);
        if (crc::crc32(payload) != crc)
            break;
        pos += 8 + len;
        bytes::reader r(payload);
        uint8_t  type   = 0;
        uint64_t id     = 0;
        uint64_t change = 0;
        if (!r.u8(type) || !r.u64(id) || (type == 'T' && !r.u64(change)))
            break;
        m_next_id = std::max(m_next_id, id + 1);
        if (type == 'D')
            delivered.push_back(id);
        else if (type == 'E')
            entries.push_back({id, payload.substr(9)});
        else if (type == 'T')
            entries.push_back({id, payload.substr(17), change});
        else if (type == 'S')
            changes[id].check = payload.substr(9);
        else if (type == 'C' || type == 'X')
            changes[id].end = static_cast<char>(type);
        else
            break;
    }
    std::sort(delivered.begin(), delivered.end());
    std::erase_if(entries, [&](const held& e) { return std::binary_search(delivered.begin(), delivered.end(), e.id); });

    // A staged change the file does not say the end of is asked of the files once, and its entries stay only if it is there.
    uint64_t unmade = 0;
    for (const held& e : entries)
        if (const auto it = changes.find(e.change); e.change != 0 && it != changes.end() && it->second.end == 0)
        {
            it->second.end = made && made(it->second.check) ? 'C' : '?';
            unmade += it->second.end == '?';
        }
    std::erase_if(entries, [&](const held& e)
    {
        const auto it = changes.find(e.change);
        return e.change != 0 && (it == changes.end() || it->second.end != 'C');
    });
    if (unmade)
        LOG_INFO((m_what + " drops what it owed for " + std::to_string(unmade) +
                  " change(s) a crash cut short before they were made").c_str());

    // Written again with only what is still owed, so the file never outgrows its undelivered entries.
    const std::string tmp = m_name + ".new";
    const int fd = ::openat(m_dir_fd, tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0)
    {
        err = "cannot write " + nd + "/" + tmp + ": " + std::strerror(errno);
        return false;
    }
    for (const held& e : entries)
        if (keep(e.id, e.payload))
        {
            // Encoded straight into the buffer, since the file it goes to is not the one appends go to yet.
            encode_record('E', e.id, e.payload);
            ++m_owed;
        }
    const bool ok = write_all(fd, m_buf.data(), m_buf.size()) && ::fsync(fd) == 0;
    ::close(fd);
    if (!ok || ::renameat(m_dir_fd, tmp.c_str(), m_dir_fd, m_name.c_str()) < 0 || ::fsync(m_dir_fd) < 0)
    {
        err = "cannot write " + nd + "/" + m_name + ": " + std::strerror(errno);
        m_buf.clear();
        return false;
    }
    m_off = m_buf.size();
    m_buf.clear();
    m_appended = m_synced = 0;
    m_fd = ::openat(m_dir_fd, m_name.c_str(), O_WRONLY | O_CLOEXEC);
    if (m_fd < 0)
    {
        err = "cannot open " + nd + "/" + m_name + ": " + std::strerror(errno);
        return false;
    }
    return true;
}

void outbox::append_record(char type, uint64_t id, std::string_view payload, uint64_t change)
{
    if (m_fd < 0 || m_stopped)
        return;
    encode_record(type, id, payload, change);
}

void outbox::encode_record(char type, uint64_t id, std::string_view payload, uint64_t change)
{
    std::string rec;
    {
        bytes::writer w;
        w.u8(static_cast<uint8_t>(type));
        w.u64(id);
        if (type == 'T')
            w.u64(change);
        rec = w.take();
    }
    rec += payload;
    bytes::writer h;
    h.u32(static_cast<uint32_t>(rec.size()));
    h.u32(crc::crc32(rec));
    m_buf += h.take();
    m_buf += rec;
    m_appended += 8 + rec.size();
}

uint64_t outbox::add(std::string_view payload)
{
    const uint64_t id = m_next_id++;
    ++m_owed;
    append_record('E', id, payload);
    return id;
}

uint64_t outbox::stage(std::string_view check, const std::vector<std::string>& payloads, std::vector<uint64_t>& ids)
{
    const uint64_t change = m_next_id++;
    append_record('S', change, check);
    ids.clear();
    for (const std::string& p : payloads)
    {
        ids.push_back(m_next_id++);
        append_record('T', ids.back(), p, change);
    }
    m_owed += payloads.size();
    // The ticket's records end here, and their sync starts now, beside the change's own.
    m_staged.emplace(change, staged_change{m_appended, payloads.size()});
    wait_for(m_appended, {});
    return change;
}

void outbox::staged(uint64_t ticket, std::function<void()> then)
{
    const auto it = m_staged.find(ticket);
    wait_for(it == m_staged.end() ? 0 : it->second.at, std::move(then));
}

void outbox::settle(uint64_t ticket, bool made, std::function<void()> then)
{
    const auto it = m_staged.find(ticket);
    if (it == m_staged.end())
    {
        then();
        return;
    }
    if (!made)
        m_owed -= std::min(m_owed, it->second.entries);
    m_staged.erase(it);
    append_record(made ? 'C' : 'X', ticket);
    sync(std::move(then));
}

void outbox::done(uint64_t id)
{
    if (m_owed)
        --m_owed;
    append_record('D', id);
    kick();
}

void outbox::wait_for(uint64_t at, std::function<void()> then)
{
    if (m_fd < 0 || at <= m_synced)
    {
        if (then)
            then();
        return;
    }
    m_waiters.push_back({at, std::move(then)});
    kick();
}

void outbox::kick()
{
    // Only what somebody waits for is synced; a delivery record lost to a crash costs a second delivery, and the next
    // sync covers it anyway.
    const bool must_sync = !m_waiters.empty();
    if (m_writing || m_rotating || m_fd < 0 || (m_buf.empty() && !must_sync))
        return;
    m_writing = true;
    auto buf  = std::make_shared<std::string>(std::move(m_buf));
    m_buf.clear();
    const uint64_t upto = m_appended;
    auto alive = m_alive;
    auto sync_then = [this, alive, buf, upto, must_sync](int64_t res)
    {
        if (!*alive)
            return;
        if (res >= 0 && !must_sync)
        {
            m_unsynced = true;
            written(res, upto, false);
            return;
        }
        if (res >= 0 && !m_io.sync(m_fd, true, [this, alive, upto](int64_t r2)
            {
                if (*alive)
                    written(r2, upto, true);
            }))
            res = -EIO;
        if (res < 0)
            written(res, upto, false);
    };
    if (buf->empty())
    {
        sync_then(0);
        return;
    }
    const uint64_t at = m_off;
    m_off += buf->size();
    if (!m_io.pwrite(m_fd, buf->data(), static_cast<uint32_t>(buf->size()), at, std::move(sync_then)))
        written(-EIO, upto, false);
}

void outbox::written(int64_t res, uint64_t upto, bool synced)
{
    m_writing = false;
    // A failed write leaves the entries in memory, delivered as long as this process lives, and is said once.
    if (res < 0 && !m_write_failed)
    {
        m_write_failed = true;
        LOG_ERROR((m_what + ": writing it failed (" + std::string(std::strerror(static_cast<int>(-res))) +
                   "); what it holds is delivered but would not survive a crash").c_str());
    }
    if (res >= 0 && synced)
    {
        m_synced   = upto;
        m_unsynced = false;
    }
    // Whoever waited on a write that failed is let go too, since nothing would ever sync it.
    const uint64_t done_upto = res < 0 ? upto : m_synced;
    std::vector<std::function<void()>> ready;
    std::erase_if(m_waiters, [&](waiter& w)
    {
        if (w.at > done_upto)
            return false;
        if (w.then)
            ready.push_back(std::move(w.then));
        return true;
    });
    for (auto& cb : ready)
        cb();
    kick();
    maybe_rotate();
}

void outbox::maybe_rotate()
{
    if (m_owed != 0 || m_writing || m_rotating || !m_buf.empty() || !m_waiters.empty() || !m_staged.empty() ||
        m_off < rotate_bytes || m_fd < 0 || m_stopped)
        return;
    m_rotating = true;
    auto alive = m_alive;
    const std::string tmp = m_name + ".new";
    auto fail = [this](std::string_view why)
    {
        LOG_WARN((m_what + " could not be started again empty: " + std::string(why)).c_str());
        m_rotating = false;
        kick();
    };
    const bool q = m_io.openat(m_dir_fd, tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644,
        [this, alive, tmp, fail](int64_t fd)
        {
            if (!*alive)
                return;
            // A stop that came in the middle closed the files this would go on with, so nothing more is done.
            if (m_stopped)
            {
                if (fd >= 0)
                    m_loop.close_fd(static_cast<int>(fd));
                m_rotating = false;
                return;
            }
            if (fd < 0)
            {
                fail(std::strerror(static_cast<int>(-fd)));
                return;
            }
            const bool q2 = m_io.renameat(m_dir_fd, tmp, m_dir_fd, m_name, [this, alive, fd, fail](int64_t r)
            {
                if (!*alive)
                    return;
                if (m_stopped)
                {
                    m_loop.close_fd(static_cast<int>(fd));
                    m_rotating = false;
                    return;
                }
                if (r < 0)
                {
                    m_loop.close_fd(static_cast<int>(fd));
                    fail(std::strerror(static_cast<int>(-r)));
                    return;
                }
                // The old file's name is gone, so its descriptor is let go of and everything after goes to the new one.
                m_loop.close_fd(m_fd);
                m_fd  = static_cast<int>(fd);
                m_off = 0;
                m_unsynced = false;
                // What the old file held is let go of, so only what waits to be written is not yet synced.
                m_synced = m_appended - m_buf.size();
                if (!m_io.fsync(m_dir_fd, false, [this, alive](int64_t)
                    {
                        if (!*alive)
                            return;
                        m_rotating = false;
                        if (!m_stopped)
                            kick();
                    }))
                {
                    m_rotating = false;
                    kick();
                }
            });
            if (!q2)
            {
                m_loop.close_fd(static_cast<int>(fd));
                fail("the ring is full");
            }
        });
    if (!q)
        fail("the ring is full");
}

void outbox::stop()
{
    if (m_stopped)
        return;
    m_stopped = true;
    // The delivery records not yet written are written here, blocking as a stop may, so a restart does not send them again.
    if (m_fd >= 0 && (!m_buf.empty() || m_unsynced) && !m_rotating)
    {
        if ((m_buf.empty() ||
             ::pwrite(m_fd, m_buf.data(), m_buf.size(), static_cast<off_t>(m_off)) == static_cast<ssize_t>(m_buf.size())) &&
            ::fdatasync(m_fd) == 0)
            m_off += m_buf.size();
        m_buf.clear();
        m_unsynced = false;
    }
    if (m_fd >= 0)
        m_loop.close_fd(m_fd);
    m_fd = -1;
    if (m_dir_fd >= 0)
        m_loop.close_fd(m_dir_fd);
    m_dir_fd = -1;
}

}   // namespace socketley
