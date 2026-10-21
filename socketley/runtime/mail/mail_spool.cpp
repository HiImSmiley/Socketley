#include "mail_spool.h"

#include <atomic>
#include <charconv>
#include <chrono>
#include <cstring>
#include <ctime>
#include <filesystem>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../shared/loop/blocking_write.h"
#include "../../shared/util/logging.h"
#include "../../shared/util/text_list.h"
#include "../../shared/util/wall_clock.h"

namespace socketley::mail
{

namespace
{

constexpr std::string_view magic = "SKLMAIL1\n";
constexpr size_t flush_at = 256u << 10;

// A word of the log or the header never holds a line's end.
std::string one_line(std::string_view s)
{
    std::string out(s.substr(0, 500));
    for (char& c : out)
        if (c == '\n' || c == '\r')
            c = ' ';
    return out;
}

std::string header_of(const spool_entry& e)
{
    std::string h(magic);
    h += "id " + e.id + "\n";
    h += "at " + std::to_string(e.at_ms) + "\n";
    h += "from " + one_line(e.from) + "\n";
    for (const auto& r : e.rcpts)
        h += "rcpt " + one_line(r.addr) + "\n";
    if (!e.user.empty())
        h += "user " + one_line(e.user) + "\n";
    if (!e.peer.empty())
        h += "peer " + one_line(e.peer) + "\n";
    if (!e.helo.empty())
        h += "helo " + one_line(e.helo) + "\n";
    if (e.bounce)
        h += "bounce 1\n";
    h += "\n";
    return h;
}

bool read_at(int fd, std::string& out, size_t n, uint64_t off)
{
    out.resize(n);
    size_t got = 0;
    while (got < n)
    {
        const ssize_t r = ::pread(fd, out.data() + got, n - got, static_cast<off_t>(off + got));
        if (r < 0 && errno == EINTR)
            continue;
        if (r <= 0)
            break;
        got += static_cast<size_t>(r);
    }
    out.resize(got);
    return got == n;
}

template <class T>
bool number(std::string_view s, T& out)
{
    const auto r = std::from_chars(s.data(), s.data() + s.size(), out);
    return r.ec == std::errc() && r.ptr == s.data() + s.size();
}

// The envelope ahead of a message's body, read back; false for a file this runtime did not write.
bool parse_header(std::string_view text, spool_entry& e, size_t& header_len)
{
    if (!text.starts_with(magic))
        return false;
    size_t at = magic.size();
    while (at < text.size())
    {
        const size_t nl = text.find('\n', at);
        if (nl == std::string_view::npos)
            return false;
        const std::string_view line = text.substr(at, nl - at);
        at = nl + 1;
        if (line.empty())
        {
            header_len = at;
            return !e.id.empty() && !e.rcpts.empty();
        }
        const size_t sp = line.find(' ');
        const std::string_view key = line.substr(0, sp);
        const std::string_view val = sp == std::string_view::npos ? std::string_view{} : line.substr(sp + 1);
        if (key == "id")
            e.id = std::string(val);
        else if (key == "at")
            number(val, e.at_ms);
        else if (key == "from")
            e.from = std::string(val);
        else if (key == "rcpt")
            e.rcpts.push_back({std::string(val), rcpt_state::waiting, {}});
        else if (key == "user")
            e.user = std::string(val);
        else if (key == "peer")
            e.peer = std::string(val);
        else if (key == "helo")
            e.helo = std::string(val);
        else if (key == "bounce")
            e.bounce = val == "1";
    }
    return false;
}

}   // namespace

size_t spool_entry::waiting() const
{
    size_t n = 0;
    for (const auto& r : rcpts)
        n += r.state == rcpt_state::waiting;
    return n;
}

std::string new_spool_id(uint32_t shard)
{
    static std::atomic<uint32_t> seq{0};
    const uint64_t us = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
    char buf[40];
    std::snprintf(buf, sizeof buf, "%013llx%05x%02x", static_cast<unsigned long long>(us),
                  seq.fetch_add(1, std::memory_order_relaxed) & 0xFFFFF, shard & 0xFF);
    return buf;
}

spool::~spool()
{
    *m_alive = false;
    close();
}

bool spool::open(const std::string& dir, bool relaxed, std::string& why)
{
    m_dir = dir;
    m_relaxed = relaxed;
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (!std::filesystem::is_directory(dir, ec))
    {
        why = "the spool directory " + dir + " cannot be made";
        return false;
    }
    if (::chmod(dir.c_str(), 0700) != 0) {}
    std::vector<std::string> cut;
    for (const auto& de : std::filesystem::directory_iterator(dir, ec))
    {
        const std::string name = de.path().filename().string();
        if (!name.ends_with(".msg"))
            continue;
        const std::string path = de.path().string();
        const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0)
            continue;
        struct stat st{};
        auto e = std::make_shared<spool_entry>();
        std::string head, tail;
        size_t header_len = 0;
        bool ok = ::fstat(fd, &st) == 0 && st.st_size > 0;
        if (ok)
        {
            read_at(fd, head, std::min<size_t>(static_cast<size_t>(st.st_size), 64u << 10), 0);
            ok = parse_header(head, *e, header_len);
        }
        if (ok)
        {
            // "\nend <length>\n" closes a file written to its end.
            const size_t n = std::min<size_t>(static_cast<size_t>(st.st_size), 40);
            read_at(fd, tail, n, static_cast<uint64_t>(st.st_size) - n);
            const size_t mark = tail.rfind("\nend ");
            uint64_t len = 0;
            ok = mark != std::string::npos && tail.back() == '\n' &&
                 number(std::string_view(tail).substr(mark + 5, tail.size() - mark - 6), len) &&
                 header_len + len + (tail.size() - mark) == static_cast<uint64_t>(st.st_size);
            e->body_off = header_len;
            e->body_len = len;
        }
        ::close(fd);
        if (!ok || name != e->id + ".msg")
        {
            cut.push_back(path);
            continue;
        }
        m_bytes += e->body_len;
        m_entries.emplace(e->id, std::move(e));
    }
    for (const auto& p : cut)
    {
        LOG_WARN(("mail: " + p + " was cut short by a crash while it was received, and is deleted; its sender was "
                  "never told it was taken")
                     .c_str());
        std::filesystem::remove(p, ec);
    }
    // What became of each recipient, the log rewritten with only the messages still here.
    const std::string log_path = dir + "/state.log";
    {
        std::string text;
        const int fd = ::open(log_path.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd >= 0)
        {
            struct stat st{};
            if (::fstat(fd, &st) == 0)
                read_at(fd, text, static_cast<size_t>(st.st_size), 0);
            ::close(fd);
        }
        std::string_view rest = text;
        while (!rest.empty())
        {
            std::string_view line = socketley::take_item(rest, '\n');
            const size_t a = line.find(' ');
            if (a == std::string_view::npos)
                continue;
            const auto it = m_entries.find(std::string(line.substr(0, a)));
            if (it == m_entries.end())
                continue;
            spool_entry& e = *it->second;
            line.remove_prefix(a + 1);
            const char kind = line.empty() ? 0 : line.front();
            line.remove_prefix(std::min<size_t>(line.size(), 2));
            const size_t b = line.find(' ');
            size_t i = 0;
            if (kind == 'r')
            {
                number(line.substr(0, b), e.attempts);
                if (b != std::string_view::npos)
                    number(line.substr(b + 1), e.next_ms);
            }
            else if ((kind == 'd' || kind == 'f') && number(line.substr(0, b), i) && i < e.rcpts.size())
            {
                e.rcpts[i].state = kind == 'd' ? rcpt_state::delivered : rcpt_state::failed;
                e.rcpts[i].why = b == std::string_view::npos ? std::string() : std::string(line.substr(b + 1));
            }
        }
    }
    std::string compact;
    std::vector<std::string> over;
    for (const auto& [id, e] : m_entries)
    {
        if (e->waiting() == 0)
        {
            over.push_back(id);
            continue;
        }
        if (e->attempts)
            compact += id + " r " + std::to_string(e->attempts) + " " + std::to_string(e->next_ms) + "\n";
        for (size_t i = 0; i < e->rcpts.size(); ++i)
            if (e->rcpts[i].state != rcpt_state::waiting)
                compact += id + (e->rcpts[i].state == rcpt_state::delivered ? " d " : " f ") + std::to_string(i) +
                           " " + one_line(e->rcpts[i].why) + "\n";
    }
    for (const auto& id : over)
    {
        std::filesystem::remove(path_of(id), ec);
        m_bytes -= m_entries[id]->body_len;
        m_entries.erase(id);
    }
    const std::string tmp = log_path + ".tmp";
    const int wfd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (wfd < 0 || !write_all(wfd, compact.data(), compact.size()) || ::fsync(wfd) != 0 ||
        ::rename(tmp.c_str(), log_path.c_str()) != 0)
    {
        if (wfd >= 0)
            ::close(wfd);
        why = log_path + " cannot be written";
        return false;
    }
    ::close(wfd);
    m_log_fd = ::open(log_path.c_str(), O_WRONLY | O_APPEND | O_CLOEXEC);
    if (m_log_fd < 0)
    {
        why = log_path + " cannot be opened";
        return false;
    }
    return true;
}

void spool::close()
{
    if (m_log_fd >= 0)
    {
        // What the log still holds goes in line, since nothing after this waits for the ring.
        if (!m_log_buf.empty() && !write_all(m_log_fd, m_log_buf.data(), m_log_buf.size())) {}
        ::close(m_log_fd);
        m_log_fd = -1;
    }
    for (auto& [id, r] : m_readers)
        if (r.fd >= 0)
            ::close(r.fd);
    m_readers.clear();
}

entry_ptr spool::find(const std::string& id) const
{
    const auto it = m_entries.find(id);
    return it == m_entries.end() ? nullptr : it->second;
}

uint64_t spool::begin(entry_ptr e, std::string_view head)
{
    const uint64_t id = m_next_writer++;
    auto w = std::make_unique<writer>();
    std::string h = header_of(*e);
    e->body_off = h.size();
    e->body_len = head.size();
    w->buf = std::move(h);
    w->buf.append(head);
    w->copy.assign(head);
    w->e = std::move(e);
    w->opening = true;
    writer* raw = w.get();
    m_writers.emplace(id, std::move(w));
    const bool queued = m_io.openat(AT_FDCWD, path_of(raw->e->id), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600,
                                    [this, id, alive = m_alive](int64_t res) {
                                        if (!*alive)
                                            return;
                                        const auto it = m_writers.find(id);
                                        if (it == m_writers.end())
                                            return;
                                        it->second->opening = false;
                                        if (res < 0)
                                            it->second->failed = true;
                                        else
                                            it->second->fd = static_cast<int>(res);
                                        pump(id);
                                    });
    if (!queued)
    {
        raw->opening = false;
        raw->failed = true;
    }
    return id;
}

void spool::append(uint64_t w, std::string_view bytes)
{
    const auto it = m_writers.find(w);
    if (it == m_writers.end())
        return;
    writer& x = *it->second;
    x.buf.append(bytes);
    x.e->body_len += bytes.size();
    if (x.copying)
    {
        if (x.copy.size() + bytes.size() <= keep_one)
            x.copy.append(bytes);
        else
        {
            x.copying = false;
            std::string().swap(x.copy);
        }
    }
    if (x.buf.size() >= flush_at)
        pump(w);
}

void spool::finish(uint64_t w, std::function<void(bool)> done)
{
    const auto it = m_writers.find(w);
    if (it == m_writers.end())
    {
        done(false);
        return;
    }
    writer& x = *it->second;
    x.done = std::move(done);
    x.finishing = true;
    x.buf += "\nend " + std::to_string(x.e->body_len) + "\n";
    pump(w);
}

void spool::abort(uint64_t w)
{
    const auto it = m_writers.find(w);
    if (it == m_writers.end())
        return;
    it->second->aborted = true;
    pump(w);
}

void spool::pump(uint64_t w)
{
    const auto it = m_writers.find(w);
    if (it == m_writers.end())
        return;
    writer& x = *it->second;
    if (x.opening || x.writing)
        return;
    if (x.aborted || x.failed)
    {
        if (x.fd >= 0)
        {
            m_loop.close_fd(x.fd);
            x.fd = -1;
            if (!m_io.unlinkat(AT_FDCWD, path_of(x.e->id), 0, [](int64_t) {})) {}
        }
        if (x.aborted)
            m_writers.erase(it);
        else if (x.finishing)
            end(w, false);
        return;
    }
    if (!x.buf.empty() && (x.finishing || x.buf.size() >= flush_at))
    {
        x.flying.swap(x.buf);
        x.buf.clear();
        x.writing = true;
        const uint64_t at = x.off;
        x.off += x.flying.size();
        if (!m_io.pwrite(x.fd, x.flying.data(), static_cast<uint32_t>(x.flying.size()), at,
                         [this, w, alive = m_alive](int64_t res) {
                             if (!*alive)
                                 return;
                             const auto i = m_writers.find(w);
                             if (i == m_writers.end())
                                 return;
                             i->second->writing = false;
                             if (res < 0)
                                 i->second->failed = true;
                             pump(w);
                         }))
        {
            x.writing = false;
            x.failed = true;
            pump(w);
        }
        return;
    }
    if (x.finishing && x.buf.empty())
    {
        x.writing = true;
        if (!m_io.sync(x.fd, true, [this, w, alive = m_alive](int64_t res) {
                if (!*alive)
                    return;
                const auto i = m_writers.find(w);
                if (i == m_writers.end())
                    return;
                i->second->writing = false;
                if (res < 0)
                {
                    i->second->failed = true;
                    pump(w);
                    return;
                }
                end(w, true);
            }))
        {
            x.writing = false;
            x.failed = true;
            pump(w);
        }
    }
}

void spool::end(uint64_t w, bool ok)
{
    const auto it = m_writers.find(w);
    if (it == m_writers.end())
        return;
    std::unique_ptr<writer> x = std::move(it->second);
    m_writers.erase(it);
    if (x->fd >= 0)
    {
        m_loop.close_fd(x->fd);
        x->fd = -1;
    }
    if (ok)
    {
        if (x->copying && m_kept + x->copy.size() <= keep_all)
        {
            m_kept += x->copy.size();
            x->e->body = std::make_shared<const std::string>(std::move(x->copy));
        }
        m_bytes += x->e->body_len;
        ++m_written;
        m_entries[x->e->id] = x->e;
    }
    else
        ++m_write_failures;
    if (x->done)
        x->done(ok);
}

void spool::log(std::string line)
{
    if (m_log_fd < 0)
        return;
    m_log_buf += line;
    if (m_log_writing)
        return;
    m_log_writing = true;
    auto flying = std::make_shared<std::string>();
    flying->swap(m_log_buf);
    const bool queued = m_io.pwrite(m_log_fd, flying->data(), static_cast<uint32_t>(flying->size()), file_io::at_stream,
                                    [this, flying, alive = m_alive](int64_t) {
                                        if (!*alive)
                                            return;
                                        m_log_writing = false;
                                        if (!m_log_buf.empty())
                                            log({});
                                    });
    if (!queued)
    {
        // The ring had no room: the line goes in line, a small append to the page cache.
        if (!write_all(m_log_fd, flying->data(), flying->size())) {}
        m_log_writing = false;
    }
}

void spool::mark(spool_entry& e, size_t rcpt, rcpt_state s, std::string_view why)
{
    if (rcpt >= e.rcpts.size())
        return;
    e.rcpts[rcpt].state = s;
    e.rcpts[rcpt].why = one_line(why);
    log(e.id + (s == rcpt_state::delivered ? " d " : " f ") + std::to_string(rcpt) + " " + e.rcpts[rcpt].why + "\n");
}

void spool::retry(spool_entry& e, uint32_t attempts, int64_t next_ms)
{
    e.attempts = attempts;
    e.next_ms = next_ms;
    log(e.id + " r " + std::to_string(attempts) + " " + std::to_string(next_ms) + "\n");
}

void spool::remove(const std::string& id)
{
    const auto it = m_entries.find(id);
    if (it == m_entries.end())
        return;
    if (it->second->body)
        m_kept -= std::min<uint64_t>(m_kept, it->second->body->size());
    m_bytes -= std::min<uint64_t>(m_bytes, it->second->body_len);
    m_entries.erase(it);
    if (const auto r = m_readers.find(id); r != m_readers.end())
    {
        if (r->second.fd >= 0)
            m_loop.close_fd(r->second.fd);
        m_readers.erase(r);
    }
    if (!m_io.unlinkat(AT_FDCWD, path_of(id), 0, [](int64_t) {}))
        ::unlink(path_of(id).c_str());
}

void spool::read(const entry_ptr& e, uint64_t off, uint32_t len,
                 std::function<void(bool ok, std::string_view bytes)> cb)
{
    if (off >= e->body_len)
    {
        cb(true, {});
        return;
    }
    len = static_cast<uint32_t>(std::min<uint64_t>(len, e->body_len - off));
    if (e->body)
    {
        cb(true, std::string_view(*e->body).substr(off, len));
        return;
    }
    const std::string id = e->id;
    const uint64_t file_off = e->body_off + off;
    auto go = [this, id, file_off, len, cb, alive = m_alive](int fd) {
        if (!*alive)
            return;
        if (fd < 0)
        {
            cb(false, {});
            return;
        }
        auto buf = std::make_shared<std::string>(len, '\0');
        if (!m_io.pread(fd, buf->data(), len, file_off, [buf, cb, len, alive](int64_t res) {
                if (!*alive)
                    return;
                if (res != static_cast<int64_t>(len))
                    cb(false, {});
                else
                    cb(true, *buf);
            }))
            cb(false, {});
    };
    reader& r = m_readers[id];
    if (r.fd >= 0)
    {
        go(r.fd);
        return;
    }
    r.waiting.push_back(std::move(go));
    if (r.opening)
        return;
    r.opening = true;
    if (!m_io.openat(AT_FDCWD, path_of(id), O_RDONLY | O_CLOEXEC, 0, [this, id, alive = m_alive](int64_t res) {
            if (!*alive)
                return;
            const auto it = m_readers.find(id);
            if (it == m_readers.end())
            {
                if (res >= 0)
                    m_loop.close_fd(static_cast<int>(res));
                return;
            }
            it->second.opening = false;
            it->second.fd = res >= 0 ? static_cast<int>(res) : -1;
            auto waiting = std::move(it->second.waiting);
            const int fd = it->second.fd;
            if (fd < 0)
                m_readers.erase(it);
            for (auto& f : waiting)
                f(fd);
        }))
    {
        auto waiting = std::move(r.waiting);
        m_readers.erase(id);
        for (auto& f : waiting)
            f(-1);
    }
}

}   // namespace socketley::mail
