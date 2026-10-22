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
#include "../../shared/util/crc.h"
#include "../../shared/util/logging.h"
#include "../../shared/util/settings.h"
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
    {
        h += "rcpt " + one_line(r.addr) + "\n";
        if (r.notify || !r.orcpt.empty())
            h += "dsn " + std::to_string(r.notify) + " " + one_line(r.orcpt) + "\n";
    }
    if (e.ret)
        h += "ret " + std::to_string(e.ret) + "\n";
    if (!e.envid.empty())
        h += "envid " + one_line(e.envid) + "\n";
    if (e.requiretls)
        h += "requiretls 1\n";
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
            e.rcpts.emplace_back(std::string(val));
        else if (key == "user")
            e.user = std::string(val);
        else if (key == "peer")
            e.peer = std::string(val);
        else if (key == "helo")
            e.helo = std::string(val);
        else if (key == "bounce")
            e.bounce = val == "1";
        else if (key == "dsn" && !e.rcpts.empty())
        {
            const size_t sp = val.find(' ');
            number(val.substr(0, sp), e.rcpts.back().notify);
            if (sp != std::string_view::npos)
                e.rcpts.back().orcpt = std::string(val.substr(sp + 1));
        }
        else if (key == "ret")
            number(val, e.ret);
        else if (key == "envid")
            e.envid = std::string(val);
        else if (key == "requiretls")
            e.requiretls = val == "1";
    }
    return false;
}


constexpr uint32_t rec_magic = 0x31434552;
constexpr std::string_view seg_magic = "SKLSPOOL1\n";
// A record's envelope and its message: a mebibyte of body and the envelope ahead of it.
constexpr size_t rec_max = (2u << 20);

void put32(char* p, uint32_t v) { std::memcpy(p, &v, 4); }
uint32_t get32(const char* p)
{
    uint32_t v = 0;
    std::memcpy(&v, p, 4);
    return v;
}

bool pwrite_all(int fd, const char* p, size_t n, uint64_t off)
{
    while (n)
    {
        const ssize_t w = ::pwrite(fd, p, n, static_cast<off_t>(off));
        if (w < 0 && errno == EINTR)
            continue;
        if (w <= 0)
            return false;
        p += w;
        n -= static_cast<size_t>(w);
        off += static_cast<uint64_t>(w);
    }
    return true;
}

std::string seg_header(uint32_t gen)
{
    std::string h(seg_magic);
    h += "gen " + std::to_string(gen) + "\n";
    h.resize(spool::seg_head, '\0');
    return h;
}

bool seg_gen_of(std::string_view h, uint32_t& gen)
{
    if (!h.starts_with(seg_magic) || !h.substr(seg_magic.size()).starts_with("gen "))
        return false;
    h.remove_prefix(seg_magic.size() + 4);
    const size_t nl = h.find('\n');
    return nl != std::string_view::npos && number(h.substr(0, nl), gen) && gen != 0;
}

// Off the loop: a new segment written to its end, so a record is an overwrite of blocks it has, and a used one given
// its next generation, which ends what its records were; synced before a record goes in.
bool make_ready(int& fd, const std::string& path, const std::string& dir, uint32_t gen)
{
    const bool fresh = fd < 0;
    if (fresh)
    {
        fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0)
            return false;
        static const std::string zeros(1u << 20, '\0');
        for (uint64_t off = 0; off < spool::seg_size; off += zeros.size())
            if (!pwrite_all(fd, zeros.data(), zeros.size(), off))
                return false;
    }
    const std::string h = seg_header(gen);
    if (!pwrite_all(fd, h.data(), h.size(), 0) || (fresh ? ::fsync(fd) : ::fdatasync(fd)) != 0)
        return false;
    if (fresh)
    {
        const int d = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        const bool ok = d >= 0 && ::fsync(d) == 0;
        if (d >= 0)
            ::close(d);
        return ok;
    }
    return true;
}

std::string trailer_of(uint64_t body_len) { return "\nend " + std::to_string(body_len) + "\n"; }

// The body length a record's or a file's last bytes say, and how long that line is; false when they say none.
bool trailer_says(std::string_view tail, uint64_t& len, size_t& line)
{
    const size_t mark = tail.rfind("\nend ");
    if (mark == std::string_view::npos || tail.empty() || tail.back() != '\n' ||
        !number(tail.substr(mark + 5, tail.size() - mark - 6), len))
        return false;
    line = tail.size() - mark;
    return true;
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
    std::vector<segment> found;
    for (const auto& de : std::filesystem::directory_iterator(dir, ec))
    {
        const std::string name = de.path().filename().string();
        const std::string path = de.path().string();
        if (name.starts_with("seg-") && name.ends_with(".spool"))
        {
            uint32_t file_no = 0;
            if (number(std::string_view(name).substr(4, name.size() - 10), file_no))
                m_next_file = std::max(m_next_file, file_no + 1);
            segment s;
            s.path = path;
            s.fd = ::open(path.c_str(), O_RDWR | O_CLOEXEC);
            struct stat st{};
            std::string h;
            if (s.fd < 0 || ::fstat(s.fd, &st) != 0 || static_cast<uint64_t>(st.st_size) != seg_size ||
                !read_at(s.fd, h, seg_head, 0) || !seg_gen_of(h, s.gen))
            {
                // A segment whose making a crash cut holds no record yet.
                if (s.fd >= 0)
                    ::close(s.fd);
                std::filesystem::remove(path, ec);
                continue;
            }
            m_next_gen = std::max(m_next_gen, s.gen + 1);
            found.push_back(std::move(s));
            continue;
        }
        if (!name.ends_with(".msg"))
            continue;
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
            // The envelope of many recipients can be long: it is read until its blank line, up to 16 MiB.
            for (size_t want = 64u << 10;; want *= 4)
            {
                read_at(fd, head, std::min<size_t>(static_cast<size_t>(st.st_size), want), 0);
                if (head.find("\n\n") != std::string::npos || head.size() < want || want >= (16u << 20))
                    break;
            }
            ok = parse_header(head, *e, header_len);
        }
        if (ok)
        {
            // "\nend <length>\n" closes a file written to its end.
            const size_t n = std::min<size_t>(static_cast<size_t>(st.st_size), 40);
            read_at(fd, tail, n, static_cast<uint64_t>(st.st_size) - n);
            uint64_t len = 0;
            size_t line = 0;
            ok = trailer_says(tail, len, line) && header_len + len + line == static_cast<uint64_t>(st.st_size);
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
    // Each segment's records up to the first a crash cut or an earlier generation left, a message moved to a later
    // segment read from there.
    std::sort(found.begin(), found.end(), [](const segment& a, const segment& b) { return a.gen < b.gen; });
    for (auto& s : found)
    {
        uint64_t pos = seg_head;
        std::string rh, payload;
        while (pos + rec_head <= seg_size && read_at(s.fd, rh, rec_head, pos))
        {
            const uint32_t len = get32(rh.data() + 4);
            // Zeros, or a record of the segment's last use, is where its records end.
            if (get32(rh.data()) != rec_magic || get32(rh.data() + 8) != s.gen)
                break;
            if (len > rec_max || pos + rec_head + len > seg_size || !read_at(s.fd, payload, len, pos + rec_head) ||
                socketley::crc::crc32c(payload) != get32(rh.data() + 12))
            {
                // A record whose bytes went bad with a whole record of this use after it is one damaged message, the
                // ones after it taken and kept; with none after it, it is the tail a crash cut.
                std::string next;
                const bool more = len <= rec_max && pos + rec_head + len + rec_head <= seg_size &&
                                  read_at(s.fd, next, rec_head, pos + rec_head + len) &&
                                  get32(next.data()) == rec_magic && get32(next.data() + 8) == s.gen;
                LOG_WARN(("mail: a message in " + s.path +
                          (more ? std::string(" was damaged on disk, and is dropped; the messages after it are kept")
                                : std::string(" was cut short by a crash while it was written, and is dropped; its "
                                              "sender was never told it was taken")))
                             .c_str());
                if (!more)
                    break;
                pos += rec_head + len;
                continue;
            }
            auto e = std::make_shared<spool_entry>();
            size_t header_len = 0;
            uint64_t body_len = 0;
            size_t line = 0;
            if (!parse_header(payload, *e, header_len) ||
                !trailer_says(std::string_view(payload).substr(payload.size() - std::min<size_t>(payload.size(), 40)),
                              body_len, line) ||
                header_len + body_len + line != len)
                break;
            e->seg = s.gen;
            e->rec_len = static_cast<uint32_t>(rec_head + len);
            e->body_off = pos + rec_head + header_len;
            e->body_len = body_len;
            pos += rec_head + len;
            if (const auto it = m_entries.find(e->id); it != m_entries.end())
                m_bytes -= it->second->body_len;
            m_bytes += e->body_len;
            m_entries[e->id] = std::move(e);
        }
        s.tail = pos;
        m_segs.emplace(s.gen, std::move(s));
    }
    // What became of each recipient, the log rewritten with only the messages still here.
    const std::string log_path = dir + "/state.log";
    std::vector<std::string> dropped;
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
            if (kind == 'x')
                dropped.push_back(e.id);
            else if (kind == 'w')
                e.delay_told = true;
            else if (kind == 'a')
            {
                e.folder = std::string(line.substr(0, b));
                e.auth = b == std::string_view::npos ? std::string() : std::string(line.substr(b + 1));
            }
            else if (kind == 'r')
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
            else if (kind == 'b' && number(line.substr(0, b), i) && i < e.rcpts.size())
                e.rcpts[i].told = true;
            else if ((kind == 't' || kind == 'u') && b != std::string_view::npos && number(line.substr(0, b), i) &&
                     i < e.rcpts.size())
                (kind == 't' ? e.rcpts[i].targets_done : e.rcpts[i].targets_failed)
                    .push_back(std::string(line.substr(b + 1)));
        }
    }
    for (const auto& id : dropped)
        if (const auto it = m_entries.find(id); it != m_entries.end())
            for (auto& r : it->second->rcpts)
                r.state = rcpt_state::failed;
    std::vector<std::string> over;
    for (const auto& [id, e] : m_entries)
        if (e->waiting() == 0)
            over.push_back(id);
    for (const auto& id : over)
    {
        if (m_entries[id]->seg == 0)
            std::filesystem::remove(path_of(id), ec);
        else
            m_gone_in_seg[id] = m_entries[id]->seg;
        m_bytes -= m_entries[id]->body_len;
        m_entries.erase(id);
    }
    for (const auto& [id, e] : m_entries)
        if (e->seg)
        {
            segment& s = m_segs[e->seg];
            ++s.live;
            s.live_bytes += e->rec_len;
        }
    // The last segment takes records again where its last one ended; one before it that holds none is free.
    const int64_t now = wall::now_ms_coarse();
    std::vector<uint32_t> empty;
    for (auto& [gen, s] : m_segs)
    {
        if (gen != m_segs.rbegin()->first || s.tail + rec_max > seg_size)
        {
            s.sealed = true;
            s.sealed_ms = now;
            if (s.live == 0)
                empty.push_back(gen);
        }
        else
            m_cur = gen;
    }
    for (const uint32_t gen : empty)
    {
        segment s = std::move(m_segs[gen]);
        m_segs.erase(gen);
        if (m_free.size() < 2)
            m_free.push_back(std::move(s));
        else
        {
            ::close(s.fd);
            std::filesystem::remove(s.path, ec);
        }
    }
    if (!m_cur)
    {
        // The first segment made here and now, so the first message waits for nothing.
        segment s;
        if (!m_free.empty())
        {
            s = std::move(m_free.back());
            m_free.pop_back();
        }
        else
            s.path = m_dir + "/seg-" + std::to_string(m_next_file++) + ".spool";
        s.gen = m_next_gen++;
        s.tail = seg_head;
        s.sealed = false;
        s.live = 0;
        s.live_bytes = 0;
        if (!make_ready(s.fd, s.path, m_dir, s.gen))
        {
            if (s.fd >= 0)
                ::close(s.fd);
            why = "the spool segment " + s.path + " cannot be written";
            return false;
        }
        m_cur = s.gen;
        m_segs.emplace(s.gen, std::move(s));
    }
    const std::string compact = log_text();
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
    m_log_base = compact.size();
    m_log_grown = 0;
    // A file named in a directory is the directory's to keep: it is synced after a file is made or renamed in it.
    m_dir_fd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (m_dir_fd >= 0 && ::fsync(m_dir_fd) != 0) {}
    m_log_fd = ::open(log_path.c_str(), O_WRONLY | O_APPEND | O_CLOEXEC);
    if (m_log_fd < 0)
    {
        why = log_path + " cannot be opened";
        return false;
    }
    prepare();
    return true;
}

void spool::close()
{
    // Each descriptor is closed through the loop, which holds it until what is in flight on it is back.
    if (m_log_fd >= 0)
    {
        // What the log still holds goes in line, since nothing after this waits for the ring.
        if (!m_log_buf.empty() && !write_all(m_log_fd, m_log_buf.data(), m_log_buf.size())) {}
        m_log_buf.clear();
        m_loop.close_fd(m_log_fd);
        m_log_fd = -1;
    }
    if (m_dir_fd >= 0)
    {
        m_loop.close_fd(m_dir_fd);
        m_dir_fd = -1;
    }
    for (auto& [id, r] : m_readers)
        if (r.fd >= 0)
            m_loop.close_fd(r.fd);
    m_readers.clear();
    for (auto* list : {&m_spare, &m_free})
    {
        for (auto& s : *list)
            if (s.fd >= 0)
                m_loop.close_fd(s.fd);
        list->clear();
    }
    for (auto& [gen, s] : m_segs)
        if (s.fd >= 0)
            m_loop.close_fd(s.fd);
    m_segs.clear();
    m_cur = 0;
}

entry_ptr spool::find(const std::string& id) const
{
    const auto it = m_entries.find(id);
    return it == m_entries.end() ? nullptr : it->second;
}

std::string spool::file_of(const spool_entry& e) const
{
    if (e.seg)
        if (const auto it = m_segs.find(e.seg); it != m_segs.end())
            return it->second.path;
    return path_of(e.id);
}

uint64_t spool::begin(entry_ptr e, std::string_view head)
{
    const uint64_t id = m_next_writer++;
    auto w = std::make_unique<writer>();
    w->buf = header_of(*e);
    w->head = w->buf.size();
    e->body_off = w->head;
    e->body_len = head.size();
    w->buf.append(head);
    w->e = std::move(e);
    m_writers.emplace(id, std::move(w));
    return id;
}

void spool::append(uint64_t w, std::string_view bytes)
{
    const auto it = m_writers.find(w);
    if (it == m_writers.end())
        return;
    writer& x = *it->second;
    x.e->body_len += bytes.size();
    // A writer whose file failed keeps counting what comes, to refuse it at its end, and holds none of it.
    if (x.failed)
        return;
    x.buf.append(bytes);
    // A record with its envelope stays within what a restart reads as one, however many recipients it has.
    if (!x.own && x.buf.size() > keep_one)
        go_own(w);
    else if (x.own && x.buf.size() >= flush_at)
        pump(w);
}

void spool::go_own(uint64_t w)
{
    writer& x = *m_writers.at(w);
    x.own = true;
    x.opening = true;
    if (!m_io.openat(AT_FDCWD, path_of(x.e->id), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600,
                     [this, w, alive = m_alive](int64_t res) {
                         if (!*alive)
                             return;
                         const auto it = m_writers.find(w);
                         if (it == m_writers.end())
                         {
                             if (res >= 0)
                                 m_loop.close_fd(static_cast<int>(res));
                             return;
                         }
                         it->second->opening = false;
                         if (res < 0)
                             it->second->failed = true;
                         else
                             it->second->fd = static_cast<int>(res);
                         pump(w);
                     }))
    {
        x.opening = false;
        x.failed = true;
    }
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
    if (x.own)
    {
        x.buf += trailer_of(x.e->body_len);
        pump(w);
        return;
    }
    queued q;
    q.writer = w;
    q.header_len = x.head;
    enqueue(q, x.buf, trailer_of(x.e->body_len));
}

void spool::abort(uint64_t w)
{
    const auto it = m_writers.find(w);
    if (it == m_writers.end())
        return;
    writer& x = *it->second;
    // A record handed to a commit is the commit's to finish.
    if (x.finishing && !x.own)
        return;
    x.aborted = true;
    if (!x.own)
    {
        m_writers.erase(it);
        return;
    }
    pump(w);
}

void spool::pump(uint64_t w)
{
    const auto it = m_writers.find(w);
    if (it == m_writers.end())
        return;
    writer& x = *it->second;
    if (!x.own || x.opening || x.writing)
        return;
    if (x.aborted || x.failed)
    {
        if (x.fd >= 0)
        {
            m_loop.close_fd(x.fd);
            x.fd = -1;
            if (!m_io.unlinkat(AT_FDCWD, path_of(x.e->id), 0, [](int64_t) {}))
                ::unlink(path_of(x.e->id).c_str());
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
                // The file's name is the directory's, which is synced too before the sender is told it is taken.
                if (m_dir_fd < 0 || !m_io.sync(m_dir_fd, false, [this, w, alive = m_alive](int64_t r) {
                        if (*alive)
                            end(w, r >= 0);
                    }))
                    end(w, m_dir_fd < 0 || ::fsync(m_dir_fd) == 0);
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
        spool_entry& e = *x->e;
        if (!x->own)
        {
            // The record's bytes are the copy kept in memory, while there is room for it.
            static const uint64_t room =
                settings::number<uint64_t>("SOCKETLEY_MAIL_SPOOL_KEEP_BYTES").value_or(keep_all);
            if (m_kept + e.body_len <= room)
            {
                // A copy of the body alone, its size what is counted, not the buffer's growth room.
                e.body = std::make_shared<const std::string>(x->buf, x->head);
                m_kept += e.body->size();
            }
            segment& s = m_segs[e.seg];
            ++s.live;
            s.live_bytes += e.rec_len;
        }
        m_bytes += e.body_len;
        ++m_written;
        m_entries[e.id] = x->e;
    }
    else
        ++m_write_failures;
    if (x->done)
        x->done(ok);
}

void spool::enqueue(queued q, std::string_view header, std::string_view body)
{
    const uint32_t len = static_cast<uint32_t>(header.size() + body.size());
    q.at = m_batch.size();
    q.len = rec_head + len;
    char h[rec_head];
    put32(h, rec_magic);
    put32(h + 4, len);
    put32(h + 8, 0);
    put32(h + 12, socketley::crc::crc32c(body, socketley::crc::crc32c(header)));
    m_batch.append(h, rec_head);
    m_batch.append(header);
    m_batch.append(body);
    m_waiting.push_back(std::move(q));
    commit();
}

void spool::commit()
{
    if (m_committing || m_waiting.empty())
        return;
    const auto cur = m_segs.find(m_cur);
    // As many waiting records as the segment has room for go in one write and one sync.
    size_t n = 0, bytes = 0;
    if (cur != m_segs.end())
        while (n < m_waiting.size() && cur->second.tail + bytes + m_waiting[n].len <= seg_size)
            bytes += m_waiting[n++].len;
    if (n == 0)
    {
        if (cur != m_segs.end())
        {
            cur->second.sealed = true;
            cur->second.sealed_ms = wall::now_ms_coarse();
            m_cur = 0;
            if (cur->second.live == 0)
                recycle(cur->first);
        }
        if (m_spare.empty())
        {
            prepare();
            return;
        }
        segment s = std::move(m_spare.front());
        m_spare.erase(m_spare.begin());
        m_cur = s.gen;
        m_segs.emplace(s.gen, std::move(s));
        prepare();
        commit();
        return;
    }
    segment& s = m_segs[m_cur];
    m_flying_recs.assign(std::make_move_iterator(m_waiting.begin()), std::make_move_iterator(m_waiting.begin() + n));
    m_waiting.erase(m_waiting.begin(), m_waiting.begin() + n);
    if (m_waiting.empty())
    {
        m_flying.swap(m_batch);
        m_batch.clear();
    }
    else
    {
        m_flying.assign(m_batch, 0, bytes);
        m_batch.erase(0, bytes);
        for (auto& q : m_waiting)
            q.at -= bytes;
    }
    for (const auto& q : m_flying_recs)
        put32(m_flying.data() + q.at + 8, s.gen);
    m_flying_seg = s.gen;
    m_flying_at = s.tail;
    s.tail += bytes;
    m_committing = true;
    if (s.tail > seg_size / 2)
        prepare();
    const int fd = s.fd;
    if (!m_io.pwrite(fd, m_flying.data(), static_cast<uint32_t>(m_flying.size()), m_flying_at,
                     [this, fd, alive = m_alive](int64_t res) {
                         if (!*alive)
                             return;
                         if (res < 0)
                         {
                             committed(false);
                             return;
                         }
                         if (!m_io.sync(fd, true, [this, alive](int64_t r) {
                                 if (*alive)
                                     committed(r >= 0);
                             }))
                             committed(false);
                     }))
        committed(false);
}

void spool::committed(bool ok)
{
    m_committing = false;
    // What a record's done starts may be the next commit, which takes these over.
    const uint32_t gen = m_flying_seg;
    const uint64_t at = m_flying_at;
    if (ok)
    {
        ++m_commits;
        m_committed += m_flying_recs.size();
    }
    else if (const auto it = m_segs.find(gen); it != m_segs.end() && gen == m_cur)
    {
        // A segment the disk would not take is used no further.
        it->second.sealed = true;
        it->second.sealed_ms = wall::now_ms_coarse();
        m_cur = 0;
    }
    std::vector<queued> recs = std::move(m_flying_recs);
    m_flying_recs.clear();
    m_flying.clear();
    for (auto& q : recs)
    {
        const uint64_t body_off = at + q.at + rec_head + q.header_len;
        if (q.writer)
        {
            const auto it = m_writers.find(q.writer);
            if (it == m_writers.end())
                continue;
            spool_entry& e = *it->second->e;
            e.seg = gen;
            e.rec_len = static_cast<uint32_t>(q.len);
            e.body_off = body_off;
            // A sync that failed may still have put the record on the disk; its sender is told to try again, so a
            // restart must not deliver it as well.
            if (!ok)
            {
                log(e.id + " x\n");
                m_gone_in_seg[e.id] = gen;
            }
            end(q.writer, ok);
            continue;
        }
        // A moved message counts in its new segment once there, if it is still here and still where it was.
        const auto it = m_entries.find(q.moved->id);
        if (!ok || it == m_entries.end() || it->second != q.moved || q.moved->seg != q.from_seg)
            continue;
        release(*q.moved);
        ++m_moved;
        q.moved->seg = gen;
        q.moved->rec_len = static_cast<uint32_t>(q.len);
        q.moved->body_off = body_off;
        segment& s = m_segs[gen];
        ++s.live;
        s.live_bytes += q.len;
    }
    if (const auto it = m_segs.find(gen); it != m_segs.end() && it->second.sealed && it->second.live == 0)
        recycle(gen);
    commit();
}

void spool::prepare()
{
    if (m_preparing || !m_spare.empty())
        return;
    m_preparing = true;
    auto job = std::make_shared<segment>();
    if (!m_free.empty())
    {
        *job = std::move(m_free.back());
        m_free.pop_back();
        // Its records end with its old generation, so the messages gone from it need no word in the log.
        forget_gone(job->gen);
    }
    else
        job->path = m_dir + "/seg-" + std::to_string(m_next_file++) + ".spool";
    job->gen = m_next_gen++;
    job->tail = seg_head;
    job->live = 0;
    job->live_bytes = 0;
    job->sealed = false;
    auto ok = std::make_shared<bool>(false);
    m_pool.submit(0, [job, ok, dir = m_dir] { *ok = make_ready(job->fd, job->path, dir, job->gen); },
                  [this, job, ok, alive = m_alive] {
                      if (!*alive)
                      {
                          if (job->fd >= 0)
                              ::close(job->fd);
                          return;
                      }
                      m_preparing = false;
                      if (*ok)
                      {
                          m_spare.push_back(std::move(*job));
                          commit();
                          return;
                      }
                      LOG_WARN(("mail: the spool segment " + job->path + " cannot be written").c_str());
                      if (job->fd >= 0)
                          m_loop.close_fd(job->fd);
                      if (!m_io.unlinkat(AT_FDCWD, job->path, 0, [](int64_t) {})) {}
                      // With no segment to write to, what waits is refused rather than left without an answer.
                      if (m_segs.find(m_cur) != m_segs.end())
                          return;
                      std::vector<queued> waiting = std::move(m_waiting);
                      m_waiting.clear();
                      m_batch.clear();
                      for (auto& q : waiting)
                          if (q.writer)
                              end(q.writer, false);
                  });
}

void spool::release(spool_entry& e)
{
    if (!e.seg)
        return;
    const auto it = m_segs.find(e.seg);
    e.seg = 0;
    if (it == m_segs.end())
        return;
    segment& s = it->second;
    s.live -= std::min<uint32_t>(s.live, 1);
    s.live_bytes -= std::min<uint64_t>(s.live_bytes, e.rec_len);
    if (s.sealed && s.live == 0)
        recycle(it->first);
}

void spool::recycle(uint32_t gen)
{
    const auto it = m_segs.find(gen);
    if (it == m_segs.end() || it->second.reading)
        return;
    segment s = std::move(it->second);
    m_segs.erase(it);
    s.moving = false;
    if (m_free.size() + m_spare.size() < 2)
    {
        m_free.push_back(std::move(s));
        return;
    }
    forget_gone(s.gen);
    m_loop.close_fd(s.fd);
    if (!m_io.unlinkat(AT_FDCWD, s.path, 0, [](int64_t) {}))
        ::unlink(s.path.c_str());
}

void spool::move_out(uint32_t gen)
{
    if (const auto s = m_segs.find(gen); s != m_segs.end())
        s->second.moving = true;
    for (const auto& [id, e] : m_entries)
    {
        if (e->seg != gen)
            continue;
        queued q;
        q.moved = e;
        q.from_seg = gen;
        const std::string header = header_of(*e);
        q.header_len = header.size();
        if (e->body)
        {
            enqueue(q, header, *e->body + trailer_of(e->body_len));
            continue;
        }
        read(e, 0, static_cast<uint32_t>(e->body_len),
             [this, q, header, e, alive = m_alive](bool ok, std::string_view bytes) {
                 if (*alive && ok && bytes.size() == e->body_len && e->seg == q.from_seg)
                     enqueue(q, header, std::string(bytes) + trailer_of(e->body_len));
             });
    }
}

void spool::tick(int64_t now_ms)
{
    // A segment a few deferred messages keep holds them in a fraction of its size; moved, it is used again.
    static const int64_t after = settings::number<int64_t>("SOCKETLEY_MAIL_SPOOL_MOVE_MS").value_or(60000);
    if (now_ms - m_moved_ms < std::min<int64_t>(after, 10000))
        return;
    m_moved_ms = now_ms;
    // The log written whole again once its appends outgrow it fourfold, past a mebibyte.
    if (!m_log_compacting && m_log_grown > std::max<uint64_t>(1u << 20, m_log_base * 4))
        compact_log();
    for (const auto& [gen, s] : m_segs)
        if (s.sealed && !s.moving && s.live && s.live_bytes * 4 < seg_size && now_ms - s.sealed_ms >= after)
        {
            move_out(gen);
            return;
        }
}

void spool::log(std::string line)
{
    if (m_log_fd < 0)
        return;
    m_log_grown += line.size();
    m_log_buf += line;
    // While the log is written whole, what is said meanwhile waits for the new file.
    if (m_log_writing || m_log_compacting)
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

std::string spool::log_text() const
{
    std::string out;
    for (const auto& [id, gen] : m_gone_in_seg)
        out += id + " x\n";
    for (const auto& [id, e] : m_entries)
    {
        if (e->attempts)
            out += id + " r " + std::to_string(e->attempts) + " " + std::to_string(e->next_ms) + "\n";
        if (!e->auth.empty())
            out += id + " a " + (e->folder.empty() ? "INBOX" : e->folder) + " " + e->auth + "\n";
        if (e->delay_told)
            out += id + " w\n";
        for (size_t i = 0; i < e->rcpts.size(); ++i)
        {
            const spool_rcpt& r = e->rcpts[i];
            if (r.state != rcpt_state::waiting)
                out += id + (r.state == rcpt_state::delivered ? " d " : " f ") + std::to_string(i) + " " +
                       one_line(r.why) + "\n";
            if (r.told)
                out += id + " b " + std::to_string(i) + "\n";
            for (const auto& t : r.targets_done)
                out += id + " t " + std::to_string(i) + " " + t + "\n";
            for (const auto& t : r.targets_failed)
                out += id + " u " + std::to_string(i) + " " + t + "\n";
        }
    }
    return out;
}

void spool::compact_log()
{
    // What memory holds is the log's truth: it is written whole on a thread, and moved into the old one's place.
    m_log_compacting = true;
    auto text = std::make_shared<std::string>(log_text());
    auto fd = std::make_shared<int>(-1);
    m_pool.submit(0,
                  [text, fd, dir = m_dir] {
                      const std::string path = dir + "/state.log", tmp = path + ".tmp";
                      const int w = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
                      // The descriptor appends go to is opened before the move, so it is the new file's either way.
                      const int a = w >= 0 ? ::open(tmp.c_str(), O_WRONLY | O_APPEND | O_CLOEXEC) : -1;
                      if (a < 0 || !write_all(w, text->data(), text->size()) || ::fsync(w) != 0 ||
                          ::rename(tmp.c_str(), path.c_str()) != 0)
                      {
                          if (w >= 0)
                              ::close(w);
                          if (a >= 0)
                              ::close(a);
                          ::unlink(tmp.c_str());
                          return;
                      }
                      ::close(w);
                      const int d = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
                      if (d >= 0)
                      {
                          if (::fsync(d) != 0) {}
                          ::close(d);
                      }
                      *fd = a;
                  },
                  [this, text, fd, alive = m_alive] {
                      if (!*alive)
                      {
                          if (*fd >= 0)
                              ::close(*fd);
                          return;
                      }
                      m_log_compacting = false;
                      if (*fd >= 0)
                      {
                          if (m_log_fd >= 0)
                              m_loop.close_fd(m_log_fd);
                          m_log_fd = *fd;
                          m_log_base = text->size();
                          m_log_grown = m_log_buf.size();
                      }
                      if (!m_log_buf.empty() && !m_log_writing)
                          log({});
                  });
}

void spool::forget_gone(uint32_t gen)
{
    std::erase_if(m_gone_in_seg, [gen](const auto& kv) { return kv.second == gen; });
}

void spool::release_reader(const std::string& id)
{
    const auto it = m_readers.find(id);
    if (it == m_readers.end())
        return;
    reader& r = it->second;
    r.users -= std::min<uint32_t>(r.users, 1);
    // A message waiting for its next try holds no descriptor: a queue of large ones would hold one each.
    if (r.users == 0 && !r.opening)
    {
        if (r.fd >= 0)
            m_loop.close_fd(r.fd);
        m_readers.erase(it);
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

void spool::target_over(spool_entry& e, size_t rcpt, std::string_view addr, bool ok, std::string_view why)
{
    if (rcpt >= e.rcpts.size())
        return;
    // A refused target keeps its answer beside it, so the report can say which of an alias's targets failed.
    const std::string word = one_line(ok ? addr : std::string(addr) + ": " + std::string(why));
    (ok ? e.rcpts[rcpt].targets_done : e.rcpts[rcpt].targets_failed).push_back(word);
    log(e.id + (ok ? " t " : " u ") + std::to_string(rcpt) + " " + word + "\n");
}

void spool::told(spool_entry& e, size_t rcpt)
{
    if (rcpt >= e.rcpts.size() || e.rcpts[rcpt].told)
        return;
    e.rcpts[rcpt].told = true;
    log(e.id + " b " + std::to_string(rcpt) + "\n");
}

void spool::retry(spool_entry& e, uint32_t attempts, int64_t next_ms)
{
    e.attempts = attempts;
    e.next_ms = next_ms;
    log(e.id + " r " + std::to_string(attempts) + " " + std::to_string(next_ms) + "\n");
}

void spool::delay_told(spool_entry& e)
{
    e.delay_told = true;
    log(e.id + " w\n");
}

void spool::note_auth(spool_entry& e, std::string results, std::string folder)
{
    e.auth = one_line(results);
    e.folder = one_line(folder);
    log(e.id + " a " + (e.folder.empty() ? "INBOX" : e.folder) + " " + e.auth + "\n");
}

void spool::remove(const std::string& id)
{
    const auto it = m_entries.find(id);
    if (it == m_entries.end())
        return;
    entry_ptr e = it->second;
    if (e->body)
        m_kept -= std::min<uint64_t>(m_kept, e->body->size());
    m_bytes -= std::min<uint64_t>(m_bytes, e->body_len);
    m_entries.erase(it);
    // A record stays in its segment until the segment is used again, so the log says it is gone.
    log(id + " x\n");
    if (e->seg)
    {
        m_gone_in_seg[id] = e->seg;
        release(*e);
        return;
    }
    if (const auto r = m_readers.find(id); r != m_readers.end())
    {
        // Reads waiting for the file to open are answered, not dropped.
        auto waiting = std::move(r->second.waiting);
        if (r->second.fd >= 0)
            m_loop.close_fd(r->second.fd);
        m_readers.erase(r);
        for (auto& f : waiting)
            f(-1);
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
    const uint64_t file_off = e->body_off + off;
    if (e->seg)
    {
        // A segment being read from is not used again until the read is back.
        const auto it = m_segs.find(e->seg);
        if (it == m_segs.end())
        {
            cb(false, {});
            return;
        }
        const uint32_t gen = e->seg;
        ++it->second.reading;
        auto buf = std::make_shared<std::string>(len, '\0');
        if (!m_io.pread(it->second.fd, buf->data(), len, file_off, [this, gen, buf, cb, len, alive = m_alive](int64_t res) {
                if (!*alive)
                    return;
                if (const auto s = m_segs.find(gen); s != m_segs.end())
                {
                    --s->second.reading;
                    if (s->second.sealed && s->second.live == 0)
                        recycle(gen);
                }
                if (res != static_cast<int64_t>(len))
                    cb(false, {});
                else
                    cb(true, *buf);
            }))
        {
            --it->second.reading;
            cb(false, {});
        }
        return;
    }
    const std::string id = e->id;
    auto go = [this, id, file_off, len, cb, alive = m_alive](int fd) {
        if (!*alive)
            return;
        if (fd < 0)
        {
            release_reader(id);
            cb(false, {});
            return;
        }
        auto buf = std::make_shared<std::string>(len, '\0');
        if (!m_io.pread(fd, buf->data(), len, file_off, [this, id, buf, cb, len, alive](int64_t res) {
                if (!*alive)
                    return;
                release_reader(id);
                if (res != static_cast<int64_t>(len))
                    cb(false, {});
                else
                    cb(true, *buf);
            }))
        {
            release_reader(id);
            cb(false, {});
        }
    };
    reader& r = m_readers[id];
    ++r.users;
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
