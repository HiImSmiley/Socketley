#include "web_run.h"

#include <algorithm>
#include <cerrno>
#include <cstring>

#include <dirent.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <linux/openat2.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "web_instance.h"
#include "web_site.h"
#include "../../shared/http/conditional.h"
#include "../../shared/http/encoding.h"
#include "../../shared/http/http_framing.h"
#include "../../shared/http/mime.h"
#include "../../shared/http/request_head.h"
#include "../../shared/http/site_path.h"
#include "../../shared/http/status.h"
#include "../../shared/http/url.h"
#include "../../shared/net/file_send.h"
#include "../../shared/persist/file_stamp.h"
#include "../../shared/util/deflate.h"
#include "../../shared/util/logging.h"
#include "../../shared/util/wall_clock.h"

namespace socketley::web
{

namespace
{

constexpr int64_t idle_secs = 60;
constexpr size_t max_head = 16 * 1024;
// The body a refused method brings is read and dropped, up to this; a larger one closes the connection.
constexpr size_t max_body = 64 * 1024;
constexpr size_t max_conns = 65536;
// A body this small goes out in the write that carries its head; a larger one is sent from its descriptor.
constexpr uint64_t inline_max = 32 * 1024;
// What the bodies kept in memory and the compressed copies may take together.
constexpr uint64_t kept_max = 256ull << 20;
// Descriptors kept open; past this a large file is opened for each request instead of kept.
constexpr uint64_t fds_max = 4096;
constexpr size_t entries_max = 200000;
// Text outside these sizes is sent as it is: too small to gain, or too large for the helper to hold.
constexpr uint64_t compress_min = 256;
constexpr uint64_t compress_max = 32ull << 20;
// Compressions queued for the helper at once; past this a file is asked about again on its next request.
constexpr size_t jobs_max = 32;
// A read out of the page cache through the ring takes this much at a time.
constexpr uint32_t cold_chunk = 256 * 1024;
constexpr size_t watch_buf_size = 64 * 1024;
constexpr uint32_t watch_mask = IN_CREATE | IN_DELETE | IN_MODIFY | IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO |
                                IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF | IN_ONLYDIR;
constexpr uint32_t above_mask = IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO | IN_ATTRIB | IN_ONLYDIR;
constexpr int max_depth = 64;

int open_beneath_fd(int dirfd, const char* path, uint64_t flags)
{
    struct open_how how{};
    how.flags = flags;
    how.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS;
    return static_cast<int>(::syscall(SYS_openat2, dirfd, path, &how, sizeof how));
}

// Whether a gzip of a type can gain: not what its format compressed already, nor bytes nobody named.
bool text_type(std::string_view type)
{
    return !socketley::http::compressed_type(type) && type != "application/octet-stream";
}

bool hidden_name(std::string_view n)
{
    return !n.empty() && n.front() == '.' && n != ".well-known";
}

// The whole of `n` bytes, from a file the caller may wait on.
bool read_whole(int fd, std::string& out, uint64_t n)
{
    out.resize(n);
    uint64_t got = 0;
    while (got < n)
    {
        const ssize_t r = ::pread(fd, out.data() + got, n - got, static_cast<off_t>(got));
        if (r < 0 && errno == EINTR)
            continue;
        if (r <= 0)
            return false;
        got += static_cast<uint64_t>(r);
    }
    return true;
}

// The same from the page cache alone, so the loop never waits on the disk: false when a byte of it is not there.
// A filesystem whose files are memory already: a read of one cannot wait on a disk.
bool memory_backed(int fd)
{
    struct statfs s{};
    return ::fstatfs(fd, &s) == 0 && (s.f_type == TMPFS_MAGIC || s.f_type == RAMFS_MAGIC);
}

bool read_cached(int fd, std::string& out, uint64_t n)
{
    out.resize(n);
    uint64_t got = 0;
    int flags = RWF_NOWAIT;
    while (got < n)
    {
        struct iovec v{out.data() + got, n - got};
        const ssize_t r = ::preadv2(fd, &v, 1, static_cast<off_t>(got), flags);
        if (r < 0 && errno == EINTR)
            continue;
        // tmpfs answers RWF_NOWAIT with EOPNOTSUPP, and its files were never kept in memory for it.
        if (r < 0 && errno == EOPNOTSUPP && flags != 0 && memory_backed(fd))
        {
            flags = 0;
            continue;
        }
        if (r <= 0)
            return false;
        got += static_cast<uint64_t>(r);
    }
    return true;
}

// The lines of `fields` a 304 repeats (RFC 9110 15.4.5): what a 200 says of the cache, and nothing of the body.
std::string revalidation_of(std::string_view fields)
{
    std::string keep;
    for (std::string_view rest = fields; !rest.empty();)
    {
        const size_t nl = rest.find("\r\n");
        const std::string_view line = rest.substr(0, nl + 2);
        rest.remove_prefix(nl + 2);
        if (line.starts_with("ETag:") || line.starts_with("Cache-Control:") || line.starts_with("Vary:"))
            keep.append(line);
    }
    return keep;
}

int64_t mtime_ns_of(const struct stat& st)
{
    return static_cast<int64_t>(st.st_mtim.tv_sec) * 1000000000 + st.st_mtim.tv_nsec;
}

}   // namespace

body::~body()
{
    if (fd >= 0)
    {
        ::close(fd);
        if (kept)
            kept->fds.fetch_sub(1, std::memory_order_relaxed);
    }
    if (kept && counted_bytes)
        kept->bytes.fetch_sub(counted_bytes, std::memory_order_relaxed);
}

web_run::web_run(web_instance& owner, event_loop& loop)
    : m_owner(owner), m_loop(loop), m_io(loop, this), m_http(loop, this, owner, *this, max_conns)
{
}

web_run::~web_run()
{
    m_pool.stop();
    forget_all();
    if (m_root_fd >= 0)
        ::close(m_root_fd);
    m_loop.deregister_owner(this);
}

// ─── Start and stop ─────────────────────────────────────────────────────────

bool web_run::open_root(std::string& why)
{
    const int fd = ::open(m_root.c_str(), O_DIRECTORY | O_RDONLY | O_CLOEXEC);
    struct stat st{};
    if (fd < 0 || ::fstat(fd, &st) != 0)
    {
        why = "--root " + m_root + ": " + std::strerror(errno);
        if (fd >= 0)
            ::close(fd);
        return false;
    }
    if (m_root_fd >= 0)
        ::close(m_root_fd);
    m_root_fd = fd;
    m_root_dev = st.st_dev;
    m_root_ino = st.st_ino;
    return true;
}

bool web_run::root_swapped()
{
    struct stat st{};
    std::string why;
    if (::stat(m_root.c_str(), &st) != 0 || (st.st_dev == m_root_dev && st.st_ino == m_root_ino) || !open_root(why))
        return false;
    ++m_c.reloads;
    return true;
}

bool web_run::start(std::string& why)
{
    m_root = std::string(m_owner.get_root());
    while (m_root.size() > 1 && m_root.back() == '/')
        m_root.pop_back();
    m_index = std::string(m_owner.get_index());
    m_fallback = std::string(m_owner.get_fallback());
    while (!m_fallback.empty() && m_fallback.front() == '/')
        m_fallback.erase(0, 1);
    if (!open_root(why))
        return false;
    m_loop.register_owner(this);

    // Changes are seen as they happen; without inotify each file is looked at again on each use.
    m_inotify = ::inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (m_inotify >= 0)
    {
        m_watch_buf = std::make_unique<char[]>(watch_buf_size);
        m_watching = true;
        rewatch();
        arm_watch();
    }
    else
        LOG_WARN(("web " + std::string(m_owner.get_name()) + ": inotify: " + std::strerror(errno) +
                  "; each file is looked at again on each use").c_str());
    if (!m_pool.attach(m_io))
        m_pool.stop();
    // Plain HTTP that the entrance terminates TLS for, so without --bind only this machine reaches it.
    const uint32_t addr = m_owner.get_bind_address().empty() ? htonl(INADDR_LOOPBACK) : m_owner.bind_in_addr();
    if (!m_http.listen_tcp(addr, m_owner.effective_port(), m_owner.get_shards() > 1, why))
        return false;
    m_http.start_accepting();
    return true;
}

void web_run::stop()
{
    if (m_stopped)
        return;
    m_stopped = true;
    m_http.stop();
    m_pool.retire(m_loop);
    // Through the loop, which cancels the read standing on it.
    if (m_inotify >= 0)
        m_loop.close_fd(m_inotify);
    m_inotify = -1;
    m_watching = false;
    if (m_tick_armed)
        m_loop.submit_timeout_remove(&m_tick_req);
}

bool web_run::drained() const
{
    return m_loop.owner_drained(this);
}

void web_run::on_loop_turn()
{
    m_http.on_loop_turn();
}

void web_run::on_cqe(struct io_uring_cqe* cqe)
{
    auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
    if (!req)
        return;
    if (file_io::owns_type(req->type))
    {
        m_io.on_cqe(cqe);
        return;
    }
    if (req == &m_tick_req)
    {
        m_tick_armed = false;
        if (!m_stopped)
            on_tick();
        return;
    }
    m_http.on_cqe(req, cqe);
}

void web_run::on_tick()
{
    const int64_t now = wall::now_sec_coarse();
    m_http.sweep(now, idle_secs);
    // A body sent from its descriptor is no answer the sweep sees owed, so a client that stopped reading it is let go
    // here.
    std::vector<std::shared_ptr<socketley::http::server_conn>> stalled;
    m_http.for_each([&](const std::shared_ptr<socketley::http::server_conn>& c) {
        if (static_cast<const web_conn&>(*c).sending_body && now - c->last > idle_secs)
            stalled.push_back(c);
    });
    m_c.stalled += stalled.size();
    for (const auto& c : stalled)
        m_http.close_conn(c);
    arm_tick();
}

void web_run::arm_tick()
{
    if (m_tick_armed || m_stopped || m_http.empty())
        return;
    m_tick_req = io_request{};
    m_tick_req.owner = this;
    m_tick_req.type = op_timeout;
    m_tick_ts = {5, 0};
    m_tick_armed = m_loop.submit_timeout(&m_tick_ts, &m_tick_req);
}

const std::string& web_run::date_field()
{
    const int64_t now = wall::now_sec_coarse();
    if (now != m_date_sec)
    {
        m_date_sec = now;
        m_date = "Date: " + socketley::http::http_date_of(now) + "\r\n";
    }
    return m_date;
}

// ─── What changed on the disk ───────────────────────────────────────────────

void web_run::lose_watching()
{
    if (!m_watching)
        return;
    m_watching = false;
    forget_all();
    LOG_WARN(("web " + std::string(m_owner.get_name()) +
              ": inotify has no watch left (fs.inotify.max_user_watches); each file is looked at again on each use")
                 .c_str());
}

void web_run::watch_above()
{
    // /srv/app/current/public: /srv for app, /srv/app for current, /srv/app/current for public.
    for (size_t slash = m_root.find('/', 1); slash != std::string::npos && m_watching;
         slash = m_root.find('/', slash + 1))
    {
        const std::string dir = m_root.substr(0, slash);
        const size_t next = m_root.find('/', slash + 1);
        const std::string below = m_root.substr(slash + 1, next == std::string::npos ? std::string::npos : next - slash - 1);
        const int wd = ::inotify_add_watch(m_inotify, dir.c_str(), above_mask);
        if (wd >= 0)
            m_above[wd] = below;
        else if (errno == ENOSPC || errno == ENOMEM)
            lose_watching();
    }
}

void web_run::rewatch()
{
    for (const auto& [wd, rel] : m_watches)
        ::inotify_rm_watch(m_inotify, wd);
    for (const auto& [wd, below] : m_above)
        ::inotify_rm_watch(m_inotify, wd);
    m_watches.clear();
    m_above.clear();
    watch_above();
    watch_tree({}, 0);
}

void web_run::watch_tree(const std::string& rel, int depth)
{
    if (!m_watching || depth > max_depth)
        return;
    const std::string full = rel.empty() ? m_root : m_root + "/" + rel;
    const int wd = ::inotify_add_watch(m_inotify, full.c_str(), watch_mask);
    if (wd < 0)
    {
        if (errno == ENOSPC || errno == ENOMEM)
            lose_watching();
        return;
    }
    m_watches[wd] = rel;
    const int dfd = open_beneath_fd(m_root_fd, rel.empty() ? "." : rel.c_str(), O_DIRECTORY | O_RDONLY | O_CLOEXEC);
    if (dfd < 0)
        return;
    DIR* d = ::fdopendir(dfd);
    if (!d)
    {
        ::close(dfd);
        return;
    }
    std::vector<std::string> dirs;
    while (const struct dirent* de = ::readdir(d))
    {
        const std::string_view n(de->d_name);
        if (n == "." || n == ".." || hidden_name(n))
            continue;
        bool is_dir = de->d_type == DT_DIR;
        if (de->d_type == DT_UNKNOWN)
        {
            struct stat st{};
            is_dir = ::fstatat(dfd, de->d_name, &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISDIR(st.st_mode);
        }
        if (is_dir)
            dirs.emplace_back(n);
    }
    ::closedir(d);
    for (const auto& n : dirs)
        watch_tree(rel.empty() ? n : rel + "/" + n, depth + 1);
}

void web_run::arm_watch()
{
    if (m_stopped || m_inotify < 0 || m_watch_armed)
        return;
    m_watch_armed = m_io.pread(m_inotify, m_watch_buf.get(), watch_buf_size, file_io::at_stream,
                               [this](int64_t res) { on_watch(res); });
    if (!m_watch_armed)
        lose_watching();
}

void web_run::on_watch(int64_t res)
{
    m_watch_armed = false;
    if (m_stopped || res == -ECANCELED)
        return;
    if (res < 0)
    {
        if (res == -EAGAIN || res == -EINTR)
            arm_watch();
        else
            lose_watching();
        return;
    }
    bool changed = false, root_moved = false, overflow = false;
    const char* p = m_watch_buf.get();
    const char* end = p + res;
    while (p + sizeof(struct inotify_event) <= end)
    {
        struct inotify_event ev;
        std::memcpy(&ev, p, sizeof ev);
        const char* name = p + sizeof(struct inotify_event);
        p += sizeof(struct inotify_event) + ev.len;
        if (p > end)
            break;
        const std::string_view leaf(name, ev.len ? ::strnlen(name, ev.len) : 0);
        if (ev.mask & IN_Q_OVERFLOW)
        {
            overflow = true;
            continue;
        }
        if (ev.mask & IN_IGNORED)
        {
            m_watches.erase(ev.wd);
            m_above.erase(ev.wd);
            continue;
        }
        if (const auto a = m_above.find(ev.wd); a != m_above.end())
        {
            root_moved = root_moved || leaf == a->second;
            continue;
        }
        const auto w = m_watches.find(ev.wd);
        if (w == m_watches.end())
            continue;
        changed = true;
        if ((ev.mask & (IN_DELETE_SELF | IN_MOVE_SELF)) && w->second.empty())
            root_moved = true;
        if ((ev.mask & IN_ISDIR) && (ev.mask & (IN_CREATE | IN_MOVED_TO)) && !hidden_name(leaf))
        {
            const std::string rel = w->second.empty() ? std::string(leaf) : w->second + "/" + std::string(leaf);
            watch_tree(rel, static_cast<int>(std::count(rel.begin(), rel.end(), '/')) + 1);
        }
    }
    // A new release under a name on the way to --root, or events lost: everything is watched again where it is now.
    if ((root_moved && root_swapped()) || overflow)
    {
        rewatch();
        changed = true;
    }
    if (changed)
        forget_all();
    arm_watch();
}

void web_run::forget_all()
{
    m_entries.clear();
    m_not_found.reset();
    m_fallback_entry.reset();
}

// ─── What an address is ─────────────────────────────────────────────────────

bool web_run::keep_bytes(uint64_t n)
{
    if (m_kept->bytes.load(std::memory_order_relaxed) + n > kept_max)
        return false;
    m_kept->bytes.fetch_add(n, std::memory_order_relaxed);
    return true;
}

int web_run::open_beneath(const std::string& rel, bool& is_dir, struct stat& st)
{
    const int fd = open_beneath_fd(m_root_fd, rel.empty() ? "." : rel.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0)
    {
        // Not there, not a directory on the way, or a way out of --root: the file is missing. Anything else is the
        // process short of something, which is not a 404 to remember.
        if (errno != ENOENT && errno != ENOTDIR && errno != ELOOP && errno != EXDEV && errno != EACCES &&
            errno != ENAMETOOLONG)
            m_transient = true;
        return -1;
    }
    if (::fstat(fd, &st) == 0 && (S_ISDIR(st.st_mode) || S_ISREG(st.st_mode)))
    {
        is_dir = S_ISDIR(st.st_mode);
        return fd;
    }
    ::close(fd);
    return -1;
}

std::shared_ptr<const body> web_run::make_body(const std::string& rel, int fd, const struct stat& st,
                                               std::string_view coding, std::string_view type)
{
    auto b = std::make_shared<body>();
    b->kept = m_kept;
    b->size = static_cast<uint64_t>(st.st_size);
    b->mtime_s = st.st_mtim.tv_sec;
    b->etag = socketley::http::etag_of(socketley::file_stamp::of(st));
    std::string& h = b->fields;
    h.append("Content-Type: ").append(type).append("\r\n");
    if (!coding.empty())
        h.append("Content-Encoding: ").append(coding).append("\r\n");
    h.append("ETag: \"").append(b->etag).append("\"\r\nLast-Modified: ");
    h.append(socketley::http::http_date_of(b->mtime_s));
    h.append("\r\nCache-Control: ").append(cache_control(rel, type)).append("\r\n");
    if (text_type(type))
        h.append("Vary: Accept-Encoding\r\n");
    // A range is of the file as it lies, which a compressed copy is not.
    if (coding.empty())
        h.append("Accept-Ranges: bytes\r\n");
    h.append("X-Content-Type-Options: nosniff\r\n");
    b->revalidation = revalidation_of(h);

    if (b->size == 0)
    {
        b->in_memory = true;
        ::close(fd);
        return b;
    }
    if (b->size <= inline_max && keep_bytes(b->size))
    {
        if (read_cached(fd, b->bytes, b->size))
        {
            b->in_memory = true;
            b->counted_bytes = b->size;
            ::close(fd);
            return b;
        }
        // Not in the page cache yet: sent from the descriptor, through the ring, until warm() finds it there.
        b->bytes.clear();
        b->bytes.shrink_to_fit();
        m_kept->bytes.fetch_sub(b->size, std::memory_order_relaxed);
    }
    b->fd = fd;
    m_kept->fds.fetch_add(1, std::memory_order_relaxed);
    return b;
}

void web_run::warm(entry& e)
{
    const body& old = *e.plain;
    if (old.in_memory || old.fd < 0 || old.size > inline_max || !keep_bytes(old.size))
        return;
    auto b = std::make_shared<body>();
    if (!read_cached(old.fd, b->bytes, old.size))
    {
        m_kept->bytes.fetch_sub(old.size, std::memory_order_relaxed);
        return;
    }
    b->kept = m_kept;
    b->counted_bytes = old.size;
    b->fields = old.fields;
    b->revalidation = old.revalidation;
    b->etag = old.etag;
    b->mtime_s = old.mtime_s;
    b->size = old.size;
    b->in_memory = true;
    e.plain = std::move(b);
}

uint64_t web_run::copies_of(const std::string& rel) const
{
    uint64_t sig = 0;
    for (const char* ext : {".br", ".gz"})
    {
        struct stat st{};
        sig = sig * 1000003 ^ (::fstatat(m_root_fd, (rel + ext).c_str(), &st, 0) == 0
                                   ? static_cast<uint64_t>(mtime_ns_of(st)) ^ (static_cast<uint64_t>(st.st_ino) << 1)
                                   : 1);
    }
    return sig;
}

std::shared_ptr<entry> web_run::file_entry(const std::string& rel, int fd, const struct stat& st, int status)
{
    auto e = std::make_shared<entry>();
    e->what = entry::kind::file;
    e->status = status;
    e->rel = rel;
    e->mtime_ns = mtime_ns_of(st);
    e->ino = static_cast<uint64_t>(st.st_ino);
    const std::string_view type = socketley::http::content_type_of(rel);
    e->plain = make_body(rel, fd, st, {}, type);
    if (!text_type(type))
        return e;
    if (!m_watching)
        e->copies = copies_of(rel);
    // The copies a build left beside the file, never one older than it.
    static constexpr std::pair<std::string_view, std::string_view> copies[] = {{"br", ".br"}, {"gzip", ".gz"}};
    for (const auto& [coding, ext] : copies)
    {
        bool is_dir = false;
        struct stat cst{};
        const int cfd = open_beneath(rel + std::string(ext), is_dir, cst);
        if (cfd < 0)
            continue;
        if (is_dir || mtime_ns_of(cst) < mtime_ns_of(st))
        {
            ::close(cfd);
            continue;
        }
        (coding == "br" ? e->br : e->gzip) = make_body(rel, cfd, cst, coding, type);
    }
    e->compressible = !e->gzip && e->plain->size >= compress_min && e->plain->size <= compress_max;
    return e;
}

std::shared_ptr<entry> web_run::missing(bool has_ext)
{
    // A single-page app's routes are addresses with no file behind them; a missing asset stays missing.
    const bool fallback = !m_fallback.empty() && !has_ext;
    std::shared_ptr<entry>& kept = fallback ? m_fallback_entry : m_not_found;
    if (kept && m_watching)
        return kept;
    std::shared_ptr<entry> e;
    bool is_dir = false;
    struct stat st{};
    for (const std::string& page : {fallback ? m_fallback : std::string(), std::string("404.html")})
    {
        if (page.empty())
            continue;
        const int fd = open_beneath(page, is_dir, st);
        if (fd < 0)
            continue;
        if (!is_dir)
        {
            e = file_entry(page, fd, st, fallback && page == m_fallback ? 200 : 404);
            break;
        }
        ::close(fd);
    }
    if (!e)
        e = std::make_shared<entry>();
    e->shared = true;
    if (!m_transient)
        kept = e;
    return e;
}

std::shared_ptr<entry> web_run::resolve(const std::string& path)
{
    const bool has_ext = path.find('.', path.rfind('/')) != std::string::npos;
    if (socketley::http::hidden_path(path))
        return missing(has_ext);

    const std::string rel = path.substr(1);
    bool is_dir = false;
    struct stat st{};
    if (path.back() == '/')
    {
        // A directory's address is its index; with none, nothing is listed.
        const std::string idx = rel + m_index;
        if (const int fd = open_beneath(idx, is_dir, st); fd >= 0)
        {
            if (!is_dir)
                return file_entry(idx, fd, st, 200);
            ::close(fd);
        }
        return missing(has_ext);
    }
    if (const int fd = open_beneath(rel, is_dir, st); fd >= 0)
    {
        if (!is_dir)
            return file_entry(rel, fd, st, 200);
        ::close(fd);
        // A directory named without its slash goes to it with one, so the page's relative links resolve under it.
        auto e = std::make_shared<entry>();
        e->what = entry::kind::redirect;
        e->location = socketley::http::url_encode(path, true) + "/";
        return e;
    }
    // /about is about.html, as a static site generator writes it.
    if (!has_ext)
        if (const int fd = open_beneath(rel + ".html", is_dir, st); fd >= 0)
        {
            if (!is_dir)
                return file_entry(rel + ".html", fd, st, 200);
            ::close(fd);
        }
    return missing(has_ext);
}

bool web_run::still_current(const entry& e) const
{
    if (e.what != entry::kind::file)
        return false;
    struct stat st{};
    return ::fstatat(m_root_fd, e.rel.c_str(), &st, 0) == 0 && mtime_ns_of(st) == e.mtime_ns &&
           static_cast<uint64_t>(st.st_ino) == e.ino && static_cast<uint64_t>(st.st_size) == e.plain->size &&
           (!text_type(socketley::http::content_type_of(e.rel)) || copies_of(e.rel) == e.copies);
}

std::shared_ptr<entry> web_run::lookup(const std::string& path)
{
    // Without inotify a release swapped in under --root's name is looked for once a second.
    if (!m_watching)
        if (const int64_t now = wall::now_sec_coarse(); now != m_root_checked)
        {
            m_root_checked = now;
            if (root_swapped())
                forget_all();
        }
    std::shared_ptr<entry> e;
    if (const auto it = m_entries.find(path); it != m_entries.end())
    {
        if (m_watching || still_current(*it->second))
            e = it->second;
        else
            m_entries.erase(it);
    }
    if (!e)
    {
        if (m_entries.size() >= entries_max)
            forget_all();
        m_transient = false;
        e = resolve(path);
        if (m_transient && e->what != entry::kind::file)
        {
            auto u = std::make_shared<entry>();
            u->what = entry::kind::unavailable;
            return u;
        }
        // An address nothing answers shares the 404 page, and a large file past the descriptors kept is opened anew.
        const bool keep = !e->shared && !m_transient &&
                          (e->what != entry::kind::file || e->plain->in_memory ||
                           m_kept->fds.load(std::memory_order_relaxed) <= fds_max);
        if (keep)
            m_entries.emplace(path, e);
    }
    if (e->what == entry::kind::file)
    {
        warm(*e);
        if (e->compressible && !e->compress_asked)
            ask_compress(e);
    }
    return e;
}

void web_run::ask_compress(const std::shared_ptr<entry>& e)
{
    if (e->compress_asked || !m_pool.enabled() || m_jobs >= jobs_max)
        return;
    e->compress_asked = true;
    ++m_jobs;
    ++m_c.compress_jobs;
    struct made
    {
        std::string bytes;
        int fd{-1};
        bool worth{false};
    };
    auto out = std::make_shared<made>();
    std::shared_ptr<const body> src = e->plain;
    m_pool.submit(0,
        [src, out]
        {
            std::string in;
            if (src->in_memory)
                in = src->bytes;
            else if (!read_whole(src->fd, in, src->size))
                return;
            std::string gz = socketley::gzip_of(in, in.size() <= (1u << 20) ? socketley::deflater::effort::best
                                                                           : socketley::deflater::effort::fast);
            // Not worth a second representation for a few bytes.
            if (gz.size() + 64 >= in.size())
                return;
            out->worth = true;
            if (gz.size() <= inline_max)
            {
                out->bytes = std::move(gz);
                return;
            }
            const int fd = ::memfd_create("socketley-web-gzip", MFD_CLOEXEC);
            size_t put = 0;
            while (fd >= 0 && put < gz.size())
            {
                const ssize_t w = ::write(fd, gz.data() + put, gz.size() - put);
                if (w < 0 && errno == EINTR)
                    continue;
                if (w <= 0)
                    break;
                put += static_cast<size_t>(w);
            }
            if (fd >= 0 && put == gz.size())
                out->fd = fd;
            else
            {
                if (fd >= 0)
                    ::close(fd);
                out->worth = false;
            }
        },
        [this, weak = std::weak_ptr<entry>(e), src, out]
        {
            --m_jobs;
            auto e = weak.lock();
            const uint64_t n = out->fd >= 0 ? static_cast<uint64_t>(::lseek(out->fd, 0, SEEK_END)) : out->bytes.size();
            // The same file still, by its tag: warm() may have put its bytes in another body meanwhile.
            if (m_stopped || !e || e->plain->etag != src->etag || !out->worth || e->gzip || !keep_bytes(n))
            {
                if (out->fd >= 0)
                    ::close(out->fd);
                return;
            }
            auto b = std::make_shared<body>();
            b->kept = m_kept;
            b->counted_bytes = n;
            b->size = n;
            b->mtime_s = src->mtime_s;
            b->etag = src->etag + "-gz";
            // The file's own fields, with its coding and tag, and no Accept-Ranges, since a range is of the file.
            const std::string_view type = socketley::http::content_type_of(e->rel);
            b->fields.append("Content-Type: ").append(type).append("\r\nContent-Encoding: gzip\r\nETag: \"");
            b->fields.append(b->etag).append("\"\r\nLast-Modified: ").append(socketley::http::http_date_of(b->mtime_s));
            b->fields.append("\r\nCache-Control: ").append(cache_control(e->rel, type));
            b->fields.append("\r\nVary: Accept-Encoding\r\nX-Content-Type-Options: nosniff\r\n");
            b->revalidation = revalidation_of(b->fields);
            if (out->fd >= 0)
            {
                b->fd = out->fd;
                m_kept->fds.fetch_add(1, std::memory_order_relaxed);
            }
            else
            {
                b->bytes = std::move(out->bytes);
                b->in_memory = true;
            }
            e->gzip = std::move(b);
        });
}

// ─── Requests ───────────────────────────────────────────────────────────────

std::shared_ptr<socketley::http::server_conn> web_run::make_conn()
{
    // The read buffer is written before it is read, so it is not cleared for each connection.
    return std::make_shared_for_overwrite<web_conn>();
}

void web_run::accepted(const std::shared_ptr<socketley::http::server_conn>&)
{
    arm_tick();
}

void web_run::serve(const std::shared_ptr<socketley::http::server_conn>& sc)
{
    const auto c = std::static_pointer_cast<web_conn>(sc);
    while (socketley::http::conn_server::takes_more(*c))
    {
        socketley::http::request_view v;
        int refusal = 400;
        request_fields f;
        const int r = socketley::http::take_request(c->in, max_head, max_body, v, refusal,
                                                    [&f](std::string_view line, std::string_view value) {
            if (header_name_equals(line, "if-none-match", 13))
                f.if_none_match.assign(value);
            else if (header_name_equals(line, "if-modified-since", 17))
                f.if_modified_since.assign(value);
            else if (header_name_equals(line, "if-match", 8))
                f.if_match.assign(value);
            else if (header_name_equals(line, "if-unmodified-since", 19))
                f.if_unmodified_since.assign(value);
            else if (header_name_equals(line, "range", 5))
                f.range.assign(value);
            else if (header_name_equals(line, "if-range", 8))
                f.if_range.assign(value);
            else if (header_name_equals(line, "accept-encoding", 15))
                f.accept_encoding.assign(value);
        });
        if (r == 0)
            break;
        if (r < 0)
        {
            ++m_c.refused;
            c->keep_alive = false;
            c->head = false;
            answer_plain(c, refusal, std::string(socketley::http::status_text(refusal)) + "\n");
            break;
        }
        // The views point into `in`, which the erase below moves.
        // Answered from views into `in`, which is let go of only after: an answer writes to `out` alone.
        const size_t used = v.head_len + v.body_len;
        c->http10 = std::string_view(c->in).substr(0, c->in.find("\r\n")).ends_with(" HTTP/1.0");
        c->keep_alive = !v.close;
        c->head = v.method == "HEAD";
        ++m_c.requests;
        runtime_instance::stat_add(m_owner.m_stat_total_messages, 1);
        const bool more = answer_request(c, v.method, v.path, v.query, f);
        c->in.erase(0, used);
        if (!more || !c->keep_alive)
            break;
    }
}

std::string_view web_run::connection_field(const web_conn& c)
{
    if (!c.keep_alive)
        return "Connection: close\r\n";
    // HTTP/1.0 closes unless the answer says otherwise.
    return c.http10 ? "Connection: keep-alive\r\n" : std::string_view{};
}

void web_run::answer_plain(const std::shared_ptr<web_conn>& c, int status, std::string_view text, std::string_view extra)
{
    std::string& o = c->out;
    o.append("HTTP/1.1 ").append(std::to_string(status)).append(" ").append(socketley::http::status_text(status));
    o.append("\r\n").append(date_field());
    if (!text.empty())
        o.append("Content-Type: text/plain; charset=utf-8\r\n");
    if (status != 204 && status != 304)
        o.append("Content-Length: ").append(std::to_string(text.size())).append("\r\n");
    o.append("X-Content-Type-Options: nosniff\r\n").append(extra).append(connection_field(*c)).append("\r\n");
    if (!c->head)
        o.append(text);
}

bool web_run::answer_request(const std::shared_ptr<web_conn>& c, std::string_view method, std::string_view raw,
                             std::string_view query, const request_fields& f)
{
    if (method != "GET" && method != "HEAD")
    {
        if (method == "OPTIONS")
        {
            answer_plain(c, 204, {}, "Allow: GET, HEAD, OPTIONS\r\n");
            return true;
        }
        ++m_c.refused;
        answer_plain(c, 405, "Method Not Allowed: a site's files are read with GET or HEAD\n",
                     "Allow: GET, HEAD, OPTIONS\r\n");
        return true;
    }
    // The absolute form a proxy may send names the same path.
    if (raw.starts_with("http://") || raw.starts_with("https://"))
    {
        const size_t slash = raw.find('/', raw.find("://") + 3);
        raw = slash == std::string_view::npos ? std::string_view("/") : raw.substr(slash);
    }
    std::string path;
    if (!socketley::http::site_path(raw, path))
    {
        ++m_c.not_found;
        answer_plain(c, 404, "Not Found\n");
        return true;
    }
    const std::shared_ptr<entry> e = lookup(path);
    switch (e->what)
    {
        case entry::kind::redirect:
        {
            ++m_c.redirects;
            std::string loc = "Location: " + e->location;
            // Only a query of visible ASCII rides along: anything else in a field line is a header someone else wrote.
            if (!query.empty() &&
                std::all_of(query.begin(), query.end(), [](char ch) { return ch > 0x20 && ch < 0x7f; }))
                loc.append("?").append(query);
            answer_plain(c, 301, {}, loc + "\r\n");
            return true;
        }
        case entry::kind::missing:
            ++m_c.not_found;
            answer_plain(c, 404, "Not Found\n");
            return true;
        case entry::kind::unavailable:
            ++m_c.unavailable;
            answer_plain(c, 503, "Service Unavailable\n", "Retry-After: 1\r\n");
            return true;
        case entry::kind::file:
            break;
    }
    if (e->status == 404)
        ++m_c.not_found;
    return answer_file(c, *e, f);
}

bool web_run::answer_file(const std::shared_ptr<web_conn>& c, const entry& e, const request_fields& f)
{
    namespace h = socketley::http;
    // A range is of the file as it lies; otherwise the coding the client takes, br before gzip.
    const bool ranged = !f.range.empty() && e.status == 200;
    std::shared_ptr<const body> b = e.plain;
    if (!ranged && !f.accept_encoding.empty())
    {
        if (e.br && h::accepts_coding(f.accept_encoding, "br"))
            b = e.br;
        else if (e.gzip && h::accepts_coding(f.accept_encoding, "gzip"))
            b = e.gzip;
    }

    if (e.status == 200)
    {
        const h::conditions cond{f.if_match, f.if_unmodified_since, f.if_none_match, f.if_modified_since};
        const h::precondition pc = h::evaluate(cond, b->etag, b->mtime_s);
        if (pc == h::precondition::not_modified)
        {
            ++m_c.not_modified;
            if (!c->keep_alive || c->http10)
            {
                answer_plain(c, 304, {}, b->revalidation);
                return true;
            }
            const std::string& date = date_field();
            if (b->ready_304_sec != m_date_sec)
            {
                b->ready_304.assign("HTTP/1.1 304 Not Modified\r\n").append(date);
                b->ready_304.append("X-Content-Type-Options: nosniff\r\n").append(b->revalidation).append("\r\n");
                b->ready_304_sec = m_date_sec;
            }
            c->out.append(b->ready_304);
            return true;
        }
        if (pc == h::precondition::failed)
        {
            ++m_c.refused;
            answer_plain(c, 412, "Precondition Failed\n");
            return true;
        }
    }

    uint64_t off = 0, n = b->size;
    int status = e.status;
    std::string range_field;
    if (ranged)
    {
        http_range r = http_parse_range(f.range, b->size);
        const bool same = h::if_range_holds(f.if_range, b->etag, b->mtime_s);
        if (r.unsatisfiable && same)
        {
            answer_plain(c, 416, {}, "Content-Range: bytes */" + std::to_string(b->size) + "\r\n");
            return true;
        }
        if (r.usable && same)
        {
            ++m_c.ranges;
            off = r.first;
            n = r.last - r.first + 1;
            status = 206;
            range_field = "Content-Range: bytes " + std::to_string(r.first) + "-" + std::to_string(r.last) + "/" +
                          std::to_string(b->size) + "\r\n";
        }
    }
    if (b != e.plain)
        ++m_c.compressed;

    // The common answer, a whole file from memory on a connection kept alive, is its kept head and its bytes.
    if (status == 200 && b->in_memory && !c->head && c->keep_alive && !c->http10)
    {
        const std::string& date = date_field();
        if (b->ready_sec != m_date_sec)
        {
            b->ready.assign("HTTP/1.1 200 OK\r\n").append(date).append(b->fields).append("Content-Length: ");
            b->ready.append(std::to_string(b->size)).append("\r\n\r\n");
            b->ready_sec = m_date_sec;
        }
        if (b->size)
            ++m_c.from_memory;
        c->out.append(b->ready).append(b->bytes);
        return true;
    }

    std::string head;
    head.reserve(160 + b->fields.size());
    head.append("HTTP/1.1 ").append(std::to_string(status)).append(" ").append(h::status_text(status)).append("\r\n");
    head.append(date_field()).append(b->fields).append("Content-Length: ").append(std::to_string(n)).append("\r\n");
    head.append(range_field).append(connection_field(*c)).append("\r\n");

    if (c->head || n == 0 || b->in_memory)
    {
        c->out.append(head);
        if (!c->head && n)
        {
            ++m_c.from_memory;
            c->out.append(b->bytes, off, n);
        }
        return true;
    }

    // From the descriptor, after the head; nothing more of the connection is read meanwhile.
    ++m_c.zero_copy;
    c->sending_body = b;
    c->file_off = off;
    c->file_left = n;
    c->waiting = true;
    // With nothing ahead of it, the head goes at once, held for the file's first bytes, and the file follows this turn.
    if (c->unsent() == 0 && !c->wr_pending)
    {
        const ssize_t s = socketley::file_send::send_head(c->fd, head);
        if (s < 0)
        {
            m_http.close_conn(c);
            return false;
        }
        runtime_instance::stat_add(m_owner.m_stat_bytes_out, static_cast<uint64_t>(s));
        if (static_cast<size_t>(s) == head.size())
        {
            switch (pump(c))
            {
                case pump_result::done:
                    c->sending_body.reset();
                    c->waiting = false;
                    return true;
                case pump_result::failed:
                    m_http.close_conn(c);
                    return false;
                case pump_result::waiting:
                    return false;
            }
        }
        head.erase(0, static_cast<size_t>(s));
    }
    c->out.append(head);
    return false;
}

web_run::pump_result web_run::pump(const std::shared_ptr<web_conn>& c)
{
    if (c->dead)
        return pump_result::failed;
    if (c->file_left == 0)
        return pump_result::done;
    const std::shared_ptr<const body> b = c->sending_body;
    if (!socketley::file_send::cold(b->fd, c->file_off, c->file_left))
    {
        uint64_t sent = 0;
        const auto r = socketley::file_send::send(c->fd, c->sock_flags, b->fd, c->file_off, c->file_left, sent);
        if (sent)
        {
            runtime_instance::stat_add(m_owner.m_stat_bytes_out, sent);
            c->last = wall::now_sec_coarse();
        }
        if (r == socketley::file_send::burst::failed)
            return pump_result::failed;
        if (r == socketley::file_send::burst::done)
            return pump_result::done;
        pump_later(c);
        return c->dead ? pump_result::failed : pump_result::waiting;
    }
    // Out of the page cache: read through the ring, which keeps the loop off the disk, and written as any answer.
    const uint32_t n = static_cast<uint32_t>(std::min<uint64_t>(c->file_left, cold_chunk));
    auto buf = std::make_shared<std::string>(n, '\0');
    std::weak_ptr<web_conn> weak = c;
    if (!m_io.pread(b->fd, buf->data(), n, c->file_off,
                    [this, weak, buf, b](int64_t res)
                    {
                        auto cc = weak.lock();
                        if (!cc || cc->dead)
                            return;
                        if (res <= 0)
                        {
                            // The file is shorter than the length already promised.
                            m_http.close_conn(cc);
                            return;
                        }
                        cc->file_off += static_cast<uint64_t>(res);
                        cc->file_left -= static_cast<uint64_t>(res);
                        buf->resize(static_cast<size_t>(res));
                        cc->out.append(*buf);
                        m_http.flush(cc);
                    }))
        return pump_result::failed;
    return pump_result::waiting;
}

void web_run::pump_later(const std::shared_ptr<web_conn>& c)
{
    std::weak_ptr<web_conn> weak = c;
    const bool armed = m_io.poll(c->fd, POLLOUT,
        [this, weak](int64_t res)
        {
            auto cc = weak.lock();
            if (!cc || cc->dead)
                return;
            if (res < 0 || (res & (POLLERR | POLLHUP)) != 0)
            {
                m_http.close_conn(cc);
                return;
            }
            written(cc);
        });
    if (!armed)
        m_http.close_conn(c);
}

bool web_run::written(const std::shared_ptr<socketley::http::server_conn>& sc)
{
    const auto c = std::static_pointer_cast<web_conn>(sc);
    if (!c->sending_body)
        return false;
    switch (pump(c))
    {
        case pump_result::done:
            c->sending_body.reset();
            m_http.resume(c);
            break;
        case pump_result::failed:
            m_http.close_conn(c);
            break;
        case pump_result::waiting:
            break;
    }
    return true;
}

void web_run::closing(const std::shared_ptr<socketley::http::server_conn>& sc)
{
    std::static_pointer_cast<web_conn>(sc)->sending_body.reset();
}

std::string web_run::stats() const
{
    const auto line = [](std::string& o, const char* k, uint64_t v) {
        o.append(k).append(":").append(std::to_string(v)).append("\n");
    };
    std::string o;
    line(o, "requests", m_c.requests);
    line(o, "not_modified", m_c.not_modified);
    line(o, "not_found", m_c.not_found);
    line(o, "redirects", m_c.redirects);
    line(o, "refused", m_c.refused);
    line(o, "unavailable", m_c.unavailable);
    line(o, "ranges", m_c.ranges);
    line(o, "from_memory", m_c.from_memory);
    line(o, "zero_copy", m_c.zero_copy);
    line(o, "compressed", m_c.compressed);
    line(o, "compress_jobs", m_c.compress_jobs);
    line(o, "reloads", m_c.reloads);
    line(o, "stalled", m_c.stalled);
    line(o, "addresses", m_entries.size());
    line(o, "kept_bytes", m_kept->bytes.load(std::memory_order_relaxed));
    line(o, "kept_files", m_kept->fds.load(std::memory_order_relaxed));
    line(o, "watching", m_watching ? 1 : 0);
    return o;
}

}   // namespace socketley::web
