#include "sync_run.h"
#include "sync_instance.h"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <fnmatch.h>
#include <climits>
#include <cstdlib>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <shared_mutex>

#include "../../shared/logging.h"
#include "../../shared/paths.h"
#include "../../shared/runtime_manager.h"
#include "../../shared/s3_sigv4.h"
#include "../storage/s3_names.h"

namespace socketley::sync
{

namespace fs = std::filesystem;
using socketley::storage::http_answer;
using socketley::storage::http_peer;
using socketley::storage::http_request;
using socketley::storage::http_target;

namespace
{

// Directory entries looked at in one loop turn: enough that a large tree is walked quickly, few enough that a stop
// is answered within a turn.
constexpr int walk_slice_entries = 512;
// A file's body is read in pieces this large, which is one read of a local disk and not a stall worth measuring.
constexpr uint32_t body_piece = 1u << 20;
// How long a target is given to answer one object.
constexpr int answer_secs = 120;
// A file larger than this goes in parts, since one request carries at most 5 GiB and a part lost costs only itself.
constexpr uint64_t multipart_above = 512ull << 20;
constexpr uint64_t part_size = 64ull << 20;
// Exchanges in flight to one target at once: a small file costs a round trip and the far side's sync, which several
// at a time overlap; the AWS CLI's default is ten.
constexpr int lanes_per_target = 8;
// How long after a target stopped answering the directory is walked again for it.
constexpr int retry_secs = 30;
// One read of inotify takes this much: some hundred events, more than a burst of saves makes.
constexpr uint32_t watch_buf_size = 64 * 1024;
// A file is looked at once it is written and closed, moved in, touched or removed; one merely created is still being
// written, and is looked at when it is closed. Links are not followed, so a watch never leaves --dir.
constexpr uint32_t watch_mask = IN_CLOSE_WRITE | IN_MOVED_TO | IN_MOVED_FROM | IN_DELETE | IN_ATTRIB | IN_CREATE |
                                IN_DELETE_SELF | IN_MOVE_SELF | IN_ONLYDIR | IN_DONT_FOLLOW | IN_EXCL_UNLINK;

std::string amz_date_now()
{
    char buf[32];
    const std::time_t t = std::time(nullptr);
    std::tm tm{};
    gmtime_r(&t, &tm);
    std::strftime(buf, sizeof buf, "%Y%m%dT%H%M%SZ", &tm);
    return buf;
}

// The text of the first <name> element of an S3 answer, empty when it has none.
std::string xml_text(std::string_view xml, std::string_view name)
{
    const std::string open = "<" + std::string(name) + ">", close = "</" + std::string(name) + ">";
    const size_t a = xml.find(open);
    if (a == std::string_view::npos)
        return {};
    const size_t from = a + open.size();
    const size_t b = xml.find(close, from);
    if (b == std::string_view::npos)
        return {};
    std::string out(xml.substr(from, b - from));
    // An ETag in XML has its quotes written as entities.
    for (size_t q; (q = out.find("&quot;")) != std::string::npos;)
        out.replace(q, 6, "\"");
    return out;
}

// Every segment of a key encoded as S3 signs it, the separators kept.
std::string encode_key(std::string_view key)
{
    std::string out;
    socketley::storage::url_encode_to(out, key, true);
    return out;
}

}   // namespace

bool read_sync_credentials(const std::string& path, sync_credentials& out, std::string& why)
{
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
    {
        why = path + ": " + std::strerror(errno);
        return false;
    }
    std::string text;
    char buf[4096];
    for (;;)
    {
        const ssize_t n = ::read(fd, buf, sizeof buf);
        if (n < 0 && errno == EINTR)
            continue;
        // Half a credentials file is a wrong secret, so a read that breaks off is no read.
        if (n < 0)
        {
            why = path + ": " + std::strerror(errno);
            ::close(fd);
            return false;
        }
        if (n == 0)
            break;
        text.append(buf, static_cast<size_t>(n));
    }
    ::close(fd);

    for (size_t p = 0; p < text.size();)
    {
        const size_t nl = std::min(text.find('\n', p), text.size());
        std::string_view line(text.data() + p, nl - p);
        p = nl + 1;
        if (const size_t hash = line.find('#'); hash != std::string_view::npos)
            line = line.substr(0, hash);
        const size_t eq = line.find('=');
        if (eq == std::string_view::npos)
            continue;
        const auto trim = [](std::string_view v)
        {
            while (!v.empty() && (v.front() == ' ' || v.front() == '\t'))
                v.remove_prefix(1);
            while (!v.empty() && (v.back() == ' ' || v.back() == '\t' || v.back() == '\r'))
                v.remove_suffix(1);
            return v;
        };
        const std::string_view k = trim(line.substr(0, eq)), v = trim(line.substr(eq + 1));
        if (k == "access_key")
            out.access_key.assign(v);
        else if (k == "secret_key")
            out.secret.assign(v);
        else if (k == "session_token")
            out.session_token.assign(v);
        else if (k == "region")
            out.region.assign(v);
    }
    if (out.access_key.empty() || out.secret.empty())
    {
        why = path + " holds no access_key and secret_key";
        return false;
    }
    return true;
}

sync_run::sync_run(sync_instance& rt, event_loop& loop)
    : m_rt(rt), m_loop(loop), m_io(loop, this), m_resolver(1)
{
}

sync_run::~sync_run() = default;

bool sync_run::resolve_targets(std::string& why)
{
    sync_credentials cred;
    if (!read_sync_credentials(std::string(m_rt.get_credentials()), cred, why))
        return false;

    for (const auto& one : m_rt.storage_targets())
    {
        sync_target_spec spec;
        if (!parse_sync_target(one, spec, why))
            return false;
        target t;
        t.name = spec.name;
        t.bucket = spec.bucket;
        t.runtime = spec.runtime;
        t.cred = cred;
        // An address is parsed now, so a bad one is refused before the job starts; a runtime's port is in the
        // daemon's map, once that has arrived.
        if (!spec.url.empty())
        {
            if (!socketley::storage::parse_http_url(spec.url, t.http, why))
                return false;
            t.addressed = true;
        }
        m_targets.push_back(std::move(t));
    }
    return !m_targets.empty();
}

bool sync_run::ensure_address(target& t)
{
    if (!t.lanes.empty())
        return true;
    if (!t.addressed)
    {
        runtime_manager* mgr = m_rt.get_runtime_manager();
        if (!mgr)
            return false;
        uint16_t port = 0;
        std::string type;
        {
            std::shared_lock lock(mgr->mutex);
            // The port the map carries, not effective_port(): a replica of another runtime is a generic object that
            // does not know its type's default, so asking for the effective one answers zero for every one of them.
            if (const runtime_instance* rt = mgr->get(t.runtime))
            {
                port = rt->get_port();
                type = type_to_string(rt->get_type());
            }
        }
        if (!type.empty() && type != "storage")
        {
            if (!t.told)
                note(t.runtime + " is a " + type + " runtime, not a storage");
            t.told = true;
            return false;
        }
        if (!port)
        {
            // The map has not come down yet, or the runtime is not there; the next turn asks again.
            if (!t.told)
                note(t.runtime + ": no storage runtime of that name is listening here" +
                     (t.runtime.find('.') != std::string::npos
                          ? "; a host is named by its URL, as in https://" + t.runtime + "/" + t.bucket
                          : std::string{}));
            t.told = true;
            return false;
        }
        std::string why;
        if (!socketley::storage::parse_http_url("http://127.0.0.1:" + std::to_string(port), t.http, why))
            return false;
        t.told = false;
    }
    for (int i = 0; i < lanes_per_target; ++i)
    {
        auto l = std::make_unique<lane>();
        l->peer = std::make_unique<http_peer>(m_loop, m_io, m_resolver, t.http, std::string{},
                                              "sync " + std::string(m_rt.get_name()) + " -> " + t.name);
        t.lanes.push_back(std::move(l));
    }
    t.lanes.front()->peer->prime();
    return true;
}

bool sync_run::start(std::string& why)
{
    const fs::path index = sync_index_path(m_rt.get_name());
    std::error_code ec;
    fs::create_directories(index.parent_path(), ec);
    if (ec)
    {
        why = index.parent_path().string() + ": " + ec.message();
        return false;
    }
    char root[PATH_MAX];
    m_root_real = ::realpath(std::string(m_rt.get_dir()).c_str(), root) ? root : std::string(m_rt.get_dir());
    // The directory and the prefix decide which object a path is, so an index kept for others is begun again.
    const std::string scope = std::string(m_rt.get_dir()) + "\n" + std::string(m_rt.get_prefix());
    if (!m_index.open(index.string(), scope, why))
        return false;
    if (!resolve_targets(why))
        return false;
    // A target no longer named is no longer this job's to remove things from.
    std::vector<std::string> names;
    for (const auto& t : m_targets)
        names.push_back(t.name);
    m_index.retain(names);

    const std::string_view ex = m_rt.get_exclude();
    for (size_t p = 0; p <= ex.size();)
    {
        const size_t comma = std::min(ex.find(',', p), ex.size());
        std::string_view one = ex.substr(p, comma - p);
        // `*.tmp, *.md` is how a list is written by hand, and a pattern starting with a space matches nothing.
        while (!one.empty() && (one.front() == ' ' || one.front() == '\t'))
            one.remove_prefix(1);
        while (!one.empty() && (one.back() == ' ' || one.back() == '\t'))
            one.remove_suffix(1);
        if (!one.empty())
            m_exclude.emplace_back(one);
        p = comma + 1;
    }

    m_stats.indexed = m_index.size();
    // A host given by name is resolved on the pool's thread, whose answers wake this loop only once it is attached.
    if (!m_resolver.attach(m_io))
        say("the resolver cannot be waited for, so a target named by a host is not reached");
    for (auto& t : m_targets)
        ensure_address(t);

    // Changes are seen as they happen; without inotify the walk on --every is what sees them.
    m_inotify = ::inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (m_inotify < 0)
        say(std::string("inotify: ") + std::strerror(errno) + "; changes are seen at the walk --every asks for");
    else
        m_watch_buf = std::make_unique<char[]>(watch_buf_size);

    begin_walk();
    arm_watch();
    arm_tick(true);
    return true;
}

void sync_run::stop()
{
    m_stopped = true;
    for (auto& t : m_targets)
        for (auto& l : t.lanes)
            l->peer->stop();
    m_iter.reset();
    m_walking = false;
    m_index.flush();
    // Through the loop, which cancels the read standing on it; its completion still comes here, which is why a
    // stopped run is kept until drained().
    if (m_inotify >= 0)
        m_loop.close_fd(m_inotify);
    m_inotify = -1;
    m_watches.clear();
    if (m_tick_armed)
        m_loop.submit_timeout_remove(&m_tick_req);
    // A resolve in progress is waited out here, which the system resolver's own timeout bounds.
    m_resolver.stop();
    if (const int fd = m_resolver.release_wake_fd(); fd >= 0)
        m_loop.close_fd(fd);
}

bool sync_run::drained() const
{
    return m_loop.owner_inflight(this) == 0 && !m_loop.owner_table_full();
}

void sync_run::on_cqe(struct io_uring_cqe* cqe)
{
    auto* req = static_cast<io_request*>(io_uring_cqe_get_data(cqe));
    // The tick only wakes the loop, whose turn calls on_loop_turn(); that is all it is for.
    if (req == &m_tick_req)
    {
        m_tick_armed = false;
        return;
    }
    m_io.on_cqe(cqe);
}

void sync_run::arm_tick(bool soon)
{
    if (m_stopped || m_tick_armed)
        return;
    // Soon while there is a walk to slice or work queued, else once a second: often enough for a stalled exchange,
    // a retry and --every, and an idle loop otherwise sleeps until something completes.
    m_tick_ts = soon ? __kernel_timespec{0, 1000000} : __kernel_timespec{1, 0};
    m_tick_req = io_request{};
    m_tick_req.owner = this;
    m_tick_req.type = op_timeout;
    m_tick_armed = m_loop.submit_timeout(&m_tick_ts, &m_tick_req);
}

size_t sync_run::open_connections() const
{
    size_t n = 0;
    for (const auto& t : m_targets)
        for (const auto& l : t.lanes)
            if (l->busy)
                ++n;
    return n;
}

bool sync_run::excluded(const std::string& rel) const
{
    const size_t slash = rel.rfind('/');
    const char* base = rel.c_str() + (slash == std::string::npos ? 0 : slash + 1);
    for (const auto& pat : m_exclude)
    {
        // A pattern with no slash names an entry at any depth, as a .gitignore line does.
        const char* against = pat.find('/') == std::string::npos ? base : rel.c_str();
        if (::fnmatch(pat.c_str(), against, 0) == 0)
            return true;
    }
    return false;
}

std::string sync_run::key_of(const std::string& rel) const
{
    std::string prefix(m_rt.get_prefix());
    if (prefix.empty())
        return rel;
    if (prefix.back() != '/')
        prefix += '/';
    return prefix + rel;
}

void sync_run::say(const std::string& what)
{
    if (what == m_logged)
        return;
    // The worker's log already names the runtime.
    LOG_WARN(what.c_str());
    m_logged = what;
}

void sync_run::note(const std::string& what)
{
    m_stats.last_error = what;
    ++m_stats.failures;
    ++m_stats.failing;
    // Once per change of what is wrong, so a host that is down for a day is one line and not one per file.
    say(what);
}

void sync_run::begin_walk()
{
    if (m_stopped || m_walking)
        return;
    m_rewalk = false;
    std::error_code ec;
    m_iter = std::make_unique<fs::recursive_directory_iterator>(
        fs::path(m_rt.get_dir()), fs::directory_options::skip_permission_denied, ec);
    if (ec)
    {
        note(std::string(m_rt.get_dir()) + ": " + ec.message());
        m_iter.reset();
        m_last_walk = std::chrono::steady_clock::now();
        owe_retry();
        return;
    }
    // Read again at every walk, so credentials put right or rotated are used without a restart.
    sync_credentials cred;
    std::string why;
    if (read_sync_credentials(std::string(m_rt.get_credentials()), cred, why))
    {
        for (auto& t : m_targets)
            t.cred = cred;
    }
    else
        note(why);
    watch_dir({});
    m_seen.clear();
    m_walking = true;
    m_walk_started = std::chrono::steady_clock::now();
}

bool sync_run::walk_slice()
{
    const fs::recursive_directory_iterator end;
    const std::string root(m_rt.get_dir());
    const std::string base = root.ends_with('/') ? root : root + "/";
    for (int n = 0; n < walk_slice_entries; ++n)
    {
        if (!m_iter || *m_iter == end)
            return true;
        std::error_code ec;
        const fs::directory_entry& de = **m_iter;
        std::string rel = de.path().string();
        // The path below --dir, which is what the index keys by and what the key is built from.
        if (rel.size() > base.size() && rel.compare(0, base.size(), base) == 0)
            rel.erase(0, base.size());
        const bool is_file = de.is_regular_file(ec) && !ec;
        if (!is_file && de.is_directory(ec) && !ec)
        {
            // An excluded directory is not walked at all, so `node_modules` or `.git` keeps its whole tree out.
            if (excluded(rel))
                m_iter->disable_recursion_pending();
            else if (!de.is_symlink(ec))
                watch_dir(rel);
            else
                m_iter->disable_recursion_pending();
        }
        if (is_file && !excluded(rel))
        {
            m_seen.push_back(rel);
            check_path(rel);
        }
        m_iter->increment(ec);
        if (ec)
        {
            // What follows the error was not seen, and is not gone for that.
            note("walking " + root + ": " + ec.message());
            return true;
        }
    }
    return false;
}

void sync_run::end_walk()
{
    m_walking = false;
    m_iter.reset();
    m_last_walk = std::chrono::steady_clock::now();
    // What the index holds and the walk did not see is gone from this side, so it is taken off the far side too --
    // but only what is provably gone: a walk that broke off, a directory it could not read and a file excluded
    // since all leave things unseen that are still here, and are left where they were carried.
    std::sort(m_seen.begin(), m_seen.end());
    std::vector<std::string> gone;
    for (const auto& [k, e] : m_index.all())
    {
        (void)e;
        if (!std::binary_search(m_seen.begin(), m_seen.end(), k.path))
            gone.push_back(k.path);
    }
    std::sort(gone.begin(), gone.end());
    gone.erase(std::unique(gone.begin(), gone.end()), gone.end());
    // A directory that is suddenly empty is far likelier a disk that is not mounted than a user who deleted every
    // file, and taking the whole bucket away on that guess cannot be undone.
    if (m_seen.empty() && !gone.empty())
    {
        note(std::string(m_rt.get_dir()) + " is empty, and " + std::to_string(gone.size()) +
             " files were carried from it: nothing is removed from the storage. Is it mounted? If the files were "
             "deleted on purpose, delete them from the storage by hand");
        gone.clear();
    }
    for (const auto& path : gone)
        if (provably_gone(path))
            for (auto& t : m_targets)
                if (m_index.find(t.name, path))
                    t.queue.push_back(job{'d', path, 0, 0});
    m_seen.clear();
    m_seen.shrink_to_fit();
    std::string why;
    if (!m_index.compact(why))
        note(why);
    m_index.flush();
}

bool sync_run::provably_gone(const std::string& rel) const
{
    struct stat st{};
    const std::string full = std::string(m_rt.get_dir()) + "/" + rel;
    if (::lstat(full.c_str(), &st) != 0)
        return errno == ENOENT || errno == ENOTDIR;
    // A link to nothing is a file this side no longer has, as much as a deleted one.
    return S_ISLNK(st.st_mode) && ::stat(full.c_str(), &st) != 0 && (errno == ENOENT || errno == ENOTDIR);
}

bool sync_run::inside(const std::string& full, std::string* real) const
{
    char buf[PATH_MAX];
    if (!::realpath(full.c_str(), buf))
        return false;
    const std::string_view r(buf);
    const bool in = r == m_root_real || (r.size() > m_root_real.size() && r.starts_with(m_root_real) &&
                                         (m_root_real == "/" || r[m_root_real.size()] == '/'));
    if (real)
        real->assign(r);
    return in;
}

void sync_run::check_path(const std::string& rel)
{
    const std::string full = std::string(m_rt.get_dir()) + "/" + rel;
    struct stat st{};
    if (::stat(full.c_str(), &st) == 0)
    {
        if (!S_ISREG(st.st_mode))
            return;
        // A link is carried as what it names only when that is below --dir: one pointing out would send a file the
        // job was never given, which anyone who may write in --dir could choose.
        struct stat lst{};
        if (::lstat(full.c_str(), &lst) == 0 && S_ISLNK(lst.st_mode) && !inside(full, nullptr))
        {
            say(rel + " is a link to a file outside " + std::string(m_rt.get_dir()) + ", which is not carried");
            return;
        }
        const int64_t mtime = int64_t(st.st_mtim.tv_sec) * 1000000000 + st.st_mtim.tv_nsec;
        for (auto& t : m_targets)
        {
            const index_entry* had = m_index.find(t.name, rel);
            // Size and time are what a local file is told to have changed by; the etag says the same of the far
            // side and is compared when `in` is carried.
            if (had && had->size == uint64_t(st.st_size) && had->mtime_ns == mtime)
                continue;
            t.queue.push_back(job{'p', rel, uint64_t(st.st_size), mtime});
        }
        return;
    }
    // Anything unreadable rather than gone stays where it was carried.
    if (!provably_gone(rel))
        return;
    for (auto& t : m_targets)
        if (m_index.find(t.name, rel))
            t.queue.push_back(job{'d', rel, 0, 0});
}

void sync_run::watch_dir(const std::string& rel)
{
    if (m_inotify < 0 || m_watch_full)
        return;
    const std::string full = rel.empty() ? std::string(m_rt.get_dir()) : std::string(m_rt.get_dir()) + "/" + rel;
    const int wd = ::inotify_add_watch(m_inotify, full.c_str(), watch_mask);
    if (wd < 0)
    {
        if (errno == ENOSPC)
        {
            m_watch_full = true;
            say("inotify has no watch left (fs.inotify.max_user_watches): changes below " + full +
                 " and the directories after it are seen at the walk --every asks for");
        }
        return;
    }
    // The same directory reached again keeps its descriptor, under the path it now has.
    m_watches[wd] = rel;
    m_stats.watched = m_watches.size();
}

void sync_run::arm_watch()
{
    if (m_stopped || m_inotify < 0 || m_watch_armed)
        return;
    if (!m_io.pread(m_inotify, m_watch_buf.get(), watch_buf_size, file_io::at_stream,
                    [this](int64_t res) { on_watch(res); }))
    {
        say("inotify: the ring took no read; changes are seen at the walk --every asks for");
        return;
    }
    m_watch_armed = true;
}

void sync_run::on_watch(int64_t res)
{
    m_watch_armed = false;
    if (m_stopped || res == -ECANCELED)
        return;
    if (res < 0)
    {
        if (res != -EAGAIN && res != -EINTR)
        {
            say(std::string("inotify: ") + std::strerror(int(-res)) + "; changes are seen at the walk --every asks for");
            return;
        }
        arm_watch();
        return;
    }
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
        if (ev.mask & IN_Q_OVERFLOW)
        {
            m_rewalk = true;
            continue;
        }
        if (ev.mask & IN_IGNORED)
        {
            m_watches.erase(ev.wd);
            m_stats.watched = m_watches.size();
            continue;
        }
        const auto w = m_watches.find(ev.wd);
        if (w == m_watches.end())
            continue;
        // The directory itself went, or the disk under it: what was below it is for a walk to find gone.
        if (ev.mask & (IN_DELETE_SELF | IN_MOVE_SELF | IN_UNMOUNT))
        {
            // One moved away keeps its watch, which would name its files under the path it no longer has; a walk
            // watches it again if it is still below --dir, and watches --dir itself again in any case.
            if (ev.mask & IN_MOVE_SELF)
            {
                ::inotify_rm_watch(m_inotify, ev.wd);
                m_watches.erase(w);
                m_stats.watched = m_watches.size();
            }
            m_rewalk = true;
            continue;
        }
        if (ev.len == 0)
            continue;
        const std::string leaf(name, ::strnlen(name, ev.len));
        const std::string rel = w->second.empty() ? leaf : w->second + "/" + leaf;
        if (excluded(rel))
            continue;
        if (ev.mask & IN_ISDIR)
        {
            // A directory that came brings files no event will name, and one that went takes files with it.
            m_rewalk = true;
            continue;
        }
        // Created and not yet closed is still being written; the close says when it is whole.
        if ((ev.mask & IN_CREATE) && !(ev.mask & ~(IN_CREATE | IN_ISDIR)))
            continue;
        m_changed.insert(rel);
    }
    arm_watch();
}

http_request sync_run::signed_request(const target& t, std::string_view method, const std::string& rel,
                                      std::string_view query, std::vector<std::pair<std::string, std::string>> extra,
                                      std::string body) const
{
    const std::string key = "/" + t.bucket + "/" + encode_key(key_of(rel));
    std::vector<std::pair<std::string, std::string>> headers;
    const std::string date = amz_date_now();
    headers.emplace_back("host", t.http.authority());
    headers.emplace_back("x-amz-date", date);
    headers.emplace_back("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
    if (!t.cred.session_token.empty())
        headers.emplace_back("x-amz-security-token", t.cred.session_token);
    for (auto& h : extra)
        headers.push_back(std::move(h));

    std::vector<socketley::s3::header_field> fields;
    fields.reserve(headers.size());
    for (const auto& [n, v] : headers)
        fields.push_back({n, v});
    socketley::s3::sign_input in;
    in.method       = method;
    in.raw_path     = key;
    in.raw_query    = query;
    in.headers      = fields;
    in.payload_hash = "UNSIGNED-PAYLOAD";
    in.access_key   = t.cred.access_key;
    in.secret       = t.cred.secret;
    in.region       = t.cred.region;
    in.amz_date     = date;

    http_request rq;
    rq.head = std::string(method) + " " + key + (query.empty() ? "" : "?" + std::string(query)) + " HTTP/1.1\r\n";
    for (const auto& [n, v] : headers)
        rq.head += n + ": " + v + "\r\n";
    rq.head += "authorization: " + socketley::s3::sign(in) + "\r\nconnection: keep-alive\r\n";
    rq.head += "user-agent: socketley-sync\r\n\r\n";
    rq.body = std::move(body);
    rq.answer_secs = answer_secs;
    return rq;
}

void sync_run::body_from(const target& t, http_request& rq, const std::shared_ptr<int>& fd, uint64_t off,
                         uint64_t len) const
{
    // Without TLS the bytes go from the file to the socket by splice and never pass through this process.
    if (!t.http.tls)
    {
        rq.file_fd = *fd;
        rq.file_off = off;
        rq.file_len = len;
        return;
    }
    // With it they are read a piece at a time, so a file larger than memory still goes.
    auto left = std::make_shared<uint64_t>(len);
    auto at = std::make_shared<uint64_t>(off);
    rq.source = [left, at, fd](socketley::storage::http_body_give give)
    {
        if (*left == 0)
        {
            give(true, {});
            return;
        }
        static thread_local std::string piece;
        piece.resize(std::min<uint64_t>(*left, body_piece));
        const ssize_t n = ::pread(*fd, piece.data(), piece.size(), static_cast<off_t>(*at));
        if (n <= 0)
        {
            give(false, {});
            return;
        }
        *at += uint64_t(n);
        *left -= uint64_t(n);
        give(true, std::string_view(piece.data(), size_t(n)));
    };
}

void sync_run::carry(target& t, lane& l, const job& j)
{
    // Opened by the path it resolves to, and only below --dir, so a link changed since it was looked at cannot
    // point the upload anywhere else.
    std::string real;
    if (!inside(std::string(m_rt.get_dir()) + "/" + j.path, &real))
    {
        l.busy = false;
        return;
    }
    const int raw = ::open(real.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW);
    struct stat st{};
    if (raw < 0 || ::fstat(raw, &st) != 0 || !S_ISREG(st.st_mode))
    {
        const int err = raw < 0 ? errno : EINVAL;
        if (raw >= 0)
            ::close(raw);
        l.busy = false;
        // Gone since it was looked at is what a removal is for, and that is queued when it is seen gone.
        if (err != ENOENT)
            note(j.path + ": " + std::strerror(err));
        return;
    }
    // Closed through the loop, which holds it open while a splice the ring has not reported still names it.
    event_loop* loop = &m_loop;
    auto fd = std::shared_ptr<int>(new int(raw), [loop](int* p) { loop->close_fd(*p); delete p; });
    // The file as it is now, not as the walk saw it: one written since is sent whole at its new length, and one
    // the index already holds at this size and time is not sent twice.
    job now = j;
    now.size = uint64_t(st.st_size);
    now.mtime_ns = int64_t(st.st_mtim.tv_sec) * 1000000000 + st.st_mtim.tv_nsec;
    if (const index_entry* had = m_index.find(t.name, j.path);
        had && had->size == now.size && had->mtime_ns == now.mtime_ns)
    {
        l.busy = false;
        return;
    }
    if (now.size > multipart_above)
    {
        begin_upload(t, l, now, fd);
        return;
    }
    http_request rq = signed_request(t, "PUT", now.path, {},
                                     {{"content-length", std::to_string(now.size)},
                                      // The time the file had here, so a job carried back out later knows it.
                                      {"x-amz-meta-mtime", std::to_string(now.mtime_ns)}});
    body_from(t, rq, fd, 0, now.size);
    l.peer->exchange(std::move(rq), [this, &t, &l, now, fd](http_answer a) {
        if (a.status / 100 == 2)
            carried(t, l, now, std::string(a.header("etag")));
        else
            refused(t, l, now, a);
    });
}

void sync_run::begin_upload(target& t, lane& l, const job& j, std::shared_ptr<int> fd)
{
    auto up = std::make_unique<upload>();
    up->j = j;
    up->fd = std::move(fd);
    // S3 takes at most 10,000 parts of at least 5 MiB, the last excepted.
    up->part = std::max<uint64_t>(part_size, (j.size + 9999) / 10000);
    l.mpu = std::move(up);
    http_request rq = signed_request(t, "POST", j.path, "uploads=",
                                     {{"content-length", "0"}, {"x-amz-meta-mtime", std::to_string(j.mtime_ns)}});
    l.peer->exchange(std::move(rq), [this, &t, &l](http_answer a) {
        if (!l.mpu)
            return;
        l.mpu->id = xml_text(a.body, "UploadId");
        if (a.status / 100 != 2 || l.mpu->id.empty())
        {
            const job j = l.mpu->j;
            l.mpu.reset();
            refused(t, l, j, a);
            return;
        }
        send_part(t, l);
    });
}

void sync_run::send_part(target& t, lane& l)
{
    upload& up = *l.mpu;
    // A file that changed under the upload would be assembled from two versions of itself.
    struct stat st{};
    if (::fstat(*up.fd, &st) != 0 || uint64_t(st.st_size) != up.j.size ||
        int64_t(st.st_mtim.tv_sec) * 1000000000 + st.st_mtim.tv_nsec != up.j.mtime_ns)
    {
        abort_upload(t, l, up.j.path + ": changed while it was carried; it is carried again once it is written");
        return;
    }
    const uint64_t n = up.etags.size() + 1;
    const uint64_t off = (n - 1) * up.part;
    const uint64_t len = std::min(up.part, up.j.size - off);
    std::string query = "partNumber=" + std::to_string(n) + "&uploadId=";
    socketley::storage::url_encode_to(query, up.id, false);
    http_request rq = signed_request(t, "PUT", up.j.path, query, {{"content-length", std::to_string(len)}});
    body_from(t, rq, up.fd, off, len);
    l.peer->exchange(std::move(rq), [this, &t, &l](http_answer a) {
        if (!l.mpu)
            return;
        const std::string etag(a.header("etag"));
        if (a.status / 100 != 2 || etag.empty())
        {
            const job j = l.mpu->j;
            abort_upload(t, l, {});
            refused(t, l, j, a);
            return;
        }
        l.mpu->etags.push_back(etag);
        if (l.mpu->etags.size() * l.mpu->part >= l.mpu->j.size)
            complete_upload(t, l);
        else
            send_part(t, l);
    });
}

void sync_run::complete_upload(target& t, lane& l)
{
    upload& up = *l.mpu;
    std::string xml = "<CompleteMultipartUpload>";
    for (size_t i = 0; i < up.etags.size(); ++i)
        xml += "<Part><PartNumber>" + std::to_string(i + 1) + "</PartNumber><ETag>" + up.etags[i] + "</ETag></Part>";
    xml += "</CompleteMultipartUpload>";
    std::string query = "uploadId=";
    socketley::storage::url_encode_to(query, up.id, false);
    // The length taken before the body is moved into the call, whose arguments may be read in any order.
    const std::string length = std::to_string(xml.size());
    http_request rq = signed_request(t, "POST", up.j.path, query,
                                     {{"content-length", length}, {"content-type", "application/xml"}}, std::move(xml));
    l.peer->exchange(std::move(rq), [this, &t, &l](http_answer a) {
        if (!l.mpu)
            return;
        const job j = l.mpu->j;
        // S3 may answer 200 and still say in the body that the upload failed.
        if (a.status / 100 != 2 || a.body.find("<Error>") != std::string::npos)
        {
            abort_upload(t, l, {});
            refused(t, l, j, a);
            return;
        }
        l.mpu.reset();
        carried(t, l, j, xml_text(a.body, "ETag"));
    });
}

void sync_run::abort_upload(target& t, lane& l, const std::string& why)
{
    if (!l.mpu)
        return;
    const std::string id = l.mpu->id;
    const job j = l.mpu->j;
    l.mpu.reset();
    // The parts sent are taken away rather than left to hold space until the storage expires them.
    if (!id.empty() && l.peer && !l.peer->busy())
    {
        std::string query = "uploadId=";
        socketley::storage::url_encode_to(query, id, false);
        l.peer->exchange(signed_request(t, "DELETE", j.path, query, {}), [](http_answer) {});
    }
    if (!why.empty())
    {
        l.busy = false;
        note(why);
        owe_retry();
    }
}

void sync_run::remove(target& t, lane& l, const job& j)
{
    l.peer->exchange(signed_request(t, "DELETE", j.path, {}, {}), [this, &t, &l, j](http_answer a) {
        l.busy = false;
        std::string why;
        // A key the storage no longer has is the state this job wanted anyway.
        if (a.status == 404 || a.status / 100 == 2)
        {
            if (!m_index.gone(t.name, j.path, why))
                note(why);
            m_stats.failing = 0;
            ++m_stats.removed;
            m_stats.indexed = m_index.size();
            return;
        }
        refused(t, l, j, a);
    });
}

void sync_run::carried(target& t, lane& l, const job& j, std::string etag)
{
    l.busy = false;
    index_entry e;
    e.size = j.size;
    e.mtime_ns = j.mtime_ns;
    e.etag = std::move(etag);
    std::string why;
    if (!m_index.carried(t.name, j.path, e, why))
        note(why);
    m_stats.failing = 0;
    ++m_stats.carried;
    m_stats.bytes_carried += j.size;
    m_stats.indexed = m_index.size();
}

void sync_run::refused(target& t, lane& l, const job& j, const http_answer& a)
{
    l.busy = false;
    if (a.status == 0)
    {
        note(t.name + ": " + (a.failure.empty() ? "no answer" : a.failure));
        // Nothing else is tried on a target that is not answering until a walk, owed in retry_secs whatever
        // --every says.
        t.queue.clear();
    }
    else
    {
        // The code S3 put in the body says more than the status: NoSuchBucket, SignatureDoesNotMatch, AccessDenied.
        const std::string code = xml_text(a.body, "Code");
        note(t.name + "/" + j.path + ": the storage answered " + std::to_string(a.status) +
             (code.empty() ? std::string{} : " " + code) + (j.kind == 'd' ? " to a removal" : ""));
    }
    owe_retry();
}

void sync_run::owe_retry()
{
    if (m_retry_at.time_since_epoch().count() == 0)
        m_retry_at = std::chrono::steady_clock::now() + std::chrono::seconds(retry_secs);
}

void sync_run::pump(target& t)
{
    if (m_stopped || t.queue.empty() || !ensure_address(t))
        return;
    for (auto& lp : t.lanes)
    {
        lane& l = *lp;
        while (!m_stopped && !l.busy && !l.peer->busy() && !t.queue.empty())
        {
            // A path already in flight on another lane waits for it, so a removal never overtakes the carrying
            // before it, nor the other way round.
            const std::string& next = t.queue.front().path;
            if (std::any_of(t.lanes.begin(), t.lanes.end(), [&](const auto& o) { return o->busy && o->path == next; }))
                return;
            const job j = t.queue.front();
            t.queue.pop_front();
            // A removal queued twice finds the record already gone, and one for a file made again since finds it
            // here.
            if (j.kind == 'd' && (!m_index.find(t.name, j.path) || !provably_gone(j.path)))
                continue;
            l.busy = true;
            l.path = j.path;
            if (j.kind == 'p')
                carry(t, l, j);
            else
                remove(t, l, j);
        }
    }
}

void sync_run::on_loop_turn()
{
    if (m_stopped)
        return;
    turn();
    uint64_t pending = m_walking || m_rewalk || !m_changed.empty() ? 1 : 0;
    for (const auto& t : m_targets)
        if (!t.queue.empty())
            for (const auto& l : t.lanes)
                if (!l->busy && !l->peer->busy())
                    ++pending;
    arm_tick(pending != 0);
}

void sync_run::turn()
{
    const auto now = std::chrono::steady_clock::now();
    if (now - m_last_tick >= std::chrono::milliseconds(200))
    {
        m_last_tick = now;
        for (auto& t : m_targets)
            for (auto& l : t.lanes)
                l->peer->tick(now);
    }
    if (m_walking && walk_slice())
        end_walk();

    // What inotify named is looked at once no walk is under way, since a walk ahead of it may yet see it too.
    if (!m_walking)
    {
        if (m_rewalk)
        {
            m_changed.clear();
            begin_walk();
        }
        else if (!m_changed.empty())
        {
            for (const auto& rel : m_changed)
                check_path(rel);
            m_changed.clear();
        }
    }

    uint64_t waiting = 0;
    for (auto& t : m_targets)
    {
        pump(t);
        // A target with no address yet keeps nothing queued: the walk owed once it has one finds it all again, and
        // a queue that could not shrink held up every target's walks and grew by a whole walk each time.
        if (t.lanes.empty())
        {
            if (!t.queue.empty())
                owe_retry();
            t.queue.clear();
        }
        waiting += t.queue.size();
    }
    m_stats.waiting = waiting;
    m_stats.last_run_secs =
        m_last_walk.time_since_epoch().count()
            ? uint64_t(std::chrono::duration_cast<std::chrono::seconds>(now - m_last_walk).count())
            : 0;

    if (m_walking || waiting != 0)
        return;
    // A target that stopped answering is tried again by a walk, which finds again what it was owed.
    if (m_retry_at.time_since_epoch().count() && now >= m_retry_at)
    {
        m_retry_at = {};
        begin_walk();
        return;
    }
    // The whole of the directory is walked again when --every says so.
    const uint32_t every = m_rt.get_every();
    if (every && m_last_walk.time_since_epoch().count() && now - m_last_walk >= std::chrono::seconds(every))
        begin_walk();
}

}   // namespace socketley::sync
