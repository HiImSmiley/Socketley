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

#include "../../shared/util/logging.h"
#include "../../shared/util/text_list.h"
#include "../../shared/persist/paths.h"
#include "../../shared/runtime/runtime_manager.h"
#include "../../shared/storage/s3_sigv4.h"
#include "../storage/s3_names.h"
#include "../../shared/http/url.h"

namespace socketley::sync
{

namespace fs = std::filesystem;
using socketley::http_answer;
using socketley::http_peer;
using socketley::http_request;
using socketley::http_target;

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
// A file is brought from the storage in ranges this large, so one that is cut off costs only its last range.
constexpr uint64_t fetch_range_bytes = 8ull << 20;
// How often the storage is listed when --every says nothing.
constexpr int default_pull_secs = 60;
// Where a file brought from the storage is written until it is whole, below --dir so the rename is atomic.
constexpr const char* temp_dir = ".socketley-sync";
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

// Every <name> element of `xml` in order, its text as xml_text would give it.
std::vector<std::string_view> xml_blocks(std::string_view xml, std::string_view name)
{
    const std::string open = "<" + std::string(name) + ">", close = "</" + std::string(name) + ">";
    std::vector<std::string_view> out;
    for (size_t at = 0;;)
    {
        const size_t a = xml.find(open, at);
        if (a == std::string_view::npos)
            return out;
        const size_t b = xml.find(close, a + open.size());
        if (b == std::string_view::npos)
            return out;
        out.push_back(xml.substr(a + open.size(), b - a - open.size()));
        at = b + close.size();
    }
}

// The five entities XML escapes text with, written back as the characters they stand for.
std::string xml_unescape(std::string s)
{
    static constexpr std::pair<std::string_view, char> ents[] = {
        {"&lt;", '<'}, {"&gt;", '>'}, {"&quot;", '"'}, {"&apos;", '\''}, {"&amp;", '&'}};
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size();)
    {
        bool hit = false;
        if (s[i] == '&')
            for (const auto& [e, c] : ents)
                if (std::string_view(s).substr(i, e.size()) == e)
                {
                    out += c;
                    i += e.size();
                    hit = true;
                    break;
                }
        if (!hit)
            out += s[i++];
    }
    return out;
}

// An ETag as its value, without the quotes one side writes and another may not.
std::string_view bare_etag(std::string_view e)
{
    while (!e.empty() && e.front() == '"')
        e.remove_prefix(1);
    while (!e.empty() && e.back() == '"')
        e.remove_suffix(1);
    return e;
}

int64_t mtime_of(const struct stat& st)
{
    return int64_t(st.st_mtim.tv_sec) * 1000000000 + st.st_mtim.tv_nsec;
}

// Every segment of a key encoded as S3 signs it, the separators kept.
std::string encode_key(std::string_view key)
{
    std::string out;
    socketley::http::url_encode_to(out, key, true);
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
            if (!socketley::parse_http_url(spec.url, t.http, why))
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
        if (!socketley::parse_http_url("http://127.0.0.1:" + std::to_string(port), t.http, why))
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

    for (std::string_view ex = m_rt.get_exclude(); !ex.empty();)
    {
        std::string_view one = take_item(ex);
        // `*.tmp, *.md` is how a list is written by hand, and a pattern starting with a space matches nothing.
        while (!one.empty() && (one.front() == ' ' || one.front() == '\t'))
            one.remove_prefix(1);
        while (!one.empty() && (one.back() == ' ' || one.back() == '\t'))
            one.remove_suffix(1);
        if (!one.empty())
            m_exclude.emplace_back(one);
    }

    // What is being brought from the storage is no file of this side's until it is whole.
    if (pulls())
        m_exclude.emplace_back(temp_dir);

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

    // Both ways, the storage is listed first: a file here the index does not know is then told from the storage's
    // copy of it before either is carried over the other.
    if (pulls())
        m_pull_due = true;
    else
        begin_walk();
    if (pushes())
        arm_watch();
    arm_tick(true);
    return true;
}

void sync_run::stop()
{
    m_stopped = true;
    for (auto& t : m_targets)
        for (auto& l : t.lanes)
        {
            l->peer->stop();
            if (l->get)
                fetch_end(t, *l, false);
        }
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
    m_resolver.retire(m_loop);
}

bool sync_run::drained() const
{
    return m_loop.owner_drained(this);
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
    if (m_stopped || m_walking || !pushes())
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
    rq.source = [left, at, fd](socketley::http_body_give give)
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
    std::vector<std::pair<std::string, std::string>> headers = {
        {"content-length", std::to_string(now.size)},
        // The time the file had here, so a job carried back out later knows it.
        {"x-amz-meta-mtime", std::to_string(now.mtime_ns)}};
    if (const auto c = condition(t, now.path); !c.first.empty())
        headers.push_back(c);
    http_request rq = signed_request(t, "PUT", now.path, {}, std::move(headers));
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
    socketley::http::url_encode_to(query, up.id, false);
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
    socketley::http::url_encode_to(query, up.id, false);
    // The length taken before the body is moved into the call, whose arguments may be read in any order.
    const std::string length = std::to_string(xml.size());
    std::vector<std::pair<std::string, std::string>> headers = {{"content-length", length},
                                                                {"content-type", "application/xml"}};
    if (const auto c = condition(t, up.j.path); !c.first.empty())
        headers.push_back(c);
    http_request rq = signed_request(t, "POST", up.j.path, query, std::move(headers), std::move(xml));
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
        socketley::http::url_encode_to(query, id, false);
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
    std::vector<std::pair<std::string, std::string>> headers;
    if (const auto c = condition(t, j.path); c.first == "if-match")
        headers.push_back(c);
    l.peer->exchange(signed_request(t, "DELETE", j.path, {}, std::move(headers)), [this, &t, &l, j](http_answer a) {
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
    // Changed on the storage since this side last saw it: the listing owed now decides, and keeps both if need be.
    if (pulls() && a.status == 412)
    {
        m_pull_due = true;
        return;
    }
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
    uint64_t pending = m_walking || m_rewalk || !m_changed.empty() || !m_fetches.empty() ? 1 : 0;
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

    // What inotify named is looked at once no walk is under way, since a walk ahead of it may yet see it too, and
    // no listing, which what it carried would race.
    if (!m_walking && !m_pulling)
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
        if (m_pulling)
            pump_fetch(t);
        else
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

    if (m_walking || waiting != 0 || m_pulling)
        return;
    // A target that stopped answering is tried again by a walk, which finds again what it was owed, after a listing
    // when the storage's side is carried too.
    if (m_retry_at.time_since_epoch().count() && now >= m_retry_at)
    {
        m_retry_at = {};
        if (pulls())
            m_pull_due = true;
        else
        {
            begin_walk();
            return;
        }
    }
    const uint32_t every = m_rt.get_every();
    if (pulls())
    {
        // The storage is listed when --every says so, and once a minute without it, since nothing tells this side
        // that it changed; the walk follows each listing.
        const auto pull_every = std::chrono::seconds(every ? every : default_pull_secs);
        if ((m_pull_due || now - m_last_pull >= pull_every) && !m_targets.empty() && idle(m_targets.front()))
            begin_pull();
        return;
    }
    // The whole of the directory is walked again when --every says so.
    if (every && m_last_walk.time_since_epoch().count() && now - m_last_walk >= std::chrono::seconds(every))
        begin_walk();
}

// ─── the storage's side ─────────────────────────────────────────────────────

bool sync_run::pushes() const
{
    return m_rt.get_mode() != sync_mode_in;
}

bool sync_run::pulls() const
{
    return m_rt.get_mode() != sync_mode_out;
}

std::pair<std::string, std::string> sync_run::condition(const target& t, const std::string& rel) const
{
    if (!pulls())
        return {};
    const index_entry* had = m_index.find(t.name, rel);
    if (!had)
        return {"if-none-match", "*"};
    if (had->etag.empty())
        return {};
    return {"if-match", "\"" + std::string(bare_etag(had->etag)) + "\""};
}

bool sync_run::idle(const target& t) const
{
    return std::none_of(t.lanes.begin(), t.lanes.end(), [](const auto& l) { return l->busy || l->peer->busy(); });
}

http_request sync_run::signed_bucket_request(const target& t, std::string_view query) const
{
    const std::string path = "/" + t.bucket;
    const std::string date = amz_date_now();
    std::vector<std::pair<std::string, std::string>> headers = {
        {"host", t.http.authority()}, {"x-amz-date", date}, {"x-amz-content-sha256", "UNSIGNED-PAYLOAD"}};
    if (!t.cred.session_token.empty())
        headers.emplace_back("x-amz-security-token", t.cred.session_token);
    std::vector<socketley::s3::header_field> fields;
    for (const auto& [n, v] : headers)
        fields.push_back({n, v});
    socketley::s3::sign_input in;
    in.method       = "GET";
    in.raw_path     = path;
    in.raw_query    = query;
    in.headers      = fields;
    in.payload_hash = "UNSIGNED-PAYLOAD";
    in.access_key   = t.cred.access_key;
    in.secret       = t.cred.secret;
    in.region       = t.cred.region;
    in.amz_date     = date;
    http_request rq;
    rq.head = "GET " + path + "?" + std::string(query) + " HTTP/1.1\r\n";
    for (const auto& [n, v] : headers)
        rq.head += n + ": " + v + "\r\n";
    rq.head += "authorization: " + socketley::s3::sign(in) + "\r\nconnection: keep-alive\r\n";
    rq.head += "user-agent: socketley-sync\r\n\r\n";
    rq.answer_secs = answer_secs;
    return rq;
}

bool sync_run::rel_of_key(std::string_view key, std::string& rel) const
{
    const std::string prefix = key_of({});
    if (!key.starts_with(prefix))
        return false;
    key.remove_prefix(prefix.size());
    if (key.empty() || key.size() > sync_index::max_path || key.back() == '/' || key.front() == '/' ||
        key.find('\0') != std::string_view::npos)
        return false;
    // A key is a name the storage's user chose, so no segment of it may climb out of --dir or name nothing.
    for (size_t p = 0; p <= key.size();)
    {
        const size_t slash = std::min(key.find('/', p), key.size());
        const std::string_view seg = key.substr(p, slash - p);
        if (seg.empty() || seg == "." || seg == "..")
            return false;
        p = slash + 1;
    }
    rel.assign(key);
    return true;
}

std::string sync_run::conflict_name(const std::string& rel) const
{
    const size_t slash = rel.rfind('/');
    const size_t base = slash == std::string::npos ? 0 : slash + 1;
    size_t dot = rel.rfind('.');
    if (dot == std::string::npos || dot <= base)
        dot = rel.size();
    char when[32];
    const std::time_t now = std::time(nullptr);
    std::tm tm{};
    localtime_r(&now, &tm);
    std::strftime(when, sizeof when, "%Y-%m-%d %H%M%S", &tm);
    const std::string dir(m_rt.get_dir());
    for (int n = 1;; ++n)
    {
        const std::string tag = " (conflict " + std::string(when) + (n > 1 ? " " + std::to_string(n) : "") + ")";
        std::string name = rel.substr(0, dot) + tag + rel.substr(dot);
        struct stat st{};
        if (::lstat((dir + "/" + name).c_str(), &st) != 0 || n > 99)
            return name;
    }
}

void sync_run::begin_pull()
{
    if (m_stopped || m_pulling || m_targets.empty())
        return;
    target& t = m_targets.front();
    if (!ensure_address(t))
    {
        owe_retry();
        return;
    }
    sync_credentials cred;
    std::string why;
    if (read_sync_credentials(std::string(m_rt.get_credentials()), cred, why))
        t.cred = cred;
    else
        note(why);
    m_pull_due = false;
    m_pulling = true;
    m_listing = true;
    m_remote.clear();
    m_list_token.clear();
    lane& l = *t.lanes.front();
    l.busy = true;
    l.path.clear();
    list_page(t, l);
}

void sync_run::list_page(target& t, lane& l)
{
    std::string query;
    if (!m_list_token.empty())
    {
        query = "continuation-token=";
        socketley::http::url_encode_to(query, m_list_token, false);
        query += "&";
    }
    query += "list-type=2&prefix=";
    socketley::http::url_encode_to(query, key_of({}), false);
    l.peer->exchange(signed_bucket_request(t, query), [this, &t, &l](http_answer a) {
        if (m_stopped)
            return;
        if (a.status != 200)
        {
            l.busy = false;
            m_pulling = false;
            m_listing = false;
            m_last_pull = std::chrono::steady_clock::now();
            m_remote.clear();
            const std::string code = xml_text(a.body, "Code");
            note(t.name + ": listing the storage " +
                 (a.status ? "was answered " + std::to_string(a.status) + (code.empty() ? "" : " " + code)
                           : std::string("failed: ") + (a.failure.empty() ? "no answer" : a.failure)));
            owe_retry();
            return;
        }
        for (const std::string_view c : xml_blocks(a.body, "Contents"))
        {
            std::string rel;
            if (!rel_of_key(xml_unescape(xml_text(c, "Key")), rel) || excluded(rel))
                continue;
            remote_obj o;
            o.etag = std::string(bare_etag(xml_text(c, "ETag")));
            o.size = std::strtoull(xml_text(c, "Size").c_str(), nullptr, 10);
            m_remote[rel] = std::move(o);
        }
        m_list_token = xml_unescape(xml_text(a.body, "NextContinuationToken"));
        if (xml_text(a.body, "IsTruncated") == "true" && !m_list_token.empty())
        {
            list_page(t, l);
            return;
        }
        l.busy = false;
        m_listing = false;
        decide_pull(t);
    });
}

void sync_run::decide_pull(target& t)
{
    const std::string dir(m_rt.get_dir());
    const bool both = pushes();
    std::string why;
    for (const auto& [rel, r] : m_remote)
    {
        const index_entry* had = m_index.find(t.name, rel);
        struct stat st{};
        const bool here = ::lstat((dir + "/" + rel).c_str(), &st) == 0;
        if (here && !S_ISREG(st.st_mode))
        {
            say(rel + " is no file here, so the storage's is not brought over it");
            continue;
        }
        const bool storage_changed = !had || bare_etag(had->etag) != r.etag;
        const bool here_changed = here && (!had || had->size != uint64_t(st.st_size) || had->mtime_ns != mtime_of(st));
        fetch f;
        f.rel = rel;
        f.key_rel = rel;
        f.etag = r.etag;
        f.size = r.size;
        f.here = here;
        f.here_size = here ? uint64_t(st.st_size) : 0;
        f.here_mtime = here ? mtime_of(st) : 0;
        if (!here)
        {
            // Deleted here since it was last the same: the walk takes it off the storage, unless the storage changed
            // it since, which is the newer word.
            if (had && !storage_changed && both)
                continue;
        }
        else if (!had)
        {
            // Met for the first time on both sides: the same length is taken as the same file, recorded and left;
            // a different one is both kept.
            if (uint64_t(st.st_size) == r.size)
            {
                if (!m_index.carried(t.name, rel, index_entry{uint64_t(st.st_size), mtime_of(st), r.etag}, why))
                    note(why);
                continue;
            }
            f.conflict = true;
        }
        else if (!storage_changed && !here_changed)
            continue;
        else if (!storage_changed)
        {
            // Changed here only: the walk carries it out; one way in, the storage's copy is put back and this side's
            // kept beside it.
            if (both)
                continue;
            f.conflict = true;
        }
        else if (here_changed)
            f.conflict = true;
        if (f.conflict)
            ++m_stats.conflicts;
        m_fetches.push_back(std::move(f));
    }

    // What the index holds and the storage no longer does was removed there, and goes here too unless it changed
    // here since; a listing with nothing in it is taken for a storage that lost its bucket, not for one emptied.
    std::vector<std::string> gone;
    for (const auto& [k, e] : m_index.all())
        if (k.target == t.name && !m_remote.contains(k.path))
            gone.push_back(k.path);
    if (m_remote.empty() && !gone.empty())
    {
        note(t.name + " lists nothing, and " + std::to_string(gone.size()) +
             " files were carried with it: nothing is removed here. If the files were deleted on purpose, delete them "
             "here by hand");
        gone.clear();
    }
    for (const std::string& rel : gone)
    {
        const index_entry* had = m_index.find(t.name, rel);
        // Carried out since the listing was asked for would be in it; a removal still queued for it is not news.
        if (!had)
            continue;
        const std::string full = dir + "/" + rel;
        struct stat st{};
        if (::lstat(full.c_str(), &st) == 0 && S_ISREG(st.st_mode) && uint64_t(st.st_size) == had->size &&
            mtime_of(st) == had->mtime_ns && inside(full, nullptr))
        {
            if (::unlink(full.c_str()) == 0)
                ++m_stats.removed_here;
            else
                note(rel + ": " + std::strerror(errno));
        }
        // One changed here since is this side's now, and the walk carries it out again as a new file.
        if (!m_index.gone(t.name, rel, why))
            note(why);
    }
    m_stats.indexed = m_index.size();
    m_remote.clear();
    if (m_fetches.empty())
        finish_pull(t);
}

void sync_run::pump_fetch(target& t)
{
    if (m_stopped || !m_pulling || m_listing)
        return;
    for (auto& lp : t.lanes)
    {
        lane& l = *lp;
        if (m_fetches.empty())
            break;
        if (l.busy || l.peer->busy())
            continue;
        l.get = std::make_unique<fetch>(std::move(m_fetches.front()));
        m_fetches.pop_front();
        l.busy = true;
        l.path = l.get->rel;
        const std::string dir = std::string(m_rt.get_dir()) + "/" + temp_dir;
        if (::mkdir(dir.c_str(), 0700) < 0 && errno != EEXIST)
        {
            note(dir + ": " + std::strerror(errno));
            fetch_end(t, l, false);
            continue;
        }
        char name[] = "/fetch-XXXXXX";
        std::string temp = dir + name;
        l.get->fd = ::mkostemp(temp.data(), O_CLOEXEC);
        if (l.get->fd < 0)
        {
            note(temp + ": " + std::strerror(errno));
            fetch_end(t, l, false);
            continue;
        }
        l.get->temp = std::move(temp);
        if (l.get->size == 0)
            fetch_end(t, l, true);
        else
            fetch_range(t, l);
    }
    // Every fetch is over once no lane holds one and none waits.
    if (m_fetches.empty() && std::none_of(t.lanes.begin(), t.lanes.end(), [](const auto& l) { return l->get != nullptr; }))
        finish_pull(t);
}

void sync_run::fetch_range(target& t, lane& l)
{
    fetch& f = *l.get;
    const uint64_t last = std::min(f.size, f.got + fetch_range_bytes) - 1;
    http_request rq = signed_request(t, "GET", f.key_rel, {},
                                     {{"range", "bytes=" + std::to_string(f.got) + "-" + std::to_string(last)},
                                      // A file the storage changed during the fetch is not put together from two.
                                      {"if-match", "\"" + f.etag + "\""}});
    l.peer->exchange(std::move(rq), [this, &t, &l](http_answer a) {
        if (m_stopped || !l.get)
            return;
        fetch& f = *l.get;
        if (a.status == 412 || a.status == 404)
        {
            // Changed or removed on the storage since it was listed: the next listing sees what it is now.
            fetch_end(t, l, false);
            return;
        }
        if ((a.status != 206 && a.status != 200) || a.body.empty() || f.got + a.body.size() > f.size)
        {
            const std::string code = xml_text(a.body, "Code");
            note(t.name + "/" + f.key_rel + ": bringing it " +
                 (a.status ? "was answered " + std::to_string(a.status) + (code.empty() ? "" : " " + code)
                           : std::string("failed: ") + (a.failure.empty() ? "no answer" : a.failure)));
            fetch_end(t, l, false);
            owe_retry();
            return;
        }
        // A whole object for a range is the storage ignoring it, which is the same bytes from the start.
        if (a.status == 200 && f.got != 0)
        {
            fetch_end(t, l, false);
            return;
        }
        for (size_t off = 0; off < a.body.size();)
        {
            const ssize_t n = ::pwrite(f.fd, a.body.data() + off, a.body.size() - off, off_t(f.got + off));
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0)
            {
                note(f.rel + ": writing it here failed: " + std::strerror(n < 0 ? errno : ENOSPC));
                fetch_end(t, l, false);
                return;
            }
            off += size_t(n);
        }
        f.got += a.body.size();
        if (f.got < f.size)
            fetch_range(t, l);
        else
            fetch_end(t, l, true);
    });
}

void sync_run::fetch_end(target& t, lane& l, bool whole)
{
    std::unique_ptr<fetch> f = std::move(l.get);
    l.busy = false;
    if (!f)
        return;
    const std::string dir(m_rt.get_dir());
    bool placed = false;
    if (whole && f->fd >= 0 && ::fsync(f->fd) == 0)
    {
        const std::string full = dir + "/" + f->rel;
        struct stat st{};
        const bool here = ::lstat(full.c_str(), &st) == 0;
        // This side's file as the decision saw it, or the storage's copy is kept beside whatever it became.
        if (!f->conflict && (here != f->here || (here && (uint64_t(st.st_size) != f->here_size || mtime_of(st) != f->here_mtime))))
        {
            f->conflict = true;
            ++m_stats.conflicts;
        }
        // Both ways, the storage's copy goes beside this side's, which the walk then carries out; one way in, the
        // storage's goes at the name and this side's beside it, so the next listing does not find the conflict again.
        std::string name = f->rel;
        bool ok = true;
        if (f->conflict && pushes())
            name = conflict_name(f->rel);
        else if (f->conflict && here && ::rename(full.c_str(), (dir + "/" + conflict_name(f->rel)).c_str()) != 0)
            ok = false;
        const std::string target_path = dir + "/" + name;
        const std::string parent = target_path.substr(0, target_path.rfind('/'));
        // The folders on the way are made here, below the deepest one there is, and only when that is no link out
        // of --dir.
        std::string have = parent;
        struct stat pst{};
        while (have.size() > dir.size() && ::lstat(have.c_str(), &pst) != 0)
            have.resize(have.rfind('/'));
        std::error_code ec;
        if (ok && inside(have, nullptr))
            fs::create_directories(parent, ec);
        else
            ok = false;
        if (ok && !ec && inside(parent, nullptr) && ::rename(f->temp.c_str(), target_path.c_str()) == 0)
        {
            placed = true;
            ++m_stats.brought;
            m_stats.bytes_carried += f->size;
            std::string why;
            // The name as the storage has it is now the same on both sides; a conflict copy is new to both, and the
            // walk carries it out, as it does this side's file over the storage's, which it now knows the etag of.
            if (name == f->rel && ::lstat(target_path.c_str(), &st) == 0 &&
                !m_index.carried(t.name, f->rel, index_entry{uint64_t(st.st_size), mtime_of(st), f->etag}, why))
                note(why);
            if (name != f->rel && !m_index.carried(t.name, f->rel, index_entry{0, -1, f->etag}, why))
                note(why);
            m_stats.failing = 0;
        }
        else
            note(name + ": it could not be put in place: " + (ec ? ec.message() : std::string(std::strerror(errno))));
    }
    if (f->fd >= 0)
        ::close(f->fd);
    if (!placed && !f->temp.empty())
        ::unlink(f->temp.c_str());
}

void sync_run::finish_pull(target&)
{
    if (!m_pulling)
        return;
    m_pulling = false;
    m_last_pull = std::chrono::steady_clock::now();
    m_stats.indexed = m_index.size();
    std::string why;
    if (!m_index.compact(why))
        note(why);
    m_index.flush();
    ::rmdir((std::string(m_rt.get_dir()) + "/" + temp_dir).c_str());
    if (pushes())
        begin_walk();
    else
        m_last_walk = m_last_pull;
}

}   // namespace socketley::sync
