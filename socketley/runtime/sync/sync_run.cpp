#include "sync_run.h"
#include "sync_instance.h"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <fnmatch.h>
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

std::string amz_date_now()
{
    char buf[32];
    const std::time_t t = std::time(nullptr);
    std::tm tm{};
    gmtime_r(&t, &tm);
    std::strftime(buf, sizeof buf, "%Y%m%dT%H%M%SZ", &tm);
    return buf;
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
    for (ssize_t n; (n = ::read(fd, buf, sizeof buf)) > 0;)
        text.append(buf, static_cast<size_t>(n));
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
        target t;
        t.name = one;
        t.cred = cred;
        const size_t slash = one.rfind('/');
        t.bucket = one.substr(slash + 1);
        t.where = one.substr(0, slash);
        // A bare name is a runtime of this daemon, whose port the daemon's map says once it has arrived; anything
        // with a scheme or a port is an address and is parsed now, so a bad one is refused before the job starts.
        if (t.where.find("://") != std::string::npos || t.where.find(':') != std::string::npos)
        {
            const std::string url =
                t.where.find("://") == std::string::npos ? "http://" + t.where : t.where;
            if (!socketley::storage::parse_http_url(url, t.http, why))
                return false;
            t.addressed = true;
        }
        m_targets.push_back(std::move(t));
    }
    return !m_targets.empty();
}

bool sync_run::ensure_address(target& t)
{
    if (t.peer)
        return true;
    if (!t.addressed)
    {
        runtime_manager* mgr = m_rt.get_runtime_manager();
        if (!mgr)
            return false;
        uint16_t port = 0;
        {
            std::shared_lock lock(mgr->mutex);
            // The port the map carries, not effective_port(): a replica of another runtime is a generic object that
            // does not know its type's default, so asking for the effective one answers zero for every one of them.
            if (const runtime_instance* rt = mgr->get(t.where))
                port = rt->get_port();
        }
        if (!port)
        {
            // The map has not come down yet, or the runtime is not there; the next turn asks again.
            if (!t.told)
            {
                note(t.where + ": no runtime of that name is listening here yet");
                t.told = true;
            }
            return false;
        }
        std::string why;
        if (!socketley::storage::parse_http_url("http://127.0.0.1:" + std::to_string(port), t.http, why))
            return false;
        t.told = false;
    }
    t.peer = std::make_unique<http_peer>(m_loop, m_io, m_resolver, t.http, std::string{},
                                         "sync " + std::string(m_rt.get_name()) + " -> " + t.name);
    t.peer->prime();
    return true;
}

bool sync_run::start(std::string& why)
{
    const auto paths = socketley_paths::resolve();
    const fs::path dir = paths.state_dir / "sync";
    std::error_code ec;
    fs::create_directories(dir, ec);
    if (ec)
    {
        why = dir.string() + ": " + ec.message();
        return false;
    }
    if (!m_index.open((dir / (std::string(m_rt.get_name()) + ".index")).string(), why))
        return false;
    if (!resolve_targets(why))
        return false;

    const std::string_view ex = m_rt.get_exclude();
    for (size_t p = 0; p <= ex.size();)
    {
        const size_t comma = std::min(ex.find(',', p), ex.size());
        std::string one(ex.substr(p, comma - p));
        if (!one.empty())
            m_exclude.push_back(std::move(one));
        p = comma + 1;
    }

    m_stats.indexed = m_index.size();
    for (auto& t : m_targets)
        ensure_address(t);
    begin_walk();
    return true;
}

void sync_run::stop()
{
    m_stopped = true;
    for (auto& t : m_targets)
        if (t.peer)
            t.peer->stop();
    m_iter.reset();
    m_walking = false;
}

void sync_run::on_cqe(struct io_uring_cqe* cqe)
{
    m_io.on_cqe(cqe);
}

size_t sync_run::open_connections() const
{
    size_t n = 0;
    for (const auto& t : m_targets)
        if (t.peer && t.peer->busy())
            ++n;
    return n;
}

bool sync_run::excluded(const std::string& rel) const
{
    for (const auto& pat : m_exclude)
        if (::fnmatch(pat.c_str(), rel.c_str(), 0) == 0)
            return true;
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

void sync_run::note(const std::string& what)
{
    m_stats.last_error = what;
    ++m_stats.failures;
}

void sync_run::begin_walk()
{
    if (m_stopped || m_walking)
        return;
    std::error_code ec;
    m_iter = std::make_unique<fs::recursive_directory_iterator>(
        fs::path(m_rt.get_dir()), fs::directory_options::skip_permission_denied, ec);
    if (ec)
    {
        note(std::string(m_rt.get_dir()) + ": " + ec.message());
        m_iter.reset();
        m_last_walk = std::chrono::steady_clock::now();
        return;
    }
    m_seen.clear();
    m_walking = true;
    m_walk_started = std::chrono::steady_clock::now();
}

bool sync_run::walk_slice()
{
    const fs::recursive_directory_iterator end;
    const std::string root(m_rt.get_dir());
    for (int n = 0; n < walk_slice_entries; ++n)
    {
        if (!m_iter || *m_iter == end)
            return true;
        std::error_code ec;
        const fs::directory_entry& de = **m_iter;
        const bool is_file = de.is_regular_file(ec) && !ec;
        if (is_file)
        {
            std::string rel = de.path().string();
            // The path below --dir, which is what the index keys by and what the key is built from.
            if (rel.size() > root.size() + 1 && rel.compare(0, root.size(), root) == 0)
                rel = rel.substr(root.size() + 1);
            if (!excluded(rel))
            {
                struct stat st{};
                if (::stat(de.path().c_str(), &st) == 0)
                {
                    m_seen.push_back(rel);
                    const int64_t mtime = int64_t(st.st_mtim.tv_sec) * 1000000000 + st.st_mtim.tv_nsec;
                    for (auto& t : m_targets)
                    {
                        const index_entry* had = m_index.find(t.name, rel);
                        // Size and time are what a local file is told to have changed by; the etag says the same of
                        // the far side and is compared when `in` is carried.
                        if (had && had->size == uint64_t(st.st_size) && had->mtime_ns == mtime)
                            continue;
                        t.queue.push_back(job{'p', rel, uint64_t(st.st_size), mtime});
                    }
                }
            }
        }
        m_iter->increment(ec);
        if (ec)
        {
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
    // What the index holds and the walk did not see is gone from this side, so it is taken off the far side too.
    std::sort(m_seen.begin(), m_seen.end());
    for (const auto& [k, e] : m_index.all())
    {
        (void)e;
        if (std::binary_search(m_seen.begin(), m_seen.end(), k.path))
            continue;
        for (auto& t : m_targets)
            if (t.name == k.target)
                t.queue.push_back(job{'d', k.path, 0, 0});
    }
    std::string why;
    if (!m_index.compact(why))
        note(why);
}

void sync_run::carry(target& t, const job& j)
{
    const std::string path = std::string(m_rt.get_dir()) + "/" + j.path;
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
    {
        // It went away between the walk and now; the next walk will take it off the far side.
        note(j.path + ": " + std::strerror(errno));
        t.in_flight = false;
        return;
    }
    const std::string key = "/" + t.bucket + "/" + encode_key(key_of(j.path));
    std::vector<std::pair<std::string, std::string>> headers;
    const std::string date = amz_date_now();
    headers.emplace_back("host", t.http.authority());
    headers.emplace_back("x-amz-date", date);
    headers.emplace_back("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
    headers.emplace_back("content-length", std::to_string(j.size));
    // The time the file had here, so a job carried back out later knows what it was.
    headers.emplace_back("x-amz-meta-mtime", std::to_string(j.mtime_ns));
    if (!t.cred.session_token.empty())
        headers.emplace_back("x-amz-security-token", t.cred.session_token);

    std::vector<socketley::s3::header_field> fields;
    fields.reserve(headers.size());
    for (const auto& [n, v] : headers)
        fields.push_back({n, v});
    socketley::s3::sign_input in;
    in.method       = "PUT";
    in.raw_path     = key;
    in.headers      = fields;
    in.payload_hash = "UNSIGNED-PAYLOAD";
    in.access_key   = t.cred.access_key;
    in.secret       = t.cred.secret;
    in.region       = t.cred.region;
    in.amz_date     = date;

    http_request rq;
    rq.head = "PUT " + key + " HTTP/1.1\r\n";
    for (const auto& [n, v] : headers)
        rq.head += n + ": " + v + "\r\n";
    rq.head += "authorization: " + socketley::s3::sign(in) + "\r\nconnection: keep-alive\r\n";
    rq.head += "user-agent: socketley-sync\r\n\r\n";
    rq.answer_secs = answer_secs;

    // The body is read a piece at a time rather than held whole, so a file larger than memory still goes.
    auto left = std::make_shared<uint64_t>(j.size);
    auto off  = std::make_shared<uint64_t>(0);
    auto held = std::shared_ptr<int>(new int(fd), [](int* p) { if (*p >= 0) ::close(*p); delete p; });
    rq.source = [left, off, held](socketley::storage::http_body_give give)
    {
        if (*left == 0)
        {
            give(true, {});
            return;
        }
        static thread_local std::string piece;
        piece.assign(std::min<uint64_t>(*left, body_piece), '\0');
        const ssize_t n = ::pread(*held, piece.data(), piece.size(), static_cast<off_t>(*off));
        if (n <= 0)
        {
            give(false, {});
            return;
        }
        *off += uint64_t(n);
        *left -= uint64_t(n);
        give(true, std::string_view(piece.data(), size_t(n)));
    };

    const job copy = j;
    t.peer->exchange(std::move(rq), [this, &t, copy](http_answer a) { finished(t, copy, a); });
}

void sync_run::remove(target& t, const job& j)
{
    const std::string key = "/" + t.bucket + "/" + encode_key(key_of(j.path));
    std::vector<std::pair<std::string, std::string>> headers;
    const std::string date = amz_date_now();
    headers.emplace_back("host", t.http.authority());
    headers.emplace_back("x-amz-date", date);
    headers.emplace_back("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
    if (!t.cred.session_token.empty())
        headers.emplace_back("x-amz-security-token", t.cred.session_token);

    std::vector<socketley::s3::header_field> fields;
    fields.reserve(headers.size());
    for (const auto& [n, v] : headers)
        fields.push_back({n, v});
    socketley::s3::sign_input in;
    in.method       = "DELETE";
    in.raw_path     = key;
    in.headers      = fields;
    in.payload_hash = "UNSIGNED-PAYLOAD";
    in.access_key   = t.cred.access_key;
    in.secret       = t.cred.secret;
    in.region       = t.cred.region;
    in.amz_date     = date;

    http_request rq;
    rq.head = "DELETE " + key + " HTTP/1.1\r\n";
    for (const auto& [n, v] : headers)
        rq.head += n + ": " + v + "\r\n";
    rq.head += "authorization: " + socketley::s3::sign(in) + "\r\nconnection: keep-alive\r\n";
    rq.head += "user-agent: socketley-sync\r\n\r\n";
    rq.answer_secs = answer_secs;

    const job copy = j;
    t.peer->exchange(std::move(rq), [this, &t, copy](http_answer a) { finished(t, copy, a); });
}

void sync_run::finished(target& t, const job& j, const http_answer& a)
{
    t.in_flight = false;
    std::string why;
    if (a.status == 0)
    {
        if (!t.told)
        {
            LOG_WARN(("sync: " + t.name + ": " + (a.failure.empty() ? "no answer" : a.failure)).c_str());
            t.told = true;
        }
        note(t.name + ": " + (a.failure.empty() ? "no answer" : a.failure));
        // Nothing else is tried on a target that is not answering until the next walk.
        t.queue.clear();
        return;
    }
    t.told = false;
    if (j.kind == 'p')
    {
        if (a.status / 100 != 2)
        {
            note(t.name + "/" + j.path + ": the storage answered " + std::to_string(a.status));
            return;
        }
        index_entry e;
        e.size = j.size;
        e.mtime_ns = j.mtime_ns;
        e.etag.assign(a.header("etag"));
        if (!m_index.carried(t.name, j.path, e, why))
            note(why);
        ++m_stats.carried;
        m_stats.bytes_carried += j.size;
    }
    else
    {
        // A key the storage no longer has is the state this job wanted anyway.
        if (a.status / 100 != 2 && a.status != 404)
        {
            note(t.name + "/" + j.path + ": the storage answered " + std::to_string(a.status) + " to a removal");
            return;
        }
        if (!m_index.gone(t.name, j.path, why))
            note(why);
        ++m_stats.removed;
    }
    m_stats.indexed = m_index.size();
}

void sync_run::pump(target& t)
{
    if (m_stopped || t.in_flight || t.queue.empty())
        return;
    if (!ensure_address(t) || t.peer->busy())
        return;
    const job j = t.queue.front();
    t.queue.pop_front();
    t.in_flight = true;
    if (j.kind == 'p')
        carry(t, j);
    else
        remove(t, j);
}

void sync_run::on_loop_turn()
{
    if (m_stopped)
        return;
    const auto now = std::chrono::steady_clock::now();
    if (now - m_last_tick >= std::chrono::milliseconds(200))
    {
        m_last_tick = now;
        for (auto& t : m_targets)
            if (t.peer)
                t.peer->tick(now);
    }
    if (m_walking && walk_slice())
        end_walk();

    uint64_t waiting = 0;
    for (auto& t : m_targets)
    {
        pump(t);
        waiting += t.queue.size();
    }
    m_stats.waiting = waiting;
    m_stats.last_run_secs =
        m_last_walk.time_since_epoch().count()
            ? uint64_t(std::chrono::duration_cast<std::chrono::seconds>(now - m_last_walk).count())
            : 0;

    // The whole of the directory is walked again when --every says so, and never while one walk is still going.
    const uint32_t every = m_rt.get_every();
    if (!m_walking && waiting == 0 && every && m_last_walk.time_since_epoch().count() &&
        now - m_last_walk >= std::chrono::seconds(every))
        begin_walk();
}

}   // namespace socketley::sync
