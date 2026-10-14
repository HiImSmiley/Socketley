#include "scrubber.h"

#include <algorithm>
#include <cstdlib>

#include <fcntl.h>
#include <unistd.h>

#include "body_reader.h"
#include "digest.h"
#include "../../shared/logging.h"

namespace socketley::storage
{

namespace
{

std::string to_hex(std::string_view s)
{
    return s.empty() ? std::string("-") : hex(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

std::string from_hex(std::string_view h)
{
    std::string out;
    if (h == "-" || h.size() % 2)
        return out;
    const auto digit = [](char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1; };
    for (size_t i = 0; i < h.size(); i += 2)
    {
        const int a = digit(h[i]), b = digit(h[i + 1]);
        if (a < 0 || b < 0)
            return {};
        out.push_back(static_cast<char>(a << 4 | b));
    }
    return out;
}

}   // namespace

struct scrubber::job
{
    std::string bucket, key, version_id;
    int         fd{-1};
    size_t      data_off{0};
    object_meta meta;
    std::optional<sse_key> key_bytes;
    // The size of each part, one for an object that is not multipart, and where the read is.
    std::vector<uint64_t> parts;
    size_t      part{0};
    uint64_t    left_in_part{0};
    std::unique_ptr<md5_stream> md5{std::make_unique<md5_stream>()};
    std::string part_md5s;
    std::shared_ptr<body_reader> reader;
};

scrubber::scrubber(event_loop& loop, file_io& io, object_store& store, hash_pool& hashes, key_opener keys,
                   std::function<void(finding)> corrupt)
    : m_loop(loop), m_io(io), m_store(store), m_hashes(hashes), m_keys(std::move(keys)), m_corrupt(std::move(corrupt))
{
}

scrubber::~scrubber()
{
    *m_alive = false;
    // A read the ring never answers keeps the job and its reader holding each other, so the reader is let go here.
    if (auto j = m_job.lock())
        j->reader.reset();
}

void scrubber::open(const std::string& dir, uint32_t shard)
{
    m_path = dir + "/.scrub." + std::to_string(shard);
    const int fd = ::open(m_path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return;
    char buf[8192];
    const ssize_t n = ::read(fd, buf, sizeof buf);
    ::close(fd);
    std::string_view text(buf, n > 0 ? static_cast<size_t>(n) : 0);
    while (!text.empty())
    {
        const size_t nl = text.find('\n');
        const std::string_view line = text.substr(0, nl);
        text = nl == std::string_view::npos ? std::string_view{} : text.substr(nl + 1);
        const size_t sp = line.find(' ');
        if (sp == std::string_view::npos)
            continue;
        const std::string_view name = line.substr(0, sp), value = line.substr(sp + 1);
        if (name == "began")
            m_pass_began = std::atoll(std::string(value).c_str());
        else if (name == "passes")
            m_c.passes = std::strtoull(std::string(value).c_str(), nullptr, 10);
        else if (name == "bucket")
            m_bucket = from_hex(value);
        else if (name == "key")
            m_key = from_hex(value);
    }
}

void scrubber::save() const
{
    if (m_path.empty())
        return;
    const std::string text = "began " + std::to_string(m_pass_began) + "\npasses " + std::to_string(m_c.passes) +
                             "\nbucket " + to_hex(m_bucket) + "\nkey " + to_hex(m_key) + "\n";
    // Unsynced: a crash that takes the note reads a few keys again.
    const std::string tmp = m_path + ".tmp";
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return;
    const bool whole = ::write(fd, text.data(), text.size()) == static_cast<ssize_t>(text.size());
    ::close(fd);
    if (whole && ::rename(tmp.c_str(), m_path.c_str()) < 0) {}
}

void scrubber::tick()
{
    if (!enabled() || m_stopped)
        return;
    const int64_t now = static_cast<int64_t>(m_store.now_ms());
    // A pass begins once the period since the last one began is over, and the first at once.
    if (m_pass_began == 0)
        m_pass_began = now;
    const uint64_t total = m_store.totals().bytes;
    const uint64_t rate  = std::max<uint64_t>(total / std::max<uint64_t>(m_period_ms / 1000, 1), min_rate);
    m_budget = std::min<int64_t>(m_budget + static_cast<int64_t>(rate), static_cast<int64_t>(rate));
    if (now - m_saved_ms >= 30000)
    {
        m_saved_ms = now;
        save();
    }
    if (!m_busy)
        next();
}

void scrubber::next()
{
    if (m_stopped || m_budget <= 0)
        return;
    const int64_t now = static_cast<int64_t>(m_store.now_ms());
    if (now < m_pass_began)
        return;
    auto all = m_store.buckets();
    std::sort(all.begin(), all.end(), [](const bucket_info& a, const bucket_info& b) { return a.name < b.name; });
    // Keys whose versions are all delete markers are passed in this loop, which ends at a version to read.
    for (;;)
    {
        if (!m_versions.empty())
        {
            std::string id = std::move(m_versions.front());
            m_versions.pop_front();
            check(std::move(id));
            return;
        }
        // The key just read is done, and the next one is taken with every version it has.
        if (!m_current_key.empty())
        {
            m_bucket = m_current_bucket;
            m_key    = m_current_key;
            m_current_key.clear();
        }
        for (const bucket_info& b : all)
        {
            if (b.name < m_bucket)
                continue;
            const std::string after = b.name == m_bucket ? m_key : std::string();
            const bool plain = m_store.bucket_versioning(b.name) == versioning::off;
            m_store.keys_after(b.name, after, 1,
                               [&](const std::string& key, const std::vector<const object_meta*>& versions)
            {
                m_current_bucket = b.name;
                m_current_key    = key;
                for (const object_meta* m : versions)
                    if (!is_delete_marker(*m))
                        m_versions.push_back(plain || !has_version(*m) ? std::string() : version_of(*m).id);
            });
            if (!m_current_key.empty())
                break;
        }
        if (!m_current_key.empty())
            continue;
        // Every key was read: the pass is over, and the next begins a period after this one did.
        ++m_c.passes;
        m_c.last_pass_ms = static_cast<uint64_t>(std::max<int64_t>(now - m_pass_began, 0));
        m_pass_began = std::max(m_pass_began + static_cast<int64_t>(m_period_ms), now);
        m_bucket.clear();
        m_key.clear();
        save();
        return;
    }
}

void scrubber::check(std::string version_id)
{
    auto j        = std::make_shared<job>();
    m_job         = j;
    j->bucket     = m_current_bucket;
    j->key        = m_current_key;
    j->version_id = std::move(version_id);
    m_busy        = true;
    auto alive    = m_alive;
    auto then     = [this, alive, j, loop = &m_loop](open_result o)
    {
        // The loop and not this scrubber, which may be gone.
        if (!*alive)
        {
            if (o.fd >= 0)
                loop->close_fd(o.fd);
            return;
        }
        opened(j, std::move(o));
    };
    if (j->version_id.empty())
        m_store.open_object(j->bucket, j->key, 0, std::move(then));
    else
        m_store.open_version(j->bucket, j->key, j->version_id, 0, std::move(then));
}

void scrubber::opened(const std::shared_ptr<job>& j, open_result o)
{
    if (o.status != st::ok || o.delete_marker)
    {
        if (o.fd >= 0)
            m_loop.close_fd(o.fd);
        done(j, false, false);
        return;
    }
    j->fd       = o.fd;
    j->data_off = o.data_off;
    j->meta     = std::move(o.meta);
    if (is_encrypted(j->meta))
    {
        sse_key k{};
        if (sse_mode_of(j->meta) == sse_mode::c || !m_keys || !m_keys(j->meta, k))
        {
            done(j, false, true);
            return;
        }
        j->key_bytes = k;
    }
    if (j->meta.parts == 0)
        j->parts.push_back(j->meta.size);
    else if (part_list pl; part_list_of(j->meta, pl) && pl.sizes.size() == j->meta.parts)
        j->parts = std::move(pl.sizes);
    else
    {
        done(j, false, true);
        return;
    }
    j->left_in_part = j->parts.front();
    j->reader = body_reader::make(m_io, &m_hashes, m_store.alive_token(), j->fd, j->data_off, j->meta,
                                  j->key_bytes ? &*j->key_bytes : nullptr, 0, j->meta.size);
    if (!j->reader)
    {
        done(j, false, true);
        return;
    }
    read(j);
}

void scrubber::read(const std::shared_ptr<job>& j)
{
    auto alive = m_alive;
    j->reader->next([this, alive, j, loop = &m_loop](bool ok, std::string_view plain)
    {
        // The job's file goes with a scrubber that is gone, as the open's does.
        if (!*alive)
        {
            if (j->fd >= 0)
                loop->close_fd(j->fd);
            j->fd = -1;
            return;
        }
        // A body that cannot be read whole is as corrupt as one whose bytes differ.
        if (!ok)
        {
            done(j, true, false);
            return;
        }
        if (plain.empty())
        {
            done(j, !whole(*j), false);
            return;
        }
        while (!plain.empty())
        {
            next_part(*j);
            const size_t n = static_cast<size_t>(std::min<uint64_t>(plain.size(), j->left_in_part));
            if (n == 0)
            {
                done(j, true, false);
                return;
            }
            j->md5->update(plain.data(), n);
            j->left_in_part -= n;
            plain.remove_prefix(n);
            m_c.bytes += n;
        }
        read(j);
    });
}

void scrubber::next_part(job& j)
{
    // A part read to its end gives its MD5, and a part of no bytes is a part too.
    while (j.left_in_part == 0 && j.part + 1 < j.parts.size())
    {
        const md5_t d = j.md5->finish();
        j.part_md5s.append(reinterpret_cast<const char*>(d.data()), d.size());
        j.md5 = std::make_unique<md5_stream>();
        j.left_in_part = j.parts[++j.part];
    }
}

bool scrubber::whole(job& j)
{
    next_part(j);
    if (j.left_in_part != 0 || j.part + 1 != j.parts.size())
        return false;
    const md5_t last = j.md5->finish();
    if (j.parts.size() == 1 && j.meta.parts == 0)
        return last == j.meta.md5;
    j.part_md5s.append(reinterpret_cast<const char*>(last.data()), last.size());
    return md5_of(j.part_md5s) == j.meta.md5;
}

void scrubber::done(const std::shared_ptr<job>& j, bool corrupt, bool skipped)
{
    if (j->fd >= 0)
    {
        m_loop.close_fd(j->fd);
        j->fd = -1;
    }
    m_busy = false;
    ++m_c.objects;
    m_budget -= static_cast<int64_t>(j->meta.size);
    if (skipped)
        ++m_c.skipped;
    // A copy found whole again, as one another node sent is, is told anew when it goes bad again.
    if (corrupt || (!skipped && !m_told.empty()))
    {
        std::string told = j->bucket + '\0' + j->key + '\0' + j->version_id + '\0' + std::to_string(j->meta.mtime_ms);
        if (!corrupt)
            m_told.erase(told);
        else if (m_told.insert(std::move(told)).second)
        {
            ++m_c.corrupt;
            m_corrupt({j->bucket, j->key, j->version_id, j->meta});
        }
    }
    if (!m_stopped)
        next();
}

void scrubber::stop()
{
    m_stopped = true;
    save();
}

}   // namespace socketley::storage
