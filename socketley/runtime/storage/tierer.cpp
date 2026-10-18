#include "tierer.h"

#include <algorithm>
#include <cstdlib>

#include <fcntl.h>
#include <unistd.h>

#include "s3_names.h"
#include "s3_xml_tree.h"
#include "../../shared/util/logging.h"
#include "../../shared/util/base64.h"
#include "../../shared/util/settings.h"

namespace socketley::storage
{

namespace
{

// A listing's page, and the pause between two of them.
constexpr int sweep_page_keys = 1000;

std::string remote_key_of(const std::string& prefix, const std::string& bucket, const std::string& key,
                          const std::string& version_id, const object_meta& m)
{
    return prefix + bucket + "/" + std::to_string(m.mtime_ms) + "-" + hex(m.md5) + "-" +
           (version_id.empty() ? std::string("_") : version_id) + "/" + key;
}

// The bucket, key, time, MD5 and version id a remote key names, false for one no move made.
bool parse_remote_key(std::string_view rk, std::string& bucket, std::string& key, int64_t& mtime, std::string& md5,
                      std::string& version_id)
{
    const size_t s1 = rk.find('/');
    if (s1 == std::string_view::npos || s1 == 0)
        return false;
    bucket = std::string(rk.substr(0, s1));
    rk.remove_prefix(s1 + 1);
    const size_t s2 = rk.find('/');
    if (s2 == std::string_view::npos)
        return false;
    const std::string_view stamp = rk.substr(0, s2);
    key = std::string(rk.substr(s2 + 1));
    const size_t d1 = stamp.find('-');
    if (d1 == std::string_view::npos || stamp.size() < d1 + 1 + 32 + 2 || stamp[d1 + 33] != '-' || key.empty())
        return false;
    mtime = std::atoll(std::string(stamp.substr(0, d1)).c_str());
    md5   = std::string(stamp.substr(d1 + 1, 32));
    version_id = std::string(stamp.substr(d1 + 34));
    if (version_id == "_")
        version_id.clear();
    return true;
}

bool same_bytes(const object_meta& m, int64_t mtime, const std::string& md5)
{
    return m.mtime_ms == mtime && hex(m.md5) == md5;
}

}   // namespace

struct tierer::job
{
    std::string bucket, key, version_id, tier;
    object_meta was;
    object_meta now;
    std::string remote_key;
    int         fd{-1};
    uint64_t    data_off{0};
    int         tmp_fd{-1};
    std::string tmp;
    std::shared_ptr<std::string> head;
    bool        source_failed{false};
};

struct tierer::sweep
{
    size_t      tier{0};
    std::string token;
    bool        listing{false};
    // The removals a page found, made one at a time at the tier the page is of.
    std::deque<std::string> doomed;
    size_t      doomed_tier{0};
    bool        removing{false};
};

tierer::tierer(event_loop& loop, file_io& io, object_store& store, hash_pool& hashes)
    : m_loop(loop), m_io(io), m_store(store), m_hashes(hashes)
{
    if (const char* e = settings::text("SOCKETLEY_STORAGE_REPLICATION_HOSTS"))
        m_hosts_file = e;
}

tierer::~tierer()
{
    *m_alive = false;
    for (auto& t : m_tiers)
        for (auto& p : t->peers)
            p->stop();
    m_resolver.retire(m_loop);
}

void tierer::set_tiers(std::vector<replication_target> tiers)
{
    m_tiers.clear();
    bool names = false;
    for (const replication_target& t : tiers)
    {
        http_endpoint e;
        names = names || !literal_endpoint(t.http.host, t.http.port, e);
    }
    if (names && !m_resolver_attached)
    {
        m_resolver_attached = m_resolver.attach(m_io);
        if (!m_resolver_attached)
            LOG_ERROR("storage: the tier resolver cannot be waited for, so tiers named by a host are not used");
    }
    for (replication_target& rt : tiers)
    {
        auto t = std::make_unique<tier>();
        // The URL's path is the bucket at the endpoint, then a prefix in it.
        std::string_view path = rt.http.path;
        while (path.starts_with('/'))
            path.remove_prefix(1);
        const size_t slash = path.find('/');
        t->bucket = std::string(path.substr(0, slash));
        if (slash != std::string_view::npos)
        {
            t->prefix = std::string(path.substr(slash + 1));
            while (t->prefix.ends_with("//"))
                t->prefix.pop_back();
            if (!t->prefix.empty() && !t->prefix.ends_with('/'))
                t->prefix.push_back('/');
        }
        t->t = std::move(rt);
        if (t->bucket.empty())
        {
            LOG_ERROR(("storage: the tier " + t->t.name + " names no bucket in its URL's path, so nothing moves to it")
                          .c_str());
            continue;
        }
        m_tiers.push_back(std::move(t));
    }
}

bool tierer::has_tier(std::string_view name) const
{
    return std::any_of(m_tiers.begin(), m_tiers.end(), [&](const auto& t) { return t->t.name == name; });
}

tierer::tier* tierer::find(std::string_view name)
{
    for (auto& t : m_tiers)
        if (t->t.name == name)
            return t.get();
    return nullptr;
}

std::string tierer::head(const tier& t, std::string_view method, const std::string& key, const std::string& query,
                         std::vector<std::pair<std::string, std::string>> headers, uint64_t length) const
{
    std::string path = "/" + t.bucket;
    if (!key.empty())
    {
        path += "/";
        url_encode_to(path, key, true);
    }
    return signed_s3_head(t.t, method, path, query, std::move(headers), length, "socketley-storage-tier");
}

void tierer::exchange(tier& t, http_request rq, std::function<void(http_answer)> done)
{
    t.waiting.emplace_back(std::move(rq), std::move(done));
    pump(t);
}

void tierer::pump(tier& t)
{
    while (!t.waiting.empty())
    {
        http_peer* free = nullptr;
        for (auto& p : t.peers)
            if (!p->busy())
            {
                free = p.get();
                break;
            }
        if (!free && t.peers.size() < peers_per_tier)
        {
            t.peers.push_back(std::make_unique<http_peer>(m_loop, m_io, m_resolver, t.t.http, m_hosts_file,
                                                          "the tier " + t.t.name));
            free = t.peers.back().get();
        }
        if (!free)
            return;
        auto [rq, done] = std::move(t.waiting.front());
        t.waiting.pop_front();
        auto alive = m_alive;
        tier* tp = &t;
        free->exchange(std::move(rq), [this, alive, tp, done = std::move(done)](http_answer a)
        {
            if (!*alive)
                return;
            done(std::move(a));
            if (!m_stopped)
                pump(*tp);
        });
    }
}

bool tierer::movable(const object_meta& m)
{
    part_trailer t;
    return !is_delete_marker(m) && !is_encrypted(m) && !is_tiered(m) && !part_trailer_of(m, t) && m.size <= max_move;
}

void tierer::move(const std::string& bucket, const std::string& key, const std::string& version_id,
                  const object_meta& m, const std::string& tier_name)
{
    if (m_stopped || !movable(m) || !find(tier_name))
        return;
    std::string id = bucket + '\0' + key + '\0' + version_id;
    if (!m_moving.insert(id).second)
        return;
    auto j        = std::make_shared<job>();
    j->bucket     = bucket;
    j->key        = key;
    j->version_id = version_id;
    j->tier       = tier_name;
    j->was        = m;
    m_queue.push_back(std::move(j));
    next_move();
}

void tierer::next_move()
{
    while (!m_stopped && m_active < moves_at_once && !m_queue.empty())
    {
        auto j = std::move(m_queue.front());
        m_queue.pop_front();
        ++m_active;
        auto alive = m_alive;
        auto then  = [this, alive, j](open_result o)
        {
            if (!*alive)
            {
                if (o.fd >= 0)
                    m_loop.close_fd(o.fd);
                return;
            }
            opened(j, std::move(o));
        };
        if (j->version_id.empty())
            m_store.open_object(j->bucket, j->key, 0, std::move(then));
        else
            m_store.open_version(j->bucket, j->key, j->version_id, 0, std::move(then));
    }
}

void tierer::opened(const std::shared_ptr<job>& j, open_result o)
{
    if (o.fd >= 0)
        j->fd = o.fd;
    tier* t = find(j->tier);
    // The file is still the version the index named, or the move waits for the next pass to look again.
    if (o.status != st::ok || o.delete_marker || !t || o.meta.size != j->was.size || o.meta.md5 != j->was.md5 ||
        o.meta.mtime_ms != j->was.mtime_ms || !movable(o.meta))
    {
        done(j, false);
        return;
    }
    j->data_off   = o.data_off;
    // Named by the version's own id however it was asked for, which is what the sweep looks it up by.
    j->remote_key = remote_key_of(t->prefix, j->bucket, j->key, has_version(j->was) ? version_of(j->was).id : "",
                                  j->was);
    const object_meta& m = o.meta;
    std::vector<std::pair<std::string, std::string>> h;
    h.emplace_back("content-type", m.content_type.empty() ? std::string("application/octet-stream")
                                                          : std::string(m.content_type));
    // A single part's MD5 is the bytes', which the tier then checks them against.
    if (m.parts == 0)
        h.emplace_back("content-md5", base64::encode(std::string_view(reinterpret_cast<const char*>(m.md5.data()), 16)));
    http_request rq;
    rq.head        = head(*t, "PUT", j->remote_key, {}, std::move(h), m.size);
    rq.answer_secs = replicator::answer_secs;
    if (!t->t.http.tls && !is_compressed(m) && m.size >= 64 * 1024)
    {
        rq.file_fd  = j->fd;
        rq.file_off = j->data_off;
        rq.file_len = m.size;
    }
    else if (m.size)
    {
        auto reader = body_reader::make(m_io, &m_hashes, m_store.alive_token(), j->fd, j->data_off, m, nullptr, 0,
                                        m.size);
        std::weak_ptr<job> weak = j;
        rq.source = [reader, weak](http_body_give give)
        {
            if (!reader)
            {
                if (auto jj = weak.lock())
                    jj->source_failed = true;
                give(false, {});
                return;
            }
            reader->next([weak, give](bool ok, std::string_view plain)
            {
                if (!ok)
                    if (auto jj = weak.lock())
                        jj->source_failed = true;
                give(ok, plain);
            });
        };
    }
    auto alive = m_alive;
    exchange(*t, std::move(rq), [this, alive, j](http_answer a)
    {
        if (*alive)
            uploaded(j, std::move(a));
    });
}

void tierer::uploaded(const std::shared_ptr<job>& j, http_answer a)
{
    if (j->fd >= 0)
    {
        m_loop.close_fd(j->fd);
        j->fd = -1;
    }
    if (a.status / 100 != 2 || j->source_failed)
    {
        LOG_WARN(("storage: " + j->bucket + "/" + j->key + " did not move to the tier " + j->tier + ": " +
                  (a.status ? "it answered " + std::to_string(a.status) : a.failure))
                     .c_str());
        done(j, false);
        return;
    }
    // The tier has the bytes: the file here becomes the header alone, which says where they are.
    j->now = j->was;
    set_lz4_record(j->now, nullptr);
    const tier_record rec{j->tier, j->remote_key};
    set_tier_record(j->now, &rec);
    j->head = std::make_shared<std::string>(encode_object_header(j->key, j->now));
    auto alive = m_alive;
    m_store.open_tmp(j->bucket, [this, alive, j](int fd, std::string name)
    {
        if (!*alive)
        {
            if (fd >= 0)
                ::close(fd);
            return;
        }
        if (fd < 0)
        {
            done(j, false);
            return;
        }
        j->tmp_fd = fd;
        j->tmp    = std::move(name);
        const bool q = m_io.pwrite(fd, j->head->data(), static_cast<uint32_t>(j->head->size()), 0,
                                   [this, alive, j](int64_t r)
        {
            if (!*alive)
                return;
            if (r != static_cast<int64_t>(j->head->size()))
            {
                done(j, false);
                return;
            }
            const bool q2 = m_io.sync(j->tmp_fd, true, [this, alive, j](int64_t r2)
            {
                if (!*alive)
                    return;
                if (r2 < 0)
                {
                    done(j, false);
                    return;
                }
                m_loop.close_fd(j->tmp_fd);
                j->tmp_fd = -1;
                std::string tmp = std::move(j->tmp);
                j->tmp.clear();
                m_store.replace_body(j->bucket, j->key, j->version_id, j->was, j->now, std::move(tmp),
                                     [this, alive, j](st s)
                {
                    if (*alive)
                        done(j, s == st::ok);
                });
            });
            if (!q2)
                done(j, false);
        });
        if (!q)
            done(j, false);
    });
}

void tierer::done(const std::shared_ptr<job>& j, bool moved)
{
    for (int* fd : {&j->fd, &j->tmp_fd})
        if (*fd >= 0)
        {
            m_loop.close_fd(*fd);
            *fd = -1;
        }
    if (!j->tmp.empty())
    {
        m_store.drop_tmp(j->bucket, j->tmp);
        j->tmp.clear();
    }
    if (moved)
    {
        ++m_c.moved;
        m_c.bytes += j->was.size;
    }
    else
        ++m_c.failed;
    m_moving.erase(j->bucket + '\0' + j->key + '\0' + j->version_id);
    --m_active;
    next_move();
}

std::shared_ptr<body_reader> tierer::reader(const object_meta& m, uint64_t first, uint64_t len)
{
    tier_record rec;
    if (!tier_of(m, rec) || !find(rec.tier))
        return nullptr;
    auto alive = m_alive;
    const std::string name = rec.tier, key = rec.remote_key;
    return body_reader::make_remote(m_store.alive_token(),
        [this, alive, name, key](uint64_t off, uint64_t n, std::function<void(bool, std::string)> give)
    {
        tier* t = *alive ? find(name) : nullptr;
        if (!t)
        {
            give(false, {});
            return;
        }
        http_request rq;
        rq.head = head(*t, "GET", key, {}, {{"range", "bytes=" + std::to_string(off) + "-" + std::to_string(off + n - 1)}},
                       0);
        exchange(*t, std::move(rq), [this, alive, n, give](http_answer a)
        {
            if (!*alive)
                return;
            const bool ok = (a.status == 206 || a.status == 200) && a.body.size() == n;
            ++(ok ? m_c.reads : m_c.read_failures);
            give(ok, ok ? std::move(a.body) : std::string{});
        });
    }, first, len);
}

void tierer::tick()
{
    if (m_stopped || m_tiers.empty())
        return;
    const auto now = std::chrono::steady_clock::now();
    for (auto& t : m_tiers)
        for (auto& p : t->peers)
            p->tick(now);
    if (!m_sweep && now >= m_next_sweep)
        m_sweep = std::make_unique<sweep>();
    if (m_sweep && !m_sweep->listing && !m_sweep->removing)
        sweep_next();
}

void tierer::sweep_next()
{
    sweep& s = *m_sweep;
    if (!s.doomed.empty())
    {
        tier* t = s.doomed_tier < m_tiers.size() ? m_tiers[s.doomed_tier].get() : nullptr;
        if (!t)
        {
            s.doomed.clear();
            return;
        }
        s.removing = true;
        const std::string key = std::move(s.doomed.front());
        s.doomed.pop_front();
        http_request rq;
        rq.head = head(*t, "DELETE", key, {}, {}, 0);
        auto alive = m_alive;
        exchange(*t, std::move(rq), [this, alive](http_answer a)
        {
            if (!*alive || !m_sweep)
                return;
            m_sweep->removing = false;
            if (a.status / 100 == 2)
                ++m_c.swept;
            sweep_next();
        });
        return;
    }
    if (s.tier >= m_tiers.size())
    {
        // Every tier was walked: the next sweep is a quarter day on, at least a second and at most six hours.
        m_sweep.reset();
        m_next_sweep = std::chrono::steady_clock::now() +
                       std::chrono::milliseconds(std::clamp<int64_t>(m_day_ms / 4, 1000, 6 * 3600 * 1000));
        return;
    }
    tier& t = *m_tiers[s.tier];
    std::string query = "list-type=2&max-keys=" + std::to_string(sweep_page_keys);
    if (!t.prefix.empty())
        query += "&prefix=" + url_encode(t.prefix, false);
    if (!s.token.empty())
        query += "&continuation-token=" + url_encode(s.token, false);
    http_request rq;
    rq.head = head(t, "GET", {}, query, {}, 0);
    s.listing = true;
    auto alive = m_alive;
    exchange(t, std::move(rq), [this, alive](http_answer a)
    {
        if (!*alive || !m_sweep)
            return;
        m_sweep->listing = false;
        sweep_page(std::move(a));
    });
}

void tierer::sweep_page(http_answer a)
{
    sweep& s = *m_sweep;
    tier* t = s.tier < m_tiers.size() ? m_tiers[s.tier].get() : nullptr;
    xml_node root;
    xml_reader rd(a.body);
    if (!t || a.status != 200 || !rd.document(root) || root.name != "ListBucketResult")
    {
        // A tier that does not list is walked again at the next sweep, and said so the first time.
        if (t && !t->list_told)
        {
            t->list_told = true;
            LOG_WARN(("storage: the tier " + t->t.name + " did not list what it holds, so nothing there is swept: " +
                      (a.status ? "it answered " + std::to_string(a.status) + " " + a.body.substr(0, 200) : a.failure))
                         .c_str());
        }
        ++s.tier;
        s.token.clear();
        return;
    }
    // A version moves a while before its file here says so, and is left at the tier that long whatever is here.
    const int64_t grace = std::clamp<int64_t>(m_day_ms / 24, 1000, 3600 * 1000);
    const int64_t now   = static_cast<int64_t>(m_store.now_ms());
    bool truncated = false;
    std::string next;
    for (const xml_node& k : root.kids)
    {
        if (k.name == "IsTruncated")
            truncated = k.text == "true";
        else if (k.name == "NextContinuationToken")
            next = k.text;
        if (k.name != "Contents")
            continue;
        std::string rk;
        int64_t modified = now;
        for (const xml_node& f : k.kids)
        {
            bool midnight = false;
            if (f.name == "Key")
                rk = f.text;
            else if (f.name == "LastModified" && !parse_iso8601(f.text, modified, midnight))
                modified = now;
        }
        if (!rk.starts_with(t->prefix) || now - modified < grace)
            continue;
        std::string bucket, key, md5, version_id;
        int64_t mtime = 0;
        if (!parse_remote_key(std::string_view(rk).substr(t->prefix.size()), bucket, key, mtime, md5, version_id) ||
            !m_store.owns(bucket, key))
            continue;
        // A version still here keeps its bytes at the tier, moved or about to be, on this node or another.
        const object_meta* m = version_id.empty() ? m_store.find(bucket, key)
                                                  : m_store.find_version(bucket, key, version_id);
        if (m && same_bytes(*m, mtime, md5))
            continue;
        if (m_moving.contains(bucket + '\0' + key + '\0' + version_id))
            continue;
        s.doomed_tier = s.tier;
        s.doomed.push_back(std::move(rk));
    }
    if (truncated && !next.empty())
        s.token = std::move(next);
    else
    {
        ++s.tier;
        s.token.clear();
    }
}

void tierer::stop()
{
    m_stopped = true;
    m_queue.clear();
    for (auto& t : m_tiers)
    {
        t->waiting.clear();
        for (auto& p : t->peers)
            p->stop();
    }
}

}   // namespace socketley::storage
