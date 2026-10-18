#include "compactor.h"

#include <algorithm>
#include <cstdlib>

#include <fcntl.h>
#include <unistd.h>

#include "../../shared/util/logging.h"

namespace socketley::storage
{

namespace
{

constexpr uint64_t window = 1u << 20;
// Keys looked at in one turn of the loop, so a store of millions does not hold it.
constexpr size_t keys_per_turn = 16384;

enum outcome : int { compressed, left, failed };

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

bool eligible(const object_meta& m)
{
    return !is_delete_marker(m) && !is_encrypted(m) && !is_compressed(m) && !is_tiered(m) && m.parts == 0 &&
           m.size >= compactor::min_size;
}

bool same_version(const object_meta& a, const object_meta& b)
{
    return a.size == b.size && a.mtime_ms == b.mtime_ms && a.md5 == b.md5 && a.parts == b.parts;
}

}   // namespace

struct compactor::job
{
    std::string bucket, key, version_id;
    object_meta was;
    object_meta now;
    int         src{-1};
    uint64_t    data_off{0};
    int         dst{-1};
    std::string tmp;
    uint64_t    header_len{0};
    uint64_t    pos{0};
    uint64_t    stored{0};
    std::shared_ptr<std::string> plain{std::make_shared<std::string>()};
    std::shared_ptr<std::string> out{std::make_shared<std::string>()};
    std::shared_ptr<std::string> table{std::make_shared<std::string>()};
};

compactor::compactor(event_loop& loop, file_io& io, object_store& store, hash_pool& hashes)
    : m_loop(loop), m_io(io), m_store(store), m_hashes(hashes)
{
}

compactor::~compactor()
{
    *m_alive = false;
}

void compactor::open(const std::string& dir, uint32_t shard)
{
    m_path = dir + "/.compact." + std::to_string(shard);
    m_lane = m_hashes.next_lane();
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
        if (name == "low")
            m_low = std::atoll(std::string(value).c_str());
        else if (name == "high")
            m_high = std::atoll(std::string(value).c_str());
        else if (name == "passes")
            m_c.passes = std::strtoull(std::string(value).c_str(), nullptr, 10);
        else if (name == "bucket")
            m_bucket = from_hex(value);
        else if (name == "key")
            m_key = from_hex(value);
    }
}

void compactor::save() const
{
    if (m_path.empty())
        return;
    const std::string text = "low " + std::to_string(m_low) + "\nhigh " + std::to_string(m_high) + "\npasses " +
                             std::to_string(m_c.passes) + "\nbucket " + to_hex(m_bucket) + "\nkey " + to_hex(m_key) +
                             "\n";
    // Unsynced: a crash that takes the note looks at a few keys again.
    const std::string tmp = m_path + ".tmp";
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return;
    const bool whole = ::write(fd, text.data(), text.size()) == static_cast<ssize_t>(text.size());
    ::close(fd);
    if (whole && ::rename(tmp.c_str(), m_path.c_str()) < 0) {}
}

void compactor::tick()
{
    if (!enabled() || m_stopped)
        return;
    const int64_t now = static_cast<int64_t>(m_store.now_ms());
    m_budget = std::min<int64_t>(m_budget + static_cast<int64_t>(rate), static_cast<int64_t>(rate));
    // A pass begins once versions old enough have been written since the last one's window, at most every quarter age.
    const int64_t ripe = now - static_cast<int64_t>(m_age_ms);
    if (m_high == 0 && ripe - m_low >= std::max<int64_t>(static_cast<int64_t>(m_age_ms / 4), 1000))
    {
        m_high = ripe;
        m_bucket.clear();
        m_key.clear();
    }
    if (now - m_saved_ms >= 30000)
    {
        m_saved_ms = now;
        save();
    }
    if (m_paused && m_budget > 0)
    {
        auto j = std::move(m_paused);
        m_paused.reset();
        read(j);
    }
    else if (!m_busy)
        next();
}

void compactor::next()
{
    if (m_stopped || m_budget <= 0 || m_high == 0)
        return;
    auto all = m_store.buckets();
    std::sort(all.begin(), all.end(), [](const bucket_info& a, const bucket_info& b) { return a.name < b.name; });
    size_t looked = 0;
    bool   more   = true;
    while (m_queue.empty() && looked < keys_per_turn && more)
    {
        more = false;
        for (const bucket_info& b : all)
        {
            if (b.name < m_bucket)
                continue;
            const std::string after = b.name == m_bucket ? m_key : std::string();
            const bool plain = m_store.bucket_versioning(b.name) == versioning::off;
            std::string last;
            const size_t n = m_store.keys_after(b.name, after, 256,
                [&](const std::string& key, const std::vector<const object_meta*>& versions)
            {
                last = key;
                for (const object_meta* m : versions)
                    if (eligible(*m) && m->mtime_ms > m_low && m->mtime_ms <= m_high)
                        m_queue.push_back({b.name, key, plain || !has_version(*m) ? std::string() : version_of(*m).id,
                                           *m});
            });
            if (n == 0)
                continue;
            looked  += n;
            m_bucket = b.name;
            m_key    = std::move(last);
            more     = true;
            break;
        }
    }
    if (!m_queue.empty())
    {
        candidate c = std::move(m_queue.front());
        m_queue.pop_front();
        start(std::move(c));
        return;
    }
    if (more)
        return;
    // Every key was looked at: the window is done, and the next pass takes what was written since.
    ++m_c.passes;
    m_low  = m_high;
    m_high = 0;
    m_bucket.clear();
    m_key.clear();
    save();
}

void compactor::start(candidate c)
{
    auto j        = std::make_shared<job>();
    j->bucket     = std::move(c.bucket);
    j->key        = std::move(c.key);
    j->version_id = std::move(c.version_id);
    j->was        = std::move(c.meta);
    m_busy        = true;
    auto alive    = m_alive;
    auto then     = [this, alive, j](open_result o)
    {
        if (!*alive)
        {
            if (o.fd >= 0)
                m_loop.close_fd(o.fd);
            return;
        }
        if (o.fd >= 0)
            j->src = o.fd;
        // The file is the version the index named, or it changed since, which a later pass sees.
        if (o.status != st::ok || o.delete_marker || !same_version(o.meta, j->was) || !eligible(o.meta))
        {
            done(j, left);
            return;
        }
        j->data_off = o.data_off;
        j->now = j->was;
        const lz4_record placeholder{0, lz4_chunks_of(j->was.size)};
        set_lz4_record(j->now, &placeholder);
        j->header_len = encode_object_header(j->key, j->now).size();
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
                done(j, failed);
                return;
            }
            j->dst = fd;
            j->tmp = std::move(name);
            read(j);
        });
    };
    if (j->version_id.empty())
        m_store.open_object(j->bucket, j->key, 0, std::move(then));
    else
        m_store.open_version(j->bucket, j->key, j->version_id, 0, std::move(then));
}

void compactor::read(const std::shared_ptr<job>& j)
{
    if (j->pos >= j->was.size)
    {
        finish(j);
        return;
    }
    const uint64_t n = std::min(window, j->was.size - j->pos);
    j->plain->resize(static_cast<size_t>(n));
    auto alive = m_alive;
    const bool q = m_io.pread(j->src, j->plain->data(), static_cast<uint32_t>(n), j->data_off + j->pos,
        [this, alive, j, n](int64_t r)
        {
            if (!*alive)
                return;
            if (r != static_cast<int64_t>(n))
            {
                done(j, failed);
                return;
            }
            j->out->clear();
            auto work = [j, n] { lz4_squeeze(j->plain->data(), static_cast<size_t>(n), *j->out, *j->table); };
            if (!m_hashes.enabled())
            {
                work();
                squeezed(j, n);
                return;
            }
            m_hashes.submit(m_lane, std::move(work), [this, alive, j, n]
            {
                if (*alive)
                    squeezed(j, n);
            });
        });
    if (!q)
        done(j, failed);
}

void compactor::squeezed(const std::shared_ptr<job>& j, uint64_t n)
{
    // A first window that does not get an eighth shorter says the rest will not either.
    if (j->pos == 0 && j->out->size() > n - n / 8)
    {
        done(j, left);
        return;
    }
    auto alive = m_alive;
    const uint64_t len = j->out->size();
    const bool q = m_io.pwrite(j->dst, j->out->data(), static_cast<uint32_t>(len), j->header_len + j->stored,
        [this, alive, j, n, len](int64_t r)
        {
            if (!*alive)
                return;
            if (r != static_cast<int64_t>(len))
            {
                done(j, failed);
                return;
            }
            j->pos    += n;
            j->stored += len;
            m_budget  -= static_cast<int64_t>(n);
            if (m_budget <= 0 && j->pos < j->was.size)
            {
                m_paused = j;
                return;
            }
            read(j);
        });
    if (!q)
        done(j, failed);
}

void compactor::finish(const std::shared_ptr<job>& j)
{
    const uint64_t size = j->was.size;
    if (j->stored + j->table->size() > size - size / 8)
    {
        done(j, left);
        return;
    }
    const lz4_record rec{j->stored, lz4_chunks_of(size)};
    set_lz4_record(j->now, &rec);
    auto head = std::make_shared<std::string>(encode_object_header(j->key, j->now));
    if (head->size() != j->header_len)
    {
        done(j, failed);
        return;
    }
    // The table, then the header that says where it is, then the file synced before it is put in place.
    auto alive = m_alive;
    const bool q = m_io.pwrite(j->dst, j->table->data(), static_cast<uint32_t>(j->table->size()),
                               j->header_len + j->stored, [this, alive, j, head](int64_t r)
    {
        if (!*alive)
            return;
        if (r != static_cast<int64_t>(j->table->size()))
        {
            done(j, failed);
            return;
        }
        const bool q2 = m_io.pwrite(j->dst, head->data(), static_cast<uint32_t>(head->size()), 0,
                                    [this, alive, j, head](int64_t r2)
        {
            if (!*alive)
                return;
            if (r2 != static_cast<int64_t>(head->size()))
            {
                done(j, failed);
                return;
            }
            const bool q3 = m_io.sync(j->dst, true, [this, alive, j](int64_t r3)
            {
                if (!*alive)
                    return;
                if (r3 < 0)
                    done(j, failed);
                else
                    synced(j);
            });
            if (!q3)
                done(j, failed);
        });
        if (!q2)
            done(j, failed);
    });
    if (!q)
        done(j, failed);
}

void compactor::synced(const std::shared_ptr<job>& j)
{
    m_loop.close_fd(j->dst);
    j->dst = -1;
    std::string tmp = std::move(j->tmp);
    j->tmp.clear();
    auto alive = m_alive;
    m_store.replace_body(j->bucket, j->key, j->version_id, j->was, j->now, std::move(tmp), [this, alive, j](st s)
    {
        if (!*alive)
            return;
        done(j, s == st::ok ? compressed : s == st::precondition_failed ? left : failed);
    });
}

void compactor::done(const std::shared_ptr<job>& j, int result)
{
    if (j->src >= 0)
    {
        m_loop.close_fd(j->src);
        j->src = -1;
    }
    if (j->dst >= 0)
    {
        m_loop.close_fd(j->dst);
        j->dst = -1;
    }
    // A file not handed to the store is its own to drop, with the hold it took.
    if (!j->tmp.empty())
    {
        m_store.drop_tmp(j->bucket, j->tmp);
        j->tmp.clear();
    }
    switch (result)
    {
        case compressed:
            ++m_c.objects;
            m_c.bytes_in  += j->was.size;
            m_c.bytes_out += j->stored + j->table->size();
            break;
        case left:
            ++m_c.skipped;
            break;
        default:
            ++m_c.failed;
            break;
    }
    m_busy = false;
    if (!m_stopped)
        next();
}

void compactor::stop()
{
    m_stopped = true;
    // A version waiting for its budget lets go of its files now, and a later run reads it again.
    if (auto j = std::move(m_paused))
        done(j, left);
    save();
}

}   // namespace socketley::storage
