#include "object_store.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>

#include <fcntl.h>

#include "s3_names.h"
#include "../../shared/logging.h"
#include "../../shared/random_id.h"

namespace socketley::storage
{

namespace
{

// The smallest string greater than every string that begins with `s`, empty
// when there is none because `s` is all 0xFF bytes.
std::string prefix_successor(std::string s)
{
    while (!s.empty() && static_cast<unsigned char>(s.back()) == 0xFF)
        s.pop_back();
    if (s.empty())
        return s;
    s.back() = static_cast<char>(static_cast<unsigned char>(s.back()) + 1);
    return s;
}

st errno_status(int64_t res)
{
    return (res == -ENOSPC || res == -EDQUOT) ? st::storage_full : st::io_error;
}

constexpr size_t compact_chunk = 256 * 1024;

}   // namespace

const char* status_name(st s)
{
    switch (s)
    {
        case st::ok:                  return "ok";
        case st::no_such_bucket:      return "no such bucket";
        case st::no_such_key:         return "no such key";
        case st::bucket_exists:       return "bucket exists";
        case st::bucket_not_empty:    return "bucket not empty";
        case st::invalid_bucket_name: return "invalid bucket name";
        case st::key_too_long:        return "key too long";
        case st::metadata_too_large:  return "metadata too large";
        case st::too_large:           return "too large";
        case st::bad_digest:          return "bad digest";
        case st::storage_full:        return "storage full";
        case st::busy:                return "busy";
        case st::io_error:            return "i/o error";
        case st::cancelled:           return "cancelled";
    }
    return "unknown";
}

object_store::object_store(event_loop& loop, file_io& io, store_options opts)
    : m_loop(&loop), m_io(&io), m_opts(std::move(opts)), m_alive(std::make_shared<bool>(true))
{
}

object_store::~object_store()
{
    if (*m_alive)
        close(false);
}

uint64_t object_store::now_ms() const
{
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

std::string object_store::tmp_name()
{
    return hex(reinterpret_cast<const uint8_t*>(std::array<uint64_t, 2>{random_u64(), random_u64()}.data()), 16);
}

object_store::bucket* object_store::find_bucket(std::string_view name)
{
    auto it = m_buckets.find(name);
    return it == m_buckets.end() ? nullptr : it->second.get();
}

const object_store::bucket* object_store::find_bucket(std::string_view name) const
{
    auto it = m_buckets.find(name);
    return it == m_buckets.end() ? nullptr : it->second.get();
}

bool object_store::has_bucket(std::string_view name) const
{
    const bucket* b = find_bucket(name);
    return b && !b->closing;
}

std::vector<bucket_info> object_store::buckets() const
{
    std::vector<bucket_info> out;
    out.reserve(m_buckets.size());
    for (const auto& [name, b] : m_buckets)
        if (!b->closing)
            out.push_back({name, b->created_ms});
    return out;
}

store_totals object_store::totals() const
{
    store_totals t = m_totals;
    t.buckets = m_buckets.size();
    return t;
}

bool object_store::busy() const
{
    if (m_inflight > 0 || !m_creating.empty())
        return true;
    for (const auto& [name, b] : m_buckets)
        if (b->j.writing || b->j.frozen || !b->j.pending.empty() || b->active_puts > 0)
            return true;
    return false;
}

const object_meta* object_store::find(std::string_view bucket_name, std::string_view key) const
{
    const bucket* b = find_bucket(bucket_name);
    if (!b)
        return nullptr;
    auto it = b->objects.find(key);
    return it == b->objects.end() ? nullptr : &it->second;
}

st object_store::list(std::string_view bucket_name, const list_query& q, list_page& out) const
{
    const bucket* b = find_bucket(bucket_name);
    if (!b || b->closing)
        return st::no_such_bucket;

    out = list_page{};
    if (q.max_keys == 0)
        return st::ok;

    // The inclusive lower bound the walk starts at, from whichever of a resume
    // point, a start-after key and the prefix reaches furthest.
    std::string lower = q.prefix;
    if (q.has_resume)
    {
        if (q.resume_at > lower)
            lower = q.resume_at;
    }
    else if (!q.start_after.empty())
    {
        const std::string after = q.start_after + '\0';
        if (after > lower)
            lower = after;
    }

    auto it = b->objects.lower_bound(lower);
    size_t count = 0;
    while (it != b->objects.end() && it->first.starts_with(q.prefix))
    {
        if (count >= q.max_keys)
        {
            out.truncated = true;
            out.resume_at = it->first;
            break;
        }
        const std::string& key = it->first;
        if (!q.delimiter.empty())
        {
            const size_t pos = key.find(q.delimiter, q.prefix.size());
            if (pos != std::string::npos)
            {
                std::string cp = key.substr(0, pos + q.delimiter.size());
                // Every key under the prefix is one entry, so the walk jumps
                // past all of them instead of stepping over each.
                const std::string next = prefix_successor(cp);
                // A marker that is itself a rolled-up prefix means the caller
                // has that prefix already, and not the keys behind it.
                const bool seen = !q.has_resume && !q.start_after.empty() && cp <= q.start_after;
                if (!seen)
                {
                    out.prefixes.push_back(std::move(cp));
                    ++count;
                }
                it = next.empty() ? b->objects.end() : b->objects.lower_bound(next);
                continue;
            }
        }
        out.objects.push_back({key, it->second});
        ++count;
        ++it;
    }
    return st::ok;
}

// ─── Journal ────────────────────────────────────────────────────────────────

void object_store::journal_append(bucket& b, std::string_view record, std::function<void(bool)> cb)
{
    b.j.pending.append(record);
    ++b.j.pending_records;
    b.j.pending_cbs.push_back(std::move(cb));
    journal_kick(b);
}

void object_store::journal_kick(bucket& b)
{
    if (b.j.writing || b.j.frozen)
        return;
    if (b.j.pending.empty())
    {
        maybe_compact(b);
        return;
    }

    b.j.inflight.swap(b.j.pending);
    b.j.pending.clear();
    b.j.inflight_records = b.j.pending_records;
    b.j.pending_records  = 0;
    b.j.inflight_cbs.swap(b.j.pending_cbs);
    b.j.pending_cbs.clear();
    b.j.writing = true;

    const std::string name = b.name;
    auto alive = m_alive;
    // Failing the writers in one place, because a refused submission and a
    // failed completion end the same way.
    auto finish = [this, alive, name](bool ok)
    {
        if (!*alive)
            return;
        bucket* bp = find_bucket(name);
        if (!bp)
            return;
        auto cbs = std::move(bp->j.inflight_cbs);
        bp->j.inflight_cbs.clear();
        if (ok)
        {
            bp->j.off += bp->j.inflight.size();
            bp->j.records += bp->j.inflight_records;
            m_totals.journal_records += bp->j.inflight_records;
        }
        bp->j.inflight.clear();
        bp->j.inflight_records = 0;
        bp->j.writing = false;
        for (auto& c : cbs)
            c(ok);
        if (bucket* again = find_bucket(name))
            journal_kick(*again);
    };

    const bool queued = m_io->pwrite(
        b.j.fd, b.j.inflight.data(), static_cast<uint32_t>(b.j.inflight.size()), b.j.off,
        [this, alive, name, finish](int64_t r)
        {
            if (!*alive)
                return;
            bucket* bp = find_bucket(name);
            if (!bp)
                return;
            if (r < 0)
            {
                LOG_WARN(("storage: appending to the journal of " + name + " failed").c_str());
                finish(false);
                return;
            }
            const bool synced = m_io->fsync(bp->j.fd, true,
                [this, alive, finish](int64_t r2)
                {
                    if (!*alive)
                        return;
                    ++m_totals.fsyncs;
                    finish(r2 >= 0);
                });
            if (!synced)
                finish(false);
        });
    if (!queued)
        finish(false);
}

void object_store::maybe_compact(bucket& b)
{
    if (b.closing || b.j.frozen || b.j.writing)
        return;
    if (b.j.records < m_opts.compact_floor || b.j.records < 2 * (b.objects.size() + 1) ||
        b.j.records < b.j.compact_after)
        return;

    b.j.frozen = true;
    ++m_inflight;
    const std::string name = b.name;
    auto alive = m_alive;
    const std::string file = "index." + std::to_string(m_opts.shard) + ".new";
    const bool queued = m_io->openat(
        b.dir_fd, file, O_WRONLY | O_CREAT | O_TRUNC, 0644,
        [this, alive, name](int64_t fd)
        {
            if (!*alive)
                return;
            bucket* bp = find_bucket(name);
            if (!bp)
                return;
            if (fd < 0)
            {
                compact_finish(name, false);
                return;
            }
            bp->dump_fd  = static_cast<int>(fd);
            bp->dump_off = 0;
            bp->dump_it  = bp->objects.cbegin();
            compact_step(alive, name);
        });
    if (!queued)
        compact_finish(name, false);
}

void object_store::compact_step(std::shared_ptr<bool> alive, const std::string& name)
{
    bucket* b = find_bucket(name);
    if (!b)
        return;

    auto buf = std::make_shared<std::string>();
    if (b->dump_off == 0)
        *buf = encode_journal_header(m_opts.shard);
    bool wrote_records = false;
    while (b->dump_it != b->objects.cend() && buf->size() < compact_chunk)
    {
        encode_put_record(*buf, b->dump_it->first, b->dump_it->second);
        ++b->dump_it;
        wrote_records = true;
    }

    if (buf->empty() || (!wrote_records && b->dump_off != 0))
    {
        // Every record is written: synced, swapped in, and the directory synced.
        const std::string live = "index." + std::to_string(m_opts.shard);
        const bool queued = m_io->fsync(b->dump_fd, true,
            [this, alive, name, live](int64_t r)
            {
                if (!*alive)
                    return;
                bucket* bp = find_bucket(name);
                if (!bp)
                    return;
                if (r < 0)
                {
                    compact_finish(name, false);
                    return;
                }
                ++m_totals.fsyncs;
                const bool q = m_io->renameat(bp->dir_fd, live + ".new", bp->dir_fd, live,
                    [this, alive, name](int64_t r2)
                    {
                        if (!*alive)
                            return;
                        bucket* bq = find_bucket(name);
                        if (!bq)
                            return;
                        if (r2 < 0)
                        {
                            compact_finish(name, false);
                            return;
                        }
                        const bool q2 = m_io->fsync(bq->dir_fd, false,
                            [this, alive, name](int64_t r3)
                            {
                                if (!*alive)
                                    return;
                                ++m_totals.fsyncs;
                                compact_finish(name, r3 >= 0);
                            });
                        if (!q2)
                            compact_finish(name, false);
                    });
                if (!q)
                    compact_finish(name, false);
            });
        if (!queued)
            compact_finish(name, false);
        return;
    }

    const bool queued = m_io->pwrite(b->dump_fd, buf->data(), static_cast<uint32_t>(buf->size()),
                                     b->dump_off,
        [this, alive, name, buf](int64_t r)
        {
            if (!*alive)
                return;
            bucket* bp = find_bucket(name);
            if (!bp)
                return;
            if (r < 0)
            {
                compact_finish(name, false);
                return;
            }
            bp->dump_off += buf->size();
            compact_step(alive, name);
        });
    if (!queued)
        compact_finish(name, false);
}

void object_store::compact_finish(const std::string& name, bool ok)
{
    bucket* b = find_bucket(name);
    if (!b)
        return;

    if (ok)
    {
        // Appends resume on the new file, which holds every live object and
        // whatever the old one's tail said that is still true.
        if (b->j.fd >= 0)
            m_loop->close_fd(b->j.fd);
        m_totals.journal_records = m_totals.journal_records - b->j.records + b->objects.size();
        b->j.fd      = b->dump_fd;
        b->j.off     = b->dump_off;
        b->j.records = b->objects.size();
        b->dump_fd   = -1;
        ++m_totals.compactions;
    }
    else
    {
        LOG_WARN(("storage: compacting the journal of " + name + " failed; it is tried again later").c_str());
        if (b->dump_fd >= 0)
        {
            m_loop->close_fd(b->dump_fd);
            b->dump_fd = -1;
        }
        if (!m_io->unlinkat(b->dir_fd, "index." + std::to_string(m_opts.shard) + ".new", 0,
                            [](int64_t) {})) {}
        b->j.compact_after = b->j.records + m_opts.compact_floor;
    }
    b->j.frozen = false;
    --m_inflight;
    journal_kick(*b);
}

// ─── Lanes: one commit at a time per key ────────────────────────────────────

void object_store::lane_enter(bucket& b, const std::string& key, std::function<void()> run)
{
    auto it = b.lanes.find(key);
    if (it == b.lanes.end())
    {
        b.lanes.emplace(key, std::vector<std::function<void()>>{});
        run();
        return;
    }
    it->second.push_back(std::move(run));
}

void object_store::lane_leave(const std::string& bucket_name, const std::string& key)
{
    bucket* b = find_bucket(bucket_name);
    if (!b)
        return;
    auto it = b->lanes.find(key);
    if (it == b->lanes.end())
        return;
    if (it->second.empty())
    {
        b->lanes.erase(it);
        return;
    }
    auto next = std::move(it->second.front());
    it->second.erase(it->second.begin());
    next();
}

void object_store::apply_put(bucket& b, const std::string& key, const object_meta& meta)
{
    auto it = b.objects.find(key);
    if (it != b.objects.end())
    {
        b.bytes -= it->second.size;
        m_totals.bytes -= it->second.size;
        it->second = meta;
    }
    else
    {
        b.objects.emplace(key, meta);
        ++m_totals.objects;
    }
    b.bytes += meta.size;
    m_totals.bytes += meta.size;
    ++m_totals.puts;
}

void object_store::apply_delete(bucket& b, const std::string& key)
{
    auto it = b.objects.find(key);
    if (it == b.objects.end())
        return;
    b.bytes -= it->second.size;
    m_totals.bytes -= it->second.size;
    --m_totals.objects;
    b.objects.erase(it);
    ++m_totals.deletes;
}

// ─── Making a directory that exists durably ─────────────────────────────────

void object_store::ensure_dirs(const std::string& bucket_name, const std::string& rel,
                               std::function<void(int, st)> cb)
{
    bucket* b = find_bucket(bucket_name);
    if (!b)
    {
        cb(-1, st::no_such_bucket);
        return;
    }
    const std::string ab   = rel.substr(0, 2);
    const std::string abcd = rel.substr(0, 5);
    auto alive = m_alive;

    // The leaf, which is what a rename and its sync need in hand.
    auto open_leaf = [this, alive, bucket_name, abcd, cb]()
    {
        bucket* bp = find_bucket(bucket_name);
        if (!bp)
        {
            cb(-1, st::no_such_bucket);
            return;
        }
        if (!m_io->openat(bp->data_fd, abcd, O_RDONLY | O_DIRECTORY, 0,
                [alive, cb](int64_t fd)
                {
                    if (!*alive)
                        return;
                    if (fd < 0)
                        cb(-1, st::io_error);
                    else
                        cb(static_cast<int>(fd), st::ok);
                }))
            cb(-1, st::io_error);
    };

    // The second level: created, then its parent synced so the name survives.
    auto make_cd = [this, alive, bucket_name, ab, abcd, cb, open_leaf]()
    {
        bucket* bp = find_bucket(bucket_name);
        if (!bp)
        {
            cb(-1, st::no_such_bucket);
            return;
        }
        if (bp->made_dirs.contains(abcd))
        {
            open_leaf();
            return;
        }
        const bool q = m_io->mkdirat(bp->data_fd, abcd, 0755,
            [this, alive, bucket_name, ab, abcd, cb, open_leaf](int64_t r)
            {
                if (!*alive)
                    return;
                bucket* bq = find_bucket(bucket_name);
                if (!bq)
                {
                    cb(-1, st::no_such_bucket);
                    return;
                }
                if (r < 0 && r != -EEXIST)
                {
                    cb(-1, errno_status(r));
                    return;
                }
                const bool q2 = m_io->openat(bq->data_fd, ab, O_RDONLY | O_DIRECTORY, 0,
                    [this, alive, bucket_name, abcd, cb, open_leaf](int64_t pfd)
                    {
                        if (!*alive)
                            return;
                        if (pfd < 0)
                        {
                            cb(-1, st::io_error);
                            return;
                        }
                        const int parent = static_cast<int>(pfd);
                        const bool q3 = m_io->fsync(parent, false,
                            [this, alive, bucket_name, abcd, cb, open_leaf, parent](int64_t r3)
                            {
                                if (!*alive)
                                    return;
                                ++m_totals.fsyncs;
                                m_loop->close_fd(parent);
                                if (r3 < 0)
                                {
                                    cb(-1, st::io_error);
                                    return;
                                }
                                if (bucket* bz = find_bucket(bucket_name))
                                    bz->made_dirs.insert(abcd);
                                open_leaf();
                            });
                        if (!q3)
                        {
                            m_loop->close_fd(parent);
                            cb(-1, st::io_error);
                        }
                    });
                if (!q2)
                    cb(-1, st::io_error);
            });
        if (!q)
            cb(-1, st::io_error);
    };

    if (b->made_dirs.contains(ab))
    {
        make_cd();
        return;
    }
    const bool q = m_io->mkdirat(b->data_fd, ab, 0755,
        [this, alive, bucket_name, ab, cb, make_cd](int64_t r)
        {
            if (!*alive)
                return;
            bucket* bp = find_bucket(bucket_name);
            if (!bp)
            {
                cb(-1, st::no_such_bucket);
                return;
            }
            if (r < 0 && r != -EEXIST)
            {
                cb(-1, errno_status(r));
                return;
            }
            const bool q2 = m_io->fsync(bp->data_fd, false,
                [this, alive, bucket_name, ab, cb, make_cd](int64_t r2)
                {
                    if (!*alive)
                        return;
                    ++m_totals.fsyncs;
                    if (r2 < 0)
                    {
                        cb(-1, st::io_error);
                        return;
                    }
                    if (bucket* bz = find_bucket(bucket_name))
                        bz->made_dirs.insert(ab);
                    make_cd();
                });
            if (!q2)
                cb(-1, st::io_error);
        });
    if (!q)
        cb(-1, st::io_error);
}

// ─── Commit ─────────────────────────────────────────────────────────────────

void object_store::commit(commit_request req, std::function<void(put_result)> cb)
{
    bucket* b = find_bucket(req.bucket);
    if (!b || b->closing)
    {
        cb({st::no_such_bucket, req.meta});
        return;
    }
    ++b->active_ops;
    ++m_inflight;

    auto alive = m_alive;
    const std::string bname = req.bucket;
    const std::string key   = req.key;
    const object_meta meta  = req.meta;
    const std::string tmp   = req.tmp_name;

    // What every way out of the commit does: the lane is handed on and the
    // bucket is released before the caller hears, because the caller is free
    // to start the next operation from its callback.
    auto done = [this, alive, bname, key, cb](put_result r)
    {
        if (!*alive)
            return;
        if (bucket* bp = find_bucket(bname))
            --bp->active_ops;
        --m_inflight;
        lane_leave(bname, key);
        cb(std::move(r));
    };

    lane_enter(*b, key, [this, alive, bname, key, meta, tmp, done]()
    {
        bucket* bp = find_bucket(bname);
        if (!bp)
        {
            done({st::no_such_bucket, meta});
            return;
        }
        const std::string rel = object_rel_path(key);
        ensure_dirs(bname, rel, [this, alive, bname, key, meta, tmp, rel, done](int leaf, st why)
        {
            if (!*alive)
                return;
            bucket* bq = find_bucket(bname);
            if (!bq || why != st::ok)
            {
                if (bq)
                    if (!m_io->unlinkat(bq->tmp_fd, tmp, 0, [](int64_t) {})) {}
                done({why == st::ok ? st::no_such_bucket : why, meta});
                return;
            }
            const bool q = m_io->renameat(bq->tmp_fd, tmp, bq->data_fd, rel,
                [this, alive, bname, key, meta, tmp, leaf, done](int64_t r)
                {
                    if (!*alive)
                        return;
                    bucket* br = find_bucket(bname);
                    if (!br)
                    {
                        done({st::no_such_bucket, meta});
                        return;
                    }
                    if (r < 0)
                    {
                        m_loop->close_fd(leaf);
                        if (!m_io->unlinkat(br->tmp_fd, tmp, 0, [](int64_t) {})) {}
                        done({errno_status(r), meta});
                        return;
                    }
                    // The rename is in the directory now and durable once the
                    // directory is synced; only then may the journal say so.
                    const bool q2 = m_io->fsync(leaf, false,
                        [this, alive, bname, key, meta, leaf, done](int64_t r2)
                        {
                            if (!*alive)
                                return;
                            ++m_totals.fsyncs;
                            m_loop->close_fd(leaf);
                            bucket* bs = find_bucket(bname);
                            if (!bs)
                            {
                                done({st::no_such_bucket, meta});
                                return;
                            }
                            if (r2 < 0)
                            {
                                done({st::io_error, meta});
                                return;
                            }
                            std::string rec;
                            encode_put_record(rec, key, meta);
                            journal_append(*bs, rec,
                                [this, alive, bname, key, meta, done](bool ok)
                                {
                                    if (!*alive)
                                        return;
                                    // The file is in place whatever the journal
                                    // said, and it is the truth, so the memory
                                    // follows it and the caller hears the failure.
                                    if (bucket* bt = find_bucket(bname))
                                        apply_put(*bt, key, meta);
                                    done({ok ? st::ok : st::io_error, meta});
                                });
                        });
                    if (!q2)
                    {
                        m_loop->close_fd(leaf);
                        done({st::io_error, meta});
                    }
                });
            if (!q)
            {
                m_loop->close_fd(leaf);
                done({st::io_error, meta});
            }
        });
    });
}

void object_store::remove(std::string_view bucket_name, std::string_view key_sv,
                          std::function<void(st, bool)> cb)
{
    bucket* b = find_bucket(bucket_name);
    if (!b || b->closing)
    {
        cb(st::no_such_bucket, false);
        return;
    }
    ++b->active_ops;
    ++m_inflight;

    auto alive = m_alive;
    const std::string bname = std::string(bucket_name);
    const std::string key   = std::string(key_sv);

    auto done = [this, alive, bname, key, cb](st s, bool existed)
    {
        if (!*alive)
            return;
        if (bucket* bp = find_bucket(bname))
            --bp->active_ops;
        --m_inflight;
        lane_leave(bname, key);
        cb(s, existed);
    };

    lane_enter(*b, key, [this, alive, bname, key, done]()
    {
        bucket* bp = find_bucket(bname);
        if (!bp)
        {
            done(st::no_such_bucket, false);
            return;
        }
        const bool existed = bp->objects.contains(key);
        const std::string rel = object_rel_path(key);
        const bool q = m_io->unlinkat(bp->data_fd, rel, 0,
            [this, alive, bname, key, rel, existed, done](int64_t r)
            {
                if (!*alive)
                    return;
                bucket* bq = find_bucket(bname);
                if (!bq)
                {
                    done(st::no_such_bucket, false);
                    return;
                }
                if (r < 0 && r != -ENOENT)
                {
                    done(errno_status(r), existed);
                    return;
                }
                if (r == -ENOENT && !existed)
                {
                    done(st::ok, false);
                    return;
                }
                // The unlink made durable before the journal says it happened,
                // or a crash brings the file back and a rebuild adopts it.
                const std::string dir = rel.substr(0, 5);
                auto journal_it = [this, alive, bname, key, existed, done]()
                {
                    bucket* br = find_bucket(bname);
                    if (!br)
                    {
                        done(st::no_such_bucket, false);
                        return;
                    }
                    std::string rec;
                    encode_delete_record(rec, key, static_cast<int64_t>(now_ms()));
                    journal_append(*br, rec,
                        [this, alive, bname, key, existed, done](bool ok)
                        {
                            if (!*alive)
                                return;
                            if (bucket* bt = find_bucket(bname))
                                apply_delete(*bt, key);
                            done(ok ? st::ok : st::io_error, existed);
                        });
                };
                if (r == -ENOENT)
                {
                    journal_it();
                    return;
                }
                const bool q2 = m_io->openat(bq->data_fd, dir, O_RDONLY | O_DIRECTORY, 0,
                    [this, alive, journal_it, done, existed](int64_t dfd)
                    {
                        if (!*alive)
                            return;
                        if (dfd < 0)
                        {
                            done(st::io_error, existed);
                            return;
                        }
                        const int fd = static_cast<int>(dfd);
                        const bool q3 = m_io->fsync(fd, false,
                            [this, alive, journal_it, done, existed, fd](int64_t r3)
                            {
                                if (!*alive)
                                    return;
                                ++m_totals.fsyncs;
                                m_loop->close_fd(fd);
                                if (r3 < 0)
                                {
                                    done(st::io_error, existed);
                                    return;
                                }
                                journal_it();
                            });
                        if (!q3)
                        {
                            m_loop->close_fd(fd);
                            done(st::io_error, existed);
                        }
                    });
                if (!q2)
                    done(st::io_error, existed);
            });
        if (!q)
            done(st::io_error, existed);
    });
}

// ─── Reading an object ──────────────────────────────────────────────────────

void object_store::open_object(std::string_view bucket_name, std::string_view key_sv,
                               size_t prefetch, std::function<void(open_result)> cb)
{
    bucket* b = find_bucket(bucket_name);
    if (!b || b->closing)
    {
        cb({st::no_such_bucket, -1, {}, 0, {}});
        return;
    }
    auto alive = m_alive;
    const std::string key = std::string(key_sv);
    const std::string rel = object_rel_path(key);

    const bool q = m_io->openat(b->data_fd, rel, O_RDONLY, 0,
        [this, alive, key, prefetch, cb](int64_t r)
        {
            if (!*alive)
                return;
            if (r < 0)
            {
                cb({r == -ENOENT ? st::no_such_key : st::io_error, -1, {}, 0, {}});
                return;
            }
            const int fd = static_cast<int>(r);
            auto buf = std::make_shared<std::string>();
            buf->resize(object_header_align + prefetch);

            // The header's own read, repeated with a longer one when the
            // header turns out to be longer than the first guess.
            auto step = std::make_shared<std::function<void(size_t)>>();
            std::weak_ptr<std::function<void(size_t)>> weak = step;
            *step = [this, alive, fd, key, prefetch, cb, buf, weak](size_t want)
            {
                auto self = weak.lock();
                const bool q2 = m_io->pread(fd, buf->data(), static_cast<uint32_t>(want), 0,
                    [this, alive, fd, key, prefetch, cb, buf, self](int64_t n)
                    {
                        if (!*alive)
                            return;
                        if (n < 0)
                        {
                            m_loop->close_fd(fd);
                            cb({st::io_error, -1, {}, 0, {}});
                            return;
                        }
                        const std::string_view got(buf->data(), static_cast<size_t>(n));
                        const decoded_header d = decode_object_header(got);
                        if (d.status == header_status::need_more && d.need > got.size() &&
                            d.need <= 64 * 1024 && self)
                        {
                            buf->resize(d.need);
                            (*self)(d.need);
                            return;
                        }
                        if (d.status != header_status::ok)
                        {
                            LOG_WARN(("storage: the header of the object \"" + key +
                                      "\" cannot be read").c_str());
                            m_loop->close_fd(fd);
                            cb({st::io_error, -1, {}, 0, {}});
                            return;
                        }
                        if (d.key != key)
                        {
                            // Two keys of one hash, which is the case the key in
                            // the header is there to tell apart.
                            m_loop->close_fd(fd);
                            cb({st::no_such_key, -1, {}, 0, {}});
                            return;
                        }
                        open_result out;
                        out.status   = st::ok;
                        out.fd       = fd;
                        out.meta     = d.meta;
                        out.data_off = d.header_len;
                        if (got.size() > d.header_len && prefetch)
                        {
                            const size_t have = got.size() - d.header_len;
                            out.prefetch = std::string(got.substr(d.header_len,
                                std::min<uint64_t>({have, prefetch, d.meta.size})));
                        }
                        cb(std::move(out));
                    });
                if (!q2)
                {
                    m_loop->close_fd(fd);
                    cb({st::io_error, -1, {}, 0, {}});
                }
            };
            (*step)(buf->size());
            // The step keeps itself alive through the copy each read holds.
            (void)step;
        });
    if (!q)
        cb({st::io_error, -1, {}, 0, {}});
}

// ─── Starting a write ───────────────────────────────────────────────────────

std::shared_ptr<put_op> object_store::begin_put(std::string_view bucket_name, std::string_view key,
                                                object_meta meta, uint64_t expected,
                                                bool size_known, st& why)
{
    bucket* b = find_bucket(bucket_name);
    if (!b || b->closing)
    {
        why = st::no_such_bucket;
        return nullptr;
    }
    if (key.empty() || key.size() > max_key_bytes)
    {
        why = st::key_too_long;
        return nullptr;
    }
    size_t meta_bytes = meta.content_type.size();
    for (const auto& [n, v] : meta.extra)
        meta_bytes += n.size() + v.size();
    if (meta_bytes > max_meta_bytes)
    {
        why = st::metadata_too_large;
        return nullptr;
    }
    if (size_known && expected > m_opts.max_object_bytes)
    {
        why = st::too_large;
        return nullptr;
    }
    if (m_opts.max_bytes && size_known &&
        m_totals.bytes + m_reserved + expected > m_opts.max_bytes)
    {
        why = st::storage_full;
        return nullptr;
    }

    std::shared_ptr<put_op> op(new put_op);
    op->begin(this, std::string(bucket_name), std::string(key), std::move(meta), expected, size_known);
    why = st::ok;
    return op;
}

// ─── Copying ────────────────────────────────────────────────────────────────

namespace
{

struct copy_state
{
    std::string dst_bucket;
    std::string dst_key;
    std::string tmp;
    object_meta meta;
    int         src_fd{-1};
    int         dst_fd{-1};
    size_t      src_off{0};
    size_t      hdr_len{0};
    uint64_t    copied{0};
    uint64_t    reserved{0};
    std::string buf;
    std::function<void(put_result)> cb;
};

}   // namespace

void object_store::copy(std::string_view src_bucket, std::string_view src_key,
                        std::string_view dst_bucket, std::string_view dst_key, object_meta meta,
                        std::function<void(put_result)> cb)
{
    bucket* sb = find_bucket(src_bucket);
    bucket* db = find_bucket(dst_bucket);
    if (!sb || sb->closing || !db || db->closing)
    {
        cb({st::no_such_bucket, meta});
        return;
    }
    auto sit = sb->objects.find(src_key);
    if (sit == sb->objects.end())
    {
        cb({st::no_such_key, meta});
        return;
    }
    if (dst_key.empty() || dst_key.size() > max_key_bytes)
    {
        cb({st::key_too_long, meta});
        return;
    }
    const uint64_t size = sit->second.size;
    if (m_opts.max_bytes && m_totals.bytes + m_reserved + size > m_opts.max_bytes)
    {
        cb({st::storage_full, meta});
        return;
    }

    auto cs = std::make_shared<copy_state>();
    cs->dst_bucket = std::string(dst_bucket);
    cs->dst_key    = std::string(dst_key);
    cs->meta       = std::move(meta);
    cs->meta.size  = size;
    cs->reserved   = size;
    cs->cb         = std::move(cb);
    m_reserved += size;
    ++db->active_ops;
    ++m_inflight;

    auto alive = m_alive;
    // The one exit, which gives back everything the copy held.
    auto finish = std::make_shared<std::function<void(put_result)>>();
    *finish = [this, alive, cs](put_result r)
    {
        if (!*alive)
            return;
        if (cs->src_fd >= 0)
            m_loop->close_fd(cs->src_fd);
        if (cs->dst_fd >= 0)
            m_loop->close_fd(cs->dst_fd);
        m_reserved -= cs->reserved;
        if (bucket* bp = find_bucket(cs->dst_bucket))
        {
            --bp->active_ops;
            if (r.status != st::ok && !cs->tmp.empty())
                if (!m_io->unlinkat(bp->tmp_fd, cs->tmp, 0, [](int64_t) {})) {}
        }
        --m_inflight;
        auto cb2 = std::move(cs->cb);
        cb2(std::move(r));
    };

    open_object(src_bucket, src_key, 0,
        [this, alive, cs, finish](open_result o)
        {
            if (!*alive)
                return;
            if (o.status != st::ok)
            {
                (*finish)({o.status, cs->meta});
                return;
            }
            cs->src_fd  = o.fd;
            cs->src_off = o.data_off;
            cs->meta.md5   = o.meta.md5;
            cs->meta.parts = o.meta.parts;
            cs->meta.mtime_ms = static_cast<int64_t>(now_ms());

            bucket* bp = find_bucket(cs->dst_bucket);
            if (!bp)
            {
                (*finish)({st::no_such_bucket, cs->meta});
                return;
            }
            cs->tmp = tmp_name();
            const bool q = m_io->openat(bp->tmp_fd, cs->tmp, O_WRONLY | O_CREAT | O_EXCL, 0600,
                [this, alive, cs, finish](int64_t tfd)
                {
                    if (!*alive)
                        return;
                    if (tfd < 0)
                    {
                        cs->tmp.clear();
                        (*finish)({errno_status(tfd), cs->meta});
                        return;
                    }
                    cs->dst_fd = static_cast<int>(tfd);
                    auto header = std::make_shared<std::string>(
                        encode_object_header(cs->dst_key, cs->meta));
                    cs->hdr_len = header->size();

                    // Header first, then the body a megabyte at a time: the
                    // source is read into one buffer and written from it, so
                    // a copy of any size holds one megabyte.
                    auto pump = std::make_shared<std::function<void()>>();
                    std::weak_ptr<std::function<void()>> wpump = pump;
                    *pump = [this, alive, cs, finish, wpump]()
                    {
                        auto self = wpump.lock();
                        if (cs->copied >= cs->meta.size)
                        {
                            const bool qs = m_io->fsync(cs->dst_fd, true,
                                [this, alive, cs, finish](int64_t rs)
                                {
                                    if (!*alive)
                                        return;
                                    ++m_totals.fsyncs;
                                    if (rs < 0)
                                    {
                                        (*finish)({errno_status(rs), cs->meta});
                                        return;
                                    }
                                    commit_request cr;
                                    cr.bucket   = cs->dst_bucket;
                                    cr.key      = cs->dst_key;
                                    cr.tmp_name = cs->tmp;
                                    cr.meta     = cs->meta;
                                    commit(std::move(cr),
                                        [this, alive, cs, finish](put_result pr)
                                        {
                                            if (!*alive)
                                                return;
                                            // Committed, so the temporary name
                                            // is gone and must not be unlinked.
                                            if (pr.status == st::ok || pr.status == st::io_error)
                                                cs->tmp.clear();
                                            (*finish)(std::move(pr));
                                        });
                                });
                            if (!qs)
                                (*finish)({st::io_error, cs->meta});
                            return;
                        }
                        const uint64_t left = cs->meta.size - cs->copied;
                        const uint32_t n = static_cast<uint32_t>(std::min<uint64_t>(left, 1u << 20));
                        cs->buf.resize(n);
                        const bool qr = m_io->pread(cs->src_fd, cs->buf.data(), n,
                                                    cs->src_off + cs->copied,
                            [this, alive, cs, finish, self](int64_t rn)
                            {
                                if (!*alive)
                                    return;
                                if (rn <= 0)
                                {
                                    (*finish)({rn < 0 ? st::io_error : st::io_error, cs->meta});
                                    return;
                                }
                                const bool qw = m_io->pwrite(cs->dst_fd, cs->buf.data(),
                                                             static_cast<uint32_t>(rn),
                                                             cs->hdr_len + cs->copied,
                                    [this, alive, cs, finish, self, rn](int64_t rw)
                                    {
                                        if (!*alive)
                                            return;
                                        if (rw < 0)
                                        {
                                            (*finish)({errno_status(rw), cs->meta});
                                            return;
                                        }
                                        cs->copied += static_cast<uint64_t>(rn);
                                        if (self)
                                            (*self)();
                                    });
                                if (!qw)
                                    (*finish)({st::io_error, cs->meta});
                            });
                        if (!qr)
                            (*finish)({st::io_error, cs->meta});
                    };

                    const bool qh = m_io->pwrite(cs->dst_fd, header->data(),
                                                 static_cast<uint32_t>(header->size()), 0,
                        [alive, cs, finish, header, pump](int64_t rh)
                        {
                            if (!*alive)
                                return;
                            if (rh < 0)
                            {
                                (*finish)({errno_status(rh), cs->meta});
                                return;
                            }
                            (*pump)();
                        });
                    if (!qh)
                        (*finish)({st::io_error, cs->meta});
                });
            if (!q)
            {
                cs->tmp.clear();
                (*finish)({st::io_error, cs->meta});
            }
        });
}

// ─── Buckets ────────────────────────────────────────────────────────────────

namespace
{

struct create_state
{
    std::string name;
    int         stage{0};
    int         fd{-1};
    int64_t     created_ms{0};
    std::string text;
    std::function<void(st)> cb;
};

}   // namespace

void object_store::create_bucket(std::string name, std::function<void(st)> cb)
{
    if (!valid_bucket_name(name))
    {
        cb(st::invalid_bucket_name);
        return;
    }
    if (m_buckets.contains(name))
    {
        cb(st::bucket_exists);
        return;
    }
    if (m_creating.contains(name))
    {
        cb(st::busy);
        return;
    }
    m_creating.insert(name);
    ++m_inflight;

    auto cs  = std::make_shared<create_state>();
    cs->name = std::move(name);
    cs->cb   = std::move(cb);
    cs->created_ms = static_cast<int64_t>(now_ms());
    cs->text = std::to_string(cs->created_ms);

    auto alive = m_alive;
    auto step  = std::make_shared<std::function<void(int64_t)>>();
    std::weak_ptr<std::function<void(int64_t)>> wstep = step;

    // A flat sequence of the steps a bucket is made of, each judged on what the
    // one before it reported.  Every step tolerates a leftover from an
    // attempt that stopped half way.
    *step = [this, alive, cs, wstep](int64_t res)
    {
        if (!*alive)
            return;
        auto self = wstep.lock();
        const std::string base = cs->name;
        auto fail = [this, cs](st why)
        {
            if (cs->fd >= 0)
                m_loop->close_fd(cs->fd);
            m_creating.erase(cs->name);
            --m_inflight;
            cs->cb(why);
        };
        auto next = [self](int64_t r) { if (self) (*self)(r); };
        const int stage = cs->stage++;
        bool queued = true;

        switch (stage)
        {
            case 0:
                queued = m_io->mkdirat(m_root_fd, base, 0755, next);
                break;
            case 1:
                if (res < 0 && res != -EEXIST) { fail(errno_status(res)); return; }
                queued = m_io->mkdirat(m_root_fd, base + "/data", 0755, next);
                break;
            case 2:
                if (res < 0 && res != -EEXIST) { fail(errno_status(res)); return; }
                queued = m_io->mkdirat(m_root_fd, base + "/tmp", 0755, next);
                break;
            case 3:
                if (res < 0 && res != -EEXIST) { fail(errno_status(res)); return; }
                queued = m_io->openat(m_root_fd, base + "/created",
                                      O_WRONLY | O_CREAT | O_TRUNC, 0644, next);
                break;
            case 4:
                if (res < 0) { fail(errno_status(res)); return; }
                cs->fd = static_cast<int>(res);
                queued = m_io->pwrite(cs->fd, cs->text.data(), static_cast<uint32_t>(cs->text.size()),
                                      0, next);
                break;
            case 5:
                if (res < 0) { fail(errno_status(res)); return; }
                queued = m_io->fsync(cs->fd, true, next);
                break;
            case 6:
                if (res < 0) { fail(errno_status(res)); return; }
                m_loop->close_fd(cs->fd);
                cs->fd = -1;
                queued = m_io->openat(m_root_fd, base + "/index." + std::to_string(m_opts.shard),
                                      O_RDWR | O_CREAT | O_TRUNC, 0644, next);
                break;
            case 7:
                if (res < 0) { fail(errno_status(res)); return; }
                cs->fd = static_cast<int>(res);
                cs->text = encode_journal_header(m_opts.shard);
                queued = m_io->pwrite(cs->fd, cs->text.data(), static_cast<uint32_t>(cs->text.size()),
                                      0, next);
                break;
            case 8:
                if (res < 0) { fail(errno_status(res)); return; }
                queued = m_io->fsync(cs->fd, true, next);
                break;
            case 9:
                // The journal descriptor is kept: appends go to it.
                if (res < 0) { fail(errno_status(res)); return; }
                queued = m_io->openat(m_root_fd, base, O_RDONLY | O_DIRECTORY, 0, next);
                break;
            case 10:
                if (res < 0) { fail(errno_status(res)); return; }
                cs->text = std::to_string(res);   // the bucket directory's descriptor
                queued = m_io->fsync(static_cast<int>(res), false, next);
                break;
            case 11:
                if (res < 0) { fail(errno_status(res)); return; }
                queued = m_io->fsync(m_root_fd, false, next);
                break;
            case 12:
                if (res < 0) { fail(errno_status(res)); return; }
                queued = m_io->openat(m_root_fd, base + "/data", O_RDONLY | O_DIRECTORY, 0, next);
                break;
            case 13:
            {
                if (res < 0) { fail(errno_status(res)); return; }
                // Remembered on the state until the last descriptor is opened.
                cs->text += " " + std::to_string(res);
                queued = m_io->openat(m_root_fd, base + "/tmp", O_RDONLY | O_DIRECTORY, 0, next);
                break;
            }
            default:
            {
                if (res < 0) { fail(errno_status(res)); return; }
                int dir_fd = -1, data_fd = -1;
                std::sscanf(cs->text.c_str(), "%d %d", &dir_fd, &data_fd);
                auto b = std::make_unique<bucket>();
                b->name       = cs->name;
                b->created_ms = cs->created_ms;
                b->dir_fd     = dir_fd;
                b->data_fd    = data_fd;
                b->tmp_fd     = static_cast<int>(res);
                b->j.fd       = cs->fd;
                b->j.off      = journal_header_len;
                cs->fd        = -1;
                m_buckets.emplace(cs->name, std::move(b));
                m_creating.erase(cs->name);
                --m_inflight;
                cs->cb(st::ok);
                return;
            }
        }
        if (!queued)
            fail(st::io_error);
    };
    (*step)(0);
    // The sequence outlives this frame through the completion each step queues.
    (void)step;
}

void object_store::delete_bucket(std::string name, std::function<void(st)> cb)
{
    bucket* b = find_bucket(name);
    if (!b || b->closing)
    {
        cb(st::no_such_bucket);
        return;
    }
    if (b->active_puts || b->active_ops || b->j.writing || b->j.frozen || !b->j.pending.empty() ||
        !b->lanes.empty())
    {
        cb(b->objects.empty() ? st::busy : st::bucket_not_empty);
        return;
    }
    if (!b->objects.empty())
    {
        cb(st::bucket_not_empty);
        return;
    }

    b->closing = true;
    ++m_inflight;
    auto alive = m_alive;
    // Renamed out of the way and removed at the next start, so deleting a
    // bucket with a great many empty directories does not walk them here.
    const std::string trash = ".trash/" + name + "." + tmp_name();
    const bool q = m_io->renameat(m_root_fd, name, m_root_fd, trash,
        [this, alive, name, cb](int64_t r)
        {
            if (!*alive)
                return;
            bucket* bp = find_bucket(name);
            if (!bp)
                return;
            if (r < 0)
            {
                bp->closing = false;
                --m_inflight;
                cb(errno_status(r));
                return;
            }
            const bool q2 = m_io->fsync(m_root_fd, false,
                [this, alive, name, cb](int64_t r2)
                {
                    if (!*alive)
                        return;
                    ++m_totals.fsyncs;
                    if (auto it = m_buckets.find(name); it != m_buckets.end())
                    {
                        bucket& bb = *it->second;
                        for (int* fd : {&bb.dir_fd, &bb.data_fd, &bb.tmp_fd, &bb.j.fd})
                            if (*fd >= 0)
                            {
                                m_loop->close_fd(*fd);
                                *fd = -1;
                            }
                        m_totals.journal_records -= std::min(m_totals.journal_records, bb.j.records);
                        m_buckets.erase(it);
                    }
                    --m_inflight;
                    cb(r2 < 0 ? st::io_error : st::ok);
                });
            if (!q2)
            {
                --m_inflight;
                cb(st::io_error);
            }
        });
    if (!q)
    {
        b->closing = false;
        --m_inflight;
        cb(st::io_error);
    }
}

}   // namespace socketley::storage
