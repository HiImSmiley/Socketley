// The versions of a key in a versioned bucket: writing a new one, putting a delete
// marker in front of the key, removing one for good, and finding and listing them.
//
// The latest version of a key is its file at the usual path, so a read without a
// version id is on any shard the read it always was.  A latest that a new version
// replaces is first linked to versions/ab/<hash>.<id> and that directory synced, and
// only then is the new file renamed over it, so every version is under at least one
// name at every moment and a start that finds one under two keeps the latest.  The
// order of a key's versions and the id a client is given are in each file's header,
// written by the key's owner under its lane, so the files alone say everything.
#include "object_store.h"

#include <cerrno>
#include <chrono>
#include <cstdio>

#include <fcntl.h>

#include "disk_chain.h"
#include "../../shared/logging.h"
#include "../../shared/random_id.h"

namespace socketley::storage
{

namespace
{

st errno_status(int64_t res)
{
    return (res == -ENOSPC || res == -EDQUOT) ? st::storage_full : st::io_error;
}

uint64_t now_us()
{
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

std::string hex16(uint64_t v)
{
    char b[17];
    std::snprintf(b, sizeof b, "%016llx", static_cast<unsigned long long>(v));
    return std::string(b, 16);
}

// The directory a path below `base` is in.
std::string parent_of(const std::string& rel)
{
    return rel.substr(0, rel.rfind('/'));
}

// Steps that make the names in directory `dir` below `base` durable.
void sync_dir(disk_chain& ch, file_io* io, event_loop* loop, int base, std::string dir)
{
    auto fd = std::make_shared<int>(-1);
    ch.then([io, base, dir = std::move(dir), fd](file_io::done d)
    {
        return io->openat(base, dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0, [fd, d](int64_t r)
        {
            if (r >= 0)
                *fd = static_cast<int>(r);
            d(r);
        });
    });
    ch.then([io, loop, fd](file_io::done d)
    {
        const bool q = io->fsync(*fd, false, [loop, fd, d](int64_t r)
        {
            loop->close_fd(*fd);
            *fd = -1;
            d(r);
        });
        if (!q)
        {
            loop->close_fd(*fd);
            *fd = -1;
        }
        return q;
    });
}

}   // namespace

struct object_store::vop
{
    enum class kind : uint8_t { commit, marker, purge };

    std::shared_ptr<bool> alive;
    kind        what{kind::commit};
    std::string bname, key;
    // The file that becomes the latest: its name, whether it is in pool/ rather than tmp/, and its metadata.
    std::string tmp;
    bool        pooled{false};
    object_meta meta;
    // A delete: the version asked for, empty for a delete marker, and what is asked of the version it removes.
    std::string version_id;
    std::function<bool(const object_meta&)> only_if;
    // The file changed on disk, so the index must follow whatever happens after.
    bool        changed{false};
    int         fd{-1};
    std::string head;
    remove_result rr;
    std::function<void()> release;
    std::function<void(put_result)> put_cb;
    std::function<void(remove_result)> rm_cb;
};

// ─── What the index knows ───────────────────────────────────────────────────

versioning object_store::bucket_versioning(std::string_view name) const
{
    const bucket* b = find_bucket(name);
    return b ? b->vstate : versioning::off;
}

const object_meta* object_store::latest_marker(std::string_view bucket_name, std::string_view key) const
{
    const bucket* b = find_bucket(bucket_name);
    if (!b || b->versions.empty())
        return nullptr;
    const auto v = b->versions.find(key);
    if (v == b->versions.end() || v->second.empty() || b->objects.find(key) != b->objects.end())
        return nullptr;
    return is_delete_marker(v->second.front()) ? &v->second.front() : nullptr;
}

const object_meta* object_store::find_version(std::string_view bucket_name, std::string_view key,
                                              std::string_view version_id) const
{
    const bucket* b = find_bucket(bucket_name);
    if (!b)
        return nullptr;
    if (const auto o = b->objects.find(key); o != b->objects.end() && version_of(o->second).id == version_id)
        return &o->second;
    if (const auto v = b->versions.find(key); v != b->versions.end())
        for (const object_meta& m : v->second)
            if (version_of(m).id == version_id)
                return &m;
    return nullptr;
}

version_tag object_store::next_version(const bucket& b, const std::string& key, bool marker) const
{
    uint64_t top = 0;
    if (const auto o = b.objects.find(key); o != b.objects.end())
        top = version_of(o->second).seq;
    if (const auto v = b.versions.find(key); v != b.versions.end() && !v->second.empty())
        top = std::max(top, version_of(v->second.front()).seq);
    version_tag t;
    // Newer than every version the key has even when the clock stepped back.
    t.seq    = std::max(now_us(), top + 1);
    t.marker = marker;
    t.id     = b.vstate == versioning::enabled ? hex16(t.seq) + hex16(random_u64()) : "null";
    return t;
}

void object_store::version_bytes(bucket& b, int64_t delta)
{
    b.bytes = static_cast<uint64_t>(static_cast<int64_t>(b.bytes) + delta);
    m_totals.bytes = static_cast<uint64_t>(static_cast<int64_t>(m_totals.bytes) + delta);
}

void object_store::version_install(bucket& b, const std::string& key, const object_meta& meta)
{
    const bool null_new = version_of(meta).id == "null";
    std::vector<object_meta>& list = b.versions[key];
    if (const auto o = b.objects.find(key); o != b.objects.end())
    {
        // The latest moves behind the new one, unless both are the key's one null version.
        if (!(null_new && version_of(o->second).id == "null"))
        {
            list.insert(list.begin(), o->second);
            version_bytes(b, static_cast<int64_t>(o->second.size));
        }
    }
    else if (!list.empty() && null_new && is_delete_marker(list.front()) && version_of(list.front()).id == "null")
        list.erase(list.begin());
    if (null_new)
        std::erase_if(list, [&](const object_meta& m)
        {
            if (version_of(m).id != "null")
                return false;
            version_bytes(b, -static_cast<int64_t>(m.size));
            return true;
        });

    std::string rec;
    if (is_delete_marker(meta))
    {
        list.insert(list.begin(), meta);
        if (b.objects.find(key) != b.objects.end())
        {
            encode_delete_record(rec, key, meta.mtime_ms);
            journal_append(b, rec, nullptr);
            apply_delete(b, key);
        }
    }
    else
    {
        encode_put_record(rec, key, meta);
        journal_append(b, rec, nullptr);
        apply_put(b, key, meta);
    }
    if (list.empty())
        b.versions.erase(key);
    hot_drop(b.name, key);
}

bool object_store::version_forget(bucket& b, const std::string& key, const std::string& id)
{
    bool latest = false;
    std::string rec;
    if (const auto o = b.objects.find(key); o != b.objects.end() && version_of(o->second).id == id)
    {
        encode_delete_record(rec, key, static_cast<int64_t>(now_ms()));
        journal_append(b, rec, nullptr);
        apply_delete(b, key);
        latest = true;
    }
    else if (const auto v = b.versions.find(key); v != b.versions.end())
    {
        auto& list = v->second;
        for (size_t i = 0; i < list.size(); ++i)
        {
            if (version_of(list[i]).id != id)
                continue;
            latest = i == 0 && is_delete_marker(list[0]) && b.objects.find(key) == b.objects.end();
            if (!is_delete_marker(list[i]))
                version_bytes(b, -static_cast<int64_t>(list[i].size));
            list.erase(list.begin() + static_cast<ptrdiff_t>(i));
            break;
        }
    }
    // The newest version left is the latest now, which a delete marker stays as at the front.
    const auto v = b.versions.find(key);
    if (latest && v != b.versions.end() && !v->second.empty() && !is_delete_marker(v->second.front()))
    {
        object_meta p = std::move(v->second.front());
        v->second.erase(v->second.begin());
        version_bytes(b, -static_cast<int64_t>(p.size));
        rec.clear();
        encode_put_record(rec, key, p);
        journal_append(b, rec, nullptr);
        apply_put(b, key, p);
    }
    if (v != b.versions.end() && v->second.empty())
        b.versions.erase(v);
    if (latest)
        hot_drop(b.name, key);
    return latest;
}

// ─── A new latest version ───────────────────────────────────────────────────

void object_store::commit_versioned(std::string bucket_name, std::string key, std::string tmp, bool pooled,
                                    object_meta meta, std::function<void()> release, std::function<void(put_result)> cb)
{
    auto v     = std::make_shared<vop>();
    v->alive   = m_alive;
    v->bname   = std::move(bucket_name);
    v->key     = std::move(key);
    v->tmp     = std::move(tmp);
    v->pooled  = pooled;
    v->meta    = std::move(meta);
    v->release = std::move(release);
    v->put_cb  = std::move(cb);
    bucket* b = find_bucket(v->bname);
    if (!b)
    {
        vop_end(std::move(v), st::no_such_bucket);
        return;
    }
    v->what = vop::kind::commit;
    set_version_extra(v->meta, next_version(*b, v->key, false));
    vop_header(std::move(v));
}

void object_store::vop_header(std::shared_ptr<vop> v)
{
    bucket* b = find_bucket(v->bname);
    if (!b)
    {
        vop_end(std::move(v), st::no_such_bucket);
        return;
    }
    // The writer's header is written again with the version in it, in the room it has when it fits.
    const int dir = v->pooled ? b->pool_fd : b->tmp_fd;
    auto ch = std::make_shared<disk_chain>(m_alive);
    ch->then([this, v, dir](file_io::done d)
    {
        return m_io->openat(dir, v->tmp, O_RDWR | O_CLOEXEC, 0, [v, d](int64_t r)
        {
            if (r >= 0)
                v->fd = static_cast<int>(r);
            d(r);
        });
    });
    ch->then([this, v](file_io::done d)
    {
        v->head.resize(64 * 1024);
        return m_io->pread(v->fd, v->head.data(), static_cast<uint32_t>(v->head.size()), 0, [v, d](int64_t r)
        {
            if (r >= 0)
                v->head.resize(static_cast<size_t>(r));
            d(r);
        });
    });
    ch->run([this, v](int64_t r)
    {
        if (r < 0)
        {
            vop_end(v, errno_status(r));
            return;
        }
        const decoded_header d = decode_object_header(v->head);
        if (d.status != header_status::ok || d.key != v->key || d.meta.size != v->meta.size ||
            d.meta.md5 != v->meta.md5)
        {
            LOG_WARN(("storage: the body written for \"" + v->key + "\" is not what its commit says").c_str());
            vop_end(v, st::io_error);
            return;
        }
        auto header = std::make_shared<std::string>(encode_object_header(v->key, v->meta, d.header_len));
        if (header->size() != d.header_len)
        {
            vop_copy(v, v->fd, d.header_len);
            return;
        }
        auto ch2 = std::make_shared<disk_chain>(m_alive);
        ch2->then([this, v, header](file_io::done d2)
        {
            return m_io->pwrite(v->fd, header->data(), static_cast<uint32_t>(header->size()), 0,
                                [header, d2](int64_t w)
                                {
                                    d2(w == static_cast<int64_t>(header->size()) ? 0 : w < 0 ? w : -EIO);
                                });
        });
        ch2->then([this, v](file_io::done d2) { return m_io->fsync(v->fd, true, std::move(d2)); });
        ch2->run([this, v](int64_t r2)
        {
            m_loop->close_fd(v->fd);
            v->fd = -1;
            if (r2 < 0)
            {
                vop_end(v, errno_status(r2));
                return;
            }
            ++m_totals.fsyncs;
            vop_install(v);
        });
    });
}

void object_store::vop_copy(std::shared_ptr<vop> v, int src, uint64_t data_off)
{
    bucket* b = find_bucket(v->bname);
    if (!b)
    {
        vop_end(std::move(v), st::no_such_bucket);
        return;
    }
    // A header that outgrew its room is written in front of a copy of the bytes, as a tag rewrite is.
    constexpr uint64_t chunk = 1u << 20;
    const int tmp_dir = b->tmp_fd;
    const std::string fresh = tmp_name();
    auto header = std::make_shared<std::string>(encode_object_header(v->key, v->meta));
    auto buf    = std::shared_ptr<char[]>(new char[chunk]);
    auto dst    = std::make_shared<int>(-1);
    auto ch     = std::make_shared<disk_chain>(m_alive);
    ch->then([this, tmp_dir, fresh, dst](file_io::done d)
    {
        return m_io->openat(tmp_dir, fresh, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600, [dst, d](int64_t r)
        {
            if (r >= 0)
                *dst = static_cast<int>(r);
            d(r);
        });
    });
    ch->then([this, dst, header](file_io::done d)
    {
        return m_io->pwrite(*dst, header->data(), static_cast<uint32_t>(header->size()), 0,
                            [header, d](int64_t r) { d(r == static_cast<int64_t>(header->size()) ? 0 : r < 0 ? r : -EIO); });
    });
    for (uint64_t off = 0; off < v->meta.size; off += chunk)
    {
        const uint32_t n = static_cast<uint32_t>(std::min(chunk, v->meta.size - off));
        ch->then([this, src, buf, n, at = data_off + off](file_io::done d)
        {
            return m_io->pread(src, buf.get(), n, at, [buf, n, d](int64_t r) { d(r == n ? 0 : r < 0 ? r : -EIO); });
        });
        ch->then([this, dst, buf, n, at = header->size() + off](file_io::done d)
        {
            return m_io->pwrite(*dst, buf.get(), n, at, [buf, n, d](int64_t r) { d(r == n ? 0 : r < 0 ? r : -EIO); });
        });
    }
    ch->then([this, dst](file_io::done d) { return m_io->fsync(*dst, true, std::move(d)); });
    ch->run([this, v, fresh, dst](int64_t r)
    {
        m_loop->close_fd(v->fd);
        v->fd = -1;
        if (*dst >= 0)
            m_loop->close_fd(*dst);
        bucket* bp = find_bucket(v->bname);
        if (r < 0 || !bp)
        {
            if (bp)
                if (!m_io->unlinkat(bp->tmp_fd, fresh, 0, [](int64_t) {})) {}
            vop_end(v, r < 0 ? errno_status(r) : st::no_such_bucket);
            return;
        }
        ++m_totals.fsyncs;
        if (!m_io->unlinkat(v->pooled ? bp->pool_fd : bp->tmp_fd, v->tmp, 0, [](int64_t) {})) {}
        v->tmp    = fresh;
        v->pooled = false;
        vop_install(v);
    });
}

void object_store::vop_install(std::shared_ptr<vop> v)
{
    bucket* b = find_bucket(v->bname);
    if (!b)
    {
        vop_end(std::move(v), st::no_such_bucket);
        return;
    }
    const std::string rel = object_rel_path(v->key);
    const bool null_new = version_of(v->meta).id == "null";

    // The latest the new file replaces is kept under its id first, unless both are the key's one null version.
    const auto o = b->objects.find(v->key);
    const object_meta* latest = o != b->objects.end() ? &o->second : latest_marker(v->bname, v->key);
    std::string keep_id;
    if (latest)
    {
        const version_tag lt = version_of(*latest);
        if (!(null_new && lt.id == "null"))
            keep_id = lt.id;
    }
    // A null version written over a key whose null version is noncurrent replaces that one.
    bool drop_null = false;
    if (null_new)
        if (const auto vs = b->versions.find(v->key); vs != b->versions.end())
            for (const object_meta& m : vs->second)
                drop_null = drop_null || (&m != latest && version_of(m).id == "null");

    const int data_fd = b->data_fd;
    const int dir_fd  = b->dir_fd;
    const int src_dir = v->pooled ? b->pool_fd : b->tmp_fd;
    auto ch = std::make_shared<disk_chain>(m_alive);
    if (!keep_id.empty())
    {
        const std::string vrel = version_rel_path(v->key, keep_id);
        // The same version linked by an attempt a crash cut short is already there.
        ch->then([this, data_fd, dir_fd, rel, vrel](file_io::done d)
                 { return m_io->linkat(data_fd, rel, dir_fd, vrel, std::move(d)); },
                 -EEXIST);
        sync_dir(*ch, m_io, m_loop, dir_fd, parent_of(vrel));
    }
    ch->then([this, v, src_dir, data_fd, rel](file_io::done d)
    {
        return m_io->renameat(src_dir, v->tmp, data_fd, rel, [v, d](int64_t r)
        {
            v->changed = r >= 0;
            d(r);
        });
    });
    sync_dir(*ch, m_io, m_loop, data_fd, parent_of(rel));
    // A start that finds the old null version beside the new one keeps the newer, so this is not waited on.
    if (drop_null)
        ch->then([this, dir_fd, key = v->key](file_io::done d)
                 { return m_io->unlinkat(dir_fd, version_rel_path(key, "null"), 0, std::move(d)); },
                 -ENOENT);
    ch->run([this, v](int64_t r) { vop_end(v, r < 0 ? errno_status(r) : st::ok); });
}

void object_store::vop_end(std::shared_ptr<vop> v, st s)
{
    if (!*v->alive)
        return;
    if (v->fd >= 0)
    {
        m_loop->close_fd(v->fd);
        v->fd = -1;
    }
    bucket* b = find_bucket(v->bname);
    const bool put = v->what == vop::kind::commit;
    if (!v->changed)
    {
        // The new file did not become anything and is nobody's.
        if (b && !v->tmp.empty())
            if (!m_io->unlinkat(v->pooled ? b->pool_fd : b->tmp_fd, v->tmp, 0, [](int64_t) {})) {}
        v->release();
        if (put)
            v->put_cb({s == st::ok ? st::io_error : s, v->meta});
        else
            v->rm_cb({s == st::ok ? st::io_error : s});
        return;
    }
    // Renamed into place, it is the latest whether or not a sync after the rename failed.
    if (b)
        version_install(*b, v->key, v->meta);
    if (s != st::ok)
        m_sync_lost = true;
    invalidate_siblings(v->bname, v->key, [v, s, put]()
    {
        if (!*v->alive)
            return;
        v->release();
        if (put)
            v->put_cb({s, v->meta});
        else
        {
            v->rr.status = s;
            v->rm_cb(v->rr);
        }
    });
}

// ─── Deletes ────────────────────────────────────────────────────────────────

void object_store::remove_versioned(std::string bucket_name, std::string key, std::string version_id,
                                    std::function<bool(const object_meta&)> only_if, std::function<void()> release,
                                    std::function<void(remove_result)> cb)
{
    auto v        = std::make_shared<vop>();
    v->alive      = m_alive;
    v->bname      = std::move(bucket_name);
    v->key        = std::move(key);
    v->version_id = std::move(version_id);
    v->only_if    = std::move(only_if);
    v->release    = std::move(release);
    v->rm_cb      = std::move(cb);
    bucket* b = find_bucket(v->bname);
    auto answer = [v](remove_result r)
    {
        v->release();
        v->rm_cb(std::move(r));
    };
    if (!b)
    {
        answer({st::no_such_bucket});
        return;
    }

    if (v->version_id.empty())
    {
        // A delete marker in front of the key, written by its owner as any other new latest is.
        const auto o = b->objects.find(v->key);
        if (v->only_if && (o == b->objects.end() || !v->only_if(o->second)))
        {
            answer({st::ok});
            return;
        }
        v->what = vop::kind::marker;
        v->meta = object_meta{};
        v->meta.mtime_ms = static_cast<int64_t>(now_ms());
        v->meta.md5      = md5_of({});
        const version_tag t = next_version(*b, v->key, true);
        set_version_extra(v->meta, t);
        v->rr = {st::ok, o != b->objects.end(), true, t.id};
        v->tmp = tmp_name();

        const int tmp_dir = b->tmp_fd;
        auto header = std::make_shared<std::string>(encode_object_header(v->key, v->meta));
        auto ch = std::make_shared<disk_chain>(m_alive);
        ch->then([this, v, tmp_dir](file_io::done d)
        {
            return m_io->openat(tmp_dir, v->tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600, [v, d](int64_t r)
            {
                if (r >= 0)
                    v->fd = static_cast<int>(r);
                d(r);
            });
        });
        ch->then([this, v, header](file_io::done d)
        {
            return m_io->pwrite(v->fd, header->data(), static_cast<uint32_t>(header->size()), 0,
                                [header, d](int64_t r) { d(r == static_cast<int64_t>(header->size()) ? 0 : r < 0 ? r : -EIO); });
        });
        ch->then([this, v](file_io::done d) { return m_io->fsync(v->fd, true, std::move(d)); });
        ch->run([this, v](int64_t r)
        {
            m_loop->close_fd(v->fd);
            v->fd = -1;
            if (r < 0)
            {
                vop_end(v, errno_status(r));
                return;
            }
            ++m_totals.fsyncs;
            vop_install(v);
        });
        return;
    }

    // A version removed for good, the one behind it becoming the latest when it was the latest.
    v->what = vop::kind::purge;
    const object_meta* f = valid_version_id(v->version_id) ? find_version(v->bname, v->key, v->version_id) : nullptr;
    if (!f || (v->only_if && !v->only_if(*f)))
    {
        answer({st::ok, false, false, v->version_id});
        return;
    }
    v->rr = {st::ok, true, is_delete_marker(*f), v->version_id};
    const auto o = b->objects.find(v->key);
    const bool in_objects = o != b->objects.end() && &o->second == f;
    const bool latest = in_objects || f == latest_marker(v->bname, v->key);
    const std::string rel = object_rel_path(v->key);
    std::string next_id;
    if (latest)
        if (const auto vs = b->versions.find(v->key); vs != b->versions.end())
        {
            const size_t at = in_objects ? 0 : 1;
            if (vs->second.size() > at)
                next_id = version_of(vs->second[at]).id;
        }

    const int data_fd = b->data_fd;
    const int dir_fd  = b->dir_fd;
    auto ch = std::make_shared<disk_chain>(m_alive);
    auto mark = [v](file_io::done d) { return [v, d](int64_t r) { v->changed = v->changed || r >= 0; d(r); }; };
    if (latest && !next_id.empty())
    {
        const std::string vrel = version_rel_path(v->key, next_id);
        ch->then([this, data_fd, dir_fd, rel, vrel, mark](file_io::done d)
                 { return m_io->renameat(dir_fd, vrel, data_fd, rel, mark(std::move(d))); });
        sync_dir(*ch, m_io, m_loop, data_fd, parent_of(rel));
        sync_dir(*ch, m_io, m_loop, dir_fd, parent_of(vrel));
    }
    else if (latest)
    {
        ch->then([this, data_fd, rel, mark](file_io::done d) { return m_io->unlinkat(data_fd, rel, 0, mark(std::move(d))); });
        sync_dir(*ch, m_io, m_loop, data_fd, parent_of(rel));
    }
    else
    {
        const std::string vrel = version_rel_path(v->key, v->version_id);
        ch->then([this, dir_fd, vrel, mark](file_io::done d) { return m_io->unlinkat(dir_fd, vrel, 0, mark(std::move(d))); });
        sync_dir(*ch, m_io, m_loop, dir_fd, parent_of(vrel));
    }
    ch->run([this, v](int64_t r)
    {
        if (!*v->alive)
            return;
        const st s = r < 0 ? errno_status(r) : st::ok;
        bucket* bp = find_bucket(v->bname);
        if (!v->changed || !bp)
        {
            v->release();
            v->rm_cb({s == st::ok ? st::io_error : s});
            return;
        }
        if (s != st::ok)
            m_sync_lost = true;
        v->rr.status = s;
        if (!version_forget(*bp, v->key, v->version_id))
        {
            v->release();
            v->rm_cb(v->rr);
            return;
        }
        invalidate_siblings(v->bname, v->key, [v]()
        {
            if (!*v->alive)
                return;
            v->release();
            v->rm_cb(v->rr);
        });
    });
}

// ─── Reading a version ──────────────────────────────────────────────────────

struct object_store::version_probe
{
    std::shared_ptr<bool> alive;
    std::string bname, key, version_id;
    size_t      prefetch{0};
    // Where the next look is, and how many have been: a version moves between its two places only by a rename.
    bool        noncurrent{false};
    int         tries{0};
    std::function<void(open_result)> cb;
};

void object_store::open_version(std::string_view bucket_name, std::string_view key, std::string version_id,
                                size_t prefetch, std::function<void(open_result)> cb)
{
    bucket* b = find_bucket(bucket_name);
    if (!b || b->closing)
    {
        cb({st::no_such_bucket, -1, {}, 0, {}});
        return;
    }
    if (!valid_version_id(version_id))
    {
        cb({st::no_such_version, -1, {}, 0, {}});
        return;
    }
    auto p        = std::make_shared<version_probe>();
    p->alive      = m_alive;
    p->bname      = std::string(bucket_name);
    p->key        = std::string(key);
    p->version_id = std::move(version_id);
    p->prefetch   = prefetch;
    p->cb         = std::move(cb);
    // The owner knows where the version is, and any other shard looks at the latest first.
    if (owns(bucket_name, key))
    {
        const object_meta* f = find_version(bucket_name, key, p->version_id);
        if (!f)
        {
            p->cb({st::no_such_version, -1, {}, 0, {}});
            return;
        }
        const auto o = b->objects.find(key);
        p->noncurrent = !(o != b->objects.end() && &o->second == f) && f != latest_marker(bucket_name, key);
    }
    version_probe_step(std::move(p));
}

void object_store::version_probe_step(std::shared_ptr<version_probe> p)
{
    bucket* b = find_bucket(p->bname);
    if (!b)
    {
        p->cb({st::no_such_bucket, -1, {}, 0, {}});
        return;
    }
    const bool nc = p->noncurrent;
    open_file(nc ? b->dir_fd : b->data_fd, nc ? version_rel_path(p->key, p->version_id) : object_rel_path(p->key),
              p->key, p->prefetch, [this, p](open_result o)
    {
        if (!*p->alive)
            return;
        const bool found = (o.status == st::ok || o.delete_marker) && version_of(o.meta).id == p->version_id;
        if (found)
        {
            if (o.delete_marker)
                o.status = st::delete_marker;
            p->cb(std::move(o));
            return;
        }
        if (o.fd >= 0)
            m_loop->close_fd(o.fd);
        if (o.status != st::ok && o.status != st::no_such_key)
        {
            p->cb({o.status, -1, {}, 0, {}});
            return;
        }
        if (++p->tries >= 3)
        {
            p->cb({st::no_such_version, -1, {}, 0, {}});
            return;
        }
        p->noncurrent = !p->noncurrent;
        version_probe_step(p);
    });
}

void object_store::stat_version(std::string_view bucket_name, std::string_view key, std::string version_id,
                                std::function<void(st, const object_meta&)> cb)
{
    const bucket* b = find_bucket(bucket_name);
    if (!b || b->closing)
    {
        cb(st::no_such_bucket, object_meta{});
        return;
    }
    if (owns(bucket_name, key))
    {
        const object_meta* f = find_version(bucket_name, key, version_id);
        if (!f)
            cb(st::no_such_version, object_meta{});
        else
            cb(is_delete_marker(*f) ? st::delete_marker : st::ok, *f);
        return;
    }
    open_version(bucket_name, key, std::move(version_id), 0, [this, cb](open_result o)
    {
        if (o.fd >= 0)
            m_loop->close_fd(o.fd);
        cb(o.status, o.meta);
    });
}

// ─── ListObjectVersions ─────────────────────────────────────────────────────

std::string object_store::walk_versioned_keys(std::string_view bucket_name, std::string_view prefix,
                                              std::string_view from, size_t max_keys, const version_walk& fn) const
{
    const bucket* b = find_bucket(bucket_name);
    if (!b || b->closing)
        return {};
    auto it = b->versions.lower_bound(std::max(prefix, from));
    for (size_t n = 0; it != b->versions.end() && it->first.starts_with(prefix); ++it, ++n)
    {
        if (n == max_keys)
            return it->first;
        const auto o = b->objects.find(it->first);
        fn(it->first, o == b->objects.end() ? nullptr : &o->second, it->second);
    }
    return {};
}

st object_store::list_versions(std::string_view bucket_name, const version_query& q, version_page& out) const
{
    out = version_page{};
    const bucket* b = find_bucket(bucket_name);
    if (!b || b->closing)
        return st::no_such_bucket;
    if (q.max_keys == 0)
        return st::ok;

    // A key marker alone was shown whole, and with a version it was shown down to that version.
    std::string lower = q.prefix;
    if (!q.key_marker.empty())
    {
        const std::string from = q.version_marker.empty() ? q.key_marker + '\0' : q.key_marker;
        if (from > lower)
            lower = from;
    }
    const auto oend = b->objects.end();
    const auto vend = b->versions.end();
    auto oi = b->objects.lower_bound(lower);
    auto vi = b->versions.lower_bound(lower);
    size_t count = 0;
    std::vector<const object_meta*> metas;
    for (;;)
    {
        const std::string* next = oi != oend ? &oi->first : nullptr;
        if (vi != vend && (!next || vi->first < *next))
            next = &vi->first;
        if (!next || !next->starts_with(q.prefix))
            break;
        const std::string key = *next;
        if (!q.delimiter.empty())
        {
            const size_t pos = key.find(q.delimiter, q.prefix.size());
            if (pos != std::string::npos)
            {
                std::string cp = key.substr(0, pos + q.delimiter.size());
                const std::string after = prefix_successor(cp);
                if (q.key_marker.empty() || cp > q.key_marker)
                {
                    if (count >= q.max_keys)
                    {
                        out.truncated = true;
                        break;
                    }
                    out.items.push_back({std::move(cp), {}, false, true});
                    ++count;
                }
                oi = after.empty() ? oend : b->objects.lower_bound(after);
                vi = after.empty() ? vend : b->versions.lower_bound(after);
                continue;
            }
        }
        metas.clear();
        const bool here_o = oi != oend && oi->first == key;
        const bool here_v = vi != vend && vi->first == key;
        if (here_o)
            metas.push_back(&oi->second);
        if (here_v)
            for (const object_meta& m : vi->second)
                metas.push_back(&m);
        size_t i = 0;
        if (key == q.key_marker && !q.version_marker.empty())
        {
            i = metas.size();
            for (size_t j = 0; j < metas.size(); ++j)
                if (version_of(*metas[j]).id == q.version_marker)
                {
                    i = j + 1;
                    break;
                }
        }
        bool full = false;
        for (; i < metas.size(); ++i)
        {
            if (count >= q.max_keys)
            {
                out.truncated = true;
                full = true;
                break;
            }
            out.items.push_back({key, *metas[i], i == 0, false});
            ++count;
        }
        if (full)
            break;
        if (here_o)
            ++oi;
        if (here_v)
            ++vi;
    }
    return st::ok;
}

}   // namespace socketley::storage
