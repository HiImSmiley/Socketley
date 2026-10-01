// A body on its way into an object: staged, hashed as it passes, written to a
// temporary file in large pieces, and handed to the store's commit.
#include "object_store.h"

#include <algorithm>
#include <cerrno>
#include <cstring>

#include <fcntl.h>

#include "../../shared/logging.h"

namespace socketley::storage
{

namespace
{

// What a trickling body gathers before its digests are handed to a helper thread.
constexpr size_t hash_batch      = 64 * 1024;
// What the end of a body may be hashed on the loop up to, rather than paying a hop for it.
constexpr size_t hash_inline_max = 16 * 1024;

st write_status(int64_t res)
{
    return (res == -ENOSPC || res == -EDQUOT) ? st::storage_full : st::io_error;
}

}   // namespace

void put_op::begin(object_store* store, std::string bucket, std::string key, object_meta meta,
                   uint64_t expected, bool size_known, bool plain)
{
    m_store  = store;
    m_alive  = store->m_alive;
    m_bucket = std::move(bucket);
    m_key    = std::move(key);
    m_meta   = std::move(meta);
    m_meta.size  = 0;
    m_meta.md5   = {};
    m_meta.parts = 0;

    // A versioned bucket's header has room for the version finish_now() puts in it, which is as long as an id makes it.
    clear_version_extra(m_meta);
    if (const object_store::bucket* vb = store->find_bucket(m_bucket); vb && vb->vstate != versioning::off)
        set_version_extra(m_meta, version_tag{0, std::string(32, '0'), false});
    m_header_len = object_header_len(m_key, m_meta);
    clear_version_extra(m_meta);

    // Sized to the object when it is known and small, so a 4 KiB object does
    // not hold a megabyte, and to a megabyte otherwise -- with a second buffer
    // whenever the body will not fit in the first, so the next bytes arrive
    // while the last are being written.
    constexpr size_t mib = 1u << 20;
    const size_t     want = size_known ? m_header_len + static_cast<size_t>(std::min<uint64_t>(expected, mib))
                                       : mib;
    m_cap = std::clamp(want, m_header_len + object_header_align, mib + m_header_len);
    m_cap = (m_cap + object_header_align - 1) / object_header_align * object_header_align;

    m_hs = std::make_shared<hash_state>();
    // A small body is hashed where it lands: the hop to a helper thread costs
    // more than the digest of a few kilobytes.
    constexpr uint64_t async_min = 256 * 1024;
    m_async = store->m_hash && store->m_hash->enabled() && (!size_known || expected >= async_min);
    if (m_async)
        m_lane = store->m_hash->next_lane();

    m_stage[0].data = std::make_shared_for_overwrite<char[]>(m_cap);
    std::memset(m_stage[0].data.get(), 0, m_header_len);
    m_stage[0].fill     = m_header_len;
    m_stage[0].hashed   = m_header_len;
    m_stage[0].file_off = 0;
    m_stage[0].state    = stage_state::filling;
    if (!size_known || m_header_len + expected > m_cap)
        m_stage[1].data = std::make_shared_for_overwrite<char[]>(m_cap);

    m_whole = size_known ? expected : UINT64_MAX;
    if (size_known)
    {
        m_reserved = expected;
        store->m_reserved += expected;
    }
    if (auto* b = store->find_bucket(m_bucket))
        ++b->active_puts;
    ++store->m_inflight;
    ++store->m_puts_active;

    object_store::bucket* b = store->find_bucket(m_bucket);
    if (plain && size_known && expected <= object_store::pooled_max && store->owns(m_bucket, m_key) &&
        store->take_pooled(*b, m_tmp_name, m_tmp_fd))
    {
        m_pooled  = true;
        m_opening = false;
        return;
    }
    m_tmp_name = store->tmp_name();
    auto self = shared_from_this();
    const bool queued = store->m_io->openat(b->tmp_fd, m_tmp_name, O_WRONLY | O_CREAT | O_EXCL, 0600,
        [self](int64_t r)
        {
            if (!*self->m_alive)
                return;
            self->m_opening = false;
            if (r < 0)
            {
                self->m_tmp_name.clear();
                self->fail(write_status(r));
                return;
            }
            self->m_tmp_fd = static_cast<int>(r);
            // A failure while the file was being made left it nobody wants.
            if (self->m_status != st::ok)
            {
                self->cleanup_tmp();
                return;
            }
            self->pump();
            self->maybe_finish();
        });
    if (!queued)
    {
        m_opening = false;
        m_tmp_name.clear();
        fail(st::io_error);
    }
}

put_op::~put_op()
{
    if (m_released || !m_alive || !*m_alive)
        return;
    // Dropped with the write neither finished nor aborted, which is a caller's
    // mistake, and the temporary file must not outlive it.
    cleanup_tmp();
    release();
}

void put_op::release()
{
    if (m_released)
        return;
    m_released = true;
    if (!*m_alive)
        return;
    m_store->m_reserved -= std::min(m_store->m_reserved, m_reserved);
    m_reserved = 0;
    if (auto* b = m_store->find_bucket(m_bucket))
        if (b->active_puts > 0)
            --b->active_puts;
    --m_store->m_inflight;
    --m_store->m_puts_active;
}

void put_op::place_body(std::string path, uint64_t off, uint64_t room)
{
    if (m_status != st::ok)
        return;
    m_placed     = true;
    m_placing    = true;
    m_place_off  = off;
    m_place_room = room;
    auto self = shared_from_this();
    const bool queued = m_store->m_io->openat(AT_FDCWD, std::move(path), O_WRONLY, 0, [self](int64_t r)
    {
        if (!*self->m_alive)
            return;
        self->m_placing = false;
        if (r < 0)
        {
            self->fail(write_status(r));
            return;
        }
        self->m_place_fd = static_cast<int>(r);
        if (self->m_status != st::ok)
        {
            self->cleanup_tmp();
            return;
        }
        self->pump();
        self->maybe_finish();
    });
    if (!queued)
    {
        m_placing = false;
        fail(st::io_error);
    }
}

void put_op::cleanup_tmp()
{
    if (!*m_alive)
        return;
    if (m_tmp_fd >= 0)
    {
        m_store->m_loop->close_fd(m_tmp_fd);
        m_tmp_fd = -1;
    }
    if (m_place_fd >= 0)
    {
        m_store->m_loop->close_fd(m_place_fd);
        m_place_fd = -1;
    }
    if (!m_tmp_name.empty() && !m_tmp_committed)
    {
        if (auto* b = m_store->find_bucket(m_bucket))
            if (!m_store->m_io->unlinkat(m_pooled ? b->pool_fd : b->tmp_fd, m_tmp_name, 0, [](int64_t) {})) {}
        m_tmp_name.clear();
    }
}

size_t put_op::stage_room() const
{
    if (m_status != st::ok || m_eof)
        return 0;
    const stage& s = m_stage[m_active];
    if (s.state == stage_state::filling && s.fill < m_cap)
        return m_cap - s.fill;
    m_want_ready = true;
    return 0;
}

char* put_op::stage_ptr()
{
    if (stage_room() == 0)
        return nullptr;
    stage& s = m_stage[m_active];
    return s.data.get() + s.fill;
}

void put_op::staged(size_t n)
{
    if (n == 0 || m_status != st::ok)
        return;
    stage& s = m_stage[m_active];
    s.fill += n;
    m_received += n;
    // A body that trickles in is handed over in batches, so a hop to a helper thread is not paid per segment.
    if (s.fill - s.hashed >= hash_batch || s.fill == m_cap || !m_async)
        hash_staged(false);

    if (m_received > m_store->m_opts.max_object_bytes)
    {
        fail(st::too_large);
        return;
    }
    // A placed body past its room would write over the next part's.
    if (m_placed && m_received > m_place_room)
    {
        fail(st::io_error);
        return;
    }
    // A body of unknown length is held to the quota as it grows.
    if (m_store->m_opts.max_bytes && m_reserved < m_received)
    {
        const uint64_t more = m_received - m_reserved;
        if (m_store->m_totals.bytes + m_store->m_reserved + more > m_store->quota())
        {
            fail(st::storage_full);
            return;
        }
        m_store->m_reserved += more;
        m_reserved += more;
    }
    // The last piece of a body of known length waits for finish(), which puts
    // the header in front of it so the two go in one write.
    if (s.fill == m_cap && m_received != m_whole)
    {
        s.state = stage_state::full;
        m_next_off = s.file_off + s.fill;
        pump();
    }
}

void put_op::hash_staged(bool last)
{
    stage& s = m_stage[m_active];
    const size_t n = s.fill - s.hashed;
    if (n == 0)
        return;
    const char* p = s.data.get() + s.hashed;
    s.hashed = s.fill;
    // The tail of a body is hashed here when nothing is ahead of it on the lane, since a hop costs more than a few kilobytes.
    if (m_async && !(last && m_hash_out == 0 && n <= hash_inline_max))
    {
        // Behind the earlier pieces of this body on one thread, reading the
        // bytes where they landed; the buffer is held until it reports.
        ++s.hash_out;
        ++m_hash_out;
        const int index = m_active;
        m_store->m_hash->submit(m_lane,
            [hs = m_hs, buf = s.data, p, n]
            {
                hs->md5.update(p, n);
                if (hs->ck)
                    hs->ck->update(p, n);
            },
            [self = shared_from_this(), index] { self->on_hashed(index); });
        return;
    }
    m_hs->md5.update(p, n);
    if (m_hs->ck)
        m_hs->ck->update(p, n);
}

size_t put_op::append(const char* p, size_t n)
{
    size_t taken = 0;
    while (taken < n)
    {
        const size_t room = stage_room();
        if (room == 0)
            break;
        const size_t k = std::min(room, n - taken);
        std::memcpy(stage_ptr(), p + taken, k);
        staged(k);
        taken += k;
        if (m_status != st::ok)
            break;
    }
    return taken;
}

void put_op::pump()
{
    if (m_status != st::ok)
        return;

    for (;;)
    {
        bool progress = false;

        // A full buffer goes to the file as soon as there is one.
        if (!m_opening && m_tmp_fd >= 0 && (!m_placed || m_place_fd >= 0))
        {
            for (stage& s : m_stage)
                if (s.state == stage_state::full)
                {
                    flush(s);
                    if (m_status != st::ok)
                        return;
                    progress = true;
                }
        }

        // And the active slot is a buffer that can take bytes, when one is free.
        if (!m_eof && m_stage[m_active].state != stage_state::filling)
        {
            for (int i = 0; i < 2; ++i)
            {
                stage& s = m_stage[i];
                if (s.data && s.state == stage_state::free)
                {
                    s.fill     = 0;
                    s.hashed   = 0;
                    s.file_off = m_next_off;
                    s.state    = stage_state::filling;
                    m_active   = i;
                    progress   = true;
                    break;
                }
            }
        }
        if (!progress)
            break;
    }

    if (m_want_ready && stage_room() > 0)
    {
        m_want_ready = false;
        if (m_ready_cb)
        {
            // Held across the call because the callback may end this operation.
            auto self = shared_from_this();
            m_ready_cb();
        }
    }
}

void put_op::flush(stage& s)
{
    s.state = stage_state::writing;
    if (s.file_off == 0)
        m_first_written = true;
    auto self = shared_from_this();
    stage* sp = &s;
    int         fd  = m_tmp_fd;
    const char* p   = s.data.get();
    size_t      n   = s.fill;
    uint64_t    off = s.file_off;
    if (m_placed)
    {
        // The room the header has at the front of the first buffer stays out of the placed file.
        const size_t skip = s.file_off == 0 ? m_header_len : 0;
        fd  = m_place_fd;
        p  += skip;
        n  -= skip;
        off = m_place_off + s.file_off + skip - m_header_len;
    }
    const bool queued = m_store->m_io->pwrite(fd, p, static_cast<uint32_t>(n), off,
        [self, sp](int64_t r)
        {
            if (!*self->m_alive)
                return;
            self->on_write_done(*sp, r);
        });
    if (!queued)
    {
        s.state = stage_state::free;
        fail(st::io_error);
    }
}

void put_op::on_write_done(stage& s, int64_t res)
{
    if (s.hash_out > 0)
    {
        // The pool is still reading it; on_hashed frees it.
        s.state = stage_state::hashing;
        if (m_status == st::ok && res < 0)
            fail(write_status(res));
        return;
    }
    s.state = stage_state::free;
    s.fill  = 0;
    if (m_status != st::ok)
        return;
    if (res < 0)
    {
        fail(write_status(res));
        return;
    }
    pump();
    maybe_finish();
}

void put_op::on_hashed(int index)
{
    if (!*m_alive)
        return;
    stage& s = m_stage[index];
    --s.hash_out;
    --m_hash_out;
    if (s.state == stage_state::hashing && s.hash_out == 0)
    {
        s.state = stage_state::free;
        s.fill  = 0;
        if (m_status == st::ok)
        {
            pump();
            maybe_finish();
        }
    }
    if (m_hash_out == 0 && m_finish_wait && m_status == st::ok)
    {
        m_finish_wait = false;
        finish_now();
    }
}

void put_op::finish(const md5_t* expected_md5, std::function<void(put_result)> cb)
{
    if (m_status != st::ok)
    {
        cb({m_status, m_meta});
        return;
    }
    m_done = std::move(cb);
    m_has_expect_md5 = expected_md5 != nullptr;
    hash_staged(true);
    if (expected_md5)
        m_expect_md5 = *expected_md5;
    // The digests are complete only when every piece has been hashed.
    if (m_hash_out > 0)
    {
        m_finish_wait = true;
        return;
    }
    finish_now();
}

void put_op::finish_now()
{
    m_eof  = true;

    m_meta.size     = m_received;
    m_meta.md5      = m_hs->md5.finish();
    m_meta.mtime_ms = static_cast<int64_t>(m_store->now_ms());
    if (m_has_expect_md5 && m_expect_md5 != m_meta.md5)
    {
        fail(st::bad_digest);
        return;
    }
    if (m_hs->ck)
    {
        const std::string got = m_hs->ck->peek_b64();
        if (!m_ck_expect.empty() && got != m_ck_expect)
        {
            fail(st::bad_digest);
            return;
        }
        const std::string_view name = checksum_header(m_hs->ck->algo());
        bool stored = false;
        for (auto& [n, v] : m_meta.extra)
            if (n == name)
            {
                v      = got;
                stored = true;
            }
        if (!stored)
            m_meta.extra.emplace_back(std::string(name), got);
    }

    // The version goes into the header before the body is synced, so the owner need not write the header again
    // unless a newer version of the key or a change of the bucket's versioning comes before its commit.
    if (const object_store::bucket* vb = m_store->find_bucket(m_bucket);
        vb && vb->vstate != versioning::off && !m_committer)
    {
        set_version_extra(m_meta, m_store->next_version(*vb, m_key, false));
        // A bucket versioned since the room was reserved leaves the version to the owner.
        if (object_header_len(m_key, m_meta) > m_header_len)
            clear_version_extra(m_meta);
    }

    // The header goes into the first buffer when that is still in memory, and
    // is written on its own otherwise.
    m_header = encode_object_header(m_key, m_meta, m_header_len);
    // The body starts where room was reserved for it, and a header that grew
    // past that would be written over it.
    if (m_header.size() != m_header_len)
    {
        fail(st::io_error);
        return;
    }
    stage& first = m_stage[0];
    if (!m_placed && !m_first_written && first.state != stage_state::writing)
    {
        std::memcpy(first.data.get(), m_header.data(), m_header_len);
        m_header_done = true;
    }

    // The buffer being filled holds the tail of the body.
    stage& a = m_stage[m_active];
    if (a.state == stage_state::filling)
    {
        if (a.fill > 0)
        {
            a.state    = stage_state::full;
            m_next_off = a.file_off + a.fill;
        }
        else
            a.state = stage_state::free;
    }
    pump();
    maybe_finish();
}

void put_op::maybe_finish()
{
    if (!m_eof || m_status != st::ok || m_sync_started || m_opening || m_placing)
        return;
    for (const stage& s : m_stage)
        if (s.state == stage_state::full || s.state == stage_state::writing ||
            (s.state == stage_state::filling && s.fill > 0))
            return;

    auto self = shared_from_this();
    if (!m_header_done)
    {
        if (m_header_writing)
            return;
        m_header_writing = true;
        const bool queued = m_store->m_io->pwrite(m_tmp_fd, m_header.data(),
                                                  static_cast<uint32_t>(m_header.size()), 0,
            [self](int64_t r)
            {
                if (!*self->m_alive)
                    return;
                if (self->m_status != st::ok)
                    return;
                if (r < 0)
                {
                    self->fail(write_status(r));
                    return;
                }
                self->m_header_done = true;
                self->maybe_finish();
            });
        if (!queued)
            fail(st::io_error);
        return;
    }

    m_sync_started = true;
    m_syncs_left   = m_placed ? 2 : 1;
    auto on_sync = [self](int64_t r)
    {
        if (!*self->m_alive)
            return;
        self->synced(r);
    };
    if (!m_store->m_io->fsync(m_tmp_fd, true, on_sync) ||
        (m_placed && !m_store->m_io->fsync(m_place_fd, true, on_sync)))
        fail(st::io_error);
}

void put_op::synced(int64_t res)
{
    if (m_status != st::ok)
        return;
    ++m_store->m_totals.fsyncs;
    if (res < 0)
    {
        fail(write_status(res));
        return;
    }
    if (--m_syncs_left > 0)
        return;
    // The descriptors are done with, and the commit owns the name from
    // here: a failure inside it removes the temporary file itself.
    m_store->m_loop->close_fd(m_tmp_fd);
    m_tmp_fd = -1;
    if (m_place_fd >= 0)
    {
        m_store->m_loop->close_fd(m_place_fd);
        m_place_fd = -1;
    }
    m_tmp_committed = true;

    commit_request req;
    req.bucket   = m_bucket;
    req.key      = m_key;
    req.tmp_name = m_tmp_name;
    req.meta     = m_meta;
    req.create_only = m_create_only;
    req.pooled      = m_pooled;
    auto self = shared_from_this();
    auto done = [self](put_result r2)
    {
        self->release();
        auto d = std::move(self->m_done);
        self->m_done = nullptr;
        if (d)
            d(std::move(r2));
    };
    if (m_committer)
        m_committer(std::move(req), std::move(done));
    else
        m_store->commit(std::move(req), std::move(done));
}

void put_op::fail(st why)
{
    if (m_status != st::ok)
        return;
    m_status = why;

    // A file still being opened is dealt with when the open reports.
    if (!m_opening)
        cleanup_tmp();
    release();

    if (m_done)
    {
        auto d = std::move(m_done);
        m_done = nullptr;
        d({why, m_meta});
    }
    else if (!m_notified_failed && m_failed_cb)
    {
        m_notified_failed = true;
        auto cb = m_failed_cb;
        auto self = shared_from_this();
        cb(why);
    }
}

void put_op::track_checksum(checksum_algo algo, std::string expected_b64)
{
    m_hs->ck    = std::make_unique<checksum_stream>(algo);
    m_ck_expect = std::move(expected_b64);
}

void put_op::expect_checksum(std::string b64)
{
    m_ck_expect = std::move(b64);
}

void put_op::abort()
{
    m_failed_cb = nullptr;
    m_ready_cb  = nullptr;
    m_done      = nullptr;
    fail(st::cancelled);
}

}   // namespace socketley::storage
