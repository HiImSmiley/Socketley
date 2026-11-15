#include "sync_index.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <utility>

#include "../../shared/loop/file_io.h"
#include "../../shared/persist/mutation_journal.h"
#include "../../shared/persist/read_file.h"

namespace socketley::sync
{

namespace
{

constexpr std::string_view magic = "SKLSYNC2";
constexpr size_t record_head = 8;
// No body is near this; a larger length is rubbish, not a record.
constexpr size_t max_body = 1 + 2 + 65535 + 2 + sync_index::max_path + 8 + 8 + 1 + 255;

void put_u16(std::string& o, uint16_t v) { o.append(reinterpret_cast<const char*>(&v), 2); }
void put_u32(std::string& o, uint32_t v) { o.append(reinterpret_cast<const char*>(&v), 4); }
void put_u64(std::string& o, uint64_t v) { o.append(reinterpret_cast<const char*>(&v), 8); }

// Reads `n` bytes at `at` of `s` into `out`, false when the record runs past the end.
bool take(std::string_view s, size_t& at, void* out, size_t n)
{
    if (at + n > s.size())
        return false;
    std::memcpy(out, s.data() + at, n);
    at += n;
    return true;
}

bool take_str(std::string_view s, size_t& at, size_t n, std::string& out)
{
    if (at + n > s.size())
        return false;
    out.assign(s.substr(at, n));
    at += n;
    return true;
}

std::string body_of(char kind, std::string_view target, std::string_view path, const index_entry& e)
{
    std::string b(1, kind);
    put_u16(b, static_cast<uint16_t>(target.size()));
    b.append(target);
    put_u16(b, static_cast<uint16_t>(path.size()));
    b.append(path);
    put_u64(b, e.size);
    put_u64(b, static_cast<uint64_t>(e.mtime_ns));
    // An etag is a few dozen bytes; a host that sends a longer one is remembered by its first 255.
    const size_t elen = std::min<size_t>(e.etag.size(), 255);
    b.push_back(static_cast<char>(elen));
    b.append(e.etag, 0, elen);
    return b;
}

std::string framed(std::string_view body)
{
    std::string out;
    put_u32(out, static_cast<uint32_t>(body.size()));
    put_u32(out, crc::crc32(body));
    out.append(body);
    return out;
}

bool write_all(int fd, std::string_view s)
{
    while (!s.empty())
    {
        const ssize_t n = ::write(fd, s.data(), s.size());
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        s.remove_prefix(static_cast<size_t>(n));
    }
    return true;
}

}   // namespace

// A descriptor an operation in the ring may still name: closed once neither the index nor any operation holds it, so
// no number a closed descriptor had is reused under a write or a sync still on its way.
struct sync_index::held_fd
{
    int fd{-1};
    explicit held_fd(int f) : fd(f) {}
    held_fd(const held_fd&)            = delete;
    held_fd& operator=(const held_fd&) = delete;
    ~held_fd()
    {
        if (fd >= 0)
            ::close(fd);
    }
};

// A rewrite of the index beside it, which takes the name once all it holds is synced.
struct sync_index::rewrite
{
    std::shared_ptr<held_fd> file;
    std::string tmp;
    // Its bytes and records, the snapshot's and those carried in behind it.
    uint64_t    size{0};
    size_t      records{0};
    // What is being written into it, kept alive for the ring.
    std::shared_ptr<std::string> writing;
    // Records written to the old file since the snapshot was taken, still to be carried in.
    std::string tail;
    size_t      tail_records{0};
    // Its bytes up to `size` are on the disk.
    bool        synced{false};
};

sync_index::~sync_index()
{
    drop_rewrite();
    // What never reached the ring is written now, as a stop would have it; the loop owes this index nothing by now.
    if (m_file && !m_buf.empty())
    {
        if (::pwrite(m_file->fd, m_buf.data(), m_buf.size(), static_cast<off_t>(m_size - m_buf.size())) < 0) {}
    }
}

void sync_index::attach(file_io& io, std::function<void(const std::string&)> failed)
{
    m_io = &io;
    m_failed = std::move(failed);
}

void sync_index::fail(const std::string& why)
{
    if (m_failed)
        m_failed(why);
}

bool sync_index::open(std::string path, std::string_view scope, std::string& why)
{
    if (scope.size() > 65535)
    {
        why = "the sync scope is too long to index";
        return false;
    }
    // What a completion of the index opened before would act on is gone, and whoever waited on it is told so; its
    // descriptors close once the last operation naming them is done.
    ++*m_gen;
    drop_rewrite();
    m_syncing = m_writing = false;
    m_written = m_landed = m_synced = m_sync_wanted = 0;
    m_buf.clear();
    m_dir_dirty = false;
    for (auto& [at, then] : std::exchange(m_waiting, {}))
        then(false);
    m_file.reset();
    m_dir.reset();
    m_path = std::move(path);
    m_scope.assign(scope);
    m_live.clear();
    m_records = 0;
    m_stale = false;
    const size_t slash = m_path.rfind('/');
    const std::string dir = slash == std::string::npos ? "." : slash == 0 ? "/" : m_path.substr(0, slash);
    m_dir = std::make_shared<held_fd>(::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (m_dir->fd < 0)
    {
        why = dir + ": " + std::strerror(errno);
        return false;
    }

    std::string text;
    if (!socketley::read_file(m_path, text, {.missing_ok = true, .no_follow = true}, &why))
        return false;
    // Empty, or the magic cut short by a crash before anything was recorded.
    if (text.size() <= magic.size() && magic.starts_with(text))
        return write_fresh(why);
    if (!std::string_view(text).starts_with(magic))
    {
        why = m_path + " is not a sync index";
        return false;
    }

    size_t at = magic.size();
    bool scoped = false;
    while (at < text.size())
    {
        // A record cut short, or one its checksum disowns, is where the file ends; what came before it still counts.
        const size_t start = at;
        uint32_t len = 0, crc = 0;
        if (!take(text, at, &len, 4) || !take(text, at, &crc, 4) || len > max_body || at + len > text.size())
        {
            at = start;
            break;
        }
        const std::string_view body(text.data() + at, len);
        if (crc::crc32(body) != crc)
        {
            at = start;
            break;
        }
        at += len;

        size_t b = 0;
        char kind = 0;
        uint16_t tlen = 0, plen = 0;
        uint64_t size = 0;
        int64_t mtime = 0;
        uint8_t elen = 0;
        index_key key;
        index_entry e;
        if (!take(body, b, &kind, 1) || !take(body, b, &tlen, 2) || !take_str(body, b, tlen, key.target) ||
            !take(body, b, &plen, 2) || !take_str(body, b, plen, key.path) || !take(body, b, &size, 8) ||
            !take(body, b, &mtime, 8) || !take(body, b, &elen, 1) || !take_str(body, b, elen, e.etag) ||
            b != body.size())
        {
            at = start;
            break;
        }
        ++m_records;
        if (kind == 's')
        {
            // The records of another directory or prefix name other objects, so they are not read as this job's.
            if (key.path != m_scope)
                return write_fresh(why);
            scoped = true;
            continue;
        }
        if (!scoped)
            return write_fresh(why);
        e.size = size;
        e.mtime_ns = mtime;
        if (kind == 'p')
            m_live[key] = std::move(e);
        else
            m_live.erase(key);
    }
    if (!scoped)
        return write_fresh(why);

    m_file = std::make_shared<held_fd>(::open(m_path.c_str(), O_WRONLY | O_CLOEXEC | O_NOFOLLOW));
    if (m_file->fd < 0)
    {
        why = m_path + ": " + std::strerror(errno);
        m_file.reset();
        return false;
    }
    // A tail no record could be read from is cut off, so the next append is not written behind rubbish.
    if (at != text.size() && ::ftruncate(m_file->fd, static_cast<off_t>(at)) != 0)
    {
        why = m_path + ": " + std::strerror(errno);
        return false;
    }
    m_size = at;
    return true;
}

bool sync_index::write_fresh(std::string& why)
{
    m_live.clear();
    m_records = 0;
    // Not synced: a fresh index lost to a crash is an empty one, or the one it replaced, which is either empty, of
    // another scope or rubbish, and so begun again too. The first sync of a record syncs its bytes and its name.
    const std::string text = snapshot();
    int fd = -1;
    if (!write_beside(text, fd, why))
        return false;
    if (::rename((m_path + ".new").c_str(), m_path.c_str()) != 0)
    {
        why = m_path + ": " + std::strerror(errno);
        ::close(fd);
        ::unlink((m_path + ".new").c_str());
        return false;
    }
    m_file = std::make_shared<held_fd>(fd);
    m_size = text.size();
    m_records = 1;
    m_stale = false;
    m_dir_dirty = true;
    return true;
}

const index_entry* sync_index::find(std::string_view target, std::string_view path) const
{
    const auto it = m_live.find(index_key{std::string(target), std::string(path)});
    return it == m_live.end() ? nullptr : &it->second;
}

bool sync_index::append(std::string_view body, std::string& why)
{
    if (!m_file)
    {
        why = m_path + ": the index is not open";
        return false;
    }
    const std::string record = framed(body);
    if (m_io)
    {
        // Behind the write in flight, if any; a write of the file can wait out the disk while a sync of it is
        // under way, which the loop does not.
        m_buf += record;
        m_size += record.size();
    }
    else
    {
        if (::lseek(m_file->fd, static_cast<off_t>(m_size), SEEK_SET) < 0 || !write_all(m_file->fd, record))
        {
            why = m_path + ": " + std::strerror(errno);
            // What went in short is cut back, or the next record would be written behind half of this one.
            if (::ftruncate(m_file->fd, static_cast<off_t>(m_size)) != 0) {}
            return false;
        }
        m_size += record.size();
    }
    ++m_records;
    ++m_written;
    if (!m_io)
        m_landed = m_written;
    // A rewrite under way holds the live set as it was when it began, and this record goes in behind it.
    if (m_rewrite)
    {
        m_rewrite->tail += record;
        ++m_rewrite->tail_records;
    }
    write_next();
    return true;
}

bool sync_index::carried(std::string_view target, std::string_view path, const index_entry& e, std::string& why)
{
    if (path.size() > max_path || target.size() > 65535)
    {
        why = "a path of " + std::to_string(path.size()) + " bytes is longer than an index record holds";
        return false;
    }
    if (!append(body_of('p', target, path, e), why))
        return false;
    index_entry& kept = m_live[index_key{std::string(target), std::string(path)}];
    kept = e;
    if (kept.etag.size() > 255)
        kept.etag.resize(255);
    return true;
}

bool sync_index::gone(std::string_view target, std::string_view path, std::string& why)
{
    if (path.size() > max_path || target.size() > 65535)
    {
        why = "a path of " + std::to_string(path.size()) + " bytes is longer than an index record holds";
        return false;
    }
    if (!append(body_of('d', target, path, index_entry{}), why))
        return false;
    m_live.erase(index_key{std::string(target), std::string(path)});
    return true;
}

void sync_index::retain(const std::vector<std::string>& targets)
{
    const size_t before = m_live.size();
    std::erase_if(m_live, [&](const auto& kv) {
        return std::find(targets.begin(), targets.end(), kv.first.target) == targets.end();
    });
    if (m_live.size() != before)
        m_stale = true;
}

std::string sync_index::snapshot() const
{
    std::string out(magic);
    out += framed(body_of('s', {}, m_scope, index_entry{}));
    for (const auto& [k, e] : m_live)
        out += framed(body_of('p', k.target, k.path, e));
    return out;
}

bool sync_index::write_beside(const std::string& text, int& fd, std::string& why) const
{
    const std::string tmp = m_path + ".new";
    fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0)
    {
        why = tmp + ": " + std::strerror(errno);
        return false;
    }
    if (!write_all(fd, text))
    {
        why = tmp + ": " + std::strerror(errno);
        ::close(fd);
        fd = -1;
        ::unlink(tmp.c_str());
        return false;
    }
    return true;
}

void sync_index::drop_rewrite()
{
    if (!m_rewrite)
        return;
    // Its descriptor is closed by whichever of this and its operation in flight lets go of it last.
    ::unlink(m_rewrite->tmp.c_str());
    m_rewrite.reset();
}

// ─── WHAT IS ON THE DISK, AND IN WHAT ORDER ─────────────────────────────────
// The order a crash must not undo: a record is written only once what it records is on the disk (the storage answered
// the upload or the removal; a file brought or removed here has had its folder synced, sync_run::settle_folders), and
// a rewrite takes the index's name only once every record it holds is synced in it -- so the index
// can fall behind the files after a crash, which costs a file carried or a removal asked for once more under the
// condition it carries, but never runs ahead of them, and no step waits for its sync.
// Records are counted three times: queued (m_written), in the file (m_landed: one write in the ring at a time, in
// order) and on the disk (m_synced: a sync begun once they had landed, with the directory when a rename is not yet
// on the disk) -- and a sync is begun only when one was asked for.

bool sync_index::sync_here()
{
    if (!m_file)
        return true;
    if (::fdatasync(m_file->fd) != 0)
        return false;
    if (m_dir_dirty && m_dir && ::fsync(m_dir->fd) != 0)
        return false;
    m_dir_dirty = false;
    return true;
}

void sync_index::flush()
{
    if (m_io)
    {
        m_sync_wanted = m_written;
        write_next();
        sync_next();
        return;
    }
    if (m_synced < m_written && sync_here())
        m_synced = m_written;
}

void sync_index::when_durable(std::function<void(bool)> then)
{
    if (m_synced >= m_written || !m_file)
    {
        then(true);
        return;
    }
    if (!m_io)
    {
        const bool ok = sync_here();
        if (ok)
            m_synced = m_written;
        then(ok);
        return;
    }
    m_waiting.emplace_back(m_written, std::move(then));
    flush();
}

void sync_index::write_next()
{
    if (!m_io || m_writing || m_buf.empty() || !m_file)
        return;
    auto buf = std::make_shared<std::string>(std::move(m_buf));
    m_buf.clear();
    const uint64_t upto = m_written;
    const uint64_t at = m_size - buf->size();
    m_writing = true;
    const std::weak_ptr<uint64_t> life = m_gen;
    const uint64_t gen = *m_gen;
    auto file = m_file;
    auto done = [this, life, gen, buf, file, upto, at](int64_t res) {
        const auto g = life.lock();
        if (!g || *g != gen)
            return;
        m_writing = false;
        if (res < 0 && file == m_file)
        {
            // What went in short is cut back and given up, which a record may always be; the rewrite the index owes
            // now writes the live set again, these among it.
            fail(m_path + ": writing the index failed: " + std::strerror(static_cast<int>(-res)));
            if (::ftruncate(file->fd, static_cast<off_t>(at)) != 0) {}
            // The records behind it were not written yet, and go where it was meant to.
            m_size = at + m_buf.size();
            m_stale = true;
        }
        m_landed = std::max(m_landed, upto);
        install();
        sync_next();
        write_next();
    };
    if (buf->size() > (1u << 30) || !m_io->pwrite(file->fd, buf->data(), static_cast<uint32_t>(buf->size()), at, done))
    {
        // A ring with no room: this one write blocks, as every write did before the ring took them.
        ssize_t n = 0;
        for (size_t off = 0; off < buf->size(); off += static_cast<size_t>(n))
        {
            n = ::pwrite(file->fd, buf->data() + off, buf->size() - off, static_cast<off_t>(at + off));
            if (n < 0 && errno == EINTR)
            {
                n = 0;
                continue;
            }
            if (n <= 0)
                break;
        }
        done(n > 0 || buf->empty() ? 0 : -(n < 0 ? errno : EIO));
    }
}

void sync_index::sync_next()
{
    if (!m_io || m_syncing || !m_file || m_synced >= m_landed || m_sync_wanted <= m_synced)
        return;
    // A rename since the last sync is synced with this one, or the name could still point at the file before it.
    const bool dir = m_dir_dirty && m_dir;
    const uint64_t upto = m_landed;
    m_syncing = true;
    m_dir_dirty = false;
    struct both
    {
        int  left{1};
        bool ok{true};
    };
    auto state = std::make_shared<both>();
    state->left = dir ? 2 : 1;
    const std::weak_ptr<uint64_t> life = m_gen;
    const uint64_t gen = *m_gen;
    auto file = m_file;
    auto dirfd = m_dir;
    auto done = [this, life, gen, state, dir, upto, file, dirfd](int64_t res) {
        if (res < 0)
            state->ok = false;
        if (--state->left > 0)
            return;
        const auto g = life.lock();
        if (!g || *g != gen)
            return;
        if (!state->ok && dir)
            m_dir_dirty = true;
        synced(upto, state->ok);
    };
    if (!m_io->fsync(file->fd, true, done))
    {
        // A ring with no room: this one sync blocks, as every sync did before the ring took them.
        m_syncing = false;
        m_dir_dirty = m_dir_dirty || dir;
        synced(upto, sync_here());
        return;
    }
    if (dir && !m_io->fsync(dirfd->fd, false, done))
        done(::fsync(dirfd->fd) == 0 ? 0 : -errno);
}

void sync_index::synced(uint64_t upto, bool ok)
{
    m_syncing = false;
    if (ok)
        m_synced = std::max(m_synced, upto);
    else
        fail(m_path + ": syncing the index failed, so what it records since may be carried again after a crash");
    // A rewrite that waited for this sync, which named the old file, takes the name now.
    install();
    // Whoever waits is told of a failure, since no sync is begun again on its own to answer them later.
    std::vector<std::function<void(bool)>> due;
    std::erase_if(m_waiting, [&](auto& w) {
        if (ok && w.first > m_synced)
            return false;
        due.push_back(std::move(w.second));
        return true;
    });
    for (auto& then : due)
        then(ok);
    // What landed meanwhile and was asked to be synced is, by the next sync; a failed one is tried again only when
    // asked again, not at once and again and again.
    if (ok)
        sync_next();
    else
        m_sync_wanted = m_synced;
}

bool sync_index::compact(std::string& why, bool force)
{
    // Twice the live set is where the dead records cost more to read than the rewrite costs to make.
    if (!force && !m_stale && (m_records < 64 || m_records < m_live.size() * 2))
        return true;
    // One at a time: the end of the next walk asks again if this one still leaves too many dead records.
    if (m_rewrite)
        return true;
    if (!m_io)
    {
        // Written beside and renamed, so a crash during the rewrite leaves the old whole file and not half a new one.
        const std::string text = snapshot();
        int fd = -1;
        if (!write_beside(text, fd, why))
            return false;
        if (::fdatasync(fd) != 0 || ::rename((m_path + ".new").c_str(), m_path.c_str()) != 0)
        {
            ::close(fd);
            ::unlink((m_path + ".new").c_str());
            why = m_path + ": the index could not be written again";
            return false;
        }
        m_file = std::make_shared<held_fd>(fd);
        m_size = text.size();
        m_records = 1 + m_live.size();
        m_stale = false;
        m_dir_dirty = true;
        return true;
    }
    auto rw = std::make_shared<rewrite>();
    rw->tmp = m_path + ".new";
    rw->file = std::make_shared<held_fd>(::open(rw->tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600));
    if (rw->file->fd < 0)
    {
        why = rw->tmp + ": " + std::strerror(errno);
        return false;
    }
    rw->writing = std::make_shared<std::string>(snapshot());
    rw->records = 1 + m_live.size();
    m_rewrite = rw;
    m_stale = false;
    rewrite_step();
    return true;
}

void sync_index::rewrite_failed(const std::string& why)
{
    fail(m_path + ": the index could not be written again: " + why);
    drop_rewrite();
    m_stale = true;
}

void sync_index::rewrite_step()
{
    std::shared_ptr<rewrite> rw = m_rewrite;
    rw->synced = false;
    const std::weak_ptr<uint64_t> life = m_gen;
    const uint64_t gen = *m_gen;
    // Its bytes are written, then synced; what was recorded meanwhile goes in behind them the same way (install()).
    auto synced_cb = [this, life, gen, rw](int64_t res) {
        const auto g = life.lock();
        if (!g || *g != gen || m_rewrite != rw)
            return;
        if (res < 0)
        {
            rewrite_failed(std::strerror(static_cast<int>(-res)));
            return;
        }
        rw->synced = true;
        install();
    };
    auto written_cb = [this, life, gen, rw, synced_cb](int64_t res) {
        const auto g = life.lock();
        if (!g || *g != gen || m_rewrite != rw)
            return;
        if (res < 0)
        {
            rewrite_failed(std::strerror(static_cast<int>(-res)));
            return;
        }
        rw->size += rw->writing->size();
        rw->writing.reset();
        if (!m_io->fsync(rw->file->fd, true, synced_cb))
            rewrite_failed("the ring has no room");
    };
    if (rw->writing->size() > (1u << 30) ||
        !m_io->pwrite(rw->file->fd, rw->writing->data(), static_cast<uint32_t>(rw->writing->size()), rw->size,
                      written_cb))
        rewrite_failed("the ring has no room");
}

void sync_index::install()
{
    std::shared_ptr<rewrite> rw = m_rewrite;
    if (!rw || !rw->synced)
        return;
    // What was recorded while it was written goes in behind the snapshot, and is synced in turn before the rename.
    if (!rw->tail.empty())
    {
        rw->writing = std::make_shared<std::string>(std::move(rw->tail));
        rw->tail.clear();
        rw->records += rw->tail_records;
        rw->tail_records = 0;
        rewrite_step();
        return;
    }
    // A write or a sync in flight names the old file; whichever ends last installs this.
    if (m_syncing || m_writing)
        return;
    m_rewrite.reset();
    if (::rename(rw->tmp.c_str(), m_path.c_str()) != 0)
    {
        fail(m_path + ": the index could not be written again: " + std::strerror(errno));
        ::unlink(rw->tmp.c_str());
        m_stale = true;
        return;
    }
    // Every record queued so far is in it and synced: those still waiting for the old file are not written there.
    m_file = rw->file;
    m_size = rw->size;
    m_records = rw->records;
    m_buf.clear();
    m_landed = m_written;
    // Every one counted on the disk is in whichever file the name is at after a crash; the next sync makes the name
    // the new file's, before what follows is counted.
    m_dir_dirty = true;
    sync_next();
}

}   // namespace socketley::sync
