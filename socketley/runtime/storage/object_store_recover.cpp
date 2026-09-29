// Starting a store from what a previous run, or a crash, left on disk.
//
// All of this is blocking on purpose: it runs in setup(), before the listener
// is bound, so no connection can wait behind it and the ring is not asked for
// anything.  Nothing here runs once the runtime serves.
#include "object_store.h"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <ctime>
#include <filesystem>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "s3_names.h"
#include "../../shared/logging.h"

namespace fs = std::filesystem;

namespace socketley::storage
{

namespace
{

std::string errstr(int e) { return std::strerror(e); }

bool write_all_fd(int fd, const char* p, size_t n)
{
    while (n)
    {
        const ssize_t w = ::write(fd, p, n);
        if (w < 0)
        {
            if (errno == EINTR)
                continue;
            return false;
        }
        p += w;
        n -= static_cast<size_t>(w);
    }
    return true;
}

bool fsync_dir_path(const std::string& path)
{
    const int fd = ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return false;
    const bool ok = ::fsync(fd) == 0;
    ::close(fd);
    return ok;
}

// A whole small file, empty on any failure.
std::string slurp(const std::string& path)
{
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return {};
    std::string out;
    char buf[4096];
    for (;;)
    {
        const ssize_t n = ::read(fd, buf, sizeof buf);
        if (n <= 0)
            break;
        out.append(buf, static_cast<size_t>(n));
        if (out.size() > 4096)
            break;
    }
    ::close(fd);
    return out;
}

int64_t wall_ms()
{
    struct timespec ts{};
    ::clock_gettime(CLOCK_REALTIME, &ts);
    return static_cast<int64_t>(ts.tv_sec) * 1000 + ts.tv_nsec / 1000000;
}

// The shard a tmp/ entry belongs to, from the "<shard>." its name begins with,
// and false for a name that has none.
bool tmp_owner(const std::string& name, uint32_t& shard)
{
    const size_t dot = name.find('.');
    if (dot == 0 || dot == std::string::npos || dot > 3)
        return false;
    const auto r = std::from_chars(name.data(), name.data() + dot, shard);
    return r.ec == std::errc{} && r.ptr == name.data() + dot;
}

// Removes this shard's own tmp/ files, and for shard 0 those of no shard of the split, never a sibling's upload in flight.
uint64_t clean_tmp(const std::string& path, uint32_t shard, uint32_t nshards)
{
    uint64_t n = 0;
    std::error_code ec;
    for (const auto& e : fs::directory_iterator(path, ec))
    {
        uint32_t who = 0;
        const bool named  = tmp_owner(e.path().filename().string(), who);
        const bool mine   = named && who == shard;
        const bool orphan = !named || who >= nshards;
        if (!mine && !(shard == 0 && orphan))
            continue;
        std::error_code rc;
        fs::remove_all(e.path(), rc);
        ++n;
    }
    return n;
}

// The number in the "<prefix><k>" a marker or a journal is named by, false
// when the name is not of that form.
bool suffix_number(const std::string& name, std::string_view prefix, uint32_t& k)
{
    if (!name.starts_with(prefix) || name.size() == prefix.size())
        return false;
    const auto r = std::from_chars(name.data() + prefix.size(), name.data() + name.size(), k);
    return r.ec == std::errc{} && r.ptr == name.data() + name.size();
}

}   // namespace

bool object_store::open(std::string& err, recovery_report* report)
{
    recovery_report rep;
    std::error_code ec;

    fs::create_directories(m_opts.dir, ec);
    if (ec)
    {
        err = "cannot create " + m_opts.dir + ": " + ec.message();
        return false;
    }
    m_root_fd = ::open(m_opts.dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (m_root_fd < 0)
    {
        err = "cannot open " + m_opts.dir + ": " + errstr(errno);
        return false;
    }

    // A bucket deleted by a rename into .trash is removed here, where walking
    // its tree blocks nobody.  Shard 0 alone does it, because it is also the
    // shard that renames buckets into it while the others may be restarting.
    const std::string trash = m_opts.dir + "/.trash";
    if (m_opts.shard == 0)
        fs::remove_all(trash, ec);
    if (::mkdir(trash.c_str(), 0700) < 0 && errno != EEXIST)
    {
        err = "cannot create " + trash + ": " + errstr(errno);
        return false;
    }

    // The marker of a stop that left nothing in flight, taken down before
    // anything is served so a crash from here on does not look like one.
    const std::string marker = m_opts.dir + "/.clean." + std::to_string(m_opts.shard);
    const bool clean = ::access(marker.c_str(), F_OK) == 0;
    if (clean)
    {
        if (::unlink(marker.c_str()) < 0) {}
        if (::fsync(m_root_fd) < 0) {}
    }
    rep.clean_start = clean;
    m_clean_start   = clean;

    // The marker of a shard the split no longer has, which a later split that
    // brings the number back would otherwise trust for a journal it never wrote.
    if (m_opts.shard == 0)
        for (const auto& e : fs::directory_iterator(m_opts.dir, ec))
        {
            uint32_t k = 0;
            if (suffix_number(e.path().filename().string(), ".clean.", k) && k >= m_opts.nshards)
                if (::unlink(e.path().c_str()) < 0) {}
        }

    std::vector<std::string> names;
    for (const auto& e : fs::directory_iterator(m_opts.dir, ec))
    {
        const std::string n = e.path().filename().string();
        if (n.empty() || n[0] == '.')
            continue;
        std::error_code dc;
        if (!e.is_directory(dc))
            continue;
        if (!valid_bucket_name(n))
        {
            LOG_WARN(("storage: ignoring the directory \"" + n + "\", which is not a bucket name").c_str());
            continue;
        }
        names.push_back(n);
    }
    std::sort(names.begin(), names.end());

    for (const std::string& n : names)
        if (!recover_bucket(n, rep, err))
            return false;

    m_totals.buckets = m_buckets.size();
    if (report)
        *report = rep;
    return true;
}

bool object_store::recover_bucket(const std::string& name, recovery_report& rep, std::string& err)
{
    const std::string base = m_opts.dir + "/" + name;
    auto b = std::make_unique<bucket>();
    b->name = name;

    for (const char* sub : {"data", "tmp"})
        if (::mkdir((base + "/" + sub).c_str(), 0755) < 0 && errno != EEXIST)
        {
            err = "cannot create " + base + "/" + sub + ": " + errstr(errno);
            return false;
        }

    // The 256 object directories are there before the first put wants one; a
    // bucket that lacks some is given them now and synced once.
    {
        bool made = false;
        static constexpr char digits[] = "0123456789abcdef";
        for (int i = 0; i < 256; ++i)
        {
            const char n[3] = {digits[i >> 4], digits[i & 15], 0};
            if (::mkdir((base + "/data/" + n).c_str(), 0755) == 0)
                made = true;
            else if (errno != EEXIST)
            {
                err = "cannot create " + base + "/data/" + n + ": " + errstr(errno);
                return false;
            }
        }
        if (made && !fsync_dir_path(base + "/data"))
        {
            err = "cannot sync " + base + "/data: " + errstr(errno);
            return false;
        }
    }

    // When the bucket came to be, kept in a file of its own because a
    // directory's mtime moves with every object written under it.
    {
        const std::string created = slurp(base + "/created");
        int64_t ms = 0;
        const auto r = std::from_chars(created.data(), created.data() + created.size(), ms);
        if (created.empty() || r.ec != std::errc{})
        {
            struct stat sb{};
            ms = ::stat(base.c_str(), &sb) == 0
                     ? static_cast<int64_t>(sb.st_mtim.tv_sec) * 1000
                     : wall_ms();
            // Shard 0 writes it, since two shards truncating one file at once could
            // leave each reading the other's half.
            const int fd = m_opts.shard != 0 ? -1
                : ::open((base + "/created").c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
            if (fd >= 0)
            {
                const std::string t = std::to_string(ms);
                if (write_all_fd(fd, t.data(), t.size()) && ::fsync(fd) == 0) {}
                ::close(fd);
            }
        }
        b->created_ms = ms;
    }

    b->dir_fd  = ::open(base.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    b->data_fd = ::open((base + "/data").c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    b->tmp_fd  = ::open((base + "/tmp").c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (b->dir_fd < 0 || b->data_fd < 0 || b->tmp_fd < 0)
    {
        err = "cannot open the directories of bucket " + name + ": " + errstr(errno);
        return false;
    }

    rep.tmp_removed += clean_tmp(base + "/tmp", m_opts.shard, m_opts.nshards);

    // The journals of shards the split no longer has hold keys some other shard
    // owns now; they are read by nobody and would be trusted by a later split.
    if (m_opts.shard == 0)
    {
        std::error_code ec;
        for (const auto& e : fs::directory_iterator(base, ec))
        {
            const std::string fn = e.path().filename().string();
            uint32_t k = 0;
            const bool stale_new = fn.ends_with(".new") &&
                                   suffix_number(fn.substr(0, fn.size() - 4), "index.", k);
            if ((stale_new && k >= m_opts.nshards) ||
                (suffix_number(fn, "index.", k) && k >= m_opts.nshards))
                if (::unlink(e.path().c_str()) < 0) {}
        }
    }

    std::string why;
    bool torn = false, corrupt = false, other_layout = false;
    const bool loaded = load_journal(*b, why, torn, corrupt, other_layout, rep);
    if (!loaded)
    {
        err = why;
        return false;
    }

    // The files are consulted when the last stop was not clean, when the
    // journal could not be trusted, when it was written for another split,
    // and when it is missing.
    bool changed = false;
    if (other_layout)
    {
        changed = true;
        LOG_INFO(("storage: the journal of bucket " + name + " was written for another shard count; "
                  "this shard's keys are rebuilt from the object files").c_str());
    }
    if (!m_clean_start || corrupt || torn || other_layout)
    {
        const uint64_t before = rep.adopted + rep.dropped;
        reconcile_with_files(*b, rep);
        changed = rep.adopted + rep.dropped != before;
        if (corrupt)
        {
            ++rep.rebuilt_journals;
            changed = true;
            LOG_WARN(("storage: the journal of bucket " + name +
                      " is damaged and was rebuilt from the object files").c_str());
        }
    }

    uint64_t bytes = 0;
    for (const auto& [k, m] : b->objects)
        bytes += m.size;
    b->bytes = bytes;

    const bool garbage = b->j.records > m_opts.compact_floor &&
                         b->j.records > 2 * (b->objects.size() + 1);
    if (changed || garbage || torn)
        if (!rewrite_journal_sync(*b, err))
            return false;

    b->j.compact_after = 0;
    m_totals.objects += b->objects.size();
    m_totals.bytes += b->bytes;
    m_totals.journal_records += b->j.records;
    rep.objects += b->objects.size();
    ++rep.buckets;
    m_buckets.emplace(name, std::move(b));
    return true;
}

bool object_store::load_journal(bucket& b, std::string& bad_why, bool& torn, bool& corrupt,
                                bool& other_layout, recovery_report& rep)
{
    const std::string path = m_opts.dir + "/" + b.name + "/index." + std::to_string(m_opts.shard);
    int fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0644);
    if (fd < 0)
    {
        bad_why = "cannot open " + path + ": " + errstr(errno);
        return false;
    }

    struct stat sb{};
    if (::fstat(fd, &sb) < 0)
    {
        bad_why = "cannot stat " + path + ": " + errstr(errno);
        ::close(fd);
        return false;
    }

    uint64_t valid_end = 0;
    if (sb.st_size == 0)
    {
        const std::string h = encode_journal_header(m_opts.shard, m_opts.nshards);
        if (!write_all_fd(fd, h.data(), h.size()) || ::fsync(fd) < 0)
        {
            bad_why = "cannot write " + path + ": " + errstr(errno);
            ::close(fd);
            return false;
        }
        valid_end = h.size();
    }
    else
    {
        std::string head(journal_header_len, '\0');
        const bool read_ok = ::pread(fd, head.data(), head.size(), 0) == static_cast<ssize_t>(head.size());
        const journal_header_status hs = read_ok ? journal_header_check(head, m_opts.shard, m_opts.nshards)
                                                 : journal_header_status::bad;
        if (hs == journal_header_status::other_layout)
        {
            // Sound, and written for another split: what it holds is not this
            // shard's to trust, and the object files are the record to go by.
            other_layout = true;
            valid_end    = 0;
        }
        else if (hs != journal_header_status::ok)
        {
            // Not a journal of ours, so everything it says is unusable and the
            // files are the only record left.
            corrupt   = true;
            valid_end = 0;
        }
        else
        {
            valid_end = journal_header_len;
            // In pieces, because a journal is as large as the bucket is old.
            constexpr size_t piece = 4u << 20;
            std::string buf;
            uint64_t    pos   = journal_header_len;
            uint64_t    total = static_cast<uint64_t>(sb.st_size);
            bool        eof   = false;
            std::string_view view;
            size_t      consumed = 0;

            while (!corrupt && !eof)
            {
                if (buf.size() - consumed < 128 * 1024 && pos < total)
                {
                    buf.erase(0, consumed);
                    consumed = 0;
                    const size_t want = static_cast<size_t>(std::min<uint64_t>(piece, total - pos));
                    const size_t old  = buf.size();
                    buf.resize(old + want);
                    const ssize_t n = ::pread(fd, buf.data() + old, want, static_cast<off_t>(pos));
                    if (n <= 0)
                    {
                        buf.resize(old);
                        eof = true;
                        break;
                    }
                    buf.resize(old + static_cast<size_t>(n));
                    pos += static_cast<uint64_t>(n);
                }
                view = std::string_view(buf).substr(consumed);
                if (view.empty())
                {
                    eof = true;
                    break;
                }
                const decoded_record d = decode_journal_record(view);
                if (d.status == record_status::ok)
                {
                    if (d.rec.type == record_type::put)
                        b.objects[d.rec.key] = d.rec.meta;
                    else
                        b.objects.erase(d.rec.key);
                    ++b.j.records;
                    consumed += d.consumed;
                    valid_end += d.consumed;
                    continue;
                }
                // What ends the journal is a torn tail when nothing follows it
                // that could be a record, and damage when the file goes on.
                const bool at_end = pos >= total;
                if (at_end && d.status == record_status::torn)
                {
                    torn = true;
                    ++rep.torn_tails;
                    break;
                }
                if (at_end && d.status == record_status::corrupt)
                {
                    // A last record that fails its checksum, or a tail the
                    // filesystem zero-filled, is a write that reached the disk
                    // in part.
                    uint32_t len = 0;
                    if (view.size() >= 4)
                        std::memcpy(&len, view.data(), 4);
                    const bool reaches_end = len > 0 && len <= 64u * 1024u &&
                                             8u + len >= view.size();
                    const bool zeros = std::all_of(view.begin(), view.end(),
                                                   [](char c) { return c == '\0'; });
                    if (reaches_end || zeros)
                    {
                        torn = true;
                        ++rep.torn_tails;
                        break;
                    }
                }
                corrupt = true;
            }
        }
    }

    if (corrupt || other_layout)
    {
        b.objects.clear();
        b.j.records = 0;
        valid_end   = 0;
    }
    // A torn tail is cut off by the rewrite the caller does for it, which is
    // what puts the next append on a record boundary.

    b.j.fd  = fd;
    b.j.off = valid_end;
    return true;
}

void object_store::reconcile_with_files(bucket& b, recovery_report& rep)
{
    const std::string data = m_opts.dir + "/" + b.name + "/data";
    std::unordered_set<std::string_view> seen;
    std::error_code ec;

    for (fs::recursive_directory_iterator it(data, ec), end; !ec && it != end; it.increment(ec))
    {
        std::error_code fc;
        if (!it->is_regular_file(fc))
            continue;
        const std::string fname = it->path().filename().string();
        if (fname.size() != 64)
            continue;

        const int fd = ::open(it->path().c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0)
            continue;

        struct stat sb{};
        std::string head(object_header_align, '\0');
        ssize_t n = ::fstat(fd, &sb) == 0
                        ? ::pread(fd, head.data(), head.size(), 0)
                        : -1;
        decoded_header d;
        if (n >= 0)
        {
            head.resize(static_cast<size_t>(n));
            d = decode_object_header(head);
            if (d.status == header_status::need_more && d.need <= 64 * 1024)
            {
                head.resize(d.need);
                n = ::pread(fd, head.data(), head.size(), 0);
                if (n >= 0)
                {
                    head.resize(static_cast<size_t>(n));
                    d = decode_object_header(head);
                }
            }
        }
        ::close(fd);

        const bool sound = n >= 0 && d.status == header_status::ok &&
                           key_hash(d.key) == fname &&
                           static_cast<uint64_t>(sb.st_size) == d.header_len + d.meta.size;
        if (!sound)
        {
            // Every shard walks every file, so one of them says so.
            if (m_opts.shard == 0)
            {
                ++rep.corrupt_files;
                LOG_WARN(("storage: " + it->path().string() +
                          " is not a whole object file and is left unserved").c_str());
            }
            continue;
        }
        // A sibling's object, which its own journal and its own start deal with.
        if (!owns(b.name, d.key))
            continue;

        auto found = b.objects.find(d.key);
        if (found == b.objects.end())
        {
            found = b.objects.emplace(d.key, d.meta).first;
            ++rep.adopted;
        }
        else if (!(found->second == d.meta))
        {
            found->second = d.meta;
            ++rep.adopted;
        }
        seen.insert(found->first);
    }

    for (auto it = b.objects.begin(); it != b.objects.end();)
    {
        if (seen.contains(std::string_view(it->first)))
            ++it;
        else
        {
            ++rep.dropped;
            it = b.objects.erase(it);
        }
    }
}

bool object_store::rewrite_journal_sync(bucket& b, std::string& err)
{
    const std::string base = m_opts.dir + "/" + b.name + "/";
    const std::string live = base + "index." + std::to_string(m_opts.shard);
    const std::string tmp  = live + ".new";

    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0)
    {
        err = "cannot write " + tmp + ": " + errstr(errno);
        return false;
    }

    std::string buf = encode_journal_header(m_opts.shard, m_opts.nshards);
    uint64_t    off = 0;
    bool        ok  = true;
    for (const auto& [k, m] : b.objects)
    {
        encode_put_record(buf, k, m);
        if (buf.size() >= (1u << 20))
        {
            ok = ok && write_all_fd(fd, buf.data(), buf.size());
            off += buf.size();
            buf.clear();
        }
    }
    ok = ok && write_all_fd(fd, buf.data(), buf.size());
    off += buf.size();
    ok = ok && ::fsync(fd) == 0;
    if (!ok)
    {
        err = "cannot write " + tmp + ": " + errstr(errno);
        ::close(fd);
        return false;
    }
    if (::rename(tmp.c_str(), live.c_str()) < 0)
    {
        err = "cannot replace " + live + ": " + errstr(errno);
        ::close(fd);
        return false;
    }
    if (!fsync_dir_path(base))
    {
        err = "cannot sync " + base + ": " + errstr(errno);
        ::close(fd);
        return false;
    }

    if (b.j.fd >= 0)
        ::close(b.j.fd);
    b.j.fd      = fd;
    b.j.off     = off;
    b.j.records = b.objects.size();
    return true;
}

bool object_store::settle_journals()
{
    for (auto& [name, b] : m_buckets)
    {
        if (b->j.frozen)
            return false;
        // A write still in the ring is written again here at the same offset
        // with the same bytes, which lands as it would have, so this need not
        // wait for a ring that is being torn down.
        std::string all = b->j.inflight + b->j.pending;
        const char* p   = all.data();
        size_t      n   = all.size();
        off_t       off = static_cast<off_t>(b->j.off);
        while (n)
        {
            const ssize_t w = ::pwrite(b->j.fd, p, n, off);
            if (w < 0)
            {
                if (errno == EINTR)
                    continue;
                return false;
            }
            p += w;
            n -= static_cast<size_t>(w);
            off += w;
        }
        if ((!all.empty() || b->j.dirty) && ::fdatasync(b->j.fd) < 0)
            return false;
    }
    return true;
}

void object_store::close(bool clean)
{
    *m_alive = false;

    // The marker only when nothing is half done, because a stop that left a
    // rename without its journal record is exactly what the next start must
    // go and look for.
    if (clean && !working() && !m_journal_lost && settle_journals() && m_root_fd >= 0)
    {
        const std::string marker = m_opts.dir + "/.clean." + std::to_string(m_opts.shard);
        const int fd = ::open(marker.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
        if (fd >= 0)
        {
            if (::fsync(fd) < 0) {}
            ::close(fd);
            if (::fsync(m_root_fd) < 0) {}
        }
    }

    for (auto& [name, b] : m_buckets)
    {
        for (int* fd : {&b->dir_fd, &b->data_fd, &b->tmp_fd, &b->j.fd, &b->dump_fd})
            if (*fd >= 0)
            {
                m_loop->close_fd(*fd);
                *fd = -1;
            }
    }
    m_buckets.clear();
    if (m_root_fd >= 0)
    {
        m_loop->close_fd(m_root_fd);
        m_root_fd = -1;
    }
}

}   // namespace socketley::storage
