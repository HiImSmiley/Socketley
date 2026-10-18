// Starting a store from what a previous run, or a crash, left on disk.
//
// All of this is blocking on purpose: it runs in setup(), before the listener
// is bound, so no connection can wait behind it and the ring is not asked for
// anything.  Nothing here runs once the runtime serves, which is also why the
// walk of the object files may take threads: they have joined before it does.
#include "object_store.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <system_error>
#include <thread>

#include <dirent.h>
#include <fcntl.h>
#include <liburing.h>
#include <sched.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include "lifecycle.h"
#include "s3_cors.h"
#include "s3_names.h"
#include "s3_notify.h"
#include "shard_owner.h"
#include "../../shared/util/logging.h"

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

// A whole small file, empty on any failure, and cut after `max` bytes.
std::string slurp(const std::string& path, size_t max = 4096)
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
        if (out.size() > max)
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
uint64_t clean_tmp(const std::string& path, uint32_t shard, uint32_t nshards,
                   const std::unordered_set<std::string>& keep)
{
    uint64_t n = 0;
    std::error_code ec;
    for (const auto& e : fs::directory_iterator(path, ec))
    {
        if (keep.contains(e.path().filename().string()))
            continue;
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

// The size of the buffer a directory is read into, some fifteen hundred names at a time.
constexpr size_t dents_bytes = 128 * 1024;

// Headers each thread of the walk has in flight, so that a cold disk has many reads to work on at once.
constexpr unsigned walk_depth = 32;

// What one object directory holds, as its files' headers say.
struct dir_scan
{
    // Keys of the journal whose file says exactly what the journal does.
    std::vector<const std::string*> matched;
    // Files the journal lacks, or describes otherwise.
    std::vector<std::pair<std::string, object_meta>> differ;
    // Below the bucket directory, the files that are not whole object files.
    std::vector<std::string> unsound;
    // Delete markers at their keys' usual paths, and the versions in versions/, which the journal is not matched against.
    std::vector<std::pair<std::string, object_meta>> versions;
    uint64_t files_read{0};
    // Why the directory could not be read whole, which fails the start rather than drop what went unseen.
    int failed{0};
};

// An error that says nothing about the file and everything about the moment, such as a descriptor table that is full.
bool transient(int e)
{
    return e == EMFILE || e == ENFILE || e == ENOMEM || e == EAGAIN || e == EINTR;
}

size_t open_fds()
{
    size_t n = 0;
    std::error_code ec;
    for (fs::directory_iterator it("/proc/self/fd", ec), end; !ec && it != end; it.increment(ec))
        ++n;
    return n;
}

// How many threads walk the object files and how many headers each has in flight.
struct walk_shape
{
    unsigned threads{1};
    // Zero reads one file at a time, without a ring.
    unsigned depth{0};
};

unsigned env_count(const char* name, unsigned fallback, unsigned lo, unsigned hi)
{
    if (const char* e = std::getenv(name))
    {
        char* end;
        const long v = std::strtol(e, &end, 10);
        if (end != e && *end == '\0' && v >= static_cast<long>(lo) && v <= static_cast<long>(hi))
            return static_cast<unsigned>(v);
    }
    return fallback;
}

walk_shape recovery_shape()
{
    walk_shape w;
    // One thread per CPU this process may use, so a pinned runtime stays on its pin.
    cpu_set_t set;
    CPU_ZERO(&set);
    const unsigned cpus = ::sched_getaffinity(0, sizeof set, &set) == 0
                              ? static_cast<unsigned>(std::clamp(CPU_COUNT(&set), 1, 16))
                              : 1u;
    w.threads = env_count("SOCKETLEY_STORAGE_RECOVERY_THREADS", cpus, 1, 64);
    w.depth   = env_count("SOCKETLEY_STORAGE_RECOVERY_DEPTH", walk_depth, 0, 256);

    // Half of what RLIMIT_NOFILE leaves, since every thread holds a directory, a ring and its files.
    struct rlimit rl{};
    if (::getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY)
    {
        const size_t used   = open_fds();
        const size_t budget = rl.rlim_cur > used ? (rl.rlim_cur - used) / 2 : 0;
        while (w.threads > 1 && budget < 3u * w.threads)
            --w.threads;
        const size_t per = budget / w.threads;
        w.depth = static_cast<unsigned>(std::min<size_t>(w.depth, per > 2 ? per - 2 : 0));
    }
    return w;
}

enum class file_verdict : uint8_t { skip, unsound, ok, failed };

// What a thread of the walk keeps from file to file: the digest files are named by, and whose keys it looks at.
struct walker
{
    const EVP_MD*    md{fetched_sha256()};
    EVP_MD_CTX*      ctx{EVP_MD_CTX_new()};
    std::string_view bucket;
    uint32_t         shard{0};
    uint32_t         nshards{1};
    // The directory walked is one of versions/, whose files are named <hash>.<id>.
    bool             versions{false};

    walker() = default;
    walker(const walker&)            = delete;
    walker& operator=(const walker&) = delete;
    ~walker()
    {
        EVP_MD_CTX_free(ctx);
    }

    // Whether `name` is the hash of `key`, the one name a file of that key may have.
    bool named_for(std::string_view key, std::string_view name)
    {
        uint8_t  out[EVP_MAX_MD_SIZE];
        unsigned len = 0;
        if (!md || !ctx || EVP_DigestInit_ex(ctx, md, nullptr) != 1 ||
            EVP_DigestUpdate(ctx, key.data(), key.size()) != 1 || EVP_DigestFinal_ex(ctx, out, &len) != 1)
            return key_hash(key) == name;
        return hex(out, len) == name;
    }

    // A key another shard owns is none of this one's business, except shard 0's, which says which files are not whole.
    bool ignores(std::string_view key) const
    {
        return nshards > 1 && shard != 0 && object_owner(bucket, key, nshards) != shard;
    }
};

// Whether `name` is the one a file of the version `d` decoded may have: its key's hash, and in versions/ its id after it.
bool named_right(walker& w, const decoded_header& d, std::string_view name)
{
    if (!w.versions)
        return w.named_for(d.key, name);
    return name.size() > 65 && w.named_for(d.key, name.substr(0, 64)) && version_id_of(d.meta) == name.substr(65);
}

// The verdict on an open object file whose first `n` bytes are in `head`, or -errno, which closes it.
file_verdict judge_object_file(walker& w, int fd, const struct stat& sb, const char* name, std::string& head,
                               ssize_t n, decoded_header& d, int& why)
{
    if (n >= 0)
    {
        head.resize(static_cast<size_t>(n));
        d = decode_object_header(head);
        if (d.status == header_status::need_more && d.need <= 64 * 1024)
        {
            head.resize(d.need);
            n = ::pread(fd, head.data(), head.size(), 0);
            if (n < 0)
                n = -errno;
            if (n >= 0)
            {
                head.resize(static_cast<size_t>(n));
                d = decode_object_header(head);
            }
        }
    }
    ::close(fd);

    // A read the moment refused says nothing about the file, which is still there to be judged on the next walk.
    if (n < 0 && transient(static_cast<int>(-n)))
    {
        why = static_cast<int>(-n);
        return file_verdict::failed;
    }
    if (n >= 0 && d.status == header_status::ok && w.ignores(d.key))
        return file_verdict::skip;
    const bool sound = n >= 0 && d.status == header_status::ok &&
                       static_cast<uint64_t>(sb.st_size) == d.header_len + stored_size(d.meta) &&
                       named_right(w, d, name);
    return sound ? file_verdict::ok : file_verdict::unsound;
}

// A name the walk found, and whether it is to be followed to a regular file first.
struct dir_entry
{
    uint32_t      at;
    unsigned char type;
};

// A file that is no regular file, followed, as a link to an object file was always read as one.
bool regular(int dir_fd, const char* name, unsigned char type)
{
    if (type == DT_REG)
        return true;
    struct stat lb{};
    return (type == DT_UNKNOWN || type == DT_LNK) && ::fstatat(dir_fd, name, &lb, 0) == 0 && S_ISREG(lb.st_mode);
}

// What a failed open of an object file means: nothing when the file cannot be opened, a failed walk when the moment is to blame.
file_verdict open_failed(int e, int& why)
{
    if (!transient(e))
        return file_verdict::skip;
    why = e;
    return file_verdict::failed;
}

// One file at a time, for a walk that has no ring.
template <typename V>
void read_files_one_by_one(walker& w, int dfd, const std::vector<dir_entry>& es, const std::string& names,
                           std::string& head, int& why, V&& verdict)
{
    for (const dir_entry& e : es)
    {
        const char* name = names.data() + e.at;
        if (!regular(dfd, name, e.type))
            continue;
        decoded_header d;
        const int fd = ::openat(dfd, name, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
        {
            verdict(name, open_failed(errno, why), d);
            continue;
        }
        struct stat sb{};
        head.resize(object_header_align);
        ssize_t n = ::fstat(fd, &sb) == 0 ? ::pread(fd, head.data(), head.size(), 0) : -1;
        if (n < 0)
            n = -errno;
        verdict(name, judge_object_file(w, fd, sb, name, head, n, d, why), d);
    }
}

// A slot of the ring's window: one file between its open and its verdict.
struct ring_slot
{
    std::string head;
    struct stat sb{};
    int         fd{-1};
    uint32_t    e{0};
};

// Every file of `es` opened and its header read through `ring`, as many at once as there are slots.
template <typename V>
void read_files_ring(walker& w, io_uring* ring, int dfd, const std::vector<dir_entry>& es, const std::string& names,
                     std::vector<ring_slot>& slots, int& why, V&& verdict)
{
    size_t   next     = 0;
    unsigned inflight = 0;
    auto start_open = [&](unsigned s)
    {
        for (; next < es.size(); ++next)
        {
            const char* name = names.data() + es[next].at;
            if (!regular(dfd, name, es[next].type))
                continue;
            io_uring_sqe* sqe = io_uring_get_sqe(ring);
            io_uring_prep_openat(sqe, dfd, name, O_RDONLY | O_CLOEXEC, 0);
            io_uring_sqe_set_data64(sqe, static_cast<uint64_t>(s) << 1);
            slots[s].e = static_cast<uint32_t>(next++);
            ++inflight;
            return;
        }
    };
    for (unsigned s = 0; s < slots.size(); ++s)
        start_open(s);
    while (inflight)
    {
        // A ring that refuses to go on fails the walk -- but not before what it holds is back: an open still names
        // a string of `names`, and a read still writes into a slot, both of which the caller reuses at once.
        const int rc = io_uring_submit_and_wait(ring, 1);
        if (rc < 0 && rc != -EINTR)
        {
            why = -rc;
            while (inflight)
            {
                io_uring_cqe* c = nullptr;
                const int wr = io_uring_wait_cqe(ring, &c);
                if (wr == -EINTR)
                    continue;
                if (wr < 0 || !c)
                    break;
                const unsigned s = static_cast<unsigned>(c->user_data >> 1);
                // An open that succeeded hands back a descriptor; a read's slot already holds its own.
                if (!(c->user_data & 1) && c->res >= 0)
                    ::close(c->res);
                else if ((c->user_data & 1) && slots[s].fd >= 0)
                {
                    ::close(slots[s].fd);
                    slots[s].fd = -1;
                }
                io_uring_cqe_seen(ring, c);
                --inflight;
            }
            return;
        }
        io_uring_cqe* cqe;
        unsigned      at;
        unsigned      seen = 0;
        io_uring_for_each_cqe(ring, at, cqe)
        {
            ++seen;
            --inflight;
            const unsigned s    = static_cast<unsigned>(cqe->user_data >> 1);
            ring_slot&     sl   = slots[s];
            const char*    name = names.data() + es[sl.e].at;
            decoded_header d;
            if (cqe->user_data & 1)
                verdict(name, judge_object_file(w, sl.fd, sl.sb, name, sl.head, cqe->res, d, why), d);
            else if (cqe->res < 0)
                verdict(name, open_failed(-cqe->res, why), d);
            else
            {
                sl.fd = cqe->res;
                if (::fstat(sl.fd, &sl.sb) < 0)
                    verdict(name, judge_object_file(w, sl.fd, sl.sb, name, sl.head, -errno, d, why), d);
                else
                {
                    // The header is read through the ring too, so a cold one waits on the disk beside the others.
                    sl.head.resize(object_header_align);
                    io_uring_sqe* sqe = io_uring_get_sqe(ring);
                    io_uring_prep_read(sqe, sl.fd, sl.head.data(), static_cast<unsigned>(sl.head.size()), 0);
                    io_uring_sqe_set_data64(sqe, (static_cast<uint64_t>(s) << 1) | 1);
                    ++inflight;
                    continue;
                }
            }
            start_open(s);
        }
        io_uring_cq_advance(ring, seen);
    }
}

// Reads every object file of data/<sub in two hex digits>, or of versions/ when the walker says so, and hands each
// whole one to `found`.
template <typename F>
void scan_object_dir(walker& w, int bucket_fd, uint32_t sub, char* dents, std::string& head, dir_scan& out, F&& found,
                     io_uring* ring, std::vector<ring_slot>& slots)
{
    static constexpr char digits[] = "0123456789abcdef";
    const char dir[3] = {digits[sub >> 4], digits[sub & 15], 0};
    const std::string top = w.versions ? "versions/" : "data/";
    const int dfd = ::openat(bucket_fd, (top + dir).c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0)
    {
        // A directory that is not there holds nothing; one that cannot be read may hold anything.
        if (errno != ENOENT)
            out.failed = errno;
        return;
    }
    std::vector<dir_entry> es;
    std::string            names;
    for (;;)
    {
        const ssize_t got = ::getdents64(dfd, dents, dents_bytes);
        if (got < 0)
            out.failed = errno;
        if (got <= 0)
            break;
        for (ssize_t off = 0; off < got;)
        {
            const auto* e = reinterpret_cast<const struct dirent64*>(dents + off);
            off += e->d_reclen;
            const std::string_view name(e->d_name);
            // Only the one path its key gives a file, which is what makes one file per key, and per version in versions/.
            const bool shaped = w.versions ? name.size() > 65 && name[64] == '.' && valid_version_id(name.substr(65))
                                           : name.size() == 64;
            if (!shaped || name[0] != dir[0] || name[1] != dir[1])
                continue;
            es.push_back({static_cast<uint32_t>(names.size()), e->d_type});
            names.append(name).push_back('\0');
        }
    }
    auto verdict = [&](const char* name, file_verdict v, decoded_header& d)
    {
        ++out.files_read;
        if (v == file_verdict::ok)
            found(d);
        else if (v == file_verdict::unsound)
            out.unsound.push_back(top + dir + "/" + name);
    };
    if (ring)
        read_files_ring(w, ring, dfd, es, names, slots, out.failed, verdict);
    else
        read_files_one_by_one(w, dfd, es, names, head, out.failed, verdict);
    ::close(dfd);
}

}   // namespace

// A bucket between its journal and its verdict.
struct object_store::recovering
{
    bucket* b{nullptr};
    bool    torn{false};
    bool    corrupt{false};
    bool    other_layout{false};
    // The object files are to be read.
    bool    scan{false};
    // The files said something the journal did not.
    bool    changed{false};
    // The bucket has versions/, whose files are read beside the latest ones when the files are.
    bool    versions{false};
    // The format of the journal, whose versions are trusted from format 3 on.
    uint32_t format{0};
    // What the walk found that is not a latest object: delete markers at the usual paths, and the files of versions/.
    std::vector<std::pair<std::string, object_meta>> markers;
    std::vector<std::pair<std::string, object_meta>> noncurrent;
};

bool object_store::lock_shard(std::string& err)
{
    const auto give_up = std::chrono::steady_clock::now() + dir_lock_wait;
    const std::string held_by_other = " of " + m_opts.dir + " is still held by another process";

    // The process this one replaces on its shard may still be finishing its stop, and must not write a journal or a marker beside it.
    const std::string lock = m_opts.dir + "/.lock." + std::to_string(m_opts.shard);
    m_lock_fd = ::open(lock.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0644);
    if (m_lock_fd < 0)
    {
        err = "cannot open " + lock + ": " + errstr(errno);
        return false;
    }
    while (::flock(m_lock_fd, LOCK_EX | LOCK_NB) < 0)
    {
        if ((errno != EWOULDBLOCK && errno != EINTR) || std::chrono::steady_clock::now() >= give_up)
        {
            err = errno == EWOULDBLOCK ? "shard " + std::to_string(m_opts.shard) + held_by_other
                                       : "cannot lock " + lock + ": " + errstr(errno);
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // The shard count this shard runs under, fixed width so a read beside the write never matches a count it does not hold.
    char layout[16];
    std::snprintf(layout, sizeof layout, "%08u", m_opts.nshards);
    if (::pwrite(m_lock_fd, layout, 8, 0) != 8)
    {
        err = "cannot write " + lock + ": " + errstr(errno);
        return false;
    }

    // A shard under another count owns other keys, whose files this one reads and takes over, so it is waited out; one under this count owns its own.
    std::error_code ec;
    for (const auto& e : fs::directory_iterator(m_opts.dir, ec))
    {
        uint32_t k = 0;
        if (!suffix_number(e.path().filename().string(), ".lock.", k) || k == m_opts.shard)
            continue;
        const int fd = ::open(e.path().c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0)
            continue;
        bool waited = false;
        for (;;)
        {
            if (::flock(fd, LOCK_EX | LOCK_NB) == 0)
            {
                waited = true;
                break;
            }
            if (errno != EWOULDBLOCK && errno != EINTR)
            {
                err = "cannot lock " + e.path().string() + ": " + errstr(errno);
                break;
            }
            char got[8];
            if (::pread(fd, got, sizeof got, 0) == 8 && std::memcmp(got, layout, 8) == 0)
            {
                waited = true;
                break;
            }
            if (std::chrono::steady_clock::now() >= give_up)
            {
                err = "shard " + std::to_string(k) + ", under another shard count," + held_by_other;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        ::close(fd);
        if (!waited)
            return false;
    }
    return true;
}

bool object_store::open(std::string& err, recovery_report* report)
{
    recovery_report rep;
    std::error_code ec;

    // A test aid: a start that works this long, as one reading a large store's files does.
    if (const char* e = std::getenv("SOCKETLEY_STORAGE_START_SPIN_MS"))
    {
        const auto until = std::chrono::steady_clock::now() +
                           std::chrono::milliseconds(std::clamp(std::strtol(e, nullptr, 10), 0L, 30000L));
        volatile uint64_t spin = 0;
        while (std::chrono::steady_clock::now() < until)
            spin = spin + 1;
    }
    // And one that waits this long doing nothing, as a wedged start does.
    if (const char* e = std::getenv("SOCKETLEY_STORAGE_START_SLEEP_MS"))
        std::this_thread::sleep_for(std::chrono::milliseconds(std::clamp(std::strtol(e, nullptr, 10), 0L, 60000L)));

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

    // Before anything below reads or removes what another process may still be writing.
    if (!lock_shard(err))
        return false;

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

    // Every journal first, then the object files of every bucket that needs them in one parallel walk, then the verdicts.
    std::vector<recovering> rs;
    rs.reserve(names.size());
    for (const std::string& n : names)
        if (!recover_bucket(n, rep, rs, err))
            return false;
    if (!reconcile_with_files(rs, rep, err))
        return false;
    for (recovering& r : rs)
        if (!finish_bucket(r, rep, err))
            return false;

    m_totals.buckets          = m_buckets.size();
    m_totals.start_files_read = rep.files_read;
    if (report)
        *report = rep;
    if (m_opts.sync == sync_mode::interval)
        start_syncer();
    return true;
}

void object_store::start_syncer()
{
    const int fd = m_root_fd;
    const auto every = std::chrono::milliseconds(std::max<uint32_t>(m_opts.sync_interval_ms, 1));
    m_syncer = std::thread([this, fd, every]()
    {
        std::unique_lock lk(m_syncer_mx);
        while (!m_syncer_cv.wait_for(lk, every, [this]() { return m_syncer_stop; }))
        {
            lk.unlock();
            // The whole filesystem, which is every write the answers since the last round promised.
            if (::syncfs(fd) < 0)
                m_syncfs_failed.fetch_add(1, std::memory_order_relaxed);
            m_syncfs_rounds.fetch_add(1, std::memory_order_relaxed);
            lk.lock();
        }
    });
}

void object_store::stop_syncer()
{
    if (!m_syncer.joinable())
        return;
    {
        std::lock_guard lk(m_syncer_mx);
        m_syncer_stop = true;
    }
    m_syncer_cv.notify_all();
    m_syncer.join();
}

bool object_store::recover_bucket(const std::string& name, recovery_report& rep, std::vector<recovering>& out,
                                  std::string& err)
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
        // The owner is the second line, which a bucket made before there were users does not have.
        if (const size_t nl = created.find('\n'); nl != std::string::npos && r.ec == std::errc{})
        {
            std::string_view owner = std::string_view(created).substr(nl + 1);
            while (!owner.empty() && (owner.back() == '\n' || owner.back() == '\r' || owner.back() == ' '))
                owner.remove_suffix(1);
            b->owner = std::string(owner);
        }
    }

    // The configuration documents shard 0 last synced, and not what a write it was cut short in left.
    for (const bucket_doc kind : all_bucket_docs)
    {
        const std::string file = base + "/" + doc_file(kind);
        if (m_opts.shard == 0 && ::unlink((file + ".new").c_str()) < 0) {}
        // A change shard 0 has not decided yet leaves this shard serving nothing of the bucket until it has.
        if (m_opts.shard != 0 && ::access((file + ".new").c_str(), F_OK) == 0)
        {
            set_doubt(*b, kind, 0);
            continue;
        }
        const std::string xml = slurp(file, doc_max_bytes);
        std::string why;
        if (xml.empty() || take_doc(*b, kind, xml, &why))
            continue;
        if (kind == bucket_doc::policy)
            LOG_ERROR(("storage: the policy of bucket " + name + " does not compile (" + why +
                       "), so the bucket refuses every request but the policy's own until it is replaced or deleted")
                          .c_str());
        else if (kind == bucket_doc::encryption)
            LOG_ERROR(("storage: the encryption configuration of bucket " + name + " does not parse (" + why +
                       "), so its new objects are encrypted with AES256 until it is replaced or deleted").c_str());
        else if (kind == bucket_doc::object_lock)
            LOG_ERROR(("storage: the object lock configuration of bucket " + name + " does not parse (" + why +
                       "), so the bucket keeps object lock with no default retention until it is replaced").c_str());
        else
            LOG_WARN(("storage: the " + std::string(doc_file(kind)) + " configuration of bucket " + name +
                      " does not parse and is not applied: " + why).c_str());
    }

    // A versioned bucket has the directories of its noncurrent versions, which a start makes again when one is gone.
    struct stat vsb{};
    const bool has_versions = ::stat((base + "/versions").c_str(), &vsb) == 0 && S_ISDIR(vsb.st_mode);
    if (b->vstate != versioning::off || has_versions)
    {
        bool made = ::mkdir((base + "/versions").c_str(), 0755) == 0;
        static constexpr char digits[] = "0123456789abcdef";
        for (int i = 0; i < 256; ++i)
        {
            const char n[3] = {digits[i >> 4], digits[i & 15], 0};
            if (::mkdir((base + "/versions/" + n).c_str(), 0755) == 0)
                made = true;
            else if (errno != EEXIST)
            {
                err = "cannot create " + base + "/versions/" + n + ": " + errstr(errno);
                return false;
            }
        }
        if (made && (!fsync_dir_path(base + "/versions") || !fsync_dir_path(base)))
        {
            err = "cannot sync " + base + "/versions: " + errstr(errno);
            return false;
        }
    }

    b->dir_fd  = ::open(base.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    b->data_fd = ::open((base + "/data").c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    b->tmp_fd  = ::open((base + "/tmp").c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (b->dir_fd < 0 || b->data_fd < 0 || b->tmp_fd < 0)
    {
        err = "cannot open the directories of bucket " + name + ": " + errstr(errno);
        return false;
    }

    std::unordered_set<std::string> keep;
    const bool versioned_dir = b->vstate != versioning::off || has_versions;
    const uint64_t rolled = roll_forward_pooled(*b, keep, versioned_dir);
    rep.rolled_forward += rolled;
    rep.tmp_removed += clean_tmp(base + "/tmp", m_opts.shard, m_opts.nshards, {});
    // What is left in pool/ is empty, cut short or another shard's, and the last two are no refill's.
    clean_tmp(base + "/pool", m_opts.shard, m_opts.nshards, keep);

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

    recovering r;
    std::string why;
    if (!load_journal(*b, why, r.torn, r.corrupt, r.other_layout, r.format, rep))
    {
        err = why;
        return false;
    }

    // The files are consulted when the last stop was not clean, when the
    // journal could not be trusted, when it was written for another split,
    // when it is missing, and when a pooled put was rolled forward.
    r.scan = !m_clean_start || r.corrupt || r.torn || r.other_layout || rolled > 0;
    // A journal of format 2 records a key's latest version only, so a versioned bucket with one is read from its files.
    r.versions = versioned_dir;
    r.scan     = r.scan || (r.versions && r.format < journal_format);
    r.b    = b.get();
    m_buckets.emplace(name, std::move(b));
    out.push_back(std::move(r));
    return true;
}

bool object_store::finish_bucket(recovering& r, recovery_report& rep, std::string& err)
{
    bucket& b = *r.b;
    bool changed = r.changed;
    if (r.other_layout)
    {
        LOG_INFO(("storage: the journal of bucket " + b.name + " was written for another shard count; "
                  "this shard's keys are rebuilt from the object files").c_str());
    }
    if (r.corrupt)
    {
        ++rep.rebuilt_journals;
        changed = true;
        LOG_WARN(("storage: the journal of bucket " + b.name +
                  " is damaged and was rebuilt from the object files").c_str());
    }

    if (r.versions && r.scan)
    {
        load_versions(r, rep, changed);
        // A journal of the format before versions were recorded is written again in the one that has them.
        changed = changed || r.format < journal_format;
    }

    uint64_t bytes = 0;
    for (const auto& [k, m] : b.objects)
        bytes += m.size;
    b.nversions = 0;
    for (const auto& [k, list] : b.versions)
    {
        b.nversions += list.size();
        for (const object_meta& m : list)
            bytes += m.size;
    }
    b.bytes = bytes;

    const bool garbage = b.j.records > m_opts.compact_floor &&
                         b.j.records > 2 * (b.objects.size() + b.nversions + 1);
    if (changed || garbage || r.torn)
        if (!rewrite_journal_sync(b, err))
            return false;

    b.j.compact_after = 0;
    m_totals.objects += b.objects.size();
    m_totals.bytes += b.bytes;
    m_totals.journal_records += b.j.records;
    rep.objects += b.objects.size();
    ++rep.buckets;
    return true;
}

namespace
{

// Whether a pooled file's body is the one its header describes: the MD5 of its bytes, or of a sealed body's
// bytes as they lie on disk, since a start holds no key that opens it.
bool pooled_body_whole(const object_meta& m, std::string_view body)
{
    if (!is_encrypted(m))
        return md5_of(body) == m.md5;
    for (const auto& [n, v] : m.extra)
        if (n == stored_md5_extra)
            return v == hex(md5_of(body));
    return false;
}

}   // namespace

// A put answered at its rename leaves, until its directories are synced, the
// whole object in pool/, which the shard owning its key moves into place; any
// shard's file is looked at, since the split may have changed.
uint64_t object_store::roll_forward_pooled(bucket& b, std::unordered_set<std::string>& keep, bool versioned)
{
    const std::string base = m_opts.dir + "/" + b.name;
    uint64_t rolled = 0;
    std::unordered_set<std::string> leaves;
    std::error_code ec;
    for (const auto& e : fs::directory_iterator(base + "/pool", ec))
    {
        const std::string name = e.path().filename().string();
        const std::string all  = slurp(e.path().string(), 64 * 1024 + sse_stored_len(pooled_max, sse_format));

        // Whole means the length the header gives and the digest it names, so
        // neither a body cut short nor one whose pages never reached the disk passes.
        const decoded_header d = decode_object_header(all);
        const bool whole = d.status == header_status::ok && all.size() == d.header_len + stored_size(d.meta) &&
                           pooled_body_whole(d.meta, std::string_view(all).substr(d.header_len));
        if (!whole)
            continue;
        if (!owns(b.name, d.key))
        {
            keep.insert(name);
            continue;
        }
        const std::string rel = object_rel_path(d.key);
        std::string to = base + "/data/" + rel;
        const decoded_header cur = decode_object_header(slurp(to, 64 * 1024));
        // What was at the key's path and what replaces it, so a start can tell an event's change from one it overwrote.
        auto& seen = m_rolled_over[b.name + '\0' + d.key];
        seen.push_back(cur.status == header_status::ok && cur.key == d.key ? std::make_shared<object_meta>(cur.meta)
                                                                          : nullptr);
        // In a bucket that keeps versions the file at the usual path is one, kept as the commit would have kept it.
        if (versioned)
        {
            const version_tag mine = version_of(d.meta);
            const version_tag was  = version_of(cur.meta);
            if (cur.status == header_status::ok && cur.key == d.key && was.id != mine.id)
            {
                const std::string vdir = base + "/versions/" + rel.substr(0, 2);
                if (was.seq > mine.seq)
                    to = base + "/" + version_rel_path(d.key, mine.id);
                else if (::link(to.c_str(), (base + "/" + version_rel_path(d.key, was.id)).c_str()) < 0 &&
                         errno != EEXIST)
                {
                    LOG_WARN(("storage: keeping the version " + was.id + " of \"" + d.key + "\" in bucket " +
                              b.name + " before rolling a put forward failed: " + errstr(errno)).c_str());
                    keep.insert(name);
                    continue;
                }
                if (!fsync_dir_path(vdir)) {}
            }
        }
        if (::rename(e.path().c_str(), to.c_str()) < 0)
        {
            LOG_WARN(("storage: rolling " + e.path().string() + " forward failed: " + errstr(errno)).c_str());
            keep.insert(name);
            continue;
        }
        seen.push_back(std::make_shared<object_meta>(d.meta));
        leaves.insert(to.substr(0, to.rfind('/')));
        ++rolled;
    }
    for (const std::string& leaf : leaves)
        if (!fsync_dir_path(leaf)) {}
    if (rolled && !fsync_dir_path(base + "/pool")) {}
    return rolled;
}

std::vector<std::pair<bucket_doc, std::string>> object_store::bucket_docs_text(std::string_view name) const
{
    std::vector<std::pair<bucket_doc, std::string>> out;
    const std::string base = m_opts.dir + "/" + std::string(name) + "/";
    for (const bucket_doc kind : all_bucket_docs)
        if (std::string xml = slurp(base + doc_file(kind), doc_max_bytes); !xml.empty())
            out.emplace_back(kind, std::move(xml));
    return out;
}

bool object_store::change_on_disk(const change_note& n) const
{
    const std::string base = m_opts.dir + "/" + n.bucket;
    const auto header_at = [&n](const std::string& path, object_meta& out)
    {
        const decoded_header d = decode_object_header(slurp(path, 64 * 1024));
        if (d.status != header_status::ok || d.key != n.key)
            return false;
        out = d.meta;
        return true;
    };
    const auto same = [&n](const object_meta& m)
    {
        const std::string id = has_version(m) ? version_of(m).id : std::string();
        return id == n.version_id && m.mtime_ms == n.mtime_ms &&
               (!n.has_object || (m.size == n.size && m.etag() == n.etag));
    };
    const auto rolled = m_rolled_over.find(n.bucket + '\0' + n.key);
    object_meta latest, kept;
    const bool has_latest = header_at(base + "/data/" + object_rel_path(n.key), latest);
    const bool has_kept   = !n.version_id.empty() && header_at(base + "/" + version_rel_path(n.key, n.version_id), kept);

    if (n.event == ev_delete || n.event == ev_lc_delete)
    {
        // A version removed for good is under neither of its names.
        if (!n.version_id.empty())
            return !has_kept && !(has_latest && has_version(latest) && version_id_of(latest) == n.version_id);
        // A key removed is not there, or was not before a start rolled a put forward onto it.
        if (!has_latest)
            return true;
        return rolled != m_rolled_over.end() &&
               std::any_of(rolled->second.begin(), rolled->second.end(), [](const auto& m) { return !m; });
    }
    if ((has_latest && same(latest)) || (has_kept && same(kept)))
        return true;
    return rolled != m_rolled_over.end() &&
           std::any_of(rolled->second.begin(), rolled->second.end(), [&same](const auto& m) { return m && same(*m); });
}

bool object_store::load_journal(bucket& b, std::string& bad_why, bool& torn, bool& corrupt,
                                bool& other_layout, uint32_t& format, recovery_report& rep)
{
    format = journal_format;
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
        const journal_header_status hs = read_ok ? journal_header_check(head, m_opts.shard, m_opts.nshards, &format)
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
                        if (n < 0 && errno == EINTR)
                            continue;
                        // A read that fails is not the journal's end: what follows it is unknown, and appending at
                        // the last record read would write over it, so the index is built from the objects instead.
                        if (n < 0)
                        {
                            LOG_ERROR(("storage: the journal of bucket " + b.name + " could not be read past byte " +
                                       std::to_string(pos) + ": " + std::strerror(errno) +
                                       "; its index is rebuilt from the objects").c_str());
                            corrupt = true;
                            break;
                        }
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
                    else if (d.rec.type == record_type::del)
                        b.objects.erase(d.rec.key);
                    else if (d.rec.type == record_type::vput)
                        place_version(b.versions[d.rec.key], d.rec.meta);
                    else if (const auto v = b.versions.find(d.rec.key); v != b.versions.end())
                    {
                        erase_version(v->second, d.rec.version_id);
                        if (v->second.empty())
                            b.versions.erase(v);
                    }
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
        b.versions.clear();
        b.j.records = 0;
        valid_end   = 0;
    }
    // A torn tail is cut off by the rewrite the caller does for it, which is
    // what puts the next append on a record boundary.

    b.j.fd  = fd;
    b.j.off = valid_end;
    return true;
}

bool object_store::reconcile_with_files(std::vector<recovering>& rs, recovery_report& rep, std::string& err)
{
    // One piece of work is one object directory of one bucket, so a single
    // large bucket spreads over the threads as well as many small ones do.
    // A versioned bucket's versions/ directories are items of the same walk, numbered after its data/ ones.
    struct item
    {
        recovering* r;
        uint32_t    sub;
    };
    std::vector<item> items;
    for (recovering& r : rs)
        if (r.scan)
            for (uint32_t sub = 0; sub < (r.versions ? 512u : 256u); ++sub)
                items.push_back({&r, sub});
    if (items.empty())
        return true;

    std::vector<dir_scan> out(items.size());
    std::atomic<size_t>   next{0};
    const walk_shape      shape = recovery_shape();

    // The journals' entries are only read while the threads run, and changed once they have joined.
    auto work = [&]()
    {
        std::unique_ptr<char[]> dents(new char[dents_bytes]);
        std::string            head;
        io_uring               ring{};
        const bool             ringed = shape.depth > 0 && io_uring_queue_init(shape.depth, &ring, 0) == 0;
        std::vector<ring_slot> slots(ringed ? shape.depth : 0);
        walker                 w;
        w.shard   = m_opts.shard;
        w.nshards = m_opts.nshards;
        for (size_t i; (i = next.fetch_add(1, std::memory_order_relaxed)) < items.size();)
        {
            const bucket& b = *items[i].r->b;
            dir_scan&     o = out[i];
            w.bucket   = b.name;
            w.versions = items[i].sub >= 256;
            scan_object_dir(w, b.dir_fd, items[i].sub & 255, dents.get(), head, o,
                [&](decoded_header& d)
                {
                    // A sibling's object, which its own journal and its own start deal with.
                    if (!owns(b.name, d.key))
                        return;
                    if (w.versions || is_delete_marker(d.meta))
                    {
                        o.versions.emplace_back(std::move(d.key), std::move(d.meta));
                        return;
                    }
                    const auto found = b.objects.find(d.key);
                    if (found != b.objects.end() && found->second == d.meta)
                        o.matched.push_back(&found->first);
                    else
                        o.differ.emplace_back(std::move(d.key), std::move(d.meta));
                }, ringed ? &ring : nullptr, slots);
        }
        if (ringed)
            io_uring_queue_exit(&ring);
    };

    std::vector<std::thread> pool;
    const size_t want = std::min<size_t>(shape.threads, items.size());
    for (size_t t = 1; t < want; ++t)
    {
        try { pool.emplace_back(work); }
        catch (const std::system_error&) { break; }
    }
    work();
    for (std::thread& t : pool)
        t.join();

    for (size_t k = 0; k < items.size(); ++k)
        if (out[k].failed)
        {
            char dir[3];
            std::snprintf(dir, sizeof dir, "%02x", items[k].sub & 255);
            err = "cannot read the object files in " + m_opts.dir + "/" + items[k].r->b->name +
                  (items[k].sub >= 256 ? "/versions/" : "/data/") + dir + ": " + errstr(out[k].failed);
            return false;
        }

    size_t k = 0;
    for (recovering& r : rs)
    {
        if (!r.scan)
            continue;
        bucket&        b      = *r.b;
        const uint64_t before = rep.adopted + rep.dropped;
        const size_t   first  = k;
        size_t         seen   = 0;
        for (; k < items.size() && items[k].r == &r; ++k)
        {
            dir_scan& s = out[k];
            for (auto& [key, meta] : s.differ)
            {
                auto found = b.objects.find(key);
                if (found == b.objects.end())
                    found = b.objects.emplace(std::move(key), std::move(meta)).first;
                else
                    found->second = std::move(meta);
                ++rep.adopted;
                s.matched.push_back(&found->first);
            }
            seen += s.matched.size();
            rep.files_read += s.files_read;
            auto& to = items[k].sub >= 256 ? r.noncurrent : r.markers;
            std::move(s.versions.begin(), s.versions.end(), std::back_inserter(to));
            // Every shard walks every file, so one of them says so.
            if (m_opts.shard == 0)
                for (const std::string& rel : s.unsound)
                {
                    ++rep.corrupt_files;
                    LOG_WARN(("storage: " + m_opts.dir + "/" + b.name + "/" + rel +
                              " is not a whole object file and is left unserved").c_str());
                }
        }

        // A key has one path, so as many whole files as entries leaves no entry without its file.
        if (seen != b.objects.size())
        {
            std::unordered_set<const std::string*> have;
            have.reserve(seen);
            for (size_t j = first; j < k; ++j)
                have.insert(out[j].matched.begin(), out[j].matched.end());
            for (auto it = b.objects.begin(); it != b.objects.end();)
            {
                if (have.contains(&it->first))
                    ++it;
                else
                {
                    ++rep.dropped;
                    it = b.objects.erase(it);
                }
            }
        }
        r.changed = rep.adopted + rep.dropped != before;
    }
    return true;
}

void object_store::load_versions(recovering& r, recovery_report& rep, bool& changed)
{
    bucket& b = *r.b;
    const std::string base = m_opts.dir + "/" + b.name + "/";
    std::map<std::string, std::vector<object_meta>, std::less<>> fresh;
    // A delete marker at a key's usual path is its latest version, and no object.
    for (auto& [key, meta] : r.markers)
    {
        fresh[key].push_back(std::move(meta));
        ++rep.versions;
    }
    std::map<std::string, std::vector<object_meta>, std::less<>> noncurrent;
    for (auto& [key, meta] : r.noncurrent)
        noncurrent[std::move(key)].push_back(std::move(meta));
    r.markers.clear();
    r.noncurrent.clear();

    for (auto& [key, list] : noncurrent)
    {
        auto& kept = fresh[key];
        const auto o = b.objects.find(key);
        const bool has_latest = o != b.objects.end() || !kept.empty();
        const std::string latest_id = o != b.objects.end() ? version_of(o->second).id
                                    : kept.empty()          ? std::string{}
                                                            : version_of(kept.front()).id;
        std::vector<object_meta> older;
        for (object_meta& m : list)
        {
            // Linked before the rename that replaced it, and the rename then landed: the copy at the usual path wins.
            if (version_id_of(m) == latest_id)
            {
                if (::unlink((base + version_rel_path(key, latest_id)).c_str()) < 0) {}
                ++rep.version_duplicates;
                changed = true;
                continue;
            }
            older.push_back(std::move(m));
            ++rep.versions;
        }
        std::sort(older.begin(), older.end(), [](const object_meta& a, const object_meta& z)
        {
            return version_seq_of(a) > version_seq_of(z);
        });
        for (object_meta& m : older)
            kept.push_back(std::move(m));

        // Versions with no latest at all, which only a file removed by hand leaves: the newest goes back in place.
        if (!has_latest && !kept.empty())
        {
            const std::string from = base + version_rel_path(key, version_of(kept.front()).id);
            const std::string rel  = object_rel_path(key);
            if (::rename(from.c_str(), (base + "data/" + rel).c_str()) == 0)
            {
                if (!fsync_dir_path(base + "data/" + rel.substr(0, 2))) {}
                if (!is_delete_marker(kept.front()))
                {
                    b.objects.emplace(key, std::move(kept.front()));
                    kept.erase(kept.begin());
                }
                changed = true;
            }
            else
                LOG_WARN(("storage: the newest version of \"" + key + "\" in bucket " + b.name +
                          " could not be made its latest again: " + errstr(errno)).c_str());
        }
        if (kept.empty())
            fresh.erase(key);
    }
    // The journal's versions stand when the files say the same, and are written again from these otherwise.
    changed = changed || fresh != b.versions;
    b.versions = std::move(fresh);
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
    auto spill = [&]()
    {
        if (buf.size() < (1u << 20))
            return;
        ok = ok && write_all_fd(fd, buf.data(), buf.size());
        off += buf.size();
        buf.clear();
    };
    for (const auto& [k, m] : b.objects)
    {
        encode_put_record(buf, k, m);
        spill();
    }
    uint64_t versions = 0;
    for (const auto& [k, list] : b.versions)
        for (const object_meta& m : list)
        {
            encode_version_record(buf, k, m);
            ++versions;
            spill();
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
    b.j.records = b.objects.size() + versions;
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
    stop_syncer();
    if (m_removed_fd >= 0)
    {
        ::close(m_removed_fd);
        m_removed_fd = -1;
    }

    // The marker only when nothing is half done, because a stop that left a
    // rename without its journal record is exactly what the next start must
    // go and look for.
    // A mode that skips syncs syncs everything here, since the marker says the files need not be read again.
    const bool synced = m_opts.sync == sync_mode::always ||
                        (m_root_fd >= 0 && ::syncfs(m_root_fd) == 0 && m_syncfs_failed.load() == 0);
    if (clean && synced && !working() && !m_journal_lost && !m_sync_lost && settle_journals() && m_root_fd >= 0)
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
        pool_close(*b);
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
    // Closed here and not on the ring, so the next process on this shard may open the moment this one is done.
    if (m_lock_fd >= 0)
    {
        ::close(m_lock_fd);
        m_lock_fd = -1;
    }
}

}   // namespace socketley::storage
