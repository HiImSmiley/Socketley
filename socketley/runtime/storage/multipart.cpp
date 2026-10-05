#include "multipart.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "disk_chain.h"
#include "s3_xml.h"
#include "../../shared/logging.h"
#include "../../shared/random_id.h"

namespace fs = std::filesystem;

namespace socketley::storage
{

namespace
{

constexpr size_t chunk_bytes = 1u << 20;
// Files removed at once when an upload goes, so ten thousand parts do not
// queue ten thousand operations.
constexpr size_t unlink_window = 16;
constexpr std::string_view algorithm_extra = "x-amz-checksum-algorithm";

st errno_st(int64_t res)
{
    return (res == -ENOSPC || res == -EDQUOT) ? st::storage_full : st::io_error;
}

std::string new_upload_id()
{
    static constexpr char digits[] = "0123456789abcdef";
    std::string id;
    id.reserve(32);
    for (int w = 0; w < 2; ++w)
    {
        uint64_t v = random_u64();
        for (int i = 0; i < 16; ++i, v >>= 4)
            id.push_back(digits[v & 15]);
    }
    return id;
}

bool valid_upload_id(std::string_view id)
{
    if (id.size() != 32)
        return false;
    for (char c : id)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    return true;
}

// A descriptor that is closed when the last holder lets go, on the loop while
// there is one and directly when the run has been freed.
std::shared_ptr<int> hold_fd(event_loop* loop, const std::shared_ptr<bool>& alive, int fd)
{
    return std::shared_ptr<int>(new int(fd), [loop, alive](int* p)
    {
        if (*p >= 0)
        {
            if (*alive)
                loop->close_fd(*p);
            else
                ::close(*p);
        }
        delete p;
    });
}

// Reads the start of a file, blocking, for the scan at startup.
bool read_prefix(const std::string& path, size_t max, std::string& out, uint64_t* file_size = nullptr)
{
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    struct stat sb{};
    if (::fstat(fd, &sb) != 0)
    {
        ::close(fd);
        return false;
    }
    if (file_size)
        *file_size = static_cast<uint64_t>(sb.st_size);
    out.resize(std::min<size_t>(max, static_cast<size_t>(sb.st_size)));
    size_t got = 0;
    while (got < out.size())
    {
        const ssize_t n = ::pread(fd, out.data() + got, out.size() - got, static_cast<off_t>(got));
        if (n <= 0)
            break;
        got += static_cast<size_t>(n);
    }
    ::close(fd);
    out.resize(got);
    return true;
}

const std::string* extra_value(const object_meta& m, std::string_view name)
{
    for (const auto& [n, v] : m.extra)
        if (n == name)
            return &v;
    return nullptr;
}

// A part's checksum in the upload's algorithm, empty when the part has none in it.
std::string part_checksum_b64(const object_meta& m, checksum_algo algo)
{
    if (algo != checksum_algo::none && m.checksum.algo == algo)
        return m.checksum.b64();
    const std::string* v = algo != checksum_algo::none ? extra_value(m, checksum_header(algo)) : nullptr;
    return v ? *v : std::string{};
}

// The header a completed object takes, with room for the MAC of its part list an SSE-C completion may add.
size_t completed_header_len(std::string_view key, object_meta m)
{
    if (sse_mode_of(m) == sse_mode::c)
        m.extra.emplace_back(std::string(sse_parts_extra), encode_parts_mac({}, {}));
    return object_header_len(key, m);
}

// The room the finished object's header needs in front of part 1, whatever its size and part count.
uint64_t place_base_of(std::string_view key, const object_meta& meta, checksum_algo algo)
{
    object_meta m = meta;
    if (algo != checksum_algo::none)
        reserve_checksum(m, algo, static_cast<uint16_t>(mpu_max_parts));
    // Parts placed in the data file are of one size, so their list is one number or names its checksums after the body,
    // and with no algorithm the room that one number leaves holds the default checksum.
    m.extra.emplace_back(std::string(part_layout_extra), std::string(20 + 1 + 64 + 1 + 2, '9'));
    m.extra.emplace_back(std::string(upload_id_extra), std::string(32, '0'));
    return completed_header_len(key, m);
}

// The list a completed object records of `parts`, with their checksums when each has one in the object's algorithm.
part_list list_of(const std::vector<mpu_part>& parts, const object_meta& meta)
{
    part_list l;
    const checksum_algo a = checksum_algo_of(meta);
    bool sums = a != checksum_algo::none;
    for (const mpu_part& p : parts)
    {
        l.numbers.push_back(p.number);
        l.sizes.push_back(p.size);
        std::string raw;
        sums = sums && base64_decode(p.checksum_b64, raw) && raw.size() == checksum_raw_len(a);
        if (sums)
            l.checksums.push_back(std::move(raw));
    }
    if (!sums)
        l.checksums.clear();
    return l;
}

// How far apart the parts of an upload lie in its data file: their size, or what that size takes sealed.
uint64_t place_stride(const mpu_upload& u)
{
    return is_encrypted(u.meta) ? sse_stored_len(u.place_size, sse_version_of(u.meta)) : u.place_size;
}

// Whether the listed parts are 1..N, each where the object needs it in the data file, and the only parts there.
bool copy_free(const mpu_upload& u, const std::vector<mpu_part>& parts)
{
    if (u.place_frozen || u.place_base == 0 || u.place_size == 0 || !u.placing.empty())
        return false;
    const uint64_t stride = place_stride(u);
    size_t in_place = 0;
    for (const auto& [n, p] : u.parts)
        in_place += p.in_place ? 1 : 0;
    if (in_place != parts.size())
        return false;
    for (size_t i = 0; i < parts.size(); ++i)
    {
        const mpu_part& p = parts[i];
        const bool last = i + 1 == parts.size();
        if (!p.in_place || p.number != i + 1 || p.data_off != u.place_base + i * stride ||
            (last ? p.size > u.place_size : p.size != u.place_size))
            return false;
    }
    return true;
}

}   // namespace

std::string encode_place(uint64_t off)
{
    std::string v = std::to_string(off);
    return std::string(20 - v.size(), '0') + v;
}

uint64_t place_of(const object_meta& meta)
{
    const std::string* v = extra_value(meta, mpu_place_extra);
    uint64_t off = 0;
    if (!v || std::from_chars(v->data(), v->data() + v->size(), off).ptr != v->data() + v->size())
        return 0;
    return off;
}

struct part_commit
{
    std::string bucket;
    std::string id;
    uint32_t    number{0};
    std::string tmp_path;
    std::string part_path;
    // Where the body was written in the upload's data file, 0 when it is in its own file.
    uint64_t    place_off{0};
    commit_request req;
    std::function<void(put_result)> done;
};

struct assemble_state
{
    std::string bucket;
    std::string id;
    std::string key;
    object_meta meta;
    std::string checksum_b64;
    std::vector<mpu_part> parts;
    std::string tmp_name;
    std::string tmp_path;
    std::string dir_path;
    std::shared_ptr<int> dst;
    size_t   hdr_len{0};
    size_t   part_idx{0};
    uint64_t part_off{0};
    uint64_t dst_off{0};
    // The descriptor of the part being read, shared with the chunks still using it.
    std::shared_ptr<int> cur;
    bool     opening{false};
    bool     header_done{false};
    bool     finishing{false};
    int      inflight{0};
    bool     failed{false};
    int64_t  err{0};
    std::unique_ptr<char[]> buf[2];
    bool     buf_free[2]{true, true};
    std::function<void()> progress;
    std::function<void(complete_result)> cb;
    // Whether the upload is this store's, to be removed or opened again when the
    // object is done; an assembler on behalf of another shard leaves that to it.
    bool     local{true};
    // The parts are in place in the data file, which becomes the object itself.
    bool     in_place{false};
    // The format the parts are sealed in, 0 for none, since their bytes on disk are more than their sizes say.
    uint8_t  sealed{0};
    complete_binder bind;
    // If-Match and If-None-Match of the completion, decided by the key's owner at the commit.
    put_condition cond;
    change_origin who;
    // The part list written after the body, when the header has no room for it.
    std::string trailer;
};

multipart_store::multipart_store(event_loop& loop, file_io& io, object_store& store)
    : m_loop(&loop), m_io(&io), m_store(&store), m_alive(std::make_shared<bool>(true))
{
    // A smaller room for the part list in the header, so a test reaches the trailer without gigabytes of parts.
    if (const char* e = std::getenv("SOCKETLEY_STORAGE_PART_LIST_MAX"))
        m_list_max = std::strtoull(e, nullptr, 10);
}

multipart_store::~multipart_store()
{
    *m_alive = false;
    for (auto& [k, up] : m_uploads)
        if (up->dir_fd >= 0)
            ::close(up->dir_fd);
}

multipart_store::key_t multipart_store::key_of(std::string_view bucket, std::string_view id)
{
    std::string k(bucket);
    k.push_back('/');
    k.append(id);
    return k;
}

std::string multipart_store::base_of(std::string_view bucket) const
{
    return m_store->options().dir + "/" + std::string(bucket);
}

std::string multipart_store::upload_path(std::string_view bucket, std::string_view id) const
{
    return base_of(bucket) + "/mpu/" + std::string(id);
}

mpu_upload* multipart_store::find_mut(std::string_view bucket, std::string_view id)
{
    const auto it = m_uploads.find(key_of(bucket, id));
    return it == m_uploads.end() ? nullptr : it->second.get();
}

const mpu_upload* multipart_store::find(std::string_view bucket, std::string_view id) const
{
    const auto it = m_uploads.find(key_of(bucket, id));
    return it == m_uploads.end() ? nullptr : it->second.get();
}

std::vector<const mpu_upload*> multipart_store::uploads_of(std::string_view bucket) const
{
    std::vector<const mpu_upload*> out;
    const std::string prefix = std::string(bucket) + "/";
    for (auto it = m_uploads.lower_bound(prefix); it != m_uploads.end() && it->first.starts_with(prefix); ++it)
        if (it->second->state != mpu_state::removing)
            out.push_back(it->second.get());
    return out;
}

bool multipart_store::bucket_uploads_busy(std::string_view bucket) const
{
    const std::string prefix = std::string(bucket) + "/";
    for (auto it = m_uploads.lower_bound(prefix); it != m_uploads.end() && it->first.starts_with(prefix); ++it)
    {
        // A part's body on its way in is a put on the bucket, which keeps it, so a place given to a body that was then
        // refused, and is never written, keeps nothing.
        const mpu_upload& u = *it->second;
        if (u.state != mpu_state::open || u.committing > 0 || !u.lanes.empty())
            return true;
    }
    return false;
}

bool multipart_store::removing_in(std::string_view bucket) const
{
    const std::string prefix = std::string(bucket) + "/";
    for (auto it = m_uploads.lower_bound(prefix); it != m_uploads.end() && it->first.starts_with(prefix); ++it)
        if (it->second->state == mpu_state::removing)
            return true;
    return false;
}

void multipart_store::after_removals(std::string_view bucket, std::function<void()> then)
{
    if (!removing_in(bucket))
    {
        then();
        return;
    }
    m_removal_waiters[std::string(bucket)].push_back(std::move(then));
}

void multipart_store::drop_bucket(std::string_view bucket)
{
    const std::string prefix = std::string(bucket) + "/";
    std::vector<std::string> ids;
    for (auto it = m_uploads.lower_bound(prefix); it != m_uploads.end() && it->first.starts_with(prefix); ++it)
        ids.push_back(it->second->id);
    for (const std::string& id : ids)
        forget(std::string(bucket), id);
}

mpu_totals multipart_store::totals() const
{
    mpu_totals t;
    for (const auto& [k, up] : m_uploads)
    {
        ++t.uploads;
        t.parts += up->parts.size();
        t.bytes += up->held;
    }
    return t;
}

// ─── Startup ────────────────────────────────────────────────────────────────

bool multipart_store::open(std::string& err)
{
    for (const bucket_info& b : m_store->buckets())
        if (!recover_bucket(b.name, err))
            return false;
    return true;
}

bool multipart_store::recover_bucket(const std::string& bucket, std::string& err)
{
    const std::string mpu = base_of(bucket) + "/mpu";
    if (::mkdir(mpu.c_str(), 0755) < 0)
    {
        if (errno != EEXIST)
        {
            err = "cannot create " + mpu + ": " + std::strerror(errno);
            return false;
        }
    }
    else
    {
        const int fd = ::open(base_of(bucket).c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd >= 0)
        {
            if (::fsync(fd) < 0) {}
            ::close(fd);
        }
    }

    std::error_code ec;
    std::vector<fs::path> entries;
    for (const auto& e : fs::directory_iterator(mpu, ec))
        entries.push_back(e.path());

    for (const fs::path& dir : entries)
    {
        const std::string id = dir.filename().string();
        std::error_code dc;
        if (!valid_upload_id(id) || !fs::is_directory(dir, dc))
        {
            LOG_WARN(("storage: ignoring " + dir.string() + ", which is not a multipart upload").c_str());
            continue;
        }

        // An upload whose meta file is not whole was never acknowledged, unless a
        // sibling shard is making it this moment, which only its age tells apart.
        std::string head;
        decoded_header dh;
        if (read_prefix(dir.string() + "/meta", 64 * 1024, head))
            dh = decode_object_header(head);
        if (dh.status != header_status::ok)
        {
            const auto age = std::filesystem::file_time_type::clock::now() - fs::last_write_time(dir, dc);
            if (m_store->shard() == 0 && !dc && (m_store->shards() == 1 || age > std::chrono::seconds(60)))
                fs::remove_all(dir, dc);
            continue;
        }
        // An upload belongs to the shard that owns its key, which is how every
        // request that names it finds it.
        if (!m_store->owns(bucket, dh.key))
            continue;

        auto up = std::make_unique<mpu_upload>();
        up->bucket       = bucket;
        up->id           = id;
        up->key          = dh.key;
        up->meta         = dh.meta;
        up->initiated_ms = dh.meta.mtime_ms;
        up->meta.mtime_ms = 0;
        for (auto it = up->meta.extra.begin(); it != up->meta.extra.end();)
        {
            if (it->first == algorithm_extra)
            {
                up->algo = checksum_from_name(it->second);
                it       = up->meta.extra.erase(it);
            }
            else
                ++it;
        }
        up->dir_fd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (up->dir_fd < 0)
        {
            err = "cannot open " + dir.string() + ": " + std::strerror(errno);
            return false;
        }
        // A body another shard was writing into the data file when this one stopped may still be.
        up->place_frozen = true;
        struct stat data_sb{};
        const bool has_data = ::stat((dir.string() + "/data").c_str(), &data_sb) == 0;

        for (const auto& pe : fs::directory_iterator(dir, dc))
        {
            const std::string name = pe.path().filename().string();
            if (name == "meta" || name == "data")
                continue;
            uint32_t n = 0;
            const auto r = std::from_chars(name.data(), name.data() + name.size(), n);
            bool keep = r.ec == std::errc{} && r.ptr == name.data() + name.size() && n >= 1 && n <= mpu_max_parts;
            mpu_part part;
            if (keep)
            {
                std::string ph;
                uint64_t    fsize = 0;
                keep = read_prefix(pe.path().string(), 64 * 1024, ph, &fsize);
                if (keep)
                {
                    const decoded_header pd = decode_object_header(ph);
                    const uint64_t at = pd.status == header_status::ok ? place_of(pd.meta) : 0;
                    // A part in the data file is a header naming its place, and the data file reaching past it.
                    keep = pd.status == header_status::ok &&
                           (at ? has_data && fsize == pd.header_len &&
                                     static_cast<uint64_t>(data_sb.st_size) >= at + stored_size(pd.meta)
                               : fsize == pd.header_len + stored_size(pd.meta));
                    if (keep)
                    {
                        part.number   = n;
                        part.size     = pd.meta.size;
                        part.md5      = pd.meta.md5;
                        part.mtime_ms = pd.meta.mtime_ms;
                        part.data_off = at ? at : pd.header_len;
                        part.in_place = at != 0;
                        part.checksum_b64 = part_checksum_b64(pd.meta, up->algo);
                        if (const std::string* v = extra_value(pd.meta, part_crc_extra))
                            part.crc_b64 = *v;
                    }
                }
            }
            if (!keep)
            {
                // A stray file, or a part that is not what its header says.
                fs::remove(pe.path(), dc);
                continue;
            }
            up->held += part.size;
            up->parts.emplace(n, std::move(part));
        }
        m_store->hold_bytes(up->held);
        m_uploads.emplace(key_of(bucket, id), std::move(up));
    }
    return true;
}

// ─── Creating ───────────────────────────────────────────────────────────────

void multipart_store::create(std::string bucket, std::string key, object_meta meta, checksum_algo algo,
                             std::function<void(st, std::string)> cb)
{
    if (!m_store->has_bucket(bucket))
    {
        cb(st::no_such_bucket, {});
        return;
    }
    if (key.empty() || key.size() > max_key_bytes)
    {
        cb(st::key_too_long, {});
        return;
    }

    struct state
    {
        std::string bucket;
        std::string key;
        std::string id;
        std::string dir;
        std::string mpu;
        std::string header;
        object_meta meta;
        checksum_algo algo{checksum_algo::none};
        int64_t     initiated{0};
        bool        mpu_made{false};
        std::shared_ptr<int> dir_fd;
        std::shared_ptr<int> file_fd;
        std::shared_ptr<int> data_fd;
        std::shared_ptr<int> sync_fd;
        std::function<void(st, std::string)> cb;
    };
    auto s = std::make_shared<state>();
    s->bucket    = std::move(bucket);
    s->key       = std::move(key);
    s->id        = new_upload_id();
    s->mpu       = base_of(s->bucket) + "/mpu";
    s->dir       = s->mpu + "/" + s->id;
    s->meta      = std::move(meta);
    s->algo      = algo;
    s->initiated = static_cast<int64_t>(m_store->now_ms());
    s->cb        = std::move(cb);
    s->dir_fd    = hold_fd(m_loop, m_alive, -1);
    s->file_fd   = hold_fd(m_loop, m_alive, -1);
    s->data_fd   = hold_fd(m_loop, m_alive, -1);
    s->sync_fd   = hold_fd(m_loop, m_alive, -1);

    // The header says what the object will be, and carries when the upload
    // began in the field an object keeps its modification time in.
    object_meta stored = s->meta;
    stored.mtime_ms    = s->initiated;
    if (algo != checksum_algo::none)
        stored.extra.emplace_back(std::string(algorithm_extra), std::string(checksum_name(algo)));
    s->header = encode_object_header(s->key, stored);

    ++m_inflight;
    auto ch = std::make_shared<disk_chain>(m_alive);
    file_io* io = m_io;

    // The directory holding every upload of the bucket, synced into the
    // bucket when this is what made it.
    ch->then([io, s](file_io::done d)
    {
        return io->mkdirat(AT_FDCWD, s->mpu, 0755, [s, d](int64_t r) { s->mpu_made = r == 0; d(r); });
    }, -EEXIST);
    ch->then([io, s](file_io::done d)
    {
        if (!s->mpu_made)
        {
            d(0);
            return true;
        }
        return io->openat(AT_FDCWD, s->mpu.substr(0, s->mpu.size() - 4), O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0,
                          [s, d](int64_t r) { if (r >= 0) *s->sync_fd = static_cast<int>(r); d(r < 0 ? r : 0); });
    });
    ch->then([io, s](file_io::done d)
    {
        if (*s->sync_fd < 0)
        {
            d(0);
            return true;
        }
        return io->sync(*s->sync_fd, false, std::move(d));
    });
    ch->then([io, s](file_io::done d)
    {
        return io->mkdirat(AT_FDCWD, s->dir, 0755, std::move(d));
    });
    ch->then([io, s](file_io::done d)
    {
        return io->openat(AT_FDCWD, s->dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0,
                          [s, d](int64_t r) { if (r >= 0) *s->dir_fd = static_cast<int>(r); d(r < 0 ? r : 0); });
    });
    ch->then([io, s](file_io::done d)
    {
        return io->openat(*s->dir_fd, "meta", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600,
                          [s, d](int64_t r) { if (r >= 0) *s->file_fd = static_cast<int>(r); d(r < 0 ? r : 0); });
    });
    ch->then([io, s](file_io::done d)
    {
        return io->pwrite(*s->file_fd, s->header.data(), static_cast<uint32_t>(s->header.size()), 0, std::move(d));
    });
    ch->then([io, s](file_io::done d) { return io->sync(*s->file_fd, true, std::move(d)); });
    // The file the parts are written into where the object will hold them, empty until they are.
    ch->then([io, s](file_io::done d)
    {
        return io->openat(*s->dir_fd, "data", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600,
                          [s, d](int64_t r) { if (r >= 0) *s->data_fd = static_cast<int>(r); d(r < 0 ? r : 0); });
    });
    ch->then([io, s](file_io::done d) { return io->sync(*s->dir_fd, false, std::move(d)); });
    // The upload's own directory is an entry of the bucket's, which the id must survive.
    ch->then([io, s](file_io::done d)
    {
        return io->openat(AT_FDCWD, s->mpu, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0,
                          [s, d](int64_t r)
                          {
                              if (r >= 0)
                              {
                                  if (*s->sync_fd >= 0)
                                      ::close(*s->sync_fd);
                                  *s->sync_fd = static_cast<int>(r);
                              }
                              d(r < 0 ? r : 0);
                          });
    });
    ch->then([io, s](file_io::done d) { return io->sync(*s->sync_fd, false, std::move(d)); });

    ch->run([this, alive = m_alive, s](int64_t r)
    {
        if (!*alive)
            return;
        --m_inflight;
        if (r < 0)
        {
            // Nothing was promised, so what was made is taken back where it can be.
            if (*s->file_fd >= 0)
                if (!m_io->unlinkat(AT_FDCWD, s->dir + "/meta", 0, [](int64_t) {})) {}
            if (*s->data_fd >= 0)
                if (!m_io->unlinkat(AT_FDCWD, s->dir + "/data", 0, [](int64_t) {})) {}
            if (*s->dir_fd >= 0)
                if (!m_io->unlinkat(AT_FDCWD, s->dir, AT_REMOVEDIR, [](int64_t) {})) {}
            s->cb(errno_st(r), {});
            return;
        }
        if (!m_store->has_bucket(s->bucket))
        {
            s->cb(st::no_such_bucket, {});
            return;
        }
        auto up = std::make_unique<mpu_upload>();
        up->bucket       = s->bucket;
        up->id           = s->id;
        up->key          = s->key;
        up->meta         = s->meta;
        up->initiated_ms = s->initiated;
        up->algo         = s->algo;
        up->place_base   = place_base_of(s->key, s->meta, s->algo);
        // The directory descriptor is the upload's from here.
        up->dir_fd = ::dup(*s->dir_fd);
        m_uploads.emplace(key_of(s->bucket, s->id), std::move(up));
        s->cb(st::ok, s->id);
    });
}

// ─── Parts ──────────────────────────────────────────────────────────────────

st multipart_store::begin_part(std::string_view bucket, std::string_view id, checksum_algo& algo) const
{
    const mpu_upload* up = find(bucket, id);
    if (!up || up->state != mpu_state::open)
        return st::no_such_key;
    algo = up->algo;
    return st::ok;
}

std::string multipart_store::data_path(std::string_view bucket, std::string_view id) const
{
    return upload_path(bucket, id) + "/data";
}

st multipart_store::begin_part(std::string_view bucket, std::string_view id, uint32_t number, uint64_t expected,
                               bool known, checksum_algo& algo, part_place& place)
{
    place = part_place{};
    const st s = begin_part(bucket, id, algo);
    mpu_upload* up = find_mut(bucket, id);
    if (s == st::ok && up)
        if (const std::string* v = sse_value(up->meta))
            place.sse = *v;
    if (s != st::ok || !up || !known || expected == 0 || up->place_base == 0 || up->place_frozen ||
        up->placed.contains(number))
        return s;
    // A first part under the minimum can only be a last part, and would fix too small a size for the rest.
    if (up->place_size == 0)
    {
        if (expected < mpu_min_part_bytes)
            return s;
        up->place_size = expected;
    }
    const uint64_t rel = static_cast<uint64_t>(number - 1) * place_stride(*up);
    if (expected > up->place_size || rel + expected > m_store->options().max_object_bytes)
        return s;
    up->placed.insert(number);
    up->placing[number] = expected;
    place.off  = up->place_base + rel;
    place.room = expected;
    place.path = data_path(bucket, id);
    return s;
}

void multipart_store::lane_enter(std::string_view bucket, std::string_view id, uint32_t number,
                                 std::function<void()> run)
{
    mpu_upload* up = find_mut(bucket, id);
    if (!up)
    {
        run();
        return;
    }
    auto it = up->lanes.find(number);
    if (it == up->lanes.end())
    {
        up->lanes.emplace(number, std::vector<std::function<void()>>{});
        run();
        return;
    }
    it->second.push_back(std::move(run));
}

void multipart_store::lane_leave(std::string_view bucket, std::string_view id, uint32_t number)
{
    mpu_upload* up = find_mut(bucket, id);
    if (!up)
        return;
    auto it = up->lanes.find(number);
    if (it == up->lanes.end())
        return;
    if (it->second.empty())
    {
        up->lanes.erase(it);
        return;
    }
    auto next = std::move(it->second.front());
    it->second.erase(it->second.begin());
    next();
}

put_op::committer multipart_store::part_committer(std::string bucket, std::string id, uint32_t number)
{
    return [this, alive = m_alive, bucket = std::move(bucket), id = std::move(id), number](
               commit_request req, std::function<void(put_result)> done)
    {
        if (!*alive)
            return;
        auto pc = std::make_shared<part_commit>();
        pc->bucket    = bucket;
        pc->id        = id;
        pc->number    = number;
        pc->tmp_path  = base_of(bucket) + "/tmp/" + req.tmp_name;
        pc->part_path = upload_path(bucket, id) + "/" + std::to_string(number);
        pc->req       = std::move(req);
        pc->done      = std::move(done);

        mpu_upload* up = find_mut(bucket, id);
        pc->place_off = place_of(pc->req.meta);
        bool place_ok = true;
        if (up && pc->place_off)
        {
            // A place is committed once, by the body it was given to, and holds no more than that body was to be.
            const auto g = up->placing.find(number);
            place_ok = g != up->placing.end() && up->place_size != 0 &&
                       pc->place_off == up->place_base + static_cast<uint64_t>(number - 1) * place_stride(*up) &&
                       pc->req.meta.size <= g->second;
            if (g != up->placing.end())
                up->placing.erase(g);
        }
        if (!up || up->state != mpu_state::open || !place_ok)
        {
            // The upload went away while the body was coming in, or the place was never this body's.
            if (!m_io->unlinkat(AT_FDCWD, pc->tmp_path, 0, [](int64_t) {})) {}
            pc->done({up && !place_ok ? st::io_error : st::cancelled, pc->req.meta});
            return;
        }
        ++up->committing;
        lane_enter(bucket, id, number, [this, alive, pc]()
        {
            if (!*alive)
                return;
            run_part_commit(pc);
        });
    };
}

void multipart_store::run_part_commit(std::shared_ptr<part_commit> pc)
{
    mpu_upload* up = find_mut(pc->bucket, pc->id);
    if (!up)
    {
        finish_part(pc, -ENOENT, false);
        return;
    }
    auto renamed = std::make_shared<bool>(false);
    auto ch = std::make_shared<disk_chain>(m_alive);
    ch->then([this, pc, renamed](file_io::done d)
    {
        return m_io->renameat(AT_FDCWD, pc->tmp_path, AT_FDCWD, pc->part_path,
                              [renamed, d](int64_t r) { *renamed = r >= 0; d(r); });
    });
    // The upload's directory, so the part is still there after a crash.
    ch->then([this, pc](file_io::done d)
    {
        mpu_upload* u = find_mut(pc->bucket, pc->id);
        if (!u || u->dir_fd < 0)
        {
            d(-ENOENT);
            return true;
        }
        return m_io->sync(u->dir_fd, false, std::move(d));
    });
    ch->run([this, alive = m_alive, pc, renamed](int64_t r)
    {
        if (!*alive)
            return;
        finish_part(pc, r, *renamed);
    });
}

void multipart_store::finish_part(const std::shared_ptr<part_commit>& pc, int64_t res, bool renamed)
{
    lane_leave(pc->bucket, pc->id, pc->number);
    mpu_upload* up = find_mut(pc->bucket, pc->id);

    put_result out{st::ok, pc->req.meta};
    if (res < 0)
    {
        if (!renamed)
        {
            if (!m_io->unlinkat(AT_FDCWD, pc->tmp_path, 0, [](int64_t) {})) {}
        }
        else if (!m_io->unlinkat(AT_FDCWD, pc->part_path, 0, [](int64_t) {})) {}
        out.status = up ? errno_st(res) : st::cancelled;
    }
    else if (up)
    {
        mpu_part part;
        part.number   = pc->number;
        part.size     = pc->req.meta.size;
        part.md5      = pc->req.meta.md5;
        part.mtime_ms = pc->req.meta.mtime_ms;
        part.data_off = pc->place_off ? pc->place_off : object_header_len(pc->req.key, pc->req.meta);
        part.in_place = pc->place_off != 0;
        part.checksum_b64 = part_checksum_b64(pc->req.meta, up->algo);
        if (const std::string* v = extra_value(pc->req.meta, part_crc_extra))
            part.crc_b64 = *v;

        const auto old = up->parts.find(pc->number);
        if (old != up->parts.end())
        {
            up->held -= std::min(up->held, old->second.size);
            m_store->release_bytes(old->second.size);
        }
        up->held += part.size;
        m_store->hold_bytes(part.size);
        up->parts[pc->number] = std::move(part);
    }
    else
        out.status = st::cancelled;

    if (up && up->committing > 0 && --up->committing == 0 && up->on_idle)
    {
        auto f = std::move(up->on_idle);
        up->on_idle = nullptr;
        f();
    }
    pc->done(std::move(out));
}

// ─── Completing ─────────────────────────────────────────────────────────────

void multipart_store::complete(std::string bucket, std::string id, std::vector<complete_part> parts,
                               std::function<void()> progress, std::function<void(complete_result)> cb,
                               complete_binder bind, put_condition cond, change_origin who)
{
    prepare_complete(bucket, id, std::move(parts),
        [this, alive = m_alive, progress = std::move(progress), cb, bind = std::move(bind),
         cond = std::move(cond), who = std::move(who)](s3_error err, assemble_plan plan) mutable
        {
            if (!*alive)
                return;
            if (!err.code.empty())
            {
                complete_result r;
                r.error = std::move(err);
                cb(std::move(r));
                return;
            }
            auto a = std::make_shared<assemble_state>();
            a->bucket       = std::move(plan.bucket);
            a->id           = std::move(plan.id);
            a->key          = std::move(plan.key);
            a->meta         = std::move(plan.meta);
            a->checksum_b64 = std::move(plan.checksum_b64);
            a->parts        = std::move(plan.parts);
            a->in_place     = plan.in_place;
            a->tmp_name     = m_store->tmp_name();
            a->tmp_path     = base_of(a->bucket) + "/tmp/" + a->tmp_name;
            a->dir_path     = upload_path(a->bucket, a->id);
            a->cb           = std::move(cb);
            a->progress     = std::move(progress);
            a->bind         = std::move(bind);
            a->cond         = std::move(cond);
            a->who          = std::move(who);
            assemble(std::move(a));
        });
}

void multipart_store::assemble_plan_object(assemble_plan plan, std::function<void()> progress,
                                           std::function<void(complete_result)> cb, complete_binder bind,
                                           put_condition cond, change_origin who)
{
    auto a = std::make_shared<assemble_state>();
    a->bucket       = std::move(plan.bucket);
    a->id           = std::move(plan.id);
    a->key          = std::move(plan.key);
    a->meta         = std::move(plan.meta);
    a->checksum_b64 = std::move(plan.checksum_b64);
    a->parts        = std::move(plan.parts);
    a->in_place     = plan.in_place;
    a->tmp_name     = m_store->tmp_name();
    a->tmp_path     = base_of(a->bucket) + "/tmp/" + a->tmp_name;
    a->dir_path     = upload_path(a->bucket, a->id);
    a->cb           = std::move(cb);
    a->progress     = std::move(progress);
    a->local        = false;
    a->bind         = std::move(bind);
    a->cond         = std::move(cond);
    a->who          = std::move(who);
    assemble(std::move(a));
}

void multipart_store::finish_complete(std::string bucket, std::string id, bool ok)
{
    mpu_upload* u = find_mut(bucket, id);
    if (!u)
        return;
    if (!ok)
    {
        reopen(*u);
        return;
    }
    u->remote_sealed = false;
    u->state = mpu_state::removing;
    remove_upload(std::move(bucket), std::move(id), {});
}

void multipart_store::reopen(mpu_upload& u)
{
    u.state         = mpu_state::open;
    u.remote_sealed = false;
    // A completion that may have linked the data file as the object leaves it to be read and never written again.
    if (u.place_planned)
        u.place_frozen = true;
    u.place_planned = false;
}

void multipart_store::unseal_stale(int64_t older_than_ms)
{
    for (auto& [k, up] : m_uploads)
        if (up->state == mpu_state::sealed && up->remote_sealed && up->sealed_ms < older_than_ms)
            reopen(*up);
}

parts_page multipart_store::list_parts(std::string_view bucket, std::string_view id, std::string_view key,
                                       uint32_t marker, uint32_t max_parts) const
{
    parts_page pg;
    const mpu_upload* up = find(bucket, id);
    if (!up || up->key != key || up->state == mpu_state::removing)
    {
        pg.status = st::no_such_key;
        return pg;
    }
    pg.key  = up->key;
    pg.id   = up->id;
    pg.algo = up->algo;
    if (acl_list a; decode_acl(object_acl_value(up->meta), a) && !object_acl_value(up->meta).empty())
        pg.owner = a.owner;
    for (auto it = up->parts.upper_bound(marker); it != up->parts.end(); ++it)
    {
        if (pg.rows.size() == max_parts)
        {
            pg.truncated = true;
            break;
        }
        const mpu_part& p = it->second;
        pg.rows.push_back({p.number, p.mtime_ms, p.etag(), p.size, up->algo, p.checksum_b64});
        pg.next_marker = p.number;
    }
    return pg;
}

void multipart_store::prepare_complete(std::string bucket, std::string id, std::vector<complete_part> parts,
                                       std::function<void(s3_error, assemble_plan)> cb, bool remote)
{
    auto fail = [&cb](std::string_view code, std::string_view message = {})
    {
        s3_error e = make_error(code);
        if (!message.empty())
            e.message = std::string(message);
        cb(std::move(e), {});
    };

    mpu_upload* up = find_mut(bucket, id);
    if (!up || up->state != mpu_state::open)
    {
        fail("NoSuchUpload");
        return;
    }
    up->state = mpu_state::sealed;
    up->remote_sealed = remote;
    up->sealed_ms     = static_cast<int64_t>(m_store->now_ms());
    ++m_inflight;

    auto go = [this, alive = m_alive, bucket, id, parts = std::move(parts), cb]() mutable
    {
        if (!*alive)
            return;
        --m_inflight;
        auto reject = [&](std::string_view code, std::string_view message = {})
        {
            if (mpu_upload* u = find_mut(bucket, id))
                reopen(*u);
            s3_error e = make_error(code);
            if (!message.empty())
                e.message = std::string(message);
            cb(std::move(e), {});
        };
        mpu_upload* u = find_mut(bucket, id);
        if (!u)
        {
            cb(make_error("NoSuchUpload"), {});
            return;
        }
        if (parts.empty())
        {
            reject("MalformedXML", "You must specify at least one part");
            return;
        }

        // The order of the list first, and then what each entry names, and only
        // then how big the parts are.
        {
            uint32_t prev = 0;
            for (const complete_part& want : parts)
            {
                if (want.number < 1 || want.number > mpu_max_parts)
                {
                    reject("InvalidArgument", "Part number must be an integer between 1 and 10000, inclusive");
                    return;
                }
                if (want.number <= prev)
                {
                    reject("InvalidPartOrder");
                    return;
                }
                prev = want.number;
            }
        }

        assemble_plan plan;
        uint64_t total = 0;
        std::string md5s;
        std::string raw_checksums;
        std::vector<std::pair<std::string, uint64_t>> part_checksums;
        for (size_t i = 0; i < parts.size(); ++i)
        {
            const complete_part& want = parts[i];
            const auto it = u->parts.find(want.number);
            if (it == u->parts.end() || it->second.etag() != want.etag)
            {
                reject("InvalidPart");
                return;
            }
            const mpu_part& have = it->second;
            if (want.checksum_algo_ != checksum_algo::none &&
                (want.checksum_algo_ != u->algo || want.checksum_b64 != have.checksum_b64))
            {
                reject("InvalidPart", "One or more of the specified parts has a checksum that does not match what was uploaded.");
                return;
            }
            if (i + 1 < parts.size() && have.size < mpu_min_part_bytes)
            {
                reject("EntityTooSmall", "Your proposed upload is smaller than the minimum allowed object size. "
                                         "Each part must be at least 5 MB in size, except the last part.");
                return;
            }
            total += have.size;
            md5s.append(reinterpret_cast<const char*>(have.md5.data()), have.md5.size());
            if (u->algo != checksum_algo::none)
            {
                std::string raw;
                if (!base64_decode(have.checksum_b64, raw))
                {
                    reject("InvalidPart");
                    return;
                }
                raw_checksums += raw;
                part_checksums.emplace_back(std::move(raw), have.size);
            }
            // A part written before parts kept their CRC leaves the object without the default, as it was then.
            else if (std::string raw; base64_decode(have.crc_b64, raw) && !raw.empty())
                part_checksums.emplace_back(std::move(raw), have.size);
            plan.parts.push_back(have);
        }
        if (total > m_store->options().max_object_bytes)
        {
            reject("EntityTooLarge");
            return;
        }

        plan.bucket   = bucket;
        plan.id       = id;
        plan.key      = u->key;
        plan.meta     = u->meta;
        plan.meta.size  = total;
        plan.meta.md5   = md5_of(md5s);
        plan.meta.parts = static_cast<uint32_t>(parts.size());
        cluster_stamp stamp;
        plan.meta.mtime_ms = cluster_stamp_of(plan.meta, stamp) ? stamp.mtime_ms : static_cast<int64_t>(m_store->now_ms());
        const auto type = std::find_if(plan.meta.extra.begin(), plan.meta.extra.end(),
                                       [](const auto& e) { return e.first == checksum_type_extra; });
        const bool full = type != plan.meta.extra.end();
        if (full)
            plan.meta.extra.erase(type);
        if (u->algo != checksum_algo::none)
        {
            plan.checksum_b64 = full ? full_object_checksum_b64(u->algo, part_checksums)
                                     : composite_checksum_b64(u->algo, raw_checksums, parts.size());
            set_checksum_b64(plan.meta, u->algo, plan.checksum_b64);
        }
        // An upload with no algorithm gives its object S3's default, of the whole bytes, combined from its parts' CRCs.
        else if (part_checksums.size() == parts.size())
        {
            plan.checksum_b64 = full_object_checksum_b64(default_checksum_algo, part_checksums);
            if (!plan.checksum_b64.empty())
                set_checksum_b64(plan.meta, default_checksum_algo, plan.checksum_b64);
        }
        // Kept in the header when it fits and after the body otherwise, so any list S3 takes completes.
        const part_list list = list_of(plan.parts, plan.meta);
        const uint8_t sealed = sse_version_of(plan.meta);
        uint64_t body = 0;
        for (const mpu_part& p : plan.parts)
            body += sealed ? sse_stored_len(p.size, sealed) : p.size;
        // A version 2 stream is sealed as the part number it was uploaded as, so its object keeps the numbers.
        bool trailer = !record_part_list(plan.meta, list, body, sealed >= sse_format, m_list_max).empty();
        plan.meta.extra.emplace_back(std::string(upload_id_extra), id);
        plan.in_place = copy_free(*u, plan.parts);
        // The room in front of part 1 was reserved without the parts' checksums, which follow the body when it is short.
        if (plan.in_place && !trailer && completed_header_len(plan.key, plan.meta) > u->place_base)
        {
            trailer = !record_part_list(plan.meta, list, body, sealed >= sse_format, 0).empty();
            plan.meta.extra.emplace_back(std::string(upload_id_extra), id);
        }
        m_trailers += trailer ? 1 : 0;
        u->place_planned = plan.in_place;
        cb({}, std::move(plan));
    };

    if (up->committing > 0)
        up->on_idle = std::move(go);
    else
        go();
}

void multipart_store::assemble(std::shared_ptr<assemble_state> a)
{
    a->sealed = sse_version_of(a->meta);
    part_trailer t;
    const bool listed_after = part_trailer_of(a->meta, t);
    if (listed_after)
        a->trailer = encode_part_list(list_of(a->parts, a->meta), a->meta.size);
    if (a->bind)
        if (s3_error e = a->bind(a->meta); !e.code.empty())
        {
            ++m_inflight;
            assemble_fail(a, std::move(e));
            return;
        }
    const uint64_t base = a->in_place && !a->parts.empty() ? a->parts.front().data_off : 0;
    auto header = std::make_shared<std::string>(encode_object_header(a->key, a->meta, base));
    // A header that outgrew the room its upload reserved would be written over part 1.
    if (!a->in_place || header->size() != base)
    {
        a->in_place = false;
        assemble_copy(std::move(a));
        return;
    }
    ++m_inflight;

    // The data file is the object already: its header goes in front, its part list after
    // the last part when the header names one there, it is synced and given a name in tmp/,
    // and that name is committed like any assembled object.
    const std::string data = a->dir_path + "/data";
    auto fd    = hold_fd(m_loop, m_alive, -1);
    auto probe = std::make_shared<std::array<char, 2>>();
    auto linking = std::make_shared<bool>(false);
    auto list  = std::make_shared<std::string>(a->trailer);
    const uint64_t end = base + (listed_after ? t.at : stored_size(a->meta));
    file_io* io = m_io;
    auto ch = std::make_shared<disk_chain>(m_alive);
    ch->then([io, data, fd](file_io::done d)
    {
        return io->openat(AT_FDCWD, data, O_RDWR | O_CLOEXEC, 0,
                          [fd, d](int64_t r) { if (r >= 0) *fd = static_cast<int>(r); d(r < 0 ? r : 0); });
    });
    // The file ends where the last part does, so nothing but the object is committed.
    ch->then([io, fd, probe, end](file_io::done d)
    {
        return io->pread(*fd, probe->data(), 2, end - 1, [d](int64_t r) { d(r == 1 ? 0 : -EIO); });
    });
    ch->then([io, fd, header](file_io::done d)
    {
        return io->pwrite(*fd, header->data(), static_cast<uint32_t>(header->size()), 0, std::move(d));
    });
    ch->then([io, fd, list, end](file_io::done d)
    {
        if (list->empty())
        {
            d(0);
            return true;
        }
        const int64_t want = static_cast<int64_t>(list->size());
        return io->pwrite(*fd, list->data(), static_cast<uint32_t>(list->size()), end,
                          [d, want](int64_t r) { d(r == want ? 0 : r < 0 ? r : -EIO); });
    });
    ch->then([io, fd](file_io::done d) { return io->sync(*fd, true, std::move(d)); });
    ch->then([io, data, a, linking](file_io::done d)
    {
        *linking = true;
        return io->linkat(AT_FDCWD, data, AT_FDCWD, a->tmp_path, std::move(d));
    });
    // The buffers a step hands the kernel live as long as the chain, since a launched step lets go of its captures.
    ch->run([this, alive = m_alive, a, fd, linking, header, probe, list](int64_t r) mutable
    {
        if (!*alive)
            return;
        fd.reset();
        if (r >= 0)
        {
            assemble_commit(a);
            return;
        }
        if (*linking)
        {
            assemble_fail(a, errno_st(r));
            return;
        }
        // Not as the plan said, so the parts are copied from where they are.
        a->in_place = false;
        --m_inflight;
        assemble_copy(a);
    });
}

void multipart_store::assemble_copy(std::shared_ptr<assemble_state> a)
{
    ++m_inflight;
    a->buf[0] = std::make_unique_for_overwrite<char[]>(chunk_bytes);
    a->buf[1] = std::make_unique_for_overwrite<char[]>(chunk_bytes);

    const bool q = m_io->openat(AT_FDCWD, a->tmp_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600,
        [this, alive = m_alive, a](int64_t r)
        {
            if (!*alive)
                return;
            if (r < 0)
            {
                a->failed = true;
                a->err    = r;
                a->header_done = true;
                assemble_pump(a);
                return;
            }
            a->dst = hold_fd(m_loop, m_alive, static_cast<int>(r));
            const auto header = std::make_shared<std::string>(encode_object_header(a->key, a->meta));
            a->hdr_len = header->size();
            a->dst_off = 0;
            const bool qh = m_io->pwrite(*a->dst, header->data(), static_cast<uint32_t>(header->size()), 0,
                [this, alive, a, header](int64_t rh)
                {
                    if (!*alive)
                        return;
                    if (rh < 0)
                    {
                        a->failed = true;
                        a->err    = rh;
                    }
                    a->dst_off     = a->hdr_len;
                    a->header_done = true;
                    assemble_pump(a);
                });
            if (!qh)
            {
                a->failed = true;
                a->err    = -EIO;
                a->header_done = true;
                assemble_pump(a);
            }
        });
    if (!q)
    {
        a->failed = true;
        a->err    = -EIO;
        a->header_done = true;
        assemble_pump(a);
    }
}

// Reads the next megabyte of the parts and writes it into the object, with a
// second buffer read while the first is written; the bytes pass through this
// process because io_uring has no copy between two files.
void multipart_store::assemble_pump(const std::shared_ptr<assemble_state>& a)
{
    while (!a->failed && a->header_done && a->part_idx < a->parts.size())
    {
        const mpu_part& p = a->parts[a->part_idx];
        const uint64_t  len = a->sealed ? sse_stored_len(p.size, a->sealed) : p.size;
        if (len == 0 || a->part_off >= len)
        {
            ++a->part_idx;
            a->part_off = 0;
            a->cur.reset();
            continue;
        }
        const int slot = a->buf_free[0] ? 0 : (a->buf_free[1] ? 1 : -1);
        if (slot < 0)
            break;
        if (!a->cur)
        {
            if (a->opening)
                break;
            a->opening = true;
            const std::string path = a->dir_path + "/" + (p.in_place ? std::string("data") : std::to_string(p.number));
            const bool q = m_io->openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0,
                [this, alive = m_alive, a](int64_t r)
                {
                    if (!*alive)
                        return;
                    a->opening = false;
                    if (r < 0)
                    {
                        a->failed = true;
                        a->err    = r;
                    }
                    else
                        a->cur = hold_fd(m_loop, m_alive, static_cast<int>(r));
                    assemble_pump(a);
                });
            if (!q)
            {
                a->opening = false;
                a->failed  = true;
                a->err     = -EIO;
            }
            break;
        }

        const uint32_t n = static_cast<uint32_t>(std::min<uint64_t>(chunk_bytes, len - a->part_off));
        const uint64_t src_off = p.data_off + a->part_off;
        const uint64_t dst_off = a->dst_off;
        std::shared_ptr<int> src = a->cur;
        a->buf_free[slot] = false;
        ++a->inflight;
        a->part_off += n;
        a->dst_off  += n;
        if (a->part_off >= len)
        {
            ++a->part_idx;
            a->part_off = 0;
            a->cur.reset();
        }

        auto chunk_done = [this, alive = m_alive, a, slot](int64_t res)
        {
            if (!*alive)
                return;
            a->buf_free[slot] = true;
            --a->inflight;
            if (a->progress)
                a->progress();
            if (res < 0 && !a->failed)
            {
                a->failed = true;
                a->err    = res;
            }
            assemble_pump(a);
        };
        char* buf = a->buf[slot].get();
        const bool qr = m_io->pread(*src, buf, n, src_off,
            [this, a, src, buf, n, dst_off, chunk_done](int64_t rn)
            {
                if (rn != static_cast<int64_t>(n))
                {
                    chunk_done(rn < 0 ? rn : -EIO);
                    return;
                }
                if (!m_io->pwrite(*a->dst, buf, n, dst_off, chunk_done))
                    chunk_done(-EIO);
            });
        if (!qr)
        {
            a->buf_free[slot] = true;
            --a->inflight;
            a->failed = true;
            a->err    = -EIO;
        }
    }

    if (a->inflight == 0 && !a->opening && a->header_done && !a->finishing &&
        (a->failed || a->part_idx >= a->parts.size()))
    {
        a->finishing = true;
        assemble_finish(a);
    }
}

void multipart_store::assemble_fail(const std::shared_ptr<assemble_state>& a, st why)
{
    assemble_fail(a, error_for(why));
}

void multipart_store::assemble_fail(const std::shared_ptr<assemble_state>& a, s3_error why)
{
    // What every way out does: the upload is open again, and the client is told why.
    --m_inflight;
    a->dst.reset();
    if (!m_io->unlinkat(AT_FDCWD, a->tmp_path, 0, [](int64_t) {})) {}
    if (a->local)
        if (mpu_upload* u = find_mut(a->bucket, a->id))
            reopen(*u);
    complete_result r;
    r.error = std::move(why);
    a->cb(std::move(r));
}

void multipart_store::assemble_finish(const std::shared_ptr<assemble_state>& a)
{
    if (a->failed)
    {
        assemble_fail(a, errno_st(a->err));
        return;
    }
    // The part list the header had no room for goes after the last part, before the sync that makes both durable.
    if (!a->trailer.empty())
    {
        auto list = std::make_shared<std::string>(std::move(a->trailer));
        a->trailer.clear();
        const bool qt = m_io->pwrite(*a->dst, list->data(), static_cast<uint32_t>(list->size()), a->dst_off,
            [this, alive = m_alive, a, list](int64_t r)
            {
                if (!*alive)
                    return;
                if (r != static_cast<int64_t>(list->size()))
                {
                    assemble_fail(a, errno_st(r < 0 ? r : -EIO));
                    return;
                }
                a->dst_off += list->size();
                assemble_finish(a);
            });
        if (!qt)
            assemble_fail(a, st::io_error);
        return;
    }
    const bool q = m_io->sync(*a->dst, true, [this, alive = m_alive, a](int64_t r)
    {
        if (!*alive)
            return;
        if (r < 0)
        {
            assemble_fail(a, errno_st(r));
            return;
        }
        a->dst.reset();
        assemble_commit(a);
    });
    if (!q)
        assemble_fail(a, st::io_error);
}

void multipart_store::assemble_commit(const std::shared_ptr<assemble_state>& a)
{
    commit_request req;
    req.bucket   = a->bucket;
    req.key      = a->key;
    req.tmp_name = a->tmp_name;
    req.meta     = a->meta;
    req.cond     = a->cond;
    req.cause    = change_cause::complete;
    req.who      = a->who;
    m_store->commit(std::move(req), [this, alive = m_alive, a](put_result pr)
    {
        if (!*alive)
            return;
        if (pr.status != st::ok)
        {
            // The commit removed the temporary file itself when it could.
            assemble_fail(a, pr.status);
            return;
        }
        --m_inflight;
        if (a->local)
            if (mpu_upload* u = find_mut(a->bucket, a->id))
                u->state = mpu_state::removing;
        complete_result out;
        out.meta         = pr.meta;
        out.checksum_b64 = a->checksum_b64;
        const std::string bucket = a->bucket;
        const std::string id     = a->id;
        const bool local = a->local;
        a->cb(std::move(out));
        if (local)
            remove_upload(bucket, id, {});
    });
}

// ─── Removing ───────────────────────────────────────────────────────────────

bool multipart_store::abort(std::string_view bucket, std::string_view id, std::function<void()> cb)
{
    mpu_upload* up = find_mut(bucket, id);
    if (!up || up->state != mpu_state::open)
        return false;
    up->state = mpu_state::removing;
    remove_upload(std::string(bucket), std::string(id), std::move(cb));
    return true;
}

size_t multipart_store::expire(int64_t cutoff_ms)
{
    std::vector<std::pair<std::string, std::string>> old;
    for (const auto& [k, up] : m_uploads)
        if (up->state == mpu_state::open && up->initiated_ms < cutoff_ms)
            old.emplace_back(up->bucket, up->id);
    for (const auto& [b, i] : old)
        if (abort(b, i, {})) {}
    return old.size();
}

void multipart_store::remove_upload(std::string bucket, std::string id, std::function<void()> cb)
{
    mpu_upload* up = find_mut(bucket, id);
    if (!up)
    {
        if (cb)
            cb();
        return;
    }
    ++m_inflight;
    auto go = [this, alive = m_alive, bucket, id, cb = std::move(cb)]() mutable
    {
        if (!*alive)
            return;
        mpu_upload* u = find_mut(bucket, id);
        std::vector<uint32_t> numbers;
        if (u)
            for (const auto& [n, p] : u->parts)
                numbers.push_back(n);
        remove_files(bucket, id, std::move(numbers), std::move(cb));
    };
    if (up->committing > 0)
        up->on_idle = std::move(go);
    else
        go();
}

void multipart_store::remove_files(std::string bucket, std::string id, std::vector<uint32_t> parts,
                                   std::function<void()> cb)
{
    struct batch
    {
        std::vector<std::string> paths;
        size_t next{0};
        size_t inflight{0};
        std::function<void()> done;
    };
    auto b = std::make_shared<batch>();
    const std::string dir = upload_path(bucket, id);
    for (uint32_t n : parts)
        b->paths.push_back(dir + "/" + std::to_string(n));
    b->paths.push_back(dir + "/data");

    auto ch = std::make_shared<disk_chain>(m_alive);
    // The meta file goes first, so an upload cut short here is not found again.
    ch->then([this, dir](file_io::done d) { return m_io->unlinkat(AT_FDCWD, dir + "/meta", 0, std::move(d)); }, -ENOENT);
    ch->then([this, b](file_io::done d)
    {
        b->done = [d]() { d(0); };
        auto pump = std::make_shared<std::function<void()>>();
        std::weak_ptr<std::function<void()>> weak = pump;
        *pump = [this, b, weak, alive = m_alive]()
        {
            if (!*alive)
                return;
            // Held by each completion, so the function lives while any is owed.
            auto self = weak.lock();
            while (b->inflight < unlink_window && b->next < b->paths.size())
            {
                const std::string& path = b->paths[b->next++];
                ++b->inflight;
                const bool q = m_io->unlinkat(AT_FDCWD, path, 0, [b, self, alive](int64_t)
                {
                    if (!*alive)
                        return;
                    --b->inflight;
                    (*self)();
                });
                if (!q)
                    --b->inflight;
            }
            if (b->inflight == 0 && b->next >= b->paths.size())
            {
                auto f = std::move(b->done);
                b->done = nullptr;
                if (f)
                    f();
            }
        };
        (*pump)();
        return true;
    });
    ch->then([this, dir](file_io::done d) { return m_io->unlinkat(AT_FDCWD, dir, AT_REMOVEDIR, std::move(d)); });

    ch->run([this, alive = m_alive, bucket, id, cb = std::move(cb)](int64_t r)
    {
        if (!*alive)
            return;
        if (r < 0)
            LOG_WARN(("storage: multipart upload " + id + " of bucket " + bucket +
                      " left files behind: " + std::strerror(static_cast<int>(-r))).c_str());
        forget(bucket, id);
        --m_inflight;
        if (cb)
            cb();
    });
}

void multipart_store::forget(const std::string& bucket, const std::string& id)
{
    const auto it = m_uploads.find(key_of(bucket, id));
    if (it == m_uploads.end())
        return;
    std::unique_ptr<mpu_upload> up = std::move(it->second);
    m_uploads.erase(it);
    m_store->release_bytes(up->held);
    if (up->dir_fd >= 0)
        m_loop->close_fd(up->dir_fd);
    up->dir_fd = -1;
    // Commits waiting behind another find the upload gone and drop their file.
    for (auto& [n, waiting] : up->lanes)
        for (auto& fn : waiting)
            fn();
    if (const auto w = m_removal_waiters.find(bucket); w != m_removal_waiters.end() && !removing_in(bucket))
    {
        std::vector<std::function<void()>> ready = std::move(w->second);
        m_removal_waiters.erase(w);
        for (auto& fn : ready)
            fn();
    }
}

}   // namespace socketley::storage
