// A folder, or some of what is in it, as one ZIP streamed while it is read: each object stored as it is (no
// compression, which films and pictures would not take), so the archive's length is known before its first byte and is
// sent as its Content-Length, and a browser shows how far it has come and how long is left. Each entry's CRC-32 is taken
// as its bytes go by and written in a data descriptor after them; an entry or an offset past 4 GiB takes ZIP64's fields,
// and the archive ZIP64's end records when anything in it needs them.
#include "storage_run.h"

#include <ctime>
#include <unordered_set>

#include "body_reader.h"
#include "checksum.h"
#include "sse.h"
#include "tierer.h"
#include "../../shared/util/logging.h"
#include "../../shared/util/text_list.h"

namespace socketley::storage
{

struct zip_job
{
    struct entry
    {
        std::string key;
        std::string name;
        uint64_t    size{0};
        int64_t     mtime_ms{0};
        uint64_t    offset{0};
        bool        zip64{false};
        uint32_t    crc{0};
    };
    std::string bucket;
    std::vector<entry> entries;
    size_t      index{0};
    enum class step : uint8_t { open, data, central, done } at{step::open};
    std::shared_ptr<body_reader> src;
    int         fd{-1};
    std::unique_ptr<checksum_stream> crc;
    uint64_t    read{0};
    uint64_t    central_offset{0};
};

namespace
{

constexpr uint64_t u32_max = 0xffffffffull;

void le16(std::string& o, uint32_t v)
{
    o += static_cast<char>(v & 0xff);
    o += static_cast<char>((v >> 8) & 0xff);
}
void le32(std::string& o, uint32_t v)
{
    le16(o, v & 0xffff);
    le16(o, v >> 16);
}
void le64(std::string& o, uint64_t v)
{
    le32(o, static_cast<uint32_t>(v & u32_max));
    le32(o, static_cast<uint32_t>(v >> 32));
}

// The DOS date and time a ZIP entry carries, in UTC, which no reader has a zone for anyway.
void dos_time(int64_t ms, uint16_t& date, uint16_t& time)
{
    const std::time_t t = static_cast<std::time_t>(ms / 1000);
    std::tm tm{};
    gmtime_r(&t, &tm);
    if (tm.tm_year < 80)
    {
        date = (1 << 5) | 1;
        time = 0;
        return;
    }
    date = static_cast<uint16_t>(((tm.tm_year - 80) << 9) | ((tm.tm_mon + 1) << 5) | tm.tm_mday);
    time = static_cast<uint16_t>((tm.tm_hour << 11) | (tm.tm_min << 5) | (tm.tm_sec / 2));
}

constexpr uint16_t flags = (1 << 3) | (1 << 11);   // sizes and CRC in a data descriptor; names in UTF-8

size_t local_size(const zip_job::entry& e) { return 30 + e.name.size() + (e.zip64 ? 20 : 0); }
size_t descriptor_size(const zip_job::entry& e) { return e.zip64 ? 24 : 16; }
size_t central_size(const zip_job::entry& e) { return 46 + e.name.size() + (e.zip64 ? 28 : 0); }

std::string local_header(const zip_job::entry& e)
{
    std::string o;
    uint16_t d, t;
    dos_time(e.mtime_ms, d, t);
    le32(o, 0x04034b50);
    le16(o, e.zip64 ? 45 : 20);
    le16(o, flags);
    le16(o, 0);   // stored
    le16(o, t);
    le16(o, d);
    le32(o, 0);   // the CRC and the sizes follow the data
    le32(o, e.zip64 ? u32_max : 0);
    le32(o, e.zip64 ? u32_max : 0);
    le16(o, static_cast<uint32_t>(e.name.size()));
    le16(o, e.zip64 ? 20 : 0);
    o += e.name;
    if (e.zip64)
    {
        le16(o, 0x0001);
        le16(o, 16);
        le64(o, 0);
        le64(o, 0);
    }
    return o;
}

std::string descriptor(const zip_job::entry& e)
{
    std::string o;
    le32(o, 0x08074b50);
    le32(o, e.crc);
    if (e.zip64)
    {
        le64(o, e.size);
        le64(o, e.size);
    }
    else
    {
        le32(o, static_cast<uint32_t>(e.size));
        le32(o, static_cast<uint32_t>(e.size));
    }
    return o;
}

std::string central_entry(const zip_job::entry& e)
{
    std::string o;
    uint16_t d, t;
    dos_time(e.mtime_ms, d, t);
    le32(o, 0x02014b50);
    le16(o, (3 << 8) | 45);   // made on Unix, ZIP64-capable
    le16(o, e.zip64 ? 45 : 20);
    le16(o, flags);
    le16(o, 0);
    le16(o, t);
    le16(o, d);
    le32(o, e.crc);
    le32(o, e.zip64 ? u32_max : static_cast<uint32_t>(e.size));
    le32(o, e.zip64 ? u32_max : static_cast<uint32_t>(e.size));
    le16(o, static_cast<uint32_t>(e.name.size()));
    le16(o, e.zip64 ? 28 : 0);
    le16(o, 0);   // comment
    le16(o, 0);   // disk
    le16(o, 0);   // internal attributes
    le32(o, 0100644u << 16);
    le32(o, e.zip64 ? u32_max : static_cast<uint32_t>(e.offset));
    o += e.name;
    if (e.zip64)
    {
        le16(o, 0x0001);
        le16(o, 24);
        le64(o, e.size);
        le64(o, e.size);
        le64(o, e.offset);
    }
    return o;
}

std::string end_records(uint64_t count, uint64_t cd_offset, uint64_t cd_size, bool zip64)
{
    std::string o;
    if (zip64)
    {
        const uint64_t at = cd_offset + cd_size;
        le32(o, 0x06064b50);
        le64(o, 44);
        le16(o, (3 << 8) | 45);
        le16(o, 45);
        le32(o, 0);
        le32(o, 0);
        le64(o, count);
        le64(o, count);
        le64(o, cd_size);
        le64(o, cd_offset);
        le32(o, 0x07064b50);
        le32(o, 0);
        le64(o, at);
        le32(o, 1);
    }
    le32(o, 0x06054b50);
    le16(o, 0);
    le16(o, 0);
    le16(o, zip64 ? 0xffff : static_cast<uint32_t>(count));
    le16(o, zip64 ? 0xffff : static_cast<uint32_t>(count));
    le32(o, zip64 ? u32_max : static_cast<uint32_t>(cd_size));
    le32(o, zip64 ? u32_max : static_cast<uint32_t>(cd_offset));
    le16(o, 0);
    return o;
}

// A key under the folder as a name an unzipper puts inside the folder it unpacks into: its segments without the empty
// ones, "." and "..", with '\\' and control characters made '_'; empty when nothing is left.
std::string entry_name(std::string_view rel)
{
    std::string out;
    while (!rel.empty())
    {
        const std::string_view seg = take_item(rel, '/');
        if (seg.empty() || seg == "." || seg == "..")
            continue;
        if (!out.empty())
            out += '/';
        for (const char ch : seg)
        {
            const auto u = static_cast<unsigned char>(ch);
            out += ch == '\\' || u < 0x20 || u == 0x7f ? '_' : ch;
        }
    }
    return out;
}

// `name` made one no entry before it has, by " (2)", " (3)" and on before its last segment's extension, since an
// unzipper writes a second entry of one name over the first.
std::string unique_name(std::string name, std::unordered_set<std::string>& taken,
                        const std::unordered_set<std::string>& dirs)
{
    if (!dirs.contains(name) && taken.insert(name).second)
        return name;
    const size_t slash = name.rfind('/');
    const size_t dot = name.rfind('.');
    const size_t cut = dot != std::string::npos && (slash == std::string::npos || dot > slash + 1) ? dot : name.size();
    for (int n = 2;; ++n)
    {
        std::string next = name.substr(0, cut) + " (" + std::to_string(n) + ")" + name.substr(cut);
        if (!dirs.contains(next) && taken.insert(next).second)
            return next;
    }
}

}   // namespace

void storage_run::zip_start(const std::shared_ptr<conn>& c, std::string bucket, std::string prefix,
                            std::vector<std::string> only, std::string archive, bool by_link)
{
    list_query q;
    q.prefix = prefix;
    std::weak_ptr<conn> weak = c;
    app_list(bucket, std::move(q), [this, weak, bucket, prefix, by_link, only = std::move(only), archive = std::move(archive)](st s, list_page p) mutable
    {
        auto c = weak.lock();
        if (!c || c->dead)
            return;
        if (s != st::ok)
        {
            app_reply(c, 404, "No such folder.\n");
            return;
        }
        if (p.truncated)
        {
            app_reply(c, 413, "The folder holds too many files for one archive.\n");
            return;
        }
        auto job = std::make_shared<zip_job>();
        job->bucket = bucket;
        uint64_t at = 0;
        size_t skipped = 0;
        std::unordered_set<std::string> taken, dirs;
        std::vector<std::pair<list_entry*, std::string>> picked;
        for (list_entry& e : p.objects)
        {
            std::string name = e.key.substr(prefix.size());
            // A folder's marker is no file, and a selection takes only what it named and what is under those.
            if (name.empty() || name.back() == '/')
                continue;
            if (!only.empty() && std::none_of(only.begin(), only.end(), [&name](const std::string& o)
                                              { return name == o || (name.starts_with(o) && name[o.size()] == '/'); }))
                continue;
            // What only its client's key opens cannot be read here, and what the user may not read is not given.
            if (sse_mode_of(e.meta) == sse_mode::c || (!by_link && !app_allowed(c, "GET", bucket, e.key)))
            {
                ++skipped;
                continue;
            }
            // A key holding "..", a leading or doubled '/', '\\' or a control character would unpack outside the folder
            // or not as named: the visitor of a link unpacks names the folder's owner chose.
            std::string safe = entry_name(name);
            if (safe.empty())
                continue;
            // A file named as a folder of another entry would keep that folder from unpacking.
            for (size_t sl = safe.find('/'); sl != std::string::npos; sl = safe.find('/', sl + 1))
                dirs.insert(safe.substr(0, sl));
            picked.emplace_back(&e, std::move(safe));
        }
        for (auto& [ep, safe] : picked)
        {
            list_entry& e = *ep;
            zip_job::entry z;
            z.key      = std::move(e.key);
            z.name     = unique_name(std::move(safe), taken, dirs);
            z.size     = e.meta.size;
            z.mtime_ms = e.meta.mtime_ms;
            z.offset   = at;
            z.zip64    = z.size >= u32_max || at >= u32_max;
            at += local_size(z) + z.size + descriptor_size(z);
            job->entries.push_back(std::move(z));
        }
        if (job->entries.empty())
        {
            app_reply(c, 404, skipped ? "Nothing here may be read into an archive.\n" : "Nothing to put in an archive.\n");
            return;
        }
        uint64_t cd = 0;
        for (const zip_job::entry& e : job->entries)
            cd += central_size(e);
        job->central_offset = at;
        const bool zip64 = job->entries.size() >= 0xffff || at >= u32_max || cd >= u32_max ||
                           std::any_of(job->entries.begin(), job->entries.end(), [](const zip_job::entry& e) { return e.zip64; });
        const uint64_t total = at + cd + (zip64 ? 56 + 20 : 0) + 22;

        response head;
        head.headers.emplace_back("Content-Type", "application/zip");
        head.headers.emplace_back("Content-Disposition", attachment_of(archive + ".zip"));
        head.headers.emplace_back("Cache-Control", "no-store");
        head.head_only = true;
        head.has_length_override = true;
        head.length_override = total;
        head.close = !c->req.keep_alive;
        c->zip = std::move(job);
        c->ph  = phase::respond;
        c->close_after_write = head.close;
        c->after_write = conn::after_kind::pump;
        access_log(c, 200, total);
        if (c->req.method == "HEAD" || c->req.head_request)
        {
            c->zip.reset();
            c->after_write = conn::after_kind::finish;
        }
        queue_write(c, response_head(*c, head));
    });
}

void storage_run::zip_end(conn& c)
{
    if (c.zip && c.zip->fd >= 0)
        m_loop.close_fd(c.zip->fd);
    c.zip.reset();
}

void storage_run::zip_pump(const std::shared_ptr<conn>& c)
{
    zip_job& j = *c->zip;
    if (j.at == zip_job::step::done)
    {
        c->zip.reset();
        file_done(c);
        return;
    }
    if (j.at == zip_job::step::central)
    {
        std::string out;
        uint64_t cd = 0;
        for (const zip_job::entry& e : j.entries)
        {
            std::string one = central_entry(e);
            cd += one.size();
            out += one;
        }
        const bool zip64 = j.entries.size() >= 0xffff || j.central_offset >= u32_max || cd >= u32_max ||
                           std::any_of(j.entries.begin(), j.entries.end(), [](const zip_job::entry& e) { return e.zip64; });
        out += end_records(j.entries.size(), j.central_offset, cd, zip64);
        j.at = zip_job::step::done;
        c->after_write = conn::after_kind::pump;
        queue_write(c, std::move(out));
        return;
    }
    if (j.at == zip_job::step::open)
    {
        if (j.index == j.entries.size())
        {
            j.at = zip_job::step::central;
            zip_pump(c);
            return;
        }
        const zip_job::entry& e = j.entries[j.index];
        std::weak_ptr<conn> weak = c;
        m_store.open_object(j.bucket, e.key, 0, [this, weak](open_result o)
        {
            auto cc = weak.lock();
            if (!cc || cc->dead || !cc->zip)
            {
                if (o.fd >= 0)
                    m_loop.close_fd(o.fd);
                return;
            }
            zip_job& z = *cc->zip;
            zip_job::entry& e = z.entries[z.index];
            sse_key key{};
            s3_error err;
            // The length is promised, so an object gone, changed in size or unreadable since it was listed can only
            // end the connection, which a browser reports as a failed download.
            const bool ok = o.status == st::ok && !o.delete_marker && o.meta.size == e.size &&
                            sse_read_key(cc, o.meta, sse_c_prefix, key, err, true);
            if (ok)
            {
                if (is_tiered(o.meta))
                {
                    if (o.fd >= 0)
                        m_loop.close_fd(o.fd);
                    o.fd = -1;
                    z.src = m_tier.reader(o.meta, 0, e.size);
                }
                else
                    z.src = body_reader::make(m_io, &m_hash, m_store.alive_token(), o.fd, o.data_off, o.meta,
                                              is_encrypted(o.meta) ? &key : nullptr, 0, e.size);
            }
            if (!ok || !z.src)
            {
                if (o.fd >= 0)
                    m_loop.close_fd(o.fd);
                LOG_WARN(("storage: \"" + z.bucket + "/" + e.key + "\" could not be read into an archive").c_str());
                close_conn(cc);
                return;
            }
            z.fd   = o.fd;
            z.crc  = std::make_unique<checksum_stream>(checksum_algo::crc32);
            z.read = 0;
            z.at   = zip_job::step::data;
            cc->after_write = conn::after_kind::pump;
            queue_write(cc, local_header(e));
        });
        return;
    }
    // The entry's bytes, a window at a time, each written before the next is read.
    std::weak_ptr<conn> weak = c;
    j.src->next([this, weak](bool ok, std::string_view piece)
    {
        auto cc = weak.lock();
        if (!cc || cc->dead || !cc->zip)
            return;
        zip_job& z = *cc->zip;
        zip_job::entry& e = z.entries[z.index];
        if (!ok || z.read + piece.size() > e.size || (piece.empty() && z.read != e.size))
        {
            LOG_WARN(("storage: \"" + z.bucket + "/" + e.key + "\" could not be read whole into an archive").c_str());
            close_conn(cc);
            return;
        }
        cc->after_write = conn::after_kind::pump;
        if (piece.empty())
        {
            const std::string raw = z.crc->peek_raw();
            e.crc = (static_cast<uint32_t>(static_cast<uint8_t>(raw[0])) << 24) |
                    (static_cast<uint32_t>(static_cast<uint8_t>(raw[1])) << 16) |
                    (static_cast<uint32_t>(static_cast<uint8_t>(raw[2])) << 8) | static_cast<uint8_t>(raw[3]);
            if (z.fd >= 0)
                m_loop.close_fd(z.fd);
            z.fd = -1;
            z.src.reset();
            z.crc.reset();
            ++z.index;
            z.at = zip_job::step::open;
            queue_write(cc, descriptor(e));
            return;
        }
        z.crc->update(piece.data(), piece.size());
        z.read += piece.size();
        queue_write(cc, std::string(piece));
    });
}

}   // namespace socketley::storage
