// A ZIP object opened on the server into a folder beside it: its central directory read from its end, then each file
// in it read from its place, opened when it is deflated, checked against its CRC-32 and size, and written as an object
// of its own, a few at a time. Nothing crosses the client's line but the request and the answer, and the job goes on
// to its end when the page that asked for it is closed.
#include "storage_run.h"

#include "body_reader.h"
#include "checksum.h"
#include "inflate.h"
#include "sse.h"
#include "tierer.h"
#include "../../shared/logging.h"

namespace socketley::storage
{

namespace
{

// What is believed of an archive before a byte of it is opened: a directory larger than this, or more entries, is
// not taken for one a drive should unpack.
constexpr uint64_t directory_max = 64ull << 20;
constexpr size_t   entries_max   = 100000;
// Files written side by side, so small ones are not each waiting for the last one's sync.
constexpr size_t   inflight_max  = 4;
// What one turn of the inflater gives the put, so a large entry never holds the loop or a megabyte more.
constexpr size_t   inflate_turn  = 1u << 20;
// Names kept for the answer, of the files not written.
constexpr size_t   names_kept    = 20;
// Where a key ends for S3.
constexpr size_t   key_max       = 1024;

uint16_t rd16(std::string_view b, size_t at)
{
    return static_cast<uint16_t>(static_cast<uint8_t>(b[at]) | static_cast<uint8_t>(b[at + 1]) << 8);
}
uint32_t rd32(std::string_view b, size_t at)
{
    return rd16(b, at) | static_cast<uint32_t>(rd16(b, at + 2)) << 16;
}
uint64_t rd64(std::string_view b, size_t at)
{
    return rd32(b, at) | static_cast<uint64_t>(rd32(b, at + 4)) << 32;
}

// The upper half of code page 437, which a ZIP's name is in unless its UTF-8 flag says otherwise.
constexpr uint16_t cp437_high[128] = {
    0x00c7, 0x00fc, 0x00e9, 0x00e2, 0x00e4, 0x00e0, 0x00e5, 0x00e7, 0x00ea, 0x00eb, 0x00e8, 0x00ef, 0x00ee, 0x00ec,
    0x00c4, 0x00c5, 0x00c9, 0x00e6, 0x00c6, 0x00f4, 0x00f6, 0x00f2, 0x00fb, 0x00f9, 0x00ff, 0x00d6, 0x00dc, 0x00a2,
    0x00a3, 0x00a5, 0x20a7, 0x0192, 0x00e1, 0x00ed, 0x00f3, 0x00fa, 0x00f1, 0x00d1, 0x00aa, 0x00ba, 0x00bf, 0x2310,
    0x00ac, 0x00bd, 0x00bc, 0x00a1, 0x00ab, 0x00bb, 0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556,
    0x2555, 0x2563, 0x2551, 0x2557, 0x255d, 0x255c, 0x255b, 0x2510, 0x2514, 0x2534, 0x252c, 0x251c, 0x2500, 0x253c,
    0x255e, 0x255f, 0x255a, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256c, 0x2567, 0x2568, 0x2564, 0x2565, 0x2559,
    0x2558, 0x2552, 0x2553, 0x256b, 0x256a, 0x2518, 0x250c, 0x2588, 0x2584, 0x258c, 0x2590, 0x2580, 0x03b1, 0x00df,
    0x0393, 0x03c0, 0x03a3, 0x03c3, 0x00b5, 0x03c4, 0x03a6, 0x0398, 0x03a9, 0x03b4, 0x221e, 0x03c6, 0x03b5, 0x2229,
    0x2261, 0x00b1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00f7, 0x2248, 0x00b0, 0x2219, 0x00b7, 0x221a, 0x207f, 0x00b2,
    0x25a0, 0x00a0};

std::string from_cp437(std::string_view s)
{
    std::string o;
    for (const char ch : s)
    {
        const auto b = static_cast<uint8_t>(ch);
        if (b < 0x80)
        {
            o += ch;
            continue;
        }
        const uint16_t u = cp437_high[b - 0x80];
        if (u < 0x800)
        {
            o += static_cast<char>(0xc0 | u >> 6);
            o += static_cast<char>(0x80 | (u & 0x3f));
        }
        else
        {
            o += static_cast<char>(0xe0 | u >> 12);
            o += static_cast<char>(0x80 | ((u >> 6) & 0x3f));
            o += static_cast<char>(0x80 | (u & 0x3f));
        }
    }
    return o;
}

bool valid_utf8(std::string_view s)
{
    for (size_t i = 0; i < s.size();)
    {
        const auto b = static_cast<uint8_t>(s[i]);
        const size_t n = b < 0x80 ? 1 : (b >> 5) == 6 ? 2 : (b >> 4) == 14 ? 3 : (b >> 3) == 30 ? 4 : 0;
        if (n == 0 || i + n > s.size())
            return false;
        for (size_t k = 1; k < n; ++k)
            if ((static_cast<uint8_t>(s[i + k]) & 0xc0) != 0x80)
                return false;
        i += n;
    }
    return true;
}

// An entry's name as a path under the folder: its parts without empty ones or ".", backslashes taken for the slashes
// a Windows archiver may have written; empty for a name that climbs out with "..", holds a control character, or is
// macOS's resource-fork shadow tree.
std::string clean_path(std::string_view name, bool& dir)
{
    std::string n(name);
    for (char& ch : n)
        if (ch == '\\')
            ch = '/';
    dir = !n.empty() && n.back() == '/';
    std::string out;
    size_t i = 0;
    while (i <= n.size())
    {
        const size_t j = std::min(n.find('/', i), n.size());
        const std::string_view part(n.data() + i, j - i);
        i = j + 1;
        if (part.empty() || part == ".")
            continue;
        if (part == "..")
            return {};
        for (const char ch : part)
            if (static_cast<uint8_t>(ch) < 0x20 || ch == 0x7f)
                return {};
        if (out.empty() && part == "__MACOSX")
            return {};
        if (!out.empty())
            out += '/';
        out += part;
    }
    return out;
}

// The type a browser is told a written file is, by its extension, as the page's own upload names it.
std::string_view type_of(std::string_view name)
{
    const size_t dot = name.rfind('.');
    if (dot == std::string_view::npos || name.find('/', dot) != std::string_view::npos)
        return "application/octet-stream";
    std::string e(name.substr(dot + 1));
    for (char& ch : e)
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    static const std::pair<std::string_view, std::string_view> types[] = {
        {"jpg", "image/jpeg"},        {"jpeg", "image/jpeg"},       {"png", "image/png"},
        {"gif", "image/gif"},         {"webp", "image/webp"},       {"avif", "image/avif"},
        {"heic", "image/heic"},       {"bmp", "image/bmp"},         {"svg", "image/svg+xml"},
        {"mp4", "video/mp4"},         {"m4v", "video/mp4"},         {"mov", "video/quicktime"},
        {"mkv", "video/x-matroska"},  {"webm", "video/webm"},       {"avi", "video/x-msvideo"},
        {"mp3", "audio/mpeg"},        {"m4a", "audio/mp4"},         {"aac", "audio/aac"},
        {"flac", "audio/flac"},       {"ogg", "audio/ogg"},         {"opus", "audio/ogg"},
        {"wav", "audio/wav"},         {"pdf", "application/pdf"},   {"zip", "application/zip"},
        {"txt", "text/plain"},        {"md", "text/markdown"},      {"json", "application/json"},
        {"csv", "text/csv"},          {"html", "text/html"},        {"htm", "text/html"},
        {"css", "text/css"},          {"js", "text/javascript"},    {"mjs", "text/javascript"},
        {"xml", "application/xml"},   {"yml", "text/yaml"},         {"yaml", "text/yaml"},
        {"srt", "text/plain"},        {"vtt", "text/vtt"},
    };
    for (const auto& [k, v] : types)
        if (k == e)
            return v;
    return "application/octet-stream";
}

// A string as JSON, a byte that begins no whole UTF-8 sequence written as U+FFFD, since a ZIP names its entries in
// whatever bytes its maker had.
void json_str(std::string& o, std::string_view v)
{
    o += '"';
    for (size_t i = 0; i < v.size();)
    {
        const auto c = static_cast<uint8_t>(v[i]);
        const size_t len = c < 0x80 ? 1 : (c & 0xE0) == 0xC0 && c >= 0xC2 ? 2 : (c & 0xF0) == 0xE0 ? 3
                         : (c & 0xF8) == 0xF0 && c <= 0xF4 ? 4 : 0;
        bool whole = len != 0 && i + len <= v.size();
        for (size_t k = 1; whole && k < len; ++k)
            whole = (static_cast<uint8_t>(v[i + k]) & 0xC0) == 0x80;
        if (!whole)
        {
            o += "\xEF\xBF\xBD";
            ++i;
            continue;
        }
        if (len == 1)
        {
            if (c == '"' || c == '\\')
                o += '\\';
            if (c >= 0x20)
                o += static_cast<char>(c);
        }
        else
            o.append(v.substr(i, len));
        i += len;
    }
    o += '"';
}

}   // namespace

struct storage_run::unzip_job : std::enable_shared_from_this<unzip_job>
{
    struct entry
    {
        std::string key;   // under the folder, a folder's with its slash
        std::string name;  // as the archive spells it, for the answer
        uint64_t    csize{0};
        uint64_t    usize{0};
        uint64_t    local{0};
        uint32_t    crc{0};
        uint16_t    method{0};
        bool        dir{false};
    };
    struct one;

    storage_run*        run{nullptr};
    std::weak_ptr<conn> who;
    std::string         bucket, key, prefix;
    object_meta         meta;
    int                 fd{-1};
    uint64_t            data_off{0};
    bool                sealed{false};
    bool                tiered{false};
    sse_key             skey{};
    std::vector<entry>  entries;
    size_t              at{0}, inflight{0};
    uint64_t            files{0}, folders{0}, bytes{0};
    size_t              skipped{0}, failed{0};
    std::vector<std::string> skipped_names, failed_names;
    bool                launching{false}, again{false}, answered{false};
    std::shared_ptr<unzip_job> keep;

    std::shared_ptr<body_reader> reader(uint64_t first, uint64_t len)
    {
        if (tiered)
            return run->m_tier.reader(meta, first, len);
        return body_reader::make(run->m_io, &run->m_hash, run->m_store.alive_token(), fd, data_off, meta,
                                 sealed ? &skey : nullptr, first, len);
    }

    // [first, first + len) of the archive gathered whole, for its directory and headers.
    void read_range(uint64_t first, uint64_t len, std::function<void(bool, std::string)> done)
    {
        auto src = reader(first, len);
        if (!src)
        {
            done(false, {});
            return;
        }
        auto buf  = std::make_shared<std::string>();
        auto step = std::make_shared<std::function<void()>>();
        *step = [src, buf, step, len, done]()
        {
            src->next([src, buf, step, len, done](bool ok, std::string_view piece)
            {
                if (!ok || buf->size() + piece.size() > len)
                {
                    *step = nullptr;
                    done(false, {});
                    return;
                }
                if (piece.empty())
                {
                    *step = nullptr;
                    const bool whole = buf->size() == len;
                    done(whole, std::move(*buf));
                    return;
                }
                buf->append(piece);
                (*step)();
            });
        };
        (*step)();
    }

    void note(std::vector<std::string>& names, std::string_view name)
    {
        if (names.size() < names_kept)
            names.emplace_back(name);
    }

    void refuse(int status, std::string why)
    {
        answered = true;
        if (auto cc = who.lock(); cc && !cc->dead)
            run->app_reply(cc, status, std::move(why));
        end();
    }

    void end()
    {
        if (fd >= 0)
            run->m_loop.close_fd(fd);
        fd = -1;
        keep.reset();
    }

    ~unzip_job() { --run->m_unzips; }

    void answer()
    {
        answered = true;
        std::string o = "{\"folder\":";
        json_str(o, prefix);
        o += ",\"files\":" + std::to_string(files) + ",\"folders\":" + std::to_string(folders) +
             ",\"bytes\":" + std::to_string(bytes) + ",\"skipped\":" + std::to_string(skipped) +
             ",\"failed\":" + std::to_string(failed) + ",\"skipped_names\":[";
        for (size_t i = 0; i < skipped_names.size(); ++i)
        {
            if (i)
                o += ',';
            json_str(o, skipped_names[i]);
        }
        o += "],\"failed_names\":[";
        for (size_t i = 0; i < failed_names.size(); ++i)
        {
            if (i)
                o += ',';
            json_str(o, failed_names[i]);
        }
        o += "]}\n";
        LOG_INFO(("storage: \"" + bucket + "/" + key + "\" unpacked into \"" + prefix + "\": " + std::to_string(files) +
                  " files, " + std::to_string(failed) + " failed, " + std::to_string(skipped) + " skipped").c_str());
        if (auto cc = who.lock(); cc && !cc->dead)
            run->app_reply(cc, failed ? 500 : 201, std::move(o), "application/json");
        end();
    }

    void start_entry(size_t i);
    void entry_done(size_t i, bool ok);

    // Starts entries while there is room; a completion inside the loop asks for another turn rather than recursing.
    void launch()
    {
        if (launching)
        {
            again = true;
            return;
        }
        launching = true;
        do
        {
            again = false;
            while (inflight < inflight_max && at < entries.size())
            {
                ++inflight;
                start_entry(at++);
            }
        } while (again);
        launching = false;
        if (at >= entries.size() && inflight == 0 && !answered)
            answer();
    }
};

// One file of the archive: its bytes read from the archive, opened when deflated, and appended to its put.
struct storage_run::unzip_job::one : std::enable_shared_from_this<one>
{
    std::shared_ptr<unzip_job>   job;
    size_t                       index{0};
    std::shared_ptr<put_op>      op;
    std::shared_ptr<body_reader> src;
    inflater                     z;
    checksum_stream              crc{checksum_algo::crc32};
    std::string                  out;
    // What the put has not taken yet: a window of the reader for a stored entry, else `out`.
    std::string_view             pending;
    uint64_t                     produced{0};
    bool                         reading{false}, src_done{false}, finishing{false}, ended{false};
    std::shared_ptr<one>         keep;

    const entry& e() const { return job->entries[index]; }

    void close(bool ok)
    {
        if (ended)
            return;
        ended = true;
        auto self = shared_from_this();
        if (!ok && op)
            op->abort();
        if (op)
        {
            op->on_ready(nullptr);
            op->on_failed(nullptr);
        }
        src.reset();
        keep.reset();
        job->entry_done(index, ok);
    }

    // The bytes just opened, counted against what the directory promised.
    bool take(std::string_view b)
    {
        crc.update(b.data(), b.size());
        produced += b.size();
        pending = b;
        return produced <= e().usize;
    }

    void finish()
    {
        const std::string raw = crc.peek_raw();
        const uint32_t got = (static_cast<uint32_t>(static_cast<uint8_t>(raw[0])) << 24) |
                             (static_cast<uint32_t>(static_cast<uint8_t>(raw[1])) << 16) |
                             (static_cast<uint32_t>(static_cast<uint8_t>(raw[2])) << 8) | static_cast<uint8_t>(raw[3]);
        if (produced != e().usize || got != e().crc)
        {
            close(false);
            return;
        }
        finishing = true;
        auto self = shared_from_this();
        op->finish(nullptr, [self](put_result pr)
        {
            if (pr.status != st::ok)
            {
                self->close(false);
                return;
            }
            self->job->run->notify_put(self->job->bucket, self->e().key, pr.meta);
            self->job->bytes += self->e().usize;
            self->close(true);
        });
    }

    void pump()
    {
        auto self = shared_from_this();
        for (;;)
        {
            if (ended || reading || finishing)
                return;
            if (op->failed())
            {
                close(false);
                return;
            }
            if (!pending.empty())
            {
                pending.remove_prefix(op->append(pending.data(), pending.size()));
                if (op->failed())
                    continue;
                if (!pending.empty())
                    return;   // the put's ready callback comes back here
            }
            if (e().method == 8)
            {
                out.clear();
                const auto r = z.run(out, inflate_turn);
                if (r == inflater::result::bad)
                {
                    close(false);
                    return;
                }
                if (!out.empty() && !take(out))
                {
                    close(false);
                    return;
                }
                if (!pending.empty())
                    continue;
                if (r == inflater::result::done)
                {
                    finish();
                    return;
                }
                if (r == inflater::result::output_full)
                    continue;
                if (src_done)
                {
                    z.end();
                    continue;
                }
            }
            else if (src_done)
            {
                finish();
                return;
            }
            reading = true;
            src->next([self](bool ok, std::string_view piece)
            {
                self->reading = false;
                if (self->ended)
                    return;
                if (!ok)
                {
                    self->close(false);
                    return;
                }
                if (piece.empty())
                    self->src_done = true;
                else if (self->e().method == 8)
                    self->z.feed(reinterpret_cast<const uint8_t*>(piece.data()), piece.size());
                else if (!self->take(piece))
                {
                    self->close(false);
                    return;
                }
                self->pump();
            });
            return;
        }
    }
};

void storage_run::unzip_job::entry_done(size_t i, bool ok)
{
    const entry& en = entries[i];
    if (ok)
        ++(en.dir ? folders : files);
    else
    {
        ++failed;
        note(failed_names, en.name);
    }
    --inflight;
    launch();
}

void storage_run::unzip_job::start_entry(size_t i)
{
    const entry& en = entries[i];
    auto self = shared_from_this();
    if (en.dir)
    {
        // A folder is the empty object its name ends in a slash, as MKCOL writes it.
        object_meta m;
        m.content_type = "application/x-directory";
        s3_error err;
        auto w = run->put_whole(bucket, en.key, std::move(m), std::string{}, [self, i](st s, const put_result*)
        {
            self->entry_done(i, s == st::ok);
        }, err);
        if (!w)
            entry_done(i, false);
        return;
    }
    // The local header's own name and extra field lengths, which may differ from the directory's, say where the
    // bytes begin.
    read_range(en.local, 30, [self, i](bool ok, std::string h)
    {
        const entry& e = self->entries[i];
        if (!ok || rd32(h, 0) != 0x04034b50)
        {
            self->entry_done(i, false);
            return;
        }
        const uint64_t first = e.local + 30 + rd16(h, 26) + rd16(h, 28);
        if (first + e.csize > self->meta.size)
        {
            self->entry_done(i, false);
            return;
        }
        object_meta m;
        m.content_type = type_of(e.key);
        s3_error err;
        auto op = self->run->begin_own_put(self->bucket, e.key, std::move(m), e.usize, err);
        auto src = op ? self->reader(first, e.csize) : nullptr;
        if (!op || !src)
        {
            if (op)
                op->abort();
            self->entry_done(i, false);
            return;
        }
        op->set_cause(change_cause::put);
        auto f    = std::make_shared<one>();
        f->job    = self;
        f->index  = i;
        f->op     = std::move(op);
        f->src    = std::move(src);
        f->keep   = f;
        std::weak_ptr<one> weak = f;
        f->op->on_ready([weak]()
        {
            if (auto p = weak.lock())
                p->pump();
        });
        f->op->on_failed([weak](st)
        {
            if (auto p = weak.lock())
                p->close(false);
        });
        f->pump();
    });
}

void storage_run::unzip_start(const std::shared_ptr<conn>& c, std::string bucket, std::string key, std::string dst)
{
    if (!app_allowed(c, "GET", bucket, key) || !app_allowed(c, "PUT", bucket, dst))
    {
        app_reply(c, 403, "Access denied.\n");
        return;
    }
    if (m_unzips >= max_unzips)
    {
        app_reply(c, 503, std::to_string(max_unzips) + " ZIPs are being unpacked already; try again in a moment.\n");
        return;
    }
    auto j    = std::make_shared<unzip_job>();
    ++m_unzips;
    j->run    = this;
    j->who    = c;
    j->bucket = std::move(bucket);
    j->key    = std::move(key);
    j->keep   = j;

    std::weak_ptr<unzip_job> wj = j;
    // The folder's name, made unique by a number when something is already there, so nothing is written over.
    auto pick = std::make_shared<std::function<void(int)>>();
    auto opened = [this, wj, pick](open_result o)
    {
        auto j = wj.lock();
        if (!j)
        {
            if (o.fd >= 0)
                m_loop.close_fd(o.fd);
            return;
        }
        auto cc = j->who.lock();
        if (!cc || cc->dead)
        {
            if (o.fd >= 0)
                m_loop.close_fd(o.fd);
            *pick = nullptr;
            j->end();
            return;
        }
        if (o.status != st::ok || o.delete_marker)
        {
            if (o.fd >= 0)
                m_loop.close_fd(o.fd);
            *pick = nullptr;
            j->refuse(404, "The archive is not there.\n");
            return;
        }
        s3_error err;
        if (!sse_read_key(cc, o.meta, sse_c_prefix, j->skey, err, true))
        {
            if (o.fd >= 0)
                m_loop.close_fd(o.fd);
            *pick = nullptr;
            j->refuse(400, "The archive is encrypted with a key of the client's.\n");
            return;
        }
        j->meta     = o.meta;
        j->sealed   = is_encrypted(o.meta);
        j->tiered   = is_tiered(o.meta);
        j->data_off = o.data_off;
        if (j->tiered)
        {
            if (o.fd >= 0)
                m_loop.close_fd(o.fd);
        }
        else
            j->fd = o.fd;
        (*pick)(1);
    };

    // The archive's end: its end-of-central-directory record, ZIP64's when the plain one's fields are full, and the
    // central directory they point at, each entry judged before anything is written.
    auto directory = std::make_shared<std::function<void()>>();
    *pick = [this, wj, pick, directory, dst](int n)
    {
        auto j = wj.lock();
        if (!j)
        {
            *pick = nullptr;
            return;
        }
        std::string name = dst;
        if (n > 1)
            name += " (" + std::to_string(n) + ")";
        name += '/';
        list_query q;
        q.prefix   = name;
        q.max_keys = 1;
        m_node.list(j->bucket, q, [wj, pick, directory, name, n](st s, list_page p)
        {
            auto j = wj.lock();
            if (!j)
            {
                *pick = nullptr;
                return;
            }
            if (s == st::ok && (!p.objects.empty() || !p.prefixes.empty()))
            {
                if (n < 100)
                {
                    (*pick)(n + 1);
                    return;
                }
                *pick = nullptr;
                j->refuse(409, "A folder of the archive's name is there already.\n");
                return;
            }
            *pick = nullptr;
            j->prefix = name;
            (*directory)();
        });
    };

    *directory = [this, wj]()
    {
        auto j = wj.lock();
        if (!j)
            return;
        const uint64_t size = j->meta.size;
        if (size < 22)
        {
            j->refuse(400, "The file is not a ZIP archive.\n");
            return;
        }
        const uint64_t tail = std::min<uint64_t>(size, 22 + 65535 + 20);
        j->read_range(size - tail, tail, [this, wj, size](bool ok, std::string t)
        {
            auto j = wj.lock();
            if (!j)
                return;
            if (!ok)
            {
                j->refuse(500, "The archive could not be read.\n");
                return;
            }
            // The last record whose comment runs to the end; failing that, the last one there is.
            size_t eocd = std::string::npos;
            for (size_t i = t.size() - 22 + 1; i-- > 0;)
                if (rd32(t, i) == 0x06054b50)
                {
                    if (eocd == std::string::npos)
                        eocd = i;
                    if (i + 22 + rd16(t, i + 20) == t.size())
                    {
                        eocd = i;
                        break;
                    }
                }
            if (eocd == std::string::npos)
            {
                j->refuse(400, "The file is not a ZIP archive.\n");
                return;
            }
            uint64_t count = rd16(t, eocd + 10), cd_size = rd32(t, eocd + 12), cd_off = rd32(t, eocd + 16);
            const bool spans = rd16(t, eocd + 4) != 0 || rd16(t, eocd + 6) != 0;
            auto read_directory = [this, wj, size](uint64_t count, uint64_t cd_size, uint64_t cd_off)
            {
                auto j = wj.lock();
                if (!j)
                    return;
                if (count > entries_max || cd_size > directory_max || cd_off + cd_size > size)
                {
                    j->refuse(400, "The archive's directory is too large or not where it says.\n");
                    return;
                }
                j->read_range(cd_off, cd_size, [this, wj, count, size](bool ok, std::string d)
                {
                    auto j = wj.lock();
                    if (!j)
                        return;
                    auto cc = j->who.lock();
                    if (!cc || cc->dead)
                    {
                        j->end();
                        return;
                    }
                    if (!ok)
                    {
                        j->refuse(500, "The archive could not be read.\n");
                        return;
                    }
                    size_t at = 0;
                    for (uint64_t k = 0; k < count; ++k)
                    {
                        if (at + 46 > d.size() || rd32(d, at) != 0x02014b50)
                        {
                            j->refuse(400, "The archive's directory is damaged.\n");
                            return;
                        }
                        const uint16_t flags = rd16(d, at + 8);
                        unzip_job::entry e;
                        e.method = rd16(d, at + 10);
                        e.crc    = rd32(d, at + 16);
                        e.csize  = rd32(d, at + 20);
                        e.usize  = rd32(d, at + 24);
                        const uint16_t nlen = rd16(d, at + 28), xlen = rd16(d, at + 30), clen = rd16(d, at + 32);
                        e.local  = rd32(d, at + 42);
                        if (at + 46 + nlen + xlen + clen > d.size())
                        {
                            j->refuse(400, "The archive's directory is damaged.\n");
                            return;
                        }
                        const std::string_view raw(d.data() + at + 46, nlen);
                        std::string name;
                        // ZIP64's sizes and offset stand in for the fields that are full, in that order; Info-ZIP's
                        // Unicode path stands in for a name written in the old code page.
                        for (size_t x = at + 46 + nlen; x + 4 <= at + 46 + nlen + xlen;)
                        {
                            const uint16_t id = rd16(d, x), len = rd16(d, x + 2);
                            if (x + 4 + len > at + 46 + nlen + xlen)
                                break;
                            if (id == 0x0001)
                            {
                                size_t f = x + 4;
                                const size_t endf = f + len;
                                for (uint64_t* v : {&e.usize, &e.csize, &e.local})
                                    if (*v == 0xffffffffull && f + 8 <= endf)
                                    {
                                        *v = rd64(d, f);
                                        f += 8;
                                    }
                            }
                            else if (id == 0x7075 && len > 5 && d[x + 4] == 1)
                                name.assign(d.data() + x + 9, len - 5);
                            x += 4 + len;
                        }
                        at += 46 + nlen + xlen + clen;
                        if (name.empty())
                            name = (flags & 0x0800) || valid_utf8(raw) ? std::string(raw) : from_cp437(raw);
                        e.name = name;
                        const std::string path = clean_path(name, e.dir);
                        const std::string_view last = std::string_view(path).substr(path.rfind('/') + 1);
                        if (last == ".DS_Store" || last == "Thumbs.db")
                            continue;
                        if (path.empty())
                        {
                            if (!name.starts_with("__MACOSX"))
                            {
                                ++j->skipped;
                                j->note(j->skipped_names, name);
                            }
                            continue;
                        }
                        e.key = j->prefix + path + (e.dir ? "/" : "");
                        // Encrypted, or packed some way other than stored or deflated, it cannot be opened here.
                        if (e.key.size() > key_max || !valid_utf8(e.key) || (flags & 1) || (e.method != 0 && e.method != 8) ||
                            (!e.dir && e.local + 30 > size) || (e.method == 0 && e.csize != e.usize) ||
                            !app_allowed(cc, "PUT", j->bucket, e.key))
                        {
                            ++j->skipped;
                            j->note(j->skipped_names, name);
                            continue;
                        }
                        j->entries.push_back(std::move(e));
                    }
                    j->launch();
                });
            };
            if (spans)
            {
                j->refuse(400, "The archive spans more than one file.\n");
                return;
            }
            if ((count == 0xffff || cd_size == 0xffffffff || cd_off == 0xffffffff) && eocd >= 20 &&
                rd32(t, eocd - 20) == 0x07064b50)
            {
                const uint64_t z64 = rd64(t, eocd - 20 + 8);
                if (z64 + 56 > size)
                {
                    j->refuse(400, "The archive's directory is not where it says.\n");
                    return;
                }
                j->read_range(z64, 56, [wj, read_directory](bool ok2, std::string r)
                {
                    auto j = wj.lock();
                    if (!j)
                        return;
                    if (!ok2 || rd32(r, 0) != 0x06064b50)
                    {
                        j->refuse(400, "The archive's ZIP64 directory is damaged.\n");
                        return;
                    }
                    read_directory(rd64(r, 32), rd64(r, 40), rd64(r, 48));
                });
                return;
            }
            read_directory(count, cd_size, cd_off);
        });
    };

    m_store.open_object(j->bucket, j->key, 0, std::move(opened));
}

}   // namespace socketley::storage
