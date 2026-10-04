// Media made from the objects: a thumbnail of a picture or a film, and a film or a song as HLS. A master playlist
// names a ladder of renditions a player switches between as its bandwidth allows; each rendition's playlist is
// written up front from the film's length, so a player seeks anywhere at once, and its segments are made on demand
// by ffmpeg, started again where a player seeks to and held still when it runs too far ahead of every player.
// ffmpeg reads the object through this runtime's own listener, and what it made is kept under <dir>/.media/ for
// every later request, on whichever shard it lands.
#include "storage_run.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <spawn.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cstdlib>

#include "digest.h"
#include "json_doc.h"
#include "s3_names.h"
#include "sse.h"

extern char** environ;

namespace socketley::storage
{

namespace
{

enum media_kind : uint8_t
{
    k_thumb,
    k_probe,
    // The source's own video, its sound made AAC, as ffmpeg's growing playlist.
    k_copy,
    // A transcoded rendition: playlist written here, segments made on demand.
    k_rendition,
    k_master,
    // What the object is, as JSON, for a player to choose between the file itself and a stream.
    k_info,
};

// Thumbnails queue behind a few at a time; a stream is someone waiting to watch, and never waits for another's film.
constexpr int     thumb_jobs_max   = 2;
constexpr int     hls_jobs_max     = 8;
constexpr int64_t media_tick_ms    = 100;
constexpr int64_t media_wait_ms    = 60000;
constexpr int64_t thumb_job_ms     = 60000;
// A stream nobody has asked for in this long is let go; what it made is kept.
constexpr int64_t hls_idle_ms      = 600000;
// A failure is answered as one for this long, and tried again after.
constexpr int64_t failed_hold_ms   = 120000;
// How long ffmpeg's address for an object stays good, which bounds one transcoding.
constexpr int64_t source_ttl_s     = 6 * 3600;
constexpr uint64_t cache_default_mb = 10240;
constexpr int64_t seg_seconds      = 4;
// A segment this close past where a job is gets waited for; one further is a seek, and the job starts again there.
constexpr int64_t seek_beyond      = 5;
// A job this far past every player is held still, and goes on once one is within resume_within of it.
constexpr int64_t pause_ahead      = 15;
constexpr int64_t resume_within    = 8;

// The rendition ladder, by the height of the 16:9 box a picture fits in, with the peak bitrate each is held to.
struct rung
{
    int64_t height;
    int64_t kbps;
};
constexpr rung ladder[] = {{2160, 20000}, {1440, 12000}, {1080, 7000}, {720, 4000}, {480, 2000}, {360, 1000}, {240, 600}};
constexpr int64_t audio_kbps = 160;

int64_t now_ms()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

int64_t mtime_ms(const struct stat& sb)
{
    return static_cast<int64_t>(sb.st_mtim.tv_sec) * 1000 + sb.st_mtim.tv_nsec / 1000000;
}

bool parse_uint(std::string_view s, uint64_t& v)
{
    const auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    return !s.empty() && ec == std::errc{} && end == s.data() + s.size();
}

// The sizes a variant may ask for, so that a cache holds a few of each medium and not any number.
bool thumb_width(std::string_view v, uint64_t& w)
{
    constexpr uint64_t allowed[] = {64, 128, 256, 320, 480, 640, 960, 1280, 1920};
    return v.starts_with("thumb-") && parse_uint(v.substr(6), w) && std::ranges::find(allowed, w) != std::end(allowed);
}

const rung* rendition_of(std::string_view v)
{
    uint64_t h = 0;
    if (!v.starts_with("hls-") || !parse_uint(v.substr(4), h))
        return nullptr;
    for (const rung& r : ladder)
        if (static_cast<uint64_t>(r.height) == h)
            return &r;
    return nullptr;
}

// A stream's segment number from its file name, -1 for the init segment, and false for anything else.
bool stream_file(std::string_view f, int64_t& seg)
{
    if (f == "init.mp4")
    {
        seg = -1;
        return true;
    }
    if (!f.starts_with("seg") || !f.ends_with(".m4s") || f.size() != 3 + 5 + 4)
        return false;
    uint64_t n = 0;
    if (!parse_uint(f.substr(3, 5), n))
        return false;
    seg = static_cast<int64_t>(n);
    return true;
}

std::string seg_name(int64_t n)
{
    char buf[16];
    std::snprintf(buf, sizeof buf, "seg%05lld.m4s", static_cast<long long>(n));
    return buf;
}

bool exists(const std::string& path)
{
    struct stat sb{};
    return ::stat(path.c_str(), &sb) == 0;
}

std::string hmac_hex(std::string_view key, std::string_view msg)
{
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int  n = 0;
    if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), reinterpret_cast<const unsigned char*>(msg.data()),
              msg.size(), out, &n))
        return {};
    return hex(out, n);
}

void clear_dir(const std::string& dir, bool keep_lock)
{
    DIR* d = ::opendir(dir.c_str());
    if (!d)
        return;
    while (dirent* e = ::readdir(d))
    {
        const std::string_view n = e->d_name;
        if (n == "." || n == ".." || (keep_lock && n == "lock"))
            continue;
        // A rendition's jobs/ is the one directory inside, and goes with it.
        if (n == "jobs" && !keep_lock)
            clear_dir(dir + "/jobs", false);
        else
            ::unlink((dir + "/" + std::string(n)).c_str());
    }
    ::closedir(d);
    if (!keep_lock)
        ::rmdir(dir.c_str());
}

void mark(const std::string& dir, const char* name)
{
    const int fd = ::open((dir + "/" + name).c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd >= 0)
        ::close(fd);
}

bool read_small(const std::string& path, std::string& out)
{
    out.clear();
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    char buf[8192];
    ssize_t n;
    while ((n = ::read(fd, buf, sizeof buf)) > 0)
        out.append(buf, static_cast<size_t>(n));
    ::close(fd);
    return n == 0;
}

std::string search_path(std::string_view name)
{
    const char* path = std::getenv("PATH");
    std::string_view rest = path ? path : "/usr/local/bin:/usr/bin:/bin";
    while (!rest.empty())
    {
        const size_t colon = rest.find(':');
        const std::string cand = std::string(rest.substr(0, colon)) + "/" + std::string(name);
        if (::access(cand.c_str(), X_OK) == 0)
            return cand;
        rest = colon == std::string_view::npos ? std::string_view{} : rest.substr(colon + 1);
    }
    return {};
}

std::string ffmpeg_path()
{
    if (const char* e = std::getenv("SOCKETLEY_FFMPEG"); e && *e)
        return ::access(e, X_OK) == 0 ? std::string(e) : std::string{};
    return search_path("ffmpeg");
}

// ffprobe beside the ffmpeg in use, as every build ships them, and the PATH's otherwise.
std::string ffprobe_path(const std::string& ffmpeg)
{
    const size_t slash = ffmpeg.rfind('/');
    if (slash != std::string::npos)
    {
        const std::string beside = ffmpeg.substr(0, slash + 1) + "ffprobe";
        if (::access(beside.c_str(), X_OK) == 0)
            return beside;
    }
    return search_path("ffprobe");
}

// The key of <dir>/.media/key, made by whichever shard comes first, and read by the others.
std::string media_key(const std::string& media_dir)
{
    const std::string path = media_dir + "/key";
    for (int attempt = 0; attempt < 50; ++attempt)
    {
        char buf[32];
        if (const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC); fd >= 0)
        {
            const ssize_t n = ::read(fd, buf, sizeof buf);
            ::close(fd);
            if (n == static_cast<ssize_t>(sizeof buf))
                return std::string(buf, sizeof buf);
        }
        unsigned char raw[32];
        if (RAND_bytes(raw, sizeof raw) != 1)
            return {};
        // Written aside and linked in, so that no shard reads a key half written.
        const std::string tmp = path + ".tmp." + std::to_string(::getpid()) + "." + std::to_string(attempt);
        const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd < 0)
            return {};
        const bool ok = ::write(fd, raw, sizeof raw) == static_cast<ssize_t>(sizeof raw) && ::fsync(fd) == 0;
        ::close(fd);
        if (ok && ::link(tmp.c_str(), path.c_str()) == 0)
        {
            ::unlink(tmp.c_str());
            return std::string(reinterpret_cast<const char*>(raw), sizeof raw);
        }
        ::unlink(tmp.c_str());
    }
    return {};
}

// ─── What ffprobe said ──────────────────────────────────────────────────────

struct probe
{
    double  duration{0};
    int64_t width{0}, height{0}, bitrate{0};
    std::string vcodec, vprofile, transfer;
    int64_t vlevel{0};
    bool    audio{false};
    std::string format, acodec;
    bool    hdr() const { return transfer == "smpte2084" || transfer == "arib-std-b67"; }
};

const jvalue* member(const jvalue& o, std::string_view n)
{
    for (const auto& [k, v] : o.members)
        if (k == n)
            return &v;
    return nullptr;
}

std::string str_of(const jvalue& o, std::string_view n)
{
    const jvalue* v = member(o, n);
    return v && (v->k == jvalue::kind::string || v->k == jvalue::kind::number) ? v->s : std::string{};
}

int64_t int_of(const jvalue& o, std::string_view n)
{
    return std::strtoll(str_of(o, n).c_str(), nullptr, 10);
}

bool read_probe(const std::string& probe_dir, probe& p)
{
    std::string text;
    jvalue root;
    if (!exists(probe_dir + "/done") || !read_small(probe_dir + "/probe.json", text) || !json_reader(text).document(root))
        return false;
    if (const jvalue* f = member(root, "format"))
    {
        p.duration = std::strtod(str_of(*f, "duration").c_str(), nullptr);
        p.bitrate = int_of(*f, "bit_rate");
        p.format = str_of(*f, "format_name");
    }
    if (const jvalue* streams = member(root, "streams"))
        for (const jvalue& s : streams->items)
        {
            const std::string type = str_of(s, "codec_type");
            // A cover picture is a video stream too, and not the film.
            const jvalue* disp = member(s, "disposition");
            if (type == "video" && p.vcodec.empty() && !(disp && int_of(*disp, "attached_pic")))
            {
                p.vcodec = str_of(s, "codec_name");
                p.vprofile = str_of(s, "profile");
                p.vlevel = int_of(s, "level");
                p.width = int_of(s, "width");
                p.height = int_of(s, "height");
                p.transfer = str_of(s, "color_transfer");
            }
            else if (type == "audio" && !p.audio)
            {
                p.audio = true;
                p.acodec = str_of(s, "codec_name");
            }
        }
    return true;
}

// A rendition's picture, fitted into the 16:9 box of its rung and never enlarged, with even sides.
void fitted(const probe& p, int64_t box_h, int64_t& w, int64_t& h)
{
    const double box_w = static_cast<double>(box_h * 16 / 9 / 2 * 2);
    const double scale = std::min({1.0, box_w / static_cast<double>(p.width), static_cast<double>(box_h) / static_cast<double>(p.height)});
    w = static_cast<int64_t>(std::lround(static_cast<double>(p.width) * scale)) / 2 * 2;
    h = static_cast<int64_t>(std::lround(static_cast<double>(p.height) * scale)) / 2 * 2;
}

// The rungs worth making of a source: those its picture fills in at least one side, and the one that keeps its size.
std::vector<const rung*> rungs_of(const probe& p)
{
    std::vector<const rung*> out;
    if (p.width <= 0 || p.height <= 0)
        return out;
    for (const rung& r : ladder)
        if (p.height >= r.height || p.width >= r.height * 16 / 9 / 2 * 2)
            out.push_back(&r);
    // A source smaller than the smallest rung still has one rendition, at its own size.
    if (out.empty())
        out.push_back(&ladder[std::size(ladder) - 1]);
    // And one that keeps its size when no rung does exactly.
    if (out.front()->height < p.height || out.front()->height * 16 / 9 / 2 * 2 < p.width)
        for (const rung& r : ladder)
            if (&r < out.front() && (r.height >= p.height || r.height * 16 / 9 / 2 * 2 >= p.width))
            {
                if (&r + 1 == out.front())
                {
                    out.insert(out.begin(), &r);
                    break;
                }
            }
    return out;
}

std::string avc_codecs(int64_t height)
{
    return height > 1080 ? "avc1.640033" : "avc1.640028";
}

// The source's own codec as a CODECS entry, for the stream that copies it; empty when no browser plays it.
std::string source_codecs(const probe& p)
{
    char buf[48];
    if (p.vcodec == "h264")
    {
        const int idc = p.vprofile.starts_with("High") ? 0x64 : p.vprofile == "Main" ? 0x4d : 0x42;
        std::snprintf(buf, sizeof buf, "avc1.%02x00%02x", idc, static_cast<int>(p.vlevel > 0 ? p.vlevel : 40));
        return buf;
    }
    if (p.vcodec == "hevc")
    {
        const bool ten = p.vprofile.find("10") != std::string::npos;
        std::snprintf(buf, sizeof buf, "hvc1.%d.%d.L%lld.B0", ten ? 2 : 1, ten ? 4 : 6,
                      static_cast<long long>(p.vlevel > 0 ? p.vlevel : 120));
        return buf;
    }
    return {};
}

void url_path(std::string& out, std::string_view variant, std::string_view source)
{
    out += "/~media/";
    out += variant;
    out += '/';
    url_encode_to(out, source, true);
}

std::string master_text(const probe& p, std::string_view source)
{
    std::string m = "#EXTM3U\n#EXT-X-VERSION:7\n#EXT-X-INDEPENDENT-SEGMENTS\n";
    const std::string audio = p.audio ? ",mp4a.40.2" : "";
    std::vector<std::string> lines;
    for (const rung* r : rungs_of(p))
    {
        int64_t w = 0, h = 0;
        fitted(p, r->height, w, h);
        std::string l = "#EXT-X-STREAM-INF:BANDWIDTH=" + std::to_string((r->kbps + (p.audio ? audio_kbps : 0)) * 1000) +
                        ",RESOLUTION=" + std::to_string(w) + "x" + std::to_string(h) + ",CODECS=\"" + avc_codecs(r->height) +
                        audio + "\"\n";
        url_path(l, "hls-" + std::to_string(r->height), source);
        l += "/index.m3u8\n";
        lines.push_back(std::move(l));
    }
    // The first listed is where a player begins: 720p, or the largest below it, before the rest.
    std::stable_partition(lines.begin(), lines.end(), [&](const std::string& l) { return l.find("hls-720/") != std::string::npos; });
    for (const std::string& l : lines)
        m += l;
    if (const std::string codecs = source_codecs(p); !codecs.empty())
    {
        m += "#EXT-X-STREAM-INF:BANDWIDTH=" + std::to_string(std::max<int64_t>(p.bitrate, 1000000) + audio_kbps * 1000) +
             ",RESOLUTION=" + std::to_string(p.width) + "x" + std::to_string(p.height) + ",CODECS=\"" + codecs + audio + "\"\n";
        url_path(m, "hls-copy", source);
        m += "/index.m3u8\n";
    }
    return m;
}

// What a browser is asked whether it plays the file itself: its container and codecs as a MIME type.
std::string info_text(const probe& p)
{
    std::string mime;
    const std::string v = source_codecs(p);
    const std::string a = p.acodec == "aac" ? "mp4a.40.2" : p.acodec == "mp3" ? "mp4a.69" : p.acodec == "opus" ? "opus"
                        : p.acodec == "flac" ? "flac" : p.acodec;
    if (p.format.find("mp4") != std::string::npos)
        mime = "video/mp4";
    else if (p.format.find("webm") != std::string::npos && (p.vcodec == "vp9" || p.vcodec == "vp8" || p.vcodec == "av1"))
        mime = "video/webm";
    std::string codecs = p.vcodec == "vp9" ? "vp9" : p.vcodec == "vp8" ? "vp8" : p.vcodec == "av1" ? "av01.0.08M.08" : v;
    if (p.audio && !a.empty())
        codecs += (codecs.empty() ? "" : ", ") + a;
    if (!mime.empty() && !codecs.empty())
        mime += "; codecs=\"" + codecs + "\"";
    std::string o = "{\"duration\":" + std::to_string(p.duration) + ",\"width\":" + std::to_string(p.width) +
                    ",\"height\":" + std::to_string(p.height) + ",\"video\":\"" + p.vcodec + "\",\"audio\":\"" + p.acodec +
                    "\",\"hdr\":" + (p.hdr() ? "true" : "false") + ",\"mime\":\"";
    for (char ch : mime)
    {
        if (ch == '"' || ch == '\\')
            o += '\\';
        o += ch;
    }
    o += "\",\"renditions\":[";
    bool first = true;
    for (const rung* r : rungs_of(p))
    {
        o += (first ? "" : ",") + std::to_string(r->height);
        first = false;
    }
    o += "]}";
    return o;
}

// A rendition's playlist, whole from the start: every segment four seconds, as the job's forced keyframes cut them.
std::string rendition_text(const probe& p)
{
    const int64_t total = static_cast<int64_t>(std::ceil(p.duration / seg_seconds));
    std::string t = "#EXTM3U\n#EXT-X-VERSION:7\n#EXT-X-TARGETDURATION:" + std::to_string(seg_seconds) +
                    "\n#EXT-X-MEDIA-SEQUENCE:0\n#EXT-X-PLAYLIST-TYPE:VOD\n#EXT-X-INDEPENDENT-SEGMENTS\n#EXT-X-MAP:URI=\"init.mp4\"\n";
    char buf[48];
    for (int64_t i = 0; i < total; ++i)
    {
        const double d = i + 1 < total ? static_cast<double>(seg_seconds) : p.duration - static_cast<double>(seg_seconds * i);
        std::snprintf(buf, sizeof buf, "#EXTINF:%.3f,\n", std::max(d, 0.001));
        t += buf;
        t += seg_name(i);
        t += '\n';
    }
    t += "#EXT-X-ENDLIST\n";
    return t;
}

int64_t segments_of(const probe& p)
{
    return static_cast<int64_t>(std::ceil(p.duration / seg_seconds));
}

// ─── A rendition's jobs, one per stretch of the film ────────────────────────
// Each job has three files under <dir>/jobs/: <from>.lock, held by the shard running it; <from>.pos, the next
// segment it writes; <from>.want, the furthest segment its players asked for, touched at every ask.

std::string job_file(const std::string& dir, int64_t from, std::string_view ext)
{
    return dir + "/jobs/" + std::to_string(from) + std::string(ext);
}

int64_t read_int(const std::string& path, int64_t fallback)
{
    std::string v;
    if (!read_small(path, v) || v.empty())
        return fallback;
    return std::strtoll(v.c_str(), nullptr, 10);
}

void write_int(const std::string& path, int64_t v)
{
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return;
    const std::string s = std::to_string(v);
    if (::write(fd, s.data(), s.size()) < 0) {}
    ::close(fd);
}

// A player's ask, which moves the job's furthest point forward and says, by the file's time, that it is watched.
void note_asked(const std::string& path, int64_t seg)
{
    if (read_int(path, -1) < seg)
        write_int(path, seg);
    else
        ::utimensat(AT_FDCWD, path.c_str(), nullptr, 0);
}

void drop_job_files(const std::string& dir, int64_t from)
{
    for (const char* ext : {".pos", ".want", ".log", ".m3u8", ".lock"})
        ::unlink(job_file(dir, from, ext).c_str());
    ::unlink(job_file(dir, from, "-init.mp4").c_str());
}

struct region
{
    int64_t from, next;
};

// The jobs of a rendition that are running, on any shard; one whose lock nobody holds is gone, and is cleared away.
std::vector<region> live_regions(const std::string& dir)
{
    std::vector<region> out;
    DIR* d = ::opendir((dir + "/jobs").c_str());
    if (!d)
        return out;
    std::vector<int64_t> froms;
    while (dirent* e = ::readdir(d))
    {
        const std::string_view n = e->d_name;
        uint64_t from = 0;
        if (n.ends_with(".lock") && parse_uint(n.substr(0, n.size() - 5), from))
            froms.push_back(static_cast<int64_t>(from));
    }
    ::closedir(d);
    for (const int64_t from : froms)
    {
        const int fd = ::open(job_file(dir, from, ".lock").c_str(), O_RDWR | O_CLOEXEC);
        if (fd < 0)
            continue;
        if (::flock(fd, LOCK_EX | LOCK_NB) == 0)
        {
            drop_job_files(dir, from);
            ::close(fd);
            continue;
        }
        ::close(fd);
        out.push_back({from, read_int(job_file(dir, from, ".pos"), from)});
    }
    return out;
}

// Every segment of the rendition is there, whichever job made each.
bool all_made(const std::string& dir, int64_t total)
{
    for (int64_t i = 0; i < total; ++i)
        if (!exists(dir + "/" + seg_name(i)))
            return false;
    return total > 0;
}

}   // namespace

void storage_run::op_media(const std::shared_ptr<conn>& c)
{
    s3_request& r = c->req;
    const std::string_view path = r.key;
    const size_t slash = path.find('/');
    const std::string_view variant = path.substr(0, slash);
    const std::string_view rest = slash == std::string_view::npos ? std::string_view{} : path.substr(slash + 1);
    if (r.method != "GET" && r.method != "HEAD")
    {
        app_reply(c, 405, "Media are read with GET.\n");
        return;
    }
    if (variant == "src")
    {
        media_source(c, rest);
        return;
    }
    media_want w;
    w.variant.assign(variant);
    w.head = r.method == "HEAD";
    uint64_t size = 0;
    std::string_view source = rest;
    const size_t last = source.rfind('/');
    const std::string_view file = last == std::string_view::npos ? std::string_view{} : source.substr(last + 1);
    if (thumb_width(variant, size))
    {
        w.kind = k_thumb;
        w.file = "thumb.jpg";
    }
    else if (variant == "info")
    {
        w.kind = k_info;
        w.file = "info";
    }
    else if (variant == "hls" && file == "master.m3u8")
    {
        w.kind = k_master;
        w.file.assign(file);
        source = source.substr(0, last);
    }
    else if ((variant == "hls-copy" || rendition_of(variant)) && (file == "index.m3u8" || stream_file(file, w.seg)))
    {
        w.kind = variant == "hls-copy" ? k_copy : k_rendition;
        w.file.assign(file);
        source = source.substr(0, last);
    }
    else
    {
        app_reply(c, 404, "No such medium: thumb-<width>/<object>, hls/<object>/master.m3u8, or hls-<height>|hls-copy/"
                          "<object>/index.m3u8 and its segments.\n");
        return;
    }
    w.source.assign(source);

    // A link's medium is the link's to give, and a bucket's is its user's as a GET of the object would be.
    if (source.starts_with("~share/"))
    {
        source.remove_prefix(7);
        const size_t s2 = source.find('/');
        const std::string_view rel = s2 == std::string_view::npos ? std::string_view{} : source.substr(s2 + 1);
        if (!share_target(c, source.substr(0, s2), rel, w.bucket, w.key))
            return;
    }
    else
    {
        if (!app_login(c, "socketley"))
            return;
        const size_t s2 = source.find('/');
        if (s2 == std::string_view::npos || s2 + 1 == source.size())
        {
            app_reply(c, 404, "A medium is /~media/<variant>/<bucket>/<key>.\n");
            return;
        }
        w.bucket.assign(source.substr(0, s2));
        w.key.assign(source.substr(s2 + 1));
        if (!app_allowed(c, "GET", w.bucket, w.key))
        {
            app_reply(c, 403, "Access denied.\n");
            return;
        }
    }
    if (!m_ffmpeg_known)
    {
        m_ffmpeg = ffmpeg_path();
        m_ffmpeg_known = true;
    }
    if (m_ffmpeg.empty())
    {
        app_reply(c, 501, "No ffmpeg: install it on the PATH, or name it in SOCKETLEY_FFMPEG.\n");
        return;
    }
    std::weak_ptr<conn> weak = c;
    const std::string bucket = w.bucket, key = w.key;
    m_store.stat_object(bucket, key, [this, weak, want = std::move(w)](st s, const object_meta& m) mutable
    {
        media_want& w = want;
        auto cc = weak.lock();
        if (!cc || cc->dead)
            return;
        if (s != st::ok)
        {
            app_reply(cc, 404, "No such object.\n");
            return;
        }
        if (sse_mode_of(m) == sse_mode::c)
        {
            app_reply(cc, 415, "An object only its client's key opens is not made into media.\n");
            return;
        }
        // A medium is the object's as it is now, so a new version of it is made anew.
        const std::string media_dir = m_store.options().dir + "/.media";
        if (::mkdir(media_dir.c_str(), 0700) < 0 && errno != EEXIST)
        {
            app_reply(cc, 500, "The media cache cannot be made.\n");
            return;
        }
        w.image = m.content_type.str().starts_with("image/");
        const std::string object = '\n' + w.bucket + '\n' + w.key + '\n' + m.etag();
        w.dir = media_dir + "/" + sha256_hex(w.variant + object);
        w.probe_dir = media_dir + "/" + sha256_hex("probe" + object);
        w.deadline_ms = now_ms() + media_wait_ms;
        if (media_try(cc, w))
            return;
        m_media_waits.emplace_back(cc, std::move(w));
        media_arm();
    });
}

void storage_run::media_source(const std::shared_ptr<conn>& c, std::string_view rest)
{
    // ffmpeg's own reads, signed by the runtime that started it and good for a while.
    s3_request& r = c->req;
    const size_t slash = rest.find('/');
    uint64_t expires = 0;
    if (slash == std::string_view::npos || !parse_uint(r.get_query("t"), expires) ||
        static_cast<int64_t>(expires) * 1000 < now_ms())
    {
        app_reply(c, 403, "Access denied.\n");
        return;
    }
    if (m_media_key.empty())
        m_media_key = media_key(m_store.options().dir + "/.media");
    std::string bucket(rest.substr(0, slash)), key(rest.substr(slash + 1));
    const std::string want = hmac_hex(m_media_key, bucket + '\n' + key + '\n' + std::to_string(expires));
    const std::string_view got = r.get_query("s");
    if (m_media_key.empty() || want.empty() || got.size() != want.size() ||
        CRYPTO_memcmp(got.data(), want.data(), want.size()) != 0)
    {
        app_reply(c, 403, "Access denied.\n");
        return;
    }
    r.method = r.method == "HEAD" ? std::string_view("HEAD") : std::string_view("GET");
    r.bucket = std::move(bucket);
    r.key    = std::move(key);
    r.query.clear();
    r.app = 0;
    c->anonymous = true;
    c->user.reset();
    c->hook = nullptr;
    hook_request(c);
}

bool storage_run::media_serve(const std::shared_ptr<conn>& c, const media_want& w, bool growing)
{
    const int fd = ::open((w.dir + "/" + w.file).c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    struct stat fs{};
    ::fstat(fd, &fs);
    ::utimensat(AT_FDCWD, (w.dir + "/lock").c_str(), nullptr, 0);
    response head;
    const std::string_view f = w.file;
    head.headers.emplace_back("Content-Type", f.ends_with(".jpg")  ? "image/jpeg"
                                            : f.ends_with(".m3u8") ? "application/vnd.apple.mpegurl"
                                            : f.ends_with(".mp4")  ? "video/mp4"
                                                                   : "video/iso.segment");
    // A playlist still growing is asked for again, and what is done does not change.
    head.headers.emplace_back("Cache-Control", growing ? "no-cache" : "private, max-age=86400");
    const uint64_t len = static_cast<uint64_t>(fs.st_size);
    ++m_c.media_served;
    if (w.head)
    {
        m_loop.close_fd(fd);
        head.head_only = true;
        head.has_length_override = true;
        head.length_override = len;
        send_response(c, std::move(head));
    }
    else
        send_file(c, std::move(head), fd, 0, len);
    return true;
}

bool storage_run::media_try(const std::shared_ptr<conn>& c, const media_want& w)
{
    struct stat sb{};
    // The playlists of a rendition and the master are written from the probe, which is made first and kept.
    if (w.kind == k_master || w.kind == k_rendition || w.kind == k_info)
    {
        probe p;
        if (!read_probe(w.probe_dir, p))
        {
            if (::stat((w.probe_dir + "/failed").c_str(), &sb) == 0 && now_ms() - mtime_ms(sb) < failed_hold_ms)
            {
                app_reply(c, 415, "ffmpeg could not read this object as a medium.\n");
                return true;
            }
            if (now_ms() > w.deadline_ms)
            {
                app_reply(c, 504, "The medium is still being looked at; ask again.\n");
                return true;
            }
            // The probe is made once, by whichever shard takes its lock, and every request waits on its answer.
            media_want pw = w;
            pw.kind = k_probe;
            pw.variant = "probe";
            pw.dir = w.probe_dir;
            if (::mkdir(w.probe_dir.c_str(), 0700) < 0 && errno != EEXIST)
            {
                app_reply(c, 500, "The media cache cannot be written.\n");
                return true;
            }
            const int lock_fd = ::open((w.probe_dir + "/lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
            if (lock_fd >= 0 && ::flock(lock_fd, LOCK_EX | LOCK_NB) == 0)
            {
                if (exists(w.probe_dir + "/done") || !media_start(pw, lock_fd, 0))
                    ::close(lock_fd);
            }
            else if (lock_fd >= 0)
                ::close(lock_fd);
            return false;
        }
        if (w.kind == k_info)
        {
            app_reply(c, 200, info_text(p), "application/json");
            return true;
        }
        if (p.vcodec.empty() && w.kind != k_master)
        {
            app_reply(c, 415, "This object has no picture to stream; its master playlist has none either.\n");
            return true;
        }
        if (w.kind == k_master || w.file == "index.m3u8")
        {
            if (p.duration <= 0 && w.kind == k_rendition)
            {
                app_reply(c, 415, "A stream of this length cannot be cut; ask for hls-copy.\n");
                return true;
            }
            std::string text = w.kind == k_master ? master_text(p, w.source) : rendition_text(p);
            ++m_c.media_served;
            response r;
            r.headers.emplace_back("Content-Type", "application/vnd.apple.mpegurl");
            r.headers.emplace_back("Cache-Control", "private, max-age=3600");
            if (w.head)
            {
                r.head_only = true;
                r.has_length_override = true;
                r.length_override = text.size();
            }
            else
                r.body = std::move(text);
            send_response(c, std::move(r));
            return true;
        }
        if (w.seg >= segments_of(p))
        {
            app_reply(c, 404, "No such segment: the film is shorter.\n");
            return true;
        }
        return media_segment(c, w);
    }

    const bool done = ::stat((w.dir + "/done").c_str(), &sb) == 0;
    const std::string lock = w.dir + "/lock";
    if ((done || w.kind == k_copy) && media_serve(c, w, w.kind == k_copy && !done && w.file == "index.m3u8"))
        return true;
    if (done)
    {
        app_reply(c, 404, "No such part of this stream.\n");
        return true;
    }
    if (::stat((w.dir + "/failed").c_str(), &sb) == 0 && now_ms() - mtime_ms(sb) < failed_hold_ms)
    {
        app_reply(c, 415, "ffmpeg could not make this from the object.\n");
        return true;
    }
    if (now_ms() > w.deadline_ms)
    {
        app_reply(c, 504, "The medium is still being made; ask again.\n");
        return true;
    }
    // Whoever holds the lock is making it, here or on another shard, and a request for it keeps it wanted.
    ::utimensat(AT_FDCWD, lock.c_str(), nullptr, 0);
    const bool stream = w.kind == k_copy;
    const auto same_kind = std::ranges::count_if(m_media_jobs, [&](const media_job& j) {
        return (j.want.kind == k_copy || j.want.kind == k_rendition) == stream;
    });
    if (same_kind >= (stream ? hls_jobs_max : thumb_jobs_max))
        return false;
    if (::mkdir(w.dir.c_str(), 0700) < 0 && errno != EEXIST)
    {
        app_reply(c, 500, "The media cache cannot be written.\n");
        return true;
    }
    const int lock_fd = ::open(lock.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lock_fd < 0)
    {
        app_reply(c, 500, "The media cache cannot be written.\n");
        return true;
    }
    if (::flock(lock_fd, LOCK_EX | LOCK_NB) != 0)
    {
        ::close(lock_fd);
        return false;
    }
    // It may have been finished between the look and the lock.
    if (::stat((w.dir + "/done").c_str(), &sb) == 0)
    {
        ::close(lock_fd);
        return media_try(c, w);
    }
    // A film's still is a few seconds in, past a black first frame.
    if (!media_start(w, lock_fd, w.kind == k_thumb && !w.image ? 1 : 0))
    {
        ::close(lock_fd);
        app_reply(c, 500, "ffmpeg could not be started.\n");
        return true;
    }
    return false;
}

bool storage_run::media_segment(const std::shared_ptr<conn>& c, const media_want& w)
{
    const std::vector<region> live = live_regions(w.dir);
    // A player's progress, also through what was made ahead of it, is what lets a job held still go on.
    auto note = [&](const region& r, int64_t seg)
    {
        note_asked(job_file(w.dir, r.from, ".want"), seg);
        for (media_job& j : m_media_jobs)
            if (j.want.kind == k_rendition && j.want.dir == w.dir && j.from == r.from)
            {
                j.wanted = std::max(j.wanted, seg);
                j.asked_ms = now_ms();
                if (j.paused && j.wanted + resume_within >= j.next)
                {
                    ::kill(j.pid, SIGCONT);
                    j.paused = false;
                }
            }
    };
    if (w.seg >= 0)
        for (const region& r : live)
            if (w.seg >= r.from && w.seg <= r.next + seek_beyond)
                note(r, w.seg);
    // Made already, by any job of any shard: served as it is.
    if (media_serve(c, w, false))
        return true;
    if (now_ms() > w.deadline_ms)
    {
        app_reply(c, 504, "The segment is still being made; ask again.\n");
        return true;
    }
    const int64_t seg = std::max<int64_t>(w.seg, 0);
    ::utimensat(AT_FDCWD, (w.dir + "/lock").c_str(), nullptr, 0);
    // A job at it or a little before it is waited for; the init segment comes from any job.
    for (const region& r : live)
        if (w.seg < 0 || (seg >= r.from && seg <= r.next + seek_beyond))
            return false;
    // Nothing near it: a seek, or the first player, and a job begins at the segment asked for.
    const auto streams = std::ranges::count_if(m_media_jobs, [](const media_job& j) {
        return j.want.kind == k_copy || j.want.kind == k_rendition;
    });
    if (streams >= hls_jobs_max)
        return false;
    if ((::mkdir(w.dir.c_str(), 0700) < 0 && errno != EEXIST) || (::mkdir((w.dir + "/jobs").c_str(), 0700) < 0 && errno != EEXIST))
    {
        app_reply(c, 500, "The media cache cannot be written.\n");
        return true;
    }
    const int lock_fd = ::open(job_file(w.dir, seg, ".lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    const int share_fd = ::open((w.dir + "/lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    // Another shard began here a moment ago, or the rendition is being evicted: either way, a look again shortly.
    if (lock_fd < 0 || share_fd < 0 || ::flock(lock_fd, LOCK_EX | LOCK_NB) != 0 || ::flock(share_fd, LOCK_SH | LOCK_NB) != 0)
    {
        if (lock_fd >= 0)
            ::close(lock_fd);
        if (share_fd >= 0)
            ::close(share_fd);
        return false;
    }
    write_int(job_file(w.dir, seg, ".pos"), seg);
    write_int(job_file(w.dir, seg, ".want"), seg);
    if (!media_start(w, lock_fd, seg))
    {
        drop_job_files(w.dir, seg);
        ::close(lock_fd);
        ::close(share_fd);
        app_reply(c, 500, "ffmpeg could not be started.\n");
        return true;
    }
    m_media_jobs.back().share_fd = share_fd;
    return false;
}

bool storage_run::media_start(const media_want& w, int lock_fd, int64_t from)
{
    // ffmpeg reads the object over the listener, which serves it decrypted and in ranges as any client is.
    sockaddr_storage ss{};
    socklen_t sl = sizeof ss;
    if (::getsockname(m_listen_fd, reinterpret_cast<sockaddr*>(&ss), &sl) < 0)
        return false;
    std::string host;
    uint16_t port = 0;
    if (ss.ss_family == AF_INET)
    {
        const auto* a = reinterpret_cast<const sockaddr_in*>(&ss);
        char buf[INET_ADDRSTRLEN];
        host = a->sin_addr.s_addr == htonl(INADDR_ANY) ? "127.0.0.1" : ::inet_ntop(AF_INET, &a->sin_addr, buf, sizeof buf);
        port = ntohs(a->sin_port);
    }
    else if (ss.ss_family == AF_INET6)
    {
        const auto* a = reinterpret_cast<const sockaddr_in6*>(&ss);
        char buf[INET6_ADDRSTRLEN];
        host = "[" + std::string(IN6_IS_ADDR_UNSPECIFIED(&a->sin6_addr) ? "::1" : ::inet_ntop(AF_INET6, &a->sin6_addr, buf, sizeof buf)) + "]";
        port = ntohs(a->sin6_port);
    }
    else
        return false;
    if (m_media_key.empty())
        m_media_key = media_key(m_store.options().dir + "/.media");
    if (m_media_key.empty())
        return false;
    const int64_t expires = now_ms() / 1000 + source_ttl_s;
    std::string url = std::string(tls_enabled() ? "https://" : "http://") + host + ":" + std::to_string(port) + "/~media/src/";
    url_encode_to(url, w.bucket, true);
    url += '/';
    url_encode_to(url, w.key, true);
    url += "?t=" + std::to_string(expires) + "&s=" + hmac_hex(m_media_key, w.bucket + '\n' + w.key + '\n' + std::to_string(expires));

    // ffmpeg's reads survive a pause long enough for the listener to let them go.
    const std::vector<std::string> input = {"-reconnect", "1", "-reconnect_on_network_error", "1", "-i", url};
    std::vector<std::string> args = {m_ffmpeg, "-nostdin", "-hide_banner", "-loglevel", "error", "-y"};
    std::string out_file;
    media_job j;
    probe p;
    switch (w.kind)
    {
        case k_thumb:
        {
            uint64_t n = 0;
            thumb_width(w.variant, n);
            clear_dir(w.dir, true);
            if (from > 0)
                args.insert(args.end(), {"-ss", "5"});
            args.insert(args.end(), input.begin(), input.end());
            args.insert(args.end(), {"-frames:v", "1", "-vf", "scale='min(" + std::to_string(n) + ",iw)':-2", "-q:v", "4",
                                     w.dir + "/thumb.jpg"});
            j.seeked = from > 0;
            break;
        }
        case k_probe:
        {
            clear_dir(w.dir, true);
            args = {ffprobe_path(m_ffmpeg), "-v", "error", "-print_format", "json", "-show_format", "-show_streams",
                    "-reconnect", "1", url};
            if (args.front().empty())
                return false;
            out_file = w.dir + "/probe.json.tmp";
            break;
        }
        case k_copy:
        {
            clear_dir(w.dir, true);
            args.insert(args.end(), input.begin(), input.end());
            // The picture as it is; the sound made AAC, which every player plays and AC3 or DTS is not.
            args.insert(args.end(), {"-map", "0:v:0?", "-map", "0:a:0?", "-c:v", "copy", "-c:a", "aac", "-b:a", "160k",
                                     "-ac", "2", "-f", "hls", "-hls_time", std::to_string(seg_seconds),
                                     "-hls_playlist_type", "event", "-hls_segment_type", "fmp4", "-hls_fmp4_init_filename",
                                     "init.mp4", "-hls_flags", "temp_file+independent_segments", "-hls_segment_filename",
                                     w.dir + "/seg%05d.m4s", w.dir + "/index.m3u8"});
            break;
        }
        case k_rendition:
        {
            if (!read_probe(w.probe_dir, p))
                return false;
            const rung* r = rendition_of(w.variant);
            int64_t width = 0, height = 0;
            fitted(p, r->height, width, height);
            std::string vf = "scale=" + std::to_string(width) + ":" + std::to_string(height);
            // HDR made SDR, as an H.264 stream's players show it, rather than washed out.
            if (p.hdr())
                vf += ",zscale=t=linear:npl=100,format=gbrpf32le,zscale=p=bt709,tonemap=tonemap=hable:desat=0,"
                      "zscale=t=bt709:m=bt709:r=tv";
            vf += ",format=yuv420p";
            const std::string offset = std::to_string(from * seg_seconds);
            // Begun at a segment's own time, with its number, so that its segments are the ones a run from the start
            // would have made: keyframes every four seconds of the film, and the film's own timestamps.
            args.insert(args.end(), {"-ss", offset});
            args.insert(args.end(), input.begin(), input.end());
            // Jellyfin's motion search: a fifth less CPU for an SSIM of 0.9690 against 0.9695, and no keyframe at a
            // scene cut, so every segment is cut where the forced ones are.
            args.insert(args.end(), {"-map", "0:v:0", "-map", "0:a:0?", "-c:v", "libx264", "-preset", "veryfast", "-crf", "23",
                                     "-x264-params", "subme=0:me_range=16:rc_lookahead=10:me=hex:open_gop=0",
                                     "-sc_threshold", "0",
                                     "-maxrate", std::to_string(r->kbps) + "k", "-bufsize", std::to_string(r->kbps * 2) + "k",
                                     "-vf", vf, "-color_primaries", "bt709", "-color_trc", "bt709", "-colorspace", "bt709",
                                     "-force_key_frames", "expr:gte(t,n_forced*" + std::to_string(seg_seconds) + ")",
                                     "-c:a", "aac", "-b:a", "160k", "-ac", "2", "-avoid_negative_ts", "disabled",
                                     // The film's time in every fragment and none in the init, so that any job's init
                                     // fits every job's segments.
                                     "-output_ts_offset", offset, "-hls_segment_options", "movflags=+frag_discont",
                                     "-f", "hls", "-hls_time", std::to_string(seg_seconds),
                                     "-hls_playlist_type", "event", "-hls_segment_type", "fmp4", "-hls_fmp4_init_filename",
                                     std::to_string(from) + "-init.mp4", "-hls_flags", "temp_file+independent_segments",
                                     "-start_number", std::to_string(from), "-hls_segment_filename", w.dir + "/seg%05d.m4s",
                                     job_file(w.dir, from, ".m3u8")});
            j.from = from;
            j.next = from;
            j.wanted = from;
            j.asked_ms = now_ms();
            j.total = segments_of(p);
            break;
        }
        default:
            return false;
    }
    std::vector<char*> argv;
    for (std::string& a : args)
        argv.push_back(a.data());
    argv.push_back(nullptr);

    posix_spawn_file_actions_t fa;
    posix_spawnattr_t attr;
    posix_spawn_file_actions_init(&fa);
    posix_spawnattr_init(&attr);
    posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_addopen(&fa, 1, out_file.empty() ? "/dev/null" : out_file.c_str(),
                                     O_WRONLY | O_CREAT | O_TRUNC, 0600);
    const std::string log = w.kind == k_rendition ? job_file(w.dir, from, ".log") : w.dir + "/log";
    posix_spawn_file_actions_addopen(&fa, 2, log.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    // Nothing else of the worker's goes with it, so a listener or a ring is never held open by an ffmpeg.
    posix_spawn_file_actions_addclosefrom_np(&fa, 3);
    // The worker ignores SIGPIPE, which ffmpeg is given back, and blocks nothing it should inherit.
    sigset_t def, none;
    sigemptyset(&def);
    sigaddset(&def, SIGPIPE);
    sigemptyset(&none);
    posix_spawnattr_setsigdefault(&attr, &def);
    posix_spawnattr_setsigmask(&attr, &none);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK);
    pid_t pid = -1;
    const int rc = ::posix_spawn(&pid, args.front().c_str(), &fa, &attr, argv.data(), environ);
    posix_spawn_file_actions_destroy(&fa);
    posix_spawnattr_destroy(&attr);
    if (rc != 0)
        return false;
    ::futimens(lock_fd, nullptr);
    j.pid = pid;
    j.lock_fd = lock_fd;
    j.want = w;
    j.started_ms = now_ms();
    m_media_jobs.push_back(std::move(j));
    media_arm();
    return true;
}

void storage_run::media_arm()
{
    if (m_media_timer.armed || m_stopped)
        return;
    m_media_timer.ts  = {0, media_tick_ms * 1000000};
    m_media_timer.req = io_request{};
    m_media_timer.req.owner = this;
    m_media_timer.req.type  = op_timeout;
    m_media_timer.armed = m_loop.submit_timeout(&m_media_timer.ts, &m_media_timer.req);
}

void storage_run::media_tick()
{
    bool finished = false;
    for (size_t i = 0; i < m_media_jobs.size();)
    {
        media_job& j = m_media_jobs[i];
        int status = 0;
        const pid_t r = ::waitpid(j.pid, &status, WNOHANG);
        struct stat sb{};
        const int64_t now = now_ms();
        if (j.want.kind == k_rendition)
        {
            // Where the job is, by its own playlist, so that segments another job made are not taken for its own.
            const std::string own = job_file(j.want.dir, j.from, ".m3u8");
            if (::stat(own.c_str(), &sb) == 0 && mtime_ms(sb) != j.playlist_mtime)
            {
                j.playlist_mtime = mtime_ms(sb);
                std::string text;
                if (read_small(own, text))
                {
                    int64_t made = 0;
                    for (size_t at = 0; (at = text.find("\nseg", at)) != std::string::npos; ++at)
                        ++made;
                    if (j.from + made > j.next)
                    {
                        j.next = j.from + made;
                        write_int(job_file(j.want.dir, j.from, ".pos"), j.next);
                    }
                }
            }
            // The rendition's init segment is the first job's, linked in whole.
            const std::string init = job_file(j.want.dir, j.from, "-init.mp4");
            if (j.next > j.from && !exists(j.want.dir + "/init.mp4") && exists(init) &&
                ::link(init.c_str(), (j.want.dir + "/init.mp4").c_str()) != 0) {}
            const std::string want = job_file(j.want.dir, j.from, ".want");
            if (::stat(want.c_str(), &sb) == 0 && mtime_ms(sb) != j.want_mtime)
            {
                j.want_mtime = mtime_ms(sb);
                j.asked_ms = std::max(j.asked_ms, j.want_mtime);
                j.wanted = std::max(j.wanted, read_int(want, j.wanted));
            }
            if (r == 0)
            {
                // Run into what another job made: this one's work is done. Two made ahead of it can only be another's.
                const bool merged = j.next > j.from && exists(j.want.dir + "/" + seg_name(j.next)) &&
                                    (j.next + 1 >= j.total || exists(j.want.dir + "/" + seg_name(j.next + 1)));
                // Held still with nobody asking for a minute, or running with nobody asking for the idle time.
                const bool abandoned = now - j.asked_ms > (j.paused ? 60000 : hls_idle_ms);
                if (!merged && !abandoned)
                {
                    if (!j.paused && j.next > j.wanted + pause_ahead)
                    {
                        ::kill(j.pid, SIGSTOP);
                        j.paused = true;
                    }
                    else if (j.paused && j.wanted + resume_within >= j.next)
                    {
                        ::kill(j.pid, SIGCONT);
                        j.paused = false;
                    }
                    ++i;
                    continue;
                }
                if (j.paused)
                    ::kill(j.pid, SIGCONT);
                ::kill(j.pid, SIGKILL);
                ::waitpid(j.pid, nullptr, 0);
            }
            else if (r != j.pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
            {
                ++m_c.media_failed;
                // A job that fails from its very start is the medium's failure, and is answered so for a while.
                if (j.next == j.from)
                    mark(j.want.dir, "failed");
            }
            if (all_made(j.want.dir, j.total) && !exists(j.want.dir + "/done"))
            {
                mark(j.want.dir, "done");
                ++m_c.media_made;
                finished = true;
            }
            drop_job_files(j.want.dir, j.from);
            ::close(j.lock_fd);
            if (j.share_fd >= 0)
                ::close(j.share_fd);
            m_media_jobs.erase(m_media_jobs.begin() + static_cast<ptrdiff_t>(i));
            continue;
        }
        if (r == 0)
        {
            const bool idle = j.want.kind == k_copy && ::fstat(j.lock_fd, &sb) == 0 && now - mtime_ms(sb) > hls_idle_ms;
            if (!idle && (j.want.kind == k_copy || now - j.started_ms <= thumb_job_ms))
            {
                ++i;
                continue;
            }
            ::kill(j.pid, SIGKILL);
            ::waitpid(j.pid, nullptr, 0);
            // A stream let go is begun again when asked for; a thumbnail or a probe that took too long is a failure.
            if (idle)
                clear_dir(j.want.dir, true);
            else
            {
                mark(j.want.dir, "failed");
                ++m_c.media_failed;
            }
        }
        else
        {
            bool ok = r == j.pid && WIFEXITED(status) && WEXITSTATUS(status) == 0;
            if (j.want.kind == k_probe)
                ok = ok && ::stat((j.want.dir + "/probe.json.tmp").c_str(), &sb) == 0 && sb.st_size > 0 &&
                     ::rename((j.want.dir + "/probe.json.tmp").c_str(), (j.want.dir + "/probe.json").c_str()) == 0;
            else
            {
                const std::string out = j.want.dir + (j.want.kind == k_copy ? "/index.m3u8" : "/thumb.jpg");
                ok = ok && ::stat(out.c_str(), &sb) == 0 && sb.st_size > 0;
            }
            // A still a few seconds in that the film is too short for is taken from its start.
            if (!ok && j.seeked)
            {
                const media_want w = j.want;
                const int lock_fd = j.lock_fd;
                m_media_jobs.erase(m_media_jobs.begin() + static_cast<ptrdiff_t>(i));
                if (!media_start(w, lock_fd, 0))
                {
                    mark(w.dir, "failed");
                    ++m_c.media_failed;
                    ::close(lock_fd);
                    finished = true;
                }
                continue;
            }
            mark(j.want.dir, ok ? "done" : "failed");
            if (j.want.kind != k_probe)
                ++(ok ? m_c.media_made : m_c.media_failed);
            finished = true;
        }
        ::close(j.lock_fd);
        m_media_jobs.erase(m_media_jobs.begin() + static_cast<ptrdiff_t>(i));
    }
    // Each waiting request looks again, and may start what a finished one made room for.
    auto waits = std::move(m_media_waits);
    m_media_waits.clear();
    for (auto& [weak, w] : waits)
    {
        auto c = weak.lock();
        if (!c || c->dead || media_try(c, w))
            continue;
        m_media_waits.emplace_back(std::move(weak), std::move(w));
    }
    if (finished)
        media_evict();
    if (!m_media_jobs.empty() || !m_media_waits.empty())
        media_arm();
}

void storage_run::media_evict()
{
    // The least recently asked for media go first, once the cache is past its size, and none that is being made.
    uint64_t cap_mb = cache_default_mb;
    if (const char* e = std::getenv("SOCKETLEY_MEDIA_CACHE_MB"); e && *e)
        parse_uint(e, cap_mb);
    const std::string media_dir = m_store.options().dir + "/.media";
    struct entry
    {
        std::string dir;
        int64_t     used_ms{0};
        uint64_t    bytes{0};
    };
    std::vector<entry> all;
    uint64_t total = 0;
    DIR* d = ::opendir(media_dir.c_str());
    if (!d)
        return;
    while (dirent* e = ::readdir(d))
    {
        const std::string_view n = e->d_name;
        if (n.size() != 64)
            continue;
        entry en;
        en.dir = media_dir + "/" + std::string(n);
        struct stat sb{};
        if (::stat((en.dir + "/lock").c_str(), &sb) == 0)
            en.used_ms = mtime_ms(sb);
        if (DIR* sub = ::opendir(en.dir.c_str()))
        {
            while (dirent* f = ::readdir(sub))
                if (f->d_name[0] != '.' && ::stat((en.dir + "/" + f->d_name).c_str(), &sb) == 0)
                    en.bytes += static_cast<uint64_t>(sb.st_size);
            ::closedir(sub);
        }
        total += en.bytes;
        all.push_back(std::move(en));
    }
    ::closedir(d);
    const uint64_t cap = cap_mb << 20;
    if (total <= cap)
        return;
    std::ranges::sort(all, {}, &entry::used_ms);
    // The medium asked for last stays, so that one larger than the whole cache is still served once made.
    for (size_t i = 0; i + 1 < all.size() && total > cap; ++i)
    {
        const entry& en = all[i];
        const int fd = ::open((en.dir + "/lock").c_str(), O_RDWR | O_CLOEXEC);
        if (fd >= 0 && ::flock(fd, LOCK_EX | LOCK_NB) != 0)
        {
            ::close(fd);
            continue;
        }
        clear_dir(en.dir, false);
        if (fd >= 0)
            ::close(fd);
        total -= en.bytes;
    }
}

void storage_run::media_stop()
{
    for (media_job& j : m_media_jobs)
    {
        // A held job is let go on, so that SIGKILL reaches it as it reaches any other.
        if (j.paused)
            ::kill(j.pid, SIGCONT);
        ::kill(j.pid, SIGKILL);
        ::waitpid(j.pid, nullptr, 0);
        if (j.want.kind == k_rendition)
            drop_job_files(j.want.dir, j.from);
        ::close(j.lock_fd);
        if (j.share_fd >= 0)
            ::close(j.share_fd);
    }
    m_media_jobs.clear();
    m_media_waits.clear();
    if (m_media_timer.armed)
        m_loop.submit_timeout_remove(&m_media_timer.req);
}

}   // namespace socketley::storage
