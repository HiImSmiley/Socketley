// Media made from the objects: a thumbnail of a picture or a film, subtitles as WebVTT, and a film or a song as
// HLS. A master playlist names a ladder of renditions a player switches between as its bandwidth allows, the
// source's own picture copied, and the subtitles; each rendition's playlist is written up front from the film's
// length, so a player seeks anywhere at once, and its segments are made on demand by ffmpeg, started again where
// a player seeks to and held still when it runs ahead of every player. ffmpeg reads an unencrypted object's file
// directly and any other through this runtime's own listener, and what it made is kept under <dir>/.media/ for
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
#include <cctype>
#include <charconv>
#include <chrono>
#include <climits>
#include <cmath>
#include <cstdlib>
#include <thread>

#include <poll.h>
#include <sys/syscall.h>

#include "../../shared/http/http_framing.h"
#include "digest.h"
#include "../../shared/json/json_doc.h"
#include "s3_names.h"
#include "s3_tagging.h"
#include "sse.h"
#include "../../shared/persist/replaced_file.h"
#include "../../shared/json/json_escape.h"

using socketley::json::jvalue;
using socketley::json::json_reader;

extern char** environ;

namespace socketley::storage
{

namespace
{

enum media_kind : uint8_t
{
    k_thumb,
    k_probe,
    // The source's own picture, its sound made AAC unless it is AAC already, as ffmpeg's growing playlist.
    k_copy,
    // A transcoded rendition: playlist written here, segments made on demand.
    k_rendition,
    k_master,
    // What the object is, as JSON, for a player to choose between the file itself and a stream.
    k_info,
    // One text subtitle stream as WebVTT, and its playlist of one segment.
    k_sub,
    // A second of video through the GPU's encoder, to learn whether renditions can be made there.
    k_hwtest,
    // Small stills through the film, tiled in one JPEG, that a seek bar shows where it would seek to.
    k_trick,
    // The film as one H.264 and AAC MP4 that starts playing before it is whole, which a chat embeds as a player.
    k_web,
};

// Thumbnails and probes queue behind one a core of the shard's share, each run on one thread, since most of what one
// costs is ffmpeg starting; a stream is someone waiting to watch, and never waits for another's film.
constexpr int     thumb_jobs_min   = 2;
constexpr int     hls_jobs_max     = 8;
// The streams a machine's GPU makes at once, shared out among its shards.
constexpr int     gpu_streams_max  = 24;
constexpr int64_t media_tick_ms    = 100;
// The look again for a request waiting on a segment, which is the most a made segment waits to be sent.
constexpr int64_t media_wait_tick_ms = 20;
constexpr int64_t media_wait_ms    = 60000;
constexpr int64_t thumb_job_ms     = 60000;
// A film's stills are read from its keyframes alone, which still reads the whole file.
constexpr int64_t trick_job_ms     = 600000;
// A whole film made over is hours on a small machine, and it is let take them.
constexpr int64_t web_job_ms       = 4 * 3600 * 1000;
// The stills: 160x90, ten a row, one every two seconds or more, two hundred at most.
constexpr int64_t trick_w = 160, trick_h = 90, trick_cols = 10, trick_max = 200;
// A stream nobody has asked for in this long is let go; what it made is kept.
constexpr int64_t hls_idle_ms      = 600000;
// A failure is answered as one for this long, and tried again after.
constexpr int64_t failed_hold_ms   = 120000;
// How long ffmpeg's address for an object stays good, which bounds one transcoding.
constexpr int64_t source_ttl_s     = 6 * 3600;
constexpr uint64_t cache_default_mb = 10240;
constexpr int64_t seg_seconds      = 4;
// A segment's name counts five digits, so a film is no longer than that many segments.
constexpr double  max_seconds      = 99999.0 * seg_seconds;
// A segment this close past where a job is gets waited for; one further is a seek, and the job starts again there.
constexpr int64_t seek_beyond      = 5;
// A job this far past every player is held still, and goes on once one is within resume_within of it; one nobody
// has asked of for a while is held once it is a little ahead, as a player that sought elsewhere left it.
constexpr int64_t pause_ahead      = 15;
constexpr int64_t resume_within    = 8;
constexpr int64_t unasked_ms       = 10000;
// A job begun for an init segment that no player has asked a segment of is held after this long.
constexpr int64_t init_only_ms     = 2000;
// A use of a medium is written to its lock's time at most this often, and eviction runs at most this often.
constexpr int64_t touch_every_ms   = 60000;
constexpr int64_t evict_every_ms   = 30000;
// An object's open file is kept this long after its last use.
constexpr int64_t source_keep_ms   = 60000;
// A medium's file this small is read and sent in one write.
constexpr uint64_t small_file      = 64 * 1024;

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

// A stream's variant without the -a<n> that picks its sound track, and that track.
std::string_view without_track(std::string_view v, int64_t& track)
{
    track = 0;
    const size_t at = v.rfind("-a");
    uint64_t n = 0;
    if (at == std::string_view::npos || !v.starts_with("hls") || !parse_uint(v.substr(at + 2), n) || n == 0 || n > 64)
        return v;
    track = static_cast<int64_t>(n);
    return v.substr(0, at);
}

const rung* rendition_of(std::string_view v)
{
    int64_t track = 0;
    v = without_track(v, track);
    uint64_t h = 0;
    if (!v.starts_with("hls-") || !parse_uint(v.substr(4), h))
        return nullptr;
    for (const rung& r : ladder)
        if (static_cast<uint64_t>(r.height) == h)
            return &r;
    return nullptr;
}

bool sub_index(std::string_view v, int64_t& index)
{
    uint64_t n = 0;
    if (!v.starts_with("sub-") || !parse_uint(v.substr(4), n) || n > 1000)
        return false;
    index = static_cast<int64_t>(n);
    return true;
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
    char buf[32];
    std::snprintf(buf, sizeof buf, "seg%05lld.m4s", static_cast<long long>(n));
    return buf;
}

bool exists(const std::string& path)
{
    struct stat sb{};
    return ::stat(path.c_str(), &sb) == 0;
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

// A lock taken on a file another shard deleted since it was opened is a lock on nothing anyone else will look at.
bool locked_fresh(int fd, const std::string& path)
{
    struct stat a{}, b{};
    return ::fstat(fd, &a) == 0 && ::stat(path.c_str(), &b) == 0 && a.st_ino == b.st_ino && a.st_dev == b.st_dev;
}

// An ffmpeg a worker that died left running is found by the pid its job wrote, and only if it is still that job's.
void kill_orphan(const std::string& pid_file, const std::string& dir)
{
    std::string v, cmdline;
    if (!read_whole_file(pid_file, v) || v.empty())
        return;
    const long pid = std::strtol(v.c_str(), nullptr, 10);
    if (pid <= 1)
        return;
    const std::string proc = "/proc/" + std::to_string(pid);
    // Its arguments name the job's directory, or a probe's, which has none there, writes its log into it.
    char log[PATH_MAX];
    const ssize_t n = ::readlink((proc + "/fd/2").c_str(), log, sizeof(log) - 1);
    const bool logs_here = n > 0 && std::string_view(log, static_cast<size_t>(n)).starts_with(dir + "/");
    if (!logs_here && (!read_whole_file(proc + "/cmdline", cmdline) || cmdline.find(dir) == std::string::npos))
        return;
    ::kill(static_cast<pid_t>(pid), SIGKILL);
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

std::string str_of(const jvalue& o, std::string_view n)
{
    const jvalue* v = member(o, n);
    return v && (v->k == jvalue::kind::string || v->k == jvalue::kind::number) ? v->s : std::string{};
}

// ffprobe writes its numbers as strings as often as not, so this reads either.
int64_t probe_int(const jvalue& o, std::string_view n)
{
    return std::strtoll(str_of(o, n).c_str(), nullptr, 10);
}

// A length or a time from ffprobe, 0 for one no film has: not a number, below zero, or past max_seconds.
double seconds_of(const jvalue& o, std::string_view n)
{
    const double s = std::strtod(str_of(o, n).c_str(), nullptr);
    return std::isfinite(s) && s > 0 && s <= max_seconds ? s : 0;
}

double rate_of(const std::string& r)
{
    const size_t slash = r.find('/');
    const double num = std::strtod(r.c_str(), nullptr);
    const double den = slash == std::string::npos ? 1.0 : std::strtod(r.c_str() + slash + 1, nullptr);
    return den > 0 ? num / den : 0;
}

// A tag by its name in any case, as Vorbis comments write them in capitals and ID3 in lowercase.
std::string tag_of(const jvalue* tags, std::string_view name)
{
    if (tags)
        for (const auto& [k, v] : tags->members)
            if (k.size() == name.size() && std::ranges::equal(k, name, [](char a, char b) { return std::tolower(static_cast<unsigned char>(a)) == b; }))
                return v.s;
    return {};
}

// The tags of a song from `tags`, each one the probe does not have yet.
void song_tags(const jvalue* tags, media_probe& p)
{
    for (auto [field, name] : {std::pair{&p.title, "title"}, {&p.artist, "artist"}, {&p.album, "album"},
                               {&p.album_artist, "album_artist"}, {&p.genre, "genre"}, {&p.date, "date"}})
        if (field->empty())
            *field = tag_of(tags, name);
    if (p.album_artist.empty())
        p.album_artist = tag_of(tags, "albumartist");
    // "3/12" is the third of twelve.
    if (p.track == 0)
        p.track = std::strtoll(tag_of(tags, "track").c_str(), nullptr, 10);
    if (p.track == 0)
        p.track = std::strtoll(tag_of(tags, "tracknumber").c_str(), nullptr, 10);
    if (p.disc == 0)
        p.disc = std::strtoll(tag_of(tags, "disc").c_str(), nullptr, 10);
    if (p.disc == 0)
        p.disc = std::strtoll(tag_of(tags, "discnumber").c_str(), nullptr, 10);
}

bool parse_probe(const std::string& text, media_probe& p)
{
    jvalue root;
    if (!json_reader(text).document(root))
        return false;
    if (const jvalue* f = member(root, "format"))
    {
        p.duration = seconds_of(*f, "duration");
        p.bitrate = probe_int(*f, "bit_rate");
        p.format = str_of(*f, "format_name");
        song_tags(member(*f, "tags"), p);
    }
    if (const jvalue* chapters = member(root, "chapters"))
        for (const jvalue& ch : chapters->items)
            p.chapters.push_back({seconds_of(ch, "start_time"), seconds_of(ch, "end_time"), tag_of(member(ch, "tags"), "title")});
    double vduration = 0;
    const jvalue* sound_tags = nullptr;
    if (const jvalue* streams = member(root, "streams"))
        for (const jvalue& s : streams->items)
        {
            const std::string type = str_of(s, "codec_type");
            // A cover picture is a video stream too, and not the film.
            const jvalue* disp = member(s, "disposition");
            if (type == "video" && p.vcodec.empty() && !(disp && probe_int(*disp, "attached_pic")))
            {
                p.vcodec = str_of(s, "codec_name");
                p.vprofile = str_of(s, "profile");
                p.vlevel = probe_int(s, "level");
                p.width = probe_int(s, "width");
                p.height = probe_int(s, "height");
                p.transfer = str_of(s, "color_transfer");
                p.fps = rate_of(str_of(s, "avg_frame_rate"));
                if (p.fps <= 0 || p.fps > 240)
                    p.fps = rate_of(str_of(s, "r_frame_rate"));
                vduration = seconds_of(s, "duration");
            }
            else if (type == "audio")
            {
                const jvalue* tags = member(s, "tags");
                p.tracks.push_back({probe_int(s, "channels"), str_of(s, "codec_name"), tag_of(tags, "language"),
                                    tag_of(tags, "title"), disp && probe_int(*disp, "default")});
                if (!p.audio)
                {
                    sound_tags = tags;
                    p.audio = true;
                    p.acodec = str_of(s, "codec_name");
                    p.achannels = probe_int(s, "channels");
                }
            }
            else if (type == "subtitle")
            {
                const std::string codec = str_of(s, "codec_name");
                if (codec != "subrip" && codec != "ass" && codec != "ssa" && codec != "mov_text" && codec != "webvtt" &&
                    codec != "text")
                    continue;
                media_probe::subtitle sub;
                sub.index = probe_int(s, "index");
                sub.codec = codec;
                if (const jvalue* tags = member(s, "tags"))
                {
                    sub.lang = str_of(*tags, "language");
                    sub.title = str_of(*tags, "title");
                }
                p.subtitles.push_back(std::move(sub));
            }
        }
    if (const jvalue* frames = member(root, "frames"))
        for (const jvalue& f : frames->items)
            if (str_of(f, "media_type") == "video")
                if (const jvalue* sides = member(f, "side_data_list"))
                    for (const jvalue& sd : sides->items)
                        p.mastering = p.mastering || str_of(sd, "side_data_type") == "Mastering display metadata";
    // An Ogg song keeps its tags on its sound; a film's sound track names only itself.
    if (p.vcodec.empty())
        song_tags(sound_tags, p);
    // The picture's own length where the container's runs on past it, so the last segment is one the picture has.
    if (vduration > 0 && vduration < p.duration)
        p.duration = vduration;
    return true;
}

// A rendition's picture, fitted into the 16:9 box of its rung and never enlarged, with even sides.
void fitted(const media_probe& p, int64_t box_h, int64_t& w, int64_t& h)
{
    const double box_w = static_cast<double>(box_h * 16 / 9 / 2 * 2);
    const double scale = std::min({1.0, box_w / static_cast<double>(p.width), static_cast<double>(box_h) / static_cast<double>(p.height)});
    w = static_cast<int64_t>(std::lround(static_cast<double>(p.width) * scale)) / 2 * 2;
    h = static_cast<int64_t>(std::lround(static_cast<double>(p.height) * scale)) / 2 * 2;
}

// Whether an object is a film, by its type or else by its name, which a client that sends no type leaves.
bool is_film(std::string_view type, std::string_view key)
{
    if (type.starts_with("video/"))
        return true;
    const size_t dot = key.rfind('.');
    if (dot == std::string_view::npos || key.size() - dot > 6)
        return false;
    std::string ext(key.substr(dot + 1));
    for (char& ch : ext)
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    static constexpr std::string_view films[] = {"mp4", "m4v", "mkv", "mov", "webm", "avi", "wmv", "flv", "ts", "mts", "m2ts"};
    return std::ranges::find(films, ext) != std::end(films);
}

// Where a medium of an object is made, by the object's bucket, key and ETag; the web copy's name changed with its
// bitrate cap, so one made before is made again.
std::string medium_dir(const std::string& media_dir, std::string_view variant, const std::string& object)
{
    return media_dir + "/" + sha256_hex((variant == "web" ? std::string("web4") : std::string(variant)) + '\n' + object);
}

// The rungs worth making of a source: those its picture fills in at least one side, and the one that keeps its size.
std::vector<const rung*> rungs_of(const media_probe& p)
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
            if (&r + 1 == out.front() && (r.height >= p.height || r.height * 16 / 9 / 2 * 2 >= p.width))
            {
                out.insert(out.begin(), &r);
                break;
            }
    return out;
}

// The H.264 level a rung is encoded at, which its CODECS entry names: 4.2 holds 1080p at 60, 5.2 holds 2160p at 60.
const char* avc_level(int64_t height)
{
    return height > 1080 ? "5.2" : "4.2";
}

std::string avc_codecs(int64_t height)
{
    return height > 1080 ? "avc1.640034" : "avc1.64002a";
}

// The source's own codec as a CODECS entry, for the stream that copies it; empty when no browser plays it.
std::string source_codecs(const media_probe& p)
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

// Sound that is AAC with two channels or fewer is copied as it is; any other is made stereo AAC.
bool audio_copies(const media_probe& p)
{
    return p.acodec == "aac" && p.achannels > 0 && p.achannels <= 2;
}

void url_path(std::string& out, std::string_view variant, std::string_view source)
{
    out += "/~media/";
    out += variant;
    out += '/';
    url_encode_to(out, source, true);
}

std::string fps_attr(const media_probe& p)
{
    if (p.fps <= 0)
        return {};
    char buf[32];
    std::snprintf(buf, sizeof buf, ",FRAME-RATE=%.3f", p.fps);
    return buf;
}

std::string master_text(const media_probe& p, std::string_view source, std::string_view version, int64_t track)
{
    const std::string a = track > 0 ? "-a" + std::to_string(track) : std::string{};
    std::string m = "#EXTM3U\n#EXT-X-VERSION:7\n#EXT-X-INDEPENDENT-SEGMENTS\n";
    const std::string v = "?v=" + std::string(version);
    // Subtitles as their own renditions, which every stream names.
    for (const media_probe::subtitle& s : p.subtitles)
    {
        // A file's own tags are the uploader's text, so neither a quote nor a line break can end the attribute or the line.
        const auto quoted = [](std::string t)
        {
            std::erase_if(t, [](char c) { return c == '"' || c == '\r' || c == '\n'; });
            return t;
        };
        const std::string name = quoted(!s.title.empty() ? s.title : !s.lang.empty() ? s.lang
                                                                                       : "Track " + std::to_string(s.index));
        const std::string lang = quoted(s.lang);
        m += "#EXT-X-MEDIA:TYPE=SUBTITLES,GROUP-ID=\"subs\",NAME=\"" + name + "\"";
        if (!lang.empty())
            m += ",LANGUAGE=\"" + lang + "\"";
        m += ",AUTOSELECT=YES,DEFAULT=NO,URI=\"";
        url_path(m, "sub-" + std::to_string(s.index), source);
        m += "/index.m3u8" + v + "\"\n";
    }
    const std::string subs = p.subtitles.empty() ? "" : ",SUBTITLES=\"subs\"";
    const std::string audio = p.audio ? ",mp4a.40.2" : "";
    std::vector<std::string> lines;
    for (const rung* r : rungs_of(p))
    {
        int64_t w = 0, h = 0;
        fitted(p, r->height, w, h);
        // A segment holds at most a quarter more than the cap over its four seconds, with a buffer of one second's cap.
        std::string l = "#EXT-X-STREAM-INF:BANDWIDTH=" + std::to_string((r->kbps * 5 / 4 + (p.audio ? audio_kbps : 0)) * 1000) +
                        ",RESOLUTION=" + std::to_string(w) + "x" + std::to_string(h) + ",CODECS=\"" + avc_codecs(r->height) +
                        audio + "\"" + fps_attr(p) + subs + "\n";
        url_path(l, "hls-" + std::to_string(r->height) + a, source);
        l += "/index.m3u8" + v + "\n";
        lines.push_back(std::move(l));
    }
    // The first listed is where a player begins: 720p, or the largest below it, before the rest.
    std::stable_partition(lines.begin(), lines.end(), [&](const std::string& l) { return l.find("hls-720/") != std::string::npos; });
    for (const std::string& l : lines)
        m += l;
    if (const std::string codecs = source_codecs(p); !codecs.empty())
    {
        m += "#EXT-X-STREAM-INF:BANDWIDTH=" + std::to_string(std::max<int64_t>(p.bitrate, 1000000) * 3 / 2 + audio_kbps * 1000) +
             ",RESOLUTION=" + std::to_string(p.width) + "x" + std::to_string(p.height) + ",CODECS=\"" + codecs + audio + "\"" +
             fps_attr(p) + (p.hdr() ? (p.transfer == "smpte2084" ? ",VIDEO-RANGE=PQ" : ",VIDEO-RANGE=HLG") : "") + subs + "\n";
        url_path(m, "hls-copy" + a, source);
        m += "/index.m3u8" + v + "\n";
    }
    return m;
}

// The seconds between a film's stills, and how many there are.
int64_t trick_every(const media_probe& p)
{
    return std::max<int64_t>(2, static_cast<int64_t>(std::ceil(p.duration / trick_max)));
}

int64_t trick_count(const media_probe& p)
{
    return std::max<int64_t>(1, static_cast<int64_t>(std::ceil(p.duration / static_cast<double>(trick_every(p)))));
}

// What a browser is asked whether it plays the file itself: its container and codecs as a MIME type.
std::string info_text(const media_probe& p, std::string_view version)
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
                    ",\"height\":" + std::to_string(p.height) + ",\"fps\":" + std::to_string(p.fps) + ",\"video\":";
    socketley::json::quote_into(o, p.vcodec);
    o += ",\"audio\":";
    socketley::json::quote_into(o, p.acodec);
    o += ",\"hdr\":";
    o += p.hdr() ? "true" : "false";
    o += ",\"mime\":";
    socketley::json::quote_into(o, mime);
    o += ",\"copy\":";
    socketley::json::quote_into(o, v.empty() ? std::string{} : v + (p.audio ? ",mp4a.40.2" : ""));
    o += ",\"version\":";
    socketley::json::quote_into(o, version);
    o += ",\"renditions\":[";
    bool first = true;
    for (const rung* r : rungs_of(p))
    {
        if (!first) o += ',';
        o += std::to_string(r->height);
        first = false;
    }
    o += "],\"subtitles\":[";
    first = true;
    for (const media_probe::subtitle& s : p.subtitles)
    {
        o += first ? "{" : ",{";
        first = false;
        o += "\"index\":" + std::to_string(s.index) + ",\"lang\":";
        socketley::json::quote_into(o, s.lang);
        o += ",\"title\":";
        socketley::json::quote_into(o, s.title);
        o += "}";
    }
    o += "],\"tracks\":[";
    first = true;
    for (const media_probe::audio_track& t : p.tracks)
    {
        o += first ? "{" : ",{";
        first = false;
        o += "\"codec\":";
        socketley::json::quote_into(o, t.codec);
        o += ",\"channels\":" + std::to_string(t.channels) + ",\"lang\":";
        socketley::json::quote_into(o, t.lang);
        o += ",\"title\":";
        socketley::json::quote_into(o, t.title);
        o += t.main ? ",\"default\":true}" : ",\"default\":false}";
    }
    o += "],\"chapters\":[";
    first = true;
    char buf[64];
    for (const media_probe::chapter& ch : p.chapters)
    {
        std::snprintf(buf, sizeof buf, "{\"start\":%.3f,\"end\":%.3f,\"title\":", ch.start, ch.end);
        o += first ? "" : ",";
        first = false;
        o += buf;
        socketley::json::quote_into(o, ch.title);
        o += "}";
    }
    o += "],\"tags\":{";
    for (auto [name, value] : {std::pair{"title", &p.title}, {"artist", &p.artist}, {"album", &p.album},
                               {"album_artist", &p.album_artist}, {"genre", &p.genre}, {"date", &p.date}})
    {
        o += '"';
        o += name;
        o += "\":";
        socketley::json::quote_into(o, *value);
        o += ',';
    }
    o += "\"track\":" + std::to_string(p.track) + ",\"disc\":" + std::to_string(p.disc) + "}";
    if (!p.vcodec.empty() && p.duration > 0)
        o += ",\"trick\":{\"every\":" + std::to_string(trick_every(p)) + ",\"count\":" + std::to_string(trick_count(p)) +
             ",\"columns\":" + std::to_string(trick_cols) + ",\"width\":" + std::to_string(trick_w) +
             ",\"height\":" + std::to_string(trick_h) + "}";
    o += "}";
    return o;
}

int64_t segments_of(const media_probe& p)
{
    return static_cast<int64_t>(std::ceil(p.duration / seg_seconds));
}

// A rendition's playlist, whole from the start: every segment four seconds, as the job's forced keyframes cut them.
std::string rendition_text(const media_probe& p, std::string_view version)
{
    const int64_t total = segments_of(p);
    const std::string v = version.empty() ? std::string{} : "?v=" + std::string(version);
    std::string t = "#EXTM3U\n#EXT-X-VERSION:7\n#EXT-X-TARGETDURATION:" + std::to_string(seg_seconds) +
                    "\n#EXT-X-MEDIA-SEQUENCE:0\n#EXT-X-PLAYLIST-TYPE:VOD\n#EXT-X-INDEPENDENT-SEGMENTS\n#EXT-X-MAP:URI=\"init.mp4" +
                    v + "\"\n";
    char buf[48];
    for (int64_t i = 0; i < total; ++i)
    {
        const double d = i + 1 < total ? static_cast<double>(seg_seconds) : p.duration - static_cast<double>(seg_seconds * i);
        std::snprintf(buf, sizeof buf, "#EXTINF:%.3f,\n", std::max(d, 0.001));
        t += buf;
        t += seg_name(i);
        t += v;
        t += '\n';
    }
    t += "#EXT-X-ENDLIST\n";
    return t;
}

// A subtitle's playlist: the whole track as one WebVTT segment as long as the film.
std::string subtitle_text(const media_probe& p, std::string_view version)
{
    const int64_t secs = std::max<int64_t>(1, static_cast<int64_t>(std::ceil(p.duration)));
    char buf[48];
    std::snprintf(buf, sizeof buf, "#EXTINF:%.3f,\n", std::max(p.duration, 1.0));
    return "#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:" + std::to_string(secs) +
           "\n#EXT-X-MEDIA-SEQUENCE:0\n#EXT-X-PLAYLIST-TYPE:VOD\n" + buf + "subs.vtt" +
           (version.empty() ? std::string{} : "?v=" + std::string(version)) + "\n#EXT-X-ENDLIST\n";
}

// ─── A rendition's jobs, one per stretch of the film ────────────────────────
// Each job has files under <dir>/jobs/: <from>.lock, held by the shard running it; <from>.pos, the next segment it
// writes; <from>.want, the furthest segment its players asked for, touched at every ask; <from>.pid, its ffmpeg.

std::string job_file(const std::string& dir, int64_t from, std::string_view ext)
{
    return dir + "/jobs/" + std::to_string(from) + std::string(ext);
}

int64_t read_int(const std::string& path, int64_t fallback)
{
    std::string v;
    if (!read_whole_file(path, v) || v.empty())
        return fallback;
    return std::strtoll(v.c_str(), nullptr, 10);
}

void write_int(const std::string& path, int64_t v)
{
    replace_file(path, std::to_string(v), false);
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
    for (const char* ext : {".pos", ".want", ".log", ".m3u8", ".pid", ".drop", ".lock"})
        ::unlink(job_file(dir, from, ext).c_str());
    ::unlink(job_file(dir, from, "-init.mp4").c_str());
}

struct region
{
    int64_t from, next;
};

// The jobs of a rendition that are running, on any shard; one whose lock nobody holds is gone, and is cleared away
// with any ffmpeg of it a dead worker left.
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
        const std::string lock = job_file(dir, from, ".lock");
        const int fd = ::open(lock.c_str(), O_RDWR | O_CLOEXEC);
        if (fd < 0)
            continue;
        if (::flock(fd, LOCK_EX | LOCK_NB) == 0)
        {
            if (locked_fresh(fd, lock))
            {
                kill_orphan(job_file(dir, from, ".pid"), dir);
                drop_job_files(dir, from);
            }
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

// A medium's ETag: the object's version and the file, which is all a medium's bytes depend on.
std::string media_etag(std::string_view version, std::string_view file)
{
    return "\"" + std::string(version) + "-" + std::string(file) + "\"";
}

bool etag_matches(std::string_view if_none_match, std::string_view etag)
{
    return !if_none_match.empty() && (if_none_match == "*" || if_none_match.find(etag) != std::string_view::npos);
}

}   // namespace

web_plan web_plan_of(const media_probe& p)
{
    // What a chat embeds is at most 50 MiB, so the copy is held to 46: the film is made as well as it looks at a
    // bitrate that fits, at most 12 Mbit/s, of as many lines as that bitrate carries well.
    constexpr double fits = 46.0 * 1024 * 1024 * 8;
    web_plan w;
    w.rate = 12000000;
    if (p.duration > 0)
        w.rate = std::clamp<int64_t>(static_cast<int64_t>(fits / p.duration) - 192000, 600000, w.rate);
    w.lines = w.rate >= 8000000 ? 1440 : w.rate >= 2500000 ? 1080 : 720;
    // A picture every browser and chat plays is copied when it fits as it is; anything else is made H.264.
    w.copies = p.vcodec == "h264" && !p.hdr() && p.height <= w.lines && (p.bitrate == 0 || p.bitrate <= 12000000) &&
               (p.duration <= 0 || p.bitrate == 0 || static_cast<double>(p.bitrate) * p.duration <= fits) &&
               (p.vprofile.empty() || p.vprofile == "High" || p.vprofile == "Main" ||
                p.vprofile == "Constrained Baseline" || p.vprofile == "Baseline");
    if (w.copies)
    {
        w.width = p.width;
        w.height = p.height;
    }
    else
        fitted(p, w.lines, w.width, w.height);
    return w;
}

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
    int64_t index = 0;
    std::string_view source = rest;
    const std::string_view stream = without_track(variant, w.audio);
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
    else if (variant == "trick")
    {
        w.kind = k_trick;
        w.file = "trick.jpg";
    }
    else if (variant == "web")
    {
        w.kind = k_web;
        w.file = "web.mp4";
        w.prepare = c->req.has_query("prepare");
    }
    else if (stream == "hls" && file == "master.m3u8")
    {
        w.kind = k_master;
        w.file.assign(file);
        source = source.substr(0, last);
    }
    else if (sub_index(variant, index) && (file == "index.m3u8" || file == "subs.vtt"))
    {
        w.kind = k_sub;
        w.file.assign(file);
        source = source.substr(0, last);
    }
    else if ((stream == "hls-copy" || rendition_of(variant)) && (file == "index.m3u8" || stream_file(file, w.seg)))
    {
        w.kind = stream == "hls-copy" ? k_copy : k_rendition;
        w.file.assign(file);
        source = source.substr(0, last);
    }
    else
    {
        app_reply(c, 404, "No such medium: thumb-<width>/<object>, info/<object>, hls/<object>/master.m3u8, "
                          "hls-<height>|hls-copy/<object>/index.m3u8 and its segments, each with -a<track> for another sound track, "
                          "sub-<stream>/<object>/subs.vtt, trick/<object>, or web/<object>.\n");
        return;
    }
    w.source.assign(source);

    // A link's medium is the link's to give, and a bucket's is its user's as a GET of the object would be.
    if (source.starts_with("~share/"))
    {
        source.remove_prefix(7);
        const size_t s2 = source.find('/');
        const std::string_view rel = s2 == std::string_view::npos ? std::string_view{} : source.substr(s2 + 1);
        std::string_view id = source.substr(0, s2);
        // A link's web copy is also <id>.mp4, since a chat embeds a player only for a URL that ends so.
        if (w.kind == k_web && rel.empty() && id.ends_with(".mp4"))
            id.remove_suffix(4);
        if (!share_target(c, id, rel, w.bucket, w.key))
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
    if (m_hw == media_hw::unknown && !m_ffmpeg.empty())
        media_hw_detect();
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
        if (!media_dir_made())
        {
            app_reply(cc, 500, "The media cache cannot be made.\n");
            return;
        }
        const std::string etag = m.etag();
        media_name(w, m);
        // An object's file whose bytes are stored as they are, opened once a minute a shard, is what ffmpeg reads; a
        // medium made needs none.
        const bool made = m_media_done.contains(w.dir);
        if (made || is_encrypted(m) || is_compressed(m) || is_tiered(m) || m_media_srcs.contains(w.object))
        {
            media_continue(cc, std::move(w));
            return;
        }
        std::weak_ptr<conn> weak2 = cc;
        const std::string b = w.bucket, k = w.key;
        m_store.open_object(b, k, 0, [this, weak2, want2 = std::move(w), etag](open_result o) mutable
        {
            if (o.status == st::ok && o.fd >= 0 && !is_encrypted(o.meta) && !is_compressed(o.meta) &&
                !is_tiered(o.meta) &&
                o.meta.etag() == etag &&
                !m_media_srcs.contains(want2.object))
            {
                m_media_srcs[want2.object] = {o.fd, o.data_off, o.meta.size, now_ms()};
                o.fd = -1;
            }
            if (o.fd >= 0)
                m_loop.close_fd(o.fd);
            if (auto c2 = weak2.lock(); c2 && !c2->dead)
                media_continue(c2, std::move(want2));
        });
    });
}

int storage_run::streams_max() const
{
    if (m_hw != media_hw::vaapi && m_hw != media_hw::vaapi_lp)
        return hls_jobs_max;
    return std::max<int>(hls_jobs_max, gpu_streams_max / static_cast<int>(std::max(1u, m_store.shards())));
}

void storage_run::media_hw_detect()
{
    // SOCKETLEY_MEDIA_HWACCEL: off, a render node, or vaapi-unchecked:<node>, which skips the test run so that a
    // test can see a GPU job fail and its rendition fall back to x264.
    const char* e = std::getenv("SOCKETLEY_MEDIA_HWACCEL");
    const std::string_view v = e ? e : "";
    m_hw = media_hw::none;
    if (v == "off")
        return;
    if (v.starts_with("vaapi-unchecked:"))
    {
        m_hw_device.assign(v.substr(16));
        m_hw = media_hw::vaapi;
        return;
    }
    m_hw_device = v.empty() ? "/dev/dri/renderD128" : std::string(v);
    if (::access(m_hw_device.c_str(), R_OK | W_OK) != 0)
        return;
    if (media_hw_test(false))
        m_hw = media_hw::testing;
}

bool storage_run::media_hw_test(bool low_power)
{
    // The whole chain a rendition takes, upload, scale and encode, on a second of test picture.
    std::vector<std::string> args = {m_ffmpeg, "-nostdin", "-hide_banner", "-loglevel", "error", "-init_hw_device",
                                     "vaapi=va:" + m_hw_device, "-filter_hw_device", "va", "-f", "lavfi", "-i",
                                     "testsrc2=s=640x360:r=25:d=1", "-vf", "format=nv12,hwupload,scale_vaapi=w=320:h=180:format=nv12",
                                     "-c:v", "h264_vaapi"};
    if (low_power)
        args.insert(args.end(), {"-low_power", "1"});
    args.insert(args.end(), {"-force_key_frames", "expr:gte(t,n_forced*1)", "-f", "null", "-"});
    std::vector<char*> argv;
    for (std::string& a : args)
        argv.push_back(a.data());
    argv.push_back(nullptr);
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_addopen(&fa, 1, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_addclosefrom_np(&fa, 3);
    pid_t pid = -1;
    const int rc = ::posix_spawn(&pid, m_ffmpeg.c_str(), &fa, nullptr, argv.data(), environ);
    posix_spawn_file_actions_destroy(&fa);
    if (rc != 0)
        return false;
    media_job j;
    j.pid = pid;
    j.want.kind = k_hwtest;
    j.started_ms = now_ms();
    j.seeked = low_power;
    m_media_jobs.push_back(std::move(j));
    media_watch_exit(pid);
    media_arm();
    return true;
}

void storage_run::media_continue(const std::shared_ptr<conn>& c, media_want w)
{
    if (media_try(c, w))
        return;
    m_media_waits.emplace_back(c, std::move(w));
    media_arm();
}

std::shared_ptr<const media_probe> storage_run::media_probe_of(const std::string& probe_dir)
{
    if (auto it = m_media_probes.find(probe_dir); it != m_media_probes.end())
    {
        media_touch(probe_dir);
        return it->second;
    }
    std::string text;
    auto p = std::make_shared<media_probe>();
    if (!exists(probe_dir + "/done") || !read_whole_file(probe_dir + "/probe.json", text) || !parse_probe(text, *p))
        return nullptr;
    if (m_media_probes.size() > 1024)
        m_media_probes.clear();
    m_media_probes.emplace(probe_dir, p);
    return p;
}

void storage_run::media_touch(const std::string& dir)
{
    const int64_t now = now_ms();
    auto& last = m_media_touched[dir];
    if (now - last < touch_every_ms)
        return;
    last = now;
    ::utimensat(AT_FDCWD, (dir + "/lock").c_str(), nullptr, 0);
    if (m_media_touched.size() > 4096)
        m_media_touched.clear();
}

void storage_run::media_source(const std::shared_ptr<conn>& c, std::string_view rest)
{
    // ffmpeg's own reads of an object it cannot read as a file, signed by the runtime that started it, good for a
    // while, and for the version it was started for.
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
    const std::string etag(r.get_query("e"));
    const std::string want = hmac_sha256_hex(m_media_key, bucket + '\n' + key + '\n' + etag + '\n' + std::to_string(expires));
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
    // An object written over since is refused, so a medium's cache never holds another version's bytes.
    if (!etag.empty())
    {
        c->app_header = "\"" + etag + "\"";
        r.headers.push_back({"if-match", c->app_header});
    }
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
    if (::fstat(fd, &fs) != 0)
    {
        ::close(fd);
        return false;
    }
    media_touch(w.dir);
    const std::string_view f = w.file;
    const std::string etag = media_etag(w.version, f);
    response head;
    head.headers.emplace_back("Content-Type", f.ends_with(".jpg")  ? "image/jpeg"
                                            : f.ends_with(".m3u8") ? "application/vnd.apple.mpegurl"
                                            : f.ends_with(".vtt")  ? "text/vtt; charset=utf-8"
                                            : f.ends_with(".mp4")  ? "video/mp4"
                                                                   : "video/iso.segment");
    // A URL that names the version never changes; one that does not is asked again, and answered 304 while it holds.
    head.headers.emplace_back("Cache-Control", growing ? "no-cache"
                                             : c->req.has_query("v") ? "private, max-age=31536000, immutable"
                                                                     : "private, no-cache");
    if (!growing)
        head.headers.emplace_back("ETag", etag);
    head.headers.emplace_back("Accept-Ranges", "bytes");
    ++m_c.media_served;
    uint64_t off = 0, len = static_cast<uint64_t>(fs.st_size);
    if (!growing && etag_matches(c->req.header("if-none-match"), etag))
    {
        ::close(fd);
        head.status = 304;
        head.head_only = true;
        head.has_length_override = true;
        head.length_override = 0;
        send_response(c, std::move(head));
        return true;
    }
    const http_range range = http_parse_range(c->req.header("range"), static_cast<size_t>(len));
    // A range wholly past the end is told the length, as the S3 path and a server tell it.
    if (range.unsatisfiable)
    {
        ::close(fd);
        head.status = 416;
        head.headers.emplace_back("Content-Range", "bytes */" + std::to_string(len));
        send_response(c, std::move(head));
        return true;
    }
    if (range.usable)
    {
        head.status = 206;
        head.headers.emplace_back("Content-Range", "bytes " + std::to_string(range.first) + "-" +
                                                       std::to_string(range.last) + "/" + std::to_string(len));
        off = range.first;
        len = range.last - range.first + 1;
    }
    if (w.head)
    {
        ::close(fd);
        head.head_only = true;
        head.has_length_override = true;
        head.length_override = len;
        send_response(c, std::move(head));
        return true;
    }
    // A thumbnail, a playlist or an init segment goes out with its head in one write.
    if (len <= small_file)
    {
        head.body.resize(len);
        const ssize_t got = ::pread(fd, head.body.data(), len, static_cast<off_t>(off));
        ::close(fd);
        if (got != static_cast<ssize_t>(len))
            return false;
        send_response(c, std::move(head));
        return true;
    }
    send_file(c, std::move(head), fd, off, len);
    return true;
}

bool storage_run::makes_web_copies(std::string_view bucket) const
{
    const auto xml = m_store.bucket_tagging(bucket);
    tag_set tags;
    s3_error err;
    return xml && parse_tagging_xml(*xml, tags, err, max_bucket_tags) &&
           std::ranges::any_of(tags, [](const auto& t) { return t.first == "socketley:web-copies" && t.second == "on"; });
}

void storage_run::media_put(std::string_view bucket, std::string_view key, const object_meta& m)
{
    if (m_stopped || sse_mode_of(m) == sse_mode::c || !is_film(m.content_type.str(), key) || !makes_web_copies(bucket))
        return;
    if (!m_ffmpeg_known)
    {
        m_ffmpeg = ffmpeg_path();
        m_ffmpeg_known = true;
    }
    if (m_ffmpeg.empty() || !media_dir_made())
        return;
    media_want w;
    w.kind = k_web;
    w.variant = "web";
    w.file = "web.mp4";
    w.bucket.assign(bucket);
    w.key.assign(key);
    media_name(w, m);
    if (std::ranges::any_of(m_media_unasked, [&w](const media_want& x) { return x.dir == w.dir; }))
        return;
    m_media_unasked.push_back(std::move(w));
    media_arm();
}

bool storage_run::media_unasked(const media_want& w)
{
    struct stat sb{};
    const int64_t now = now_ms();
    // One that waited longer than a copy may take is let go: a look at its link asks for it again.
    if (now - w.asked_ms > web_job_ms || m_media_done.contains(w.dir) || exists(w.dir + "/done"))
        return true;
    const auto pp = media_probe_of(w.probe_dir);
    if (!pp)
    {
        if (::stat((w.probe_dir + "/failed").c_str(), &sb) == 0 && now - mtime_ms(sb) < failed_hold_ms)
            return true;
        return !media_probe_begin(w);
    }
    if (pp->vcodec.empty() || (::stat((w.dir + "/failed").c_str(), &sb) == 0 && now - mtime_ms(sb) < failed_hold_ms))
        return true;
    // The shard's one web copy at a time, which one a client waits for is as much as one made for nobody.
    if (std::ranges::any_of(m_media_jobs, [](const media_job& j) { return j.want.kind == k_web; }))
        return false;
    if (::mkdir(w.dir.c_str(), 0700) < 0 && errno != EEXIST)
        return true;
    const std::string lock = w.dir + "/lock";
    const int lock_fd = ::open(lock.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lock_fd < 0)
        return true;
    // Held, it is being made already, here or on another shard.
    if (::flock(lock_fd, LOCK_EX | LOCK_NB) != 0 || !locked_fresh(lock_fd, lock))
    {
        ::close(lock_fd);
        return true;
    }
    kill_orphan(w.dir + "/pid", w.dir);
    if (exists(w.dir + "/done") || !media_start(w, lock_fd, 0))
        ::close(lock_fd);
    return true;
}

bool storage_run::media_dir_made()
{
    if (!m_media_dir_ready)
        m_media_dir_ready = ::mkdir((m_store.options().dir + "/.media").c_str(), 0700) == 0 || errno == EEXIST;
    return m_media_dir_ready;
}

void storage_run::media_name(media_want& w, const object_meta& m)
{
    // A medium is the object's as it is now, so a new version of it is made anew.
    const std::string media_dir = m_store.options().dir + "/.media";
    const std::string etag = m.etag();
    w.image = m.content_type.str().starts_with("image/");
    w.object = w.bucket + '\n' + w.key + '\n' + etag;
    w.version = etag.substr(0, 16);
    w.dir = medium_dir(media_dir, w.variant, w.object);
    // The second probe's, which also holds chapters; the first's are left for eviction.
    w.probe_dir = medium_dir(media_dir, "probe2", w.object);
    w.asked_ms = now_ms();
    w.deadline_ms = w.asked_ms + media_wait_ms;
}

bool storage_run::media_probe_begin(const media_want& w)
{
    media_want pw = w;
    pw.kind = k_probe;
    pw.variant = "probe";
    pw.dir = w.probe_dir;
    if (::mkdir(w.probe_dir.c_str(), 0700) < 0 && errno != EEXIST)
        return false;
    const std::string lock = w.probe_dir + "/lock";
    const int lock_fd = ::open(lock.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lock_fd >= 0 && ::flock(lock_fd, LOCK_EX | LOCK_NB) == 0 && locked_fresh(lock_fd, lock))
    {
        kill_orphan(w.probe_dir + "/pid", w.probe_dir);
        if (exists(w.probe_dir + "/done") || !media_start(pw, lock_fd, 0))
            ::close(lock_fd);
    }
    else if (lock_fd >= 0)
        ::close(lock_fd);
    return true;
}

void storage_run::media_known(const std::string& bucket, const std::string& key, const std::string& etag,
                              std::shared_ptr<const media_probe>& probe, bool& web_made)
{
    const std::string media_dir = m_store.options().dir + "/.media";
    const std::string object = bucket + '\n' + key + '\n' + etag;
    probe = media_probe_of(medium_dir(media_dir, "probe2", object));
    const std::string web = medium_dir(media_dir, "web", object);
    struct stat sb{};
    web_made = m_media_done.contains(web) || ::stat((web + "/done").c_str(), &sb) == 0;
}

bool storage_run::media_try(const std::shared_ptr<conn>& c, const media_want& w)
{
    struct stat sb{};
    // A file of a medium made whole is served as it is, without the probe it was made from.
    if (w.kind == k_thumb || w.kind == k_trick || w.kind == k_web || w.kind == k_copy || (w.kind == k_sub && w.file == "subs.vtt") ||
        (w.kind == k_rendition && w.file != "index.m3u8"))
    {
        const bool done = m_media_done.contains(w.dir) || ::stat((w.dir + "/done").c_str(), &sb) == 0;
        if (done)
        {
            m_media_done.insert(w.dir);
            if (media_serve(c, w, false))
                return true;
        }
    }
    // Everything but a thumbnail is made from the probe, which is made first, once, and kept.
    std::shared_ptr<const media_probe> pp;
    if (w.kind != k_thumb)
    {
        pp = media_probe_of(w.probe_dir);
        if (!pp)
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
            if (!media_probe_begin(w))
            {
                app_reply(c, 500, "The media cache cannot be written.\n");
                return true;
            }
            return false;
        }
    }
    const media_probe* p = pp.get();
    if (p && w.audio > 0 && static_cast<size_t>(w.audio) >= p->tracks.size())
    {
        app_reply(c, 404, "No such sound track.\n");
        return true;
    }
    if (w.kind == k_info || w.kind == k_master || (w.kind == k_rendition && w.file == "index.m3u8") ||
        (w.kind == k_sub && w.file == "index.m3u8"))
    {
        if (w.kind != k_info && p->vcodec.empty() && w.kind != k_master && w.kind != k_sub)
        {
            app_reply(c, 415, "This object has no picture to stream.\n");
            return true;
        }
        if (w.kind == k_rendition && p->duration <= 0)
        {
            app_reply(c, 415, "A stream of this length cannot be cut; ask for hls-copy.\n");
            return true;
        }
        int64_t index = 0;
        if (w.kind == k_sub && (!sub_index(w.variant, index) ||
                                std::ranges::none_of(p->subtitles, [&](const auto& s) { return s.index == index; })))
        {
            app_reply(c, 404, "No such text subtitle stream.\n");
            return true;
        }
        std::string text = w.kind == k_info       ? info_text(*p, w.version)
                         : w.kind == k_master     ? master_text(*p, w.source, w.version, w.audio)
                         : w.kind == k_rendition  ? rendition_text(*p, w.version)
                                                  : subtitle_text(*p, w.version);
        // These texts are written by this binary, so their tag names what they say: an upgrade that adds to them is not
        // answered 304 with what the browser kept from the one before.
        const std::string etag = media_etag(w.version, w.variant + "/" + sha256_hex(text).substr(0, 16));
        ++m_c.media_served;
        response r;
        r.headers.emplace_back("Content-Type", w.kind == k_info ? "application/json" : "application/vnd.apple.mpegurl");
        // The master and the info name the object's current version, so they are asked again; the rest are fixed by it.
        r.headers.emplace_back("Cache-Control", (w.kind == k_master || w.kind == k_info || !c->req.has_query("v"))
                                                    ? "private, no-cache" : "private, max-age=31536000, immutable");
        r.headers.emplace_back("ETag", etag);
        if (etag_matches(c->req.header("if-none-match"), etag))
        {
            r.status = 304;
            r.head_only = true;
            r.has_length_override = true;
            r.length_override = 0;
        }
        else
            r.body = std::move(text);
        send_response(c, std::move(r));
        return true;
    }
    if (w.kind == k_rendition)
    {
        if (w.seg >= segments_of(*p))
        {
            app_reply(c, 404, "No such segment: the film is shorter.\n");
            return true;
        }
        return media_segment(c, w);
    }
    if (w.kind == k_sub)
    {
        int64_t index = 0;
        if (!sub_index(w.variant, index) || std::ranges::none_of(p->subtitles, [&](const auto& s) { return s.index == index; }))
        {
            app_reply(c, 404, "No such text subtitle stream.\n");
            return true;
        }
    }
    if (w.kind == k_trick && (p->vcodec.empty() || p->duration <= 0))
    {
        app_reply(c, 415, "This object has no film to take stills of.\n");
        return true;
    }
    if (w.kind == k_web && p->vcodec.empty())
    {
        app_reply(c, 415, "This object has no film to make a web copy of.\n");
        return true;
    }

    // A thumbnail, a subtitle track and a copied stream: one job each, made whole, kept.
    const bool done = m_media_done.contains(w.dir) || ::stat((w.dir + "/done").c_str(), &sb) == 0;
    if (done)
        m_media_done.insert(w.dir);
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
    media_touch(w.dir);
    const bool stream = w.kind == k_copy;
    // The GPU's test run is no client's job, so it holds no place a thumbnail or a probe waits for; a film's stills,
    // which take minutes, have a place of their own, so thumbnails never wait behind them.
    const auto same_kind = std::ranges::count_if(m_media_jobs, [&](const media_job& j) {
        return j.want.kind != k_hwtest && (j.want.kind == k_trick) == (w.kind == k_trick) &&
               (j.want.kind == k_web) == (w.kind == k_web) &&
               (j.want.kind == k_copy || j.want.kind == k_rendition) == stream;
    });
    // The core count read once, since asking it opens a sysfs file and every waiting thumbnail asks fifty times a second.
    static const unsigned cores = std::thread::hardware_concurrency();
    const int thumb_jobs_max = std::max<int>(thumb_jobs_min, static_cast<int>(cores / std::max(1u, m_store.shards())));
    // A web copy, which takes every core it is given for as long as the film is, is made one at a time a shard.
    if (same_kind >= (stream ? streams_max() : w.kind == k_trick || w.kind == k_web ? 1 : thumb_jobs_max))
    {
        if (w.prepare)
        {
            app_reply(c, 202, "It is made once those before it are.\n");
            return true;
        }
        return false;
    }
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
    if (::flock(lock_fd, LOCK_EX | LOCK_NB) != 0 || !locked_fresh(lock_fd, lock))
    {
        ::close(lock_fd);
        // Being made already, here or on another shard, which is all a request to prepare it wants to know.
        if (w.prepare)
        {
            app_reply(c, 202, "It is being made.\n");
            return true;
        }
        return false;
    }
    kill_orphan(w.dir + "/pid", w.dir);
    // It may have been finished between the look and the lock.
    if (::stat((w.dir + "/done").c_str(), &sb) == 0)
    {
        ::close(lock_fd);
        return media_try(c, w);
    }
    // A film's still is a few seconds in, past a black first frame, and its seek bar's stills are from its keyframes.
    if (!media_start(w, lock_fd, (w.kind == k_thumb && !w.image) || w.kind == k_trick ? 1 : 0))
    {
        ::close(lock_fd);
        app_reply(c, 500, "ffmpeg could not be started.\n");
        return true;
    }
    if (w.prepare)
    {
        app_reply(c, 202, "It is being made.\n");
        return true;
    }
    return false;
}

bool storage_run::media_segment(const std::shared_ptr<conn>& c, const media_want& w)
{
    struct stat sb{};
    // A rendition made whole is served without a look at its jobs.
    if (m_media_done.contains(w.dir) && media_serve(c, w, false))
        return true;
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
    // A rendition ffmpeg failed on is answered so for a while, and segments past the picture's end are none.
    if (::stat((w.dir + "/failed").c_str(), &sb) == 0 && now_ms() - mtime_ms(sb) < failed_hold_ms)
    {
        app_reply(c, 415, "ffmpeg could not make this from the object.\n");
        return true;
    }
    const int64_t seg = std::max<int64_t>(w.seg, 0);
    if (seg >= read_int(w.dir + "/end", INT64_MAX))
    {
        app_reply(c, 404, "No such segment: the picture ends before it.\n");
        return true;
    }
    media_touch(w.dir);
    // A job at it or a little before it is waited for; the init segment comes from any job.
    for (const region& r : live)
        if (w.seg < 0 || (seg >= r.from && seg <= r.next + seek_beyond))
            return false;
    // A far segment is a seek, and a job begun only for an init, which no player asked a segment of, is let go.
    if (w.seg >= 0)
        for (const region& r : live)
            if (read_int(job_file(w.dir, r.from, ".want"), 0) < 0)
                mark(w.dir + "/jobs", (std::to_string(r.from) + ".drop").c_str());
    // Nothing near it: a seek, or the first player, and a job begins at the segment asked for, making room by
    // ending a job held still that nobody asks of.
    auto streams = std::ranges::count_if(m_media_jobs, [](const media_job& j) {
        return j.want.kind == k_copy || j.want.kind == k_rendition;
    });
    if (streams >= streams_max())
    {
        size_t oldest = m_media_jobs.size();
        for (size_t i = 0; i < m_media_jobs.size(); ++i)
            if (m_media_jobs[i].want.kind == k_rendition && m_media_jobs[i].paused &&
                now_ms() - m_media_jobs[i].asked_ms > unasked_ms &&
                (oldest == m_media_jobs.size() || m_media_jobs[i].asked_ms < m_media_jobs[oldest].asked_ms))
                oldest = i;
        if (oldest == m_media_jobs.size())
            return false;
        media_end_rendition(oldest, true);
        --streams;
    }
    if ((::mkdir(w.dir.c_str(), 0700) < 0 && errno != EEXIST) || (::mkdir((w.dir + "/jobs").c_str(), 0700) < 0 && errno != EEXIST))
    {
        app_reply(c, 500, "The media cache cannot be written.\n");
        return true;
    }
    const std::string lock = job_file(w.dir, seg, ".lock");
    const int lock_fd = ::open(lock.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    const int share_fd = ::open((w.dir + "/lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    // Another shard began here a moment ago, or the rendition is being evicted: either way, a look again shortly.
    if (lock_fd < 0 || share_fd < 0 || ::flock(lock_fd, LOCK_EX | LOCK_NB) != 0 || !locked_fresh(lock_fd, lock) ||
        ::flock(share_fd, LOCK_SH | LOCK_NB) != 0)
    {
        if (lock_fd >= 0)
            ::close(lock_fd);
        if (share_fd >= 0)
            ::close(share_fd);
        return false;
    }
    // The encoder is the rendition's for good, written by its first job: one rendition never mixes a GPU's
    // segments with x264's, whose inits differ.
    if (!exists(w.dir + "/encoder"))
    {
        const auto pp = media_probe_of(w.probe_dir);
        // HDR is tone-mapped on the GPU from its mastering display metadata, and with x264 where it has none.
        const bool gpu = (m_hw == media_hw::vaapi || m_hw == media_hw::vaapi_lp) && pp && (!pp->hdr() || pp->mastering);
        replace_file(w.dir + "/encoder", gpu ? (m_hw == media_hw::vaapi_lp ? "vaapi-lp" : "vaapi") : "x264", false);
    }
    write_int(job_file(w.dir, seg, ".pos"), seg);
    // A job begun for an init has been asked no segment yet, which is -1.
    write_int(job_file(w.dir, seg, ".want"), w.seg < 0 ? -1 : seg);
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
    // An unencrypted object is read from its open file, past its header; any other over the listener, which
    // serves it decrypted and in ranges as any client is.
    int src_fd = -1;
    std::string url;
    if (auto it = m_media_srcs.find(w.object); it != m_media_srcs.end())
    {
        it->second.used_ms = now_ms();
        src_fd = it->second.fd;
        url = "subfile,,start," + std::to_string(it->second.off) + ",end," + std::to_string(it->second.off + it->second.len) +
              ",,:/proc/self/fd/3";
    }
    else
    {
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
        const std::string etag = w.object.substr(w.object.rfind('\n') + 1);
        url = std::string(tls_enabled() ? "https://" : "http://") + host + ":" + std::to_string(port) + "/~media/src/";
        url_encode_to(url, w.bucket, true);
        url += '/';
        url_encode_to(url, w.key, true);
        url += "?t=" + std::to_string(expires) + "&e=" + etag + "&s=" +
               hmac_sha256_hex(m_media_key, w.bucket + '\n' + w.key + '\n' + etag + '\n' + std::to_string(expires));
    }

    // Reads over the listener survive a pause long enough for it to let them go; a file's need nothing of the sort.
    std::vector<std::string> input;
    if (src_fd < 0)
        input = {"-reconnect", "1", "-reconnect_on_network_error", "1"};
    input.insert(input.end(), {"-i", url});
    // As many encoder threads as cores, rather than x264's half again as many, when several jobs share them.
    const std::string threads = std::to_string(std::max(1u, std::thread::hardware_concurrency()));
    std::vector<std::string> args = {m_ffmpeg, "-nostdin", "-hide_banner", "-loglevel", "error", "-y"};
    std::string out_file;
    media_job j;
    std::shared_ptr<const media_probe> pp;
    if (w.kind == k_copy || w.kind == k_rendition || w.kind == k_trick || w.kind == k_web)
    {
        pp = media_probe_of(w.probe_dir);
        if (!pp)
            return false;
        // Another sound track is made or copied as the first would be, by its own codec and channels.
        if (w.audio > 0 && static_cast<size_t>(w.audio) < pp->tracks.size())
        {
            auto q = std::make_shared<media_probe>(*pp);
            q->acodec = q->tracks[static_cast<size_t>(w.audio)].codec;
            q->achannels = q->tracks[static_cast<size_t>(w.audio)].channels;
            pp = std::move(q);
        }
    }
    // Sound is copied only by the copied stream, which never begins mid-film: a copy begun at a seek keeps the
    // packets from the keyframe before it, and its segment starts there instead of at its own four seconds.
    const std::vector<std::string> aac = {"-c:a", "aac", "-aac_coder", "fast", "-b:a", "160k", "-ac", "2"};
    const std::vector<std::string> audio = !pp || !pp->audio ? std::vector<std::string>{}
                                         : w.kind == k_copy && audio_copies(*pp) ? std::vector<std::string>{"-c:a", "copy"}
                                         : aac;
    switch (w.kind)
    {
        case k_thumb:
        {
            uint64_t n = 0;
            thumb_width(w.variant, n);
            clear_dir(w.dir, true);
            // One frame is decoded and one written: ffmpeg's pools of threads, one a core for the decoder, the filter
            // and the encoder each, cost more to start than the picture, 166 ms against 72 for a 1600x1200 JPEG.
            args.insert(args.end(), {"-threads", "1", "-filter_threads", "1"});
            if (from > 0)
                args.insert(args.end(), {"-ss", "5"});
            args.insert(args.end(), input.begin(), input.end());
            args.insert(args.end(), {"-frames:v", "1", "-vf", "scale='min(" + std::to_string(n) + ",iw)':-2", "-q:v", "4",
                                     "-threads", "1", w.dir + "/thumb.jpg"});
            j.seeked = from > 0;
            break;
        }
        case k_web:
        {
            const media_probe& p = *pp;
            clear_dir(w.dir, true);
            args.insert(args.end(), input.begin(), input.end());
            args.insert(args.end(), {"-map", "0:v:0", "-map", "0:a:0?", "-sn", "-dn"});
            const web_plan plan = web_plan_of(p);
            const int64_t rate = plan.rate;
            if (plan.copies)
                args.insert(args.end(), {"-c:v", "copy"});
            else
            {
                std::string vf = "scale=" + std::to_string(plan.width) + ":" + std::to_string(plan.height);
                // Below the bitrate 1440 lines are made at, the bits a second frame of 60 would take go to the picture.
                if (plan.lines < 1440 && p.fps > 31)
                    vf += ",fps=30";
                if (p.hdr())
                    vf += ",zscale=t=linear:npl=100,format=gbrpf32le,zscale=p=bt709,tonemap=tonemap=hable:desat=0,"
                          "zscale=t=bt709:m=bt709:r=tv";
                vf += ",format=yuv420p";
                // Close to the original where the picture is easy, and held under the bitrate where it is not.
                args.insert(args.end(), {"-vf", vf, "-c:v", "libx264", "-preset", "slow", "-crf", "18",
                                         "-maxrate", std::to_string(rate), "-bufsize", std::to_string(rate * 2),
                                         "-profile:v", "high", "-threads", threads});
            }
            if (!p.audio)
                args.push_back("-an");
            else if (audio_copies(p))
                args.insert(args.end(), {"-c:a", "copy"});
            else
                args.insert(args.end(), aac.begin(), aac.end());
            // The index in front, so a player starts at once and seeks by range before the whole has come.
            args.insert(args.end(), {"-movflags", "+faststart", "-f", "mp4", w.dir + "/web.mp4"});
            break;
        }
        case k_trick:
        {
            const int64_t rows = (trick_count(*pp) + trick_cols) / trick_cols;
            clear_dir(w.dir, true);
            // Keyframes only are decoded first, and every frame when that gives no picture, as for a film of one keyframe;
            // a still is taken every so many seconds, fitted into its tile and tiled.
            if (from > 0)
                args.insert(args.end(), {"-skip_frame", "nokey"});
            j.seeked = from > 0;
            args.insert(args.end(), input.begin(), input.end());
            args.insert(args.end(), {"-map", "0:v:0", "-an", "-sn", "-vf",
                                     "fps=1/" + std::to_string(trick_every(*pp)) + ",scale=" + std::to_string(trick_w) + ":" +
                                     std::to_string(trick_h) + ":force_original_aspect_ratio=decrease,pad=" +
                                     std::to_string(trick_w) + ":" + std::to_string(trick_h) + ":(ow-iw)/2:(oh-ih)/2,tile=" +
                                     std::to_string(trick_cols) + "x" + std::to_string(rows),
                                     "-frames:v", "1", "-q:v", "5", w.dir + "/trick.jpg"});
            break;
        }
        case k_probe:
        {
            clear_dir(w.dir, true);
            // The first picture of each stream as well, whose side data says whether HDR comes with its mastering display.
            args = {ffprobe_path(m_ffmpeg), "-v", "error", "-print_format", "json", "-show_format", "-show_streams",
                    "-show_chapters", "-show_frames", "-read_intervals", "%+#1"};
            if (args.front().empty())
                return false;
            if (src_fd < 0)
                args.insert(args.end(), {"-reconnect", "1"});
            args.push_back(url);
            out_file = w.dir + "/probe.json.tmp";
            break;
        }
        case k_sub:
        {
            int64_t index = 0;
            sub_index(w.variant, index);
            clear_dir(w.dir, true);
            args.insert(args.end(), input.begin(), input.end());
            args.insert(args.end(), {"-map", "0:" + std::to_string(index), "-c:s", "webvtt", "-f", "webvtt",
                                     w.dir + "/subs.tmp.vtt"});
            break;
        }
        case k_copy:
        {
            clear_dir(w.dir, true);
            args.insert(args.end(), input.begin(), input.end());
            args.insert(args.end(), {"-map", "0:v:0?", "-map", "0:a:0?", "-c:v", "copy"});
            // HEVC as hvc1, the tag Apple's players take it in.
            if (pp->vcodec == "hevc")
                args.insert(args.end(), {"-tag:v", "hvc1"});
            args.insert(args.end(), audio.begin(), audio.end());
            args.insert(args.end(), {"-f", "hls", "-hls_time", std::to_string(seg_seconds),
                                     "-hls_playlist_type", "event", "-hls_segment_type", "fmp4", "-hls_fmp4_init_filename",
                                     "init.mp4", "-hls_flags", "temp_file+independent_segments", "-hls_segment_filename",
                                     w.dir + "/seg%05d.m4s", w.dir + "/index.m3u8"});
            break;
        }
        case k_rendition:
        {
            const media_probe& p = *pp;
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
            std::string encoder;
            read_whole_file(w.dir + "/encoder", encoder);
            const bool gpu = encoder.starts_with("vaapi") && !m_hw_device.empty();
            // On the GPU the picture is decoded, scaled, tone-mapped and encoded there, and never copied back.
            if (gpu)
                args.insert(args.end(), {"-init_hw_device", "vaapi=va:" + m_hw_device, "-filter_hw_device", "va",
                                         "-hwaccel", "vaapi", "-hwaccel_output_format", "vaapi"});
            // Begun at a segment's own time, with its number, so that its segments are the ones a run from the start
            // would have made: keyframes every four seconds of the film, and the film's own timestamps.
            args.insert(args.end(), {"-ss", offset});
            args.insert(args.end(), input.begin(), input.end());
            if (gpu)
            {
                std::string hwvf = "scale_vaapi=w=" + std::to_string(width) + ":h=" + std::to_string(height) + ":format=nv12";
                if (p.hdr())
                    hwvf = "tonemap_vaapi=format=nv12:p=bt709:t=bt709:m=bt709," + hwvf;
                args.insert(args.end(), {"-map", "0:v:0", "-map", "0:a:0?", "-c:v", "h264_vaapi"});
                if (encoder == "vaapi-lp")
                    args.insert(args.end(), {"-low_power", "1"});
                args.insert(args.end(), {"-rc_mode", "VBR", "-b:v", std::to_string(r->kbps * 3 / 5) + "k",
                                         "-maxrate", std::to_string(r->kbps) + "k", "-bufsize", std::to_string(r->kbps) + "k",
                                         "-profile:v", "high", "-level", avc_level(r->height), "-vf", hwvf,
                                         "-force_key_frames", "expr:gte(t,n_forced*" + std::to_string(seg_seconds) + ")"});
                j.gpu = true;
            }
            else
            // Jellyfin's motion search: a fifth less CPU for an SSIM of 0.9690 against 0.9695, and no keyframe at a
            // scene cut, so every segment is cut where the forced ones are. The buffer is one second of the cap, so a
            // segment holds at most a quarter more than the cap over its four seconds, as BANDWIDTH says.
                args.insert(args.end(), {"-map", "0:v:0", "-map", "0:a:0?", "-c:v", "libx264", "-preset", "veryfast", "-crf", "23",
                                         "-x264-params", "subme=0:me_range=16:rc_lookahead=10:me=hex:open_gop=0",
                                         "-sc_threshold", "0", "-threads", threads, "-level:v", avc_level(r->height),
                                         "-maxrate", std::to_string(r->kbps) + "k", "-bufsize", std::to_string(r->kbps) + "k",
                                         "-vf", vf,
                                         "-force_key_frames", "expr:gte(t,n_forced*" + std::to_string(seg_seconds) + ")"});
            // BT.709 is said in the bitstream, since ffmpeg 8 and later take the colour options on the output for a
            // conversion, which puts software frames behind scale_vaapi and leaves x264's transfer and matrix unsaid.
            args.insert(args.end(), {"-bsf:v", "h264_metadata=colour_primaries=1:transfer_characteristics=1:matrix_coefficients=1"});
            args.insert(args.end(), audio.begin(), audio.end());
            // The film's time in every fragment and none in the init, so that any job's init fits every job's segments.
            args.insert(args.end(), {"-avoid_negative_ts", "disabled", "-output_ts_offset", offset,
                                     "-hls_segment_options", "movflags=+frag_discont",
                                     "-f", "hls", "-hls_time", std::to_string(seg_seconds),
                                     "-hls_playlist_type", "event", "-hls_segment_type", "fmp4", "-hls_fmp4_init_filename",
                                     std::to_string(from) + "-init.mp4", "-hls_flags", "temp_file+independent_segments",
                                     "-start_number", std::to_string(from), "-hls_segment_filename", w.dir + "/seg%05d.m4s",
                                     job_file(w.dir, from, ".m3u8")});
            j.from = from;
            j.next = from;
            j.wanted = w.seg < 0 ? -1 : from;
            j.asked_ms = now_ms();
            j.total = segments_of(p);
            break;
        }
        default:
            return false;
    }
    if (w.audio > 0)
        std::ranges::replace(args, std::string("0:a:0?"), "0:a:" + std::to_string(w.audio) + "?");
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
    // The object's file as fd 3, and nothing else of the worker's, so a listener or a ring is never held by ffmpeg.
    if (src_fd >= 0)
        posix_spawn_file_actions_adddup2(&fa, src_fd, 3);
    posix_spawn_file_actions_addclosefrom_np(&fa, src_fd >= 0 ? 4 : 3);
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
    if (src_fd >= 0)
        ++m_c.media_direct;
    if (j.gpu)
        ++m_c.media_hw;
    // The pid, by which a later worker finds an ffmpeg this one leaves behind when it dies.
    write_int(w.kind == k_rendition ? job_file(w.dir, from, ".pid") : w.dir + "/pid", pid);
    ::futimens(lock_fd, nullptr);
    j.pid = pid;
    j.lock_fd = lock_fd;
    j.want = w;
    j.started_ms = now_ms();
    m_media_jobs.push_back(std::move(j));
    media_watch_exit(pid);
    media_arm();
    return true;
}

void storage_run::media_arm()
{
    if (m_media_timer.armed || m_stopped)
        return;
    const int64_t ms = m_media_waits.empty() ? media_tick_ms : media_wait_tick_ms;
    m_media_timer.ts  = {0, ms * 1000000};
    m_media_timer.req = io_request{};
    m_media_timer.req.owner = this;
    m_media_timer.req.type  = op_timeout;
    m_media_timer.armed = m_loop.submit_timeout(&m_media_timer.ts, &m_media_timer.req);
}

void storage_run::media_end_rendition(size_t i, bool kill)
{
    media_job& j = m_media_jobs[i];
    if (kill)
    {
        if (j.paused)
            ::kill(j.pid, SIGCONT);
        ::kill(j.pid, SIGKILL);
        reap_later(j.pid);
    }
    if (all_made(j.want.dir, j.total) && !exists(j.want.dir + "/done"))
    {
        mark(j.want.dir, "done");
        m_media_done.insert(j.want.dir);
        ++m_c.media_made;
    }
    drop_job_files(j.want.dir, j.from);
    ::close(j.lock_fd);
    if (j.share_fd >= 0)
        ::close(j.share_fd);
    m_media_jobs.erase(m_media_jobs.begin() + static_cast<ptrdiff_t>(i));
}

// A killed ffmpeg reaped now if it has ended, and at a later tick if not: one stuck in the kernel on a hung disk
// would otherwise hold the loop in waitpid until the disk answered.
void storage_run::reap_later(pid_t pid)
{
    if (::waitpid(pid, nullptr, WNOHANG) == 0)
        m_media_unreaped.push_back(pid);
}

void storage_run::media_tick()
{
    std::erase_if(m_media_unreaped, [](pid_t pid) { return ::waitpid(pid, nullptr, WNOHANG) != 0; });
    bool finished = false;
    // A stream finished is a large medium in: eviction runs at once, where a thumbnail's waits its turn.
    bool large = false;
    std::string made;
    for (size_t i = 0; i < m_media_jobs.size();)
    {
        media_job& j = m_media_jobs[i];
        int status = 0;
        const pid_t r = ::waitpid(j.pid, &status, WNOHANG);
        struct stat sb{};
        const int64_t now = now_ms();
        if (j.want.kind == k_hwtest)
        {
            if (r == 0 && now - j.started_ms < 15000)
            {
                ++i;
                continue;
            }
            if (r == 0)
            {
                ::kill(j.pid, SIGKILL);
                reap_later(j.pid);
            }
            const bool ok = r == j.pid && WIFEXITED(status) && WEXITSTATUS(status) == 0;
            const bool lp = j.seeked;
            m_media_jobs.erase(m_media_jobs.begin() + static_cast<ptrdiff_t>(i));
            // The full encoder first, then the low-power one, which is all some GPUs have; else none.
            if (ok)
                m_hw = lp ? media_hw::vaapi_lp : media_hw::vaapi;
            else if (lp || !media_hw_test(true))
                m_hw = media_hw::none;
            continue;
        }
        if (j.want.kind == k_rendition)
        {
            // Where the job is, by its own playlist, so that segments another job made are not taken for its own.
            const std::string own = job_file(j.want.dir, j.from, ".m3u8");
            if (::stat(own.c_str(), &sb) == 0 && mtime_ms(sb) != j.playlist_mtime)
            {
                j.playlist_mtime = mtime_ms(sb);
                std::string text;
                if (read_whole_file(own, text))
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
            // The rendition's init segment is the first job's, linked in whole; every job's is the same bytes.
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
                // Held still with nobody asking for a minute, running with nobody asking for the idle time, or begun
                // for an init and let go by the seek that followed it.
                const bool abandoned = now - j.asked_ms > (j.paused ? 60000 : hls_idle_ms) ||
                                       exists(job_file(j.want.dir, j.from, ".drop"));
                if (!merged && !abandoned)
                {
                    const bool unasked = now - j.asked_ms > unasked_ms ||
                                         (j.wanted < 0 && now - j.started_ms > init_only_ms);
                    if (!j.paused && (j.next > j.wanted + pause_ahead || (unasked && j.next > j.wanted + 2)))
                    {
                        ::kill(j.pid, SIGSTOP);
                        j.paused = true;
                    }
                    else if (j.paused && !unasked && j.wanted + resume_within >= j.next)
                    {
                        ::kill(j.pid, SIGCONT);
                        j.paused = false;
                    }
                    ++i;
                    continue;
                }
                media_end_rendition(i, true);
                continue;
            }
            if (r != j.pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
            {
                ++m_c.media_failed;
                // A GPU job that fails before the rendition has anything is the GPU's failure with this film: the
                // rendition is made with x264 from then on. Any other that fails from its very start is the medium's.
                if (j.gpu && j.next == j.from && !exists(j.want.dir + "/init.mp4"))
                    replace_file(j.want.dir + "/encoder", "x264", false);
                else if (j.next == j.from)
                    mark(j.want.dir, "failed");
            }
            else if (j.next == j.from && j.from > 0)
            {
                // A job that ran to its end and made nothing began past the last frame: no segment from there exists.
                if (read_int(j.want.dir + "/end", INT64_MAX) > j.from)
                    write_int(j.want.dir + "/end", j.from);
            }
            made = m_media_jobs[i].want.dir;
            media_end_rendition(i, false);
            finished = true;
            large = true;
            continue;
        }
        if (r == 0)
        {
            const bool idle = j.want.kind == k_copy && ::fstat(j.lock_fd, &sb) == 0 && now - mtime_ms(sb) > hls_idle_ms;
            const int64_t allowed = j.want.kind == k_trick ? trick_job_ms : j.want.kind == k_web ? web_job_ms : thumb_job_ms;
            if (!idle && (j.want.kind == k_copy || now - j.started_ms <= allowed))
            {
                ++i;
                continue;
            }
            ::kill(j.pid, SIGKILL);
            reap_later(j.pid);
            // A stream let go is begun again when asked for; anything else that took too long is a failure.
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
            else if (j.want.kind == k_sub)
            {
                // The track's cues on the film's own clock, as an HLS player is told they are.
                std::string vtt;
                ok = ok && read_whole_file(j.want.dir + "/subs.tmp.vtt", vtt) && vtt.starts_with("WEBVTT");
                if (ok)
                {
                    const size_t eol = vtt.find('\n');
                    vtt.insert(eol == std::string::npos ? vtt.size() : eol + 1, "X-TIMESTAMP-MAP=MPEGTS:0,LOCAL:00:00:00.000\n");
                    replace_file(j.want.dir + "/subs.vtt", vtt, false);
                    ::unlink((j.want.dir + "/subs.tmp.vtt").c_str());
                }
            }
            else
            {
                const std::string out = j.want.dir + (j.want.kind == k_copy    ? "/index.m3u8"
                                                    : j.want.kind == k_trick ? "/trick.jpg"
                                                    : j.want.kind == k_web   ? "/web.mp4"
                                                                             : "/thumb.jpg");
                ok = ok && ::stat(out.c_str(), &sb) == 0 && sb.st_size > 0;
            }
            // A still a few seconds in that the film is too short for is taken from its start, and stills its keyframes
            // did not give are taken from every frame.
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
            if (ok)
                m_media_done.insert(j.want.dir);
            large = large || j.want.kind == k_copy || j.want.kind == k_web;
            made = j.want.dir;
            if (j.want.kind != k_probe)
                ++(ok ? m_c.media_made : m_c.media_failed);
            finished = true;
        }
        ::unlink((j.want.dir + "/pid").c_str());
        ::close(j.lock_fd);
        m_media_jobs.erase(m_media_jobs.begin() + static_cast<ptrdiff_t>(i));
    }
    // Each waiting request looks again, and may start what a finished one made room for; a request that waits is
    // making progress as far as the idle sweep goes.
    const auto now_steady = std::chrono::steady_clock::now();
    auto waits = std::move(m_media_waits);
    m_media_waits.clear();
    for (auto& [weak, w] : waits)
    {
        auto c = weak.lock();
        if (!c || c->dead || media_try(c, w))
            continue;
        c->last_progress = now_steady;
        m_media_waits.emplace_back(std::move(weak), std::move(w));
    }
    std::erase_if(m_media_unasked, [this](const media_want& w) { return media_unasked(w); });
    // An object's file no job has started from for a minute is let go.
    const int64_t now = now_ms();
    for (auto it = m_media_srcs.begin(); it != m_media_srcs.end();)
    {
        if (now - it->second.used_ms > source_keep_ms)
        {
            m_loop.close_fd(it->second.fd);
            it = m_media_srcs.erase(it);
        }
        else
            ++it;
    }
    if (finished && (large || now - m_media_evicted_ms > evict_every_ms))
    {
        m_media_evicted_ms = now;
        media_evict(made);
    }
    if (!m_media_jobs.empty() || !m_media_waits.empty() || !m_media_srcs.empty() || !m_media_unasked.empty())
        media_arm();
}

void storage_run::media_evict(const std::string& keep)
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
    // The medium just made stays, so that one larger than the whole cache is still served once made.
    for (size_t i = 0; i < all.size() && total > cap; ++i)
    {
        const entry& en = all[i];
        if (en.dir == keep)
            continue;
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
        m_media_done.erase(en.dir);
        m_media_probes.erase(en.dir);
    }
}

// The kernel says when a job's process ends, through a pidfd the ring polls, so what it made is served at once
// rather than at the next look of the tick; without pidfds (Linux before 5.3) the tick alone finds it.
void storage_run::media_watch_exit(pid_t pid)
{
    const int fd = static_cast<int>(::syscall(SYS_pidfd_open, pid, 0));
    if (fd < 0)
        return;
    auto& e = m_media_exits.emplace_back();
    e.fd = fd;
    e.req = io_request{};
    e.req.owner = this;
    e.req.type  = op_poll;
    if (!m_loop.submit_poll_add(fd, POLLIN, &e.req))
    {
        ::close(fd);
        m_media_exits.pop_back();
    }
}

bool storage_run::media_exit_done(io_request* req)
{
    for (auto it = m_media_exits.begin(); it != m_media_exits.end(); ++it)
        if (&it->req == req)
        {
            if (it->fd >= 0)
                ::close(it->fd);
            m_media_exits.erase(it);
            if (!m_stopped)
                media_tick();
            return true;
        }
    return false;
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
    m_media_unasked.clear();
    for (auto& [object, src] : m_media_srcs)
        m_loop.close_fd(src.fd);
    m_media_srcs.clear();
    if (m_media_timer.armed)
        m_loop.submit_timeout_remove(&m_media_timer.req);
    // The processes are gone, so their polls complete; each is withdrawn and its fd closed, and the loop forgets them.
    for (auto& e : m_media_exits)
    {
        if (!m_loop.submit_poll_remove(&e.req)) {}
        // Its cancelled poll still completes into media_exit_done(), which must not close the number again.
        ::close(e.fd);
        e.fd = -1;
    }
}

}   // namespace socketley::storage
