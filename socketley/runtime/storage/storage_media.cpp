// Media made from the objects: a thumbnail of a picture or a film, and a film or a song as HLS, which a player
// streams while it is still being made. ffmpeg makes both, reading the object through this runtime's own listener,
// and what it made is kept under <dir>/.media/ for every later request, on whichever shard it lands.
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
#include <cstdlib>

#include "digest.h"
#include "s3_names.h"
#include "sse.h"

extern char** environ;

namespace socketley::storage
{

namespace
{

// Thumbnails queue behind a few at a time; a stream is someone waiting to watch, and never waits for another's film.
constexpr int     thumb_jobs_max   = 2;
constexpr int     hls_jobs_max     = 8;
constexpr int64_t media_tick_ms    = 100;
constexpr int64_t media_wait_ms    = 60000;
constexpr int64_t thumb_job_ms     = 60000;
// A stream nobody has asked for in this long is let go, and made again from the start when asked for.
constexpr int64_t hls_idle_ms      = 600000;
// A failure is answered as one for this long, and tried again after.
constexpr int64_t failed_hold_ms   = 120000;
// How long ffmpeg's address for an object stays good, which bounds one transcoding.
constexpr int64_t source_ttl_s     = 6 * 3600;
constexpr uint64_t cache_default_mb = 10240;
constexpr std::string_view hls_seconds = "4";

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

bool hls_height(std::string_view v, uint64_t& h)
{
    constexpr uint64_t allowed[] = {240, 360, 480, 720, 1080, 1440, 2160};
    if (v == "hls-copy")
    {
        h = 0;
        return true;
    }
    return v.starts_with("hls-") && parse_uint(v.substr(4), h) && std::ranges::find(allowed, h) != std::end(allowed);
}

bool hls_file(std::string_view f)
{
    if (f == "index.m3u8" || f == "init.mp4")
        return true;
    if (!f.starts_with("seg") || !f.ends_with(".m4s") || f.size() != 3 + 5 + 4)
        return false;
    return std::ranges::all_of(f.substr(3, 5), [](char ch) { return ch >= '0' && ch <= '9'; });
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

std::string ffmpeg_path()
{
    if (const char* e = std::getenv("SOCKETLEY_FFMPEG"); e && *e)
        return ::access(e, X_OK) == 0 ? std::string(e) : std::string{};
    const char* path = std::getenv("PATH");
    std::string_view rest = path ? path : "/usr/local/bin:/usr/bin:/bin";
    while (!rest.empty())
    {
        const size_t colon = rest.find(':');
        const std::string cand = std::string(rest.substr(0, colon)) + "/ffmpeg";
        if (::access(cand.c_str(), X_OK) == 0)
            return cand;
        rest = colon == std::string_view::npos ? std::string_view{} : rest.substr(colon + 1);
    }
    return {};
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
    if (thumb_width(variant, size))
        w.file = "thumb.jpg";
    else if (hls_height(variant, size))
    {
        // The playlist and its segments sit beside one another under the medium's path.
        const size_t last = source.rfind('/');
        if (last == std::string_view::npos || !hls_file(source.substr(last + 1)))
        {
            app_reply(c, 404, "A stream is index.m3u8 and its segments.\n");
            return;
        }
        w.file.assign(source.substr(last + 1));
        source = source.substr(0, last);
        w.hls = true;
    }
    else
    {
        app_reply(c, 404, "No such variant: thumb-<width> or hls-<height>.\n");
        return;
    }

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
        w.dir = media_dir + "/" + sha256_hex(w.variant + '\n' + w.bucket + '\n' + w.key + '\n' + m.etag());
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

bool storage_run::media_try(const std::shared_ptr<conn>& c, const media_want& w)
{
    struct stat sb{};
    const bool done = ::stat((w.dir + "/done").c_str(), &sb) == 0;
    const std::string lock = w.dir + "/lock";
    if (done || w.hls)
    {
        // A stream's playlist and segments are served as they are written, each one whole as ffmpeg renames it in.
        const int fd = ::open((w.dir + "/" + w.file).c_str(), O_RDONLY | O_CLOEXEC);
        if (fd >= 0)
        {
            struct stat fs{};
            ::fstat(fd, &fs);
            ::utimensat(AT_FDCWD, lock.c_str(), nullptr, 0);
            response head;
            const std::string_view f = w.file;
            head.headers.emplace_back("Content-Type", f.ends_with(".jpg")  ? "image/jpeg"
                                                    : f.ends_with(".m3u8") ? "application/vnd.apple.mpegurl"
                                                    : f.ends_with(".mp4")  ? "video/mp4"
                                                                           : "video/iso.segment");
            // A playlist still growing is asked for again, and what is done does not change.
            head.headers.emplace_back("Cache-Control", f.ends_with(".m3u8") && !done ? "no-cache" : "private, max-age=86400");
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
        if (done)
        {
            app_reply(c, 404, "No such part of this stream.\n");
            return true;
        }
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
    const auto same_kind = std::ranges::count_if(m_media_jobs, [&](const media_job& j) { return j.want.hls == w.hls; });
    if (same_kind >= (w.hls ? hls_jobs_max : thumb_jobs_max))
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
    if (!media_start(w, lock_fd, !w.image && !w.hls))
    {
        ::close(lock_fd);
        app_reply(c, 500, "ffmpeg could not be started.\n");
        return true;
    }
    return false;
}

bool storage_run::media_start(const media_want& w, int lock_fd, bool seek)
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

    clear_dir(w.dir, true);
    std::vector<std::string> args = {m_ffmpeg, "-nostdin", "-hide_banner", "-loglevel", "error", "-y"};
    uint64_t n = 0;
    if (thumb_width(w.variant, n))
    {
        // A film's still is a few seconds in, past a black first frame; a short one is taken from the start instead.
        if (seek)
            args.insert(args.end(), {"-ss", "5"});
        args.insert(args.end(), {"-i", url, "-frames:v", "1", "-vf", "scale='min(" + std::to_string(n) + ",iw)':-2",
                                 "-q:v", "4", w.dir + "/thumb.jpg"});
    }
    else
    {
        hls_height(w.variant, n);
        args.insert(args.end(), {"-i", url, "-map", "0:v:0?", "-map", "0:a:0?"});
        if (n == 0)
            args.insert(args.end(), {"-c", "copy"});
        else
            args.insert(args.end(), {"-c:v", "libx264", "-preset", "veryfast", "-crf", "23", "-pix_fmt", "yuv420p",
                                     // A height names the 16:9 box the picture fits in, so a scope film at 720 is 1280 wide.
                                     "-vf", "scale='min(" + std::to_string(n * 16 / 9 / 2 * 2) + ",iw)':'min(" + std::to_string(n) +
                                         ",ih)':force_original_aspect_ratio=decrease:force_divisible_by=2",
                                     "-force_key_frames", "expr:gte(t,n_forced*" + std::string(hls_seconds) + ")",
                                     "-c:a", "aac", "-b:a", "160k", "-ac", "2"});
        // CMAF segments, which every HLS player of today plays, and which are fragments of one MP4.
        args.insert(args.end(), {"-f", "hls", "-hls_time", std::string(hls_seconds), "-hls_playlist_type", "event",
                                 "-hls_segment_type", "fmp4", "-hls_fmp4_init_filename", "init.mp4",
                                 "-hls_flags", "temp_file+independent_segments", "-hls_segment_filename",
                                 w.dir + "/seg%05d.m4s", w.dir + "/index.m3u8"});
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
    posix_spawn_file_actions_addopen(&fa, 1, "/dev/null", O_WRONLY, 0);
    const std::string log = w.dir + "/log";
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
    const int rc = ::posix_spawn(&pid, m_ffmpeg.c_str(), &fa, &attr, argv.data(), environ);
    posix_spawn_file_actions_destroy(&fa);
    posix_spawnattr_destroy(&attr);
    if (rc != 0)
        return false;
    ::futimens(lock_fd, nullptr);
    media_job j;
    j.pid = pid;
    j.lock_fd = lock_fd;
    j.want = w;
    j.started_ms = now_ms();
    j.seeked = seek;
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
        if (r == 0)
        {
            const int64_t now = now_ms();
            const bool idle = j.want.hls && ::fstat(j.lock_fd, &sb) == 0 && now - mtime_ms(sb) > hls_idle_ms;
            if (!idle && (j.want.hls || now - j.started_ms <= thumb_job_ms))
            {
                ++i;
                continue;
            }
            ::kill(j.pid, SIGKILL);
            ::waitpid(j.pid, nullptr, 0);
            // A stream let go is begun again when asked for; a thumbnail that took too long is a failure.
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
            const std::string out = j.want.dir + (j.want.hls ? "/index.m3u8" : "/thumb.jpg");
            const bool ok = r == j.pid && WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
                            ::stat(out.c_str(), &sb) == 0 && sb.st_size > 0;
            // A still a few seconds in that the film is too short for is taken from its start.
            if (!ok && j.seeked)
            {
                const media_want w = j.want;
                const int lock_fd = j.lock_fd;
                m_media_jobs.erase(m_media_jobs.begin() + static_cast<ptrdiff_t>(i));
                if (!media_start(w, lock_fd, false))
                {
                    mark(w.dir, "failed");
                    ++m_c.media_failed;
                    ::close(lock_fd);
                    finished = true;
                }
                continue;
            }
            mark(j.want.dir, ok ? "done" : "failed");
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
        ::kill(j.pid, SIGKILL);
        ::waitpid(j.pid, nullptr, 0);
        ::close(j.lock_fd);
    }
    m_media_jobs.clear();
    m_media_waits.clear();
    if (m_media_timer.armed)
        m_loop.submit_timeout_remove(&m_media_timer.req);
}

}   // namespace socketley::storage
