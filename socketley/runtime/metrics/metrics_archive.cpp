#include "metrics_archive.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <ctime>
#include <vector>

#include "metrics_block.h"
#include "../sync/sync_run.h"
#include "../../shared/http/http_url.h"
#include "../../shared/persist/read_file.h"
#include "../../shared/persist/replaced_file.h"
#include "../../shared/storage/s3_sigv4.h"
#include "../../shared/util/logging.h"

namespace socketley::metrics
{

namespace
{

constexpr int64_t a_day = 86'400'000;
// A body read this much at a time when TLS keeps it from going by splice.
constexpr size_t body_piece = 256u << 10;

std::string amz_date_now()
{
    char buf[32];
    const std::time_t t = std::time(nullptr);
    std::tm tm{};
    gmtime_r(&t, &tm);
    std::strftime(buf, sizeof buf, "%Y%m%dT%H%M%SZ", &tm);
    return buf;
}

}   // namespace

archiver::archiver(event_loop& loop, file_io& io, hash_pool& resolver, std::string owner)
    : m_loop(loop), m_io(io), m_resolver(resolver), m_owner(std::move(owner))
{
}

archiver::~archiver() { stop(); }

bool archiver::configure(std::string_view url, std::string credentials, std::string dir, std::string& why)
{
    socketley::http_target t;
    if (!socketley::parse_http_url(url, t, why))
        return false;
    std::string_view path = t.path;
    while (path.starts_with('/'))
        path.remove_prefix(1);
    while (path.ends_with('/'))
        path.remove_suffix(1);
    const size_t slash = path.find('/');
    m_bucket.assign(path.substr(0, slash));
    m_prefix = slash == std::string_view::npos ? std::string() : std::string(path.substr(slash + 1)) + "/";
    if (m_bucket.empty())
        return why = std::string(url) + " names no bucket: http[s]://host/bucket[/prefix]", false;
    m_credentials = std::move(credentials);
    m_dir = std::move(dir);
    m_peer = std::make_unique<socketley::http_peer>(m_loop, m_io, m_resolver, t, std::string{},
                                                    "metrics " + m_owner + ": the archive");
    std::string text;
    if (socketley::read_file(m_dir + "/archived", text))
        for (size_t at = 0; at < text.size();)
        {
            const size_t nl = std::min(text.find('\n', at), text.size());
            if (nl > at)
                m_done.emplace(text.substr(at, nl - at));
            at = nl + 1;
        }
    return true;
}

void archiver::stop()
{
    *m_alive = false;
    if (m_peer)
        m_peer->stop();
    m_running = false;
}

void archiver::save() const
{
    std::string text;
    for (const std::string& n : m_done)
        text += n + "\n";
    if (!socketley::replace_file(m_dir + "/archived", text, socketley::durability::data)) {}
}

int64_t archiver::tick(int64_t now)
{
    if (!m_peer)
        return INT64_MAX;
    if (m_running)
    {
        m_peer->tick(std::chrono::steady_clock::now());
        return now + 1000;
    }
    if (now < m_next)
        return m_next;
    m_next = now + every_ms;
    // The oldest block first that is whole for good: a day or more, or two days past its end, so a merge seldom
    // replaces what was copied.
    std::vector<std::string> due;
    if (DIR* d = ::opendir((m_dir + "/blocks").c_str()))
    {
        while (const dirent* e = ::readdir(d))
        {
            int64_t step = 0, mint = 0, maxt = 0;
            const std::string n = e->d_name;
            if (parse_block_name(n, step, mint, maxt) && !m_done.contains(n) &&
                (maxt - mint >= a_day || now - maxt >= 2 * a_day))
                due.push_back(n);
        }
        ::closedir(d);
    }
    // The names' copies that no longer lie in blocks/ are forgotten, as the file would otherwise grow for good.
    std::erase_if(m_done, [&](const std::string& n) {
        struct stat st{};
        return ::stat((m_dir + "/blocks/" + n).c_str(), &st) != 0;
    });
    if (due.empty())
        return m_next;
    std::sort(due.begin(), due.end(), [](const std::string& a, const std::string& b) {
        int64_t sa = 0, ma = 0, xa = 0, sb = 0, mb = 0, xb = 0;
        parse_block_name(a, sa, ma, xa);
        parse_block_name(b, sb, mb, xb);
        return ma < mb;
    });
    start(due.front());
    return now + 1000;
}

void archiver::start(const std::string& name)
{
    socketley::sync::sync_credentials cred;
    std::string why;
    if (!socketley::sync::read_sync_credentials(m_credentials, cred, why))
    {
        ++m_f.failures;
        if (!m_said)
            LOG_WARN(("metrics " + m_owner + ": the archive's credentials do not read: " + why).c_str());
        m_said = true;
        return;
    }
    const std::string path = m_dir + "/blocks/" + name;
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    struct stat st{};
    if (fd < 0 || ::fstat(fd, &st) != 0)
    {
        if (fd >= 0)
            ::close(fd);
        return;
    }
    auto file = std::shared_ptr<int>(new int(fd), [](int* p) {
        ::close(*p);
        delete p;
    });
    const uint64_t len = static_cast<uint64_t>(st.st_size);
    const std::string key = "/" + m_bucket + "/" + m_prefix + name;
    const std::string date = amz_date_now();
    const std::vector<std::pair<std::string, std::string>> headers = {
        {"host", m_peer->target().authority()},
        {"x-amz-date", date},
        {"x-amz-content-sha256", "UNSIGNED-PAYLOAD"},
        {"content-length", std::to_string(len)}};
    std::vector<socketley::s3::header_field> fields;
    for (const auto& [n, v] : headers)
        fields.push_back({n, v});
    if (!cred.session_token.empty())
        fields.push_back({"x-amz-security-token", cred.session_token});
    socketley::s3::sign_input in;
    in.method = "PUT";
    in.raw_path = key;
    in.headers = fields;
    in.payload_hash = "UNSIGNED-PAYLOAD";
    in.access_key = cred.access_key;
    in.secret = cred.secret;
    in.region = cred.region;
    in.amz_date = date;
    socketley::http_request rq;
    rq.head = "PUT " + key + " HTTP/1.1\r\n";
    for (const auto& [n, v] : headers)
        rq.head += n + ": " + v + "\r\n";
    if (!cred.session_token.empty())
        rq.head += "x-amz-security-token: " + cred.session_token + "\r\n";
    rq.head += "authorization: " + socketley::s3::sign(in) + "\r\nuser-agent: socketley-metrics\r\n\r\n";
    rq.answer_secs = 60;
    if (!m_peer->target().tls)
    {
        // Without TLS the bytes go from the file to the socket by splice and never pass through this process.
        rq.file_fd = *file;
        rq.file_off = 0;
        rq.file_len = len;
    }
    else
    {
        auto at = std::make_shared<uint64_t>(0);
        rq.source = [file, at, len](socketley::http_body_give give) {
            if (*at >= len)
                return give(true, {});
            static thread_local std::string piece;
            piece.resize(std::min<uint64_t>(len - *at, body_piece));
            const ssize_t n = ::pread(*file, piece.data(), piece.size(), static_cast<off_t>(*at));
            if (n <= 0)
                return give(false, {});
            *at += static_cast<uint64_t>(n);
            give(true, std::string_view(piece.data(), static_cast<size_t>(n)));
        };
    }
    m_running = true;
    std::weak_ptr<bool> alive = m_alive;
    m_peer->exchange(std::move(rq), [this, alive, file, name, len](socketley::http_answer a) {
        const auto held = alive.lock();
        if (!held || !*held)
            return;
        m_running = false;
        if (a.failure.empty() && a.status >= 200 && a.status < 300)
        {
            m_done.insert(name);
            save();
            ++m_f.blocks;
            m_f.bytes += len;
            m_said = false;
            // The next one at once, so a backlog is copied one block after the other.
            m_next = 0;
            return;
        }
        ++m_f.failures;
        if (!m_said)
            LOG_WARN(("metrics " + m_owner + ": the archive did not take " + name + ": " +
                      (a.failure.empty() ? "HTTP " + std::to_string(a.status) : a.failure) + "; tried again each minute")
                         .c_str());
        m_said = true;
    });
}

}   // namespace socketley::metrics
