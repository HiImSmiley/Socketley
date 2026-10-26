#include "mail_greylist.h"

#include <algorithm>
#include <cstdio>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../shared/crypto/mac.h"
#include "../../shared/loop/blocking_write.h"
#include "../../shared/util/ascii.h"

namespace socketley::mail
{

namespace
{

std::string hash_of(std::string_view network, std::string_view sender, std::string_view recipient)
{
    std::string what = std::string(network) + '\n' + std::string(sender) + '\n' + std::string(recipient);
    socketley::ascii::lower_in_place(what);
    const std::string h = socketley::crypto::hmac_sha256("socketley greylist", what);
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < 16 && i < h.size(); ++i)
    {
        const auto b = static_cast<unsigned char>(h[i]);
        out += hex[b >> 4];
        out += hex[b & 15];
    }
    return out;
}

// The file locked against every other shard for as long as this lives.
class file_lock
{
public:
    explicit file_lock(const std::string& path)
    {
        m_fd = ::open((path + ".lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (m_fd >= 0 && ::flock(m_fd, LOCK_EX) != 0)
        {
            ::close(m_fd);
            m_fd = -1;
        }
    }
    ~file_lock()
    {
        if (m_fd >= 0)
            ::close(m_fd);
    }
    file_lock(const file_lock&)            = delete;
    file_lock& operator=(const file_lock&) = delete;
    bool held() const { return m_fd >= 0; }

private:
    int m_fd{-1};
};

}   // namespace

std::string greylist::network_of(std::string_view ip)
{
    unsigned char a[16];
    const std::string s(ip);
    if (::inet_pton(AF_INET, s.c_str(), a) == 1)
        return std::to_string(a[0]) + "." + std::to_string(a[1]) + "." + std::to_string(a[2]) + ".0/24";
    if (::inet_pton(AF_INET6, s.c_str(), a) == 1)
    {
        std::fill(a + 8, a + 16, 0);
        char buf[INET6_ADDRSTRLEN];
        return std::string(::inet_ntop(AF_INET6, a, buf, sizeof buf)) + "/64";
    }
    return s;
}

bool greylist::read_tail()
{
    const int fd = ::open(m_path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
    {
        if (errno != ENOENT)
            return false;
        m_entries.clear();
        m_ino = m_read = m_lines = 0;
        return true;
    }
    struct stat st{};
    if (::fstat(fd, &st) != 0)
    {
        ::close(fd);
        return false;
    }
    // A file folded by another shard is another inode, read from its start; otherwise only what came since.
    if (static_cast<uint64_t>(st.st_ino) != m_ino || static_cast<uint64_t>(st.st_size) < m_read)
    {
        m_entries.clear();
        m_ino = static_cast<uint64_t>(st.st_ino);
        m_read = m_lines = 0;
    }
    std::string tail(static_cast<size_t>(static_cast<uint64_t>(st.st_size) - m_read), '\0');
    const ssize_t n = tail.empty() ? 0 : ::pread(fd, tail.data(), tail.size(), static_cast<off_t>(m_read));
    ::close(fd);
    if (n < 0)
        return false;
    tail.resize(static_cast<size_t>(n));
    const size_t whole = tail.rfind('\n');
    if (whole == std::string::npos)
        return true;
    m_read += whole + 1;
    std::string_view rest(tail.data(), whole + 1);
    while (!rest.empty())
    {
        const size_t nl = rest.find('\n');
        const std::string line(rest.substr(0, nl));
        rest.remove_prefix(nl + 1);
        ++m_lines;
        long long first = 0, passed = 0;
        char h[33] = {};
        if (std::sscanf(line.c_str(), "%lld %lld %32s", &first, &passed, h) != 3)
            continue;
        entry& e = m_entries[h];
        e.first_ms = std::max<int64_t>(e.first_ms, first);
        e.passed_ms = std::max<int64_t>(e.passed_ms, passed);
    }
    return true;
}

bool greylist::append(const std::string& hash, const entry& e)
{
    const std::string line = std::to_string(e.first_ms) + " " + std::to_string(e.passed_ms) + " " + hash + "\n";
    const int fd = ::open(m_path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    const bool ok = fd >= 0 && socketley::write_all(fd, line.data(), line.size());
    if (fd >= 0)
        ::close(fd);
    return ok;
}

void greylist::fold(int64_t now_ms)
{
    // What is past its time goes, and past the bound the oldest; the file is rewritten whole once it holds twice
    // what is live.
    std::erase_if(m_entries, [&](const auto& kv) {
        const entry& e = kv.second;
        return e.passed_ms ? now_ms - e.passed_ms > pass_ms : now_ms - e.first_ms > retry_window_ms;
    });
    if (m_lines <= 2 * m_entries.size() + 1000 && m_entries.size() <= max_entries)
        return;
    std::vector<std::pair<int64_t, std::string>> live;
    for (const auto& [h, e] : m_entries)
        live.emplace_back(std::max(e.first_ms, e.passed_ms), h);
    std::sort(live.begin(), live.end(), std::greater<>());
    if (live.size() > max_entries)
        live.resize(max_entries);
    std::string text;
    for (const auto& [t, h] : live)
    {
        const entry& e = m_entries[h];
        text += std::to_string(e.first_ms) + " " + std::to_string(e.passed_ms) + " " + h + "\n";
    }
    const std::string tmp = m_path + ".tmp." + std::to_string(::getpid());
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    const bool ok = fd >= 0 && socketley::write_all(fd, text.data(), text.size());
    if (fd >= 0)
        ::close(fd);
    if (!ok || ::rename(tmp.c_str(), m_path.c_str()) != 0)
        ::unlink(tmp.c_str());
    // Read again from the new file at the next check.
    m_ino = m_read = m_lines = 0;
    m_entries.clear();
}

int64_t greylist::check(std::string_view network, std::string_view sender, std::string_view recipient, int64_t now_ms)
{
    const std::string h = hash_of(network, sender, recipient);
    const file_lock lock(m_path);
    std::lock_guard<std::mutex> g(m_mu);
    if (!lock.held() || !read_tail())
        return 0;
    entry& e = m_entries[h];
    int64_t wait = 0;
    if (e.passed_ms && now_ms - e.passed_ms <= pass_ms)
        return 0;
    if (e.first_ms && now_ms - e.first_ms >= m_delay_ms && now_ms - e.first_ms <= retry_window_ms)
    {
        // It came back in time: it passes, and is let by from now on.
        e.passed_ms = now_ms;
        if (!append(h, e))
            return 0;
    }
    else
    {
        if (!e.first_ms || now_ms - e.first_ms > retry_window_ms)
        {
            e = {now_ms, 0};
            if (!append(h, e))
                return 0;
        }
        wait = std::max<int64_t>(1, (e.first_ms + m_delay_ms - now_ms + 999) / 1000);
    }
    fold(now_ms);
    return wait;
}

}   // namespace socketley::mail
