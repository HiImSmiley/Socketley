#include "log_ring.h"

#include <fcntl.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <deque>
#include <mutex>
#include <thread>

#include "logging.h"

namespace log_ring
{

namespace
{

struct source
{
    int fd{-1};
    std::string runtime, partial;
};

std::mutex g_ring_mtx;
std::deque<entry> g_ring;
uint64_t g_seq{0};

// The pipes, and the one thread that reads them; g_io_mtx is held while lines are taken from them, by the thread
// and by drain().
std::mutex g_io_mtx;
std::vector<source> g_sources;
std::vector<source> g_new;
int g_wake{-1};
bool g_started{false};

std::string level_of(std::string_view line)
{
    const std::string_view head = line.substr(0, 32);
    if (head.find("[ERROR]") != std::string_view::npos)
        return "error";
    if (head.find("[WARN]") != std::string_view::npos)
        return "warn";
    if (head.find("[DEBUG]") != std::string_view::npos)
        return "debug";
    return "info";
}

int64_t now_ms()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

void keep(std::string_view runtime, std::string_view line)
{
    std::lock_guard lock(g_ring_mtx);
    entry e;
    e.seq = ++g_seq;
    e.at_ms = now_ms();
    e.runtime.assign(runtime);
    e.level = level_of(line);
    e.text.assign(line.substr(0, 4096));
    g_ring.push_back(std::move(e));
    while (g_ring.size() > capacity)
        g_ring.pop_front();
}

// What is in `s`'s pipe now, passed on to the daemon's stderr and kept line by line; false at its end.
bool take(source& s)
{
    char buf[65536];
    for (;;)
    {
        const ssize_t n = ::read(s.fd, buf, sizeof buf);
        if (n == 0 || (n < 0 && errno != EAGAIN && errno != EINTR))
        {
            if (!s.partial.empty())
            {
                keep(s.runtime, s.partial);
                s.partial += '\n';
                if (::write(STDERR_FILENO, s.partial.data(), s.partial.size()) < 0) {}
            }
            return false;
        }
        if (n < 0)
            return true;
        // Passed on as it came, so the journal sees what it always saw.
        if (::write(STDERR_FILENO, buf, static_cast<size_t>(n)) < 0) {}
        s.partial.append(buf, static_cast<size_t>(n));
        for (size_t nl; (nl = s.partial.find('\n')) != std::string::npos;)
        {
            if (nl > 0)
                keep(s.runtime, std::string_view(s.partial).substr(0, nl));
            s.partial.erase(0, nl + 1);
        }
        // A line that never ends is kept in pieces rather than held for ever.
        if (s.partial.size() > 16384)
        {
            keep(s.runtime, s.partial);
            s.partial.clear();
        }
    }
}

void reader()
{
    std::vector<pollfd> fds;
    for (;;)
    {
        {
            std::lock_guard lock(g_io_mtx);
            for (source& s : g_new)
                g_sources.push_back(std::move(s));
            g_new.clear();
            fds.clear();
            fds.push_back({g_wake, POLLIN, 0});
            for (const source& s : g_sources)
                fds.push_back({s.fd, POLLIN, 0});
        }
        if (::poll(fds.data(), fds.size(), -1) < 0)
            continue;
        if (fds[0].revents)
        {
            uint64_t v;
            if (::read(g_wake, &v, sizeof v) < 0) {}
        }
        std::lock_guard lock(g_io_mtx);
        for (size_t i = 1; i < fds.size(); ++i)
        {
            if (!fds[i].revents)
                continue;
            for (auto it = g_sources.begin(); it != g_sources.end(); ++it)
                if (it->fd == fds[i].fd)
                {
                    if (!take(*it))
                    {
                        ::close(it->fd);
                        g_sources.erase(it);
                    }
                    break;
                }
        }
    }
}

void tap(const char* line, size_t n)
{
    std::string_view l(line, n);
    while (!l.empty() && l.back() == '\n')
        l.remove_suffix(1);
    keep({}, l);
}

}   // namespace

void start()
{
    if (g_started)
        return;
    g_wake = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (g_wake < 0)
        return;
    g_started = true;
    logger::g_tap = tap;
    std::thread(reader).detach();
}

void drain()
{
    if (!g_started)
        return;
    std::lock_guard lock(g_io_mtx);
    for (source& s : g_sources)
        take(s);
}

int worker_pipe(std::string_view runtime)
{
    if (!g_started)
        return -1;
    int p[2];
    if (::pipe2(p, O_CLOEXEC) != 0)
        return -1;
    // Room for a burst, so a worker that logs a lot is not held up by one slow pass of the reader.
    if (::fcntl(p[0], F_SETPIPE_SZ, 1 << 18) < 0) {}
    const int fl = ::fcntl(p[0], F_GETFL);
    if (fl < 0 || ::fcntl(p[0], F_SETFL, fl | O_NONBLOCK) < 0)
    {
        ::close(p[0]);
        ::close(p[1]);
        return -1;
    }
    {
        std::lock_guard lock(g_io_mtx);
        source s;
        s.fd = p[0];
        s.runtime.assign(runtime);
        g_new.push_back(std::move(s));
    }
    const uint64_t one = 1;
    if (::write(g_wake, &one, sizeof one) < 0) {}
    return p[1];
}

void add_own(std::string_view line)
{
    keep({}, line);
}

std::vector<entry> since(uint64_t seq, size_t max, std::string_view runtime, std::string_view level, uint64_t& next)
{
    const auto rank = [](std::string_view l) { return l == "error" ? 3 : l == "warn" ? 2 : l == "info" ? 1 : 0; };
    const int floor = level.empty() ? 0 : rank(level);
    const std::string quoted = "'" + std::string(runtime) + "'";
    std::vector<entry> out;
    std::lock_guard lock(g_ring_mtx);
    next = g_seq;
    for (auto it = g_ring.rbegin(); it != g_ring.rend() && it->seq > seq && out.size() < max; ++it)
    {
        if (rank(it->level) < floor)
            continue;
        if (!runtime.empty() && it->runtime != runtime && it->text.find(quoted) == std::string::npos)
            continue;
        out.push_back(*it);
    }
    std::reverse(out.begin(), out.end());
    return out;
}

}   // namespace log_ring
