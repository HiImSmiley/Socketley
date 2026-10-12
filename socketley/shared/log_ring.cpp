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

// What the reader thread touches, made once and never destroyed.
//
// The thread is detached and runs as long as the process does, so it is still in its walk over the sources when the
// static destructors run -- and a vector destroyed under it is storage it then reads.  Measured: AddressSanitizer's
// heap-use-after-free at that walk, one run in four of test_storage_slow_start, at the daemon's exit.  Kept reachable
// by the pointer, so nothing reads it as a leak.
struct state
{
    std::mutex ring_mtx;
    std::deque<entry> ring;
    uint64_t seq{0};
    // The pipes, and the one thread that reads them; io_mtx is held while lines are taken from them, by the thread
    // and by drain().
    std::mutex io_mtx;
    std::vector<source> sources;
    // Pipes handed over by worker_pipe(), under a lock of their own: a spawn waits for nothing a slow stderr holds up.
    std::mutex new_mtx;
    std::vector<source> fresh;
};

state& st()
{
    static state* s = new state;
    return *s;
}

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
    std::lock_guard lock(st().ring_mtx);
    entry e;
    e.seq = ++st().seq;
    e.at_ms = now_ms();
    e.runtime.assign(runtime);
    e.level = level_of(line);
    e.text.assign(line.substr(0, 4096));
    st().ring.push_back(std::move(e));
    while (st().ring.size() > capacity)
        st().ring.pop_front();
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
        // Walked by offset with one erase at the end, since an erase per line made a read of many lines quadratic.
        size_t from = 0;
        for (size_t nl; (nl = s.partial.find('\n', from)) != std::string::npos; from = nl + 1)
            if (nl > from)
                keep(s.runtime, std::string_view(s.partial).substr(from, nl - from));
        s.partial.erase(0, from);
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
            std::lock_guard lock(st().io_mtx);
            {
                std::lock_guard taken(st().new_mtx);
                for (source& s : st().fresh)
                    st().sources.push_back(std::move(s));
                st().fresh.clear();
            }
            fds.clear();
            fds.push_back({g_wake, POLLIN, 0});
            for (const source& s : st().sources)
                fds.push_back({s.fd, POLLIN, 0});
        }
        if (::poll(fds.data(), fds.size(), -1) < 0)
            continue;
        if (fds[0].revents)
        {
            uint64_t v;
            if (::read(g_wake, &v, sizeof v) < 0) {}
        }
        std::lock_guard lock(st().io_mtx);
        for (size_t i = 1; i < fds.size(); ++i)
        {
            if (!fds[i].revents)
                continue;
            for (auto it = st().sources.begin(); it != st().sources.end(); ++it)
                if (it->fd == fds[i].fd)
                {
                    if (!take(*it))
                    {
                        ::close(it->fd);
                        st().sources.erase(it);
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
    std::lock_guard lock(st().io_mtx);
    for (source& s : st().sources)
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
        std::lock_guard lock(st().new_mtx);
        source s;
        s.fd = p[0];
        s.runtime.assign(runtime);
        st().fresh.push_back(std::move(s));
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
    const auto wanted = [&](const entry& e)
    {
        return rank(e.level) >= floor &&
               (runtime.empty() || e.runtime == runtime || e.text.find(quoted) != std::string::npos);
    };
    std::vector<entry> out;
    std::lock_guard lock(st().ring_mtx);
    next = st().seq;
    // A first look is the newest lines; a cursor goes on from where it was, oldest first, and its next names the last
    // line given, so lines past `max` come with the following ask and none is skipped.
    if (seq == 0)
    {
        for (auto it = st().ring.rbegin(); it != st().ring.rend() && out.size() < max; ++it)
            if (wanted(*it))
                out.push_back(*it);
        std::reverse(out.begin(), out.end());
        return out;
    }
    auto it = std::find_if(st().ring.begin(), st().ring.end(), [seq](const entry& e) { return e.seq > seq; });
    for (; it != st().ring.end(); ++it)
    {
        if (!wanted(*it))
            continue;
        if (out.size() == max)
        {
            next = out.back().seq;
            break;
        }
        out.push_back(*it);
    }
    return out;
}

}   // namespace log_ring
