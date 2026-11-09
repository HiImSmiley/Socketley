#pragma once
// A worker's running Lua callback as the daemon sees it: one cache line in a memfd the worker writes with plain stores
// and the daemon reads on its loop, so a callback past its budget is found without the worker reading a clock or
// arming a timer for it.
#include <algorithm>
#include <atomic>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <ctime>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace deadline_slot
{

// The name memfd_create() is given, which is also how a worker tells this descriptor from one it was not handed.
inline constexpr const char* region_name = "socketley-deadline";

// A page, because a mapping is one whatever the file says and a shorter file faults on the rest of it.
inline constexpr size_t region_size = 4096;

// What tells a Lua thread its callback is past its budget: unused anywhere else in the tree, and ignored by default,
// so a process that never installed the handler loses nothing to a stray one.
inline constexpr int stop_signal = SIGURG;

// How often the daemon reads every worker's line, which is also the granularity of the deadline.
inline constexpr uint32_t scan_ms = 100;

// What a stopped callback gets to reach its next VM instruction before its worker is replaced: a second at least,
// because the hook is seen only once the callback leaves whatever C function it is in, and a quarter of the budget
// beyond that, because what a C function may legitimately be doing grows with the budget it was given.
inline uint32_t grace_ms(uint32_t limit_ms)
{
    return std::max<uint32_t>(1000, limit_ms / 4);
}

inline constexpr size_t what_words = 5;

struct alignas(64) slot
{
    // Odd while a callback with a limit runs, so one store says both which invocation it is and that it is running.
    std::atomic<uint64_t> seq;
    // CLOCK_MONOTONIC nanoseconds at the start of the loop turn the invocation runs in.
    std::atomic<uint64_t> start_ns;
    std::atomic<uint32_t> limit_ms;
    std::atomic<uint32_t> reserved;
    // The callback's name, written by the worker only once it is told to stop, for the line the daemon logs.
    std::atomic<uint64_t> what[what_words];
};
static_assert(sizeof(slot) == 64);
static_assert(std::atomic<uint64_t>::is_always_lock_free,
              "deadline_slot needs lock-free 64-bit atomics to cross a process boundary");

// ── The writer, a worker's Lua thread and nobody else ──────────────────────
// No read-modify-write anywhere, because a locked instruction per callback is the cost this layout exists to avoid;
// the caller keeps the sequence and hands each value in.
inline void enter(slot& s, uint64_t seq_odd, uint64_t start_ns, uint32_t limit_ms) noexcept
{
    // Orders the two stores below after the previous leave(), which a release on the store alone does not.
    std::atomic_thread_fence(std::memory_order_release);
    s.start_ns.store(start_ns, std::memory_order_relaxed);
    if (s.limit_ms.load(std::memory_order_relaxed) != limit_ms)
        s.limit_ms.store(limit_ms, std::memory_order_relaxed);
    s.seq.store(seq_odd, std::memory_order_release);
}

inline void leave(slot& s, uint64_t seq_even) noexcept
{
    s.seq.store(seq_even, std::memory_order_release);
}

// Async-signal-safe, since the stop signal's handler is where a worker names its callback.
inline void name(slot& s, const char* what) noexcept
{
    char buf[what_words * sizeof(uint64_t)] = {};
    if (what)
        for (size_t i = 0; i + 1 < sizeof(buf) && what[i]; ++i)
            buf[i] = what[i];
    for (size_t k = 0; k < what_words; ++k)
    {
        uint64_t w;
        std::memcpy(&w, buf + k * sizeof(w), sizeof(w));
        s.what[k].store(w, std::memory_order_relaxed);
    }
}

// ── The reader ──────────────────────────────────────────────────────────────
struct reading
{
    uint64_t seq{0};
    uint64_t start_ns{0};
    uint32_t limit_ms{0};
};

// One look at a line, false when the worker moved on in the middle of it.
inline bool read(const slot& s, reading& r) noexcept
{
    r.seq      = s.seq.load(std::memory_order_acquire);
    r.start_ns = s.start_ns.load(std::memory_order_relaxed);
    r.limit_ms = s.limit_ms.load(std::memory_order_relaxed);
    std::atomic_thread_fence(std::memory_order_acquire);
    return s.seq.load(std::memory_order_relaxed) == r.seq;
}

inline std::string named(const slot& s)
{
    char buf[what_words * sizeof(uint64_t) + 1] = {};
    for (size_t k = 0; k < what_words; ++k)
    {
        const uint64_t w = s.what[k].load(std::memory_order_relaxed);
        std::memcpy(buf + k * sizeof(w), &w, sizeof(w));
    }
    return buf[0] ? std::string(buf) : std::string("a callback");
}

// What a reader remembers about one line between two looks.
struct watch
{
    uint64_t seq{0};
    // The look before this invocation was first seen, which it cannot have started before -- so a turn stamp that is
    // older than it is not taken at its word.
    uint64_t floor_ns{0};
    uint64_t last_ns{0};
    // When this invocation was first told to stop, 0 before then.
    uint64_t stopped_ns{0};
};

enum class verdict { none, stop, replace };

// The decision the daemon takes about one worker on each scan: an invocation seen running on two looks in a row and
// past its limit is told to stop, and one that has been told for its whole grace is replaced.
inline verdict judge(const reading& r, watch& w, uint64_t now_ns) noexcept
{
    const uint64_t previous = w.last_ns;
    w.last_ns = now_ns;

    if ((r.seq & 1) == 0 || r.limit_ms == 0)
    {
        w.seq        = r.seq;
        w.stopped_ns = 0;
        return verdict::none;
    }
    if (r.seq != w.seq)
    {
        w.seq        = r.seq;
        w.floor_ns   = previous;
        w.stopped_ns = 0;
        return verdict::none;
    }

    const uint64_t start = std::max(r.start_ns, w.floor_ns);
    if (now_ns <= start || now_ns - start <= uint64_t{r.limit_ms} * 1000000u)
        return verdict::none;
    if (w.stopped_ns == 0)
    {
        w.stopped_ns = now_ns;
        return verdict::stop;
    }
    if (now_ns - w.stopped_ns >= uint64_t{grace_ms(r.limit_ms)} * 1000000u)
        return verdict::replace;
    return verdict::stop;
}

inline uint64_t monotonic_ns() noexcept
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000u + static_cast<uint64_t>(ts.tv_nsec);
}

// ── The daemon's half: one line per worker, kept across that worker's restarts ──
class region
{
public:
    region() = default;
    ~region() { close(); }
    region(const region&)            = delete;
    region& operator=(const region&) = delete;

    // MFD_CLOEXEC, so it reaches only the child it is placed into on purpose.
    bool create()
    {
        close();
        const int fd = static_cast<int>(::syscall(SYS_memfd_create, region_name, MFD_CLOEXEC));
        if (fd < 0)
            return false;
        if (::ftruncate(fd, static_cast<off_t>(region_size)) < 0)
        {
            ::close(fd);
            return false;
        }
        void* p = ::mmap(nullptr, region_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (p == MAP_FAILED)
        {
            ::close(fd);
            return false;
        }
        m_fd   = fd;
        m_slot = static_cast<slot*>(p);
        return true;
    }

    bool  mapped() const { return m_slot != nullptr; }
    int   fd()     const { return m_fd; }
    slot* get()          { return m_slot; }

    // Zeroed for a new child, so nothing the dead one left running is judged against the next.
    void reset()
    {
        if (!m_slot)
            return;
        m_slot->start_ns.store(0, std::memory_order_relaxed);
        m_slot->limit_ms.store(0, std::memory_order_relaxed);
        name(*m_slot, nullptr);
        m_slot->seq.store(0, std::memory_order_release);
    }

    void close()
    {
        if (m_slot)
            ::munmap(m_slot, region_size);
        if (m_fd >= 0)
            ::close(m_fd);
        m_slot = nullptr;
        m_fd   = -1;
    }

private:
    int   m_fd{-1};
    slot* m_slot{nullptr};
};

// ── The worker's half ───────────────────────────────────────────────────────
// The line behind `fd` when it is one of these, mapped for the life of the process with the descriptor closed, and
// null with `fd` left alone when it is anything else -- the test being memfd's name, because a guess would close a
// descriptor somebody else owns.
inline slot* adopt(int fd)
{
    struct stat st{};
    if (fd < 0 || ::fstat(fd, &st) < 0 || st.st_size != static_cast<off_t>(region_size))
        return nullptr;

    char path[64];
    const int n = std::snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    if (n <= 0 || static_cast<size_t>(n) >= sizeof(path))
        return nullptr;
    char link[256];
    const ssize_t len = ::readlink(path, link, sizeof(link) - 1);
    if (len <= 0)
        return nullptr;
    static const std::string want = std::string("/memfd:") + region_name;
    if (std::string_view(link, static_cast<size_t>(len)).substr(0, want.size()) != want)
        return nullptr;

    void* p = ::mmap(nullptr, region_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    ::close(fd);
    return p == MAP_FAILED ? nullptr : static_cast<slot*>(p);
}

}  // namespace deadline_slot
