#pragma once
// What N shards publish so any one can answer for all without a round trip;
// one aligned slot each, so it carries only counters a reader SUMS.
// memfd, not a file: survives exec, has no path, dies with the last child.
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "runtime_definitions.h"   // max_shards

namespace shard_stats
{

// A fallback lock would live in each process's own address space, so this must
// be lock-free or the guarantee is nothing.  Fails the build, not the run.
static_assert(std::atomic<uint64_t>::is_always_lock_free,
              "shard_stats needs lock-free 64-bit atomics to cross a process boundary");

// The name memfd_create() is given, and the reason it is a constant rather than
// a literal at the call: it is also how a reader decides whether a descriptor
// it was handed is one of these.  See looks_like_region().
inline constexpr const char* region_name = "socketley-shards";

inline constexpr size_t   line_size      = 64;
inline constexpr uint32_t magic_value    = 0x534b4c53u;   // 'SKLS'
inline constexpr uint32_t format_version = 2u;

// One shard's line, written by it alone.  `generation` is not a seqlock -- it
// counts attachments, which is how a reader tells an unused slot from one whose
// legitimate count is zero.
struct alignas(line_size) slot
{
    std::atomic<uint64_t> generation;
    std::atomic<uint64_t> active_connections;
    std::atomic<uint64_t> total_connections;
    std::atomic<uint64_t> total_messages;
    std::atomic<uint64_t> bytes_in;
    std::atomic<uint64_t> bytes_out;
    std::atomic<uint64_t> reserved[2];
};
static_assert(sizeof(slot) == line_size);

// One struct so the writer cannot publish four of five; every field must be a
// number a reader only ADDS.  Not a snapshot -- that is what wait-free costs.
struct figures
{
    uint64_t active_connections{0};
    uint64_t total_connections{0};
    uint64_t total_messages{0};
    uint64_t bytes_in{0};
    uint64_t bytes_out{0};

    bool operator==(const figures&) const = default;
};

struct alignas(line_size) header
{
    std::atomic<uint32_t> magic;
    std::atomic<uint32_t> version;
    std::atomic<uint32_t> shard_count;
    std::atomic<uint32_t> reserved[13];
};
static_assert(sizeof(header) == line_size);

// Always max_shards slots, so the size is a constant and nothing has to be
// negotiated across the exec; a region of the wrong length is refused.
struct table
{
    header h;
    slot   slots[max_shards];
};
static_assert(sizeof(table) == line_size * (max_shards + 1));

// "is fd 4 open" is the wrong test, because adopt() takes ownership and a guess
// CLOSES somebody else's descriptor; memfd's name in /proc/self/fd is the test.
inline bool looks_like_region(int fd)
{
    if (fd < 0)
        return false;

    struct stat st{};
    if (::fstat(fd, &st) < 0 || st.st_size != static_cast<off_t>(sizeof(table)))
        return false;

    char path[64];
    const int n = ::snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    if (n <= 0 || static_cast<size_t>(n) >= sizeof(path))
        return false;

    char link[256];
    const ssize_t len = ::readlink(path, link, sizeof(link) - 1);
    if (len <= 0)
        return false;
    link[len] = '\0';

    // "/memfd:<name> (deleted)".  Prefix-matched: the suffix is the kernel's
    // and has changed shape between versions, and the name is what identifies
    // it.
    static const std::string want = std::string("/memfd:") + region_name;
    return std::string_view(link, static_cast<size_t>(len)).substr(0, want.size()) == want;
}

// Both halves of one region: create() is the daemon's, adopt() the worker's,
// publish_active() only the process that adopted a slot, sum_active() anyone.
class shard_table
{
public:
    shard_table() = default;
    ~shard_table() { close(); }

    shard_table(const shard_table&)            = delete;
    shard_table& operator=(const shard_table&) = delete;

    // A fresh zeroed region, with the descriptor kept so every shard forked
    // afterwards -- including a replacement -- is handed the same one.
    bool create(uint32_t shard_count)
    {
        close();
        if (shard_count == 0 || shard_count > max_shards)
            return false;

        // MFD_CLOEXEC so it reaches only children dup2'd it deliberately.
        const int fd = static_cast<int>(::syscall(SYS_memfd_create,
                                                  region_name, MFD_CLOEXEC));
        if (fd < 0)
            return false;

        if (::ftruncate(fd, static_cast<off_t>(sizeof(table))) < 0)
        {
            ::close(fd);
            return false;
        }

        void* p = ::mmap(nullptr, sizeof(table), PROT_READ | PROT_WRITE,
                         MAP_SHARED, fd, 0);
        if (p == MAP_FAILED)
        {
            ::close(fd);
            return false;
        }

        m_fd    = fd;
        m_table = static_cast<table*>(p);
        m_index = invalid_index;
        m_count = shard_count;

        // ftruncate gives zeroed pages, so the counters are already zero.  The
        // header is written last and the magic last of all, so a reader that
        // sees the magic sees a complete header.
        m_table->h.version.store(format_version, std::memory_order_relaxed);
        m_table->h.shard_count.store(shard_count, std::memory_order_relaxed);
        m_table->h.magic.store(magic_value, std::memory_order_release);
        return true;
    }

    // Slots above the new count are cleared, or a shrink leaves stale lines
    // still being summed.
    void set_shard_count(uint32_t shard_count)
    {
        if (!m_table || shard_count == 0 || shard_count > max_shards)
            return;
        for (uint32_t i = shard_count; i < m_count; ++i)
            clear_slot(i);
        m_count = shard_count;
        m_table->h.shard_count.store(shard_count, std::memory_order_release);
    }

    // The daemon clears it, not the departing shard: the case that matters is
    // the shard that did nothing on its way out.
    void clear_slot(uint32_t i)
    {
        if (!m_table || i >= max_shards)
            return;
        m_table->slots[i].active_connections.store(0, std::memory_order_relaxed);
        m_table->slots[i].total_connections.store(0, std::memory_order_relaxed);
        m_table->slots[i].total_messages.store(0, std::memory_order_relaxed);
        m_table->slots[i].bytes_in.store(0, std::memory_order_relaxed);
        m_table->slots[i].bytes_out.store(0, std::memory_order_relaxed);
        m_table->slots[i].generation.store(0, std::memory_order_release);
    }

    int fd() const { return m_fd; }

    // Map the region and take slot `index`.  Takes the descriptor either way,
    // or a refused config leaks one.
    bool adopt(int fd, uint32_t index)
    {
        close();
        if (fd < 0)
            return false;

        struct stat st{};
        if (::fstat(fd, &st) < 0 || st.st_size != static_cast<off_t>(sizeof(table)))
        {
            ::close(fd);
            return false;
        }

        void* p = ::mmap(nullptr, sizeof(table), PROT_READ | PROT_WRITE,
                         MAP_SHARED, fd, 0);
        if (p == MAP_FAILED)
        {
            ::close(fd);
            return false;
        }

        auto* t = static_cast<table*>(p);
        if (t->h.magic.load(std::memory_order_acquire) != magic_value
            || t->h.version.load(std::memory_order_relaxed) != format_version)
        {
            ::munmap(p, sizeof(table));
            ::close(fd);
            return false;
        }

        const uint32_t count = t->h.shard_count.load(std::memory_order_acquire);
        if (index >= count || count > max_shards)
        {
            ::munmap(p, sizeof(table));
            ::close(fd);
            return false;
        }

        m_fd    = fd;
        m_table = t;
        m_index = index;
        m_count = count;

        // Whatever the previous occupant of this slot last said is not about
        // this process.  Cleared before the generation is bumped, so a reader
        // never sees a live generation over a dead count.
        m_table->slots[index].active_connections.store(0, std::memory_order_relaxed);
        m_table->slots[index].total_connections.store(0, std::memory_order_relaxed);
        m_table->slots[index].total_messages.store(0, std::memory_order_relaxed);
        m_table->slots[index].bytes_in.store(0, std::memory_order_relaxed);
        m_table->slots[index].bytes_out.store(0, std::memory_order_relaxed);
        m_table->slots[index].generation.fetch_add(1, std::memory_order_release);
        return true;
    }

    // Read-only attach for the placeholder, which is what `stats` and every Lua
    // binding ask.  Not adopt(): that claims a slot, and the daemon is no
    // shard.  The descriptor is DUPLICATED, or two objects close one number.
    bool attach_reader(int fd)
    {
        close();
        if (fd < 0)
            return false;

        const int dup_fd = ::fcntl(fd, F_DUPFD_CLOEXEC, 0);
        if (dup_fd < 0)
            return false;

        struct stat st{};
        if (::fstat(dup_fd, &st) < 0 || st.st_size != static_cast<off_t>(sizeof(table)))
        {
            ::close(dup_fd);
            return false;
        }

        void* p = ::mmap(nullptr, sizeof(table), PROT_READ | PROT_WRITE,
                         MAP_SHARED, dup_fd, 0);
        if (p == MAP_FAILED)
        {
            ::close(dup_fd);
            return false;
        }

        auto* t = static_cast<table*>(p);
        if (t->h.magic.load(std::memory_order_acquire) != magic_value
            || t->h.version.load(std::memory_order_relaxed) != format_version)
        {
            ::munmap(p, sizeof(table));
            ::close(dup_fd);
            return false;
        }

        m_fd    = dup_fd;
        m_table = t;
        m_index = invalid_index;          // reader: no slot, never writable
        m_count = t->h.shard_count.load(std::memory_order_acquire);
        return true;
    }

    // ── both ────────────────────────────────────────────────────────────────

    bool     mapped()  const { return m_table != nullptr; }
    bool     writable() const { return m_table != nullptr && m_index < max_shards; }
    uint32_t index()   const { return m_index; }
    uint32_t count()   const { return m_table ? m_count : 0; }

    // This shard's own figure.  One store, no barrier heavier than a release,
    // and no call at all for a runtime that is not sharded.
    void publish_active(uint64_t n)
    {
        if (!writable())
            return;
        m_table->slots[m_index].active_connections.store(n, std::memory_order_release);
    }

    // One function rather than five setters, so a field added to `figures` is
    // published by every existing call site without one being edited.
    void publish(const figures& f)
    {
        if (!writable())
            return;
        slot& s = m_table->slots[m_index];
        s.total_connections.store(f.total_connections, std::memory_order_relaxed);
        s.total_messages.store(f.total_messages,       std::memory_order_relaxed);
        s.bytes_in.store(f.bytes_in,                   std::memory_order_relaxed);
        s.bytes_out.store(f.bytes_out,                 std::memory_order_relaxed);
        // Last, and the only release of the five: active_connections is what
        // every freshness assertion in the tree reads, so a reader that sees a
        // new count also sees the counters that were taken with it.
        s.active_connections.store(f.active_connections, std::memory_order_release);
    }

    // Wait-free: a descheduled or dead shard delays this by nothing, and a
    // retired one holds zero because the daemon cleared it.
    uint64_t sum_active() const
    {
        if (!m_table)
            return 0;
        uint64_t total = 0;
        const uint32_t n = m_count;
        for (uint32_t i = 0; i < n; ++i)
            total += m_table->slots[i].active_connections.load(std::memory_order_acquire);
        return total;
    }

    // Every shard's whole line, added up.  Same wait-free property and the same
    // reason it is one call: a reader that summed four of the five fields would
    // print a runtime whose bytes_out did not match its own bytes_in.
    figures sum() const
    {
        figures f;
        if (!m_table)
            return f;
        const uint32_t n = m_count;
        for (uint32_t i = 0; i < n; ++i)
        {
            const slot& s = m_table->slots[i];
            f.active_connections += s.active_connections.load(std::memory_order_acquire);
            f.total_connections  += s.total_connections.load(std::memory_order_relaxed);
            f.total_messages     += s.total_messages.load(std::memory_order_relaxed);
            f.bytes_in           += s.bytes_in.load(std::memory_order_relaxed);
            f.bytes_out          += s.bytes_out.load(std::memory_order_relaxed);
        }
        return f;
    }

    // Separates "every shard reports zero" from "no shard has reported yet",
    // which the daemon needs before printing figures out of shared memory.
    bool any_live() const
    {
        if (!m_table)
            return false;
        for (uint32_t i = 0; i < m_count; ++i)
            if (m_table->slots[i].generation.load(std::memory_order_acquire) != 0)
                return true;
        return false;
    }

    // One named shard's whole line.  `stats` prints these under a [shard i]
    // heading so that an operator can see how the work is spread, which is a
    // question the sum deliberately cannot answer.
    figures at(uint32_t i) const
    {
        figures f;
        if (!m_table || i >= m_count)
            return f;
        const slot& s = m_table->slots[i];
        f.active_connections = s.active_connections.load(std::memory_order_acquire);
        f.total_connections  = s.total_connections.load(std::memory_order_relaxed);
        f.total_messages     = s.total_messages.load(std::memory_order_relaxed);
        f.bytes_in           = s.bytes_in.load(std::memory_order_relaxed);
        f.bytes_out          = s.bytes_out.load(std::memory_order_relaxed);
        return f;
    }

    // What one named shard last said.  For diagnostics and for the tests; the
    // sum above is what production reads.
    uint64_t active_at(uint32_t i) const
    {
        if (!m_table || i >= m_count)
            return 0;
        return m_table->slots[i].active_connections.load(std::memory_order_acquire);
    }

    void close()
    {
        if (m_table)
        {
            ::munmap(m_table, sizeof(table));
            m_table = nullptr;
        }
        if (m_fd >= 0)
        {
            ::close(m_fd);
            m_fd = -1;
        }
        m_index = invalid_index;
        m_count = 0;
    }

private:
    static constexpr uint32_t invalid_index = 0xFFFFFFFFu;

    int      m_fd{-1};
    table*   m_table{nullptr};
    uint32_t m_index{invalid_index};
    uint32_t m_count{0};
};

}   // namespace shard_stats

// `self.clients()` is deliberately not here: ids are descriptors, so summing is
// meaningless and concatenating hands one shard's id to another.  It needs
// conn_refs, which makes it a consumer of routing rather than of this.
