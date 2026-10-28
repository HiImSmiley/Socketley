#pragma once
// What N shards publish so any one can answer for all without a round trip,
// one aligned slot each of counters a reader sums, in a memfd that survives
// exec and dies with the last child.
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

#include "../runtime/runtime_definitions.h"   // max_shards
#include "../../cli/command_hashing.h" // fnv1a, for the channel filter

namespace shard_stats
{

// A fallback lock would live in each process's own address space, so this must
// be lock-free or the guarantee is nothing.
static_assert(std::atomic<uint64_t>::is_always_lock_free,
              "shard_stats needs lock-free 64-bit atomics to cross a process boundary");

// The name memfd_create() is given, a constant because it is also how a reader
// decides whether a descriptor it was handed is one of these.
inline constexpr const char* region_name = "socketley-shards";

inline constexpr size_t   line_size      = 64;
inline constexpr uint32_t magic_value    = 0x534b4c53u;   // 'SKLS'
inline constexpr uint32_t format_version = 3u;

// One shard's line, written by it alone, where `generation` counts attachments
// so a reader can tell an unused slot from a legitimate zero.
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

// One shard's channel filter: a bit per hash bucket of the channels it holds
// a subscriber for, set before that subscriber is answered and cleared with
// the bucket's last channel, so a publish crosses only to shards that can
// hold somebody -- a set bit costs at worst the crossing every publish used
// to cost, and a clear bit is never wrong.
inline constexpr uint32_t channel_bits  = 1u << 16;
inline constexpr uint32_t channel_words = channel_bits / 64;
struct alignas(line_size) channel_filter
{
    std::atomic<uint64_t> word[channel_words];
};
static_assert(sizeof(channel_filter) == channel_words * sizeof(uint64_t));

// One bit reserved to mean "this shard has pattern subscribers".  A pattern
// cannot be hashed to a channel's bit -- it matches channels that do not exist
// yet -- so a shard holding one has to be woken by every publish, and this is
// how the publisher finds out without a second table.  A real channel hashing
// here costs one extra wake, which is what a filter collision already costs.
inline constexpr uint32_t pattern_bit = 0;

inline uint32_t channel_bit(std::string_view channel)
{
    return fnv1a(channel) & (channel_bits - 1);
}

// One struct so the writer cannot publish four of five, every field a number a
// reader only adds.
struct figures
{
    uint64_t active_connections{0};
    uint64_t total_connections{0};
    uint64_t total_messages{0};
    uint64_t bytes_in{0};
    uint64_t bytes_out{0};

    bool operator==(const figures&) const = default;
    figures& operator+=(const figures& o)
    {
        active_connections += o.active_connections;
        total_connections  += o.total_connections;
        total_messages     += o.total_messages;
        bytes_in           += o.bytes_in;
        bytes_out          += o.bytes_out;
        return *this;
    }
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
    header         h;
    slot           slots[max_shards];
    channel_filter channels[max_shards];
};
static_assert(sizeof(table) == line_size * (max_shards + 1)
                               + sizeof(channel_filter) * max_shards);

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

    // "/memfd:<name> (deleted)", prefix-matched because the suffix is the
    // kernel's and has changed shape between versions.
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

        // ftruncate gives zeroed pages, and the magic is written last, so a
        // reader that sees the magic sees a complete header.
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
        for (auto& w : m_table->channels[i].word)
            w.store(0, std::memory_order_relaxed);
        m_table->slots[i].generation.store(0, std::memory_order_release);
    }

    int fd() const { return m_fd; }

    // Map the region and take slot `index`, taking the descriptor either way
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

        // Whatever the previous occupant of this slot said is not about this
        // process, and is cleared before the generation is bumped.
        m_table->slots[index].active_connections.store(0, std::memory_order_relaxed);
        m_table->slots[index].total_connections.store(0, std::memory_order_relaxed);
        m_table->slots[index].total_messages.store(0, std::memory_order_relaxed);
        m_table->slots[index].bytes_in.store(0, std::memory_order_relaxed);
        m_table->slots[index].bytes_out.store(0, std::memory_order_relaxed);
        for (auto& w : m_table->channels[index].word)
            w.store(0, std::memory_order_relaxed);
        m_table->slots[index].generation.fetch_add(1, std::memory_order_release);
        return true;
    }

    // Read-only attach for the placeholder, not adopt(), which claims a slot,
    // and the descriptor is duplicated or two objects close one number.
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
        // A count past the slots there are, as adopt() refuses too, would have every sum read beyond them.
        if (t->h.magic.load(std::memory_order_acquire) != magic_value
            || t->h.version.load(std::memory_order_relaxed) != format_version
            || t->h.shard_count.load(std::memory_order_acquire) > max_shards)
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

    // This shard's own figure, one store with no barrier heavier than a
    // release.
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

    // Two numbers of this shard's own for its siblings, which the runtime gives their meaning: a sharded db's
    // writer puts the change its log is on the disk up to, and how often its segments were rearranged.  The second
    // is stored first, so a reader that loads the first and then the second sees a second at least as new as the one
    // published with the first.
    void publish_words(uint64_t first, uint64_t second)
    {
        if (!writable())
            return;
        slot& s = m_table->slots[m_index];
        s.reserved[1].store(second, std::memory_order_release);
        s.reserved[0].store(first, std::memory_order_release);
    }
    uint64_t word_at(uint32_t i, uint32_t k) const
    {
        if (!m_table || i >= m_count || i >= max_shards || k > 1)
            return 0;
        return m_table->slots[i].reserved[k].load(std::memory_order_acquire);
    }

    // This shard's own filter, one bit at a time.
    void channel_set(uint32_t bit)
    {
        if (writable())
            m_table->channels[m_index].word[bit / 64].fetch_or(
                uint64_t{1} << (bit % 64), std::memory_order_release);
    }
    void channel_clear(uint32_t bit)
    {
        if (writable())
            m_table->channels[m_index].word[bit / 64].fetch_and(
                ~(uint64_t{1} << (bit % 64)), std::memory_order_release);
    }

    // Whether shard `i` can hold a subscriber of a channel in this bucket,
    // with a slot nobody has adopted answering yes, because a shard that has
    // not said what it holds is crossed to as every shard used to be.
    bool channel_may_have(uint32_t i, uint32_t bit) const
    {
        if (!m_table || i >= m_count || i >= max_shards)
            return true;
        if (m_table->slots[i].generation.load(std::memory_order_acquire) == 0)
            return true;
        return (m_table->channels[i].word[bit / 64].load(std::memory_order_acquire)
                >> (bit % 64)) & 1u;
    }

    // Wait-free: a descheduled or dead shard delays this by nothing, and a
    // retired one holds zero because the daemon cleared it.
    uint64_t sum_active() const
    {
        // The pointer once, so the check and the loads below are the same
        // value.  What keeps the MAPPING alive across them is the caller's
        // lock -- see close() -- and this only makes the read itself
        // well-defined rather than a null check followed by N loads of a field
        // another thread may have cleared in between.
        const table* t = m_table;
        if (!t)
            return 0;
        uint64_t total = 0;
        const uint32_t n = m_count;
        for (uint32_t i = 0; i < n; ++i)
            total += t->slots[i].active_connections.load(std::memory_order_acquire);
        return total;
    }

    // Every shard's whole line added up in one call, so no reader prints a
    // runtime whose bytes_out did not match its own bytes_in.
    figures sum() const
    {
        figures f;
        // Once, for sum_active()'s reason.
        const table* t = m_table;
        if (!t)
            return f;
        const uint32_t n = m_count;
        for (uint32_t i = 0; i < n; ++i)
        {
            const slot& s = t->slots[i];
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

    // One named shard's whole line, which `stats` prints so an operator can
    // see how the work is spread.
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

    // What one named shard last said, for diagnostics and tests, where the sum
    // above is what production reads.
    uint64_t active_at(uint32_t i) const
    {
        if (!m_table || i >= m_count)
            return 0;
        return m_table->slots[i].active_connections.load(std::memory_order_acquire);
    }

    // ─── WHO MAY CALL THIS, AND HOLDING WHAT ────────────────────────────────
    // The unmap, and therefore the only transition in this class that can hurt
    // a reader: attach_reader() going null -> valid costs a reader at worst a
    // momentary zero, because m_count is still 0 for the instant between the
    // two stores.  This one takes the pages away underneath one.
    //
    // sum() and sum_active() are called from the metrics thread under a SHARED
    // lock on runtime_manager::mutex, and two shared holders exclude nothing.
    // So the caller of close() must hold that mutex EXCLUSIVELY, or the unmap
    // can land between a reader's null check and its loads and the daemon
    // takes the fault on a thread that was only being asked for a number.
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

// `self.clients()` is deliberately not here, because ids are descriptors:
// summing is meaningless and concatenating hands one shard's id to another.
