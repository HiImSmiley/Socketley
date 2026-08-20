#pragma once
// What N processes serving ONE runtime publish about themselves, so that any
// one of them can answer for all of them without asking.
//
// ─── WHY THIS EXISTS ────────────────────────────────────────────────────────
//
// --shards runs a runtime as N worker processes sharing one listening socket.
// Every figure a script can ask about is then per-process, and the script is
// not told: `self.connections()` on a four-shard runtime holding 40 clients
// answers 10, 11, 9 or 10 depending on which shard the callback happened to run
// in, and each of those answers is a correct count of the wrong thing.
//
// ─── WHY NOT THE CONTROL SOCKET ─────────────────────────────────────────────
//
// Every other cross-process question in this tree travels the supervisor's
// socketpair, and for a request that is right: somebody is waiting on an answer
// only another process has.  Aggregation is not that shape.  Nothing has to be
// decided at the far end — the far end has already computed the number, it just
// has not said it out loud — so a round trip buys latency and nothing else.
//
// Measured on this box, 2026-08-20, `floor_pingpong -n 20000 -m 64 -P 7`: an
// AF_UNIX round trip is 5.68 us pinned and 10.28 us unpinned, and unpinned is
// the deployed case because two shards are two processes the scheduler places
// where it likes.  Summing over eight shards through the daemon would be eight
// wakeups on foreign cores; here it is eight loads out of two cache lines.
//
// ─── WHY IT IS WAIT-FREE, AND WHAT THAT COSTS ───────────────────────────────
//
// One slot per shard, one writer per slot, cache-line aligned so that two
// shards publishing never contend on the same line.  A reader loads; it never
// takes a lock, never waits for a writer, and cannot be delayed by a shard that
// has been descheduled or has stopped running altogether.
//
// What that buys is bounded by what it can carry: a fixed set of counters that
// each shard produces independently and that the reader only ever SUMS.  It is
// not a place to put a map with arbitrary keys, or a client list — see the note
// on `clients()` at the bottom of this file.
//
// ─── WHY A memfd AND NOT A FILE ─────────────────────────────────────────────
//
// The mapping has to survive fork AND exec — the worker is exec'd, so an
// anonymous MAP_SHARED mapping is gone by the time it could be read.  A file in
// the state directory would survive both and brings two problems this tree has
// already been bitten by: it is a path, so it is a stale node to clean up and a
// second uid's business (state files are written 0644, and under umask 0 they
// have been written 0666), and it outlives the daemon that made it.
//
// memfd_create has neither property.  There is no path, so nothing outside this
// process tree can open it; the descriptor is handed to exactly the children
// that need it and the region is freed when the last of them closes.
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "runtime_definitions.h"   // max_shards

namespace shard_stats
{

// A 64-bit atomic has to be lock-free for this to be shared memory at all: a
// libstdc++ fallback lock lives in the reader's own address space, so two
// processes "locking" would each take their own and the guarantee would be
// nothing.  x86-64 satisfies this; the assert is here so that a port to a
// target that does not fails to build rather than fails to synchronise.
static_assert(std::atomic<uint64_t>::is_always_lock_free,
              "shard_stats needs lock-free 64-bit atomics to cross a process boundary");

inline constexpr size_t   line_size      = 64;
inline constexpr uint32_t magic_value    = 0x534b4c53u;   // 'SKLS'
inline constexpr uint32_t format_version = 1u;

// One shard's line.  Written by that shard and by nobody else; read by all of
// them.
//
// `generation` is not a seqlock.  Every field below it is a single 64-bit value
// that is meaningful on its own, so a reader can never catch a half-written
// one and there is nothing to protect.  It says how many times a process has
// attached to this slot, which is what tells a reader "a shard has lived here"
// from "this slot has never been used" — a distinction that matters because a
// slot's zero is also a legitimate count.
struct alignas(line_size) slot
{
    std::atomic<uint64_t> generation;
    std::atomic<uint64_t> active_connections;
    std::atomic<uint64_t> reserved[6];
};
static_assert(sizeof(slot) == line_size);

struct alignas(line_size) header
{
    std::atomic<uint32_t> magic;
    std::atomic<uint32_t> version;
    std::atomic<uint32_t> shard_count;
    std::atomic<uint32_t> reserved[13];
};
static_assert(sizeof(header) == line_size);

// Always max_shards slots, whatever the runtime asked for.  4160 bytes for the
// largest shard count this build allows, which is one page and a bit — so the
// size is a constant, both sides compute it the same way by construction, and
// there is no size to negotiate across the exec.  A region whose length does
// not match is refused rather than mapped short.
struct table
{
    header h;
    slot   slots[max_shards];
};
static_assert(sizeof(table) == line_size * (max_shards + 1));

// The daemon's half and the worker's half of one region.
//
// One object, two roles, because they are two ends of the same thing and the
// alternative is two classes that have to agree about a layout.  create() is
// the daemon's; adopt() is the worker's; publish_active() is only ever called
// by the process that adopted a slot, and sum_active() by anyone.
class shard_table
{
public:
    shard_table() = default;
    ~shard_table() { close(); }

    shard_table(const shard_table&)            = delete;
    shard_table& operator=(const shard_table&) = delete;

    // ── daemon side ─────────────────────────────────────────────────────────
    //
    // A fresh region for one runtime, zeroed, with the descriptor kept so that
    // every shard forked afterwards — including one forked to replace a shard
    // that died — is handed the same one.
    bool create(uint32_t shard_count)
    {
        close();
        if (shard_count == 0 || shard_count > max_shards)
            return false;

        // MFD_CLOEXEC because this descriptor must not reach a child that was
        // not deliberately handed it; proxy_supervisor::spawn dup2s it onto a
        // fixed number for the children that were, and dup2 clears the flag on
        // the copy.
        const int fd = static_cast<int>(::syscall(SYS_memfd_create,
                                                  "socketley-shards", MFD_CLOEXEC));
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

    // The runtime's shard count has changed and the region has to say so.
    // Slots above the new count are cleared, because a shrink retires those
    // shards and a stale line would otherwise keep being summed by the ones
    // that remain.
    void set_shard_count(uint32_t shard_count)
    {
        if (!m_table || shard_count == 0 || shard_count > max_shards)
            return;
        for (uint32_t i = shard_count; i < m_count; ++i)
            clear_slot(i);
        m_count = shard_count;
        m_table->h.shard_count.store(shard_count, std::memory_order_release);
    }

    // A shard is gone — retired, shrunk away, or dead — and its last published
    // figure must stop being counted.  The daemon does this rather than the
    // departing shard, because the case that matters is the shard that did not
    // get to do anything on its way out.
    void clear_slot(uint32_t i)
    {
        if (!m_table || i >= max_shards)
            return;
        m_table->slots[i].active_connections.store(0, std::memory_order_release);
        m_table->slots[i].generation.store(0, std::memory_order_release);
    }

    int fd() const { return m_fd; }

    // ── worker side ─────────────────────────────────────────────────────────
    //
    // Map the region handed over on `fd` and take slot `index` as this
    // process's own.  Takes ownership of the descriptor either way: a failure
    // that left the caller holding it would leak one per refused config.
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
        m_table->slots[index].generation.fetch_add(1, std::memory_order_release);
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

    // Every shard's figure, added up.  Wait-free: a shard that is descheduled,
    // stopped or dead delays this by nothing — its slot holds whatever it last
    // said, and a shard the daemon has retired holds zero because the daemon
    // cleared it.
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

// ─── WHAT DOES NOT FIT HERE, AND WHY IT IS SAID OUT LOUD ────────────────────
//
// `self.clients()` is the other aggregate on the list and it is NOT this shape.
// It returns a list of client ids, and a shard's ids are its own descriptors:
// two shards both have a client 12 and they are different sockets.  Summing is
// meaningless and concatenating is worse, because the caller's next move is
// `self.send(id, ...)` and an id from another shard names one of this shard's
// connections instead — which is the descriptor-as-a-name defect that
// conn_identity.h exists to have already fixed.
//
// So a cross-shard client list is a list of conn_refs, and a conn_ref is only
// useful to a caller that can route to it.  That makes `clients()` a consumer
// of the routing step and not of this one; it is deliberately left alone here
// rather than made to return a fraction with a shared mapping behind it.
