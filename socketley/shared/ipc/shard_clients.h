#pragma once
// Which connections each shard holds, by name, behind a seqlock a reader
// retries, because a list is a length and N entries that must agree.
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <vector>

#include "../net/conn_identity.h"
#include "../runtime/runtime_definitions.h"   // max_shards

namespace shard_clients
{

static_assert(std::atomic<uint64_t>::is_always_lock_free,
              "shard_clients needs lock-free 64-bit atomics to cross a process boundary");

inline constexpr size_t   line_size             = 64;
inline constexpr uint32_t magic_value           = 0x534b4c43u;   // 'SKLC'
inline constexpr uint32_t format_version        = 1u;
inline constexpr uint32_t max_clients_per_shard = 8192u;         // server MAX_FDS
inline constexpr int      read_attempts         = 64;

// Two atomics rather than a conn_ref: a seqlock payload is read while a writer
// may be in it, and the version's acquire/release is what orders the relaxed reads.
struct entry
{
    std::atomic<uint64_t> owner;
    std::atomic<uint64_t> serial;
};

struct alignas(line_size) block_header
{
    std::atomic<uint64_t> version;    // odd while a writer is inside
    std::atomic<uint32_t> count;
    std::atomic<uint32_t> generation; // bumped by each process that adopts
    std::atomic<uint64_t> reserved[6];
};
static_assert(sizeof(block_header) == line_size);

struct alignas(line_size) region_header
{
    std::atomic<uint32_t> magic;
    std::atomic<uint32_t> version;
    std::atomic<uint32_t> shard_count;
    std::atomic<uint32_t> reserved[13];
};
static_assert(sizeof(region_header) == line_size);

inline constexpr size_t block_size =
    sizeof(block_header) + sizeof(entry) * max_clients_per_shard;

// Sized from the shard count, which both sides already have; a mapping whose
// length disagrees with the header is refused rather than mapped short.
inline size_t region_size(uint32_t shard_count)
{
    return sizeof(region_header) + block_size * static_cast<size_t>(shard_count);
}

class client_table
{
public:
    client_table() = default;
    ~client_table() { close(); }

    client_table(const client_table&)            = delete;
    client_table& operator=(const client_table&) = delete;

    // ── daemon side ─────────────────────────────────────────────────────────
    bool create(uint32_t shard_count)
    {
        close();
        if (shard_count == 0 || shard_count > max_shards)
            return false;

        const size_t len = region_size(shard_count);
        const int fd = static_cast<int>(::syscall(SYS_memfd_create,
                                                  "socketley-shard-clients", MFD_CLOEXEC));
        if (fd < 0)
            return false;
        if (::ftruncate(fd, static_cast<off_t>(len)) < 0) { ::close(fd); return false; }

        void* p = ::mmap(nullptr, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (p == MAP_FAILED) { ::close(fd); return false; }

        m_fd    = fd;
        m_base  = static_cast<uint8_t*>(p);
        m_len   = len;
        m_count = shard_count;
        m_index = invalid_index;

        auto* h = header();
        h->version.store(format_version, std::memory_order_relaxed);
        h->shard_count.store(shard_count, std::memory_order_relaxed);
        h->magic.store(magic_value, std::memory_order_release);
        return true;
    }

    // A shard has gone, so the count stops it being read; the entries are left
    // alone because a reader past that check holds a version it will re-check.
    void clear_block(uint32_t i)
    {
        if (!m_base || i >= m_count) return;
        auto* b = block(i);
        b->version.fetch_add(1, std::memory_order_acq_rel);
        b->count.store(0, std::memory_order_release);
        b->version.fetch_add(1, std::memory_order_release);
    }

    int fd() const { return m_fd; }

    // ── worker side ─────────────────────────────────────────────────────────
    bool adopt(int fd, uint32_t index, uint32_t shard_count)
    {
        close();
        if (fd < 0 || shard_count == 0 || shard_count > max_shards) { if (fd >= 0) ::close(fd); return false; }

        const size_t len = region_size(shard_count);
        struct stat st{};
        if (::fstat(fd, &st) < 0 || st.st_size != static_cast<off_t>(len)) { ::close(fd); return false; }

        void* p = ::mmap(nullptr, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (p == MAP_FAILED) { ::close(fd); return false; }

        m_base = static_cast<uint8_t*>(p);
        m_len  = len;
        auto* h = header();
        if (h->magic.load(std::memory_order_acquire) != magic_value
            || h->version.load(std::memory_order_relaxed) != format_version
            || h->shard_count.load(std::memory_order_acquire) != shard_count
            || index >= shard_count)
        {
            ::munmap(p, len); m_base = nullptr; ::close(fd);
            return false;
        }

        m_fd    = fd;
        m_count = shard_count;
        m_index = index;

        // Whatever the previous occupant left is not about this process.
        auto* b = block(index);
        b->version.fetch_add(1, std::memory_order_acq_rel);
        b->count.store(0, std::memory_order_release);
        b->generation.fetch_add(1, std::memory_order_relaxed);
        b->version.fetch_add(1, std::memory_order_release);
        return true;
    }

    bool     mapped()   const { return m_base != nullptr; }
    bool     writable() const { return m_base != nullptr && m_index < m_count; }
    uint32_t index()    const { return m_index; }
    uint32_t count()    const { return m_base ? m_count : 0; }

    // The whole list, copied from m_active_fds rather than a second structure
    // to keep in step -- a disagreement here is a send to a closed connection.
    void publish(const std::vector<conn_ref>& refs)
    {
        if (!writable()) return;
        auto* b = block(m_index);
        auto* e = entries(m_index);

        const uint32_t n = refs.size() > max_clients_per_shard
                             ? max_clients_per_shard
                             : static_cast<uint32_t>(refs.size());

        b->version.fetch_add(1, std::memory_order_acq_rel);      // -> odd
        for (uint32_t i = 0; i < n; ++i)
        {
            e[i].owner.store(refs[i].owner,  std::memory_order_relaxed);
            e[i].serial.store(refs[i].serial, std::memory_order_relaxed);
        }
        b->count.store(n, std::memory_order_relaxed);
        b->version.fetch_add(1, std::memory_order_release);      // -> even
    }

    // One entry's worth of stores each, mirroring what server_instance does to
    // m_active_fds -- same order, same swap-remove, so the two stay aligned.
    void push(const conn_ref& r)
    {
        if (!writable()) return;
        auto* b = block(m_index);
        const uint32_t n = b->count.load(std::memory_order_relaxed);
        if (n >= max_clients_per_shard) return;      // cannot happen; see the header

        auto* e = entries(m_index);
        b->version.fetch_add(1, std::memory_order_acq_rel);
        e[n].owner.store(r.owner,  std::memory_order_relaxed);
        e[n].serial.store(r.serial, std::memory_order_relaxed);
        b->count.store(n + 1, std::memory_order_relaxed);
        b->version.fetch_add(1, std::memory_order_release);
    }

    void swap_remove(uint32_t idx)
    {
        if (!writable()) return;
        auto* b = block(m_index);
        const uint32_t n = b->count.load(std::memory_order_relaxed);
        if (n == 0 || idx >= n) return;

        auto* e = entries(m_index);
        b->version.fetch_add(1, std::memory_order_acq_rel);
        if (idx != n - 1)
        {
            e[idx].owner.store(e[n-1].owner.load(std::memory_order_relaxed),
                               std::memory_order_relaxed);
            e[idx].serial.store(e[n-1].serial.load(std::memory_order_relaxed),
                                std::memory_order_relaxed);
        }
        b->count.store(n - 1, std::memory_order_relaxed);
        b->version.fetch_add(1, std::memory_order_release);
    }

    void clear_own()
    {
        if (!writable()) return;
        auto* b = block(m_index);
        b->version.fetch_add(1, std::memory_order_acq_rel);
        b->count.store(0, std::memory_order_relaxed);
        b->version.fetch_add(1, std::memory_order_release);
    }

    uint32_t own_count() const
    {
        if (!writable()) return 0;
        return block(m_index)->count.load(std::memory_order_relaxed);
    }

    // `skip` is this process's own block and invalid_index reads all; false
    // means a block could not be read and `out` holds the rest.
    bool read_others(std::vector<conn_ref>& out, uint32_t skip) const
    {
        out.clear();
        if (!m_base) return true;

        bool complete = true;
        for (uint32_t s = 0; s < m_count; ++s)
        {
            if (s == skip) continue;
            if (!read_block(s, out)) complete = false;
        }
        return complete;
    }

    // One block, appended to `out`.  False when it could not be read cleanly.
    bool read_block(uint32_t s, std::vector<conn_ref>& out) const
    {
        if (!m_base || s >= m_count) return true;
        const auto* b = block(s);
        const auto* e = entries(s);

        for (int attempt = 0; attempt < read_attempts; ++attempt)
        {
            const uint64_t v1 = b->version.load(std::memory_order_acquire);
            if (v1 & 1u) continue;                   // a writer is inside

            uint32_t n = b->count.load(std::memory_order_relaxed);
            if (n > max_clients_per_shard) n = max_clients_per_shard;

            const size_t before = out.size();
            for (uint32_t i = 0; i < n; ++i)
                out.push_back(conn_ref{e[i].owner.load(std::memory_order_relaxed),
                                       e[i].serial.load(std::memory_order_relaxed)});

            std::atomic_thread_fence(std::memory_order_acquire);
            if (b->version.load(std::memory_order_acquire) == v1)
                return true;                          // nothing moved underneath

            out.resize(before);                       // torn; drop and retry
        }
        return false;
    }

    void close()
    {
        if (m_base) { ::munmap(m_base, m_len); m_base = nullptr; }
        if (m_fd >= 0) { ::close(m_fd); m_fd = -1; }
        m_len = 0; m_count = 0; m_index = invalid_index;
    }

    static constexpr uint32_t invalid_index = 0xFFFFFFFFu;

private:
    region_header* header() const
    { return reinterpret_cast<region_header*>(m_base); }

    block_header* block(uint32_t i) const
    {
        return reinterpret_cast<block_header*>(
            m_base + sizeof(region_header) + block_size * static_cast<size_t>(i));
    }

    entry* entries(uint32_t i) const
    {
        return reinterpret_cast<entry*>(
            reinterpret_cast<uint8_t*>(block(i)) + sizeof(block_header));
    }

    int      m_fd{-1};
    uint8_t* m_base{nullptr};
    size_t   m_len{0};
    uint32_t m_count{0};
    uint32_t m_index{invalid_index};
};

}   // namespace shard_clients
