#pragma once
// Blocks, the immutable files a store's history lies in, and the head log its open window is kept in.
//
// A block is one aligned window of one kind, raw chunks or the points of one tier, laid out as
//   chunks    back to back, each a metrics_chunk.h chunk
//   symbols   u32 n | u32 off[n+1] | the bytes
//   series    u32 n | u32 off[n+1] | per series: u32 labels | (u32 name, u32 value)* | i64 mint | i64 maxt |
//             u64 offset of its first chunk | u32 chunks | (i64 mint, i64 maxt, u32 length)*
//   postings  u32 n | per label pair: u32 name | u32 value | u32 ids | u32 local id*
//   footer    magic | u32 version | i64 step | i64 mint | i64 maxt | 4 x (u64 offset, u64 length, u32 crc32c) | u32 crc32c
// with every part under its own crc32c, so a block is read whole or refused whole.
//
// A head log is a 16-byte header naming its window and then records of `u32 length | u32 crc32c | payload`: a series'
// labels under the id the records after it use, a closed chunk, or a batch of samples.
//
// Thread-safety: a block is immutable once set_globals() returned and may then be read from any thread; a writer
// and the log codec belong to whichever thread calls them.
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "metrics_types.h"

namespace socketley::metrics
{

inline constexpr int64_t minute_ms = 60'000;
inline constexpr int64_t hour_ms = 60 * minute_ms;
inline constexpr int64_t day_ms = 24 * hour_ms;
// The window a block is cut from the head at.
inline constexpr int64_t block_ms = 2 * hour_ms;

// A block file's name for its kind (0 raw, else a tier's step) and window [mint, maxt).
std::string block_name(int64_t step, int64_t mint, int64_t maxt);
bool parse_block_name(std::string_view name, int64_t& step, int64_t& mint, int64_t& maxt);

class block
{
public:
    // `path` mapped and checked whole; null with `why` when any part of it is damaged.
    static std::shared_ptr<block> open(const std::string& path, std::string& why);
    ~block();
    block(const block&) = delete;
    block& operator=(const block&) = delete;

    const std::string& path() const { return m_path; }
    // 0 for raw chunks, else the step of the tier whose points the chunks hold.
    int64_t step() const { return m_step; }
    int64_t mint() const { return m_mint; }
    int64_t maxt() const { return m_maxt; }
    uint64_t file_bytes() const { return m_size; }
    uint32_t count() const { return m_nseries; }

    void labels(uint32_t local, label_set& out) const;

    struct chunk
    {
        int64_t mint;
        int64_t maxt;
        std::span<const uint8_t> bytes;
    };
    // The first and last time of `local`'s chunks.
    void range(uint32_t local, int64_t& mint, int64_t& maxt) const;
    // Each chunk of `local` in time order handed to `f`, until it answers false.
    template <class F>
    void each_chunk(uint32_t local, F&& f) const
    {
        const uint8_t* e = entry(local);
        const uint32_t nl = load32(e);
        e += 4 + 8 * size_t(nl);
        uint64_t off = load64(e + 16);
        const uint32_t nc = load32(e + 24);
        e += 28;
        for (uint32_t i = 0; i < nc; ++i, e += 20)
        {
            const uint32_t len = load32(e + 16);
            const chunk c{static_cast<int64_t>(load64(e)), static_cast<int64_t>(load64(e + 8)),
                          std::span<const uint8_t>(m_map + off, len)};
            off += len;
            if (!f(c))
                return;
        }
    }

    // The label pairs a block lists postings for, each with how many series carry it; for a test of the file.
    void postings(std::vector<std::pair<label, uint32_t>>& out) const;

    // Which store id each local series is, set once before the block is shared.
    void set_globals(std::span<const uint32_t> global_of_local);
    // The local series that is store id `global`, or 0xFFFFFFFF.
    uint32_t local_of(uint32_t global) const;
    std::span<const uint32_t> globals() const { return m_globals; }
    size_t ram_bytes() const { return sizeof(*this) + m_path.capacity() + (m_globals.capacity() + m_locals.capacity()) * 4; }

private:
    block() = default;
    static uint32_t load32(const uint8_t* p) { return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24; }
    static uint64_t load64(const uint8_t* p) { return uint64_t(load32(p)) | uint64_t(load32(p + 4)) << 32; }
    const uint8_t* entry(uint32_t local) const { return m_series + load32(m_series_off + 4 * size_t(local)); }
    std::string_view symbol(uint32_t s) const;

    std::string m_path;
    const uint8_t* m_map{nullptr};
    uint64_t m_size{0};
    int64_t m_step{0}, m_mint{0}, m_maxt{0};
    uint32_t m_nsyms{0}, m_nseries{0};
    const uint8_t* m_sym_off{nullptr};
    const uint8_t* m_sym_bytes{nullptr};
    const uint8_t* m_series_off{nullptr};
    const uint8_t* m_series{nullptr};
    const uint8_t* m_postings{nullptr};
    uint64_t m_postings_len{0};
    std::vector<uint32_t> m_globals;
    std::vector<uint32_t> m_locals;
};

// A block written series by series to a file beside its name, synced and renamed into place at finish().
class block_writer
{
public:
    block_writer(std::string dir, int64_t step, int64_t mint, int64_t maxt);
    ~block_writer();
    block_writer(const block_writer&) = delete;
    block_writer& operator=(const block_writer&) = delete;

    bool begin(std::string& why);
    // A series after every one added before it in label order; one that is given no chunk is left out.
    void add_series(const label_set& ls, uint32_t global);
    void add_chunk(int64_t mint, int64_t maxt, std::span<const uint8_t> bytes);
    // The block on the disk under path(), its directory synced; false with `why`, leaving nothing behind.
    bool finish(std::string& why);

    const std::string& path() const { return m_path; }
    // The store id of each local series, in the order written.
    const std::vector<uint32_t>& globals() const { return m_globals; }

private:
    struct impl;
    std::unique_ptr<impl> m;
    std::string m_path;
    std::vector<uint32_t> m_globals;
};

// ── The head log ──────────────────────────────────────────────────────────

inline constexpr size_t head_log_header_bytes = 16;

std::string head_log_name(int64_t window);
bool parse_head_log_name(std::string_view name, int64_t& window);
void head_log_header(std::string& buf, int64_t window);

// A series' labels, under the id the records after it in the same log use.
void log_series(std::string& buf, uint32_t id, std::span<const std::pair<std::string_view, std::string_view>> labels);
void log_chunk(std::string& buf, uint32_t id, int64_t mint, int64_t maxt, std::span<const uint8_t> bytes);

// Samples gathered into one record, which flush_into() closes.
class log_samples
{
public:
    void add(uint32_t id, int64_t t, double v);
    void flush_into(std::string& buf);
    bool empty() const { return m_n == 0; }
    size_t bytes() const { return m_body.capacity(); }

private:
    std::string m_body;
    uint32_t m_n{0};
    int64_t m_base{0};
};

class log_visitor
{
public:
    virtual ~log_visitor() = default;
    virtual void series(uint32_t id, label_set& ls) = 0;
    virtual void chunk(uint32_t id, int64_t mint, int64_t maxt, std::span<const uint8_t> bytes) = 0;
    virtual void sample(uint32_t id, int64_t t, double v) = 0;
};

// The records of a head log handed to `v` in order: the length of its whole records, short of the file's when its
// tail is torn or damaged, which `why` then says; 0 when the header is not one.
size_t read_head_log(std::span<const uint8_t> file, int64_t& window, log_visitor& v, std::string& why);

}   // namespace socketley::metrics
