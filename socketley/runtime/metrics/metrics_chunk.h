#pragma once
// Gorilla chunks: timestamps as delta-of-delta milliseconds, values XOR'd against the one before, and a decoder that
// stays inside whatever bytes it is handed.
//
// A chunk is a little-endian u16 sample count and then a bit stream, most significant bit first: the first sample as
// 64 bits of time and 64 of value, every later one as a delta-of-delta of its time and an XOR of its value's bits.
// A tier chunk is the same stream with seven value columns per point, each XOR'd against its own column.
#include <bit>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

#include "metrics_types.h"

namespace socketley::metrics
{

// A chunk closes once it holds this many samples.
inline constexpr uint16_t chunk_samples = 120;
inline constexpr size_t chunk_head_bytes = 2;
// The most bits a sample after the first can take: the widest delta-of-delta and a full XOR window.
inline constexpr uint32_t max_sample_bits = 4 + 64 + 2 + 5 + 6 + 64;
inline constexpr uint32_t first_sample_bits = 128;
// Timestamps past this distance from the epoch are refused, so window arithmetic never overflows.
inline constexpr int64_t max_abs_time = int64_t(1) << 60;

// Floor division, which C++'s `/` is not for a negative time.
inline int64_t floor_div(int64_t a, int64_t b)
{
    const int64_t q = a / b;
    return (a % b != 0 && ((a < 0) != (b < 0))) ? q - 1 : q;
}

// The start of the `span`-aligned window holding `t`.
inline int64_t align_down(int64_t t, int64_t span) { return floor_div(t, span) * span; }

// Subtraction that wraps rather than overflows, as the codec's deltas may.
inline int64_t wrap_sub(int64_t a, int64_t b)
{
    return static_cast<int64_t>(static_cast<uint64_t>(a) - static_cast<uint64_t>(b));
}
inline int64_t wrap_add(int64_t a, int64_t b)
{
    return static_cast<int64_t>(static_cast<uint64_t>(a) + static_cast<uint64_t>(b));
}

// The low `n` bits of `v` written at bit `pos` of a buffer the caller zeroed and sized.
inline void put_bits(uint8_t* buf, uint32_t& pos, uint64_t v, unsigned n)
{
    while (n > 0)
    {
        const unsigned room = 8 - (pos & 7);
        const unsigned take = n < room ? n : room;
        const auto part = static_cast<unsigned>((v >> (n - take)) & ((1u << take) - 1));
        buf[pos >> 3] |= static_cast<uint8_t>(part << (room - take));
        pos += take;
        n -= take;
    }
}

class bit_reader
{
public:
    bit_reader() = default;
    bit_reader(const uint8_t* p, size_t bytes) : m_p(p), m_bits(bytes * 8) {}

    // `n` bits, at most 64, or false when fewer are left.
    bool get(unsigned n, uint64_t& out)
    {
        if (n > m_bits - m_pos)
            return false;
        uint64_t v = 0;
        while (n > 0)
        {
            const unsigned room = 8 - static_cast<unsigned>(m_pos & 7);
            const unsigned take = n < room ? n : room;
            const unsigned byte = m_p[m_pos >> 3];
            v = (v << take) | ((byte >> (room - take)) & ((1u << take) - 1));
            m_pos += take;
            n -= take;
        }
        out = v;
        return true;
    }

    bool bit(bool& out)
    {
        uint64_t v = 0;
        if (!get(1, v))
            return false;
        out = v != 0;
        return true;
    }

private:
    const uint8_t* m_p{nullptr};
    size_t m_bits{0};
    size_t m_pos{0};
};

// The window of meaningful bits the last XOR was written with; lead 0xff before the first.
struct xor_state
{
    uint64_t prev{0};
    uint8_t lead{0xff};
    uint8_t trail{0};
};

void put_dod(uint8_t* buf, uint32_t& pos, int64_t dod);
bool get_dod(bit_reader& r, int64_t& dod);
void put_xor(uint8_t* buf, uint32_t& pos, xor_state& x, uint64_t bits);
bool get_xor(bit_reader& r, xor_state& x);

// A chunk being written into a fixed buffer, the state kept beside the bytes rather than in them.
struct chunk_appender
{
    int64_t mint{0};
    int64_t maxt{0};
    int64_t delta{0};
    xor_state x{};
    uint32_t bits{0};
    uint16_t n{0};

    // Whether a buffer of `cap` bytes has room for one more sample.
    bool fits(size_t cap) const
    {
        const uint64_t need = n == 0 ? first_sample_bits : max_sample_bits;
        return n < 0xFFFF && chunk_head_bytes * 8 + uint64_t(bits) + need <= uint64_t(cap) * 8;
    }

    // The sample written behind the others into `buf`, zero past what was written; false, writing nothing, when it
    // does not fit.
    bool append(uint8_t* buf, size_t cap, int64_t t, double v);

    // The chunk's length in bytes, its count included.
    size_t bytes() const { return chunk_head_bytes + (size_t(bits) + 7) / 8; }

    // The buffer zeroed where this chunk wrote, and the state set back to an empty chunk.
    void reset(uint8_t* buf)
    {
        std::memset(buf, 0, bytes());
        *this = chunk_appender{};
    }
};

class chunk_reader
{
public:
    explicit chunk_reader(std::span<const uint8_t> bytes);

    // The next sample, false at the end and at damage, which failed() then tells apart.
    bool next();
    int64_t t() const { return m_t; }
    double v() const { return std::bit_cast<double>(m_x.prev); }
    uint64_t vbits() const { return m_x.prev; }
    uint16_t count() const { return m_n; }
    bool failed() const { return m_failed; }

private:
    bit_reader m_r;
    uint16_t m_n{0};
    uint16_t m_i{0};
    int64_t m_t{0};
    int64_t m_delta{0};
    xor_state m_x{};
    bool m_failed{false};
};

// `in` as one chunk, at most 65535 samples, in `out`.
void encode_chunk(std::span<const sample> in, std::vector<uint8_t>& out);
// The samples of `bytes` appended to `out`; false at damage, with what decoded before it appended.
bool decode_chunk(std::span<const uint8_t> bytes, std::vector<sample>& out);

// ── Tiers ─────────────────────────────────────────────────────────────────

// One step of a tier as it is kept: an agg_point, plus the step's first sample and its increase from that first
// sample on, so a coarser step and a step's `inc` are both made exactly from these.
// NaN, the stale marker among them, takes no part in a tier.
struct tier_point
{
    int64_t t{0};
    double min{0};
    double max{0};
    double sum{0};
    double count{0};
    double last{0};
    double first{0};
    double rise{0};
};

inline constexpr unsigned tier_columns = 7;
// A tier chunk holds at most this many points, so a range read skips the rest by its bounds.
inline constexpr size_t tier_chunk_points = 1024;

// A counter's increase from `from` to `to`, a fall read as a reset to zero.
inline double counter_rise(double from, double to) { return to >= from ? to - from : to; }

// `v` folded into the step `p` already holds.
inline void fold_value(tier_point& p, double v)
{
    p.rise += counter_rise(p.last, v);
    if (v < p.min)
        p.min = v;
    if (v > p.max)
        p.max = v;
    p.sum += v;
    p.count += 1;
    p.last = v;
}

// A finer step `q` that follows `p`'s, folded into the coarser step `p` holds.
inline void fold_point(tier_point& p, const tier_point& q)
{
    p.rise += counter_rise(p.last, q.first) + q.rise;
    if (q.min < p.min)
        p.min = q.min;
    if (q.max > p.max)
        p.max = q.max;
    p.sum += q.sum;
    p.count += q.count;
    p.last = q.last;
}

// The step of `step` that `t` falls in, by the time it ends.
inline int64_t step_end(int64_t t, int64_t step) { return align_down(t, step) + step; }

// Raw samples folded, in time order, into the points of one tier.
class tier_folder
{
public:
    tier_folder(int64_t step, std::vector<tier_point>& out) : m_step(step), m_out(out) {}
    ~tier_folder() { finish(); }

    void add(int64_t t, double v)
    {
        if (std::isnan(v))
            return;
        const int64_t e = step_end(t, m_step);
        if (m_open && e == m_p.t)
        {
            fold_value(m_p, v);
            return;
        }
        finish();
        m_p = tier_point{e, v, v, v, 1, v, v, 0};
        m_open = true;
    }

    // Finer points, in time order, folded into this coarser tier.
    void add(const tier_point& q)
    {
        const int64_t e = step_end(q.t - 1, m_step);
        if (m_open && e == m_p.t)
        {
            fold_point(m_p, q);
            return;
        }
        finish();
        m_p = q;
        m_p.t = e;
        m_open = true;
    }

    void finish()
    {
        if (m_open)
            m_out.push_back(m_p);
        m_open = false;
    }

private:
    int64_t m_step;
    std::vector<tier_point>& m_out;
    tier_point m_p{};
    bool m_open{false};
};

// The point a query reads: its increase measured from the previous step's last sample, when that step has one.
inline agg_point to_agg(const tier_point& p, const tier_point* prev, int64_t step)
{
    double inc = p.rise;
    if (prev && prev->t == p.t - step)
        inc += counter_rise(prev->last, p.first);
    return agg_point{p.t, p.min, p.max, p.sum, p.count, p.last, inc};
}

// `in`, at most 65535 points, as one tier chunk in `out`.
void encode_tier_chunk(std::span<const tier_point> in, std::vector<uint8_t>& out);
// The points of `bytes` appended to `out`; false at damage.
bool decode_tier_chunk(std::span<const uint8_t> bytes, std::vector<tier_point>& out);

}   // namespace socketley::metrics
