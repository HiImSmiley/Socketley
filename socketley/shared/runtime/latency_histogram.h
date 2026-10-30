#pragma once
// A latency histogram a loop thread fills in a few nanoseconds: fixed log2 buckets of microseconds, counted without a
// lock because each shard's belongs to its one loop thread, and carried in the stats text as one line the catalog
// reads back and turns into a Prometheus histogram.
//
// The line is `key:<sum_ns> <c0> <c1> ... <c19>`, each count the bucket's own and not cumulative, so the line of a
// second shard is added to the first's bucket by bucket.
#include <array>
#include <bit>
#include <charconv>
#include <cstdint>
#include <string>
#include <string_view>

namespace socketley
{

class latency_histogram
{
public:
    // Bucket i holds what is at most 2^(i + first_shift) microseconds, the last one what is longer than them all.
    static constexpr int first_shift = 6;
    static constexpr int finite = 19;
    static constexpr int buckets = finite + 1;

    // The upper bounds as the exposition format's `le` label spells them, seconds, ascending, ending in +Inf.
    static constexpr std::array<std::string_view, buckets> le = {
        "0.000064", "0.000128", "0.000256", "0.000512", "0.001024", "0.002048", "0.004096",
        "0.008192", "0.016384", "0.032768", "0.065536", "0.131072", "0.262144", "0.524288",
        "1.048576", "2.097152", "4.194304", "8.388608", "16.777216", "+Inf"};

    static constexpr uint64_t bound_us(int i) noexcept { return uint64_t{1} << (i + first_shift); }

    // The bucket of a duration: the smallest i whose bound it does not exceed, by one bit width and no loop.
    static constexpr int index_of_ns(uint64_t ns) noexcept
    {
        const uint64_t us = (ns + 999) / 1000;
        const uint64_t below = us != 0 ? us - 1 : 0;
        const int i = std::bit_width(below | (bound_us(0) - 1)) - first_shift;
        return i < finite ? i : finite;
    }

    void observe_ns(uint64_t ns) noexcept
    {
        ++m_count[static_cast<size_t>(index_of_ns(ns))];
        m_sum_ns += ns;
    }

    // From a start stamp to an end stamp of the same clock, an end that is not later counted as no time at all; a start
    // of 0 is one never taken, and counts nothing.
    void observe(uint64_t start_ns, uint64_t end_ns) noexcept
    {
        if (start_ns != 0)
            observe_ns(end_ns > start_ns ? end_ns - start_ns : 0);
    }

    void merge(const latency_histogram& o) noexcept
    {
        for (size_t i = 0; i < buckets; ++i)
            m_count[i] += o.m_count[i];
        m_sum_ns += o.m_sum_ns;
    }

    uint64_t bucket(int i) const noexcept { return m_count[static_cast<size_t>(i)]; }
    uint64_t sum_ns() const noexcept { return m_sum_ns; }
    uint64_t count() const noexcept
    {
        uint64_t n = 0;
        for (const uint64_t c : m_count)
            n += c;
        return n;
    }

    // The stats line under `key`.
    void put(std::string& out, std::string_view key) const
    {
        out += key;
        out += ':';
        append(out, m_sum_ns);
        for (const uint64_t c : m_count)
        {
            out += ' ';
            append(out, c);
        }
        out += '\n';
    }

    // A stats line's value read back, false for one that is not exactly a sum and a count per bucket.
    static bool parse(std::string_view v, latency_histogram& out) noexcept
    {
        const char* p = v.data();
        const char* const end = p + v.size();
        latency_histogram h;
        for (int i = -1; i < buckets; ++i)
        {
            if (i >= 0)
            {
                if (p == end || *p != ' ')
                    return false;
                ++p;
            }
            uint64_t n = 0;
            const auto r = std::from_chars(p, end, n);
            if (r.ec != std::errc{})
                return false;
            p = r.ptr;
            if (i < 0)
                h.m_sum_ns = n;
            else
                h.m_count[static_cast<size_t>(i)] = n;
        }
        if (p != end)
            return false;
        out = h;
        return true;
    }

private:
    static void append(std::string& out, uint64_t v)
    {
        char buf[24];
        const auto r = std::to_chars(buf, buf + sizeof buf, v);
        out.append(buf, static_cast<size_t>(r.ptr - buf));
    }

    std::array<uint64_t, buckets> m_count{};
    uint64_t m_sum_ns{0};
};

}   // namespace socketley
