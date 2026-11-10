#pragma once
// Newline framing over bytes wherever they lie, so a line can be handed on
// from the buffer it arrived in rather than from a copy of it.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <algorithm>
#include <memory>
#if defined(__SSE2__)
#include <emmintrin.h>
#endif

namespace socketley
{

// What for_each_line returns when `deliver` asked it to stop, in place of the
// offset just past the last newline it consumed.
inline constexpr size_t line_framing_stopped = static_cast<size_t>(-1);

// Each complete line in [data, data + len), '\r' stripped and empty ones
// skipped, goes to `deliver`, which returns false when the bytes may no longer
// be read, and the search starts at `search_from` because the caller knows the
// bytes before it hold no newline.
template <class Deliver>
inline size_t for_each_line(const char* data, size_t len, size_t search_from,
                            Deliver&& deliver)
{
    size_t start = 0;
    while (search_from < len)
    {
        const void* nl = std::memchr(data + search_from, '\n', len - search_from);
        if (!nl)
            break;
        const size_t pos = static_cast<size_t>(static_cast<const char*>(nl) - data);
        std::string_view line(data + start, pos - start);
        start = search_from = pos + 1;

        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        if (line.empty())
            continue;
        if (!deliver(line))
            return line_framing_stopped;
    }
    return start;
}

// How many '\n' are in [data, data + len), sixty-four bytes a step in vector
// code both SSE2 and NEON compile, since std::count widens every byte to 64 bits.
inline size_t count_newlines(const char* data, size_t len)
{
    typedef signed char v16 __attribute__((vector_size(16)));
    const v16 nl = {'\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n',
                    '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n'};
    size_t n = 0;
    size_t i = 0;
    while (len - i >= 64)
    {
        // A lane matches -1, so subtracting counts it; four accumulators so the loads are not serialised on one,
        // and 255 steps is as far as a byte lane can count.
        v16 a0 = {}, a1 = {}, a2 = {}, a3 = {};
        for (int step = 0; step < 255 && len - i >= 64; ++step, i += 64)
        {
            v16 b0, b1, b2, b3;
            std::memcpy(&b0, data + i, 16);
            std::memcpy(&b1, data + i + 16, 16);
            std::memcpy(&b2, data + i + 32, 16);
            std::memcpy(&b3, data + i + 48, 16);
            a0 -= (b0 == nl);
            a1 -= (b1 == nl);
            a2 -= (b2 == nl);
            a3 -= (b3 == nl);
        }
        for (int lane = 0; lane < 16; ++lane)
            n += static_cast<size_t>(static_cast<unsigned char>(a0[lane])) + static_cast<unsigned char>(a1[lane])
               + static_cast<unsigned char>(a2[lane]) + static_cast<unsigned char>(a3[lane]);
    }
    for (; i < len; ++i)
        n += data[i] == '\n';
    return n;
}

// How many lines for_each_line would deliver from [data, data + len), a line
// being empty when its '\n' follows the start or another '\n', with at most a
// '\r' between, so the count is one pass of vector code instead of a memchr a
// line.
inline size_t count_lines(const char* data, size_t len)
{
    typedef signed char v16 __attribute__((vector_size(16)));
    const v16 nl = {'\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n'};
    const v16 cr = {'\r', '\r', '\r', '\r', '\r', '\r', '\r', '\r', '\r', '\r', '\r', '\r', '\r', '\r', '\r', '\r'};
    // The block before the first is all newlines, since the data starts a line.
    v16 prev_nl = nl == nl;
    v16 prev_cr = {};
    size_t n = 0;
    size_t i = 0;
    while (len - i >= 16)
    {
        v16 acc = {};
        for (int step = 0; step < 255 && len - i >= 16; ++step, i += 16)
        {
            v16 b;
            std::memcpy(&b, data + i, 16);
            const v16 is_nl = b == nl;
            const v16 is_cr = b == cr;
            // Each lane's one and two bytes before, from this block and the last.
            const v16 nl1 = __builtin_shuffle(prev_nl, is_nl, v16{15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30});
            const v16 cr1 = __builtin_shuffle(prev_cr, is_cr, v16{15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30});
            const v16 nl2 = __builtin_shuffle(prev_nl, is_nl, v16{14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29});
            // A lane that ends a line which is not empty is -1, so subtracting counts it, 255 steps being what a
            // byte lane can count.
            acc -= is_nl & ~(nl1 | (cr1 & nl2));
            prev_nl = is_nl;
            prev_cr = is_cr;
        }
        for (int lane = 0; lane < 16; ++lane)
            n += static_cast<unsigned char>(acc[lane]);
    }
    for (; i < len; ++i)
        n += data[i] == '\n'
             && !(i == 0 || data[i - 1] == '\n' || (data[i - 1] == '\r' && (i == 1 || data[i - 2] == '\n')));
    return n;
}

// The offset of the first `c` in [p, p + n), or n, sixteen bytes a step where
// SSE2 is there, because a memchr call costs more than the search across one
// short line.
inline size_t find_byte(const unsigned char* p, size_t n, unsigned char c)
{
    size_t i = 0;
#if defined(__SSE2__)
    const __m128i want = _mm_set1_epi8(static_cast<char>(c));
    for (; n - i >= 16; i += 16)
    {
        const int hit = _mm_movemask_epi8(_mm_cmpeq_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(p + i)), want));
        if (hit)
            return i + static_cast<size_t>(__builtin_ctz(static_cast<unsigned>(hit)));
    }
#endif
    for (; i < n; ++i)
        if (p[i] == c)
            return i;
    return n;
}

// Where each line of some bytes ends, kept between reads for its storage.
struct line_ends
{
    std::unique_ptr<uint32_t[]> at;
    size_t                      size = 0;
    size_t                      cap  = 0;

    // Room for `more` past size, so a writer checks once a block and not once an entry.
    void reserve_more(size_t more)
    {
        if (cap - size >= more)
            return;
        const size_t grown = std::max(cap * 2, size + more + 1024);
        std::unique_ptr<uint32_t[]> next(new uint32_t[grown]);
        if (size)
            std::memcpy(next.get(), at.get(), size * sizeof(uint32_t));
        at  = std::move(next);
        cap = grown;
    }
};

// The length past which the index takes a read's lines for long ones.
inline constexpr size_t k_long_line = 256;

// The offset of every '\n' in [data, data + len) into `ends`, and how many of
// the lines they end for_each_line would deliver, for a reader that walks the
// lines again without searching for them.
inline size_t index_lines(const char* data, size_t len, line_ends& ends)
{
    ends.size = 0;
    size_t lines = 0;
    size_t start = 0;
    // A line is empty when it ends where it starts, or one past it on a '\r'.
    const auto add = [&](size_t end) {
        ends.at[ends.size++] = static_cast<uint32_t>(end);
        lines += end != start && !(end == start + 1 && data[start] == '\r');
        start = end + 1;
    };
    size_t i = 0;
    // A first line past k_long_line bytes makes these long lines, each of whose ends glibc's memchr finds at the machine's
    // own width: sixteen bytes a step was 14% of a client reading 4 KiB lines, and a test a step cost short ones 2%.
    if (len > k_long_line && !std::memchr(data, '\n', k_long_line))
    {
        while (const void* next = std::memchr(data + i, '\n', len - i))
        {
            ends.reserve_more(1);
            add(static_cast<size_t>(static_cast<const char*>(next) - data));
            i = start;
        }
        return lines;
    }
#if defined(__SSE2__)
    const __m128i nl = _mm_set1_epi8('\n');
    for (; len - i >= 16; i += 16)
    {
        unsigned hit = static_cast<unsigned>(
            _mm_movemask_epi8(_mm_cmpeq_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data + i)), nl)));
        if (!hit)
            continue;
        ends.reserve_more(16);
        do
        {
            add(i + static_cast<size_t>(__builtin_ctz(hit)));
            hit &= hit - 1;
        } while (hit);
    }
#endif
    for (; i < len; ++i)
    {
        if (data[i] != '\n')
            continue;
        ends.reserve_more(1);
        add(i);
    }
    return lines;
}

} // namespace socketley
