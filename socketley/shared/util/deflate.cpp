#include "deflate.h"

#include <algorithm>

namespace socketley
{

namespace
{

constexpr size_t window = 32768;
constexpr size_t hash_size = 1u << 15;
constexpr int chain = 64;
constexpr uint32_t min_match = 3, max_match = 258;

constexpr uint16_t length_base[29] = {3,  4,  5,  6,  7,  8,  9,  10, 11,  13,  15,  17,  19,  23, 27,
                                      31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
constexpr uint8_t length_extra[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
                                      2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
constexpr uint16_t dist_base[30] = {1,   2,   3,   4,   5,   7,    9,    13,   17,   25,   33,   49,   65,    97,    129,
                                    193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
constexpr uint8_t dist_extra[30] = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6,
                                    6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};

uint32_t hash3(const unsigned char* p)
{
    return ((static_cast<uint32_t>(p[0]) << 16 | static_cast<uint32_t>(p[1]) << 8 | p[2]) * 2654435761u) >> 17;
}

}   // namespace

deflater::deflater() : m_head(hash_size, -1), m_prev(window, -1) {}

void deflater::bits(uint32_t value, int count, std::string& out)
{
    // Least significant bit first, as DEFLATE packs everything but its Huffman codes.
    m_bitbuf |= value << m_bitcount;
    m_bitcount += count;
    while (m_bitcount >= 8)
    {
        out.push_back(static_cast<char>(m_bitbuf & 0xFF));
        m_bitbuf >>= 8;
        m_bitcount -= 8;
    }
}

void deflater::code(uint32_t c, int length, std::string& out)
{
    // A Huffman code goes most significant bit first, so it is reversed into the stream's order.
    uint32_t r = 0;
    for (int i = 0; i < length; ++i)
        r |= ((c >> i) & 1u) << (length - 1 - i);
    bits(r, length, out);
}

void deflater::literal(uint8_t c, std::string& out)
{
    if (c < 144)
        code(0x30 + c, 8, out);
    else
        code(0x190 + (c - 144), 9, out);
}

void deflater::match(uint32_t length, uint32_t distance, std::string& out)
{
    int li = 28;
    while (li > 0 && length_base[li] > length)
        --li;
    const uint32_t sym = 257 + static_cast<uint32_t>(li);
    if (sym < 280)
        code(sym - 256, 7, out);
    else
        code(0xC0 + (sym - 280), 8, out);
    if (length_extra[li])
        bits(length - length_base[li], length_extra[li], out);
    int di = 29;
    while (di > 0 && dist_base[di] > distance)
        --di;
    code(static_cast<uint32_t>(di), 5, out);
    if (dist_extra[di])
        bits(distance - dist_base[di], dist_extra[di], out);
}

void deflater::compress(std::string_view in, std::string& out)
{
    if (in.empty())
        return;
    // The history and the new bytes in one buffer, cut at its front only once it holds twice the window; a place in
    // the stream is m_hist_at plus its index in it.
    if (m_hist.size() > 2 * window)
    {
        const size_t drop = m_hist.size() - window;
        m_hist.erase(0, drop);
        m_hist_at += drop;
    }
    const size_t start = m_hist.size();
    m_hist.append(in);
    const std::string& buf = m_hist;
    const auto* p = reinterpret_cast<const unsigned char*>(buf.data());
    const uint64_t base = m_hist_at;
    const size_t end = buf.size();
    // A block of the fixed codes, not the last.
    bits(0, 1, out);
    bits(1, 2, out);
    const auto insert = [&](size_t i) {
        if (i + min_match > end)
            return;
        const uint32_t h = hash3(p + i);
        const int64_t at = static_cast<int64_t>(base + i);
        m_prev[static_cast<size_t>(at) & (window - 1)] = m_head[h];
        m_head[h] = at;
    };
    for (size_t i = start; i < end;)
    {
        uint32_t best = 0, best_dist = 0;
        if (i + min_match <= end)
        {
            int64_t cand = m_head[hash3(p + i)];
            const int64_t here = static_cast<int64_t>(base + i);
            const uint32_t limit = static_cast<uint32_t>(std::min<size_t>(max_match, end - i));
            for (int steps = 0; cand >= 0 && steps < chain; ++steps)
            {
                const int64_t dist = here - cand;
                if (dist <= 0 || dist > static_cast<int64_t>(window) || cand < static_cast<int64_t>(base))
                    break;
                const size_t j = static_cast<size_t>(cand - static_cast<int64_t>(base));
                uint32_t n = 0;
                while (n < limit && p[j + n] == p[i + n])
                    ++n;
                if (n > best)
                {
                    best = n;
                    best_dist = static_cast<uint32_t>(dist);
                    if (n == limit)
                        break;
                }
                cand = m_prev[static_cast<size_t>(cand) & (window - 1)];
            }
        }
        if (best >= min_match)
        {
            match(best, best_dist, out);
            for (uint32_t k = 0; k < best; ++k)
                insert(i + k);
            i += best;
        }
        else
        {
            literal(p[i], out);
            insert(i);
            ++i;
        }
    }
    // The block's end, then an empty stored block whose header ends on a byte: a sync flush.
    code(0, 7, out);
    bits(0, 1, out);
    bits(0, 2, out);
    if (m_bitcount > 0)
        bits(0, 8 - m_bitcount, out);
    out.append("\x00\x00\xff\xff", 4);
}

}   // namespace socketley
