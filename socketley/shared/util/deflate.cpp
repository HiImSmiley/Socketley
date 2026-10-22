#include "deflate.h"

#include <algorithm>
#include <array>

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
// The order the code lengths' code lengths are written in (RFC 1951 3.2.7).
constexpr uint8_t cl_order[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};

uint32_t hash3(const unsigned char* p)
{
    return ((static_cast<uint32_t>(p[0]) << 16 | static_cast<uint32_t>(p[1]) << 8 | p[2]) * 2654435761u) >> 17;
}

// A literal or the end (sym < 257, dist 0), or a match of its length symbol, length and distance.
struct token
{
    uint16_t sym;
    uint16_t length;
    uint16_t dist;
};

int length_index(uint32_t length)
{
    int li = 28;
    while (li > 0 && length_base[li] > length)
        --li;
    return li;
}

int dist_index(uint32_t distance)
{
    int di = 29;
    while (di > 0 && dist_base[di] > distance)
        --di;
    return di;
}

// Code lengths of at most `limit` bits for `freq`: Huffman's, then, where a code passes the limit, the rarest symbols
// lengthened until the lengths again make a code (Kraft's sum), as zlib's builder does; a symbol never used gets none,
// and a code of one symbol is given a second so the decoder has a complete tree.
std::vector<uint8_t> code_lengths(const std::vector<uint32_t>& freq, int limit)
{
    std::vector<uint8_t> len(freq.size(), 0);
    std::vector<uint32_t> used;
    for (size_t i = 0; i < freq.size(); ++i)
        if (freq[i])
            used.push_back(static_cast<uint32_t>(i));
    if (used.empty())
        return len;
    if (used.size() == 1)
    {
        len[used[0]] = 1;
        len[used[0] == 0 ? 1 : 0] = 1;
        return len;
    }
    std::sort(used.begin(), used.end(), [&](uint32_t a, uint32_t b) { return freq[a] < freq[b]; });
    // Two queues, the leaves in order of weight and the joined nodes as they are made, which come out in order too.
    const size_t n = used.size();
    std::vector<uint64_t> weight(2 * n - 1);
    std::vector<int32_t> parent(2 * n - 1, -1);
    for (size_t i = 0; i < n; ++i)
        weight[i] = freq[used[i]];
    size_t leaf = 0, node = n, made = n;
    const auto take = [&]() -> size_t {
        if (leaf < n && (node >= made || weight[leaf] <= weight[node]))
            return leaf++;
        return node++;
    };
    for (; made < 2 * n - 1; ++made)
    {
        const size_t a = take(), b = take();
        weight[made] = weight[a] + weight[b];
        parent[a] = parent[b] = static_cast<int32_t>(made);
    }
    std::vector<int> depth(2 * n - 1, 0);
    for (size_t i = 2 * n - 2; i-- > 0;)
        depth[i] = depth[static_cast<size_t>(parent[i])] + 1;
    bool over = false;
    for (size_t i = 0; i < n; ++i)
    {
        int d = depth[i];
        if (d > limit)
        {
            d = limit;
            over = true;
        }
        len[used[i]] = static_cast<uint8_t>(d);
    }
    if (over)
    {
        uint64_t kraft = 0;
        for (const uint32_t s : used)
            kraft += 1ull << (limit - len[s]);
        const uint64_t full = 1ull << limit;
        // The rarest first: lengthening one of length l takes 2^(limit-l-1) off the sum.
        while (kraft > full)
            for (const uint32_t s : used)
                if (len[s] < limit)
                {
                    kraft -= 1ull << (limit - len[s] - 1);
                    ++len[s];
                    if (kraft <= full)
                        break;
                }
        // What that left over is given back to the most frequent, so the code is complete, as a decoder asks.
        for (bool changed = true; kraft < full && changed;)
        {
            changed = false;
            for (auto it = used.rbegin(); it != used.rend() && kraft < full; ++it)
                if (len[*it] > 1 && kraft + (1ull << (limit - len[*it])) <= full)
                {
                    kraft += 1ull << (limit - len[*it]);
                    --len[*it];
                    changed = true;
                }
        }
    }
    return len;
}

// The canonical codes of `len` (RFC 1951 3.2.2).
std::vector<uint16_t> canonical(const std::vector<uint8_t>& len)
{
    std::array<uint16_t, 16> count{}, next{};
    for (const uint8_t l : len)
        if (l)
            ++count[l];
    uint16_t c = 0;
    for (int bits = 1; bits < 16; ++bits)
    {
        c = static_cast<uint16_t>((c + count[bits - 1]) << 1);
        next[bits] = c;
    }
    std::vector<uint16_t> codes(len.size(), 0);
    for (size_t i = 0; i < len.size(); ++i)
        if (len[i])
            codes[i] = next[len[i]]++;
    return codes;
}

// The code lengths of both alphabets run-length coded with 16, 17 and 18 (RFC 1951 3.2.7): each a symbol and its
// extra bits' value.
std::vector<std::pair<uint8_t, uint8_t>> rle(const std::vector<uint8_t>& lens)
{
    std::vector<std::pair<uint8_t, uint8_t>> out;
    for (size_t i = 0; i < lens.size();)
    {
        const uint8_t l = lens[i];
        size_t run = 1;
        while (i + run < lens.size() && lens[i + run] == l)
            ++run;
        if (l == 0 && run >= 3)
        {
            const size_t n = std::min<size_t>(run, 138);
            out.emplace_back(n >= 11 ? 18 : 17, static_cast<uint8_t>(n >= 11 ? n - 11 : n - 3));
            i += n;
            continue;
        }
        if (l != 0 && run >= 4)
        {
            out.emplace_back(l, 0);
            const size_t n = std::min<size_t>(run - 1, 6);
            out.emplace_back(16, static_cast<uint8_t>(n - 3));
            i += 1 + n;
            continue;
        }
        out.emplace_back(l, 0);
        ++i;
    }
    return out;
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
    const auto insert = [&](size_t i) {
        if (i + min_match > end)
            return;
        const uint32_t h = hash3(p + i);
        const int64_t at = static_cast<int64_t>(base + i);
        m_prev[static_cast<size_t>(at) & (window - 1)] = m_head[h];
        m_head[h] = at;
    };
    // The matches found first, so the block's codes can be made for what it holds.
    std::vector<token> toks;
    toks.reserve(in.size() / 2 + 1);
    std::vector<uint32_t> lit_freq(286, 0), dist_freq(30, 0);
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
            const int li = length_index(best);
            toks.push_back({static_cast<uint16_t>(257 + li), static_cast<uint16_t>(best), static_cast<uint16_t>(best_dist)});
            ++lit_freq[257 + static_cast<size_t>(li)];
            ++dist_freq[static_cast<size_t>(dist_index(best_dist))];
            for (uint32_t k = 0; k < best; ++k)
                insert(i + k);
            i += best;
        }
        else
        {
            toks.push_back({p[i], 0, 0});
            ++lit_freq[p[i]];
            insert(i);
            ++i;
        }
    }
    toks.push_back({256, 0, 0});
    ++lit_freq[256];

    // The fixed codes' cost against the block's own codes and their description, the cheaper written.
    const auto fixed_len = [](uint32_t s) { return s < 144 ? 8 : s < 256 ? 9 : s < 280 ? 7 : 8; };
    uint64_t fixed_bits = 3, extra_bits = 0;
    for (size_t s = 0; s < 286; ++s)
        fixed_bits += static_cast<uint64_t>(lit_freq[s]) * static_cast<uint64_t>(fixed_len(static_cast<uint32_t>(s)));
    for (size_t d = 0; d < 30; ++d)
        fixed_bits += 5ull * dist_freq[d];
    for (size_t li = 0; li < 29; ++li)
        extra_bits += static_cast<uint64_t>(lit_freq[257 + li]) * length_extra[li];
    for (size_t d = 0; d < 30; ++d)
        extra_bits += static_cast<uint64_t>(dist_freq[d]) * dist_extra[d];
    fixed_bits += extra_bits;

    std::vector<uint8_t> lit_len, dist_len;
    if (in.size() >= 1024)
    {
        lit_len = code_lengths(lit_freq, 15);
        dist_len = code_lengths(dist_freq, 15);
    }
    else
    {
        lit_len.assign(286, 8);
        dist_len.assign(30, 5);
    }
    // A block with no match still describes one distance code (RFC 1951 3.2.7).
    if (std::all_of(dist_len.begin(), dist_len.end(), [](uint8_t l) { return l == 0; }))
        dist_len[0] = 1;
    size_t hlit = 286, hdist = 30;
    while (hlit > 257 && lit_len[hlit - 1] == 0)
        --hlit;
    while (hdist > 1 && dist_len[hdist - 1] == 0)
        --hdist;
    std::vector<uint8_t> both(lit_len.begin(), lit_len.begin() + static_cast<long>(hlit));
    both.insert(both.end(), dist_len.begin(), dist_len.begin() + static_cast<long>(hdist));
    const auto runs = rle(both);
    std::vector<uint32_t> cl_freq(19, 0);
    for (const auto& [s, v] : runs)
        ++cl_freq[s];
    const std::vector<uint8_t> cl_len = code_lengths(cl_freq, 7);
    size_t hclen = 19;
    while (hclen > 4 && cl_len[cl_order[hclen - 1]] == 0)
        --hclen;
    uint64_t dyn_bits = 3 + 5 + 5 + 4 + 3 * hclen + extra_bits;
    for (const auto& [s, v] : runs)
        dyn_bits += cl_len[s] + (s == 16 ? 2 : s == 17 ? 3 : s == 18 ? 7 : 0);
    for (size_t s = 0; s < 286; ++s)
        dyn_bits += static_cast<uint64_t>(lit_freq[s]) * lit_len[s];
    for (size_t d = 0; d < 30; ++d)
        dyn_bits += static_cast<uint64_t>(dist_freq[d]) * dist_len[d];

    // A short piece is not worth making codes for: the fixed ones go out at once.
    const bool dynamic = in.size() >= 1024 && dyn_bits < fixed_bits;
    std::vector<uint16_t> lit_code, dist_code;
    if (dynamic)
    {
        lit_code = canonical(lit_len);
        dist_code = canonical(dist_len);
        const std::vector<uint16_t> cl_code = canonical(cl_len);
        bits(0, 1, out);
        bits(2, 2, out);
        bits(static_cast<uint32_t>(hlit - 257), 5, out);
        bits(static_cast<uint32_t>(hdist - 1), 5, out);
        bits(static_cast<uint32_t>(hclen - 4), 4, out);
        for (size_t i = 0; i < hclen; ++i)
            bits(cl_len[cl_order[i]], 3, out);
        for (const auto& [s, v] : runs)
        {
            code(cl_code[s], cl_len[s], out);
            if (s == 16)
                bits(v, 2, out);
            else if (s == 17)
                bits(v, 3, out);
            else if (s == 18)
                bits(v, 7, out);
        }
    }
    else
    {
        // The fixed codes, as RFC 1951 3.2.6 gives them.
        lit_len.assign(288, 0);
        for (size_t s = 0; s < 288; ++s)
            lit_len[s] = static_cast<uint8_t>(s < 144 ? 8 : s < 256 ? 9 : s < 280 ? 7 : 8);
        dist_len.assign(30, 5);
        lit_code = canonical(lit_len);
        dist_code = canonical(dist_len);
        bits(0, 1, out);
        bits(1, 2, out);
    }
    for (const token& t : toks)
    {
        code(lit_code[t.sym], lit_len[t.sym], out);
        if (t.sym <= 256)
            continue;
        const size_t li = t.sym - 257u;
        if (length_extra[li])
            bits(t.length - length_base[li], length_extra[li], out);
        const int di = dist_index(t.dist);
        code(dist_code[static_cast<size_t>(di)], dist_len[static_cast<size_t>(di)], out);
        if (dist_extra[di])
            bits(t.dist - dist_base[di], dist_extra[di], out);
    }
    // An empty stored block whose header ends on a byte: a sync flush.
    bits(0, 1, out);
    bits(0, 2, out);
    if (m_bitcount > 0)
        bits(0, 8 - m_bitcount, out);
    out.append("\x00\x00\xff\xff", 4);
}

}   // namespace socketley
