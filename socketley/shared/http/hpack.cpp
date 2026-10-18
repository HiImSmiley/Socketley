#include "hpack.h"

#include <algorithm>
#include <utility>

namespace socketley::hpack
{

namespace
{

// The Huffman code of RFC 7541 Appendix B: each symbol's code, right-aligned, and its length in bits; 256 is EOS.
constexpr uint32_t huff_code[257] = {
    0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5, 0xfffffe6, 0xfffffe7,
    0xfffffe8, 0xffffea, 0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb, 0xfffffec,
    0xfffffed, 0xfffffee, 0xfffffef, 0xffffff0, 0xffffff1, 0xffffff2, 0x3ffffffe, 0xffffff3,
    0xffffff4, 0xffffff5, 0xffffff6, 0xffffff7, 0xffffff8, 0xffffff9, 0xffffffa, 0xffffffb,
    0x14, 0x3f8, 0x3f9, 0xffa, 0x1ff9, 0x15, 0xf8, 0x7fa,
    0x3fa, 0x3fb, 0xf9, 0x7fb, 0xfa, 0x16, 0x17, 0x18,
    0x0, 0x1, 0x2, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
    0x1e, 0x1f, 0x5c, 0xfb, 0x7ffc, 0x20, 0xffb, 0x3fc,
    0x1ffa, 0x21, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62,
    0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
    0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72,
    0xfc, 0x73, 0xfd, 0x1ffb, 0x7fff0, 0x1ffc, 0x3ffc, 0x22,
    0x7ffd, 0x3, 0x23, 0x4, 0x24, 0x5, 0x25, 0x26,
    0x27, 0x6, 0x74, 0x75, 0x28, 0x29, 0x2a, 0x7,
    0x2b, 0x76, 0x2c, 0x8, 0x9, 0x2d, 0x77, 0x78,
    0x79, 0x7a, 0x7b, 0x7ffe, 0x7fc, 0x3ffd, 0x1ffd, 0xffffffc,
    0xfffe6, 0x3fffd2, 0xfffe7, 0xfffe8, 0x3fffd3, 0x3fffd4, 0x3fffd5, 0x7fffd9,
    0x3fffd6, 0x7fffda, 0x7fffdb, 0x7fffdc, 0x7fffdd, 0x7fffde, 0xffffeb, 0x7fffdf,
    0xffffec, 0xffffed, 0x3fffd7, 0x7fffe0, 0xffffee, 0x7fffe1, 0x7fffe2, 0x7fffe3,
    0x7fffe4, 0x1fffdc, 0x3fffd8, 0x7fffe5, 0x3fffd9, 0x7fffe6, 0x7fffe7, 0xffffef,
    0x3fffda, 0x1fffdd, 0xfffe9, 0x3fffdb, 0x3fffdc, 0x7fffe8, 0x7fffe9, 0x1fffde,
    0x7fffea, 0x3fffdd, 0x3fffde, 0xfffff0, 0x1fffdf, 0x3fffdf, 0x7fffeb, 0x7fffec,
    0x1fffe0, 0x1fffe1, 0x3fffe0, 0x1fffe2, 0x7fffed, 0x3fffe1, 0x7fffee, 0x7fffef,
    0xfffea, 0x3fffe2, 0x3fffe3, 0x3fffe4, 0x7ffff0, 0x3fffe5, 0x3fffe6, 0x7ffff1,
    0x3ffffe0, 0x3ffffe1, 0xfffeb, 0x7fff1, 0x3fffe7, 0x7ffff2, 0x3fffe8, 0x1ffffec,
    0x3ffffe2, 0x3ffffe3, 0x3ffffe4, 0x7ffffde, 0x7ffffdf, 0x3ffffe5, 0xfffff1, 0x1ffffed,
    0x7fff2, 0x1fffe3, 0x3ffffe6, 0x7ffffe0, 0x7ffffe1, 0x3ffffe7, 0x7ffffe2, 0xfffff2,
    0x1fffe4, 0x1fffe5, 0x3ffffe8, 0x3ffffe9, 0xffffffd, 0x7ffffe3, 0x7ffffe4, 0x7ffffe5,
    0xfffec, 0xfffff3, 0xfffed, 0x1fffe6, 0x3fffe9, 0x1fffe7, 0x1fffe8, 0x7ffff3,
    0x3fffea, 0x3fffeb, 0x1ffffee, 0x1ffffef, 0xfffff4, 0xfffff5, 0x3ffffea, 0x7ffff4,
    0x3ffffeb, 0x7ffffe6, 0x3ffffec, 0x3ffffed, 0x7ffffe7, 0x7ffffe8, 0x7ffffe9, 0x7ffffea,
    0x7ffffeb, 0xffffffe, 0x7ffffec, 0x7ffffed, 0x7ffffee, 0x7ffffef, 0x7fffff0, 0x3ffffee,
    0x3fffffff,
};
constexpr uint8_t huff_len[257] = {
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
    28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
    5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
    13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
    15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
    6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
    20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
    24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
    22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
    21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
    19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
    20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
    26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
    30,
};
// RFC 7541 Appendix A, indexed from 1.
constexpr std::pair<std::string_view, std::string_view> static_table[61] = {
    {":authority", ""},
    {":method", "GET"},
    {":method", "POST"},
    {":path", "/"},
    {":path", "/index.html"},
    {":scheme", "http"},
    {":scheme", "https"},
    {":status", "200"},
    {":status", "204"},
    {":status", "206"},
    {":status", "304"},
    {":status", "400"},
    {":status", "404"},
    {":status", "500"},
    {"accept-charset", ""},
    {"accept-encoding", "gzip, deflate"},
    {"accept-language", ""},
    {"accept-ranges", ""},
    {"accept", ""},
    {"access-control-allow-origin", ""},
    {"age", ""},
    {"allow", ""},
    {"authorization", ""},
    {"cache-control", ""},
    {"content-disposition", ""},
    {"content-encoding", ""},
    {"content-language", ""},
    {"content-length", ""},
    {"content-location", ""},
    {"content-range", ""},
    {"content-type", ""},
    {"cookie", ""},
    {"date", ""},
    {"etag", ""},
    {"expect", ""},
    {"expires", ""},
    {"from", ""},
    {"host", ""},
    {"if-match", ""},
    {"if-modified-since", ""},
    {"if-none-match", ""},
    {"if-range", ""},
    {"if-unmodified-since", ""},
    {"last-modified", ""},
    {"link", ""},
    {"location", ""},
    {"max-forwards", ""},
    {"proxy-authenticate", ""},
    {"proxy-authorization", ""},
    {"range", ""},
    {"referer", ""},
    {"refresh", ""},
    {"retry-after", ""},
    {"server", ""},
    {"set-cookie", ""},
    {"strict-transport-security", ""},
    {"transfer-encoding", ""},
    {"user-agent", ""},
    {"vary", ""},
    {"via", ""},
    {"www-authenticate", ""},
};

// The Huffman code is canonical: codes of one length are consecutive, ordered by symbol, and each length's first code
// follows the last of the length before. Decoding walks the lengths with their counts as inflate does.
struct huffman_index
{
    uint16_t count[31]{};
    uint32_t first[31]{};
    uint16_t offset[31]{};
    uint16_t symbol[257]{};
    // By the next eight bits, the symbol whose code is that long or shorter and its length; 0 for a longer code.
    uint8_t  fast_sym[256]{};
    uint8_t  fast_len[256]{};

    huffman_index()
    {
        for (unsigned s = 0; s < 256; ++s)
            if (const unsigned len = huff_len[s]; len <= 8)
                for (uint32_t t = huff_code[s] << (8 - len), e = t + (1u << (8 - len)); t < e; ++t)
                {
                    fast_sym[t] = static_cast<uint8_t>(s);
                    fast_len[t] = static_cast<uint8_t>(len);
                }
        for (unsigned s = 0; s < 257; ++s)
            ++count[huff_len[s]];
        uint16_t at = 0;
        for (unsigned len = 1; len <= 30; ++len)
        {
            offset[len] = at;
            at = static_cast<uint16_t>(at + count[len]);
        }
        uint16_t fill[31]{};
        // Symbols of one length in the order of their codes.
        for (unsigned len = 1; len <= 30; ++len)
        {
            uint32_t lowest = 0xffffffffu;
            for (unsigned s = 0; s < 257; ++s)
                if (huff_len[s] == len)
                {
                    lowest = std::min(lowest, huff_code[s]);
                    symbol[offset[len] + fill[len]++] = static_cast<uint16_t>(s);
                }
            first[len] = lowest;
            std::sort(symbol + offset[len], symbol + offset[len] + count[len],
                      [](uint16_t a, uint16_t b) { return huff_code[a] < huff_code[b]; });
        }
    }
};

const huffman_index& index()
{
    static const huffman_index h;
    return h;
}

// An HPACK integer with an N-bit prefix, from `p`; false when it runs past the end or past 2^32.
bool read_int(std::string_view b, size_t& at, unsigned prefix, uint64_t& v)
{
    if (at >= b.size())
        return false;
    const unsigned mask = (1u << prefix) - 1;
    v = static_cast<uint8_t>(b[at++]) & mask;
    if (v < mask)
        return true;
    for (unsigned shift = 0; shift <= 28; shift += 7)
    {
        if (at >= b.size())
            return false;
        const auto byte = static_cast<uint8_t>(b[at++]);
        v += static_cast<uint64_t>(byte & 0x7f) << shift;
        if (!(byte & 0x80))
            return v <= 0xffffffffull;
    }
    return false;
}

void write_int(std::string& out, uint8_t first_bits, unsigned prefix, uint64_t v)
{
    const unsigned mask = (1u << prefix) - 1;
    if (v < mask)
    {
        out += static_cast<char>(first_bits | v);
        return;
    }
    out += static_cast<char>(first_bits | mask);
    v -= mask;
    while (v >= 0x80)
    {
        out += static_cast<char>(0x80 | (v & 0x7f));
        v >>= 7;
    }
    out += static_cast<char>(v);
}

bool read_string(std::string_view b, size_t& at, std::string& out)
{
    if (at >= b.size())
        return false;
    const bool huff = static_cast<uint8_t>(b[at]) & 0x80;
    uint64_t len = 0;
    if (!read_int(b, at, 7, len) || len > b.size() - at)
        return false;
    const std::string_view s = b.substr(at, static_cast<size_t>(len));
    at += static_cast<size_t>(len);
    out.clear();
    if (!huff)
    {
        out.assign(s);
        return true;
    }
    return huffman_decode(s, out);
}

void write_string(std::string& out, std::string_view s)
{
    write_int(out, 0, 7, s.size());
    out.append(s);
}

constexpr size_t entry_overhead = 32;

}   // namespace

uint32_t huffman_code(unsigned sym, unsigned& len)
{
    len = huff_len[sym];
    return huff_code[sym];
}

bool huffman_decode(std::string_view in, std::string& out)
{
    const huffman_index& h = index();
    // The unread bits, highest first; whatever lies below `nb` is zero.
    uint64_t acc = 0;
    unsigned nb  = 0;
    size_t   i   = 0;
    out.reserve(out.size() + in.size() * 8 / 5);
    for (;;)
    {
        while (nb <= 56 && i < in.size())
        {
            acc |= static_cast<uint64_t>(static_cast<uint8_t>(in[i++])) << (56 - nb);
            nb += 8;
        }
        if (nb == 0)
            return true;

        // Eight bits at a time for the codes that short, which are most of what a header holds.
        if (const unsigned top = static_cast<unsigned>(acc >> 56); h.fast_len[top] && h.fast_len[top] <= nb)
        {
            out += static_cast<char>(h.fast_sym[top]);
            acc <<= h.fast_len[top];
            nb  -= h.fast_len[top];
            continue;
        }

        // A longer code, bit by bit from nine, as the canonical table counts them.
        uint32_t code = static_cast<uint32_t>(acc >> 56);
        unsigned len  = 8;
        bool     hit  = false;
        if (nb > 8)
            while (len < 30 && len < nb)
            {
                code = (code << 1) | static_cast<uint32_t>((acc >> (63 - len)) & 1u);
                ++len;
                if (h.count[len] && code >= h.first[len] && code - h.first[len] < h.count[len])
                {
                    const uint16_t sym = h.symbol[h.offset[len] + (code - h.first[len])];
                    if (sym == 256)
                        return false;   // EOS inside a string is an error
                    out += static_cast<char>(sym);
                    acc <<= len;
                    nb  -= len;
                    hit  = true;
                    break;
                }
            }
        if (hit)
            continue;

        // No code ends in what is left, which is padding only if every byte is read, it is under eight bits, and
        // those are the high bits of EOS, all ones.
        if (i < in.size() || nb >= 8)
            return false;
        return (acc >> (64 - nb)) == (1u << nb) - 1;
    }
}

bool decoder::entry(uint64_t index, const header*& h) const
{
    static header statics[61];
    static const bool filled = []
    {
        for (size_t i = 0; i < 61; ++i)
            statics[i] = {std::string(static_table[i].first), std::string(static_table[i].second)};
        return true;
    }();
    (void)filled;
    if (index == 0)
        return false;
    if (index <= 61)
    {
        h = &statics[index - 1];
        return true;
    }
    index -= 62;
    if (index >= m_table.size())
        return false;
    h = &m_table[static_cast<size_t>(index)];
    return true;
}

void decoder::evict()
{
    while (m_size > m_max && !m_table.empty())
    {
        m_size -= m_table.back().name.size() + m_table.back().value.size() + entry_overhead;
        m_table.pop_back();
    }
}

void decoder::insert(header h)
{
    const size_t n = h.name.size() + h.value.size() + entry_overhead;
    // An entry larger than the table empties it and is not kept.
    if (n > m_max)
    {
        m_table.clear();
        m_size = 0;
        return;
    }
    m_size += n;
    m_table.push_front(std::move(h));
    evict();
}

decoder::result decoder::decode(std::string_view b, std::vector<header>& out, size_t max_list)
{
    size_t at = 0, listed = 0;
    bool over = false, fields = false;
    // A list past its limit is still decoded to its end, so the table stays in step, but nothing more of it is kept:
    // a block of one-byte references to a large entry costs a count, not a copy each.
    auto add = [&](const header& h)
    {
        fields = true;
        listed += h.name.size() + h.value.size() + entry_overhead;
        if (listed > max_list)
            over = true;
        if (!over)
            out.push_back(h);
    };
    while (at < b.size())
    {
        const auto first = static_cast<uint8_t>(b[at]);
        uint64_t idx = 0;
        if (first & 0x80)
        {
            // Indexed field.
            const header* h = nullptr;
            if (!read_int(b, at, 7, idx) || !entry(idx, h))
                return result::error;
            add(*h);
        }
        else if ((first & 0xe0) == 0x20)
        {
            // A dynamic table size update, only before the block's first field and within what the settings allow.
            if (fields || !read_int(b, at, 5, idx) || idx > m_limit)
                return result::error;
            m_max = static_cast<size_t>(idx);
            evict();
        }
        else
        {
            // A literal: with incremental indexing (01), without (0000) or never indexed (0001).
            const bool indexing = (first & 0xc0) == 0x40;
            if (!read_int(b, at, indexing ? 6 : 4, idx))
                return result::error;
            header h;
            if (idx)
            {
                const header* named = nullptr;
                if (!entry(idx, named))
                    return result::error;
                h.name = named->name;
            }
            else if (!read_string(b, at, h.name))
                return result::error;
            if (!read_string(b, at, h.value))
                return result::error;
            add(h);
            if (indexing)
                insert(std::move(h));
        }
    }
    return over ? result::too_large : result::ok;
}

void encode(std::string& out, std::string_view name, std::string_view value)
{
    size_t name_index = 0;
    for (size_t i = 0; i < 61; ++i)
        if (static_table[i].first == name)
        {
            if (static_table[i].second == value && !value.empty())
            {
                write_int(out, 0x80, 7, i + 1);
                return;
            }
            if (!name_index)
                name_index = i + 1;
        }
    write_int(out, 0x00, 4, name_index);
    if (!name_index)
        write_string(out, name);
    write_string(out, value);
}

}   // namespace socketley::hpack
