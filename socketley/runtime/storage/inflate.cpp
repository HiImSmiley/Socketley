#include "inflate.h"

#include <algorithm>

namespace socketley::storage
{

namespace
{

constexpr uint16_t length_base[29] = {3,  4,  5,  6,  7,  8,  9,  10, 11,  13,  15,  17,  19,  23, 27,
                                      31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
constexpr uint8_t  length_extra[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
                                       2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
constexpr uint16_t dist_base[30] = {1,   2,   3,   4,   5,   7,    9,    13,   17,   25,   33,   49,   65,    97,    129,
                                    193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
constexpr uint8_t  dist_extra[30] = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6,
                                     6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};
// The order a dynamic block lists its code-length code's lengths in.
constexpr uint8_t  clen_order[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};

}   // namespace

bool inflater::huffman::build(const uint8_t* lengths, unsigned n)
{
    std::fill(std::begin(count), std::end(count), uint16_t{0});
    for (unsigned s = 0; s < n; ++s)
        ++count[lengths[s]];
    // More codes of a length than the shorter ones leave room for is no prefix code.
    int left = 1;
    for (unsigned len = 1; len < 16; ++len)
    {
        left <<= 1;
        left -= count[len];
        if (left < 0)
            return false;
    }
    uint16_t offs[16]{};
    for (unsigned len = 1; len < 15; ++len)
        offs[len + 1] = static_cast<uint16_t>(offs[len] + count[len]);
    symbol.assign(n, 0);
    for (unsigned s = 0; s < n; ++s)
        if (lengths[s])
            symbol[offs[lengths[s]]++] = static_cast<uint16_t>(s);

    // The first look: each code reversed, since a code's first bit is the lowest of what is read.
    fast.assign(1u << fast_bits, 0);
    uint32_t code = 0;
    unsigned idx  = 0;
    for (unsigned len = 1; len <= fast_bits; ++len)
    {
        for (unsigned k = 0; k < count[len]; ++k, ++code, ++idx)
        {
            uint32_t rev = 0;
            for (unsigned b = 0; b < len; ++b)
                rev |= ((code >> b) & 1u) << (len - 1 - b);
            for (uint32_t i = rev; i < (1u << fast_bits); i += 1u << len)
                fast[i] = static_cast<uint16_t>((symbol[idx] << 4) | len);
        }
        code <<= 1;
    }
    return true;
}

void inflater::feed(const uint8_t* p, size_t n)
{
    m_in.append(reinterpret_cast<const char*>(p), n);
}

void inflater::compact()
{
    const size_t used = static_cast<size_t>(m_bit >> 3);
    if (used == 0)
        return;
    m_in.erase(0, used);
    m_bit -= static_cast<uint64_t>(used) << 3;
}

bool inflater::bits(unsigned n, uint32_t& v)
{
    if (m_bit + n > static_cast<uint64_t>(m_in.size()) << 3)
        return false;
    v = 0;
    for (unsigned got = 0; got < n;)
    {
        const auto byte  = static_cast<uint8_t>(m_in[static_cast<size_t>(m_bit >> 3)]);
        const unsigned at   = static_cast<unsigned>(m_bit & 7);
        const unsigned take = std::min(8 - at, n - got);
        v |= static_cast<uint32_t>((byte >> at) & ((1u << take) - 1)) << got;
        got += take;
        m_bit += take;
    }
    return true;
}

bool inflater::decode(const huffman& h, unsigned& sym)
{
    uint32_t peek = 0;
    const uint64_t at = m_bit;
    if (bits(huffman::fast_bits, peek))
    {
        const uint16_t e = h.fast[peek];
        if (e)
        {
            m_bit = at + (e & 15);
            sym   = e >> 4;
            return true;
        }
        m_bit = at;
    }
    // A long code, or the input's last few bits: one bit at a time, as RFC 1951's canonical codes are counted.
    int code = 0, first = 0, index = 0;
    for (unsigned len = 1; len < 16; ++len)
    {
        uint32_t b = 0;
        if (!bits(1, b))
            return false;
        code |= static_cast<int>(b);
        const int count = h.count[len];
        if (code - count < first)
        {
            sym = h.symbol[static_cast<size_t>(index + (code - first))];
            return true;
        }
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    m_at = state::failed;   // a code no table holds
    return false;
}

void inflater::put(uint8_t b, std::string& out)
{
    out.push_back(static_cast<char>(b));
    m_window[m_wpos] = b;
    m_wpos = (m_wpos + 1) & 32767;
    ++m_produced;
}

bool inflater::dynamic_tables()
{
    uint32_t hlit = 0, hdist = 0, hclen = 0;
    if (!bits(5, hlit) || !bits(5, hdist) || !bits(4, hclen))
        return false;
    hlit += 257;
    hdist += 1;
    hclen += 4;
    if (hlit > 286 || hdist > 30)
    {
        m_at = state::failed;
        return false;
    }
    uint8_t clen[19]{};
    for (unsigned i = 0; i < hclen; ++i)
    {
        uint32_t v = 0;
        if (!bits(3, v))
            return false;
        clen[clen_order[i]] = static_cast<uint8_t>(v);
    }
    huffman lencode;
    if (!lencode.build(clen, 19))
    {
        m_at = state::failed;
        return false;
    }
    uint8_t lengths[286 + 30]{};
    for (unsigned i = 0; i < hlit + hdist;)
    {
        unsigned sym = 0;
        if (!decode(lencode, sym))
            return false;
        if (sym < 16)
        {
            lengths[i++] = static_cast<uint8_t>(sym);
            continue;
        }
        uint8_t  fill = 0;
        uint32_t rep  = 0;
        if (sym == 16)
        {
            if (i == 0)
            {
                m_at = state::failed;
                return false;
            }
            fill = lengths[i - 1];
            if (!bits(2, rep))
                return false;
            rep += 3;
        }
        else if (sym == 17)
        {
            if (!bits(3, rep))
                return false;
            rep += 3;
        }
        else
        {
            if (!bits(7, rep))
                return false;
            rep += 11;
        }
        if (i + rep > hlit + hdist)
        {
            m_at = state::failed;
            return false;
        }
        while (rep--)
            lengths[i++] = fill;
    }
    // A block with no end-of-block code could never end.
    if (lengths[256] == 0 || !m_lit.build(lengths, hlit) || !m_dist.build(lengths + hlit, hdist))
    {
        m_at = state::failed;
        return false;
    }
    return true;
}

inflater::result inflater::run(std::string& out, size_t max_out)
{
    size_t given = 0;
    for (;;)
    {
        while (m_copy_left && given < max_out)
        {
            put(m_window[(m_wpos - m_copy_dist) & 32767], out);
            --m_copy_left;
            ++given;
        }
        if (m_at == state::finished)
            return result::done;
        if (m_at == state::failed)
            return result::bad;
        if (given >= max_out)
            return result::output_full;

        // Each step below is taken whole or not at all: one that runs out of input goes back to where it began.
        const uint64_t mark = m_bit;
        bool ok = true;
        switch (m_at)
        {
            case state::header:
            {
                uint32_t h = 0;
                if (!(ok = bits(3, h)))
                    break;
                m_last = h & 1;
                const uint32_t type = h >> 1;
                if (type == 0)
                    m_at = state::stored_len;
                else if (type == 1)
                {
                    uint8_t lengths[288 + 30];
                    std::fill(lengths, lengths + 144, uint8_t{8});
                    std::fill(lengths + 144, lengths + 256, uint8_t{9});
                    std::fill(lengths + 256, lengths + 280, uint8_t{7});
                    std::fill(lengths + 280, lengths + 288, uint8_t{8});
                    std::fill(lengths + 288, lengths + 318, uint8_t{5});
                    m_lit.build(lengths, 288);
                    m_dist.build(lengths + 288, 30);
                    m_at = state::codes;
                }
                else if (type == 2)
                {
                    if ((ok = dynamic_tables()))
                        m_at = state::codes;
                }
                else
                    m_at = state::failed;
                break;
            }
            case state::stored_len:
            {
                m_bit = (m_bit + 7) & ~uint64_t{7};
                uint32_t len = 0, nlen = 0;
                if (!(ok = bits(16, len) && bits(16, nlen)))
                    break;
                if ((len ^ 0xffff) != nlen)
                {
                    m_at = state::failed;
                    break;
                }
                m_stored_left = len;
                m_at = len ? state::stored_copy : (m_last ? state::finished : state::header);
                break;
            }
            case state::stored_copy:
            {
                const size_t have = m_in.size() - static_cast<size_t>(m_bit >> 3);
                const size_t n    = std::min<size_t>({m_stored_left, have, max_out - given});
                if (n == 0)
                {
                    ok = false;
                    break;
                }
                const auto* p = reinterpret_cast<const uint8_t*>(m_in.data()) + (m_bit >> 3);
                for (size_t i = 0; i < n; ++i)
                    put(p[i], out);
                m_bit += static_cast<uint64_t>(n) << 3;
                given += n;
                m_stored_left -= static_cast<uint32_t>(n);
                if (m_stored_left == 0)
                    m_at = m_last ? state::finished : state::header;
                break;
            }
            case state::codes:
            {
                unsigned sym = 0;
                if (!(ok = decode(m_lit, sym)))
                    break;
                if (sym < 256)
                {
                    put(static_cast<uint8_t>(sym), out);
                    ++given;
                    break;
                }
                if (sym == 256)
                {
                    m_at = m_last ? state::finished : state::header;
                    break;
                }
                sym -= 257;
                if (sym >= 29)
                {
                    m_at = state::failed;
                    break;
                }
                uint32_t extra = 0, dextra = 0;
                unsigned dsym = 0;
                if (!(ok = bits(length_extra[sym], extra) && decode(m_dist, dsym)))
                    break;
                if (dsym >= 30)
                {
                    m_at = state::failed;
                    break;
                }
                if (!(ok = bits(dist_extra[dsym], dextra)))
                    break;
                const uint32_t dist = dist_base[dsym] + dextra;
                if (dist > m_produced)
                {
                    m_at = state::failed;
                    break;
                }
                m_copy_left = length_base[sym] + extra;
                m_copy_dist = dist;
                break;
            }
            case state::finished:
            case state::failed:
                break;
        }
        if (ok || m_at == state::failed)
            continue;
        m_bit = mark;
        if (m_ended)
        {
            m_at = state::failed;
            return result::bad;
        }
        compact();
        return result::need_input;
    }
}

}   // namespace socketley::storage
