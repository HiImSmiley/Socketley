#include "lz4_block.h"

#include <cstring>

namespace socketley::storage
{

namespace
{

constexpr size_t min_match   = 4;
// The block's last five bytes are literals, and its last match begins at least twelve bytes before its end.
constexpr size_t last_literals = 5;
constexpr size_t match_limit   = 12;
constexpr int    hash_log      = 14;

uint32_t read32(const uint8_t* p)
{
    uint32_t v;
    std::memcpy(&v, p, 4);
    return v;
}

uint32_t hash4(uint32_t v)
{
    return (v * 2654435761u) >> (32 - hash_log);
}

// A length past the token's fifteen, as runs of 255 and a last byte below it.
uint8_t* put_length(uint8_t* op, size_t len)
{
    while (len >= 255)
    {
        *op++ = 255;
        len -= 255;
    }
    *op++ = static_cast<uint8_t>(len);
    return op;
}

uint8_t* put_sequence(uint8_t* op, const uint8_t* lit, size_t lit_len, size_t offset, size_t match_len, bool last)
{
    uint8_t* token = op++;
    const size_t ml = last ? 0 : match_len - min_match;
    *token = static_cast<uint8_t>((lit_len >= 15 ? 15 : lit_len) << 4 | (last ? 0 : (ml >= 15 ? 15 : ml)));
    if (lit_len >= 15)
        op = put_length(op, lit_len - 15);
    std::memcpy(op, lit, lit_len);
    op += lit_len;
    if (last)
        return op;
    *op++ = static_cast<uint8_t>(offset);
    *op++ = static_cast<uint8_t>(offset >> 8);
    if (ml >= 15)
        op = put_length(op, ml - 15);
    return op;
}

}   // namespace

size_t lz4_compress(const uint8_t* in, size_t n, uint8_t* out)
{
    uint8_t* op = out;
    const uint8_t* anchor = in;
    if (n > match_limit)
    {
        static thread_local uint32_t table[1u << hash_log];
        std::memset(table, 0, sizeof table);
        const uint8_t* const end   = in + n;
        const uint8_t* const limit = end - match_limit;
        const uint8_t* ip = in + 1;
        while (ip < limit)
        {
            const uint32_t seq  = read32(ip);
            const uint32_t h    = hash4(seq);
            // The table holds a position plus one, so zero is a slot nothing was put in.
            const uint32_t prev = table[h];
            table[h] = static_cast<uint32_t>(ip - in) + 1;
            const uint8_t* ref = in + (prev ? prev - 1 : 0);
            if (prev == 0 || ip - ref > 65535 || read32(ref) != seq)
            {
                ++ip;
                continue;
            }
            // Extend backwards over equal bytes, then forwards up to where the last literals begin.
            while (ip > anchor && ref > in && ip[-1] == ref[-1])
            {
                --ip;
                --ref;
            }
            const uint8_t* m = ip + min_match;
            const uint8_t* r = ref + min_match;
            const uint8_t* const match_end_limit = end - last_literals;
            while (m < match_end_limit && *m == *r)
            {
                ++m;
                ++r;
            }
            op = put_sequence(op, anchor, static_cast<size_t>(ip - anchor), static_cast<size_t>(ip - ref),
                              static_cast<size_t>(m - ip), false);
            ip = anchor = m;
        }
    }
    return static_cast<size_t>(put_sequence(op, anchor, static_cast<size_t>(in + n - anchor), 0, 0, true) - out);
}

long lz4_decompress(const uint8_t* in, size_t n, uint8_t* out, size_t cap)
{
    const uint8_t* ip = in;
    const uint8_t* const iend = in + n;
    uint8_t* op = out;
    uint8_t* const oend = out + cap;
    const auto length = [&](size_t len) -> long
    {
        if (len != 15)
            return static_cast<long>(len);
        for (;;)
        {
            if (ip >= iend)
                return -1;
            const uint8_t b = *ip++;
            len += b;
            if (b != 255)
                return static_cast<long>(len);
        }
    };
    while (ip < iend)
    {
        const uint8_t token = *ip++;
        const long lit = length(token >> 4);
        if (lit < 0 || static_cast<size_t>(iend - ip) < static_cast<size_t>(lit) ||
            static_cast<size_t>(oend - op) < static_cast<size_t>(lit))
            return -1;
        std::memcpy(op, ip, static_cast<size_t>(lit));
        op += lit;
        ip += lit;
        // The last sequence ends with its literals.
        if (ip == iend)
            break;
        if (iend - ip < 2)
            return -1;
        const size_t offset = static_cast<size_t>(ip[0]) | static_cast<size_t>(ip[1]) << 8;
        ip += 2;
        const long ml = length(token & 15);
        if (ml < 0 || offset == 0 || static_cast<size_t>(op - out) < offset)
            return -1;
        const size_t match = static_cast<size_t>(ml) + min_match;
        if (static_cast<size_t>(oend - op) < match)
            return -1;
        // A match may overlap what it writes, so it is copied a byte at a time when it is close.
        const uint8_t* from = op - offset;
        if (offset >= match)
            std::memcpy(op, from, match);
        else
            for (size_t i = 0; i < match; ++i)
                op[i] = from[i];
        op += match;
    }
    return static_cast<long>(op - out);
}

}   // namespace socketley::storage
