#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

// CRC-32 (IEEE, as zlib, gzip and zip use it) and CRC-32C (Castagnoli), the two every format here checks with.
namespace socketley::crc
{

namespace detail
{
// Slicing-by-8: row k is the CRC of a byte followed by k zero bytes, so eight
// bytes fold in one step of eight independent lookups.
struct table8
{
    uint32_t v[8][256];
};

inline constexpr table8 make_table8(uint32_t poly)
{
    table8 t{};
    for (uint32_t i = 0; i < 256; ++i)
    {
        uint32_t c = i;
        for (int k = 0; k < 8; ++k)
            c = (c & 1u) ? (poly ^ (c >> 1)) : (c >> 1);
        t.v[0][i] = c;
    }
    for (uint32_t i = 0; i < 256; ++i)
        for (int k = 1; k < 8; ++k)
            t.v[k][i] = t.v[0][t.v[k - 1][i] & 0xFFu] ^ (t.v[k - 1][i] >> 8);
    return t;
}

// Built at compile time, because pasting 256 constants is how a table acquires a typo.
inline constexpr table8 ieee = make_table8(0xEDB88320u);
inline constexpr table8 castagnoli = make_table8(0x82F63B78u);

inline uint32_t sliced(const table8& tab, uint32_t c, const void* data, size_t n)
{
    const auto* p = static_cast<const unsigned char*>(data);
    const auto& t = tab.v;
    while (n >= 8)
    {
        const uint32_t lo = c ^ (uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16
                                 | uint32_t(p[3]) << 24);
        c = t[7][lo & 0xFFu] ^ t[6][(lo >> 8) & 0xFFu] ^ t[5][(lo >> 16) & 0xFFu] ^ t[4][lo >> 24]
          ^ t[3][p[4]] ^ t[2][p[5]] ^ t[1][p[6]] ^ t[0][p[7]];
        p += 8;
        n -= 8;
    }
    while (n--)
        c = t[0][(c ^ *p++) & 0xFFu] ^ (c >> 8);
    return c;
}
} // namespace detail

// The register itself, neither inverted on the way in nor out, for a caller that folds part of the input elsewhere.
inline uint32_t crc32_register(uint32_t reg, const void* p, size_t n)
{
    return detail::sliced(detail::ieee, reg, p, n);
}

// `crc` is the result over the bytes before these, 0 to begin.
inline uint32_t crc32(const void* p, size_t n, uint32_t crc = 0)
{
    return ~crc32_register(~crc, p, n);
}

inline uint32_t crc32(std::string_view s, uint32_t crc = 0)
{
    return crc32(s.data(), s.size(), crc);
}

// `crc` is the result over the bytes before these, 0 to begin; SSE4.2 computes it where the CPU has it.
uint32_t crc32c(const void* p, size_t n, uint32_t crc = 0);

inline uint32_t crc32c(std::string_view s, uint32_t crc = 0)
{
    return crc32c(s.data(), s.size(), crc);
}

} // namespace socketley::crc
