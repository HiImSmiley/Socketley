#pragma once
// NH under a key drawn once per process, the hash for every table whose strings a client may choose.
//
// libstdc++'s std::hash is Murmur64A with a fixed seed, and Murmur's multicollisions do not depend on the seed: a
// 16-byte block and the same block mixed to its top bit flipped leave its state alike, so n such pairs give 2^n keys
// of one hash, for any seed. NH (UMAC's, and UMASH's first layer) multiplies each 16-byte chunk as (a + k0)(b + k1)
// over 128 bits under secret words, and two strings of one length share a sum with probability 2^-64 over the key.
// It costs what Murmur did, where SipHash cost a cache 30 per cent of its SETs and an MQTT broker 19 per cent.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>

#include "random_id.h"

namespace socketley
{

struct nh_key
{
    // Two words per 16-byte chunk of a 256-byte block, a polynomial's root for longer strings, and the finaliser's.
    uint64_t k[32];
    uint64_t r;
    uint64_t fin;
};

// This process's key, drawn at its first use; a worker forked after that shares it, which no client can learn.
inline const nh_key& process_nh_key() noexcept
{
    static const nh_key key = []
    {
        nh_key k;
        for (uint64_t& w : k.k)
            w = random_u64();
        k.r   = random_u64() & ((uint64_t{1} << 61) - 1);
        k.fin = random_u64();
        return k;
    }();
    return key;
}

namespace nh_detail
{

inline uint64_t ld64(const unsigned char* p) noexcept
{
    uint64_t v;
    std::memcpy(&v, p, 8);
    return v;
}

inline uint64_t ld32(const unsigned char* p) noexcept
{
    uint32_t v;
    std::memcpy(&v, p, 4);
    return v;
}

inline uint64_t fmix(uint64_t x) noexcept
{
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdull;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ull;
    x ^= x >> 33;
    return x;
}

// NH of up to 256 bytes: whole chunks, then the last 16 read overlapping the one before (under 16, overlapping reads
// of what there is), which for one length still reads every byte; the length offsets the first word's key.
inline unsigned __int128 block(const nh_key& K, const unsigned char* p, size_t n) noexcept
{
    using u128 = unsigned __int128;
    if (n <= 16)
    {
        uint64_t a = 0, b = 0;
        if (n >= 8)
        {
            a = ld64(p);
            b = ld64(p + n - 8);
        }
        else if (n >= 4)
            a = ld32(p) | (ld32(p + n - 4) << 32);
        else if (n > 0)
            a = uint64_t{p[0]} | (uint64_t{p[n >> 1]} << 8) | (uint64_t{p[n - 1]} << 16);
        return u128(a + K.k[0] + n) * (b + K.k[1]);
    }
    u128 acc = 0;
    size_t i = 0, j = 0;
    uint64_t off = n;
    for (; i + 16 < n; i += 16, j += 2, off = 0)
        acc += u128(ld64(p + i) + K.k[j] + off) * (ld64(p + i + 8) + K.k[j + 1]);
    return acc + u128(ld64(p + n - 16) + K.k[j] + off) * (ld64(p + n - 8) + K.k[j + 1]);
}

}   // namespace nh_detail

// A string longer than 256 bytes is its blocks' NH sums as a polynomial mod 2^61-1 in the secret root.
inline uint64_t nh_hash(std::string_view s) noexcept
{
    const nh_key& K = process_nh_key();
    const auto* p = reinterpret_cast<const unsigned char*>(s.data());
    const size_t n = s.size();
    uint64_t h;
    if (n <= 256)
    {
        const unsigned __int128 a = nh_detail::block(K, p, n);
        h = static_cast<uint64_t>(a) ^ (static_cast<uint64_t>(a >> 64) * 0x9E3779B97F4A7C15ull);
    }
    else
    {
        constexpr uint64_t P = (uint64_t{1} << 61) - 1;
        uint64_t acc = 0;
        for (size_t i = 0; i < n; i += 256)
        {
            const size_t m = n - i < 256 ? n - i : 256;
            const unsigned __int128 a = nh_detail::block(K, p + i, m);
            const uint64_t w = (static_cast<uint64_t>(a) ^ static_cast<uint64_t>(a >> 64)) & P;
            const unsigned __int128 x = static_cast<unsigned __int128>(acc) * K.r;
            uint64_t r = (static_cast<uint64_t>(x) & P) + static_cast<uint64_t>(x >> 61);
            r = r >= P ? r - P : r;
            acc = r + w;
            acc = acc >= P ? acc - P : acc;
        }
        h = acc ^ n;
    }
    return nh_detail::fmix(h ^ K.fin);
}

}   // namespace socketley
