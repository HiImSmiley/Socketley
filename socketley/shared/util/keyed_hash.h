#pragma once
// SipHash-2-4 under a key drawn once per process, for a table whose keys a client chooses: without the key nobody can
// pick keys that land in one place, as anybody can for std::hash, whose seed is fixed and whose code is public.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>

#include "random_id.h"

namespace socketley
{

struct sip_key
{
    uint64_t k0{0}, k1{0};
};

// SipHash-2-4 of `s` under `key`, as its reference computes it on a little-endian machine.
inline uint64_t siphash24(const sip_key& key, std::string_view s) noexcept
{
    const auto rotl = [](uint64_t x, int b) { return (x << b) | (x >> (64 - b)); };
    uint64_t v0 = 0x736f6d6570736575ULL ^ key.k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ key.k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ key.k0;
    uint64_t v3 = 0x7465646279746573ULL ^ key.k1;
    const auto sipround = [&] {
        v0 += v1;
        v1 = rotl(v1, 13);
        v1 ^= v0;
        v0 = rotl(v0, 32);
        v2 += v3;
        v3 = rotl(v3, 16);
        v3 ^= v2;
        v0 += v3;
        v3 = rotl(v3, 21);
        v3 ^= v0;
        v2 += v1;
        v1 = rotl(v1, 17);
        v1 ^= v2;
        v2 = rotl(v2, 32);
    };
    const auto* p = reinterpret_cast<const unsigned char*>(s.data());
    const size_t n = s.size();
    const size_t whole = n - n % 8;
    for (size_t i = 0; i < whole; i += 8)
    {
        uint64_t m;
        std::memcpy(&m, p + i, 8);
        v3 ^= m;
        sipround();
        sipround();
        v0 ^= m;
    }
    uint64_t last = static_cast<uint64_t>(n) << 56;
    for (size_t i = 0; i < n % 8; ++i)
        last |= static_cast<uint64_t>(p[whole + i]) << (8 * i);
    v3 ^= last;
    sipround();
    sipround();
    v0 ^= last;
    v2 ^= 0xff;
    sipround();
    sipround();
    sipround();
    sipround();
    return v0 ^ v1 ^ v2 ^ v3;
}

// This process's key, drawn at its first use.
inline const sip_key& process_sip_key() noexcept
{
    static const sip_key key{random_u64(), random_u64()};
    return key;
}

// `s` hashed under this process's key.
inline uint64_t keyed_hash(std::string_view s) noexcept
{
    return siphash24(process_sip_key(), s);
}

}   // namespace socketley
