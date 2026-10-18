#pragma once
// Random identities and tokens, from the kernel's generator.
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <string>
#include <sys/random.h>
#include <unistd.h>

#include "base64.h"
#include "hex.h"

namespace socketley
{

// A number that is never zero, for the identities that must not repeat across a restart: a Raft node, a replica's
// incarnation.

inline uint64_t random_u64()
{
    uint64_t v = 0;
    while (v == 0)
        if (::getrandom(&v, sizeof v, 0) != static_cast<ssize_t>(sizeof v))
            v = static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count()) ^ ::getpid();
    return v;
}

// False when the kernel gave fewer than `n` bytes, which leaves nothing a secret may be made from.
inline bool random_bytes(void* out, size_t n)
{
    auto* p = static_cast<unsigned char*>(out);
    while (n)
    {
        const ssize_t got = ::getrandom(p, n, 0);
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            return false;
        p += got;
        n -= static_cast<size_t>(got);
    }
    return true;
}

// `n` random bytes in base64url, empty when the generator failed.
inline std::string random_b64url(size_t n)
{
    std::string b(n, '\0');
    return random_bytes(b.data(), n) ? base64url::encode(b) : std::string{};
}

// `n` random bytes in hex, empty when the generator failed.
inline std::string random_hex(size_t n, bool upper = false)
{
    std::string b(n, '\0');
    return random_bytes(b.data(), n) ? hex_encode(b, upper) : std::string{};
}

}   // namespace socketley
