#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

// HMACs under a secret and the comparison of what they make, never both by one caller's own hand.
namespace socketley::crypto
{

inline constexpr size_t sha256_bytes = 32;

// The raw HMAC-SHA256 of `msg` under `key` into the 32 bytes at `out`; false when OpenSSL could not compute it, which
// leaves them unusable.
inline bool hmac_sha256(std::string_view key, std::string_view msg, uint8_t* out)
{
    unsigned int n = 0;
    return HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
                reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), out, &n) != nullptr &&
           n == sha256_bytes;
}

// The same 32 bytes as a string, empty on failure.
inline std::string hmac_sha256(std::string_view key, std::string_view msg)
{
    uint8_t out[sha256_bytes];
    return hmac_sha256(key, msg, out) ? std::string(reinterpret_cast<const char*>(out), sizeof out) : std::string{};
}

// HMAC-SHA1, which only AWS Signature Version 2 still asks for; empty on failure.
inline std::string hmac_sha1(std::string_view key, std::string_view msg)
{
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int  n = 0;
    if (!HMAC(EVP_sha1(), key.data(), static_cast<int>(key.size()), reinterpret_cast<const unsigned char*>(msg.data()),
              msg.size(), out, &n))
        return {};
    return std::string(reinterpret_cast<const char*>(out), n);
}

// Whether two secrets or MACs are the same bytes, in a time that tells nothing of where they differ; lengths are not
// secret, and absence is the caller's to refuse.
inline bool secure_equal(std::string_view a, std::string_view b)
{
    return a.size() == b.size() && CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

inline bool secure_equal(const void* a, const void* b, size_t n)
{
    return CRYPTO_memcmp(a, b, n) == 0;
}

} // namespace socketley::crypto
