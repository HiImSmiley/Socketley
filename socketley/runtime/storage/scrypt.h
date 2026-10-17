#pragma once
// scrypt (RFC 7914), the same bytes as OpenSSL's EVP_PBE_scrypt and refused where it refuses, made faster: Salsa20/8
// on SSE2 for one hash, and on AVX2 for up to four at once, whose dependent chains one core then runs side by side.
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace socketley::storage::scrypt
{

// What derive_many() takes at once.
inline constexpr size_t max_batch = 4;

struct job
{
    std::string_view password;
    std::string_view salt;
    unsigned char* out{nullptr};
    size_t out_len{0};
};

// False for the parameters OpenSSL refuses, or ones needing more than `max_mem` bytes as it counts them.
bool derive(std::string_view password, std::string_view salt, uint64_t N, uint32_t r, uint32_t p, uint64_t max_mem,
            unsigned char* out, size_t out_len);

// Up to max_batch jobs under the same N and r, p = 1, at once where the CPU can; false as derive() would be.
bool derive_many(std::span<const job> jobs, uint64_t N, uint32_t r, uint64_t max_mem);

}   // namespace socketley::storage::scrypt
