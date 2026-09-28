#pragma once
#include <cstddef>

// Bytes glibc malloc spends on a request of `request`, its 8-byte header and 16-byte rounding included.
constexpr size_t malloc_chunk_bytes(size_t request)
{
    constexpr size_t header = 8, align = 16, min_chunk = 32;
    const size_t chunk = (request + header + align - 1) & ~(align - 1);
    return chunk < min_chunk ? min_chunk : chunk;
}
