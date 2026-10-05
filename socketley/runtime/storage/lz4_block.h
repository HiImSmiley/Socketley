#pragma once
// The LZ4 block format, compressed and opened: a sequence of a token, literals, a two-byte offset and a match,
// as https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md describes it, so any LZ4 decoder reads what this
// writes.  Fast rather than small: one greedy pass over a table of four-byte hashes.
#include <cstddef>
#include <cstdint>

namespace socketley::storage
{

// The most a block of `n` bytes can take compressed.
constexpr size_t lz4_bound(size_t n)
{
    return n + n / 255 + 16;
}

// Compresses `n` bytes of `in` into `out`, which holds lz4_bound(n); the bytes written.
size_t lz4_compress(const uint8_t* in, size_t n, uint8_t* out);

// Opens the `n` bytes of block `in` into `out`, which holds `cap`; the bytes written, or -1 for a block that is not
// one or would not fit.
long lz4_decompress(const uint8_t* in, size_t n, uint8_t* out, size_t cap);

}   // namespace socketley::storage
