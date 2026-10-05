#pragma once
// An object's body stored compressed, with no I/O.
//
// ─── FORMAT ─────────────────────────────────────────────────────────────────
// The body is cut into chunks of 64 KiB of its bytes, each an LZ4 block on its own, or the bytes as they are when
// the block would be no shorter, so a range is read by opening only the chunks it touches.  The chunks lie one
// after another and are followed by a table of each one's length on disk, four bytes little-endian, its top bit set
// for a chunk kept as it is.
//
//   x-socketley-lz4: 1;65536;<where the table begins, after the header>;<chunks>
//
// Only a body in the clear and of one part is stored so; its ETag and checksums are of the bytes it holds.
#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "object_format.h"

namespace socketley::storage
{

inline constexpr std::string_view lz4_extra = "x-socketley-lz4";
inline constexpr size_t lz4_chunk = 64 * 1024;
// A chunk's table entry has this bit when its bytes are kept as they are.
inline constexpr uint32_t lz4_raw_bit = 0x80000000u;

struct lz4_record
{
    uint64_t table_at{0};
    uint64_t chunks{0};
};

// The record `m` carries, false for a body not stored compressed or a record that does not fit its size.
bool lz4_record_of(const object_meta& m, lz4_record& out);
inline bool is_compressed(const object_meta& m)
{
    for (const auto& e : m.extra)
        if (e.first == lz4_extra)
            return true;
    return false;
}
// The value of a record, its numbers at a fixed width so a header written before them is as long as after.
std::string encode_lz4_record(const lz4_record& r);
// Makes `m` say its body is stored as `r` says, or as it is when `r` is null.
void set_lz4_record(object_meta& m, const lz4_record* r);

inline uint64_t lz4_chunks_of(uint64_t size)
{
    return (size + lz4_chunk - 1) / lz4_chunk;
}

// Where each chunk is, read from the table after the body.
struct lz4_table
{
    uint64_t size{0};
    // Each chunk's start on disk, one more than there are chunks, the last being where the table begins.
    std::vector<uint64_t> at;
    std::vector<bool>     raw;
    uint64_t plain_len(uint64_t i) const { return std::min<uint64_t>(lz4_chunk, size - i * lz4_chunk); }
};

// False for a table whose lengths do not add up to where it begins.
bool lz4_table_decode(std::string_view bytes, const object_meta& m, const lz4_record& r, lz4_table& out);

// Opens chunks [first, first + n), whose bytes on disk begin at `stored`, into `out`; false for one that does not
// open to its length.
bool lz4_open_chunks(const lz4_table& t, uint64_t first, uint64_t n, const char* stored, char* out);

// Opens a whole compressed body held in memory, its table included.
bool lz4_open_body(const object_meta& m, std::string_view stored, std::string& plain);

// Compresses `n` bytes into whole chunks, the last of the body possibly shorter, appending the chunks to `out` and
// their entries to `table`.
void lz4_squeeze(const char* in, size_t n, std::string& out, std::string& table);

}   // namespace socketley::storage
