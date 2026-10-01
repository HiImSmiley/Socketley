#pragma once
// Server-side encryption of an object's bytes at rest, with no I/O.
//
// ─── FORMAT ─────────────────────────────────────────────────────────────────
// Every object gets a random 256-bit data key, kept in its header wrapped by
// AES-256-GCM under the runtime's master key (SSE-S3) or the client's own key
// (SSE-C), and its body is cut into chunks of 64 KiB of plaintext, each sealed
// on its own as nonce(12) | ciphertext | tag(16) with the chunk's index in the
// additional data, so a range is read by opening only the chunks it touches.
// A multipart object is its parts' chunk streams one after another, each
// counted from zero, located by the part sizes its header records.
//
//   x-socketley-sse: 1;<s3|c>;65536;<o|p>;<master key id>;<wrapped key, base64>
#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "digest.h"
#include "object_format.h"

namespace socketley::storage
{

inline constexpr std::string_view sse_extra = "x-socketley-sse";
inline constexpr size_t sse_chunk     = 64 * 1024;
inline constexpr size_t sse_nonce     = 12;
inline constexpr size_t sse_tag       = 16;
inline constexpr size_t sse_overhead  = sse_nonce + sse_tag;
inline constexpr size_t sse_key_bytes = 32;
// nonce, sealed data key, tag.
inline constexpr size_t sse_wrapped_bytes = sse_nonce + sse_key_bytes + sse_tag;

using sse_key = std::array<uint8_t, sse_key_bytes>;

enum class sse_mode : uint8_t
{
    none,
    // Wrapped by the runtime's master key.
    s3,
    // Wrapped by the key the client sends with every request.
    c,
};

struct sse_record
{
    sse_mode    mode{sse_mode::none};
    // The body is one chunk stream per part, as a completed multipart upload leaves it.
    bool        per_part{false};
    // Which master key wrapped it, so a runtime given another one says so instead of failing to open it.
    std::array<uint8_t, 4> kid{};
    std::string wrapped;
};

std::string encode_sse(const sse_record& r);
bool decode_sse(std::string_view v, sse_record& out);
// The record `m` carries, null for an object stored in the clear.
const std::string* sse_value(const object_meta& m);
sse_mode sse_mode_of(const object_meta& m);
inline bool is_encrypted(const object_meta& m) { return sse_value(m) != nullptr; }

// Bytes on disk of a stream of `plain` bytes.
inline uint64_t sse_stored_len(uint64_t plain)
{
    return plain + (plain + sse_chunk - 1) / sse_chunk * sse_overhead;
}

// The bytes of `m`'s body on disk, UINT64_MAX when an encrypted multipart object's part sizes are not known.
uint64_t stored_size(const object_meta& m);

// What a commit or an open needs to know of the chunks of an encrypted body.
class sse_layout
{
public:
    // False when the record is not one, or a per-part body's part sizes are not recorded.
    bool init(const object_meta& m);

    struct chunk
    {
        // Index within its part's stream, which is what the chunk was sealed with.
        uint64_t index{0};
        uint64_t plain_off{0};
        uint64_t plain_len{0};
        uint64_t cipher_off{0};
    };
    // The chunk holding plaintext byte `x`, which must be below the size.
    chunk at(uint64_t x) const;
    uint64_t size() const { return m_size; }
    uint64_t stored() const { return m_stored; }

private:
    uint64_t m_size{0};
    uint64_t m_stored{0};
    // Where each part begins in the plaintext and on disk, empty for a single stream.
    std::vector<uint64_t> m_plain_at;
    std::vector<uint64_t> m_cipher_at;
};

sse_key sse_random_key();
// A short name of a master key, which is what its objects record.
std::array<uint8_t, 4> sse_key_id(const sse_key& master);
bool sse_wrap(const sse_key& kek, const sse_key& data, std::string& wrapped);
bool sse_unwrap(const sse_key& kek, std::string_view wrapped, sse_key& data);

// Seals `n` plaintext bytes chunk by chunk into `out`, sse_stored_len(n) bytes; the first chunk has index `first`.
bool sse_seal(const sse_key& key, uint64_t first, const char* in, size_t n, char* out);
// Opens `n` stored bytes, whole chunks the first of which has index `first`, into `out`; false when a tag fails.
bool sse_open(const sse_key& key, uint64_t first, const char* in, size_t n, char* out);

// The ETag of an SSE-C object, which S3 makes something other than the MD5 of its bytes.
md5_t sse_opaque_etag(const sse_key& data, const md5_t& md5);

// The bytes and the ETag rule a put seals its body with.
struct sse_seal_spec
{
    sse_key key{};
    bool    opaque_etag{false};
};

// A master key from a file of 32 bytes, or of 64 hex digits and an optional newline, that only its owner may read.
bool load_sse_master(const std::string& path, sse_key& out, std::string& err);

}   // namespace socketley::storage
