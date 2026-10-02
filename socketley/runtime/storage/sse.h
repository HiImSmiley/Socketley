#pragma once
// Server-side encryption of an object's bytes at rest, with no I/O.
//
// ─── FORMAT ─────────────────────────────────────────────────────────────────
// Every object gets a random 256-bit data key, kept in its header wrapped by
// AES-256-GCM under the runtime's master key (SSE-S3) or the client's own key
// (SSE-C), and its body is cut into chunks of 64 KiB of plaintext, each sealed
// on its own as nonce(12) | ciphertext | tag(16), so a range is read by opening
// only the chunks it touches.  A multipart object is its parts' chunk streams
// one after another, each counted from zero, located by the part sizes and
// numbers its header records.
//
//   x-socketley-sse: <version>;<s3|c>;65536;<o|p>;<master key id>;<wrapped key, base64>
//
// Version 1 seals a chunk with its index alone, so nothing marks a stream's
// end and the chunks at one index of two parts are interchangeable.  Version 2
// seals it with the part number its stream was uploaded as (0 for an object
// that is one stream), its index and whether it is the stream's last, and
// every stream ends in a last chunk shorter than 64 KiB, empty when the
// stream's length is a multiple of it.  A completed multipart object's data
// key is wrapped again with the digest of its part list, so a header that
// names fewer parts, or other ones, no longer unwraps it.  An SSE-C upload
// begun since that binding was enforced wraps its key as an upload's, which a
// completed object opens only with its list bound: by the client's key, or,
// when the completion did not carry it, by a MAC under the master key.  An
// upload begun before then has no such wrap, so it completes only with the key.
//
//   x-socketley-sse-parts: <master key id>;<HMAC-SHA256 of the record and the part list, hex>
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

// The format of objects written before streams were bound to their part and their end.
inline constexpr uint8_t sse_format_v1 = 1;
// The format every new object and upload is written in.
inline constexpr uint8_t sse_format = 2;

using sse_key = std::array<uint8_t, sse_key_bytes>;
using sse_digest = std::array<uint8_t, 32>;

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
    uint8_t     version{sse_format};
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
// The format `m`'s body is sealed in, 0 for one stored in the clear or whose record does not decode.
uint8_t sse_version_of(const object_meta& m);
inline bool is_encrypted(const object_meta& m) { return sse_value(m) != nullptr; }

// Chunks in a stream of `plain` bytes: a version 2 stream always ends in a short one.
inline uint64_t sse_chunks(uint64_t plain, uint8_t version)
{
    return version == sse_format_v1 ? (plain + sse_chunk - 1) / sse_chunk : plain / sse_chunk + 1;
}

// Bytes on disk of a stream of `plain` bytes.
inline uint64_t sse_stored_len(uint64_t plain, uint8_t version)
{
    return plain + sse_chunks(plain, version) * sse_overhead;
}

// The bytes after `m`'s header on disk, its part list included when that follows the body, UINT64_MAX when an
// encrypted multipart object's part sizes are not known.
uint64_t stored_size(const object_meta& m);

// What a commit or an open needs to know of the chunks of an encrypted body.
class sse_layout
{
public:
    // False when the record is not one, or a per-part body's parts are not recorded; `list` is the one read
    // after the body when the header has no room for it.
    bool init(const object_meta& m, const part_list* list = nullptr);

    struct chunk
    {
        // The part number the chunk's stream was sealed as, its index there and whether it ends the stream.
        uint32_t stream{0};
        uint64_t index{0};
        bool     last{false};
        uint64_t plain_off{0};
        uint64_t plain_len{0};
        uint64_t cipher_off{0};
        // The position of its stream among the object's.
        uint32_t part{0};
        uint64_t stored() const { return plain_len + sse_overhead; }
    };
    // The chunk holding plaintext byte `x`, which must be below the size.
    chunk at(uint64_t x) const;
    // The first chunk on disk, which every body has but a version 1 empty one.
    bool first(chunk& c) const;
    // Moves `c` to the chunk after it on disk, false after the last.
    bool next(chunk& c) const;
    uint64_t size() const { return m_size; }
    uint64_t stored() const { return m_stored; }
    uint8_t version() const { return m_version; }
    // The digest of the part list a per-part object's data key is wrapped with.
    sse_digest parts_digest() const;

private:
    chunk make(uint32_t part, uint64_t index) const;

    uint8_t  m_version{sse_format};
    uint64_t m_size{0};
    uint64_t m_stored{0};
    // Each stream's part number, length, and where it begins in the plaintext and on disk.
    std::vector<uint32_t> m_stream;
    std::vector<uint64_t> m_len;
    std::vector<uint64_t> m_plain_at;
    std::vector<uint64_t> m_cipher_at;
};

// The digest a version 2 per-part object's data key is wrapped with, from its header alone.
bool sse_parts_digest(const object_meta& m, sse_digest& out);

sse_key sse_random_key();
// A short name of a master key, which is what its objects record.
std::array<uint8_t, 4> sse_key_id(const sse_key& master);
// `parts`, when given, binds the wrap to a completed object's part list, which a version 2 per-part record needs.
// `upload` marks an SSE-C upload's wrap, which a completed object is read with only beside a part list MAC.
bool sse_wrap(const sse_key& kek, const sse_key& data, std::string& wrapped, uint8_t version = sse_format,
              const sse_digest* parts = nullptr, bool upload = false);
bool sse_unwrap(const sse_key& kek, std::string_view wrapped, sse_key& data, uint8_t version = sse_format,
                const sse_digest* parts = nullptr, bool upload = false);

// The key an SSE-C object's part list is MACed with, derived from the master key by HKDF-SHA256.
sse_key sse_parts_mac_key(const sse_key& master);
// The MAC of an object's encryption record, which names its upload's data key, and of its part list.
sse_digest sse_parts_mac(const sse_key& mac_key, std::string_view record, const sse_digest& parts);
std::string encode_parts_mac(const std::array<uint8_t, 4>& kid, const sse_digest& mac);
bool decode_parts_mac(std::string_view v, std::array<uint8_t, 4>& kid, sse_digest& mac);

// Seals `n` plaintext bytes of stream `stream` chunk by chunk into `out`, the first chunk having index `first`.
// `last` says the bytes end the stream, which in version 2 closes it with a short chunk; otherwise `n` is
// whole chunks.  Writes sse_sealed_len() bytes.
bool sse_seal(const sse_key& key, uint8_t version, uint32_t stream, uint64_t first, const char* in, size_t n,
              bool last, char* out);
inline uint64_t sse_sealed_len(uint64_t n, uint8_t version, bool last)
{
    return last ? sse_stored_len(n, version) : n + (n + sse_chunk - 1) / sse_chunk * sse_overhead;
}
// Opens `count` chunks laid one after another in `in`, writing their plaintext one after another to `out`;
// false when a tag fails.
bool sse_open(const sse_key& key, uint8_t version, const sse_layout::chunk* chunks, size_t count, const char* in,
              char* out);

// The ETag of an SSE-C object, which S3 makes something other than the MD5 of its bytes.
md5_t sse_opaque_etag(const sse_key& data, const md5_t& md5);

// The bytes and the ETag rule a put seals its body with.
struct sse_seal_spec
{
    sse_key  key{};
    bool     opaque_etag{false};
    uint8_t  version{sse_format};
    // The part number the body is uploaded as, 0 for an object.
    uint32_t stream{0};
};

// A master key from a file of 32 bytes, or of 64 hex digits and an optional newline, that only its owner may read.
bool load_sse_master(const std::string& path, sse_key& out, std::string& err);

}   // namespace socketley::storage
