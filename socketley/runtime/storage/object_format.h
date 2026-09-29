#pragma once
// What an object is on disk: the metadata a key carries, the self-describing
// header in front of its bytes, and the journal record that names it.
//
// Pure encoding with no I/O, so a unit test and a fuzz target reach it without a ring.
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "digest.h"

namespace socketley::storage
{

// Everything S3 tells a client about an object beyond its bytes.
struct object_meta
{
    uint64_t size{0};
    // Milliseconds since the epoch, the moment the object was committed.
    int64_t  mtime_ms{0};
    md5_t    md5{};
    // Zero for a single-part object, else the part count of the multipart ETag.
    uint32_t parts{0};
    std::string content_type;
    // Lowercase header name and value: cache-control, content-disposition,
    // content-encoding, content-language, expires and every x-amz-meta-*.
    std::vector<std::pair<std::string, std::string>> extra;

    // The ETag as S3 spells it, without the quotes: 32 hex digits, and "-N"
    // after them for a multipart object.
    std::string etag() const
    {
        std::string e = hex(md5);
        if (parts)
            e += "-" + std::to_string(parts);
        return e;
    }

    bool operator==(const object_meta&) const = default;
};

inline constexpr size_t object_header_align = 4096;
inline constexpr size_t max_key_bytes       = 1024;
// User metadata is 2 KB in S3 and the system fields ride beside it, so this is
// the total the header may carry before the request is refused.
inline constexpr size_t max_meta_bytes      = 8192;

// Appends the meta fields in the encoding both the header and the journal use.
void encode_meta(std::string& out, std::string_view key, const object_meta& m);

// The header that precedes an object's bytes, padded to a multiple of
// object_header_align and at least `min_len` long, so the body starts where
// the caller reserved room for it.
std::string encode_object_header(std::string_view key, const object_meta& m, size_t min_len = 0);

// The smallest header_len encode_object_header() will produce for this key and
// meta, so a writer can reserve exactly that much before the etag is known.
size_t object_header_len(std::string_view key, const object_meta& m);

enum class header_status : uint8_t
{
    ok,
    // The header is longer than the bytes given; `need` says how many are wanted.
    need_more,
    bad,
};

struct decoded_header
{
    header_status status{header_status::bad};
    size_t        header_len{0};
    size_t        need{0};
    std::string   key;
    object_meta   meta;
};

decoded_header decode_object_header(std::string_view bytes);

// ─── The index journal ──────────────────────────────────────────────────────
inline constexpr std::string_view journal_magic = std::string_view("SKLIDX\x01\x00", 8);
inline constexpr size_t           journal_header_len = 16;

std::string encode_journal_header(uint32_t shard);
bool        journal_header_ok(std::string_view bytes, uint32_t shard);

enum class record_type : uint8_t { put = 1, del = 2 };

struct journal_record
{
    record_type type{record_type::put};
    std::string key;
    object_meta meta;        // put
    int64_t     mtime_ms{0}; // del
};

void encode_put_record(std::string& out, std::string_view key, const object_meta& m);
void encode_delete_record(std::string& out, std::string_view key, int64_t mtime_ms);

enum class record_status : uint8_t
{
    ok,
    // The bytes end inside a record, which is what a crash mid-append leaves.
    torn,
    // A whole record whose checksum or shape is wrong.
    corrupt,
};

struct decoded_record
{
    record_status  status{record_status::torn};
    size_t         consumed{0};
    journal_record rec;
};

decoded_record decode_journal_record(std::string_view bytes);

// The path of an object's file below a bucket's data directory.
std::string object_rel_path(std::string_view key);
std::string key_hash(std::string_view key);

}   // namespace socketley::storage
