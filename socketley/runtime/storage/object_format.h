#pragma once
// What an object is on disk: the metadata a key carries, the self-describing
// header in front of its bytes, and the journal record that names it.
//
// Pure encoding with no I/O, so a unit test and a fuzz target reach it without a ring.
#include <array>
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

// Whether a comma-separated If-Match / If-None-Match list names `etag`, quoted or weak, or is "*".
bool etag_list_matches(std::string_view list, std::string_view etag);

// The extra entry an object's tags are kept in: each tag's key and value, each followed by a NUL.
inline constexpr std::string_view tags_extra = "x-amz-tagging";

// The object's tags in that encoding, empty when it has none.
std::string_view tags_of(const object_meta& m);
// Makes `tags` the object's tags, as the last extra entry, or removes them when it is empty.
void set_tags_extra(object_meta& m, std::string_view tags);

// The extra entry a multipart object's part sizes are kept in: one size when
// every part but the last has it, else every size, comma-separated.
inline constexpr std::string_view part_sizes_extra = "x-socketley-part-sizes";
// The longest list kept, so the header stays within its bounds; a longer one is not recorded.
inline constexpr size_t max_part_sizes_bytes = 4096;

// The entry for parts of these sizes, empty when it would be longer than `max`.
std::string encode_part_sizes(const std::vector<uint64_t>& sizes, size_t max = max_part_sizes_bytes);

// The extra entry naming the numbers a multipart object's parts were uploaded as, when they are not 1..N:
// single numbers and ranges, comma-separated, such as 1-3,5,9.
inline constexpr std::string_view part_numbers_extra = "x-socketley-part-numbers";

// The entry for these ascending numbers, empty when they are 1..N or the entry would be longer than `max`.
std::string encode_part_numbers(const std::vector<uint32_t>& numbers, size_t max = max_part_sizes_bytes);

// A multipart object's parts in order: the number each was uploaded as, and its size.
struct part_list
{
    std::vector<uint32_t> numbers;
    std::vector<uint64_t> sizes;
};

// The parts `m`'s header records, a single-part object being its own part 1; false when they are not
// recorded there or do not add up to the object.
bool part_list_of(const object_meta& m, part_list& out);

// Removes what `m` records of its parts, for a copy that is one part whatever its source was.
void clear_part_layout(object_meta& m);

// The list in one canonical encoding, of 20 + 12 bytes per part, which is what a digest of it is taken over.
std::string encode_part_list(const part_list& l, uint64_t total);

// The extra entry of a multipart object whose part list did not fit in its header and follows its body
// instead, in the canonical encoding: the body's length on disk, a semicolon, and the list's SHA-256 in hex.
inline constexpr std::string_view part_layout_extra = "x-socketley-part-layout";
// The extra entry an SSE-C object completed without its client's key keeps its part list's MAC in.
inline constexpr std::string_view sse_parts_extra = "x-socketley-sse-parts";
// The extra entry of an SSE-C upload whose key is wrapped as an upload's, which its completion removes.
inline constexpr std::string_view sse_upload_wrap_extra = "x-socketley-sse-wrap";

// Where a part list kept after the body lies, counted from the body's start, and the digest it must have.
struct part_trailer
{
    uint64_t at{0};
    uint64_t len{0};
    std::array<uint8_t, 32> digest{};
};

// False when `m` keeps no part list after its body.
bool part_trailer_of(const object_meta& m, part_trailer& out);

// The list `bytes` hold, false unless they are the ones `t` names and describe `m`.
bool decode_part_trailer(std::string_view bytes, const object_meta& m, const part_trailer& t, part_list& out);

// Records `l` in `m`'s header when it fits in `max` bytes, the numbers only when `numbers` asks and they are not
// 1..N, and otherwise names a trailer after a body of `body_stored` bytes, whose bytes are returned.
std::string record_part_list(object_meta& m, const part_list& l, uint64_t body_stored, bool numbers,
                             size_t max = max_part_sizes_bytes);

// The extra entry of a sealed body written to a pooled file: the MD5 of its bytes as they lie on disk, in hex,
// which is how a start knows the file is whole without the key that opens it.
inline constexpr std::string_view stored_md5_extra = "x-socketley-stored-md5";

// The extra entry naming the upload a multipart object was completed from, so a retried completion finds it.
inline constexpr std::string_view upload_id_extra = "x-socketley-upload-id";

// The extra entry a version of a key in a versioned bucket is named by: its order among the
// key's versions, whether it is a delete marker, and its id.
inline constexpr std::string_view version_extra = "x-socketley-version";

struct version_tag
{
    // Larger is newer, so a key's versions sort newest first by it.
    uint64_t    seq{0};
    // "null", or 32 lowercase hex digits.
    std::string id;
    bool        marker{false};
};

// The version `m` records; an object written without versioning is the null version of its own time.
version_tag version_of(const object_meta& m);
// Whether `m` records a version, which only an object written to a versioned bucket does.
bool has_version(const object_meta& m);
// Whether `m` is a delete marker, cheaply false for an object with no version.
bool is_delete_marker(const object_meta& m);
void set_version_extra(object_meta& m, const version_tag& v);
void clear_version_extra(object_meta& m);
// A version id the store could have given, which is also what keeps one out of a path.
bool valid_version_id(std::string_view id);
// The path of a key's noncurrent version below its bucket directory.
std::string version_rel_path(std::string_view key, std::string_view id);

enum class part_status : uint8_t
{
    ok,
    // The object has fewer parts than the one asked for.
    out_of_range,
    // A multipart object completed without its sizes recorded.
    unknown,
    // The sizes follow the object's body, which has to be read for them.
    in_trailer,
};

// Where part `n` (from 1) of the object begins and how long it is; a
// single-part object is its own part 1.
part_status part_range(const object_meta& m, uint32_t n, uint64_t& first, uint64_t& len);
// The same from a list read after the body, which part_range() says it needs with in_trailer.
part_status part_range_in(const part_list& l, uint32_t n, uint64_t& first, uint64_t& len);

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
    // Where the header's own fields end and its zero padding begins.
    size_t        meta_end{0};
    // The slot in that padding whose tags replaced the ones the header was written with, -1 for none.
    int8_t        tag_slot{-1};
    uint64_t      tag_seq{0};
};

// Tags changed after an object was written go into one of two slots in the
// padding of its header's first 4 KiB, whole 512-byte sectors written in turn
// and checksummed with a sequence number, so a torn write of one leaves the
// other and the object's bytes, ETag and time never move.
decoded_header decode_object_header(std::string_view bytes);

// The bytes that make `tags` the tags of the object `d` decoded, and the offset
// they go at, or empty when its header has no room for them.
std::string encode_tag_slot(const decoded_header& d, std::string_view tags, uint64_t& at);

// ─── The index journal ──────────────────────────────────────────────────────
inline constexpr std::string_view journal_magic = std::string_view("SKLIDX\x01\x00", 8);
inline constexpr size_t           journal_header_len = 24;

// A journal says which shard wrote it and under how many, because the owner of
// a key moves with the shard count and a journal from another split holds the
// wrong keys.
std::string encode_journal_header(uint32_t shard, uint32_t nshards);

// The journal format that records every version of a key, where format 2 recorded only its latest object.
inline constexpr uint32_t journal_format = 3;

enum class journal_header_status : uint8_t
{
    ok,
    // A journal of ours from another shard count: sound, and not what this split owns.
    other_layout,
    bad,
};

// `format`, when given, is told the format of a sound header.
journal_header_status journal_header_check(std::string_view bytes, uint32_t shard, uint32_t nshards,
                                           uint32_t* format = nullptr);

// put and del name a key's latest object; vput and vdel add and remove one of its other versions.
enum class record_type : uint8_t { put = 1, del = 2, vput = 3, vdel = 4 };

struct journal_record
{
    record_type type{record_type::put};
    std::string key;
    object_meta meta;        // put, vput
    int64_t     mtime_ms{0}; // del
    std::string version_id;  // vdel
};

// A version of `key` that is not its latest object: a noncurrent one, or a delete marker.
void encode_version_record(std::string& out, std::string_view key, const object_meta& m);
void encode_version_drop_record(std::string& out, std::string_view key, std::string_view version_id);
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
