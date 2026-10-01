#pragma once
// What the shards of a storage runtime say to one another, and how their
// listings are put back together.
//
// Pure encoding and merging with no I/O, so a unit test reaches it without a
// ring.  A request is a magic, an op and its fields; a reply is a status byte
// and whatever the op answers with.
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "multipart.h"
#include "object_store.h"

namespace socketley::storage::wire
{

// Tells a request of this protocol from any other payload a runtime's name is
// sent, since a request channel carries whatever it is given.
inline constexpr uint32_t magic = 0x31475453u;   // "STG1"

enum class op : uint8_t
{
    commit        = 1,
    remove        = 2,
    list          = 3,
    // To shard 0, which makes and drops buckets.
    bucket_create = 4,
    bucket_delete = 5,
    // From shard 0 to the others.
    bucket_adopt  = 6,
    drop_prepare  = 7,
    drop_abort    = 8,
    drop_forget   = 9,
    // Multipart, to the shard that owns the upload's key.
    mpu_create    = 10,
    mpu_begin     = 11,
    mpu_part      = 12,
    mpu_prepare   = 13,
    mpu_finish    = 14,
    mpu_abort     = 15,
    mpu_parts     = 16,
    mpu_list      = 17,
    // From the owner of a key to its siblings: drop the small copy you hold of it.
    hot_drop      = 18,
    // From a shard that has just started: drop every copy you hold of my keys.
    hot_owner_started = 19,
};

// The op of a request, false when the payload is not one of ours.
bool request_op(std::string_view payload, op& out);

std::string encode_commit(const commit_request& req);
bool        decode_commit(std::string_view payload, commit_request& out);

std::string encode_remove(std::string_view bucket, std::string_view key);
bool        decode_remove(std::string_view payload, std::string& bucket, std::string& key);

std::string encode_hot_drop(std::string_view bucket, std::string_view key);
bool        decode_hot_drop(std::string_view payload, std::string& bucket, std::string& key);
std::string encode_hot_owner_started(uint32_t shard);
bool        decode_hot_owner_started(std::string_view payload, uint32_t& shard);

std::string encode_list(std::string_view bucket, const list_query& q);
bool        decode_list(std::string_view payload, std::string& bucket, list_query& q);

// A request that names a bucket, and for an adoption when it was made.
std::string encode_bucket(op o, std::string_view bucket, int64_t created_ms = 0);
bool        decode_bucket(std::string_view payload, std::string& bucket, int64_t& created_ms);

// ── Multipart ───────────────────────────────────────────────────────────────
// An upload as a listing names it.
struct upload_stub
{
    std::string key;
    std::string id;
    int64_t     initiated_ms{0};
};

std::string encode_mpu_create(std::string_view bucket, std::string_view key, const object_meta& meta,
                              checksum_algo algo);
bool        decode_mpu_create(std::string_view payload, std::string& bucket, std::string& key,
                              object_meta& meta, checksum_algo& algo);

// The requests that name an upload and carry at most three numbers and a flag:
// begin (part number, body size, size known), abort, a page of parts (marker, max) and finish (ok).
struct mpu_ref
{
    std::string bucket;
    std::string key;
    std::string id;
    uint32_t    a{0};
    uint32_t    b{0};
    bool        flag{false};
    uint64_t    size{0};
};
std::string encode_mpu_ref(op o, const mpu_ref& r);
bool        decode_mpu_ref(std::string_view payload, op want, mpu_ref& r);

std::string encode_mpu_part(const commit_request& req, std::string_view id, uint32_t number);
bool        decode_mpu_part(std::string_view payload, commit_request& req, std::string& id, uint32_t& number);

std::string encode_mpu_prepare(const mpu_ref& r, const std::vector<complete_part>& parts);
bool        decode_mpu_prepare(std::string_view payload, mpu_ref& r, std::vector<complete_part>& parts);

// ── Replies ─────────────────────────────────────────────────────────────────
std::string encode_mpu_created(st s, std::string_view id);
bool        decode_mpu_created(std::string_view reply, st& s, std::string& id);
// The place is the part's in the upload's data file, off 0 for a file of its own; the path is not sent.
std::string encode_mpu_begin(st s, checksum_algo algo, const part_place& place = {});
bool        decode_mpu_begin(std::string_view reply, st& s, checksum_algo& algo, part_place& place);
// An empty error code is a plan.
std::string encode_mpu_plan(const s3_error& err, const assemble_plan& plan);
bool        decode_mpu_plan(std::string_view reply, s3_error& err, assemble_plan& plan);
std::string encode_parts_page(const parts_page& pg);
bool        decode_parts_page(std::string_view reply, parts_page& pg);
std::string encode_upload_list(const std::vector<upload_stub>& uploads);
bool        decode_upload_list(std::string_view reply, std::vector<upload_stub>& uploads);

std::string encode_status(st s);
// The remove's answer says whether there was anything to remove, and a
// bucket's creation when it was made.
std::string encode_removed(st s, bool existed);
std::string encode_created(st s, int64_t created_ms);
bool        decode_status(std::string_view reply, st& s);
bool        decode_removed(std::string_view reply, st& s, bool& existed);
bool        decode_created(std::string_view reply, st& s, int64_t& created_ms);

// The most of a page that goes in one reply, so a shard's answer fits in what a
// link carries whatever the metadata of its objects weighs.
inline constexpr size_t max_page_bytes = 1u << 20;

// A page cut back to `max_bytes` from the end, marked truncated when it was.
void limit_page(list_page& page, size_t max_bytes = max_page_bytes);

std::string encode_page(st s, const list_page& page);
bool        decode_page(std::string_view reply, st& s, list_page& out);

// The page one shard holding every key would give, from each shard's page for the query, and shorter than max_keys when a shard's page was cut short.
list_page merge_pages(const std::vector<list_page>& pages, size_t max_keys);

}   // namespace socketley::storage::wire
