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

#include "../../shared/byte_codec.h"
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
    // A bucket's configuration document, to shard 0 to be changed; from it to the others, a change that may
    // happen (prepare), the document it made (adopt) or that it was abandoned (abort).
    doc_put       = 20,
    doc_adopt     = 21,
    // An object's new tags, to the owner of its key.
    set_tags      = 22,
    // A shard's part of ListObjectVersions.
    list_versions = 23,
    doc_prepare   = 24,
    doc_abort     = 25,
    // From a sibling to the owner of a key: may I keep this version, and tell me when it changes.
    hot_hold      = 26,
};

// The op of a request, false when the payload is not one of ours.
bool request_op(std::string_view payload, op& out);

std::string encode_commit(const commit_request& req);
bool        decode_commit(std::string_view payload, commit_request& out);

// The owner's answer to a commit: its status and the version it gave, empty for none.
std::string encode_committed(const put_result& r);
bool        decode_committed(std::string_view reply, put_result& r);

// A delete of the key, or of its version `version_id` when that is not empty.
std::string encode_remove(std::string_view bucket, std::string_view key, std::string_view version_id = {});
bool        decode_remove(std::string_view payload, std::string& bucket, std::string& key,
                          std::string* version_id = nullptr);

std::string encode_set_tags(std::string_view bucket, std::string_view key, std::string_view version_id,
                            std::string_view tags);
bool        decode_set_tags(std::string_view payload, std::string& bucket, std::string& key, std::string& version_id,
                            std::string& tags);
// The answer to a tag change: its status and the version it changed.
std::string encode_tagged(st s, std::string_view version_id);
bool        decode_tagged(std::string_view reply, st& s, std::string& version_id);

std::string encode_list_versions(std::string_view bucket, const version_query& q);
bool        decode_list_versions(std::string_view payload, std::string& bucket, version_query& q);
std::string encode_version_page(st s, const version_page& page);
bool        decode_version_page(std::string_view reply, st& s, version_page& page);
// The page one shard holding every key would give, from each shard's; shorter than max_keys when a shard's was cut short.
version_page merge_version_pages(std::vector<version_page> pages, size_t max_keys);

std::string encode_hot_drop(std::string_view bucket, std::string_view key);
bool        decode_hot_drop(std::string_view payload, std::string& bucket, std::string& key);
std::string encode_hot_owner_started(uint32_t shard);
bool        decode_hot_owner_started(std::string_view payload, uint32_t& shard);
// A key a sibling read and the version it read, one of the holds it asks an owner for in one message.
struct hold_entry
{
    std::string bucket;
    std::string key;
    object_meta meta;
};
// The most holds one message carries.
inline constexpr size_t max_holds = 256;
std::string encode_hot_hold(uint32_t shard, const hold_entry* entries, size_t n);
bool        decode_hot_hold(std::string_view payload, uint32_t& shard, std::vector<hold_entry>& out);
// The answer to a message of holds: a byte per hold, 1 where the version read is the one indexed.
std::string encode_held(const std::vector<uint8_t>& held);
bool        decode_held(std::string_view reply, std::vector<uint8_t>& held);

std::string encode_list(std::string_view bucket, const list_query& q);
bool        decode_list(std::string_view payload, std::string& bucket, list_query& q);

// A request that names a bucket, and for an adoption when it was made.
std::string encode_bucket(op o, std::string_view bucket, int64_t created_ms = 0);
bool        decode_bucket(std::string_view payload, std::string& bucket, int64_t& created_ms);

// A bucket's configuration document of one kind, empty for none, and the change of shard 0's it belongs to.
std::string encode_doc(op o, bucket_doc kind, std::string_view bucket, std::string_view xml, uint64_t seq = 0);
bool        decode_doc(std::string_view payload, op want, bucket_doc& kind, std::string& bucket, std::string& xml,
                       uint64_t& seq);

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
// The remove's answer says what it removed or made, and a bucket's creation when it was made.
std::string encode_removed(const remove_result& r);
std::string encode_created(st s, int64_t created_ms);
bool        decode_status(std::string_view reply, st& s);
bool        decode_removed(std::string_view reply, remove_result& r);
bool        decode_created(std::string_view reply, st& s, int64_t& created_ms);

// The most of a page that goes in one reply, so a shard's answer fits in what a
// link carries whatever the metadata of its objects weighs.
inline constexpr size_t max_page_bytes = 1u << 20;

// A walk's entries written straight into a page reply, in the name order a walk
// gives them, and cut back to `max_bytes` from the end, marked truncated when it was.
class page_writer final : public list_visitor
{
public:
    explicit page_writer(size_t max_bytes = max_page_bytes) : m_max(max_bytes) {}

    void object(const std::string& key, const object_meta& meta) override;
    void prefix(std::string common) override;
    void truncated(const std::string& resume_at) override;
    std::string finish(st s);

private:
    // Whether an entry of `cost` still fits, and otherwise the page ends at `name`.
    bool fits(const std::string& name, size_t cost);

    size_t        m_max;
    size_t        m_total{0};
    bool          m_cut{false};
    bool          m_truncated{false};
    std::string   m_resume;
    uint32_t      m_prefix_count{0};
    uint32_t      m_object_count{0};
    bytes::writer m_prefixes;
    bytes::writer m_objects;
    std::string   m_record;
};

// A built page as a page_writer would have written it.
std::string encode_page(st s, const list_page& page, size_t max_bytes = max_page_bytes);
bool        decode_page(std::string_view reply, st& s, list_page& out);

// The page one shard holding every key would give, from each shard's page for the query, and shorter than max_keys when a shard's page was cut short.
list_page merge_pages(std::vector<list_page> pages, size_t max_keys);

}   // namespace socketley::storage::wire
