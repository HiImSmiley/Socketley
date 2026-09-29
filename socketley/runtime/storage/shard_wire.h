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
};

// The op of a request, false when the payload is not one of ours.
bool request_op(std::string_view payload, op& out);

std::string encode_commit(const commit_request& req);
bool        decode_commit(std::string_view payload, commit_request& out);

std::string encode_remove(std::string_view bucket, std::string_view key);
bool        decode_remove(std::string_view payload, std::string& bucket, std::string& key);

std::string encode_list(std::string_view bucket, const list_query& q);
bool        decode_list(std::string_view payload, std::string& bucket, list_query& q);

// A request that names a bucket, and for an adoption when it was made.
std::string encode_bucket(op o, std::string_view bucket, int64_t created_ms = 0);
bool        decode_bucket(std::string_view payload, std::string& bucket, int64_t& created_ms);

// ── Replies ─────────────────────────────────────────────────────────────────
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

// One shard's page for the same query from each shard, as the page a single
// shard holding every key would have given.  A shard whose page is cut short is
// only known as far as its last name, and nothing beyond the nearest such name
// is used, so a page can be shorter than max_keys and never wrong.
list_page merge_pages(const std::vector<list_page>& pages, size_t max_keys);

}   // namespace socketley::storage::wire
