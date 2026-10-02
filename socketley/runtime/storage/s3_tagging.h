#pragma once
// Object tags as S3 has them: the Tagging document, the x-amz-tagging header,
// S3's limits on both, and the encoding a tag set is stored in.
//
// Pure parsing and encoding with no I/O, so a unit test reaches it without a ring.
#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "s3_auth.h"

namespace socketley::storage
{

using tag_set = std::vector<std::pair<std::string, std::string>>;

inline constexpr size_t max_object_tags     = 10;
inline constexpr size_t max_bucket_tags     = 50;
// The most a bucket's Tagging document is kept as.
inline constexpr size_t bucket_tagging_max_bytes = 64 * 1024;
inline constexpr size_t max_tag_key_chars   = 128;
inline constexpr size_t max_tag_value_chars = 256;

// False with `err` when the set breaks S3's rules: at most ten tags, keys of 1
// to 128 and values of up to 256 characters, of letters, digits, spaces and
// + - = . _ : / @, keys unique and none beginning "aws:".
bool check_tags(const tag_set& tags, s3_error& err, size_t max_tags = max_object_tags);

// A PutObjectTagging body, checked; false with `err` the S3 error a client is given.  A bucket's takes `max_tags` 50.
bool parse_tagging_xml(std::string_view xml, tag_set& out, s3_error& err, size_t max_tags = max_object_tags);

// An x-amz-tagging header, a URL-encoded query string, checked the same way.
bool parse_tagging_header(std::string_view header, tag_set& out, s3_error& err);

// The document GetObjectTagging answers with.
std::string tagging_xml(const tag_set& tags);

// The set as an object's metadata keeps it, empty for none, and back.
std::string encode_tags(const tag_set& tags);
tag_set     decode_tags(std::string_view stored);
size_t      tag_count(std::string_view stored);
// Whether the stored set has `key` with exactly `value`.
bool        tags_have(std::string_view stored, std::string_view key, std::string_view value);

}   // namespace socketley::storage
