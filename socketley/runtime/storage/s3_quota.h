#pragma once
// A bucket's quota, the BucketQuota document `?quota` sets: the most bytes its objects and versions may hold and
// the most of them there may be, either 0 for no bound.
#include <cstdint>
#include <string>
#include <string_view>

#include "s3_xml.h"

namespace socketley::storage
{

struct bucket_quota
{
    uint64_t max_bytes{0};
    uint64_t max_objects{0};

    bool any() const { return max_bytes || max_objects; }
};

// `<BucketQuota><MaxBytes>n</MaxBytes><MaxObjects>n</MaxObjects></BucketQuota>`, either element optional; false
// with `err` for anything else.
bool parse_bucket_quota(std::string_view xml, bucket_quota& out, s3_error& err);

// The document as GET ?quota answers it.
std::string bucket_quota_xml(const bucket_quota& q);

}   // namespace socketley::storage
