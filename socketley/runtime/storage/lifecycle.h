#pragma once
// A bucket's lifecycle configuration, read, checked and written back, with no I/O.
//
// What it takes is the core of S3 lifecycle on a store with no versions and no
// storage classes: expiration by days or by date and the abort of incomplete
// multipart uploads, filtered by key prefix.  A rule asking for anything else is
// refused, never accepted to do less than it says.
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "s3_auth.h"

namespace socketley::storage
{

inline constexpr size_t lifecycle_max_rules  = 1000;
inline constexpr size_t lifecycle_max_id     = 255;
inline constexpr int64_t lifecycle_day_ms    = 86400000;
// The most the document is written back as, so it crosses to a sibling shard in one message.
inline constexpr size_t lifecycle_max_bytes  = 4u << 20;

struct lifecycle_rule
{
    std::string id;
    bool        enabled{false};
    std::string prefix;
    // The prefix came as the rule's own <Prefix>, the form before <Filter>, and is written back that way.
    bool        legacy_prefix{false};
    // The <Filter> named a <Prefix>, which an empty filter written back does not.
    bool        filter_prefix{false};
    // Days after an object's mtime it expires, zero for none.
    uint32_t    expire_days{0};
    // The midnight from which every object under the rule expires, when has_date.
    bool        has_date{false};
    int64_t     expire_date_ms{0};
    // <ExpiredObjectDeleteMarker>, kept to be written back: without versions there is no marker it could remove.
    int8_t      delete_marker{-1};
    // Days after an incomplete multipart upload began it is aborted, zero for none.
    uint32_t    abort_days{0};

    bool expires() const { return enabled && (expire_days != 0 || has_date); }
    bool aborts() const { return enabled && abort_days != 0; }
};

struct lifecycle_config
{
    std::vector<lifecycle_rule> rules;
};

// False with `err` the S3 error a client is given for the document.
bool parse_lifecycle(std::string_view xml, lifecycle_config& out, s3_error& err);

// The document GetBucketLifecycleConfiguration answers with.
std::string lifecycle_xml(const lifecycle_config& c);

// When something begun at `from_ms` is `days` days old, rounded up to the next day boundary since the epoch as S3
// does: with a real day that boundary is midnight UTC, and `day_ms` is shorter only for a test.
int64_t lifecycle_due_ms(int64_t from_ms, uint32_t days, int64_t day_ms);

// Whether an object of `key` written at `mtime_ms` has expired under `r` at `now_ms`.
bool lifecycle_object_due(const lifecycle_rule& r, std::string_view key, int64_t mtime_ms, int64_t now_ms,
                          int64_t day_ms);

// Whether an upload of `key` begun at `initiated_ms` is to be aborted under `r` at `now_ms`.
bool lifecycle_upload_due(const lifecycle_rule& r, std::string_view key, int64_t initiated_ms, int64_t now_ms,
                          int64_t day_ms);

}   // namespace socketley::storage
