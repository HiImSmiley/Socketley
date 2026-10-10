#pragma once
// A bucket's server access logging, S3's BucketLoggingStatus: the bucket its access log is delivered to, the prefix
// of the log objects' keys, and whether those keys are partitioned by date.
#include <string>
#include <string_view>
#include <vector>

#include "s3_xml.h"

namespace socketley::storage
{

struct logging_config
{
    std::string target_bucket;
    std::string target_prefix;
    // [prefix][owner]/[region]/[bucket]/[YYYY]/[MM]/[DD]/ in front of each object's name, rather than the prefix alone.
    bool        partitioned{false};
    // The date source the configuration named, read back as it was given; a batch's delivery and its events fall on
    // the same day here, so both partition alike.
    bool        event_time{false};
    // What TargetGrants give each log object beside its owner's full control: a grantee as a grant header names one
    // (id, uri or emailaddress, and its value) and a permission.
    struct grant
    {
        std::string kind;
        std::string value;
        std::string permission;
    };
    std::vector<grant> grants;
    // TargetGrants was given, empty or not, which a target whose ACLs are disabled refuses either way.
    bool        grants_given{false};
};

// The document PutBucketLogging takes; false with `err` for anything S3 would refuse, and true with an empty
// target for a status with no LoggingEnabled, which turns logging off.
bool parse_logging_config(std::string_view xml, logging_config& out, s3_error& err);

// The document GetBucketLogging answers, an empty status for null.
std::string logging_config_xml(const logging_config* c);

}   // namespace socketley::storage
