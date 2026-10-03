#pragma once
// S3 bucket replication with no I/O: a bucket's ReplicationConfiguration, which of its rules a version or a delete
// marker answers to, and the x-amz-replication-status an object records.
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "object_format.h"
#include "s3_names.h"
#include "s3_xml.h"

namespace socketley::storage
{

// The most a ReplicationConfiguration may be, and the most rules it may hold.
inline constexpr size_t replication_max_bytes = 256 * 1024;
inline constexpr size_t replication_max_rules = 1000;

// A destination bucket is named by an ARN of this form, its name after the prefix.
inline constexpr std::string_view bucket_arn_prefix = "arn:aws:s3:::";

inline constexpr std::string_view replication_pending   = "PENDING";
inline constexpr std::string_view replication_completed = "COMPLETED";
inline constexpr std::string_view replication_failed    = "FAILED";
inline constexpr std::string_view replication_replica   = "REPLICA";

struct replication_rule
{
    std::string id;
    bool        has_priority{false};
    int64_t     priority{0};
    bool        enabled{true};
    // The rule names its keys with a Prefix of its own, the first schema, rather than a Filter.
    bool        v1{false};
    // How the Filter was given, kept to write it back as it came: none, a Prefix, a Tag, or an And.
    enum class filter_form : uint8_t { none, prefix, tag, both };
    filter_form form{filter_form::none};
    std::string prefix;
    std::vector<std::pair<std::string, std::string>> tags;
    std::string dest_arn;
    std::string dest_bucket;
    std::string account;
    std::string storage_class;
    bool        owner_override{false};
    bool        has_delete_markers{false};
    bool        delete_markers{false};
    bool        has_sse_kms{false};
    bool        sse_kms{false};
    bool        has_existing{false};
};

struct replication_config
{
    std::string role;
    // The replication target the Role names, the part after its last '/'.
    std::string target;
    std::vector<replication_rule> rules;
};

// False with `err` for a configuration S3 would refuse, or one naming what this runtime does not do: MalformedXML for
// one that is not a ReplicationConfiguration, InvalidArgument and InvalidRequest as S3 answers a bad rule, and
// NotImplemented for existing-object replication, replica modification sync, KMS and replication time control.
bool parse_replication_config(std::string_view xml, replication_config& out, s3_error& err);

// What GetBucketReplication answers, and what the bucket keeps.
std::string replication_config_xml(const replication_config& c);

// The rules a new version of `key` with `tags` (in the encoding of tags_of()) is replicated by, or that a delete
// marker of it is when `marker`: for each destination bucket the matching enabled rule of the highest priority, and a
// marker only where that rule replicates delete markers.
std::vector<const replication_rule*> replication_rules_for(const replication_config& c, std::string_view key,
                                                            std::string_view tags, bool marker);

}   // namespace socketley::storage
