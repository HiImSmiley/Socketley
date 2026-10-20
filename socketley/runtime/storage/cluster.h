#pragma once
// A storage runtime's cluster: the nodes that each keep every bucket, and what one node sends another.
//
// ─── THE FILE ───────────────────────────────────────────────────────────────
//   self <name>                  the node this runtime is
//   node <name> <url> [ca=file]  every node, this one included, by the S3 endpoint the others reach it at
//   key <access_key> <secret>    the credentials the nodes sign for each other with, the same in every node's file
//   sync <n> [ms]                a write is answered once n other nodes have it, or after ms (5000) whatever they say
//
// Every node takes writes; each sends every change it made to the others through its replication outbox, and a node
// keeps another's write when it is newer than what it has: a version by its id, which all nodes share, and an object
// of a bucket that keeps no versions by the time it was written, a removal made after it included.
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "../../shared/http/outbound_http.h"
#include "replicator.h"

namespace socketley::storage
{

struct cluster_config
{
    std::string self;
    // The other nodes, each a target of the replicator signed with the cluster's key.
    std::vector<replication_target> peers;
    std::string access_key;
    std::string secret;
    // How many other nodes have a write before it is answered, 0 for none, and how long that is waited for at most.
    uint32_t    sync{0};
    uint32_t    sync_ms{5000};
};

// False with `why` for a file that names no `self` among its nodes, a node twice, or no key.
bool parse_cluster(std::string_view text, cluster_config& out, std::string& why);
bool load_cluster(const std::string& path, cluster_config& out, std::string& why);

// The headers a node's write to another carries: the stamp it was made with, and a version's lock, whose values are
// those of the extra entries.
inline constexpr std::string_view cluster_stamp_header      = "x-socketley-cluster-stamp";
inline constexpr std::string_view cluster_retention_header  = "x-socketley-cluster-retention";
inline constexpr std::string_view cluster_legal_hold_header = "x-socketley-cluster-legal-hold";
// The query of a POST that applies a record of a bucket's or a version's change, and the most such a record holds.
inline constexpr std::string_view cluster_query = "x-socketley-cluster";
inline constexpr uint64_t         cluster_max_body = 2u << 20;

// A change no S3 request makes as it was made: a bucket made with its owner, removed, or a document of it set, a
// version's retention or legal hold changed past what S3 allows a client, the IAM API's users, groups and roles, and
// the share links.
struct cluster_record
{
    // 'c' made, 'r' removed, 'd' a document set or removed, 'l' a version's lock, 'i' the IAM document, its revision
    // in `owner`, 'h' a share link, its id in `owner` and nothing for one revoked, and 'q' a version the scrub of the
    // node `owner` found corrupt, which it asks to be sent again.
    char        kind{0};
    std::string owner;
    // A document's kind as bucket_doc numbers it, or a lock's as header_change::kind does.
    uint8_t     what{0};
    // The document, empty for one removed, or the lock's value.
    std::string value;
    std::string version_id;
};

std::string encode_cluster_record(const cluster_record& r);
bool        decode_cluster_record(std::string_view bytes, cluster_record& out);

}   // namespace socketley::storage
