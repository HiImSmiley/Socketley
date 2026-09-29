#pragma once
// The cluster's desired state as a replicated state machine: which runtimes exist, how many replicas each wants, and which node holds each replica.
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace socketley::cluster
{

using node_id = uint64_t;

inline constexpr size_t   max_name     = 128;
// The most bytes the flags of one spec may hold in all, and the most of them, so the create line stays under the argument limit.
inline constexpr size_t   max_args     = 4096;
inline constexpr size_t   max_arg_count = 90;
inline constexpr uint32_t max_replicas = 64;

// What `create` takes for a runtime, kept as the argument text every node hands to its own `create` verb.
struct spec
{
    std::string type;
    // The flags after the name, one argument each and never split again; "{node}" in one stands for the name of the node that runs the replica.
    std::vector<std::string> args;
    uint32_t    replicas = 1;

    bool operator==(const spec&) const = default;
};

enum class op : uint8_t { create = 1, remove = 2, scale = 3, assign = 4, unassign = 5, promote = 6 };

struct command
{
    cluster::op op = cluster::op::create;
    std::string name;
    // The whole spec on create, only the replica count on scale.
    spec        sp;
    node_id     node = 0;
    // On promote, which incarnation of the replica on `node` leads and the epoch it leads, one past the last.
    uint64_t    incarnation = 0;
    uint64_t    epoch       = 0;

    bool operator==(const command&) const = default;
};

// Every replicated command begins with this byte, which no membership record does.
inline constexpr char command_tag = 'C';

std::string encode(const command& c);
bool        is_command(std::string_view data);
// False on anything but one whole command that refusal() accepts, so no node ever applies what another would have refused.
bool        decode(std::string_view data, command& out);

// The operator's reason a command cannot be proposed, empty when it can.
std::string refusal(const command& c);
// The types that may run as a cluster runtime, and the reason for one that may not.
std::string type_refusal(std::string_view type);
// Why the flags of a cluster cache cannot work, empty when they can: the followers dial the primary's -p, so that is
// what it needs, and the cluster sets the rest of replication itself.
std::string cache_flags_refusal(const std::vector<std::string>& args);

// What "{node}" stands for: the node's name with everything but letters, digits, '-', '_' and '.' turned into '_', so two names can share one label.
std::string node_label(std::string_view name);
// The member other than `id` whose label is the same as `name`'s, or zero: two of them would expand {node} to one string.
node_id label_holder(const std::map<node_id, std::string>& names, node_id id, std::string_view name);
// The argument with "{node}" replaced by the node's label.
std::string expand_args(std::string_view arg, std::string_view node_name);
std::vector<std::string> expand_args(const std::vector<std::string>& args, std::string_view node_name);

// An argument as one word of a command line: '%', spaces and control bytes as %XX, so an argument with a space in it survives the trip.
std::string quote_arg(std::string_view arg);
// False on a % that is not followed by two hex digits.
bool        unquote_arg(std::string_view word, std::string& out);

// Which replica of a cache leads it: the node, the incarnation of the process there (a restarted replica is a new one
// and holds nothing the old one did), and the epoch it leads, which only ever grows.
struct primary_record
{
    node_id  node        = 0;
    uint64_t incarnation = 0;
    uint64_t epoch       = 0;

    bool operator==(const primary_record&) const = default;
};

struct state
{
    std::map<std::string, spec> specs;
    // Ordered, so two nodes that applied the same log walk the same replicas in the same order.
    std::map<std::string, std::set<node_id>> owners;
    // One per cache spec and none for another type; the node is zero while nobody leads.
    std::map<std::string, primary_record> primaries;

    // True when the command changed something, false when it was a repeat or named nothing, and identically on every node.
    bool apply(const command& c);

    size_t load(node_id n) const;
    size_t placed(const std::string& name) const;
    // Replicas wanted and not held by any node.
    size_t missing(const std::string& name) const;

    bool operator==(const state&) const = default;
};

// Why a well-formed operator command would change nothing on this state, so the operator hears it instead of a silent
// no-op; empty when it would take effect.
std::string conflict(const state& s, const command& c);

// The bytes a snapshot carries, and false from decode on anything that is not exactly what encode wrote.
std::string encode(const state& s);
bool        decode(std::string_view data, state& out);

// The assign and unassign commands that bring the owners in line with the specs on the nodes given, a pure function
// so any node would choose the same.  A scale-down never takes the replica that leads a cache.
std::vector<command> plan(const state& s, const std::vector<node_id>& live);

// A replica a promotion may choose: what it last said about its copy, which the leader hears on every lease request.
struct candidate
{
    node_id  node        = 0;
    uint64_t incarnation = 0;
    // The epoch of the primary whose stream the copy came from, and how far into it; copies compare by both, in that order.
    uint64_t epoch  = 0;
    uint64_t offset = 0;
};

// The most up-to-date copy: the highest epoch, then the highest offset, then the lowest node; nothing when there is none.
std::optional<candidate> best_candidate(const std::vector<candidate>& from);

// Where the other replicas of a cluster cache dial the one whose flags (already expanded for its node) are `args`, on
// the host that node is reached at; empty when the flags name no port.
std::string replica_address(const std::vector<std::string>& args, std::string_view host);

}   // namespace socketley::cluster
