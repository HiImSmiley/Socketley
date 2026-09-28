#pragma once
// The cluster's desired state as a replicated state machine: which runtimes exist, how many replicas each wants, and which node holds each replica.
#include <cstddef>
#include <cstdint>
#include <map>
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

enum class op : uint8_t { create = 1, remove = 2, scale = 3, assign = 4, unassign = 5 };

struct command
{
    cluster::op op = cluster::op::create;
    std::string name;
    // The whole spec on create, only the replica count on scale.
    spec        sp;
    node_id     node = 0;

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

// The argument with "{node}" replaced by a label made of letters, digits, '-', '_' and '.'.
std::string expand_args(std::string_view arg, std::string_view node_name);
std::vector<std::string> expand_args(const std::vector<std::string>& args, std::string_view node_name);

// An argument as one word of a command line: '%', spaces and control bytes as %XX, so an argument with a space in it survives the trip.
std::string quote_arg(std::string_view arg);
// False on a % that is not followed by two hex digits.
bool        unquote_arg(std::string_view word, std::string& out);

struct state
{
    std::map<std::string, spec> specs;
    // Ordered, so two nodes that applied the same log walk the same replicas in the same order.
    std::map<std::string, std::set<node_id>> owners;

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
// so any node would choose the same.
std::vector<command> plan(const state& s, const std::vector<node_id>& live);

}   // namespace socketley::cluster
