#pragma once
// Raft's wire format between daemons: a versioned binary payload carried in an ipc_frame.
#include <cstdint>
#include <string>
#include <string_view>

#include "raft.h"

namespace socketley::raft::wire
{

// A peer speaking another version is refused, never guessed at.
inline constexpr uint8_t version = 1;

enum class kind : uint8_t { message = 1, hello = 2, join = 3 };

// The first frame on every connection a node dials, naming who is speaking.
struct hello
{
    node_id     id = no_node;
    std::string name;
    std::string addr;

    bool operator==(const hello&) const = default;
};

// A node asking the leader to add it, as a learner that is promoted once it has caught up when `voter` is set.
struct join
{
    node_id     id = no_node;
    std::string name;
    std::string addr;
    bool        voter = true;

    bool operator==(const join&) const = default;
};

struct frame
{
    wire::kind    kind = wire::kind::message;
    raft::message msg;
    wire::hello   hi;
    wire::join    req;
};

// Names and addresses are short, so a longer one is a corrupt frame rather than a long name.
inline constexpr size_t max_label = 255;

std::string encode(const raft::message& m);
std::string encode(const hello& h);
std::string encode(const join& j);

// False on anything but one whole, well-formed payload of this version, with the reason in `why`.
bool decode(std::string_view payload, frame& out, std::string* why = nullptr);

// Field-by-field equality, the snapshot compared by content, for round-trip checks.
bool same(const raft::message& a, const raft::message& b);

}   // namespace socketley::raft::wire
