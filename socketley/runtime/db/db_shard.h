#pragma once
// A sharded db: shard 0 writes the one log and every shard reads it, so N cores answer reads and one stream of syncs
// takes every write. The others take what they read from the same files as shard 0 makes them durable, and send it
// the writes, in the frames here.
#include <cstdint>
#include <string>
#include <string_view>

#include "db_store.h"

namespace socketley::db
{

// A write another shard takes to shard 0, in the asker's principal; the marker tells it from a script's call.
inline constexpr std::string_view cross_marker = "\x02skl-db-shard\n";
// Shard 0's word to the others that more of its log is on the disk, answered at once.
inline constexpr std::string_view nudge_marker = "\x02skl-db-nudge\n";

struct crossing
{
    principal who;
    std::string_view method;
    std::string_view path;
    std::string_view body;
    std::string_view if_match;
    std::string_view if_none_match;
};

std::string encode_crossing(const crossing& c);
// False when it is not one; the views are into `in`.
bool decode_crossing(std::string_view in, crossing& out);

std::string encode_crossing_reply(int status, uint64_t version, std::string_view body);
bool decode_crossing_reply(std::string_view in, int& status, uint64_t& version, std::string_view& body);

}   // namespace socketley::db
