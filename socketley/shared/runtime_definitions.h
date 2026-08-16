#pragma once
#include <cstdint>

enum runtime_state : uint8_t
{
    runtime_created = 0,
    runtime_running = 1,
    runtime_stopped = 2,
    runtime_failed  = 3
};

enum runtime_type : uint8_t
{
    runtime_server = 0,
    runtime_client = 1,
    runtime_proxy  = 2,
    runtime_cache  = 3
};

// The most worker processes one runtime may be split into; see --shards in
// flag_handlers.cpp and runtime_instance::set_shards().
//
// 64 is a bound on the typo, not a recommendation.  Past the machine's core
// count an extra shard is another process competing for the cores already in
// use, plus its own ring, its own control socket and its own idle cost — so a
// number far above it is never what was meant, and forking it is a worse answer
// than refusing it.  Here rather than in the parser because the state file is a
// second way in: a document written by another build, or edited by hand, has to
// meet the same bound as a command line.
inline constexpr uint32_t max_shards = 64;

inline constexpr const char* type_to_string(runtime_type t)
{
    switch (t)
    {
        case runtime_server: return "server";
        case runtime_client: return "client";
        case runtime_proxy:  return "proxy";
        case runtime_cache:  return "cache";
    }
    return "unknown";
}
