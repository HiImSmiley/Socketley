#pragma once
#include <cstdint>
#include <string>
#include <string_view>

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

// A bound on the typo, not a recommendation.  Here rather than in the parser
// because a state file is a second way in and must meet the same bound.
inline constexpr uint32_t max_shards = 64;

// Which of the two processes this is; only the rules about the daemon's
// decision to FORK differ.  Not lua_context's flag of the same name, and not
// runtime_manager::m_replica -- a worker starts its runtime without a manager.
inline bool g_worker_process = false;
inline void set_worker_process(bool on) { g_worker_process = on; }
inline bool in_worker_process()         { return g_worker_process; }

// The whole --shards rule; every route asks, because a command line is not the
// only way a shard count arrives.
inline std::string shards_config_refusal(runtime_type type,
                                         uint32_t    shards,
                                         std::string_view listen_path)
{
    // The unsharded case, which is every runtime that never typed the flag.
    // Nothing below may fire for it: a rule that refuses a default is a rule
    // that refuses everything.
    if (shards <= 1)
        return {};

    if (shards > max_shards)
        return "--shards must be between 1 and " + std::to_string(max_shards) + "\n";

    if (type == runtime_client)
        return "--shards is not available on a client: a client dials out and "
               "has no listening socket to share, so N of them would be N "
               "connections to the peer -- a different feature wearing this "
               "flag's name\n";

    if (!listen_path.empty())
        return "--shards and --listen are not compatible: shards share a port "
               "through SO_REUSEPORT, and a unix socket is a path -- N "
               "processes would unlink each other's node and only the last to "
               "bind would be reachable.  Use -p for a sharded listener\n";

    return {};
}

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
