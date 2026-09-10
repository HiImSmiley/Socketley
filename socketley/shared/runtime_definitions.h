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

// The four names, once.  Five places had this switch -- lua_context,
// cluster_discovery, metrics_endpoint, daemon_handler's ps --json, and the
// --log file that was about to be the fifth -- all returning the same four
// strings, which is exactly the shape a state renamed in one of them would
// have gone wrong in.
inline const char* state_to_string(runtime_state s)
{
    switch (s)
    {
        case runtime_created: return "created";
        case runtime_running: return "running";
        case runtime_stopped: return "stopped";
        case runtime_failed:  return "failed";
    }
    return "unknown";
}

// A bound on the typo, here rather than in the parser because a state file is
// a second way in.
inline constexpr uint32_t max_shards = 64;

// Which of the two processes this is, for the daemon's decision to fork; not
// lua_context's flag of the same name, nor runtime_manager::m_replica.
inline bool g_worker_process = false;
inline void set_worker_process(bool on) { g_worker_process = on; }
inline bool in_worker_process()         { return g_worker_process; }

// The whole --shards rule; every route asks, because a command line is not the
// only way a shard count arrives.
inline std::string shards_config_refusal(runtime_type type,
                                         uint32_t    shards)
{
    // The unsharded case, which every runtime that never typed the flag is, so
    // nothing below may fire for it.
    if (shards <= 1)
        return {};

    if (shards > max_shards)
        return "--shards must be between 1 and " + std::to_string(max_shards) + "\n";

    if (type == runtime_client)
        return "--shards is not available on a client: a client dials out and "
               "has no listening socket to share, so N of them would be N "
               "connections to the peer -- a different feature wearing this "
               "flag's name\n";

    // --listen used to be refused here, on the grounds that N processes
    // binding one path unlink each other's node.  That is true of one path and
    // not of N: each shard binds its own, name#0.sock .. name#N-1.sock, the
    // same rule companion_path already uses.  Over AF_UNIX the transport is
    // worth at least 1.22x of TCP on a four-shard cache here.
    //
    // Every listening type, and the reason is the same for all three read the
    // right way round.  On a server and a proxy the nodes are INTERCHANGEABLE
    // -- every shard answers every request -- so a caller takes any one and
    // there is nothing to get wrong.  On a cache they are not, and that is
    // exactly where choosing pays: a caller that hashes the key the way
    // CLUSTER KEYSLOT does and picks that shard's node crosses nothing.  Both
    // are reasons to allow it, not to refuse it.
    //
    // A client is already refused above, and for a different reason: it has no
    // listening socket at all.

    return {};
}

// Defined in type_registry.cpp, because a registered type's name lives in the
// registry and cannot be a constant here.
const char* type_to_string(runtime_type t);
