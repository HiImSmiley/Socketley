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

// ─── Which of the two processes this code is running in ─────────────────────
//
// The daemon and a worker run the same binary, and almost everything in this
// tree is deliberately identical on both sides — that is the property the
// process split was built to have.  A handful of rules are not, because they
// are about the daemon's decision to FORK, and a worker asking one of them gets
// a wrong answer: a worker's runtime is in-process by construction, so
// "is this runtime out of process?" is false in the one place where it means
// "yes, it is a worker".
//
// lua_context has a bit of its own with the same name and a different job — it
// decides what an interpreter is built with — and it is compiled out entirely
// under SOCKETLEY_NO_LUA, where its stub answers false.  A placement rule that
// read it would come back wrong in a no-Lua worker, so this one is here instead
// and both are set on adjacent lines in proxy_worker's entry point.
//
// runtime_manager carries a per-OBJECT flag for the same distinction --
// m_replica, set on the worker's copy of the map -- and it is deliberately not
// what this reads.  A worker starts its runtime by calling
// runtime_instance::start() directly (proxy_worker.cpp:1336), never through
// runtime_manager::start(), which refuses on a replica; so on the one path that
// has to answer this question there is no manager in the call at all, and the
// instance's own pointer to one is not guaranteed to be set by then.  A bit
// that belongs to the process is the honest shape for a fact about the process.
//
// Written once, before any runtime exists, and read-only afterwards.
inline bool g_worker_process = false;
inline void set_worker_process(bool on) { g_worker_process = on; }
inline bool in_worker_process()         { return g_worker_process; }

// ─── May this runtime be split into this many processes? ────────────────────
//
// The whole of the --shards rule, in the one place every way in has to pass.
// It returns the refusal text, newline-terminated, or an empty string when the
// configuration is one this build can honour.
//
// Here rather than in the flag parser for the reason max_shards is here: a
// command line is not the only way a shard count arrives.  A state file written
// by another build, a `show | import` round trip, `socketley.create` from a
// script and a worker rebuilding itself from a config frame all set the same
// field without going near flag_handlers.cpp, and a rule that lives only in the
// parser is one every other route walks around in silence.  So the parser asks
// this, `create` asks it again once every flag has been seen, `edit` and
// `import` ask it, and runtime_instance::start() asks it last of all.
//
// ─── WHAT IS BEING DECLARED ─────────────────────────────────────────────────
//
// Sharding is correct exactly when nothing is shared between connections, and
// nothing can detect that.  So it is asked for and never inferred, and the
// question this function answers is not "is it correct" but "is the operator in
// a position to declare it".
//
// A PROXY: yes.  "Nothing is shared between connections" is a property of this
// tree's proxy — audited, fixed, and true by construction — so the operator is
// asserting something about code they can read here.
//
// A SERVER WITH NO SCRIPT: yes, and this is the half of the widening the
// original refusal named.  Without --lua a server has no cross-connection state
// to lose: it accepts, it echoes or serves files, and every byte it holds
// belongs to the connection it came from.  There is nothing for a second
// process to be unaware of.
//
// A SERVER WITH A SCRIPT: no.  The property would be one of the operator's own
// file, where cross-connection state is the common case rather than the
// exception — a chat room, a presence table, a counter — and the failure is
// silent: a message from a client on shard 1 never reaches a client on shard 2,
// and nothing reports it.  self.broadcast, owner_broadcast and
// upstream_broadcast are per-process today, so a script that broadcasts is
// wrong the moment there is a second process, and no flag the operator types
// makes it right.  An explicit opt-in inside the script's own declaration is
// the other half of the widening and is deliberately not invented here.
//
// A CACHE: no.  N shards are N separate stores behind one port.  A SET lands in
// whichever process the kernel gave that connection to and a later GET on a new
// connection asks a different one, so the answer is a miss for data that was
// stored — 1/N of the time, without an error anywhere.
//
// A CLIENT: no.  There is no listening socket to share.  A client dials out; N
// of them would be N connections to the peer, which is a different feature
// wearing this flag's name.
//
// ─── AND TWO CONFIGURATIONS THAT WOULD DO NOTHING, OR WORSE ─────────────────
//
// --listen unix:/path is refused above one shard because SO_REUSEPORT is not
// what a unix socket does.  bind() on a path that exists fails, so the listener
// setup unlinks a stale node first — and with N shards that is N-1 processes
// unlinking each other's node and binding their own.  The last one to bind owns
// the path and the rest hold a listening socket nothing can reach: a server
// that reports N shards, Up, and serves 1/N of nothing.
//
// --daemon-process is refused above one shard because a shard IS a worker
// process.  reconcile_proxy_workers() only forks for a runtime that is out of
// process, so `--shards 4 --daemon-process` was accepted, persisted, and
// reported by `show` as four while exactly one event loop served the port.  The
// operator asked for four and got one, reported by nothing as wrong.  That
// predates servers being shardable — it is reachable on a proxy on this tree —
// and it is refused here rather than at the proxy because the trap is the
// flag's, not the type's.
//
// `served_by_workers` is that last question, and it is NOT simply
// is_out_of_process().  There are three objects a shard count can be attached
// to and only two of them are the same: the daemon's placeholder, which is out
// of process and is the thing that forks; the daemon's own in-daemon runtime,
// which is the misconfiguration above; and a WORKER's runtime, which is
// in-process by construction and is itself one of the shards.  Asking
// is_out_of_process() in a worker answers false and refuses a configuration the
// daemon just accepted — measured, before this parameter had its name: all four
// shards of `create server ss -p P --shards 4 -s` exited config_refused and the
// command reported "the worker did not accept its configuration".  So the
// caller says whether this runtime is served by worker processes, and in a
// worker the answer is yes.
inline std::string shards_config_refusal(runtime_type type,
                                         uint32_t    shards,
                                         bool        has_lua,
                                         std::string_view listen_path,
                                         bool        served_by_workers)
{
    // The unsharded case, which is every runtime that never typed the flag.
    // Nothing below may fire for it: a rule that refuses a default is a rule
    // that refuses everything.
    if (shards <= 1)
        return {};

    if (shards > max_shards)
        return "--shards must be between 1 and " + std::to_string(max_shards) + "\n";

    if (type == runtime_cache)
        return "--shards is not available on a cache: N shards are N separate "
               "stores behind one port, so a SET lands in one process and a "
               "later GET on a new connection asks another -- a miss for data "
               "that was stored, with no error anywhere\n";

    if (type == runtime_client)
        return "--shards is not available on a client: a client dials out and "
               "has no listening socket to share, so N of them would be N "
               "connections to the peer -- a different feature wearing this "
               "flag's name\n";

    if (type == runtime_server && has_lua)
        return "--shards is not available on a server with --lua: sharding "
               "declares that nothing is shared between connections, and with a "
               "script that is a property of your file rather than of this "
               "build -- a message from a client on one shard never reaches a "
               "client on another, and nothing reports it.  Shard a server with "
               "no script, or run the scripted one unsharded\n";

    if (!listen_path.empty())
        return "--shards and --listen are not compatible: shards share a port "
               "through SO_REUSEPORT, and a unix socket is a path -- N "
               "processes would unlink each other's node and only the last to "
               "bind would be reachable.  Use -p for a sharded listener\n";

    if (!served_by_workers)
        return "--shards and --daemon-process are not compatible: a shard is a "
               "worker process, so a runtime asked to stay in the daemon has "
               "exactly one however many shards it declares.  Drop one of the "
               "two rather than being told four and served by one\n";

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
