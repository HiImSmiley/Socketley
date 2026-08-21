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
// A SERVER, WITH OR WITHOUT A SCRIPT: yes.  Without --lua it always could —
// a server with no script has no cross-connection state to lose.  With one it
// was refused, and the refusal named the reason: "a message from a client on
// one shard never reaches a client on another, and nothing reports it."
//
// ─── THAT REFUSAL WAS ON THE WRONG RUNTIME ──────────────────────────────────
//
// The failure it described was real and it was never fixed; it was only made
// unreachable on ONE of the two types that could reach it.  proxy + --lua +
// --shards has been accepted by this build all along, and it was answering a
// fraction: measured on the tip, `self.connections()` on a four-shard proxy
// holding forty clients reported between 5 and 13, and a `self.broadcast`
// reached 15 of 40.  So the refusal protected a scripted server from a defect
// that a scripted proxy was shipping.
//
// What removes it is that the three shapes a script can ask for now cross a
// shard boundary, each proved against its own measured red:
//
//   aggregate   self.connections() sums every shard's own published counter
//               out of a shared mapping -- wait-free, ~10 ns over eight shards
//               against ~10 us for one AF_UNIX round trip.  shard_stats.h.
//   fan out     self.broadcast reaches every shard's clients, once each: the
//               local delivery happens where it stands and the daemon fans the
//               rest, excluding the shard that asked.
//   route       self.clients() lists the whole runtime -- this shard's
//               descriptors plus a stable handle per sibling's client -- and
//               self.send(id) reaches the owning shard in one hop, because a
//               conn_ref carries its minting shard in its serial.
//
// What a script does NOT get, and this is a property of sharding rather than a
// gap in it: per-connection state is per SHARD.  on_connect for a sibling's
// client fired in that sibling, so a script holds no state for the ids
// clients() hands it from elsewhere.  That is what sharding means, and it is
// unambiguously better than being told a fraction with no way to know.
//
// self.route is still refused in a worker — sharded or not, and for a reason
// that predates shards: route_client() reaches into another runtime's private
// maps and calls its on_connect on this thread's stack.  Nothing here lifts
// that.
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

    // ── The one refusal with a way past it, and why ─────────────────────────
    //
    // A CACHE: still no, and the reason above is still true of what ships.  The
    // routing that removes it is being built one command class at a time —
    // single-key first, then multi-key, then the keyspace-wide commands, then
    // persistence across a changed shard count — and until all four are done a
    // sharded cache answers some commands out of one shard's slice.
    //
    // -DSOCKETLEY_SCRATCH_CACHE_SHARDS compiles this one line out.  It exists so
    // that test/integration/pending_cache_shard_routing.sh can be RUN rather
    // than merely read: a test whose red nobody else can reproduce proves
    // nothing, and the alternative was an uncommitted patch described in prose.
    //
    // It is not a supported configuration and it is not an operator-facing
    // switch — nothing reads it at run time, no flag reaches it, and a default
    // build has no way to arrive here.  It goes when the refusal does.
#ifndef SOCKETLEY_SCRATCH_CACHE_SHARDS
    if (type == runtime_cache)
        return "--shards is not available on a cache: N shards are N separate "
               "stores behind one port, so a SET lands in one process and a "
               "later GET on a new connection asks another -- a miss for data "
               "that was stored, with no error anywhere\n";
#endif

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
