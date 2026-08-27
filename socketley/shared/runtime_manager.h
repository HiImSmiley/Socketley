#pragma once

#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <string>
#include <string_view>
#include <shared_mutex>
#include <functional>
#include <vector>
#include <atomic>

#include "runtime_instance.h"
// runtime_string_hash / runtime_string_equal live here now, with the table
// whose lookups they exist for.
#include "endpoint_table.h"
#include "request_channel.h"

class event_loop;
class cluster_discovery;
struct cluster_event;

class runtime_manager
{
public:
    using runtime_map = std::unordered_map<std::string, std::unique_ptr<runtime_instance>,
                                            runtime_string_hash, runtime_string_equal>;

    // ── A manager that owns nothing ─────────────────────────────────────────
    //
    // A worker process holds one runtime and no map, which is what made the
    // twelve cross-runtime Lua calls answer a refusal out there.  It holds a
    // manager all the same — for the request channel — and the map inside it
    // was left empty on purpose.
    //
    // This says the map is no longer empty and no longer this process's to
    // change: it is a REPLICA of the daemon's, refreshed by install_replica()
    // from a frame on the control socket.  Everything that reads it — get(),
    // list(), and through them socketley.get and socketley.list — works
    // unchanged.
    //
    // Three things are refused instead of applied, and each would be silent
    // damage rather than a missing feature:
    //
    //   create/start/stop/remove/rename — a write to a copy.  The runtime would
    //     exist in one worker and nowhere else, and the next snapshot would
    //     erase it.  Those four Lua calls are refused out here for reasons of
    //     their own; this is the guard under the refusal.
    //
    //   publish_endpoints() — it REBUILDS the endpoint table from this map and
    //     pushes it into every runtime, which in a worker means overwriting the
    //     authoritative table the daemon sent.  The daemon's copy folds in
    //     remote cluster members, and a worker has no cluster_discovery to fold
    //     them from, so one publish here silently drops every remote member of
    //     every group a proxy routes to.  It also clears the request channel's
    //     sink table, which in a worker was registered by hand for the one
    //     runtime this process holds.
    //
    // Set once, when the worker wires its manager up, and never cleared.  A
    // daemon never calls it, so nothing about the in-daemon path changes.
    void mark_replica();
    bool is_replica() const { return m_replica; }

    // One runtime as the daemon last described it: the six fields
    // socketley.get() answers with, plus the group the cluster calls are about.
    // See worker_proto::runtime_wire, which is the same list on the wire.
    struct replica_entry
    {
        std::string   name;
        runtime_type  type{runtime_server};
        runtime_state state{runtime_created};
        uint16_t      port{0};
        uint64_t      connections{0};
        std::string   owner;
        std::string   group;
    };

    // Make the map say exactly this.  REPLICA MANAGERS ONLY, and only from a
    // point where no script frame is live — see the guard at the top of it.
    //
    // Entries already present are updated in place rather than replaced, so a
    // pointer a caller took out of get() a statement ago still names the same
    // object; entries the snapshot does not mention are dropped.
    //
    // No invalidation and no synchronous refresh, deliberately.  Both would
    // mean the worker asking the daemon a question and waiting for the answer
    // on its event-loop thread, which is the thing the split exists to avoid;
    // the price is that a name created in the last few milliseconds may not be
    // here yet, and that is the same price `stats` already pays for a worker's
    // figures.
    void install_replica(const std::vector<replica_entry>& entries);

    // Declared below as a wrapper over try_create(), which p0-crashes added
    // so a refused create can say WHY.  The old bare declaration is gone.
    // What a runtime may be called.  Enforced by create() and rename(), which
    // are the only two ways a name is acquired; see the definition for the four
    // places a name has to survive.
    static bool valid_name(std::string_view name);

    // Why a create did not happen.
    //
    // create() answered a bare bool, and cmd_create reported every false as
    // "runtime already exists" — measured on a daemon with NO runtimes at all:
    //
    //     $ socketley create server 'q"uote' -p 18722
    //     runtime already exists: q"uote
    //
    // which sends the operator looking for a runtime that does not exist while
    // the actual problem is a character in the name.
    enum class create_result { ok, invalid_name, name_taken, internal };

    create_result try_create(runtime_type type, std::string_view name);

    // The old spelling, for callers that only need to know whether it worked.
    bool create(runtime_type type, std::string_view name)
    { return try_create(type, name) == create_result::ok; }
    bool start(std::string_view name, event_loop& loop);
    bool stop(std::string_view name, event_loop& loop);
    // Takes the runtime out of the map.  The object itself may outlive the call
    // — see retire() for why — but it is gone as far as every reader is
    // concerned, and its name is free again immediately.
    bool remove(std::string_view name);
    bool rename(std::string_view old_name, std::string_view new_name);
    void stop_all(event_loop& loop);

    // Destroys every retired instance.  Only legal once the io_uring instance is
    // gone: event_loop::run() exits the ring on its way out, and that is the
    // first moment nothing can complete against retired storage any more.
    void free_retired();

    // Free the retired instances the ring has finished with.  Safe at any time:
    // an instance is released only once the loop reports that no request it
    // submitted is still in flight, which is exactly the condition its storage
    // was being held for.  Does nothing while the loop's owner table is full,
    // because a zero is then not proof of anything.  Returns how many went.
    //
    // Called from removal, and — because removal can only ever reap what was
    // retired before it — from the daemon's periodic timer, so that the last
    // runtime removed is released too.
    size_t reap_retired(const event_loop& loop);
    size_t retired_count() const;

    // ── Off-thread stats ────────────────────────────────────────────────────
    // Begin publishing every runtime's connection count and stats text for
    // readers that are not on the event-loop thread — see
    // runtime_instance::publish_offthread_stats() for why they cannot read the
    // live figures themselves.
    //
    // Off until something asks, because publishing costs one get_stats() string
    // per runtime per sweep and a daemon with no metrics endpoint has nobody to
    // read it: metrics is disabled unless metrics_port is set in the config, and
    // that is the only off-thread reader there is.  One-way — once on it stays
    // on for the life of the daemon, so nothing has to reason about a reader
    // that stopped between two sweeps.
    void enable_offthread_stats();

    // Refresh those figures for every runtime in the map.  EVENT-LOOP THREAD
    // ONLY.  No-op unless enable_offthread_stats() has been called.
    void publish_offthread_stats();

    // Cross-runtime pub/sub: dispatch a published message to all runtimes
    void dispatch_publish(std::string_view cache_name, std::string_view channel, std::string_view message);

    // Cluster event dispatch: forward topology changes to all runtimes with Lua callbacks
    void dispatch_cluster_events(const std::vector<cluster_event>& events);

    // ── Ownership cascading ─────────────────────────────────────────────────
    //
    // Stopping a runtime applies each child's on_parent_stop policy to it, and
    // to that child's own descendants.  The walk is over a graph, not a tree:
    // `owner` is a plain string that nothing validates, so it can name a
    // runtime already on the path — including the runtime itself.
    //
    // Every entry point below therefore carries a set of the names it has
    // already descended into.  See the note on cascade_seen in the .cpp for the
    // crash that arrives without it.
    std::vector<std::string> get_children(std::string_view parent_name) const;
    void stop_children(std::string_view parent_name, event_loop& loop);
    void remove_children(std::string_view parent_name, event_loop& loop);

    // Build the name/group → endpoint snapshot and hand it to every runtime
    // that asked for one.  EVENT-LOOP THREAD ONLY, like every other push into a
    // running instance.
    //
    // This replaced get_by_group(), which returned live runtime_instance
    // pointers so that the proxy could read a port off each one — a runtime
    // reaching into other runtimes, on the connection path, under this mutex.
    // Call it wherever membership changes: create, start, stop, remove, rename,
    // and whenever the cluster's view of a remote daemon moves.  Cheap enough
    // to call on any doubt; there is no path that calls it per request.
    void publish_endpoints();

    // Where the table goes besides the in-process runtimes.
    //
    // A runtime living in a worker process cannot be handed a shared_ptr, so it
    // is handed the same table encoded onto its control socket instead.  The
    // manager does not know that: it calls a sink, and the daemon decides what
    // that means.  That is the boundary rule applied to the manager itself —
    // what crosses is the answer, and the thing on the far side may as well be
    // a socket, because for a worker it is one.
    void set_endpoint_sink(std::function<void(const endpoint_table&)> sink);

    // And the finer half of the same table: who answers for ONE SHARD of a
    // runtime that is N processes.
    //
    // publish_endpoints() registers a sink per runtime NAME, which is the right
    // answer to "who serves this runtime" and cannot be the answer to "who owns
    // this key" — a sharded cache has N stores and the name resolves to shard 0.
    // The daemon holds the N supervisors, so it is the only side that can add
    // the qualified entries; the manager calls this after it has rebuilt the
    // table and before anything can use it.  See shared/shard_target.h.
    //
    // Unset in a worker, which has one shard and no map to enumerate.
    void set_shard_sink_publisher(std::function<void(request_channel&)> sink);

    // Where a published message goes besides the in-process runtimes — the same
    // boundary rule as the endpoint sink, for the other thing the daemon used to
    // deliver by calling into each instance.
    //
    // dispatch_publish() skips a runtime that lives in a worker process and
    // hands it to this instead.  Skipping is not an optimisation: the daemon
    // keeps a placeholder for such a runtime, the placeholder loaded the same
    // script, and its subscribe callbacks are therefore registered here as well
    // — so without the skip one PUBLISH ran the callback twice, once in the
    // daemon against a copy of the runtime that serves nothing, and never in the
    // process that does.
    void set_publish_sink(std::function<void(std::string_view cache_name,
                                             std::string_view channel,
                                             std::string_view message)> sink);

    // Where a message for a named runtime goes when that runtime's connections
    // are in another process — the third of the same shape, for the third thing
    // the daemon used to do by calling into an instance.
    //
    // `socketley.send(name, msg)` broadcasts to a runtime's connections, and
    // since 8399bee those are normally held by a worker.  Called on the
    // placeholder the call succeeds, returns true and delivers to the empty
    // tables of an object that serves nothing.  cmd_send() was fixed for
    // exactly this in the commit that added the deliver frame; the Lua binding
    // was left calling lua_broadcast() on the placeholder, so a script's send
    // went nowhere while reporting that it had gone.
    //
    // Returns whether the message was handed to the process holding the
    // connections, so the binding can answer false rather than repeat the lie
    // in a quieter voice.  Unset — a manager with no daemon around it — is
    // false for the same reason: nothing was delivered.
    //
    // A worker installs one too, and there it means one hop less: handed to the
    // daemon, which holds the map and knows which process the name is in.  See
    // worker_proto's deliver_to for why that hop is not waited on.
    void set_deliver_sink(
        std::function<bool(std::string_view name, std::string_view message)> sink);
    bool deliver_out_of_process(std::string_view name, std::string_view message) const;

    // ── The four calls that CHANGE the map, asked of whoever holds it ───────
    //
    // The fifth sink of the same shape, and the first that waits for an answer.
    // socketley.create/.start/.stop/.remove alter the map; a worker holds a
    // replica and altering that would build a runtime the daemon never hears
    // about.  So a worker installs this and the call travels; the daemon
    // installs nothing and the call is served locally, which is why the
    // presence of the sink -- not a process flag -- is what decides.
    //
    // It blocks for the round trip, unlike every other sink here, because the
    // script is mid-expression: `if socketley.create(...) then` needs the
    // answer, not the acceptance.  What that costs and why it is affordable on
    // this path is set out at encode_map_request in worker_protocol.h.
    void set_map_sink(
        std::function<bool(std::string_view op, std::string_view name,
                           std::string_view config, std::string& err)> sink);
    bool has_map_sink() const { return static_cast<bool>(m_map_sink); }
    bool map_mutate(std::string_view op, std::string_view name,
                    std::string_view config, std::string& err) const;

    // "The map has changed; let go of anything that names a runtime leaving
    // it."  The fourth of the same shape, and the one with no payload: what
    // crosses here is a moment, not an answer.
    //
    // A supervisor holds a raw pointer to the placeholder it writes stats into
    // and clears an override on, and only proxy_supervisor::retire() severs
    // that safely — while the placeholder is still known to be alive.
    // cmd_remove() reaches retire() by reconciling before the instance leaves
    // the map, and says so in a comment.  socketley.remove() had no way to, so
    // it freed the instance under a supervisor still holding it.
    void set_worker_release_sink(std::function<void()> sink);
    void release_workers() const;

    // Where a runtime sends a request meant for another runtime.  One per
    // daemon, attached to the event loop by daemon_start() and detached before
    // the ring goes; see shared/request_channel.h for why this is a channel and
    // not a call.
    //
    // Its sink table is the third thing publish_endpoints() rebuilds: the
    // endpoint table says where a runtime is, the endpoint sink carries that
    // same table out of this address space, and this says who answers for it.
    // Only in-process runtimes register here — a worker's placeholder has no
    // interpreter to run a request on, and the only runtime that answers one is
    // a cache, which does not split yet.
    request_channel& requests() { return m_requests; }
    const request_channel& requests() const { return m_requests; }

    const runtime_map& list() const;
    runtime_instance* get(std::string_view name);

    // Cluster discovery integration
    void set_cluster_discovery(cluster_discovery* cd);
    cluster_discovery* get_cluster_discovery() const;

    mutable std::shared_mutex mutex;

private:
    // The names one cascade has already descended into.
    //
    // Not a member: a cascade is a single call tree, and two of them must not
    // share state.  It is threaded through the three functions below instead,
    // which is also what keeps the public entry points re-entrant — a script's
    // on_stop may call socketley.stop from inside one of these.
    using cascade_seen = std::unordered_set<std::string>;

    // The recursive halves of stop()/stop_children()/remove_children().  The
    // public spellings create an empty set and call these.
    bool stop_cascading(std::string_view name, event_loop& loop, cascade_seen& seen);
    void stop_children_cascading(std::string_view parent, event_loop& loop, cascade_seen& seen);
    void remove_children_cascading(std::string_view parent, event_loop& loop, cascade_seen& seen);

    // Takes over an instance that has just left the map.  Called with the map
    // lock released.
    void retire(std::unique_ptr<runtime_instance> inst);

    // True while a Lua callback is on this thread's stack, and false in a build
    // with no Lua at all.  Both places below that would otherwise destroy a
    // runtime_instance immediately ask this first; see retire().
    static bool script_frame_live();

    std::function<void(const endpoint_table&)> m_endpoint_sink;
    std::function<void(request_channel&)> m_shard_sink_publisher;
    std::function<void(std::string_view, std::string_view, std::string_view)> m_publish_sink;
    std::function<bool(std::string_view, std::string_view)> m_deliver_sink;
    std::function<bool(std::string_view, std::string_view,
                       std::string_view, std::string&)> m_map_sink;
    std::function<void()> m_worker_release_sink;

    // Declared BEFORE the map and the graveyard, so that it is destroyed AFTER
    // them.  A runtime revokes its origin as it goes — ~server_instance calls
    // requests().drop_origin(this), because a runtime can be freed without ever
    // having been stopped — and that call needs a channel that is still alive.
    //
    // It used to sit below them, with the reasoning that the channel had to go
    // first so "its queue is emptied while the runtimes it names are still
    // alive".  The queue does not need them: an entry carries its own copy of
    // the target name and the payload, an origin is a bare pointer, and
    // ~request_channel clears three containers and dereferences nothing.  So
    // that order bought nothing and cost the reverse — the channel died first
    // and every instance destructor after it called into freed storage.  UBSan
    // in the nightly, on the first run after test_sdk_engine started being
    // executed at all:
    //
    //     server_instance.cpp:47:36: runtime error: member call on address
    //     0x7fff... which does not point to an object of type 'request_channel'
    request_channel m_requests;

    runtime_map runtimes;

    // The graveyard: instances that are gone as far as every reader is
    // concerned, but whose storage the ring may still point into.  Drained by
    // reap_retired() as the completions land, and by free_retired() at daemon
    // shutdown for whatever never completed.
    std::vector<std::unique_ptr<runtime_instance>> m_retired;
    size_t m_retired_warn_at = 32;

    // Set by a reader on another thread, read by the event-loop thread on every
    // sweep, so it has to be an atomic even though it only ever goes false→true.
    std::atomic<bool> m_offthread_stats{false};

    // See mark_replica().  Plain bool: written once at wiring time, read on the
    // one thread that ever touches this object in a worker.
    bool m_replica = false;

    cluster_discovery* m_cluster = nullptr;
};
