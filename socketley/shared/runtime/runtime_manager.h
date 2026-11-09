#pragma once
#include <chrono>

#include <map>
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
#include "../net/endpoint_table.h"
#include "../ipc/request_channel.h"
#include "../cluster/cluster_view.h"

class event_loop;
class cluster_discovery;

// Forward-declared rather than included, or route_relay.h would drag the
// server into every translation unit that only wants the map.
namespace route_relay { struct sink; }
struct cluster_event;

// The map's lock, which fills an unfilled replica before its first shared acquisition, because every read of the map
// takes it shared and a worker whose runtime never reads the map is then never sent it.
class replica_mutex
{
public:
    void lock() { m_m.lock(); ++t_held; }
    bool try_lock() { return m_m.try_lock() && (++t_held, true); }
    void unlock() { --t_held; m_m.unlock(); }
    void lock_shared() { fill(); m_m.lock_shared(); ++t_held; }
    bool try_lock_shared() { fill(); return m_m.try_lock_shared() && (++t_held, true); }
    void unlock_shared() { --t_held; m_m.unlock_shared(); }

    // The lock without the fill, for the manager's own walks that no replica row can answer.
    std::shared_mutex& raw() { return m_m; }

private:
    friend class runtime_manager;

    void fill()
    {
        if (!m_owed.load(std::memory_order_relaxed) || m_filling) [[likely]]
            return;
        // Not with the lock already held by this thread, because the fill installs under the exclusive lock.
        if (t_held != 0)
            return;
        // A second after a fill that failed, so a daemon that is slow to answer costs one wait and not one per read.
        const auto now = std::chrono::steady_clock::now();
        if (now < m_retry_at)
            return;
        m_filling = true;
        m_fill();
        m_filling = false;
        if (m_owed.load(std::memory_order_relaxed))
            m_retry_at = now + std::chrono::seconds(1);
    }

    std::shared_mutex    m_m;
    std::function<void()> m_fill;
    // Set once at wiring and cleared by the first install, so the daemon's readers on other threads only ever load a false.
    std::atomic<bool>    m_owed{false};
    bool                 m_filling{false};
    std::chrono::steady_clock::time_point m_retry_at{};
    // How many holds of the map's lock this thread has, shared or exclusive, through this class.
    static inline thread_local int t_held = 0;
};

class runtime_manager
{
public:
    using runtime_map = std::unordered_map<std::string, std::unique_ptr<runtime_instance>,
                                            runtime_string_hash, runtime_string_equal>;

    // ── A manager that owns nothing ─────────────────────────────────────────
    // This map is a replica of the daemon's, refreshed by install_replica(),
    // so reads work unchanged while the five mutations and publish_endpoints()
    // are refused -- each would be silent damage rather than a missing
    // feature.
    void mark_replica();
    bool is_replica() const { return m_replica; }

    // One runtime as the daemon last described it: the six fields
    // socketley.get() answers with, plus the group the cluster calls are
    // about.
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

    // Make the map say exactly this, for replica managers only and only
    // outside a script frame, updating entries in place and dropping what the
    // snapshot omits, with no invalidation and no synchronous refresh; false
    // when a script frame refused it.
    bool install_replica(const std::vector<replica_entry>& entries);

    // How a replica is filled the first time anything reads it, armed until an install_replica() fills it.
    void set_replica_fill(std::function<void()> fill);
    // An unfilled replica, which drops the rows of a delta because a delta onto nothing is not the map.
    bool replica_unfilled() const { return mutex.m_owed.load(std::memory_order_relaxed); }
    // Owed again, for a worker that can no longer tell which map it holds.
    void replica_owe() { if (mutex.m_fill) mutex.m_owed.store(true, std::memory_order_relaxed); }
    // Whether an unfilled replica can ask for its map at all, which a worker without a map socket cannot.
    bool replica_can_fill() const { return static_cast<bool>(mutex.m_fill); }

    // Only the rows a push moved, applied and refused exactly as install_replica would.
    bool apply_replica_delta(const std::vector<replica_entry>& upserts,
                             const std::vector<std::string>& removed);

    // One row of the replica, corrected the instant this worker changed it,
    // because install_replica's push is up to an interval old and a script
    // must not read `running` from the line after its own stop returned.
    void replica_note(std::string_view op, std::string_view name,
                      const replica_entry& e);

    // What a runtime may be called, enforced by create() and rename(), which
    // are the only two ways a name is acquired.
    static bool valid_name(std::string_view name);

    // Why a create did not happen, because a bare bool had cmd_create
    // reporting every refusal as "runtime already exists".
    enum class create_result { ok, invalid_name, name_taken, internal };

    create_result try_create(runtime_type type, std::string_view name);

    // The old spelling, for callers that only need to know whether it worked.
    bool create(runtime_type type, std::string_view name)
    { return try_create(type, name) == create_result::ok; }
    // `refusal`, when given, is filled with the reason a start did not happen
    // in the cases that have one to give -- so the ten callers can hand the
    // operator the sentence instead of "could not start runtime", and the boot
    // restore can put it in the log.  Left untouched when the start succeeds.
    bool start(std::string_view name, event_loop& loop,
               std::string* refusal = nullptr);
    bool stop(std::string_view name, event_loop& loop);
    // Takes the runtime out of the map, freeing its name immediately, though
    // the object itself may outlive the call.
    bool remove(std::string_view name);
    bool rename(std::string_view old_name, std::string_view new_name);
    void stop_all(event_loop& loop);

    // Destroys every retired instance, legal only once the ring is gone, which
    // event_loop::run() exits on its way out.
    void free_retired();

    // Free the retired instances the ring has finished with, safe at any time,
    // doing nothing while the owner table is full because a zero is then not
    // proof of anything.
    size_t reap_retired(const event_loop& loop);
    size_t retired_count() const;

    // ── Off-thread stats ────────────────────────────────────────────────────
    // Begin publishing every runtime's figures for off-thread readers, off
    // until something asks and one-way once on, because the metrics endpoint
    // is the only reader there is.
    void enable_offthread_stats();

    // Refresh those figures for every runtime in the map, event-loop thread
    // only, and a no-op unless enable_offthread_stats() has been called.
    void publish_offthread_stats();

    // Cross-runtime pub/sub: dispatch a published message to all runtimes
    void dispatch_publish(std::string_view cache_name, std::string_view channel, std::string_view message);

    // Cluster event dispatch: forward topology changes to all runtimes with Lua callbacks
    void dispatch_cluster_events(const std::vector<cluster_event>& events);

    // ── Ownership cascading ─────────────────────────────────────────────────
    // The cascade walks a graph and not a tree, because `owner` is a plain
    // string that can name a runtime already on the path, so every entry point
    // carries the set of names it has descended into.
    std::vector<std::string> get_children(std::string_view parent_name) const;
    void stop_children(std::string_view parent_name, event_loop& loop);
    void remove_children(std::string_view parent_name, event_loop& loop);

    // Build the name/group to endpoint snapshot and hand it to every runtime
    // that asked, event-loop thread only, called wherever membership changes
    // and never per request.
    void publish_endpoints();

    // Where the table goes besides the in-process runtimes, since a runtime in
    // a worker cannot be handed a shared_ptr and is handed the encoded table
    // instead.
    void set_endpoint_sink(std::function<void(const endpoint_table&)> sink);

    // Who answers for one shard of a runtime that is N processes, added by the
    // daemon because it holds the N supervisors, and unset in a worker.
    void set_shard_sink_publisher(std::function<void(request_channel&)> sink);

    // Where a published message goes besides the in-process runtimes, with
    // dispatch_publish() skipping a worker-backed runtime so one PUBLISH does
    // not run the placeholder's callbacks as well.
    void set_publish_sink(std::function<void(std::string_view cache_name,
                                             std::string_view channel,
                                             std::string_view message)> sink);

    // Where a message for a named runtime goes when its connections are in
    // another process, answering whether it was handed to that process so the
    // binding can say false rather than repeat the lie quietly.
    void set_deliver_sink(
        std::function<bool(std::string_view name, std::string_view message)> sink);
    bool deliver_out_of_process(std::string_view name, std::string_view message) const;

    // The four calls that change the map, asked of whoever holds it, and the
    // first sink that waits -- because `if socketley.create(...) then` needs
    // the answer rather than the acceptance.
    void set_map_sink(
        std::function<bool(std::string_view op, std::string_view name,
                           std::string_view config, std::string& err)> sink);
    bool has_map_sink() const { return static_cast<bool>(m_map_sink); }
    bool map_mutate(std::string_view op, std::string_view name,
                    std::string_view config, std::string& err) const;

    // A connection served here and answered somewhere else: an interface
    // rather than two std::functions, because a process could otherwise
    // install half of it, and non-owning because the daemon_handler and the
    // worker outlive their manager.
    void set_cluster_event_sink(std::function<void(const cluster_ev_wire&)> s)
    { m_cluster_event_sink = std::move(s); }

    void set_route_sink(route_relay::sink* sink) { m_route_sink = sink; }
    route_relay::sink* route_sink() const { return m_route_sink; }

    // The map has changed and anything naming a runtime leaving it must let
    // go, which only proxy_supervisor::retire() can do safely, while the
    // placeholder is still known to be alive.
    void set_worker_release_sink(std::function<void()> sink);
    void release_workers() const;
    // Waits for a started runtime's workers to answer, as the CLI's start does, and gives their refusal or "".
    void set_worker_await_sink(std::function<std::string(std::string_view)> sink) { m_worker_await_sink = std::move(sink); }
    std::string await_workers(std::string_view name) const
    { return m_worker_await_sink ? m_worker_await_sink(name) : std::string(); }

    // Where a runtime sends a request meant for another runtime, one per
    // daemon, whose sink table is the third thing publish_endpoints()
    // rebuilds.
    request_channel& requests() { return m_requests; }
    const request_channel& requests() const { return m_requests; }

    const runtime_map& list() const;
    runtime_instance* get(std::string_view name);

    // Cluster discovery integration
    void set_cluster_discovery(cluster_discovery* cd);
    cluster_discovery* get_cluster_discovery() const;

    // Where the primary of each Raft cluster cache is reached, published as a group named for the cache so that a proxy
    // with `--backend @<name>` follows it; republished when it changes.
    using cluster_primaries = std::map<std::string, std::pair<std::string, uint16_t>>;
    void set_cluster_primaries(cluster_primaries primaries);

    mutable replica_mutex mutex;

private:
    // The names one cascade has already descended into, threaded through
    // rather than a member, so two cascades share no state and the public
    // entry points stay re-entrant.
    using cascade_seen = std::unordered_set<std::string>;

    // The recursive halves of stop()/stop_children()/remove_children(), which
    // the public spellings call with an empty set.
    bool stop_cascading(std::string_view name, event_loop& loop, cascade_seen& seen);
    void stop_children_cascading(std::string_view parent, event_loop& loop, cascade_seen& seen);
    void remove_children_cascading(std::string_view parent, event_loop& loop, cascade_seen& seen);

    // Takes over an instance that has just left the map, called with the map
    // lock released.
    void retire(std::unique_ptr<runtime_instance> inst);

    // True while a Lua callback is on this thread's stack, and false in a
    // build with no Lua at all.
    static bool script_frame_live();

    std::function<void(const endpoint_table&)> m_endpoint_sink;
    std::function<void(request_channel&)> m_shard_sink_publisher;
    std::function<void(std::string_view, std::string_view, std::string_view)> m_publish_sink;
    std::function<bool(std::string_view, std::string_view)> m_deliver_sink;
    std::function<bool(std::string_view, std::string_view,
                       std::string_view, std::string&)> m_map_sink;
    std::function<void()> m_worker_release_sink;
    std::function<std::string(std::string_view)> m_worker_await_sink;
    route_relay::sink*    m_route_sink{nullptr};
    std::function<void(const cluster_ev_wire&)> m_cluster_event_sink;

    // Declared before the map and the graveyard so it is destroyed after them,
    // because ~server_instance revokes its origin here and a channel destroyed
    // first is a call into freed storage.
    request_channel m_requests;

    runtime_map runtimes;

    // The graveyard of instances the ring may still point into, drained by
    // reap_retired() as completions land and by free_retired() at shutdown.
    std::vector<std::unique_ptr<runtime_instance>> m_retired;
    size_t m_retired_warn_at = 32;

    // Set by a reader on another thread, read by the event-loop thread on every
    // sweep, so it has to be an atomic even though it only ever goes false→true.
    std::atomic<bool> m_offthread_stats{false};

    // See mark_replica(): a plain bool, written once at wiring time and read
    // on the one thread that touches this object in a worker.
    bool m_replica = false;

    // One row of a push written into the replica, with the mutex held and a replaced object handed to `dropped`.
    void upsert_replica_row(const replica_entry& e, std::vector<std::unique_ptr<runtime_instance>>& dropped);

    cluster_discovery* m_cluster = nullptr;
    cluster_primaries  m_cluster_primaries;
};
