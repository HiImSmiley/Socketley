#pragma once

#include <unordered_map>
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

class event_loop;
class cluster_discovery;
struct cluster_event;

class runtime_manager
{
public:
    using runtime_map = std::unordered_map<std::string, std::unique_ptr<runtime_instance>,
                                            runtime_string_hash, runtime_string_equal>;

    bool create(runtime_type type, std::string_view name);
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

    // Ownership cascading
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

    const runtime_map& list() const;
    runtime_instance* get(std::string_view name);

    // Cluster discovery integration
    void set_cluster_discovery(cluster_discovery* cd);
    cluster_discovery* get_cluster_discovery() const;

    mutable std::shared_mutex mutex;

private:
    // Takes over an instance that has just left the map.  Called with the map
    // lock released.
    void retire(std::unique_ptr<runtime_instance> inst);

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

    cluster_discovery* m_cluster = nullptr;
};
