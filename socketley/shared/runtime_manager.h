#pragma once

#include <unordered_map>
#include <memory>
#include <string>
#include <string_view>
#include <shared_mutex>
#include <functional>
#include <vector>

#include "runtime_instance.h"

class event_loop;
class cluster_discovery;
struct cluster_event;

// Transparent hash for heterogeneous lookup (avoids string copies on find)
struct runtime_string_hash
{
    using is_transparent = void;

    size_t operator()(std::string_view sv) const noexcept
    {
        return std::hash<std::string_view>{}(sv);
    }

    size_t operator()(const std::string& s) const noexcept
    {
        return std::hash<std::string_view>{}(s);
    }
};

struct runtime_string_equal
{
    using is_transparent = void;

    bool operator()(std::string_view lhs, std::string_view rhs) const noexcept
    {
        return lhs == rhs;
    }
};

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

    // Cross-runtime pub/sub: dispatch a published message to all runtimes
    void dispatch_publish(std::string_view cache_name, std::string_view channel, std::string_view message);

    // Cluster event dispatch: forward topology changes to all runtimes with Lua callbacks
    void dispatch_cluster_events(const std::vector<cluster_event>& events);

    // Ownership cascading
    std::vector<std::string> get_children(std::string_view parent_name) const;
    void stop_children(std::string_view parent_name, event_loop& loop);
    void remove_children(std::string_view parent_name, event_loop& loop);

    // Group query: return all running instances with the given group tag
    std::vector<runtime_instance*> get_by_group(std::string_view group) const;

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

    cluster_discovery* m_cluster = nullptr;
};
