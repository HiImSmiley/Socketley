#pragma once

#include <unordered_map>
#include <memory>
#include <string>
#include <string_view>
#include <shared_mutex>
#include <functional>

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
    bool run(std::string_view name, event_loop& loop);
    bool stop(std::string_view name, event_loop& loop);
    bool remove(std::string_view name);
    // Like remove(), but returns ownership so the caller controls when destruction happens.
    std::unique_ptr<runtime_instance> extract(std::string_view name);
    bool rename(std::string_view old_name, std::string_view new_name);
    void stop_all(event_loop& loop);

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
    runtime_map runtimes;
    cluster_discovery* m_cluster = nullptr;
};
