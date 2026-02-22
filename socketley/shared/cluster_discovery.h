#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <functional>
#include <cstdint>
#include <ctime>

#include "event_loop_definitions.h"
#include <linux/time_types.h>

class event_loop;
class runtime_manager;

struct cluster_event
{
    enum type_t { daemon_join, daemon_leave, group_change } kind;
    std::string daemon_name;   // for join/leave
    std::string group_name;    // for group_change
    int member_count = 0;      // for group_change (new count)
};

struct remote_runtime
{
    std::string daemon_name;
    std::string host;
    std::string name;
    std::string type;
    std::string group;
    uint16_t port = 0;
    std::string state;
    size_t connections = 0;
};

struct remote_daemon
{
    std::string name;
    std::string host;
    time_t heartbeat = 0;
    std::vector<remote_runtime> runtimes;
};

class cluster_discovery : public io_handler
{
public:
    cluster_discovery(std::string_view daemon_name,
                      std::string_view cluster_dir,
                      runtime_manager& manager);
    ~cluster_discovery() override;

    // Start the publish/scan timer cycle.
    // Returns false if a daemon with the same name is already active in the cluster.
    bool start(event_loop& loop);

    // Stop and unpublish (graceful shutdown)
    void stop();

    // Get remote runtimes matching a group (thread-safe, returns snapshot)
    struct remote_endpoint { std::string host; uint16_t port; };
    std::vector<remote_endpoint> get_remote_group(std::string_view group) const;

    // Get all remote daemons (thread-safe, returns snapshot)
    std::vector<remote_daemon> get_all_daemons() const;

    // Event callback for topology changes
    using event_callback_t = std::function<void(const std::vector<cluster_event>&)>;
    void set_event_callback(event_callback_t cb);

    // Get the cluster directory path
    std::string_view get_cluster_dir() const { return m_cluster_dir; }

    // Get this daemon's name
    std::string_view get_daemon_name() const { return m_daemon_name; }

    // Get the advertised cluster address
    std::string_view get_cluster_addr() const { return m_cluster_addr; }

    // io_handler — timer CQE callback
    void on_cqe(struct io_uring_cqe* cqe) override;

private:
    // Publish this daemon's state to <cluster_dir>/<name>.json
    void publish();

    // Scan all *.json files in cluster_dir (skip own), update cache
    void scan();

    // Delete this daemon's JSON file
    void unpublish();

    // Schedule the next timer
    void schedule_timer();

    // Build JSON string for this daemon's state
    std::string build_publish_json() const;

    // Parse a remote daemon's JSON file into remote_daemon struct
    bool parse_daemon_json(const std::string& json, remote_daemon& out) const;

    std::string m_daemon_name;
    std::string m_cluster_dir;
    std::string m_cluster_addr;   // advertised host for remote daemons
    runtime_manager& m_manager;
    event_loop* m_loop = nullptr;

    // Timer
    io_request m_timer_req{};
    struct __kernel_timespec m_timer_ts{};

    // Cached remote daemons (protected by mutex)
    mutable std::mutex m_remote_mutex;
    std::unordered_map<std::string, remote_daemon> m_remote_daemons;

    // mtime cache: filename → last seen mtime (skip re-reading unchanged files)
    std::unordered_map<std::string, time_t> m_mtime_cache;

    // Change detection for event callbacks
    event_callback_t m_event_callback;
    std::unordered_set<std::string> m_previous_daemon_names;
    std::unordered_map<std::string, int> m_previous_group_counts;

    static constexpr int PUBLISH_INTERVAL_SEC = 2;
    static constexpr int STALE_THRESHOLD_SEC = 10;
};
