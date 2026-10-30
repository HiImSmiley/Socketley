#pragma once
#include <cstddef>
#include <cstdint>
#include <atomic>
#include <string>
#include <thread>
#include <chrono>
#include <functional>
#include <memory>
#include <unordered_map>
#include <utility>
#include <vector>

#include "../shared/runtime/metric_catalog.h"
#include "dashboard.h"

class runtime_manager;

class metrics_endpoint
{
public:
    metrics_endpoint(runtime_manager& mgr);
    ~metrics_endpoint();

    struct options
    {
        // The file the dashboard's admins sign in from, empty for a read-only page.
        std::string dashboard_credentials;
        // The state directory, whose disk the fact series measure.
        std::string state_dir;
        // The URL alerts are posted to, which the page's test reaches, empty for none.
        std::string alert_webhook;
        // The idp runtime whose admins sign in to the dashboard, empty for none.
        std::string dashboard_idp;
    };
    bool start(uint16_t port, options o = {});
    void stop();

    // What the fact series read slowly, kept from one render to the next.
    struct fact_cache
    {
        // Each certificate's end in seconds since the epoch, INT64_MIN when it cannot be read, and when it was read.
        std::unordered_map<std::string, std::pair<int64_t, int64_t>> certs;
        // Each storage directory's mirrors: the runtime, the repository's name and id, and whether its last pull failed.
        struct mirror
        {
            std::string runtime, repo, id;
            bool failed;
            // What the failed pull said, its first line.
            std::string error;
        };
        std::vector<mirror> mirrors;
        std::vector<std::string> mirror_dirs;
        int64_t mirrors_at{INT64_MIN};
        size_t last_size{0};
    };

    // Every series /metrics writes, family after family, handed to `out`: the text of /metrics and a metrics runtime's
    // local feed are this one walk, so the two cannot disagree on a name or a label. `refresh_memory` reads each
    // process's memory again rather than taking what the last sample read.
    static void walk_series(const runtime_manager& manager, fact_cache& cache, const std::string& state_dir,
                            bool refresh_memory, socketley::metric_catalog::sink_ref out);

private:
    void serve_loop();
    void serve(int fd, const dashboard::request& req, bool via);
    std::string build_metrics() const;
    std::string build_json_overview() const;
    std::string build_json_runtimes() const;
    std::string build_json_runtime(std::string_view name) const;
    // The page's history of a runtime, '' for all of them, and its alerts, both read from a metrics runtime.
    std::string history_json(std::string_view runtime, int64_t range, size_t points) const;
    std::string alerts_json() const;

    runtime_manager& m_manager;
    std::unique_ptr<dashboard::server> m_dash;
    std::string m_state_dir;
    std::string m_webhook;
    int m_listen_fd{-1};

    // How stop() reaches a thread parked waiting for a connection, so stopping
    // is a byte and a join rather than a close of a descriptor the other
    // thread is still naming.
    int m_wake_fd{-1};

    std::atomic<bool> m_running{false};
    std::thread m_thread;
    std::chrono::steady_clock::time_point m_start_time{};

    std::unique_ptr<fact_cache> m_facts;
    mutable std::string m_cached_metrics;
    mutable std::string m_cached_json_overview;
    mutable std::string m_cached_json_runtimes;
    mutable std::chrono::steady_clock::time_point m_cache_time{};
    static constexpr auto METRICS_CACHE_TTL = std::chrono::seconds(1);
    // How long a connection has to send its whole request, and how many may be sending one at once.
    static constexpr auto request_deadline = std::chrono::seconds(5);
    static constexpr size_t max_waiting = 32;
};
