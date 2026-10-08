#pragma once
#include <cstdint>
#include <atomic>
#include <string>
#include <thread>
#include <chrono>
#include <memory>

#include "dashboard.h"

class runtime_manager;

class metrics_endpoint
{
public:
    metrics_endpoint(runtime_manager& mgr);
    ~metrics_endpoint();

    // `dashboard_credentials` is the file the dashboard's admins sign in from, empty for a read-only page.
    bool start(uint16_t port, std::string dashboard_credentials = {});
    void stop();

private:
    void serve_loop();
    void serve(int fd, const dashboard::request& req, bool via);
    std::string build_metrics() const;
    std::string build_json_overview() const;
    std::string build_json_runtimes() const;
    std::string build_json_runtime(std::string_view name) const;

    runtime_manager& m_manager;
    std::unique_ptr<dashboard::server> m_dash;
    int m_listen_fd{-1};

    // How stop() reaches a thread parked waiting for a connection, so stopping
    // is a byte and a join rather than a close of a descriptor the other
    // thread is still naming.
    int m_wake_fd{-1};

    std::atomic<bool> m_running{false};
    std::thread m_thread;
    std::chrono::steady_clock::time_point m_start_time{};

    mutable std::string m_cached_metrics;
    mutable std::string m_cached_json_overview;
    mutable std::string m_cached_json_runtimes;
    mutable std::chrono::steady_clock::time_point m_cache_time{};
    static constexpr auto METRICS_CACHE_TTL = std::chrono::seconds(1);
};
