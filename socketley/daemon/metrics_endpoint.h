#pragma once
#include <cstdint>
#include <atomic>
#include <string>
#include <thread>
#include <chrono>
#include <memory>

#include "dashboard.h"
#include "alerts.h"
#include "history.h"

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
        // Where the history and the alerts told of are kept, empty to keep them in memory only.
        std::string state_dir;
        // The URL alerts are posted to, empty for none, and what takes each message for it.
        std::string alert_webhook;
        std::function<void(std::string)> alert_send;
        // What publishes each alert raised and cleared on daemon.events, empty for nothing.
        std::function<void(std::string, std::string)> alert_event;
        // The idp runtime whose admins sign in to the dashboard, empty for none.
        std::string dashboard_idp;
    };
    bool start(uint16_t port, options o = {});
    void stop();

private:
    void serve_loop();
    void serve(int fd, const dashboard::request& req, bool via);
    std::string build_metrics() const;
    std::string build_json_overview() const;
    std::string build_json_runtimes() const;
    std::string build_json_runtime(std::string_view name) const;
    // Every runtime's figures and the daemon's, into the history, and a look for what is wrong.
    void sample();

    runtime_manager& m_manager;
    std::unique_ptr<dashboard::server> m_dash;
    std::unique_ptr<history::keeper> m_history;
    std::unique_ptr<alerts::monitor> m_alerts;
    std::string m_state_dir;
    std::chrono::steady_clock::time_point m_next_sample{}, m_next_save{};
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
