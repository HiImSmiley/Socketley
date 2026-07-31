#pragma once
#include <cstdint>
#include <atomic>
#include <string>
#include <thread>
#include <chrono>

class runtime_manager;

class metrics_endpoint
{
public:
    metrics_endpoint(runtime_manager& mgr);
    ~metrics_endpoint();

    bool start(uint16_t port);
    void stop();

private:
    void serve_loop();
    std::string build_metrics() const;
    std::string build_json_overview() const;
    std::string build_json_runtimes() const;
    std::string build_json_runtime(std::string_view name) const;

    runtime_manager& m_manager;
    int m_listen_fd{-1};

    // How stop() reaches a thread that is parked waiting for a connection.
    // serve_loop() waits on this and the listener together, so stopping is a
    // byte written here and a join — never a close of a descriptor the other
    // thread is still naming.  See stop() for what that was.
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
