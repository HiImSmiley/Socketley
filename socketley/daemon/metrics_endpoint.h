#pragma once
#include <cstdint>
#include <atomic>
#include <string>

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

    runtime_manager& m_manager;
    int m_listen_fd{-1};
    std::atomic<bool> m_running{false};
};
