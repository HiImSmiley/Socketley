#include "metrics_endpoint.h"
#include "../shared/runtime_manager.h"
#include "../shared/runtime_instance.h"

#include <unistd.h>
#include <cstring>
#include <sstream>
#include <shared_mutex>
#include <thread>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

metrics_endpoint::metrics_endpoint(runtime_manager& mgr)
    : m_manager(mgr)
{
}

metrics_endpoint::~metrics_endpoint()
{
    stop();
}

bool metrics_endpoint::start(uint16_t port)
{
    m_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (m_listen_fd < 0)
        return false;

    int opt = 1;
    setsockopt(m_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(m_listen_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }

    if (listen(m_listen_fd, 16) < 0)
    {
        close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }

    m_running.store(true, std::memory_order_release);
    std::thread(&metrics_endpoint::serve_loop, this).detach();
    return true;
}

void metrics_endpoint::stop()
{
    m_running.store(false, std::memory_order_release);
    if (m_listen_fd >= 0)
    {
        close(m_listen_fd);
        m_listen_fd = -1;
    }
}

void metrics_endpoint::serve_loop()
{
    while (m_running.load(std::memory_order_acquire))
    {
        struct sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(m_listen_fd, reinterpret_cast<struct sockaddr*>(&client_addr), &client_len);
        if (client_fd < 0)
            continue;

        // Read request (we only care about GET /metrics)
        char buf[1024];
        ssize_t n = read(client_fd, buf, sizeof(buf) - 1);
        if (n > 0)
        {
            buf[n] = '\0';

            // Simple check: any GET request gets metrics
            if (std::strncmp(buf, "GET ", 4) == 0)
            {
                std::string body = build_metrics();
                std::string response;
                response.reserve(body.size() + 128);
                response += "HTTP/1.1 200 OK\r\n"
                            "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
                            "Connection: close\r\n"
                            "Content-Length: ";
                response += std::to_string(body.size());
                response += "\r\n\r\n";
                response += body;

                // Blocking write is fine for metrics (small payload, rare calls)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
                write(client_fd, response.data(), response.size());
#pragma GCC diagnostic pop
            }
        }

        close(client_fd);
    }
}

std::string metrics_endpoint::build_metrics() const
{
    std::ostringstream out;

    // Collect stats from all runtimes under shared lock
    std::shared_lock lock(m_manager.mutex);
    const auto& runtimes = m_manager.list();

    uint64_t total_connections = 0;
    uint64_t total_messages = 0;
    uint64_t total_bytes_in = 0;
    uint64_t total_bytes_out = 0;
    uint64_t active_connections = 0;
    int running_count = 0;
    int total_count = static_cast<int>(runtimes.size());

    for (const auto& [name, rt] : runtimes)
    {
        total_connections += rt->m_stat_total_connections.load(std::memory_order_relaxed);
        total_messages += rt->m_stat_total_messages.load(std::memory_order_relaxed);
        total_bytes_in += rt->m_stat_bytes_in.load(std::memory_order_relaxed);
        total_bytes_out += rt->m_stat_bytes_out.load(std::memory_order_relaxed);
        active_connections += rt->get_connection_count();

        if (rt->get_state() == runtime_running)
            running_count++;
    }

    // Prometheus exposition format
    out << "# HELP socketley_runtimes_total Total number of runtimes.\n"
        << "# TYPE socketley_runtimes_total gauge\n"
        << "socketley_runtimes_total " << total_count << "\n\n";

    out << "# HELP socketley_runtimes_running Number of running runtimes.\n"
        << "# TYPE socketley_runtimes_running gauge\n"
        << "socketley_runtimes_running " << running_count << "\n\n";

    out << "# HELP socketley_connections_total Total connections accepted.\n"
        << "# TYPE socketley_connections_total counter\n"
        << "socketley_connections_total " << total_connections << "\n\n";

    out << "# HELP socketley_connections_active Current active connections.\n"
        << "# TYPE socketley_connections_active gauge\n"
        << "socketley_connections_active " << active_connections << "\n\n";

    out << "# HELP socketley_messages_total Total messages processed.\n"
        << "# TYPE socketley_messages_total counter\n"
        << "socketley_messages_total " << total_messages << "\n\n";

    out << "# HELP socketley_bytes_received_total Total bytes received.\n"
        << "# TYPE socketley_bytes_received_total counter\n"
        << "socketley_bytes_received_total " << total_bytes_in << "\n\n";

    out << "# HELP socketley_bytes_sent_total Total bytes sent.\n"
        << "# TYPE socketley_bytes_sent_total counter\n"
        << "socketley_bytes_sent_total " << total_bytes_out << "\n\n";

    // Per-runtime metrics
    out << "# HELP socketley_runtime_connections Active connections per runtime.\n"
        << "# TYPE socketley_runtime_connections gauge\n";
    for (const auto& [name, rt] : runtimes)
    {
        if (rt->get_state() != runtime_running)
            continue;

        const char* type_str = "unknown";
        switch (rt->get_type())
        {
            case runtime_server: type_str = "server"; break;
            case runtime_client: type_str = "client"; break;
            case runtime_proxy:  type_str = "proxy";  break;
            case runtime_cache:  type_str = "cache";  break;
        }

        out << "socketley_runtime_connections{name=\"" << name
            << "\",type=\"" << type_str << "\"} "
            << rt->get_connection_count() << "\n";
    }
    out << "\n";

    out << "# HELP socketley_runtime_messages_total Total messages per runtime.\n"
        << "# TYPE socketley_runtime_messages_total counter\n";
    for (const auto& [name, rt] : runtimes)
    {
        out << "socketley_runtime_messages_total{name=\"" << name << "\"} "
            << rt->m_stat_total_messages.load(std::memory_order_relaxed) << "\n";
    }

    return out.str();
}
