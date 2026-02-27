#include "metrics_endpoint.h"
#include "dashboard_html.h"
#include "../shared/runtime_manager.h"
#include "../shared/runtime_instance.h"

#include <unistd.h>
#include <cstring>
#include <charconv>
#include <sstream>
#include <shared_mutex>
#include <thread>
#include <chrono>
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
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
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
    m_start_time = std::chrono::steady_clock::now();
    m_thread = std::thread(&metrics_endpoint::serve_loop, this);
    return true;
}

void metrics_endpoint::stop()
{
    bool was = m_running.exchange(false, std::memory_order_acq_rel);
    if (m_listen_fd >= 0)
    {
        close(m_listen_fd);
        m_listen_fd = -1;
    }
    if (was && m_thread.joinable())
        m_thread.join();
}

static void send_http_response(int fd, std::string_view content_type, std::string_view body)
{
    std::string response;
    response.reserve(body.size() + 256);
    response += "HTTP/1.1 200 OK\r\nContent-Type: ";
    response += content_type;
    response += "\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: ";
    char len_buf[24];
    auto [end, ec] = std::to_chars(len_buf, len_buf + sizeof(len_buf), body.size());
    response.append(len_buf, end - len_buf);
    response += "\r\n\r\n";
    response += body;
    // Blocking write is fine for dashboard (small payload, rare calls)
    if (::write(fd, response.data(), response.size()) < 0) { /* ignore */ }
}

static void send_http_404(int fd)
{
    static constexpr const char* resp =
        "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNot Found";
    if (::write(fd, resp, std::strlen(resp)) < 0) { /* ignore */ }
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

        char buf[2048];
        ssize_t n = read(client_fd, buf, sizeof(buf) - 1);
        if (n > 0)
        {
            buf[n] = '\0';

            if (std::strncmp(buf, "GET ", 4) == 0)
            {
                // Extract path
                const char* path_start = buf + 4;
                const char* path_end = std::strchr(path_start, ' ');
                if (!path_end) path_end = path_start + std::strlen(path_start);
                std::string_view path(path_start, path_end - path_start);

                if (path == "/" || path == "/dashboard")
                {
                    send_http_response(client_fd, "text/html; charset=utf-8", DASHBOARD_HTML);
                }
                else if (path == "/metrics")
                {
                    std::string body = build_metrics();
                    send_http_response(client_fd, "text/plain; version=0.0.4; charset=utf-8", body);
                }
                else if (path == "/api/overview")
                {
                    std::string body = build_json_overview();
                    send_http_response(client_fd, "application/json", body);
                }
                else if (path == "/api/runtimes")
                {
                    std::string body = build_json_runtimes();
                    send_http_response(client_fd, "application/json", body);
                }
                else if (path.starts_with("/api/runtime/"))
                {
                    std::string_view name = path.substr(13);
                    std::string body = build_json_runtime(name);
                    if (body.empty())
                        send_http_404(client_fd);
                    else
                        send_http_response(client_fd, "application/json", body);
                }
                else
                {
                    send_http_404(client_fd);
                }
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

static const char* runtime_type_str(runtime_type t)
{
    switch (t)
    {
        case runtime_server: return "server";
        case runtime_client: return "client";
        case runtime_proxy:  return "proxy";
        case runtime_cache:  return "cache";
        default:             return "unknown";
    }
}

static const char* runtime_state_str(runtime_state s)
{
    switch (s)
    {
        case runtime_created: return "created";
        case runtime_running: return "running";
        case runtime_stopped: return "stopped";
        case runtime_failed:  return "failed";
        default:              return "unknown";
    }
}

// Escape a JSON string value (minimal: just quotes and backslashes)
static void json_escape_into(std::string& out, std::string_view s)
{
    for (char c : s)
    {
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else out += c;
    }
}

static void json_append_uint(std::string& out, uint64_t v)
{
    char buf[24];
    auto [end, ec] = std::to_chars(buf, buf + sizeof(buf), v);
    out.append(buf, end - buf);
}

std::string metrics_endpoint::build_json_overview() const
{
    std::shared_lock lock(m_manager.mutex);
    const auto& runtimes = m_manager.list();

    uint64_t total_connections = 0, total_messages = 0;
    uint64_t total_bytes_in = 0, total_bytes_out = 0;
    uint64_t active_connections = 0;
    int running_count = 0;

    for (const auto& [name, rt] : runtimes)
    {
        total_connections += rt->m_stat_total_connections.load(std::memory_order_relaxed);
        total_messages += rt->m_stat_total_messages.load(std::memory_order_relaxed);
        total_bytes_in += rt->m_stat_bytes_in.load(std::memory_order_relaxed);
        total_bytes_out += rt->m_stat_bytes_out.load(std::memory_order_relaxed);
        active_connections += rt->get_connection_count();
        if (rt->get_state() == runtime_running) running_count++;
    }

    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - m_start_time).count();

    std::string j;
    j.reserve(512);
    j += "{\"version\":\"1.0.6\",\"uptime_seconds\":";
    json_append_uint(j, static_cast<uint64_t>(uptime));
    j += ",\"runtimes_total\":";
    json_append_uint(j, runtimes.size());
    j += ",\"runtimes_running\":";
    json_append_uint(j, static_cast<uint64_t>(running_count));
    j += ",\"connections_total\":";
    json_append_uint(j, total_connections);
    j += ",\"connections_active\":";
    json_append_uint(j, active_connections);
    j += ",\"messages_total\":";
    json_append_uint(j, total_messages);
    j += ",\"bytes_in\":";
    json_append_uint(j, total_bytes_in);
    j += ",\"bytes_out\":";
    json_append_uint(j, total_bytes_out);
    j += "}";
    return j;
}

std::string metrics_endpoint::build_json_runtimes() const
{
    std::shared_lock lock(m_manager.mutex);
    const auto& runtimes = m_manager.list();

    std::string j;
    j.reserve(runtimes.size() * 256);
    j += "[";

    bool first = true;
    for (const auto& [name, rt] : runtimes)
    {
        if (!first) j += ",";
        first = false;

        j += "{\"name\":\"";
        json_escape_into(j, name);
        j += "\",\"type\":\"";
        j += runtime_type_str(rt->get_type());
        j += "\",\"state\":\"";
        j += runtime_state_str(rt->get_state());
        j += "\",\"port\":";
        json_append_uint(j, rt->get_port());
        j += ",\"connections\":";
        json_append_uint(j, rt->get_connection_count());
        j += ",\"messages_total\":";
        json_append_uint(j, rt->m_stat_total_messages.load(std::memory_order_relaxed));
        j += ",\"connections_total\":";
        json_append_uint(j, rt->m_stat_total_connections.load(std::memory_order_relaxed));
        j += ",\"bytes_in\":";
        json_append_uint(j, rt->m_stat_bytes_in.load(std::memory_order_relaxed));
        j += ",\"bytes_out\":";
        json_append_uint(j, rt->m_stat_bytes_out.load(std::memory_order_relaxed));
        j += "}";
    }

    j += "]";
    return j;
}

std::string metrics_endpoint::build_json_runtime(std::string_view name) const
{
    std::shared_lock lock(m_manager.mutex);
    const auto& runtimes = m_manager.list();

    auto it = runtimes.find(std::string(name));
    if (it == runtimes.end())
        return {};

    const auto& rt = it->second;
    std::string j;
    j.reserve(512);
    j += "{\"name\":\"";
    json_escape_into(j, name);
    j += "\",\"type\":\"";
    j += runtime_type_str(rt->get_type());
    j += "\",\"state\":\"";
    j += runtime_state_str(rt->get_state());
    j += "\",\"port\":";
    json_append_uint(j, rt->get_port());
    j += ",\"connections\":";
    json_append_uint(j, rt->get_connection_count());
    j += ",\"messages_total\":";
    json_append_uint(j, rt->m_stat_total_messages.load(std::memory_order_relaxed));
    j += ",\"connections_total\":";
    json_append_uint(j, rt->m_stat_total_connections.load(std::memory_order_relaxed));
    j += ",\"bytes_in\":";
    json_append_uint(j, rt->m_stat_bytes_in.load(std::memory_order_relaxed));
    j += ",\"bytes_out\":";
    json_append_uint(j, rt->m_stat_bytes_out.load(std::memory_order_relaxed));

    // Add detailed stats if available
    std::string stats = rt->get_stats();
    if (!stats.empty())
    {
        j += ",\"stats\":\"";
        json_escape_into(j, stats);
        j += "\"";
    }

    j += "}";
    return j;
}
