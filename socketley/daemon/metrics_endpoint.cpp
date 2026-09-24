#include "metrics_endpoint.h"
#include "dashboard_html.h"
#include "../shared/runtime_manager.h"
#include "../shared/runtime_instance.h"
#include "../shared/blocking_write.h"
#include "../shared/logging.h"
#include "../shared/version.h"
#include "../shared/runtime_definitions.h"
#include "../shared/daemon_client.h"
#include "daemon_handler.h"

#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <charconv>
#include <cstdio>
#include <shared_mutex>
#include <thread>
#include <chrono>
#include <vector>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/eventfd.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <fcntl.h>

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
    // SOCK_CLOEXEC because the daemon forks proxy workers, and with
    // SO_REUSEADDR but not SO_REUSEPORT an inherited copy keeps the metrics
    // port bound after the daemon is gone.
    m_listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (m_listen_fd < 0)
        return false;

    int opt = 1;
    setsockopt(m_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    // Raw close, and every close in this file is: see serve_loop() for why none
    // of these descriptors is the event loop's to hold.
    if (bind(m_listen_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        LOG_ERROR(("metrics: port " + std::to_string(port) + " could not be bound: " +
                   std::string(std::strerror(errno))).c_str());
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

    // The listener is polled rather than blocked on, so accept() must be able
    // to say nothing after all when a reset takes the pending connection away
    // again.
    int flags = fcntl(m_listen_fd, F_GETFL, 0);
    if (flags < 0 || fcntl(m_listen_fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }

    // Accepted sockets do not inherit O_NONBLOCK on Linux, so the read() and
    // write_all() below block, each bounded by the timeouts serve_loop sets.

    m_wake_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (m_wake_fd < 0)
    {
        close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }

    // From here a second thread reads runtimes, so the manager is asked to
    // publish the figures this endpoint needs and nothing below reads a live
    // connection table.
    m_manager.enable_offthread_stats();

    m_running.store(true, std::memory_order_release);
    m_start_time = std::chrono::steady_clock::now();
    m_thread = std::thread(&metrics_endpoint::serve_loop, this);
    return true;
}

void metrics_endpoint::stop()
{
    bool was = m_running.exchange(false, std::memory_order_acq_rel);

    // Ring the bell, wait, then close, because closing a descriptor another
    // thread is inside a syscall on frees the number at once and a runtime
    // starting its listener is handed it.
    if (m_wake_fd >= 0)
    {
        const uint64_t one = 1;
        // Nothing to do if it fails: a full eventfd counter is already a
        // pending wake, and the loop re-reads m_running on every pass anyway.
        if (write(m_wake_fd, &one, sizeof(one)) < 0) {}
    }

    if (was && m_thread.joinable())
        m_thread.join();

    // Raw close — see serve_loop() for why none of this file's descriptors is
    // the event loop's to hold.
    if (m_listen_fd >= 0)
    {
        close(m_listen_fd);
        m_listen_fd = -1;
    }
    if (m_wake_fd >= 0)
    {
        close(m_wake_fd);
        m_wake_fd = -1;
    }
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
    // Content-Length promises the whole body, so a short write here leaves the
    // scraper waiting for bytes that are never coming.
    socketley::write_all(fd, response.data(), response.size());
}

static void send_http_404(int fd)
{
    static constexpr const char* resp =
        "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNot Found";
    socketley::write_all(fd, resp, std::strlen(resp));
}

void metrics_endpoint::serve_loop()
{
    while (m_running.load(std::memory_order_acquire))
    {
        // Both, always, because the listener alone left this thread parked in
        // accept() with no way for stop() to reach it.
        struct pollfd fds[2];
        fds[0] = { m_listen_fd, POLLIN, 0 };
        fds[1] = { m_wake_fd,   POLLIN, 0 };

        int ready = poll(fds, 2, -1);
        if (ready < 0)
        {
            if (errno == EINTR)
                continue;
            break;
        }

        // stop() rang, and leaving now is what lets it join before it closes
        // either descriptor.
        if (fds[1].revents != 0)
            break;

        if ((fds[0].revents & POLLIN) == 0)
            continue;

        struct sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);

        // accept4 rather than accept, because this runs on its own thread and
        // a fork for a proxy worker can land between the accept and any later
        // fcntl.
        int client_fd = accept4(m_listen_fd, reinterpret_cast<struct sockaddr*>(&client_addr),
                                &client_len, SOCK_CLOEXEC);
        if (client_fd < 0)
            continue;

        // Bounded both ways, because this thread serves one connection at a
        // time and a peer that connects and says nothing held every scrape,
        // and stop() with them.
        const struct timeval io_bound{2, 0};
        if (setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &io_bound, sizeof(io_bound)) < 0 ||
            setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &io_bound, sizeof(io_bound)) < 0)
        {
            close(client_fd);
            continue;
        }

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
                    auto now = std::chrono::steady_clock::now();
                    if ((now - m_cache_time) >= METRICS_CACHE_TTL)
                    {
                        m_cached_metrics = build_metrics();
                        m_cached_json_overview.clear();
                        m_cached_json_runtimes.clear();
                        m_cache_time = now;
                    }
                    // The branch both JSON endpoints have and this one did
                    // not: the three share one cache and one clock, and each
                    // refresh empties the other two.  A dashboard poll inside
                    // the TTL therefore left this serving 200 OK with
                    // Content-Length: 0 -- a scrape Prometheus records as
                    // successful, with every socketley_ series missing from
                    // that sample.
                    else if (m_cached_metrics.empty())
                    {
                        m_cached_metrics = build_metrics();
                    }
                    send_http_response(client_fd, "text/plain; version=0.0.4; charset=utf-8", m_cached_metrics);
                }
                else if (path == "/api/overview")
                {
                    auto now = std::chrono::steady_clock::now();
                    if ((now - m_cache_time) >= METRICS_CACHE_TTL)
                    {
                        m_cached_json_overview = build_json_overview();
                        m_cached_metrics.clear();
                        m_cached_json_runtimes.clear();
                        m_cache_time = now;
                    }
                    else if (m_cached_json_overview.empty())
                    {
                        m_cached_json_overview = build_json_overview();
                    }
                    send_http_response(client_fd, "application/json", m_cached_json_overview);
                }
                else if (path == "/api/runtimes")
                {
                    auto now = std::chrono::steady_clock::now();
                    if ((now - m_cache_time) >= METRICS_CACHE_TTL)
                    {
                        m_cached_json_runtimes = build_json_runtimes();
                        m_cached_metrics.clear();
                        m_cached_json_overview.clear();
                        m_cache_time = now;
                    }
                    else if (m_cached_json_runtimes.empty())
                    {
                        m_cached_json_runtimes = build_json_runtimes();
                    }
                    send_http_response(client_fd, "application/json", m_cached_json_runtimes);
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

        // Raw close and the right one, because no SQE has ever named this
        // descriptor and close_fd() would be a plain data race against the
        // event-loop thread's own tables.
        close(client_fd);
    }
}

// A control character has no literal spelling in a JSON string, and this
// escaper passed every one but newline through raw -- reachable because
// m_stat_detail is a registered type's own get_stats() text, which is whatever
// the plugin author writes.
static void json_escape_into(std::string& out, std::string_view s)
{
    for (char c : s)
    {
        switch (c)
        {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20)
                {
                    char u[7];
                    std::snprintf(u, sizeof(u), "\\u%04x",
                                  static_cast<unsigned>(static_cast<unsigned char>(c)));
                    out += u;
                }
                else
                    out += c;
        }
    }
}

// The same three characters as json_escape_into was before it was fixed, and
// separate from it because Prometheus takes a raw tab in a label value and
// rejects the \t that JSON now requires.
static void label_escape_into(std::string& out, std::string_view s)
{
    for (char c : s)
    {
        if (c == '\\')      out += "\\\\";
        else if (c == '"')  out += "\\\"";
        else if (c == '\n') out += "\\n";
        else                out += c;
    }
}

static void json_append_uint(std::string& out, uint64_t v)
{
    char buf[24];
    auto [end, ec] = std::to_chars(buf, buf + sizeof(buf), v);
    out.append(buf, end - buf);
}

std::string metrics_endpoint::build_metrics() const
{
    // Snapshot runtime data under lock
    struct runtime_snapshot {
        std::string name;
        runtime_type type;
        runtime_state state;
        uint64_t total_connections, total_messages, bytes_in, bytes_out;
        size_t active_connections;
    };
    std::vector<runtime_snapshot> snapshots;
    {
        std::shared_lock lock(m_manager.mutex);
        const auto& runtimes = m_manager.list();
        snapshots.reserve(runtimes.size());
        for (const auto& [name, rt] : runtimes)
        {
            // The published count and not get_connection_count(), which walks
            // tables the event loop rewrites unsynchronised -- except for a
            // runtime in a worker, where worker_figures() sums a shared table
            // as safely as reading an atomic.
            const shard_stats::figures f = rt->worker_figures();
            snapshots.push_back({name, rt->get_type(), rt->get_state(),
                f.total_connections,
                f.total_messages,
                f.bytes_in,
                f.bytes_out,
                static_cast<size_t>(f.active_connections)});
        }
    }

    // Now build metrics string without holding lock
    uint64_t total_connections = 0;
    uint64_t total_messages = 0;
    uint64_t total_bytes_in = 0;
    uint64_t total_bytes_out = 0;
    uint64_t active_connections = 0;
    int running_count = 0;
    int total_count = static_cast<int>(snapshots.size());

    for (const auto& s : snapshots)
    {
        total_connections += s.total_connections;
        total_messages += s.total_messages;
        total_bytes_in += s.bytes_in;
        total_bytes_out += s.bytes_out;
        active_connections += s.active_connections;

        if (s.state == runtime_running)
            running_count++;
    }

    std::string out;
    out.reserve(2048 + snapshots.size() * 256);

    // Prometheus exposition format
    //
    // Which daemon answered, first: several may serve one machine and every
    // series below is identically named on each of them.  The scrape target
    // distinguishes them only for whoever configured the scrape.
    std::string exe;
    uint64_t dev = 0, ino = 0;
    if (!socketley::self_exe_identity(exe, dev, ino))
        exe.clear();

    out += "# HELP socketley_daemon_info The daemon these numbers come from.\n"
           "# TYPE socketley_daemon_info gauge\n"
           "socketley_daemon_info{version=\"";
    label_escape_into(out, SOCKETLEY_VERSION);
    out += "\",pid=\"";
    json_append_uint(out, static_cast<uint64_t>(::getpid()));
    out += "\",socket=\"";
    label_escape_into(out, daemon_handler::socket_path);
    out += "\",exe=\"";
    label_escape_into(out, exe);
    out += "\"} 1\n\n";

    out += "# HELP socketley_runtimes_total Total number of runtimes.\n"
           "# TYPE socketley_runtimes_total gauge\n"
           "socketley_runtimes_total ";
    json_append_uint(out, static_cast<uint64_t>(total_count));
    out += "\n\n# HELP socketley_runtimes_running Number of running runtimes.\n"
           "# TYPE socketley_runtimes_running gauge\n"
           "socketley_runtimes_running ";
    json_append_uint(out, static_cast<uint64_t>(running_count));
    out += "\n\n# HELP socketley_connections_total Total connections accepted.\n"
           "# TYPE socketley_connections_total counter\n"
           "socketley_connections_total ";
    json_append_uint(out, total_connections);
    out += "\n\n# HELP socketley_connections_active Current active connections.\n"
           "# TYPE socketley_connections_active gauge\n"
           "socketley_connections_active ";
    json_append_uint(out, active_connections);
    out += "\n\n# HELP socketley_messages_total Total messages processed.\n"
           "# TYPE socketley_messages_total counter\n"
           "socketley_messages_total ";
    json_append_uint(out, total_messages);
    out += "\n\n# HELP socketley_bytes_received_total Total bytes received.\n"
           "# TYPE socketley_bytes_received_total counter\n"
           "socketley_bytes_received_total ";
    json_append_uint(out, total_bytes_in);
    out += "\n\n# HELP socketley_bytes_sent_total Total bytes sent.\n"
           "# TYPE socketley_bytes_sent_total counter\n"
           "socketley_bytes_sent_total ";
    json_append_uint(out, total_bytes_out);
    out += "\n\n";

    // Per-runtime metrics
    out += "# HELP socketley_runtime_connections Active connections per runtime.\n"
           "# TYPE socketley_runtime_connections gauge\n";
    for (const auto& s : snapshots)
    {
        if (s.state != runtime_running)
            continue;

        // The registry, not a switch over the four built-ins: a registered
        // type has no enumerator to name and was scraped as "unknown".
        const char* type_str = type_to_string(s.type);

        out += "socketley_runtime_connections{name=\"";
        label_escape_into(out, s.name);
        out += "\",type=\"";
        label_escape_into(out, type_str);
        out += "\"} ";
        json_append_uint(out, static_cast<uint64_t>(s.active_connections));
        out += "\n";
    }
    out += "\n";

    out += "# HELP socketley_runtime_messages_total Total messages per runtime.\n"
           "# TYPE socketley_runtime_messages_total counter\n";
    for (const auto& s : snapshots)
    {
        out += "socketley_runtime_messages_total{name=\"";
        label_escape_into(out, s.name);
        out += "\"} ";
        json_append_uint(out, s.total_messages);
        out += "\n";
    }

    return out;
}

static const char* runtime_type_str(runtime_type t)
{
    return type_to_string(t);
}

std::string metrics_endpoint::build_json_overview() const
{
    // Snapshot under lock
    uint64_t total_connections = 0, total_messages = 0;
    uint64_t total_bytes_in = 0, total_bytes_out = 0;
    uint64_t active_connections = 0;
    int running_count = 0;
    size_t runtimes_total = 0;
    {
        std::shared_lock lock(m_manager.mutex);
        const auto& runtimes = m_manager.list();
        runtimes_total = runtimes.size();
        for (const auto& [name, rt] : runtimes)
        {
            // Published, not live, and for a runtime in a worker summed out of
            // its shared table at this instant.
            const shard_stats::figures f = rt->worker_figures();
            total_connections += f.total_connections;
            total_messages    += f.total_messages;
            total_bytes_in    += f.bytes_in;
            total_bytes_out   += f.bytes_out;
            active_connections += f.active_connections;
            if (rt->get_state() == runtime_running) running_count++;
        }
    }

    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - m_start_time).count();

    std::string j;
    j.reserve(512);
    j += "{\"version\":\"" SOCKETLEY_VERSION "\",\"uptime_seconds\":";
    json_append_uint(j, static_cast<uint64_t>(uptime));
    j += ",\"runtimes_total\":";
    json_append_uint(j, runtimes_total);
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
    // Snapshot runtime data under lock
    struct runtimes_snapshot {
        std::string name;
        runtime_type type;
        runtime_state state;
        uint16_t port;
        uint64_t total_connections, total_messages, bytes_in, bytes_out;
        size_t active_connections;
    };
    std::vector<runtimes_snapshot> snapshots;
    {
        std::shared_lock lock(m_manager.mutex);
        const auto& runtimes = m_manager.list();
        snapshots.reserve(runtimes.size());
        for (const auto& [name, rt] : runtimes)
        {
            // Published, not live — see build_metrics().
            const shard_stats::figures f = rt->worker_figures();
            snapshots.push_back({name, rt->get_type(), rt->get_state(),
                // The bound port, the same one `ps` prints: an unset -p means
                // the type's default, and this reported 0 for a runtime that
                // was serving.
                rt->effective_port(),
                f.total_connections,
                f.total_messages,
                f.bytes_in,
                f.bytes_out,
                static_cast<size_t>(f.active_connections)});
        }
    }

    std::string j;
    j.reserve(snapshots.size() * 256);
    j += "[";

    bool first = true;
    for (const auto& s : snapshots)
    {
        if (!first) j += ",";
        first = false;

        j += "{\"name\":\"";
        json_escape_into(j, s.name);
        j += "\",\"type\":\"";
        j += runtime_type_str(s.type);
        j += "\",\"state\":\"";
        j += state_to_string(s.state);
        j += "\",\"port\":";
        json_append_uint(j, s.port);
        j += ",\"connections\":";
        json_append_uint(j, static_cast<uint64_t>(s.active_connections));
        j += ",\"messages_total\":";
        json_append_uint(j, s.total_messages);
        j += ",\"connections_total\":";
        json_append_uint(j, s.total_connections);
        j += ",\"bytes_in\":";
        json_append_uint(j, s.bytes_in);
        j += ",\"bytes_out\":";
        json_append_uint(j, s.bytes_out);
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
    j += state_to_string(rt->get_state());
    j += "\",\"port\":";
    json_append_uint(j, rt->effective_port());
    j += ",\"connections\":";
    // Published, not live, and for a runtime in a worker summed out of its
    // shared table at this instant.
    const shard_stats::figures f = rt->worker_figures();
    json_append_uint(j, f.active_connections);
    j += ",\"messages_total\":";
    json_append_uint(j, f.total_messages);
    j += ",\"connections_total\":";
    json_append_uint(j, f.total_connections);
    j += ",\"bytes_in\":";
    json_append_uint(j, f.bytes_in);
    j += ",\"bytes_out\":";
    json_append_uint(j, f.bytes_out);

    // The published text, because get_stats() is overridden per type and every
    // override reads a container the event loop rewrites underneath this
    // thread.
    std::string stats = rt->stat_detail_snapshot();
    if (!stats.empty())
    {
        j += ",\"stats\":\"";
        json_escape_into(j, stats);
        j += "\"";
    }

    j += "}";
    return j;
}
