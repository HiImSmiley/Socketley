#include "metrics_endpoint.h"
#include "dashboard_html.h"
#include "../shared/runtime_manager.h"
#include "../shared/runtime_instance.h"
#include "../shared/blocking_write.h"

#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <charconv>
#include <shared_mutex>
#include <thread>
#include <chrono>
#include <vector>
#include <arpa/inet.h>
#include <sys/socket.h>
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
    // SOCK_CLOEXEC because the daemon forks proxy workers.  This listener sets
    // SO_REUSEADDR and *not* SO_REUSEPORT, so an inherited copy is the one kind
    // of leak that cannot be worked around: the metrics port stays bound by a
    // worker after the daemon is gone, and the next daemon's start() fails on
    // bind with nothing on the machine to explain what holds the port.
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

    // The listener is polled, not blocked on, so accept() must be able to say
    // "nothing after all": a connection reset between poll() reporting it and
    // accept() collecting it takes the pending connection away again, and on a
    // blocking listener that leaves the thread stuck in accept() until the next
    // client happens along — which is exactly the state stop() must not have to
    // wait for.
    int flags = fcntl(m_listen_fd, F_GETFL, 0);
    if (flags < 0 || fcntl(m_listen_fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }

    // Accepted sockets do not inherit O_NONBLOCK on Linux, so the read() and
    // write_all() below stay the plain blocking calls they always were.

    m_wake_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (m_wake_fd < 0)
    {
        close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }

    // From here on there is a second thread reading runtimes, and it must not
    // touch a runtime's live connection tables — the event loop rewrites those
    // with no synchronisation.  Ask the manager to start publishing the figures
    // this endpoint needs; everything below reads only what it published.
    m_manager.enable_offthread_stats();

    m_running.store(true, std::memory_order_release);
    m_start_time = std::chrono::steady_clock::now();
    m_thread = std::thread(&metrics_endpoint::serve_loop, this);
    return true;
}

void metrics_endpoint::stop()
{
    bool was = m_running.exchange(false, std::memory_order_acq_rel);

    // Ring the bell, then wait, then close.  In that order, and the order is
    // the point.
    //
    // This used to close m_listen_fd here to break serve_loop() out of the
    // accept() it was blocked in, and only then join.  Closing a descriptor
    // another thread is inside a syscall on does not reliably end that syscall
    // — and worse, it frees the number immediately.  A runtime starting its
    // listener in the same moment is handed that very number by the kernel,
    // whose accept() then resolves to the runtime's socket: the metrics thread
    // takes a connection meant for a server or a cache, reads the client's
    // first bytes, answers with an HTTP 404, and closes it.  Nothing on either
    // side can see why.  Plain descriptor reuse; the io_uring loop is not
    // involved and neither is close_fd(), which is for descriptors the ring
    // names and cannot help a thread blocked in a syscall of its own.
    //
    // The eventfd is the thing serve_loop() waits on alongside the listener, so
    // this wakes it rather than pulling anything out from under it.  After the
    // join nothing can be naming either descriptor, and closing them is
    // ordinary.
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
        // Both, always.  The listener alone is what left this thread parked in
        // accept() with no way for stop() to reach it but closing the
        // descriptor underneath it — see stop().
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

        // stop() rang.  m_running is already false; leaving now is what lets it
        // join, and only after that join does it close either descriptor.
        if (fds[1].revents != 0)
            break;

        if ((fds[0].revents & POLLIN) == 0)
            continue;

        struct sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);

        // accept4 rather than accept: this is the only accept() syscall in the
        // daemon — every other connection arrives through io_uring, where the
        // same flag is an SQE field — and it runs on its own thread, so a fork
        // for a proxy worker can land between the accept and any fcntl that
        // tried to set FD_CLOEXEC afterwards.  Set at creation, there is no
        // such window.
        int client_fd = accept4(m_listen_fd, reinterpret_cast<struct sockaddr*>(&client_addr),
                                &client_len, SOCK_CLOEXEC);
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
                    auto now = std::chrono::steady_clock::now();
                    if ((now - m_cache_time) >= METRICS_CACHE_TTL)
                    {
                        m_cached_metrics = build_metrics();
                        m_cached_json_overview.clear();
                        m_cached_json_runtimes.clear();
                        m_cache_time = now;
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

        // Raw close, and the right one.  This whole endpoint is deliberately
        // outside the event loop: the descriptor came from an accept() on this
        // thread, was read with read() and written with write_all(), and no SQE
        // has ever named it — there is nothing queued that a reissued number
        // could be redirected onto.
        //
        // Routing it through event_loop::close_fd() would also be wrong rather
        // than merely unnecessary.  close_fd() reads and writes the loop's
        // per-descriptor tables with no synchronisation, because everything else
        // that touches them runs on the event-loop thread; calling it from here
        // would be a plain data race against that thread for a descriptor the
        // tables have no entry for.  metrics_endpoint holds no event_loop
        // reference at all, and this is the reason to keep it that way.
        close(client_fd);
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
            // The published count, not get_connection_count().  This runs on
            // m_thread, and that call walks the runtime's own connection tables
            // — a server's m_upstreams and m_active_fds, a cache's m_clients —
            // which the event loop mutates without synchronising at all.  The
            // lock held here is the manager's, and it covers the runtime map,
            // not the insides of a runtime: reading one of those maps while the
            // event loop rehashes it is undefined, not just out of date.
            // Published every 2 s by the event-loop thread, so this is up to
            // that much older than the truth on top of the response cache.
            snapshots.push_back({name, rt->get_type(), rt->get_state(),
                rt->m_stat_total_connections.load(std::memory_order_relaxed),
                rt->m_stat_total_messages.load(std::memory_order_relaxed),
                rt->m_stat_bytes_in.load(std::memory_order_relaxed),
                rt->m_stat_bytes_out.load(std::memory_order_relaxed),
                static_cast<size_t>(rt->m_stat_active_connections.load(std::memory_order_relaxed))});
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

        const char* type_str = "unknown";
        switch (s.type)
        {
            case runtime_server: type_str = "server"; break;
            case runtime_client: type_str = "client"; break;
            case runtime_proxy:  type_str = "proxy";  break;
            case runtime_cache:  type_str = "cache";  break;
        }

        out += "socketley_runtime_connections{name=\"";
        out += s.name;
        out += "\",type=\"";
        out += type_str;
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
        out += s.name;
        out += "\"} ";
        json_append_uint(out, s.total_messages);
        out += "\n";
    }

    return out;
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
            total_connections += rt->m_stat_total_connections.load(std::memory_order_relaxed);
            total_messages += rt->m_stat_total_messages.load(std::memory_order_relaxed);
            total_bytes_in += rt->m_stat_bytes_in.load(std::memory_order_relaxed);
            total_bytes_out += rt->m_stat_bytes_out.load(std::memory_order_relaxed);
            // Published, not live — see build_metrics().
            active_connections += rt->m_stat_active_connections.load(std::memory_order_relaxed);
            if (rt->get_state() == runtime_running) running_count++;
        }
    }

    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - m_start_time).count();

    std::string j;
    j.reserve(512);
    j += "{\"version\":\"1.0.9\",\"uptime_seconds\":";
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
            snapshots.push_back({name, rt->get_type(), rt->get_state(),
                rt->get_port(),
                rt->m_stat_total_connections.load(std::memory_order_relaxed),
                rt->m_stat_total_messages.load(std::memory_order_relaxed),
                rt->m_stat_bytes_in.load(std::memory_order_relaxed),
                rt->m_stat_bytes_out.load(std::memory_order_relaxed),
                static_cast<size_t>(rt->m_stat_active_connections.load(std::memory_order_relaxed))});
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
        j += runtime_state_str(s.state);
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
    j += runtime_state_str(rt->get_state());
    j += "\",\"port\":";
    json_append_uint(j, rt->get_port());
    j += ",\"connections\":";
    // Published, not live — see build_metrics().
    json_append_uint(j, rt->m_stat_active_connections.load(std::memory_order_relaxed));
    j += ",\"messages_total\":";
    json_append_uint(j, rt->m_stat_total_messages.load(std::memory_order_relaxed));
    j += ",\"connections_total\":";
    json_append_uint(j, rt->m_stat_total_connections.load(std::memory_order_relaxed));
    j += ",\"bytes_in\":";
    json_append_uint(j, rt->m_stat_bytes_in.load(std::memory_order_relaxed));
    j += ",\"bytes_out\":";
    json_append_uint(j, rt->m_stat_bytes_out.load(std::memory_order_relaxed));

    // Add detailed stats if available.
    //
    // The published text, for the same reason as the count above and rather more
    // urgently: get_stats() is overridden per type, and server_instance's
    // override iterates m_upstreams outright while cache_instance's reads the
    // store's key count, its channel count and its follower list — every one of
    // them a container the event loop rewrites underneath this thread.  Empty
    // until the first sweep after the endpoint started, which is the same thing
    // this already prints nothing for.
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
