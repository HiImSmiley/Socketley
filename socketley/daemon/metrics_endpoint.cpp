#include "metrics_endpoint.h"

#include <algorithm>
#include "dashboard_html.h"
#include "../shared/runtime_manager.h"
#include "../shared/runtime_instance.h"
#include "../shared/blocking_write.h"
#include "../shared/logging.h"
#include "../shared/version.h"
#include "../shared/runtime_definitions.h"
#include "../shared/daemon_client.h"
#include "../shared/fast_lo.h"
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
    response += "\r\nConnection: close\r\nContent-Length: ";
    char len_buf[24];
    auto [end, ec] = std::to_chars(len_buf, len_buf + sizeof(len_buf), body.size());
    response.append(len_buf, end - len_buf);
    response += "\r\n\r\n";
    response += body;
    // Content-Length promises the whole body, so a short write here leaves the
    // scraper waiting for bytes that are never coming.
    socketley::write_all(fd, response.data(), response.size());
}

// Whether the request's Host names this machine, which a loopback listener's
// honest clients always do and a DNS-rebound page never can; no Host at all is
// an HTTP/1.0 scraper and is served.
static bool host_is_loopback(const char* req)
{
    const char* h = ::strcasestr(req, "\r\nhost:");
    if (!h)
        return true;
    h += 7;
    while (*h == ' ' || *h == '\t') ++h;
    const char* end = h;
    while (*end && *end != '\r' && *end != '\n') ++end;
    std::string_view v(h, static_cast<size_t>(end - h));
    while (!v.empty() && (v.back() == ' ' || v.back() == '\t')) v.remove_suffix(1);
    if (!v.empty() && v.front() == '[')
    {
        const size_t close = v.find(']');
        return close != std::string_view::npos && v.substr(1, close - 1) == "::1";
    }
    if (const size_t colon = v.rfind(':'); colon != std::string_view::npos)
        v = v.substr(0, colon);
    if (v == "localhost")
        return true;
    // Numeric only, or "127.0.0.1.attacker.example" would pass as loopback.
    in_addr a{};
    return ::inet_pton(AF_INET, std::string(v).c_str(), &a) == 1 &&
           (ntohl(a.s_addr) >> 24) == 127;
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

            if (std::strncmp(buf, "GET ", 4) == 0 && !host_is_loopback(buf))
            {
                // A page whose name was rebound to 127.0.0.1 reaches this port
                // as its own origin and reads runtime names, ports and paths,
                // so only a request that asked for this machine by name is
                // served.
                static constexpr std::string_view refused =
                    "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                socketley::write_all(client_fd, refused.data(), refused.size());
            }
            else if (std::strncmp(buf, "GET ", 4) == 0)
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

// CPU time and resident memory of a set of processes, read from /proc, as the shards of a runtime or the whole daemon.
struct process_usage
{
    double   cpu_seconds{0};
    uint64_t rss_bytes{0};
    uint32_t processes{0};
};

static void add_process_usage(pid_t pid, process_usage& u)
{
    char path[48];
    std::snprintf(path, sizeof path, "/proc/%d/stat", static_cast<int>(pid));
    FILE* f = std::fopen(path, "re");
    if (!f)
        return;
    char buf[1024];
    const size_t n = std::fread(buf, 1, sizeof buf - 1, f);
    std::fclose(f);
    buf[n] = '\0';
    // The command name may hold spaces and parentheses, so the fields are counted from its last closing parenthesis.
    const char* p = std::strrchr(buf, ')');
    if (!p)
        return;
    unsigned long long utime = 0, stime = 0;
    long long rss_pages = 0;
    if (std::sscanf(p + 1, " %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %llu %llu %*s %*s %*s %*s %*s %*s %*s %*s %lld",
                    &utime, &stime, &rss_pages) != 3)
        return;
    static const long tick = ::sysconf(_SC_CLK_TCK);
    static const long page = ::sysconf(_SC_PAGESIZE);
    u.cpu_seconds += static_cast<double>(utime + stime) / static_cast<double>(tick > 0 ? tick : 100);
    u.rss_bytes += rss_pages > 0 ? static_cast<uint64_t>(rss_pages) * static_cast<uint64_t>(page > 0 ? page : 4096) : 0;
    ++u.processes;
}

static process_usage usage_of(const std::vector<pid_t>& pids)
{
    process_usage u;
    for (const pid_t pid : pids)
        add_process_usage(pid, u);
    return u;
}

static void append_usage_json(std::string& out, const process_usage& u)
{
    char buf[48];
    std::snprintf(buf, sizeof buf, "%.2f", u.cpu_seconds);
    out += ",\"cpu_seconds\":";
    out += buf;
    out += ",\"rss_bytes\":";
    json_append_uint(out, u.rss_bytes);
    out += ",\"processes\":";
    json_append_uint(out, u.processes);
}

// One storage runtime's `stats` text as figures: the lines are `key:value`, and
// the ones that are not numbers are left out.
struct storage_row
{
    std::string name;
    std::vector<std::pair<std::string, uint64_t>> figures;

    bool get(std::string_view key, uint64_t& out) const
    {
        for (const auto& [k, v] : figures)
            if (k == key)
            {
                out = v;
                return true;
            }
        return false;
    }
};

static storage_row parse_storage_row(std::string_view name, std::string_view detail)
{
    storage_row row;
    row.name = std::string(name);
    while (!detail.empty())
    {
        const size_t nl = detail.find('\n');
        const std::string_view line = detail.substr(0, nl);
        detail = nl == std::string_view::npos ? std::string_view{} : detail.substr(nl + 1);
        const size_t colon = line.find(':');
        if (colon == std::string_view::npos)
            continue;
        uint64_t v = 0;
        const std::string_view num = line.substr(colon + 1);
        const auto [end, ec] = std::from_chars(num.data(), num.data() + num.size(), v);
        if (ec != std::errc{} || end != num.data() + num.size())
            continue;
        // A sharded runtime's text is one section per shard, so a figure that
        // comes again is the next shard's: added, except the ones every shard
        // holds a whole copy of.
        const std::string_view key = line.substr(0, colon);
        bool merged = false;
        for (auto& [k, held] : row.figures)
            if (k == key)
            {
                if (key != "buckets" && key != "max_bytes" && key != "tls" && key != "shard_index")
                    held += v;
                merged = true;
                break;
            }
        if (!merged)
            row.figures.emplace_back(std::string(key), v);
    }
    return row;
}

// The series a storage runtime has that no other type does: what it holds, what
// it was asked, what it moved and how it answered.
static void append_storage_series(std::string& out, const std::vector<storage_row>& rows)
{
    if (rows.empty())
        return;

    // The figures a family of their own carries, which the catch-all at the end leaves out.
    std::vector<std::string_view> named;
    const auto family = [&](std::string_view metric, std::string_view type, std::string_view help,
                            std::string_view key)
    {
        named.push_back(key);
        out += "\n# HELP ";
        out += metric;
        out += ' ';
        out += help;
        out += "\n# TYPE ";
        out += metric;
        out += ' ';
        out += type;
        out += '\n';
        for (const auto& r : rows)
        {
            uint64_t v;
            if (!r.get(key, v))
                continue;
            out += metric;
            out += "{name=\"";
            label_escape_into(out, r.name);
            out += "\"} ";
            json_append_uint(out, v);
            out += '\n';
        }
    };

    family("socketley_storage_buckets", "gauge", "Buckets a storage runtime holds.", "buckets");
    family("socketley_storage_objects", "gauge", "Objects a storage runtime holds.", "objects");
    family("socketley_storage_bytes_stored", "gauge", "Object bytes a storage runtime holds.", "bytes");
    family("socketley_storage_bytes_received_total", "counter",
           "Bytes a storage runtime read from its clients, including protocol framing.", "bytes_in");
    family("socketley_storage_bytes_sent_total", "counter",
           "Bytes a storage runtime wrote to its clients, including protocol framing.", "bytes_out");
    family("socketley_storage_zero_copy_bytes_total", "counter",
           "Object bytes sent from file to socket without entering the process.", "zero_copy_bytes");
    family("socketley_storage_tls_handshakes_total", "counter",
           "TLS handshakes a storage runtime completed.", "tls_handshakes");
    family("socketley_storage_tls_failures_total", "counter",
           "TLS handshakes that failed or never finished.", "tls_failures");

    // The subsystems a runtime runs beside its requests: what waits, what went, what failed.
    static constexpr struct
    {
        const char* metric;
        const char* type;
        const char* help;
        const char* key;
    } subsystems[] = {
        {"socketley_storage_notify_sent_total", "counter", "Event notifications delivered.", "notify_sent"},
        {"socketley_storage_notify_failed_total", "counter", "Event notification attempts that failed.", "notify_failed"},
        {"socketley_storage_notify_queued", "gauge", "Event notifications waiting to be delivered.", "notify_queued"},
        {"socketley_storage_notify_dropped_total", "counter", "Event notifications dropped past the queue's bound.",
         "notify_dropped"},
        {"socketley_storage_replication_pending", "gauge", "Versions and delete markers waiting to be replicated.",
         "replication_pending"},
        {"socketley_storage_replication_completed_total", "counter", "Versions and delete markers a replication target took.",
         "replication_completed"},
        {"socketley_storage_replication_failed_total", "counter", "Versions a replication target refused for good.",
         "replication_failed"},
        {"socketley_storage_replication_retries_total", "counter", "Replication attempts tried again.", "replication_retries"},
        {"socketley_storage_replication_bytes_total", "counter", "Body bytes replication targets took.", "replication_bytes"},
        {"socketley_storage_cluster_pending", "gauge", "Changes waiting for another node of the cluster.", "cluster_pending"},
        {"socketley_storage_cluster_sent_total", "counter", "Changes the other nodes of the cluster took.", "cluster_sent"},
        {"socketley_storage_cluster_failed_total", "counter", "Changes the other nodes refused for good.", "cluster_failed"},
        {"socketley_storage_cluster_received_total", "counter", "Bucket, IAM and share records other nodes sent.", "cluster_in"},
        {"socketley_storage_cluster_seeding", "gauge", "Nodes this runtime has not yet sent everything it holds.",
         "cluster_seeding"},
        {"socketley_storage_cluster_overflows_total", "counter", "Queues for a node let go for a full resend.",
         "cluster_overflows"},
        {"socketley_storage_cluster_synced_total", "counter", "Writes answered once the nodes sync names had them.",
         "cluster_synced"},
        {"socketley_storage_cluster_sync_timeouts_total", "counter", "Writes answered when their wait for the nodes was over.",
         "cluster_sync_timeouts"},
        {"socketley_storage_scrub_objects_total", "counter", "Versions the scrub read back.", "scrub_objects"},
        {"socketley_storage_scrub_bytes_total", "counter", "Bytes the scrub read back.", "scrub_bytes"},
        {"socketley_storage_scrub_corrupt_total", "counter", "Copies the scrub found whose bytes are not their MD5's.",
         "scrub_corrupt"},
        {"socketley_storage_scrub_passes_total", "counter", "Whole passes of the scrub.", "scrub_passes"},
        {"socketley_storage_scrub_heals_total", "counter", "Corrupt copies another node was asked to send again.",
         "scrub_heals"},
        {"socketley_storage_scrub_unhealed_total", "counter", "Corrupt copies no other node held whole.", "scrub_unhealed"},
        {"socketley_storage_compressed_objects_total", "counter", "Versions compressed where they lie.",
         "compressed_objects"},
        {"socketley_storage_compressed_bytes_in_total", "counter", "Bytes of the versions compressed.",
         "compressed_bytes_in"},
        {"socketley_storage_compressed_bytes_out_total", "counter", "What the versions compressed take on disk.",
         "compressed_bytes_out"},
        {"socketley_storage_tier_moved_total", "counter", "Versions a lifecycle moved to a tier.", "tier_moved"},
        {"socketley_storage_tier_moved_bytes_total", "counter", "Bytes of the versions moved to a tier.",
         "tier_moved_bytes"},
        {"socketley_storage_tier_failed_total", "counter", "Moves to a tier that did not finish.", "tier_failed"},
        {"socketley_storage_tier_reads_total", "counter", "Windows read back from a tier for a client.", "tier_reads"},
        {"socketley_storage_tier_read_failures_total", "counter", "Windows a tier did not give back.",
         "tier_read_failures"},
        {"socketley_storage_lifecycle_expired_total", "counter", "Objects and versions lifecycle rules removed.",
         "lifecycle_expired"},
        {"socketley_storage_lifecycle_aborted_total", "counter", "Uploads lifecycle rules aborted.", "lifecycle_aborted"},
        {"socketley_storage_multipart_completed_total", "counter", "Multipart uploads completed.", "multipart_completed"},
        {"socketley_storage_media_made_total", "counter", "Thumbnails and stream segments made.", "media_made"},
        {"socketley_storage_media_failed_total", "counter", "Media that could not be made.", "media_failed"},
        {"socketley_storage_fsyncs_total", "counter", "Syncs the store made for durability.", "fsyncs"},
    };
    for (const auto& f : subsystems)
    {
        // A family no runtime reports, as one of a build without the subsystem, has no lines to print.
        if (std::none_of(rows.begin(), rows.end(), [&f](const storage_row& r) { uint64_t v; return r.get(f.key, v); }))
            continue;
        family(f.metric, f.type, f.help, f.key);
    }

    out += "\n# HELP socketley_storage_requests_total Requests a storage runtime served, by operation.\n"
           "# TYPE socketley_storage_requests_total counter\n";
    static constexpr std::pair<const char*, const char*> ops[] = {
        {"gets", "get"}, {"heads", "head"}, {"puts", "put"},
        {"deletes", "delete"}, {"lists", "list"}, {"copies", "copy"},
    };
    for (const auto& [key, op] : ops)
        named.push_back(key);
    for (const auto& r : rows)
        for (const auto& [key, op] : ops)
        {
            uint64_t v;
            if (!r.get(key, v))
                continue;
            out += "socketley_storage_requests_total{name=\"";
            label_escape_into(out, r.name);
            out += "\",op=\"";
            out += op;
            out += "\"} ";
            json_append_uint(out, v);
            out += '\n';
        }

    // One line per code that has been answered, so a runtime that has never
    // refused anything has no series to graph.
    out += "\n# HELP socketley_storage_errors_total S3 errors a storage runtime answered, by code.\n"
           "# TYPE socketley_storage_errors_total counter\n";
    for (const auto& r : rows)
        for (const auto& [key, v] : r.figures)
        {
            if (key.compare(0, 6, "error_") != 0)
                continue;
            out += "socketley_storage_errors_total{name=\"";
            label_escape_into(out, r.name);
            out += "\",code=\"";
            label_escape_into(out, std::string_view(key).substr(6));
            out += "\"} ";
            json_append_uint(out, v);
            out += '\n';
        }

    // Every other figure of `stats`, by the name it has there, so nothing a runtime counts is missing from a scrape.
    out += "\n# HELP socketley_storage_stat A storage runtime's other stats figures, by name.\n"
           "# TYPE socketley_storage_stat untyped\n";
    for (const auto& r : rows)
        for (const auto& [key, v] : r.figures)
        {
            if (key.starts_with("error_") || std::find(named.begin(), named.end(), key) != named.end())
                continue;
            out += "socketley_storage_stat{name=\"";
            label_escape_into(out, r.name);
            out += "\",stat=\"";
            label_escape_into(out, key);
            out += "\"} ";
            json_append_uint(out, v);
            out += '\n';
        }
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
        // What the worker last published, kept for the types whose own
        // counters are series of their own.
        std::string detail;
        std::vector<pid_t> pids;
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
                static_cast<size_t>(f.active_connections),
                rt->get_type() == runtime_storage ? rt->stat_detail_snapshot() : std::string{},
                rt->shard_pids()});
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

    // The loopback shortcut, whose bytes no counter on lo sees.
    const socketley::fast_lo_figures lo = socketley::fast_lo_now();
    out += "# HELP socketley_fast_lo_info The loopback shortcut's mode: off, own, all, trust, or unavailable.\n"
           "# TYPE socketley_fast_lo_info gauge\n"
           "socketley_fast_lo_info{mode=\"";
    label_escape_into(out, lo.mode);
    out += "\"} 1\n\n";
    if (lo.mode != "off" && lo.mode != "unavailable")
    {
        auto series = [&out](const char* name, const char* type, const char* help,
                             std::initializer_list<std::pair<const char*, uint64_t>> vals) {
            out += "# HELP "; out += name; out += ' '; out += help;
            out += "\n# TYPE "; out += name; out += ' '; out += type; out += '\n';
            for (const auto& [labels, v] : vals)
            {
                out += name; out += labels; out += ' ';
                json_append_uint(out, v);
                out += '\n';
            }
            out += '\n';
        };
        series("socketley_fast_lo_sockets", "gauge",
               "Sockets entered in the shortcut, by how they send now (as of the last sweep).",
               { { "{path=\"shortcut\"}", lo.sockets_shortcut }, { "{path=\"tcp\"}", lo.sockets_tcp } });
        series("socketley_fast_lo_entered_total", "counter", "Sockets entered in the shortcut.",
               { { "", lo.entered } });
        series("socketley_fast_lo_tainted_total", "counter",
               "Sockets pinned to TCP for good, by reason.",
               { { "{reason=\"bound\"}", lo.tainted_bound },
                 { "{reason=\"unanswered\"}", lo.tainted_unanswered },
                 { "{reason=\"budget\"}", lo.tainted_budget },
                 { "{reason=\"peer_off\"}", lo.tainted_peer_off } });
        series("socketley_fast_lo_held_bytes", "gauge",
               "Unread bytes redirected into receivers, summed across pairs.", { { "", lo.held_bytes } });
        series("socketley_fast_lo_budget_bytes", "gauge", "The global bound on held bytes.",
               { { "", lo.budget_bytes } });
        series("socketley_fast_lo_pair_limit_bytes", "gauge", "The per-pair bound on held bytes.",
               { { "", lo.pair_bytes } });
        series("socketley_fast_lo_over_budget", "gauge",
               "1 while held bytes are at the global budget and new sends are tainted.",
               { { "", lo.over_budget ? 1u : 0u } });
    }

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

    out += "\n# HELP socketley_runtime_cpu_seconds_total CPU time of a runtime's processes, user and system.\n"
           "# TYPE socketley_runtime_cpu_seconds_total counter\n";
    std::vector<process_usage> usages;
    usages.reserve(snapshots.size());
    for (const auto& s : snapshots)
    {
        usages.push_back(usage_of(s.pids));
        char buf[48];
        std::snprintf(buf, sizeof buf, "%.2f", usages.back().cpu_seconds);
        out += "socketley_runtime_cpu_seconds_total{name=\"";
        label_escape_into(out, s.name);
        out += "\"} ";
        out += buf;
        out += "\n";
    }
    out += "\n# HELP socketley_runtime_resident_memory_bytes Resident memory of a runtime's processes.\n"
           "# TYPE socketley_runtime_resident_memory_bytes gauge\n";
    for (size_t i = 0; i < snapshots.size(); ++i)
    {
        out += "socketley_runtime_resident_memory_bytes{name=\"";
        label_escape_into(out, snapshots[i].name);
        out += "\"} ";
        json_append_uint(out, usages[i].rss_bytes);
        out += "\n";
    }
    out += "\n";

    std::vector<storage_row> storage_rows;
    for (const auto& s : snapshots)
        if (s.type == runtime_storage && s.state == runtime_running && !s.detail.empty())
        {
            storage_row row = parse_storage_row(s.name, s.detail);
            // The byte counts are the shared table's, summed as the other
            // runtimes' are, and not part of the published text.
            row.figures.insert(row.figures.begin(),
                               {{"bytes_in", s.bytes_in}, {"bytes_out", s.bytes_out}});
            storage_rows.push_back(std::move(row));
        }
    append_storage_series(out, storage_rows);

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
    std::vector<pid_t> pids{::getpid()};
    {
        std::shared_lock lock(m_manager.mutex);
        const auto& runtimes = m_manager.list();
        runtimes_total = runtimes.size();
        for (const auto& [name, rt] : runtimes)
        {
            for (const pid_t pid : rt->shard_pids())
                pids.push_back(pid);
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
    // The daemon and every runtime's processes, with the CPUs online so that a reader can say what share of the host it is.
    append_usage_json(j, usage_of(pids));
    j += ",\"cpus\":";
    json_append_uint(j, static_cast<uint64_t>(std::max(1L, ::sysconf(_SC_NPROCESSORS_ONLN))));
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
        std::vector<pid_t> pids;
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
                static_cast<size_t>(f.active_connections),
                rt->shard_pids()});
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
        append_usage_json(j, usage_of(s.pids));
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
    append_usage_json(j, usage_of(rt->shard_pids()));

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
