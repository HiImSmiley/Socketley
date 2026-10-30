#include "metrics_endpoint.h"

#include <algorithm>
#include "dashboard.h"
#include "../shared/runtime/runtime_manager.h"
#include "../shared/runtime/runtime_instance.h"
#include "../shared/util/logging.h"
#include "../shared/util/version.h"
#include "../shared/runtime/runtime_definitions.h"
#include "../shared/ipc/daemon_client.h"
#include "../shared/net/fast_lo.h"
#include "daemon_handler.h"
#include "../runtime/storage/storage_instance.h"
#include "../shared/json/json_escape.h"
#include "../shared/util/wall_clock.h"
#include "../shared/util/proc_stat.h"
#include "../shared/runtime/stats_text.h"
#include "../shared/loop/eventfd_wake.h"
#include "../shared/runtime/metric_catalog.h"
#include "../shared/runtime/metric_text.h"
#include "../shared/crypto/cert_keeper.h"
#include "../shared/json/json_doc.h"
#include "../runtime/storage/git_mirrors.h"

#include <unistd.h>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <charconv>
#include <cstdlib>
#include <cstdio>
#include <mutex>
#include <unordered_map>
#include <shared_mutex>
#include <thread>
#include <chrono>
#include <vector>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/eventfd.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>

namespace metric_catalog = socketley::metric_catalog;

metrics_endpoint::metrics_endpoint(runtime_manager& mgr)
    : m_manager(mgr), m_facts(std::make_unique<fact_cache>())
{
}

metrics_endpoint::~metrics_endpoint()
{
    stop();
}

bool metrics_endpoint::start(uint16_t port, options o)
{
    m_dash = std::make_unique<dashboard::server>(std::move(o.dashboard_credentials), std::move(o.dashboard_idp),
                                                 m_manager);
    m_state_dir = o.state_dir;
    m_history = std::make_unique<history::keeper>(o.state_dir.empty() ? std::string() : o.state_dir + "/.history");
    m_alerts = std::make_unique<alerts::monitor>(o.state_dir.empty() ? std::string() : o.state_dir + "/.alerts",
                                                 std::move(o.alert_webhook), std::move(o.alert_send),
                                                 std::move(o.alert_event));
    m_history->load(socketley::wall::now_sec());
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

    // Accepted sockets do not inherit O_NONBLOCK on Linux, so serve_loop reads
    // them only when poll says so and dashboard::send writes with a deadline.

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
    m_next_sample = m_start_time;
    m_next_save = m_start_time + std::chrono::minutes(5);
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
        socketley::eventfd_bump(m_wake_fd);

    if (was && m_thread.joinable())
        m_thread.join();
    if (was && m_history)
        m_history->save();

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

void metrics_endpoint::serve_loop()
{
    // Connections whose request is still arriving, read side by side so a peer that trickles holds only its own.
    struct pending
    {
        int fd;
        std::string in;
        std::string peer;
        std::chrono::steady_clock::time_point deadline;
    };
    std::vector<pending> waiting;
    // Raw close and the right one, because no SQE has ever named these
    // descriptors and close_fd() would be a plain data race against the
    // event-loop thread's own tables.
    const auto drop = [&](size_t i) {
        close(waiting[i].fd);
        waiting.erase(waiting.begin() + static_cast<std::ptrdiff_t>(i));
    };
    std::vector<struct pollfd> fds;
    while (m_running.load(std::memory_order_acquire))
    {
        // Woken for the next point of the history too, which this thread takes between requests.
        auto now = std::chrono::steady_clock::now();
        if (now >= m_next_sample)
        {
            sample();
            m_next_sample = std::max(m_next_sample + std::chrono::seconds(history::step), now + std::chrono::seconds(1));
            if (now >= m_next_save)
            {
                m_history->save();
                m_next_save = now + std::chrono::minutes(5);
            }
        }
        now = std::chrono::steady_clock::now();
        for (size_t i = waiting.size(); i-- > 0;)
            if (now >= waiting[i].deadline)
                drop(i);

        // Both, always, because the listener alone left this thread parked in
        // accept() with no way for stop() to reach it.
        fds.clear();
        fds.push_back({ m_listen_fd, POLLIN, 0 });
        fds.push_back({ m_wake_fd,   POLLIN, 0 });
        auto until = m_next_sample;
        for (const pending& w : waiting)
        {
            fds.push_back({ w.fd, POLLIN, 0 });
            until = std::min(until, w.deadline);
        }
        const auto wait = std::chrono::duration_cast<std::chrono::milliseconds>(until - now);
        int ready = poll(fds.data(), static_cast<nfds_t>(fds.size()),
                         static_cast<int>(std::clamp<int64_t>(wait.count(), 0, history::step * 1000)));
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
        if (ready == 0)
            continue;

        // Each request that came whole is served, last to first so the indexes of those before stay put.
        for (size_t i = waiting.size(); i-- > 0;)
        {
            if (fds[i + 2].revents == 0)
                continue;
            char buf[16384];
            const ssize_t n = ::recv(waiting[i].fd, buf, sizeof buf, MSG_DONTWAIT);
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
                continue;
            if (n <= 0)
            {
                drop(i);
                continue;
            }
            waiting[i].in.append(buf, static_cast<size_t>(n));
            dashboard::request req;
            req.peer = waiting[i].peer;
            const dashboard::parse_state got = dashboard::parse_request(waiting[i].in, req);
            if (got == dashboard::parse_state::more)
                continue;
            if (got == dashboard::parse_state::done)
            {
                const bool via = !req.header("via").empty();
                const std::string host_line = "\r\nhost: " + std::string(req.header("host")) + "\r\n";
                // A page whose name was rebound to 127.0.0.1 reaches this port as its own origin, so only a request that
                // asked for this machine by name is served -- or a proxy's, which carries Via, which no page can set.
                if (!via && !req.header("host").empty() && !host_is_loopback(host_line.c_str()))
                    dashboard::send(waiting[i].fd, 403, {}, {});
                else
                    serve(waiting[i].fd, req, via);
            }
            drop(i);
        }

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
        {
            // The pending connection stays in the backlog, so without a pause the listener polls ready again at once.
            if (errno == EMFILE || errno == ENFILE)
            {
                struct pollfd pause{m_wake_fd, POLLIN, 0};
                if (poll(&pause, 1, 100) > 0)
                    break;
            }
            continue;
        }

        // An honest client sends its request in one go, so a few seconds bound one that does not, and the oldest of
        // too many gives way to the newest.
        if (waiting.size() >= max_waiting)
            drop(0);
        char ip[INET_ADDRSTRLEN] = {};
        ::inet_ntop(AF_INET, &client_addr.sin_addr, ip, sizeof ip);
        waiting.push_back({ client_fd, {}, ip, std::chrono::steady_clock::now() + request_deadline });
    }
    for (size_t i = waiting.size(); i-- > 0;)
        drop(i);
}

void metrics_endpoint::serve(int fd, const dashboard::request& req, bool via)
{
    const std::string_view path = req.path;
    const auto refresh = [&](std::string& cached, auto build) {
        const auto now = std::chrono::steady_clock::now();
        // The three share one cache and one clock, and each refresh empties the other two, so one asked inside the
        // TTL after another was refreshed is built again rather than served empty.
        if (now - m_cache_time >= METRICS_CACHE_TTL)
        {
            m_cached_metrics.clear();
            m_cached_json_overview.clear();
            m_cached_json_runtimes.clear();
            m_cache_time = now;
        }
        if (cached.empty())
            cached = build();
        return std::string_view(cached);
    };
    if (path == "/metrics")
    {
        // A scraper on this machine, or the signed-in page; through a proxy, only the latter.
        if (m_dash->configured() && (via || req.peer.rfind("127.", 0) != 0) && m_dash->session_of(req).empty())
            dashboard::send(fd, 401, "text/plain; charset=utf-8", "Sign in first.\n");
        else
            dashboard::send(fd, 200, "text/plain; version=0.0.4; charset=utf-8",
                            refresh(m_cached_metrics, [&] { return build_metrics(); }));
        return;
    }
    if (path == "/api/history")
    {
        if (!m_dash->may_read(req))
        {
            dashboard::send(fd, 401, "text/plain; charset=utf-8", "Sign in first.\n");
            return;
        }
        const int64_t now = socketley::wall::now_sec();
        const std::string body = m_history->query(dashboard::query_field(req.query, "runtime"), now,
            std::strtoll(dashboard::query_field(req.query, "range").c_str(), nullptr, 10),
            std::strtoul(dashboard::query_field(req.query, "points").c_str(), nullptr, 10));
        dashboard::send(fd, 200, "application/json", body.empty() ? std::string("{}") : body);
        return;
    }
    if (path == "/api/alerts" || path == "/api/alerts/test")
    {
        if (!m_dash->may_read(req) || (path != "/api/alerts" && m_dash->session_of(req).empty()))
            dashboard::send(fd, 401, "text/plain; charset=utf-8", "Sign in first.\n");
        else if (path == "/api/alerts")
            dashboard::send(fd, 200, "application/json", m_alerts->json());
        else if (req.method != "POST" || req.header("x-socketley-dashboard") != "1")
            dashboard::send(fd, 403, "text/plain; charset=utf-8", "A test comes from the dashboard's own page.\n");
        else if (const std::string why = m_alerts->test(); why.empty())
            dashboard::send(fd, 204, {}, {});
        else
            dashboard::send(fd, 502, "text/plain; charset=utf-8", why + "\n");
        return;
    }
    if (path.starts_with("/api/overview") || path.starts_with("/api/runtimes") || path.starts_with("/api/runtime/"))
    {
        if (!m_dash->may_read(req))
        {
            dashboard::send(fd, 401, "text/plain; charset=utf-8", "Sign in first.\n");
            return;
        }
        if (path == "/api/overview")
            dashboard::send(fd, 200, "application/json", refresh(m_cached_json_overview, [&] { return build_json_overview(); }));
        else if (path == "/api/runtimes")
            dashboard::send(fd, 200, "application/json", refresh(m_cached_json_runtimes, [&] { return build_json_runtimes(); }));
        else if (const std::string body = build_json_runtime(path.substr(13)); path.starts_with("/api/runtime/") && !body.empty())
            dashboard::send(fd, 200, "application/json", body);
        else
            dashboard::send(fd, 404, "text/plain; charset=utf-8", "Not Found\n");
        return;
    }
    if (!m_dash->handle(fd, req))
        dashboard::send(fd, 404, "text/plain; charset=utf-8", "Not Found\n");
}

using socketley::metric_text::label_escape_into;
using socketley::metric_text::metric_head;

static void json_append_uint(std::string& out, uint64_t v)
{
    socketley::metric_text::append_uint(out, v);
}

// CPU time and memory of a set of processes, read from /proc, as the shards of a runtime or the whole daemon.
struct process_usage
{
    double   cpu_seconds{0};
    uint64_t rss_bytes{0};
    // What the set actually costs: a page shared with other processes counted by the share this one holds of it, so
    // the binary's own pages are counted once across a runtime's shards rather than once per shard. Summing resident
    // memory instead over-reports by the binary's resident size for every shard past the first -- measured on a live
    // daemon of ten runtimes in seventeen processes, 289 MB against the 136 MB the machine was actually holding.
    uint64_t memory_bytes{0};
    uint32_t processes{0};
};

// The process's share of every page it has resident, from smaps_rollup's Pss, in bytes; 0 where the kernel does not
// offer it. Reading it walks the page tables, which costs about ten times a read of /proc/<pid>/stat -- measured, 356
// against 25 microseconds a process -- and is taken at the same cadence as the rest rather than per request.
static uint64_t proportional_bytes(pid_t pid)
{
    char path[48];
    std::snprintf(path, sizeof path, "/proc/%d/smaps_rollup", static_cast<int>(pid));
    FILE* f = std::fopen(path, "re");
    if (!f)
        return 0;
    char line[256];
    uint64_t kb = 0;
    while (std::fgets(line, sizeof line, f))
        if (std::strncmp(line, "Pss:", 4) == 0)
        {
            kb = std::strtoull(line + 4, nullptr, 10);
            break;
        }
    std::fclose(f);
    return kb * 1024;
}

// Resident pages from /proc/<pid>/statm, a read a tenth the cost of smaps_rollup's walk; 0 when it cannot be read.
static uint64_t resident_pages(pid_t pid)
{
    char path[48];
    std::snprintf(path, sizeof path, "/proc/%d/statm", static_cast<int>(pid));
    FILE* f = std::fopen(path, "re");
    if (!f)
        return 0;
    unsigned long long size = 0, resident = 0;
    const int got = std::fscanf(f, "%llu %llu", &size, &resident);
    std::fclose(f);
    return got == 2 ? resident : 0;
}

// Pss by process, read for every process at the history's cadence by sample() and only looked up by a request,
// since a dashboard polling every two seconds otherwise walked every runtime's page tables on each poll.
struct pss_cache
{
    struct entry
    {
        uint64_t pss{0};
        uint64_t resident{0};
        std::chrono::steady_clock::time_point read_at;
    };
    std::mutex                       mu;
    std::unordered_map<pid_t, entry> by_pid;
};

static pss_cache& pss()
{
    static pss_cache c;
    return c;
}

// A process the last sample did not see, a runtime started since, is read now and kept until the next.
static uint64_t cached_pss(pid_t pid)
{
    auto& c = pss();
    std::lock_guard<std::mutex> lk(c.mu);
    if (const auto it = c.by_pid.find(pid); it != c.by_pid.end())
        return it->second.pss;
    const uint64_t b = proportional_bytes(pid);
    c.by_pid.emplace(pid, pss_cache::entry{b, resident_pages(pid), std::chrono::steady_clock::now()});
    return b;
}

static void refresh_pss(const std::vector<pid_t>& every)
{
    // A process whose resident pages did not change keeps its Pss for up to a minute, so an idle machine walks no
    // page tables between; a sibling mapping or dropping a shared page moves it no further than that.
    constexpr auto max_age = std::chrono::seconds(60);
    const auto now = std::chrono::steady_clock::now();
    std::unordered_map<pid_t, pss_cache::entry> old;
    {
        auto& c = pss();
        std::lock_guard<std::mutex> lk(c.mu);
        old = c.by_pid;
    }
    std::unordered_map<pid_t, pss_cache::entry> fresh;
    fresh.reserve(every.size());
    for (const pid_t pid : every)
    {
        if (fresh.contains(pid))
            continue;
        const uint64_t resident = resident_pages(pid);
        if (const auto it = old.find(pid);
            it != old.end() && resident != 0 && it->second.resident == resident && now - it->second.read_at < max_age)
            fresh.emplace(pid, it->second);
        else
            fresh.emplace(pid, pss_cache::entry{proportional_bytes(pid), resident, now});
    }
    auto& c = pss();
    std::lock_guard<std::mutex> lk(c.mu);
    c.by_pid.swap(fresh);
}

static void add_process_usage(pid_t pid, process_usage& u)
{
    socketley::proc_stat st;
    if (!socketley::read_proc_stat(pid, st))
        return;
    static const long tick = ::sysconf(_SC_CLK_TCK);
    static const long page = ::sysconf(_SC_PAGESIZE);
    u.cpu_seconds += static_cast<double>(st.utime + st.stime) / static_cast<double>(tick > 0 ? tick : 100);
    u.rss_bytes += st.rss_pages > 0 ? static_cast<uint64_t>(st.rss_pages) * static_cast<uint64_t>(page > 0 ? page : 4096)
                                    : 0;
    u.memory_bytes += cached_pss(pid);
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
    out += ",\"memory_bytes\":";
    json_append_uint(out, u.memory_bytes);
    out += ",\"processes\":";
    json_append_uint(out, u.processes);
}

// A family of one unlabelled value, and the blank line after it.
static void metric_scalar(std::string& out, std::string_view name, std::string_view type, std::string_view help,
                          uint64_t v)
{
    metric_head(out, name, type, help);
    out += name;
    out += ' ';
    json_append_uint(out, v);
    out += "\n\n";
}

// One runtime as every view of the fleet reads it, taken under the manager's lock and written out after it.
struct runtime_row
{
    std::string name;
    runtime_type type;
    runtime_state state;
    uint16_t port;
    // Published and not live, so nothing here walks a table the event loop rewrites.
    shard_stats::figures figures;
    // What its worker last published, whose figures the catalog makes series of; /metrics alone reads it.
    std::string detail;
    std::vector<pid_t> pids;
    // What the fact series read, /metrics alone again: restarts, the certificate served with, a storage's directory.
    unsigned restarts{0};
    std::string cert, dir;
};

// `full` for /metrics, which reads each runtime's published text and its configuration besides its figures.
static std::vector<runtime_row> runtime_rows(const runtime_manager& manager, bool full = false)
{
    std::shared_lock lock(manager.mutex);
    const auto& runtimes = manager.list();
    std::vector<runtime_row> rows;
    rows.reserve(runtimes.size());
    for (const auto& [name, rt] : runtimes)
    {
        // The bound port, the one `ps` prints: an unset -p is the type's default.
        runtime_row& r = rows.emplace_back(runtime_row{name, rt->get_type(), rt->get_state(), rt->effective_port(),
                                                       rt->worker_figures(), {}, rt->shard_pids(), 0, {}, {}});
        if (!full)
            continue;
        if (r.state == runtime_running)
            r.detail = rt->stat_detail_snapshot();
        r.restarts = rt->restart_count();
        r.cert = dashboard::served_cert(*rt);
        if (r.type == runtime_storage)
        {
            const auto held = rt->config_lock();
            r.dir.assign(static_cast<const storage_instance*>(rt.get())->get_dir());
        }
    }
    return rows;
}

struct fleet_totals
{
    shard_stats::figures sum;
    uint64_t running{0};
};

static fleet_totals fleet_sum(const std::vector<runtime_row>& rows)
{
    fleet_totals t;
    for (const runtime_row& r : rows)
    {
        t.sum += r.figures;
        t.running += r.state == runtime_running;
    }
    return t;
}

// ─── Fact series: what the daemon's alerts look at, as series a rule can read ───

namespace fact
{

using metric_catalog::family;
using metric_catalog::kind;
using metric_catalog::label;
using metric_catalog::series;

constexpr family state{"socketley_runtime_state", kind::gauge, "1 for the state a runtime is in, 0 for the other three."};
constexpr family restarts{"socketley_runtime_restarts_total", kind::counter,
                          "Times a runtime's worker went down and was started again."};
constexpr family cert_expiry{"socketley_cert_expiry_seconds", kind::gauge,
                             "Seconds until the certificate a runtime serves with ends, below 0 once it has."};
constexpr family disk_ratio{"socketley_disk_free_ratio", kind::gauge,
                            "The share of a disk under the state directory or a storage runtime still free."};
constexpr family disk_free{"socketley_disk_free_bytes", kind::gauge, "Bytes of that disk still free."};
constexpr family disk_size{"socketley_disk_size_bytes", kind::gauge, "Bytes that disk holds in all."};
constexpr family mem_ratio{"socketley_host_memory_available_ratio", kind::gauge,
                           "The share of the host's memory available, as MemAvailable over MemTotal."};
constexpr family mem_avail{"socketley_host_memory_available_bytes", kind::gauge, "The host's MemAvailable."};
constexpr family mem_total{"socketley_host_memory_total_bytes", kind::gauge, "The host's MemTotal."};
constexpr family quota{"socketley_runtime_quota_ratio", kind::gauge,
                       "What a runtime that refuses past its limit holds of it: a storage's --max-bytes, a cache's "
                       "--max-memory without eviction."};
constexpr family git_failed{"socketley_git_mirror_failed", kind::gauge,
                            "1 when the last pull of a storage runtime's git mirror failed, 0 when it went through."};

constexpr int64_t cert_every = 300;
constexpr int64_t git_every = 60;

}   // namespace fact

struct metrics_endpoint::fact_cache
{
    // Each certificate's end in seconds since the epoch, INT64_MIN when it cannot be read, and when it was read.
    std::unordered_map<std::string, std::pair<int64_t, int64_t>> certs;
    // Each storage directory's mirrors: the runtime, the repository's name and id, and whether its last pull failed.
    struct mirror
    {
        std::string runtime, repo, id;
        bool failed;
    };
    std::vector<mirror> mirrors;
    std::vector<std::string> mirror_dirs;
    int64_t mirrors_at{INT64_MIN};
    size_t last_size{0};
};

// MemTotal and MemAvailable in bytes, both 0 when /proc/meminfo cannot be read.
static void host_memory(uint64_t& total, uint64_t& avail)
{
    total = avail = 0;
    char buf[4096];
    const int fd = ::open("/proc/meminfo", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return;
    const ssize_t n = ::read(fd, buf, sizeof buf - 1);
    ::close(fd);
    if (n <= 0)
        return;
    buf[n] = '\0';
    const auto kb = [&](const char* key) -> uint64_t {
        const char* at = std::strstr(buf, key);
        return at ? std::strtoull(at + std::strlen(key), nullptr, 10) * 1024 : 0;
    };
    total = kb("MemTotal:");
    avail = kb("MemAvailable:");
}

static void append_facts(metrics_endpoint::fact_cache& cache, const std::string& state_dir,
                         const std::vector<runtime_row>& rows, const std::vector<metric_catalog::figures>& figs,
                         socketley::metric_text::writer& out)
{
    using fact::series;
    using fact::label;
    label ls[3];
    for (const runtime_row& r : rows)
    {
        ls[0] = {"name", r.name};
        ls[1] = {"type", type_to_string(r.type)};
        for (const runtime_state s : {runtime_created, runtime_running, runtime_stopped, runtime_failed})
        {
            ls[2] = {"state", state_to_string(s)};
            out(series::of(fact::state, std::span<const label>(ls, 3), uint64_t{r.state == s}));
        }
    }
    for (const runtime_row& r : rows)
    {
        ls[0] = {"name", r.name};
        out(series::of(fact::restarts, std::span<const label>(ls, 1), uint64_t{r.restarts}));
    }

    // Each certificate read when first named and every five minutes after, what is left counted down between.
    const int64_t now = socketley::wall::now_sec();
    std::erase_if(cache.certs, [&](const auto& kv) {
        return std::none_of(rows.begin(), rows.end(), [&](const runtime_row& r) { return r.cert == kv.first; });
    });
    for (const runtime_row& r : rows)
    {
        if (r.cert.empty())
            continue;
        auto it = cache.certs.find(r.cert);
        if (it == cache.certs.end() || now - it->second.second >= fact::cert_every)
        {
            cert_keeper::cert_facts c;
            const bool ok = cert_keeper::read_cert(r.cert, c) && c.expiry_known;
            it = cache.certs.insert_or_assign(r.cert, std::make_pair(ok ? now + c.expires_in : INT64_MIN, now)).first;
        }
        if (it->second.first == INT64_MIN)
            continue;
        ls[0] = {"name", r.name};
        ls[1] = {"path", r.cert};
        out(series::of(fact::cert_expiry, std::span<const label>(ls, 2), static_cast<double>(it->second.first - now)));
    }

    // The disks under the state directory and the storage runtimes, each disk once, by the first directory on it.
    struct disk
    {
        std::string_view path;
        uint64_t free, size;
    };
    std::vector<disk> disks;
    std::vector<dev_t> devs;
    const auto look = [&](std::string_view dir) {
        struct statvfs v{};
        struct stat st{};
        const std::string d(dir);
        if (d.empty() || ::statvfs(d.c_str(), &v) != 0 || v.f_blocks == 0 || ::stat(d.c_str(), &st) != 0 ||
            std::find(devs.begin(), devs.end(), st.st_dev) != devs.end())
            return;
        devs.push_back(st.st_dev);
        disks.push_back({dir, static_cast<uint64_t>(v.f_bavail) * v.f_frsize, static_cast<uint64_t>(v.f_blocks) * v.f_frsize});
    };
    look(state_dir);
    for (const runtime_row& r : rows)
        look(r.dir);
    for (const disk& d : disks)
    {
        ls[0] = {"path", d.path};
        out(series::of(fact::disk_ratio, std::span<const label>(ls, 1), static_cast<double>(d.free) / static_cast<double>(d.size)));
    }
    for (const disk& d : disks)
    {
        ls[0] = {"path", d.path};
        out(series::of(fact::disk_free, std::span<const label>(ls, 1), d.free));
    }
    for (const disk& d : disks)
    {
        ls[0] = {"path", d.path};
        out(series::of(fact::disk_size, std::span<const label>(ls, 1), d.size));
    }

    uint64_t total = 0, avail = 0;
    host_memory(total, avail);
    if (total > 0)
    {
        out(series::of(fact::mem_ratio, {}, static_cast<double>(avail) / static_cast<double>(total)));
        out(series::of(fact::mem_avail, {}, avail));
        out(series::of(fact::mem_total, {}, total));
    }

    // What a runtime holds against its limit, from the figures its series came from; a cache that evicts is full by
    // design, so only one that refuses is said.
    for (size_t i = 0; i < rows.size(); ++i)
    {
        uint64_t used = 0, limit = 0, ev = 1;
        if (rows[i].type == runtime_storage)
        {
            if (!figs[i].get("bytes", used) || !figs[i].get("max_bytes", limit))
                continue;
        }
        else if (rows[i].type != runtime_cache || !figs[i].get("eviction", ev) || ev != 0 ||
                 !figs[i].get("memory_used", used) || !figs[i].get("max_memory", limit))
            continue;
        if (limit == 0)
            continue;
        ls[0] = {"name", rows[i].name};
        ls[1] = {"type", type_to_string(rows[i].type)};
        out(series::of(fact::quota, std::span<const label>(ls, 2), static_cast<double>(used) / static_cast<double>(limit)));
    }

    // Git mirrors, read every minute and when a storage runtime comes or goes.
    std::vector<std::string> dirs;
    for (const runtime_row& r : rows)
        if (!r.dir.empty())
            dirs.push_back(r.dir);
    if (now - cache.mirrors_at >= fact::git_every || dirs != cache.mirror_dirs)
    {
        cache.mirrors.clear();
        for (const runtime_row& r : rows)
        {
            if (r.dir.empty())
                continue;
            socketley::storage::git_mirrors g;
            g.open(r.dir, 1, {}, false, {});
            for (const auto& repo : g.repos())
            {
                socketley::json::jvalue st;
                if (!socketley::json::json_reader(g.state_json(repo.id)).document(st))
                    continue;
                const auto* ok = member(st, "ok");
                if (ok && ok->k == socketley::json::jvalue::kind::boolean)
                    cache.mirrors.push_back({r.name, repo.name, repo.id, !ok->b});
            }
        }
        cache.mirror_dirs = std::move(dirs);
        cache.mirrors_at = now;
    }
    for (const auto& m : cache.mirrors)
    {
        ls[0] = {"name", m.runtime};
        ls[1] = {"repo", m.repo};
        ls[2] = {"id", m.id};
        out(series::of(fact::git_failed, std::span<const label>(ls, 3), uint64_t{m.failed}));
    }
}

std::string metrics_endpoint::build_metrics() const
{
    std::vector<runtime_row> snapshots = runtime_rows(m_manager, true);
    const fleet_totals totals = fleet_sum(snapshots);
    const uint64_t total_connections = totals.sum.total_connections, total_messages = totals.sum.total_messages,
                   total_bytes_in = totals.sum.bytes_in, total_bytes_out = totals.sum.bytes_out,
                   active_connections = totals.sum.active_connections, running_count = totals.running;
    const uint64_t total_count = snapshots.size();

    std::string out;
    // The last render's size, since a catalog series is about sixty bytes and a storage runtime has a hundred.
    out.reserve(std::max<size_t>(m_facts->last_size, 2048 + snapshots.size() * 256));

    // Prometheus exposition format
    //
    // Which daemon answered, first: several may serve one machine and every
    // series below is identically named on each of them.  The scrape target
    // distinguishes them only for whoever configured the scrape.
    std::string exe;
    uint64_t dev = 0, ino = 0;
    if (!socketley::self_exe_identity(exe, dev, ino))
        exe.clear();

    metric_head(out, "socketley_daemon_info", "gauge", "The daemon these numbers come from.");
    out += "socketley_daemon_info{version=\"";
    label_escape_into(out, SOCKETLEY_VERSION);
    out += "\",pid=\"";
    json_append_uint(out, static_cast<uint64_t>(::getpid()));
    out += "\",socket=\"";
    label_escape_into(out, daemon_handler::socket_path);
    out += "\",exe=\"";
    label_escape_into(out, exe);
    out += "\"} 1\n\n";

    metric_scalar(out, "socketley_runtimes_total", "gauge", "Total number of runtimes.", total_count);
    metric_scalar(out, "socketley_runtimes_running", "gauge", "Number of running runtimes.", running_count);
    metric_scalar(out, "socketley_connections_total", "counter", "Total connections accepted.", total_connections);
    metric_scalar(out, "socketley_connections_active", "gauge", "Current active connections.", active_connections);
    metric_scalar(out, "socketley_messages_total", "counter", "Total messages processed.", total_messages);
    metric_scalar(out, "socketley_bytes_received_total", "counter", "Total bytes received.", total_bytes_in);
    metric_scalar(out, "socketley_bytes_sent_total", "counter", "Total bytes sent.", total_bytes_out);

    // The loopback shortcut, whose bytes no counter on lo sees.
    const socketley::fast_lo_figures lo = socketley::fast_lo_now();
    metric_head(out, "socketley_fast_lo_info", "gauge",
                "The loopback shortcut's mode: off, own, all, trust, or unavailable.");
    out += "socketley_fast_lo_info{mode=\"";
    label_escape_into(out, lo.mode);
    out += "\"} 1\n\n";
    if (lo.mode != "off" && lo.mode != "unavailable")
    {
        auto series = [&out](const char* name, const char* type, const char* help,
                             std::initializer_list<std::pair<const char*, uint64_t>> vals) {
            metric_head(out, name, type, help);
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
    metric_head(out, "socketley_runtime_connections", "gauge", "Active connections per runtime.");
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
        json_append_uint(out, s.figures.active_connections);
        out += "\n";
    }
    out += "\n";

    metric_head(out, "socketley_runtime_messages_total", "counter", "Total messages per runtime.");
    for (const auto& s : snapshots)
    {
        out += "socketley_runtime_messages_total{name=\"";
        label_escape_into(out, s.name);
        out += "\"} ";
        json_append_uint(out, s.figures.total_messages);
        out += "\n";
    }

    out += '\n';
    metric_head(out, "socketley_runtime_cpu_seconds_total", "counter",
                "CPU time of a runtime's processes, user and system.");
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
    out += '\n';
    metric_head(out, "socketley_runtime_resident_memory_bytes", "gauge",
                "Resident memory of a runtime's processes, a page shared between shards counted once per shard.");
    for (size_t i = 0; i < snapshots.size(); ++i)
    {
        out += "socketley_runtime_resident_memory_bytes{name=\"";
        label_escape_into(out, snapshots[i].name);
        out += "\"} ";
        json_append_uint(out, usages[i].rss_bytes);
        out += "\n";
    }
    out += '\n';
    metric_head(out, "socketley_runtime_memory_bytes", "gauge",
                "What a runtime costs the machine: a page it shares counted by the share it holds of it, so the sum "
                "over the runtimes is the memory they hold between them.");
    for (size_t i = 0; i < snapshots.size(); ++i)
    {
        out += "socketley_runtime_memory_bytes{name=\"";
        label_escape_into(out, snapshots[i].name);
        out += "\"} ";
        json_append_uint(out, usages[i].memory_bytes);
        out += "\n";
    }
    out += "\n";

    // Each running runtime's own figures, read once, then written type by type through the catalog.
    std::vector<metric_catalog::figures> figs(snapshots.size());
    for (size_t i = 0; i < snapshots.size(); ++i)
        if (runtime_row& s = snapshots[i]; s.state == runtime_running && !s.detail.empty())
            figs[i].parse(s.type, std::move(s.detail), s.figures.bytes_in, s.figures.bytes_out);
    socketley::metric_text::writer w(out);
    std::vector<metric_catalog::source> sources;
    sources.reserve(snapshots.size());
    for (const metric_catalog::type_entry& e : metric_catalog::types())
    {
        sources.clear();
        for (size_t i = 0; i < snapshots.size(); ++i)
            if (snapshots[i].type == e.type && !figs[i].empty())
                sources.push_back({snapshots[i].name, &figs[i]});
        if (!sources.empty())
            metric_catalog::emit(e, sources, w);
    }
    append_facts(*m_facts, m_state_dir, snapshots, figs, w);
    w.finish();
    m_facts->last_size = out.size();
    return out;
}

std::string metrics_endpoint::build_json_overview() const
{
    const std::vector<runtime_row> rows = runtime_rows(m_manager);
    const fleet_totals totals = fleet_sum(rows);
    const uint64_t total_connections = totals.sum.total_connections, total_messages = totals.sum.total_messages,
                   total_bytes_in = totals.sum.bytes_in, total_bytes_out = totals.sum.bytes_out,
                   active_connections = totals.sum.active_connections, running_count = totals.running;
    const size_t runtimes_total = rows.size();
    std::vector<pid_t> pids{::getpid()};
    for (const runtime_row& r : rows)
        pids.insert(pids.end(), r.pids.begin(), r.pids.end());

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

void metrics_endpoint::sample()
{
    std::vector<std::pair<std::string, history::reading>> readings;
    std::vector<std::vector<pid_t>> pids;
    std::vector<alerts::facts> facts;
    {
        std::shared_lock lock(m_manager.mutex);
        const auto& runtimes = m_manager.list();
        readings.reserve(runtimes.size() + 1);
        for (const auto& [name, rt] : runtimes)
        {
            const shard_stats::figures f = rt->worker_figures();
            history::reading r;
            r.connections = f.active_connections;
            r.messages = f.total_messages;
            r.bytes_in = f.bytes_in;
            r.bytes_out = f.bytes_out;
            readings.emplace_back(name, r);
            pids.push_back(rt->shard_pids());

            alerts::facts a;
            a.name = name;
            a.type = type_to_string(rt->get_type());
            a.failed = rt->get_state() == runtime_failed;
            a.restarts = rt->restart_count();
            a.cert = dashboard::served_cert(*rt);
            // What it holds against its limit, from the same text the figures come from; a cache that evicts is
            // full by design, so only one that refuses is watched.
            std::string detail = rt->stat_detail_snapshot();
            if (rt->get_type() == runtime_sync && rt->get_state() == runtime_running)
                a.error = socketley::stats_text::field(detail, "last_error");
            metric_catalog::figures row;
            row.parse(rt->get_type(), std::move(detail));
            if (rt->get_type() == runtime_storage)
            {
                {
                    const auto held = rt->config_lock();
                    a.dir.assign(static_cast<const storage_instance*>(rt.get())->get_dir());
                }
                row.get("bytes", a.used);
                row.get("max_bytes", a.limit);
            }
            // Only a running sync owes anything: a stopped one keeps the figures it stopped with.
            else if (rt->get_type() == runtime_sync && rt->get_state() == runtime_running)
            {
                row.get("failing", a.failing);
            }
            else if (rt->get_type() == runtime_mail && rt->get_state() == runtime_running)
            {
                row.get("mail_queued", a.queued);
                row.get("mail_self_listed", a.listed);
            }
            else if (uint64_t ev = 1; rt->get_type() == runtime_cache && row.get("eviction", ev) && ev == 0)
            {
                row.get("memory_used", a.used);
                row.get("max_memory", a.limit);
            }
            facts.push_back(std::move(a));
        }
    }
    // The daemon's own is the sum of its runtimes', its own process added to theirs.
    history::reading all;
    std::vector<pid_t> every{::getpid()};
    for (const auto& p : pids)
        every.insert(every.end(), p.begin(), p.end());
    refresh_pss(every);
    const process_usage own = usage_of({::getpid()});
    all.cpu_seconds = own.cpu_seconds;
    all.rss_bytes = own.memory_bytes;
    for (size_t i = 0; i < readings.size(); ++i)
    {
        const process_usage u = usage_of(pids[i]);
        history::reading& r = readings[i].second;
        r.cpu_seconds = u.cpu_seconds;
        // The chart plots what the runtime costs the machine, which is also what its tile says.
        r.rss_bytes = u.memory_bytes;
        all.connections += r.connections;
        all.messages += r.messages;
        all.bytes_in += r.bytes_in;
        all.bytes_out += r.bytes_out;
        all.cpu_seconds += u.cpu_seconds;
        all.rss_bytes += u.memory_bytes;
    }
    readings.emplace_back(std::string(), all);
    const int64_t now_ms = socketley::wall::now_ms();
    m_history->record(now_ms, readings);
    m_alerts->check(now_ms / 1000, facts, m_state_dir.empty() ? std::vector<std::string>{} : std::vector<std::string>{m_state_dir});
}

// One runtime as /api/runtimes and /api/runtime/<name> both write it, left open for what the second adds.
static void append_runtime_row(std::string& j, std::string_view name, runtime_type type, runtime_state state,
                               uint16_t port, const shard_stats::figures& f, const std::vector<pid_t>& pids)
{
    j += "{\"name\":\"";
    socketley::json::escape_into(j, name);
    j += "\",\"type\":\"";
    j += type_to_string(type);
    j += "\",\"state\":\"";
    j += state_to_string(state);
    j += "\",\"port\":";
    json_append_uint(j, port);
    j += ",\"connections\":";
    json_append_uint(j, static_cast<uint64_t>(f.active_connections));
    j += ",\"messages_total\":";
    json_append_uint(j, f.total_messages);
    j += ",\"connections_total\":";
    json_append_uint(j, f.total_connections);
    j += ",\"bytes_in\":";
    json_append_uint(j, f.bytes_in);
    j += ",\"bytes_out\":";
    json_append_uint(j, f.bytes_out);
    append_usage_json(j, usage_of(pids));
}

std::string metrics_endpoint::build_json_runtimes() const
{
    const std::vector<runtime_row> snapshots = runtime_rows(m_manager);

    std::string j;
    j.reserve(snapshots.size() * 256);
    j += "[";

    bool first = true;
    for (const auto& s : snapshots)
    {
        if (!first) j += ",";
        first = false;

        append_runtime_row(j, s.name, s.type, s.state, s.port, s.figures, s.pids);
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
    // Published, not live, and for a runtime in a worker summed out of its shared table at this instant.
    append_runtime_row(j, name, rt->get_type(), rt->get_state(), rt->effective_port(), rt->worker_figures(),
                       rt->shard_pids());

    // The published text, because get_stats() is overridden per type and every
    // override reads a container the event loop rewrites underneath this
    // thread.
    std::string stats = rt->stat_detail_snapshot();
    if (!stats.empty())
    {
        j += ",\"stats\":\"";
        socketley::json::escape_into(j, stats);
        j += "\"";
    }

    j += "}";
    return j;
}
