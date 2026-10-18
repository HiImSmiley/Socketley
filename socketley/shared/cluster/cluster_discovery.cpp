#include "cluster_discovery.h"
#include "../loop/event_loop.h"
#include "../runtime/runtime_manager.h"
#include "../util/logging.h"
#include "../../cli/command_hashing.h"
#include "../json/json_escape.h"
#include "../json/json_doc.h"
#include "../persist/replaced_file.h"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <cstring>
#include <charconv>
#include <shared_mutex>
#include <unordered_set>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>

namespace fs = std::filesystem;

// ─── Minimal JSON helpers (local to this TU) ───

namespace cd_detail {

const char* type_str(runtime_type t)
{
    return type_to_string(t);
}

// The kernel's boot id, empty when /proc is not there, which makes every claim
// foreign and every conflict a refusal.
std::string read_boot_id()
{
    std::ifstream f("/proc/sys/kernel/random/boot_id");
    if (!f.is_open())
        return {};

    std::string id;
    std::getline(f, id);
    while (!id.empty() && (id.back() == '\n' || id.back() == '\r' || id.back() == ' '))
        id.pop_back();
    return id;
}

} // namespace cd_detail

// ─── cluster_discovery implementation ───

cluster_discovery::cluster_discovery(std::string_view daemon_name,
                                     std::string_view cluster_dir,
                                     std::string_view socket_path,
                                     runtime_manager& manager)
    : m_daemon_name(daemon_name)
    , m_cluster_dir(cluster_dir)
    , m_socket_path(socket_path)
    , m_boot_id(cd_detail::read_boot_id())
    , m_manager(manager)
{
    char buf[256];
    if (gethostname(buf, sizeof(buf)) == 0)
        m_cluster_addr = buf;
    else
        m_cluster_addr = daemon_name;
}

cluster_discovery::~cluster_discovery()
{
    stop();
}

bool cluster_discovery::read_claim_file(const std::string& path,
                                        node_claim& out, int64_t& heartbeat) const
{
    std::ifstream f(path);
    if (!f.is_open())
        return false;

    std::ostringstream ss;
    ss << f.rdbuf();
    socketley::json::jvalue doc;
    if (!socketley::json::json_reader(ss.str()).document(doc))
        return false;

    heartbeat = socketley::json::int_of(doc, "heartbeat");
    out.host  = std::string(socketley::json::string_of(doc, "host"));
    out.sock  = std::string(socketley::json::string_of(doc, "sock"));
    out.boot  = std::string(socketley::json::string_of(doc, "boot"));
    out.pid   = socketley::json::int_of(doc, "pid");
    return true;
}

// ─── "me, again" versus "somebody else" ─────────────────────────────────────
// A fresh file under our name is this node restarted or a second daemon, told
// apart by boot id, advertised host and control socket path, of which the
// socket path is load-bearing because only one process can hold it.
bool cluster_discovery::claim_is_ours(const node_claim& c) const
{
    if (c.host.empty() || c.sock.empty() || c.boot.empty())
        return false;   // written before claims existed, or by something else

    return c.host == m_cluster_addr
        && c.sock == m_socket_path
        && c.boot == m_boot_id;
}

bool cluster_discovery::start(event_loop& loop)
{
    m_last_error.clear();
    m_loop = &loop;

    // Ensure cluster directory exists
    std::error_code ec;
    fs::create_directories(m_cluster_dir, ec);

    // A restart inside the staleness window must rejoin and a second daemon
    // must be refused without touching the file, because deleting a live
    // holder's file would blind its peers.
    const std::string our_path = m_cluster_dir + "/" + m_daemon_name + ".json";
    node_claim held;
    int64_t hb = 0;

    if (read_claim_file(our_path, held, hb) && hb > 0)
    {
        const time_t age = std::time(nullptr) - static_cast<time_t>(hb);
        if (age <= STALE_THRESHOLD_SEC)
        {
            if (!claim_is_ours(held))
            {
                m_last_error = "daemon name \"" + m_daemon_name + "\" is held in "
                    + m_cluster_dir + " by host=" + (held.host.empty() ? "?" : held.host)
                    + " sock=" + (held.sock.empty() ? "?" : held.sock)
                    + " pid=" + std::to_string(held.pid)
                    + ", last heartbeat " + std::to_string(static_cast<long long>(age))
                    + "s ago; that daemon is another one, not this one restarting";
                LOG_ERROR(("cluster: " + m_last_error).c_str());
                LOG_ERROR("cluster: cluster mode is OFF for this daemon — it publishes "
                          "nothing, joins no group and is invisible to every peer");
                m_loop = nullptr;
                return false;
            }

            LOG_WARN(("cluster: reclaiming \"" + m_daemon_name +
                      "\" from this node's previous incarnation (pid " +
                      std::to_string(held.pid) + ", heartbeat " +
                      std::to_string(static_cast<long long>(age)) +
                      "s ago) — same host, same control socket, same boot").c_str());
        }
    }

    // Do an initial publish + scan immediately
    publish();
    scan();

    // Here and not at the top, because every refusal above returns having
    // submitted nothing and a slot claimed by a handler that never deregisters
    // is never handed out again.
    m_owner_token = loop.register_owner(this);

    // Start the timer cycle
    schedule_timer();
    return true;
}

void cluster_discovery::stop()
{
    m_loop = nullptr;
    unpublish();
}

uint32_t cluster_discovery::retire()
{
    event_loop* const loop = m_loop;

    // Before stop(), which clears m_loop, so the timeout's -ECANCELED is not
    // up to two seconds away.
    if (loop && m_timer_armed)
        if (!loop->submit_timeout_remove(&m_timer_req)) {}

    stop();

    if (!loop)
        return 0;

    const uint32_t tok = m_owner_token;
    m_owner_token      = 0;

    // Last, and only after m_loop is null, after which completions are dropped
    // rather than dispatched -- which still reads the request, so the caller
    // must wait for token_inflight() before freeing.
    loop->deregister_owner(this);
    return tok;
}

void cluster_discovery::on_cqe(struct io_uring_cqe* /*cqe*/)
{
    // Spent, whatever it reported and whether or not the cycle continues below.
    m_timer_armed = false;

    if (!m_loop)
        return;

    // Timer fired — publish + scan, then reschedule
    publish();
    scan();
    schedule_timer();
}

void cluster_discovery::schedule_timer()
{
    if (!m_loop)
        return;

    m_timer_ts.tv_sec = PUBLISH_INTERVAL_SEC;
    m_timer_ts.tv_nsec = 0;
    m_timer_req   = { this, nullptr, -1, 0, op_timeout };
    m_timer_armed = m_loop->submit_timeout(&m_timer_ts, &m_timer_req);

    // A refused submission is the end of the publish cycle: nothing else
    // reschedules it, so this daemon would stop heartbeating into the cluster
    // directory and its peers would age it out without one line saying so.
    if (SOCKETLEY_UNLIKELY(!m_timer_armed))
        LOG_WARN("cluster: the publish timer could not be armed; this daemon "
                 "stops heartbeating and its peers will treat it as stale");
}

std::string cluster_discovery::build_publish_json() const
{
    using namespace cd_detail;
    std::string json;
    json.reserve(1024);

    json += "{\"daemon\":\"";
    json += socketley::json::escape(m_daemon_name);
    json += "\",\"host\":\"";
    json += socketley::json::escape(m_cluster_addr);

    // The claim, which a reader of this directory needs none of and this
    // daemon needs all of when it finds the file under its own name on the
    // next boot.
    json += "\",\"sock\":\"";
    json += socketley::json::escape(m_socket_path);
    json += "\",\"boot\":\"";
    json += socketley::json::escape(m_boot_id);
    json += "\",\"pid\":";

    char pid_buf[16];
    auto [pidend, pidec] = std::to_chars(pid_buf, pid_buf + sizeof(pid_buf),
                                         static_cast<int64_t>(getpid()));
    json.append(pid_buf, static_cast<size_t>(pidend - pid_buf));

    json += ",\"heartbeat\":";

    char ts_buf[24];
    auto now = static_cast<int64_t>(std::time(nullptr));
    auto [end, ec] = std::to_chars(ts_buf, ts_buf + sizeof(ts_buf), now);
    json.append(ts_buf, static_cast<size_t>(end - ts_buf));

    json += ",\"runtimes\":[";

    // Snapshot local runtimes under read lock
    bool first = true;
    {
        std::shared_lock lock(m_manager.mutex);
        const auto& runtimes = m_manager.list();
        for (const auto& [name, inst] : runtimes)
        {
            if (!first) json += ',';
            first = false;

            json += "{\"name\":\"";
            json += socketley::json::escape(name);
            json += "\",\"type\":\"";
            json += type_str(inst->get_type());
            json += "\",\"group\":\"";
            json += socketley::json::escape(inst->get_group());
            json += "\",\"port\":";

            char port_buf[8];
            auto [pend, pec] = std::to_chars(port_buf, port_buf + sizeof(port_buf),
                                              inst->get_port());
            json.append(port_buf, static_cast<size_t>(pend - port_buf));

            json += ",\"state\":\"";
            json += state_to_string(inst->get_state());
            json += "\",\"connections\":";

            char conn_buf[16];
            // The reported figure and not the local tables, because this
            // runtime's connections may be in a worker and a peer choosing by
            // load would read an idle member.
            auto [cend, cec] = std::to_chars(conn_buf, conn_buf + sizeof(conn_buf),
                                              inst->reported_connection_count());
            json.append(conn_buf, static_cast<size_t>(cend - conn_buf));

            json += '}';
        }
    }

    json += "]}";
    return json;
}

void cluster_discovery::publish()
{
    std::string json = build_publish_json();
    std::string path = m_cluster_dir + "/" + m_daemon_name + ".json";

    // Unsynced, as it is written again within the second.
    if (!socketley::replace_file(path, json, socketley::durability::none, nullptr, 0644))
    {
        LOG_WARN("cluster: could not write state file");
        return;
    }

    m_published = true;
}

void cluster_discovery::scan()
{
    DIR* dir = opendir(m_cluster_dir.c_str());
    if (!dir)
        return;

    time_t now = std::time(nullptr);

    // Track which daemons we see in this scan (for removing stale entries)
    std::unordered_set<std::string> seen;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr)
    {
        std::string_view fname(entry->d_name);

        // Only .json files, which is also what keeps a half-written
        // "<name>.json.<pid>.<n>.tmp" out, so renaming the temporary would mean
        // changing this test with it.
        if (fname.size() < 6 || fname.substr(fname.size() - 5) != ".json")
            continue;

        // Extract daemon name from filename (strip .json)
        std::string daemon_name(fname.substr(0, fname.size() - 5));

        // Skip our own file
        if (daemon_name == m_daemon_name)
            continue;

        seen.insert(daemon_name);

        // Check mtime — only re-read if file changed
        std::string full_path = m_cluster_dir + "/" + std::string(fname);
        struct stat st{};
        if (stat(full_path.c_str(), &st) != 0)
            continue;

        auto mit = m_mtime_cache.find(daemon_name);
        if (mit != m_mtime_cache.end() && mit->second == st.st_mtime)
        {
            // File unchanged — just check if the cached daemon is stale
            std::lock_guard lock(m_remote_mutex);
            auto dit = m_remote_daemons.find(daemon_name);
            if (dit != m_remote_daemons.end() &&
                (now - dit->second.heartbeat) > STALE_THRESHOLD_SEC)
            {
                m_remote_daemons.erase(dit);
            }
            continue;
        }

        // Read and parse the file
        std::ifstream f(full_path);
        if (!f.is_open())
            continue;

        std::ostringstream ss;
        ss << f.rdbuf();
        std::string content = ss.str();

        remote_daemon rd;
        if (!parse_daemon_json(content, rd))
            continue;

        // Check if stale
        if ((now - rd.heartbeat) > STALE_THRESHOLD_SEC)
        {
            std::lock_guard lock(m_remote_mutex);
            m_remote_daemons.erase(daemon_name);
            m_mtime_cache[daemon_name] = st.st_mtime;
            continue;
        }

        // Update cache
        m_mtime_cache[daemon_name] = st.st_mtime;
        {
            std::lock_guard lock(m_remote_mutex);
            m_remote_daemons[daemon_name] = std::move(rd);
        }
    }

    closedir(dir);

    // Remove entries for daemons whose files no longer exist
    {
        std::lock_guard lock(m_remote_mutex);
        for (auto it = m_remote_daemons.begin(); it != m_remote_daemons.end(); )
        {
            if (seen.find(it->first) == seen.end())
            {
                m_mtime_cache.erase(it->first);
                it = m_remote_daemons.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }

    // ─── Change detection for event callbacks ───
    if (!m_event_callback)
        return;

    // Build current daemon name set and group counts under lock
    std::unordered_set<std::string> current_names;
    std::unordered_map<std::string, int> current_groups;
    {
        std::lock_guard lock(m_remote_mutex);
        for (const auto& [name, daemon] : m_remote_daemons)
        {
            current_names.insert(name);
            for (const auto& rt : daemon.runtimes)
            {
                if (!rt.group.empty() && rt.state == "running" && rt.port > 0)
                    ++current_groups[rt.group];
            }
        }
    }

    // Also count local group members
    {
        std::shared_lock lock(m_manager.mutex);
        for (const auto& [_, inst] : m_manager.list())
        {
            auto g = inst->get_group();
            if (!g.empty() && inst->get_state() == runtime_running && inst->get_port() > 0)
                ++current_groups[std::string(g)];
        }
    }

    // Diff against previous state
    std::vector<cluster_event> events;

    // New daemons = join events
    for (const auto& name : current_names)
    {
        if (m_previous_daemon_names.find(name) == m_previous_daemon_names.end())
            events.push_back({cluster_event::daemon_join, name, {}, 0});
    }

    // Missing daemons = leave events
    for (const auto& name : m_previous_daemon_names)
    {
        if (current_names.find(name) == current_names.end())
            events.push_back({cluster_event::daemon_leave, name, {}, 0});
    }

    // Changed group counts = group_change events
    for (const auto& [group, count] : current_groups)
    {
        auto it = m_previous_group_counts.find(group);
        if (it == m_previous_group_counts.end() || it->second != count)
            events.push_back({cluster_event::group_change, {}, group, count});
    }
    for (const auto& [group, _] : m_previous_group_counts)
    {
        if (current_groups.find(group) == current_groups.end())
            events.push_back({cluster_event::group_change, {}, group, 0});
    }

    // Update previous state
    m_previous_daemon_names = std::move(current_names);
    m_previous_group_counts = std::move(current_groups);

    // Fire callback
    if (!events.empty())
        m_event_callback(events);
}

// Delete this daemon's file and only this daemon's: nothing to remove unless
// we wrote something, and nothing to remove if the name has since been taken
// by a claim that is not ours.
void cluster_discovery::unpublish()
{
    if (!m_published)
        return;

    const std::string path = m_cluster_dir + "/" + m_daemon_name + ".json";

    node_claim held;
    int64_t hb = 0;
    if (read_claim_file(path, held, hb) && !claim_is_ours(held))
    {
        LOG_WARN("cluster: leaving the state file alone on shutdown — it is no "
                 "longer ours");
        return;
    }

    unlink(path.c_str());
    m_published = false;
}

bool cluster_discovery::parse_daemon_json(const std::string& json, remote_daemon& out) const
{
    using socketley::json::int_of;
    using socketley::json::string_of;
    socketley::json::jvalue doc;
    if (!socketley::json::json_reader(json).document(doc))
        return false;
    out.name = std::string(string_of(doc, "daemon"));
    out.host = std::string(string_of(doc, "host"));
    out.heartbeat = static_cast<time_t>(int_of(doc, "heartbeat"));

    if (out.name.empty() || out.heartbeat == 0)
        return false;

    if (const auto* list = socketley::json::member(doc, "runtimes"))
        for (const auto& obj : list->items)
        {
            remote_runtime rt;
            rt.daemon_name = out.name;
            rt.host = out.host;
            rt.name = std::string(string_of(obj, "name"));
            rt.type = std::string(string_of(obj, "type"));
            rt.group = std::string(string_of(obj, "group"));
            rt.port = static_cast<uint16_t>(int_of(obj, "port"));
            rt.state = std::string(string_of(obj, "state"));
            rt.connections = static_cast<size_t>(int_of(obj, "connections"));
            out.runtimes.push_back(std::move(rt));
        }

    return true;
}

std::vector<cluster_discovery::remote_endpoint>
cluster_discovery::get_remote_group(std::string_view group) const
{
    std::vector<remote_endpoint> result;

    std::lock_guard lock(m_remote_mutex);
    for (const auto& [_, daemon] : m_remote_daemons)
    {
        for (const auto& rt : daemon.runtimes)
        {
            if (rt.group == group && rt.state == "running" && rt.port > 0)
                result.push_back({rt.host, rt.port});
        }
    }

    return result;
}

void cluster_discovery::set_event_callback(event_callback_t cb)
{
    std::lock_guard lock(m_remote_mutex);
    m_event_callback = std::move(cb);
}

std::vector<remote_daemon> cluster_discovery::get_all_daemons() const
{
    std::vector<remote_daemon> result;

    std::lock_guard lock(m_remote_mutex);
    result.reserve(m_remote_daemons.size());
    for (const auto& [_, daemon] : m_remote_daemons)
        result.push_back(daemon);

    return result;
}
