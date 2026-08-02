#include "cluster_discovery.h"
#include "event_loop.h"
#include "runtime_manager.h"
#include "logging.h"
#include "../cli/command_hashing.h"

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

std::string json_escape(std::string_view s)
{
    std::string out;
    out.reserve(s.size() + 4);
    for (char c : s)
    {
        switch (c)
        {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            default:   out += c;      break;
        }
    }
    return out;
}

// Extract a string value for a given key from a flat JSON object
// Simple parser — sufficient for our well-known format
std::string json_get_string(std::string_view json, std::string_view key)
{
    // Look for "key":"value"
    std::string needle = "\"";
    needle += key;
    needle += "\":\"";
    auto pos = json.find(needle);
    if (pos == std::string_view::npos)
        return {};

    pos += needle.size();
    auto end = json.find('"', pos);
    if (end == std::string_view::npos)
        return {};

    return std::string(json.substr(pos, end - pos));
}

// Extract a numeric value for a given key
int64_t json_get_number(std::string_view json, std::string_view key)
{
    std::string needle = "\"";
    needle += key;
    needle += "\":";
    auto pos = json.find(needle);
    if (pos == std::string_view::npos)
        return 0;

    pos += needle.size();
    // Skip whitespace
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t'))
        ++pos;

    int64_t val = 0;
    auto [ptr, ec] = std::from_chars(json.data() + pos,
        json.data() + json.size(), val);
    if (ec != std::errc{})
        return 0;
    return val;
}

// Parse the "runtimes" array from the JSON
// Returns vector of {start_pos, end_pos} for each object in the array
std::vector<std::string_view> json_get_array_objects(std::string_view json, std::string_view key)
{
    std::vector<std::string_view> result;

    std::string needle = "\"";
    needle += key;
    needle += "\":[";
    auto pos = json.find(needle);
    if (pos == std::string_view::npos)
        return result;

    pos += needle.size();

    while (pos < json.size())
    {
        // Skip whitespace
        while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' ||
               json[pos] == '\n' || json[pos] == '\r' || json[pos] == ','))
            ++pos;

        if (pos >= json.size() || json[pos] == ']')
            break;

        if (json[pos] != '{')
            break;

        // Find matching closing brace (no nesting in our format)
        auto end = json.find('}', pos);
        if (end == std::string_view::npos)
            break;

        result.push_back(json.substr(pos, end - pos + 1));
        pos = end + 1;
    }

    return result;
}

const char* type_str(runtime_type t)
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

const char* state_str(runtime_state s)
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

// The kernel's boot id: one value per boot of the machine, the same in every
// container on it.  Empty when /proc is not there, which makes every claim
// foreign and every conflict a refusal — the safe direction.
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
    using namespace cd_detail;

    std::ifstream f(path);
    if (!f.is_open())
        return false;

    std::ostringstream ss;
    ss << f.rdbuf();
    const std::string content = ss.str();

    heartbeat = json_get_number(content, "heartbeat");
    out.host  = json_get_string(content, "host");
    out.sock  = json_get_string(content, "sock");
    out.boot  = json_get_string(content, "boot");
    out.pid   = json_get_number(content, "pid");
    return true;
}

// ─── "me, again" versus "somebody else" ─────────────────────────────────────
//
// The hazard a duplicate name creates is two LIVE daemons publishing one file:
// their peers then see an endpoint set that belongs to neither, and traffic for
// `api1` splits between two machines that both believe they are api1.  So the
// question a restarting node has to answer is not "is this file mine" in some
// sentimental sense — it is "can the daemon that wrote it still be running".
//
// Three fields answer that, and they only have to answer it for a file whose
// heartbeat is FRESH; anything older than the staleness threshold is dropped by
// every peer anyway and is not a claim on anything.
//
//   boot   The machine's current boot id.  A fresh file with a different one
//          was written seconds ago by a kernel that is not this one, so it is
//          another machine — a reboot cannot have happened inside the window.
//
//   host   The address the writer advertised, which is what peers dial.  In the
//          documented deployment this is the container's hostname and it
//          survives a restart, a redeploy and a crash loop.
//
//   sock   The writer's control socket path.  This is the load-bearing one: a
//          unix socket path can be bound by exactly one process at a time, and
//          every other way into this daemon connects to that path rather than
//          binding it.  So on one machine, under one hostname, whoever holds
//          that path IS the daemon — and we hold it, or we would not be here.
//          A fresh file carrying our triple was therefore written by a process
//          that no longer exists.
//
// pid is published for the operator and for the message below, never for the
// decision: a restarted container's pid namespace is new, so the old pid is
// both meaningless and likely to have been handed to us.
//
// What this cannot tell apart: two containers on ONE host that were both given
// the SAME hostname and both run on the default socket path.  Their triples are
// identical and no file on the volume can separate them.  It is also the case
// where the distinction has no meaning to a peer, since both advertise the same
// address — the two would be interchangeable to every proxy in the cluster.
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

    // A file under our name with a fresh heartbeat is either this node's own
    // previous incarnation — a restart inside the staleness window, which is
    // what every container restart, redeploy and crash loop looks like — or a
    // second daemon claiming a name that is taken.  The first must rejoin; the
    // second must be refused, and refused without touching the file, because
    // the holder is live and deleting it would blind its peers.
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

    // Start the timer cycle
    schedule_timer();
    return true;
}

void cluster_discovery::stop()
{
    m_loop = nullptr;
    unpublish();
}

void cluster_discovery::on_cqe(struct io_uring_cqe* /*cqe*/)
{
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
    m_timer_req = { this, nullptr, -1, 0, op_timeout };
    m_loop->submit_timeout(&m_timer_ts, &m_timer_req);
}

std::string cluster_discovery::build_publish_json() const
{
    using namespace cd_detail;
    std::string json;
    json.reserve(1024);

    json += "{\"daemon\":\"";
    json += json_escape(m_daemon_name);
    json += "\",\"host\":\"";
    json += json_escape(m_cluster_addr);

    // The claim.  A reader of this directory needs none of it; the daemon that
    // finds this file under its own name on the next boot needs all of it.
    json += "\",\"sock\":\"";
    json += json_escape(m_socket_path);
    json += "\",\"boot\":\"";
    json += json_escape(m_boot_id);
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
            json += json_escape(name);
            json += "\",\"type\":\"";
            json += type_str(inst->get_type());
            json += "\",\"group\":\"";
            json += json_escape(inst->get_group());
            json += "\",\"port\":";

            char port_buf[8];
            auto [pend, pec] = std::to_chars(port_buf, port_buf + sizeof(port_buf),
                                              inst->get_port());
            json.append(port_buf, static_cast<size_t>(pend - port_buf));

            json += ",\"state\":\"";
            json += state_str(inst->get_state());
            json += "\",\"connections\":";

            char conn_buf[16];
            auto [cend, cec] = std::to_chars(conn_buf, conn_buf + sizeof(conn_buf),
                                              inst->get_connection_count());
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

    // Write atomically: write to tmp, then rename
    std::string tmp_path = path + ".tmp";
    {
        std::ofstream f(tmp_path, std::ios::trunc);
        if (!f.is_open())
        {
            LOG_WARN("cluster: could not write state file");
            return;
        }
        f << json;
    }

    if (std::rename(tmp_path.c_str(), path.c_str()) != 0)
    {
        LOG_WARN("cluster: could not rename state file");
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

        // Only process .json files.
        //
        // This one test is also what keeps a half-written file out.  publish()
        // writes "<name>.json" + ".tmp" and renames it into place, so the
        // temporary is "<name>.json.tmp" — it does not end in ".json" and never
        // reaches the line below.  A guard for ".tmp.json" used to stand here
        // as if it were the thing doing that; it was the suffix written
        // backwards, no writer in the tree produces that spelling, and the
        // branch had never been taken.  Traced against a running daemon: the
        // only names that ever appear in the cluster directory are
        // "<name>.json" and, for the moment between the write and the rename,
        // "<name>.json.tmp".  If the temporary file is ever renamed — say to
        // "<name>.tmp.json" — this test stops hiding it and something here has
        // to change with it.
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

// Delete this daemon's file — and only this daemon's file.
//
// Two ways in, and both used to be wrong.  A refused start() left the caller
// holding an object it then reset, and ~cluster_discovery() came here and
// unlinked the entry of the live peer the refusal had just declined to
// overwrite.  The peer republished two seconds later, so the damage looked like
// a blip; the real cost was that the very next attempt found no file and was
// allowed in, which is how a guard against two daemons sharing a name let two
// daemons share a name on the second try.
//
// So: nothing to remove unless we wrote something, and nothing to remove if the
// name has meanwhile been taken by someone whose claim is not ours.
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
    using namespace cd_detail;
    out.name = json_get_string(json, "daemon");
    out.host = json_get_string(json, "host");
    out.heartbeat = static_cast<time_t>(json_get_number(json, "heartbeat"));

    if (out.name.empty() || out.heartbeat == 0)
        return false;

    auto objects = json_get_array_objects(json, "runtimes");
    for (auto obj : objects)
    {
        remote_runtime rt;
        rt.daemon_name = out.name;
        rt.host = out.host;
        rt.name = json_get_string(obj, "name");
        rt.type = json_get_string(obj, "type");
        rt.group = json_get_string(obj, "group");
        rt.port = static_cast<uint16_t>(json_get_number(obj, "port"));
        rt.state = json_get_string(obj, "state");
        rt.connections = static_cast<size_t>(json_get_number(obj, "connections"));
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
