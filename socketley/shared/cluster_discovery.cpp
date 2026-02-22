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
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>

namespace fs = std::filesystem;

// ─── Minimal JSON helpers (local to this TU) ───

namespace {

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

} // namespace

// ─── cluster_discovery implementation ───

cluster_discovery::cluster_discovery(std::string_view daemon_name,
                                     std::string_view cluster_dir,
                                     runtime_manager& manager)
    : m_daemon_name(daemon_name)
    , m_cluster_dir(cluster_dir)
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

bool cluster_discovery::start(event_loop& loop)
{
    m_loop = &loop;

    // Ensure cluster directory exists
    std::error_code ec;
    fs::create_directories(m_cluster_dir, ec);

    // Check for duplicate daemon name: if a file with our name already exists
    // and has a fresh heartbeat, another daemon is using this name.
    std::string our_path = m_cluster_dir + "/" + m_daemon_name + ".json";
    {
        std::ifstream f(our_path);
        if (f.is_open())
        {
            std::ostringstream ss;
            ss << f.rdbuf();
            std::string content = ss.str();

            int64_t hb = json_get_number(content, "heartbeat");
            if (hb > 0)
            {
                time_t now = std::time(nullptr);
                if ((now - static_cast<time_t>(hb)) <= STALE_THRESHOLD_SEC)
                {
                    LOG_ERROR("cluster: daemon name already in use");
                    m_loop = nullptr;
                    return false;
                }
            }
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

void cluster_discovery::on_cqe(struct io_uring_cqe* cqe)
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
    m_timer_req = { op_timeout, -1, nullptr, 0, this };
    m_loop->submit_timeout(&m_timer_ts, &m_timer_req);
}

std::string cluster_discovery::build_publish_json() const
{
    std::string json;
    json.reserve(1024);

    json += "{\"daemon\":\"";
    json += json_escape(m_daemon_name);
    json += "\",\"host\":\"";
    json += json_escape(m_cluster_addr);
    json += "\",\"heartbeat\":";

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
        LOG_WARN("cluster: could not rename state file");
}

void cluster_discovery::scan()
{
    DIR* dir = opendir(m_cluster_dir.c_str());
    if (!dir)
        return;

    time_t now = std::time(nullptr);

    // Track which daemons we see in this scan (for removing stale entries)
    std::vector<std::string> seen;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr)
    {
        std::string_view fname(entry->d_name);

        // Only process .json files
        if (fname.size() < 6 || fname.substr(fname.size() - 5) != ".json")
            continue;

        // Skip .tmp files
        if (fname.size() > 9 && fname.substr(fname.size() - 9) == ".tmp.json")
            continue;

        // Extract daemon name from filename (strip .json)
        std::string daemon_name(fname.substr(0, fname.size() - 5));

        // Skip our own file
        if (daemon_name == m_daemon_name)
            continue;

        seen.push_back(daemon_name);

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
            bool found = false;
            for (const auto& s : seen)
            {
                if (s == it->first) { found = true; break; }
            }
            if (!found)
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

void cluster_discovery::unpublish()
{
    std::string path = m_cluster_dir + "/" + m_daemon_name + ".json";
    unlink(path.c_str());
}

bool cluster_discovery::parse_daemon_json(const std::string& json, remote_daemon& out) const
{
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
