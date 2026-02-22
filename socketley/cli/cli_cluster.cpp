#include "cli.h"
#include "ipc_client.h"
#include "command_hashing.h"
#include "../shared/cluster_discovery.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>
#include <filesystem>
#include <iomanip>
#include <charconv>
#include <ctime>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

namespace fs = std::filesystem;

// ─── Minimal JSON helpers (same as cluster_discovery.cpp) ───

namespace {

std::string json_get_string(std::string_view json, std::string_view key)
{
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

int64_t json_get_number(std::string_view json, std::string_view key)
{
    std::string needle = "\"";
    needle += key;
    needle += "\":";
    auto pos = json.find(needle);
    if (pos == std::string_view::npos)
        return 0;

    pos += needle.size();
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t'))
        ++pos;

    int64_t val = 0;
    auto [ptr, ec] = std::from_chars(json.data() + pos,
        json.data() + json.size(), val);
    if (ec != std::errc{})
        return 0;
    return val;
}

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
        while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' ||
               json[pos] == '\n' || json[pos] == '\r' || json[pos] == ','))
            ++pos;

        if (pos >= json.size() || json[pos] == ']')
            break;

        if (json[pos] != '{')
            break;

        auto end = json.find('}', pos);
        if (end == std::string_view::npos)
            break;

        result.push_back(json.substr(pos, end - pos + 1));
        pos = end + 1;
    }

    return result;
}

struct cluster_daemon
{
    std::string name;
    std::string host;
    int64_t heartbeat = 0;
    struct rt_info
    {
        std::string name;
        std::string type;
        std::string group;
        uint16_t port = 0;
        std::string state;
        int64_t connections = 0;
    };
    std::vector<rt_info> runtimes;
    bool stale = false;
};

std::vector<cluster_daemon> load_cluster_dir(const std::string& dir)
{
    std::vector<cluster_daemon> daemons;
    time_t now = std::time(nullptr);

    DIR* d = opendir(dir.c_str());
    if (!d)
        return daemons;

    struct dirent* entry;
    while ((entry = readdir(d)) != nullptr)
    {
        std::string_view fname(entry->d_name);
        if (fname.size() < 6 || fname.substr(fname.size() - 5) != ".json")
            continue;
        if (fname.size() > 9 && fname.substr(fname.size() - 9) == ".tmp.json")
            continue;

        std::string path = dir + "/" + std::string(fname);
        std::ifstream f(path);
        if (!f.is_open())
            continue;

        std::ostringstream ss;
        ss << f.rdbuf();
        std::string content = ss.str();

        cluster_daemon cd;
        cd.name = json_get_string(content, "daemon");
        cd.host = json_get_string(content, "host");
        cd.heartbeat = json_get_number(content, "heartbeat");

        if (cd.name.empty())
            continue;

        cd.stale = (now - cd.heartbeat) > 10;

        auto objects = json_get_array_objects(content, "runtimes");
        for (auto obj : objects)
        {
            cluster_daemon::rt_info rt;
            rt.name = json_get_string(obj, "name");
            rt.type = json_get_string(obj, "type");
            rt.group = json_get_string(obj, "group");
            rt.port = static_cast<uint16_t>(json_get_number(obj, "port"));
            rt.state = json_get_string(obj, "state");
            rt.connections = json_get_number(obj, "connections");
            cd.runtimes.push_back(std::move(rt));
        }

        daemons.push_back(std::move(cd));
    }

    closedir(d);
    return daemons;
}

std::string format_heartbeat_ago(int64_t heartbeat)
{
    time_t now = std::time(nullptr);
    int64_t diff = now - heartbeat;
    if (diff < 0) diff = 0;

    if (diff < 60)
        return std::to_string(diff) + "s ago";
    if (diff < 3600)
        return std::to_string(diff / 60) + "m ago";
    return std::to_string(diff / 3600) + "h ago";
}

} // namespace

// ─── Subcommand implementations ───

static int cluster_ls(const std::string& dir)
{
    auto daemons = load_cluster_dir(dir);
    if (daemons.empty())
        return 0;

    std::cout << std::left
              << std::setw(14) << "DAEMON"
              << std::setw(18) << "HOST"
              << std::setw(10) << "RUNTIMES"
              << std::setw(10) << "RUNNING"
              << "HEARTBEAT\n";

    for (const auto& d : daemons)
    {
        int running = 0;
        for (const auto& rt : d.runtimes)
            if (rt.state == "running") ++running;

        std::string hb = d.stale ? "stale" : format_heartbeat_ago(d.heartbeat);

        std::cout << std::setw(14) << d.name
                  << std::setw(18) << d.host
                  << std::setw(10) << d.runtimes.size()
                  << std::setw(10) << running
                  << hb << "\n";
    }

    return 0;
}

static int cluster_ps(const std::string& dir)
{
    auto daemons = load_cluster_dir(dir);

    bool any = false;
    for (const auto& d : daemons)
        if (!d.stale && !d.runtimes.empty()) { any = true; break; }

    if (!any)
        return 0;

    std::cout << std::left
              << std::setw(14) << "DAEMON"
              << std::setw(16) << "NAME"
              << std::setw(8)  << "TYPE"
              << std::setw(8)  << "PORT"
              << std::setw(8)  << "GROUP"
              << std::setw(6)  << "CONN"
              << "STATUS\n";

    for (const auto& d : daemons)
    {
        if (d.stale)
            continue;

        for (const auto& rt : d.runtimes)
        {
            std::cout << std::setw(14) << d.name
                      << std::setw(16) << rt.name
                      << std::setw(8)  << rt.type
                      << std::setw(8)  << (rt.port > 0 ? std::to_string(rt.port) : "-")
                      << std::setw(8)  << (rt.group.empty() ? "-" : rt.group)
                      << std::setw(6)  << rt.connections
                      << rt.state << "\n";
        }
    }

    return 0;
}

static int cluster_group(const std::string& dir, std::string_view group_name)
{
    auto daemons = load_cluster_dir(dir);

    bool any = false;

    std::cout << std::left
              << std::setw(14) << "DAEMON"
              << std::setw(16) << "NAME"
              << std::setw(8)  << "PORT"
              << std::setw(6)  << "CONN"
              << "STATUS\n";

    for (const auto& d : daemons)
    {
        if (d.stale)
            continue;

        for (const auto& rt : d.runtimes)
        {
            if (rt.group == group_name)
            {
                any = true;
                std::cout << std::setw(14) << d.name
                          << std::setw(16) << rt.name
                          << std::setw(8)  << (rt.port > 0 ? std::to_string(rt.port) : "-")
                          << std::setw(6)  << rt.connections
                          << rt.state << "\n";
            }
        }
    }

    if (!any)
    {
        std::cerr << "no members in group: " << group_name << "\n";
        return 1;
    }

    return 0;
}

static int cluster_show(const std::string& dir, std::string_view daemon_name)
{
    std::string path = dir + "/" + std::string(daemon_name) + ".json";
    std::ifstream f(path);
    if (!f.is_open())
    {
        std::cerr << "daemon not found: " << daemon_name << "\n";
        return 1;
    }

    std::ostringstream ss;
    ss << f.rdbuf();
    std::cout << ss.str() << "\n";
    return 0;
}

static int cluster_stats(const std::string& dir)
{
    auto daemons = load_cluster_dir(dir);

    int healthy = 0, stale = 0;
    int total_runtimes = 0, running_runtimes = 0;
    std::unordered_map<std::string, int> groups;

    for (const auto& d : daemons)
    {
        if (d.stale)
            ++stale;
        else
            ++healthy;

        for (const auto& rt : d.runtimes)
        {
            ++total_runtimes;
            if (rt.state == "running")
                ++running_runtimes;
            if (!rt.group.empty())
                groups[rt.group]++;
        }
    }

    std::cout << "Daemons: " << daemons.size()
              << " (" << healthy << " healthy, " << stale << " stale)\n";
    std::cout << "Runtimes: " << total_runtimes
              << " total, " << running_runtimes << " running\n";

    if (!groups.empty())
    {
        std::cout << "Groups:";
        bool first = true;
        for (const auto& [name, count] : groups)
        {
            if (!first) std::cout << ",";
            first = false;
            std::cout << " " << name << " (" << count << " members)";
        }
        std::cout << "\n";
    }

    return 0;
}

static int cluster_watch(const std::string& dir)
{
    while (true)
    {
        // Clear screen
        std::cout << "\033[2J\033[H";
        std::cout << "Cluster: " << dir << "\n\n";
        cluster_ps(dir);
        std::cout << "\n";
        cluster_stats(dir);
        std::cout << "\n(refreshing every 2s, Ctrl+C to stop)\n";
        usleep(2000000);
    }
    return 0;
}

// ─── Main dispatch ───

int cli_cluster(int argc, char** argv)
{
    // Query daemon for cluster directory
    std::string dir;
    int rc = ipc_send("cluster-dir", dir);
    if (rc < 0)
    {
        std::cerr << "failed to connect to daemon\n";
        return 2;
    }
    if (rc != 0)
    {
        // daemon returned error (e.g. not in cluster mode)
        if (!dir.empty())
            std::cerr << dir;
        return rc;
    }

    // Trim trailing newline
    while (!dir.empty() && (dir.back() == '\n' || dir.back() == '\r'))
        dir.pop_back();

    std::string subcmd;
    int i = 2;

    if (i < argc)
        subcmd = argv[i];

    if (subcmd.empty())
    {
        // Default to ls
        return cluster_ls(dir);
    }

    switch (fnv1a(subcmd.data()))
    {
        case fnv1a("ls"):
            return cluster_ls(dir);

        case fnv1a("ps"):
            return cluster_ps(dir);

        case fnv1a("group"):
            if (i + 1 >= argc)
            {
                std::cerr << "usage: cluster group <name>\n";
                return 1;
            }
            return cluster_group(dir, argv[i + 1]);

        case fnv1a("show"):
            if (i + 1 >= argc)
            {
                std::cerr << "usage: cluster show <daemon-name>\n";
                return 1;
            }
            return cluster_show(dir, argv[i + 1]);

        case fnv1a("stats"):
            return cluster_stats(dir);

        case fnv1a("watch"):
            return cluster_watch(dir);

        default:
            std::cerr << "unknown cluster subcommand: " << subcmd << "\n";
            return 1;
    }
}
