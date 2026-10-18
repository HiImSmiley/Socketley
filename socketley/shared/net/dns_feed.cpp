#include "dns_feed.h"
#include "../persist/paths.h"
#include "../persist/replaced_file.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace dns_feed
{

namespace
{

std::string read_file(const std::string& path)
{
    std::ifstream f(path);
    if (!f)
        return {};
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// Written beside itself and renamed over, so a reader sees the old file or the new one and never half of one.
bool write_atomic(const std::string& path, std::string_view data)
{
    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(path).parent_path(), ec);
    return socketley::replace_file(path, data, socketley::durability::none, nullptr, 0644);
}

}   // namespace

std::string dir()
{
    static const std::string d = (socketley_paths::resolve().state_dir / ".dns").string();
    return d;
}

bool write_names(const std::vector<std::string>& names)
{
    std::vector<std::string> sorted = names;
    std::sort(sorted.begin(), sorted.end());
    sorted.erase(std::unique(sorted.begin(), sorted.end()), sorted.end());
    std::string text;
    for (const auto& n : sorted)
        text += n + "\n";
    const std::string path = dir() + "/names";
    struct stat st{};
    // Nothing written when nothing changed, and no file made for nothing.
    if (::stat(path.c_str(), &st) < 0 ? text.empty() : read_file(path) == text)
        return true;
    return write_atomic(path, text);
}

bool write_challenge(std::string_view name, std::string_view value, std::string_view token, std::string& path)
{
    std::string safe;
    for (char c : token)
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_')
            safe += c;
    if (safe.empty() || name.empty() || value.empty() || name.find_first_of(" \n") != std::string_view::npos ||
        value.find_first_of(" \n") != std::string_view::npos)
        return false;
    path = dir() + "/acme-" + safe.substr(0, 64);
    return write_atomic(path, std::string(name) + " " + std::string(value) + "\n");
}

std::string routes_path(std::string_view entrance)
{
    return dir() + "/routes-" + std::string(entrance);
}

bool write_routes(std::string_view entrance, std::string_view table)
{
    const std::string path = routes_path(entrance);
    struct stat st{};
    if (::stat(path.c_str(), &st) == 0 && read_file(path) == table)
        return true;
    return write_atomic(path, table);
}

void remove_routes_except(const std::vector<std::string>& entrances)
{
    DIR* d = ::opendir(dir().c_str());
    if (!d)
        return;
    std::vector<std::string> gone;
    while (const dirent* e = ::readdir(d))
    {
        const std::string_view fn = e->d_name;
        if (fn.starts_with("routes-") && !fn.ends_with(".tmp") &&
            std::find(entrances.begin(), entrances.end(), fn.substr(7)) == entrances.end())
            gone.emplace_back(fn);
    }
    ::closedir(d);
    for (const auto& g : gone)
        ::unlink((dir() + "/" + g).c_str());
}

int64_t stamp_ns()
{
    struct stat st{};
    if (::stat(dir().c_str(), &st) < 0)
        return 0;
    return static_cast<int64_t>(st.st_mtim.tv_sec) * 1000000000 + st.st_mtim.tv_nsec;
}

snapshot read()
{
    snapshot s;
    s.stamp_ns = stamp_ns();
    if (!s.stamp_ns)
        return s;
    {
        std::istringstream in(read_file(dir() + "/names"));
        for (std::string line; std::getline(in, line);)
            if (std::string why; !line.empty() && valid_name(line, why))
                s.names.push_back(line);
    }
    DIR* d = ::opendir(dir().c_str());
    if (!d)
        return s;
    while (const dirent* e = ::readdir(d))
    {
        const std::string_view fn = e->d_name;
        if (!fn.starts_with("acme-") || fn.ends_with(".tmp"))
            continue;
        std::istringstream in(read_file(dir() + "/" + std::string(fn)));
        std::string name, value;
        if (in >> name >> value)
            s.challenges.emplace_back(name, value);
    }
    ::closedir(d);
    std::sort(s.challenges.begin(), s.challenges.end());
    return s;
}

bool valid_name(std::string_view n, std::string& why)
{
    std::string_view rest = n;
    if (rest.starts_with("*."))
        rest.remove_prefix(2);
    if (rest.ends_with("."))
        rest.remove_suffix(1);
    if (rest.empty() || rest.size() > 253)
    {
        why = "'" + std::string(n) + "' is not a name";
        return false;
    }
    size_t label = 0;
    for (size_t i = 0; i <= rest.size(); ++i)
    {
        if (i == rest.size() || rest[i] == '.')
        {
            if (label == 0 || label > 63)
            {
                why = "'" + std::string(n) + "' has an empty or overlong label";
                return false;
            }
            label = 0;
            continue;
        }
        const char c = rest[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'))
        {
            why = "'" + std::string(n) + "' holds '" + std::string(1, c) + "'; a name is letters, digits and hyphens";
            return false;
        }
        ++label;
    }
    return true;
}

}   // namespace dns_feed
