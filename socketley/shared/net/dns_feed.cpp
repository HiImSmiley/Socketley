#include "dns_feed.h"
#include "../persist/paths.h"
#include "../persist/replaced_file.h"
#include "../persist/read_file.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <sstream>

#include <dirent.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace dns_feed
{

namespace
{

std::string read_file(const std::string& path)
{
    std::string out;
    socketley::read_whole_file(path, out);
    return out;
}

// Written beside itself and renamed over, so a reader sees the old file or the new one and never half of one.
bool write_atomic(const std::string& path, std::string_view data)
{
    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(path).parent_path(), ec);
    return socketley::replace_file(path, data, socketley::durability::none, nullptr, 0644);
}

// A name a change reached, as the file beside the directory keeps it: absolute and lower case, or "." for a name
// relative to every zone.
std::string reached_name(std::string_view n, bool relative)
{
    if (relative || n.empty() || n == "@")
        return ".";
    std::string out(n);
    for (char& c : out)
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
    if (out.back() != '.')
        out += '.';
    return out;
}

// A published name is relative when it has no dot past a leading "*.", as dns_zone's add_extra reads it.
std::string reached_by_published(std::string_view n)
{
    return reached_name(n, n.find('.', n.starts_with("*.") ? 2 : 0) == std::string_view::npos);
}

// A record line's owner, the first word: absolute only where it ends in a dot.
std::string reached_by_record(std::string_view line)
{
    const size_t b = line.find_first_not_of(" \t");
    if (b == std::string_view::npos)
        return {};
    const std::string_view owner = line.substr(b, line.find_first_of(" \t", b) - b);
    return reached_name(owner, !owner.ends_with('.'));
}

// The lines of `a` not in `b`, and of `b` not in `a`.
std::vector<std::string> lines_apart(std::string_view a, std::string_view b)
{
    const auto split = [](std::string_view t)
    {
        std::vector<std::string> v;
        std::istringstream in{std::string(t)};
        for (std::string line; std::getline(in, line);)
            if (!line.empty())
                v.push_back(line);
        std::sort(v.begin(), v.end());
        v.erase(std::unique(v.begin(), v.end()), v.end());
        return v;
    };
    const auto va = split(a), vb = split(b);
    std::vector<std::string> out;
    std::set_symmetric_difference(va.begin(), va.end(), vb.begin(), vb.end(), std::back_inserter(out));
    return out;
}

std::string changed_path()
{
    return dir() + "-changed";
}

// The second `reached` names last changed, kept beside the directory; made with "." at `before` for every name, the
// second the whole directory stood at until now.
void note_reached(const std::vector<std::string>& reached, int64_t before, int64_t at)
{
    std::map<std::string, int64_t> last;
    const std::string text = read_file(changed_path());
    struct stat st{};
    if (::stat(changed_path().c_str(), &st) < 0)
        last["."] = before;
    std::istringstream in(text);
    int64_t sec = 0;
    for (std::string name; in >> sec >> name;)
        last[name] = std::max(last[name], sec);
    for (const auto& n : reached)
        if (!n.empty())
            last[n] = std::max(last[n], at);
    std::string out;
    for (const auto& [name, s] : last)
        out += std::to_string(s) + " " + name + "\n";
    if (out != text)
        write_atomic(changed_path(), out);
}

// A change to the directory, made under a lock beside it, after which the directory's time is moved past the
// second it held before, so two changes in one second still raise the serial a dns runtime adds that second to; and
// that second noted for each name the change reached.
template <class F>
bool change(const std::vector<std::string>& reached, F&& f)
{
    std::error_code ec;
    std::filesystem::create_directories(dir(), ec);
    const int lock = ::open((dir() + "-lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0644);
    if (lock >= 0 && ::flock(lock, LOCK_EX) < 0) {}
    const int64_t before = stamp_ns() / 1000000000;
    const bool ok = f();
    struct stat st{};
    if (::stat(dir().c_str(), &st) == 0)
    {
        int64_t at = st.st_mtim.tv_sec;
        if (before > 0 && at <= before)
        {
            at = before + 1;
            const timespec times[2] = {{0, UTIME_OMIT}, {static_cast<time_t>(at), 0}};
            if (::utimensat(AT_FDCWD, dir().c_str(), times, 0) < 0) {}
        }
        // After the directory, so a dns runtime that read the change before its second looks again at this file's.
        note_reached(reached, before, at);
    }
    if (lock >= 0)
        ::close(lock);
    return ok;
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
    const std::string was = ::stat(path.c_str(), &st) < 0 ? std::string() : read_file(path);
    if (::stat(path.c_str(), &st) < 0 ? text.empty() : was == text)
        return true;
    std::vector<std::string> reached;
    for (const auto& n : lines_apart(was, text))
        reached.push_back(reached_by_published(n));
    return change(reached, [&] { return write_atomic(path, text); });
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
    return change({reached_name("_acme-challenge." + std::string(name), false)},
                  [&] { return write_atomic(path, std::string(name) + " " + std::string(value) + "\n"); });
}

void remove_challenge(const std::string& path)
{
    std::istringstream in(read_file(path));
    std::string name;
    std::vector<std::string> reached;
    if (in >> name)
        reached.push_back(reached_name("_acme-challenge." + name, false));
    change(reached, [&] { return ::unlink(path.c_str()) == 0; });
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
    // An entrance's table is no record of any zone.
    return change({}, [&] { return write_atomic(path, table); });
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
    if (gone.empty())
        return;
    change({}, [&] {
        for (const auto& g : gone)
            ::unlink((dir() + "/" + g).c_str());
        return true;
    });
}

bool write_records(std::string_view runtime, std::string_view text)
{
    std::string safe;
    for (char c : runtime)
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.')
            safe += c;
    if (safe.empty() || safe.front() == '.')
        return false;
    const std::string path = dir() + "/records-" + safe;
    struct stat st{};
    const bool there = ::stat(path.c_str(), &st) == 0;
    const std::string was = there ? read_file(path) : std::string();
    if (there && was == text && !text.empty())
        return true;
    std::vector<std::string> reached;
    for (const auto& line : lines_apart(was, text))
        if (std::string r = reached_by_record(line); !r.empty())
            reached.push_back(std::move(r));
    if (text.empty())
        return !there || change(reached, [&] { return ::unlink(path.c_str()) == 0; });
    return change(reached, [&] { return write_atomic(path, text); });
}

// Beside the directory and not in it, since the directory's time dates the records and the zones are none of them.
std::string zones_path()
{
    return dir() + "-zones";
}

bool write_zones(std::string_view text)
{
    const std::string path = zones_path();
    struct stat st{};
    if (::stat(path.c_str(), &st) < 0 ? text.empty() : read_file(path) == text)
        return true;
    return write_atomic(path, text);
}

std::vector<std::pair<std::string, std::string>> read_zones()
{
    std::vector<std::pair<std::string, std::string>> out;
    std::istringstream in(read_file(zones_path()));
    std::string rt, origin;
    while (in >> rt >> origin)
        out.emplace_back(rt, origin);
    return out;
}

int64_t stamp_ns()
{
    struct stat st{};
    if (::stat(dir().c_str(), &st) < 0)
        return 0;
    return static_cast<int64_t>(st.st_mtim.tv_sec) * 1000000000 + st.st_mtim.tv_nsec;
}

int64_t changed_stamp_ns()
{
    struct stat st{};
    if (::stat(changed_path().c_str(), &st) < 0)
        return 0;
    return static_cast<int64_t>(st.st_mtim.tv_sec) * 1000000000 + st.st_mtim.tv_nsec;
}

snapshot read()
{
    snapshot s;
    // Both times before what they date, so a change made while this reads is a change still to be read.
    s.stamp_ns = stamp_ns();
    s.changed_ns = changed_stamp_ns();
    if (!s.stamp_ns)
        return s;
    if (s.changed_ns)
    {
        std::istringstream in(read_file(changed_path()));
        int64_t sec = 0;
        for (std::string name; in >> sec >> name;)
            s.reached.emplace_back(name, sec);
    }
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
        if (fn.starts_with("records-") && !fn.ends_with(".tmp"))
        {
            std::istringstream rin(read_file(dir() + "/" + std::string(fn)));
            for (std::string line; std::getline(rin, line);)
                if (!line.empty())
                    s.records.push_back(line);
            continue;
        }
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
