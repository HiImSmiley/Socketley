#include "mail_sieve_store.h"

#include <algorithm>
#include <cstdio>
#include <filesystem>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../shared/loop/blocking_write.h"
#include "../../shared/persist/read_file.h"

namespace socketley::mail
{

namespace
{

int64_t mtime_ns(const std::string& path)
{
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0)
        return -1;
    return static_cast<int64_t>(st.st_mtim.tv_sec) * 1000000000 + st.st_mtim.tv_nsec;
}

// Written whole beside the file and moved over it, so a reader on another shard sees the old text or the new.
bool write_whole(const std::string& path, std::string_view text)
{
    const std::string tmp = path + ".tmp." + std::to_string(::getpid());
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    const bool ok = fd >= 0 && socketley::write_all(fd, text.data(), text.size()) && ::fsync(fd) == 0;
    if (fd >= 0)
        ::close(fd);
    if (!ok || ::rename(tmp.c_str(), path.c_str()) != 0)
    {
        ::unlink(tmp.c_str());
        return false;
    }
    return true;
}

}   // namespace

bool sieve_store::name_ok(std::string_view name)
{
    if (name.empty() || name.size() > 128 || name == "." || name == ".." || name.front() == '.')
        return false;
    for (const char c : name)
    {
        const auto u = static_cast<unsigned char>(c);
        if (u < 0x20 || u == 0x7f || c == '/' || c == '\\')
            return false;
    }
    return true;
}

std::string sieve_store::user_dir(const std::string& user) const
{
    // A user's name is a directory's: one that could leave the directory has none.
    if (!name_ok(user))
        return m_dir + "/.none";
    return m_dir + "/" + user;
}

std::string sieve_store::path_of(const std::string& user, const std::string& name) const
{
    return user_dir(user) + "/" + name + ".sieve";
}

std::string sieve_store::active_name(const std::string& user) const
{
    std::string text;
    if (!socketley::read_file(user_dir(user) + "/.active", text))
        return {};
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r'))
        text.pop_back();
    return text;
}

std::vector<std::pair<std::string, bool>> sieve_store::list(const std::string& user) const
{
    std::vector<std::pair<std::string, bool>> out;
    const std::string active = active_name(user);
    std::error_code ec;
    for (const auto& de : std::filesystem::directory_iterator(user_dir(user), ec))
    {
        const std::string f = de.path().filename().string();
        if (!f.ends_with(".sieve") || f.starts_with("."))
            continue;
        std::string name = f.substr(0, f.size() - 6);
        out.emplace_back(name, name == active);
    }
    std::sort(out.begin(), out.end());
    return out;
}

bool sieve_store::get(const std::string& user, const std::string& name, std::string& text) const
{
    return name_ok(name) && socketley::read_file(path_of(user, name), text);
}

bool sieve_store::fits(const std::string& user, const std::string& name, uint64_t size, std::string& code) const
{
    if (size > max_script)
    {
        code = "QUOTA/MAXSIZE";
        return false;
    }
    uint64_t used = 0;
    size_t n = 0;
    bool there = false;
    for (const auto& [s, active] : list(user))
    {
        std::string text;
        if (s == name)
        {
            there = true;
            continue;
        }
        if (get(user, s, text))
            used += text.size();
        ++n;
    }
    if (!there && n >= max_scripts)
    {
        code = "QUOTA/MAXSCRIPTS";
        return false;
    }
    if (used + size > max_user)
    {
        code = "QUOTA/MAXSIZE";
        return false;
    }
    return true;
}

bool sieve_store::put(const std::string& user, const std::string& name, std::string_view text, std::string& code,
                      std::string& why)
{
    if (!name_ok(name))
    {
        why = "a script's name is printable and holds no /";
        return false;
    }
    if (!fits(user, name, text.size(), code))
    {
        why = "the script would pass what a user may keep";
        return false;
    }
    if (!sieve::script::compile(text, why))
        return false;
    std::error_code ec;
    std::filesystem::create_directories(user_dir(user), ec);
    if (!write_whole(path_of(user, name), text))
    {
        why = "the script could not be written";
        return false;
    }
    return true;
}

bool sieve_store::remove(const std::string& user, const std::string& name, std::string& code, std::string& why)
{
    if (!name_ok(name) || ::access(path_of(user, name).c_str(), F_OK) != 0)
    {
        code = "NONEXISTENT";
        why = "there is no script " + name;
        return false;
    }
    if (active_name(user) == name)
    {
        code = "ACTIVE";
        why = "the active script is not deleted";
        return false;
    }
    if (::unlink(path_of(user, name).c_str()) != 0)
    {
        why = "the script could not be deleted";
        return false;
    }
    return true;
}

bool sieve_store::rename(const std::string& user, const std::string& from, const std::string& to, std::string& code,
                         std::string& why)
{
    if (!name_ok(from) || ::access(path_of(user, from).c_str(), F_OK) != 0)
    {
        code = "NONEXISTENT";
        why = "there is no script " + from;
        return false;
    }
    if (!name_ok(to))
    {
        why = "a script's name is printable and holds no /";
        return false;
    }
    if (::access(path_of(user, to).c_str(), F_OK) == 0)
    {
        code = "ALREADYEXISTS";
        why = "there is a script " + to + " already";
        return false;
    }
    if (::rename(path_of(user, from).c_str(), path_of(user, to).c_str()) != 0)
    {
        why = "the script could not be renamed";
        return false;
    }
    if (active_name(user) == from && !write_whole(user_dir(user) + "/.active", to + "\n"))
    {
        why = "the script was renamed, but is no longer the active one";
        return false;
    }
    return true;
}

bool sieve_store::activate(const std::string& user, const std::string& name, std::string& code, std::string& why)
{
    if (name.empty())
    {
        ::unlink((user_dir(user) + "/.active").c_str());
        return true;
    }
    if (!name_ok(name) || ::access(path_of(user, name).c_str(), F_OK) != 0)
    {
        code = "NONEXISTENT";
        why = "there is no script " + name;
        return false;
    }
    if (!write_whole(user_dir(user) + "/.active", name + "\n"))
    {
        why = "the active script could not be set";
        return false;
    }
    return true;
}

std::shared_ptr<const sieve::script> sieve_store::active(const std::string& user)
{
    const std::string marker = user_dir(user) + "/.active";
    const int64_t am = mtime_ns(marker);
    std::lock_guard<std::mutex> g(m_mu);
    compiled& c = m_cache[user];
    if (am < 0)
    {
        c = {};
        return nullptr;
    }
    // The marker and the script it names are looked at; either changed, the script is read and compiled again.
    if (am != c.active_mtime_ns)
    {
        c.active_mtime_ns = am;
        c.name = active_name(user);
        c.mtime_ns = -1;
    }
    const int64_t sm = name_ok(c.name) ? mtime_ns(path_of(user, c.name)) : -1;
    if (sm < 0)
    {
        c.script.reset();
        return nullptr;
    }
    if (sm != c.mtime_ns)
    {
        c.mtime_ns = sm;
        std::string text, why;
        c.script = socketley::read_file(path_of(user, c.name), text) ? sieve::script::compile(text, why) : nullptr;
    }
    return c.script;
}

bool sieve_store::answered(const std::string& user, const std::string& handle, const std::string& sender,
                           uint32_t seconds, int64_t now_s)
{
    // One line a sender answered: when, the handle and the address; the lines out of date go as it is written.
    const std::string path = user_dir(user) + "/.vacation";
    std::string h = handle.empty() ? std::string("-") : handle;
    for (char& c : h)
        if (c == ' ' || c == '\n' || c == '\r')
            c = '_';
    std::lock_guard<std::mutex> g(m_mu);
    std::string text, kept;
    socketley::read_file(path, text);
    bool seen = false;
    std::string_view rest = text;
    while (!rest.empty())
    {
        const size_t nl = rest.find('\n');
        const std::string_view line = rest.substr(0, nl);
        rest = nl == std::string_view::npos ? std::string_view{} : rest.substr(nl + 1);
        const size_t a = line.find(' '), b = a == std::string_view::npos ? a : line.find(' ', a + 1);
        if (b == std::string_view::npos)
            continue;
        int64_t until = 0;
        if (std::sscanf(std::string(line.substr(0, a)).c_str(), "%ld", &until) != 1 || until <= now_s)
            continue;
        if (line.substr(a + 1, b - a - 1) == h && line.substr(b + 1) == sender)
            seen = true;
        kept.append(line).append("\n");
    }
    if (seen)
        return true;
    kept += std::to_string(now_s + seconds) + " " + h + " " + sender + "\n";
    std::error_code ec;
    std::filesystem::create_directories(user_dir(user), ec);
    write_whole(path, kept);
    return false;
}

}   // namespace socketley::mail
