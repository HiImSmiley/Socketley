#include "mail_sieve_store.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <filesystem>

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../shared/crypto/mac.h"
#include "../../shared/loop/blocking_write.h"
#include "../../shared/persist/read_file.h"
#include "../../shared/util/logging.h"

namespace socketley::mail
{

const std::string sieve_store::global_user = std::string("\x01global");

namespace
{

void sync_dir(const std::string& dir)
{
    if (const int d = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC); d >= 0)
    {
        if (::fsync(d) != 0) {}
        ::close(d);
    }
}

// Written whole beside the file and moved over it, so a reader on another shard sees the old text or the new; synced
// with the directory where `durable`, as a script is and a memory need not be.
bool write_whole(const std::string& path, std::string_view text, bool durable = true)
{
    const std::string tmp = path + ".tmp." + std::to_string(::getpid());
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    const bool ok = fd >= 0 && socketley::write_all(fd, text.data(), text.size()) && (!durable || ::fsync(fd) == 0);
    if (fd >= 0)
        ::close(fd);
    if (!ok || ::rename(tmp.c_str(), path.c_str()) != 0)
    {
        ::unlink(tmp.c_str());
        return false;
    }
    if (durable)
        sync_dir(std::filesystem::path(path).parent_path().string());
    return true;
}

// A user's directory locked against every other shard for as long as this lives.
class user_lock
{
public:
    explicit user_lock(const std::string& dir)
    {
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        m_fd = ::open((dir + "/.lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (m_fd >= 0 && ::flock(m_fd, LOCK_EX) != 0)
        {
            ::close(m_fd);
            m_fd = -1;
        }
    }
    ~user_lock()
    {
        if (m_fd >= 0)
            ::close(m_fd);
    }
    user_lock(const user_lock&)            = delete;
    user_lock& operator=(const user_lock&) = delete;
    bool held() const { return m_fd >= 0; }

private:
    int m_fd{-1};
};

// A key as its memory keeps it: 128 bits of its hash, in hex, so no line of the file holds what a sender wrote.
std::string hash_of(std::string_view key)
{
    const std::string h = socketley::crypto::hmac_sha256("socketley sieve memory", key);
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < 16 && i < h.size(); ++i)
    {
        const auto b = static_cast<unsigned char>(h[i]);
        out += hex[b >> 4];
        out += hex[b & 15];
    }
    return out;
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
    if (user == global_user)
        return m_dir + "/.global";
    // A name that could be a directory's is one, as it always was; any other is written %XX, which no such name holds,
    // so two users never share a directory.
    if (name_ok(user) && user.find('%') == std::string::npos)
        return m_dir + "/" + user;
    static constexpr char hex[] = "0123456789ABCDEF";
    std::string safe = "%";
    for (const char c : user)
    {
        const auto u = static_cast<unsigned char>(c);
        if (std::isalnum(u) || c == '-' || c == '_' || c == '@' || c == '+')
            safe += c;
        else
        {
            safe += '%';
            safe += hex[u >> 4];
            safe += hex[u & 15];
        }
    }
    return m_dir + "/" + (safe.size() > 200 ? "%h" + hash_of(user) : safe);
}

std::string sieve_store::path_of(const std::string& user, const std::string& name) const
{
    return user_dir(user) + "/" + name + ".sieve";
}

sieve_store::stamp sieve_store::stamp_of(const std::string& path)
{
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0)
        return {};
    return {static_cast<uint64_t>(st.st_ino), static_cast<uint64_t>(st.st_size),
            static_cast<int64_t>(st.st_mtim.tv_sec) * 1000000000 + st.st_mtim.tv_nsec,
            static_cast<int64_t>(st.st_ctim.tv_sec) * 1000000000 + st.st_ctim.tv_nsec};
}

sieve::loader sieve_store::loader_for(const std::string& user) const
{
    return [this, user](bool global, std::string_view name, std::string& text) {
        const std::string n(name);
        return name_ok(n) && socketley::read_file(path_of(global ? global_user : user, n), text);
    };
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
    if (!name_ok(name))
    {
        code = {};
        return false;
    }
    if (size > max_script)
    {
        code = "QUOTA/MAXSIZE";
        return false;
    }
    uint64_t used = 0;
    size_t n = 0;
    bool there = false;
    // Each script's size from its inode, not from reading it.
    for (const auto& entry : list(user))
    {
        const std::string& s = entry.first;
        if (s == name)
        {
            there = true;
            continue;
        }
        used += stamp_of(path_of(user, s)).size;
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
    if (!sieve::script::compile(text, why))
        return false;
    // The bound and the write under the user's lock, so two shards cannot pass it together.
    const user_lock lock(user_dir(user));
    if (!lock.held())
    {
        why = "the user's scripts could not be locked";
        return false;
    }
    if (!fits(user, name, text.size(), code))
    {
        why = "the script would pass what a user may keep";
        return false;
    }
    if (!write_whole(path_of(user, name), text))
    {
        why = "the script could not be written";
        return false;
    }
    return true;
}

bool sieve_store::remove(const std::string& user, const std::string& name, std::string& code, std::string& why)
{
    const user_lock lock(user_dir(user));
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
    sync_dir(user_dir(user));
    return true;
}

bool sieve_store::rename(const std::string& user, const std::string& from, const std::string& to, std::string& code,
                         std::string& why)
{
    const user_lock lock(user_dir(user));
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
    // The new name is linked first and named active, the old one taken away last, so the active script is there at
    // every moment between.
    if (::link(path_of(user, from).c_str(), path_of(user, to).c_str()) != 0)
    {
        code = errno == EEXIST ? "ALREADYEXISTS" : "";
        why = errno == EEXIST ? "there is a script " + to + " already" : "the script could not be renamed";
        return false;
    }
    if (active_name(user) == from && !write_whole(user_dir(user) + "/.active", to + "\n"))
    {
        ::unlink(path_of(user, to).c_str());
        why = "the active script could not be renamed";
        return false;
    }
    if (::unlink(path_of(user, from).c_str()) != 0) {}
    sync_dir(user_dir(user));
    return true;
}

bool sieve_store::activate(const std::string& user, const std::string& name, std::string& code, std::string& why)
{
    const user_lock lock(user_dir(user));
    if (name.empty())
    {
        ::unlink((user_dir(user) + "/.active").c_str());
        sync_dir(user_dir(user));
        return true;
    }
    std::string text;
    if (!name_ok(name) || !socketley::read_file(path_of(user, name), text))
    {
        code = "NONEXISTENT";
        why = "there is no script " + name;
        return false;
    }
    // A script that no longer compiles, with what it includes, would filter nothing: it is not made the active one.
    if (!sieve::script::compile(text, why, loader_for(user)))
        return false;
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
    const stamp am = stamp_of(marker);
    std::lock_guard<std::mutex> g(m_mu);
    compiled& c = m_cache[user];
    if (am.mtime_ns < 0)
    {
        c = {};
        return nullptr;
    }
    if (!(am == c.active_stamp))
    {
        c.active_stamp = am;
        c.name = active_name(user);
        c.files.clear();
    }
    return fresh(c, user, "the active Sieve script");
}

std::shared_ptr<const sieve::script> sieve_store::named(const std::string& user, const std::string& name)
{
    std::lock_guard<std::mutex> g(m_mu);
    // A bound on what a stranger's metadata could make this keep.
    if (m_named.size() > 4096)
        m_named.clear();
    compiled& c = m_named[user + '\n' + name];
    c.name = name;
    return fresh(c, user, "the imapsieve script");
}

std::shared_ptr<const sieve::script> sieve_store::fresh(compiled& c, const std::string& user, const char* what)
{
    // The script and what it includes are looked at; any of them changed, it is read and compiled again.
    const bool same = !c.files.empty() && std::all_of(c.files.begin(), c.files.end(), [](const auto& f) {
        return stamp_of(f.first) == f.second;
    });
    if (same)
        return c.script;
    c.files.clear();
    c.script.reset();
    if (!name_ok(c.name))
        return nullptr;
    const std::string path = path_of(user, c.name);
    c.files.emplace_back(path, stamp_of(path));
    std::string text, why;
    if (!socketley::read_file(path, text))
        return nullptr;
    // Each file the compile asks for is stamped before it is read, so a rewrite after the read is seen as a change.
    const sieve::loader load = loader_for(user);
    const sieve::loader stamping = [&](bool global, std::string_view name, std::string& body) {
        const std::string n(name);
        if (name_ok(n))
        {
            const std::string p = path_of(global ? global_user : user, n);
            c.files.emplace_back(p, stamp_of(p));
        }
        return load(global, name, body);
    };
    c.script = sieve::script::compile(text, why, stamping);
    if (!c.script)
    {
        LOG_WARN(("mail: " + std::string(what) + " " + c.name + " no longer compiles, and filters nothing: " + why)
                     .c_str());
        return nullptr;
    }
    return c.script;
}

sieve_store::memory& sieve_store::memory_of(const std::string& user, const char* kind)
{
    return m_memory[user + '\n' + kind];
}

bool sieve_store::recall(const std::string& user, const char* kind, const std::string& hash, int64_t now_s, bool& ok)
{
    memory& mem = memory_of(user, kind);
    const std::string path = user_dir(user) + "/." + kind;
    ok = true;
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
    {
        ok = errno == ENOENT;
        mem = {};
        return false;
    }
    struct stat st{};
    if (::fstat(fd, &st) != 0)
    {
        ::close(fd);
        ok = false;
        return false;
    }
    // A file folded by another shard is another inode, read from its start; otherwise only what was appended since.
    if (static_cast<uint64_t>(st.st_ino) != mem.ino || static_cast<uint64_t>(st.st_size) < mem.read)
        mem = {{}, static_cast<uint64_t>(st.st_ino), 0, 0};
    std::string tail(static_cast<size_t>(static_cast<uint64_t>(st.st_size) - mem.read), '\0');
    const ssize_t n = tail.empty() ? 0 : ::pread(fd, tail.data(), tail.size(), static_cast<off_t>(mem.read));
    ::close(fd);
    if (n < 0)
    {
        ok = false;
        return false;
    }
    tail.resize(static_cast<size_t>(n));
    const size_t whole = tail.rfind('\n');
    if (whole != std::string::npos)
    {
        mem.read += whole + 1;
        std::string_view rest(tail.data(), whole + 1);
        while (!rest.empty())
        {
            const size_t nl = rest.find('\n');
            const std::string_view line = rest.substr(0, nl);
            rest.remove_prefix(nl + 1);
            ++mem.lines;
            const size_t a = line.find(' ');
            if (a == std::string_view::npos)
                continue;
            int64_t until = 0;
            if (std::sscanf(std::string(line.substr(0, a)).c_str(), "%ld", &until) != 1)
                continue;
            // A line of the older vacation memory names its handle and sender, which is what its key is made of.
            std::string_view key = line.substr(a + 1);
            const size_t b = key.find(' ');
            const std::string h = b == std::string_view::npos ? std::string(key)
                                                               : hash_of(std::string(key.substr(0, b)) + '\n' +
                                                                         std::string(key.substr(b + 1)));
            int64_t& u = mem.until[h];
            u = std::max(u, until);
        }
    }
    const auto it = mem.until.find(hash);
    return it != mem.until.end() && it->second > now_s;
}

bool sieve_store::remember(const std::string& user, const char* kind, const std::string& hash, int64_t until,
                           int64_t now_s)
{
    memory& mem = memory_of(user, kind);
    const std::string path = user_dir(user) + "/." + kind;
    const std::string line = std::to_string(until) + " " + hash + "\n";
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    // An append is one write of a short line, which no other shard's append cuts into.
    const bool ok = fd >= 0 && socketley::write_all(fd, line.data(), line.size());
    if (fd >= 0)
        ::close(fd);
    if (!ok)
        return false;
    int64_t& u = mem.until[hash];
    u = std::max(u, until);
    // Folded once it holds twice what is live, or more than may be kept: the newest kept, the rest let go.
    std::erase_if(mem.until, [now_s](const auto& e) { return e.second <= now_s; });
    if (mem.lines + 1 > 2 * mem.until.size() + 1000 || mem.until.size() > max_memory)
    {
        std::vector<std::pair<int64_t, std::string>> live;
        for (const auto& [h, t] : mem.until)
            live.emplace_back(t, h);
        std::sort(live.begin(), live.end(), std::greater<>());
        if (live.size() > max_memory)
            live.resize(max_memory);
        std::string text;
        for (const auto& [t, h] : live)
            text += std::to_string(t) + " " + h + "\n";
        if (write_whole(path, text, false))
            mem = {};
        return true;
    }
    ++mem.lines;
    mem.read += line.size();
    return true;
}

bool sieve_store::answered(const std::string& user, const std::string& handle, const std::string& sender,
                           uint32_t seconds, int64_t now_s)
{
    std::string h = handle.empty() ? std::string("-") : handle;
    for (char& c : h)
        if (c == ' ' || c == '\n' || c == '\r')
            c = '_';
    const std::string key = hash_of(h + '\n' + sender);
    // Under the user's lock, so two shards given two messages of one sender answer one of them.
    const user_lock lock(user_dir(user));
    std::lock_guard<std::mutex> g(m_mu);
    bool ok = true;
    if (recall(user, "vacation", key, now_s, ok) || !ok || !lock.held())
        return true;
    return !remember(user, "vacation", key, now_s + seconds, now_s);
}

bool sieve_store::seen(const std::string& user, std::string_view key, int64_t now_s)
{
    std::lock_guard<std::mutex> g(m_mu);
    bool ok = true;
    return recall(user, "duplicate", hash_of(key), now_s, ok);
}

void sieve_store::keep_seen(const std::string& user, std::string_view key, uint32_t seconds, int64_t now_s)
{
    const user_lock lock(user_dir(user));
    std::lock_guard<std::mutex> g(m_mu);
    const std::string hash = hash_of(key);
    bool ok = true;
    // What other shards appended is read first, so remember() extends the cursor from the end of the file.
    recall(user, "duplicate", hash, now_s, ok);
    if (!ok || !lock.held())
        return;
    if (!remember(user, "duplicate", hash, now_s + seconds, now_s)) {}
}

}   // namespace socketley::mail
