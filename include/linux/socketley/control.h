// ═══════════════════════════════════════════════════════════════════
//  socketley/control.h — Header-only daemon client (Tier 1)
//
//  Fully self-contained. No io_uring, no OpenSSL, no Lua.
//  Just #include <socketley/control.h> and compile with -std=c++17.
//
//  All functions are inline — no implementation macro needed.
//
//  Example:
//    #include <socketley/control.h>
//    int main() {
//        auto r = socketley::ctl::create("server", "myapp", "-p 9000 -s");
//        if (r.exit_code != 0) return 1;
//        socketley::ctl::stop("myapp");
//    }
//    // g++ -std=c++17 myapp.cpp -o myapp
// ═══════════════════════════════════════════════════════════════════
#pragma once

#ifndef __linux__
#  error "Socketley requires Linux"
#endif

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <unistd.h>

namespace socketley {

// ── Result type ─────────────────────────────────────────────────────

struct result
{
    int exit_code;     // 0 = success, 1 = bad input, 2 = fatal, -1 = connect failed
    std::string data;  // response payload (may be empty on success)

    // The question every caller asks first, spelled once.  Not operator bool,
    // deliberately: `if (r)` reads as "got a response", and a result whose
    // exit_code is 1 IS a response — the daemon's refusal, with the reason in
    // `data`.  ok() asks the narrower question.
    bool ok() const { return exit_code == 0; }
};

// ── Socket path resolution ──────────────────────────────────────────

namespace detail {

inline std::string resolve_socket_path()
{
    // 1. SOCKETLEY_SOCKET env var
    const char* env = std::getenv("SOCKETLEY_SOCKET");
    if (env && env[0])
        return env;

    // 2. System install: /run/socketley/socketley.sock (if accessible)
    if (access("/run/socketley/socketley.sock", R_OK | W_OK) == 0)
        return "/run/socketley/socketley.sock";

    // 3. Dev mode fallback
    return "/tmp/socketley.sock";
}

// Low-level IPC: connect, send command\n, read response (exit_code byte + data + NUL)
inline result ipc_send(const std::string& socket_path, std::string_view command)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return {-1, "socket() failed"};

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);

    if (connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        close(fd);
        return {-1, "failed to connect to daemon"};
    }

    struct timeval tv{5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Send: command + newline
    std::string msg(command);
    msg += '\n';

    {
        size_t total = 0;
        while (total < msg.size())
        {
            ssize_t w = write(fd, msg.data() + total, msg.size() - total);
            if (w < 0)
            {
                close(fd);
                return {-1, "write() failed"};
            }
            total += static_cast<size_t>(w);
        }
    }

    // Read response: first byte = exit code, then data until NUL terminator
    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n < 1)
    {
        close(fd);
        return {-1, "read() failed"};
    }

    int exit_code = static_cast<unsigned char>(buf[0]);
    std::string data;

    // Check if NUL terminator is in first read
    auto* nul = static_cast<char*>(std::memchr(buf + 1, '\0', static_cast<size_t>(n - 1)));
    if (nul)
    {
        data.append(buf + 1, static_cast<size_t>(nul - buf - 1));
        close(fd);
        return {exit_code, std::move(data)};
    }

    data.append(buf + 1, static_cast<size_t>(n - 1));

    // Continue reading until NUL terminator
    for (;;)
    {
        n = read(fd, buf, sizeof(buf));
        if (n <= 0)
            break;

        nul = static_cast<char*>(std::memchr(buf, '\0', static_cast<size_t>(n)));
        if (nul)
        {
            data.append(buf, static_cast<size_t>(nul - buf));
            break;
        }

        data.append(buf, static_cast<size_t>(n));
    }

    close(fd);
    return {exit_code, std::move(data)};
}

} // namespace detail

// ── Public API ──────────────────────────────────────────────────────

namespace ctl {

// Send any raw command string to the daemon.
inline result command(const std::string& cmd)
{
    return detail::ipc_send(detail::resolve_socket_path(), cmd);
}

// Send a raw command to a daemon at a specific socket path.
inline result command(const std::string& socket_path, const std::string& cmd)
{
    return detail::ipc_send(socket_path, cmd);
}

// ── Runtime management ──────────────────────────────────────────────

inline result create(const std::string& type, const std::string& name,
                     const std::string& flags = "")
{
    std::string cmd = "create " + type + " " + name;
    if (!flags.empty())
        cmd += " " + flags;
    return command(cmd);
}

inline result start(const std::string& name)
{
    return command("start " + name);
}

inline result stop(const std::string& name)
{
    return command("stop " + name);
}

inline result remove(const std::string& name)
{
    return command("remove " + name);
}

inline result send(const std::string& name, const std::string& message)
{
    return command("send " + name + " " + message);
}

inline result ls()
{
    return command("ls");
}

inline result ps()
{
    return command("ps");
}

inline result stats(const std::string& name)
{
    return command("stats " + name);
}

inline result show(const std::string& name)
{
    return command("show " + name);
}

// Stop, then start.  Two IPC round trips, because that is what a restart is:
// the daemon has no `restart` command — the CLI's is the same two commands —
// and this function used to send one anyway, so every call was answered
// "unknown command: restart" from the day it was written.  The stop's answer
// is read before the start goes out, exactly as the CLI does it: a restart of
// a name the daemon does not hold reports the stop's refusal, not a second
// refusal from a start that was never going to succeed.
inline result restart(const std::string& name)
{
    result r = command("stop " + name);
    if (r.exit_code != 0)
        return r;
    return command("start " + name);
}

inline result reload(const std::string& name)
{
    return command("reload " + name);
}

inline result reload_lua(const std::string& name)
{
    return command("reload-lua " + name);
}

inline result edit(const std::string& name, const std::string& flags)
{
    return command("edit " + name + " " + flags);
}

inline result owner(const std::string& name)
{
    return command("owner " + name);
}

// "who is serving this socket" — version, pid, and the exact executable path,
// read fresh from /proc on the daemon side.  The reply is
// `socketley-daemon <version> <pid> <dev:inode> <path>`, and the path goes
// last because a path may contain spaces.
inline result ping()
{
    return command("ping");
}

// The daemon's version string, extracted from ping().  There is no `version`
// IPC command and never was — this function used to send one and was answered
// "unknown command: version" against every daemon ever shipped.  The CLI's
// `socketley version` prints the CLI's own compile-time version; a Tier-1
// client has no compile-time version to print, so the daemon's answer is the
// only honest one available here.
inline result version()
{
    result r = ping();
    if (r.exit_code != 0)
        return r;

    // "socketley-daemon 1.1.0 <pid> <dev:inode> <path>" -> "1.1.0"
    constexpr std::string_view prefix = "socketley-daemon ";
    if (r.data.rfind(prefix, 0) != 0)
        return {2, "unrecognised ping reply: " + r.data};
    const size_t start = prefix.size();
    const size_t end   = r.data.find(' ', start);
    r.data = r.data.substr(start, end == std::string::npos ? end : end - start);
    return r;
}

inline result add(const std::string& path, const std::string& flags = "")
{
    std::string cmd = "add " + path;
    if (!flags.empty())
        cmd += " " + flags;
    return command(cmd);
}

// Create a runtime from a JSON document — the inverse of show(), whose output
// is accepted here unchanged.  Not named `import`: that is a context-sensitive
// keyword in C++20 modules, and a header cannot know it will never be included
// in one.
inline result import_runtime(const std::string& name, const std::string& json)
{
    return command("import " + name + " " + json);
}

inline result daemon_name()
{
    return command("daemon-name");
}

inline result cluster_dir()
{
    return command("cluster-dir");
}

// ── Cluster ──────────────────────────────────────────────────────────
//
// A daemon in cluster mode publishes itself into the cluster directory as
// `<name>.json` — host, heartbeat, and its runtime table — and discovers its
// peers by reading the same directory.  The roster is files, not IPC: there
// are no `cluster ls`-style daemon commands, and the functions below used to
// send them anyway, so every call was answered "unknown command: cluster"
// against every daemon ever shipped.  What the daemon does answer over IPC is
// cluster_status(); the rest reads the directory, exactly as the CLI does.
//
// A peer whose heartbeat (unix seconds, `"heartbeat":` in its file) is more
// than 10 seconds old is stale — cluster_ls() lists it anyway, because a name
// that has stopped beating is an answer too, and the caller has the timestamp.

namespace detail {

// One line of "key:value" out of a cluster-status reply.
inline std::string status_field(std::string_view status, std::string_view key)
{
    std::string needle(key);
    needle += ':';
    size_t pos = 0;
    while (pos < status.size())
    {
        const size_t eol = status.find('\n', pos);
        std::string_view line = status.substr(
            pos, eol == std::string_view::npos ? std::string_view::npos : eol - pos);
        if (line.size() >= needle.size() && line.substr(0, needle.size()) == needle)
            return std::string(line.substr(needle.size()));
        if (eol == std::string_view::npos)
            break;
        pos = eol + 1;
    }
    return {};
}

} // namespace detail

// `cluster:on|off`, `name:`, `dir:`, `host:`, and — when the daemon asked for
// cluster mode and was refused, e.g. its name was already taken — `error:`.
inline result cluster_status()
{
    return command("cluster-status");
}

// The daemons publishing into this cluster's directory, one name per line,
// stale ones included.  {1, reason} when this daemon is not in cluster mode.
inline result cluster_ls()
{
    result st = cluster_status();
    if (st.exit_code != 0)
        return st;
    if (detail::status_field(st.data, "cluster") != "on")
    {
        std::string err = detail::status_field(st.data, "error");
        return {1, err.empty()
            ? std::string("daemon is not in cluster mode (start it with "
                          "--name <n> --cluster <dir>)")
            : "cluster mode is off: " + err};
    }

    const std::string dir = detail::status_field(st.data, "dir");
    DIR* d = opendir(dir.c_str());
    if (!d)
        return {2, "cannot read cluster directory " + dir};

    std::string names;
    while (struct dirent* e = readdir(d))
    {
        std::string_view f(e->d_name);
        // The ".json" test also keeps half-written files out: publish() writes
        // "<name>.json.tmp" and renames it into place.
        if (f.size() < 6 || f.substr(f.size() - 5) != ".json")
            continue;
        if (!names.empty())
            names += '\n';
        names.append(f.substr(0, f.size() - 5));
    }
    closedir(d);
    return {0, std::move(names)};
}

// The raw published JSON for one daemon: daemon, host, heartbeat, pid, and a
// `runtimes` array of {name, type, group, port, state, connections}.  Returned
// unparsed, deliberately: the format belongs to the daemon's publisher, and a
// second parser in this header is a second thing that drifts.
inline result cluster_show(const std::string& name)
{
    result st = cluster_status();
    if (st.exit_code != 0)
        return st;
    if (detail::status_field(st.data, "cluster") != "on")
        return {1, "daemon is not in cluster mode (start it with "
                   "--name <n> --cluster <dir>)"};

    const std::string dir = detail::status_field(st.data, "dir");
    std::ifstream f(dir + "/" + name + ".json");
    if (!f.is_open())
        return {1, "no daemon named " + name + " publishes into " + dir};

    std::ostringstream ss;
    ss << f.rdbuf();
    return {0, ss.str()};
}

// The three below are CLI renderings over the same files — a cross-daemon
// runtime table, a group filter, a live-updating terminal view.  A library
// has no terminal to render into, so they refuse with the recipe instead of
// asking the daemon a question it has never answered.

inline result cluster_ps()
{
    return {1, "cluster ps is a CLI rendering: read cluster_ls() and each "
               "peer's cluster_show(name), and aggregate the `runtimes` "
               "arrays -- every field the table shows is in the JSON"};
}

inline result cluster_group(const std::string& group)
{
    return {1, "cluster group is a CLI rendering: read each peer's "
               "cluster_show(name) and filter its `runtimes` array by "
               "\"group\":\"" + group + "\""};
}

inline result cluster_stats(const std::string& name)
{
    return {1, "cluster stats is a CLI rendering: cluster_show(\"" + name +
               "\") carries the published figures, and stats(<runtime>) asks "
               "a local runtime directly"};
}

inline result cluster_watch()
{
    return {1, "cluster watch is a terminal view: poll cluster_ls()/"
               "cluster_show() yourself -- peers republish every few seconds "
               "and a heartbeat more than 10s old is stale"};
}

inline result dashboard()
{
    return command("dashboard");
}

// ── Cache: strings ──────────────────────────────────────────────────

inline result cache_get(const std::string& cache_name, const std::string& key)
{
    return command("action " + cache_name + " get " + key);
}

inline result cache_set(const std::string& cache_name, const std::string& key,
                        const std::string& value)
{
    return command("action " + cache_name + " set " + key + " " + value);
}

inline result cache_del(const std::string& cache_name, const std::string& key)
{
    return command("action " + cache_name + " del " + key);
}

inline result cache_exists(const std::string& cache_name, const std::string& key)
{
    return command("action " + cache_name + " exists " + key);
}

// ── Cache: lists ────────────────────────────────────────────────────

inline result cache_lpush(const std::string& cache_name, const std::string& key,
                          const std::string& value)
{
    return command("action " + cache_name + " lpush " + key + " " + value);
}

inline result cache_rpush(const std::string& cache_name, const std::string& key,
                          const std::string& value)
{
    return command("action " + cache_name + " rpush " + key + " " + value);
}

inline result cache_lpop(const std::string& cache_name, const std::string& key)
{
    return command("action " + cache_name + " lpop " + key);
}

inline result cache_rpop(const std::string& cache_name, const std::string& key)
{
    return command("action " + cache_name + " rpop " + key);
}

inline result cache_llen(const std::string& cache_name, const std::string& key)
{
    return command("action " + cache_name + " llen " + key);
}

// ── Cache: sets ─────────────────────────────────────────────────────

inline result cache_sadd(const std::string& cache_name, const std::string& key,
                         const std::string& member)
{
    return command("action " + cache_name + " sadd " + key + " " + member);
}

inline result cache_srem(const std::string& cache_name, const std::string& key,
                         const std::string& member)
{
    return command("action " + cache_name + " srem " + key + " " + member);
}

inline result cache_sismember(const std::string& cache_name, const std::string& key,
                              const std::string& member)
{
    return command("action " + cache_name + " sismember " + key + " " + member);
}

inline result cache_scard(const std::string& cache_name, const std::string& key)
{
    return command("action " + cache_name + " scard " + key);
}

// ── Cache: hashes ───────────────────────────────────────────────────

inline result cache_hset(const std::string& cache_name, const std::string& key,
                         const std::string& field, const std::string& value)
{
    return command("action " + cache_name + " hset " + key + " " + field + " " + value);
}

inline result cache_hget(const std::string& cache_name, const std::string& key,
                         const std::string& field)
{
    return command("action " + cache_name + " hget " + key + " " + field);
}

inline result cache_hdel(const std::string& cache_name, const std::string& key,
                         const std::string& field)
{
    return command("action " + cache_name + " hdel " + key + " " + field);
}

inline result cache_hlen(const std::string& cache_name, const std::string& key)
{
    return command("action " + cache_name + " hlen " + key);
}

// ── Cache: TTL ──────────────────────────────────────────────────────

inline result cache_expire(const std::string& cache_name, const std::string& key,
                           int seconds)
{
    return command("action " + cache_name + " expire " + key + " " + std::to_string(seconds));
}

inline result cache_ttl(const std::string& cache_name, const std::string& key)
{
    return command("action " + cache_name + " ttl " + key);
}

inline result cache_persist(const std::string& cache_name, const std::string& key)
{
    return command("action " + cache_name + " persist " + key);
}

// ── Cache: pub/sub ──────────────────────────────────────────────────

inline result cache_publish(const std::string& cache_name, const std::string& channel,
                            const std::string& message)
{
    return command("action " + cache_name + " publish " + channel + " " + message);
}

// ── Cache: string arithmetic ────────────────────────────────────────

inline result cache_incr(const std::string& cache_name, const std::string& key)
{
    return command("action " + cache_name + " incr " + key);
}

inline result cache_decr(const std::string& cache_name, const std::string& key)
{
    return command("action " + cache_name + " decr " + key);
}

inline result cache_incrby(const std::string& cache_name, const std::string& key, int delta)
{
    return command("action " + cache_name + " incrby " + key + " " + std::to_string(delta));
}

inline result cache_decrby(const std::string& cache_name, const std::string& key, int delta)
{
    return command("action " + cache_name + " decrby " + key + " " + std::to_string(delta));
}

inline result cache_append(const std::string& cache_name, const std::string& key,
                           const std::string& value)
{
    return command("action " + cache_name + " append " + key + " " + value);
}

// ── Cache: list range/index ─────────────────────────────────────────

inline result cache_lrange(const std::string& cache_name, const std::string& key,
                           int start, int stop)
{
    return command("action " + cache_name + " lrange " + key + " " +
                   std::to_string(start) + " " + std::to_string(stop));
}

inline result cache_lindex(const std::string& cache_name, const std::string& key, int index)
{
    return command("action " + cache_name + " lindex " + key + " " + std::to_string(index));
}

// ── Cache: set enumeration ──────────────────────────────────────────

inline result cache_smembers(const std::string& cache_name, const std::string& key)
{
    return command("action " + cache_name + " smembers " + key);
}

// ── Cache: hash enumeration ─────────────────────────────────────────

inline result cache_hgetall(const std::string& cache_name, const std::string& key)
{
    return command("action " + cache_name + " hgetall " + key);
}

// ── Cache: multi-key ────────────────────────────────────────────────

inline result cache_keys(const std::string& cache_name, const std::string& pattern = "*")
{
    return command("action " + cache_name + " keys " + pattern);
}

inline result cache_mget(const std::string& cache_name,
                         const std::vector<std::string>& keys)
{
    if (keys.empty())
        return {1, "mget needs at least one key"};
    std::string cmd = "action " + cache_name + " mget";
    for (const auto& k : keys)
    {
        cmd += ' ';
        cmd += k;
    }
    return command(cmd);
}

inline result cache_mset(const std::string& cache_name,
                         const std::vector<std::pair<std::string, std::string>>& kvs)
{
    if (kvs.empty())
        return {1, "mset needs at least one key/value pair"};
    std::string cmd = "action " + cache_name + " mset";
    for (const auto& [k, v] : kvs)
    {
        cmd += ' ';
        cmd += k;
        cmd += ' ';
        cmd += v;
    }
    return command(cmd);
}

// ── Cache: admin ────────────────────────────────────────────────────

inline result cache_size(const std::string& cache_name)
{
    return command("action " + cache_name + " size");
}

inline result cache_memory(const std::string& cache_name)
{
    return command("action " + cache_name + " memory");
}

inline result cache_flush(const std::string& cache_name,
                          const std::string& path = "")
{
    std::string cmd = "action " + cache_name + " flush";
    if (!path.empty())
        cmd += " " + path;
    return command(cmd);
}

inline result cache_load(const std::string& cache_name,
                         const std::string& path = "")
{
    std::string cmd = "action " + cache_name + " load";
    if (!path.empty())
        cmd += " " + path;
    return command(cmd);
}

} // namespace ctl
} // namespace socketley
