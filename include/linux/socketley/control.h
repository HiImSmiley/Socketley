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
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace socketley {

// ── Result type ─────────────────────────────────────────────────────

struct result
{
    int exit_code;     // 0 = success, 1 = bad input, 2 = fatal, -1 = connect failed
    std::string data;  // response payload (may be empty on success)
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

    // Send: command + newline
    std::string msg(command);
    msg += '\n';

    ssize_t written = write(fd, msg.data(), msg.size());
    if (written < 0)
    {
        close(fd);
        return {-1, "write() failed"};
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

// ── Cache operations ────────────────────────────────────────────────

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

inline result cache_flush(const std::string& cache_name,
                          const std::string& path = "")
{
    std::string cmd = "action " + cache_name + " flush";
    if (!path.empty())
        cmd += " " + path;
    return command(cmd);
}

} // namespace ctl
} // namespace socketley
