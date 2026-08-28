#pragma once

// The AF_UNIX rules, stated once; the connect side is fill_addr() plus
// connect(2) and is here so it cannot disagree about the address.
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <string>
#include <string_view>

namespace socketley::unix_sock
{

// Why `path` may not name a unix socket, or empty if it may; asked again from
// setup(), which is the one function every route to a socket passes through.
inline std::string path_refusal(std::string_view path)
{
    if (path.empty())
        return "no socket path was given";

    // Also what refuses the abstract namespace ("@name" or a leading NUL):
    // see the header comment for why that is a decision and not a gap.
    if (path[0] != '/')
        return "the socket path must be absolute (got \"" + std::string(path) + "\")";

    struct sockaddr_un probe{};
    if (path.size() >= sizeof(probe.sun_path))
        return "the socket path is " + std::to_string(path.size()) +
               " bytes and the kernel's limit is " +
               std::to_string(sizeof(probe.sun_path) - 1) +
               " -- it would be truncated to a different socket";

    // A NUL inside the path would end it early for the kernel and not for us,
    // which is the truncation above wearing a different hat.
    if (path.find('\0') != std::string_view::npos)
        return "the socket path contains a NUL byte";

    return {};
}

// The address `path` names, and how many bytes the kernel reads.  size() + 1 so
// the terminator goes with it, and offsetof rather than sizeof so the length
// stops there -- otherwise the kernel compares the whole sun_path.
inline socklen_t fill_addr(std::string_view path, struct sockaddr_un& out)
{
    out.sun_family = AF_UNIX;
    std::memcpy(out.sun_path, path.data(), path.size());
    out.sun_path[path.size()] = '\0';
    return static_cast<socklen_t>(offsetof(struct sockaddr_un, sun_path) +
                                  path.size() + 1);
}

// fd >= 0 is a listening socket the caller owns and must unlink on teardown;
// fd < 0 carries the reason for the caller to prefix and log.
struct bind_result
{
    int fd = -1;
    std::string error;
};

// A stale node is probed by connecting rather than unlinked blind, so a second
// copy cannot take the path from a live one.  chmod 0600, not the umask.
inline bind_result bind_listener(const std::string& path)
{
    bind_result r;

    struct sockaddr_un addr{};
    const socklen_t addr_len = fill_addr(path, addr);

    {
        // SOCK_NONBLOCK: a blocking connect to a full backlog waits for room,
        // on the loop thread.  EAGAIN is still "somebody is serving this".
        const int probe = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (probe >= 0)
        {
            const int rc = connect(probe, reinterpret_cast<const struct sockaddr*>(&addr),
                                   addr_len);
            const int err = errno;
            close(probe);   // never registered with any ring; a plain close is its own
            if (rc == 0 || err == EAGAIN || err == EWOULDBLOCK)
            {
                r.error = "--listen " + path +
                          " is already being served by something -- refusing rather "
                          "than taking the path away from it";
                return r;
            }
            // ECONNREFUSED means a leftover; unlink's own failure is left to
            // bind() so the operator gets one message, not two.
            if (err != ENOENT)
                if (unlink(path.c_str()) < 0) {}
        }
    }

    // Plain close(): none of these has been given to a ring yet.
    const int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
    {
        r.error = "--listen " + path + ": socket() failed: " + std::strerror(errno);
        return r;
    }

    // No SO_REUSE*, no TCP_*: the first mean nothing here, the second are TCP.
    if (bind(fd, reinterpret_cast<const struct sockaddr*>(&addr), addr_len) < 0)
    {
        r.error = "--listen " + path + " could not be bound: " + std::strerror(errno);
        close(fd);
        return r;
    }

    // Before listen(), so there is no instant at which the node both accepts
    // connections and carries whatever the umask made of it.
    if (chmod(path.c_str(), S_IRUSR | S_IWUSR) < 0)
    {
        r.error = "--listen " + path + " was bound but its mode could not be "
                  "set to 0600 -- refusing rather than serving on a node whose "
                  "permissions are whatever the umask left";
        close(fd);
        if (unlink(path.c_str()) < 0) {}
        return r;
    }

    if (listen(fd, 4096) < 0)
    {
        r.error = "--listen " + path + ": listen() failed: " + std::strerror(errno);
        close(fd);
        if (unlink(path.c_str()) < 0) {}
        return r;
    }

    r.fd = fd;
    return r;
}

// What a unix listener excludes, judged at every listening runtime's setup().
// Flags only some types carry (--udp, --cluster) stay with that runtime, and
// --shards is deliberately absent: shards_config_refusal owns that pair.
inline std::string listen_config_refusal(std::string_view listen_path,
                                         uint16_t port, bool tls)
{
    if (listen_path.empty())
        return {};

    if (port != 0)
        return "--listen and -p are two different listeners, and this "
               "runtime asks for both -- say which one it is";

    if (tls)
        return "--tls encrypts a listener against the network, and a "
               "unix socket is not on one -- the permissions on the socket "
               "node are what restrict it.  Refusing rather than spending a "
               "handshake on a peer that cannot be anywhere else";

    // The path rules, re-checked at setup because the flag parser is not on
    // the restore or import path.  sun_path truncates silently.
    if (std::string why = path_refusal(listen_path); !why.empty())
        return "--listen \"" + std::string(listen_path) + "\": " + why;

    return {};
}

} // namespace socketley::unix_sock
