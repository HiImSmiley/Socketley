#pragma once

// The AF_UNIX rules, stated once: path_refusal(), fill_addr(), bind_listener().
//
// The connect side is fill_addr() plus connect(2) and is in this same header,
// because what the two sides share is how a path becomes an address and how
// many bytes of it the kernel reads -- a second copy is how the server and the
// proxy came to disagree.  A dialler gets none of the stale-node machinery.
//
// The abstract namespace is refused by the absolute-path rule: it is bounded by
// the network namespace, so any uid in it may connect, and the 0600 chmod this
// file relies on does not exist there.
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

// Why `path` may not name a unix socket, or empty if it may.  Configuration
// time on purpose: the kernel truncates an over-long sun_path silently, and a
// trimmed path names a different socket that something else may be serving.
//
// Asked from the flag parser AND from every runtime's setup(), and the second
// asking is not redundancy: setup() is the one function every route to a
// socket passes through — create, the daemon's restore of a persisted runtime,
// a worker rebuilding from its config frame, `import`, and a restart after
// `edit` — and the flag parser is on exactly one of those routes.
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

// What bind_listener has to say for itself.  fd >= 0 is a listening socket the
// caller now owns (and must remember it bound `path`, so its teardown removes
// exactly that node); fd < 0 comes with the reason, which the caller prefixes
// with its runtime type and logs — the shared code does not know who it is
// speaking for.
struct bind_result
{
    int fd = -1;
    std::string error;
};

// The AF_UNIX listener, for `--listen unix:/path/to.sock`.
//
// A node outlives the process that made it, so bind() fails EADDRINUSE whether
// or not anyone is serving.  Unlinking unconditionally would also let a second
// copy take the path from a live one, so the node is probed by connecting: a
// refusal means stale and it is removed, a success means this start is refused.
//
// chmod 0600 rather than the umask, because connecting needs write permission
// on the node and `umask 0` would otherwise publish it to the whole machine.
// There is no flag to widen it; use a parent directory the operator controls.
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
            // ENOENT is nothing to remove; anything else -- ECONNREFUSED above
            // all, which is what a node with nobody behind it answers -- is a
            // leftover.  unlink's own failure is left to bind() to report, which
            // says which path and why in one message rather than two.
            if (err != ENOENT)
                if (unlink(path.c_str()) < 0) {}
        }
    }

    // Plain close() on every failure path below: none of these descriptors has
    // been given to a ring yet, and handing a ring a close for something it
    // does not know about is how a teardown starts owing a completion nobody
    // will deliver.  The caller tracks the fd it is returned.
    const int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
    {
        r.error = "--listen " + path + ": socket() failed: " + std::strerror(errno);
        return r;
    }

    // Deliberately no SO_REUSEADDR, no SO_REUSEPORT, no TCP_NODELAY and no
    // TCP_DEFER_ACCEPT.  The first two mean nothing for a path the bind below
    // has just made exclusive, and the last two are TCP-level options that
    // would fail on this socket and buy nothing if they did not.
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
