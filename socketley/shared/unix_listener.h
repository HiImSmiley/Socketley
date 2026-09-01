#pragma once

// The AF_UNIX rules, stated once; the connect side is fill_addr() plus
// connect(2) and is here so it cannot disagree about the address.
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>

#include "runtime_definitions.h"

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

// Where a runtime's companion node goes: beside the daemon's own socket rather
// than in the state directory, whose name already spells the socket path out
// and leaves ~11 bytes of the kernel's 108.  One rule, called by the daemon to
// publish it and by the worker to bind it, so the two cannot disagree about
// which file they mean.  Empty means this runtime gets none.
inline std::string companion_path(std::string_view daemon_socket,
                                  std::string_view runtime_name)
{
    if (daemon_socket.empty() || runtime_name.empty())
        return {};

    // A name is a file name here, so anything that could climb out of the
    // directory disqualifies it rather than being escaped.
    if (runtime_name.find('/') != std::string_view::npos ||
        runtime_name.find("..") != std::string_view::npos)
        return {};

    if (daemon_socket.find('/') == std::string_view::npos)
        return {};

    // Named after the daemon's own socket rather than put beside it: the
    // default socket is /tmp/socketley.sock, and a sibling directory called
    // "rt" would be a generic name in a namespace every user on the machine
    // shares.  This spelling is socketley's and it is per-daemon, so two
    // daemons never reach for one directory and no other program will.
    std::string p(daemon_socket);
    p += ".rt/";
    p += runtime_name;
    p += ".sock";

    // Judged by the same rule every other path is: too long is not a warning
    // here, it is a different socket.
    return path_refusal(p).empty() ? p : std::string{};
}

// The directory companion nodes go in, created if it is absent and CHECKED if
// it is not: mkdir answering EEXIST says a directory is there and nothing at
// all about whose it is.  A directory somebody else owns, or one anybody can
// write to, is where a stranger holds a live node at a path this daemon is
// about to publish -- and a live node is one bind_listener refuses to take,
// which leaves the path published and served by them.
//
// False means no companion nodes anywhere, which is the state every build
// before this one was in.
inline bool secure_node_dir(const std::string& dir)
{
    if (::mkdir(dir.c_str(), 0700) < 0 && errno != EEXIST)
        return false;

    // lstat and not stat: a symlink here would point the check at one
    // directory and the bind at another.
    struct stat st{};
    if (::lstat(dir.c_str(), &st) < 0)
        return false;

    return S_ISDIR(st.st_mode)
        && st.st_uid == ::geteuid()
        && (st.st_mode & (S_IRWXG | S_IRWXO)) == 0;
}

// The directory `path` belongs in, or empty.
inline std::string node_dir_of(std::string_view path)
{
    const size_t slash = path.rfind('/');
    return slash == std::string_view::npos ? std::string{}
                                           : std::string(path.substr(0, slash));
}

// Whether this runtime gets a node beside its port.  Asked by the daemon to
// decide whether to publish one and by the runtime to decide whether to bind
// one, in one function because a daemon that publishes a node nothing bound
// sends every caller to a path that is not there.
inline bool wants_companion(runtime_type type, uint16_t port,
                            std::string_view listen_path, bool tls, bool udp)
{
    // Only a type that actually BINDS one.  The daemon publishes what this
    // says and a runtime binds what this says, so a type listed here and not
    // wired to a listener is a path published into thin air -- which a proxy
    // then dials instead of the port that works.  Measured as exactly that:
    // a cache backend, a node nobody bound, and every request unanswered.
    if (type != runtime_server)
        return false;

    // The measurement control, so a node and a port differ in the route alone
    // rather than in the build -- the same switch the shard mesh and the peer
    // links have.  Read in both processes, which agree because a worker
    // inherits the daemon's environment.
    static const bool disabled = []
    {
        const char* off = ::getenv("SOCKETLEY_NO_COMPANION");
        return off && *off && *off != '0';
    }();
    if (disabled)
        return false;

    // A port to be beside; a runtime already on a node has nothing to add; no
    // TLS, since a cleartext node would undo what the port was configured to
    // give; and not UDP, whose port carries datagrams and whose runtime has no
    // accept path for a stream node to hand a connection to.
    return port != 0 && listen_path.empty() && !tls && !udp;
}

// The address `path` names, size() + 1 so the terminator goes with it and
// offsetof rather than sizeof so the kernel does not compare the whole
// sun_path.
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
// copy cannot take the path from a live one.
// `what` names the thing being bound in every message, because the same code
// binds what an operator asked for with --listen and what the daemon puts
// beside a port, and an error naming the wrong one sends the reader to the
// wrong place.
inline bind_result bind_listener(const std::string& path,
                                 std::string_view what = "--listen")
{
    bind_result r;
    const std::string tag = std::string(what) + " " + path;

    struct sockaddr_un addr{};
    const socklen_t addr_len = fill_addr(path, addr);

    {
        // SOCK_NONBLOCK, because a blocking connect to a full backlog waits
        // for room on the loop thread.
        const int probe = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (probe >= 0)
        {
            const int rc = connect(probe, reinterpret_cast<const struct sockaddr*>(&addr),
                                   addr_len);
            const int err = errno;
            close(probe);   // never registered with any ring; a plain close is its own
            if (rc == 0 || err == EAGAIN || err == EWOULDBLOCK)
            {
                r.error = tag +
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
        r.error = tag + ": socket() failed: " + std::strerror(errno);
        return r;
    }

    // No SO_REUSE*, no TCP_*: the first mean nothing here, the second are TCP.
    if (bind(fd, reinterpret_cast<const struct sockaddr*>(&addr), addr_len) < 0)
    {
        r.error = tag + " could not be bound: " + std::strerror(errno);
        close(fd);
        return r;
    }

    // Before listen(), so there is no instant at which the node both accepts
    // connections and carries whatever the umask made of it.
    if (chmod(path.c_str(), S_IRUSR | S_IWUSR) < 0)
    {
        r.error = tag + " was bound but its mode could not be "
                  "set to 0600 -- refusing rather than serving on a node whose "
                  "permissions are whatever the umask left";
        close(fd);
        if (unlink(path.c_str()) < 0) {}
        return r;
    }

    if (listen(fd, 4096) < 0)
    {
        r.error = tag + ": listen() failed: " + std::strerror(errno);
        close(fd);
        if (unlink(path.c_str()) < 0) {}
        return r;
    }

    r.fd = fd;
    return r;
}

// What a unix listener excludes, judged at every listening runtime's setup(),
// without --shards: shards_config_refusal owns that pair.
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
    // the restore or import path.
    if (std::string why = path_refusal(listen_path); !why.empty())
        return "--listen \"" + std::string(listen_path) + "\": " + why;

    return {};
}

} // namespace socketley::unix_sock
