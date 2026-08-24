#pragma once

// The AF_UNIX rules, stated once.
//
// Three decisions live here, because each used to have more than one home and
// this tree has counted what that costs (see CLAUDE-adjacent history in
// shared/: conn_reachability.h, http_framing.h).  Before this header the path
// rules were decided in three places (the flag parser, the server's setup
// re-check, the proxy's backend configuration), the sockaddr_un construction
// in two (the server's bind, the proxy's connect), and the listener mechanism
// existed only in the server while the cache and client had no AF_UNIX at all.
//
//   path_refusal()    — is this string allowed to name a socket node at all?
//   fill_addr()       — the one correct sockaddr_un, with the one correct length.
//   bind_listener()   — the stale-node probe, the bind, the 0600, the listen.
//
// THE CONNECT SIDE IS fill_addr() PLUS connect(2), AND IT IS DELIBERATELY IN
// THIS SAME HEADER rather than a second one.  What the two sides share is the
// load-bearing fact — how a path becomes an address and how many bytes of it
// the kernel is to read — and a connect header with its own copy of that is
// how the server and the proxy came to disagree about it in the first place.
// What the connect side does NOT get is any of the stale-node machinery below:
// a dialler that unlinked or probed would be taking decisions that belong to
// whoever owns the node.
//
// ─── THE ABSTRACT NAMESPACE, CONSIDERED AND REFUSED ─────────────────────────
//
// A sun_path beginning with '\0' names a socket in no filesystem: the whole
// stale-node problem below disappears, and cleanup is automatic on process
// exit.  It is refused anyway, by the absolute-path rule in path_refusal(),
// and the proxy's backend side already refused it for the same reason: an
// abstract name is bounded by nothing but the network namespace, so ANY uid
// in it may connect.  Everything this file does about access control — the
// 0600 chmod, the parent-directory escape hatch — is filesystem permissions,
// which an abstract socket does not have; replacing them would mean a
// per-accept SO_PEERCRED check that every runtime would have to remember to
// make.  The stale-node problem, meanwhile, is already solved once, below.
// Trading a solved problem for an unsolved one is not an improvement.

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

// Why `path` may not name a unix socket, or empty if it may.
//
// Every refusal here is a configuration-time one on purpose.  The kernel
// truncates a path of sizeof(sun_path) bytes or more without saying so, and a
// trimmed path names a DIFFERENT socket — very possibly a real one that
// something else is serving — so the earliest caller is the last point at
// which the operator can be told which socket they actually asked for.
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

// The address `path` names, and how many bytes of it the kernel is to read.
//
// The caller has already refused a path that would not fit (path_refusal), so
// this cannot truncate.  size() + 1 bytes, so the terminator goes with it:
// sun_path is a C string to the kernel, and copying the NUL is what makes this
// correct whether or not the caller's buffer arrived zeroed.
//
// offsetof rather than sizeof for the length: passing the whole structure
// works, but the kernel then compares the full sun_path against a bound
// socket's, and a length that stops at the terminator is what makes the
// address say exactly what was configured.
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
// ─── THE NODE THAT IS ALREADY THERE ─────────────────────────────────────────
//
// bind() on a path that exists fails EADDRINUSE whether or not anything is
// serving it, and a unix socket node outlives the process that made it: a
// daemon killed with SIGKILL, a machine that lost power, a container image
// with a socket committed into it all leave one behind.  Unlinking
// unconditionally would answer that — and would also let a second copy of a
// runtime take the path away from the first while it is serving traffic, with
// the first left holding a socket no client can reach and no error anywhere.
//
// So the node is asked whether anyone is home, by connecting to it.  A refusal
// means the node is stale and it is removed; a connection that succeeds means
// somebody is serving this path and this start is refused, which is the answer
// a second bind to a live TCP port would get.  There is a race in that — a
// server could bind between the probe and ours — and it is the same race
// `unlink` before `bind` has always had; the probe converts the common case
// (nobody there) from a failure into a start, and the dangerous case
// (somebody there) from a silent theft into a refusal.
//
// ─── WHO MAY CONNECT ────────────────────────────────────────────────────────
//
// The node is chmod'ed 0600 rather than left to the umask.  Connecting to a
// unix socket needs write permission on the node, so the umask normally
// decides who may — and a daemon running under `umask 0` publishes a listener
// anybody on the machine can talk to, which is the same defect this tree
// already has recorded against its 0666 control socket and its 0644 state
// files.  0600 is the conservative end of that: the sidecar case this flag
// exists for is a proxy and a backend under one daemon, which is one uid.
//
// NOT DONE, and worth saying rather than discovering: there is no flag to
// widen it.  A peer running as another user cannot connect, and the way round
// it today is a parent directory the operator owns and controls.
inline bind_result bind_listener(const std::string& path)
{
    bind_result r;

    struct sockaddr_un addr{};
    const socklen_t addr_len = fill_addr(path, addr);

    {
        // SOCK_NONBLOCK, and that matters rather than being tidy.  A blocking
        // connect() to a unix socket whose listener has a FULL backlog waits
        // for room -- and this runs on the daemon's event loop thread, the one
        // thread that serves every runtime in the process.  A busy server on
        // that path would have stalled the whole daemon for as long as it
        // stayed busy.  Non-blocking, the same case answers EAGAIN, which is
        // still "somebody is serving this" and is read as such.
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

// The configuration set a unix listener excludes, judged wherever a listening
// runtime's setup() runs — the chokepoint the path rules above name.  The
// members every listening runtime shares are here; the ones only some carry
// (--udp on a server, --cluster on a cache) stay next to the runtime that has
// them, with their own stated reason.
//
// Deliberately NOT --shards: that pair is refused by shards_config_refusal
// (runtime_definitions.h), which the create, edit, import and worker paths
// already all ask, and a second home for the same rule is how the two homes
// come to disagree.
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
