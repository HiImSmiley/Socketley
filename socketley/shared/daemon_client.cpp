#include "daemon_client.h"
#include "paths.h"
#include <cerrno>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>

namespace socketley {

static std::string g_attached_name;

static constexpr std::string_view deleted_marker = " (deleted)";

bool split_deleted_suffix(std::string& path)
{
    if (path.size() <= deleted_marker.size() ||
        path.compare(path.size() - deleted_marker.size(),
                     deleted_marker.size(), deleted_marker) != 0)
        return false;

    path.resize(path.size() - deleted_marker.size());
    return true;
}

bool self_exe_identity(std::string& raw_path, uint64_t& dev, uint64_t& ino)
{
    char    buf[4096];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0)
        return false;
    buf[n] = '\0';

    struct stat st{};
    if (stat("/proc/self/exe", &st) != 0)
        return false;

    raw_path.assign(buf, static_cast<size_t>(n));
    dev = static_cast<uint64_t>(st.st_dev);
    ino = static_cast<uint64_t>(st.st_ino);
    return true;
}

daemon_identity daemon_probe(const char*   socket_path,
                             daemon_ident* out,
                             int           timeout_ms)
{
    // SOCK_CLOEXEC for the same reason as every other socket the CLI opens:
    // ensure_daemon() forks and execs a daemon, and the only descriptors that
    // exec is meant to receive are the three it puts /dev/null onto.
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return daemon_identity::absent;   // no probe possible; behave as before

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        // EACCES/EPERM is not "nothing is there".  The socket exists and this
        // uid has no write permission on it, which since the mode was tightened
        // is what a second user on one machine, or an operator who is not in
        // the `socketley` group, gets.  Reported as `absent` it became "failed
        // to start daemon" after the CLI forked a daemon that could not bind —
        // a message that names neither the cause nor the fix.
        const int err = errno;
        close(fd);
        if (err == EACCES || err == EPERM)
            return daemon_identity::forbidden;
        return daemon_identity::absent;
    }

    // Both directions.  A peer that accepts and then never reads would
    // otherwise block the write instead of the read, and the deadline has to
    // cover the whole exchange rather than half of it.
    struct timeval tv{ timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    static constexpr char probe[] = "ping\n";
    if (write(fd, probe, sizeof(probe) - 1) != static_cast<ssize_t>(sizeof(probe) - 1))
    {
        close(fd);
        return daemon_identity::mute;
    }

    // The reply frame is one exit-code byte, then the text, then a NUL.  Read
    // until the NUL rather than trusting one read() to hold the lot: the
    // identifying line is short enough that it always does in practice, but
    // "in practice" is the reasoning that put this defect here.
    //
    // Sized past PATH_MAX because the reply now ends in the daemon's executable
    // path.  The classification below does not depend on the frame fitting
    // anyway — see there — but a buffer that a legitimate path could overrun is
    // not a thing to leave standing in the function that decides whether to
    // trust the peer.
    char   buf[4160];
    size_t total = 0;
    bool   framed = false;
    while (total < sizeof(buf))
    {
        ssize_t n = read(fd, buf + total, sizeof(buf) - total);
        if (n <= 0)
            break;
        total += static_cast<size_t>(n);
        if (memchr(buf + 1, '\0', total - 1) != nullptr)
        {
            framed = true;
            break;
        }
    }
    close(fd);

    if (total == 0)
        return daemon_identity::mute;

    // The identification is the exit byte and the prefix, and nothing else.
    // Deliberately not gated on the frame being complete: a reply too long for
    // the buffer would otherwise fall through to `foreign` and the CLI would
    // refuse to talk to a daemon that had just named itself correctly.  A
    // truncated reply is still a daemon; it is only a daemon we know less
    // about, and the fields below are what get skipped.
    if (total >= 1 + daemon_ident_prefix.size() && buf[0] == 0 &&
        memcmp(buf + 1, daemon_ident_prefix.data(), daemon_ident_prefix.size()) == 0)
    {
        if (out && framed)
        {
            const char*  body     = buf + 1;
            const size_t body_len = static_cast<size_t>(
                static_cast<const char*>(memchr(buf + 1, '\0', total - 1)) - body);

            std::string_view rest(body + daemon_ident_prefix.size(),
                                  body_len - daemon_ident_prefix.size());
            if (!rest.empty() && rest.back() == '\n')
                rest.remove_suffix(1);

            auto take = [&rest]() -> std::string_view
            {
                const size_t sp = rest.find(' ');
                std::string_view tok = rest.substr(0, sp);
                rest = (sp == std::string_view::npos) ? std::string_view()
                                                      : rest.substr(sp + 1);
                return tok;
            };

            out->version = std::string(take());
            take();                                   // the pid; nothing reads it
            const std::string_view devino = take();

            // Everything left is the path, verbatim rather than tokenised: an
            // executable may live somewhere with a space in the name, and it is
            // last in the reply for exactly that reason.
            const std::string_view exe = rest;

            const size_t colon = devino.find(':');
            uint64_t     d = 0, i = 0;
            if (!exe.empty() && colon != std::string_view::npos &&
                std::from_chars(devino.data(), devino.data() + colon, d).ec == std::errc() &&
                std::from_chars(devino.data() + colon + 1,
                                devino.data() + devino.size(), i).ec == std::errc())
            {
                out->exe_path = std::string(exe);
                out->exe_deleted = split_deleted_suffix(out->exe_path);
                out->exe_dev = d;
                out->exe_ino = i;
                out->has_exe = true;
            }
        }
        return daemon_identity::daemon;
    }

    // A daemon built before `ping` existed routes it to the `default:` arm of
    // process_command(), which writes its complaint to the daemon's own stdout
    // and leaves the reply body empty — so the frame on the wire is exactly
    // {1, 0}.  Measured against the build this check was added to.  Nothing
    // about it depends on the wording of a message, which is what makes it a
    // safe thing for a compatibility shim to rest on; when no such daemon can
    // still be running, the arm can go.
    if (total == 2 && buf[0] == 1 && buf[1] == 0)
        return daemon_identity::predates_ping;

    return daemon_identity::foreign;
}

// Send one command to the daemon, return daemon exit code (or -1 on IPC error).
static int daemon_ipc(const char* cmd)
{
    auto paths = socketley_paths::resolve();
    std::string sock_path = paths.socket_path.string();

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path.c_str(), sizeof(addr.sun_path) - 1);

    if (connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        close(fd);
        return -1;
    }

    std::string msg = std::string(cmd) + "\n";
    if (write(fd, msg.data(), msg.size()) < 0)
    {
        close(fd);
        return -1;
    }

    char buf[512];
    int  ec = -1;
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n >= 1)
        ec = static_cast<unsigned char>(buf[0]);

    close(fd);
    return ec;
}

bool daemon_attach(std::string_view name, std::string_view type, uint16_t port)
{
    // The same question the CLI asks, for the same reason.  An attach names this
    // process, its type, its port and its pid — everything an operator's
    // inventory is built from — and it was written to whatever happened to be
    // bound to the socket path.  A managed program has no operator watching its
    // startup, so an attach delivered to a stranger is a program that believes
    // it is registered and is not.
    {
        auto paths = socketley_paths::resolve();
        const daemon_identity who = daemon_probe(paths.socket_path.string().c_str());
        if (who != daemon_identity::daemon && who != daemon_identity::predates_ping)
            return false;
    }

    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "attach %.*s %.*s %u --pid %d",
             static_cast<int>(type.size()), type.data(),
             static_cast<int>(name.size()), name.data(),
             static_cast<unsigned>(port),
             static_cast<int>(getpid()));

    int rc = daemon_ipc(cmd);
    if (rc == 0)
    {
        g_attached_name = std::string(name);
        atexit([]{ daemon_detach(); });
        return true;
    }
    return false;
}

void daemon_detach()
{
    if (g_attached_name.empty()) return;
    std::string cmd = "remove " + g_attached_name;
    daemon_ipc(cmd.c_str());
    g_attached_name.clear();
}

} // namespace socketley
