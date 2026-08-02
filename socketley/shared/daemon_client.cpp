#include "daemon_client.h"
#include "paths.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

namespace socketley {

static std::string g_attached_name;

daemon_identity daemon_probe(const char* socket_path,
                             std::string*  version_out,
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
        close(fd);
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
    char   buf[256];
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

    if (framed && buf[0] == 0)
    {
        const char* body = buf + 1;
        const size_t body_len = static_cast<size_t>(
            static_cast<const char*>(memchr(buf + 1, '\0', total - 1)) - body);

        if (body_len >= daemon_ident_prefix.size() &&
            memcmp(body, daemon_ident_prefix.data(), daemon_ident_prefix.size()) == 0)
        {
            if (version_out)
            {
                const char*  v   = body + daemon_ident_prefix.size();
                const size_t rest = body_len - daemon_ident_prefix.size();
                size_t       len  = 0;
                while (len < rest && v[len] != ' ' && v[len] != '\n')
                    ++len;
                version_out->assign(v, len);
            }
            return daemon_identity::daemon;
        }
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
