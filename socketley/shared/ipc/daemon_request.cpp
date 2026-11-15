#include "daemon_request.h"
#include "daemon_client.h"
#include "ipc_framing.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <unistd.h>
#include <cerrno>
#include <cstdio>
#include <cstring>

namespace socketley {

int daemon_connect(const std::string& socket_path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return ipc_unreachable;

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);

    if (connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        close(fd);
        return ipc_unreachable;
    }

    // Asked before a byte is written, because a shared /tmp path is bound by whoever comes first and a command carries its secrets.
    if (!socket_peer_trusted(fd))
    {
        close(fd);
        return ipc_stranger;
    }

    // Five seconds to answer, and a command that waits on a worker can spend
    // longer than that -- so what this deadline means to the caller is the
    // whole of ipc_report_failure() below.
    struct timeval tv{5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return fd;
}

// A read that also takes a descriptor sent with what it reads, close-on-exec, since a shell runs programs.
static ssize_t read_passing(int fd, char* buf, size_t len, int& passed)
{
    struct iovec iov{buf, len};
    alignas(struct cmsghdr) char ctl[CMSG_SPACE(sizeof(int))]{};
    struct msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctl;
    msg.msg_controllen = sizeof ctl;
    const ssize_t n = ::recvmsg(fd, &msg, MSG_CMSG_CLOEXEC);
    for (struct cmsghdr* c = CMSG_FIRSTHDR(&msg); n >= 0 && c; c = CMSG_NXTHDR(&msg, c))
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS && c->cmsg_len == CMSG_LEN(sizeof(int)))
        {
            int got = -1;
            std::memcpy(&got, CMSG_DATA(c), sizeof got);
            if (passed >= 0)
                ::close(passed);
            passed = got;
        }
    return n;
}

// Leaves the connection open, for the next command or for the caller to close; `sent` says whether any of the
// command reached the socket, so a caller may send it again on a new connection only when none did.
int daemon_exchange(int fd, std::string_view command, std::string& data, bool& sent, int* passed)
{
    sent = false;
    if (passed)
        *passed = -1;
    // A line unless it cannot be one, so every ordinary command stays
    // byte-identical and a new CLI can talk to a daemon that has not been
    // restarted.
    std::string msg;
    const bool framed = ipc_frame::needs_frame(command);
    if (framed)
    {
        msg = ipc_frame::encode(command);
    }
    else
    {
        msg.assign(command);
        msg += '\n';
    }

    {
        size_t total = 0;
        while (total < msg.size())
        {
            // send, not write, so a daemon that closed first is an error here and not a SIGPIPE that ends the CLI.
            ssize_t w = ::send(fd, msg.data() + total, msg.size() - total, MSG_NOSIGNAL);
            if (w < 0 && errno == EINTR)
                continue;
            if (w < 0) return ipc_unreachable;
            sent = true;
            total += static_cast<size_t>(w);
        }
    }

    // Read response: first byte = exit code, then data until NUL terminator
    char buf[4096];
    ssize_t n;
    // A socket with a receive deadline is never restarted after a signal, and a shell's SIGCHLD arrives at any time.
    do
        n = passed ? read_passing(fd, buf, sizeof(buf), *passed) : read(fd, buf, sizeof(buf));
    while (n < 0 && errno == EINTR);

    if (n < 1)
    {
        // The deadline expiring is not the socket failing: the daemon took the
        // command and is working on it, and telling the operator it could not
        // be reached is the one thing that is certainly untrue.
        const bool timed_out = n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK);

        // Ahead of the framing message below, because a framed command that
        // ran out of time was answered by a daemon that reads frames perfectly
        // well and is simply still busy.
        if (timed_out)
            return ipc_no_answer;

        // The one case where "failed to connect" would be the wrong sentence,
        // said here because this is the only place that knows a frame went out
        // to a daemon that predates framing.
        if (framed)
            std::fputs("the daemon did not answer a length-framed command.\n"
                       "  Commands carrying a newline — a message, a value, an "
                       "imported document — are\n"
                       "  sent this way.  A daemon started before this build "
                       "does not read them;\n"
                       "  restart it (`socketley version` reports a daemon "
                       "running an earlier build).\n",
                       stderr);
        return ipc_unreachable;
    }

    int exit_code = static_cast<unsigned char>(buf[0]);

    data.clear();

    // Check if NUL terminator is in first read
    auto* nul = static_cast<char*>(std::memchr(buf + 1, '\0', n - 1));
    if (nul)
    {
        data.append(buf + 1, nul - buf - 1);
        return exit_code;
    }

    data.append(buf + 1, n - 1);

    // Continue reading until NUL terminator
    while (true)
    {
        n = read(fd, buf, sizeof(buf));
        // The same distinction as the first read, and here it decides what the
        // caller PRINTS: a deadline expiring in the middle of an answer ended
        // the loop, so half an answer went out under the daemon's own exit code
        // and read as the whole of it.
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        {
            return ipc_no_answer;
        }
        if (n < 0 && errno == EINTR)
            continue;
        // The end of the stream before the NUL is an answer cut short, which is not the daemon's to give a code to.
        if (n <= 0)
        {
            return ipc_cut_short;
        }

        nul = static_cast<char*>(std::memchr(buf, '\0', n));
        if (nul)
        {
            data.append(buf, nul - buf);
            break;
        }

        data.append(buf, n);
    }

    return exit_code;
}

int daemon_request(const std::string& socket_path, std::string_view command, std::string& data)
{
    const int fd = daemon_connect(socket_path);
    if (fd < 0)
        return fd;
    bool sent = false;
    const int rc = daemon_exchange(fd, command, data, sent);
    close(fd);
    return rc;
}

int daemon_request_failure(const std::string& socket_path, int rc)
{
    if (rc == ipc_no_answer)
    {
        std::fprintf(stderr,
                     "the daemon at %s took the command and has not answered in 5s\n"
                     "  It is busy, not gone.  A start, a reload or a cache verb "
                     "that waits on a\n"
                     "  worker holds the daemon while it waits, and this command's "
                     "answer is lost\n"
                     "  when it comes.  `socketley ls` says what happened, once "
                     "the daemon is free.\n",
                     socket_path.c_str());
        return 2;
    }

    if (rc == ipc_cut_short)
    {
        std::fprintf(stderr, "the daemon at %s closed the connection before its answer was whole\n",
                     socket_path.c_str());
        return 2;
    }
    if (rc == ipc_stranger)
    {
        std::fprintf(stderr,
                     "the daemon socket at %s is held by a process of another user\n"
                     "  Nothing was sent to it. Point SOCKETLEY_SOCKET at a path you own.\n",
                     socket_path.c_str());
        return 2;
    }
    std::fputs("failed to connect to daemon\n", stderr);
    return 2;
}

} // namespace socketley
