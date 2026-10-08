#include "ipc_client.h"
#include "daemon_handler.h"
#include "../shared/ipc_framing.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <iostream>

int ipc_send(std::string_view command, std::string& data)
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return ipc_unreachable;

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, daemon_handler::socket_path.c_str(), sizeof(addr.sun_path) - 1);

    if (connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        close(fd);
        return ipc_unreachable;
    }

    // Five seconds to answer, and a command that waits on a worker can spend
    // longer than that -- so what this deadline means to the caller is the
    // whole of ipc_report_failure() below.
    struct timeval tv{5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

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
            ssize_t w = write(fd, msg.data() + total, msg.size() - total);
            if (w < 0) { close(fd); return ipc_unreachable; }
            total += static_cast<size_t>(w);
        }
    }

    // Read response: first byte = exit code, then data until NUL terminator
    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf));

    if (n < 1)
    {
        // The deadline expiring is not the socket failing: the daemon took the
        // command and is working on it, and telling the operator it could not
        // be reached is the one thing that is certainly untrue.
        const bool timed_out = n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK);
        close(fd);

        // Ahead of the framing message below, because a framed command that
        // ran out of time was answered by a daemon that reads frames perfectly
        // well and is simply still busy.
        if (timed_out)
            return ipc_no_answer;

        // The one case where "failed to connect" would be the wrong sentence,
        // said here because this is the only place that knows a frame went out
        // to a daemon that predates framing.
        if (framed)
            std::cerr << "the daemon did not answer a length-framed command.\n"
                         "  Commands carrying a newline — a message, a value, an "
                         "imported document — are\n"
                         "  sent this way.  A daemon started before this build "
                         "does not read them;\n"
                         "  restart it (`socketley version` reports a daemon "
                         "running an earlier build).\n";
        return ipc_unreachable;
    }

    int exit_code = static_cast<unsigned char>(buf[0]);

    data.clear();

    // Check if NUL terminator is in first read
    auto* nul = static_cast<char*>(std::memchr(buf + 1, '\0', n - 1));
    if (nul)
    {
        data.append(buf + 1, nul - buf - 1);
        close(fd);
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
            close(fd);
            return ipc_no_answer;
        }
        if (n <= 0)
            break;

        nul = static_cast<char*>(std::memchr(buf, '\0', n));
        if (nul)
        {
            data.append(buf, nul - buf);
            break;
        }

        data.append(buf, n);
    }

    close(fd);
    return exit_code;
}

int ipc_report_failure(int rc)
{
    if (rc == ipc_no_answer)
    {
        std::cerr << "the daemon at " << daemon_handler::socket_path
                  << " took the command and has not answered in 5s\n"
                     "  It is busy, not gone.  A start, a reload or a cache verb "
                     "that waits on a\n"
                     "  worker holds the daemon while it waits, and this command's "
                     "answer is lost\n"
                     "  when it comes.  `socketley ls` says what happened, once "
                     "the daemon is free.\n";
        return 2;
    }

    std::cerr << "failed to connect to daemon\n";
    return 2;
}
