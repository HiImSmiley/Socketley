#include "ipc_client.h"
#include "../daemon/daemon_handler.h"
#include "../shared/ipc_framing.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <unistd.h>
#include <cstring>
#include <iostream>

int ipc_send(std::string_view command, std::string& data)
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, daemon_handler::socket_path.c_str(), sizeof(addr.sun_path) - 1);

    if (connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        close(fd);
        return -1;
    }

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
            if (w < 0) { close(fd); return -1; }
            total += static_cast<size_t>(w);
        }
    }

    // Read response: first byte = exit code, then data until NUL terminator
    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf));

    if (n < 1)
    {
        close(fd);

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
        return -1;
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
