#include "daemon_client.h"
#include "paths.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

namespace socketley {

static std::string g_attached_name;

// Send one command to the daemon, return daemon exit code (or -1 on IPC error).
static int daemon_ipc(const char* cmd)
{
    auto paths = socketley_paths::resolve();
    std::string sock_path = paths.socket_path.string();

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
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
    (void)write(fd, msg.data(), msg.size());

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
