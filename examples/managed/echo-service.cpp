// =============================================================================
// echo-service.cpp - Minimal Managed External Service
// =============================================================================
//
// A standalone echo server built with the C++ SDK (attach.h).
// When registered via `socketley add`, the daemon manages its full lifecycle:
// fork+exec on start, auto-restart on crash, re-launch on daemon boot.
//
// BUILD:
//   g++ -std=c++17 -I/path/to/socketley/include/linux echo-service.cpp -o echo-service
//
// USAGE (standalone, self-attaches):
//   ./echo-service
//
// USAGE (managed by daemon):
//   socketley add ./echo-service -s
//   socketley ls                        # shows "echo-service" running
//   kill $(socketley ps | grep echo | awk '{print $NF}')   # daemon restarts it
//   socketley stop echo-service
//   socketley start echo-service        # daemon re-launches
//   socketley remove echo-service
//
// =============================================================================

#include <socketley/attach.h>

#include <cstdio>
#include <cstring>
#include <csignal>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>

static volatile sig_atomic_t g_running = 1;

static void on_signal(int) { g_running = 0; }

int main()
{
    signal(SIGTERM, on_signal);
    signal(SIGINT,  on_signal);
    signal(SIGPIPE, SIG_IGN);

    // Create a TCP listen socket
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(7070);

    if (bind(listen_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        perror("bind");
        close(listen_fd);
        return 1;
    }

    listen(listen_fd, 16);

    // Register with the daemon.
    // In managed mode (SOCKETLEY_MANAGED=1), the name comes from SOCKETLEY_NAME
    // and the binary does NOT self-remove on exit.
    // In standalone mode, uses "echo-service" and auto-removes on exit.
    socketley::daemon_attach("echo-service", "server", 7070);

    fprintf(stderr, "[echo-service] listening on port 7070\n");

    // Simple poll-based echo loop
    struct pollfd fds[64];
    int nfds = 1;
    fds[0].fd = listen_fd;
    fds[0].events = POLLIN;

    while (g_running)
    {
        int ret = poll(fds, nfds, 500);
        if (ret < 0) { if (errno == EINTR) continue; break; }
        if (ret == 0) continue;

        // Check for new connections
        if (fds[0].revents & POLLIN)
        {
            int client = accept(listen_fd, nullptr, nullptr);
            if (client >= 0 && nfds < 64)
            {
                fds[nfds].fd = client;
                fds[nfds].events = POLLIN;
                ++nfds;
            }
            else if (client >= 0)
            {
                close(client);
            }
        }

        // Check existing clients
        for (int i = 1; i < nfds; ++i)
        {
            if (!(fds[i].revents & POLLIN))
                continue;

            char buf[1024];
            ssize_t n = read(fds[i].fd, buf, sizeof(buf));
            if (n <= 0)
            {
                close(fds[i].fd);
                fds[i] = fds[--nfds];
                --i;
                continue;
            }

            // Echo back
            if (write(fds[i].fd, buf, n) < 0) {}
        }
    }

    for (int i = 0; i < nfds; ++i)
        close(fds[i].fd);

    fprintf(stderr, "[echo-service] stopped\n");
    return 0;
}
