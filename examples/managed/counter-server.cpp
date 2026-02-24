// =============================================================================
// counter-server.cpp - Managed Connection Counter (Wrapper API)
// =============================================================================
//
// A simple server using the socketley::server wrapper that tracks connection
// count and replies to each message with a per-connection message counter.
//
// Works both standalone and as a daemon-managed binary via `socketley add`.
// When managed: auto-restarts on crash, re-launches on daemon boot.
//
// BUILD:
//   g++ -std=c++17 -O2 -Iinclude/linux counter-server.cpp \
//       -Lbin/Release -lsocketley_sdk -luring -lssl -lcrypto -o counter-server
//
// STANDALONE:
//   ./counter-server
//
// MANAGED:
//   socketley add ./counter-server --name counter -s
//   socketley ls
//   echo "hello" | nc -w1 localhost 7071        # → [counter] #1: hello
//   socketley stop counter
//   socketley start counter
//   socketley remove counter
//
// =============================================================================

#include <socketley/server.h>
#include <socketley/attach.h>

#include <cstdio>
#include <string>

int main()
{
    constexpr uint16_t PORT = 7071;
    int total_connections = 0;

    socketley::server srv(PORT);

    srv.on_connect([&](int fd) {
        ++total_connections;
        fprintf(stderr, "[counter] client %d connected (total: %d)\n",
                fd, total_connections);
        // Store a per-connection message counter
        srv.set_data(fd, "count", "0");
    });

    srv.on_disconnect([&](int fd) {
        --total_connections;
        fprintf(stderr, "[counter] client %d disconnected (total: %d)\n",
                fd, total_connections);
    });

    srv.on_message([&](int fd, std::string_view msg) {
        // Increment per-connection counter
        int count = std::stoi(srv.get_data(fd, "count")) + 1;
        srv.set_data(fd, "count", std::to_string(count));

        // Reply with counter prefix
        std::string reply = "[counter] #" + std::to_string(count)
                          + ": " + std::string(msg);
        srv.send(fd, reply);
    });

    // Register with daemon
    socketley::daemon_attach("counter-server", "server", PORT);

    fprintf(stderr, "[counter] listening on port %d\n", PORT);

    srv.start();
    return 0;
}
