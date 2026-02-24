// =============================================================================
// chat-server.cpp - Managed Chat Server (Wrapper API)
// =============================================================================
//
// A multi-client chat server using the socketley::server wrapper.
// Messages from any client are broadcast to all others.
//
// Works both standalone and as a daemon-managed binary via `socketley add`.
// When managed: auto-restarts on crash, re-launches on daemon boot.
//
// BUILD:
//   g++ -std=c++17 -O2 -Iinclude/linux chat-server.cpp \
//       -Lbin/Release -lsocketley_sdk -luring -lssl -lcrypto -o chat-server
//
// STANDALONE:
//   ./chat-server
//
// MANAGED:
//   socketley add ./chat-server --name chat -s
//   socketley ls
//   socketley stop chat
//   socketley start chat
//   socketley remove chat
//
// =============================================================================

#include <socketley/server.h>
#include <socketley/attach.h>

#include <cstdio>
#include <string>

int main()
{
    constexpr uint16_t PORT = 7070;

    socketley::server srv(PORT);

    srv.on_connect([](int fd) {
        fprintf(stderr, "[chat] client %d joined\n", fd);
    });

    srv.on_disconnect([](int fd) {
        fprintf(stderr, "[chat] client %d left\n", fd);
    });

    srv.on_message([&](int fd, std::string_view msg) {
        // Broadcast to everyone (including sender)
        srv.broadcast(msg);
    });

    // Register with daemon — works both standalone and managed.
    // When managed (launched via `socketley add`), the daemon sets
    // SOCKETLEY_MANAGED=1 and SOCKETLEY_NAME, so daemon_attach()
    // uses the assigned name and skips atexit self-removal.
    socketley::daemon_attach("chat-server", "server", PORT);

    fprintf(stderr, "[chat] listening on port %d\n", PORT);

    srv.start();  // Blocks until SIGTERM/SIGINT
    return 0;
}
