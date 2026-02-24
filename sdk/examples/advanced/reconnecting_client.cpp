// Socketley SDK — client with auto-reconnect and periodic heartbeat
//
// Build:
//   g++ -std=c++23 sdk/examples/advanced/reconnecting_client.cpp \
//       -I. -Iinclude/linux -Ithirdparty/sol2 -Ithirdparty/luajit \
//       -Lbin/Release -lsocketley_sdk -luring -lssl -lcrypto -lluajit \
//       -o /tmp/reconnecting_client
//
// Run (start an echo server first):
//   /tmp/reconnecting_client
//
// Try: kill the server and restart it — the client will auto-reconnect.

#include <socketley/client.h>
#include <cstdio>

int main()
{
    socketley::client cli("127.0.0.1", 9000);

    cli.reconnect(10);         // retry up to 10 times on disconnect
    cli.tick_interval(5000);   // 5-second heartbeat tick

    cli.on_connect([&](int) {
        printf("[connected] sending hello\n");
        cli.send("hello\n");
    });

    cli.on_disconnect([](int) {
        printf("[disconnected] will reconnect...\n");
    });

    cli.on_message([](std::string_view msg) {
        printf("[recv] %.*s\n", (int)msg.size(), msg.data());
    });

    cli.on_tick([&](double dt) {
        printf("[tick] %.0f ms — sending ping\n", dt);
        cli.send("ping\n");
    });

    cli.start();
    return 0;
}
