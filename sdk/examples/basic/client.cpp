// Socketley SDK — minimal client example
//
// Build:
//   g++ -std=c++23 sdk/examples/basic/client.cpp \
//       -I. -Iinclude/linux -Ithirdparty/sol2 -Ithirdparty/luajit \
//       -Lbin/Release -lsocketley_sdk -luring -lssl -lcrypto -lluajit \
//       -o /tmp/client
//
// Run (start an echo server first, e.g. /tmp/echo_server):
//   /tmp/client

#include <socketley/client.h>
#include <cstdio>

int main()
{
    socketley::client cli("127.0.0.1", 9000);

    cli.on_connect([&](int) {
        printf("connected to server\n");
        cli.send("hello from SDK client\n");
    });

    cli.on_message([](std::string_view msg) {
        printf("server: %.*s\n", (int)msg.size(), msg.data());
    });

    cli.on_disconnect([](int) {
        printf("disconnected\n");
    });

    cli.start();
    return 0;
}
