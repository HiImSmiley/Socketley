// Socketley SDK — echo server example (no daemon required)
//
// Build:
//   g++ -std=c++23 sdk/examples/basic/echo_server.cpp \
//       -I. -Iinclude/linux -Ithirdparty/sol2 -Ithirdparty/luajit \
//       -Lbin/Release -lsocketley_sdk -luring -lssl -lcrypto -lluajit \
//       -o /tmp/echo_server
//
// Run: /tmp/echo_server
// Test: echo "hello" | nc -q1 127.0.0.1 9000

#include <socketley/server.h>
#include <cstdio>

int main()
{
    socketley::server srv(9000);

    srv.on_connect([](int fd) {
        printf("client %d connected\n", fd);
    });

    srv.on_message([&](int fd, std::string_view msg) {
        printf("client %d: %.*s\n", fd, (int)msg.size(), msg.data());
        srv.send(fd, "echo: " + std::string(msg));
    });

    srv.on_disconnect([](int fd) {
        printf("client %d disconnected\n", fd);
    });

    srv.start();
    return 0;
}
