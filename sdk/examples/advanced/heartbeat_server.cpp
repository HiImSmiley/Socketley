// Socketley SDK — server that disconnects idle clients
//
// Build:
//   g++ -std=c++23 sdk/examples/advanced/heartbeat_server.cpp \
//       -I. -Iinclude/linux -Ithirdparty/sol2 -Ithirdparty/luajit \
//       -Lbin/Release -lsocketley_sdk -luring -lssl -lcrypto -lluajit \
//       -o /tmp/heartbeat_server
//
// Run: /tmp/heartbeat_server
// Test: nc 127.0.0.1 9000   (idle for 30s to get kicked)

#include <socketley/server.h>
#include <cstdio>
#include <ctime>
#include <string>

static std::string now_str()
{
    return std::to_string(static_cast<long>(time(nullptr)));
}

int main()
{
    socketley::server srv(9000);
    constexpr long idle_limit = 30; // seconds

    srv.tick_interval(1000);
    srv.idle_timeout(60); // network-level backup

    srv.on_start([] {
        printf("heartbeat server on port 9000 (idle limit: 30s)\n");
    });

    srv.on_connect([&](int fd) {
        srv.set_data(fd, "last_seen", now_str());
        srv.send(fd, "connected — send data to stay alive\n");
        printf("[+] client %d (%s)\n", fd, srv.peer_ip(fd).c_str());
    });

    srv.on_message([&](int fd, std::string_view msg) {
        srv.set_data(fd, "last_seen", now_str());
        srv.send(fd, "echo: " + std::string(msg));
    });

    srv.on_tick([&](double) {
        long now = static_cast<long>(time(nullptr));
        for (int fd : srv.clients()) {
            std::string ts = srv.get_data(fd, "last_seen");
            if (ts.empty()) continue;
            long last = std::stol(ts);
            if (now - last > idle_limit) {
                printf("[idle] disconnecting client %d (idle %lds)\n", fd, now - last);
                srv.send(fd, "idle timeout — disconnecting\n");
                srv.disconnect(fd);
            }
        }
    });

    srv.on_disconnect([](int fd) {
        printf("[-] client %d\n", fd);
    });

    srv.start();
    return 0;
}
