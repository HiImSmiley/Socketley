// Socketley SDK — production-hardened TLS echo server
//
// Build:
//   g++ -std=c++23 sdk/examples/advanced/tls_server.cpp \
//       -I. -Iinclude/linux -Ithirdparty/sol2 -Ithirdparty/luajit \
//       -Lbin/Release -lsocketley_sdk -luring -lssl -lcrypto -lluajit \
//       -o /tmp/tls_server
//
// Generate self-signed cert for testing:
//   openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
//       -days 365 -nodes -subj "/CN=localhost"
//
// Run: /tmp/tls_server
// Test: openssl s_client -connect 127.0.0.1:9443 -quiet <<< "hello"

#include <socketley/server.h>
#include <cstdio>

int main()
{
    socketley::server srv(9443);

    srv.tls("cert.pem", "key.pem")
       .max_connections(10000)
       .rate_limit(100)
       .idle_timeout(60);

    srv.on_start([] {
        printf("TLS server ready on port 9443\n");
    });

    srv.on_connect([&](int fd) {
        printf("[+] %s (fd %d)\n", srv.peer_ip(fd).c_str(), fd);
    });

    srv.on_message([&](int fd, std::string_view msg) {
        srv.send(fd, "echo: " + std::string(msg));
    });

    srv.on_disconnect([](int fd) {
        printf("[-] fd %d\n", fd);
    });

    srv.start();
    return 0;
}
