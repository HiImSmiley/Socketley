// Socketley SDK — static HTTP file server with access logging
//
// Build:
//   g++ -std=c++23 sdk/examples/advanced/http_file_server.cpp \
//       -I. -Iinclude/linux -Ithirdparty/sol2 -Ithirdparty/luajit \
//       -Lbin/Release -lsocketley_sdk -luring -lssl -lcrypto -lluajit \
//       -o /tmp/http_file_server
//
// Run: mkdir -p ./public && echo "<h1>Hello</h1>" > ./public/index.html
//      /tmp/http_file_server
// Test: curl http://127.0.0.1:8080/index.html

#include <socketley/server.h>
#include <cstdio>

int main()
{
    socketley::server srv(8080);

    srv.http_dir("./public")
       .http_cache()
       .idle_timeout(30);

    srv.on_start([] {
        printf("HTTP file server on port 8080 (serving ./public)\n");
    });

    srv.on_stop([] {
        printf("HTTP file server stopped\n");
    });

    srv.on_connect([&](int fd) {
        printf("[+] %s\n", srv.peer_ip(fd).c_str());
    });

    srv.on_disconnect([&](int fd) {
        printf("[-] fd %d\n", fd);
    });

    srv.start();
    return 0;
}
