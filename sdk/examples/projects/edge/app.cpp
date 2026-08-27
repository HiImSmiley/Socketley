// edge — the application server behind the gateway.
//
// It listens on an AF_UNIX socket, not a port: the only thing that should
// reach it is the gateway in front of it, and a filesystem node with 0700 on
// its directory enforces that better than a firewall rule.  This is the
// `--listen unix:` feature through the SDK's unix-path constructor.
//
// It serves static files over HTTP from ./public (http_dir mode with the
// response cache on), so the gateway has something real to terminate TLS for.
//
// Build (from the repo root, after building libsocketley_sdk.a):
//   g++ -std=c++23 sdk/examples/projects/edge/app.cpp \
//       -I. -Iinclude/linux -Ithirdparty/sol2 -Ithirdparty/luajit \
//       -Lbin/Release -Lthirdparty/luajit \
//       -lsocketley_sdk -luring -lssl -lcrypto -lluajit -o /tmp/edge-app
//
// Run:  /tmp/edge-app   (from the directory holding ./public)

#include <socketley/server.h>
#include <cstdio>

int main()
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    socketley::server app("unix:/tmp/edge-app.sock");
    app.http_dir("./public")
       .http_cache();

    printf("edge-app: serving ./public on unix:/tmp/edge-app.sock\n");
    return app.start() ? 0 : 2;
}
