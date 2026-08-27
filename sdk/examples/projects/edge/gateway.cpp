// edge — a TLS-terminating gateway in front of a unix-socket application.
//
// The public face of the pair: TLS on the listener, HTTP awareness for
// per-request routing, the sidecar mesh defaults (TCP health checks, circuit
// breaker, retries, drain), and a backend that is a filesystem node rather
// than a port.  Adding a second backend("...") is a one-line scale-out; the
// strategy then load-balances across them, and health checks eject the dead.
//
// Certificates: any pair works for a demo —
//   openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
//       -days 30 -nodes -subj "/CN=localhost"
//
// Build (from the repo root, after building libsocketley_sdk.a):
//   g++ -std=c++23 sdk/examples/projects/edge/gateway.cpp \
//       -I. -Iinclude/linux -Ithirdparty/sol2 -Ithirdparty/luajit \
//       -Lbin/Release -Lthirdparty/luajit \
//       -lsocketley_sdk -luring -lssl -lcrypto -lluajit -o /tmp/edge-gw
//
// Run:  /tmp/edge-gw            (edge-app must be up first; see app.cpp)
// Try:  curl -k https://127.0.0.1:8443/gw/index.html

#include <socketley/proxy.h>
#include <cstdio>

int main()
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    // The name is the URL prefix: an HTTP-mode proxy routes by "/<name>/",
    // so this gateway serves https://host:8443/gw/...
    socketley::proxy gw(8443, "gw");
    gw.tls("cert.pem", "key.pem")            // terminate TLS here
      .protocol(protocol_http)               // route per request, not per conn
      .backend("unix:/tmp/edge-app.sock")    // the app is a node, not a port
      .sidecar();                            // health checks, breaker, retry, drain

    // The hooks see every request head (and body chunks); here they are a
    // one-line access log, which is also the way to add or strip headers.
    // The return contract is not the obvious one -- see proxy.h:
    //   nullopt = DROP the bytes, "" = pass unchanged, "..." = replace.
    gw.on_proxy_request([](int, std::string_view head) -> std::optional<std::string> {
        printf("gw: %.*s\n", (int)head.substr(0, head.find('\r')).size(), head.data());
        return std::string{};                // empty = forward unmodified
    });

    printf("edge-gw: https on :8443 -> unix:/tmp/edge-app.sock\n");
    gw.start();
    return 0;
}
