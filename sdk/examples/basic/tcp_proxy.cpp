// Socketley SDK — minimal TCP proxy example
//
// Build:
//   g++ -std=c++23 sdk/examples/basic/tcp_proxy.cpp \
//       -I. -Iinclude/linux -Ithirdparty/sol2 -Ithirdparty/luajit \
//       -Lbin/Release -lsocketley_sdk -luring -lssl -lcrypto -lluajit \
//       -o /tmp/tcp_proxy
//
// Run (start backends on ports 9001 and 9002 first):
//   /tmp/tcp_proxy
// Test: echo "hello" | nc -q1 127.0.0.1 8080

#include <socketley/proxy.h>

int main()
{
    socketley::proxy px(8080);
    px.backend("127.0.0.1:9001")
      .backend("127.0.0.1:9002")
      .protocol(protocol_tcp)
      .strategy(strategy_round_robin);
    px.start();
    return 0;
}
