// Socketley SDK — standalone server example (no daemon required)
//
// Build (with LuaJIT):
//   g++ -std=c++23 sdk/examples/standalone_server.cpp \
//       -I. -Iinclude/linux -Ithirdparty/sol2 -Ithirdparty/luajit \
//       -Lbin/Release -lsocketley_sdk -luring -lssl -lcrypto -lluajit \
//       -o /tmp/standalone_server
//
// Build (without LuaJIT):
//   g++ -std=c++23 -DSOCKETLEY_NO_LUA sdk/examples/standalone_server.cpp \
//       -I. -Iinclude/linux \
//       -Lbin/Release -lsocketley_sdk_nolua -luring -lssl -lcrypto \
//       -o /tmp/standalone_server_nolua
//
// Run: /tmp/standalone_server
// Test: echo "hello" | nc 127.0.0.1 9000

#include <socketley/server.h>
#include <csignal>
#include <cstdio>

static event_loop* g_loop = nullptr;

int main()
{
    signal(SIGPIPE, SIG_IGN);

    event_loop loop;
    if (!loop.init())
    {
        fprintf(stderr, "event_loop::init() failed\n");
        return 1;
    }
    g_loop = &loop;

    runtime_manager manager;
    if (!manager.create(runtime_server, "srv"))
    {
        fprintf(stderr, "create failed\n");
        return 1;
    }

    auto* inst = manager.get("srv");
    inst->set_port(9000);
    inst->set_runtime_manager(&manager);
    inst->set_event_loop(&loop);

    if (!manager.start("srv", loop))
    {
        fprintf(stderr, "start failed\n");
        return 1;
    }

    signal(SIGINT,  [](int){ if (g_loop) g_loop->request_stop(); });
    signal(SIGTERM, [](int){ if (g_loop) g_loop->request_stop(); });

    loop.run();

    manager.stop_all(loop);
    return 0;
}
