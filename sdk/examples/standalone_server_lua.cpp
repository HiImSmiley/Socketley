// Socketley SDK — standalone server example with Lua scripting
//
// Requires: apt install libluajit-5.1-dev  (or build LuaJIT from source)
//
// Build:
//   g++ -std=c++23 sdk/examples/standalone_server_lua.cpp \
//       -I. -Iinclude/linux -Ithirdparty/sol2 -Ithirdparty/luajit \
//       -Lbin/Release -lsocketley_sdk -luring -lssl -lcrypto -lluajit \
//       -o /tmp/standalone_server_lua
//
// Run: /tmp/standalone_server_lua sdk/examples/server_config.lua
//
// Example Lua config (sdk/examples/server_config.lua):
//
//   tick_ms = 5000
//
//   function on_start()
//     socketley.log("server started on port " .. tostring(self.port))
//   end
//
//   function on_connect(client_id)
//     socketley.log("client " .. tostring(client_id) .. " connected")
//   end
//
//   function on_message(msg)
//     socketley.log("received: " .. msg)
//     self.broadcast("echo: " .. msg)
//   end
//
//   function on_disconnect(client_id)
//     socketley.log("client " .. tostring(client_id) .. " disconnected")
//   end
//
//   function on_tick(dt)
//     socketley.log("tick, dt=" .. tostring(dt) .. " ms")
//   end

#include <socketley/server.h>
#include <csignal>
#include <cstdio>

static event_loop* g_loop = nullptr;

int main(int argc, char* argv[])
{
    const char* lua_script = (argc > 1) ? argv[1] : "sdk/examples/server_config.lua";

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

    if (!inst->load_lua_script(lua_script))
    {
        fprintf(stderr, "failed to load Lua script: %s\n", lua_script);
        return 1;
    }

    if (!manager.run("srv", loop))
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
