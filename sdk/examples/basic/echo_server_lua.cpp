// Socketley SDK — echo server with Lua scripting
//
// Requires: apt install libluajit-5.1-dev  (or build LuaJIT from source)
//
// Build:
//   g++ -std=c++23 sdk/examples/basic/echo_server_lua.cpp \
//       -I. -Iinclude/linux -Ithirdparty/sol2 -Ithirdparty/luajit \
//       -Lbin/Release -lsocketley_sdk -luring -lssl -lcrypto -lluajit \
//       -o /tmp/echo_server_lua
//
// Run: /tmp/echo_server_lua sdk/examples/server_config.lua
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
#include <cstdio>

int main(int argc, char* argv[])
{
    const char* lua_script = (argc > 1) ? argv[1] : "sdk/examples/server_config.lua";

    socketley::server srv(9000);
    srv.lua(lua_script);
    srv.start();

    return 0;
}
