// Socketley SDK — chat server with nicknames, rooms, and commands
//
// Build:
//   g++ -std=c++23 sdk/examples/advanced/chat_server.cpp \
//       -I. -Iinclude/linux -Ithirdparty/sol2 -Ithirdparty/luajit \
//       -Lbin/Release -lsocketley_sdk -luring -lssl -lcrypto -lluajit \
//       -o /tmp/chat_server
//
// Run: /tmp/chat_server
// Test: open multiple terminals with `nc 127.0.0.1 9000`
//   /nick Alice       — set your nickname
//   /who              — list connected users
//   /quit             — disconnect
//   anything else     — broadcast to all users

#include <socketley/server.h>
#include <cstdio>
#include <string>

int main()
{
    socketley::server srv(9000);

    srv.on_start([] {
        printf("chat server ready on port 9000\n");
    });

    srv.on_connect([&](int fd) {
        std::string name = "user_" + std::to_string(fd);
        srv.set_data(fd, "nick", name);
        srv.send(fd, "Welcome! You are " + name + ". Use /nick <name> to change.\n");
        srv.broadcast("[" + name + " joined]\n");
        printf("[+] %s (%s)\n", name.c_str(), srv.peer_ip(fd).c_str());
    });

    srv.on_message([&](int fd, std::string_view msg) {
        std::string nick = srv.get_data(fd, "nick");

        // Strip trailing newline for command parsing
        std::string_view trimmed = msg;
        while (!trimmed.empty() && (trimmed.back() == '\n' || trimmed.back() == '\r'))
            trimmed.remove_suffix(1);

        if (trimmed.starts_with("/nick ") && trimmed.size() > 6) {
            std::string old_nick = nick;
            std::string new_nick(trimmed.substr(6));
            srv.set_data(fd, "nick", new_nick);
            srv.broadcast("[" + old_nick + " is now " + new_nick + "]\n");
            return;
        }

        if (trimmed == "/who") {
            std::string list = "Online:";
            for (int id : srv.clients())
                list += " " + srv.get_data(id, "nick");
            list += "\n";
            srv.send(fd, list);
            return;
        }

        if (trimmed == "/quit") {
            srv.send(fd, "Goodbye!\n");
            srv.disconnect(fd);
            return;
        }

        srv.broadcast("[" + nick + "] " + std::string(msg));
    });

    srv.on_disconnect([&](int fd) {
        std::string nick = srv.get_data(fd, "nick");
        srv.broadcast("[" + nick + " left]\n");
        printf("[-] %s\n", nick.c_str());
    });

    srv.start();
    return 0;
}
