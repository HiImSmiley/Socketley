// chatroom — a chat service with rooms, presence and WebSocket clients.
//
// One server wrapper, but the whole surface of it: multicast groups as rooms,
// per-connection data as presence, the tick as a janitor, and the listener's
// dual protocol — the same port speaks newline-framed TCP (nc) and WebSocket
// (a browser, or the cross-platform ws_client.h; see chat_cli.cpp).  Frames
// are decoded before on_message fires, so the room logic never knows which
// transport a member arrived on.
//
// Commands (one per line, from either transport):
//   /nick <name>      set your name
//   /join <room>      leave your room, join another (default room: lobby)
//   /who              list the members of your room
//   /quit             disconnect
//   anything else     say it to your room
//
// Build (from the repo root, after building libsocketley_sdk.a):
//   g++ -std=c++23 sdk/examples/projects/chatroom/chatd.cpp \
//       -I. -Iinclude/linux -Ithirdparty/sol2 -Ithirdparty/luajit \
//       -Lbin/Release -Lthirdparty/luajit \
//       -lsocketley_sdk -luring -lssl -lcrypto -lluajit -o /tmp/chatd
//
// Run:   /tmp/chatd
// Try:   nc 127.0.0.1 9000                (several terminals)
//        /tmp/chat_cli                    (WebSocket transport)

#include <socketley/server.h>

#include <cstdio>
#include <string>
#include <string_view>

static std::string_view trim(std::string_view s)
{
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r'))
        s.remove_suffix(1);
    return s;
}

int main()
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    socketley::server srv(9000);

    // mode_in matters here.  The default (mode_inout) makes the server a hub:
    // every inbound line is ALSO relayed raw to every other client, on top of
    // whatever on_message does with it — so each chat line would arrive twice,
    // once as "[nick] ..." and once bare.  A server whose on_message IS the
    // protocol wants the relay off, and mode_in is that switch.
    srv.mode(mode_in)
       .idle_timeout(300)      // the transport reaps silent connections
       .max_connections(500)
       .tick_interval(30000);  // presence heartbeat, below

    srv.on_connect([&](int fd) {
        const std::string nick = "user_" + std::to_string(fd);
        srv.set_data(fd, "nick", nick);
        srv.set_data(fd, "room", "lobby");
        srv.join_group(fd, "lobby");
        srv.send(fd, "hello " + nick + " -- you are in #lobby. "
                     "/nick /join /who /quit\n");
        srv.group_send("lobby", "* " + nick + " joined #lobby\n");
    });

    // A WebSocket arrival carries headers a TCP one does not; log the origin
    // so the two transports are distinguishable in the server's own output.
    srv.on_websocket([&](int fd, const server_instance::ws_headers_result& h) {
        printf("chatd: fd %d upgraded to websocket (origin: %s)\n",
               fd, h.origin.empty() ? "-" : h.origin.c_str());
    });

    srv.on_message([&](int fd, std::string_view raw) {
        const std::string_view msg = trim(raw);
        const std::string nick = srv.get_data(fd, "nick");
        const std::string room = srv.get_data(fd, "room");

        if (msg.rfind("/nick ", 0) == 0 && msg.size() > 6)
        {
            const std::string next(msg.substr(6));
            srv.set_data(fd, "nick", next);
            srv.group_send(room, "* " + nick + " is now " + next + "\n");
            return;
        }
        if (msg.rfind("/join ", 0) == 0 && msg.size() > 6)
        {
            const std::string next(msg.substr(6));
            srv.leave_group(fd, room);
            srv.group_send(room, "* " + nick + " left #" + room + "\n");
            srv.set_data(fd, "room", next);
            srv.join_group(fd, next);
            srv.group_send(next, "* " + nick + " joined #" + next + "\n");
            return;
        }
        if (msg == "/who")
        {
            std::string out = "#" + room + ":";
            for (int id : srv.clients())
                if (srv.get_data(id, "room") == room)
                    out += " " + srv.get_data(id, "nick");
            srv.send(fd, out + "\n");
            return;
        }
        if (msg == "/quit")
        {
            srv.send(fd, "bye\n");
            srv.disconnect(fd);
            return;
        }
        srv.group_send(room, "[" + nick + "] " + std::string(msg) + "\n");
    });

    srv.on_disconnect([&](int fd) {
        const std::string nick = srv.get_data(fd, "nick");
        const std::string room = srv.get_data(fd, "room");
        if (!room.empty())
            srv.group_send(room, "* " + nick + " disconnected\n");
    });

    // The janitor: not connection reaping (idle_timeout owns that), but the
    // slow-cadence work every chat service grows — here, a presence line.
    srv.on_tick([&](double) {
        printf("chatd: %zu connected\n", srv.connection_count());
    });

    printf("chatd: rooms on :9000 (TCP and WebSocket)\n");
    srv.start();
    return 0;
}
