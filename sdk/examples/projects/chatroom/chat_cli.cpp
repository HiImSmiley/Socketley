// chatroom — a terminal chat client over WebSocket.
//
// Built on the cross-platform ws_client.h, so the same file compiles on
// Linux, Windows and macOS with nothing but the one header.  It connects to
// chatd's port with a real RFC 6455 handshake — the server speaks TCP and
// WebSocket on the same listener and decodes frames before the room logic
// sees them, which is what makes this client and a bare `nc` equal citizens
// in the same room.
//
// One thread reads frames and prints them; the main thread reads stdin and
// sends.  recv() answers pings itself, so the reader loop is just messages.
//
// Build (Linux):
//   g++ -std=c++17 sdk/examples/projects/chatroom/chat_cli.cpp \
//       $(sdk/socketley-config --cflags --libs) -o /tmp/chat_cli
// (Windows: cl /std:c++17 /EHsc /I include\windows chat_cli.cpp
//  macOS:   clang++ -std=c++17 -I include/darwin chat_cli.cpp -o chat_cli)
//
// Run:  /tmp/chat_cli [host]

#include <socketley/ws_client.h>

#include <atomic>
#include <cstdio>
#include <iostream>
#include <string>
#include <thread>

int main(int argc, char** argv)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    const std::string host = argc > 1 ? argv[1] : "127.0.0.1";

    socketley::ws_client c;
    if (!c.connect(host, 9000))
    {
        fprintf(stderr, "cannot reach chatd at %s:9000\n", host.c_str());
        return 1;
    }
    printf("connected over websocket -- /nick /join /who /quit\n");

    std::atomic<bool> gone{false};

    std::thread reader([&] {
        for (;;)
        {
            auto msg = c.recv();
            if (msg.error || msg.is_close)
            {
                gone = true;
                printf("server closed the connection\n");
                return;
            }
            if (!msg.data.empty())
            {
                // One frame, one line: WebSocket frames carry the payload
                // without the newline framing TCP clients see.
                if (msg.data.back() == '\n')
                    printf("%s", msg.data.c_str());
                else
                    printf("%s\n", msg.data.c_str());
            }
        }
    });

    std::string line;
    while (!gone && std::getline(std::cin, line))
    {
        if (!c.send(line))
            break;
        if (line == "/quit")
            break;
    }

    c.close();      // unblocks the reader's recv()
    reader.join();
    return 0;
}
