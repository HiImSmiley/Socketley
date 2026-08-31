# chatroom — rooms, presence, and two transports on one port

A chat service that uses the whole server wrapper, not one callback: multicast
groups as rooms, per-connection data as presence, the tick as slow-cadence
housekeeping, and the listener's dual protocol — the same port serves
newline-framed TCP (`nc`) and WebSocket (a browser, or the cross-platform
`ws_client.h`) with the room logic never knowing which transport a member
arrived on.

```
 nc ──────────────┐
 browser (ws) ────┤──►  chatd :9000 ── rooms via join_group/group_send
 chat_cli (ws) ───┘        │            presence via set_data/get_data
                           └─ on_websocket sees the upgrade headers
```

| file | role | needs |
|---|---|---|
| `chatd.cpp` | the service: rooms, presence, commands | `libsocketley_sdk.a` (Tier 2 wrapper) |
| `chat_cli.cpp` | terminal client over real RFC 6455 WebSocket | one header, any OS |

## Build

```bash
g++ -std=c++23 sdk/examples/projects/chatroom/chatd.cpp \
    $(sdk/socketley-config --cflags --libs) -o chatd

g++ -std=c++17 sdk/examples/projects/chatroom/chat_cli.cpp \
    $(sdk/socketley-config --cflags --libs) -o chat_cli
```

## Run

```bash
./chatd
# terminal 2:            # terminal 3:
nc 127.0.0.1 9000        ./chat_cli
/nick alice              /join dev
hello lobby              /who
/join dev                anyone here?
```

Members in the same room see each other's lines regardless of transport, and
`chatd`'s own log shows which connections arrived by WebSocket upgrade.

## What this example is really about

- **`mode_in` is load-bearing.** The wrapper's default (`mode_inout`) makes
  the server a hub: every inbound line is *also* relayed raw to every other
  client, on top of what `on_message` sends — each chat line would arrive
  twice. A server whose `on_message` IS the protocol turns the relay off.
- **Rooms are groups.** `join_group` / `leave_group` / `group_send` is the
  multicast machinery; the example never keeps its own member lists.
- **Presence is connection data.** `set_data(fd, "nick", …)` /
  `set_data(fd, "room", …)` lives with the connection and vanishes with it —
  no map to keep consistent with disconnects.
- **One port, two protocols.** The server detects the WebSocket handshake by
  itself and decodes frames before `on_message`; `on_websocket` is where the
  upgrade headers (origin, cookie, protocol, auth) are readable.
- **The tick is a janitor, not a scheduler.** Transport-level reaping belongs
  to `idle_timeout`; the tick is for the slow-cadence work a service grows.
