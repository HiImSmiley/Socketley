# chat-room

A browser chat where **one runtime on one port** serves the page, the WebSocket
and a plain TCP client — and the handler does not know which is which.

```
browser ──HTTP──> the page from www/
        ──WS────> the same port, upgraded
netcat  ──TCP───> the same port again, no upgrade
```

```bash
./run.sh
```

Then open `http://localhost:38090` for the real thing. The script proves all
three paths without a browser: it curls the page, drives the socket with
`wsclient.py`, and talks to the same port with `nc`.

## What makes this one runtime and not three

**WebSocket needs no flag.** It is detected per connection from the `Upgrade`
header. Frames are decoded before `on_client_message` sees them, so the same
handler serves a browser and a netcat session, and neither has to be told about
the other.

**The page comes from `--http` because this script does not define
`on_http_request`.** A server answers an HTTP request with `on_http_request` if
the script has one, with the static file server if `--http` is set, and 404
otherwise — in that order. Defining the callback here would take the page away
from `--http` and make `chat.lua` responsible for serving it.

## Two things the demo output will make you ask

**Both clients are called `guest10`.** `client_id` is a **file descriptor**, and
descriptors are reused: the WebSocket client gets 10, disconnects, and the
netcat client that connects next gets 10 again. It is a connection identifier,
not a user identifier. If you need one that outlives a connection, put it in
`self.set_data(id, ...)` at connect time and derive it from something the client
sends — a cookie reaches you in `on_websocket(id, headers)`.

**A joiner sees what was said before it arrived.** `chat.lua` keeps the last 20
lines and replays them on connect. That is deliberate, and it is also the whole
persistence story: the history and the nicknames live in Lua tables in this
process. They are gone when the runtime stops, and `--shards N` would give you N
independent chat rooms sharing a port, because a Lua table does not cross a
process boundary. The runtime is created without shards for that reason.

## The files

| File | What it is |
|---|---|
| `chat.lua` | The whole server: connect, message, disconnect, `/nick`, `/who`, `/quit` |
| `www/index.html` | The browser client. No build step, no framework, no dependencies |
| `wsclient.py` | RFC 6455 in one file, so `run.sh` can verify the socket without a browser |
| `run.sh` | Brings it up, exercises all three paths, removes everything |

## Where to go from here

- `../link-shortener/` — a TLS gateway in front of an HTTP API
- `../../server/websocket-session.lua` — session tracking from a browser cookie
- `../../server/http-dashboard.lua` — the same HTTP + WebSocket pairing, smaller
- `../../server/auth-token.lua` — refusing a connection before it can say anything
