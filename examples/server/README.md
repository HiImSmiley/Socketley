# Server examples

Everything here attaches to a `server` runtime. The `.sh` files create and drive
a runtime themselves; the `.lua` files are **handlers** — you attach one with
`--lua` and the daemon loads it:

```bash
socketley create server demo -p 9000 --lua auth-token.lua -s
```

A handler is not a configuration. A callback written into a file passed to
`socketley --lua` at the CLI is never loaded and never called — that distinction
is the whole subject of [`../lua-config/README.md`](../lua-config/README.md),
and it is the mistake this directory exists to keep you out of.

## Scripts you run

| File | What it shows |
|---|---|
| `sharded-server.sh` | `--shards N`: N worker processes on one port through `SO_REUSEPORT`, still one runtime. Also what the flag refuses, and why — `--listen unix:` is incompatible with it |
| `tls-server.sh` | TLS on a listener, and mutual TLS with `--ca`. Also what fails closed: an incomplete key pair, a certificate with no `--tls` |

## Handlers you attach

| File | What it shows |
|---|---|
| `auth-token.lua` | First-message token authentication, using `self.disconnect` |
| `auth-ip-allowlist.lua` | An IP allowlist in `on_auth`, using `self.peer_ip` |
| `rate-limit.lua` | Per-client rate limiting from `on_tick` |
| `session-ids.lua` | A session id per connection, for end-to-end tracing |
| `websocket-session.lua` | Session tracking from a browser `Cookie` header |
| `redis-session.lua` | Distributed sessions against an **external Redis**, not a socketley cache. Needs `luarocks install redis-lua`, installed where LuaJIT looks — see the note at the top of the file, and be aware a `require` that cannot resolve fails the script load and the runtime never serves |
| `large-body-paced.lua` | Sending a body past the write-queue bound, pacing on `self.pending`/`self.watermark` and resuming in `on_writable` |
| `upstream-hub.lua` | Bridging connected clients and an `--upstream` connection |
| `service-discovery.lua` | Registering with Consul from `on_start`/`on_stop`, using `socketley.http` |
| `http-dashboard.lua` | HTTP plus WebSocket in one listener; serves `http-dashboard/` |
| `message-counter.lua` | Counting messages in `on_message` — and what its own number is worth |

## Two things worth knowing before you start

**`socketley.http` blocks the event loop.** `service-discovery.lua` uses it in
`on_start` and `on_stop` deliberately: those run once. Calling it from
`on_message` stalls every runtime in that process for the length of the request.

**WebSocket needs no flag.** It is detected per connection, and a WebSocket
client and a raw TCP client can be served by the same listener at the same time.
