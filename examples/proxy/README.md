# Proxy Examples

HTTP and TCP reverse proxy configurations with load balancing.

## Prerequisites

The daemon must be running. When installed via package, it runs as a systemd service automatically. In dev mode, start it manually: `./bin/Release/socketley daemon &`

## Examples

### HTTP Proxy
Basic HTTP reverse proxy with path-based routing. `ws://` works through it on
the same port with no extra flag: an upgrade request keeps the two headers that
constitute the offer, the backend's `101` is relayed verbatim, and the
connection becomes a byte relay until one end closes. The proxy never parses a
frame — see `LIMITATIONS` in the man page for what follows from that.

### Load Balancer
Round-robin and random load balancing across backends.

### TCP Proxy
Raw TCP byte forwarding without HTTP parsing.

### Sharded Proxy
`--shards N` serves one proxy from N worker processes sharing its listening
socket through `SO_REUSEPORT` — the only way a single runtime uses more than the
one core its event loop runs on. It stays one runtime: `ls` shows one line,
`stats` sums the connection count across the shards, `stop` takes all of them
down. It is a declaration, and it is offered only where an operator can make
it: a cache refuses it because N shards would be N separate stores behind one
port, a client because it has no listener to share, and a server may shard only
when it has no `--lua` — with a script the state being split would be the
script's own, and it splits silently. See `../server/sharded-server.sh`.
`SO_REUSEPORT` balances per connection, not per request.

### Unix Socket Sidecar
`--backend unix:/path/to.sock` on the proxy and `--listen unix:/path/to.sock` on
the server, so a sidecar and the process it fronts talk without a loopback TCP
stack between them. Measured on a quiet machine, 64-byte round trips through the
proxy: one connection unpinned, 41.4 us over TCP against 37.0 us over AF_UNIX;
eight connections unpinned, 66,620 round trips a second against 85,217. What the
swap removes is CPU — 17.5 us per round trip across proxy and backend over TCP
against 14.5 over AF_UNIX — so it reads as a fifth of the throughput under load
and as almost nothing (21.5 us against 20.7) for one serial connection on one
core, where the round trip is waiting on wakeups and freed CPU has nothing to
do. The backend can be named by path or by runtime name. The socket node is
created `0600`, so both ends must run as the same user; there is no flag to
widen it, and TLS to a unix backend is refused rather than ignored.

### TLS Proxy
TLS on the proxy's own listener, on the leg to an `https://` backend, or both,
with mutual TLS in either direction. The backend leg always verifies the chain
and the endpoint's name and cannot be told not to.

### Group Discovery
Dynamic backend discovery using runtime groups (`-g` and `@group`).

### Multi-Backend Lua
Custom routing logic with Lua scripts.

### Filter Chain
Authentication, per-IP rate limiting and header rewriting as a chain of filters
that runs *before* a backend is chosen — so a refused request never opens one.

### Declared Routes
A handler states the paths it answers and the methods allowed on each; the
daemon publishes that declaration to the proxies in front of it, which refuse an
undeclared method at the edge with `405` and an `Allow` header. Declared in the
handler's script, not on the proxy — a method list written down in two runtimes
is one truth in two places, and two places drift.

## Key Concepts

### Path-Based Routing (HTTP Mode)
In HTTP mode, requests to `/<proxy-name>/*` are forwarded with the prefix stripped:

```
Client Request:  GET /gateway/api/users HTTP/1.1
Proxy Name:      gateway
Backend Request: GET /api/users HTTP/1.1
```

### Backend Resolution
Backends can be specified as:
- IP:Port: `127.0.0.1:9001`
- URL: `https://10.0.0.7:8443` (reached over TLS) or `http://…` (cleartext)
- Runtime name: `api-server` (resolved via runtime_manager)
- Group reference: `@api` (dynamically discovers all running members of group `api`)

Group backends are resolved at connection time, so new members are picked up
automatically without restarting the proxy.

### Load Balancing Strategies

| Strategy | Behavior |
|----------|----------|
| `round-robin` | Sequential distribution (default) |
| `random` | Random backend selection |
| `lua` | Custom logic via `on_route()` callback |

### Backend Response Deadline (HTTP Mode)

Every HTTP proxy has `--backend-timeout` set to 2 seconds unless told otherwise.
It bounds how long a backend may take to send the **first byte** of a response —
not how long the response body may take, and not TCP mode, which has no request
boundary to measure from. On expiry the request is retried if `--retry` allows
it, answered `504 Gateway Timeout` otherwise, and the backend is charged an
error so the circuit breaker can take it out of rotation.

This is the only check that catches a backend which accepts connections and then
never answers: a TCP health check connects to such a process quite happily.

If a backend normally needs longer than 2 seconds to *begin* answering, raise the
deadline or switch it off — otherwise working requests are cut short and a
healthy backend gets circuit-broken:

```bash
socketley create proxy slowapi -p 8080 --backend 127.0.0.1:9001 \
    --backend-timeout 30 -s      # 0 disables the deadline entirely
```

`--sidecar` does not set this flag, but it does enable the circuit breaker the
expiry feeds, so pass `--backend-timeout` alongside it for slow applications.
