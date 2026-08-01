# Proxy Examples

HTTP and TCP reverse proxy configurations with load balancing.

## Prerequisites

The daemon must be running. When installed via package, it runs as a systemd service automatically. In dev mode, start it manually: `./bin/Release/socketley daemon &`

## Examples

### HTTP Proxy
Basic HTTP reverse proxy with path-based routing.

### Load Balancer
Round-robin and random load balancing across backends.

### TCP Proxy
Raw TCP byte forwarding without HTTP parsing.

### TLS Proxy
TLS on the proxy's own listener, on the leg to an `https://` backend, or both,
with mutual TLS in either direction. The backend leg always verifies the chain
and the endpoint's name and cannot be told not to.

### Group Discovery
Dynamic backend discovery using runtime groups (`-g` and `@group`).

### Multi-Backend Lua
Custom routing logic with Lua scripts.

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
