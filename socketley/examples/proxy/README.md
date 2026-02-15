# Proxy Examples

HTTP and TCP reverse proxy configurations with load balancing.

## Prerequisites

```bash
socketley daemon &
```

## Examples

### HTTP Proxy
Basic HTTP reverse proxy with path-based routing.

### Load Balancer
Round-robin and random load balancing across backends.

### TCP Proxy
Raw TCP byte forwarding without HTTP parsing.

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
- Runtime name: `api-server` (resolved via runtime_manager)

### Load Balancing Strategies

| Strategy | Behavior |
|----------|----------|
| `round-robin` | Sequential distribution (default) |
| `random` | Random backend selection |
| `lua` | Custom logic via `on_route()` callback |
