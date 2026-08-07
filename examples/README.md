# Socketley Examples

This directory contains practical examples demonstrating all features of socketley.

## Directory Structure

```
examples/
├── basic/              # Getting started, minimal setups
├── server-client/      # Server-client communication patterns
├── proxy/              # HTTP/TCP proxy configurations
├── cache/              # Caching with persistence
├── lua-config/         # Lua configuration and scripting
├── managed/            # Managed external binaries (C++ SDK)
├── udp/                # UDP server/client examples
└── advanced/           # Complex multi-runtime setups
```

## Quick Start

1. **Ensure the daemon is running.** When installed via package, it runs as a systemd service automatically. In dev mode, start it manually: `./bin/Release/socketley daemon &`

2. **Choose an example** and follow its README.

3. **Clean up** when done:
   ```bash
   socketley ls                    # See all runtimes
   socketley stop <name>           # Stop each runtime
   socketley remove <name>         # Remove each runtime
   ```

## Examples Overview

### Basic
- `01-hello-server.sh` - Your first server
- `02-hello-client.sh` - Your first client
- `03-combined.sh` - Server + client together

### Server-Client
- `echo-server.sh` - Echo server pattern
- `broadcast.sh` - One-to-many messaging
- `bidirectional.sh` - Full duplex communication
- `modes.sh` - in/out/inout message modes
- `tls-client.sh` - a client that dials its target over TLS, with the chain and
  the host name verified; also mutual TLS and what is refused

### Server
- `tls-server.sh` - TLS on a server listener, plus mutual TLS; also shows what
  is refused (TLS on a cache, and any incomplete key pair)
- `auth-token.lua`, `auth-ip-allowlist.lua` - connection authorisation
- `rate-limit.lua`, `session-ids.lua`, `websocket-session.lua` - per-connection state
- `upstream-hub.lua`, `service-discovery.lua` - upstream and discovery patterns
- `http-dashboard.lua` - HTTP + WebSocket dashboard

### Proxy
- `http-proxy.sh` - Basic HTTP reverse proxy
- `load-balancer.sh` - Round-robin load balancing
- `group-discovery.sh` - Dynamic backends with `@group` discovery
- `tcp-proxy.sh` - Raw TCP byte forwarding
- `tls-proxy.sh` - TLS on both legs: the proxy's own listener, and an
  `https://` backend whose chain and name are verified
- `multi-backend.lua` + `multi-backend-handler.lua` - Method- and path-based
  backend selection. Needs `--strategy lua`; the config sets it

### Cache
- `basic-cache.sh` - In-memory key-value store
- `persistent-cache.sh` - Cache with file persistence
- `cache-integration.lua` + `cache-integration-handler.lua` - A cache as shared
  state, reached by a server's clients over `--cache`

### Lua Config
Each of these is a **pair**: a configuration read by the CLI, and a handler
loaded by the daemon. A callback written in the configuration is never loaded
and never called — see `lua-config/README.md`.

- `simple-config.lua` + `simple-config-handler.lua` - Basic Lua configuration
- `callbacks.lua` + `callbacks-handler.lua` - Event callbacks (on_start,
  on_stop, on_message, on_send)
- `custom-routing.lua` + `custom-routing-handler.lua` - Lua-based proxy routing
- `full-setup.lua` + `full-setup-handler.lua` - Complete orchestration
- `callbacks-connect.lua` - A handler on its own, attached with
  `create ... --lua`

### Managed External Runtimes
- `echo-service.cpp` - Minimal C++ echo server using the SDK
- `01-add-and-run.sh` - Register and start a managed binary
- `02-auto-restart.sh` - Daemon auto-restarts crashed binaries
- `03-stop-start-cycle.sh` - Full lifecycle: add, stop, start, remove
- `chat-server.cpp` - Chat server using wrapper API (`socketley::server`)
- `04-managed-chat.sh` - Managed chat with auto-restart demo
- `counter-server.cpp` - Per-connection counter using wrapper API
- `05-managed-counter.sh` - Managed counter with stop/start lifecycle

### UDP
- `udp-echo.sh` - Fire-and-forget UDP messaging

### Advanced
- `io-tuning.sh` - `--cpus` and `--sqpoll`: where a runtime's I/O runs, and
  whether its ring carries a polling kernel thread
- `microservices.lua` + `microservices-handler.lua` - Microservice architecture
- `high-availability.lua` + `high-availability-handler.lua` - HA with failover
- `logging-pipeline.lua` + `logging-pipeline-handler.lua` - Centralized logging
- `development-env.lua` + `development-env-handler.lua` - Development stack
- `game-routing.lua` - A lobby that creates and routes to sub-servers. Must be
  created with `--daemon-process`; see the file for why
