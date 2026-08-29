# Socketley Examples

This directory contains practical examples demonstrating all features of socketley.

## Directory Structure

```
examples/
├── basic/              # Getting started, minimal setups
├── server-client/      # Server-client communication patterns
├── server/             # Server flags, and the Lua handlers you attach to one
├── proxy/              # HTTP/TCP proxy configurations
├── cache/              # Caching, persistence, sharding
├── lua-config/         # Lua configuration and scripting
├── cluster/            # Several daemons discovering each other
├── managed/            # Binaries the daemon supervises, via `socketley add`
├── udp/                # UDP server/client examples
├── advanced/           # Complex multi-runtime setups
└── projects/           # Complete systems you can run, not single features
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
- `sharded-server.sh` - `--shards N` on a server: N worker processes on one
  port through `SO_REUSEPORT`, still one runtime. Only without `--lua`, and
  the example shows what is refused and why
- `tls-server.sh` - TLS on a server listener, plus mutual TLS; also shows what
  is refused (TLS on a cache, and any incomplete key pair)
- `auth-token.lua`, `auth-ip-allowlist.lua` - connection authorisation
- `rate-limit.lua`, `session-ids.lua`, `websocket-session.lua` - per-connection state
- `upstream-hub.lua`, `service-discovery.lua` - upstream and discovery patterns
- `http-dashboard.lua` - HTTP + WebSocket dashboard, serving `http-dashboard/`
- `redis-session.lua` - distributed sessions against an **external** Redis via
  `redis-lua`; needs a luarocks install, and an unresolvable `require` fails the
  script load so the runtime never serves
- `message-counter.lua` - counting in `on_message`, and what its own rate figure
  is worth given `os.time()` resolves to one second
- `README.md` - what each of the above is, and the handler-vs-configuration trap

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
- `sharded-cache.sh` - `--shards N` on a cache: N worker processes on one port,
  and still ONE keyspace — a key belongs to the shard its hash falls to, and a
  command naming another shard's key is answered by that shard. Shows the
  keyspace-wide commands answering for the runtime, the per-shard dumps, and a
  restart at a different shard count with every key still there

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
`socketley add` registers a binary you built yourself, and the daemon then
supervises it like any other runtime. Most of the programs here are plain
sockets — only the two marked below reach for the SDK wrapper.

- `echo-service.cpp` - Minimal C++ echo server, plain sockets
- `01-add-and-run.sh` - Register and start a managed binary
- `02-auto-restart.sh` - Daemon auto-restarts crashed binaries
- `03-stop-start-cycle.sh` - Full lifecycle: add, stop, start, remove
- `chat-server.cpp` - Chat server using wrapper API (`socketley::server`)
- `04-managed-chat.sh` - Managed chat with auto-restart demo
- `counter-server.cpp` - Per-connection counter using wrapper API
- `05-managed-counter.sh` - Managed counter with stop/start lifecycle

### UDP
- `udp-echo.sh` - Fire-and-forget UDP messaging

### Projects
Complete little systems rather than one flag each. Every one of these runs on its
own daemon, on its own socket, and removes what it made on the way out.

- `link-shortener/` - a TLS gateway in front of an HTTP API. Exercises
  `on_http_request`, TLS termination, health checks, a circuit breaker and
  retries, and states plainly what it cannot do: the links live in a Lua table,
  so they do not survive a restart and would not survive `--shards` either
- `chat-room/` - a browser chat where one runtime on one port serves the page,
  the WebSocket and a plain TCP client, and the handler does not know which is
  which. Ships its own RFC 6455 client so `run.sh` can verify the socket without
  a browser

### Cluster
- `docker-compose.yml` - three daemons in three containers sharing a volume;
  this is the real shape of cluster mode
- `01-local-cluster.sh` - the same topology **simulated** on one machine, which
  is why every command in it carries its own `SOCKETLEY_SOCKET`
- `README.md` - what discovery resolves, and what it is not (no leader, no
  quorum, and a partition nobody reports)

### Advanced
- `io-tuning.sh` - `--cpus` and `--sqpoll`: where a runtime's I/O runs, and
  whether its ring carries a polling kernel thread
- `microservices.lua` + `microservices-handler.lua` - Microservice architecture
- `high-availability.lua` + `high-availability-handler.lua` - HA with failover
- `logging-pipeline.lua` + `logging-pipeline-handler.lua` - Centralized logging
- `development-env.lua` + `development-env-handler.lua` - Development stack
- `game-routing.lua` + `game-routing-handler.lua` - A lobby that creates and
  routes to sub-servers. The lobby needed `daemon_process = true` and no longer
  does; see the file
  for why

### Registered Types (SDK)
- `sdk/examples/custom-type/` - a runtime type of your own: a TOML manifest the
  daemon reads (name, worker binary, config-key schema) plus a worker built
  with `<socketley/worker.h>`. The daemon never loads your code — it forks and
  execs the binary like its own workers. See REGISTERED TYPES in `man socketley`
