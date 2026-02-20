# Socketley

A high-performance Linux daemon and CLI tool that manages long-living network runtimes (servers, clients, proxies, caches) in a Docker-like style. Written in C++ with io_uring for async I/O and Lua scripting via LuaJIT.

## Features

- **Server** -- TCP/UDP listener with broadcast, WebSocket auto-detection, master mode
- **Client** -- TCP/UDP connector with auto-reconnect
- **Proxy** -- HTTP/TCP reverse proxy with round-robin, random, or Lua-based routing
- **Cache** -- In-memory key-value store with strings, lists, sets, hashes, TTL, pub/sub, RESP2 (Redis wire protocol), LRU eviction, persistence, and leader-follower replication
- **Lua scripting** -- Per-runtime callbacks (`on_message`, `on_connect`, `on_route`, etc.) with hot-reload
- **TLS/SSL** -- Optional encryption for all runtime types
- **WebSocket** -- Auto-detected per connection, coexists with raw TCP on the same port
- **io_uring** -- Multishot accept, SQPOLL, provided buffers, writev coalescing
- **State persistence** -- Runtime configs saved as JSON, auto-restored on daemon restart
- **Monitoring** -- `socketley stats` for live metrics, `--rate-limit` and `--max-connections` for resource control

## Performance

Benchmarked against Redis 7.x on the same hardware (single-threaded, TCP):

| Operation | Socketley | Redis | Speedup |
|-----------|-----------|-------|---------|
| STRING SET 64B | 1.93M ops/s | 641K ops/s | **3.0x** |
| STRING GET | 11.0M ops/s | 2.08M ops/s | **5.3x** |
| LIST LPUSH | 8.77M ops/s | 1.38M ops/s | **6.4x** |
| LIST LPOP | 15.2M ops/s | 1.75M ops/s | **8.7x** |
| SET SADD | 4.06M ops/s | 1.28M ops/s | **3.2x** |
| HASH HSET | 3.76M ops/s | 957K ops/s | **3.9x** |
| Pipeline depth=5000 | 0.81 us/op | 1.78 us/op | **2.2x** |

Server: ~87K connections/sec burst, ~4.3M messages/sec concurrent (100 clients).

## Quick Start

```bash
# Build
./bin/premake5 gmake2
cd make && make config=release_x64 -j$(nproc)

# Start daemon
./bin/Release/socketley daemon &

# Create and start a server
socketley create server myapp -p 9000 -s

# Send a message (broadcasts to all connected clients)
socketley send myapp "Hello, world!"

# Create a cache (Redis-compatible)
socketley create cache db -p 6379 --resp -s
redis-cli -p 6379 SET mykey myval
redis-cli -p 6379 GET mykey

# Create a reverse proxy
socketley create proxy gw -p 8080 --backend 127.0.0.1:9000 -s

# List all runtimes
socketley ls

# View stats
socketley stats myapp
```

## Installation

### From source

```bash
# Dependencies (Ubuntu/Debian)
sudo apt install build-essential liburing-dev libssl-dev

# Build
./bin/premake5 gmake2
cd make && make config=release_x64 -j$(nproc)

# Install system-wide (optional)
sudo bash packaging/install.sh
```

### Debian package

```bash
bash packaging/build-deb.sh
sudo dpkg -i socketley_*.deb
```

## CLI Reference

```
socketley create <type> <name> [flags]    # types: server, client, proxy, cache
socketley start <name|pattern>... [-i]    # start runtime(s), -i for interactive
socketley stop <name|pattern>...          # stop runtime(s)
socketley remove <name|pattern>...        # remove runtime(s)
socketley send <name> [message]           # send/broadcast message
socketley stats <name|pattern>...         # show runtime statistics
socketley reload <name|pattern>...        # restart runtime
socketley reload-lua <name|pattern>...    # hot-reload Lua script
socketley show <name|pattern>...          # print JSON config
socketley edit <name> [flags]             # modify runtime config
socketley ls                              # list all runtimes
socketley ps                              # list running runtimes
```

Glob patterns supported: `socketley stop "api-*"` stops all runtimes matching `api-*`.

See `socketley --help` or `man socketley` for full documentation.

## Lua Scripting

```lua
-- example.lua
function on_start()
    socketley.log("Server started on port " .. self.port)
end

function on_message(msg)
    socketley.log("Received: " .. msg)
    self.broadcast("Echo: " .. msg)
end

function on_connect(client_id)
    self.send(client_id, "Welcome!")
end
```

```bash
socketley create server echo -p 9000 --lua example.lua -s
```

## Testing

```bash
# Unit tests
./bin/Release/test_command_hashing
./bin/Release/test_cache_store
./bin/Release/test_resp_parser
./bin/Release/test_ws_parser

# Integration tests (starts daemon automatically)
bash test/run_all.sh

# Benchmarks
bash test/benchmark/run_all.sh
```

## Architecture

- Single-binary daemon + CLI communicating via Unix socket IPC
- io_uring event loop (single-threaded, SQPOLL)
- All runtimes managed in-process (no subprocess spawning)
- FNV-1a hash switching for zero-allocation command dispatch
- sol2/LuaJIT for Lua callbacks
- Everything statically linked for portability

## Requirements

- Linux 5.19+ (for io_uring multishot accept)
- liburing-dev
- libssl-dev (for TLS and WebSocket)
- GCC 12+ or Clang 15+ (C++23)

## License

MIT
