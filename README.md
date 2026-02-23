# Socketley

A high-performance Linux daemon and CLI that manages network runtimes (servers, clients, proxies, Redis-compatible caches) in a Docker-like style - with clustering, TLS, WebSocket, Lua scripting, and io_uring async I/O.

**[Documentation](https://hiimsmiley.github.io/Socketley/)**

## About Me and the Project

Hi, I'm Smiley. This project was born out of a university module called Networked Systems, where I spent a lot of time working with Docker, proxies, sockets, caches, and the protocols that tie them all together. While reading into virtual threads, I stumbled upon Linux's io_uring interface and was immediately hooked.

What bothered me was how many moving parts you need to set up a proper networked system - separate tools for servers, proxies, caches, each with their own config and lifecycle. My goal with Socketley was to combine all of that into something simpler and more unified, at least in my opinion and hope.

I've been programming for over a decade, but this project pushed me into entirely new territory: io_uring internals, protocol design, benchmarking methodology, hot-path optimization, and rapid prototyping. It's also been my first deep dive into AI-assisted development with Claude Code, which has been a genuinely exciting experiment in seeing how far that workflow can go.

It's been an amazing journey so far, and I hope others see the same potential in this project that I do. I'll keep building with the same mindset and love I started with.

## Installation

### Quick install

```bash
curl -fsSL https://raw.githubusercontent.com/HiImSmiley/Socketley/main/install.sh | sudo sh
```

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

## What's Included

Beyond the CLI and daemon, there's a lot more in this repository:

- **[Web documentation](https://hiimsmiley.github.io/Socketley/)**: A full interactive documentation site covering every runtime type, flag, Lua callback, and addon pattern with working examples.
- **Interactive help**: Run `socketley --help` for a full interactive help system in your terminal, covering every command, flag, and runtime type.
- **Man page**: A complete `man socketley` page ships with the `.deb` package and is available in `man/`. It covers every command, flag, and configuration option.
- **C++ SDK**: The `include/linux/` directory provides headers (`socketley.h`, `server.h`, `client.h`, `proxy.h`, `cache.h`, etc.) so you can build your own custom C++ runtimes on top of Socketley's io_uring event loop and runtime lifecycle. Your custom runtimes can attach to a running daemon, giving them full access to the CLI, monitoring, state persistence, and interaction with other runtimes.
- **Persistent networks**: Runtime configurations are saved as JSON and automatically restored when the daemon restarts. You can build entire network topologies that survive reboots.
- **Working examples**: The `examples/` directory has ready-to-run scripts and Lua configs for every use case, from basic echo servers to SQLite-backed caches, auth middleware, reverse proxies, and multi-daemon clusters.

## Features

- **Server**:TCP/UDP listener with broadcast, WebSocket auto-detection, master mode
- **Client**:TCP/UDP connector with auto-reconnect
- **Proxy**:HTTP/TCP reverse proxy with round-robin, random, or Lua-based routing
- **Cache**:In-memory key-value store with strings, lists, sets, hashes, TTL, pub/sub, RESP2 (Redis wire protocol), LRU eviction, persistence, leader-follower replication, and DB-backend Lua hooks for read-through / write-behind caching
- **Lua scripting**:Per-runtime callbacks (`on_message`, `on_connect`, `on_auth`, `on_route`, etc.) with hot-reload, timers, HTTP client, cross-runtime pub/sub
- **Cluster mode**:Multi-daemon discovery via shared directory, `@group` backend routing, Lua cluster API
- **Master mode**:One client claims master, broadcasts to all; optional forwarding
- **HTTP static serving**:`--http <dir>` with auto-injected WebSocket, optional in-memory caching
- **TLS/SSL**:Optional encryption for all runtime types
- **WebSocket**:Auto-detected per connection, coexists with raw TCP on the same port
- **io_uring**:Multishot accept, SQPOLL, provided buffers, writev coalescing
- **State persistence**:Runtime configs saved as JSON, auto-restored on daemon restart
- **Ownership**:Parent-child runtime relationships with configurable `on_parent_stop` policies
- **Monitoring**:`socketley stats` for live metrics, `--rate-limit` and `--max-connections` for resource control

## Performance

All benchmarks: single-threaded, loopback TCP, Release build. Measured inside a Lima VM (4 vCPU / 3.8 GiB) on an Intel Core Ultra 5 125H, Linux 6.8. Bare-metal performance will be higher.

### Cache vs Redis 7.0 (RESP2, `redis-benchmark`)

> Both servers use the same Redis wire protocol (RESP2) and the same benchmark tool.
> Socketley is **single-threaded**. Redis 7.x is also single-threaded (event loop).

**Pipeline depth = 1** (one outstanding request per client, 50 clients, 200K ops each):

| Operation    | Socketley     | Redis 7.0     | Ratio  |
|-------------|---------------|---------------|--------|
| SET         | 182K ops/s    | 179K ops/s    | 1.0x   |
| GET         | 186K ops/s    | 184K ops/s    | 1.0x   |
| LPUSH       | 185K ops/s    | 189K ops/s    | 1.0x   |
| LPOP        | 188K ops/s    | 189K ops/s    | 1.0x   |
| SADD        | 190K ops/s    | 184K ops/s    | 1.0x   |
| HSET        | 200K ops/s    | 180K ops/s    | **1.1x** |

At P=1, throughput is dominated by loopback round-trip latency (~0.14 ms), both servers are essentially equivalent.

**Pipeline depth = 100** (100 pipelined requests, 50 clients, 2M ops each):

| Operation    | Socketley      | Redis 7.0     | Speedup   |
|-------------|----------------|---------------|-----------|
| SET         | **8.93M ops/s** | 3.14M ops/s  | **2.8x**  |
| GET         | **10.2M ops/s** | 4.01M ops/s  | **2.5x**  |
| LPUSH       | **8.20M ops/s** | 2.98M ops/s  | **2.8x**  |
| LPOP        | **10.4M ops/s** | 2.68M ops/s  | **3.9x**  |
| SADD        | **7.17M ops/s** | 3.67M ops/s  | **2.0x**  |
| HSET        | **8.30M ops/s** | 3.00M ops/s  | **2.8x**  |

Socketley is **2-4x faster than Redis 7** at sustained pipelined throughput.

The advantage comes from:
- **io_uring SQPOLL** eliminates all `epoll_wait`/`sendmsg` syscalls, zero syscalls per op in the hot path
- **Zero-allocation RESP2 codec**: parse and encode directly into/from the connection buffer using `to_chars` and `string_view`; no heap allocations per command
- **Batch CQE drain**: all completions from a submit round are processed in one pass; single `io_uring_cq_advance`
- **writev coalescing**: up to 16 responses batched into a single `writev` SQE

**Latency comparison** (P=100):

| Metric   | Socketley | Redis 7.0 |
|----------|-----------|-----------|
| p50 SET  | 0.30 ms   | 1.48 ms   |
| p50 GET  | 0.25 ms   | 1.14 ms   |
| p99 SET  | 0.82 ms   | 1.78 ms   |
| p99 GET  | 0.38 ms   | 1.40 ms   |

### Server: Connection Rate & Message Throughput

| Test                               | Result             |
|------------------------------------|--------------------|
| Connection rate (2000 conns)       | **75.7K conn/s**   |
| Burst (5000 simultaneous)          | **91.9K conn/s**   |
| Single client 64B msg throughput   | **474K msg/s** (29.4 MB/s) |
| Single client 1KB msg throughput   | **530K msg/s** (518 MB/s)  |
| 100 clients × 500 msgs (aggregate) | **3.32M msg/s**    |

5-run median, 10% warm-up, `clock_gettime(CLOCK_MONOTONIC)`. All on a single-threaded io_uring event loop with `IORING_SETUP_SQPOLL`.

### Proxy: TCP Forwarding

| Test                              | Result             |
|-----------------------------------|--------------------|
| TCP message throughput (128B)     | **463K msg/s** (57 MB/s) |
| 20 concurrent clients             | **1.07M msg/s**    |
| Named-runtime backend resolution  | **844K msg/s**     |

### WebSocket

| Test                              | Result             |
|-----------------------------------|--------------------|
| Handshake throughput (200 ops)    | **30.8K handshake/s** |
| Frame send throughput (64B)       | **581K frame/s** (38.8 MB/s) |
| 20 concurrent clients             | **63.0K handshake/s** |

## Quick Start

After installing (via `dpkg -i` or `install.sh`), the daemon runs as a systemd service — no manual startup needed:

```bash
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

## CLI Reference

```
socketley create <type> <name> [flags]    # types: server, client, proxy, cache
socketley attach <type> <name> <port>     # register an external process as a runtime
socketley start <name|pattern>... [-i]    # start runtime(s), -i for interactive
socketley stop <name|pattern>...          # stop runtime(s)
socketley remove <name|pattern>...        # remove runtime(s)
socketley send <name> [message]           # send/broadcast message
socketley stats <name|pattern>...         # show runtime statistics
socketley reload <name|pattern>...        # restart runtime
socketley reload-lua <name|pattern>...    # hot-reload Lua script
socketley show <name|pattern>...          # print JSON config
socketley edit <name> [flags]             # modify runtime config
socketley owner <name>                    # show parent/children/policy
socketley ls                              # list all runtimes
socketley ps                              # list running runtimes
socketley --lua <file.lua>                # run Lua orchestration script
socketley cluster ls|ps|group|show|stats|watch  # multi-daemon cluster inspection
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

## Cache: DB Backend

Four Lua callbacks connect the cache to any database, no built-in drivers, no rebuild required. Install whichever Lua DB library you prefer and implement the hooks you need.

| Callback | Signature | When |
|---|---|---|
| `on_miss(key)` | → `value [, ttl_seconds]` | GET miss, fetch from DB and populate cache |
| `on_write(key, value, ttl)` | → nothing | After SET / SETEX / SETNX / MSET |
| `on_delete(key)` | → nothing | After DEL |
| `on_expire(key)` | → nothing | After TTL sweep removes key |

```lua
-- sqlite-backend.lua  (luarocks install lsqlite3)
local db, pending = nil, {}
tick_ms = 2000  -- flush writes every 2 s

function on_start()
    db = require("lsqlite3").open("/tmp/cache.db")
    db:exec("CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT)")
end

function on_miss(key)   -- transparent fetch on GET miss
    for row in db:nrows("SELECT value FROM kv WHERE key=" .. db:quote(key)) do
        return row.value, 300   -- value + 300 s TTL
    end
end

function on_write(key, value, ttl)  -- write-behind: buffer, flush in on_tick
    pending[key] = value
end

function on_tick(dt)
    for k, v in pairs(pending) do
        db:exec("INSERT OR REPLACE INTO kv(key,value) VALUES("
                ..db:quote(k)..","..db:quote(v)..")")
    end
    pending = {}
end

function on_delete(key)
    db:exec("DELETE FROM kv WHERE key=" .. db:quote(key))
end
```

```bash
socketley create cache mydb -p 9000 --lua sqlite-backend.lua -s
```

See [`examples/cache/db-backend.lua`](examples/cache/db-backend.lua) for MySQL and PostgreSQL examples.

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

Apache 2.0
