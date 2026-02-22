# Socketley

A high-performance Linux daemon and CLI tool that manages long-living network runtimes (servers, clients, proxies, caches) in a Docker-like style. Written in C++ with io_uring for async I/O and Lua scripting via LuaJIT.

## Features

- **Server** -- TCP/UDP listener with broadcast, WebSocket auto-detection, master mode
- **Client** -- TCP/UDP connector with auto-reconnect
- **Proxy** -- HTTP/TCP reverse proxy with round-robin, random, or Lua-based routing
- **Cache** -- In-memory key-value store with strings, lists, sets, hashes, TTL, pub/sub, RESP2 (Redis wire protocol), LRU eviction, persistence, leader-follower replication, and DB-backend Lua hooks for read-through / write-behind caching
- **Lua scripting** -- Per-runtime callbacks (`on_message`, `on_connect`, `on_auth`, `on_route`, etc.) with hot-reload, timers, HTTP client, cross-runtime pub/sub
- **Cluster mode** -- Multi-daemon discovery via shared directory, `@group` backend routing, Lua cluster API
- **Master mode** -- One client claims master, broadcasts to all; optional forwarding
- **HTTP static serving** -- `--http <dir>` with auto-injected WebSocket, optional in-memory caching
- **TLS/SSL** -- Optional encryption for all runtime types
- **WebSocket** -- Auto-detected per connection, coexists with raw TCP on the same port
- **io_uring** -- Multishot accept, SQPOLL, provided buffers, writev coalescing
- **State persistence** -- Runtime configs saved as JSON, auto-restored on daemon restart
- **Ownership** -- Parent-child runtime relationships with configurable `on_parent_stop` policies
- **Monitoring** -- `socketley stats` for live metrics, `--rate-limit` and `--max-connections` for resource control

## Performance

All benchmarks: single-threaded, loopback TCP, Intel Core Ultra 5 125H, Linux 6.8, Release build.

### Cache — vs Redis 7.0 (RESP2, `redis-benchmark`)

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

At P=1, throughput is dominated by loopback round-trip latency (~0.14 ms) — both servers are essentially equivalent.

**Pipeline depth = 100** (100 pipelined requests, 50 clients, 2M ops each):

| Operation    | Socketley      | Redis 7.0     | Speedup   |
|-------------|----------------|---------------|-----------|
| SET         | **8.93M ops/s** | 3.14M ops/s  | **2.8x**  |
| GET         | **10.2M ops/s** | 4.01M ops/s  | **2.5x**  |
| LPUSH       | **8.20M ops/s** | 2.98M ops/s  | **2.8x**  |
| LPOP        | **10.4M ops/s** | 2.68M ops/s  | **3.9x**  |
| SADD        | **7.17M ops/s** | 3.67M ops/s  | **2.0x**  |
| HSET        | **8.30M ops/s** | 3.00M ops/s  | **2.8x**  |

Socketley is **2–4x faster than Redis 7** at sustained pipelined throughput.

The advantage comes from:
- **io_uring SQPOLL** eliminates all `epoll_wait`/`sendmsg` syscalls — zero syscalls per op in the hot path
- **Zero-allocation RESP2 codec** — parse and encode directly into/from the connection buffer using `to_chars` and `string_view`; no heap allocations per command
- **Batch CQE drain** — all completions from a submit round are processed in one pass; single `io_uring_cq_advance`
- **writev coalescing** — up to 16 responses batched into a single `writev` SQE

**Latency comparison** (P=100):

| Metric   | Socketley | Redis 7.0 |
|----------|-----------|-----------|
| p50 SET  | 0.30 ms   | 1.48 ms   |
| p50 GET  | 0.25 ms   | 1.14 ms   |
| p99 SET  | 0.82 ms   | 1.78 ms   |
| p99 GET  | 0.38 ms   | 1.40 ms   |

### Server — Connection Rate & Message Throughput

| Test                               | Result             |
|------------------------------------|--------------------|
| Connection rate (2000 conns)       | **72.9K conn/s**   |
| Burst (5000 simultaneous)          | **117.6K conn/s**  |
| Single client 64B msg throughput   | **719K msg/s** (44.6 MB/s) |
| Single client 1KB msg throughput   | **792K msg/s** (775 MB/s)  |
| 100 clients × 500 msgs (aggregate) | **3.12M msg/s**    |

All on a single-threaded io_uring event loop. `IORING_SETUP_SQPOLL` keeps the submission thread hot — no syscalls during sustained traffic.

### Proxy — Overhead vs Direct

| Test                              | Result             |
|-----------------------------------|--------------------|
| TCP message throughput            | **49.2K msg/s** (5.9 MB/s) |
| 20 concurrent clients             | **62.5K msg/s**    |
| Latency overhead vs direct        | **+5.5%**          |
| Named-runtime backend resolution  | **50.0K req/s**    |

The proxy adds roughly 2 ms median latency on top of the direct path — mostly loopback TCP overhead, not protocol processing.

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

## CLI Reference

```
socketley daemon [--name <n>] [--cluster <dir>]  # start the daemon
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

## Cache — DB Backend

Four Lua callbacks connect the cache to any database — no built-in drivers, no rebuild required. Install whichever Lua DB library you prefer and implement the hooks you need.

| Callback | Signature | When |
|---|---|---|
| `on_miss(key)` | → `value [, ttl_seconds]` | GET miss — fetch from DB and populate cache |
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

See [`socketley/examples/cache/db-backend.lua`](socketley/examples/cache/db-backend.lua) for MySQL and PostgreSQL examples.

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
