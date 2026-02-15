# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Socketley is a Linux-only central daemon and CLI tool that manages long-living network runtimes (server, client, proxy, cache) in a Docker-like style — persistent configurations, simple management, user-friendly CLI. Written in C++ (C++latest, C17) with Lua scripting via sol2/LuaJIT. Everything is statically linked for portability. Performance-critical paths use io_uring for async I/O.

## Build Commands

```bash
# Generate Makefiles (run from project root)
./bin/premake5 gmake2

# Build from make/ directory
cd make
make config=debug_x64        # Debug build
make config=release_x64      # Release build
make clean                   # Clean artifacts
```

Output goes to `bin/Debug/` or `bin/Release/`.

### Running Tests

```bash
# Unit tests (doctest)
./bin/Release/test_command_hashing
./bin/Release/test_cache_store
./bin/Release/test_resp_parser

# Integration tests (requires daemon)
bash test/run_all.sh

# Or individual integration tests
bash test/integration/test_basic.sh
bash test/integration/test_cache.sh
bash test/integration/test_pubsub.sh
bash test/integration/test_stats.sh
bash test/integration/test_lua_callbacks.sh
```

## CLI Usage

```bash
socketley create <type> <name> [flags]   # types: server, client, proxy, cache
socketley start <name|pattern>... [-i]   # start runtime(s) (glob patterns, -i = interactive)
socketley stop <name|pattern>...         # stop runtime(s) (glob patterns supported)
socketley remove <name|pattern>...       # remove runtime(s) (glob patterns supported)
socketley send <name> [message]          # send/broadcast message (stdin supported)
socketley stats <name|pattern>...        # show runtime statistics (glob patterns)
socketley reload <name|pattern>...       # restart runtime (stop + start)
socketley reload-lua <name|pattern>...   # hot-reload Lua script (glob patterns)
socketley show <name|pattern>...         # print JSON config (glob patterns)
socketley edit <name>                    # open config in $EDITOR (interactive)
socketley edit <name> -r                 # interactive edit + auto-reload Lua
socketley edit <name> [flags]            # flag-based edit (e.g. -p 9001)
socketley ls                             # all runtimes (Docker-style table)
socketley ps                             # running runtimes only
socketley --config <lua_file>            # load Lua orchestration config
```

### Start flags

- `-i` — interactive mode: opens a live terminal session (stdin/stdout). Server: stdin broadcasts, stdout shows received messages. Client: stdin sends, stdout shows received. Cache: stdin accepts commands, stdout shows responses (like redis-cli). Ctrl+C to detach. Not supported for proxy. Works on already-running runtimes (attach without restart).

### Daemon flags

- `--log-level <debug|info|warn|error>` — set log verbosity (default: info)

### Common flags (all runtime types)

- `-p <port>` — listener/connection port
- `-s` — start immediately after creation
- `--test` — dry run, validate without starting
- `--log <file>` — log state transitions (created, running, stopped, failed)
- `-w <file>` — write every message to file
- `--config <lua_file>` — attach Lua config with callbacks (alias: `--lua`)
- `-b` — output received messages to stdout (bash mode)
- `-bp` — output with runtime name prefix: `[name] message`
- `-bt` — output with timestamp: `[HH:MM:SS] message`
- `-bpt` — output with both: `[HH:MM:SS] [name] message`
- `--max-connections <n>` — limit concurrent connections (0 = unlimited, default). Alias: `--max-conn`
- `--rate-limit <n>` — messages/sec per connection via token bucket (0 = unlimited, default)
- `--drain` — graceful shutdown: flush pending writes before closing connections
- `--tls` — enable TLS encryption (requires `--cert` + `--key` or `--ca`)
- `--cert <file>` — TLS certificate (PEM)
- `--key <file>` — TLS private key (PEM)
- `--ca <file>` — TLS CA certificate

### Type-specific flags

**Server/Client:** `--mode <inout|in|out|master>` (message flow direction), `--udp` (use UDP instead of TCP)

**Server (master mode):**
- `--master-pw <password>` — static password for master authentication
- `--master-forward` — forward non-master messages to master as `[<fd>] msg`

**Client:** `-t <host:port>` (target server)

**Cache:**
- `--persistent <file>` — persistent storage file
- `--maxmemory <size>` — max memory (supports K/M/G suffixes, e.g. `256M`)
- `--eviction <noeviction|allkeys-lru|allkeys-random>` — eviction policy when maxmemory reached
- `--resp` — force RESP2 protocol (Redis wire protocol) for all connections
- `--replicate <host:port>` — connect as follower to a leader cache

**Proxy:**
- `--backend <addr>` — Backend (repeatable, comma-separated). `<addr>` = `ip:port` or runtime name
- `--strategy <round-robin|random|lua>` — Load-Balancing (default: round-robin)
- `--protocol <http|tcp>` — Protocol mode (default: http)

**Auto-detected features (no flags):**
- **WebSocket**: Per-connection auto-detection from HTTP upgrade headers. Raw TCP and WebSocket clients coexist on the same port. Browser JS `new WebSocket("ws://host:port")` works transparently.
- **Cache access**: Clients send `cache <cmd>` through a `--cache`-linked server. Response sent to sender only, never broadcast.

Flags combine freely — e.g. create a client, start it immediately, connect to a cache, enable logging, send an initial message, and run Lua callbacks all in one command.

### Proxy Examples

```bash
# HTTP proxy with path-based routing (requests to /gw/* forwarded to backend)
socketley create proxy gw -p 8080 --backend 127.0.0.1:9001 -s
curl localhost:8080/gw/api/data  # → forwarded to 127.0.0.1:9001/api/data

# Round-robin load balancing across multiple backends
socketley create proxy lb -p 8080 --backend 127.0.0.1:9001,127.0.0.1:9002 --strategy round-robin -s

# Backend by runtime name (resolves port from runtime_manager)
socketley create server api1 -p 9001 -s
socketley create proxy gw -p 8080 --backend api1 -s

# TCP mode (bidirectional byte forwarding, no HTTP parsing)
socketley create proxy tcpgw -p 8080 --backend 127.0.0.1:9001 --protocol tcp -s
```

### Master Mode Examples

```bash
# One controller, many viewers
socketley create server broadcast -p 9000 --mode master --master-pw secret -s
# Client sends "master secret" → "master: ok", then messages broadcast
# Non-master messages silently dropped

# With forwarding (non-master messages forwarded to master)
socketley create server ctrl -p 9000 --mode master --master-pw admin --master-forward -s

# Lua auth (use --config with on_master_auth callback)
```

### WebSocket Examples

```bash
# WebSocket auto-detected, no flags needed
socketley create server ws -p 9000 -s

# Browser JavaScript:
# const ws = new WebSocket("ws://localhost:9000");
# ws.onmessage = e => console.log(e.data);
# ws.send("hello");

# Raw TCP clients also work on the same port
echo "hello" | nc localhost 9000
```

### Cache Access via Server

```bash
# Link server to cache
socketley create cache db -p 9001 -s
socketley create server api -p 9000 --cache db -s

# Clients send "cache <cmd>" for direct cache access
echo "cache set user:1 alice" | nc localhost 9000  # → ok
echo "cache get user:1" | nc localhost 9000        # → alice
echo "hello" | nc localhost 9000                    # → broadcast as usual
```

### ls/ps Output Format

```
ID        NAME          TYPE    PORT    CONN  STATUS              CREATED
a1b2c3    api-server    server  9000    3     Up 2 hours          3 hours ago
d4e5f6    my-client     client  -       1     Up 45 minutes       1 hour ago
g7h8i9    gateway       proxy   8080    12    Stopped             2 days ago
```

- **ID**: 6-char hex identifier (like Docker short IDs)
- **CONN**: Active connections (server: clients, proxy: client connections, client: 0/1, cache: clients)
- **STATUS**: "Up X time" for running, "Created/Stopped/Failed" otherwise

### Bash Output Examples

```bash
# Raw message output
socketley create server echo -p 9000 -b -s
# → Daemon stdout: hello world

# With prefix and timestamp
socketley create server echo -p 9000 -bpt -s
# → Daemon stdout: [14:32:05] [echo] hello world
```

### Send Command (stdin Support)

```bash
# Direct message
socketley send myserver "Hello everyone"

# Pipe from stdin
echo "Hello" | socketley send myserver
cat message.txt | socketley send myclient

# Server broadcasts to all clients, client sends to server
# Respects --mode (fails if mode is receive-only)
```

### Cache Protocol

Cache runtimes accept TCP connections with newline-terminated commands (all lowercase).
Also supports RESP2 (Redis wire protocol) — auto-detected or forced with `--resp`.

**Strings:**

| Command | Response |
|---------|----------|
| `set key value` | `ok` or `error: type conflict` |
| `get key` | Value or `nil` |
| `del key` | `ok` or `nil` (works on any type) |
| `exists key` | `1` or `0` |
| `size` | Number (counts all types) |

**Lists (ordered, deque-backed):**

| Command | Response |
|---------|----------|
| `lpush key value` | `ok` or `error: type conflict` |
| `rpush key value` | `ok` or `error: type conflict` |
| `lpop key` | Value or `nil` |
| `rpop key` | Value or `nil` |
| `llen key` | Number |
| `lindex key index` | Value or `nil` (negative = from end) |
| `lrange key start stop` | Multi-line values, `end` terminator |

**Sets (unique members):**

| Command | Response |
|---------|----------|
| `sadd key member` | `ok`, `exists`, or `error: type conflict` |
| `srem key member` | `ok` or `nil` |
| `sismember key member` | `1` or `0` |
| `scard key` | Number |
| `smembers key` | Multi-line members, `end` terminator |

**Hashes (nested key-value):**

| Command | Response |
|---------|----------|
| `hset key field value` | `ok` or `error: type conflict` |
| `hget key field` | Value or `nil` |
| `hdel key field` | `ok` or `nil` |
| `hlen key` | Number |
| `hgetall key` | Multi-line `field value`, `end` terminator |

**TTL / Expiry:**

| Command | Response |
|---------|----------|
| `expire key seconds` | `ok` or `nil` (key not found) |
| `ttl key` | Seconds, `-1` (no ttl), or `-2` (not found) |
| `persist key` | `ok` or `nil` |

**Pub/Sub:**

| Command | Response |
|---------|----------|
| `subscribe channel` | `ok` |
| `unsubscribe channel` | `ok` |
| `publish channel message` | Number of subscribers reached |

Subscribers receive: `message <channel> <payload>\n`

**Memory Management:**

| Command | Response |
|---------|----------|
| `maxmemory` | Max memory setting in bytes (0 = unlimited) |
| `memory` | Current memory usage in bytes |

**Admin:**

| Command | Response |
|---------|----------|
| `flush [path]` | `ok` or error (requires admin mode) |
| `load [path]` | `ok` or error (requires admin mode) |

Type enforcement: a key can only hold one type. `set` on a list key returns `error: type conflict`. `del` removes any type.

Multi-line responses (`lrange`, `smembers`, `hgetall`) terminate with `end\n`.

```bash
# Create cache with maxmemory and LRU eviction
socketley create cache store -p 9000 --persistent /tmp/cache.bin --maxmemory 256M --eviction allkeys-lru -s

# Strings
echo "set user:1 alice" | nc localhost 9000   # → ok
echo "get user:1" | nc localhost 9000         # → alice

# Lists
echo "rpush queue task1" | nc localhost 9000  # → ok
echo "rpush queue task2" | nc localhost 9000  # → ok
echo "lpop queue" | nc localhost 9000         # → task1

# Sets
echo "sadd tags linux" | nc localhost 9000    # → ok
echo "smembers tags" | nc localhost 9000      # → linux\nend

# Hashes
echo "hset user:1 name alice" | nc localhost 9000  # → ok
echo "hgetall user:1" | nc localhost 9000          # → name alice\nend

# TTL
echo "expire user:1 300" | nc localhost 9000  # → ok
echo "ttl user:1" | nc localhost 9000         # → 299

# Pub/Sub
echo "subscribe news" | nc localhost 9000     # Stays connected, receives messages
echo "publish news hello" | nc localhost 9000 # → 1 (subscriber count)

# RESP mode (redis-cli compatible)
socketley create cache myredis -p 6379 --resp -s
redis-cli -p 6379 SET mykey myval
redis-cli -p 6379 GET mykey

# Replication
socketley create cache leader -p 9000 -s
socketley create cache follower -p 9001 --replicate 127.0.0.1:9000 -s

# CLI actions
socketley store set mykey myval
socketley store get mykey                     # → myval
socketley store lpush mylist hello
socketley store hset user name bob
socketley store expire mykey 60
socketley store publish news "breaking update"
```

## Architecture

**Build system:** Premake5 generates GNU Makefiles. Root `premake5.lua` defines all projects. All source files under `socketley/` are compiled into the main `socketley` ConsoleApp. Test projects link specific source files.

**Source layout:**

- `socketley/` — Main application
  - `cli/` — CLI commands dispatched via FNV-1a hash switching (`command_hashing.h`)
  - `daemon/` — Daemon handler, flag parsing, IPC
  - `shared/` — Core: `runtime_instance` (atomic state machine), `runtime_manager` (thread-safe registry), `event_loop` (io_uring), `lua_context`, `logging`, `tls_context`, `ws_protocol` (WebSocket frame encode/decode), `paths` (system/dev mode detection), `state_persistence` (JSON config persistence)
  - `runtime/server/` — Server runtime
  - `runtime/client/` — Client runtime
  - `runtime/proxy/` — HTTP/TCP reverse proxy
  - `runtime/cache/` — Cache runtime with `cache_store`, `resp_parser`
  - `man/` — Man page and interactive help
  - `examples/` — Example scripts and Lua configs
- `test/` — Test framework
  - `unit/` — doctest unit tests (cache_store, resp_parser, command_hashing)
  - `integration/` — Shell-based integration tests
  - `benchmark/` — Stress testing tools
- `thirdparty/` — Vendored LuaJIT, sol2, doctest
- `packaging/` — systemd service, install/uninstall scripts, deb builder

**State persistence:** Runtime configs saved as JSON files in a state directory. On daemon startup, all persisted runtimes are restored; those with `was_running: true` are auto-started. State is updated after create/run/stop/remove/edit commands. System mode uses `/var/lib/socketley/runtimes/`, dev mode uses `~/.local/share/socketley/runtimes/`.

**Path resolution:** `socketley_paths::resolve()` auto-detects system vs dev mode. System mode activates when `/usr/bin/socketley` exists and running as root. Socket path, state dir, and config path differ accordingly.

**Runtime lifecycle:** `created → running → stopped` (also `failed`). Transitions enforced atomically in `runtime_instance::start()` and `stop()`.

**Lua integration:** Callbacks (`on_start`, `on_stop`, `on_message`, `on_connect`, `on_disconnect`, `on_send`) are attached per runtime. Hot-reloadable via `socketley reload`. Proxy supports `on_route(method, path)` for Lua-based backend selection. Server master mode supports `on_master_auth(client_id, password)` returning bool.

**Lua API:**
- `self` table: `name`, `port`, `type`, `state`, `protocol` + action methods per runtime type
- Server: `self.broadcast(msg)`, `self.send(client_id, msg)`
- Client: `self.send(msg)`
- Cache: `self.get/set/del`, lists, sets, hashes, TTL, `self.publish(channel, msg)`
- `socketley.log(msg)` → stderr with `[lua]` prefix

**Cache features:** Strings, lists, sets, hashes, TTL/expiry, pub/sub, RESP2 protocol, maxmemory + LRU/random eviction, leader-follower replication, persistence (SKV2 format).

**Concurrency model:** `shared_mutex` for the runtime manager (concurrent reads, exclusive writes). Atomic state with acquire/release semantics per runtime instance. io_uring with SQPOLL for async I/O.

**Design principles:** All runtimes managed centrally, no subprocess spawning per runtime. Extensible via new runtime types, new CLI flags, or Lua callbacks. Minimalist CLI that exposes full control.

## Claude Code Rules

**IMPORTANT for Claude Code:**
- **NEVER read files from `thirdparty/`** — This folder contains vendored libraries (LuaJIT, sol2, doctest) that should not be modified or analyzed.
- **Silence is golden** — Success operations should produce no output. Only errors go to stdout.
- **Exit codes:** 0 = success, 1 = bad input, 2 = fatal error

## Documentation Maintenance

**IMPORTANT:** When making changes to the codebase (new flags, commands, runtime features, Lua callbacks, etc.), always update the documentation:

1. **Man page** (`socketley/man/socketley.1`) — Update command syntax, flags, examples
2. **Interactive help** (`socketley/man/socketley-help.sh`) — Update menus and examples
3. **Examples** (`socketley/examples/`) — Add/update relevant examples demonstrating new features

Documentation locations:
- `socketley/man/` — Man page and interactive help
- `socketley/examples/basic/` — Getting started examples
- `socketley/examples/server-client/` — Server/client communication patterns
- `socketley/examples/proxy/` — Proxy configurations
- `socketley/examples/cache/` — Cache usage (including pub/sub, RESP mode, replication)
- `socketley/examples/lua-config/` — Lua scripting examples (including connection callbacks)
- `socketley/examples/advanced/` — Complex multi-runtime setups (including stats/monitoring)
