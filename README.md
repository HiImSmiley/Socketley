# Socketley

A high-performance Linux daemon and CLI that manages network runtimes (servers, clients, proxies, Redis-compatible caches) in a Docker-like style - with clustering, WebSocket, Lua scripting, and io_uring async I/O.

**[Documentation](https://hiimsmiley.github.io/Socketley/)**

> **TLS, on every role that has a handshake to put it on.** All four runtime
> types do:
>
> - a **server** listener, so one port serves `https://` and `wss://` too
> - a **cache** listener, which also refuses to replicate out of one in cleartext
> - a **client**'s outbound socket, pinning the host from `-t` and verifying the
>   chain against the system store
> - a **proxy**, on *both* legs — its own listener and the connections it dials
>   to its backends, with the backend handshake reused rather than repeated per
>   request
>
> `--ca` adds mutual TLS on a listener; `--cert`/`--key` are the certificate a
> client or proxy presents when a peer asks for one.
>
> **The one thing with no handshake behind it is a datagram socket.** `--tls`
> with `--udp` would be DTLS, which is not implemented, and it is refused.
>
> **Everything incomplete fails closed** — refused when you type the flag, and
> refused again before the runtime starts, including for configurations that
> never came from a command line. `--tls` with no key pair, a certificate with
> no `--tls`, a key that does not match its certificate, half of a client
> certificate pair, a `--client-ca` on a role with no listener to receive one:
> the runtime goes to `failed` and the port is never bound. A flag that errors
> out costs you an afternoon; a flag that silently serves cleartext on a port
> you were told was encrypted is a breach.

```bash
socketley create server secure -p 9443 --tls --cert server.pem --key server-key.pem -s
curl --cacert server.pem https://localhost:9443/
```

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
sudo apt install build-essential libssl-dev libluajit-5.1-dev git

# liburing >= 2.7, which is NOT what `apt install liburing-dev` gives you.
# Ubuntu 24.04 packages liburing 2.5 (April 2024) and the event loop has used
# IORING_SETUP_NO_SQARRAY, io_uring_register_napi (2.6) and
# IORING_ACCEPT_POLL_FIRST (2.7) since 2026-07-28, so 2.5 does not compile this
# tree at all.  This script checks what you have and builds a current release
# only if it needs to — it exits immediately if your liburing is already good.
bash scripts/install-liburing.sh

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
- **C++ SDK**: The `include/linux/socketley/` directory provides a three-tier modular SDK. Tier 1 (`control.h`) is header-only — control a running daemon with zero dependencies. Tier 2 (`server.h`, `client.h`, `proxy.h`, `cache.h`) lets you embed the full io_uring engine in your own binary. Tier 3 (`attach.h`) registers your process as a runtime in a running daemon. Custom runtimes get full access to the CLI, monitoring, state persistence, and interaction with other runtimes.
- **Persistent networks**: Runtime configurations are saved as JSON and automatically restored when the daemon restarts. You can build entire network topologies that survive reboots.
- **Working examples**: The `examples/` directory has ready-to-run scripts and Lua configs for every use case, from basic echo servers to SQLite-backed caches, auth middleware, reverse proxies, and multi-daemon clusters.

## Features

- **Server**:TCP/UDP listener with broadcast, WebSocket auto-detection, master mode
- **Client**:TCP/UDP connector with auto-reconnect
- **Proxy**:HTTP/TCP reverse proxy with round-robin, random, or Lua-based routing
- **Cache**:In-memory key-value store with strings, lists, sets, hashes, TTL, pub/sub, RESP2 (Redis wire protocol), LRU eviction, persistence, leader-follower replication, and DB-backend Lua hooks for read-through / write-behind caching
- **Lua scripting**:Per-runtime callbacks (`on_message`, `on_connect`, `on_auth`, `on_route`, etc.) with hot-reload, timers, HTTP client, cross-runtime pub/sub
- **Cluster mode**:Multi-daemon discovery via shared directory, `@group` backend routing, Lua cluster API
- **Sharding**:`--shards N` runs one runtime across N worker processes behind a single port via `SO_REUSEPORT`, on servers, proxies and caches — a sharded cache keeps one keyspace, so `mget`, `dbsize` and `publish` still answer for the whole runtime
- **Process isolation**:Every runtime is a supervised worker process by default, so one runtime cannot take the daemon down with it; `--daemon-process` opts back in to sharing it
- **Unix sockets**:`--listen unix:/path` on a listener and `--backend unix:/path` for a proxy's backends
- **CPU placement**:`--cpus max | 0-3 | 0,1,2,3` says where the I/O may run, and SQPOLL is a choice rather than always on
- **Master mode**:One client claims master, broadcasts to all; optional forwarding
- **HTTP static serving**:`--http <dir>` with auto-injected WebSocket, optional in-memory caching
- **TLS/SSL**:Server, cache and proxy listeners terminate TLS (incl. mutual TLS); client runtimes and proxy backend legs dial over it — see the note at the top
- **WebSocket**:Auto-detected per connection, coexists with raw TCP on the same port
- **io_uring**:Multishot accept, SQPOLL, provided buffers, writev coalescing
- **State persistence**:Runtime configs saved as JSON, auto-restored on daemon restart
- **Ownership**:Parent-child runtime relationships with configurable `on_parent_stop` policies
- **Monitoring**:`socketley stats` for live metrics, `--rate-limit` and `--max-connections` for resource control

## Performance

**How these were measured.** Development box, 4 cores, Linux 7.0, Release
build, loopback TCP. The daemon is pinned to CPU 0,1 and the load generator to
CPU 2,3, so the two are not competing for the same cores. Every measurement
waits until fewer than 1000 sockets are in `TIME_WAIT` before it starts — a
2000-connection run leaves ~10000 behind for a full 2×MSL, and a benchmark
started on top of that measures port pressure rather than this daemon. Each
figure is the median of three runs, and the spread across those runs is given
beside it, because several of these numbers move by more than a fifth between
runs on a machine this size.

Numbers from a different machine are not comparable with these. That is what
the spread column is for: treat anything inside it as unchanged.

### Cache vs Redis 7.0.15 (RESP2, `redis-benchmark`)

> Both servers speak RESP2 and are driven by the same tool, `redis-benchmark`,
> 50 clients. Socketley is single-threaded; Redis 7.x is also single-threaded.

**Pipeline depth 1** — 200K operations per test:

| Operation | Socketley    | Redis 7.0.15 | Ratio |
|-----------|--------------|--------------|-------|
| SET       | 186K ±6%     | 192K ±7%     | 0.97× |
| GET       | 180K ±7%     | 178K ±7%     | 1.01× |
| LPUSH     | 173K ±12%    | 180K ±6%     | 0.96× |
| LPOP      | 167K ±19%    | 170K ±26%    | 0.98× |
| SADD      | 177K ±27%    | 164K ±28%    | 1.08× |
| HSET      | 170K ±27%    | 165K ±27%    | 1.03× |

At depth 1 the two are **indistinguishable**: every ratio is inside the spread
of the measurement. Throughput here is dominated by the loopback round trip,
and neither server is doing enough work per operation for the difference to
show. Any claim of an advantage in either direction at this depth is noise.

**Pipeline depth 100** — 2M operations per test:

| Operation | Socketley     | Redis 7.0.15 | Speedup |
|-----------|---------------|--------------|---------|
| SET       | 9.05M ±26%    | 2.79M ±29%   | 3.2×    |
| GET       | 9.85M ±21%    | 3.36M ±18%   | 2.9×    |
| LPUSH     | 9.48M ±14%    | 2.51M ±6%    | 3.8×    |
| LPOP      | 10.36M ±31%   | 2.26M ±3%    | 4.6×    |
| SADD      | 7.19M ±42%    | 3.03M ±15%   | 2.4×    |
| HSET      | 8.97M ±30%    | 2.44M ±9%    | 3.7×    |

Pipelined, socketley is **2.4× to 4.6× faster than Redis 7**, and the margin is
far larger than the spread. The advantage comes from:

- **io_uring SQPOLL** — no `epoll_wait`/`sendmsg` syscalls in the hot path
- **Zero-allocation RESP2 codec** — parse and encode directly into and out of
  the connection buffer with `to_chars` and `string_view`
- **Batch CQE drain** — every completion from a submit round in one pass, one
  `io_uring_cq_advance`
- **writev coalescing** — up to 16 responses in a single `writev` SQE

The shape of these two tables is the interesting part: the advantage exists
only when there is enough work per connection to amortise the per-operation
cost. That is also where the weakness is — see below.

### Server, proxy and WebSocket

Median of three runs, `socketley_bench`, same pinning and `TIME_WAIT`
discipline.

| Test                               | Result             | Spread |
|------------------------------------|--------------------|--------|
| Connection rate (2000 conns)       | **81K conn/s**     | ±16%   |
| Burst (5000 simultaneous)          | **113K conn/s**    | ±2%    |
| WebSocket handshakes (200)         | **30K/s**          | ±7%    |
| WebSocket, 20 concurrent clients   | **80K/s**          | ±6%    |

**Six rows have been withdrawn rather than restated.** Single client 64B and
1KB, 100 clients × 500 msgs, proxy TCP forwarding, proxy 20 concurrent, and
WebSocket frames were all produced by benchmarks that sent in a loop and never
read a reply. What those measured was how fast the load generator could fill a
socket buffer — roughly 1/latency of a `write()` — and not how fast anything was
served. Their latency percentiles were the cost of `write()`. The figures were
therefore too high by a large and *test-dependent* factor: measured on this tree
after the loops were fixed, between 4× (single client) and 40× (100 concurrent
clients).

Those benchmarks now complete a round trip per operation against an echoing
backend, so the numbers they produce are not comparable with the ones that stood
here, and quoting either in the other's place would be wrong. They are left out
until they have been re-recorded with the pinning and `TIME_WAIT` discipline the
rest of this table was taken under — `test/benchmark/record_throughput.sh`. An
absent row is a smaller error than a confident one.

The two connection-rate rows and the two WebSocket handshake rows are unchanged:
those never depended on a reply that was not being read. `socketley_bench` now
states beside every figure whether it is a round trip, a write with nothing read
back, or a connection establishment, and publishes each under a JSON key named
for its kind, so this cannot happen again silently.

One row that remains is still given without emphasis on purpose: the WebSocket
concurrent figure is an aggregate test, and aggregates are where the spread on
this machine is worst. See the weakness below.

**Known weakness, stated rather than omitted.** Single connections are fast and
pipelined depth is fast; many *simultaneous* connections are not proportionally
fast. The cost per connection has grown, and it disappears at one connection and
dominates at a hundred.

How much of that conclusion survives the withdrawn rows is itself open. It was
drawn by comparing aggregate figures against a February 2026 build measured on
the same day — but both sides of that comparison were write-only numbers, so it
compared two socket-buffer fill rates and not two service rates. The pipelined
RESP tables above are unaffected (`redis-benchmark` reads its replies), and they
show the same shape, which is why the weakness is still stated rather than
withdrawn with the rows. It needs re-establishing on round trips before the
figure attached to it means anything.

Part of that is the price of correctness: the February build did not release
registered file slots on teardown, did not cancel operations armed on them,
leaked descriptors across `exec`, and closed clients without an answer. Some of
it is probably not. Where it might be, and the experiment that would settle
each candidate, is written down in `test/benchmark/hotspots.md`.

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

# Integration tests (each test starts a daemon of its own)
bash test/run_all.sh

# Benchmarks
bash test/benchmark/run_all.sh
```

Two integration runs on one machine no longer interfere. Each test brings up its
own daemon on its own socket and state directory, and each run claims a private
window of two thousand ports for every port it binds, so a second run — an agent
verifying a change while somebody measures a baseline — collides with the first
on nothing. The benchmarks are a different matter: those measure the machine and
still want it to themselves.

## Architecture

- Single-binary daemon + CLI communicating via Unix socket IPC
- io_uring event loop (single-threaded, SQPOLL)
- Each runtime gets its own supervised worker process by default;
  `--daemon-process` keeps it inside the daemon instead
- FNV-1a hash switching for zero-allocation command dispatch
- sol2/LuaJIT for Lua callbacks
- LuaJIT is statically linked; liburing, OpenSSL and the C++ runtime are
  resolved from the host (`ldd` is the authority — see
  [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md))

## Requirements

- Linux 5.19+ (for io_uring multishot accept)
- **liburing 2.7 or newer** — `liburing-dev` from Ubuntu 24.04 is 2.5 and will
  not build this project. Install it with `bash scripts/install-liburing.sh`,
  which is what CI, the release job and the Dockerfile all use. 2.15 is the
  version everything is tested against; 2.7 is the oldest that compiles.
  Distributions carrying 2.7 or later (Debian 13, Fedora 40+, Arch) need no
  extra step. A binary built this way needs liburing 2.6+ at *run* time, which
  is why the `.deb` depends on `liburing2 (>= 2.6)`.
- libssl-dev (TLS on every role that has a handshake, and WebSocket handshake hashing)
- GCC 12+ (C++23)

### Toolchain

Socketley is built with **GCC**. That is the only compiler you need to build it,
run the test suite, or produce a release binary — `make config=release_x64` is a
GCC build start to finish.

**Clang is not a build dependency.** It is used only as a *testing* toolchain,
in two places, both optional and neither required to build or ship:

- **libFuzzer** (`test/fuzz/build_libfuzzer.sh`) — coverage-guided fuzzing is a
  clang feature with no GCC equivalent. Without clang the fuzz targets still
  build and run through a GCC replay driver; you lose coverage guidance, not the
  tests.
- **A second opinion on warnings** — clang diagnoses things GCC does not, so CI
  compiles the tree with `clang++-18 -Wall -Wextra` as an advisory check.

If you are packaging, porting, or just building socketley, you can ignore clang
entirely.

## License

Apache 2.0 — see [LICENSE](LICENSE).

### Third-party components

Socketley vendors and links against software under other licences, all of them
permissive. The full list, with versions, licence texts and which components
actually end up inside the shipped binary, is in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

- **[LuaJIT](https://luajit.org/)** (MIT) — statically linked; the Lua runtime
- **[sol2](https://github.com/ThePhD/sol2)** (MIT) — header-only; the C++/Lua binding
- **[liburing](https://github.com/axboe/liburing)** (MIT) — dynamically linked; io_uring
- **[doctest](https://github.com/doctest/doctest)** (MIT) — header-only; unit tests only
- **[OpenSSL](https://openssl-library.org/)** (Apache-2.0) — dynamically linked; TLS
