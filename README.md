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

# The two static archives this tree links but does not track. Both are covered
# by the `*.a` rule in .gitignore, so a fresh clone has the headers and neither
# archive, and the build ends in `cannot find -lluajit`. Note that the apt
# package above is not a drop-in: it installs libluajit-5.1.a and premake links
# -lluajit, so the name never matches. This script settles both.
./bin/build-thirdparty.sh

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
- **Process isolation**:Every runtime is a supervised worker process, so one runtime cannot take the daemon down with it — there is no flag and no in-daemon mode; the whole cross-runtime Lua API works across the boundary
- **Unix sockets**:`--listen unix:/path` on a listener and `--backend unix:/path` for a proxy's backends
- **CPU placement**:`--cpus max | 0-3 | 0,1,2,3` says where the I/O may run
- **Master mode**:One client claims master, broadcasts to all; optional forwarding
- **HTTP static serving**:`--http <dir>` with auto-injected WebSocket, optional in-memory caching
- **TLS/SSL**:Server, cache and proxy listeners terminate TLS (incl. mutual TLS); client runtimes and proxy backend legs dial over it — see the note at the top
- **WebSocket**:Auto-detected per connection, coexists with raw TCP on the same port
- **io_uring**:Multishot accept, provided buffers, writev coalescing
- **State persistence**:Runtime configs saved as JSON, auto-restored on daemon restart
- **Ownership**:Parent-child runtime relationships with configurable `on_parent_stop` policies
- **Monitoring**:`socketley stats` for live metrics, `--rate-limit` and `--max-connections` for resource control

## Performance

**How these were measured.** 16-core Linux 7.0 guest, Release build, loopback
TCP, `2026-09-01`. Every figure below comes from **one run**, with all arms
interleaved inside it and the order rotated between passes. Nothing here is
compared against a number taken earlier, and neither should you compare it
against yours.

That is not caution for its own sake. This box is a guest: it has no
`cpufreq`, and `/proc/cpuinfo` reports a constant `2995.200 MHz` no matter what
the host is doing. A frequency change on the host is therefore **invisible from
inside** and moves every absolute figure with no sign in the output. Measured
here on one day, hours apart, with an unchanged binary:

```
morning   clock_probe ns_per_iter=2.4386  equiv_ghz=1.23
midday    clock_probe ns_per_iter=1.3462  equiv_ghz=2.23
```

An 80% swing that nothing in the machine's own reporting would have shown. So
every run records the probe before and after itself — the run below moved
2.21 → 2.23 GHz, under 1% — and comparisons only ever live inside one run,
where a clock change moves both arms together and the paired difference
survives it.

Each measurement is the **median of the per-pass differences**, not the
difference of two medians, and the spread across passes is printed beside it.
Treat anything whose spread contains the null result as unchanged; several
numbers on a machine this size move by a third between passes.

### Round trip against the C floor

The only figure that says how much is left to win. `test/benchmark/floor_server.c`
is a bare io_uring TCP echo with nothing of this project in it; the same client,
the same six bytes in each direction, one connection, 20 000 round trips per
pass, 9 passes.

| Arm | p50 | p95 | Server CPU per round trip | Spread |
|-------------------------------|-----------|-----------|--------|-------|
| C floor (`floor_server`)      | 10.42 µs  | 11.20 µs  | 5.46 µs | 2.7% |
| **cache**, `get` over TCP     | 11.01 µs  | 11.97 µs  | 6.36 µs | 2.2% |
| **server**, Lua echo callback | 11.55 µs  | 12.63 µs  | 7.27 µs | 1.3% |

Paired per pass, n = 9:

| Over the floor | Latency | Range | CPU |
|----------------|---------|-------|-----|
| cache          | **+0.52 µs** | [+0.42, +0.85] | +0.91 µs |
| server + Lua   | **+1.19 µs** | [+0.96, +1.28] | +1.36 µs |

Neither range contains zero, so both are real rather than noise — unlike most
of the depth-1 throughput ratios below. **0.5 µs buys** the key lookup, the
runtime's connection state and its statistics; **another 0.7 µs buys the whole
Lua dispatch**, a callback entered and returned per message. The optimum is +0
and unreachable.

The CPU column quantises: `CLK_TCK` is 100, so over 22 000 round trips one tick
is 0.45 µs and every value in it is a multiple of that. The two differences are
two and three ticks, which survives the resolution; a one-tick difference would
not have been reportable.

### Cache vs Redis 7.0.15 (RESP2, `redis-benchmark`)

Both speak RESP2 and are driven by the same tool, **four** `redis-benchmark`
processes per arm at 50 connections each. Four, not one: a single
`redis-benchmark` pegs at 1.0 core on this box and then the number measured is
the client's ceiling, not the server's. Client CPU is recorded beside every
figure and averaged 0.35 cores per process here, well clear of the cap.

**What `-P` changes, and why there are two tables.** Without pipelining the
client sends one command and waits for its reply, so every operation costs a
full round trip through the kernel and *that* dominates the measurement — which
is why the two servers are indistinguishable at depth 1. At `-P 100` the client
sends 100 commands before reading, so they arrive in one `read()` and the
per-message syscall and wakeup cost is amortised by a hundred; what is left is
the server's own parsing and execution. **Depth 1 measures the round trip.
Depth 100 measures the code.** Most applications do not pipeline, so depth 1 is
the honest number for an ordinary client and depth 100 is the ceiling for bulk
work. Quoting either alone would mislead.

**Pipeline depth 1** — 200 K operations per test, 5 passes:

| Operation | Socketley      | Redis 7.0.15   | Ratio | Ratio spread |
|-----------|----------------|----------------|-------|--------------|
| SET       | 288 K ±3%      | 268 K ±13%     | 1.09× | [1.06, 1.21] |
| GET       | 249 K ±20%     | 267 K ±2%      | 0.93× | [0.88, 1.09] |
| LPUSH     | 260 K ±31%     | 253 K ±24%     | 1.03× | [0.80, 1.44] |
| LPOP      | 279 K ±32%     | 232 K ±24%     | 1.14× | [0.88, 1.25] |
| SADD      | 240 K ±38%     | 244 K ±23%     | 0.99× | [0.93, 1.20] |
| HSET      | 270 K ±30%     | 251 K ±7%      | 1.09× | [0.83, 1.10] |

Five of the six ratio spreads contain 1.00: at depth 1 the two are
**indistinguishable**, and any claim of an advantage in either direction is
noise. SET is the one exception — its spread excluded 1.00 in this run and in a
second run the same day (+9% and +10%) — and a 9% edge on one verb is worth
noting and not worth building a claim on.

**Pipeline depth 100** — 2 M operations per test, 5 passes:

| Operation | Socketley       | Redis 7.0.15    | Speedup | Spread       |
|-----------|-----------------|-----------------|---------|--------------|
| SET       | 11.47 M ±36%    | 2.96 M ±18%     | 3.99×   | [2.78, 4.63] |
| GET       | 13.09 M ±32%    | 3.70 M ±19%     | 3.35×   | [2.68, 4.34] |
| LPUSH     | 8.92 M ±31%     | 2.76 M ±17%     | 3.23×   | [2.66, 4.23] |
| LPOP      | 11.26 M ±11%    | 2.45 M ±8%      | 4.74×   | [4.28, 4.82] |
| SADD      | 8.28 M ±21%     | 3.30 M ±16%     | 2.46×   | [2.23, 2.88] |
| HSET      | 9.80 M ±22%     | 2.89 M ±17%     | 3.51×   | [2.84, 4.02] |

Pipelined, socketley is **2.5× to 4.7× faster than Redis 7**, and every spread
sits well above 1.00. A second run the same day reproduced all six within their
spreads (3.23×–4.74× against 2.48×–4.66×), which is the only kind of
cross-run agreement worth quoting: the conclusions repeat, the absolute figures
do not have to.

The same data read the other way is the clearer statement of cause. Pipelining
is worth roughly **31× to 54×** to socketley and **10× to 14×** to Redis, and
the mechanism is that a batch is where this tree does its work:

- **Zero-allocation RESP2 codec** — parse and encode directly into and out of
  the connection buffer with `to_chars` and `string_view`
- **Batch CQE drain** — every completion from a submit round in one pass, one
  `io_uring_cq_advance`
- **`writev` coalescing** — up to 16 responses in a single `writev` SQE

None of the three has anything to bundle at depth 1, which is exactly why the
advantage is absent there.

### Not re-measured

The connection-rate and WebSocket-handshake rows that stood here were taken
before this file recorded a clock probe, so there is no way to say what machine
they describe. They are removed rather than restated: an absent row is a smaller
error than one whose provenance is unknown. `test/benchmark/run_all.sh` produces
them.

Six further rows were withdrawn earlier and have not returned — single client
64 B and 1 KB, 100 clients × 500 msgs, proxy TCP forwarding, proxy 20 concurrent,
and WebSocket frames. Those benchmarks sent in a loop and never read a reply, so
what they measured was how fast the load generator could fill a socket buffer,
roughly 1/latency of a `write()`, and their latency percentiles were the cost of
`write()`. The overstatement was large and *test-dependent*: between 4× and 40×.
They now complete a round trip per operation, which makes them incomparable with
what stood here, and they stay out until re-recorded.

**Known weakness, stated rather than omitted.** Single connections are fast and
pipelined depth is fast; many *simultaneous* connections are not proportionally
fast. The cost per connection has grown, and it disappears at one connection and
dominates at a hundred. How much of that survives the withdrawn rows is itself
open — it was drawn by comparing aggregate figures that were both write-only, so
it compared two socket-buffer fill rates rather than two service rates. The
pipelined tables above are unaffected, since `redis-benchmark` reads its
replies, and they show the same shape, which is why the weakness is still
stated. It needs re-establishing on round trips before the figure attached to it
means anything.

Part of that is the price of correctness: an early build did not release
registered file slots on teardown, did not cancel operations armed on them,
leaked descriptors across `exec`, and closed clients without an answer. Some of
it is probably not. Where it might be, and the experiment that would settle each
candidate, is written down in `test/benchmark/hotspots.md`.

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
- io_uring event loop (single-threaded, `SINGLE_ISSUER | DEFER_TASKRUN`)
- Each runtime gets its own supervised worker process — always, for every
  type, with no flag and no in-daemon mode
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
