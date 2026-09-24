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
> `--cert`/`--key` are the certificate a server, cache or proxy listener serves,
> and the one a client presents when its peer asks for one. `--ca` is mutual TLS
> on a server or cache listener, and the trust store for the peer a client or
> proxy dials. A proxy's own listener takes mutual TLS from `--client-ca`, and
> presents `--client-cert`/`--client-key` to a backend that asks for one.
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
mkdir -p www && echo hello > www/hello.txt
socketley create server secure -p 9443 --tls --cert server.pem --key server-key.pem --http www -s
curl --cacert server.pem https://localhost:9443/hello.txt
```

## About Me and the Project

Hi, I'm Smiley. This project was born out of a university module called Networked Systems, where I spent a lot of time working with Docker, proxies, sockets, caches, and the protocols that tie them all together. While reading into virtual threads, I stumbled upon Linux's io_uring interface and was immediately hooked.

What bothered me was how many moving parts you need to set up a proper networked system - separate tools for servers, proxies, caches, each with their own config and lifecycle. My goal with Socketley was to combine all of that into something simpler and more unified, at least in my opinion and hope.

I've been programming for over a decade, but this project pushed me into entirely new territory: io_uring internals, protocol design, benchmarking methodology, hot-path optimization, and rapid prototyping. It's also been my first deep dive into AI-assisted development with Claude Code, which has been a genuinely exciting experiment in seeing how far that workflow can go.

It's been an amazing journey so far, and I hope others see the same potential in this project that I do. I'll keep building with the same mindset and love I started with.

## Installation

### From a clone, on a machine that has nothing on it

```bash
git clone https://github.com/HiImSmiley/Socketley
cd Socketley
bash scripts/install-from-source.sh
```

That is the whole of it. The script checks the kernel, the architecture and the
compiler; installs the build dependencies; builds the liburing this tree needs,
because the one your distribution packages is probably too old (see
[Requirements](#requirements)); builds Release; installs the binary, the man
page, the help script and the systemd service; and then starts the daemon and
asks it for its runtime list before it reports success.

- `--dry-run` prints every command it would run and runs none of them.
- `--uninstall` removes exactly what a previous run installed, from a manifest
  that run wrote — and leaves `/var/lib/socketley`, `/etc/socketley` and the
  `socketley` account alone, because those are not the installer's to delete.
- `--prefix` moves the install. The default is `/usr` and not `/usr/local`
  because the binary tests `/usr/bin/socketley` to decide whether it is
  installed at all; under any other prefix it runs in user mode and no systemd
  service is installed. `--help` says so too.
- It names every step that needs root, and why, before it takes any.

It refuses rather than guesses. A kernel below 5.19, GCC below 12, an
architecture that is not x86\_64, a distribution whose package names are not
written down anywhere in this repository, or a `socketley` `.deb` already
owning `/usr/bin` — each one stops the run with the reason and the way forward,
and changes nothing.

### Prebuilt release

```bash
curl -fsSL https://raw.githubusercontent.com/HiImSmiley/Socketley/main/install.sh | sudo sh
```

Downloads the newest release `.deb` and installs it. Nothing is compiled, so it
is minutes faster and gives you whatever the last tag was rather than what is on
`main`.

### From source, step by step

Roughly what the script above does, if you would rather run it yourself:

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

`./bin/build-thirdparty.sh` with no argument builds *both* archives, and
`thirdparty/liburing/` is on the link path, so `-luring` then resolves to
`liburing.a` and you get liburing statically linked. The Dockerfile, CI, the
release job and `scripts/install-from-source.sh` all say `luajit` instead and
take liburing from the system, which is what the `.deb`'s
`Depends: liburing2 (>= 2.6)` describes. Both build; `ldd` on the result is
what tells you which one you have.

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

- **Server**:TCP/UDP listener with broadcast, WebSocket auto-detection, master mode (TCP only), and `--send-to` to say who an incoming message reaches
- **Client**:TCP/UDP connector with auto-reconnect
- **Proxy**:HTTP/TCP reverse proxy with round-robin, random, or Lua-based routing
- **Cache**:In-memory key-value store with strings, lists, sets, hashes, TTL, pub/sub, RESP2 (Redis wire protocol), LRU eviction, persistence, leader-follower replication, and DB-backend Lua hooks for read-through / write-behind caching
- **Lua scripting**:Per-runtime callbacks (`on_message`, `on_connect`, `on_auth`, `on_route`, etc.) with hot-reload, timers, HTTP client, cross-runtime pub/sub
- **Cluster mode**:Multi-daemon discovery via shared directory, `@group` backend routing, Lua cluster API
- **Sharding**:`--shards N` runs one runtime across N worker processes behind a single port via `SO_REUSEPORT`, on servers, proxies and caches — a sharded cache keeps one keyspace, so `mget`, `dbsize` and `publish` still answer for the whole runtime. On a **cache** add `--cluster` and point a cluster-aware client at it: behind one address the shard a connection lands on relays every key it does not own, which measured 1.75× for 3.95 cores at four shards against 2.80× slot-routed — see **Sharding a cache** under Performance
- **Process isolation**:Every runtime is a supervised worker process, so one runtime cannot take the daemon down with it — there is no flag and no in-daemon mode; the whole cross-runtime Lua API works across the boundary
- **Unix sockets**:`--listen unix:/path` on a listener and `--backend unix:/path` for a proxy's backends
- **CPU placement**:`--cpus max | 0-3 | 0,1,2,3` says where the I/O may run
- **Master mode**:One client claims master and broadcasts to all; `--send-to` decides what happens to what everybody else says
- **HTTP static serving**:`--http <dir>` with auto-injected WebSocket, optional in-memory caching
- **TLS/SSL**:Server, cache and proxy listeners terminate TLS (incl. mutual TLS); client runtimes and proxy backend legs dial over it — see the note at the top
- **WebSocket**:Auto-detected per connection, coexists with raw TCP on the same port
- **io_uring**:Multishot accept, provided buffers, writev coalescing
- **State persistence**:Runtime configs saved as JSON, auto-restored on daemon restart
- **Ownership**:Parent-child runtime relationships with configurable `on_parent_stop` policies
- **Monitoring**:`socketley stats` for live metrics, `--rate-limit` and `--max-connections` for resource control

## Performance

**How these were measured.** 16-core Linux **7.2.2** guest, Release build,
loopback TCP, `2026-09-01`. Every figure below comes from **one run**, with all
arms interleaved inside it and the order rotated between passes. Nothing here is
compared against a number taken earlier, and neither should you compare it
against yours.

The kernel matters enough to name: this box ran 7.0.0-30 earlier the same day,
and the whole section was re-measured after moving to 7.2.2. That move is the
one comparison here that **cannot** be interleaved — two kernels do not run at
once — so it is quoted with that on the label. Two independent instruments
agreed, both arms of the floor moved together, and the clock probe read
2.13–2.22 GHz on 7.0 against 2.15–2.18 GHz on 7.2, so if anything the newer
kernel was measured on a slower clock:

| | 7.0.0-30 | 7.2.2 | change |
|---|---|---|---|
| bare TCP loopback round trip | 10.63 µs | 10.14 µs | −0.49 µs |
| cache server CPU per `get` | 3.98 µs | 3.64 µs | **−0.33 µs** |

No line of this project changed. If you are reading these figures against your
own box, its kernel is worth about as much as anything below.

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

**The CPU of both ends is recorded beside every throughput figure**, because a
rate on its own cannot say whose ceiling it is. Four client processes per arm,
not one: a single `redis-benchmark` pegs at 1.0 core here, and a number taken
that way is the client's limit wearing the server's name.

### Round trip against the C floor

The only figure that says how much is left to win. `test/benchmark/floor_server.c`
is a bare io_uring TCP echo with nothing of this project in it; the same client,
the same six bytes in each direction, one connection, 20 000 round trips per
pass, 9 passes.

Six bytes each way is exact rather than approximate: the request is the inline
`get k\n`, and the key holds a five-character value, so the reply `hello\n` is
the same length. The floor and the Lua server echo those six bytes back, so all
three arms move identical traffic and only the server differs.

| Arm | p50 | p95 | Server CPU per round trip | Spread |
|-------------------------------|-----------|-----------|--------|-------|
| C floor (`floor_server`)      | 9.94 µs   | 11.18 µs  | 5.0 µs | 2.2% |
| **cache**, `get` over TCP     | 10.65 µs  | 13.15 µs  | 6.0 µs | 1.4% |
| **server**, Lua echo callback | 11.28 µs  | 14.20 µs  | 7.0 µs | 1.3% |

Paired per pass, n = 9:

| Over the floor | Latency | Range | CPU |
|----------------|---------|-------|-----|
| cache          | **+0.70 µs** | [+0.59, +0.85] | +1.0 µs |
| server + Lua   | **+1.33 µs** | [+1.11, +1.42] | +2.0 µs |

Neither range contains zero, so both are real rather than noise — unlike most
of the depth-1 throughput ratios below. **0.7 µs buys** the key lookup, the
runtime's connection state and its statistics; **another 0.6 µs buys the whole
Lua dispatch**, a callback entered and returned per message. The optimum is +0
and unreachable.

The CPU column quantises: `CLK_TCK` is 100, so over 20 000 round trips one tick
is 0.5 µs and every value in it is a multiple of that. The two differences are
two and four ticks, which survives the resolution; a one-tick difference would
not have been reportable, and the column should not be read more finely than
that.

### What the transport costs

The same cache, the same client, one run, order rotated over 9 passes — reached
over TCP on loopback and over an `AF_UNIX` socket:

| Arm | p50 | User CPU/rt | Kernel CPU/rt |
|-----------------------------|----------|---------|---------|
| C floor over TCP            | 10.02 µs | 0.0 µs | 5.0 µs |
| cache over **TCP**          | 10.64 µs | 0.5 µs | 5.5 µs |
| cache over **AF_UNIX**      | **6.57 µs** | 1.0 µs | **3.5 µs** |

The two CPU columns are at the same 0.5 µs quantum as the table above, so read
the kernel column's 2 µs drop and not the user column's single tick.

Paired per pass: **−4.10 µs** [−4.26, −4.00] against the same cache over TCP,
and −3.45 µs against a *bare C echo server* over TCP. Switching the transport
buys more than deleting every line this project contributes.

TCP is a protocol for making an unreliable link reliable. Over loopback there is
no link — the kernel is talking to itself — and the machinery runs anyway:
sequence numbers, windows, ACKs, retransmit timers, an skb allocated and queued
per direction through IP and the loopback device, and netfilter walking every
packet that never leaves the machine. `AF_UNIX` has no protocol at all; the
bytes are copied into the peer socket's queue, and ordering and reliability come
free because it is one kernel and one queue.

**How much netfilter is worth is measurable, and it is not socketley's to
remove.** This box runs Docker, so it carries Docker's `nat` and `filter` tables
and conntrack. Running the identical cache inside a fresh network namespace,
where the ruleset is empty, is the same measurement with netfilter deleted:
**0.93 µs per round trip at the floor** (12 of 12 passes, in a namespace checked
first for the same loopback MTU, socket buffers and congestion control) and
**0.51 µs of server CPU per `get`** at the product, worth about 16% of cache
throughput. The same pair measured on 7.0 gave 0.91 µs and 0.68 µs, so the
charge is the kernel-independent part of this section. `perf` attributes it: netfilter is 7.1% of the workload in the
host namespace and 0.13% in the empty one.

Two things follow. A TCP listener on a container host pays that for rules it
never uses, and no rule of ours can skip it — `iptables … -j NOTRACK` on
loopback measures **exactly nothing**, because `iptables-nft` implements that
target through the xtables compatibility layer and it costs about what conntrack
saves; written natively in `nft` it is still only 0.14 µs. And `--listen unix:`
skips all of it for free, because `AF_UNIX` never enters netfilter at all — and
at 4.10 µs against 0.93 µs that is more than four times the saving, in one flag.

The saving is **per message**, not per operation: 2.00 µs of server CPU at
depth 1, where one message carries one operation. At depth 100 a message carries
a hundred, so the same saving should read 0.020 µs per operation — and it
measures 0.016. The same order and the same mechanism, agreeing to about 20%
rather than to 5%; an earlier run on the older kernel agreed more tightly, and
quoting the looser figure is the honest one to keep.

Whether the depth-100 figures "barely move" depends on which server. Redis gains
1.02× from the transport at depth 100 — genuinely nothing, because its own
per-message work of ~32 µs dwarfs a 2 µs saving. socketley gains **1.25×**,
because its per-message work at that depth is only ~8 µs and the same saving is
a quarter of it. The transport matters in proportion to how little else is
left.

**None of this is socketley's doing, and Redis gets it too.** Measured with all
four arms in one run — both servers over both transports, 9 passes, order
rotated, every server between 0.973 and 1.003 cores:

| depth 1 | over TCP | over AF_UNIX | transport gain |
|-----------|----------|--------------|----------------|
| socketley SET | 273 K | **601 K** | 2.21× [1.98, 3.40] |
| Redis SET     | 255 K | **502 K** | 1.96× [1.73, 2.15] |
| socketley GET | 266 K | **650 K** | 2.40× [1.85, 2.66] |
| Redis GET     | 246 K | **511 K** | 2.07× [1.78, 2.34] |

So most of the win belongs to Linux, not to this project: anything speaking a
socket on one machine can have it. What is socketley's is the *difference* in
how much each keeps, and it has a visible consequence:

| socketley ÷ Redis, depth 1 | over TCP | over AF_UNIX |
|------|----------|--------------|
| SET  | 1.08× [0.81, 1.22] | **1.29× [1.13, 1.60]** |
| GET  | 1.09× [0.96, 1.24] | 1.28× [0.99, 1.47] |

Over TCP both spreads contain 1.00. Over AF_UNIX **SET clears it and GET does
not** — GET's lower bound is 0.99, which grazes. So the effect is one row
short of the clean statement an earlier run on the older kernel produced, and
the row that fell short is named rather than dropped.

What survives is the direction and the mechanism: **take the kernel's
per-message price out of the way and the difference in the code above it grows.**
It shows again at depth 100, measured in the same four-arm shape — socketley ÷
Redis goes from 3.94× over TCP to **4.63×** over AF_UNIX for SET, and 3.46× to
**4.22×** for GET.

**`--shards` composes with it, and used not to.** It was refused with
`--listen unix:` on the grounds that `SO_REUSEPORT` is not something a unix
socket does, so N processes on one path would unlink each other's node. That is
true of one path and not of N: each shard now binds its own,
`name#0.sock` … `name#N-1.sock`, the same rule the companion socket already
used. So the two levers combine rather than exclude — the cheap transport on
each of N cores. No figure for that pair is quoted here, because this section's
run did not measure it.

You also give up reach: a unix socket is a filesystem path, not an address.
Access control becomes file ownership and mode, which for a local service is
usually the better answer than "whoever can open the port".

### Cache vs Redis 7.0.15 (RESP2, `redis-benchmark`)

Both speak RESP2 and are driven by the same tool, **four** `redis-benchmark`
processes per arm at 50 connections each. Four, not one: a single
`redis-benchmark` pegs at 1.0 core on this box and then the number measured is
the client's ceiling, not the server's. Client CPU is recorded beside every
figure and averaged 0.35 cores per process here, well clear of the cap.

**Both servers sit at 1.000 cores in every row below** — measured, across all
108 runs at depth 1 both held 0.992–1.002, and at depth 100 0.968–1.012. Neither table is
limited by the client or by waiting on the network: each is a direct reading of
**CPU cost per operation**, since throughput is one core divided by that cost.

**What `-P` changes, then.** Without pipelining, one message carries one
command, so each operation is charged a full trip through the kernel: syscall,
socket, TCP, wakeup. That charge is the same for both servers and it is nearly
all of the cost — for `GET`, 3.71 µs of server CPU per operation at depth 1
against 0.073 µs at depth 100, so **98% of a depth-1 operation is per-message
overhead rather than work on the data**. At `-P 100` a hundred commands arrive in one `read()` and that
charge is divided by a hundred; what remains is parsing and execution.

So depth 1 is not "the round trip while the server idles" — the server is flat
out. It is the server spending nearly all of a core on the kernel's per-message
price, which both servers pay identically. Depth 100 is the same server
spending it on its own code, which is where they differ. Most applications do
not pipeline, so depth 1 is the honest number for an ordinary client and depth
100 is the ceiling for bulk work; quoting either alone would mislead.

**Pipeline depth 1** — 200 K operations per test, 9 passes:

| Operation | Socketley   | Redis 7.0.15 | Ratio | Ratio spread | Server cores |
|-----------|-------------|--------------|-------|--------------|--------------|
| SET       | 261 K ±21%  | 228 K ±27%   | 1.15× | [0.86, 1.23] | 0.996 / 0.998 |
| GET       | 269 K ±16%  | 253 K ±18%   | 1.08× | [1.01, 1.23] | 0.997 / 0.997 |
| LPUSH     | 262 K ±25%  | 230 K ±23%   | 1.13× | [0.79, 1.30] | 0.998 / 0.998 |
| LPOP      | 265 K ±16%  | 248 K ±16%   | 1.11× | [1.03, 1.40] | 0.996 / 0.998 |
| SADD      | 266 K ±10%  | 256 K ±17%   | 1.05× | [0.99, 1.29] | 0.998 / 0.999 |
| HSET      | 266 K ±9%   | 251 K ±14%   | 1.09× | [1.04, 1.20] | 0.998 / 0.998 |

At depth 1, **over TCP**, do not read any individual row as a result. Three
spreads clear 1.00 here — GET, LPOP and HSET — but in a five-pass run of the
same arms an hour earlier it was SET, GET, LPOP and SADD, and LPUSH and HSET
contained 1.00. **Which rows clear keeps changing, which is what a false
positive out of six comparisons looks like.**

What does not change is the direction: all twelve medians across those two runs
sit above 1.00, between 1.05× and 1.15×. So the honest reading is a small
advantage of **at most about 10%**, too close to resolve row by row — not the
flat tie an earlier run reported, and not something to quote per operation.

The qualifier matters: over `AF_UNIX` the same comparison is 1.28×–1.29×, and
SET's spread does not contain 1.00 (see **What the transport costs**). This table
is a TCP measurement, and at depth 1 that is mostly a measurement of the
kernel's per-message price, which both servers pay alike.

**Pipeline depth 100** — 2 M operations per test, 9 passes:

| Operation | Socketley    | Redis 7.0.15 | Speedup | Spread       | Server cores |
|-----------|--------------|--------------|---------|--------------|--------------|
| SET       | 10.31 M ±37% | 3.06 M ±13%  | 3.45×   | [3.27, 4.57] | 0.992 / 0.999 |
| GET       | 13.39 M ±7%  | 3.63 M ±10%  | 3.68×   | [3.53, 4.04] | 0.982 / 0.996 |
| LPUSH     | 8.90 M ±23%  | 2.78 M ±14%  | 3.32×   | [2.97, 3.91] | 0.993 / 0.998 |
| LPOP      | 10.26 M ±25% | 2.43 M ±8%   | 4.27×   | [3.90, 4.99] | 0.996 / 0.998 |
| SADD      | 8.86 M ±17%  | 3.23 M ±12%  | 2.62×   | [2.26, 2.95] | 0.994 / 0.997 |
| HSET      | 10.12 M ±22% | 2.86 M ±9%   | 3.52×   | [2.91, 3.80] | 0.989 / 0.999 |

Pipelined, socketley is **2.6× to 4.3× faster than Redis 7**, and every spread
sits well above 1.00. The previous run, on the older kernel, gave 2.4× to 4.6×
and reproduced all six within their spreads — which is the only kind of
cross-run agreement worth quoting: the conclusions repeat, the absolute figures
do not have to.

At 13.4 M GET/s on one core at ~2.15 GHz an operation costs about **158 cycles**
— parse, hash lookup, encode, with no syscall of its own. The same operation on
the serial path costs about **7,970 cycles**, and the difference is the
per-message charge that pipelining removes. (An earlier revision of this section
put the serial figure at ~1,160 cycles, which cannot be right: it contradicts
the 3.5 µs per operation quoted two paragraphs above it in the same text.)

The same data read the other way is the clearer statement of cause. Pipelining
is worth roughly **33× to 50×** to socketley and **10× to 14×** to Redis, and
the mechanism is that a batch is where this tree does its work:

- **Zero-allocation RESP2 codec** — parse and encode directly into and out of
  the connection buffer with `to_chars` and `string_view`
- **Batch CQE drain** — every completion from a submit round in one pass, one
  `io_uring_cq_advance`
- **`writev` coalescing** — up to 16 responses in a single `writev` SQE

None of the three has anything to bundle at depth 1, which is exactly why the
advantage is absent there.

### Sharding a cache

`--shards` is two different bargains and the README used to quote neither. On a
**server** the shards are interchangeable — every one answers every request — and
the man page's measurement is 3.57× at eight shards. On a **cache** they are not:
a key belongs to exactly one shard, `SO_REUSEPORT` hands out whole connections
without knowing the key, and the shard that accepted a foreign key relays it to
the owner.

Measured 2026-09-20, daemon pinned to four cores with eight `redis-benchmark`
processes of 24 connections each on the other twelve, GET at depth 1, six
interleaved passes with the order rotated, first discarded, clock probe on both
ends (2.15–2.23 GHz). Client CPU beside every row, because a capped client
inverts the sign of a comparison before it changes its size — it never passed
5.8 of its 12 cores.

| arrangement | GET/s | × 1 shard | server cores | µs CPU/op |
|---|---|---|---|---|
| 1 shard | 240,671 | 1.00 | 1.00 | 4.16 |
| 2 shards, one address | 251,959 | 1.05 | 1.91 | 7.60 |
| 4 shards, one address | 421,093 | 1.75 | 3.95 | 9.38 |
| 4 shards, slot-routed | 673,017 | 2.80 | 3.65 | 5.43 |

**Behind one address the shards buy far less than the cores they take.** Two of
them take 1.91 cores and return 1.05×; four take 3.95 and return 1.75×. Half the
keys, then three quarters, belong to a sibling, and the per-operation cost of
serving them roughly doubles — 4.16 µs at one shard against 7.60 at two and 9.38
at four. Point a client that picks the owner at the same four shards and they
return **2.80×** at 5.43 µs, which is most of what the crossings were costing.

**How well the crossings batch decides the size of this, and the client decides
that.** The mesh queues a crossing and flushes once per loop turn, so requests
that arrive together cross together. At the same 192 connections, twelve client
processes of sixteen connections give the two-shard arm 0.90× where eight of
twenty-four give it 1.05× — while the one-shard arm reads 235,421 and 240,671,
unmoved. On a floor of two processes and two rings, one crossing at a time costs
8.13 µs where thirty-two in a batch cost 282 ns apiece. **A figure for this flag
is a figure for an arrival pattern**, and the table above is the friendlier of
the two shapes tried.

**The ceiling above that is the machine, not this flag.** Four independent
`redis-server` processes on the same four cores, driven the same way, reach
2.88× where four slot-routed shards reach 2.80× — and socketley is ahead of them
in absolute throughput at every count tried, 1.12× at one and 1.09× at four.

**What was not established.** The curve above four shards. `redis-benchmark`
costs two to three times the server's CPU per operation, so on sixteen cores the
server can never be given more than four or five and still be saturated.
Settling it needs a C client of the kind `test/benchmark/floor_*.c` already are.

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

### Pipelined throughput, and what it costs to get it

A cache worker profiled at pipeline depth 100 spends **65% of its time in one
hash-table lookup** and another 2.7% hashing for it. At depth 1 the same lookup
is 13%, because there the kernel's per-message charge is 86% of the operation —
which is why work on the cache's own code pays pipelined and almost not at all
serially.

Measured against the commit this branch started from, GET at `-P 100`, nine
interleaved passes each way with the arms exchanged, first discarded:

| | GET/s | µs CPU/op |
|---|---|---|
| before | 4,415,620 | 0.226 |
| after | **5,678,045** | **0.176** |

**+24.3%**, eight of eight passes in each direction. Three changes: huge pages
for the cache's heap (+17.9%), comparing short keys inline instead of calling
libc (+4.3%), and the per-connection memory work below (+2.9%).

**The huge-page share depends on the machine having 2 MB pages to give.** On a
box whose `vm.compaction_proactiveness` had been turned down and whose
`/proc/buddyinfo` showed twelve order-9 blocks, the same A/B read **+3.2%**; at
716 blocks it read +17.9%. `thp_fault_fallback` was zero throughout — a starved
system still gets huge pages and gets less out of them. Check `buddyinfo` before
doubting the figure.

### Many simultaneous connections

This section used to say that many simultaneous connections are "not
proportionally fast", and said in the same breath that the figure behind it came
from write-only benchmarks that compared two socket-buffer fill rates rather
than two service rates. Re-established on round trips, against Redis on the same
four cores with the same client, it is **the other way round**: the cost per
operation *falls* as connections are added, because more requests arriving
together is what lets the loop batch them.

| connections | socketley | µs CPU/op | RSS | Redis 7 | µs CPU/op | RSS |
|---|---|---|---|---|---|---|
| 16 | 158,266/s | 6.31 | 38.5 MB | 159,008/s | 6.28 | 29.3 MB |
| 64 | 223,250/s | 4.47 | 38.5 MB | 183,528/s | 5.44 | 30.4 MB |
| 256 | 250,970/s | 3.98 | 40.5 MB | 219,728/s | 4.54 | 32.8 MB |
| 1024 | 253,398/s | 3.89 | 40.5 MB | 220,476/s | 4.48 | 39.8 MB |

Level with Redis at sixteen connections and 14 to 22% ahead from sixty-four up.
Read the RSS column beside it: over those 1008 further connections socketley
grows **2.0 MB** where Redis grows **10.5 MB**.

That is recent. An idle connection used to be charged three or four blocks of
four to sixty-four kilobytes the moment it was accepted and before it had said
anything — measured, and then taken out where taking it out did not cost
something else:

| runtime | before | after | |
|---|---|---|---|
| cache | 14.10 KB | **2.04 KB** | −85.5% |
| server | 22.21 KB | **4.92 KB** | −77.8% |
| proxy | 69.93 KB | 65.93 KB | −5.7% |

The proxy keeps its sixty-four kilobytes on purpose, and that is a measurement
and not an omission: taking them lazily from the heap made the *bounded* upload
path hold 113 MB more at 1,100 uploading clients, and a sixteen-kilobyte inline
buffer made it worse still. The buffer is load-bearing for the memory bound, not
for speed. `socketley/runtime/proxy/proxy_instance.h` carries both figures at the
field.

What remains, measured and deliberately not acted on: the pool builds every
connection with `make_unique<T>()`, which value-initializes, so the whole struct
is zero-filled and touched before a byte arrives. `make_unique_for_overwrite`
would skip that at no cost — but `int fd;` and four `io_request` members carry no
initializer of their own and rely on the zeroing, so the swap wants MSan before
anyone makes it.

## Quick Start

After installing — via `scripts/install-from-source.sh`, `install.sh` or
`dpkg -i` — the daemon runs as a systemd service, so there is no manual startup.
Only root and members of the `socketley` group reach it; anyone else silently
gets a private daemon of their own, so join the group with
`sudo usermod -aG socketley $USER` and log in again:

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
socketley daemon                          # start the daemon (systemd does this when installed)
socketley create <type> <name> [flags]    # types: server, client, proxy, cache
socketley add <path> [--name <n>] [-s]    # register and manage an external SDK binary
socketley attach <type> <name> <port>     # register an external process as a runtime
socketley start <name|pattern>... [-i]    # start runtime(s), -i for interactive
socketley stop <name|pattern>...          # stop runtime(s)
socketley remove <name|pattern>...        # remove runtime(s)
socketley send <name> [message]           # send/broadcast message
socketley stats <name|pattern>...         # show runtime statistics
socketley restart <name> [-i]             # stop and start, keeping the configuration
socketley reload <name|pattern>...        # restart runtime
socketley reload-lua <name|pattern>...    # hot-reload Lua script
socketley show <name|pattern>...          # print JSON config
socketley edit <name> [flags]             # modify runtime config
socketley import <name> [json]            # update config from JSON (stdin if omitted)
socketley owner <name>                    # show parent/children/policy
socketley ls                              # list all runtimes
socketley ps                              # list running runtimes
socketley --lua <file.lua>                # run Lua orchestration script
socketley cluster ls|ps|group|show|stats|watch  # multi-daemon cluster inspection
socketley dashboard                       # print the web dashboard URL
socketley ping                            # ask the daemon to identify itself
socketley version                         # print the version; needs no daemon
```

Glob patterns supported: `socketley stop "api-*"` stops all runtimes matching `api-*`.

See `socketley --help` or `man socketley` for full documentation.

### Who a server answers: `--send-to`

A server with no Lua `on_message` still has to decide who hears an incoming
message, and `--mode` never said: it names a *direction*, not a set of
recipients. `--send-to` names the recipients, as a comma-separated set of
**disjoint** ones:

| value | who |
|---|---|
| `sender` | the connection the message came from |
| `others` | every other connection, the master excepted |
| `master` | the master connection, which only `--mode master` has at all |

Disjoint, so `sender,others` reaches everyone and there is deliberately no
`all`: `others` meaning "everyone else" would make `others,master` mean exactly
`others`, which is one behaviour under two spellings.

Unset keeps what each mode has always done — `others` in `--mode inout`, which
is the default mode, and in `--mode master` dropping what a non-master says.

```bash
socketley create server echo  -p 9000 --mode inout  --send-to sender        -s
socketley create server chat  -p 9001 --mode inout  --send-to sender,others -s
socketley create server relay -p 9002 --mode master --send-to master        -s
```

It is refused outside `--mode inout` and `--mode master` — `in` and `out` carry
messages one way and answer nobody, so no recipient means anything there — and
`master` is refused outside `--mode master`, where nothing ever claims that
connection. Both are refusals rather than warnings: a flag accepted and then
ignored is the shape this option exists to remove.

**`--master-forward` is gone.** It was one recipient carrying its own flag, and
it is now `--send-to master` — byte for byte the same behaviour, including the
`[<fd>] ` prefix that puts the sender's descriptor in front of the forwarded
line so the master can tell two clients apart. Typing the old flag prints the
replacement rather than "unknown flag".

**`--mode master` with `--udp` is refused.** Master mode claims a *connection*
as the master, and a datagram is not one.

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

A relative path is resolved where you run the command, and the packaged daemon
runs as user `socketley`, which must be able to read the file.

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
- x86\_64. `premake5.lua` declares one platform and Release compiles
  `-march=x86-64-v2`, so another architecture is a port and not a flag.

`scripts/install-from-source.sh` checks every line of this list before it
builds anything, and refuses with the reason rather than failing later.

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
