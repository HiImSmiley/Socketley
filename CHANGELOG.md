# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- **A cache serves only this machine unless told otherwise.** A TCP peer whose
  address is not loopback is answered `-DENIED` and closed. A cache has no
  password and answers every client with everything it holds, so reaching one
  from the network is now something to say: create it with `--public`, or give
  its listener mutual TLS (`--tls --ca`). A follower on another host needs its
  leader to be public. Unix-socket peers are unaffected.
- A relative path in a flag the daemon opens (`--lua`, `--log`, `-w`,
  `--persistent`, `--http`, the TLS files, `--listen unix:`) is resolved against
  the directory the command was typed in, not the daemon's.
- A proxied HTTP request carries `X-Forwarded-For`, `-Proto` and `-Host`.
- The daemon ignores SIGHUP; rotate `--log` and `-w` files with `copytruncate`.
- The packaged unit reads home directories (`ProtectHome=read-only`), so a
  script or certificate kept there can be used.
- **SDK:** `cache_store::hget()` and `lindex()` return
  `std::optional<std::string_view>` instead of `const std::string*`, and the
  list `list_ptr()` returns is read through `at()` and iterators of views. A
  small hash and a small list are packed and hold no `std::string` to point at.
- A cache is faster once its keyspace outgrows the CPU caches: the keyspace is
  an open-addressed table, the RESP loop fetches the keys of the next eight
  pipelined commands ahead of running them, and MGET/MSET fetch theirs in
  batches. Pipelined GET over 100,000 random keys went from 4.7 M to 8.8 M/s,
  over a million from 2.9 M to 7.4 M; MGET and MSET of ten keys gained 72–78%.
- Small hashes, sorted sets and lists take less memory: a five-field hash 631 →
  248 bytes, a five-member sorted set 1,575 → 248, a five-element list 808 →
  231. RPUSH is a third faster and LRANGE 9–12%; LINDEX and LSET on lists of
  tens of elements are up to 14% slower, since a packed list is walked.
- A cache key costs 17 bytes less in every type, and a small set 81 bytes
  less: the keyspace and field tables hold one word per slot instead of two.
  Writes into one large hash are 6% faster.
- A cache key's entry holds its key as a 4-byte length instead of a 16-byte
  view, 16 bytes less a string, hash or list key: a string key is 85 bytes
  against Redis's 104, a five-field hash 165 against 168.
- A small sorted set stores a whole-number score in 1, 2 or 4 bytes instead of
  8, as Redis's listpack does, and no longer carries the index pointer only a
  large one uses: 133 bytes a five-member set against Redis's 136.
- ZREVRANGE on a small sorted set is 67% faster and ZINCRBY 58% faster.
- A large sorted set keeps each member's name once, inside its skiplist node,
  and finds a member through an index of the nodes themselves: 90 bytes a
  member of a million-member set instead of 186 (Redis 125), ZADD into it 21%
  faster and ZRANK 12% faster.
- ZINCRBY or ZADD that leaves a member between the same neighbours changes
  its score in place instead of taking it out and putting it back: 5% more
  ZINCRBYs by 0.001 on a million-member set, at 6% less CPU each.
- ZADD is about twice as fast (0.53× Redis → 0.99×), SADD into a large set 54%
  faster, and HGET/ZSCORE over many small keys 30–50% faster.
- The proxy sends a relayed message directly when nothing is queued ahead of
  it, instead of through a submission and a completion: one connection's small
  round trips went from level with nginx's stream proxy (0.96-0.99x) to
  1.03-1.08x, at 11% less CPU per round trip.
- A server's and a cache's answer to a single client goes out by a direct
  send instead of a submission and a completion: 2.5-3% more round trips and
  6-7% less CPU each. With several clients the answers still share one ring
  entry per turn, which a send per answer measured slower.
- A server's message to its upstream goes out by a direct send when nothing
  is queued ahead of it, as its answers to a single client already did, and
  `self.upstream_send` no longer builds a string and a shared pointer per
  message: 2.2% more upstream round trips, the distance to a C relay 2.39 →
  1.82 µs.
- A line a server script sends to one client with `self.send` goes out
  straight from the script's string when nothing is queued ahead of it,
  instead of being copied into a new string first: 2.7% more 16 KB round
  trips through a Lua echo, the distance to a C echo 2.04 → 1.65 µs.
- A message a server script sends to one WebSocket client with `self.send` is
  framed without being copied twice: when nothing is queued ahead of it the
  frame goes out from a header on the stack and the script's string, and
  otherwise it is built once from the message rather than from a copy of it
  with a newline added. TODO: measurement.
- A client hands its script each line straight from the buffer it was read
  into, and copies only a line that is still unfinished at the end of a read:
  TODO% more lines a second through a client script.
- A client counts its messages and bytes with plain adds instead of locked
  ones, since only its own loop writes them: TODO%.
- `EVAL` is 46% faster, and a script calling `redis.call` about twice as fast:
  `redis.call` works on the Lua stack and hands its arguments to the cache
  without encoding them as RESP. An error a script catches from `redis.call`
  is the cache's own text, without a `lua: error:` prefix.

### Fixed

- A script that stopped its own runtime from inside a callback
  (`socketley.stop(self.name)` in `on_message`) read and popped an empty frame
  stack once the callback returned.
- A TCP proxy whose backend shut its sending side first no longer drops the
  rest of what the client is still sending: the backend's FIN reaches the
  client after the last byte of its answer, and the pair closes once both sides
  have finished, as HAProxy does.
- The proxy finds the end of a chunked response, so the next keep-alive request
  is served at once instead of after the 10 s header deadline, and the end of a
  chunked request body, so a request pipelined behind one is checked like any
  other instead of reaching the backend raw.
- A follower can join a leader holding more than 8 MiB.
- A dump restores a TTL as the deadline it was, not as the time that was left.
- A write accepted after a torn journal tail survives the next crash.
- `EVAL` refuses precompiled bytecode.
- A script can no longer end the cache's worker: a returned table whose
  `__index` raised did, and so did `EVAL` from inside `EVAL`. A script is
  refused, as Redis refuses it, the commands that would outlive it on the
  caller's connection (`MULTI`, `WATCH`, `SUBSCRIBE`, `EVAL`, `SCRIPT`, `RESET`,
  …), and a blocking pop in a script answers at once.
- Twelve cache answers Redis clients depend on, among them a bare
  `UNSUBSCRIBE`, the subscription count, `HSET`'s count, `READONLY`, and
  `FLUSHALL` and `MULTI` on a sharded cache.
- A stopping persistent cache is given time to finish its dump.
- A request the server or the proxy refuses while it is still arriving (413,
  431, 400, 502–504) reaches the client instead of being reset away by the
  unread rest: the connection reads it away behind its FIN, for up to ten
  seconds or 64 MiB.
- A server answers a request head past 16 KiB with `431`, as documented,
  instead of closing without a word.
- A worker whose control socket backs up says so once per stall, not once per
  refused frame.
- A cache's memory limit holds against a hash field or list element set long
  and then short: the long value's buffer stayed behind, charged as the short
  one, so 64 fields set to 100 KB and back to one byte held 6.4 MB the cache
  counted as 5 KB, as many times over as a client liked.

## [1.1.0] - 2026-08-27

Six months of work since v1.0.9, across 581 commits. The headline is that a
runtime is no longer confined to the daemon's process or to one core.

### Added

#### Multi-process runtimes and sharding

- **Every runtime now runs in its own supervised worker process.** One runtime
  can no longer take the daemon down with it. There is no opt-out and no flag:
  `--daemon-process`, and the older `--out-of-process` / `--in-daemon` pair it
  replaced, are all gone. A command line carrying one is refused as an unknown
  flag; a configuration file with `daemon_process` in it is refused naming the
  line.
- **The whole cross-runtime Lua API works in a worker.** Thirteen calls were
  refused there; the count is zero. `socketley.send/.list/.get` and
  `socketley.cluster.*` are answered from a replica map the daemon pushes;
  `.create/.start/.stop/.remove` are asked of the daemon over a socket of the
  worker's own and wait for the answer, so `if socketley.create(...) then`
  branches on what happened; and `socketley.pipe` across two runtimes and
  `self.route()` reach a runtime in another process. Despite the name neither
  hands a descriptor over — the origin keeps the socket and relays.
- **A script runs when its runtime starts, not when it is created.** `create`
  compiles the file — one that does not parse is still refused by the command
  that asked — and the worker runs it. Without `-s` there is no worker yet, so
  the top level has not run, `socketley.subscribe` has not registered, and a
  global like `tick_ms` has not been checked; all of that happens at `start`,
  and a refusal there is reported by that command. Previously a runtime kept in
  the daemon loaded and ran its script during `create`.
- A worker that will not accept its configuration now sends the reason up, so
  `create` says `'path' must start with '/'` rather than "the reason is in the
  daemon log".
- `on_cluster_join`, `on_cluster_leave` and `on_group_change` reach a worker.
  They previously fired only for a runtime inside the daemon, which since the
  split meant nowhere.
- A map change made from a script is visible to that script immediately:
  `socketley.stop("x")` followed by `socketley.get("x")` reports `stopped`,
  where the worker's replica used to answer `running` until the next push.
- When a runtime holding routed connections goes away — stopped, removed,
  crashed or killed — every runtime on the other end is told to let go, and its
  `on_disconnect` runs. The daemon does the telling, because a killed worker
  runs no teardown of its own.
- **`--shards N`** runs a single runtime across N worker processes behind one
  port via `SO_REUSEPORT`, on servers, proxies and caches.
- A **sharded cache keeps one keyspace.** `mget`, `dbsize`, `publish` and
  `SET`/`GET` answer for the whole runtime rather than for whichever process
  the client happened to reach. Dumps record their shard count and refuse to
  load under a different one, because that loses keys in silence.
- A **sharded server's Lua** sees the runtime, not its own process:
  `self.clients()`, `self.send` and the connection counts span all shards.
- A **cross-process request channel**, so a runtime in one process can ask a
  runtime in another — and a runtime that cannot see its target now says so
  instead of answering as though the target did not exist.
- **`socketley.cluster.*` and the runtime map work inside a worker.** Twelve
  Lua calls that used to be refused for being in a worker now answer.

#### TLS on every role

- **Server**, **cache** and **proxy** listeners terminate TLS, including mutual
  TLS via `--ca`.
- **Client** runtimes dial over TLS, pinning the host from `-t` and verifying
  the chain against the system store.
- A **proxy dials its backends over TLS on the other leg**, and reuses the
  backend handshake instead of performing one per request.
- The **health probe handshakes**, so a TLS backend can be checked by asking it
  something rather than by opening a socket at it.
- A cache **refuses to replicate out of a TLS listener in cleartext**.
- The **SDK can present a client certificate**.
- `--tls` with `--udp` is refused: that would be DTLS, which is not implemented.

#### Clustering, transport and routing

- **`--cluster`**, off by default — client routing is a decision rather than a
  consequence of `--shards`.
- **`--listen unix:/path`** on a listener and **`--backend unix:/path`** for a
  proxy's backends.
- **`--cpus max | 0-3 | 0,1,2,3`** says where the I/O may run, and **SQPOLL is
  now a choice** rather than always on.
- A **WebSocket client can talk through a socketley proxy** instead of hanging
  after the handshake.
- A filter can **remove** a header, not only add or overwrite one.
- An endpoint can declare **which methods it takes**, so the gateway can refuse
  the rest.
- A connection can be **moved to another process, or relayed to one**.
- `socketley daemon` reads the command line it is given.

#### Lua

- **A callback that never returns no longer takes the daemon with it** — there
  is a deadline.
- `socketley.unsubscribe`, so a subscription can be ended.
- A runtime in a worker declares its routes and the daemon publishes them.

#### Operations

- `socketley stats` reports a worker's figures with an age, rather than as
  though it had just read them.
- A runtime that **failed to start is visible to `ps`** — which is the command
  an operator types when a runtime did not start.
- `create` no longer stalls every other runtime for the duration of its
  `fsync`.

### Security

- **The IPC socket is `0660 socketley:socketley`.** It was `0666`, so any local
  user could drive the daemon and run code as its owner. Membership of the
  `socketley` group is now the administrative boundary; upgrading tightens it,
  and the package says so on install.
- **A cache's `--persistent` dump is no longer readable by every user on the
  machine.** The state directory is `0750` and the records inside it `0600`;
  they contain `--master-pw` in plaintext and the paths of TLS private keys.
- **A `.deb` now ships `/usr/share/doc/socketley/copyright`.** It previously
  shipped none, which was both a Debian policy break and a distribution of
  statically linked MIT code with no notice attached.

### Fixed

264 fixes. The ones a user would notice:

- A **runtime whose worker refused its configuration was recorded as running**
  and restored on the next daemon start, where it stole unix socket paths and
  answered 404 forever.
- **HTTP request framing** was stated nine times across two runtimes, and seven
  of its eight rules existed in only one of them — the server executed smuggled
  requests the proxy refused. It is now one decision in
  `shared/http_framing.h`.
- A **connection left waiting on a read only its dead peer could finish** — the
  same defect in the cache and, months later, in the server. Now decided once
  in `shared/conn_reachability.h`.
- **HTTP took one request per read** and left the rest for a read that was
  never coming.
- `reload-lua` on a script that would not compile left the runtime **with no
  script at all**; on a script with a timer it freed the context and left the
  timer pointing at it.
- A **stopped runtime went on running its script's timers**.
- Cancelling a Lua timer **muted it without withdrawing it**.
- `start` reported success for a worker that had not started, and `reload`
  never reached one.
- A full submission queue was read as a permanent failure and **the message was
  thrown away**.
- A RESP client in the relay set **read relay bytes as its reply**.
- One client that stopped reading **held a stopped runtime forever**.
- A **configuration file could not ask for a runtime in the daemon**.

### Changed

- The `--out-of-process` / `--in-daemon` flag pair is replaced by
  `--daemon-process`. Neither old spelling is kept as a synonym.

---

## [1.0.9] - 2026-03-02

Earlier releases are recorded in the
[GitHub releases](https://github.com/HiImSmiley/Socketley/releases).
