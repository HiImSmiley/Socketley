# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Cluster runtimes: on a daemon in Raft mode the cluster heals itself.**
  `socketley cluster create server api -p 8080 --replicas 2` declares a
  runtime once for the whole cluster; the leader places each replica on a
  different node (fewest replicas first, lowest id on a tie) and writes the
  assignment to the Raft log, and every node starts, stops and removes its
  replicas through the same `create`, `start`, `stop` and `remove` an operator
  uses. When a node dies its replicas run on survivors with no operator action:
  measured at the defaults on one host with real daemons and `kill -9`, a
  follower's replica was serving again on a survivor after 3.9-4.3 s, a
  leader's after 5.1-6.0 s (an election first). Also `cluster scale <name> <n>`,
  `cluster remove <name>` and `cluster placement`, which shows the runtimes,
  where each is placed and what is unplaced, the leader's view of every node,
  and this node's replicas. A server, a proxy, a client or a cache (below).
  `{node}` in the flags is the name of
  the node running the replica, which is how several nodes share one host
  (`--listen unix:/run/api-{node}.sock`). Replicas are marked `[cluster]` in
  `ls` and `ps` (`"cluster":true` in `--json`, `cluster:replica` in `stats`),
  have no state file, and refuse `stop`, `start`, `remove` and `edit` by name.
  A replica count above the node count runs what fits and `placement` says how
  many are unplaced; nothing is rebalanced when a node returns.
- **A node serves its replicas only while it holds a lease from the leader.**
  A follower asks for one every quarter election timeout; the leader answers
  when it holds a quorum, and calls a node down when it has heard no request for
  `--raft-down-after` (default four election timeouts, at least three). A lease
  runs from when the request was sent and lasts three quarters of that time, so
  a node the leader cannot reach stops serving a quarter of the timeout before
  its replicas move: a minority, an isolated node and a leader that lost its
  quorum stop, and a healed node runs only what the log still gives it. A lease
  that had lapsed is taken up again only after the node has applied the leader's
  log as it stood at the grant. Losing the quorum stops every cluster replica
  on every node until there is one again. A hung daemon (not a dead one) cannot
  stop the workers of a server, a proxy or a client (a cache's fences itself),
  and a leader change longer than the lease restarts the
  survivors' replicas; both are in the manual, with what is not built yet.
  Tested in a simulation of the real Raft core and the real placement logic
  (300 seeds of loss, delay, one-way cuts, splits, kills and reboots in the
  suite, 6000 run once) that checks after every tick that no runtime runs on
  more nodes than it has replicas, and with three real daemons and `kill -9`.
- **A cluster cache survives the loss of its primary's node.**
  `socketley cluster create cache db -p 6379 --replicas 3` gives one primary
  and followers on distinct nodes, replicating with the cache's own
  `--replicate` (a full dump, then every write). When the primary's node dies
  the leader promotes the follower whose copy is the most up to date and writes
  it to the log with the next epoch: measured with `kill -9` and real daemons, a
  survivor took its first write 3.9-4.1 s after a node that was not the Raft
  leader died (11 kills) and 5.2-5.7 s after the leader's (4 kills). A proxy
  with `--backend @db` follows the primary (the cache's name is published as a
  group of one), and `cluster placement` names it, with the epoch and offset of
  every copy. What a replica may do is decided twice: the log must name the very
  process it runs (an incarnation, so a restarted primary comes back empty and
  does not lead) AND its node must hold a lease, and the worker enforces the
  lease itself: it takes the daemon's order every 100 ms, standing for the lease
  the daemon had left, so a daemon that hangs or dies leaves a primary that
  refuses every command within its lease (measured 2.7-3.1 s with a daemon
  stopped by SIGSTOP, 2.8-3.2 s for a primary that lost its quorum, both in nine
  runs). A fence keeps the data, so a primary that lost its quorum for a minute
  is the primary again with everything it held. The old primary that comes back
  follows the new one and takes a full dump. Replication stays asynchronous, and
  the manual says what that loses, measured: with a client writing and `kill -9`
  of the node, none of 4,500-4,900 writes a few seconds apart, none of
  630,000-720,000 pipelined at 230,000 a second, and 876,000-922,000 of about 1.6
  million when both followers had stopped receiving four seconds before; what
  survives is always a prefix of the primary's history. Promotion compares copies
  by epoch and then a count of the records the primary produced, which rides on
  every lease request. A cache with `--tls`, `--listen`, `--shards` or
  `--replicate` is refused as a cluster runtime. Tested in the cluster
  simulation (real Raft core, real brain, the real replica state machine, a
  hung daemon, cuts and reboots; no cache is ever led by two replicas at any
  tick) and with three real daemons.
- **Two nodes cannot share a `--raft-name`.** `{node}` would name both alike, so
  the leader refuses a join whose name (or whose name once made safe for a
  command line) is a member's, and the joiner stops with the reason in its log
  and in `cluster raft-status`.
- **Streams in the cache**, wire-compatible with Redis 7.0: XADD (NOMKSTREAM,
  MAXLEN/MINID with `=` and `~`, LIMIT, `*`, `ms-*` and explicit ids), XLEN,
  XRANGE, XREVRANGE, XREAD with BLOCK, XDEL, XTRIM, XSETID, XGROUP (CREATE with
  MKSTREAM and ENTRIESREAD, SETID, DESTROY, CREATECONSUMER, DELCONSUMER),
  XREADGROUP with BLOCK and NOACK, XACK, XPENDING, XCLAIM, XAUTOCLAIM and XINFO
  (STREAM with FULL, GROUPS, CONSUMERS); `TYPE` answers `stream` and
  `SCAN`/`DBSIZE` take `TYPE stream`. Replies and error texts are compared
  against a redis-server command by command. A stream is kept in blocks of up
  to a hundred packed entries, cut where Redis cuts its nodes so `MAXLEN ~`
  trims what it trims there; a million short entries hold 24 bytes each
  against Redis's 25. Readers blocked on a stream are woken by the XADD they
  wait for. The dump, the journal and a follower carry entries, counters,
  groups, consumers and every pending entry with its delivery time and count;
  an XADD with `*` replicates the id it got. XADD, XGROUP CREATE and
  CREATECONSUMER are refused at `--maxmemory`, as Redis refuses its denyoom
  commands. On a sharded cache XREAD's streams must belong to one shard, and a
  blocking read is served by the shard that owns them (its `--cluster` port).
  Against Redis 7.0.15 over four `redis-benchmark` clients: XADD 1.23× at
  depth 1 and 2.59× at depth 16, XRANGE and XREAD about 1.85× and 3.2–3.5×,
  XREADGROUP 1.87× and 3.87×, XACK level.
- **SDK:** `cache_store` holds streams (`stream_get`, `stream_find`,
  `stream_make`, `stream_admit`, `stream_change`) as `stream_log`, which is
  usable on its own from `socketley/runtime/cache/stream_log.h`.
- **`socketley daemon --fast-lo [own|all|trust]`** puts TCP pairs whose both
  ends are on loopback (127.0.0.1, 127.0.0.1 IPv4-mapped on a dual-stack
  socket, or ::1) on a kernel shortcut: a BPF sockops program enters both
  sockets in a sockhash when the connection is established, and an `sk_msg`
  program places every send straight into the peer's receive queue, skipping
  TCP/IP, the loopback device and its softirq. Off unless given; the mode
  defaults to `all`. Needs `CAP_BPF` and `CAP_NET_ADMIN` and cgroup v2; without
  them the daemon logs `fast-lo: unavailable, serving without it` and serves
  on the ordinary path. The programs are hand-assembled, loaded with a raw
  `bpf(2)` (a verifier `EAGAIN` from the daemon's own pending io_uring task
  work is retried, as libbpf does) and detached when the daemon exits.
  - **Modes.** `own`: only pairs whose both ends are the daemon's runtimes,
    such as a client runtime and a server runtime. `all`: also a local client
    of any process connecting to a runtime's port, and every connection a
    runtime makes to any local listener (a tcp proxy with `--backend
    127.0.0.1:8080` in front of a local application, a client runtime, a Lua
    HTTP call). `trust`: `all` without the receiver rule below.
  - **The receiver rule (`own`, `all`).** A send is redirected only when the
    socket that will receive it is one of the daemon's workers' (a runtime that
    connected, or one that accepted on a runtime's listener); a send into a
    foreign socket goes by ordinary TCP, each direction of a pair decided by
    its own receiver. A redirected byte sits in the receiver's ingress queue,
    which only `recvmsg` drains: a foreign process reading with `splice(2)`,
    `sendfile(2)`, `TCP_ZEROCOPY_RECEIVE`, Go's `io.Copy` between two TCP
    connections or HAProxy with splicing never sees it (measured: a Python
    backend splicing behind a proxy echoed 0 of 500 bytes) and cannot be told
    apart from outside. The rule keeps such readers whole; the price is that a
    foreign client of a cache, or a proxy's foreign backend, gains nothing on
    the reply. `trust` is for an operator who knows every local client reads
    with `recv`/`read`/`recvmsg`: it redirects into foreign receivers too and
    a reader that splices loses its bytes. `daemon stats` and
    `socketley_fast_lo_info{mode}` say which is running. Our own proxy already
    keeps splice off any pair with a loopback leg. Measured with
    `redis-benchmark` (50 connections, 4 threads) against a cache, six
    alternating passes, requests per second off / `all` / `trust`: GET -P1
    240-279K / 222-250K / 387-667K, SET -P1 222-286K / 197-273K / 462-632K,
    GET -P16 2.3-4.0M / 2.7-3.4M / 5.3-6.9M; a bulk reader of 64 KiB values
    1377-1488 / 1276-1322 / 2464-3040 MB/s (one GET -P1 pass of the first run,
    169K off, was taken beside another job and is left out). A client runtime
    against a cache, both ends ours, round trips per second off / `all`: one
    in flight 83-85K / 110-116K, eight 577-700K / 686-771K; a tcp proxy to a
    local C echo backend, 64 B one connection, 44-48K off / 41-45K `all` /
    86-88K `trust` (the last measured on the build before the receiver rule,
    which redirected exactly as `trust` does).
  - **Bounded.** The redirected backlog is capped by `--fast-lo-limit
    <per-pair-MiB>,<global-MiB>` (default 4,64): the `sk_msg` program counts
    each pair's sends in a BPF map and, each time the count passes a mark, asks
    a reconciler thread through a BPF ring buffer for the peer's true queue,
    which it reads with one exact `sock_diag` lookup (`INET_DIAG_SKMEMINFO`,
    which counts the ingress backlog on this kernel) and hands back in tens of
    microseconds. A reader that keeps up is snapped back, so a pair moving 3
    GB/s stays on the shortcut; a pair whose peer really holds the per-pair
    bound, or whose count reaches twice it unanswered, is tainted to TCP, which
    then gives the ordinary `EAGAIN` backpressure, and a flag taints new sends
    once the sum across pairs reaches the global budget. A sweep once a second
    recomputes the sum and re-asks any check whose answer was lost. Without a
    bound a receiver that read nothing took 731 MiB before the kernel's global
    TCP memory ran out; with the default it stays near 4 MiB per pair. The
    taint is permanent, which keeps bytes in order: `tcp_bpf_recvmsg` drains
    the redirect queue before the TCP receive queue. Two edges stay coarse: a
    pair moving gigabytes a second whose answer is held up for more than about a
    millisecond reaches the hard ceiling and is tainted (costs speed, not
    bytes), and many pairs stalling in the same instant can each hold their
    per-pair bound before the global flag is raised.
  - **Fenced.** Under `all` and `trust` the sockops program is attached at the
    root cgroup, where it fires for containers too, so it bakes in the
    daemon's netns cookie (`SO_NETNS_COOKIE`; without it the shortcut refuses
    to attach) and takes only sockets of that namespace, and every insert at
    entry is `BPF_NOEXIST`, so a container's identical 127.0.0.1 tuple can
    neither overwrite a daemon socket's entry nor be redirected into. A
    connect of ours that never establishes deletes its mark on close.
  - **Seen.** Shortcut bytes skip netfilter, conntrack and the loopback
    device, so nftables on `lo` and `tcpdump -i lo` do not see them.
    `socketley daemon stats` prints `key:value` lines and the metrics endpoint
    carries `socketley_fast_lo_*`: the mode (`off`, `own`, `all`, `trust` or
    `unavailable` with the reason), sockets on the shortcut and pinned to TCP,
    sockets entered, taints by reason (`bound`, `unanswered`, `budget`,
    `peer_off`), and bytes held against the budget, counted in a per-CPU BPF
    array with one atomic add per entered socket and per taint, never per send.

- **`socketley daemon --raft-listen <ip:port>` runs a Raft node on the daemon.**
  Off unless asked for; nothing else about the daemon changes, and the cluster
  directory keeps working as before. This release forms the cluster and keeps
  it: leader election with pre-vote and check-quorum, a replicated log on disk,
  membership, and graceful handover. No runtime, placement or cache failover
  goes through it yet.
- `--raft-init` founds a cluster; `--raft-join <ip:port>` joins one, first as a
  learner and then promoted to voter once caught up. Both apply to the first
  start only; afterwards the node comes back from its own state.
- Mutual TLS between members is required (`--raft-cert`, `--raft-key`,
  `--raft-ca`, `--raft-name`); a certificate that does not name the member it
  speaks for is refused. `--raft-insecure` runs it in cleartext on purpose.
- The log is a CRC32C-checked WAL under the state directory, 0600, every write
  fsynced through io_uring before anything that depends on it is sent; a torn
  tail is cut back on restart. A SIGTERM'd leader hands leadership over first.
- `socketley cluster raft-status` shows role, term, leader, commit/applied,
  voters, learners and whether a quorum is reachable, and exits 2 without one.
- **The whole cross-runtime Lua API works in a worker.** Thirteen calls were
  refused there; the count is zero. `socketley.send/.list/.get` and
  `socketley.cluster.*` are answered from a replica map the daemon pushes;
  `.create/.start/.stop/.remove` are asked of the daemon over a socket of the
  worker's own and wait for the answer, so `if socketley.create(...) then`
  branches on what happened; and `socketley.pipe` across two runtimes and
  `self.route()` reach a runtime in another process. Despite the name neither
  hands a descriptor over — the origin keeps the socket and relays.
### Fixed

### Changed

- **Unix stream sockets get a 1 MiB send buffer** (512 KiB asked, doubled by
  the kernel, capped at `net.core.wmem_max`): every socket accepted off
  `--listen unix:` or a companion node by a server, cache or proxy, a proxy's
  connection to a `--backend unix:` or a local runtime's node, and a client's
  `-t unix:`. The sender's buffer is all the flow control a unix stream has,
  and an accepted one inherits nothing from its listener, so these ran at the
  208 KB default. One connection of pipelined 64 KB GETs, both builds up at
  once and alternating: a Python reader taking 4 MiB a read 2.21–2.33 →
  2.88–3.09 GB/s (1.32×, per-pass 1.27–1.38, n=11) with the cache worker at
  0.57 → 0.44 cores, 41% less CPU per byte; a TCP proxy in front of a cache
  reached over its node 3.21–3.82 → 3.53–4.26 GB/s (1.10×, 1.00–1.27, n=11);
  a proxy on `--listen unix:` 1.10× (0.86–1.38). A C reader and a Python
  reader taking 64 KB a read were at ~10 GB/s with the worker's core as the
  ceiling, and stay there (1.02×, 1.05×). `redis-benchmark -c 50 --threads 4`
  GET and SET at `-P 1` and `-P 16`: 0.96–1.00× per-pass medians, inside one
  tick of its ~0.125 s completion check. 512 KiB is the knee: 256 KiB gave less than
  half the gain and 1–4 MiB none more. Memory: 1000 idle connections
  hold 0 bytes of send buffer either way and the worker's RSS is unchanged; a
  connection whose reader stopped holds 1.07 MB in the kernel instead of
  223 KB. The server's per-accept 128 KB `SO_RCVBUF` on unix clients is gone:
  a unix stream receiver's buffer does not limit anything (4 KB and 4 MB read
  the same).
- XACK finds a pending entry through a hash index instead of walking an
  ordered tree of every pending entry: 50% more XACKs on a group with
  200,000 pending (level with Redis before, 1.48× after), at about 20 bytes
  more per pending entry.
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
  otherwise it is built once from the message. 1.5–3.3% more WebSocket round
  trips through a Lua echo; the distance to a C echo 1.44 → 1.16 µs at 64
  bytes and 1.80 → 1.48 µs at 1 KB.
- A client hands its script each line straight from the buffer it was read
  into, and copies only a line still unfinished at the end of a read: the
  distance to a C client at 16 KB lines 1.49 → 1.28 µs; unchanged at 64 bytes
  and 1 KB.
- Server, proxy, cache and client count their messages, connections and bytes
  with plain adds instead of locked ones, since only their own loop writes
  them. No difference this machine resolves.
- A read re-armed on a socket the last read left empty waits for data instead
  of first trying a receive that can only come back empty: the proxy's HTTP
  and early TCP reads, its read on a backend taken from the pool, a server's
  upstream read, and a client's single-shot read. No difference this machine
  resolves yet.
- A server's HTTP path allocates less per request: the header list is kept
  between requests on a keep-alive connection, a GET's `Cookie`, `Origin`,
  `Sec-WebSocket-Protocol` and `Authorization` are copied only for a WebSocket
  upgrade, a static path without a percent escape is looked up without being
  copied, a response with nothing queued ahead of it goes straight to the
  socket, and `on_http_request` gets its tables built at their final size and
  its `body` copied once. Together: the distance to a C server on one
  keep-alive connection 1.48 → 1.36 µs.
- `EVAL` is 46% faster, and a script calling `redis.call` about twice as fast:
  `redis.call` works on the Lua stack and hands its arguments to the cache
  without encoding them as RESP. An error a script catches from `redis.call`
  is the cache's own text, without a `lua: error:` prefix.
- A proxied HTTP request is rewritten into a buffer its connection keeps, so
  a keep-alive connection no longer allocates and frees one per request.
- An HTTP proxy with one backend keeps a keep-alive client's backend
  connection for that client's next request, from its second answer on,
  instead of returning it to the pool and probing it on the way back out, as
  HAProxy's `http-reuse safe` does. A backend closing such an idle connection
  costs the client nothing and is not counted against the backend's circuit
  breaker, and an idempotent request that meets that close on its way out is
  sent again on a fresh connection instead of answered 502. A held connection
  idle past the pool's 60 s is not reused; `stats` shows the held connections
  as `parked_connections`, and they go to the pool when the client leaves.
  Against HAProxy on one keep-alive connection 1.30× → 1.32× the rate and
  1.51× → 1.62× per core; at 32 connections 1.32× → 1.47×.
- **A script runs when its runtime starts, not when it is created.** `create`
  compiles the file — one that does not parse is still refused by the command
  that asked — and the worker runs it. Without `-s` there is no worker yet, so
  the top level has not run, `socketley.subscribe` has not registered, and a
  global like `tick_ms` has not been checked; all of that happens at `start`,
  and a refusal there is reported by that command. Previously a runtime kept in
  the daemon loaded and ran its script during `create`.

### Fixed

- SINTERSTORE, SUNIONSTORE and SDIFFSTORE are refused with `-OOM` when their
  result has no room under `--maxmemory`, and leave the destination as it
  was; they stored it past the limit.
- LPUSH, RPUSH, SADD, ZADD, ZINCRBY and LSET past `--maxmemory` answer `-OOM`
  instead of `WRONGTYPE` (LSET: `index out of range`), and LMOVE instead of
  nil, so a client no longer treats a full store as a key of another type.
  LSET on a key of another type answers `WRONGTYPE`, as Redis does, not
  `no such key`.
- COPY past `--maxmemory` answers `-OOM`, as Redis does, instead of `0`, which
  a client reads as "the destination exists"; the text protocol answers
  `error: out of memory`.
- Under a memory limit with an eviction policy, `LMOVE` and `RPOPLPUSH` could
  evict their own source list to make room in the destination, answering nil
  with the element in neither list; `SMOVE` could likewise evict the rest of
  its source set. The source is now never an eviction candidate for its own
  move: another key is evicted, or the move is refused with nothing lost.
- A server now fails a WebSocket connection whose text message is not valid
  UTF-8, with close code 1007, as RFC 6455 8.1 requires. Such a message used
  to be handed to `on_message` and `on_client_message` as it was, and with no
  script relayed as a binary frame. A message split into fragments is judged
  whole, so a character split across two fragments is accepted. Binary
  messages are not checked.
- A binary WebSocket message whose bytes happened to be valid UTF-8 was
  relayed by a server without a script as a text frame, so a browser got a
  string where it expected a Blob or ArrayBuffer. A relayed message now keeps
  the opcode it arrived with, including after reassembly from fragments and
  when it was held for a client still finishing its upgrade. What a script
  sends is framed as before: text if it is valid UTF-8, binary otherwise.
- A backend that answers `HTTP/1.0` without `Connection: keep-alive` closes its
  connection behind the answer, and the proxy no longer keeps that connection
  for the client's next request: the request goes out on a new one instead of
  into the one closing, where it was sent twice or answered 502. The client's
  own connection stays open.
- An HTTP client that closes its side while its answer is still coming -- one
  that ends only when the backend closes, or one short of its Content-Length --
  is no longer held open for as long as the backend stays silent: from then on
  the backend may go `--backend-timeout` without sending before both
  connections are closed. A half-closed client still receives an answer that
  keeps coming.
- A backend that answers a HEAD with a body, or otherwise sends bytes after
  an answer, no longer has them glued to the next answer on the same backend
  connection: the proxy sends that request again on a fresh connection, or
  answers 502, instead of relaying bytes that do not start a response. The
  client connection is also no longer left open behind that answer after
  the client closes it.
- A WebSocket upgrade on a keep-alive connection that had already served a
  plain GET could hand `on_websocket` and `self.ws_headers` that GET's
  `Cookie`, `Origin`, `Sec-WebSocket-Protocol` or `Authorization` when the
  upgrade itself did not carry the field.
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
- A cache's memory limit counts what a collection holds besides its elements:
  a list's segment blocks and map, a hash's table and slots, a sorted set's
  skiplist head and index, a set's slots, and the room a small one's buffer
  keeps after it shrinks. Lists of one 100-byte element filled a 1 MB limit
  with 2.6 MB, and a hash, set or sorted set grown to 100,000 members and
  emptied to one held 2 MB counted as nothing. A large hash, set or sorted set
  now reads about 9 bytes a member more, a list key 24 and a set key 48.
- The name of a sorted set created by `ZADD` and of a list created by `LMOVE`
  is counted; it was given back when the collection emptied, so each such
  round trip wore the count down by the length of the name.
- `COPY`, `RENAME`, the `STORE` forms of set algebra, `SMOVE` and an `LTRIM`
  to nothing keep a cache's memory count: a copy or a stored set was never
  counted and was taken off when deleted, a rename kept the old name's size,
  `SMOVE` never gave back what it moved, and `LTRIM` gave back every element
  twice. Each wore the count toward zero, and the limit with it, and deleting
  a copied list or set left the count at 16 EiB. `COPY` past the limit copies
  nothing and answers 0, counting what `REPLACE` frees, a renamed key can be
  evicted again, and `SMOVE` onto its own set leaves the member where it is.
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

### Removed

- **Every runtime now runs in its own supervised worker process.** One runtime
  can no longer take the daemon down with it. There is no opt-out and no flag:
  `--daemon-process`, and the older `--out-of-process` / `--in-daemon` pair it
  replaced, are all gone. A command line carrying one is refused as an unknown
  flag; a configuration file with `daemon_process` in it is refused naming the
  line.

## [1.1.0] - 2026-08-27

Six months of work since v1.0.9, across 581 commits. The headline is that a
runtime is no longer confined to the daemon's process or to one core.

### Added

#### Multi-process runtimes and sharding

- **Every runtime now runs in its own supervised worker process by default.**
  One runtime can no longer take the daemon down with it. `--daemon-process`
  opts back in to sharing the daemon's process; it replaces the older
  `--out-of-process` and `--in-daemon` pair, which were one bit under two
  spellings.
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
