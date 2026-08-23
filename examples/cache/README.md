# Cache Examples

Key-value caching with optional persistence and access control.

## Prerequisites

The daemon must be running. When installed via package, it runs as a systemd service automatically. In dev mode, start it manually: `./bin/Release/socketley daemon &`

## Examples

### Basic Cache
In-memory key-value store.

### Persistent Cache
Cache with file-based persistence across restarts.

### Cache Modes
Access control for cache operations:

```bash
# Read-only cache (GET, SIZE only)
socketley create cache lookup -p 9000 --mode readonly -s

# Read-write cache (GET, SET, DEL, SIZE - default)
socketley create cache store -p 9001 --mode readwrite -s

# Admin cache (all commands including FLUSH, LOAD)
socketley create cache admin -p 9002 --mode admin -s
```

### Cache Integration
Using cache with server/client via Lua.

### TLS (`tls-cache.sh`)
A cache terminates TLS on its own listening port with the same three flags a
server uses:

```bash
socketley create cache tls-store -p 9000 \
    --tls --cert cache.pem --key cache-key.pem -s

# ...and --ca additionally demands a certificate from every client (mutual TLS)
socketley create cache mtls-store -p 9001 \
    --tls --cert cache.pem --key cache-key.pem --ca ca.pem -s
```

RESP is auto-detected from the first byte of the *decrypted* stream, so an
existing Redis client speaks the protocol it always did — one layer up. The
line protocol works on the same port. A plaintext client is refused rather than
downgraded: its bytes are not a TLS record, the handshake fails, and nothing it
sent is ever executed as a command.

**Replication is not encrypted, and cannot be combined with `--tls`.** A
follower dials its leader itself, in cleartext, and on a leader a promoted
follower is written to by a second writer that goes around the record layer by
design. Encrypting the listener and replicating out of it would put the whole
dataset on the wire in the clear, from a runtime `inspect` reports as
encrypted — so the pair is refused at `create`, by `edit` and `import`, and
again at every `start`, and a TLS cache refuses the `replicate` command so it
never becomes a leader either. Replicate over a private network with cleartext
caches; an honestly cleartext cache is better than a half-encrypted one.

### Cache Access via Server (`server-cache-access.sh`)
A server created with `--cache <name>` lets its own clients reach that cache:
any message beginning `cache ` is run against the linked cache and the answer
goes back to the sender alone.

The request is asynchronous — the server posts the command and answers when the
reply arrives, one turn of the event loop later, rather than running the cache's
interpreter on the connection that asked. Replies on one connection come back in
request order, so commands can be pipelined; a cache that is not running is
answered with an `error:` line rather than with silence.

## Key Concepts

### Cache Operations
- `get(key)` - Retrieve value
- `set(key, value)` - Store key-value pair
- `del(key)` - Delete key

### Cache Modes
| Mode | Allowed Commands |
|------|------------------|
| `readonly` | GET, SIZE |
| `readwrite` | GET, SET, DEL, SIZE (default) |
| `admin` | All commands including FLUSH, LOAD |

### Persistence Format
Binary format: `[key_len][key][val_len][value]...`

- Loaded automatically on startup
- Saved automatically on shutdown
- Efficient binary encoding

### Sharding (`--shards N`)
A cache may be served from N worker processes on one port. It is still **one
keyspace**: a key belongs to the shard its hash falls to, and a command naming
another shard's key is answered by that shard, so `dbsize` sums, `keys` lists
all of them, `scan` walks the whole keyspace and `publish` reaches every
subscriber.

Measured, four clients at pipeline depth 1: **172k → 289k ops/s, 1.68x at four
shards**. Drive it with more than one client — a single `redis-benchmark`
process tops out near 90–110k ops/s and a series measured with one client is a
series about the client.

`--persistent` writes one dump per shard (`file.shard0`, `file.shard1`, …).
Each records the split it was written under, so a set dumped at four shards and
started at eight is **redistributed** rather than loaded into the wrong slices.
A set with a missing slice, or whose files disagree about the shard count,
refuses the start rather than serving part of itself.

`replicate` is **refused** on a sharded cache: a follower arrives as one
connection on one shard and would receive that shard's writes only. A sharded
cache may still *be* a follower.

See `sharded-cache.sh`.

### Letting the client pick the shard — `--cluster` (`cluster-cache.sh`)

Sharding costs a **crossing**: with N shards a random key is foreign (N-1)/N of
the time, because all N shards share one port under `SO_REUSEPORT` and the
kernel assigns connections by four-tuple hash.

Measured on this tree — 8 client processes x 50 connections, three interleaved
passes per arm, medians, **rps per server core**:

| four shards, clients on | rps/core | CPU per request | crossings |
|---|---|---|---|
| the shared port | 63,849 | 15.66 us | ~9.0 M |
| the per-shard ports | **87,401** | **11.44 us** | **0** |
| *four independent single-shard caches* | *87,663* | *11.40 us* | *0* |

**+36.9%, and the routed arm lands within 0.3% of four separate caches.** The
whole gap between a sharded runtime and N unsharded ones was the crossing.

**`--cluster` is off by default, and you should read why before turning it on.**

> A routing client connects to **every shard directly**, and the address this
> cache advertises is the one the *asking* connection arrived on. Put the cache
> behind a proxy and the map names the address the **proxy** reaches it on:
> either the client can reach that too — and the proxy's rules have been
> bypassed by a map the cache handed out — or it cannot, and the client spends
> its retry budget on a connection refused. Neither outcome logs anything.
>
> This is not fixable here. It is what client-side routing *is*, and Redis
> Cluster has the same property. **A `--cluster` cache cannot sit behind a proxy
> used for access control** — choose which of the two you want. Without the flag
> the cache is reached only through its one port, which is what a proxy in front
> of it depends on.

With `--cluster`, the crossing is removed by letting the client route, and the
client is not ours:

* a key's owner is **CRC16 mod 16384**, Redis's hash slot function including the
  `{hash tag}` rule, so `redis-cli -c`, `redis-benchmark --cluster`, redis-py,
  go-redis, lettuce and node-redis all compute it themselves;
* shard *i* binds **`port + 1 + i`** as well as the shared port, and a key that
  arrives on the wrong one is answered `-MOVED slot host:port`;
* `CLUSTER SLOTS`, `SHARDS`, `NODES`, `INFO`, `MYID`, `KEYSLOT` and
  `COUNTKEYSINSLOT` are answered on every port.

`port+1 .. port+N` therefore have to be free, and a cache that cannot bind one
of them **refuses to start** rather than being advertised at an address nothing
answers on — the message names the flag, because that is the thing you can turn
off. Without `--cluster` nothing but the shared port is bound, so two four-shard
caches one port apart work as they always did.

`--cluster` is legal at `--shards 1`: one node on the base port, nothing extra
bound, so a client can be written once and deployed at any N.

**Without the flag, `--shards N` behaves exactly as it did before this existed**:
shared port only, no redirects, `cluster_enabled:0`, and `CLUSTER SLOTS`
publishing a single node holding every slot on that port — true and safe. The
`CLUSTER` commands are answered either way; a client that asks deserves a
straight answer.

**The shared port is unchanged.** A client that has never heard of a slot map
connects there and is served over the mesh exactly as before; one runtime serves
both kinds at once. On a per-shard port `DBSIZE`, `KEYS`, `SCAN`, `FLUSH` and
`LOAD` answer for that shard, which is what a cluster client means when it asks
a node; on the shared port they still fan out and merge.

To check that a client is actually routing, count crossings rather than
requests: `socketley stats <name>` reports `mesh_direct` and `mesh_relayed` per
shard, and for a routing client both are near zero. Throughput alone cannot tell
a routing client from one that is being served over the mesh.
