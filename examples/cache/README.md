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
