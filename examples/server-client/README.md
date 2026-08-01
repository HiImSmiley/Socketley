# Server-Client Examples

Advanced server-client communication patterns.

## Prerequisites

The daemon must be running. When installed via package, it runs as a systemd service automatically. In dev mode, start it manually: `./bin/Release/socketley daemon &`

## Examples

### Echo Server Pattern
A server that echoes received messages back to clients.

### Broadcast Pattern
One server broadcasting to multiple clients.

### Bidirectional Communication
Full duplex messaging between server and clients.

### Message Modes
Demonstrates `--mode in`, `--mode out`, and `--mode inout`.

### TLS (`tls-client.sh`)
A client that dials its target over TLS. The peer is verified on two counts and
neither can be switched off: the chain against `--ca` or the system trust store,
and the certificate against the host given in `-t`. `--cert`/`--key` present a
certificate of the client's own for a peer that demands one. A peer that fails
verification costs the socket and is re-dialled; nothing is ever sent in the
clear.

## Key Concepts

### Server Default Behavior
- Accepts multiple concurrent connections
- Can broadcast messages to all connected clients
- Default port: 8000

### Client Default Behavior
- Maintains single connection to target
- Reconnects automatically on disconnect
- Default target: 127.0.0.1:8000

### Message Modes

| Mode | Server | Client |
|------|--------|--------|
| `inout` | Receive + Broadcast | Receive + Send |
| `in` | Receive only | Receive only |
| `out` | Broadcast only | Send only |
