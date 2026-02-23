# Server-Client Examples

Advanced server-client communication patterns.

## Prerequisites

```bash
socketley daemon &
```

## Examples

### Echo Server Pattern
A server that echoes received messages back to clients.

### Broadcast Pattern
One server broadcasting to multiple clients.

### Bidirectional Communication
Full duplex messaging between server and clients.

### Message Modes
Demonstrates `--mode in`, `--mode out`, and `--mode inout`.

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
