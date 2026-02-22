# Lua Configuration Examples

Lua-based configuration and scripting for socketley.

## Prerequisites

```bash
socketley daemon &
```

## Examples

### Simple Config
Basic Lua configuration file structure.

### Callbacks
Event callbacks (on_start, on_stop, on_message, on_send).

### Custom Routing
Lua-based proxy routing with on_route().

### Full Setup
Complete orchestration with all features.

## Key Concepts

### Configuration Structure
```lua
runtimes = {
    { type = "server", name = "...", port = ..., mode = "inout", ... },
    { type = "client", name = "...", target = "...", mode = "inout", ... },
    { type = "proxy", name = "...", backends = {...}, strategy = "round-robin", ... },
    { type = "cache", name = "...", persistent = "...", mode = "readwrite", ... },
}
```

### Cache Modes
| Mode | Allowed Commands |
|------|------------------|
| `readonly` | GET, SIZE |
| `readwrite` | GET, SET, DEL, SIZE (default) |
| `admin` | All commands including FLUSH, LOAD |

### Available Callbacks
| Callback | Trigger | Parameters |
|----------|---------|------------|
| `on_start()` | Runtime started | none |
| `on_stop()` | Runtime stopped | none |
| `on_message(msg)` | Message received (claims handling; no default broadcast) | message string |
| `on_send(msg)` | Message sent | message string |
| `on_route(method, path)` | HTTP request (proxy) | method, path |

### Runtime Methods
```lua
self.name         -- Runtime name
self.port         -- Port number
self.state        -- Current state
self.type         -- Runtime type
self.send(msg)    -- Send message
self.broadcast(msg) -- Broadcast (server)
self.get(key)     -- Cache get
self.set(key,val) -- Cache set
self.del(key)     -- Cache delete
```

### Global Functions
```lua
socketley.log(msg) -- Log with [lua] prefix
```
