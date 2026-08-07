# Lua Configuration Examples

Lua-based configuration and scripting for socketley.

## Prerequisites

The daemon must be running. When installed via package, it runs as a systemd service automatically. In dev mode, start it manually: `./bin/Release/socketley daemon &`

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
| `on_route(method, path)` | HTTP request (proxy), *after* a backend is needed | method, path (see below) |
| `filters = {fn, ...}` | HTTP request (proxy), *before* backend selection | req table |

`on_route` receives its two arguments on `--protocol http` only. A TCP proxy
has no request line to read them from and calls it with none, so a body written
for HTTP — `return hash(path) % n` — raises on the first request once it is
moved to a TCP proxy. A call that raises is reported on stderr and the proxy
falls back to the selection it would have made without the callback; the
request is still forwarded.

`filters` is an array, not a single callback: each function runs in order and
either says nothing (carry on) or returns the answer, ending the request before
any backend is selected, resolved or connected to. That is where
authentication, rate limiting and header rewriting belong — `on_route` only
answers "where does this go", and runs once the proxy is already committed to
sending it somewhere. See `examples/proxy/filter-chain.lua` and
`socketley(1)`, section "Proxy Filter Chain".

### Callback Deadline

Every callback invocation gets a wall-clock budget — 10000 ms by default. A
callback that has not returned by then is stopped with an error, the daemon logs
why, and the runtime carries on serving. The event loop is one thread serving
every runtime in the daemon, so a callback that never returns used to freeze all
of them until the daemon was killed.

The script's top level is bounded the same way, and it runs inside `create`: a
top level that never returns refuses the create with a reason instead of
blocking the terminal on a command that will never answer.

```lua
callback_timeout_ms = 30000   -- this script does slow work on purpose
callback_timeout_ms = 0       -- no bound at all for this script
```

`SOCKETLEY_LUA_TIMEOUT_MS` in the daemon's environment moves the default for
every script that declares nothing; a script that declares its own wins.

`socketley.http` lives inside the same budget — its `timeout_ms` is clamped to
what is left — so a callback waiting on a slow host gets an ordinary
`ok = false` result rather than being stopped mid-request.

LuaJIT runs interpreted while the bound is in force. An ordinary callback shows
no measurable difference; one whose cost is its own arithmetic loop runs at
about 80% of its unhooked rate. Setting the bound to `0` installs no hook.

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
