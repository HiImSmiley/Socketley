# Lua Configuration Examples

Lua-based configuration and scripting for socketley.

## Prerequisites

The daemon must be running. When installed via package, it runs as a systemd service automatically. In dev mode, start it manually: `./bin/Release/socketley daemon &`

## Two kinds of `.lua` file

This is the distinction everything else here depends on.

| | **Configuration** | **Handler** |
|---|---|---|
| Example | `simple-config.lua` | `simple-config-handler.lua` |
| Run by | `socketley --lua config.lua` | the daemon, via `--lua` on a `create` |
| Read for | `daemon` and `runtimes` tables | `on_*` callbacks, `filters`, `routes` |
| Callbacks in it | **never loaded, never called** | are the whole point |

A configuration runs in the CLI process. socketley reads two tables out of it,
turns them into `create` commands, and exits — the file never reaches the
daemon. Writing `function on_start()` in one is dead code, and nothing says so:
the create succeeds, `ls` is green, and the callback never fires.

A configuration attaches a handler by naming its path:

```lua
runtimes = {
  { type = "server", name = "api", port = 9000,
    config = "examples/lua-config/simple-config-handler.lua",  -- becomes --lua
    start = true },
}
```

`config` and `lua` are the same key. That path is opened by the **daemon**, so
it resolves against the daemon's working directory, not the config file's — run
these from the repository root, or use absolute paths.

A handler needs no configuration at all; it can be attached directly:

```bash
socketley create server tracker -p 9000 --lua callbacks-connect.lua -s
```

### The configuration interpreter is smaller than the daemon's

It opens `base`, `package` and `table`, and nothing else.

- No `os`. `os.execute("mkdir -p /tmp/logs")` is not a sandbox refusal but
  `attempt to index global 'os' (a nil value)`: the file is refused whole,
  exit 1, and not one runtime is created. Make directories from the shell.
- No `string`, so `string.format` and the method form `path:match(...)` are
  unavailable. `..` and `tostring()` are core and still work.
- No `math`, no `io`.

### A handler is not sandboxed

A handler's interpreter has all of the above plus `os`, `io` and `package`, and
**it runs with the daemon's full privileges** — `io.popen` is a shell,
`io.open(path, "w")` truncates any file that user can write, `package.loadlib`
maps native code. Treat a handler as a program you are about to run as that
user.

Two `os` names are removed, and neither is a security boundary: `os.exit`,
which ends the daemon from inside a callback, and `os.setlocale`, which changes
the `LC_NUMERIC` that `json_encode`/`json_decode` spell numbers with. Both are
guards against one line damaging every *other* runtime in the shared process by
accident. `os.time`, `os.clock`, `os.date` and `os.difftime` remain — they are
reads.

What decides *who* may hand this daemon a handler is the permission on its IPC
socket (`0660 socketley:socketley` for the packaged daemon, `0600` otherwise),
not anything in the interpreter.

## Examples

### Simple Config
`simple-config.lua` + `simple-config-handler.lua` — the basic pair, one handler
serving both a server and a client.

### Callbacks
`callbacks.lua` + `callbacks-handler.lua` — on_start, on_stop, on_message,
on_send, and what each one sees.

### Callbacks: connect / disconnect
`callbacks-connect.lua` — a handler used directly, with no configuration file.

### Custom Routing
`custom-routing.lua` + `custom-routing-handler.lua` — `on_route`. Needs
`strategy = "lua"`, which the configuration sets; without it the proxy never
consults the callback.

### Full Setup
`full-setup.lua` + `full-setup-handler.lua` — cache, three services, an HTTP
gateway and two clients, one handler branching on `self.name`.

## Key Concepts

### Runtimes table keys
`type`, `name`, `port`, `target`, `mode`, `log`, `write`, `persistent`,
`protocol`, `strategy`, `backends`, `config`/`lua`, `bash`, `cache`, `group`,
`master_pw`, `master_forward`, `http`, `http_cache`, `udp`, `test`, `start`.

`daemon_process` was in this list and is refused now, naming the line, rather
than ignored — see [The cross-runtime API in a
worker](#the-cross-runtime-api-in-a-worker-all-of-it-works) below. Refusing it
rather than dropping it is deliberate: a silently ignored key would leave you
believing a runtime is somewhere it is not.

An unrecognised key is ignored in silence. Flags this list does not reach — the
health-check, circuit-breaker, retry and TLS families — cannot be set from a
configuration at all; use `create` or `edit`.

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
| `on_route(method, path, backend_path)` | HTTP request (proxy) under `--strategy lua` ONLY, *after* a backend is needed | method, path, backend_path (see below) |
| `filters = {fn, ...}` | HTTP request (proxy), *before* backend selection | req table |
| `on_client_message(id, msg)` | Message received, with sender (server) | client_id, message |
| `on_miss(key)` | Cache GET found nothing | key; return value[, ttl] |
| `on_write(key, val, ttl)` | After a successful cache SET | key, value, ttl |
| `on_delete(key)` | After a cache DEL that removed something | key |
| `on_expire(key)` | After the TTL sweep removed a key | key |
| `routes = {{path=,methods=}}` | Not a callback: what this runtime answers, published to the proxies in front of it | — |

`on_route` is consulted only when the proxy was created `--strategy lua`.
Without that flag the proxy keeps round-robin, never looks the callback up, and
the script silently does nothing — the usual reason an `on_route` "that works"
appears to have no effect.

`path` is the path **as the client sent it**, with this proxy's own
`/<name>/` prefix still on the front — the same path the filter chain is handed,
because a filter judges the request the client made. `backend_path` is that
path with the prefix removed: what the backend actually receives, and what a
routing pattern is nearly always written against. A proxy named `gw` handed
`/gw/api/users` sees both:

```lua
function on_route(method, path, backend_path)
    -- path         == "/gw/api/users"
    -- backend_path == "/api/users"
    if backend_path:match("^/api/") then return 0 end
    return 1
end
```

`backend_path` exists so scripts stop computing it. Every proxy example in this
tree used to do it by hand, and the case that makes it worth handing over is the
bare one: the gateway's own root arrives as `/gw`, which is *shorter* than the
five-character prefix, so `sub()` past the end yields `""` and matches nothing.
A handler that declares only two parameters is unaffected — Lua discards
arguments a function does not name.

`on_route` receives its arguments on `--protocol http` only. A TCP proxy
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

`self` carries a different set of methods depending on the runtime's type.
Calling a cache method on a server is `attempt to call field 'get' (a nil
value)`, not a no-op.

```lua
-- All four types
self.name, self.port, self.state, self.type
self.connections()          -- current connection count

-- Server
self.send(client_id, msg)   -- TWO arguments
self.broadcast(msg)
self.clients(), self.multicast(ids, msg), self.disconnect(id)
self.peer_ip(id), self.ws_headers(id)
self.set_data(id, k, v), self.get_data(id, k)
self.join_group(id, g), self.leave_group(id, g), self.group_send(g, msg)
self.route(id, target)      -- refused in a worker, permanently: it moves a
                            -- connection, not a name.  See below.
self.unroute(id), self.get_route(id)
self.owner_send(id, msg), self.owner_broadcast(msg)

-- Client
self.send(msg)              -- ONE argument

-- Cache
self.get(k), self.set(k, v), self.del(k)
self.lpush/rpush/lpop/rpop/llen, self.sadd/srem/sismember/scard
self.hset/hget/hdel/hlen, self.expire/ttl/persist, self.publish(ch, msg)

-- Proxy
self.clients(), self.peer_ip(id), self.close_client(id)
self.backends()             -- 1-based; on_route's n is backends()[n + 1]
self.backend_health()       -- "closed" | "open" | "half_open", same order
self.stats()                -- {connections, bytes_in, bytes_out, ...}
```

### Global Functions
```lua
socketley.log(msg)                 -- One INFO line, prefixed [lua <runtime>]
socketley.json_encode(v)           -- Lua value -> JSON string
socketley.json_decode(s)           -- JSON string -> Lua value
socketley.set_timeout(ms, fn)      -- one-shot timer, returns an id
socketley.set_interval(ms, fn)     -- repeating timer, returns an id
socketley.subscribe(cache, ch, fn) -- receive a cache's PUBLISH
socketley.http(opts)               -- blocking HTTP/HTTPS client
```

`require "cjson"` is not one of the options: cjson is not bundled with LuaJIT,
no binary module ships with socketley, and `package.cpath` is left at its
default — the require fails the script load and the runtime is left `failed`.
`socketley.json_encode` needs nothing installed.

### When a script runs

When its runtime **starts**, not when it is created. `create` compiles the file
— so one that does not parse is refused by the command that asked for it — and
the worker runs it. Without `start = true` (or `-s` on the command line) there
is no worker yet and nothing has run: no top level, no `socketley.subscribe`,
and no check of a global like `tick_ms`. Those happen at the start that forks
the worker, and a refusal there is reported by that command.

A configuration file always starts what it creates, so this is only visible
from the command line.

### The cross-runtime API in a worker: all of it works

`socketley.create/.start/.stop/.remove/.send/.list/.get/.pipe`, everything
under `socketley.cluster`, and `self.route()` all act on the runtime map, which
lives in the daemon — and every runtime runs in its own worker process. So a
script calling these is always running somewhere the map is not.

They all work there, and **how** differs by group:

| group | calls | in a worker |
|---|---|---|
| read the map | `.send` `.list` `.get`, all of `socketley.cluster` | answered from a replica the daemon pushes |
| change the map | `.create` `.start` `.stop` `.remove` | asked of the daemon, and they **wait** for the answer |
| move a connection | `.pipe(src,fd,dst)`, `self.route()` | relayed to the runtime that answers |

The four that **change** the map do not touch the replica — being told what the
map holds is not permission to alter it. They travel: the request goes to the
daemon over a socket the worker holds for exactly this, the daemon acts on the
map it holds, and the answer comes back before the Lua call returns. So
`if socketley.create(...) then` branches on what happened rather than on what
was accepted, and what it says is the daemon's own wording — a script cannot
tell which process it is running in from the reason it is given.

They block the worker's event loop while they wait, which is affordable for one
reason: these are written in `on_start` or on a rare control message, never per
request. Measured at about 10 µs for a call that forks nothing, and bounded at
five seconds for one that does. `socketley.http()` on the same table blocks the
same loop for a network round trip and is three orders of magnitude longer.

The two that **move a connection** were the last to be refused, and their
refusal named the wrong missing thing — worth knowing, because the message may
still be in someone's notes. It said `socketley.pipe` hands an **open file
descriptor** between runtimes and would need `SCM_RIGHTS` over a channel nothing
had built. Across two runtimes it hands no descriptor over at all: it is
`route_client()`, which writes into the *target's* maps, runs the target's
`on_connect`, and then leaves the socket exactly where it was and relays the
bytes through it. What was missing was a way to **name** the far end's
connection, not a way to move one.

`self.route()` is the same call under another name and was refused for the same
wrong reason. Both cross a process boundary now, called exactly as before.
`unroute()`, `get_route()` and `owner_send()` read this runtime's own tables and
always did.

When a runtime holding routed connections goes away — stopped, removed, crashed
or killed — every runtime on the other end is told to let go and its
`on_disconnect` runs. The daemon does that, not the departing runtime: a killed
worker runs no teardown at all.

The four-argument form, `socketley.pipe(src, fd_a, src, fd_b)`, pairs two
connections of *one* server and crosses nothing. Call it from that server's own
script — only that process holds its connections — or use the equivalent
`self.pipe(fd_a, fd_b)`.
