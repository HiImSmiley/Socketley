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
`master_pw`, `master_forward`, `http`, `http_cache`, `udp`, `test`,
`daemon_process`, `start`.

`daemon_process = true` is what a runtime whose handler uses the cross-runtime
API has to say — see [The cross-runtime API needs
`--daemon-process`](#the-cross-runtime-api-needs---daemon-process) below for
which calls those are. Omit it and the runtime is created, listed and
connectable while every one of those calls raises inside its callbacks, is
caught, logged, and does nothing; `edit` will not add the flag afterwards, so
the runtime has to be recreated.

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
self.route(id, target)      -- refused in a worker: needs --daemon-process
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

### The cross-runtime API needs `--daemon-process`

`socketley.create/.start/.stop/.remove/.send/.list/.get/.pipe`, everything
under `socketley.cluster`, and `self.route()` all act on the runtime map, which
lives in the daemon. A runtime gets its own worker process unless it was
created with `--daemon-process`, and a worker has no map — so each of these
raises a Lua error there naming the call and the way out.

From a configuration file that flag is the `daemon_process = true` key on the
runtime's entry; from the command line it is `--daemon-process` on `create`.

At a script's top level that fails the load and the `create` is refused, which
is loud. Inside a callback it is caught and logged and the runtime carries on —
`ls` green, connections accepted, and none of the work done. That second case
is the one to watch for.

`socketley.pipe` is in that list for a different reason and its message says a
different thing. A pipe hands an **open file descriptor** from one runtime to
another, and a descriptor does not travel in a snapshot of the runtime map the
way a name or a port does — it has to be passed with `SCM_RIGHTS` over a channel
between the two processes, and there is no such channel between runtimes yet.
The mechanism exists and is tested (`shared/conn_transfer.h`); nothing is wired
to it, and the daemon-worker control socket carries no descriptors by design. So
it is the one call here that is not waiting on the runtime map. To pair two
connections of the *same* server from inside a worker, use `self.pipe(fd_a,
fd_b)`: it is the same operation on the same tables, it crosses nothing, and it
is not refused there.
