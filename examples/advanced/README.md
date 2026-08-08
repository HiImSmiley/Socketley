# Advanced Examples

Complex multi-runtime setups for production-like scenarios.

## Prerequisites

The daemon must be running. When installed via package, it runs as a systemd service automatically. In dev mode, start it manually: `./bin/Release/socketley daemon &`

## Two kinds of `.lua` file

Each example here is a **pair**, and mixing them up is the single most common
way to end up with a runtime that starts, looks healthy, and does nothing.

| | `foo.lua` (configuration) | `foo-handler.lua` (handler) |
|---|---|---|
| Run by | `socketley --lua foo.lua` | the daemon, via `--lua` on a `create` |
| Read for | `daemon` and `runtimes` tables | `on_*` callbacks, `filters`, `routes` |
| Callbacks in it | **never loaded, never called** | are the point |

A configuration attaches a handler with `config = "path/to/handler.lua"`. That
path is opened by the **daemon**, so it resolves against the daemon's working
directory, not the config file's — run these from the repository root, or use
absolute paths.

The configuration is read by a smaller interpreter than the daemon's: `base`,
`package` and `table` only. There is no `os` (so no `os.execute` — make
directories from the shell first) and no `string` (so no `string.format` and no
`path:match()`).

The **handler** has all of them and is not sandboxed: it runs with the daemon's
full privileges. `io.popen` is a shell, `io.open(p, "w")` truncates,
`package.loadlib` maps native code. Only `os.exit` and `os.setlocale` are
removed, and not as a boundary — one call to either damages every *other*
runtime in the shared process. Read a handler the way you would read a program
you are about to run as the daemon's user, because that is what it is.

## Examples

### Microservices
`microservices.lua` + `microservices-handler.lua`. Path-based routing to four
services through one HTTP gateway. Needs `strategy = "lua"`, which the config
sets — `on_route` is consulted under that strategy and no other.

### High Availability
`high-availability.lua` + `high-availability-handler.lua`. Replica groups
behind `@group` load balancers, with per-replica lifecycle logging.

### Logging Pipeline
`logging-pipeline.lua` + `logging-pipeline-handler.lua`. Centralized logging.
Run `mkdir -p /tmp/socketley-central-logs` first — the daemon opens the log
files the config names.

### Development Environment
`development-env.lua` + `development-env-handler.lua`. Local dev stack with a
routing proxy and a seeded mock database. Run
`mkdir -p /tmp/socketley-dev` first.

### Game Routing
`game-routing.lua` + `rapid-handler.lua` / `blitz-handler.lua`. A lobby that
creates sub-servers and routes players to them. **Must be created with
`--daemon-process`** — every call it makes reaches for the runtime map, which
lives in the daemon and not in a worker. Without the flag the lobby comes up
green and answers nothing.

## Architecture Patterns

### Service Mesh Pattern
```
[client] → [proxy] → [service-a]
                  → [service-b]
                  → [service-c]
```

### Fan-Out Pattern
```
[gateway] → [load-balancer] → [worker-1]
                           → [worker-2]
                           → [worker-n]
```

### Sidecar Pattern
```
[main-service] ←→ [sidecar-client]
                        ↓
               [monitoring-service]
```
