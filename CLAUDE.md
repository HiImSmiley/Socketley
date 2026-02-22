# CLAUDE.md

## Project Overview

Socketley is a Linux-only daemon + CLI managing long-living network runtimes (server, client, proxy, cache) in a Docker-like style. C++ (C++latest, C17), Lua scripting (sol2/LuaJIT), statically linked, io_uring async I/O.

## Build

```bash
./bin/premake5 gmake2 && cd make && make config=release_x64 -j$(nproc)  # Release
./bin/premake5 gmake2 && cd make && make config=debug_x64 -j$(nproc)    # Debug
```

Output: `bin/Release/` or `bin/Debug/`

## Tests

```bash
# Unit tests
./bin/Release/test_command_hashing && ./bin/Release/test_cache_store && ./bin/Release/test_resp_parser

# Integration tests (requires daemon)
bash test/run_all.sh
```

## File Guide — What to Read per Task

**NEVER read:** `thirdparty/` (vendored libs), `test/benchmark/` (only for perf debugging), `docs/` (generated HTML), `.github/` (CI config, read only if CI task)

### By task type → files to read/edit

| Task | Read/Edit these | Skip everything else |
|------|----------------|---------------------|
| **CLI command** (add/change/fix) | `socketley/cli/cli.cpp`, `socketley/daemon/daemon_handler.cpp` | |
| **Flag parsing** (add/change flag) | `socketley/daemon/flag_handlers.cpp`, `socketley/daemon/daemon_handler.h` | |
| **Server runtime** | `socketley/runtime/server/server_instance.{cpp,h}` | |
| **Client runtime** | `socketley/runtime/client/client_instance.{cpp,h}` | |
| **Proxy runtime** | `socketley/runtime/proxy/proxy_instance.{cpp,h}` | |
| **Cache runtime** | `socketley/runtime/cache/cache_instance.{cpp,h}`, `cache_store.h` | |
| **Cache RESP protocol** | `socketley/runtime/cache/resp_parser.h` | |
| **io_uring / event loop** | `socketley/shared/event_loop.{cpp,h}`, `event_loop_definitions.h` | |
| **Lua scripting** | `socketley/shared/lua_context.{cpp,h}` | |
| **WebSocket** | `socketley/shared/ws_protocol.h` | |
| **TLS** | `socketley/shared/tls_context.{cpp,h}` | |
| **Runtime lifecycle** | `socketley/shared/runtime_instance.{cpp,h}`, `runtime_manager.{cpp,h}` | |
| **State persistence** | `socketley/shared/state_persistence.{cpp,h}` | |
| **Logging** | `socketley/shared/logging.h` | |
| **Metrics/Prometheus** | `socketley/daemon/metrics_endpoint.{cpp,h}` | |
| **Build system** | `premake5.lua` | |
| **Packaging/install** | `packaging/` | |
| **Unit tests** | `test/unit/` | |
| **Integration tests** | `test/integration/` | |
| **Docs update** | `socketley/man/socketley.1`, `socketley/man/socketley-help.sh`, `socketley/examples/` | |

### Cross-cutting (read only when relevant)
- `socketley/shared/paths.h` — path resolution (system vs dev mode)
- `socketley/shared/command_hashing.h` — FNV-1a hash function (only if adding new CLI commands)
- `socketley/daemon/daemon.cpp` — daemon main loop (rarely needs changes)

## Key Architecture

- Single binary: daemon + CLI via Unix socket IPC
- io_uring event loop (single-threaded, SQPOLL)
- Runtime lifecycle: `created → running → stopped` (also `failed`), atomic transitions
- Concurrency: `shared_mutex` on runtime_manager, atomic state per instance
- State persistence: JSON per runtime in state dir, `was_running` auto-restart

## Rules

- **NEVER read files from `thirdparty/`**
- **Silence is golden** — success = no output, only errors to stdout
- **Exit codes:** 0 = success, 1 = bad input, 2 = fatal error
- **Zero warnings, zero errors** — every build must be completely clean. After any code change, verify with `make config=release_x64 -j$(nproc) 2>&1 | grep -E "warning:|error:"` and fix all output before finishing. The `(void)` cast does not suppress `warn_unused_result` on this toolchain — use `if (expr < 0) {}` for intentionally-ignored return values instead.

## Documentation Maintenance

When making codebase changes (flags, commands, features, callbacks), update:
1. `socketley/man/socketley.1` — man page
2. `socketley/man/socketley-help.sh` — interactive help
3. `socketley/examples/` — relevant examples

## Reference (read on demand, not memorized)

For CLI flags, cache protocol, Lua API, examples — read the man page, help script, or relevant source files directly. Key references:
- CLI flags & usage: `socketley/man/socketley.1`, `socketley/daemon/flag_handlers.cpp`
- Cache protocol: `socketley/runtime/cache/cache_instance.cpp`, `socketley/runtime/cache/cache_store.h`
- Lua API & callbacks: `socketley/shared/lua_context.cpp`, `socketley/shared/lua_context.h`
- WebSocket: `socketley/shared/ws_protocol.h`
- Examples: `socketley/examples/{basic,server-client,proxy,cache,lua-config,advanced}/`
