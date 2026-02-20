# Contributing to Socketley

## Build

```bash
# Dependencies (Ubuntu/Debian)
sudo apt install build-essential liburing-dev libssl-dev

# Generate Makefiles
./bin/premake5 gmake2

# Build
cd make
make config=release_x64 -j$(nproc)    # Release build
make config=debug_x64 -j$(nproc)      # Debug build
make config=sanitize_x64 -j$(nproc)   # ASAN/UBSan build
```

Output goes to `bin/Release/`, `bin/Debug/`, or `bin/Sanitize/`.

## Testing

```bash
# Unit tests (fast, no daemon needed)
./bin/Release/test_command_hashing
./bin/Release/test_cache_store
./bin/Release/test_resp_parser
./bin/Release/test_name_resolver
./bin/Release/test_ws_parser

# Full test suite (unit + integration, starts daemon)
bash test/run_all.sh

# Individual integration tests
bash test/integration/test_basic.sh
bash test/integration/test_cache.sh

# Benchmarks
bash test/benchmark/run_all.sh
```

## Code Style

- C++23 (`C++latest`), C17 for C code
- 4-space indentation, Allman brace style
- `snake_case` for variables, functions, and filenames
- `m_` prefix for member variables
- `std::string_view` for read-only string parameters
- No exceptions on hot paths -- use return codes
- No output on success (silence is golden), errors to stdout
- Exit codes: 0 = success, 1 = bad input, 2 = fatal

## Architecture

- `socketley/cli/` -- CLI command dispatch (FNV-1a hash switching)
- `socketley/daemon/` -- Daemon handler, flag parsing, IPC
- `socketley/shared/` -- Core infrastructure (event loop, runtime manager, Lua context, TLS, WebSocket)
- `socketley/runtime/` -- Runtime implementations (server, client, proxy, cache)
- `test/unit/` -- doctest unit tests
- `test/integration/` -- Shell-based integration tests
- `test/benchmark/` -- Performance benchmarks

## Adding a New Feature

1. Implement in the appropriate runtime or shared module
2. Add CLI flag handling in `socketley/daemon/flag_handlers.cpp`
3. Update state persistence in `socketley/shared/state_persistence.cpp`
4. Add tests (unit and/or integration)
5. Update documentation: man page (`socketley/man/socketley.1`), help script (`socketley/man/socketley-help.sh`), examples (`socketley/examples/`), and `CLAUDE.md`

## Adding a New Integration Test

Create `test/integration/test_yourfeature.sh` following the existing pattern. It will be auto-discovered by `test/run_all.sh`.

## Vendored Dependencies

The `thirdparty/` directory contains vendored libraries (LuaJIT, sol2, doctest). Do not modify these files.
