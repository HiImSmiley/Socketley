# Managed External Runtimes

Register standalone C++ binaries with the daemon for full lifecycle management:
auto-restart on crash, re-launch on daemon boot, and normal stop/start/remove.

## Prerequisites

The daemon must be running. When installed via package, it runs as a systemd
service automatically. In dev mode: `./bin/Release/socketley daemon &`

A C++17 compiler is needed to build the example binary.

## How It Works

```
socketley add /path/to/binary --name myapp -s
```

The daemon fork+exec's the binary with `SOCKETLEY_MANAGED=1` and
`SOCKETLEY_NAME=myapp` in its environment. The binary calls `daemon_attach()`
to report its type and port back to the daemon.

```
┌─────────────────────┐         ┌───────────────────┐
│     daemon          │  fork   │   managed binary   │
│                     │ ──────> │                    │
│  health check (2s)  │         │  daemon_attach()   │
│  auto-restart       │ <────── │  (re-attach IPC)   │
│  persist state      │         │                    │
└─────────────────────┘         └───────────────────┘
```

## Managed vs Attach

| Feature | `attach` | `add` (managed) |
|---------|----------|-----------------|
| Daemon sees in `ls`/`ps` | Yes | Yes |
| Daemon starts the binary | No | Yes |
| Auto-restart on crash | No | Yes |
| Survives daemon restart | No | Yes |
| `stop` / `start` cycle | No | Yes |

## Examples

### echo-service.cpp

Minimal echo server using the C++ SDK (`attach.h`). Works both standalone
and as a managed binary.

```bash
g++ -std=c++17 -I../../include/linux echo-service.cpp -o echo-service
```

### 01 - Add and Run

Register the binary and start it immediately.

```bash
./01-add-and-run.sh
```

### 02 - Auto-Restart

Kill the binary and watch the daemon restart it automatically.

```bash
./02-auto-restart.sh
```

### 03 - Stop/Start Cycle

Full lifecycle: add, stop, start, remove.

```bash
./03-stop-start-cycle.sh
```

## Cleanup

```bash
socketley stop echo-svc crash-test lifecycle 2>/dev/null
socketley remove echo-svc crash-test lifecycle 2>/dev/null
```
