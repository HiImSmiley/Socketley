# jobqueue — a job queue service, end to end

A queue you can actually run: one daemon-free process hosting two runtimes on
one io_uring loop (the raw SDK API), and a worker built on the cross-platform
client header, so the fleet that drains the queue does not have to run Linux.

```
 producer                jobd (one process)                 worker(s)
 nc / any TCP  ──────►  server "ingest" :9000               cache_client.h
                          │  validates, then calls           (Linux/Win/mac)
                          ▼  the cache directly                   │
                        cache "jobs" :6380  ◄────── lpop ─────────┘
                          └─ persists to /tmp/jobqueue.dat
```

| file | role | needs |
|---|---|---|
| `jobd.cpp` | queue store + submit API in one process | `libsocketley_sdk.a` (Tier 2, raw API) |
| `worker.cpp` | drains the queue, counts `jobs_done` | one header, any OS (cross-platform client) |

## Build

From the repo root, after `./bin/premake5 gmake2 && cd make && make
config=release_x64 socketley_sdk`:

```bash
g++ -std=c++23 sdk/examples/projects/jobqueue/jobd.cpp \
    $(sdk/socketley-config --cflags --libs) -o jobd

g++ -std=c++17 sdk/examples/projects/jobqueue/worker.cpp \
    $(sdk/socketley-config --cflags --libs) -o jobworker
```

## Run

```bash
./jobd &
echo "submit build-42" | nc -q1 127.0.0.1 9000   # -> queued 1
echo "submit deploy-7" | nc -q1 127.0.0.1 9000   # -> queued 2
echo "status"          | nc -q1 127.0.0.1 9000   # -> depth 2  submitted 2

./jobworker                                       # drains, prints each job
echo "get jobs_done"   | nc -q1 127.0.0.1 6380   # -> 2
```

The queue port speaks the cache text protocol, so `redis-cli -p 6380` and any
of the `ctl::cache_*` Tier-1 functions work against it too.

## What this example is really about

- **Two runtimes, one loop.** The wrapper classes (`socketley::server`,
  `socketley::cache`, …) each own their event loop, so a process that needs
  both uses the raw API: one `event_loop`, one `runtime_manager`, N instances.
- **In-process wiring beats IPC.** `ingest`'s message callback calls
  `jobs->lua_rpush()` directly — your code owns both instances, and the push
  costs a function call, not a round trip.
- **Restart safety.** `set_persistent` means a killed `jobd` comes back with
  its queue; run the submit lines, Ctrl-C, restart, and `status` still shows
  the depth.
- **Polling is the contract, and it is named.** The text protocol has no
  blocking pop, so the worker's sleep interval is the latency floor for a
  queued job. If that matters, the store's pub/sub (`publish`/`subscribe`) can
  wake workers instead — see the cross-platform client's `subscribe()`.
