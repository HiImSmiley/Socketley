# link-shortener

A complete little system rather than one flag: a TLS gateway in front of an
HTTP API, both socketley runtimes, brought up and torn down by one script.

```
client ──TLS──> gateway (proxy) ──http──> api (server, --lua api.lua)
                  health checks
                  circuit breaker
                  retry
```

```bash
./run.sh
```

It builds nothing, needs no arguments, and removes everything it made on the way
out. It uses ports 38081 and 38443, which are outside every window
`test/lib_ports.sh` hands out, so it can run while the test suite is running.

## What it does

| Request | Answer |
|---|---|
| `POST /gateway/shorten` with a URL as the body | `201` and a short code |
| `GET /gateway/<code>` | `302` to the target |
| `GET /gateway/stats` | `200`, JSON counters |
| `GET /gateway/health` | `200`, what the gateway's health check asks for |

## The one thing that catches everyone

**An HTTP proxy answers under its own runtime name.**

`GET /shorten` through the gateway is not a request the gateway forwards — it
reads as a request for a runtime called `shorten`, there is none, and the answer
is `404` with no backend contacted at all. The path is `/gateway/shorten`, and
the backend sees `/shorten` with the prefix stripped.

This is worth stating plainly because the failure looks like a broken backend
and is not: `socketley stats gateway` shows `backend_connections: 0`, so nothing
was ever asked. It is also why `api.lua` writes its paths with no prefix — the
prefix belongs to the edge, not to the handler.

## What each flag buys

- `--tls --cert --key` — the gateway terminates TLS. The backend leg stays
  plaintext here because both live on one host; `--client-ca`, `--client-cert`
  and `--client-key` are what encrypt that leg too.
- `--health-check http --health-path /health` — the proxy asks the backend a
  real question at an interval, instead of assuming a listening port means a
  working service. `api.lua` answers it.
- `--circuit-threshold 5 --circuit-timeout 30` — after five consecutive backend
  errors the circuit opens and requests fail immediately rather than waiting for
  a connect that will not work. Thirty seconds later one probe is let through.
- `--retry 2` — a failed request is retried on the next backend in the pool.
  Only idempotent methods, unless you add `--retry-all` and accept that a POST
  body is replayed.
- `--backend-timeout 5` — how long the backend may take for the first response
  byte before the request is given up on.

`--sidecar` is shorthand for most of that. It is spelled out here so you can see
what it sets.

## Where the state lives, and what that costs

In a Lua table, in the API server's process. That is a real limitation and the
example says so rather than hiding behind a demo that never restarts:

- it is lost when the runtime stops;
- **`--shards N` would make it N separate tables**, because each shard is its own
  process and a Lua table does not cross one. That is why the API runtime here
  is created without shards.

The durable answer is a `cache` runtime, and socketley's Lua cannot reach one
synchronously from a server: `socketley.send()` is fire-and-forget and
`socketley.subscribe()` is pub/sub, so neither gives you a read-back inside a
request. If you need shared, durable state behind an HTTP handler today, the
options are the C++ SDK — whose `cache_get()` is synchronous — or a client-facing
`--cache` passthrough, which is a different shape of application.

## Where to go from here

- `../../proxy/declared-routes.lua` — let the handler declare which methods it
  answers, so the gateway can refuse the rest at the edge
- `../../server/sharded-server.sh` — `--shards`, and what it refuses
- `../../cache/sharded-cache.sh` — one keyspace across N processes
- `../../cluster/` — several daemons discovering each other
