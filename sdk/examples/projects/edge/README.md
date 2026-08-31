# edge — a TLS gateway in front of a unix-socket application

The deployment shape reverse proxies exist for, in two small binaries: an
application server that is reachable only through the filesystem, and a
gateway that owns the network — TLS termination, per-request routing, health
checks, circuit breaker, retries.

```
 curl -k https://:8443/gw/...          (TLS, the only public surface)
        │
        ▼
   edge-gw :8443     proxy: tls() + protocol_http + sidecar()
        │                   on_proxy_request = access log
        ▼
   unix:/tmp/edge-app.sock              (a node, not a port)
        │
   edge-app          server: http_dir("./public") + http_cache()
```

| file | role | shows |
|---|---|---|
| `app.cpp` | static-file app server on an AF_UNIX listener | the `unix:` constructor, `http_dir` |
| `gateway.cpp` | TLS-terminating HTTP gateway | `tls()`, `sidecar()`, unix backend, hooks, the name-as-prefix rule |

## Build & run

```bash
# certificates (any pair works for the demo)
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
    -days 30 -nodes -subj "/CN=localhost"

g++ -std=c++23 sdk/examples/projects/edge/app.cpp \
    $(sdk/socketley-config --cflags --libs) -o edge-app
g++ -std=c++23 sdk/examples/projects/edge/gateway.cpp \
    ... same flags ... -o edge-gw

cd sdk/examples/projects/edge   # so ./public and the .pem files resolve
./edge-app &  ./edge-gw &
curl -k https://127.0.0.1:8443/gw/index.html
```

## What this example is really about

- **The app has no port.** `server("unix:/tmp/edge-app.sock")` binds a
  filesystem node (mode 0600); nothing off-machine can reach it, and the
  gateway addresses it with `backend("unix:/tmp/edge-app.sock")`.
- **The proxy's name is its URL space.** In `protocol_http` mode the runtime
  routes by path prefix `/<name>/` — `proxy(8443, "gw")` serves `/gw/...` and
  answers 404 for anything else before a backend is consulted. `protocol_tcp`
  has no prefix (and no per-request anything).
- **The hook contract is not the obvious one.** `on_proxy_request` returns
  `std::optional<std::string>`: `nullopt` DROPS the bytes, an empty string
  passes them unchanged, a non-empty string replaces them. Read the comment
  in `proxy.h` before writing one — a hook that returns `nullopt` meaning
  "no edit" forwards nothing, and every request dies at `backend_timeout`.
- **Scale-out is one line.** A second `backend(...)` makes the strategy load
  balance; `sidecar()`'s health checks eject a dead one and the breaker stops
  hammering it.
