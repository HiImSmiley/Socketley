#!/usr/bin/env python3
"""Closed-loop HTTP client for the proxy benchmarks.

Both HTTP tests used to drive the proxy from bash: a subshell per request,
/dev/tcp for the connection, and `read` for the reply.  What that timed was
bash.  The single-backend test additionally called get_time_ms() twice inside
each subshell -- and that forks `date` -- so it paid three process creations per
request where the load-balancing test paid one.  The two then reported 710 and
3603 req/sec against the same proxy, and the difference was entirely their own
forking: one number was quoted as the cost of a proxy hop and the other as the
benefit of a second backend, and neither was either.

The proxy serves half a million messages a second on the TCP path in the same
suite.  Nothing that reports three digits for HTTP on loopback is describing it.

So: one client, used by both tests, so their numbers are comparable by
construction rather than by hope.  Requests are issued from threads that keep no
state between them, latency is measured around the request itself in-process,
and a reply only counts when it is a status line -- a connection that opened and
returned nothing is a failure, not a fast success.

`Connection: close` is kept from the original: this measures a fresh connection
per request, which is the harder case for a proxy and the one the tests were
written for.  Reusing connections would be a different measurement, not a better
version of this one.

Usage: http_load.py HOST PORT PATH TOTAL CONCURRENCY
Prints one line: success=N elapsed_ms=N avg_ms=F p99_ms=F
"""
import socket
import sys
import threading
import time

host, port, path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
total, concurrency = int(sys.argv[4]), int(sys.argv[5])

REQUEST = (
    "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % (path, host)
).encode()

lock = threading.Lock()
latencies = []
successes = 0


def worker(count):
    global successes
    mine = []
    ok = 0
    for _ in range(count):
        t0 = time.perf_counter()
        try:
            s = socket.create_connection((host, port), 5)
            s.settimeout(5)
            s.sendall(REQUEST)
            data = s.recv(4096)
            s.close()
        except Exception:
            continue
        # A status line, not merely bytes: a proxy that closes on us returns
        # b"" here, and counting that as a served request is how a broken
        # backend turns into a throughput record.
        if data.startswith(b"HTTP/1."):
            mine.append((time.perf_counter() - t0) * 1000.0)
            ok += 1
    with lock:
        latencies.extend(mine)
        successes += ok


# Split the work so the last thread absorbs the remainder rather than a thread
# being started for it.
per = total // concurrency
extra = total % concurrency
threads = []
start = time.perf_counter()
for i in range(concurrency):
    n = per + (extra if i == concurrency - 1 else 0)
    if n <= 0:
        continue
    t = threading.Thread(target=worker, args=(n,))
    t.start()
    threads.append(t)
for t in threads:
    t.join()
elapsed_ms = (time.perf_counter() - start) * 1000.0

latencies.sort()
avg = sum(latencies) / len(latencies) if latencies else 0.0
p99 = latencies[min(len(latencies) - 1, int(len(latencies) * 0.99))] if latencies else 0.0

print("success=%d elapsed_ms=%.0f avg_ms=%.3f p99_ms=%.3f"
      % (successes, elapsed_ms, avg, p99))
