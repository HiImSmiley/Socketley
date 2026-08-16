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
non2xx = []


def worker(count):
    global successes
    mine = []
    mine_bad = []
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
        #
        # And the CODE, not merely a status line.  An http proxy routes on a
        # "/<proxy-name>/" prefix and answers everything else 404 -- itself,
        # without opening a backend connection at all -- so a request that has
        # lost the prefix is served several times faster than the thing being
        # measured, and to a check that stops at b"HTTP/1." it is indis-
        # tinguishable from a successful proxy hop.  The figure published would
        # be the rate at which this proxy can refuse to proxy.
        #
        # Nothing is mis-routed today: bench_proxy.sh asks for /bench_proxy/test
        # against a proxy named bench_proxy, and that was measured returning 200
        # with the backend contacted, while / and /test on the same proxy
        # returned 404.  It is one rename away from not being, and the failure
        # is silent and reads as a speed-up -- which is the combination that
        # wants an oracle rather than a comment.
        if data.startswith(b"HTTP/1."):
            rtt = (time.perf_counter() - t0) * 1000.0
            try:
                code = int(data.split(None, 2)[1])
            except (IndexError, ValueError):
                code = 0
            if 200 <= code < 300:
                mine.append(rtt)
                ok += 1
            else:
                # Deliberately not counted and deliberately not timed: the
                # latency of a refusal is not the latency of a proxy hop, and
                # averaging the two describes neither.
                mine_bad.append(code)
    with lock:
        latencies.extend(mine)
        successes += ok
        non2xx.extend(mine_bad)


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

# non2xx is appended rather than folded into success, so a caller that greps
# success= is unaffected and a caller that wants the oracle has it.  A run with
# a non-zero count here is not a slow run, it is a run measuring the wrong
# thing -- and saying so on the same line is what makes that visible without
# anyone having to go looking.
line = ("success=%d elapsed_ms=%.0f avg_ms=%.3f p99_ms=%.3f non2xx=%d"
        % (successes, elapsed_ms, avg, p99, len(non2xx)))
if non2xx:
    codes = {}
    for c in non2xx:
        codes[c] = codes.get(c, 0) + 1
    line += " codes=" + ",".join("%d:%d" % (c, n) for c, n in sorted(codes.items()))
print(line)
