#!/usr/bin/env bash
# Integration test: a connection that says nothing costs the others nothing
#
# ─── WHAT THIS REPLACES ─────────────────────────────────────────────────────
# refresh_pacing_watermark() ran once per loop turn and summed the write queue
# of EVERY connection the runtime held, to answer one yes/no question about a
# budget -- and it fed a hold that lasts fifty milliseconds, so the answer was
# recomputed thousands of times for every time it could possibly change.  Each
# step of that walk is a pointer into a separate allocation, so the cost was a
# cache miss per connection, paid by whichever connection happened to be doing
# work.  Measured on one ping-pong per turn with all the others idle:
#
#     open      p50 round trip     worker CPU per request
#     1001          26.3 us              26.7 us
#     3001          56.7 us              96.7 us
#     5001         124.9 us             193.3 us
#
# A profile at 5001 put 81.72% of the worker inside that one call, computing
# a total that was zero.
#
# ─── WHY A RATIO OF CPU AND NOT OF TIME ─────────────────────────────────────
# Microseconds depend on the machine, the governor and what else is running --
# this box is a KVM guest whose host can change frequency without saying so.
# The PROPERTY is that idle connections are free, and a ratio states it without
# pinning a number that would rot.  It is the worker's CPU per request, read off
# its CPU clock, because the walk is CPU and a round trip on a loaded machine is
# mostly the scheduler, which a parallel suite turned red with the walk gone.
# Only requests that went round fast count: on a machine loaded enough that each
# wakeup waits for the next tick, every turn finds the 2 ms sample due and pays
# the walk the fix spaces out -- measured at 14x, with the fix in.
# The two counts are interleaved, low, high, high, low, so a machine that
# changes under the test changes both alike.
#
# ─── WHY TEN THOUSAND ───────────────────────────────────────────────────────
# The walk is a few nanoseconds a connection while the connections fit in the
# cache: with it put back, four thousand cost 1.4x and p50 did not move at all,
# so the test at four thousand was green with the defect in.  Eight thousand
# cost 2.7-2.9x with the walk and 1.0-1.2x without it, too near the line on the
# defect's side; the loopback range leaves room for ten thousand to one port.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate idlecost
PORT=$((SL_PORT_BASE+530))
PASS=0; FAIL=0; TOTAL=0

cleanup() { "$BIN" stop ic 2>/dev/null || true; "$BIN" remove ic 2>/dev/null || true; daemon_stop; }
trap cleanup EXIT
daemon_start "$BIN"

ok() {
    TOTAL=$((TOTAL+1))
    if [ "$1" = "yes" ]; then PASS=$((PASS+1)); echo "  PASS: $2"
    else FAIL=$((FAIL+1)); echo "  FAIL: $2"; fi
}

"$BIN" create server ic -p "$PORT" --send-to sender --max-connections 200000 >/dev/null
"$BIN" start ic >/dev/null
for _ in $(seq 1 100); do (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && break; sleep 0.2; done

# The worker's CPU per ping-pong on one connection, and its p50 for the record, while 500 and then 10000 others sit
# open and silent.
W=$(cat /proc/"$SOCKETLEY_DPID"/task/*/children 2>/dev/null | tr ' ' '\n' | grep . | head -1 || true)
OUT=$(python3 - "$PORT" "${W:-0}" "$BIN" <<'PY'
import os, resource, socket, struct, subprocess, sys, time
port, worker, binary = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
if soft != resource.RLIM_INFINITY and soft < 11000:
    resource.setrlimit(resource.RLIMIT_NOFILE, (11000 if hard == resource.RLIM_INFINITY else min(11000, hard), hard))

# The worker's own CPU clock, MAKE_PROCESS_CPUCLOCK(pid, CPUCLOCK_SCHED), exact where schedstat trails by a tick.
clock = (~worker << 3) | 2

def cpu_ns():
    return time.clock_gettime_ns(clock)

def open_n(n):
    out = []
    try:
        for _ in range(n):
            out.append(socket.create_connection(("127.0.0.1", port), 10))
    except OSError:
        pass
    return out

def held():
    # The connections the runtime says it holds, which trail what this side has opened or reset while it catches up.
    out = subprocess.run([binary, "stats", "ic"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if line.startswith("connections:"):
            return int(line.split(":", 1)[1])
    return -1

def quiet(want):
    # Until the worker holds what this side holds, and has stopped spending CPU on getting there.
    for _ in range(400):
        if held() == want:
            break
        time.sleep(0.05)
    last = cpu_ns()
    for _ in range(100):
        time.sleep(0.1)
        now = cpu_ns()
        if now - last < 2_000_000:
            return
        last = now

if not worker or not os.path.isdir("/proc/%d/task" % worker):
    print("NO_WORKER"); raise SystemExit(0)
base = open_n(500)
m = socket.create_connection(("127.0.0.1", port), 10)
m.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
msg, buf = b"p" * 29 + b"\n", b""

def ping(n):
    global buf
    lat = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        m.sendall(msg)
        while b"\n" not in buf:
            d = m.recv(65536)
            if not d:
                return lat
            buf += d
        _, buf = buf.split(b"\n", 1)
        lat.append(time.perf_counter_ns() - t0)
    return lat

def phase(chunks=30, n=100):
    # Each hundred requests as its CPU per request and its mean round trip.
    out, lat = [], []
    for _ in range(chunks):
        c0, t0 = cpu_ns(), time.perf_counter_ns()
        got = ping(n)
        c1, t1 = cpu_ns(), time.perf_counter_ns()
        if len(got) < n:
            return None
        lat += got
        out.append(((c1 - c0) / n, (t1 - t0) / n))
    lat.sort()
    return out, lat[len(lat) // 2]

if len(base) < 400 or len(ping(200)) < 200:
    print("TOO_FEW"); raise SystemExit(0)
extra, got = [], {"low": [], "high": []}
for arm in ("low", "high", "high", "low"):
    if arm == "high" and not extra:
        extra = open_n(9500)
        if len(extra) < 9000:
            print("TOO_FEW"); raise SystemExit(0)
    if arm == "low" and extra:
        for s in extra:
            # A reset, so ten thousand closes leave no TIME_WAIT on the ports a parallel suite shares.
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            s.close()
        extra = []
    quiet(len(base) + len(extra) + 1)
    ping(200)
    r = phase()
    if r is None:
        print("NONE"); raise SystemExit(0)
    got[arm].append(r)
# Only the hundreds whose round trips were well inside the 2 ms the walk is sampled on count, because a turn that
# waited longer for a loaded machine to wake the client finds the sample due every time, walk or no walk; and the
# cheap end of those, the first quarter, because a loop that spins while it waits only ever adds.
fast = {a: [c for r in got[a] for c, t in r[0] if t < 200_000] for a in got}
if not fast["low"] or not fast["high"]:
    print("SLOW", len(fast["low"]), len(fast["high"])); raise SystemExit(0)
cpu = {a: int(sorted(fast[a])[len(fast[a]) // 4]) for a in got}
p50 = {a: int(sum(r[1] for r in got[a]) / len(got[a])) for a in got}
print(cpu["low"], cpu["high"], p50["low"], p50["high"], len(fast["low"]), len(fast["high"]))
PY
)
read -r LOW HIGH P50LOW P50HIGH NLOW NHIGH <<<"$OUT" || true
echo "  worker CPU per request with 500 idle: ${LOW} ns, with 10000 idle: ${HIGH} ns (p50 ${P50LOW:-?} ns, ${P50HIGH:-?} ns; ${NLOW:-?} and ${NHIGH:-?} fast hundreds)"

case "$LOW$HIGH" in
    SLOW*)
        # A machine too loaded to turn the loop fast says nothing about the walk, either way.
        echo "  SKIP: no hundred requests went round in under 200 us at one of the counts ($OUT)" ;;
    ''|*[!0-9]*)
        ok no "the measurement ran at all (got $OUT)" ;;
    *)
        # Integer arithmetic: HIGH must be under 2.5x LOW.
        ok "$([ "$((HIGH * 10))" -lt "$((LOW * 25))" ] && echo yes || echo no)" \
           "ten thousand silent connections cost the busy one under 2.5x the worker's CPU per request" ;;
esac

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
