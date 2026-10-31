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
# ─── WHY A RATIO AND NOT A NUMBER ───────────────────────────────────────────
# Microseconds depend on the machine, the governor and what else is running --
# this box is a KVM guest whose host can change frequency without saying so.
# The PROPERTY is that idle connections are free, and a ratio states it without
# pinning a number that would rot.  Two and a half is far outside both sides:
# measured at 4.1x before the fix and 1.0x after, six runs each, interleaved.
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

# p50 of a ping-pong on one connection while N others sit open and silent.
p50() {
    python3 - "$PORT" "$1" <<'PY'
import socket, sys
port, nidle = int(sys.argv[1]), int(sys.argv[2])
idle = []
try:
    for _ in range(nidle):
        s = socket.create_connection(("127.0.0.1", port), 10)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        idle.append(s)
except OSError:
    pass
if len(idle) < nidle // 2:
    print("TOO_FEW"); raise SystemExit(0)
import time
m = socket.create_connection(("127.0.0.1", port), 10)
m.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
msg, buf, lat = b"p"*29 + b"\n", b"", []
for _ in range(1500):
    t0 = time.perf_counter_ns()
    m.sendall(msg)
    while b"\n" not in buf:
        d = m.recv(65536)
        if not d: break
        buf += d
    if b"\n" not in buf: break
    _, buf = buf.split(b"\n", 1)
    lat.append(time.perf_counter_ns() - t0)
lat.sort()
print(lat[len(lat)//2] if lat else "NONE")
m.close()
for s in idle: s.close()
PY
}

LOW=$(p50 500)
HIGH=$(p50 4000)
echo "  p50 with 500 idle: ${LOW} ns, with 4000 idle: ${HIGH} ns"

case "$LOW$HIGH" in
    *TOO_FEW*|*NONE*)
        ok no "the measurement ran at all (got LOW=$LOW HIGH=$HIGH)" ;;
    *)
        # Integer arithmetic: HIGH must be under 2.5x LOW.
        ok "$([ "$((HIGH * 10))" -lt "$((LOW * 25))" ] && echo yes || echo no)" \
           "four thousand silent connections cost the busy one under 2.5x (was 4.1x)" ;;
esac

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
