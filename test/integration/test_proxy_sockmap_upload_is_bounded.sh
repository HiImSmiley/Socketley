#!/usr/bin/env bash
# suite: quiet -- a stalled upload storm pushes the machine's memory, which a
# test running beside it would feel.
# Integration test: the kernel relay's backlog does not grow without bound
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# With SOCKETLEY_PROXY_SOCKMAP the kernel redirects a pair's bytes between two
# sockets, and a backend that stops reading makes the kernel hold the client's
# upload with no bound of its own -- a standalone probe pushed 512 MB into a
# stalled backend and watched the host lose 549 MB with nothing refused.  Unlike
# the copy path, the kernel path cannot pace: deleting a socket from the map to
# hand it back drops whatever is queued in the redirect's backlog (measured,
# 1.5 MB of 4 MB), so there is no lossless way out.  The proxy's 250 ms sweep
# therefore DROPS a pair whose in-kernel backlog passes --write-buffer, the same
# terminal answer the copy path gives when its write queue passes that bound.
# The cap is coarse -- the redirect has no backpressure and fills at the link's
# rate (~3 GB/s on loopback, measured), so within a sweep the hold tracks the
# bytes in flight; the sweep bounds it to one interval of that, not to
# --write-buffer.  So this asserts the pair is DROPPED (the backend sees a small
# fraction of what was sent), not a tight memory figure, which loopback cannot
# give; the peak drop is reported for the record.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * the sweep never firing, so the pair stays in the map and the kernel holds
#     the whole upload until the backend reads, delivering all of it -- the
#     backend would count everything that was sent rather than a fraction
#
# Skips cleanly where BPF cannot be loaded (no CAP_BPF/CAP_NET_ADMIN).
set -euo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

echo "=== Integration: a stalled kernel-relay pair is dropped, not buffered whole ==="
if ! command -v python3 >/dev/null 2>&1; then
    echo "  SKIP: python3 not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0
fi
if ! command -v gcc >/dev/null 2>&1; then
    echo "  SKIP: no C compiler"; echo "  Results: 0/0 passed (0 failed)"; exit 0
fi

PASS=0; FAIL=0; TOTAL=0
WORK=$(mktemp -d)
BEPID=""
cleanup(){ [ -n "$BEPID" ] && { kill -9 "$BEPID" 2>/dev/null || true; }; rm -rf "$WORK"; daemon_stop; }
trap cleanup EXIT
pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; for l in "${@:3}"; do echo "        $l"; done; }
not_asserted(){ TOTAL=$((TOTAL+1)); echo "  NOT ASSERTED [$1]: $2"; }

SANITIZED=""
if nm -C "$BIN" 2>/dev/null | grep -q '__asan_'; then SANITIZED="ASan"; fi

BPORT=$((SL_PORT_BASE + 1771))
PPORT=$((SL_PORT_BASE + 1772))
CONNS=4
PER=$((64 * 1024 * 1024))     # 256 MB in flight, dwarfing the 8 MiB write bound
QUIET=3

# A backend that accepts and does not read for QUIET seconds, then drains and
# counts what each connection delivered.
cat >"$WORK/sink.py" <<'PY'
import socket, sys, selectors, time
port, quiet = int(sys.argv[1]), float(sys.argv[2])
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port)); srv.listen(64); srv.setblocking(False)
sel = selectors.DefaultSelector(); sel.register(srv, selectors.EVENT_READ, None)
held, counts, t0 = [], {}, time.time()
draining, seen, live = False, 0, 0
while True:
    for key, _ in sel.select(timeout=0.2):
        if key.data is None:
            while True:
                try: c, _ = srv.accept()
                except OSError: break
                c.setblocking(False); held.append(c); counts[c.fileno()] = 0; seen += 1
                if draining: sel.register(c, selectors.EVENT_READ, c.fileno()); live += 1
        else:
            try: d = key.fileobj.recv(262144)
            except OSError: d = b""
            if d: counts[key.data] += len(d)
            else: sel.unregister(key.fileobj); key.fileobj.close(); live -= 1
    if not draining and time.time() - t0 > quiet:
        draining = True
        for c in held:
            try: sel.register(c, selectors.EVENT_READ, c.fileno()); live += 1
            except (KeyError, ValueError, OSError): pass
    if draining and seen > 0 and live <= 0: break
    if time.time() - t0 > quiet + 120: break
with open(sys.argv[3], "w") as f:
    for v in counts.values(): f.write("%d\n" % v)
PY

if ! gcc -O2 -pthread -o "$WORK/load" "$HERE/lib_hold_load.c" 2>"$WORK/cc.log"; then
    echo "  SKIP: C compiler could not build the load helper"; cat "$WORK/cc.log"
    echo "  Results: 0/0 passed (0 failed)"; exit 0
fi

mem_avail_kb(){ awk '/^MemAvailable:/{print $2}' /proc/meminfo; }

daemon_isolate sockmapbound
export SOCKETLEY_PROXY_SOCKMAP=1
daemon_start "$BIN"
"$BIN" create proxy skb -p "$PPORT" --backend "127.0.0.1:$BPORT" --protocol tcp -s >/dev/null 2>&1 || true
for _ in $(seq 1 150); do ss -ltn 2>/dev/null | grep -q ":$PPORT " && break; sleep 0.1; done

# Without the capabilities the proxy said so and stayed on the copy path; this
# file is about the kernel path, so it skips rather than measures the copy one.
for _ in $(seq 1 30); do grep -q 'kernel relay is unavailable' "$SOCKETLEY_DLOG" 2>/dev/null && break; sleep 0.1; done
if grep -q 'kernel relay is unavailable' "$SOCKETLEY_DLOG" 2>/dev/null; then
    echo "  SKIP: kernel relay unavailable (needs CAP_BPF/CAP_NET_ADMIN)"
    echo "  Results: 0/0 passed (0 failed)"; exit 0
fi
if ! ss -ltn 2>/dev/null | grep -q ":$PPORT "; then
    echo "  FATAL: the proxy never bound $PPORT"; echo "  Results: 0/0 passed (0 failed)"; exit 2
fi

WORKER=$(ss -ltnp 2>/dev/null | awk -v p=":$PPORT" '$4 ~ p"$" {
    if (match($0, /pid=[0-9]+/)) print substr($0, RSTART+4, RLENGTH-4) }' | head -1)
rss_kb(){ awk '/^VmRSS/{print $2}' "/proc/$1/status" 2>/dev/null || echo 0; }

# Start the stalled backend, then a storm that each pushes PER into it.
python3 "$WORK/sink.py" "$BPORT" "$QUIET" "$WORK/counts" >"$WORK/be.log" 2>&1 &
BEPID=$!
for _ in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$BPORT " && break; sleep 0.1; done

BASE_MEM=$(mem_avail_kb); BASE_RSS=$(rss_kb "$WORKER")
"$WORK/load" up "$PPORT" "$CONNS" "$PER" >"$WORK/up" 2>/dev/null &
UP=$!
LOW_MEM=$BASE_MEM; PEAK_RSS=$BASE_RSS
# Sample only across the stall, before the backend starts draining.
for _ in $(seq 1 $(( QUIET * 10 )) ); do
    sleep 0.1
    kill -0 "$UP" 2>/dev/null || break
    m=$(mem_avail_kb); [ -n "$m" ] && [ "$m" -lt "$LOW_MEM" ] && LOW_MEM=$m
    [ -n "$WORKER" ] && { r=$(rss_kb "$WORKER"); [ -n "$r" ] && [ "$r" -gt "$PEAK_RSS" ] && PEAK_RSS=$r; }
done
wait "$UP" 2>/dev/null || true
OPENED=$(sed -n 1p "$WORK/up" 2>/dev/null || echo 0)
SENT=$(sed -n 2p "$WORK/up" 2>/dev/null || echo 0)
MEM_DROP=$(( (BASE_MEM - LOW_MEM) / 1024 ))
RSS_GREW=$(( (PEAK_RSS - BASE_RSS) / 1024 ))
INTENDED=$(( CONNS * PER / 1024 / 1024 ))
echo "  $OPENED clients uploaded into a backend stalled ${QUIET}s: intended ${INTENDED} MB in flight,"
echo "  host MemAvailable dropped ${MEM_DROP} MB, worker RSS grew ${RSS_GREW} MB"

# Let the backend drain and count.
for _ in $(seq 1 600); do [ -s "$WORK/counts" ] && break; sleep 0.2; done
daemon_stop
[ -n "$BEPID" ] && { kill -9 "$BEPID" 2>/dev/null || true; }; BEPID=""

GOT_TOTAL=$(awk '{s+=$1} END{print s+0}' "$WORK/counts" 2>/dev/null || echo 0)
GOT_FULL=$(awk -v w="$PER" '$1 >= w {n++} END{print n+0}' "$WORK/counts" 2>/dev/null || echo 0)
echo "  backend counted $((GOT_TOTAL/1024/1024)) MB in $GOT_FULL whole uploads of $CONNS"

# The peak host-memory drop within the stall is reported, not asserted: the
# redirect has no backpressure and fills at the link's rate (~3 GB/s on
# loopback, measured), so between two sweeps the kernel's hold tracks the bytes
# in flight, and the cap is one sweep of that, not --write-buffer.  On a real
# NIC the same sweep bounds the hold at rate x 250 ms.  Reported so the coarse-
# ness is visible rather than asserted away.
echo "  (peak host MemAvailable drop during the stall: ${MEM_DROP} MB of ${INTENDED} MB" \
     "in flight -- the redirect cannot be paced, so this tracks the link within a sweep)"

# ── 1. the valve fires: a stalled pair is dropped, not buffered whole ────────
# Without the valve the pair stays in the map and the kernel holds the entire
# upload until the backend finally reads, delivering all of it -- unbounded and
# indefinite.  With it, the sweep resets an over-bound pair mid-stall, so the
# backend sees almost nothing of what was sent.  That the delivered total is a
# small fraction of what was sent is the proof the proxy drops rather than
# holding it all for later.
if [ "${OPENED:-0}" -lt "$CONNS" ]; then
    fail "the storm reached the proxy" \
         "only $OPENED of $CONNS clients connected, so there is nothing to bound"
elif [ "${GOT_TOTAL:-0}" -lt $(( CONNS * PER / 4 )) ]; then pass
else fail "the kernel relay drops a stalled pair rather than buffering it whole" \
          "the backend received $((GOT_TOTAL/1024/1024)) MB of the $((CONNS*PER/1024/1024)) MB sent" \
          "-- the sweep should reset a pair whose in-kernel backlog passes the" \
          "   write bound, so a stalled reader cannot make the kernel hold the" \
          "   whole upload for eventual delivery"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" = 0 ] || exit 1
