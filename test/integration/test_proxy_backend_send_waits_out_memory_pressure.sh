#!/usr/bin/env bash
# Integration test: a TCP proxy's send to its backend waits out TCP memory
# pressure instead of dropping the pair
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# A backend socket is created SOCK_NONBLOCK for its asynchronous connect.  Once
# the machine's TCP memory is over tcp_mem's pressure point the kernel refuses
# sends from sockets over their share, while poll still calls them writable, so
# io_uring's retry after the poll fails the same way and the send completes with
# -EAGAIN.  handle_backend_write took every res <= 0 as the backend being gone
# and closed the pair.  Measured with 1,100 uploads of 1 MiB into a backend that
# reads nothing for six seconds: 116 to 639 of them cut short, the client's own
# socket reset in the middle of a body, and in one run every client reporting
# its megabyte written while 116 of them never reached the backend -- bytes the
# client had been told were delivered, dropped without a line in any log.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * the kernel never reaching pressure, which would make the rest a test of
#     nothing -- reported as not asserted, never as a pass
#   * every upload reaching the backend byte for byte
#   * and no client seeing its connection end early
set -euo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1
PASS=0; FAIL=0; TOTAL=0
WORK=$(mktemp -d)
BEPID=""
cleanup(){ [ -n "$BEPID" ] && { kill -9 "$BEPID" 2>/dev/null || true; }; rm -rf "$WORK"; daemon_stop; }
trap cleanup EXIT
pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; for l in "${@:3}"; do echo "        $l"; done; }
not_asserted(){ TOTAL=$((TOTAL+1)); echo "  NOT ASSERTED [$1]: $2"; }

echo "=== Integration: a proxy's backend send waits out TCP memory pressure ==="

# Half again the pressure point in 1 MiB uploads, because the kernel holds most
# of each one in the four socket buffers it crosses; 1,100 on a box with 11 GiB.
PER=1048576
read -r _ TCP_PRESSURE_PAGES _ < /proc/sys/net/ipv4/tcp_mem
N=$(( TCP_PRESSURE_PAGES * 4096 * 3 / 2 / PER + 1 ))
if [ "$N" -gt 2000 ]; then
    echo "  SKIP: tcp_mem puts pressure at $(( TCP_PRESSURE_PAGES * 4096 / 1048576 )) MB, out of reach of $N uploads"
    echo "  Results: 0/0 passed (0 failed)"; exit 0
fi
if [ "$(ulimit -n)" -lt $(( N * 2 + 256 )) ]; then
    echo "  SKIP: ulimit -n $(ulimit -n) is too low for $N uploads"
    echo "  Results: 0/0 passed (0 failed)"; exit 0
fi
if ! gcc -O2 -pthread -o "$WORK/load" "$HERE/lib_hold_load.c" 2>"$WORK/cc.log"; then
    echo "  SKIP: no C compiler"; cat "$WORK/cc.log"; echo "  Results: 0/0 passed (0 failed)"; exit 0
fi

P=$((SL_PORT_BASE + 115)); BP=$((P + 1))
pressures(){ awk '/^TcpExt:/ { if (!h) { split($0, k); h = 1 } else { split($0, v)
    for (i in k) if (k[i] == "TCPMemoryPressures") print v[i] } }' /proc/net/netstat; }

# Six seconds without reading is what puts the machine over the pressure point,
# and the drain after it is what lets every upload finish.
"$WORK/load" drain "$BP" 6 "$WORK/counts" >/dev/null 2>&1 &
BEPID=$!
for _ in $(seq 1 50); do ss -ltn 2>/dev/null | grep -q ":$BP " && break; sleep 0.1; done

daemon_isolate backendpressure
daemon_start "$BIN"
"$BIN" create proxy bp -p "$P" --backend "127.0.0.1:$BP" --protocol tcp -s >/dev/null 2>&1 || true
for _ in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$P " && break; sleep 0.1; done
if ! ss -ltn 2>/dev/null | grep -q ":$P "; then
    echo "  FATAL: the proxy never bound $P"; echo "  Results: 0/0 passed (0 failed)"; exit 2
fi

BEFORE=$(pressures)
read -r FULL ERRS < <("$WORK/load" whole "$P" "$N" "$PER" 2>&1 >/dev/null | tail -1)
wait "$BEPID" 2>/dev/null || true
BEPID=""
AFTER=$(pressures)
WHOLE=$(awk -v w="$PER" '$1 == w { n++ } END { print n + 0 }' "$WORK/counts" 2>/dev/null || echo 0)
SEEN=$(wc -l < "$WORK/counts" 2>/dev/null || echo 0)
echo "  $N uploads of 1 MiB: $WHOLE whole of $SEEN at the backend, clients $FULL written and $ERRS cut," \
     "memory pressure entered $(( AFTER - BEFORE )) time(s)"

# ── 1. the machine was under pressure ───────────────────────────────────────
if [ $(( AFTER - BEFORE )) -gt 0 ]; then
    pass
    # ── 2. and every upload arrived whole ───────────────────────────────────
    if [ "$WHOLE" = "$N" ]; then pass
    else fail "every upload reaches the backend whole" "$WHOLE of $N arrived whole, $SEEN connections seen" \
              "-- a send refused for memory came back -EAGAIN and was taken as the backend gone"; fi
    # ── 3. and no client was cut ────────────────────────────────────────────
    if [ "$FULL" = "$N" ] && [ "$ERRS" = 0 ]; then pass
    else fail "no client connection ends early" "$FULL of $N wrote everything, $ERRS saw an error"; fi
else
    not_asserted "the machine was under TCP memory pressure" \
                 "TCPMemoryPressures did not move, so nothing here was refused for memory"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
