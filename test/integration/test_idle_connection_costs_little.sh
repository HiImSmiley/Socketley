#!/usr/bin/env bash
# Integration test: an idle cache connection costs kilobytes, not tens of them.
#
# ─── WHAT THIS GUARDS ───────────────────────────────────────────────────────
#
# A connection used to be charged three four-kilobyte blocks the moment it was
# accepted and before it had said anything: an inline read_buf, and a
# reserve(4096) apiece on partial and response_buf.  Measured against a fresh
# worker per reading, five thousand idle connections, five passes:
#
#     14.10 KB per connection  ->  2.04 KB     -85.5%
#
# Redis on the same box is 1.25 to 1.38 KB, so this went from ten times its
# cost to one and a half.  Throughput did not move: measured in both directions
# with the arms exchanged, 0.9862 one way and 1.0062 the other, which is the
# instrument and not the code.
#
# A server carried the same shape and worse -- a SIXTEEN kilobyte read_buf and
# a reserve(8192) -- and came out 22.21 -> 4.92 KB, identical in four passes,
# with its throughput at 1.0040 across the swap, which is again the instrument.
#
# A proxy kept its sixty-four kilobyte read buffer zero-filled at allocation,
# so every pooled struct was resident before a byte arrived: 65.99 -> 6.89 KB
# once it is built by make_connection and the pages are touched by the reads
# that use them.  It was held back twice on test_proxy_upload_is_bounded.sh
# reading 120 MB more with the change, which was the upload flood's own pairs
# being cut by -EAGAIN under TCP memory pressure and freeing their buffers at
# random -- with that fixed the change holds less there, not more.  12 KB
# catches the zero-fill coming back and cannot fail on 6.89 drifting.
#
# The read_buf is the last arm of four -- bundle, multishot, provided-buffer
# read, and only then a plain read into it -- so with a buffer ring, which is
# every start that gets one, it was never written to.  It is now allocated only
# by a start that has no ring, and held rather than freed once taken so no read
# can be armed on storage that has gone.
#
# ─── WHY A THRESHOLD AND NOT A FIGURE ───────────────────────────────────────
#
# RSS is the machine's answer, not the program's, so the assertion is a bound
# far above what was measured and far below what the defect cost: 5 KB per
# connection catches a return to 14 and cannot fail on 2.04 drifting.  A test
# that pinned 2.04 would fail on a different allocator and teach nobody
# anything.
set -euo pipefail

# ─── NOT UNDER A SANITIZER ──────────────────────────────────────────────────
# Every bound here is bytes of RSS per connection, and a sanitizer build spends
# bytes of RSS per allocation on purpose: ASan puts a redzone either side of
# each block and keeps a shadow byte for every eight.  Measured on this file
# under SOCKETLEY_CONFIG=Sanitize, against the Release numbers the bounds were
# drawn from:
#
#     cache   2.04 KB -> 6.12 KB       bound 5
#     server  4.92 KB -> 8.16 KB
#
# Loosening the bounds to fit both would leave numbers that guard nothing in
# either build.  So this measures the allocator it was written about and says
# so when it is handed a different one.
if [ "${SOCKETLEY_CONFIG:-}" = "Sanitize" ]; then
    echo "  SKIP: RSS per connection measures the sanitizer's redzones under Sanitize"
    exit 0
fi

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_ready.sh"
daemon_isolate idlecost

P=$((SL_PORT_BASE+1890))
P_SRV=$((SL_PORT_BASE+1892))
P_BE=$((SL_PORT_BASE+1894))
P_PRX=$((SL_PORT_BASE+1896))
CONNS=2000
BUDGET_KB=5
BUDGET_SRV_KB=9
BUDGET_PRX_KB=12

PASS=0; FAIL=0; TOTAL=0
ok()    { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad()   { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "expected '$2', got '$3'"; fi; }

HOLDER=""
cleanup() {
    [ -n "$HOLDER" ] && { { kill -9 "$HOLDER" 2>/dev/null; wait "$HOLDER"; } 2>/dev/null || true; }
    for n in ic is ip ib; do "$BIN" stop "$n" >/dev/null 2>&1 || true; done
    sleep 0.3
    for n in ic is ip ib; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: an idle connection costs kilobytes, not tens ==="
daemon_start "$BIN"
create_ok "a cache" "$BIN" create cache ic -p "$P"
"$BIN" start ic >/dev/null 2>&1 || true
ready_resp 127.0.0.1 "$P" 15 || true

# The worker behind the port, not any socketley: this test reads /proc and a
# reading taken from the wrong process is a number about nothing.
WORKER=""
for p in $(pgrep -x socketley 2>/dev/null); do
    grep -qz "SOCKETLEY_SOCKET=$SOCKETLEY_SOCKET" "/proc/$p/environ" 2>/dev/null || continue
    ss -ltnpH "sport = :$P" 2>/dev/null | grep -q "pid=$p," && { WORKER=$p; break; }
done
if [ -n "$WORKER" ]; then ok; else bad "the worker was found" "none listening on $P"; fi
[ -n "$WORKER" ] || { echo; echo "  $PASS/$TOTAL passed"; exit 1; }

rss_kb() { awk '/VmRSS/{print $2}' "/proc/$1/status" 2>/dev/null || echo 0; }
sleep 1
BEFORE=$(rss_kb "$WORKER")

python3 - "127.0.0.1" "$P" "$CONNS" <<'PY' > /tmp/idlecost.$$ 2>&1 &
import socket, sys, time
host, port, n = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
socks = []
try:
    for _ in range(n):
        s = socket.create_connection((host, port), 10)
        socks.append(s)
except Exception as e:
    print("ERR", e, flush=True)
    sys.exit(1)
print("open", len(socks), flush=True)
time.sleep(60)
PY
HOLDER=$!

for i in $(seq 1 300); do
    grep -q "^open $CONNS" "/tmp/idlecost.$$" 2>/dev/null && break
    sleep 0.1
done
if grep -q "^open $CONNS" "/tmp/idlecost.$$" 2>/dev/null; then ok
else bad "$CONNS connections were opened" "$(head -2 /tmp/idlecost.$$ 2>/dev/null)"; fi

sleep 3
AFTER=$(rss_kb "$WORKER")
PER=$(awk -v a="$BEFORE" -v b="$AFTER" -v n="$CONNS" 'BEGIN{printf "%.2f", (b-a)/n}')
echo "  RSS $(awk -v x=$BEFORE 'BEGIN{printf "%.1f", x/1024}') -> $(awk -v x=$AFTER 'BEGIN{printf "%.1f", x/1024}') MB over $CONNS idle connections = $PER KB each"

UNDER=$(awk -v p="$PER" -v b="$BUDGET_KB" 'BEGIN{print (p > 0 && p < b) ? "yes" : "no"}')
check "each idle connection costs under ${BUDGET_KB} KB" "yes" "$UNDER"

# And the cache is still serving with all of them held, which is the half of
# "cheap" that matters.
REPLY=$(printf '*1\r\n$4\r\nPING\r\n' | timeout 5 nc -q0 127.0.0.1 "$P" 2>/dev/null | tr -d '\r\n' || true)
check "and it still answers with them all held" "+PONG" "$REPLY"

# Braces and a swallowed stderr, because the shell announces a killed job by
# printing the whole command -- heredoc and all -- into the test's output.
{ kill -9 "$HOLDER" 2>/dev/null; wait "$HOLDER"; } 2>/dev/null || true
HOLDER=""
rm -f "/tmp/idlecost.$$"

# ─── the same question of a server ──────────────────────────────────────────
# It carried a SIXTEEN kilobyte read_buf where the cache carried four, and a
# reserve(8192) beside it: 22.21 KB per connection, measured, against 4.92
# after.  If the two runtimes ever drift apart, this is the arm that says so.
create_ok "a server" "$BIN" create server is -p "$P_SRV"
"$BIN" start is >/dev/null 2>&1 || true
ready_tcp 127.0.0.1 "$P_SRV" 15 || true
SWORKER=""
for p in $(pgrep -x socketley 2>/dev/null); do
    grep -qz "SOCKETLEY_SOCKET=$SOCKETLEY_SOCKET" "/proc/$p/environ" 2>/dev/null || continue
    ss -ltnpH "sport = :$P_SRV" 2>/dev/null | grep -q "pid=$p," && { SWORKER=$p; break; }
done
if [ -n "$SWORKER" ]; then ok; else bad "the server's worker was found" "none on $P_SRV"; fi

if [ -n "$SWORKER" ]; then
    sleep 1
    SBEFORE=$(rss_kb "$SWORKER")
    python3 - "127.0.0.1" "$P_SRV" "$CONNS" <<'PYS' > /tmp/idlecost.$$ 2>&1 &
import socket, sys, time
host, port, n = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
socks = []
try:
    for _ in range(n):
        socks.append(socket.create_connection((host, port), 10))
except Exception as e:
    print("ERR", e, flush=True); sys.exit(1)
print("open", len(socks), flush=True)
time.sleep(60)
PYS
    HOLDER=$!
    for i in $(seq 1 300); do grep -q "^open $CONNS" "/tmp/idlecost.$$" 2>/dev/null && break; sleep 0.1; done
    if grep -q "^open $CONNS" "/tmp/idlecost.$$" 2>/dev/null; then ok
    else bad "$CONNS server connections were opened" "$(head -2 /tmp/idlecost.$$ 2>/dev/null)"; fi
    sleep 3
    SAFTER=$(rss_kb "$SWORKER")
    SPER=$(awk -v a="$SBEFORE" -v b="$SAFTER" -v n="$CONNS" 'BEGIN{printf "%.2f", (b-a)/n}')
    echo "  server RSS $(awk -v x=$SBEFORE 'BEGIN{printf "%.1f", x/1024}') -> $(awk -v x=$SAFTER 'BEGIN{printf "%.1f", x/1024}') MB over $CONNS idle = $SPER KB each"
    SUNDER=$(awk -v p="$SPER" -v b="$BUDGET_SRV_KB" 'BEGIN{print (p > 0 && p < b) ? "yes" : "no"}')
    check "each idle server connection costs under ${BUDGET_SRV_KB} KB" "yes" "$SUNDER"
    { kill -9 "$HOLDER" 2>/dev/null; wait "$HOLDER"; } 2>/dev/null || true
    HOLDER=""
    rm -f "/tmp/idlecost.$$"
fi

# ─── and a proxy, which carried the most of the three ───────────────────────
create_ok "a backend" "$BIN" create server ib -p "$P_BE"
"$BIN" start ib >/dev/null 2>&1 || true
create_ok "a proxy"   "$BIN" create proxy ip -p "$P_PRX" --backend "127.0.0.1:$P_BE"
"$BIN" start ip >/dev/null 2>&1 || true
ready_tcp 127.0.0.1 "$P_PRX" 15 || true
PWORKER=""
for p in $(pgrep -x socketley 2>/dev/null); do
    grep -qz "SOCKETLEY_SOCKET=$SOCKETLEY_SOCKET" "/proc/$p/environ" 2>/dev/null || continue
    ss -ltnpH "sport = :$P_PRX" 2>/dev/null | grep -q "pid=$p," && { PWORKER=$p; break; }
done
if [ -n "$PWORKER" ]; then ok; else bad "the proxy's worker was found" "none on $P_PRX"; fi

if [ -n "$PWORKER" ]; then
    sleep 1
    PBEFORE=$(rss_kb "$PWORKER")
    python3 - "127.0.0.1" "$P_PRX" "$CONNS" <<'PYP' > /tmp/idlecost.$$ 2>&1 &
import socket, sys, time
host, port, n = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
socks = []
try:
    for _ in range(n):
        socks.append(socket.create_connection((host, port), 10))
except Exception as e:
    print("ERR", e, flush=True); sys.exit(1)
print("open", len(socks), flush=True)
time.sleep(60)
PYP
    HOLDER=$!
    for i in $(seq 1 300); do grep -q "^open $CONNS" "/tmp/idlecost.$$" 2>/dev/null && break; sleep 0.1; done
    if grep -q "^open $CONNS" "/tmp/idlecost.$$" 2>/dev/null; then ok
    else bad "$CONNS proxy connections were opened" "$(head -2 /tmp/idlecost.$$ 2>/dev/null)"; fi
    sleep 3
    PAFTER=$(rss_kb "$PWORKER")
    PPER=$(awk -v a="$PBEFORE" -v b="$PAFTER" -v n="$CONNS" 'BEGIN{printf "%.2f", (b-a)/n}')
    echo "  proxy  RSS $(awk -v x=$PBEFORE 'BEGIN{printf "%.1f", x/1024}') -> $(awk -v x=$PAFTER 'BEGIN{printf "%.1f", x/1024}') MB over $CONNS idle = $PPER KB each"
    PUNDER=$(awk -v p="$PPER" -v b="$BUDGET_PRX_KB" 'BEGIN{print (p > 0 && p < b) ? "yes" : "no"}')
    check "each idle proxy connection costs under ${BUDGET_PRX_KB} KB" "yes" "$PUNDER"
    { kill -9 "$HOLDER" 2>/dev/null; wait "$HOLDER"; } 2>/dev/null || true
    HOLDER=""
    rm -f "/tmp/idlecost.$$"
fi

echo
echo "  $PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || exit 1
