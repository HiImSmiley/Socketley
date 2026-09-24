#!/usr/bin/env bash
# Integration test: what one connection can make the cache hold
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# The cache bounds what it owes ONE connection at 8 MiB and closes a client that
# stops draining, and it caps the reply buffer of a pipelined batch at 1 MiB.
# Both were written and neither bound, because the batch loop did not stop when
# the connection was marked closing: flush_responses() returns true for a closing
# connection -- a skip its callers read as success -- so the cap called a flush
# that did nothing and cleared nothing, and the rest of the batch was still parsed
# and still answered into a buffer that was never drained.
#
# Measured before the stop, one connection asking for a 256 KiB value and reading
# none of it:
#
#     64 pipelined GET      16 MB asked for     +17 MB resident
#    512 pipelined GET     128 MB asked for    +141 MB
#  4,096 pipelined GET       1 GB asked for  +1,063 MB
#
# A GET is about thirty bytes, so that is roughly 8,700 to one, bounded by nothing
# but how many commands fit in one read.  After: 11 MB at every size.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a client that asks for far more than the bound and reads nothing must not
#     move the worker past it.  A build without the stop reports about the whole
#     amount asked for, which is what this file exists for
#   * and it is still closed, because that was the right answer all along and
#     only the cost of reaching it was wrong
#   * a client that pipelines the same batch and DOES read gets every byte, which
#     is the assertion that stops the bound being "answer less"
set -euo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1
daemon_isolate cachepipe
PASS=0; FAIL=0; TOTAL=0
WORK=$(mktemp -d)
cleanup(){ rm -rf "$WORK"; daemon_stop; }
trap cleanup EXIT
pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; for l in "${@:3}"; do echo "        $l"; done; }

echo "=== Integration: one connection cannot make the cache hold what it asked for ==="

VAL=262144
N=512
ASKED=$(( VAL * N / 1048576 ))      # MB
daemon_start "$BIN"
P=$((SL_PORT_BASE + 1700))
"$BIN" create cache cp -p $((P+1)) -s >/dev/null 2>&1 || true
for i in $(seq 1 150); do ss -ltn 2>/dev/null | grep -q ":$((P+1)) " && break; sleep 0.1; done
if ! ss -ltn 2>/dev/null | grep -q ":$((P+1)) "; then
    echo "  FATAL: the cache never bound its port"; echo "  Results: 0/0 passed (0 failed)"; exit 2
fi
WORKER=$(ss -ltnp 2>/dev/null | awk -v p=":$((P+1))" '$4 ~ p"$" {
    if (match($0, /pid=[0-9]+/)) print substr($0, RSTART+4, RLENGTH-4) }' | head -1)
[ -z "${WORKER:-}" ] && { echo "  FATAL: no pid for the listener"; echo "  Results: 0/0 passed (0 failed)"; exit 2; }
rss(){ awk '/^VmRSS/{print $2}' "/proc/$WORKER/status" 2>/dev/null || echo 0; }

# The value, through stdin: past 128 KB an argument is more than execve takes and
# the shell refuses to run redis-cli at all, which reads as the cache storing
# nothing.
if ! head -c "$VAL" /dev/zero | tr '\0' 'v' | redis-cli -p $((P+1)) -x set big >/dev/null 2>&1; then
    echo "  SKIP: redis-cli not usable here"; echo "  Results: 0/0 passed (0 failed)"; exit 0
fi
if [ "$(redis-cli -p $((P+1)) strlen big 2>/dev/null)" != "$VAL" ]; then
    echo "  FATAL: the value did not store"; echo "  Results: 0/0 passed (0 failed)"; exit 2
fi

cat > "$WORK/greedy.py" <<'PY'
# Asks N times and reads nothing, then holds the socket while the caller samples.
import socket, sys, time
port, n, hold = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3])
s = socket.create_connection(("127.0.0.1", port), 5)
s.sendall(b"*2\r\n$3\r\nGET\r\n$3\r\nbig\r\n" * n)
time.sleep(hold)
s.close()
PY

BASE=$(rss)
python3 "$WORK/greedy.py" $((P+1)) "$N" 3 >/dev/null 2>&1 &
GP=$!
PEAK=$BASE
for _ in $(seq 1 40); do sleep 0.1; r=$(rss); [ "${r:-0}" -gt "$PEAK" ] && PEAK=$r; done
wait "$GP" 2>/dev/null || true
ADDED=$(( (PEAK - BASE) / 1024 ))
ALLOW=$(( ASKED / 4 ))

# ── 1. the memory does not follow what was asked for ────────────────────────
if [ "$ADDED" -lt "$ALLOW" ]; then
    echo "  $N pipelined GETs asked for $ASKED MB and added $ADDED MB"
    pass
else fail "asking for $ASKED MB does not cost $ASKED MB" \
          "the worker added $ADDED MB, against an allowance of $ALLOW MB" \
          "-- a build whose batch loop does not stop on a closing connection" \
          "answers the whole batch into a buffer no flush will ever drain, and" \
          "reports about the full amount asked for"; fi

# ── 2. and the client is still closed ───────────────────────────────────────
# `timeout` around it and not redis-cli's own -t, which this version does not
# have: it answers "Unrecognized option" and the assertion then tests the flag
# rather than the cache.  It read as the runtime being wedged by one client.
if [ "$(timeout 5 redis-cli -p $((P+1)) ping 2>/dev/null)" = "PONG" ]; then pass
else fail "the cache still serves everyone else" \
          "PING after the greedy client did not answer PONG -- dropping that one" \
          "connection is right, and taking the runtime with it is not"; fi

# ── 2b. the same through the text protocol ──────────────────────────────────
# Its line loop had no 1 MiB flush at all, so one read of `get big` lines was
# answered in full before the write-queue bound was ever consulted.
cat > "$WORK/greedy_text.py" <<'PY'
import socket, sys, time
port, n, hold = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3])
s = socket.create_connection(("127.0.0.1", port), 5)
s.sendall(b"get big\n" * n)
time.sleep(hold)
s.close()
PY
BASE=$(rss)
python3 "$WORK/greedy_text.py" $((P+1)) "$N" 3 >/dev/null 2>&1 &
GP=$!
PEAK=$BASE
for _ in $(seq 1 40); do sleep 0.1; r=$(rss); [ "${r:-0}" -gt "$PEAK" ] && PEAK=$r; done
wait "$GP" 2>/dev/null || true
ADDED=$(( (PEAK - BASE) / 1024 ))
if [ "$ADDED" -lt "$ALLOW" ]; then
    echo "  $N pipelined text gets asked for $ASKED MB and added $ADDED MB"
    pass
else fail "the text protocol is bounded the same way" \
          "the worker added $ADDED MB for $ASKED MB asked, against $ALLOW MB" \
          "-- a line loop with no mid-batch flush answers the whole read first"; fi

# ── 3. a client that pipelines AND reads gets every byte ────────────────────
cat > "$WORK/polite.py" <<'PY'
import socket, sys
port, n, val = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
s = socket.create_connection(("127.0.0.1", port), 5); s.settimeout(30)
s.sendall(b"*2\r\n$3\r\nGET\r\n$3\r\nbig\r\n" * n)
want = (len(b"$%d\r\n" % val) + val + 2) * n
got = 0
while got < want:
    b = s.recv(1 << 20)
    if not b: break
    got += len(b)
s.close()
print(got)
PY
# Sixteen, not sixty-four: a batch's replies are built before the loop returns to
# the ring, so nothing drains while it runs and the whole batch has to fit inside
# the 8 MiB the connection is allowed to owe.  Sixty-four of these is 16 MB and is
# closed at the bound -- reading or not, on this build and on the one before it.
# That is the runtime's rule and this asserts the side of it that must work.
GOT=$(timeout 60 python3 "$WORK/polite.py" $((P+1)) 16 "$VAL" 2>/dev/null || echo 0)
WANT=$(( (${#VAL} + 3 + VAL + 2) * 16 ))
if [ "${GOT:-0}" -eq "$WANT" ]; then pass
else fail "a pipelined batch that fits the bound is answered in full" \
          "read $GOT bytes of $WANT for 16 pipelined GETs of $VAL" \
          "-- bounding memory must not turn into answering less"; fi

# ── 4. and one that does not fit is closed rather than half-answered ────────
GOT2=$(timeout 60 python3 "$WORK/polite.py" $((P+1)) 64 "$VAL" 2>/dev/null || echo 0)
WANT2=$(( (${#VAL} + 3 + VAL + 2) * 64 ))
if [ "${GOT2:-0}" -lt "$WANT2" ] && [ "$(timeout 5 redis-cli -p $((P+1)) ping 2>/dev/null)" = "PONG" ]; then
    echo "  a 64-deep batch of $VAL-byte values is cut at $GOT2 of $WANT2 bytes, and the cache stays up"
    pass
else fail "a batch larger than the bound is closed, not buffered" \
          "read $GOT2 of $WANT2 and ping said '$(timeout 5 redis-cli -p $((P+1)) ping 2>/dev/null)'" \
          "-- the rule is that one connection may owe 8 MiB, and a batch is built" \
          "before the loop returns to the ring, so a batch has to fit inside it"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" = 0 ] || exit 1
