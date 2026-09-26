#!/usr/bin/env bash
# Integration test: a worker whose control socket backs up says so once per
# stall, not once per frame it refuses
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# A cache forwards each PUBLISH to the daemon while any other process has a Lua
# script, and a publisher faster than the daemon fills the 4 MiB the frame
# writer allows.  The warning for that was re-armed by the next frame that fit,
# and while the daemon drained a few bytes at a time the next frame always did:
# 2,738 "backlog full" lines in two minutes of the fan-out benchmark, one per
# refusal and about as many as there were refusals.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * the writer never filling, which would make the rest a test of nothing --
#     reported as not asserted, never as a pass
#   * the warning said more than a handful of times for one flood
#   * and every stall it opened being closed by a line naming what it refused
set -euo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1
PASS=0; FAIL=0; TOTAL=0
WORK=$(mktemp -d)
cleanup(){ rm -rf "$WORK"; daemon_stop; }
trap cleanup EXIT
pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; for l in "${@:3}"; do echo "        $l"; done; }
not_asserted(){ TOTAL=$((TOTAL+1)); echo "  NOT ASSERTED [$1]: $2"; }

echo "=== Integration: a backed-up control socket is reported once per stall ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }

P=$((SL_PORT_BASE + 131)); SP=$((P + 1))
daemon_isolate backlogwarn
daemon_start "$BIN"

# Any script in another process is what keeps the cache forwarding.
printf -- '-- present so publishes are forwarded\n' > "$WORK/any.lua"
"$BIN" create server scripted -p "$SP" --lua "$WORK/any.lua" -s >/dev/null 2>&1 || true
"$BIN" create cache pubc -p "$P" -s >/dev/null 2>&1 || true
for _ in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$P " && break; sleep 0.1; done
if ! ss -ltn 2>/dev/null | grep -q ":$P "; then
    echo "  FATAL: the cache never bound $P"; echo "  Results: 0/0 passed (0 failed)"; exit 2
fi
# The daemon tells the worker whether to forward on its health tick.
sleep 1.5

# 400,000 publishes of 200 bytes in one pipelined stream, replies drained as
# they come so the cache never stops reading.
SENT=$(timeout 120 python3 - "$P" <<'PY'
import socket, sys, threading
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
n, line = 400000, b"publish ch " + b"x" * 200 + b"\n"
got = [0]
def drain():
    while got[0] < n:
        b = s.recv(1 << 20)
        if not b: break
        got[0] += b.count(b"\n")
t = threading.Thread(target=drain); t.start()
batch = line * 1000
for _ in range(n // 1000): s.sendall(batch)
t.join(60)
print(got[0])
PY
) || SENT=0
sleep 1

FULL=$(grep -c 'frame writer: backlog full' "$SOCKETLEY_DLOG" 2>/dev/null || true)
DRAINED=$(grep -c 'backlog drained;' "$SOCKETLEY_DLOG" 2>/dev/null || true)
echo "  $SENT of 400000 publishes answered; 'backlog full' said $FULL time(s), 'drained' $DRAINED"

if [ "${FULL:-0}" -gt 0 ]; then
    # ── 1. once per stall, and a flood is a few stalls at most ─────────────
    if [ "$FULL" -le 5 ]; then pass
    else fail "the warning is said once per stall" "$FULL lines for one flood" \
              "-- re-armed by each frame that fit rather than by the backlog draining"; fi
    # ── 2. and each stall is closed by the count of what it refused ────────
    if [ "$DRAINED" -ge $(( FULL - 1 )) ] && [ "$DRAINED" -le "$FULL" ]; then pass
    else fail "each stall ends with what it refused" "$FULL stalls, $DRAINED drained lines"; fi
else
    not_asserted "the control socket backed up" "no refusal in $SENT publishes, so nothing here was tested"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
