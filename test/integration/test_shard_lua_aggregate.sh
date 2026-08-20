#!/usr/bin/env bash
# Integration test: what a SCRIPT is told about a runtime that is N processes.
#
# ─── THE DEFECT THIS IS ABOUT ───────────────────────────────────────────────
#
# --shards N runs one runtime as N worker processes sharing one listening
# socket.  Every figure a script can ask about was then a figure about ONE of
# those processes, and nothing said so: `self.connections()` on a four-shard
# runtime holding 40 clients answered 9, 10 or 11 — a correct count of the
# wrong thing, with no error, no warning and no way for the script to tell.
#
# This is not hypothetical and it is not new.  proxy + --lua + --shards is a
# configuration this tree ACCEPTS today; the refusal that exists is on a server
# with --lua, and it names this exact failure as its reason.  So the wrong
# answer is reachable on the tip, on a supported configuration, and this file
# is the thing that says which answer is which.
#
# ─── WHY A PROXY AND NOT A SERVER ───────────────────────────────────────────
#
# Because a sharded scripted server cannot be created yet — shards_config_refusal
# refuses it, and lifting that refusal is what this work is FOR.  A proxy is the
# same mechanism with the refusal already absent, so the red is measurable on
# the tip rather than only after the thing being proved has been built.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   the sharded arm    Every shard must report the whole runtime's count.
#                      Broken build: a fraction — measured at 9-11 of 40 on
#                      four shards before this change.  An assertion of "did it
#                      answer at all" cannot tell those apart, so what is
#                      asserted is the NUMBER, and it is asserted against every
#                      shard rather than against the best one: a build where
#                      only the shard the script happened to run in is right is
#                      the build we already had.
#
#   the one-shard arm  The same script, the same clients, --shards 1.  This is
#                      the control, and it is not decorative: it is what
#                      separates "aggregation works" from "the count is now
#                      inflated for everybody".  A build that returned 40 by
#                      summing something four times over passes the arm above
#                      and fails this one.
#
#   after a disconnect The count has to come DOWN as well as up.  A slot that is
#                      published on connect and never again reads 40 forever —
#                      which passes every assertion above it.
#
#   the spread         Recorded, not asserted: the per-shard client counts, to
#                      show the connections really were spread across processes.
#                      If the kernel gave every connection to one shard the two
#                      arms above would agree for a reason that has nothing to
#                      do with the change, and this is what makes that visible.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

PASS=0; FAIL=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
check(){ [[ "$2" == "$3" ]] && ok "$1 ($2)" || bad "$1: expected '$3', got '$2'"; }

daemon_isolate shardagg
daemon_start "$BIN"

P_PROXY=$((SL_PORT_BASE+720))
P_BACK=$((SL_PORT_BASE+721))
P_PROXY1=$((SL_PORT_BASE+722))

WORK=$(mktemp -d)
OUT4="$WORK/shards4.log"
OUT1="$WORK/shards1.log"
HOLDER_PY="$WORK/hold.py"
BACKEND_PY="$WORK/back.py"

cleanup() {
    [[ -n "${HOLD_PID:-}" ]] && kill -9 "$HOLD_PID" 2>/dev/null
    [[ -n "${BACK_PID:-}" ]] && kill -9 "$BACK_PID" 2>/dev/null
    "$BIN" stop  agg4 >/dev/null 2>&1 || true
    "$BIN" stop  agg1 >/dev/null 2>&1 || true
    sleep 0.2
    "$BIN" remove agg4 >/dev/null 2>&1 || true
    "$BIN" remove agg1 >/dev/null 2>&1 || true
    rm -rf "$WORK"
    daemon_stop
}
trap cleanup EXIT

# ── a backend that is not this tree's code and is not the bottleneck ─────────
cat > "$BACKEND_PY" <<'PY'
import socket, selectors, sys
port = int(sys.argv[1])
s = socket.socket(); s.setblocking(False)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', port)); s.listen(1024)
sel = selectors.DefaultSelector(); sel.register(s, selectors.EVENT_READ, None)
while True:
    for key, _ in sel.select():
        if key.data is None:
            try:
                c, _a = s.accept(); c.setblocking(False)
                sel.register(c, selectors.EVENT_READ, True)
            except OSError: pass
        else:
            c = key.fileobj
            try:
                d = c.recv(65536)
                if not d: sel.unregister(c); c.close(); continue
                c.sendall(d)
            except OSError:
                try: sel.unregister(c); c.close()
                except Exception: pass
PY
python3 "$BACKEND_PY" "$P_BACK" & BACK_PID=$!

# ── a holder that opens N connections, PROVES each one is live, and waits ────
#
# Each connection sends a byte and reads the echo back before the holder reports
# ready.  Without that, connect() returning only means the kernel accepted a SYN
# — the proxy may not have accept()ed it yet, and the test would be racing the
# thing it is measuring rather than measuring it.  A connection that has echoed
# has certainly been accepted by a shard and counted by it.
cat > "$HOLDER_PY" <<'PY'
import socket, sys, time, signal
port = int(sys.argv[1]); n = int(sys.argv[2]); ready = sys.argv[3]
socks = []
for i in range(n):
    s = socket.create_connection(('127.0.0.1', port), timeout=5)
    s.sendall(b'x')
    if s.recv(16) != b'x':
        raise SystemExit("backend did not echo")
    socks.append(s)
open(ready, 'w').write('ok')
# Half of them go away on SIGUSR1, so the falling edge can be measured too.
def drop(_sig, _frm):
    for s in socks[: n // 2]:
        try: s.close()
        except Exception: pass
    open(ready, 'w').write('dropped')
signal.signal(signal.SIGUSR1, drop)
while True:
    time.sleep(3600)
PY

# ── the script under test ───────────────────────────────────────────────────
#
# One line per tick per shard, appended.  O_APPEND from several processes is
# atomic for a write this small, which is why N shards may share one file.
mk_script() {
    cat > "$1" <<LUA
local out = "$2"
socketley.set_interval(100, function()
    local f = io.open(out, "a")
    if f then
        f:write(tostring(self.connections()) .. "\n")
        f:close()
    end
end)
LUA
}

SCRIPT4="$WORK/agg4.lua"
SCRIPT1="$WORK/agg1.lua"
mk_script "$SCRIPT4" "$OUT4"
mk_script "$SCRIPT1" "$OUT1"

# The highest and the lowest figure any shard reported in a window.  Both,
# because "some shard once said 40" is not the claim — the claim is that EVERY
# shard says 40, and the lowest is what falsifies it.
window_max() { sort -n "$1" | tail -1; }
window_min() { sort -n "$1" | head -1; }

N=40

echo "== a scripted proxy on four shards =="
"$BIN" create proxy agg4 -p $P_PROXY --backend 127.0.0.1:$P_BACK \
       --protocol tcp --lua "$SCRIPT4" --shards 4 >/dev/null 2>&1
rc=$?
check "sharded scripted proxy is accepted" "$rc" "0"
"$BIN" start agg4 >/dev/null 2>&1
sleep 0.6

READY="$WORK/ready4"
python3 "$HOLDER_PY" "$P_PROXY" "$N" "$READY" & HOLD_PID=$!
for _ in $(seq 1 100); do [[ -s "$READY" ]] && break; sleep 0.1; done
[[ -s "$READY" ]] && ok "$N connections are open and echoing" \
                  || bad "the holder never came up"

# Discard everything written while the connections were still arriving; only a
# window taken after they are all up says anything about the total.
sleep 0.5
: > "$OUT4"
sleep 0.5

M4=$(window_max "$OUT4"); L4=$(window_min "$OUT4")
echo "  observed: four shards reported between $L4 and $M4 for $N connections"
check "the highest any shard reported" "$M4" "$N"
check "the lowest any shard reported"  "$L4" "$N"

# Which shard held what, from the daemon's own per-shard detail.  Recorded and
# not asserted: the kernel decides the spread, and a run where it happened to
# be uneven is not a failure of this change.
echo "  per-shard spread, from the daemon:"
"$BIN" stats agg4 2>/dev/null | sed -n 's/^/    /p' | head -20

echo "== and the falling edge =="
kill -USR1 "$HOLD_PID" 2>/dev/null
sleep 0.6
: > "$OUT4"
sleep 0.5
M4b=$(window_max "$OUT4"); L4b=$(window_min "$OUT4")
echo "  observed: between $L4b and $M4b after half of them closed"
check "the highest after half closed" "$M4b" "$((N/2))"
check "the lowest after half closed"  "$L4b" "$((N/2))"

kill -9 "$HOLD_PID" 2>/dev/null; HOLD_PID=
"$BIN" stop agg4 >/dev/null 2>&1
sleep 0.3
"$BIN" remove agg4 >/dev/null 2>&1

echo "== the control: the same script on ONE shard =="
"$BIN" create proxy agg1 -p $P_PROXY1 --backend 127.0.0.1:$P_BACK \
       --protocol tcp --lua "$SCRIPT1" --shards 1 >/dev/null 2>&1
"$BIN" start agg1 >/dev/null 2>&1
sleep 0.6

READY1="$WORK/ready1"
python3 "$HOLDER_PY" "$P_PROXY1" "$N" "$READY1" & HOLD_PID=$!
for _ in $(seq 1 100); do [[ -s "$READY1" ]] && break; sleep 0.1; done
sleep 0.5
: > "$OUT1"
sleep 0.5

M1=$(window_max "$OUT1"); L1=$(window_min "$OUT1")
echo "  observed: one shard reported between $L1 and $M1 for $N connections"
check "one shard reports exactly the connections it has" "$M1" "$N"
check "and never more"                                   "$L1" "$N"

echo
echo "shard aggregate: PASS=$PASS FAIL=$FAIL"
[[ $FAIL -eq 0 ]]
