#!/usr/bin/env bash
# Integration test: the shared shard table across a shard's LIFETIME.
#
# test_shard_lua_aggregate.sh proves the sum is right while four shards sit
# still.  This file is about the two moments when the set of shards changes,
# because that is where a shared table goes wrong silently rather than loudly.
#
# ─── WHY THESE TWO AND NOT OTHERS ───────────────────────────────────────────
#
# A slot holds whatever its shard last wrote.  That is the whole point — it is
# what makes a read wait-free, and it is what lets a reader answer while a
# sibling is descheduled.  It is also the hazard: a shard that stops writing
# does not write a zero on its way out, so its last figure is summed forever by
# everyone else.  Two things stop a shard writing:
#
#   it dies      SIGKILL, a crash, an OOM.  Nothing runs in it afterwards, so
#                nothing it could have been taught would help.  The replacement
#                has to clear the slot when it takes it, and that is the only
#                place the clearing can live.
#
#   it is retired  --shards 4 -> 2.  Here the daemon knows, and the daemon is
#                who has to say so.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   sum is 0 after      This is the one that matters, and what it catches was
#   the kill            established by breaking the tree rather than by
#                       reasoning about it.
#
#                       It catches a build that does not keep the shared region
#                       ACROSS A RESTART -- one where the supervisor hands the
#                       region to its first child and not to the replacement.
#                       Measured, with proxy_supervisor::spawn() dropping the
#                       descriptor after the fork: 0-9 with every connection
#                       closed, and 9-40 afterwards, because the dead shard's
#                       last figure of 9 sits in the table forever while the
#                       replacement, mapping nothing, answers with its own nine
#                       clients against its siblings' forty.  Both ends of the
#                       range are needed to see it -- the max catches the stale
#                       figure, the min catches the shard that fell out of the
#                       aggregation.
#
#                       It does NOT catch a missing clear in shard_table::adopt().
#                       Also measured, with that store commented out: 20 of 20
#                       still passed.  The replacement publishes its own count
#                       at the end of its first turn, microseconds after it
#                       starts, so the stale figure is overwritten long before
#                       any window here opens.  The clear is still right -- it
#                       closes the gap between adopt() and that first turn, and
#                       it is the only place a dead shard's slot CAN be cleared
#                       by the process taking it -- but this file is not what
#                       proves it.  test_shard_stats.cpp is: it publishes, exits
#                       the writer, and re-adopts with no loop running at all.
#
#   sum is 40 again     The replacement rejoined the AGGREGATION, not merely the
#   afterwards          port.  A restarted shard that binds and serves but never
#                       adopts its slot is invisible to `ls`, invisible to
#                       `stats` -- which reads the control socket, not the table
#                       -- and shows up only here, as a script that reports 30
#                       of 40.  Which is why the number is asserted and not
#                       "did it answer".
#
#   four workers again  Asserted separately, because assertion two passes
#                       without it: with three shards alive the kernel gives all
#                       40 connections to those three and the sum is still 40.
#                       The pair together are what says four processes are
#                       serving and all four agree on the total.
#
#   2 shards, then 4    A shrink must stop the retired shards being counted, and
#                       a grow must bring the new ones in.  A build that reuses
#                       a stale region across the edit reports 80 for 40
#                       connections -- the old shards' figures plus the new
#                       ones'.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

PASS=0; FAIL=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
check(){ [[ "$2" == "$3" ]] && ok "$1 ($2)" || bad "$1: expected '$3', got '$2'"; }

daemon_isolate shardlife
daemon_start "$BIN"

P_PROXY=$((SL_PORT_BASE+740))
P_BACK=$((SL_PORT_BASE+741))

WORK=$(mktemp -d)
OUT="$WORK/reported.log"
trap 'cleanup' EXIT
cleanup() {
    [[ -n "${HOLD_PID:-}" ]] && kill -9 "$HOLD_PID" 2>/dev/null
    [[ -n "${BACK_PID:-}" ]] && kill -9 "$BACK_PID" 2>/dev/null
    "$BIN" stop  shl >/dev/null 2>&1 || true
    sleep 0.2
    "$BIN" remove shl >/dev/null 2>&1 || true
    rm -rf "$WORK"
    daemon_stop
}

cat > "$WORK/back.py" <<'PY'
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
python3 "$WORK/back.py" "$P_BACK" & BACK_PID=$!

# Each connection is proved live -- a byte out and the echo back -- before the
# holder reports ready.  connect() returning only means a SYN was accepted; a
# connection that has echoed has certainly been accept()ed by a shard and
# counted by it, which is the difference between measuring this and racing it.
cat > "$WORK/hold.py" <<'PY'
import socket, sys, time
port = int(sys.argv[1]); n = int(sys.argv[2]); ready = sys.argv[3]
socks = []
for _ in range(n):
    s = socket.create_connection(('127.0.0.1', port), timeout=5)
    s.sendall(b'x')
    if s.recv(16) != b'x':
        raise SystemExit("backend did not echo")
    socks.append(s)
open(ready, 'w').write('ok')
while True:
    time.sleep(3600)
PY

cat > "$WORK/agg.lua" <<LUA
local out = "$OUT"
socketley.set_interval(100, function()
    local f = io.open(out, "a")
    if f then
        f:write(tostring(self.connections()) .. "\n")
        f:close()
    end
end)
LUA

# Every worker of THIS run's daemon.  Never \`pgrep -f\`: -f matches the whole
# command line, so it also matches the shell that merely carries the string in
# its own arguments -- including the one doing the matching.
shard_pids() {
    for p in $(pgrep -x socketley 2>/dev/null); do
        [[ "$(readlink /proc/$p/exe 2>/dev/null)" == "$BIN" ]] || continue
        grep -qz "SOCKETLEY_SOCKET=$SOCKETLEY_SOCKET" "/proc/$p/environ" 2>/dev/null || continue
        tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q 'proxy-worker' && echo "$p"
    done
}
shard_count() { shard_pids | wc -l; }

# Wait for a condition with a bound, and say so if the bound runs out.  A test
# that sleeps a fixed amount either wastes the difference or fails on a loaded
# box; a test that waits forever hangs the suite.
wait_for_shards() {
    local want=$1 tries=${2:-100}
    for _ in $(seq 1 "$tries"); do
        [[ "$(shard_count)" == "$want" ]] && return 0
        sleep 0.2
    done
    return 1
}

# What every shard reported in a fresh window.  Both ends of the range: "some
# shard once said 40" is not the claim -- the claim is that every shard says 40,
# and the lowest is what falsifies it.
open_window() { : > "$OUT"; sleep 0.6; }
w_max() { sort -n "$OUT" | tail -1; }
w_min() { sort -n "$OUT" | head -1; }

start_holder() {
    local n=$1
    rm -f "$WORK/ready"
    python3 "$WORK/hold.py" "$P_PROXY" "$n" "$WORK/ready" & HOLD_PID=$!
    for _ in $(seq 1 100); do [[ -s "$WORK/ready" ]] && return 0; sleep 0.1; done
    return 1
}
stop_holder() {
    [[ -n "${HOLD_PID:-}" ]] && kill -9 "$HOLD_PID" 2>/dev/null
    HOLD_PID=
    sleep 0.6
}

N=40

echo "== four shards, forty clients =="
"$BIN" create proxy shl -p $P_PROXY --backend 127.0.0.1:$P_BACK \
       --protocol tcp --lua "$WORK/agg.lua" --shards 4 >/dev/null 2>&1
check "a sharded scripted proxy is accepted" "$?" "0"
"$BIN" start shl >/dev/null 2>&1
wait_for_shards 4 && ok "four worker processes" || bad "four workers: got $(shard_count)"

start_holder $N && ok "$N connections open and echoing" || bad "holder never came up"
open_window
check "every shard reports the whole runtime" "$(w_min)-$(w_max)" "$N-$N"

echo "== a shard is killed, and everything closes =="
VICTIM=$(shard_pids | head -1)
[[ -n "$VICTIM" ]] && ok "a shard to kill: $VICTIM" || bad "no worker to kill"
kill -9 "$VICTIM" 2>/dev/null
stop_holder

# The replacement has to be up before the window is read, or a table that is
# never going to be cleared is indistinguishable from one that has not been
# cleared yet.
wait_for_shards 4 && ok "the dead shard was replaced" \
                  || bad "replacement: $(shard_count) workers, wanted 4"

# The live shards may still be closing the holder's connections, which settles; a dead shard's figure never does.
for _ in $(seq 1 16); do
    open_window
    [ "$(w_min)-$(w_max)" = "0-0" ] && break
done
echo "  observed: shards reported between $(w_min) and $(w_max) with nothing connected"
check "a dead shard's last figure is not summed forever" "$(w_min)-$(w_max)" "0-0"

echo "== and the replacement rejoined the aggregation =="
start_holder $N && ok "$N connections open again" || bad "holder never came up"
open_window
echo "  observed: shards reported between $(w_min) and $(w_max) for $N connections"
check "four shards agree on the total again" "$(w_min)-$(w_max)" "$N-$N"
check "still four worker processes"          "$(shard_count)"    "4"

echo "== shrink to two, and grow back to four =="
out=$("$BIN" edit shl --shards 2 2>&1); rc=$?
check "the shard count cannot be edited while running" "$rc" "1"
[[ "$out" == *"while running"* ]] && ok "and it says why" || bad "reason: $out"

stop_holder
"$BIN" stop shl >/dev/null 2>&1
wait_for_shards 0 && ok "stopping took every shard down" || bad "left $(shard_count) workers"

"$BIN" edit shl --shards 2 >/dev/null 2>&1
check "the shard count is editable once stopped" "$?" "0"
"$BIN" start shl >/dev/null 2>&1
wait_for_shards 2 && ok "two worker processes" || bad "two workers: got $(shard_count)"

start_holder $N && ok "$N connections open on two shards" || bad "holder never came up"
open_window
echo "  observed: two shards reported between $(w_min) and $(w_max) for $N connections"
check "two shards report the runtime, not four slots' worth" "$(w_min)-$(w_max)" "$N-$N"

stop_holder
"$BIN" stop shl >/dev/null 2>&1
wait_for_shards 0 >/dev/null
"$BIN" edit shl --shards 4 >/dev/null 2>&1
"$BIN" start shl >/dev/null 2>&1
wait_for_shards 4 && ok "grown back to four worker processes" || bad "got $(shard_count)"

start_holder $N && ok "$N connections open on four shards again" || bad "holder never came up"
open_window
echo "  observed: four shards reported between $(w_min) and $(w_max) for $N connections"
check "and four shards report the runtime" "$(w_min)-$(w_max)" "$N-$N"

echo
echo "shard aggregate lifecycle: PASS=$PASS FAIL=$FAIL"
[[ $FAIL -eq 0 ]]
