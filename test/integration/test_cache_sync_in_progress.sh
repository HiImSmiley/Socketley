#!/usr/bin/env bash
# ─── WHAT WENT WRONG ────────────────────────────────────────────────────────
#
# A follower's link was reported "up" from the moment the read was armed, which
# is before the leader has sent a single byte of the dump.  Between those two
# points the follower is connected and answering out of a dataset that is on
# its way to being replaced -- and since a full sync now begins by clearing
# that dataset, the wrong answer during the window is "no such key" rather than
# a stale value.  Nothing in `info` or `stats` separated that from a follower
# in sync.
#
# ─── WHAT IS ASSERTED ───────────────────────────────────────────────────────
#
# The window is microseconds against a real leader, so it is held open here by
# a leader that accepts the connection and then says nothing -- which is also
# the case where it never closes on its own.  Paired against a real pair, so a
# build that reported "syncing" forever would fail rather than pass twice.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate sync_progress
PASS=0; FAIL=0; TOTAL=0

STALL_PID=""
cleanup() {
    [ -n "$STALL_PID" ] && kill -9 "$STALL_PID" 2>/dev/null
    "$BIN" stop  sync_stalled sync_leader sync_live >/dev/null 2>&1 || true
    "$BIN" remove sync_stalled >/dev/null 2>&1 || true
    "$BIN" remove sync_leader  >/dev/null 2>&1 || true
    "$BIN" remove sync_live    >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}
send_to() { echo "$2" | nc -q 1 127.0.0.1 "$1" 2>/dev/null | tr -d '\r'; }
field()   { grep -m1 "^$2" <<<"$1" | tr -d '\r' || true; }

echo "=== Integration: a follower says whether it is synced, not just connected ==="

daemon_start "$BIN"
P=$((SL_PORT_BASE + 910))
STALL_PORT=$((P + 0))
LEADER_PORT=$((P + 1))

# ─── A leader that accepts and then says nothing ────────────────────────────
#
# It has to hold the connection rather than close it: a close is a link drop,
# which the follower already reported correctly.  What was never reported is a
# connection that stands with no dump behind it.
python3 -c "
import socket, sys, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $STALL_PORT)); s.listen(8)
sys.stderr.write('ready\n'); sys.stderr.flush()
held = []
while True:
    c, _ = s.accept(); held.append(c)
" 2>/dev/null &
STALL_PID=$!
disown "$STALL_PID" 2>/dev/null || true

READY=""
for _ in $(seq 1 40); do
    ss -ltn 2>/dev/null | grep -q ":$STALL_PORT " && { READY=yes; break; }
    sleep 0.25
done
if [ "$READY" = yes ]; then pass
else fail "the stalled leader is listening" "nothing bound :$STALL_PORT after 10s"; fi

RC=0
timeout 20 "$BIN" create cache sync_stalled -p $((P + 10)) \
    --replicate "127.0.0.1:$STALL_PORT" -s >/dev/null 2>&1 || RC=$?
if [ "$RC" -eq 0 ]; then pass
else fail "a follower of a silent leader still comes up" "create exited $RC"; fi
sleep 1.5

INFO_STALLED=$(send_to $((P + 10)) 'info')
if grep -q "role:slave" <<<"$INFO_STALLED"; then pass
else fail "the stalled follower knows it is a follower" \
          "got: $(field "$INFO_STALLED" role)"; fi

# The connection did stand -- without this, everything below would also pass on
# a build where the dial simply failed, which is a different bug entirely.
if [ "$("$BIN" stats sync_stalled 2>/dev/null | grep -m1 '^master_link:' | cut -d: -f2)" = "1" ]; then pass
else fail "the socket to the silent leader is open" \
          "got: $("$BIN" stats sync_stalled 2>/dev/null | grep -m1 '^master_link:' || echo '<no line>')"; fi

if grep -q "master_sync_in_progress:1" <<<"$INFO_STALLED"; then pass
else fail "a connected follower with no dump behind it says so" \
          "got: $(field "$INFO_STALLED" master_sync_in_progress)"; fi

if grep -q "master_link_status:down" <<<"$INFO_STALLED"; then pass
else fail "and does not call that link standing" \
          "got: $(field "$INFO_STALLED" master_link_status)"; fi

if [ "$("$BIN" stats sync_stalled 2>/dev/null | grep -m1 '^master_sync_in_progress:' | cut -d: -f2)" = "1" ]; then pass
else fail "stats says it too, for a caller that is not speaking the dialect" \
          "got: $("$BIN" stats sync_stalled 2>/dev/null | grep -m1 '^master_sync_in_progress:' || echo '<no line>')"; fi

# ─── The same three questions on a pair that really is synced ───────────────
#
# A build that answered "syncing" unconditionally would have passed every
# assertion above.
create_rc=0
timeout 20 "$BIN" create cache sync_leader -p "$LEADER_PORT" -s >/dev/null 2>&1 || create_rc=$?
sleep 0.6
send_to "$LEADER_PORT" 'set synckey syncval' >/dev/null
timeout 20 "$BIN" create cache sync_live -p $((P + 11)) \
    --replicate "127.0.0.1:$LEADER_PORT" -s >/dev/null 2>&1 || create_rc=$?
if [ "$create_rc" -eq 0 ]; then pass
else fail "the real pair is created" "a create exited $create_rc"; fi

GOT=""
for _ in $(seq 1 10); do
    GOT=$(send_to $((P + 11)) 'get synckey')
    [ "$GOT" = "syncval" ] && break
    sleep 0.5
done
if [ "$GOT" = "syncval" ]; then pass
else fail "the real follower took the dump" "got: '$GOT'"; fi

INFO_LIVE=$(send_to $((P + 11)) 'info')
if grep -q "master_sync_in_progress:0" <<<"$INFO_LIVE"; then pass
else fail "a synced follower reports no sync in progress" \
          "got: $(field "$INFO_LIVE" master_sync_in_progress)"; fi
if grep -q "master_link_status:up" <<<"$INFO_LIVE"; then pass
else fail "and calls its link standing" \
          "got: $(field "$INFO_LIVE" master_link_status)"; fi

# A leader is not a follower and must not grow either field: they would read as
# "0" and be taken for an answer rather than for silence.
INFO_LEADER=$(send_to "$LEADER_PORT" 'info')
if ! grep -q "master_sync_in_progress" <<<"$INFO_LEADER"; then pass
else fail "a leader does not answer a follower's question" \
          "got: $(field "$INFO_LEADER" master_sync_in_progress)"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
