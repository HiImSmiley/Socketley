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
TMPDIR_T=$(mktemp -d)
PASS=0; FAIL=0; TOTAL=0

STALL_PID=""
cleanup() {
    [ -n "$STALL_PID" ] && kill -9 "$STALL_PID" 2>/dev/null
    rm -rf "$TMPDIR_T" 2>/dev/null
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
# An offset nothing else in the directory claims, which matters here more than
# elsewhere: the listener below is not a runtime, so daemon_stop does not reap
# it, and a run killed hard enough to skip the trap would leave it holding the
# port for the rest of the suite -- landing on two files that would each read as
# a product defect.  test_ipc_framing, test_proxy_circuit_breaker and
# test_lua_config_parity are what +910 and +920 would have hit.
P=$((SL_PORT_BASE + 1001))
STALL_PORT=$((P + 0))
LEADER_PORT=$((P + 1))

# ─── A leader that accepts and then says nothing ────────────────────────────
#
# It has to hold the connection rather than close it: a close is a link drop,
# which the follower already reported correctly.  What was never reported is a
# connection that stands with no dump behind it.
ACCEPTS="$TMPDIR_T/stall.accepts"
: > "$ACCEPTS"
python3 -c "
import socket, sys, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $STALL_PORT)); s.listen(8)
sys.stderr.write('ready\n'); sys.stderr.flush()
held = []
n = 0
# Its own deadline, because the trap that kills it does not run if this test is
# killed rather than finished, and the port has to come back either way.  The
# assertions below need it for about 35 seconds.
s.settimeout(5)
deadline = time.time() + 180
while time.time() < deadline:
    try:
        c, _ = s.accept()
    except socket.timeout:
        continue
    held.append(c); n += 1
    with open('$ACCEPTS', 'w') as f:
        f.write(str(n) + '\n')
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
# Asked until the leader answers, since a write sent before it listens is lost and shows up only as an empty dump below.
SET=""
for _ in $(seq 1 20); do
    SET=$(send_to "$LEADER_PORT" 'set synckey syncval' || true)
    [ "$SET" = "ok" ] && break
    sleep 0.2
done
if [ "$SET" = "ok" ]; then pass
else fail "the leader takes the write" "got: '$SET'"; fi
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
# The leader's own role line proves the reply arrived, so the absence below is not silence.
if grep -q "^role:master" <<<"$INFO_LEADER" && ! grep -q "master_sync_in_progress" <<<"$INFO_LEADER"; then pass
else fail "a leader does not answer a follower's question" \
          "role: $(field "$INFO_LEADER" role)  got: $(field "$INFO_LEADER" master_sync_in_progress)"; fi

# ─── And it does not wait forever ───────────────────────────────────────────
#
# The link never dropped, so the retry chain never saw it: a follower could sit
# on a standing socket with no dump behind it for as long as the leader kept the
# connection open.  The deadline is 30s of no bytes at all, so a dump that is
# merely slow re-arms it instead of being dropped.
#
# Asserted on the leader's accept count rather than on the follower's link
# state: the window between the drop and the next dial is one second, and a
# poll that has to land inside it is a coin toss.  An accept that happened is
# permanent.
ACC=0
# Ninety seconds for a 30s deadline and a one-second redial, since a loaded box runs the deadline's sweep late.
for _ in $(seq 1 90); do
    ACC=$(cat "$ACCEPTS" 2>/dev/null || echo 0)
    [ "${ACC:-0}" -ge 2 ] && break
    sleep 1
done
if [ "${ACC:-0}" -ge 2 ]; then pass
else fail "a sync that never finishes is given up on and dialled again" \
          "the silent leader was connected to ${ACC:-0} time(s) in 90s, expected at least 2"; fi

# The real follower is not collateral: its deadline fires too, finds itself
# synced, and must do nothing.
if [ "$(send_to $((P + 11)) 'get synckey')" = "syncval" ]; then pass
else fail "the synced follower survived its own deadline" \
          "got: '$(send_to $((P + 11)) 'get synckey')'"; fi
if grep -q "master_link_status:up" <<<"$(send_to $((P + 11)) 'info')"; then pass
else fail "and still calls its link standing afterwards" \
          "got: $(field "$(send_to $((P + 11)) 'info')" master_link_status)"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
