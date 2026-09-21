#!/usr/bin/env bash
# Integration test: upstreams:N/M counts upstreams, not dial attempts
#
# ─── WHAT THIS REPLACES ─────────────────────────────────────────────────────
# upstream_try_connect() set `connected` and fired on_upstream_connect one line
# after a NON-BLOCKING connect(), which answers EINPROGRESS whenever the target
# is not already there.  So both the number an operator reads and the callback
# a script receives were claims about a far end that had not been heard from.
#
# Measured against a port nobody held, sampled once a second for thirty:
#   before   ?11111111111111111111111110000   -- 25 of 30 said "connected"
#   after    ?00000000000000000000000000000   --  0 of 30
# The ones were not one long lie but a short one repeating: each dial set the
# flag, the refusal cleared it, the backoff re-dialled.  Early on the backoff
# is one or two seconds, so a sampler mostly catches the flag up; only once it
# reaches sixteen does the gap grow wide enough to fall into.
#
# ─── WHY BOTH ARMS ARE HERE ─────────────────────────────────────────────────
# A fix that reports 0 for everything passes the dead half on its own.  The
# live half is what makes the dead half mean something.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate upstreamreports
PORT=$((SL_PORT_BASE+200)); DEAD=$((SL_PORT_BASE+201)); LIVE=$((SL_PORT_BASE+202))
PASS=0; FAIL=0; TOTAL=0
LISTENER=""

cleanup() {
    "$BIN" stop u_dead 2>/dev/null || true; "$BIN" remove u_dead 2>/dev/null || true
    "$BIN" stop u_live 2>/dev/null || true; "$BIN" remove u_live 2>/dev/null || true
    [ -n "$LISTENER" ] && kill "$LISTENER" 2>/dev/null
    daemon_stop
}
trap cleanup EXIT

ok() {
    TOTAL=$((TOTAL+1))
    if [ "$1" = "$2" ]; then PASS=$((PASS+1)); echo "  PASS: $3"
    else FAIL=$((FAIL+1)); echo "  FAIL [$3]: got '$1', want '$2'"; fi
}

# The number, sampled rather than read once: the defect this file is about
# produced a flag that flickered, and a single read lands wherever it lands.
sample() {   # name, how many seconds
    local out=""
    for _ in $(seq 1 "$2"); do
        out="$out$("$BIN" stats "$1" 2>/dev/null | sed -n 's|^upstreams:\([0-9]*\)/.*|\1|p' | head -1)"
        sleep 1
    done
    echo "$out"
}

# Nothing is listening here, and nothing ever will be.
"$BIN" create server u_dead -p "$PORT" -u "127.0.0.1:$DEAD" >/dev/null
"$BIN" start u_dead >/dev/null

# A listener that accepts and then holds the connection open, so "connected"
# has something true to be about.
python3 -c "
import socket, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $LIVE)); s.listen(8)
while True:
    c, _ = s.accept(); time.sleep(60)
" & LISTENER=$!
for _ in $(seq 1 40); do (exec 3<>/dev/tcp/127.0.0.1/$LIVE) 2>/dev/null && break; sleep 0.2; done

"$BIN" create server u_live -p $((PORT+10)) -u "127.0.0.1:$LIVE" >/dev/null
"$BIN" start u_live >/dev/null

# Ten seconds spans the 1, 2, 4 and 8 second dials, so the flag gets every
# chance the old code gave it to read as up.
DEADS=$(sample u_dead 10)
ok "$(echo "$DEADS" | tr -cd '1' | wc -c)" "0" "a dial to nobody is never counted as an upstream ($DEADS)"

LIVES=$(sample u_live 4)
ok "$(echo "$LIVES" | tr -cd '1' | wc -c)" "4" "a connection that exists is counted every time ($LIVES)"

# The control on the control: the dead one must still SAY it has an upstream
# configured, or "0" would just mean the line vanished.
ok "$("$BIN" stats u_dead 2>/dev/null | grep -c '^upstreams:0/1$')" "1" \
   "the dead one still reports its configured upstream, as 0 of 1"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
