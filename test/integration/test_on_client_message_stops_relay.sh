#!/usr/bin/env bash
# Integration test: on_client_message returning true stops the relay, without
# an empty on_message beside it.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
# Only on_message took a message over from the relay.  A script that answered
# in on_client_message -- the callback that knows who spoke -- still had the
# line relayed to every other client, so the manual told authors to define an
# empty on_message as well.  That empty function cost a second Lua call per
# message: a pipelined echo ran 1.45 M/s with it against 1.55 M/s without.
#
# Defining on_client_message cannot itself be the signal: a script that
# answers there AND wants the relay exists (test_relay_into_resp_reply.sh's
# answers PING and relays every line), so the handler says it by returning
# true, which no existing handler returns.
#
# ─── THE ASSERTIONS ────────────────────────────────────────────────────────
#
# Two clients of an inout server whose on_client_message answers and returns
# true: the speaker gets the answer and the other client gets nothing.  The
# control is the same handler without the return: there the relay must still
# reach the other client, because that is what every existing script of that
# shape gets -- and without the control, a build that stopped relaying for any
# defined on_client_message would pass.  The master's own message in master
# mode is relayed by a branch of its own, so it is asserted separately.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: on_client_message returning true takes a message over from the relay ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

P1=$((SL_PORT_BASE+1855))
P2=$((SL_PORT_BASE+1856))
P3=$((SL_PORT_BASE+1857))

daemon_isolate ocmrelay
trap 'daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

cat > "$SOCKETLEY_TMPD/answers.lua" <<'LUAEOF'
function on_client_message(id, msg)
    self.send(id, "re:" .. msg)
    return true
end
LUAEOF
cat > "$SOCKETLEY_TMPD/relays.lua" <<'LUAEOF'
function on_client_message(id, msg)
    self.send(id, "re:" .. msg)
end
LUAEOF

"$BIN" create server ocm1 -p "$P1" --lua "$SOCKETLEY_TMPD/answers.lua" -s >/dev/null 2>&1
"$BIN" create server ocm2 -p "$P2" --lua "$SOCKETLEY_TMPD/relays.lua" -s >/dev/null 2>&1
"$BIN" create server ocm3 -p "$P3" --mode master --master-pw pw \
    --lua "$SOCKETLEY_TMPD/answers.lua" -s >/dev/null 2>&1
sleep 1.5

pair() {
    python3 -c "
import socket, time
a = socket.create_connection(('127.0.0.1', $1)); a.settimeout(0.6)
b = socket.create_connection(('127.0.0.1', $1)); b.settimeout(0.6)
time.sleep(0.3)
if $2:
    a.sendall(b'master pw\n'); time.sleep(0.3); a.recv(65536)
a.sendall(b'hi\n'); time.sleep(0.4)
def drain(s):
    got = b''
    while True:
        try:
            d = s.recv(65536)
            if not d: return got
            got += d
        except Exception: return got
print('A ' + drain(a).decode().replace('\n', '|'))
print('B ' + drain(b).decode().replace('\n', '|'))
" 2>/dev/null
}

OUT=$(pair "$P1" False)
A=$(printf '%s\n' "$OUT" | sed -n 's/^A //p')
B=$(printf '%s\n' "$OUT" | sed -n 's/^B //p')
if [ "$A" = "re:hi|" ]; then
    ok "the speaker got the script's answer"
else
    bad "on_client_message answers the speaker" "the speaker received '${A:-<nothing>}', wanted 're:hi|'"
fi
if [ -z "$B" ]; then
    ok "and nobody else heard the line"
else
    bad "on_client_message returning true stops the relay" \
        "the other client received '$B', wanted nothing;" \
        "'hi|' is the defect -- only on_message took a message over"
fi

OUT=$(pair "$P2" False)
B=$(printf '%s\n' "$OUT" | sed -n 's/^B //p')
if [ "$B" = "hi|" ]; then
    ok "the same handler without 'return true' still has the line relayed (control)"
else
    bad "a handler that does not return true keeps the relay" \
        "the other client received '${B:-<nothing>}', wanted 'hi|'"
fi

OUT=$(pair "$P3" True)
B=$(printf '%s\n' "$OUT" | sed -n 's/^B //p')
if [ -z "$B" ]; then
    ok "and the master's own message is not relayed either"
else
    bad "return true stops the master's relay" "the other client received '$B', wanted nothing"
fi

for r in ocm1 ocm2 ocm3; do "$BIN" stop $r >/dev/null 2>&1; "$BIN" remove $r >/dev/null 2>&1; done
daemon_stop
trap - EXIT

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
