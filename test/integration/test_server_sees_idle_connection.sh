#!/usr/bin/env bash
# Integration test: a server sees a connection that has not spoken yet
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# setup_tcp_listener set TCP_DEFER_ACCEPT with a one-second timeout, to save
# "the empty-accept + read round-trip on the hot path".  What that option does
# is tell the kernel not to complete a connection until the CLIENT sends data.
# A client that connects and waits is therefore not a connection the server
# has: no accept, no on_connect, no row in any count, nothing to send a
# greeting to.  Measured on Release before the fix, one idle client against a
# --mode inout server:
#
#     t=0.5s   server side SYN-RECV,  ls says CONN=0, client connected
#     t=2.0s   server side ESTAB,     ls says CONN=0
#     t=5.0s                          ls says CONN=1
#
# And the second half is worse than the delay.  A connection still in SYN-RECV
# is a request sock rather than a socket, and when the listener closes the
# kernel drops it SILENTLY -- no FIN, no RST.  The client keeps an ESTABLISHED
# socket against a peer that no longer exists, and nothing on either end sets
# SO_KEEPALIVE, so it keeps it until it next tries to write.  That is how
# test_client_reconnect.sh fails on a Sanitize build, whose wider window let a
# server be removed inside it: four clients reporting a live connection to a
# server that had been deleted, for as long as anyone watched.
#
# The option bought nothing measurable.  Interleaved A/B, five passes each:
# connection rate 17,064/s with against 16,842/s without (0.987x), round trip
# p50 21.36us against 20.78us -- both inside the run-to-run spread.
#
# ─── WHAT THESE ASSERTIONS WOULD CATCH ──────────────────────────────────────
#
# 1 and 2 are the delay: a build that restores the option reports CONN=0 while
# a client sits connected, and its Lua on_connect has not run.  Both are
# checked inside two seconds, which is under the old option's own timeout, so
# they cannot pass by waiting it out.
#
# 3 is the silent drop, and it is the one that cannot be faked: the client
# waits for its own connection to end after the server is removed.  On the old
# build nothing ever arrives and it reports `timeout`.  An assertion on `ls`
# alone would not catch that -- the daemon is perfectly consistent about a
# connection it never had.

set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
# lib_ports.sh opens its lock with `exec 9>`; put stderr back afterwards.
exec 2>&1
daemon_isolate idleconn
PASS=0; FAIL=0; TOTAL=0

HOLD_PID=""
cleanup() { [ -n "$HOLD_PID" ] && kill "$HOLD_PID" 2>/dev/null; daemon_stop; }
trap cleanup EXIT

# Under `set -e` every assertion here is silent when it passes, so a command
# that fails between them ends the file having printed nothing but its title --
# which is what this looked like the first time it happened inside the full
# suite, and standalone it passed on the next two runs.  A death with no line
# number is not something the next reader can act on, so it says which line.
trap 'rc=$?; echo "  ABORTED at line $LINENO (exit $rc): ${BASH_COMMAND}"; exit $rc' ERR

pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

echo "=== Integration: a server sees a connection that has not spoken ==="

daemon_start "$BIN"
P=$((SL_PORT_BASE + 1520))
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"; cleanup' EXIT

conns() { "$BIN" ls 2>/dev/null | awk -v n="$1" '$2==n{print $5}'; }

# on_connect writes a line, so "the server knows" is checked against the script
# it is supposed to be running and not only against a counter the same code
# path maintains.
cat > "$WORK/greet.lua" <<LUA
function on_connect(client_id)
    local f = io.open("$WORK/connected", "a")
    if f then f:write("connect\n"); f:close() end
end
function on_message(msg) end
function on_client_message(client_id, msg) self.send(client_id, msg) end
LUA

# ─── 1. An idle client is a connection, within two seconds ──────────────────
#
# Two and not ten: the option's own timeout was one second, so a deadline much
# past it would be satisfied by the broken build simply waiting, and the
# assertion would be describing the kernel's patience rather than the server.
"$BIN" create server idlesrv -p $((P + 1)) --mode inout --lua "$WORK/greet.lua" -s >/dev/null 2>&1 || true
sleep 1.0

python3 "$HERE/lib_idle_conn.py" hold 127.0.0.1 $((P + 1)) 8 > "$WORK/hold.out" 2>&1 &
HOLD_PID=$!
for _ in $(seq 1 40); do grep -q connected "$WORK/hold.out" 2>/dev/null && break; sleep 0.1; done

if grep -q connected "$WORK/hold.out" 2>/dev/null; then pass
else fail "the client connects at all" "no handshake against port $((P + 1)); nothing below is a result"; fi

# The kernel's own view first, because it is the mechanism and it is not on a
# timer we have to guess at.  With TCP_DEFER_ACCEPT the server end of a silent
# connection sits in SYN-RECV -- a request sock, not a socket -- while the
# client end is ESTABLISHED.  Without it both ends are ESTABLISHED at once.
srv_state() {
    ss -tan 2>/dev/null | awk -v p="$1" '
        { n = split($4, l, ":"); m = split($5, r, ":")
          if (l[n] == p && r[m] != "*") { print $1; exit } }'
}
ST=""
for _ in $(seq 1 10); do        # 10 x 0.1s = 1s, well inside the old 1s deferral
    ST=$(srv_state $((P + 1)))
    [ -n "$ST" ] && break
    sleep 0.1
done
case "$ST" in
    ESTAB) pass ;;
    *)     fail "the server end of a silent connection is established" \
                "the kernel reports '${ST:-no such socket}' on the server side while the client is connected" \
                "SYN-RECV is TCP_DEFER_ACCEPT holding the connection back: it is a request sock," \
                "not a socket, so nothing downstream of accept() exists for it yet" ;;
esac

# And the same thing as the daemon reports it.  Weaker than the check above --
# on a Release build the deferral sometimes resolves inside these two seconds,
# so this one is not reliably red on a build that has the option back.  It is
# here because it is what an operator actually looks at.
SEEN=""
for _ in $(seq 1 20); do        # 20 x 0.1s = 2s
    [ "$(conns idlesrv)" = "1" ] && { SEEN=yes; break; }
    sleep 0.1
done
if [ -n "$SEEN" ]; then pass
else fail "an idle connection is reported within 2s" \
          "ls still says CONN=$(conns idlesrv) for idlesrv while a client sits connected" \
          "TCP_DEFER_ACCEPT holds a silent connection in SYN-RECV, so the server never accepted it"; fi

# ─── 2. on_connect ran ──────────────────────────────────────────────────────
if [ -s "$WORK/connected" ]; then pass
else fail "on_connect fires for an idle connection" \
          "the script's on_connect wrote nothing, so the connection reached no Lua at all"; fi

# `wait ""` is an error, so the pid is used before it is cleared.
kill "$HOLD_PID" 2>/dev/null || true
wait "$HOLD_PID" 2>/dev/null || true
HOLD_PID=""

# ─── 3. Removing the server ends the client's connection ────────────────────
#
# The assertion the counter cannot make.  A connection the server never
# accepted is dropped with the listener and nothing is sent, so the client is
# left ESTABLISHED against nothing -- and with no keepalive anywhere, an idle
# client never finds out.  8s is far past the ~1s a real FIN takes on loopback
# and far short of a keepalive.
"$BIN" create server dropsrv -p $((P + 2)) --mode inout -s >/dev/null 2>&1 || true
sleep 1.0

# The pipeline is guarded rather than left to `set -o pipefail`: a python that
# cannot start would otherwise end the file silently instead of failing this
# assertion, which is the difference between a result and a mystery.
RES=$(python3 "$HERE/lib_idle_conn.py" eof 127.0.0.1 $((P + 2)) 8 "$BIN" remove dropsrv 2>&1 | tail -1) \
    || RES="the probe itself failed"
case "$RES" in
    eof\ *) pass ;;
    *)      fail "removing a server ends an idle client's connection" \
                 "the client got '$RES' instead of an EOF within 8s" \
                 "a request sock dropped with its listener sends neither FIN nor RST," \
                 "so the client holds a dead connection with nothing to notice" ;;
esac

echo
echo "  passed: $PASS / $TOTAL"
[ "$FAIL" -eq 0 ] || exit 1
