#!/usr/bin/env bash
# Integration test: a UDP server's peer table has a way out.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
# A UDP peer was entered on its first datagram and removed by exactly one
# thing: teardown.  There was no last-seen, nothing read ICMP, and
# MAX_UDP_PEERS was a wall rather than a bound -- at ten thousand addresses
# every datagram from a NEW sender was dropped before process_message, without
# a log line or a counter, until the runtime stopped.  Every restart of every
# UDP client brings a fresh ephemeral port, so ten thousand restarts get there
# on their own; before that, each broadcast pays a blocking sendto per entry to
# addresses that are mostly gone, and `ps` reports them all as connections.
#
# ─── AND THE LARGER HALF, FOUND WHILE FIXING IT ────────────────────────────
#
# --idle-timeout was INERT on a UDP server.  setup() arms the idle sweep near
# its end, and the UDP path returns several hundred lines earlier, so the flag
# was accepted, `show` reported it, and no sweep was ever armed to act on it.
# That is why the peer table had no way out even in principle: the one timer
# that could have emptied it never ran.  Measured with a log line in the sweep
# body: not one tick in 36 seconds on a UDP server, while a TCP server beside
# it closed its idle connection on schedule.
#
# ─── AND A THIRD PEER, SAYING NOTHING ──────────────────────────────────────
#
# handle_udp_read tested `res <= 0` and returned before find_or_add_peer, so a
# zero-length datagram never entered its sender in the table and never
# refreshed one already there.  0 is an end of stream on TCP and a legitimate
# datagram on UDP, and the client had to learn that twice -- in handle_read and
# again in handle_write.
#
# The assertion is the peer COUNT, which for a UDP runtime is what
# get_connection_count() returns and what `stats` prints, so it is the table
# itself being read and not a proxy for it.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: the UDP peer table forgets ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

PS=$((SL_PORT_BASE+1420))
PK=$((SL_PORT_BASE+1421))
PE=$((SL_PORT_BASE+1422))

daemon_isolate udppeertable
trap 'kill ${KEEPER_PID:-0} ${EKEEPER_PID:-0} 2>/dev/null; daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

# Two seconds, so "idle" is reached long before the sweep's own 30-second tick
# and the wait below is about the sweep running at all.
"$BIN" create server upt -p "$PS" --udp --idle-timeout 2 -s >/dev/null 2>&1
"$BIN" create server upk -p "$PK" --udp --idle-timeout 2 -s >/dev/null 2>&1
"$BIN" create server upe -p "$PE" --udp --idle-timeout 2 -s >/dev/null 2>&1
sleep 1.5

peers() { "$BIN" stats "$1" 2>/dev/null | awk -F: '$1=="connections"{print $2;exit}'; }

# Paced: a burst of two hundred datagrams at once overruns the receive buffer
# and the table then holds whatever survived, which is a measurement of the
# socket and not of this code.
python3 -c "
import socket, time
for i in range(200):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('127.0.0.1', 0))
    s.sendto(b'hello\n', ('127.0.0.1', $PS)); time.sleep(0.004); s.close()
time.sleep(0.5)" 2>/dev/null

ENTERED=$(peers upt)
if [ "${ENTERED:-0}" -ge 150 ]; then
    ok "200 senders entered the table ($ENTERED of 200 datagrams survived the socket)"
else
    bad "the senders reach the server at all" \
        "the table holds ${ENTERED:-<none>} after 200 paced datagrams;" \
        "nothing below would mean anything"
fi

# One peer that keeps talking, on its own runtime so the two questions -- does
# a silent peer go, does a live one stay -- cannot be confused for each other.
python3 -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('127.0.0.1', 0))
end = time.time() + 50
while time.time() < end:
    s.sendto(b'alive\n', ('127.0.0.1', $PK)); time.sleep(0.5)
s.close()" >/dev/null 2>&1 &
KEEPER_PID=$!

# And the same peer again, saying nothing at all.  A zero-length datagram is a
# message its sender sent: it cost a syscall, it crossed the wire, and it is
# the whole of some protocols' keepalive.  handle_udp_read tested `res <= 0`
# and returned before find_or_add_peer, so a peer whose traffic was empty
# datagrams was forgotten on schedule while it was still talking -- out of the
# fan-out and out of the count `ps` prints.  The CLIENT had to learn this
# exact lesson twice, in handle_read and in handle_write, and 0 is an end of
# stream on TCP but a legitimate datagram on UDP.
python3 -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('127.0.0.1', 0))
end = time.time() + 50
while time.time() < end:
    s.sendto(b'', ('127.0.0.1', $PE)); time.sleep(0.5)
s.close()" >/dev/null 2>&1 &
EKEEPER_PID=$!

sleep 1
KEPT_BEFORE=$(peers upk)
EKEPT_BEFORE=$(peers upe)

# One tick of the sweep, with room for the tick that lands after it.
sleep 36

LEFT=$(peers upt)
KEPT=$(peers upk)
EKEPT=$(peers upe)

if [ "${LEFT:-1}" -eq 0 ]; then
    ok "every silent peer was forgotten ($ENTERED -> $LEFT)"
else
    bad "a UDP peer idle past --idle-timeout is forgotten" \
        "the table still holds ${LEFT:-<none>} of $ENTERED after 36 s with --idle-timeout 2;" \
        "unchanged is the defect: a peer was entered on its first datagram and removed" \
        "only by teardown -- and on a UDP server the idle sweep was never armed at all," \
        "because setup() returns on the UDP path before it reaches the arm"
fi

if [ "${KEPT:-0}" -ge 1 ]; then
    ok "and a peer that keeps sending is kept ($KEPT_BEFORE -> $KEPT)"
else
    bad "the sweep forgets the silent and keeps the talking" \
        "the still-sending peer's table went ${KEPT_BEFORE:-<none>} -> ${KEPT:-<none>};" \
        "0 means last_seen is not being refreshed on arrival, which would drop every" \
        "peer of a busy server every thirty seconds"
fi

if [ "${EKEPT:-0}" -ge 1 ]; then
    ok "and a peer whose datagrams are empty is kept too ($EKEPT_BEFORE -> $EKEPT)"
else
    bad "an empty datagram refreshes last_seen like any other" \
        "the peer sending nothing but zero-length datagrams went ${EKEPT_BEFORE:-<none>} ->" \
        "${EKEPT:-<none>} while the one sending 'alive' went ${KEPT_BEFORE:-<none>} ->" \
        "${KEPT:-<none>}; 0 -> 0 is handle_udp_read returning on \`res <= 0\` before it" \
        "ever reaches find_or_add_peer, so such a peer is neither entered nor refreshed" \
        "-- it is invisible to the fan-out and to \`ps\` while it is still talking"
fi

# And the server is not deaf afterwards: a forgotten peer is one that comes
# back on its next datagram, which is the whole point of forgetting it.
python3 -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('127.0.0.1', 0))
s.sendto(b'again\n', ('127.0.0.1', $PS)); time.sleep(0.5); s.close()" 2>/dev/null
sleep 0.5
BACK=$(peers upt)
if [ "${BACK:-0}" -ge 1 ]; then
    ok "a new datagram enters its sender again ($BACK)"
else
    bad "forgetting a peer does not make the server deaf to it" \
        "the table holds ${BACK:-<none>} after a fresh datagram"
fi

kill "$KEEPER_PID" "$EKEEPER_PID" 2>/dev/null
wait "$KEEPER_PID" "$EKEEPER_PID" 2>/dev/null
for n in upt upk upe; do
    "$BIN" stop "$n" >/dev/null 2>&1; "$BIN" remove "$n" >/dev/null 2>&1
done
daemon_stop
trap - EXIT

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
