#!/usr/bin/env bash
# Integration test: --upstream on a UDP server.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
# --upstream WAS ACCEPTED ON A UDP SERVER AND NOTHING EVER DIALLED IT.  setup()
# has two exits, and the UDP one returns several hundred lines before the loop
# that turns m_upstream_targets into m_upstreams.  So the flag parsed, `show`
# reported it, the target sat in the vector for the life of the runtime, and no
# connection was ever attempted -- while `stats` printed
#
#     upstreams:0/1
#
# for ever, which reads as an upstream that is down and was an upstream nobody
# had ever tried to reach.  That is the same defect --idle-timeout had at the
# same return, found the same way and fixed the same way; test_udp_peer_table.sh
# describes that one in its own head comment.
#
# ─── WHY IT IS WIRED AND NOT REFUSED ───────────────────────────────────────
#
# An upstream is a TCP socket this runtime DIALS.  It has nothing to do with
# the family its own listener was configured in: handle_upstream_read feeds
# on_upstream and nothing else, and upstream_send writes to a socket the
# listener never touches.  The pairing that IS refused -- --udp with
# --mode master -- is refused because master reads a prefix off an
# authenticated connection and a datagram has none, so there is nothing to make
# work.  Here there is, and it works unchanged.
#
# ─── THE ASSERTIONS ────────────────────────────────────────────────────────
#
# `upstreams:1/1` on its own would pass against a fix that built the struct and
# dialled nothing, so the second assertion is the upstream process reading the
# bytes the UDP datagram turned into.  And the TCP server beside it is the
# control: without it, "the upstream received nothing" is also what a broken
# fixture looks like.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: --upstream on a UDP server ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

PU=$((SL_PORT_BASE+1434))    # where the upstream listens
PS=$((SL_PORT_BASE+1435))    # the UDP server under test
PT=$((SL_PORT_BASE+1436))    # the TCP control

daemon_isolate udpupstream
trap 'kill ${UP_PID:-0} 2>/dev/null; daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

# The upstream: a plain TCP listener that writes everything it is told into a
# file, so what is asserted is bytes off the wire and not a runtime's opinion.
SEEN="$SOCKETLEY_TMPD/upstream.txt"
: > "$SEEN"
python3 -c "
import socket, threading
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', $PU)); srv.listen(8)
def serve(c):
    with open('$SEEN', 'ab', buffering=0) as f:
        while True:
            b = c.recv(4096)
            if not b: break
            f.write(b)
    c.close()
while True:
    c, _ = srv.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
" >/dev/null 2>&1 &
UP_PID=$!
sleep 0.8

RELAY="$SOCKETLEY_TMPD/relay.lua"
cat > "$RELAY" <<'LUAEOF'
function on_message(msg)
    self.upstream_broadcast("relay:" .. msg)
end
LUAEOF

"$BIN" create server udpup -p "$PS" --udp --upstream "127.0.0.1:$PU" --lua "$RELAY" -s >/dev/null 2>&1
"$BIN" create server tcpup -p "$PT"        --upstream "127.0.0.1:$PU" --lua "$RELAY" -s >/dev/null 2>&1
sleep 2

ups_of() { "$BIN" stats "$1" 2>/dev/null | awk -F: '$1=="upstreams"{print $2;exit}'; }

CTRL=$(ups_of tcpup)
if [ "${CTRL:-}" = "1/1" ]; then
    ok "the control TCP server reached the same upstream (${CTRL})"
else
    bad "the fixture's upstream is reachable at all" \
        "a TCP server with the same --upstream reads upstreams:${CTRL:-<none>};" \
        "nothing below would mean anything"
fi

GOT=$(ups_of udpup)
if [ "${GOT:-}" = "1/1" ]; then
    ok "a UDP server dials its --upstream (${GOT})"
else
    bad "--upstream is acted on by a UDP server" \
        "stats reads upstreams:${GOT:-<none>};" \
        "0/1 is the UDP exit in setup() returning before the loop that dials them --" \
        "the target was parsed, stored, reported by \`show\`, and never connected to"
fi

# And the leg carries traffic, which a struct that was built and never dialled
# cannot fake.
python3 -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b'from-a-datagram\n', ('127.0.0.1', $PS)); time.sleep(0.5); s.close()" 2>/dev/null
sleep 1

if grep -q "relay:from-a-datagram" "$SEEN" 2>/dev/null; then
    ok "and a datagram it received reaches that upstream"
else
    bad "the upstream leg of a UDP server carries traffic" \
        "the upstream process read $(wc -c < "$SEEN") byte(s) and none of them said" \
        "relay:from-a-datagram; self.upstream_broadcast() had no upstream to broadcast to"
fi

for n in udpup tcpup; do
    "$BIN" stop "$n" >/dev/null 2>&1; "$BIN" remove "$n" >/dev/null 2>&1
done
kill "$UP_PID" 2>/dev/null; wait "$UP_PID" 2>/dev/null
daemon_stop
trap - EXIT

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
