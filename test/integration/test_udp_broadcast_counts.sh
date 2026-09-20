#!/usr/bin/env bash
# Integration test: what self.broadcast() answers on a UDP server.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
# self.broadcast() ANSWERED (0, 0) ON EVERY UDP SERVER, ALWAYS.  The UDP arm of
# broadcast() called udp_broadcast() and returned a default-constructed
# fanout_count, with a comment saying a datagram has no queue to fall behind
# in.  The kernel disagrees: the socket send buffer is that queue, and
# sendto(..., MSG_DONTWAIT, ...) answers EAGAIN or ENOBUFS when it is full and
# EMSGSIZE for a payload over 65507 bytes.  Every one of those return values
# was discarded.
#
# So the worst case was a broadcast that reached NOBODY -- 70 KB in one
# datagram is the easy way there -- reported to the script as exactly what a
# delivered one is reported as, with no log line anywhere.  A script that
# checks its fan-out, which is the reason the two numbers are returned at all,
# could not tell the two apart.
#
# ─── THE ASSERTIONS ────────────────────────────────────────────────────────
#
# Two peers and a payload that fits: taken must be 2.  The same two peers and
# 70,000 bytes: taken must be 0 and backlogged 2, because the datagram was
# refused for each of them.  One case alone would not do -- a fix that
# returned the peer count without asking the socket passes the first and fails
# the second, and a fix that reported everything as lost passes the second.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: self.broadcast() on a UDP server ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

PS=$((SL_PORT_BASE+1438))

daemon_isolate udpbcastcounts
trap 'daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

SCRIPT="$SOCKETLEY_TMPD/bcast.lua"
cat > "$SCRIPT" <<'LUAEOF'
-- on_message is defined, so the runtime's own fan-out is skipped and every
-- datagram that leaves here is one this script asked for.
function on_message(msg)
    if msg == "go" then
        local t, b = self.broadcast("small")
        socketley.log("UBC small taken=" .. tostring(t) .. " backlogged=" .. tostring(b))
    elseif msg == "big" then
        local t, b = self.broadcast(string.rep("x", 70000))
        socketley.log("UBC big taken=" .. tostring(t) .. " backlogged=" .. tostring(b))
    end
end
LUAEOF

"$BIN" create server ubc -p "$PS" --udp --lua "$SCRIPT" -s >/dev/null 2>&1
sleep 1.5

# Two peers, and the second is the one that asks for the fan-out, so the table
# holds both by the time the broadcast runs.
python3 -c "
import socket, time
a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); a.bind(('127.0.0.1', 0))
b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); b.bind(('127.0.0.1', 0))
a.sendto(b'hello\n', ('127.0.0.1', $PS)); time.sleep(0.4)
b.sendto(b'go\n',    ('127.0.0.1', $PS)); time.sleep(0.6)
b.sendto(b'big\n',   ('127.0.0.1', $PS)); time.sleep(0.6)
a.close(); b.close()" 2>/dev/null
sleep 1

PEERS=$("$BIN" stats ubc 2>/dev/null | awk -F: '$1=="connections"{print $2;exit}')
if [ "${PEERS:-0}" -eq 2 ]; then
    ok "both peers are in the table when the fan-out runs ($PEERS)"
else
    bad "the fixture puts two peers on the server" \
        "the table holds ${PEERS:-<none>}; the counts below are about a different number"
fi

SMALL=$(grep -o 'UBC small taken=[0-9-]* backlogged=[0-9-]*' "$SOCKETLEY_DLOG" | tail -1) || true
if [ "$SMALL" = "UBC small taken=2 backlogged=0" ]; then
    ok "a datagram that fits is counted for every peer it reached ($SMALL)"
else
    bad "self.broadcast() reports what a UDP fan-out reached" \
        "the script was told '${SMALL:-<no line>}', wanted taken=2 backlogged=0;" \
        "taken=0 backlogged=0 is the defect -- the UDP arm returned a default" \
        "fanout_count and threw away what sendto said, for every peer"
fi

BIG=$(grep -o 'UBC big taken=[0-9-]* backlogged=[0-9-]*' "$SOCKETLEY_DLOG" | tail -1) || true
if [ "$BIG" = "UBC big taken=0 backlogged=2" ]; then
    ok "and one no peer can receive is counted as reaching nobody ($BIG)"
else
    bad "a datagram over 65507 bytes is reported as lost" \
        "the script was told '${BIG:-<no line>}', wanted taken=0 backlogged=2;" \
        "taken=0 backlogged=0 is what a delivered broadcast used to answer too," \
        "which is the whole defect: the two cases were indistinguishable"
fi

"$BIN" stop ubc >/dev/null 2>&1; "$BIN" remove ubc >/dev/null 2>&1
daemon_stop
trap - EXIT

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
