#!/usr/bin/env bash
# Integration test: what a UDP client's self.send() actually delivers.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
#   EVERY SEND AFTER THE FIRST, INSIDE ONE CALLBACK, WAS DROPPED -- and
#   answered true.  The TCP arm of lua_send() queues when a write is in flight;
#   the UDP arm called a void send_to_server() that returned silently on
#   write_pending.  No completion can arrive while a callback is running, so
#   "a second message in the same callback" is the ordinary case, not the
#   exception: a script sending ten lines from on_connect delivered one, and
#   the script saw ten trues.
#
#   AN EMPTY DATAGRAM CLOSED THE CLIENT'S OWN SOCKET.  handle_read() and
#   handle_write() tested `res <= 0` before branching on m_udp, and 0 is an end
#   of stream on TCP but a legitimate zero-length datagram on UDP.  So
#   self.send("") disconnected the sender, and a peer -- or a server's own
#   broadcast("") -- disconnected every UDP client that received one.
#
# The server's total_messages is the instrument because it is the SERVER's own
# count, and what these cases assert is delivery rather than what the script
# did with it.  It counts non-empty datagrams, which is what makes case B
# readable -- the empty one is not in the total either way, so the number is
# about what came AFTER it.
#
#   AND BOTH BYTE COUNTERS WERE DEAD.  See case C: bytes_in and bytes_out were
#   never touched on the UDP path at either end, so a UDP server reported 0 and
#   0 for its whole life while total_messages climbed beside them.
#
# (An earlier version of this comment said a Lua script cannot write a file
# here.  That is the DAEMON CONFIG loader, which opens base, package, table,
# string and math; a runtime script gets io and package too, and
# lua_context's constructor says as much: "This is not a sandbox and says so".
# Verified by writing a file from on_client_message.)
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: a UDP client's sends ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

PA=$((SL_PORT_BASE+1404))
PB=$((SL_PORT_BASE+1405))
PC=$((SL_PORT_BASE+1406))

daemon_isolate udpclientsends
trap 'daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

stat_of() { "$BIN" stats "$1" 2>/dev/null | awk -F: -v k="$2" '$1 == k { print $2; exit }'; }

# ── A. Ten sends from one callback ─────────────────────────────────────────
TEN="$SOCKETLEY_TMPD/ten.lua"
cat > "$TEN" <<'LUAEOF'
function on_connect()
    for i = 1, 10 do self.send("m" .. i) end
end
LUAEOF
"$BIN" create server ucs_a -p "$PA" --udp -s >/dev/null 2>&1
sleep 1.2
"$BIN" create client ucc_a --udp -t "127.0.0.1:$PA" --lua "$TEN" -s >/dev/null 2>&1
sleep 2

GOT_A=$(stat_of ucs_a total_messages)
if [ "${GOT_A:-0}" -eq 10 ]; then
    ok "ten sends from one callback all arrive ($GOT_A of 10)"
else
    bad "every send inside a callback is delivered" \
        "the server counted ${GOT_A:-<none>} of 10;" \
        "1 is the UDP arm having no queue: no completion can arrive while the" \
        "callback runs, so everything after the first was dropped -- and" \
        "self.send() answered true for each of them"
fi

# ── B. An empty datagram is a message, not a hang-up ───────────────────────
EMPTY="$SOCKETLEY_TMPD/empty.lua"
cat > "$EMPTY" <<'LUAEOF'
function on_connect()
    self.send("")
    self.send("a1")
    self.send("a2")
    self.send("a3")
end
LUAEOF
"$BIN" create server ucs_b -p "$PB" --udp -s >/dev/null 2>&1
sleep 1.2
"$BIN" create client ucc_b --udp -t "127.0.0.1:$PB" --lua "$EMPTY" -s >/dev/null 2>&1
sleep 2

GOT_B=$(stat_of ucs_b total_messages)
CST=$("$BIN" ls 2>/dev/null | awk '$2 == "ucc_b" { print $7; exit }')
if [ "${GOT_B:-0}" -eq 3 ] && [ "$CST" = "Up" ]; then
    ok "an empty datagram is sent and the three behind it still arrive ($GOT_B of 3, client $CST)"
else
    bad "self.send(\"\") does not disconnect the sender" \
        "the server counted ${GOT_B:-<none>} of 3 and the client reads '${CST:-<none>}';" \
        "0 is the write completion for a zero-length datagram reporting 0 bytes and" \
        "being read as an end of stream, which ran drop_connection on a healthy socket"
fi

# ── C. What the two byte counters on a UDP server say ──────────────────────
# bytes_in and bytes_out were never touched on the UDP path, at either end:
# handle_udp_read counted the message and not the bytes, and both sendto call
# sites dropped the return value.  So a UDP server reported bytes_in:0 and
# bytes_out:0 for its whole life while total_messages climbed beside them --
# two dead fields in a block that reads as live, feeding `stats`, the
# Prometheus endpoint, the JSON and the daemon-wide totals.  The TCP arm counts
# in three places and the CLIENT counts for UDP, which is what makes this an
# omission rather than a decision.
#
# Exact numbers, because "greater than zero" would pass against a counter wired
# to the wrong end.  Five datagrams of `payload-NN\n`: eleven bytes each on the
# way in, and the echo is the message with its newline stripped, so ten each on
# the way out.
"$BIN" create server ucs_c -p "$PC" --udp --send-to sender -s >/dev/null 2>&1
sleep 1.2

ECHOED=$(python3 -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1.0); s.bind(('127.0.0.1', 0))
got = 0
for i in range(5):
    s.sendto(('payload-%02d' % i).encode() + b'\n', ('127.0.0.1', $PC))
    try:
        s.recv(2048); got += 1
    except socket.timeout:
        pass
print(got); s.close()" 2>/dev/null)
sleep 0.8

IN_C=$(stat_of ucs_c bytes_in)
OUT_C=$(stat_of ucs_c bytes_out)
if [ "${IN_C:-0}" -eq 55 ] && [ "${OUT_C:-0}" -eq 50 ] && [ "${ECHOED:-0}" -eq 5 ]; then
    ok "a UDP server counts both directions (bytes_in:$IN_C bytes_out:$OUT_C, $ECHOED echoes)"
else
    bad "bytes_in and bytes_out are answered on a UDP server" \
        "stats reads bytes_in:${IN_C:-<none>} of 55 and bytes_out:${OUT_C:-<none>} of 50," \
        "with ${ECHOED:-<none>} of 5 echoes actually received;" \
        "0 and 0 with five echoes is the defect -- the datagrams moved and nothing counted them"
fi

for n in ucc_a ucs_a ucc_b ucs_b ucs_c; do
    "$BIN" stop "$n" >/dev/null 2>&1; "$BIN" remove "$n" >/dev/null 2>&1
done
daemon_stop
trap - EXIT

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
