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
# The server's total_messages is the instrument, because a Lua script cannot
# write a file here: the sandbox opens base, package, table, string and math,
# and io is shut.  It counts non-empty datagrams, which is what makes case B
# readable -- the empty one is not in the total either way, so the number is
# about what came AFTER it.
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

for n in ucc_a ucs_a ucc_b ucs_b; do
    "$BIN" stop "$n" >/dev/null 2>&1; "$BIN" remove "$n" >/dev/null 2>&1
done
daemon_stop
trap - EXIT

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
