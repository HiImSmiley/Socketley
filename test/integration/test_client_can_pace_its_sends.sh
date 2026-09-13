#!/usr/bin/env bash
# Integration test: a client runtime can see and survive its own backlog.
#
# ─── WHAT THE CLIENT ALREADY HAD, AND WHAT IT SAID ──────────────────────────
#
# The client is in better shape than the server was: lua_send() already answers
# false at the hard bound, and it already logs the stall once. So the "reported
# success for a dropped message" defect does not exist here.
#
# What it got wrong was the REASON. Every refusal came back as one sentence:
#
#     "<name> is not connected to its server, or was created --mode in and
#      does not send"
#
# For a client whose server simply stopped reading, all three of those are
# false. The connection is up, the mode is fine, and the only true thing --
# that 8 MiB are queued -- was not among the options. Same defect as the
# server's "there is no open connection": a name for the symptom that points
# at the wrong cause, and the two causes want opposite responses.
#
# And self.pending() did not exist on the client at all, so a producer could
# not pace. The runtime had been reading the 4 MiB watermark internally at two
# sites since long before -- lowering a report latch on the way back down --
# so the crossing was already detected. Only nobody was told.
#
# ─── WHY THE SERVER'S MECHANISM WAS NOT COPIED ──────────────────────────────
#
# It needed no queue of pending ids: a client has ONE connection, so there is
# nothing to disambiguate. self.pending() takes no argument and on_writable()
# receives none it has to use. The two existing crossing sites set a flag and
# on_loop_turn() makes the call, off the write path's stack -- the same
# reasoning the server's dispatch gives at length.
#
# ─── TWO THINGS THE HARNESS GOT WRONG FIRST ─────────────────────────────────
#
# Both are recorded because both read as runtime defects and neither was.
#
# SO_RCVBUF=2048 on the peer, against 64 KB writes, produced a TCP window in
# which the transfer stopped moving at all: the queue drained 2.6 MB and then
# sat at 5,838,489 bytes for as long as the test ran, with the peer reading.
#
# And a fixed `sleep 6` after the peer starts reading is short of the drain, so
# the callback read as missing. Adding an on_tick made it pass, which looked
# like the dispatch depending on a loop turn from elsewhere -- it does not; the
# same script with no tick fires once given the time.
#
# ─── THE HARNESS ────────────────────────────────────────────────────────────
#
# The peer here is a plain python listener, not a socketley server: a server
# always has a read armed, so it cannot be made to stop reading. The listener
# accepts, sets a small receive buffer, and reads nothing until told to.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate clientpace

P=$((SL_PORT_BASE+1956))
NAMES="cp_cli"
LUA="$SOCKETLEY_TMPD/cp.lua"
GO="$SOCKETLEY_TMPD/drain_now"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "expected '$2', got '$3'"; fi; }

LPID=""
cleanup() {
    # Waited for as well as killed, so bash does not print its own "Killed"
    # notice into the suite's output after the results line.
    if [ -n "$LPID" ]; then
        { kill -9 "$LPID" && wait "$LPID"; } 2>/dev/null || true
    fi
    for n in $NAMES; do "$BIN" stop "$n"   >/dev/null 2>&1 || true; done
    sleep 0.3
    for n in $NAMES; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

# ─── A peer that accepts and does not read until a file appears ─────────────
# Written to a file and then started, rather than a heredoc on a backgrounded
# command: bash does not treat `<<'EOF' &` as a heredoc, and the body lands in
# the script's own output instead of in python.
cat > "$SOCKETLEY_TMPD/peer.py" <<'PYEOF'
import os, socket, sys, time
port, go = int(sys.argv[1]), sys.argv[2]
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port)); srv.listen(8)
c, _ = srv.accept()
# The receive buffer is left alone, deliberately.  Setting it to 2048 against
# 64 KB writes was the first draft, and it produced a TCP window in which the
# transfer stopped moving altogether: the queue drained 2.6 MB and then sat at
# 5,838,489 bytes for as long as the test ran, with the peer reading.  It read
# as a stall in the runtime and it was the harness.
# The kernel's own buffers absorb a couple of megabytes; 400 x 64 KB is 26 MB,
# so the 8 MiB queue fills regardless.
# Not one byte is read while this loop runs: that is the whole point.
while not os.path.exists(go):
    time.sleep(0.05)
c.settimeout(5)
total = 0
end = time.time() + 30
while time.time() < end:
    try:
        b = c.recv(1 << 18)
        if not b: break
        total += len(b)
    except socket.timeout:
        break
print("LISTENER_DRAINED=%d" % total, flush=True)
PYEOF
python3 "$SOCKETLEY_TMPD/peer.py" "$P" "$GO" > "$SOCKETLEY_TMPD/listener.out" 2>&1 &
LPID=$!

# Bound before the client is created, and checked with ss rather than by
# connecting: this peer accepts exactly one connection and `nc -z` would spend it.
#
# Without the wait this file failed about one run in six, and the reason is worth
# writing down because it is not the test's alone.  python needs a moment to bind;
# the client's non-blocking connect answers EINPROGRESS and client_instance.cpp
# falls straight through to its `connected:` label, so on_connect fires and the
# script queues its 8 MB flood on a socket whose connect has not finished.  When
# that connect is then refused, the armed write completes ECONNREFUSED and the
# connection goes with everything queued on it -- `stats` read connections:0 and
# the daemon log said nothing at all until the WARN this commit adds.  Waiting
# here removes the race; on_connect firing before a connect completes is a
# separate thing and is named in the message.
for _ in $(seq 1 200); do
    ss -ltn 2>/dev/null | grep -q ":$P " && break
    sleep 0.05
done

cat > "$LUA" <<'LUAEOF'
local CHUNK = string.rep("z", 65536)
local sent, refused, first, fired = 0, 0, nil, 0

-- The flood, from on_connect: the peer is not reading, so this is certain to
-- reach the bound however fast the machine is.
function on_connect()
    socketley.log("CP start watermark=" .. tostring(self.watermark())
        .. " pending=" .. tostring(self.pending()))
    for _ = 1, 400 do
        local okay, why = self.send(CHUNK)
        if okay then sent = sent + 1
        else
            refused = refused + 1
            if not first then first = tostring(why) end
        end
    end
    socketley.log("CP flood sent=" .. sent .. " refused=" .. refused
        .. " pending=" .. tostring(self.pending())
        .. " why=[" .. tostring(first) .. "]")
end

-- The resume half: the peer starts reading, the queue crosses back under the
-- watermark, and this is where a paced producer would carry on.
function on_writable()
    fired = fired + 1
    if fired == 1 then
        socketley.log("CP writable fired pending=" .. tostring(self.pending()))
    end
end

LUAEOF

echo "=== Integration: a client sees its own backlog ==="
daemon_start "$BIN"

create_ok "a scripted client" "$BIN" create client cp_cli \
    -t "127.0.0.1:$P" --lua "$LUA" -s
sleep 3

L0=$(grep -o 'CP start .*' "$SOCKETLEY_DLOG" | tail -1) || true
L1=$(grep -o 'CP flood .*' "$SOCKETLEY_DLOG" | tail -1) || true
g() { printf '%s\n' "$2" | sed -n "s/.* $1=\([^ ]*\).*/\1/p"; }

# ─── 1. The field is there and is the runtime's own number ──────────────────
if [ -n "$L0" ]; then ok; else
    bad "the client script ran at all" "no 'CP start' line -- nothing below measures anything"; fi
check "self.watermark is the runtime's watermark" "4194304" "$(g watermark "$L0")"
check "and pending is zero before sending"        "0"       "$(g pending "$L0")"

# ─── 2. The flood is refused, and named ─────────────────────────────────────
REF=$(g refused "$L1")
if [ "${REF:-0}" -gt 0 ]; then ok; else
    bad "a send that cannot go is refused" \
        "refused=$REF of 400 against a peer that reads nothing"; fi

SENT=$(g sent "$L1")
if [ "${SENT:-0}" -gt 0 ] && [ "${SENT:-0}" -lt 400 ]; then ok; else
    bad "and the ones that went still answered true" \
        "sent=$SENT of 400; 400 means nothing was reported, 0 means everything is refused"; fi

# The assertion this file exists for: which of the four reasons it was. The old
# sentence claims the connection is down or the mode is wrong, and neither is
# true of a connected --mode out client whose peer stopped reading.
case "$L1" in
    *"more queued for its server than it could take"*) ok ;;
    *"is not connected to its server"*)
        bad "the refusal names the backlog and not the connection" \
            "it said 'is not connected to its server, or was created --mode in'," \
            "which is three false statements about a connected client" ;;
    *) bad "the refusal names the backlog" "why=[$(g why "$L1")]" ;;
esac

# ─── 3. And the number a producer would pace on ─────────────────────────────
PEND=$(g pending "$L1")
if [ "${PEND:-0}" -gt 1000000 ]; then ok; else
    bad "self.pending reports what is owed" \
        "pending=$PEND after 400 x 64 KB into a peer that read nothing"; fi

# ─── 4. The peer starts reading; the crossing is reported ───────────────────
# Waited for, not slept for. A fixed `sleep 6` here reported the callback as
# missing, and adding an on_tick to the script "fixed" it -- which read as the
# dispatch needing a loop turn from somewhere else. It does not: the same run
# with no tick and a longer wait fires normally. The tick was making the drain
# finish sooner, and six seconds was simply short of it.
touch "$GO"
W=""
for _ in $(seq 1 80); do
    W=$(grep -o 'CP writable .*' "$SOCKETLEY_DLOG" | tail -1) || true
    [ -n "$W" ] && break
    sleep 0.5
done
if [ -n "$W" ]; then ok; else
    bad "on_writable fires when the queue drains" \
        "no 'CP writable' line after the peer began reading -- the crossing is" \
        "detected at two sites in the write path and nobody was told"; fi

# Below the watermark at the moment of the call, which is the contract: the
# call means there is room, not merely that something was written.
WP=$(g pending "$W")
if [ -n "$WP" ] && [ "$WP" -lt 4194304 ] 2>/dev/null; then ok; else
    bad "and it means there is room" "pending=$WP at the call, watermark is 4194304"; fi

# ─── 5. The runtime is still there ──────────────────────────────────────────
# A client that tore itself down would satisfy several assertions above.
check "the client is still running" "Up" \
      "$("$BIN" ps -a 2>/dev/null | awk '$2=="cp_cli" { print $7 }')"

echo "  measured: start=[$L0]"
echo "            flood=[$L1]"
echo "            drain=[${W:-<none>}]"
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || { cat "$SOCKETLEY_TMPD/listener.out" 2>/dev/null | sed 's/^/    peer: /'; echo "  FAILED"; }
[ "$FAIL" -eq 0 ]
