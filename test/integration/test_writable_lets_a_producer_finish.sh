#!/usr/bin/env bash
# Integration test: a paced producer delivers a body bigger than the queue bound.
#
# ─── WHAT WAS MISSING, AND WHERE IT WAS ALREADY PRESENT ─────────────────────
#
# write_queue_backpressure_bytes -- the SOFT 4 MiB watermark -- was read in five
# places in the proxy and two in the client, and in none in the server. The
# proxy uses it to stop reading from the peer while the queue is over it and
# resume under it, which is why a proxy streams without accumulating. The server
# had only the hard 8 MiB cap, which closes the connection: a cliff where its
# two siblings have a slope.
#
# The server cannot copy the proxy's mechanism, because the server's producer is
# a Lua script and a script cannot be paused mid-loop. So it needs the inverse
# -- tell the producer, and call it back:
#
#     self.pending(id)   how much is still owed        (landed previously)
#     self.watermark()   the number to compare against
#     on_writable(id)    the queue came back under it
#
# ─── THE ASSERTION ──────────────────────────────────────────────────────────
#
# 200 x 64 KB is 13 MB, comfortably past the 8 MiB cap, so an unpaced loop
# cannot deliver it however the machine behaves -- the connection is closed
# partway by definition. A paced loop delivers all of it. Measured against a
# client that reads in 256 KB bites with a 5 ms pause, so the producer really
# does outrun it:
#
#     unpaced   client received  8,454,273 of 13,107,400 bytes, connection closed
#     paced     client received 13,107,400 of 13,107,400 bytes, fired 3 times
#
# Three is the number it should be, which is worth checking rather than just
# being non-zero: the queue is refilled to the 4 MiB watermark each time, and
# 13.1 MB is a first fill plus three of them.
#
# That second row is not an improvement on a number. It is a transfer that had
# no expressible form before: every script sending a body past the bound lost
# the connection, and the only way to avoid it was to already know the bound
# and stay under it for the whole life of the connection.
#
# ─── WHY THE WATERMARK IS A FIELD AND NOT A CONSTANT IN EVERY SCRIPT ────────
#
# on_writable fires on the crossing, so a producer that paces BELOW the
# watermark never crosses it and is never called back -- it would wait forever
# for an event its own caution prevented. The field and the callback have to
# name one value, and it is not the script's to guess. Hence self.watermark(),
# and the first case below asserts it is the number the runtime actually uses
# rather than a plausible-looking one.
#
# A CALL and not a field, which --write-buffer is the reason for: measured as a
# field, `edit x --write-buffer 512K` moved the runtime's bound while the script
# went on reading 4194304 until the runtime was restarted. The cache's mode()
# carries the same note for the same reason.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_ready.sh"
daemon_isolate writable

P=$((SL_PORT_BASE+1950))
NAMES="wr_srv"
LUA="$SOCKETLEY_TMPD/wr.lua"

# 200 chunks of 64 KB, each with the newline the server appends.
CHUNKS=200
EXPECT=$((CHUNKS * 65537))

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "expected '$2', got '$3'"; fi; }

cleanup() {
    for n in $NAMES; do "$BIN" stop "$n"   >/dev/null 2>&1 || true; done
    sleep 0.3
    for n in $NAMES; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

cat > "$LUA" <<'LUAEOF'
local CHUNK  = string.rep("x", 65536)
local CHUNKS = 200

local sent, fired, done = 0, 0, false
local paced_id = nil

-- Sends until the queue reaches the watermark, then stops and waits to be
-- called back.  self.watermark() and not a literal: pacing below the number
-- on_writable fires on would wait for a crossing it prevented.
local function pump(id)
    while sent < CHUNKS do
        if (self.pending(id) or 0) >= self.watermark() then return end
        local okay, why = self.send(id, CHUNK)
        if not okay then
            socketley.log("WR paced refused at=" .. sent .. " why=[" .. tostring(why) .. "]")
            return
        end
        sent = sent + 1
    end
    if not done then
        done = true
        socketley.log("WR paced done sent=" .. sent .. " fired=" .. fired)
    end
end

function on_writable(id)
    -- The flood connection crosses the watermark too on its way to being
    -- closed; only the paced one is being driven from here.
    if id ~= paced_id then return end
    fired = fired + 1
    pump(id)
end

function on_client_message(id, msg)
    if msg == "paced" then
        sent, fired, done, paced_id = 0, 0, false, id
        pump(id)

    elseif msg == "flood" then
        -- The same body with no pacing at all, which is the arm that cannot
        -- finish: 13 MB through an 8 MiB bound.
        local s, f = 0, 0
        for _ = 1, CHUNKS do
            if self.send(id, CHUNK) then s = s + 1 else f = f + 1 end
        end
        socketley.log("WR flood sent=" .. s .. " failed=" .. f)

    elseif msg == "probe" then
        socketley.log("WR probe watermark=" .. tostring(self.watermark())
            .. " pending=" .. tostring(self.pending(id)))
        self.send(id, "PROBE-OK")
    end
end
LUAEOF

# One reader for both arms, so the difference between them is the script and
# not the harness. Reads in bites with a pause, which is what makes a producer
# able to outrun it at all.
read_arm() {
    timeout 60 python3 - "$P" "$1" "$EXPECT" <<'PYEOF' 2>/dev/null || true
import socket, sys, time
port, word, expect = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
s = socket.create_connection(("127.0.0.1", port), 5)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
s.sendall((word + "\n").encode())
s.settimeout(6)
total, closed = 0, 0
while total < expect:
    try:
        b = s.recv(262144)
    except socket.timeout:
        break
    if not b:
        closed = 1
        break
    total += len(b)
    time.sleep(0.005)
print("BYTES=%d CLOSED=%d" % (total, closed))
s.close()
PYEOF
}

echo "=== Integration: a paced producer finishes what a flood cannot ==="
daemon_start "$BIN"

create_ok "a scripted server" "$BIN" create server wr_srv -p "$P" --lua "$LUA" -s
ready_tcp 127.0.0.1 "$P" >/dev/null 2>&1 || true

# ─── 1. The runtime is serving and the field is there ───────────────────────
PR=$(read_arm probe)
if [ -n "$PR" ]; then ok; else bad "the server answers at all" "no reply from the probe arm"; fi

PL=$(grep -o 'WR probe .*' "$SOCKETLEY_DLOG" | tail -1) || true
# 4 MiB, and asserted as a number rather than "not nil" -- a field that read
# nil would make every pacing comparison below silently true.
check "self.watermark is the runtime's own watermark" "4194304" \
      "$(printf '%s\n' "$PL" | sed -n 's/.* watermark=\([^ ]*\).*/\1/p')"
check "and pending is zero on a quiet connection" "0" \
      "$(printf '%s\n' "$PL" | sed -n 's/.* pending=\([^ ]*\).*/\1/p')"

# ─── 2. The unpaced arm cannot deliver it ───────────────────────────────────
# Not a judgement about speed: 13 MB does not fit through an 8 MiB bound, so
# this arm ends short on any machine.
FA=$(read_arm flood)
FB=$(printf '%s\n' "$FA" | sed -n 's/.*BYTES=\([0-9]*\).*/\1/p')
if [ "${FB:-0}" -gt 0 ] && [ "${FB:-0}" -lt "$EXPECT" ]; then ok; else
    bad "an unpaced flood ends short of the body" \
        "received ${FB:-0} of $EXPECT -- 0 would mean nothing was sent at all," \
        "and the full body would mean the bound is not being reached"; fi

# ─── 3. The paced arm delivers all of it ────────────────────────────────────
PA=$(read_arm paced)
PB=$(printf '%s\n' "$PA" | sed -n 's/.*BYTES=\([0-9]*\).*/\1/p')
check "a paced producer delivers the whole body" "$EXPECT" "${PB:-0}"

# ─── 4. And it got there by being called back ───────────────────────────────
# The half that says why: a paced arm which simply never reached the watermark
# would deliver the body too, and prove nothing about on_writable.
DL=$(grep -o 'WR paced done .*' "$SOCKETLEY_DLOG" | tail -1) || true
check "the script sent every chunk" "200" \
      "$(printf '%s\n' "$DL" | sed -n 's/.* sent=\([0-9]*\).*/\1/p')"
FIRED=$(printf '%s\n' "$DL" | sed -n 's/.* fired=\([0-9]*\).*/\1/p')
if [ "${FIRED:-0}" -gt 0 ]; then ok; else
    bad "on_writable is what let it continue" \
        "fired=${FIRED:-0} -- the body arrived without the callback ever firing," \
        "so the queue never reached the watermark and this arm measured nothing"; fi

# ─── 5. Nothing was refused along the way ───────────────────────────────────
# A paced producer should never see the hard cap; if it does, the pacing is not
# actually holding the queue below it.
if grep -q 'WR paced refused' "$SOCKETLEY_DLOG"; then
    bad "a paced producer never hits the hard cap" \
        "$(grep -o 'WR paced refused .*' "$SOCKETLEY_DLOG" | tail -1)"
else
    ok
fi

# ─── 6. And no callback reached a connection that was gone ──────────────────
# The dispatch resolves a serial a loop turn after the completion, so a
# connection closed in between must simply not be called.
if grep -q "on_writable error" "$SOCKETLEY_DLOG"; then
    bad "on_writable was never called on a dead connection" \
        "$(grep -o 'on_writable error.*' "$SOCKETLEY_DLOG" | tail -1)"
else
    ok
fi

# ─── 7. The runtime is still healthy afterwards ─────────────────────────────
check "the runtime survived both arms" "Up" \
      "$("$BIN" ps -a 2>/dev/null | awk '$2=="wr_srv" { print $7 }')"

# Printed on success too, because the point of this file is a pair of numbers
# and a green exit code does not show them.
echo "  measured: unpaced=${FB:-0}/$EXPECT bytes, paced=${PB:-0}/$EXPECT bytes," \
     "on_writable fired ${FIRED:-0}x"
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
if [ "$FAIL" -eq 0 ]; then echo "  OK"; else
    echo "    probe: $PL"
    echo "    flood: $FA / $(grep -o 'WR flood .*' "$SOCKETLEY_DLOG" | tail -1)"
    echo "    paced: $PA / $DL"
    echo "  FAILED"
fi
[ "$FAIL" -eq 0 ]
