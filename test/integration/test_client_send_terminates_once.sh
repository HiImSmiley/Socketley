#!/usr/bin/env bash
# Integration test: what self.send() puts on the wire, byte for byte.
#
# ─── WHY THIS EXISTS ────────────────────────────────────────────────────────
#
# A client terminates each message with a newline, and adds one only when the
# caller left one off.  That decision is made twice -- once on the path that
# writes straight to the socket and once on the path that queues behind a write
# already in flight -- and nothing in this directory had ever looked at the
# bytes.  A script sending "line\n" could have been given "line\n\n" and every
# test would have stayed green, because every reader here splits on newlines
# and two of them look like one empty message nobody asserts about.
#
# The target is a plain socket that records what arrives rather than a runtime
# that parses it: a server would frame the bytes before anything could count
# them, which is the same reason this file does not use one.
#
# ─── WHAT IT ASSERTS ────────────────────────────────────────────────────────
#
#   a message with no terminator     gets exactly one
#   a message that has one           keeps exactly one, not two
#   an empty message                 is one terminator and nothing else
#   the queued path as well          by sending all four from one callback,
#                                    which leaves a write in flight and puts
#                                    the rest through the queue
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate sendterm

PORT=$((SL_PORT_BASE+1774))
CAP="$SOCKETLEY_TMPD/capture.bin"
LUA="$SOCKETLEY_TMPD/sender.lua"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    "$BIN" stop   st_cli >/dev/null 2>&1 || true
    "$BIN" remove st_cli >/dev/null 2>&1 || true
    [ -n "${SINK_PID:-}" ] && kill "$SINK_PID" 2>/dev/null
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a client terminates a message once, never twice ==="
daemon_start "$BIN"

# A listener that accepts one connection and writes every byte to a file, so
# the assertion is about what left the client and not about what a parser made
# of it.
python3 - "$PORT" "$CAP" <<'PY' >"$SOCKETLEY_TMPD/sink.log" 2>&1 &
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(1)
c, _ = s.accept()
c.settimeout(6)
with open(sys.argv[2], "wb") as f:
    try:
        while True:
            b = c.recv(65536)
            if not b:
                break
            f.write(b); f.flush()
    except Exception:
        pass
PY
SINK_PID=$!

for i in $(seq 1 60); do
    ss -ltnH "sport = :$PORT" 2>/dev/null | grep -q . && break
    sleep 0.1
done

cat > "$LUA" <<'LUAEOF'
-- All four from one callback: the first goes straight to the socket and the
-- rest queue behind it, so both terminator decisions are exercised.
function on_connect()
    -- The first send goes straight to the socket and already ends in a
    -- terminator, so the direct path's "do not add a second" is covered too;
    -- with "prime" it was only ever the queued path's.
    self.send("prime\n")
    self.send("abc")
    self.send("def\n")
    self.send("")
end
LUAEOF

"$BIN" create client st_cli -t "127.0.0.1:$PORT" --lua "$LUA" >/dev/null 2>&1
"$BIN" start st_cli >/dev/null 2>&1

for i in $(seq 1 60); do
    [ -s "$CAP" ] && break
    sleep 0.1
done
sleep 3

# Compared as FILES and never through a variable.  `$(cat file)` strips every
# trailing newline, so the two bytes this test exists to count are exactly the
# ones the comparison would have thrown away -- which is what the first version
# of this file did, and it read as the daemon dropping them.
WANT="$SOCKETLEY_TMPD/expected.bin"
printf 'prime\nabc\ndef\n\n' > "$WANT"

if cmp -s "$WANT" "$CAP" 2>/dev/null; then ok; else
    bad "the four messages arrive with one terminator each" \
        "expected $(od -c "$WANT" 2>/dev/null | head -2 | tr '\n' ' ')" \
        "got      $(od -c "$CAP"  2>/dev/null | head -2 | tr '\n' ' ')"
fi

# Named separately so a failure says which rule broke rather than only that
# the whole string differs.
NL=$(tr -cd '\n' < "$CAP" 2>/dev/null | wc -c)
if [ "$NL" = "4" ]; then ok; else
    bad "four messages produce four terminators" \
        "counted $NL newlines in $(wc -c < "$CAP" 2>/dev/null || echo 0) bytes" \
        "five would mean the message that already ended in one was given another"
fi

# The specific way this breaks, named on its own: two terminators in a row
# where "def" ends, which is a doubled one and not the empty message's.
if od -An -c "$CAP" 2>/dev/null | tr -s ' ' | tr -d '\n' | grep -q 'd e f \\n \\n \\n'; then
    bad "a message that ends in a newline keeps one" \
        "'def' arrived with two terminators before the empty message's"
else
    ok
fi

echo
echo "  $PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || exit 1
