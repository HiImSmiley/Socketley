#!/usr/bin/env bash
# Integration test: a server handler that waits keeps its connection, across a second await and a reload-lua
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# A handler that waits holds the connection it answers open, so a peer that
# half-closes after its line still gets the reply, and lets it go when the
# answer has been used.  What would be wrong and quiet: a handler's second
# await holding nothing, so the reply to `echo twice | nc` is lost; a context
# made by reload-lua letting go of nothing, so every connection a handler
# waited for stays open until the runtime stops; and an answer the cache gives
# to the old context's handler taken by the new context's, whose ids start
# again at one.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate awreload

CP=$((SL_PORT_BASE+1986)); SP=$((SL_PORT_BASE+1987))
NAMES="arsrv arcache"
SCRIPT="$SOCKETLEY_TMPD/await.lua"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "expected '$2', got '$3'"; fi; }

FROZEN=""
cleanup() {
    [ -n "$FROZEN" ] && kill -CONT "$FROZEN" 2>/dev/null; true
    for n in $NAMES; do "$BIN" stop "$n"   >/dev/null 2>&1 || true; done
    sleep 0.3
    for n in $NAMES; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a waiting handler's connection across a second await and reload-lua ==="

cat > "$SCRIPT" <<'LUA'
function on_client_message(id, msg)
    if msg == "twice" then
        local a = self.cache("get k1")
        local b = self.cache("get k2")
        self.send(id, "a=" .. tostring(a) .. " b=" .. tostring(b))
        return
    end
    local v, err = self.cache("get " .. msg)
    self.send(id, msg .. "=" .. tostring(v or err))
end
LUA

# One line, the writing side shut at once, and what came back before the server closed, or "open" past 4 seconds.
cat > "$SOCKETLEY_TMPD/ask.py" <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
s.sendall((sys.argv[2] + "\n").encode())
if sys.argv[3] == "shut":
    s.shutdown(socket.SHUT_WR)
s.settimeout(4)
got = b""
try:
    while True:
        b = s.recv(4096)
        if not b:
            print(" ".join(got.decode().split()) + "|closed")
            break
        got += b
except socket.timeout:
    print(" ".join(got.decode().split()) + "|open")
PY
ask() { python3 "$SOCKETLEY_TMPD/ask.py" "$SP" "$1" "${2:-shut}"; }

daemon_start "$BIN"
create_ok "a cache" "$BIN" create cache arcache -p "$CP" -s
sleep 0.5
printf 'set k1 one\nset k2 two\n' | nc -q1 127.0.0.1 "$CP" >/dev/null 2>&1
create_ok "a server whose handler waits on it" "$BIN" create server arsrv -p "$SP" --cache arcache --lua "$SCRIPT" -s
for _ in $(seq 1 50); do [ "$(ask k1)" = "k1=one|closed" ] && break; sleep 0.1; done

check "a handler that waits answers a peer that half-closed, and the connection ends" "k1=one|closed" "$(ask k1)"
check "and one that waits twice answers it too" "a=one b=two|closed" "$(ask twice)"

"$BIN" reload-lua arsrv >/dev/null 2>&1 || true
check "after reload-lua the connection a handler waited for is let go" "k1=one|closed" "$(ask k1)"
check "and a second await still holds it" "a=one b=two|closed" "$(ask twice)"

# An answer on its way to the old context's handler when the script is replaced is not the new one's.
CACHE_PID=$("$BIN" stats arcache 2>/dev/null | grep -oP '^pid:\K[0-9]+' | head -1)
if [ -z "$CACHE_PID" ]; then
    bad "setup" "the cache reports no pid to freeze"
else
    FROZEN=$CACHE_PID
    kill -STOP "$FROZEN"
    python3 "$SOCKETLEY_TMPD/ask.py" "$SP" k1 keep > "$SOCKETLEY_TMPD/old.out" &
    OLD=$!
    sleep 0.5
    "$BIN" reload-lua arsrv >/dev/null 2>&1 || true
    python3 "$SOCKETLEY_TMPD/ask.py" "$SP" k2 keep > "$SOCKETLEY_TMPD/new.out" &
    NEW=$!
    sleep 0.5
    kill -CONT "$FROZEN"
    FROZEN=""
    wait "$OLD" "$NEW" || true
    check "the new context's handler gets its own answer" "k2=two|open" "$(cat "$SOCKETLEY_TMPD/new.out")"
    # The old handler is let go with its context, so its client hears no answer, only the lines the server relays.
    check "and the old one's is not answered with it" "0" "$(grep -c '=' "$SOCKETLEY_TMPD/old.out" || true)"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
