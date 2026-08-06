#!/usr/bin/env bash
# Integration test: Lua HTTP worker (on_http_request callback) + multi-protocol auto-detection
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
daemon_isolate httpworker
HTTP_PORT=19391
PASS=0; FAIL=0; TOTAL=0
LUA_SCRIPT="/tmp/test_http_worker.lua"

cleanup() {
    "$BIN" stop http_svr 2>/dev/null || true
    "$BIN" stop proto_svr 2>/dev/null || true
    "$BIN" stop short_svr 2>/dev/null || true
    sleep 0.5
    "$BIN" remove http_svr 2>/dev/null || true
    "$BIN" remove proto_svr 2>/dev/null || true
    "$BIN" remove short_svr 2>/dev/null || true
    rm -f "$LUA_SCRIPT"
    daemon_stop
}
trap cleanup EXIT

assert_contains() {
    TOTAL=$((TOTAL+1))
    if grep -q "$2" <<<"$1"; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL: expected '$2' in output"
    fi
}

pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

# counter RUNTIME FIELD
#
# One numeric field out of `stats`, or the empty string when the runtime is not
# there or the daemon did not answer.  Deliberately not 0 in that case: 0 is a
# legitimate reading of every counter used below, and "there was nothing to
# read" must not compare equal to it -- that substitution is exactly how these
# checks would go back to passing for the wrong reason.
counter() {
    local v
    v=$("$BIN" stats "$1" 2>/dev/null | sed -n "s/^$2:\([0-9][0-9]*\)$/\1/p" | head -1) || v=""
    printf '%s' "$v"
}

# wait_counter RUNTIME FIELD BASE WANT
#
# Poll FIELD until it has reached at least BASE+WANT, then print what it says.
# Beats sleeping a guess at how long the server takes to account for a
# connection, and on success it returns as soon as the number has moved.
wait_counter() {
    local rt=$1 field=$2 base=$3 want=$4 v i
    v=$(counter "$rt" "$field")
    for i in $(seq 1 40); do
        v=$(counter "$rt" "$field")
        if [ -n "$base" ] && [ -n "$v" ] && [ "$v" -ge "$((base + want))" ]; then break; fi
        sleep 0.1
    done
    printf '%s' "$v"
}

echo "=== Integration: HTTP worker + multi-protocol ==="

# Ensure daemon is running
daemon_start "$BIN"

# --- Test 1: Lua HTTP worker ---

# Create Lua script with on_http_request handler
cat > "$LUA_SCRIPT" << 'EOLUA'
function on_http_request(req)
    if req.path == "/api/hello" then
        return {
            status = 200,
            headers = {["Content-Type"] = "application/json"},
            body = '{"message":"hello world"}'
        }
    elseif req.path == "/api/echo" then
        return {
            status = 200,
            headers = {["Content-Type"] = "text/plain"},
            body = req.method .. " " .. req.path
        }
    else
        return {
            status = 404,
            body = "not found"
        }
    end
end
EOLUA

create_ok "HTTP server created" "$BIN" create server http_svr -p "$HTTP_PORT" \
    --lua "$LUA_SCRIPT" -s
sleep 0.5

# Test: HTTP GET to /api/hello returns JSON
REPLY=$(curl -s --max-time 2 "http://127.0.0.1:$HTTP_PORT/api/hello" 2>/dev/null) || true
assert_contains "$REPLY" "hello world"

# Test: HTTP GET to /api/echo returns method and path
REPLY=$(curl -s --max-time 2 "http://127.0.0.1:$HTTP_PORT/api/echo" 2>/dev/null) || true
assert_contains "$REPLY" "GET /api/echo"

# Test: HTTP GET to unknown path returns 404
TOTAL=$((TOTAL+1))
STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 "http://127.0.0.1:$HTTP_PORT/unknown" 2>/dev/null) || true
if [ "$STATUS" = "404" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL: expected 404, got $STATUS"
fi

# Test: HTTP POST to /api/echo
REPLY=$(curl -s --max-time 2 -X POST "http://127.0.0.1:$HTTP_PORT/api/echo" 2>/dev/null) || true
assert_contains "$REPLY" "POST /api/echo"

# --- Test 2: Multi-protocol auto-detection ---
# Same server should also handle plain TCP connections

PROTO_PORT=19392
create_ok "multi-protocol server created" "$BIN" create server proto_svr -p "$PROTO_PORT" -s
sleep 0.3

# TCP (newline-delimited) connection should work
#
# ─── What the old check could not tell apart ────────────────────────────────
#
#     RC=0
#     echo "hello tcp" | nc -q 1 127.0.0.1 "$PROTO_PORT" 2>/dev/null || RC=$?
#     if [ "$RC" -eq 0 ]; then PASS=$((PASS+1)); ...
#
# The whole assertion was nc's exit status, which is 0 for anything at all that
# accepts a TCP connection on that port.  Staged: with a foreign process holding
# 19392 so `create server proto_svr` was refused and the runtime never existed,
# this file printed 7/9 and `tcp connect` was not one of the two failures.  It
# passed against a stranger.  Worth noting that `http connect`, three lines
# below, went red in that same run without being touched -- curl has to parse a
# response, so it was already asking for something a stranger cannot give.  This
# check asked for nothing.
#
# The oracle is this daemon's own counters, which nothing outside this daemon
# can move: proto_svr must count the connection, and the payload's bytes must
# actually arrive at it.
PROTO_PAYLOAD="hello tcp"
PROTO_N=$(( ${#PROTO_PAYLOAD} + 1 ))     # printf adds the newline that is also sent
PC0=$(counter proto_svr total_connections)
PB0=$(counter proto_svr bytes_in)

# `timeout` around nc: `-q 1` only bounds the wait *after* the peer hangs up, so
# a peer that accepts and then holds the connection open forever leaves nc
# blocked with nothing to time it out and the file never reaches its `Results`
# line.  Staged against such a peer the old form wedged until it was killed.
RC=0
printf '%s\n' "$PROTO_PAYLOAD" | timeout 10 nc -q 1 127.0.0.1 "$PROTO_PORT" >/dev/null 2>&1 || RC=$?

PC1=$(wait_counter proto_svr total_connections "$PC0" 1)
PB1=$(wait_counter proto_svr bytes_in "$PB0" "$PROTO_N")

if [ -z "$PC0" ] || [ -z "$PC1" ]; then
    fail "tcp connect: proto_svr counted the connection" \
         "could not read proto_svr's total_connections (before='$PC0' after='$PC1')" \
         "— stats did not answer, so nothing was measured and nothing may be concluded"
elif [ "$PC1" -eq "$((PC0 + 1))" ]; then
    pass
else
    fail "tcp connect: proto_svr counted the connection" \
         "total_connections went $PC0 -> $PC1, wanted exactly one more (nc exited $RC)." \
         "Something may still answer port $PROTO_PORT — that is what the old nc-exit-code" \
         "check measured — but it is not this server."
fi

if [ -z "$PB0" ] || [ -z "$PB1" ]; then
    fail "tcp connect: the payload arrived" \
         "could not read proto_svr's bytes_in (before='$PB0' after='$PB1')"
elif [ "$PB1" -eq "$((PB0 + PROTO_N))" ]; then
    pass
else
    fail "tcp connect: the payload arrived" \
         "proto_svr's bytes_in went $PB0 -> $PB1, wanted exactly $PROTO_N more." \
         "The connection was accepted but the newline-delimited payload did not land."
fi

# --- Test 2b: a short first line is answered, not held ------------------------
#
# Detection reads four bytes before it will name a protocol, and used to wait
# for them unconditionally.  A line-protocol client writes "hi\n" and then waits
# to be answered, so the fourth byte is one it will not send until the answer
# comes: the connection deadlocked with three bytes in the buffer, no callback
# ran, and nothing was logged.  From the client's side that is indistinguishable
# from a server that received nothing.
#
# The oracle is the echo, not a connection counter or a byte counter: both of
# those move for data the server has merely *received*, which is exactly the
# state this defect leaves a connection in.  Only a reply proves the bytes
# reached the script.  And the reply has to carry the payload back, so a server
# answering some canned greeting cannot pass.
#
# Paired with a longer line through the same code on the same server: without
# it, "the short line was answered" would also fail on a build that answers
# nothing, and the failure would be read as this defect returning.
ECHO_LUA="$SOCKETLEY_TMPD/echo.lua"
cat > "$ECHO_LUA" <<'LUAEOF'
function on_client_message(client_id, msg)
    self.send(client_id, "echo:" .. msg)
end
LUAEOF
SHORT_PORT=19393
create_ok "line-echo server created" "$BIN" create server short_svr -p "$SHORT_PORT" \
          --lua "$ECHO_LUA" -s
sleep 0.3

# say PORT PAYLOAD -> whatever came back within the timeout, or the empty string
say() {
    python3 -c "
import socket,sys
try:
    s=socket.create_connection(('127.0.0.1',int(sys.argv[1])),timeout=3)
    s.settimeout(3)
    s.sendall(sys.argv[2].encode())
    try: sys.stdout.write(s.recv(4096).decode('latin1','replace'))
    except Exception: pass
    s.close()
except Exception: pass" "$1" "$2" 2>/dev/null || printf ''
}

SHORT_REPLY=$(say "$SHORT_PORT" 'hi
')
LONG_REPLY=$(say "$SHORT_PORT" 'hello
')

# The control first: if this fails, the claim below proves nothing.
TOTAL=$((TOTAL+1))
if [ "$LONG_REPLY" = "echo:hello" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [control: a normal line is echoed]: got '$LONG_REPLY', wanted 'echo:hello'"
    echo "        the short-line assertion below is not measuring anything while this fails"
fi

TOTAL=$((TOTAL+1))
if [ "$SHORT_REPLY" = "echo:hi" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [a two-byte line is answered]: got '$SHORT_REPLY', wanted 'echo:hi'"
    echo "        'hi\\n' is three bytes on the wire, one short of what protocol"
    echo "        detection wants; an empty answer here is the connection deadlocking"
    echo "        with the line sitting unread, which is what this asserts is over"
fi

# And the detection it must not have broken: the same server still has to see
# an HTTP request as HTTP rather than as a line of text.
TOTAL=$((TOTAL+1))
SHORT_HTTP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 \
             "http://127.0.0.1:$SHORT_PORT/" 2>/dev/null) || SHORT_HTTP="000"
if [ "$SHORT_HTTP" != "000" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [detection still recognises HTTP]: curl got '$SHORT_HTTP'"
    echo "        deciding early on a completed short line must not change what a"
    echo "        four-byte method prefix is classified as"
fi

# HTTP connection should get a response (no Lua = 404 or static)
TOTAL=$((TOTAL+1))
STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 "http://127.0.0.1:$PROTO_PORT/" 2>/dev/null) || STATUS="000"
if [ "$STATUS" != "000" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [http connect]: curl returned status $STATUS"
fi

# HTTP keep-alive: multiple requests on same connection
#
# ─── What the old check could not tell apart ────────────────────────────────
#
#     } | nc -q 1 127.0.0.1 "$HTTP_PORT" >/dev/null 2>&1 || RC=$?
#     if [ "$RC" -eq 0 ]; then PASS=$((PASS+1)); ...
#
# The responses went to /dev/null, so the claim "multiple requests on one
# connection are served" rested entirely on nc's exit status.  It could not tell
# two responses from zero.  A server that accepts and immediately closes passes
# it; so does a stranger on the port.  Staged with a foreign process holding
# 19391, so `create server http_svr` was refused and the runtime never existed,
# this file printed 4/9 and `keep-alive` was not one of the five failures.
#
# Both halves of the name are now asserted separately, because they fail
# separately and the failures mean different things:
#
#   * *multiple requests*: exactly two HTTP responses come back.  Counted by
#     occurrence rather than by line -- the first body carries no trailing
#     newline, so the second status line is concatenated onto it and `grep -c`
#     reports one match for two responses.
#   * *on one connection*: http_svr's total_connections goes up by exactly one.
#     A server that answered the first request, closed, and was reconnected to
#     would still produce two responses; it would produce two connections.
KA_OUT="$SOCKETLEY_TMPD/keepalive.out"
KC0=$(counter http_svr total_connections)

RC=0
{
    printf "GET /api/hello HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n"
    sleep 0.2
    printf "GET /api/hello HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    sleep 0.2
} | timeout 10 nc -q 1 127.0.0.1 "$HTTP_PORT" >"$KA_OUT" 2>/dev/null || RC=$?

# `|| RESP=0` is load-bearing under `set -euo pipefail`: grep exits 1 when it
# matches nothing, which is precisely the failure this assertion exists to
# report, and an unguarded capture would end the file at this line instead.
RESP=$(grep -o 'HTTP/1\.1 [0-9][0-9][0-9]' "$KA_OUT" 2>/dev/null | wc -l) || RESP=0
[ -n "$RESP" ] || RESP=0
KC1=$(wait_counter http_svr total_connections "$KC0" 1)

if [ "$RESP" -eq 2 ]; then
    pass
else
    fail "keep-alive: both requests were answered" \
         "$RESP HTTP responses came back, wanted 2 (nc exited $RC, $(wc -c <"$KA_OUT" 2>/dev/null || echo 0) bytes read)." \
         "The old form sent this to /dev/null and asserted nc's exit status, which" \
         "cannot tell two responses from zero."
fi

if [ -z "$KC0" ] || [ -z "$KC1" ]; then
    fail "keep-alive: both were served on one connection" \
         "could not read http_svr's total_connections (before='$KC0' after='$KC1')" \
         "— stats did not answer, so nothing was measured"
elif [ "$KC1" -eq "$((KC0 + 1))" ]; then
    pass
else
    fail "keep-alive: both were served on one connection" \
         "http_svr's total_connections went $KC0 -> $KC1, wanted exactly one more." \
         "Two responses over two connections is not keep-alive."
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
