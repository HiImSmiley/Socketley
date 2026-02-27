#!/usr/bin/env bash
# Integration test: Lua HTTP worker (on_http_request callback) + multi-protocol auto-detection
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
HTTP_PORT=19391
PASS=0; FAIL=0; TOTAL=0
LUA_SCRIPT="/tmp/test_http_worker.lua"

cleanup() {
    "$BIN" stop http_svr 2>/dev/null || true
    "$BIN" stop proto_svr 2>/dev/null || true
    sleep 0.5
    "$BIN" remove http_svr 2>/dev/null || true
    "$BIN" remove proto_svr 2>/dev/null || true
    rm -f "$LUA_SCRIPT"
}
trap cleanup EXIT

assert_contains() {
    TOTAL=$((TOTAL+1))
    if echo "$1" | grep -q "$2"; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL: expected '$2' in output"
    fi
}

echo "=== Integration: HTTP worker + multi-protocol ==="

# Ensure daemon is running
"$BIN" daemon 2>/dev/null &
sleep 0.3

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

"$BIN" create server http_svr -p "$HTTP_PORT" --lua "$LUA_SCRIPT" -s 2>&1 || true
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
"$BIN" create server proto_svr -p "$PROTO_PORT" -s 2>&1 || true
sleep 0.3

# TCP (newline-delimited) connection should work
TOTAL=$((TOTAL+1))
RC=0
echo "hello tcp" | nc -q 1 127.0.0.1 "$PROTO_PORT" 2>/dev/null || RC=$?
if [ "$RC" -eq 0 ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [tcp connect]: nc exit code $RC"
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
TOTAL=$((TOTAL+1))
RC=0
{
    printf "GET /api/hello HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n"
    sleep 0.2
    printf "GET /api/hello HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    sleep 0.2
} | nc -q 1 127.0.0.1 "$HTTP_PORT" >/dev/null 2>&1 || RC=$?
if [ "$RC" -eq 0 ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [keep-alive]: nc exit code $RC"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
