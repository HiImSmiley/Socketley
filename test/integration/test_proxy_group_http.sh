#!/usr/bin/env bash
# Integration test: HTTP proxy routing through an @group backend.
#
# Group backends are resolved per connection, so the group entry in m_backends
# deliberately carries no resolved_host/resolved_port.  Anything that describes
# the target after selection has to read the endpoint off the connection — get
# that wrong and the forwarded request goes out with a literal "Host: :0".
#
# The group member is a TCP proxy pointing at a netcat listener, which gives us
# the exact bytes the gateway put on the wire.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
SINK_PORT=19284
MEMBER_PORT=19283
GW_PORT=19282
GROUP=grphttp
CAPTURE="/tmp/test-group-http-$$.txt"
NC_PID=""
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop grphttp_gw 2>/dev/null || true
    "$BIN" stop grphttp_be 2>/dev/null || true
    sleep 0.5
    "$BIN" remove grphttp_gw 2>/dev/null || true
    "$BIN" remove grphttp_be 2>/dev/null || true
    [ -n "$NC_PID" ] && kill "$NC_PID" 2>/dev/null || true
    rm -f "$CAPTURE"
}
trap cleanup EXIT

assert_contains() {
    TOTAL=$((TOTAL+1))
    if echo "$1" | grep -q "$2"; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$3]: expected '$2' in output"
    fi
}

assert_not_contains() {
    TOTAL=$((TOTAL+1))
    if echo "$1" | grep -q "$2"; then
        FAIL=$((FAIL+1))
        echo "  FAIL [$3]: did not expect '$2' in output"
    else
        PASS=$((PASS+1))
    fi
}

echo "=== Integration: proxy @group over HTTP ==="

# Ensure daemon is running
"$BIN" daemon 2>/dev/null &
sleep 0.3

# Capture whatever the gateway forwards
rm -f "$CAPTURE"
timeout 15 nc -l 127.0.0.1 "$SINK_PORT" > "$CAPTURE" &
NC_PID=$!
sleep 0.3

# Group member: TCP proxy that passes bytes through to the capture listener
"$BIN" create proxy grphttp_be -p "$MEMBER_PORT" \
    --backend "127.0.0.1:$SINK_PORT" --protocol tcp -g "$GROUP" -s 2>&1 || true
sleep 0.3

# Gateway: HTTP proxy routing to the group
"$BIN" create proxy grphttp_gw -p "$GW_PORT" \
    --backend "@$GROUP" --protocol http -s 2>&1 || true
sleep 0.5

OUT=$("$BIN" ps 2>&1)
assert_contains "$OUT" "grphttp_be" "group member in ps"
assert_contains "$OUT" "grphttp_gw" "gateway in ps"

# The HTTP proxy only accepts its own /<name>/ prefix.  No response is expected —
# the listener never answers; what matters is what arrived.
curl -s -m 4 -o /dev/null "http://127.0.0.1:$GW_PORT/grphttp_gw/hello" 2>/dev/null || true
sleep 1.5

FORWARDED=$(cat "$CAPTURE" 2>/dev/null || true)

TOTAL=$((TOTAL+1))
if [ -z "$FORWARDED" ]; then
    FAIL=$((FAIL+1))
    echo "  FAIL [request reached member]: nothing was forwarded"
else
    PASS=$((PASS+1))
fi

assert_contains "$FORWARDED" "GET /hello HTTP/1.1" "request line forwarded"
assert_contains "$FORWARDED" "Host: 127.0.0.1:$MEMBER_PORT" "Host names the selected group member"
assert_not_contains "$FORWARDED" "Host: :0" "no empty Host from the unresolved group entry"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
