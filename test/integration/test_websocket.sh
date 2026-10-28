#!/usr/bin/env bash
# Integration test: WebSocket upgrade detection and TCP coexistence
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate ws
PORT=$((SL_PORT_BASE+200))
PASS=0; FAIL=0; TOTAL=0

P_LISTED=$((SL_PORT_BASE+201))
P_ANY=$((SL_PORT_BASE+202))

cleanup() {
    for n in ws_test ws_listed ws_any; do "$BIN" stop "$n" 2>/dev/null || true; done
    sleep 0.5
    for n in ws_test ws_listed ws_any; do "$BIN" remove "$n" 2>/dev/null || true; done
    daemon_stop
}
trap cleanup EXIT

assert_eq() {
    TOTAL=$((TOTAL+1))
    local got="$1" expected="$2" label="$3"
    if [ "$got" = "$expected" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$label]: got '$got', expected '$expected'"
    fi
}

assert_contains() {
    TOTAL=$((TOTAL+1))
    if grep -q "$2" <<<"$1"; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$2]: not found in output"
    fi
}

echo "=== Integration: WebSocket ==="

# Ensure daemon is running
daemon_start "$BIN"

create_ok "server created" "$BIN" create server ws_test -p "$PORT" -s
sleep 0.3

# Test: Send WebSocket upgrade request, expect 101 Switching Protocols
WS_KEY="dGhlIHNhbXBsZSBub25jZQ=="
# `|| true` on the pipeline, as the two raw-TCP checks below already have: with
# nothing listening on $PORT nc exits non-zero, `pipefail` promotes it, and this
# lone `VAR=$(…)` takes its status from the substitution — so a refused create
# ended the file here, before a single one of its six assertions had run and
# before any `Results` line.  An empty response is the finding; the three
# assert_contains below are what report it.
WS_RESPONSE=$(printf "GET / HTTP/1.1\r\nHost: 127.0.0.1:$PORT\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: $WS_KEY\r\nSec-WebSocket-Version: 13\r\n\r\n" | nc -q 1 127.0.0.1 "$PORT" 2>/dev/null | tr -d '\r') || true
assert_contains "$WS_RESPONSE" "101 Switching Protocols" "WS upgrade 101"
assert_contains "$WS_RESPONSE" "Upgrade: websocket" "WS upgrade header"
assert_contains "$WS_RESPONSE" "Sec-WebSocket-Accept" "WS accept header"

# Test: Plain TCP coexists with WebSocket on the same port.
#
# These two used to read
#
#     TOTAL=$((TOTAL+1))
#     echo "hello-tcp" | nc -q 1 127.0.0.1 "$PORT" 2>/dev/null || true
#     PASS=$((PASS+1))
#
# -- the `|| true` swallowed nc's status and PASS rose unconditionally, so both
# counted themselves green against a port with nothing on it.  Two of this
# file's six reported assertions could not fail.  What is actually being
# claimed is that the server ACCEPTED the connection, so that is what is asked:
# the connection count it reports has to move.
conns_now() {
    "$BIN" stats ws_test 2>/dev/null \
        | sed -n 's/^total_connections:\([0-9][0-9]*\)$/\1/p' | head -1
}
BEFORE_CONNS=$(conns_now)
if [ -n "$BEFORE_CONNS" ]; then
    echo "hello-tcp" | nc -q 1 127.0.0.1 "$PORT" 2>/dev/null || true
    echo "hello-again" | nc -q 1 127.0.0.1 "$PORT" 2>/dev/null || true
    sleep 0.4
    AFTER_CONNS=$(conns_now)
    TOTAL=$((TOTAL+1))
    if [ -n "$AFTER_CONNS" ] && [ "$AFTER_CONNS" -ge $((BEFORE_CONNS + 2)) ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [two raw TCP connections were accepted]: total connections"
        echo "        went $BEFORE_CONNS -> ${AFTER_CONNS:-unreported}, wanted at"
        echo "        least $((BEFORE_CONNS + 2))"
    fi
else
    # Counted as a failure and not skipped: a stats line this test cannot read
    # is the same blind spot the old version had, and saying so is the point.
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [two raw TCP connections were accepted]: stats reported no"
    echo "        connection count to compare against"
fi

# The status code an upgrade to port $1 is answered with, the rest of the
# arguments being extra header lines.
upgrade_status() {
    local port=$1; shift
    local extra="" h
    for h in "$@"; do extra="$extra$h\r\n"; done
    printf "GET / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: $WS_KEY\r\nSec-WebSocket-Version: 13\r\n$extra\r\n" \
        | nc -q 1 127.0.0.1 "$port" 2>/dev/null | head -1 | tr -d '\r' | awk '{print $2}' || true
}

# A page on another site drives the server through its visitor's browser, so
# only the server's own origin and the ones --origins lists are upgraded.
create_ok "server with listed origins" "$BIN" create server ws_listed -p "$P_LISTED" \
    --origins https://app.example,http://other.example:8080 -s
create_ok "server with any origin" "$BIN" create server ws_any -p "$P_ANY" --origins '*' -s
sleep 0.3

assert_eq "$(upgrade_status "$PORT")" "101" "no Origin is not a browser, and is upgraded"
assert_eq "$(upgrade_status "$PORT" "Origin: http://127.0.0.1:$PORT")" "101" "the page's own origin is upgraded"
assert_eq "$(upgrade_status "$PORT" "Origin: http://evil.example")" "403" "another site's page is refused"
assert_eq "$(upgrade_status "$PORT" "Origin: null")" "403" "an opaque origin is refused"
assert_eq "$(upgrade_status "$PORT" "Origin: http://app.local:8080" "X-Forwarded-Host: app.local:8080")" "101" \
    "the origin a proxy in front was asked for is upgraded"
assert_eq "$(upgrade_status "$P_LISTED" "Origin: http://other.example:8080")" "101" "a listed origin is upgraded"
assert_eq "$(upgrade_status "$P_LISTED" "Origin: HTTPS://APP.EXAMPLE")" "101" "a listed origin matches in any case"
assert_eq "$(upgrade_status "$P_LISTED" "Origin: http://evil.example")" "403" "an origin the list lacks is refused"
assert_eq "$(upgrade_status "$P_ANY" "Origin: http://evil.example")" "101" "* admits any origin"

# Kept in the state file, so the list survives the restart the daemon makes itself.
SF=$(find "${HOME}/.local/share/socketley" -name 'ws_listed.json' 2>/dev/null | head -1)
TOTAL=$((TOTAL+1))
if [ -n "$SF" ] && grep -q '"origins": "https://app.example,http://other.example:8080"' "$SF"; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1)); echo "  FAIL [the origins persist]: not in ${SF:-<no state file>}"
fi

# Test: Server is still running after mixed connections
OUT=$("$BIN" ps 2>&1) || daemon_required "ps"
assert_contains "$OUT" "ws_test" "server still running"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
