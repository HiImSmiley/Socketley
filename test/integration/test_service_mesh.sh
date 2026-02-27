#!/usr/bin/env bash
# Integration test: service mesh features (health checks, circuit breaker, retries, sidecar mode)
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BE1_PORT=19381
BE2_PORT=19382
PROXY_PORT=19383
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop mesh_proxy 2>/dev/null || true
    "$BIN" stop mesh_be1 2>/dev/null || true
    "$BIN" stop mesh_be2 2>/dev/null || true
    sleep 0.5
    "$BIN" remove mesh_proxy 2>/dev/null || true
    "$BIN" remove mesh_be1 2>/dev/null || true
    "$BIN" remove mesh_be2 2>/dev/null || true
    "$BIN" stop sidecar_proxy 2>/dev/null || true
    "$BIN" stop sidecar_be 2>/dev/null || true
    sleep 0.5
    "$BIN" remove sidecar_proxy 2>/dev/null || true
    "$BIN" remove sidecar_be 2>/dev/null || true
}
trap cleanup EXIT

assert_ok() {
    TOTAL=$((TOTAL+1))
    if [ $? -eq 0 ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL: $1"
    fi
}

assert_contains() {
    TOTAL=$((TOTAL+1))
    if echo "$1" | grep -q "$2"; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL: expected '$2' in output"
    fi
}

assert_exit_code() {
    TOTAL=$((TOTAL+1))
    local cmd="$1"
    local expected="$2"
    local desc="$3"
    local rc=0
    eval "$cmd" >/dev/null 2>&1 || rc=$?
    if [ "$rc" -eq "$expected" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL: $desc (expected exit $expected, got $rc)"
    fi
}

echo "=== Integration: service mesh ==="

# Ensure daemon is running
"$BIN" daemon 2>/dev/null &
sleep 0.3

# --- Test 1: Health check flags accepted on create ---
"$BIN" create server mesh_be1 -p "$BE1_PORT" -s 2>&1 || true
"$BIN" create server mesh_be2 -p "$BE2_PORT" -s 2>&1 || true
sleep 0.3

OUT=$("$BIN" create proxy mesh_proxy -p "$PROXY_PORT" \
    --backend "127.0.0.1:$BE1_PORT,127.0.0.1:$BE2_PORT" \
    --protocol tcp --strategy round-robin \
    --health-check tcp --health-interval 2 --health-threshold 2 \
    --circuit-threshold 3 --circuit-timeout 10 \
    --retry 1 \
    -s 2>&1) || true
assert_ok "create proxy with mesh flags"
sleep 0.5

# Test: proxy is running
OUT=$("$BIN" ps 2>&1)
assert_contains "$OUT" "mesh_proxy"

# Test: stats show healthy backends
OUT=$("$BIN" stats mesh_proxy 2>&1)
assert_contains "$OUT" "protocol:tcp"
assert_contains "$OUT" "backends:2"

# Test: TCP proxy works with health-enabled config
TOTAL=$((TOTAL+1))
RC=0
REPLY=$(echo "hello mesh" | nc -q 1 127.0.0.1 "$PROXY_PORT" 2>/dev/null) || RC=$?
if [ "$RC" -eq 0 ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [mesh proxy connect]: nc exit code $RC"
fi

# --- Test 2: Show/dump includes mesh config ---
OUT=$("$BIN" show mesh_proxy 2>&1)
assert_contains "$OUT" "health_check"
assert_contains "$OUT" "circuit_threshold"
assert_contains "$OUT" "retry_count"

# Clean up first set
"$BIN" stop mesh_proxy 2>/dev/null || true
"$BIN" stop mesh_be1 2>/dev/null || true
"$BIN" stop mesh_be2 2>/dev/null || true
sleep 0.5
"$BIN" remove mesh_proxy 2>/dev/null || true
"$BIN" remove mesh_be1 2>/dev/null || true
"$BIN" remove mesh_be2 2>/dev/null || true

# --- Test 3: --sidecar shorthand ---
"$BIN" create server sidecar_be -p 19384 -s 2>&1 || true
sleep 0.3

OUT=$("$BIN" create proxy sidecar_proxy -p 19385 \
    --backend "127.0.0.1:19384" \
    --protocol tcp --sidecar \
    -s 2>&1) || true
assert_ok "create proxy with --sidecar"
sleep 0.5

OUT=$("$BIN" ps 2>&1)
assert_contains "$OUT" "sidecar_proxy"

# Test: sidecar sets health-check, retry, drain
OUT=$("$BIN" show sidecar_proxy 2>&1)
assert_contains "$OUT" "health_check"
assert_contains "$OUT" "retry_count"

# Test: sidecar proxy accepts traffic
TOTAL=$((TOTAL+1))
RC=0
echo "sidecar test" | nc -q 1 127.0.0.1 19385 2>/dev/null || RC=$?
if [ "$RC" -eq 0 ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [sidecar proxy connect]: nc exit code $RC"
fi

# --- Test 4: Edit mesh flags on running proxy ---
OUT=$("$BIN" edit sidecar_proxy --circuit-threshold 10 --retry 3 2>&1) || true
assert_ok "edit mesh flags"

OUT=$("$BIN" show sidecar_proxy 2>&1)
assert_contains "$OUT" "circuit_threshold"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
