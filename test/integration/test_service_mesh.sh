#!/usr/bin/env bash
# Integration test: service mesh features (health checks, circuit breaker, retries, sidecar mode)
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
daemon_isolate mesh
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
    daemon_stop
}
trap cleanup EXIT

# assert_ok STATUS LABEL [OUTPUT]
#
# The status is passed in.  It used to be read from $? inside the function, one
# line after `TOTAL=$((TOTAL+1))` — and an assignment is a command, so $? was the
# status of the arithmetic and never anything else.  All three uses below —
# creating the mesh proxy, creating the sidecar, editing the mesh flags — passed
# unconditionally, and each of their callers also ended in `|| true`.
assert_ok() {
    TOTAL=$((TOTAL+1))
    local rc="$1" label="$2" out="${3:-}"
    if [ "$rc" -eq 0 ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$label]: exit $rc"
        # An `if` rather than `[ -n … ] && printf`: the latter is the last
        # command of the function, so an empty message would make the function
        # return 1 and `set -e` would end the run at the first failed assertion.
        if [ -n "$out" ]; then printf '        said: %s\n' "$out"; fi
    fi
}

# The output goes out on failure, not just the pattern that was missing.  Every
# caller below is fed by a CLI command that is allowed to fail, and when one
# does, $1 holds the reason — `no such runtime: mesh_proxy` — while "expected
# 'protocol:tcp' in output" describes only the symptom.  Printing the pattern
# and swallowing the cause is the same trade ba7a147 spent 70 call sites undoing.
assert_contains() {
    TOTAL=$((TOTAL+1))
    if echo "$1" | grep -q "$2"; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL: expected '$2' in output"
        printf '%s\n' "${1:-<nothing>}" | sed 's/^/        got: /'
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
daemon_start "$BIN"

# --- Test 1: Health check flags accepted on create ---
create_ok "backend 1 created" "$BIN" create server mesh_be1 -p "$BE1_PORT" -s
create_ok "backend 2 created" "$BIN" create server mesh_be2 -p "$BE2_PORT" -s
sleep 0.3

create_ok "create proxy with mesh flags" \
    "$BIN" create proxy mesh_proxy -p "$PROXY_PORT" \
    --backend "127.0.0.1:$BE1_PORT,127.0.0.1:$BE2_PORT" \
    --protocol tcp --strategy round-robin \
    --health-check tcp --health-interval 2 --health-threshold 2 \
    --circuit-threshold 3 --circuit-timeout 10 \
    --retry 1 \
    -s
sleep 0.5

# Test: proxy is running
#
# ─── Why every capture below carries a `|| daemon_required` ─────────────────
#
# `OUT=$(cmd)` alone on a line is a simple command whose exit status is the
# substitution's, so under `set -euo pipefail` a failing CLI command ended this
# file *at the assignment*: no assertion, no `Results`, no `OK`/`FAILED`.  With
# the proxy's port held so its create was refused, that is what this file did —
#
#     FAIL [create proxy with mesh flags]: create refused, exit 2 …
#     FAIL: expected 'mesh_proxy' in output
#     (nothing — gone at `OUT=$("$BIN" stats mesh_proxy 2>&1)`)
#
# — two assertions out of eighteen, and the entire --sidecar half of the file,
# which shares nothing with the proxy that failed, never ran or reported.
#
# `|| true` would fix the abort and cost the distinction that matters: a `stats`
# that fails because the runtime is missing is a finding the assertion below
# states precisely, while a `stats` that fails because the daemon died makes the
# fourteen assertions after it noise.  daemon_required tells those apart, lets
# the first carry on, and stops the second *with a summary* rather than by
# evaporating.
OUT=$("$BIN" ps 2>&1)                    || daemon_required "ps"
assert_contains "$OUT" "mesh_proxy"

# Test: stats show healthy backends
OUT=$("$BIN" stats mesh_proxy 2>&1)      || daemon_required "stats mesh_proxy"
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
OUT=$("$BIN" show mesh_proxy 2>&1)       || daemon_required "show mesh_proxy"
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
create_ok "sidecar backend created" "$BIN" create server sidecar_be -p 19384 -s
sleep 0.3

create_ok "create proxy with --sidecar" \
    "$BIN" create proxy sidecar_proxy -p 19385 \
    --backend "127.0.0.1:19384" \
    --protocol tcp --sidecar \
    -s
sleep 0.5

OUT=$("$BIN" ps 2>&1)                    || daemon_required "ps"
assert_contains "$OUT" "sidecar_proxy"

# Test: sidecar sets health-check, retry, drain
OUT=$("$BIN" show sidecar_proxy 2>&1)    || daemon_required "show sidecar_proxy"
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
RC=0; OUT=$("$BIN" edit sidecar_proxy --circuit-threshold 10 --retry 3 2>&1) || RC=$?
assert_ok "$RC" "edit mesh flags" "$OUT"

OUT=$("$BIN" show sidecar_proxy 2>&1)    || daemon_required "show sidecar_proxy"
assert_contains "$OUT" "circuit_threshold"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
