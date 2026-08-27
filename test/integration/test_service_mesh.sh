#!/usr/bin/env bash
# Integration test: service mesh features (health checks, circuit breaker, retries, sidecar mode)
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate mesh
BE1_PORT=$((SL_PORT_BASE+381))
BE2_PORT=$((SL_PORT_BASE+382))
PROXY_PORT=$((SL_PORT_BASE+383))
SIDECAR_BE_PORT=$((SL_PORT_BASE+384))
SIDECAR_PX_PORT=$((SL_PORT_BASE+385))
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
# and swallowing the cause is the same trade c76e965 spent 70 call sites undoing.
assert_contains() {
    TOTAL=$((TOTAL+1))
    if grep -q "$2" <<<"$1"; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL: expected '$2' in output"
        printf '%s\n' "${1:-<nothing>}" | sed 's/^/        got: /'
    fi
}

# mesh_counter RUNTIME FIELD
#
# One numeric field out of `stats`, or the empty string when the runtime is not
# there or the daemon did not answer.  Deliberately not 0 in that case: 0 is a
# legitimate reading of every counter here, and "there was nothing to read" must
# not compare equal to it — that substitution is how the checks below would go
# back to passing for the wrong reason.
mesh_counter() {
    local v
    v=$("$BIN" stats "$1" 2>/dev/null | sed -n "s/^$2:\([0-9][0-9]*\)$/\1/p" | head -1) || v=""
    printf '%s' "$v"
}

# mesh_sum_bytes_in RUNTIME...
#
# Combined bytes_in over the named backends, or the empty string if any one of
# them could not be read.  Summed because round-robin picks the backend and
# either choice is a pass; a partial sum is not a smaller number, it is no
# measurement, and it says so.
mesh_sum_bytes_in() {
    local total=0 rt v
    for rt in "$@"; do
        v=$(mesh_counter "$rt" bytes_in)
        if [ -z "$v" ]; then printf ''; return 0; fi
        total=$((total + v))
    done
    printf '%s' "$total"
}

# assert_proxy_served PROXY PORT PAYLOAD LABEL BACKEND...
#
# ─── What the old check could not tell apart ────────────────────────────────
#
#     RC=0
#     REPLY=$(echo "hello mesh" | nc -q 1 127.0.0.1 "$PROXY_PORT" 2>/dev/null) || RC=$?
#     if [ "$RC" -eq 0 ]; then PASS=$((PASS+1)); …
#
# $REPLY was captured and never read, so the entire assertion was nc's exit
# status — which is 0 for anything at all that accepts a TCP connection on that
# port.  It passed, in a staged run, against another agent's port-holder: a
# python process that accepted the connection and did nothing else.  A proxy
# whose backends were all down, or a create that was refused while a stranger
# held the port, are the same 0.  Connecting is not the claim.
#
# The claim is that the *mesh proxy* served it and forwarded it to a *mesh
# backend*, so the oracle is this daemon's own counters, which nothing outside
# this daemon can move:
#
#   * the proxy's total_connections goes up by exactly one.  A stranger holding
#     the port cannot produce that, because the connection never reached us.
#   * the payload's bytes arrive at one of the backends.  A proxy that accepts
#     and forwards nowhere cannot produce that.
#
# Health checks disturb neither number, and that was measured rather than
# assumed: they are outbound connections made by the proxy, so they are not
# counted by its listener, and they carry no payload, so an idle backend sits at
# bytes_in:0 across any number of them.
assert_proxy_served() {
    local proxy=$1 port=$2 payload=$3 label=$4; shift 4
    local n rc=0 c0 c1 b0 b1 i
    n=$(( ${#payload} + 1 ))          # printf adds the newline that is also sent

    c0=$(mesh_counter "$proxy" total_connections)
    b0=$(mesh_sum_bytes_in "$@")

    # `timeout` around nc, because `-q 1` only bounds the wait *after* the peer
    # has hung up.  A peer that accepts and then holds the connection open
    # forever — a stray port-holder is exactly that — leaves nc blocked with
    # nothing to time it out, and the file never reaches its Results line at
    # all.  Both forms of this check had that hang; a run that never reports is
    # worse than one that reports red, so the wait is bounded and whatever nc
    # exited with is carried into the failure message below.
    printf '%s\n' "$payload" | timeout 10 nc -q 1 127.0.0.1 "$port" >/dev/null 2>&1 || rc=$?

    # Wait for the counters to settle rather than sleeping a guess at how long
    # forwarding takes; on success this returns as soon as both have moved.
    c1=$c0; b1=$b0
    for i in $(seq 1 40); do
        c1=$(mesh_counter "$proxy" total_connections)
        b1=$(mesh_sum_bytes_in "$@")
        if [ -n "$c0" ] && [ -n "$c1" ] && [ -n "$b0" ] && [ -n "$b1" ] \
           && [ "$c1" -gt "$c0" ] && [ "$b1" -ge "$((b0 + n))" ]; then
            break
        fi
        sleep 0.1
    done

    TOTAL=$((TOTAL+1))
    if [ -z "$c0" ] || [ -z "$c1" ]; then
        FAIL=$((FAIL+1))
        echo "  FAIL [$label: the mesh proxy accepted the connection]: could not read"
        echo "        $proxy's total_connections (before='$c0' after='$c1') — stats did not"
        echo "        answer, so nothing was measured and nothing may be concluded"
    elif [ "$c1" -eq "$((c0 + 1))" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$label: the mesh proxy accepted the connection]: $proxy's"
        echo "        total_connections went $c0 -> $c1, wanted exactly one more (nc exited $rc)."
        echo "        Something may still be answering port $port — that is what the old"
        echo "        nc-exit-code check measured — but it is not this proxy."
    fi

    TOTAL=$((TOTAL+1))
    if [ -z "$b0" ] || [ -z "$b1" ]; then
        FAIL=$((FAIL+1))
        echo "  FAIL [$label: the payload reached a mesh backend]: could not read bytes_in"
        echo "        for $* (before='$b0' after='$b1') — stats did not answer"
    elif [ "$b1" -eq "$((b0 + n))" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$label: the payload reached a mesh backend]: bytes_in across $*"
        echo "        went $b0 -> $b1, wanted exactly $n more ($((b1 - b0)) arrived).  The"
        echo "        proxy took the connection but the payload did not reach a backend."
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
assert_proxy_served mesh_proxy "$PROXY_PORT" "hello mesh" "mesh proxy" mesh_be1 mesh_be2

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
create_ok "sidecar backend created" "$BIN" create server sidecar_be -p "$SIDECAR_BE_PORT" -s
sleep 0.3

create_ok "create proxy with --sidecar" \
    "$BIN" create proxy sidecar_proxy -p "$SIDECAR_PX_PORT" \
    --backend "127.0.0.1:$SIDECAR_BE_PORT" \
    --protocol tcp --sidecar \
    -s
sleep 0.5

OUT=$("$BIN" ps 2>&1)                    || daemon_required "ps"
assert_contains "$OUT" "sidecar_proxy"

# Test: sidecar sets health-check, retry, drain
OUT=$("$BIN" show sidecar_proxy 2>&1)    || daemon_required "show sidecar_proxy"
assert_contains "$OUT" "health_check"
assert_contains "$OUT" "retry_count"

# Test: sidecar proxy accepts traffic — the same claim about the same shape of
# check, so it gets the same oracle.  This one was not in the brief; it is the
# identical defect three lines further down the file, and leaving it would have
# meant fixing one of a matched pair.
assert_proxy_served sidecar_proxy "$SIDECAR_PX_PORT" "sidecar test" "sidecar proxy" sidecar_be

# --- Test 4: Edit mesh flags on running proxy ---
RC=0; OUT=$("$BIN" edit sidecar_proxy --circuit-threshold 10 --retry 3 2>&1) || RC=$?
assert_ok "$RC" "edit mesh flags" "$OUT"

OUT=$("$BIN" show sidecar_proxy 2>&1)    || daemon_required "show sidecar_proxy"
assert_contains "$OUT" "circuit_threshold"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
