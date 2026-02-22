#!/usr/bin/env bash
# Docker-based cluster discovery test (manual — not CI)
#
# Builds the socketley image, starts a 3-node cluster via docker compose,
# verifies discovery and proxy routing, then tears down.
#
# Prerequisites: docker, docker compose
# Usage: bash test/docker/test_cluster_docker.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.cluster.yml"
PROJECT="socketley-cluster-test"
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    echo "Tearing down..."
    docker compose -f "$COMPOSE_FILE" -p "$PROJECT" down -v --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

assert_contains() {
    TOTAL=$((TOTAL+1))
    if echo "$1" | grep -q "$2"; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL: expected '$2' in output"
        echo "  GOT: $1"
    fi
}

echo "=== Docker cluster test ==="
echo ""

# ─── Build and start ──────────────────────────────────────────────────────────

echo "Building socketley image..."
docker compose -f "$COMPOSE_FILE" -p "$PROJECT" build --quiet

echo "Starting cluster (3 containers)..."
docker compose -f "$COMPOSE_FILE" -p "$PROJECT" up -d

# Wait for daemons + heartbeat cycle
echo "Waiting for cluster discovery (6s)..."
sleep 6

# ─── Test 1: cluster ls inside container ───────────────────────────────────────

echo "  Test 1: cluster ls"
OUT=$(docker compose -f "$COMPOSE_FILE" -p "$PROJECT" \
    exec -T gateway socketley cluster ls 2>&1)
assert_contains "$OUT" "api1"
assert_contains "$OUT" "api2"
assert_contains "$OUT" "gateway"

# ─── Test 2: cluster group api ─────────────────────────────────────────────────

echo "  Test 2: cluster group api"
OUT=$(docker compose -f "$COMPOSE_FILE" -p "$PROJECT" \
    exec -T gateway socketley cluster group api 2>&1)
assert_contains "$OUT" "api1"
assert_contains "$OUT" "api2"

# ─── Test 3: TCP connect through gateway proxy ─────────────────────────────────

echo "  Test 3: proxy routing"
TOTAL=$((TOTAL+1))
RC=0
echo "hello docker cluster" | nc -q 1 127.0.0.1 18080 2>/dev/null || RC=$?
if [ "$RC" -eq 0 ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [proxy connect]: nc exit code $RC"
fi

# ─── Test 4: check container logs for errors ───────────────────────────────────

echo "  Test 4: no errors in logs"
TOTAL=$((TOTAL+1))
LOGS=$(docker compose -f "$COMPOSE_FILE" -p "$PROJECT" logs 2>&1)
if echo "$LOGS" | grep -qi "segfault\|sigsegv\|abort\|fatal"; then
    FAIL=$((FAIL+1))
    echo "  FAIL: errors found in container logs"
    echo "$LOGS" | grep -i "segfault\|sigsegv\|abort\|fatal" | head -5
else
    PASS=$((PASS+1))
fi

# ─── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
