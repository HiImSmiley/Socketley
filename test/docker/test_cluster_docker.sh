#!/usr/bin/env bash
# Cluster discovery in the shape the man page documents.
#
# Three containers, one daemon each, every one of them on the DEFAULT socket
# path, sharing nothing but a Docker volume and a network.  Two backends carry
# group `api`; the gateway runs a proxy with `--backend @api` and is the only
# container with a published port.
#
# ─── WHAT THIS PROVES THAT test/integration/test_cluster.sh CANNOT ──────────
#
# The integration suite runs several daemons inside one filesystem namespace,
# told apart by SOCKETLEY_SOCKET.  That is the development simulation of a
# cluster and it is the only thing the suite has ever covered.  In the shape
# this file runs, every daemon is /run/socketley/socketley.sock and the only
# things that distinguish nodes are the network address each one advertises out
# of gethostname(3) and the file it writes to the shared volume.  Nothing else
# in the tree exercises that.
#
# ─── WHAT THE ASSERTIONS ARE ────────────────────────────────────────────────
#
# The claim is the product's, not the script's: a runtime on one daemon is
# reachable through a proxy on another, discovered only through the volume.  So
# the replies carry the name of the backend runtime that produced them
# (test/docker/identity.lua), and the test reads which container answered
# rather than inferring it from a connection that did not fail.  The previous
# version of this file asserted `nc` exit status 0 against a gateway proxy,
# which is true of a proxy with no backends at all.
#
# The negative half matters as much: a member whose container is killed stops
# receiving traffic within the 10s staleness window the man page documents, and
# starts again when it comes back.  Both halves are checked twice over, once
# against the volume (which involves no proxy at all) and once against traffic
# through the gateway — because traffic alone would not distinguish cluster
# staleness from the proxy's own circuit breaker ejecting a backend that had
# stopped answering, and the volume view is what makes it a cluster claim.
#
# Prerequisites: docker, docker compose.  bash for /dev/tcp; no netcat.
# Usage: bash test/docker/test_cluster_docker.sh
#        DOCKER="sudo -n docker" bash test/docker/test_cluster_docker.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.cluster.yml"
PROJECT="${COMPOSE_PROJECT:-socketley-cluster-test}"

# docker is not always usable without sudo (a developer machine where the user
# is not in the docker group); CI runners need no prefix at all.
DOCKER="${DOCKER:-docker}"

# The host-side port the gateway is published on, and the one every request in
# this file goes to.  Nothing in group `api` is published, so a reply naming a
# backend can only have arrived through the proxy.
export GW_PORT="${GW_PORT:-18080}"
export BUILD_JOBS="${BUILD_JOBS:-1}"

# The documented threshold is 10s and the publish interval is 2s, so a killed
# member is expected out within about 12s.  The ceiling is generous because a
# loaded machine is allowed to be slow; it is not generous enough to pass if
# staleness never happens.
STALE_DEADLINE="${STALE_DEADLINE:-25}"
REJOIN_DEADLINE="${REJOIN_DEADLINE:-25}"
REQ_TIMEOUT=5

PASS=0; FAIL=0; TOTAL=0

dc() { $DOCKER compose -f "$COMPOSE_FILE" -p "$PROJECT" "$@"; }

cleanup() {
    echo "Tearing down..."
    dc down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "    ok: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "    FAIL: $1"; }

assert_contains() {   # assert_contains HAYSTACK NEEDLE LABEL
    if printf '%s' "$1" | grep -q -- "$2"; then
        ok "$3"
    else
        bad "$3 — expected '$2' in:"
        printf '%s\n' "$1" | sed 's/^/          /'
    fi
}

# ─── One request through the gateway ─────────────────────────────────────────
#
# bash's /dev/tcp rather than netcat: the reply is the assertion here, and a
# netcat that has to be told how long to wait for it with -q is one more thing
# to be wrong about on a machine with a different netcat.  Prints the reply
# line, or nothing if the connection failed or nothing came back — which is a
# distinction the caller makes, not this function.
req() {
    local reply=""
    exec 3<>"/dev/tcp/127.0.0.1/$GW_PORT" 2>/dev/null || { printf '\n'; return 0; }
    printf 'who\n' >&3 2>/dev/null
    IFS= read -r -t "$REQ_TIMEOUT" reply <&3 2>/dev/null || reply=""
    exec 3<&- 2>/dev/null
    exec 3>&- 2>/dev/null
    printf '%s\n' "$reply"
}

sample() {  # sample N -> N lines, one reply each (possibly empty)
    local n=$1 i
    for ((i = 0; i < n; i++)); do
        req
    done
}

# ─── Sampling against a deadline ─────────────────────────────────────────────
#
# Every traffic claim in this file is about what routing settles to, not about
# what it is at some instant, because none of the moments involved are ones a
# test gets to pick.  A member's file is written every 2s, read on the peer's
# own 2s timer, and only then does the endpoint table reach the proxy — a
# cold-started cluster takes about two seconds after its last node reports
# ready before both backends are in rotation, and a killed one takes the 10s
# threshold plus a cycle.
#
# So: sample until the predicate holds, and fail when the deadline passes.  The
# deadline is the assertion — not the sleep length, which is what a one-shot
# sample after a fixed sleep is really asserting, and which passes or fails
# with the machine's load rather than with the product.
#
# converge SECONDS PREDICATE_FN  ->  sets CONVERGED_REPLIES and CONVERGED_AT
converge() {
    local timeout=$1 pred=$2
    local started=$SECONDS
    CONVERGED_REPLIES=""
    while [ $((SECONDS - started)) -lt "$timeout" ]; do
        CONVERGED_REPLIES=$(sample 8)
        if "$pred" "$CONVERGED_REPLIES"; then
            CONVERGED_AT=$((SECONDS - started))
            return 0
        fi
        sleep 1
    done
    CONVERGED_AT=$((SECONDS - started))
    return 1
}

# Both backends answered, and nothing else did, and nothing went unanswered.
both_backends() {
    printf '%s' "$1" | grep -q '^web1$' &&
    printf '%s' "$1" | grep -q '^web2$' &&
    [ "$(printf '%s\n' "$1" | grep -cv '^web[12]$')" -eq 0 ]
}

# Only the surviving backend answered, every time.
only_web1() {
    [ "$(printf '%s\n' "$1" | grep -cv '^web1$')" -eq 0 ]
}

# The rejoined backend is taking traffic again.
has_web2() {
    printf '%s' "$1" | grep -q '^web2$'
}

# ─── Readiness ───────────────────────────────────────────────────────────────
#
# On the node's own "ready" line, printed after its daemon is serving, after it
# has been named and joined to the cluster, and after its runtime is started.
#
# By count, not by presence: `docker compose start` on a container that was
# killed restarts the same container and its log is appended to, so the ready
# line from the first boot is still there.  Waiting for "a ready line" would
# return instantly for a node that has not come back yet, and every assertion
# after that would be measuring the gap rather than the rejoin.
ready_count() {  # ready_count SERVICE NAME
    dc logs --no-log-prefix "$1" 2>/dev/null | grep -c "node $2 ready"
}

wait_ready() {   # wait_ready SERVICE NAME MIN_COUNT [TIMEOUT]
    local svc=$1 name=$2 want=$3 timeout=${4:-180}
    local deadline=$((SECONDS + timeout))
    while [ "$SECONDS" -lt "$deadline" ]; do
        [ "$(ready_count "$svc" "$name")" -ge "$want" ] && return 0
        sleep 0.5
    done
    echo "  FATAL: $svc never reported ready (wanted $want occurrences)"
    dc logs --tail 40 "$svc" 2>&1 | sed 's/^/         /'
    return 1
}

echo "=== Docker cluster test ==="
echo ""

# ─── Build and start ──────────────────────────────────────────────────────────

echo "Building socketley image (BUILD_JOBS=$BUILD_JOBS)..."
if ! dc build api1; then
    echo "  FATAL: image build failed"
    exit 2
fi

echo "Starting cluster (3 containers)..."
dc up -d >/dev/null 2>&1 || { echo "  FATAL: compose up failed"; dc logs 2>&1 | tail -40; exit 2; }

wait_ready api1    api1    1 || exit 2
wait_ready api2    api2    1 || exit 2
wait_ready gateway gateway 1 || exit 2

# One publish interval, so that every node has written its file and read the
# others'.  This is the only unconditional sleep in the file and it is the
# product's own 2s cycle, not a guess about startup.
sleep 3

# ─── Test 1: the volume is the discovery channel ───────────────────────────────

echo "  Test 1: discovery through the shared volume"
OUT=$(dc exec -T gateway socketley cluster ls 2>&1)
assert_contains "$OUT" "api1"    "gateway sees api1"
assert_contains "$OUT" "api2"    "gateway sees api2"
assert_contains "$OUT" "gateway" "gateway sees itself"

# The advertised address, not just the name: this is what a proxy on another
# node dials, and it comes from gethostname(3) inside the peer's container.
assert_contains "$OUT" "api1 *api1"  "api1 advertises a routable host"
assert_contains "$OUT" "api2 *api2"  "api2 advertises a routable host"

OUT=$(dc exec -T gateway socketley cluster group api 2>&1)
assert_contains "$OUT" "web1" "group api contains api1's runtime"
assert_contains "$OUT" "web2" "group api contains api2's runtime"

# ─── Test 2: cross-node routing ───────────────────────────────────────────────
#
# The headline claim.  Eight requests into the published gateway port; the
# replies name the container that produced them.  Both backends have to appear,
# because the gateway container has no member of group `api` of its own —
# every answer necessarily crossed a container boundary, over an address that
# came out of the volume.

echo "  Test 2: a request to the gateway is answered by a backend on another node"
if converge 30 both_backends; then
    ok "both remote backends answered, ${CONVERGED_AT}s after the last node was ready"
    echo "        replies: $(printf '%s' "$CONVERGED_REPLIES" | tr '\n' ' ')"
else
    bad "routing never reached both remote backends within 30s"
    printf '%s\n' "$CONVERGED_REPLIES" | sed 's/^/          /'
    echo "        (an empty reply is a connection the gateway accepted and had"
    echo "         no live group member to hand to)"
fi

# ─── Test 3: a killed member goes stale and stops receiving traffic ───────────
#
# SIGKILL, not `compose stop`: a graceful shutdown deletes the node's file and
# the peers drop it immediately, which is the OTHER row of the stale-detection
# table.  Killed, the file stays behind with a frozen heartbeat and the only
# thing that can remove the member is the 10s threshold — which is the
# mechanism under test.

echo "  Test 3: a killed node goes stale within the documented window"
dc kill -s SIGKILL api2 >/dev/null 2>&1

# Proof that this is the stale path and not the unpublish path: the file the
# dead daemon wrote is still on the volume.  If it were gone, everything below
# would pass for a reason that has nothing to do with heartbeats.
FILES=$(dc exec -T gateway ls /cluster 2>&1)
assert_contains "$FILES" "api2.json" "the killed node left its file behind"

STARTED=$SECONDS
STALE_OUT=""
while [ $((SECONDS - STARTED)) -lt "$STALE_DEADLINE" ]; do
    STALE_OUT=$(dc exec -T gateway socketley cluster ls 2>&1)
    if ! printf '%s\n' "$STALE_OUT" | grep '^api2' | grep -qv "stale"; then
        break
    fi
    sleep 1
done
ELAPSED=$((SECONDS - STARTED))

if [ "$ELAPSED" -lt "$STALE_DEADLINE" ]; then
    ok "api2 was dropped or marked stale after ${ELAPSED}s (threshold 10s)"
else
    bad "api2 was still healthy ${ELAPSED}s after being killed"
    printf '%s\n' "$STALE_OUT" | sed 's/^/          /'
fi

# And the traffic half.  Against a deadline, because the CLI's staleness view
# above is read straight off the volume by the CLI process and says nothing
# about when the gateway daemon's own scan runs, drops the member and pushes a
# new endpoint table to the proxy.  Those are two independent clocks and only
# one of them is the one that stops traffic.
#
# What is asserted is that it settles at all, and inside a bound: every one of
# eight consecutive requests answered, and answered by the survivor.  While the
# dead member is still in rotation some of them come back empty, which is the
# documented cost of the window and not a failure.
if converge "$STALE_DEADLINE" only_web1; then
    ok "traffic settled on the survivor ${CONVERGED_AT}s after the kill"
    echo "        replies: $(printf '%s' "$CONVERGED_REPLIES" | tr '\n' ' ')"
else
    bad "requests were still reaching the killed node, or failing, after ${STALE_DEADLINE}s"
    printf '%s\n' "$CONVERGED_REPLIES" | sed 's/^/          /'
fi

# ─── Test 4: it comes back ────────────────────────────────────────────────────

echo "  Test 4: the node rejoins when its container comes back"
dc start api2 >/dev/null 2>&1
wait_ready api2 api2 2 60 || exit 2

if converge "$REJOIN_DEADLINE" has_web2; then
    ok "api2 was answering again ${CONVERGED_AT}s after its container came back"
else
    bad "api2 never took traffic again within ${REJOIN_DEADLINE}s"
    printf '%s\n' "$CONVERGED_REPLIES" | sed 's/^/          /'
fi

# ─── Test 5: a graceful shutdown is not the same mechanism ────────────────────
#
# The man page distinguishes "graceful shutdown → file deleted → immediate"
# from "container killed → stale heartbeat → ~10 seconds".  Asserting the
# removal happens well inside the 10s threshold is what tells the two apart:
# aged out would take longer than this bound allows.

echo "  Test 5: a graceful stop unpublishes rather than going stale"
dc stop -t 10 api2 >/dev/null 2>&1
STARTED=$SECONDS
GONE=0
while [ $((SECONDS - STARTED)) -lt 6 ]; do
    if ! dc exec -T gateway ls /cluster 2>/dev/null | grep -q "api2.json"; then
        GONE=1
        break
    fi
    sleep 0.5
done

if [ "$GONE" -eq 1 ]; then
    ok "api2 deleted its own file in $((SECONDS - STARTED))s, inside the 10s threshold"
else
    bad "api2's file was still on the volume 6s after SIGTERM (it aged out instead)"
fi

# ─── Test 6: nothing crashed ──────────────────────────────────────────────────

echo "  Test 6: no crashes in container logs"
LOGS=$(dc logs 2>&1)
CRASH=$(printf '%s\n' "$LOGS" | grep -i "segfault\|sigsegv\|core dumped\|terminate called\|Assertion.*failed")
if [ -z "$CRASH" ]; then
    ok "no crash markers"
else
    bad "crash markers in container logs"
    printf '%s\n' "$CRASH" | head -5 | sed 's/^/          /'
fi

# ─── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
