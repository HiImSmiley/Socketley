#!/usr/bin/env bash
# Three containers, one daemon each, every one on the default socket path and
# sharing nothing but a Docker volume and a network -- which is what the
# integration suite cannot produce, since it tells its daemons apart by
# SOCKETLEY_SOCKET while here the only distinguishing facts are the address
# each node advertises out of gethostname and the file it writes to the volume.
# ─── WHAT THE ASSERTIONS ARE ────────────────────────────────────────────────
# The replies name the backend runtime that produced them, so the test reads
# which container answered rather than inferring it from a connection that did
# not fail -- and the negative half is checked both against the volume and
# against traffic, because traffic alone cannot tell cluster staleness from the
# proxy's own circuit breaker; requires docker and docker compose, with bash
# for /dev/tcp and no netcat.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.cluster.yml"
PROJECT="${COMPOSE_PROJECT:-socketley-cluster-test}"

# docker is not always usable without sudo (a developer machine where the user
# is not in the docker group); CI runners need no prefix at all.
DOCKER="${DOCKER:-docker}"

# Nothing in group `api` is published, so a reply naming a backend can only
# have arrived through the proxy.
export GW_PORT="${GW_PORT:-18080}"
export BUILD_JOBS="${BUILD_JOBS:-1}"

# A generous ceiling over the documented 10s threshold and 2s publish interval,
# but not generous enough to pass if staleness never happens.
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
# bash's /dev/tcp rather than netcat, because the reply is the assertion and a
# netcat that has to be told how long to wait is one more thing to be wrong
# about on another machine.
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
# Sample until the predicate holds and fail when the deadline passes, because
# every traffic claim here is about what routing settles to and a one-shot
# sample after a fixed sleep asserts the sleep length rather than the product.
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
# On the node's own ready line and by count rather than presence, because a
# restarted container appends to the same log and waiting for "a ready line"
# returns instantly for a node that has not come back.
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

# One publish interval, so every node has written its file and read the others'
# -- the only unconditional sleep in the file, and it is the product's own
# cycle rather than a guess about startup.
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
# The headline claim: both backends have to appear, and since the gateway
# container holds no member of group `api` every answer necessarily crossed a
# container boundary over an address that came out of the volume.

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

# SIGKILL rather than `compose stop`, because a graceful shutdown deletes the
# node's file and peers drop it immediately, while a killed node leaves a
# frozen heartbeat that only the 10s threshold can remove.

echo "  Test 3: a killed node goes stale within the documented window"
dc kill -s SIGKILL api2 >/dev/null 2>&1

# Proof that this is the stale path and not the unpublish path, without which
# everything below would pass for a reason that has nothing to do with
# heartbeats.
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

# The traffic half runs against a deadline because the CLI's view of the volume
# and the gateway daemon's own scan are two independent clocks, and what is
# asserted is that it settles at all inside a bound -- replies that come back
# empty while the dead member is still in rotation are the documented cost of
# the window.
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

# A container restart, a systemd Restart=on-failure and a crash loop all come
# back well inside the 10s threshold, where the node meets its own file still
# fresh under its own name -- a shape only this arrangement produces, since the
# container returns with a new pid namespace, the same hostname and the same
# default socket path.

echo "  Test 5: a node restarted inside the staleness window rejoins"

READY_BEFORE=$(ready_count api2 api2)
dc kill -s SIGKILL api2 >/dev/null 2>&1
dc start api2 >/dev/null 2>&1

RESTARTED=0
if wait_ready api2 api2 $((READY_BEFORE + 1)) 60; then
    ok "api2 came back up and reported ready"
    RESTARTED=1
else
    bad "api2 never came back — a node refused its own name takes the container"
    bad "down under set -e, which is what this assertion is for"
fi

# Proof that the window was actually reached, polled rather than read once
# because the reclaim line reaches the container's log a moment after the ready
# line this test waited on.
RECLAIM_DEADLINE=$((SECONDS + 15))
RECLAIMED=0
while [ "$SECONDS" -lt "$RECLAIM_DEADLINE" ]; do
    LOG_API2=$(dc logs --no-log-prefix api2 2>/dev/null)
    if printf '%s\n' "$LOG_API2" | grep -q 'reclaiming "api2" from this node'; then
        RECLAIMED=1
        break
    fi
    sleep 0.5
done

if [ "$RECLAIMED" -eq 1 ]; then
    ok "the rejoin went through the reclaim path — its own entry was still fresh"
    printf '%s\n' "$LOG_API2" | grep 'reclaiming "api2"' | sed 's/^/        /'
else
    bad "no reclaim in api2's log: either the entry aged out before the restart"
    bad "got there (this run tested nothing), or the rejoin took another path"
    printf '%s\n' "$LOG_API2" | tail -12 | sed 's/^/          /'
fi

if printf '%s\n' "$LOG_API2" | grep -q "name may already be in use\|cluster mode not enabled"; then
    bad "api2 was refused its own name inside the window"
else
    ok "api2 was not refused its own name"
fi

if [ "$RESTARTED" -eq 1 ]; then
    if converge "$REJOIN_DEADLINE" has_web2; then
        ok "api2 was taking traffic again ${CONVERGED_AT}s after the restart"
    else
        bad "api2 rejoined the volume but never took traffic again"
        printf '%s\n' "$CONVERGED_REPLIES" | sed 's/^/          /'
    fi
fi

# Asserting the removal happens well inside the 10s threshold is what tells a
# graceful shutdown apart from a killed node, whose entry could only age out
# later than this bound allows.

echo "  Test 6: a graceful stop unpublishes rather than going stale"
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

# ─── Test 7: nothing crashed ──────────────────────────────────────────────────

echo "  Test 7: no crashes in container logs"
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
