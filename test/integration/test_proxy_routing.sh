#!/usr/bin/env bash
# Integration test: proxy routing (TCP round-robin)
#
# Runs its own daemon on its own socket and state directory, like the rest of
# this directory.  On the shared socket this file did not test what it says it
# tests: `create` on a name that already exists fails, every failure here is
# swallowed by `|| true`, and the assertions that follow are satisfied by
# whatever `ps` happens to list -- so a run against a daemon that already had
# proxy_be1 from an earlier run passed while creating nothing.  It could also
# not be run beside anything else, which is how it came to be skipped.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_ready.sh"
# For daemon_required only.  This file keeps its own inline isolation — it is the
# one the library was generalised from — and sourcing defines functions without
# running anything, so nothing here changes hands.
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")

TMPD=$(mktemp -d /tmp/socketley-routing-XXXXXX)
export HOME="$TMPD/home"
export SOCKETLEY_SOCKET="$TMPD/daemon.sock"
mkdir -p "$HOME"
DLOG="$TMPD/daemon.log"
DPID=""

# Ports come off one base so two runs can share a machine.  The socket and the
# state directory are already per-run; the ports were the one thing left that
# made a second run collide with the first, and a collision here looks exactly
# like a proxy that will not forward.
PORT_BASE=$((SL_PORT_BASE+260))
BE1_PORT=$((PORT_BASE+1))
BE2_PORT=$((PORT_BASE+2))
TCP_PROXY_PORT=$((PORT_BASE+3))
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    if [ -n "$DPID" ]; then
        kill "$DPID" 2>/dev/null || true
        for _ in $(seq 1 50); do kill -0 "$DPID" 2>/dev/null || break; sleep 0.1; done
        kill -9 "$DPID" 2>/dev/null || true
        wait "$DPID" 2>/dev/null || true
    fi
    # Kill by socket, not only by pid.  Every CLI command except `daemon`,
    # `version` and `help` auto-starts a daemon when the socket does not answer,
    # forking and setsid-ing one detached from this shell; killing $DPID alone
    # would leave that one running for good, holding this test's ports and
    # answering for a state directory that is about to be deleted.
    #
    # Matched by exact process name and by this run's socket, never by a
    # command-line pattern: `pgrep -f 'socketley daemon'` also matches any shell
    # whose own command line carries that string -- including a test runner --
    # and a -f match that is one character too broad kills the run doing the
    # matching.  The socket path comes from mktemp, so the environ check below
    # can only ever hit daemons belonging to this run.
    for p in $(pgrep -x socketley 2>/dev/null || true); do
        case "$(tr '\0' ' ' <"/proc/$p/cmdline" 2>/dev/null)" in
            *" daemon "*|*" daemon") ;;
            *) continue ;;
        esac
        if grep -qx "SOCKETLEY_SOCKET=$SOCKETLEY_SOCKET" \
                < <(tr '\0' '\n' <"/proc/$p/environ" 2>/dev/null); then
            kill -9 "$p" 2>/dev/null || true
        fi
    done
    rm -rf "$TMPD"
}
trap cleanup EXIT

ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

assert_contains() {
    if grep -q "$2" <<<"$1"; then ok; else bad "$3" "expected '$2' in output"; fi
}

# counter RUNTIME FIELD
#
# One numeric field out of `stats`, or the empty string when the runtime is not
# there or the daemon did not answer.  Deliberately not 0 in that case: 0 is a
# legitimate reading of every counter here, and "there was nothing to read" must
# not compare equal to it -- that substitution is how the check below would go
# back to passing for the wrong reason.
counter() {
    local v
    v=$("$BIN" stats "$1" 2>/dev/null | sed -n "s/^$2:\([0-9][0-9]*\)$/\1/p" | head -1) || v=""
    printf '%s' "$v"
}

# sum_bytes_in RUNTIME...
#
# Combined bytes_in over the named backends, or the empty string if any one of
# them could not be read.  Summed because round-robin picks the backend and
# either choice is a pass; a partial sum is not a smaller number, it is no
# measurement, and it says so.
sum_bytes_in() {
    local total=0 rt v
    for rt in "$@"; do
        v=$(counter "$rt" bytes_in)
        if [ -z "$v" ]; then printf ''; return 0; fi
        total=$((total + v))
    done
    printf '%s' "$total"
}

echo "=== Integration: proxy routing ==="

# Wait on the daemon's own log line, never by polling with a CLI command: a CLI
# command run before the socket answers starts a daemon of its own, so polling
# with one races the daemon this test just launched.  "daemon started" is
# printed after the IPC socket is bound and after any state is restored, so it
# is the readiness signal and it comes from this process rather than from a
# socket path someone else might own.
"$BIN" daemon >"$DLOG" 2>&1 &
DPID=$!
for _ in $(seq 1 100); do
    grep -q "daemon started" "$DLOG" 2>/dev/null && break
    sleep 0.1
done

TOTAL=$((TOTAL+1))
if [ -S "$SOCKETLEY_SOCKET" ] && kill -0 "$DPID" 2>/dev/null; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [setup]: this test's own daemon never came up; everything below"
    echo "        would be measuring whatever else is on the machine"
    tail -5 "$DLOG" 2>/dev/null | sed 's/^/        /' || true
fi

# Create two backend servers.  Checked rather than swallowed: on a fresh daemon
# a create that fails is a real failure, and the `ps` assertions below cannot
# tell a runtime this test made from one that was already there.
create() {
    local why=$1; shift
    if "$BIN" create "$@" >/dev/null 2>&1; then ok; else bad "$why" "create failed"; fi
}

create "backend 1 created" server proxy_be1 -p "$BE1_PORT" -s
create "backend 2 created" server proxy_be2 -p "$BE2_PORT" -s
ready_tcp 127.0.0.1 "$BE1_PORT" 10 || true
ready_tcp 127.0.0.1 "$BE2_PORT" 10 || true

# Create TCP proxy with round-robin strategy
create "proxy created" proxy proxy_tcp -p "$TCP_PROXY_PORT" \
    --backend "127.0.0.1:$BE1_PORT,127.0.0.1:$BE2_PORT" \
    --protocol tcp --strategy round-robin -s
ready_tcp 127.0.0.1 "$TCP_PROXY_PORT" 10 || true

# Test: All 3 runtimes show in ps
#
# A lone `OUT=$(cmd)` takes its exit status from the substitution; the guard is
# what keeps a failing `ps` from ending the file before its `Results` line.
OUT=$("$BIN" ps 2>&1) || daemon_required "ps"
assert_contains "$OUT" "proxy_be1" "backend 1 in ps"
assert_contains "$OUT" "proxy_be2" "backend 2 in ps"
assert_contains "$OUT" "proxy_tcp" "proxy in ps"

# Test: TCP proxy accepts connections and forwards to a backend
#
# ─── What the old check could not tell apart ────────────────────────────────
#
#     RC=0
#     echo "hello proxy" | nc -q 1 127.0.0.1 "$TCP_PROXY_PORT" 2>/dev/null || RC=$?
#     if [ "$RC" -eq 0 ]; then ok; else bad "TCP proxy connect" "nc exit code $RC"; fi
#
# The entire assertion was nc's exit status, which is 0 for anything at all that
# accepts a TCP connection on that port.  Staged: with a foreign process holding
# the proxy's port so `create proxy` was refused and proxy_tcp never existed,
# this file printed 6/8 and `TCP proxy connect` was not one of the two.  It passed
# against a stranger.  Connecting is not the claim.
#
# The claim is that *this* proxy served the connection and forwarded it to *this
# test's* backend, so the oracle is this daemon's own counters, which nothing
# outside this daemon can move:
#
#   * proxy_tcp's total_connections goes up by exactly one.  A stranger holding
#     the port cannot produce that, because the connection never reached us.
#   * the payload's bytes arrive at a backend.  A proxy that accepts and
#     forwards nowhere cannot produce that.
#
# Summed over both backends because round-robin picks which one gets it and
# either choice is a pass.
PAYLOAD="hello proxy"
NBYTES=$(( ${#PAYLOAD} + 1 ))        # echo adds the newline that is also sent
# The baseline has to be a SETTLED reading, not an instantaneous one.
#
# ready_tcp above uses `nc -z`, which opens a connection and closes it — that is
# how it knows the port answers — so the proxy has already counted one by the
# time this line runs, and the baseline has to include it.
#
# The counter is read at print time on both paths now: a worker stores its line
# into shared memory once per turn of its event loop and `stats` sums the slots
# as it prints.  What is left to settle is the worker's own loop, not a publish
# interval — the accept is counted on the turn that reaps it, and `nc -z`'s
# close is counted on a later one — so the value can still be moving for a few
# turns after the probe returns.
#
# Two agreeing readings are not enough on their own: they can both fall between
# the accept and the close.  Three readings across two gaps is the cheap way to
# be sure, and the gaps no longer have to out-wait anything.
settle_counter() {                 # name key -> the value, once three agree
    local cur="" same=0 prev=""
    for _ in $(seq 1 30); do
        cur=$(counter "$1" "$2")
        if [ -n "$cur" ] && [ "$cur" = "$prev" ]; then
            same=$((same + 1))
            [ "$same" -ge 2 ] && { printf '%s' "$cur"; return 0; }
        else
            same=0
        fi
        prev=$cur
        sleep 0.4
    done
    printf '%s' "$cur"
}
C0=$(settle_counter proxy_tcp total_connections)
B0=$(sum_bytes_in proxy_be1 proxy_be2)

# `timeout` around nc, because `-q 1` only bounds the wait *after* the peer has
# hung up.  A peer that accepts and then holds the connection open forever -- a
# stray port-holder is exactly that -- leaves nc blocked with nothing to time it
# out, and the file never reaches its `Results` line at all.  Staged against such
# a peer the old form wedged until it was killed at 60s, having printed two
# FAILs and no summary.  A run that never reports is worse than one that reports
# red, so the wait is bounded and nc's status is carried into the message below
# as a symptom rather than used as the verdict.
RC=0
printf '%s\n' "$PAYLOAD" | timeout 10 nc -q 1 127.0.0.1 "$TCP_PROXY_PORT" >/dev/null 2>&1 || RC=$?

# Wait for the counters to settle rather than sleeping a guess at how long
# forwarding takes; on success this returns as soon as both have moved.
C1=$C0; B1=$B0
for _ in $(seq 1 40); do
    C1=$(counter proxy_tcp total_connections)
    B1=$(sum_bytes_in proxy_be1 proxy_be2)
    if [ -n "$C0" ] && [ -n "$C1" ] && [ -n "$B0" ] && [ -n "$B1" ] \
       && [ "$C1" -gt "$C0" ] && [ "$B1" -ge "$((B0 + NBYTES))" ]; then
        break
    fi
    sleep 0.1
done

if [ -z "$C0" ] || [ -z "$C1" ]; then
    bad "TCP proxy accepted the connection" \
        "could not read proxy_tcp's total_connections (before='$C0' after='$C1') — stats did not answer, so nothing was measured"
elif [ "$C1" -eq "$((C0 + 1))" ]; then
    ok
else
    bad "TCP proxy accepted the connection" \
        "proxy_tcp's total_connections went $C0 -> $C1, wanted exactly one more (nc exited $RC); something may still answer port $TCP_PROXY_PORT, but it is not this proxy"
fi

if [ -z "$B0" ] || [ -z "$B1" ]; then
    bad "payload reached a backend" \
        "could not read bytes_in for proxy_be1/proxy_be2 (before='$B0' after='$B1') — stats did not answer"
elif [ "$B1" -eq "$((B0 + NBYTES))" ]; then
    ok
else
    bad "payload reached a backend" \
        "bytes_in across proxy_be1+proxy_be2 went $B0 -> $B1, wanted exactly $NBYTES more ($((B1 - B0)) arrived); the proxy took the connection but the payload did not reach a backend"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
