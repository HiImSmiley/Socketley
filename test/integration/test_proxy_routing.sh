#!/usr/bin/env bash
# Its own daemon on its own socket and state directory, because on the shared
# one a `create` for a name an earlier run had left behind failed into `||
# true` and every assertion was satisfied by whatever `ps` happened to list.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_ready.sh"
# For daemon_required only: this file keeps its own inline isolation, and
# sourcing defines functions without running anything.
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")

TMPD=$(mktemp -d /tmp/socketley-routing-XXXXXX)
export HOME="$TMPD/home"
export SOCKETLEY_SOCKET="$TMPD/daemon.sock"
mkdir -p "$HOME"
DLOG="$TMPD/daemon.log"
DPID=""

# Ports come off one base so two runs can share a machine, because a collision
# here looks exactly like a proxy that will not forward.
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
    # Killed by socket as well as by pid and matched on exact process name,
    # because a CLI command against an absent daemon starts a detached one that
    # would hold this test's ports, and a `pgrep -f` pattern one character too
    # broad kills the run doing the matching.
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

# One numeric field out of `stats`, empty rather than 0 when it could not be
# read, because 0 is a legitimate reading of every counter here.
counter() {
    local v
    v=$("$BIN" stats "$1" 2>/dev/null | sed -n "s/^$2:\([0-9][0-9]*\)$/\1/p" | head -1) || v=""
    printf '%s' "$v"
}

# Combined bytes_in over the named backends, or empty if any could not be read,
# because round-robin picks the backend and a partial sum is no measurement
# rather than a smaller number.
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

# Wait on the daemon's own log line, which is printed after the socket is bound
# and state restored and comes from this process, never by polling with a CLI
# command that would start a daemon of its own.
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

# Checked rather than swallowed, because on a fresh daemon a failed create is a
# real failure and the `ps` assertions cannot tell a runtime this test made
# from one already there.
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

# The oracle is this daemon's own counters, which nothing outside it can move
# -- the proxy's total_connections up by exactly one, which a stranger holding
# the port cannot produce, and the payload's bytes arriving at a backend, which
# a proxy forwarding nowhere cannot -- summed over both backends because
# round-robin picks which one gets it.
PAYLOAD="hello proxy"
NBYTES=$(( ${#PAYLOAD} + 1 ))        # echo adds the newline that is also sent
# The baseline has to be a settled reading, because the readiness probe is
# itself a connection whose accept and close are counted on different loop
# turns -- and two agreeing readings can both fall between them, so three
# readings across two gaps is the cheap way to be sure.
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

# `timeout` around nc, because `-q 1` only bounds the wait after the peer has
# hung up and a stray port-holder that accepts and holds leaves nc blocked
# until it is killed, with two FAILs printed and no summary.
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
