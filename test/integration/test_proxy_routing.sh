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
PORT_BASE=${PORT_BASE:-19260}
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
        if tr '\0' '\n' <"/proc/$p/environ" 2>/dev/null \
           | grep -qx "SOCKETLEY_SOCKET=$SOCKETLEY_SOCKET"; then
            kill -9 "$p" 2>/dev/null || true
        fi
    done
    rm -rf "$TMPD"
}
trap cleanup EXIT

ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

assert_contains() {
    if echo "$1" | grep -q "$2"; then ok; else bad "$3" "expected '$2' in output"; fi
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
OUT=$("$BIN" ps 2>&1)
assert_contains "$OUT" "proxy_be1" "backend 1 in ps"
assert_contains "$OUT" "proxy_be2" "backend 2 in ps"
assert_contains "$OUT" "proxy_tcp" "proxy in ps"

# Test: TCP proxy accepts connections and forwards to backend
# Server broadcasts to other clients, so send from two connections:
# first one establishes, second one sends data, first should receive broadcast
RC=0
echo "hello proxy" | nc -q 1 127.0.0.1 "$TCP_PROXY_PORT" 2>/dev/null || RC=$?
if [ "$RC" -eq 0 ]; then ok; else bad "TCP proxy connect" "nc exit code $RC"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
