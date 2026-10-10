#!/usr/bin/env bash
# Keying the state directory to a non-default socket and copying the legacy
# directory into a fresh keyed one are each correct and catastrophic together,
# because an operator debugging beside the deployed daemon presents exactly the
# signature of an upgrade -- one `ls` was enough to put two daemons on one
# port, the second holding a copy of the first's state file that `remove` would
# delete; the oracle is the port rather than the file, since the second bind
# succeeds silently, and the other direction is asserted too because "B adopted
# nothing" also passes where adoption was deleted; it must touch the default
# socket, since an asymmetric case with both daemons on overrides is the
# arrangement that already passed ten checks while this was live, so it refuses
# to run if anything is serving that path, unlinks the socket only if it
# created it, and kills only pids it started.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
# For daemon_pids and daemon_sweep only: sourcing defines functions and runs
# nothing, and this file arranges its own isolation deliberately.
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

DEFAULT_SOCK=/tmp/socketley.sock
PORT_A=$((SL_PORT_BASE+930))
PORT_B=$((SL_PORT_BASE+931))
PASS=0; FAIL=0; TOTAL=0

ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

echo "=== Integration: a second daemon does not adopt a live daemon's runtimes ==="

# Reported rather than silent, because a check that quietly does not run is the
# failure mode this suite has been paying down.
if [ -n "$(daemon_pids "$DEFAULT_SOCK")" ]; then
    echo "  SKIP: something is already serving $DEFAULT_SOCK (pid$(daemon_pids "$DEFAULT_SOCK"))."
    echo "        This file has to start a daemon on the default path -- that is the"
    echo "        rule under test -- and it will not do so beside a daemon it did not"
    echo "        start.  Stop that daemon and run this file again."
    exit 0
fi

# Whether the socket FILE was there before us decides whether we may remove it.
SOCK_PREEXISTING=0
[ -e "$DEFAULT_SOCK" ] && SOCK_PREEXISTING=1

TMPD=$(mktemp -d /tmp/socketley-asym-XXXXXX)

daemon_watch "$TMPD"   # its processes go with it if it is killed
export HOME="$TMPD/home"; mkdir -p "$HOME"
SOCK_B="$TMPD/b.sock"
APID=""; BPID=""

cleanup() {
    set +e
    for p in $APID $BPID; do
        [ -n "$p" ] || continue
        kill "$p" 2>/dev/null
        for _ in $(seq 1 30); do kill -0 "$p" 2>/dev/null || break; sleep 0.1; done
        kill -9 "$p" 2>/dev/null
        wait "$p" 2>/dev/null
    done
    # Anything a CLI command auto-started on either of our two paths, asked of
    # the socket rather than by name or command line.
    daemon_sweep "$SOCK_B"
    daemon_sweep "$DEFAULT_SOCK"
    # Only if this run created it, because a socket file belonging to somebody
    # else's daemon is not ours to unlink.
    [ "$SOCK_PREEXISTING" = "0" ] && rm -f "$DEFAULT_SOCK"
    rm -rf "$TMPD"
    return 0
}
trap cleanup EXIT

# Counted from /proc/net/tcp rather than `ss` so it does not depend on
# iproute2, and two daemons that both bound the port under SO_REUSEPORT are two
# rows -- which is the reason the port is the oracle at all, since the second
# bind succeeds and reports nothing.
listeners() {   # port -> count
    local hexp
    hexp=$(printf '%04X' "$1")
    awk -v h=":$hexp" '$4 == "0A" && $2 ~ h"$" { n++ } END { print n+0 }' \
        /proc/net/tcp 2>/dev/null
}

boot() {   # LOG, [socket] -> pid on stdout; no socket argument means the default path
    local l=$1 s=${2:-} i n want
    n=$(grep -c "daemon started" "$l" 2>/dev/null) || n=0
    want=$((n + 1))
    if [ -n "$s" ]; then
        SOCKETLEY_SOCKET="$s" "$BIN" daemon >>"$l" 2>&1 &
    else
        env -u SOCKETLEY_SOCKET "$BIN" daemon >>"$l" 2>&1 &
    fi
    local pid=$!
    for i in $(seq 1 100); do
        n=$(grep -c "daemon started" "$l" 2>/dev/null) || n=0
        [ "$n" -ge "$want" ] && break
        sleep 0.1
    done
    echo "$pid"
}

halt() {   # pid
    local p=$1
    kill "$p" 2>/dev/null || true
    for _ in $(seq 1 50); do kill -0 "$p" 2>/dev/null || break; sleep 0.1; done
    kill -9 "$p" 2>/dev/null || true
    wait "$p" 2>/dev/null || true
}

# ── Daemon A: the deployed one, on the path the rule exempts ────────────────
APID=$(boot "$TMPD/a.log")
if [ -z "$(daemon_pids "$DEFAULT_SOCK")" ]; then
    echo "  FATAL: this test's own daemon never came up on $DEFAULT_SOCK;"
    echo "         nothing below would be measuring this build."
    tail -5 "$TMPD/a.log" 2>/dev/null | sed 's/^/         /'
    exit 2
fi
env -u SOCKETLEY_SOCKET "$BIN" create server asym_a -p "$PORT_A" -s >/dev/null 2>&1 || true
env -u SOCKETLEY_SOCKET "$BIN" create server asym_b -p "$PORT_B" -s >/dev/null 2>&1 || true
sleep 0.6

# Setup guard: one listener has to be there first, or "not two" would pass on a
# run where the runtime never started.
A_L=$(listeners "$PORT_A")
if [ "$A_L" = "1" ]; then
    ok
else
    bad "the deployed daemon is serving its runtime" \
        "$A_L listening sockets on :$PORT_A, expected 1" \
        "Nothing below can mean anything: the collision this file looks for is a" \
        "second listener appearing beside the first, and there is no first."
fi

LEGACY_N=$(find "$HOME/.local/share/socketley/runtimes" -name '*.json' 2>/dev/null | wc -l)
if [ "$LEGACY_N" -ge 2 ]; then
    ok
else
    bad "the deployed daemon's state is in the unkeyed directory" \
        "$LEGACY_N state file(s) found, expected 2" \
        "There is nothing for the second daemon to wrongly adopt, so the" \
        "assertions below could not fail however the build behaves."
fi

# ── Daemon B: an operator debugging beside it ──────────────────────────────
BPID=$(boot "$TMPD/b.log" "$SOCK_B")
sleep 0.6

# THE ORACLE.  Two rows on either port means two daemons bound it.
B_LA=$(listeners "$PORT_A")
B_LB=$(listeners "$PORT_B")
if [ "$B_LA" = "1" ] && [ "$B_LB" = "1" ]; then
    ok
else
    bad "a second daemon does not bind the running daemon's ports" \
        "listening sockets: :$PORT_A=$B_LA :$PORT_B=$B_LB, expected 1 and 1" \
        "The second daemon adopted state files belonging to a daemon that is" \
        "still serving them and bound its ports.  SO_REUSEPORT means that bind" \
        "succeeded silently, so nothing but this count reports it."
fi

# ...and the inventory, which says the same thing from the daemon's own mouth.
B_PS=$(SOCKETLEY_SOCKET="$SOCK_B" "$BIN" ps -a 2>&1 || true)
if grep -q 'asym_a\|asym_b' <<<"$B_PS"; then
    bad "the second daemon has no runtimes of its own" \
        "it lists runtimes belonging to the daemon on $DEFAULT_SOCK" \
        "$(grep 'asym_a\|asym_b' <<<"$B_PS" | head -2)"
else
    ok
fi

# The decline has to be readable, because to the operator this looks exactly
# like their runtimes vanishing and the daemon log is the only place that can
# say otherwise.
B_LOG=$(cat "$TMPD/b.log" 2>/dev/null || true)
if grep -q "NOT adopting" <<<"$B_LOG" \
   && grep -q "$DEFAULT_SOCK" <<<"$B_LOG" \
   && grep -qF "$HOME/.local/share/socketley/runtimes" <<<"$B_LOG"; then
    ok
else
    bad "the decline is in the log, naming both directories" \
        "nothing in the second daemon's log explains why it started empty" \
        "An operator whose runtimes appear to have vanished has nothing to read." \
        "$(grep -i 'state' <<<"$B_LOG" | head -3)"
fi

# A declined adoption must not leave the marker behind: it is not a decision,
# and the next boot has to ask again.
KEYED_DIR=$(find "$HOME" -type d -name 'runtimes.*' 2>/dev/null | head -1 || true)
if [ -z "$KEYED_DIR" ]; then
    bad "a declined adoption is provisional, not recorded as settled" \
        "no keyed runtimes.* directory under $HOME, so there was no marker to look for"
elif [ -f "$KEYED_DIR/.adopted" ]; then
    bad "a declined adoption is provisional, not recorded as settled" \
        "the .adopted marker was written for a decline" \
        "That makes the refusal permanent: once the daemon on $DEFAULT_SOCK is" \
        "gone, this daemon would still never take its runtimes back."
else
    ok
fi

# And daemon A is unharmed by all of it.
A_PS=$(env -u SOCKETLEY_SOCKET "$BIN" ps 2>&1 || true)
if grep -q 'asym_a' <<<"$A_PS"; then
    ok
else
    bad "the deployed daemon still has its runtimes" \
        "asym_a is gone from the daemon on $DEFAULT_SOCK" \
        "$(head -3 <<<"$A_PS")"
fi

# ── The other direction ────────────────────────────────────────────────────
# Everything above passes on a build that never adopts anything, so A is
# stopped and B restarted with the adoption required to happen now -- same
# daemon, same two directories, one fact changed.
halt "$APID"; APID=""
sleep 0.6
halt "$BPID"
BPID=$(boot "$TMPD/b.log" "$SOCK_B")
sleep 0.8

B_PS2=$(SOCKETLEY_SOCKET="$SOCK_B" "$BIN" ps -a 2>&1 || true)
if grep -q 'asym_a' <<<"$B_PS2" && grep -q 'asym_b' <<<"$B_PS2"; then
    ok
else
    bad "with the default socket free, the same daemon does adopt" \
        "the runtimes were still not adopted after the daemon on $DEFAULT_SOCK stopped" \
        "The decline is meant to be about who is using them, not a refusal to" \
        "ever adopt -- without this, every assertion above would also pass on a" \
        "build that had lost the upgrade path altogether." \
        "$(grep -i 'state' "$TMPD/b.log" 2>/dev/null | tail -2)"
fi

halt "$BPID"; BPID=""

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
