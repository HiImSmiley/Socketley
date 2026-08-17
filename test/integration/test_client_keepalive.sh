#!/usr/bin/env bash
# Integration test: a client's socket has a keepalive timer running
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# A peer that closes sends a FIN or an RST, and a client acts on either the
# moment it arrives.  A peer that simply stops existing sends nothing: a machine
# that loses power, a link that partitions, a firewall that forgets an idle
# flow.  The socket stays ESTABLISHED against nothing, and an idle client never
# writes, so it never finds out.
#
# With --reconnect that is the worse half of the failure, not the smaller one:
# the runtime believes it is connected and therefore never reconnects.  The
# documented promise -- "the client comes back" -- is broken for as long as
# nobody writes, and the kernel's own default before it gives up is two hours.
#
# ─── WHAT THIS ASSERTION IS, AND WHAT IT IS NOT ─────────────────────────────
#
# It reads the kernel's timer on the client's own socket: `ss -tano` prints
# `timer:(keepalive,...)` only for a socket with SO_KEEPALIVE set and idling.
# That is a fact about this connection, not about the code that made it, and it
# is false on a build without the option -- which is what makes it an assertion
# rather than a restatement.
#
# It is NOT a test that detection works.  Proving that needs a peer that
# vanishes without a packet, which on one host means dropping traffic with a
# firewall rule and root, and then waiting out the 90 seconds the settings
# below choose.  Neither belongs in this suite.  What is checked here is the
# part that was missing and the part a regression would remove: the timer
# exists, and it is on the timescale that was chosen rather than the kernel's
# two-hour default.

set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
# lib_ports.sh opens its lock with `exec 9>`; put stderr back afterwards.
exec 2>&1
daemon_isolate clika
PASS=0; FAIL=0; TOTAL=0

cleanup() { daemon_stop; }
trap cleanup EXIT
trap 'rc=$?; echo "  ABORTED at line $LINENO (exit $rc): ${BASH_COMMAND}"; exit $rc' ERR

pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

echo "=== Integration: a client keeps its connection alive ==="

daemon_start "$BIN"
P=$((SL_PORT_BASE + 1560))

"$BIN" create server ka_srv -p $((P + 1)) --mode inout -s >/dev/null 2>&1 || true
sleep 0.8
"$BIN" create client ka_cli -t "127.0.0.1:$((P + 1))" --reconnect -s >/dev/null 2>&1 || true

# The client side of the pair, found by its remote port -- and only if it is
# ESTABLISHED.  Without that filter the first run of this against a build with
# no keepalive matched a TIME-WAIT leftover on the same port and reported its
# timer, which is a different socket answering a question about this one.
#
# The awk reads to the end and keeps the first match rather than exiting on it:
# an early exit closes the pipe,
# `ss` takes SIGPIPE, and under `set -o pipefail` the assignment reports 141 --
# so it would blow up precisely when it matched.  This tree has learned that
# three times; see run_all.sh and lib_daemon.sh.
cli_line() {
    ss -tano 2>/dev/null | awk -v p="$1" '
        got == "" && $1 == "ESTAB" { n = split($5, r, ":")
                                     if (r[n] == p) got = $0 }
        END { print got }'
}

LINE=""
for _ in $(seq 1 60); do        # 60 x 0.25s = 15s for the client to dial
    LINE=$(cli_line $((P + 1)))
    [ -n "$LINE" ] && break
    sleep 0.25
done

if [ -n "$LINE" ]; then pass
else fail "the client connects at all" \
          "no socket with remote port $((P + 1)); nothing below is a result"; fi

# ─── 1. There is a keepalive timer ──────────────────────────────────────────
#
# `ss` reports the ARMED timer, and a socket that has just been written to
# shows `timer:(on,...)` for the retransmit instead.  This connection is idle
# from the moment it is up, so keepalive is the one that arms -- but it is
# polled rather than sampled once, because "idle" is a state the socket enters
# rather than one it starts in.
TIMER=""
for _ in $(seq 1 40); do        # 10s
    LINE=$(cli_line $((P + 1)))
    case "$LINE" in
        *timer:\(keepalive*) TIMER="$LINE"; break ;;
    esac
    sleep 0.25
done

if [ -n "$TIMER" ]; then pass
else fail "the client's socket has a keepalive timer" \
          "ss reports no keepalive timer on the connection to $((P + 1))" \
          "without SO_KEEPALIVE a peer that vanishes without a FIN is never noticed," \
          "and --reconnect never fires because the runtime still believes it is up" \
          "line was: ${LINE:-<none>}"; fi

# ─── 2. On the chosen timescale, not the kernel's two hours ─────────────────
#
# The timer prints as `timer:(keepalive,58sec,0)`.  Anything under two minutes
# is this build's 60s idle; the kernel's own default would print in hours and
# is what a build that set SO_KEEPALIVE and nothing else would show.  The bound
# is deliberately loose -- it is asking which of two timescales this is, not
# re-deriving the constant.
SECS=$(printf '%s' "$TIMER" | sed -n 's/.*timer:(keepalive,\([0-9]*\)\(sec\|min\|ms\).*/\1\2/p')
case "$SECS" in
    *sec) N=${SECS%sec}; [ "$N" -le 120 ] && pass || fail "the keepalive idle is the one this build chose" \
              "timer says ${SECS}, which is longer than the 60s idle configured" ;;
    *min) N=${SECS%min}; [ "$N" -le 2 ] && pass || fail "the keepalive idle is the one this build chose" \
              "timer says ${SECS} -- that is the kernel's default, so only SO_KEEPALIVE was set" ;;
    *)    fail "the keepalive idle is the one this build chose" \
               "could not read a timer value out of '${TIMER:-<none>}'" ;;
esac

echo
echo "  passed: $PASS / $TOTAL"
[ "$FAIL" -eq 0 ] || exit 1
