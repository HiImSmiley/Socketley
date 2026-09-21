#!/usr/bin/env bash
# Integration test: how far ahead of a UDP server a burst may get.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
# THE UDP LISTENER WAS THE ONE SOCKET IN THE TREE WITH NO SO_RCVBUF.  The TCP
# listener takes 128 KB through socket_tuning::tcp_listener_defaults and hands
# it to every accepted connection, the cache listener sets both directions, the
# proxy sets both on every socket it tunes -- and the datagram socket got
# SO_REUSEADDR, SO_REUSEPORT and the kernel default.
#
# It is also the one socket that cannot recover from the shortfall.  A stream
# whose receive buffer fills closes its window and the sender waits; a datagram
# that arrives with the buffer full is dropped by the kernel, silently, with no
# retransmit behind it and nothing counted anywhere.
#
# ─── WHAT IS ASSERTED AND WHY IT IS ASSERTED THIS WAY ──────────────────────
#
# Not a throughput number: a running server drains faster than a sender on the
# same box can fill it -- 199,889 of 200,000 arrived at the UNFIXED binary from
# a sendmmsg blaster, so a rate test measures the box and not the buffer.  What
# the buffer buys is BURST DEPTH: how far ahead the wire may get while this
# runtime is inside one callback and not reading.  So the worker is stopped,
# the burst is sent at a socket nobody is draining, and the worker is let go.
#
# Measured, twenty thousand 100-byte datagrams, six runs per arm interleaved
# in both orders:  221 survived before, 2,184 after.  Every run of each arm
# gave the identical number, so the threshold below is nowhere near either.
#
# The control is the same burst with the worker running, which must arrive
# nearly whole -- without it, "few datagrams survived" is also what a sender
# that never sent looks like.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: the UDP receive buffer ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

PR=$((SL_PORT_BASE+1440))
PB=$((SL_PORT_BASE+1441))
BURST=20000

daemon_isolate udprecvbuf
trap 'kill -CONT ${WPID:-0} 2>/dev/null; daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

blast() {
    python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4*1024*1024)
pay = b'x' * 99 + b'\n'
to = ('127.0.0.1', $1)
for _ in range($BURST):
    try: s.sendto(pay, to)
    except OSError: pass
s.close()" 2>/dev/null
}
msgs_of() { "$BIN" stats "$1" 2>/dev/null | awk -F: '$1=="total_messages"{print $2;exit}'; }

# ── the control: the same burst at a server that is reading ────────────────
"$BIN" create server urb_c -p "$PB" --udp -s >/dev/null 2>&1
sleep 1.2
blast "$PB"
sleep 2
LIVE=$(msgs_of urb_c)
if [ "${LIVE:-0}" -ge 5000 ]; then
    ok "a server that is reading takes thousands of the burst ($LIVE of $BURST)"
else
    bad "the fixture can fill a socket at all" \
        "a running server counted ${LIVE:-<none>} of $BURST;" \
        "the depth measured below would be about a sender that never sent." \
        "This is deliberately a floor and not a fraction: how much of the burst a" \
        "READING server takes is a race between python and the drain loop and was" \
        "measured anywhere from 10,960 to 20,000 of 20,000 on the same binary"
fi

# ── the measurement: the same burst at a server that is not ────────────────
"$BIN" create server urb -p "$PR" --udp -s >/dev/null 2>&1
sleep 1.2
WPID=$("$BIN" stats urb 2>/dev/null | awk -F: '$1=="pid"{print $2;exit}')
if [ -z "${WPID:-}" ]; then
    bad "the runtime names the process it is in" \
        "stats printed no pid: line for urb, so the worker cannot be held still"
else
    # Held for well under the 15 s the wedge detector reports on, and let go
    # again on the trap whatever happens below.
    kill -STOP "$WPID"
    sleep 0.3
    blast "$PR"
    sleep 0.3
    kill -CONT "$WPID"
    sleep 2.5

    DEEP=$(msgs_of urb)
    if [ "${DEEP:-0}" -ge 1000 ]; then
        ok "a burst may get $DEEP datagrams ahead of a runtime that is not reading"
    else
        bad "the UDP listener's receive buffer is tuned" \
            "only ${DEEP:-<none>} of $BURST survived a burst at a socket nobody was draining;" \
            "221 is the kernel default with no SO_RCVBUF set, which is what this listener" \
            "had while every other socket in the tree was tuned -- and a datagram dropped" \
            "there is gone, with no window to close and no retransmit behind it"
    fi
fi

for n in urb urb_c; do
    "$BIN" stop "$n" >/dev/null 2>&1; "$BIN" remove "$n" >/dev/null 2>&1
done
daemon_stop
trap - EXIT

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
