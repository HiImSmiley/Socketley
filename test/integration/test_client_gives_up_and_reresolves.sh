#!/usr/bin/env bash
# suite: host -- HOSTALIASES moves a name only through DNS, which a network namespace of its own cannot reach
# Integration test: a client that stopped trying, and one whose peer moved.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
#   THE --reconnect LIMIT WAS REPORTED AS A SUCCESS.  schedule_reconnect()
#   answered true for "the configured limit, reached as asked", and true is
#   what drop_connection() reads as "something will bring this client back".
#   So nothing marked it, nothing logged it, and nothing in the ring would ever
#   wake it again: `ps` said running, `stats` said zero connections, and
#   was_running started it into the same state at the next daemon restart.
#
#   THE RESOLVED ADDRESS WAS KEPT FOR THE LIFE OF THE RUNTIME.  The cache was
#   cleared only when connect() failed SYNCHRONOUSLY, and a non-blocking
#   connect to a remote address answers EINPROGRESS -- the refusal arrives
#   later as -ECONNREFUSED on a CQE, down a path that never touched it.  A
#   client dialling `app:9000` therefore kept an address a recreated container
#   had already released, for ever, while the manual promises automatic
#   reconnection for exactly that case.
#
# The second one needs a name that resolves to one address and then to another.
# HOSTALIASES gives that without root, but it maps a name to another NAME, so
# the box has to offer two resolvable names with different addresses --
# `localhost` and this machine's own hostname, which not every box has.  When
# it does not, the assertion is reported as NOT ASSERTED rather than passed:
# a skip that reads as a pass is how a path stays unmeasured.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: a client that gave up, and one whose peer moved ==="

PASS=0; FAIL=0; TOTAL=0; NOTASSERTED=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}
skip() { NOTASSERTED=$((NOTASSERTED+1)); echo "  NOT ASSERTED [$1]: $2"; }

P=$((SL_PORT_BASE+1406))

daemon_isolate clientgivesup
trap 'daemon_stop 2>/dev/null || true' EXIT
# Exported before the daemon starts, because the worker is forked from it and
# inherits the environment; glibc re-reads the file on every lookup.
ALIASES="$SOCKETLEY_TMPD/hostaliases"
: > "$ALIASES"
export HOSTALIASES="$ALIASES"
daemon_start "$BIN"

state_of() { "$BIN" ls 2>/dev/null | awk -v n="$1" '$2 == n { print $7; exit }'; }

# ── 1. The --reconnect limit is an end, and it says so ─────────────────────
#
# Port 1 refuses in microseconds, so two attempts and their 1s and 2s backoffs
# are over well inside the wait below.
"$BIN" create client cgu_dead -t "127.0.0.1:1" --reconnect 2 -s >/dev/null 2>&1
sleep 10
ST=$(state_of cgu_dead)
SAID=$(grep -c "reconnect limit" "$SOCKETLEY_DLOG" 2>/dev/null || true)
if [ "$ST" != "Up" ] && [ "${SAID:-0}" -ge 1 ]; then
    ok "a client at its --reconnect limit reads '$ST' and the log says why"
else
    bad "reaching the --reconnect limit is not reported as running" \
        "state is '${ST:-<none>}' and the log named the limit ${SAID} time(s);" \
        "Up here means schedule_reconnect() answered true for 'reached as asked'," \
        "so drop_connection() never marked it and nothing will dial again -- an" \
        "operator sees a running client with no socket and no reason"
fi
"$BIN" stop cgu_dead >/dev/null 2>&1; "$BIN" remove cgu_dead >/dev/null 2>&1

# ── 2. The address is resolved again after a failed attempt ────────────────
HOSTNAME_ADDR=$(python3 -c "
import socket
try: print(socket.getaddrinfo(socket.gethostname(),80,socket.AF_INET,socket.SOCK_STREAM)[0][4][0])
except Exception: print('')" 2>/dev/null)
LOCAL_ADDR=127.0.0.1

if [ -z "$HOSTNAME_ADDR" ] || [ "$HOSTNAME_ADDR" = "$LOCAL_ADDR" ]; then
    skip "a client re-resolves its peer after a failed attempt" \
         "this box offers no second resolvable name (hostname gave '${HOSTNAME_ADDR:-<nothing>}')," \
         "and HOSTALIASES maps a name to a NAME, so two addresses cannot be built here"
else
    # The peer is a plain listener bound to 127.0.0.1 ONLY, and not a socketley
    # server, for one reason: a socketley server binds INADDR_ANY, so it would
    # answer on BOTH addresses and a cached one would work as well as a fresh
    # one -- the assertion would pass on a build that never re-resolves.  The
    # finding is about the client's resolver, and the peer is scenery.
    ACCEPTED="$SOCKETLEY_TMPD/accepted"
    : > "$ACCEPTED"
    python3 -c "
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $P)); s.listen(8); s.settimeout(60)
try:
    c, a = s.accept()
    open('$ACCEPTED', 'w').write('yes\\n')
    c.close()
except Exception:
    pass
s.close()" >/dev/null 2>&1 &
    PEER_PID=$!
    sleep 0.7

    # Phase 1: the name points at this machine's other address, where nothing
    # is listening, so every attempt is refused at once and the address that
    # gets cached is the wrong one.
    printf 'cgupeer %s\n' "$(hostname)" > "$ALIASES"
    "$BIN" create client cgu_move -t "cgupeer:$P" --reconnect 0 -s >/dev/null 2>&1
    sleep 3

    # Phase 2: the name moves to where the peer actually is.
    printf 'cgupeer localhost\n' > "$ALIASES"

    CONNECTED=no
    for _ in $(seq 1 40); do
        [ -s "$ACCEPTED" ] && { CONNECTED=yes; break; }
        sleep 1
    done
    kill "$PEER_PID" 2>/dev/null; wait "$PEER_PID" 2>/dev/null

    if [ "$CONNECTED" = "yes" ]; then
        ok "a client whose name moved reaches the peer at its new address"
    else
        bad "a client re-resolves its peer after a failed attempt" \
            "the listener on $LOCAL_ADDR:$P saw no connection in 40 s after the name" \
            "moved from $HOSTNAME_ADDR to $LOCAL_ADDR;" \
            "the cached address was cleared only on a SYNCHRONOUS connect failure, and a" \
            "non-blocking connect answers EINPROGRESS -- so the refusal never reached it"
    fi
    "$BIN" stop cgu_move >/dev/null 2>&1; "$BIN" remove cgu_move >/dev/null 2>&1
fi

daemon_stop
trap - EXIT

echo "  Results: $PASS/$TOTAL passed ($FAIL failed, $NOTASSERTED not asserted)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
