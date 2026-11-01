#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: a connection a runtime dials and only reads from has keepalive, as an accepted one does.
#
# What it would catch: a cache replica's link to its leader, or a server's --upstream, dialled without SO_KEEPALIVE.
# Neither side sends anything while quiet, so a peer that loses power or is dropped by a NAT without a FIN leaves the
# read armed for ever: the replica reports its link up and never re-dials.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a dialled connection that only reads has keepalive ==="
command -v ss >/dev/null 2>&1 || { echo "  SKIP: ss is required"; exit 0; }
daemon_isolate obka
P=$((SL_PORT_BASE + 1985))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
daemon_start "$BIN"

# The timer ss reports on the connection from a local port other than the listener to `port`.
timer_to() {
    local port=$1 out=""
    for _ in $(seq 1 50); do
        out=$(ss -tnoH state established "( dport = :$port )" 2>/dev/null | head -1)
        [ -n "$out" ] && break
        sleep 0.1
    done
    grep -o 'timer:([a-z]*' <<<"$out" | cut -d'(' -f2
}

"$BIN" create cache leader -p "$P" -s >/dev/null 2>&1
"$BIN" create cache replica -p $((P+1)) --replicate "127.0.0.1:$P" -s >/dev/null 2>&1
t=$(timer_to "$P")
if [ "$t" = keepalive ]; then ok; else bad "a replica's link to its leader has keepalive" "timer '${t:-none}'"; fi

"$BIN" create server up -p $((P+2)) -s >/dev/null 2>&1
"$BIN" create server down -p $((P+3)) --upstream "127.0.0.1:$((P+2))" -s >/dev/null 2>&1
t=$(timer_to $((P+2)))
if [ "$t" = keepalive ]; then ok; else bad "a server's --upstream has keepalive" "timer '${t:-none}'"; fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
