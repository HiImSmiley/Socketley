#!/usr/bin/env bash
# Integration test: an accepted connection is reaped when its peer disappears.
#
# A peer that loses power sends no FIN and no RST, so the connection stays
# ESTABLISHED on this side for ever.  The client's dial and both of a proxy's
# legs already asked the kernel to notice -- SO_KEEPALIVE at 60/10/3, with the
# reason written beside it -- and the server and the cache did not.
#
# Their only other defence is --idle-timeout, which is 0 by default and is not
# a substitute anyway: it closes connections that are QUIET, and a websocket
# that says nothing for an hour is quiet and alive.  Keepalive closes the ones
# that are DEAD.
#
# Measured from outside the process, because what matters is what the kernel
# was told: `ss -tno` prints a keepalive timer on a socket that has it armed
# and nothing on one that has not.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate keepalive

PORT_CACHE=$((SL_PORT_BASE+1430))
PORT_SERVER=$((SL_PORT_BASE+1431))
PORT_PROXY=$((SL_PORT_BASE+1432))
PORT_BACK=$((SL_PORT_BASE+1433))
SOCK_UNIX="$SOCKETLEY_TMPD/unix-server.sock"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

cleanup() {
    exec 7<&- 8<&- 9<&- 2>/dev/null
    for n in kv sv px ux; do "$BIN" remove "$n" >/dev/null 2>&1; done
    daemon_stop
}
trap cleanup EXIT

daemon_start "$BIN"

wait_port() { local p=$1 i; for i in $(seq 1 200); do ss -ltn | grep -q ":$p " && return 0; sleep 0.1; done; return 1; }

# The accepted end is the one whose LOCAL port is the runtime's.  Read to the
# end and keep the first match: `exit` out of a pipe under pipefail reports 141
# precisely when it matched.
keepalive_on() {
    local port=$1 line
    line=$(ss -tno 2>/dev/null | awk -v p=":$port\$" '$4 ~ p {print; found=1} END{}' | head -1)
    [ -n "$line" ] || { echo "NOCONN"; return; }
    case "$line" in *keepalive*) echo "yes" ;; *) echo "no" ;; esac
}

echo "=== Integration: an accepted connection outlives a vanished peer ==="

"$BIN" create cache  kv -p "$PORT_CACHE"  -s >/dev/null 2>&1
"$BIN" create server sv -p "$PORT_SERVER" -s >/dev/null 2>&1
wait_port "$PORT_CACHE"  || { echo "  FATAL: cache never bound";  exit 2; }
wait_port "$PORT_SERVER" || { echo "  FATAL: server never bound"; exit 2; }

echo "--- 1. the two that had none ---"
exec 7<>"/dev/tcp/127.0.0.1/$PORT_CACHE"  || { echo "  FATAL: cannot reach cache";  exit 2; }
exec 8<>"/dev/tcp/127.0.0.1/$PORT_SERVER" || { echo "  FATAL: cannot reach server"; exit 2; }
sleep 1

for pair in "cache:$PORT_CACHE" "server:$PORT_SERVER"; do
    what=${pair%%:*}; port=${pair##*:}
    got=$(keepalive_on "$port")
    if [ "$got" = "yes" ]; then ok; else
        bad "an accepted $what connection has keepalive armed" \
            "ss says '$got' for the socket with local port $port"
    fi
done

echo "--- 2. the two that already had it, after the decision moved to shared/ ---"
"$BIN" create proxy px -p "$PORT_PROXY" --backend "127.0.0.1:$PORT_BACK" -s >/dev/null 2>&1
wait_port "$PORT_PROXY" || { echo "  FATAL: proxy never bound"; exit 2; }
exec 9<>"/dev/tcp/127.0.0.1/$PORT_PROXY" || { echo "  FATAL: cannot reach proxy"; exit 2; }
sleep 1
got=$(keepalive_on "$PORT_PROXY")
if [ "$got" = "yes" ]; then ok; else
    bad "the proxy kept its keepalive" "ss says '$got'"
fi

echo "--- 3. a unix listener is not charged for a TCP option ---"
# The control that keeps arm 1 honest: if the call were unconditional it would
# still pass above, and a unix socket has no keepalive to arm.  This asserts the
# runtime works at all on a unix listener rather than reading its options.
"$BIN" create server ux --listen "unix:$SOCK_UNIX" -s >/dev/null 2>&1
for i in $(seq 1 100); do [ -S "$SOCK_UNIX" ] && break; sleep 0.1; done
if [ -S "$SOCK_UNIX" ]; then ok; else
    bad "a unix-listening server still starts" "no socket at $SOCK_UNIX"
fi
if "$BIN" ls 2>&1 | awk '$2 == "ux" && $3 == "server" && /Up / { f=1 } END { exit !f }'; then ok; else
    bad "the unix-listening server is up" "$("$BIN" ls)"
fi

echo
echo "=============================="
echo " Summary: $PASS passed, $FAIL failed (of $TOTAL)"
echo "=============================="
[ "$FAIL" -eq 0 ]
