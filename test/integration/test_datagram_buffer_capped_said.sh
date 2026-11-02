#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: a datagram socket the kernel gives less buffer than it asked for says so, once, with the sysctl
# that gives it all.
#
# What each part would catch:
#   * a receive buffer capped by net.core.rmem_max without a word: a dns runtime asks 8 MiB, an HTTP/3 endpoint 4 MiB,
#     and on a stock kernel either holds 208 KiB, where a burst past it is lost and nothing says why
#   * the same said for every socket a process opens, rather than once
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a datagram socket given less buffer than it asked says so ==="
max=$(cat /proc/sys/net/core/rmem_max 2>/dev/null || echo 0)
# The dns runtime asks 8 MiB; a kernel that allows it has nothing to say.
if [ "$max" -ge $((8 << 20)) ]; then echo "  SKIP: net.core.rmem_max is $max, which gives a dns runtime all it asks"; exit 0; fi
daemon_isolate dgrambuf
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1956))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
printf '$ORIGIN t.test.\n$TTL 60\n@ SOA ns host 1 1 1 1 1\n@ NS ns\nns A 192.0.2.1\n' > "$T/t.zone"
daemon_start "$BIN"
"$BIN" create dns ns -p "$P" --bind 127.0.0.1 --zone "$T/t.zone" --rrl 0 --proxy none -s >/dev/null 2>&1
for _ in $(seq 1 100); do grep -q "receive buffer is" "$SOCKETLEY_DLOG" 2>/dev/null && break; sleep 0.1; done
line=$(grep -m1 "receive buffer is" "$SOCKETLEY_DLOG" 2>/dev/null)
echo "  ${line:-<nothing said>}"
case "$line" in *"of the 8192 KiB asked"*"net.core.rmem_max=8388608"*) ok ;; *) bad "a capped buffer is said, with the sysctl" "${line:-nothing}" ;; esac
# Two sockets in one process, said once.
[ "$(grep -c "receive buffer is" "$SOCKETLEY_DLOG")" = 1 ] && ok || bad "once a process" "$(grep -c "receive buffer is" "$SOCKETLEY_DLOG") times"

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
