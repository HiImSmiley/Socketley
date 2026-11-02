#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: a cache with millions of keys with a deadline sweeps them without holding its loop, and still
# removes the ones that are due.
#
# What each part would catch:
#   * a sweep over every key with a deadline at each tick: at two million of them it held the loop about 35 ms twice
#     a second, which a client sees as a stall however little it asks
#   * a sweep that stops for its budget and never goes on, or starts over from the front each time: expired keys
#     that keep their memory until something touches them
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a cache's TTL sweep holds its loop briefly, and removes what is due ==="
command -v redis-cli >/dev/null 2>&1 || { echo "  SKIP: redis-cli is required"; exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
if nm -C "$BIN" 2>/dev/null | grep -q '__asan_'; then
    echo "  SKIP: a stall in milliseconds measures the sanitizer, not the sweep"; exit 0
fi
daemon_isolate ttlsweep
P=$((SL_PORT_BASE + 1925))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
daemon_start "$BIN"
"$BIN" create cache ttl -p "$P" --resp -s >/dev/null 2>&1
for _ in $(seq 1 50); do redis-cli -p "$P" ping >/dev/null 2>&1 && break; sleep 0.1; done

python3 -c "
import sys
w = sys.stdout.write
for i in range(2000000): w('SET long:%d v EX 3600\r\n' % i)
for i in range(300000): w('SET short:%d v PX 1500\r\n' % i)
" | redis-cli -p "$P" --pipe >/dev/null 2>&1
n=$(redis-cli -p "$P" dbsize)
if [ "${n:-0}" -ge 2000000 ]; then ok; else bad "two million keys with a deadline are loaded" "dbsize ${n:-none}"; fi

# The worst a PING waits over four seconds, which covers eight ticks of the old sweep and several cycles of the new.
worst=$(python3 - "$P" <<'PY'
import socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1]))); worst = 0.0
end = time.time() + 4
while time.time() < end:
    t = time.perf_counter(); s.sendall(b"PING\r\n"); s.recv(64)
    worst = max(worst, (time.perf_counter() - t) * 1000); time.sleep(0.001)
print("%.1f" % worst)
PY
)
echo "  the worst PING among 2.3 million keys with a deadline: ${worst} ms"
if awk -v w="$worst" 'BEGIN{exit !(w < 15)}'; then ok
else bad "the sweep holds the loop briefly" "a PING waited ${worst} ms"; fi

# The 300,000 short ones expired seconds ago, and a sweep that goes on from where it stopped has reached them all.
for _ in $(seq 1 100); do [ "$(redis-cli -p "$P" dbsize)" -le 2000000 ] && break; sleep 0.1; done
n=$(redis-cli -p "$P" dbsize)
if [ "${n:-0}" = 2000000 ]; then ok; else bad "and every key that is due is removed by it" "dbsize $n, 2000000 should be left"; fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
