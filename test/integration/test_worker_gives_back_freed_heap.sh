#!/usr/bin/env bash
# suite: quiet -- the worst PING of 75 s, which a busy box's scheduler sets as surely as the loop does
# Integration test: a worker hands the heap a burst freed back to the kernel once it has lain idle a while.
#
# What each part would catch:
#   * freed memory kept by glibc below the top of its arenas: a cache that held 200,000 keys and dropped them all
#     stayed at 76 MB for good, and the dashboard's memory line with it
#   * a trim that holds the loop: a client of the worker asking all along waits for it
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

echo "=== Integration: a worker gives back the heap a burst freed ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
# The sanitizer brings an allocator of its own, which this does not speak to.
if nm -C "$BIN" 2>/dev/null | grep '__asan_' >/dev/null; then echo "  SKIP: the sanitizer's allocator is not glibc's"; exit 0; fi
daemon_isolate heaptrim
P=$((SL_PORT_BASE + 1976))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
daemon_start "$BIN"
"$BIN" create cache c -p "$P" --resp -s >/dev/null 2>&1
for _ in $(seq 1 50); do (exec 3<>"/dev/tcp/127.0.0.1/$P") 2>/dev/null && break; sleep 0.1; done
pid=$(ss -ltnpH "sport = :$P" | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2)
rss() { awk '/^VmRSS/ {print int($2 / 1024)}' "/proc/$pid/status"; }

timeout 150 python3 - "$P" > "$SOCKETLEY_TMPD/out" <<'PY' &
import socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=30)
v = b"v" * 200
for base in range(0, 200000, 1000):
    s.sendall(b"".join(b"*3\r\n$3\r\nSET\r\n$%d\r\nkey:%d\r\n$200\r\n%s\r\n" % (len(b"key:%d" % i), i, v)
                       for i in range(base, base + 1000)))
    got = 0
    while got < 1000: got += s.recv(65536).count(b"+OK")
print("filled", flush=True)
s.sendall(b"*1\r\n$8\r\nFLUSHALL\r\n"); s.recv(64)
worst, end = 0.0, time.time() + 75
while time.time() < end:
    t = time.perf_counter(); s.sendall(b"*1\r\n$4\r\nPING\r\n"); s.recv(64)
    worst = max(worst, (time.perf_counter() - t) * 1000)
    time.sleep(0.01)
print("%.2f" % worst)
PY
reader=$!
for _ in $(seq 1 300); do [ "$(rss)" -gt 60 ] && break; sleep 0.2; done
full=$(rss)
wait "$reader"
worst=$(tail -1 "$SOCKETLEY_TMPD/out")
after=$(rss)
echo "  200,000 keys held at ${full} MB, all dropped and 75 s idle ${after} MB, the worst PING meanwhile ${worst} ms"
[ "${after:-999}" -lt $(( ${full:-0} - 20 )) ] && ok || bad "the heap a burst freed is given back" "${full} MB then ${after} MB"
awk -v w="${worst:-99}" 'BEGIN{exit !(w < 20)}' && ok || bad "and giving it back does not hold the loop" "${worst} ms"

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
