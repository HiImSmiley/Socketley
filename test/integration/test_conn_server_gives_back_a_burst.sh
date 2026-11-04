#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: a conn_server connection that carried a burst and went quiet gives back what the burst grew --
# the capacity its strings kept and its grown read buffer -- so the worker's heap can go back to the kernel.
#
# What it would catch: every connection holding what its largest request grew for the rest of its life, measured on a
# tunnel as 840 KiB per quiet connection after 4 MiB each, for good, against 22-27 KiB once trimmed.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a quiet conn_server connection gives back what a burst grew ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
# The sanitizer brings an allocator of its own, which neither trims nor reports as glibc's does.
if nm -C "$BIN" 2>/dev/null | grep '__asan_' >/dev/null; then echo "  SKIP: the sanitizer's allocator is not glibc's"; exit 0; fi
daemon_isolate cstrim
P=$((SL_PORT_BASE + 1940))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
daemon_start "$BIN"
"$BIN" create mcp tools -p "$P" --anonymous --max-connections 10000 -s >/dev/null 2>&1 || bad "an mcp runtime is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 50); do ss -ltn | grep -q ":$P " && break; sleep 0.1; done
pid=$(ss -ltnpH "( sport = :$P )" | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2)
rss() { awk '/^VmRSS/ {print $2}' "/proc/$pid/status"; }
N=200
r0=$(rss)

# Each connection posts a 2 MiB body, reads the answer, and stays open and silent.
python3 - "$P" "$N" "$SOCKETLEY_TMPD/phase" <<'PY' &
import socket, sys, time
port, n, phase = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
body = b"x" * (2 << 20)
head = b"POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n" % len(body)
cs = []
for _ in range(n):
    s = socket.create_connection(("127.0.0.1", port))
    s.sendall(head + body)
    got = b""
    while b"\r\n\r\n" not in got:
        got += s.recv(65536)
    cs.append(s)
open(phase, "w").write("burst done")
time.sleep(120)
PY
client=$!
for _ in $(seq 1 600); do [ -s "$SOCKETLEY_TMPD/phase" ] && break; sleep 0.1; done
r1=$(rss)
# trim() withdraws what a connection quiet for 5 s holds; the worker hands its heap back at most once a minute.
for _ in $(seq 1 80); do sleep 1; [ $(( ($(rss) - r0) * 1024 / N )) -lt 131072 ] && break; done
r2=$(rss)
kill "$client" 2>/dev/null; wait "$client" 2>/dev/null
per1=$(( (r1 - r0) * 1024 / N )); per2=$(( (r2 - r0) * 1024 / N ))
echo "  $N connections after a 2 MiB request each: $per1 B each, quiet $per2 B each"
[ "$per1" -gt 1048576 ] && ok || bad "the burst grew each connection, or this measures nothing" "$per1 B each"
[ "$per2" -lt 131072 ] && ok || bad "a quiet connection gives back what its burst grew" "$per2 B each"

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
