#!/usr/bin/env bash
# suite: isolated -- a daemon, socket and port window of its own, so it runs beside the others
# Integration test: a FIFO under a server's --http root is a missing file, not a stalled runtime.
#
# ─── THE DEFECT (round 8b) ──────────────────────────────────────────────────
#
# Disk mode opened the requested file with O_RDONLY and checked S_ISREG only after the open.  open(2) of a FIFO with
# no writer blocks, and it ran on the runtime's loop: one GET of a FIFO under the root -- placed by anyone who may
# write there, an upload directory, a second account -- and the server answered nothing more, to anybody, until
# something wrote to the FIFO.  Measured on dev 3b7db9690: the GET timed out, the next GET of index.html too (000),
# and both came back once a writer appeared.  The web runtime already opened with O_NONBLOCK; the server's cache
# build, the proxy's FastCGI files and the Lua page loader did not either, and do now.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate fifo
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1980))
trap 'daemon_stop' EXIT

echo "=== Integration: a FIFO under --http is answered 404 and stalls nothing ==="
daemon_start "$BIN"
mkdir -p "$T/root"
printf 'hello\n' > "$T/root/index.html"
mkfifo "$T/root/x.txt"
"$BIN" create server s -p "$P" --http "$T/root" -s >/dev/null 2>&1
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$P/index.html" && break; sleep 0.1; done
code() { curl -s -m 3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$P/$1"; }

expect "an ordinary file is served" "$(code index.html)" 200
expect "a FIFO is not found, at once" "$(code x.txt)" 404
expect "and the server still answers after it" "$(code index.html)" 200
mkfifo "$T/root/y.txt"
expect "a FIFO made after the start is not found either" "$(code y.txt)" 404
expect "and stalls nothing" "$(code index.html)" 200

# Let a stalled open go, so a red run ends without a hung worker.
( exec 3>"$T/root/x.txt" ) & sleep 0.5; kill $! 2>/dev/null
( exec 3>"$T/root/y.txt" ) & sleep 0.5; kill $! 2>/dev/null

echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
