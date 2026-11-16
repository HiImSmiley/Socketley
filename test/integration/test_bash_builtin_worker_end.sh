#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: a shell's line to a worker that is ending is not taken, and the daemon says why
#
# A shell's `socketley send` goes on a link straight to the runtime's worker, and `remove` returns before that worker
# has ended.  A line on the link in between was read by nobody: the worker closed the link without an answer, and the
# shell said the worker ended before it answered for the line (exit 2) where the runtime was simply gone (exit 1).  The
# worker's end is held here (SOCKETLEY_WORKER_END_HOLD_MS) so the line lands in that window every run.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate bbend

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "expected '$2', got '$3'"; fi; }

echo "=== Integration: a shell's line to a worker that is ending is not taken ==="
SO="$(cd "$(dirname "$BIN")" && pwd)/socketley-bash.so"
if [ ! -f "$SO" ]; then
    echo "  SKIP: no $SO in this build"
    exit 0
fi

P=$((SL_PORT_BASE + 1968))
GOT="$SOCKETLEY_TMPD/got"
: > "$GOT"
LPID=""
cleanup() {
    [ -n "$LPID" ] && { kill -9 "$LPID" && wait "$LPID"; } 2>/dev/null
    daemon_stop
}
trap cleanup EXIT

python3 - "$P" "$GOT" > /dev/null 2>&1 <<'PY' &
import socket, sys
port, out = int(sys.argv[1]), sys.argv[2]
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port)); srv.listen(8)
with open(out, "ab", buffering=0) as f:
    while True:
        c, _ = srv.accept()
        while True:
            b = c.recv(65536)
            if not b:
                break
            f.write(b)
PY
LPID=$!
for _ in $(seq 1 200); do
    ss -ltnH 2>/dev/null > "$SOCKETLEY_TMPD/ss"
    grep -q ":$P " "$SOCKETLEY_TMPD/ss" && break
    sleep 0.05
done

SOCKETLEY_WORKER_END_HOLD_MS=4000 daemon_start "$BIN"
"$BIN" create client bbe -t "127.0.0.1:$P" -s >/dev/null 2>&1 && ok || bad "a client is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 50); do
    "$BIN" ls 2>/dev/null > "$SOCKETLEY_TMPD/ls"
    grep -q "bbe.*Up" "$SOCKETLEY_TMPD/ls" && break
    sleep 0.1
done
W=$("$BIN" stats bbe 2>/dev/null | sed -n 's/^pid://p')
[ -n "$W" ] && ok || bad "the worker's pid is in the stats" "none"

# The first line makes the link; after `remove` the worker stops its runtime and is held, alive, for four seconds.
SHELLPATH="$(cd "$(dirname "$BIN")" && pwd):$PATH"
out=$(PATH="$SHELLPATH" bash -c "enable -f '$SO' socketley
    socketley send bbe e1; echo \"|\$?\"
    socketley remove bbe >/dev/null 2>&1 || { socketley stop bbe; socketley remove bbe; } >/dev/null 2>&1
    sleep 1; kill -0 $W 2>/dev/null && echo '|alive'
    socketley send bbe e2; echo \"|\$?\"" 2>&1 | tr -d '\n')
check "a line to a removed runtime's ending worker is refused as the daemon refuses it" \
    "|0|aliveruntime not found: bbe|1" "$out"
for _ in $(seq 1 20); do grep -q e1 "$GOT" && break; sleep 0.1; done
check "only the line that was answered 0 reached the peer" "e1" "$(paste -sd'|' "$GOT")"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
