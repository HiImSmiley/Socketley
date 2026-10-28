#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: the dashboard reads a runtime's cert, bind and listen while `edit` rewrites them.
#
# What it would catch:
#   * the metrics thread copying a path the event loop is reassigning, which a TSan build reports as a data race and
#     which can crash any build when the copy reads a buffer the assignment has just freed
#   * a lock between the two that the event loop or the dashboard waits on for good
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }

# The config path and not the variable, as test_metrics_endpoint.sh explains.
unset SOCKETLEY_CONFIG

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: the dashboard reads a runtime that edit is changing ==="
daemon_isolate dashedit
M=$((SL_PORT_BASE + 1976))
P=$((SL_PORT_BASE + 1977))
HAMMER=""
trap '[ -n "$HAMMER" ] && kill "$HAMMER" 2>/dev/null; daemon_stop' EXIT
mkdir -p "$HOME/.config/socketley"
printf 'config = { metrics_port = %s }\n' "$M" > "$HOME/.config/socketley/config.lua"
daemon_start "$BIN"
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$M/" && break; sleep 0.1; done

# Four readers of /api/edge, which copies every runtime's cert, bind and listen on the metrics thread.
python3 - "$M" <<'PY' &
import socket, sys, threading
port = int(sys.argv[1])
def read():
    while True:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            s.sendall(b"GET /api/edge HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            while s.recv(65536):
                pass
            s.close()
        except OSError:
            pass
for _ in range(4):
    threading.Thread(target=read, daemon=True).start()
threading.Event().wait()
PY
HAMMER=$!

# Each runtime's path doubles edit by edit, so every assignment outgrows the buffer the reader may be copying and frees it.
long() { printf '/tmp/%s' "$(head -c "$1" /dev/zero | tr '\0' "$2")"; }
edits=0
for r in $(seq 1 12); do
    "$BIN" create server "ed$r" -p "$((P + r))" >/dev/null 2>&1
    for n in 1000 2000 4000 8000 16000 32000 64000 120000; do
        "$BIN" edit "ed$r" --tls --cert "$(long "$n" c)" --key /tmp/k -p "127.0.0.$((n % 200 + 1)):$((P + r))" \
            >/dev/null 2>&1
        edits=$((edits + 1))
    done
    "$BIN" edit "ed$r" --listen "/tmp/ed$r.sock" >/dev/null 2>&1
    kill -0 "$SOCKETLEY_DPID" 2>/dev/null || break
done
kill "$HAMMER" 2>/dev/null; wait "$HAMMER" 2>/dev/null; HAMMER=""

kill -0 "$SOCKETLEY_DPID" 2>/dev/null && ok || bad "the daemon outlives $edits edits read by the dashboard" \
    "$(tail -3 "$SOCKETLEY_DLOG")"
code=$(curl -s -o /dev/null -w '%{http_code}' -m 5 "http://127.0.0.1:$M/api/edge")
[ "$code" = 200 ] && ok || bad "and the dashboard still answers" "HTTP $code"
"$BIN" show ed12 2>/dev/null | grep -q "\"cert_path\": \"/tmp/cccc" && ok || bad "and the last edit is the one kept" \
    "$("$BIN" show ed12 2>&1 | head -c 200)"
! grep -qE 'Sanitizer:|runtime error:' "$SOCKETLEY_DLOG" && ok || bad "and a sanitizer build reports no race between them" \
    "$(grep -E -A12 'Sanitizer:' "$SOCKETLEY_DLOG" | head -30)"

echo "  Results: $PASS/$((PASS+FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
