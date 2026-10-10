#!/usr/bin/env bash
# Integration test: --http-cache over a root with an unreadable directory in it serves the rest.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * the cache's walk of the root throwing filesystem_error on the directory it
#     may not open, which nothing on the start path catches, so the worker died
#     and nothing was served at all
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

echo "=== Integration: --http-cache skips a directory it may not read ==="
if [ "$(id -u)" = 0 ]; then echo "  SKIP: root reads every directory"; exit 0; fi

daemon_isolate httpunread
P=$((SL_PORT_BASE+1963))
W=$SOCKETLEY_TMPD/www
mkdir -p "$W/sealed" "$W/open"
echo "front" > "$W/index.html"
echo "inner" > "$W/open/page.txt"
echo "hidden" > "$W/sealed/secret.txt"
chmod 000 "$W/sealed"
trap 'chmod 755 "$W/sealed"; daemon_stop' EXIT

daemon_start "$BIN"
"$BIN" create server hc -p "$P" --http "$W" --http-cache -s >/dev/null 2>&1
got=""
for _ in $(seq 1 30); do got=$(curl -s -m 2 "http://127.0.0.1:$P/open/page.txt"); [ -n "$got" ] && break; sleep 0.2; done
expect "a file beside the unreadable directory is served" "$got" "inner"
expect "and the one inside it is not" "$(curl -s -m 2 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$P/sealed/secret.txt")" "404"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
