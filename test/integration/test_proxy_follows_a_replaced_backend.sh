#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a proxy whose backend address was a runtime reached over its one companion node follows that
# address when another runtime, which binds no node, takes the port.
#
# What it would catch: a backend that took one node from the table kept no record of it, so follow_published_nodes
# saw no node before and none after and never resolved it again -- every request went to the node of a runtime that
# was gone, a 502 until the proxy restarted. Seen live when a docs server was replaced by a web runtime.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }

echo "=== Integration: a proxy follows a backend address another runtime took ==="
daemon_isolate pxfollow
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1950))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
daemon_start "$BIN"

mkdir -p "$T/site"; printf 'page\n' > "$T/site/index.html"
"$BIN" create server docs -p "$P" --bind 127.0.0.1 --http "$T/site" -s >/dev/null 2>&1 || bad "a server is made" "$(tail -3 "$SOCKETLEY_DLOG")"
"$BIN" create proxy px -p $((P+1)) --backend "127.0.0.1:$P" -s >/dev/null 2>&1 || bad "a proxy is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 50); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$((P+1))/px/")" = 200 ] && break; sleep 0.1; done
expect "the server answers through the proxy" "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$((P+1))/px/")" "200"
grep -q "is reached over .*docs" "$SOCKETLEY_DLOG" && ok || bad "the proxy reaches it over its node" "$(grep 'reached over' "$SOCKETLEY_DLOG" | tail -1)"

"$BIN" stop docs >/dev/null 2>&1; "$BIN" remove docs >/dev/null 2>&1
"$BIN" create web docs -p "$P" --root "$T/site" -s >/dev/null 2>&1 || bad "a web runtime takes the port" "$(tail -3 "$SOCKETLEY_DLOG")"
code=000
for _ in $(seq 1 50); do code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$((P+1))/px/"); [ "$code" = 200 ] && break; sleep 0.1; done
expect "the proxy reaches the runtime that took the port" "$code" "200"

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
