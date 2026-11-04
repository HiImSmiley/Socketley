#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: how a connection of a runtime on shared/http/conn_server ends, asked of an mcp and a web runtime.
#
# What it would catch: a request pipelined behind one that said Connection: close answered all the same (RFC 9112
# 9.6). The FIN that conn_server sends with that last answer is a race only a loaded server loses, which the web
# benchmark's connection-per-request row measures and no test here can.
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

echo "=== Integration: a conn_server connection ends where it says it does ==="
daemon_isolate connend
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1960))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
daemon_start "$BIN"

mkdir -p "$T/site"; printf 'page\n' > "$T/site/index.html"
"$BIN" create mcp tools -p "$P" --anonymous -s >/dev/null 2>&1 || bad "an mcp runtime is made" "$(tail -3 "$SOCKETLEY_DLOG")"
"$BIN" create web site -p $((P+1)) --root "$T/site" -s >/dev/null 2>&1 || bad "a web runtime is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for p in "$P" $((P+1)); do
    for _ in $(seq 1 50); do ss -ltn | grep -q ":$p " && break; sleep 0.1; done
done

for p in "$P" $((P+1)); do
    n=$(printf 'GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n' |
        timeout 3 nc -q2 127.0.0.1 "$p" 2>/dev/null | grep -ao 'HTTP/1.1 [0-9][0-9][0-9]' | wc -l)
    expect "port $p: nothing behind a Connection: close is answered" "$n" "1"
done

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
