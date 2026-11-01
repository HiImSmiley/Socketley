#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: a script that sends to a connection while --http is sending it a file does not put its bytes
# inside the file.
#
# What it would catch: self.send() to a client id whose connection has a file body in flight. The body goes by
# sendfile (or a splice, for a window out of the page cache) straight from the file to the socket, so a write the
# script's send hands the ring lands between two of its bursts, and the download is no longer the file.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate httpsend
T=$SOCKETLEY_TMPD; WWW="$T/www"; P=$((SL_PORT_BASE+1963))
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
trap 'daemon_stop' EXIT

mkdir -p "$WWW"
head -c $((64 << 20)) /dev/urandom >"$WWW/big.bin"
cat >"$T/talk.lua" <<'LUA'
tick_ms = 10
local ids = {}
function on_connect(id) ids[id] = true end
function on_disconnect(id) ids[id] = nil end
function on_tick(dt) for id in pairs(ids) do self.send(id, "SCRIPT-SAYS-HELLO") end end
LUA

echo "=== Integration: a script's send does not land inside a file being sent ==="
daemon_start "$BIN"
"$BIN" create server hs -p "$P" --http "$WWW" --lua "$T/talk.lua" -s >/dev/null
for _ in $(seq 1 50); do curl -s -o /dev/null -r 0-0 "http://127.0.0.1:$P/big.bin" && break; sleep 0.1; done

want=$(sha256sum <"$WWW/big.bin" | cut -c1-16)
for i in 1 2 3; do
    got=$(curl -s --limit-rate 64M -m 60 "http://127.0.0.1:$P/big.bin" | sha256sum | cut -c1-16)
    if [ "$got" = "$want" ]; then ok; else bad "download $i is the file, the script's sends kept out of it" "got $got want $want"; fi
done
got=$(curl -s -m 60 -o /dev/null -o "$T/second" -w '%{http_code}' "http://127.0.0.1:$P/big.bin" "http://127.0.0.1:$P/big.bin" | tail -c 3)
if [ "$(sha256sum <"$T/second" | cut -c1-16)" = "$want" ]; then ok; else bad "and the second file on a kept-alive connection" "differs"; fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
