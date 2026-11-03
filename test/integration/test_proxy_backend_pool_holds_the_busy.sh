#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# A proxy keeps as many backend connections as its clients keep busy: two hundred keep-alive clients through one
# backend open about two hundred connections to it, not one for most of their requests.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a pool bounded below what one turn of answers hands back: past it each socket handed back is closed, and the
#     next request connects anew -- at a bound of 32, tens of thousands of connects in a few seconds
#   * the load not reaching the backend at all, which would pass the first on no connections
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ready.sh"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

daemon_isolate proxy_pool_busy
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+420))
BE=$P; PX=$((P+1)); N=200
trap daemon_stop EXIT

echo "=== Integration: a proxy keeps the backend connections its clients keep busy ==="

if ! gcc -O2 -o "$T/load" "$HERE/lib_ka_get_load.c" 2>"$T/cc.log"; then
    bad "the load client builds" "$(head -3 "$T/cc.log")"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"; exit 1
fi
cat > "$T/be.lua" <<'LUAEOF'
function on_http_request(req)
    return { status = 200, headers = { ["Content-Type"] = "text/plain" }, body = "pooled" }
end
LUAEOF

daemon_start "$BIN"
"$BIN" create server be -p "$BE" --bind 127.0.0.1 --lua "$T/be.lua" -s >/dev/null 2>&1
"$BIN" create proxy px -p "$PX" --bind 127.0.0.1 --backend "127.0.0.1:$BE" -s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$BE"; ready_tcp 127.0.0.1 "$PX"
for _ in $(seq 1 50); do [ "$(curl -s "http://127.0.0.1:$PX/px/x")" = pooled ] && break; sleep 0.1; done

conns() { "$BIN" stats be 2>/dev/null | awk -F': *' '$1 == "total_connections" {print $2}'; }
before=$(conns)
out=$("$T/load" "$PX" "$N" 3 /px/x)
sleep 0.5
after=$(conns)
answered=$(echo "$out" | tr ' ' '\n' | awk -F: '$1 == "200" {print $2 + 0}')
opened=$(( ${after:-0} - ${before:-0} ))
echo "  answers: $out, backend connections opened: $opened"

[ "${answered:-0}" -gt 5000 ] && ok "the load reached the backend (${answered:-0} answers)" \
    || bad "the load reached the backend" "$out"
[ -n "$before" ] && [ "$opened" -le $((N * 2)) ] && ok "and opened no more connections to it than clients, twice over" \
    || bad "connections opened" "$opened for $N clients (before ${before:-none}, after ${after:-none})"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
