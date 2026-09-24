#!/usr/bin/env bash
# Integration test: after a websocket close handshake the server closes the TCP
# connection first, even with many clients closing at once.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# RFC 6455 7.1.1 has the server close the underlying connection first, so the
# TIME-WAIT sits on its fixed port and not on a client's ephemeral one.  The
# server answered a Close frame through the write queue and sent its FIN from
# the write's completion -- a turn after the frame had woken the client.  One
# client at a time loses that race rarely (1 of 300); sixteen at once lose it
# nearly always: 4,750 of 4,800 TIME-WAITs on the clients' ports.  The frame
# now leaves by a direct send with our FIN in the same segment, as the --http
# answers do (send_final_and_fin).
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * every client gets its Close frame back -- a FIN ahead of the frame would
#     pass the next assertion and break the handshake
#   * the TIME-WAIT rows, counted per 4-tuple from the clients' own ports, are
#     the server's
#   * the server still upgrades a new client afterwards
set -euo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1
daemon_isolate wsclose
PASS=0; FAIL=0; TOTAL=0
WORK=$(mktemp -d)
cleanup(){ rm -rf "$WORK"; daemon_stop; }
trap cleanup EXIT
pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; for l in "${@:3}"; do echo "        $l"; done; }

echo "=== Integration: the server closes after a websocket close handshake ==="
if ! gcc -O2 -o "$WORK/client" "$HERE/lib_ws_close_race.c" 2>"$WORK/cc.log"; then
    echo "  SKIP: no C compiler"; cat "$WORK/cc.log"; echo "  Results: 0/0 passed (0 failed)"; exit 0
fi

daemon_start "$BIN"
P=$((SL_PORT_BASE + 106))
"$BIN" create server wc -p "$P" -s >/dev/null 2>&1 || true
for _ in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$P " && break; sleep 0.1; done
if ! ss -ltn 2>/dev/null | grep -q ":$P "; then
    echo "  FATAL: the server never bound $P"; echo "  Results: 0/0 passed (0 failed)"; exit 2
fi

C=16; N=100
# The clients' pids and not a bare wait, which would wait for the daemon too.
PIDS=()
for i in $(seq 1 "$C"); do
    "$WORK/client" "$P" "$N" >"$WORK/got.$i" 2>"$WORK/ports.$i" &
    PIDS+=($!)
done
wait "${PIDS[@]}"
cat "$WORK"/ports.* > "$WORK/ports"
GOT=$(cat "$WORK"/got.* | awk '{s += $1} END {print s + 0}')
sleep 0.5
read -r srv cli < <(ss -tan state time-wait 2>/dev/null | awk -v p="$P" -v f="$WORK/ports" '
    BEGIN { while ((getline l < f) > 0) mine[l] = 1 }
    NR > 1 { n = split($3, a, ":"); lp = a[n]; n = split($4, b, ":"); rp = b[n]
             if (lp == p && (rp in mine)) s++
             if (rp == p && (lp in mine)) c++ }
    END { printf "%d %d\n", s, c }')
TOT=$((C * N))
echo "  $TOT close handshakes from $C clients: TIME-WAIT on the server's port $srv, on the clients' $cli"

# ── 1. every handshake completed ────────────────────────────────────────────
if [ "$GOT" = "$TOT" ]; then pass
else fail "every client gets its Close frame back" "$GOT of $TOT"; fi

# ── 2. and the server closed first ──────────────────────────────────────────
if [ "$srv" -ge $((TOT * 8 / 10)) ] && [ "$cli" -le $((TOT / 10)) ]; then pass
else fail "the server holds the TIME-WAIT, not the clients" \
          "server-side rows $srv, client-side rows $cli for $TOT handshakes" \
          "-- a FIN sent from the write's completion loses to a client that" \
          "closes as soon as the Close frame arrives"; fi

# ── 3. and still serves ─────────────────────────────────────────────────────
if [ "$("$WORK/client" "$P" 1 2>/dev/null)" = "1" ]; then pass
else fail "the server still completes a handshake afterwards" "a new client got no Close back"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
