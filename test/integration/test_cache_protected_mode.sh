#!/usr/bin/env bash
# Integration test: a cache serves only this machine unless told otherwise.
#
# ─── WHY ────────────────────────────────────────────────────────────────────
#
# A cache binds every interface, has no password, and answers any client with
# everything it holds -- REPLICATE hands over the whole dataset, FLUSHALL
# empties it, EVAL runs a script.  That is the configuration Redis shipped
# until mass compromises made it add protected mode, and the reason is the
# same here: reaching an unauthenticated datastore from the network has to be
# something the operator said, not something the default did.
#
# So a TCP peer whose address is not loopback is answered -DENIED and closed,
# unless the cache was created with --public or with mutual TLS.
#
# ─── WHAT KEEPS IT HONEST ───────────────────────────────────────────────────
#
# The remote peer is this machine reached through its own non-loopback
# address, which the cache sees as exactly that.  Loopback must still be
# served on the same cache, --public must open it, and --public must survive
# a daemon restart, or the flag works once and the restore closes it again.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate protmode

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1))
        if [ "$1" = "$2" ]; then PASS=$((PASS+1)); echo "  PASS: $3"
        else FAIL=$((FAIL+1)); echo "  FAIL [$3]: got '$1', want '$2'"; fi; }
cleanup() { daemon_stop; }
trap cleanup EXIT

echo "=== Integration: a cache serves only this machine unless told otherwise ==="
command -v redis-cli >/dev/null 2>&1 || { echo "  FAIL: redis-cli required"; exit 1; }

# A non-loopback IPv4 address of this machine, which a connection to it
# arrives from as well.
EXT=$(ip -4 -o addr show scope global 2>/dev/null | awk '{sub(/\/.*/, "", $4); print $4; exit}')
[ -n "$EXT" ] || { echo "  FAIL: this machine has no non-loopback IPv4 address to test from"; exit 1; }
echo "  remote peer address: $EXT"

daemon_start "$BIN"
P=$((SL_PORT_BASE + 1800))
"$BIN" create cache pm_closed -p "$P" -s >/dev/null 2>&1
"$BIN" create cache pm_open -p $((P + 1)) --public -s >/dev/null 2>&1
for p in "$P" $((P + 1)); do
    for _ in $(seq 1 100); do redis-cli -p "$p" ping 2>/dev/null | grep -q PONG && break; sleep 0.1; done
done

remote() {
    python3 - "$EXT" "$1" <<'PYEOF'
import socket, sys
s = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=3)
s.sendall(b"*1\r\n$4\r\nPING\r\n")
out = b""
try:
    while True:
        b = s.recv(4096)
        if not b: break
        out += b
        if out.endswith(b"\r\n"): break
except socket.timeout:
    pass
print(out.split(b"\r\n")[0].decode("latin1")[:8])
PYEOF
}

remote_set() {
    python3 - "$EXT" "$1" <<'PYEOF'
import socket, sys
s = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=3)
s.sendall(b"*3\r\n$3\r\nSET\r\n$7\r\nrefused\r\n$1\r\nv\r\n")
s.settimeout(1)
try:
    s.recv(4096)
except socket.timeout:
    pass
PYEOF
}

ok "$(redis-cli -h 127.0.0.1 -p "$P" ping 2>/dev/null)" "PONG" "a default cache serves loopback"
ok "$(remote "$P")" "-DENIED " "and refuses a peer on another address"
remote_set "$P" >/dev/null
ok "$(redis-cli -h 127.0.0.1 -p "$P" exists refused 2>/dev/null)" "0" "a write from the refused peer was not run"
ok "$(redis-cli -h 127.0.0.1 -p "$P" dbsize 2>/dev/null)" "0" "the refused peer changed nothing"
ok "$(remote $((P + 1)))" "+PONG" "a --public cache serves that peer"

# The flag is part of the runtime, so the restored one is public too.
kill "$SOCKETLEY_DPID" 2>/dev/null
for _ in $(seq 1 60); do kill -0 "$SOCKETLEY_DPID" 2>/dev/null || break; sleep 0.1; done
wait "$SOCKETLEY_DPID" 2>/dev/null
"$BIN" daemon >>"$SOCKETLEY_DLOG" 2>&1 & SOCKETLEY_DPID=$!
for p in "$P" $((P + 1)); do
    for _ in $(seq 1 100); do redis-cli -p "$p" ping 2>/dev/null | grep -q PONG && break; sleep 0.1; done
done
ok "$(remote $((P + 1)))" "+PONG" "--public survives a daemon restart"
ok "$(remote "$P")" "-DENIED " "and so does the default"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
