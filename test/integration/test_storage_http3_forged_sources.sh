#!/usr/bin/env bash
# Integration test: handshakes from an address that never proved it is the sender's do not count against that
# address's share of the QUIC table.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   forged       an Initial costs nothing to send with someone else's source address.  The table keeps 256
#                connections from any one address, and it counted a connection from its first Initial -- before the
#                address had been proven by a Retry token or a finished handshake.  With the Retry threshold raised
#                (SOCKETLEY_STORAGE_HTTP3_RETRY_AFTER), 300 Initials "from" a victim's address, never finished and
#                renewed every 10 s, shut that address out of HTTP/3 (the class of nginx's CVE-2026-40460).  Now only
#                a connection whose address is proven counts, so the victim is still served.
#   proven       the 256 a proven address may hold are still its bound (test_storage_http3's crowd holds that).
#
# Skipped when the binary was built without HTTP/3 or the python aioquic library is missing.
# suite: isolated
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgh3f
P1=$((SL_PORT_BASE+1878))
T="$SOCKETLEY_TMPD"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }
skip() { echo "  SKIP: $1"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }

cleanup() {
    "$BIN" stop stgh3f >/dev/null 2>&1 || true
    sleep 0.3
    "$BIN" remove stgh3f >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: QUIC handshakes from unproven addresses ==="
for tool in openssl curl python3; do
    command -v "$tool" >/dev/null 2>&1 || skip "$tool is not available"
done
python3 -c 'import aioquic, sys; sys.exit(int(aioquic.__version__.split(".")[0]) < 1)' 2>/dev/null \
    || skip "the python aioquic library 1.0 or later is not installed (pip install aioquic)"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout "$T/key.pem" -out "$T/cert.pem" -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1

# No Retry at all, which an operator chooses to spare every client a round trip; the daemon hands its environment
# to the runtimes it starts.
SOCKETLEY_STORAGE_HTTP3_RETRY_AFTER=100000 daemon_start "$BIN"
"$BIN" create storage stgh3f -p "$P1" --dir "$T/data" --anonymous --tls --cert "$T/cert.pem" --key "$T/key.pem" \
    --shards 1 -s >/dev/null 2>&1 || bad "create" "the runtime was not created"
for _ in $(seq 1 100); do [ "$(curl -s -m 5 --cacert "$T/cert.pem" -o /dev/null -w '%{http_code}' "https://localhost:$P1/")" = 200 ] && break; sleep 0.1; done

sum() { "$BIN" stats stgh3f 2>/dev/null | awk -F: -v k="$1" '$1==k {s+=$2} END {print s+0}'; }
for _ in $(seq 1 50); do [ "$(sum h3)" -ge 1 ] && break; sleep 0.1; done
[ "$(sum h3)" -ge 1 ] || skip "this build has no HTTP/3"

expect "a client is served before anything else" \
    "$(python3 "$HERE/lib_storage_http3_edge.py" peer "$P1" "$T/cert.pem" | awk '{print $NF}')" 200

# 300 Initials from 127.0.0.1, each from a port of its own and never answered: what a forger sending with the
# victim's address leaves behind, since the server's answers go to the victim and not to him.
python3 "$HERE/lib_storage_http3_edge.py" halfopen "$P1" 300 >/dev/null 2>&1
for _ in $(seq 1 50); do [ "$(sum h3_open)" -ge 256 ] && break; sleep 0.1; done
shaking=$(sum h3_open)
if [ "$shaking" -ge 256 ]; then ok "the forged handshakes are under way ($shaking)"
else bad "the forged handshakes are under way" "h3_open=$shaking"; fi

expect "the address the forger named is still served while they are" \
    "$(python3 "$HERE/lib_storage_http3_edge.py" peer "$P1" "$T/cert.pem" | awk '{print $NF}')" 200

for _ in $(seq 1 150); do [ "$(sum h3_open)" -eq 0 ] && break; sleep 0.1; done
expect "every handshake never finished is dropped within its 10 s" "$(sum h3_open)" 0

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
