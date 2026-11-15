#!/usr/bin/env bash
# Integration test: HTTP/3's critical streams -- the control stream and the two QPACK streams of each side.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   closed       either side's control or QPACK stream ended by FIN, by RESET_STREAM, or asked to end by
#                STOP_SENDING closes the connection H3_CLOSED_CRITICAL_STREAM (0x104; RFC 9114 6.2.1, RFC 9204 4.2).
#                A reset or a STOP_SENDING closed it before too, but as a transport INTERNAL_ERROR (0x1): nghttp3's
#                answer was turned into "the callback failed" without its code, which tells the peer this side broke.
#   twice        a second control, QPACK encoder or QPACK decoder stream closes it H3_STREAM_CREATION_ERROR (0x103);
#                there is no third chance, since the server allows the client three unidirectional streams in all
#                (the class of nginx's CVE-2026-42530, an encoder stream opened again).
#   after        the runtime still serves.
#
# Skipped when the binary was built without HTTP/3 or the python aioquic library is missing.
# suite: isolated
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgh3k
P1=$((SL_PORT_BASE+1879))
T="$SOCKETLEY_TMPD"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }
skip() { echo "  SKIP: $1"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }

cleanup() {
    "$BIN" stop stgh3k >/dev/null 2>&1 || true
    sleep 0.3
    "$BIN" remove stgh3k >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: HTTP/3 critical streams ==="
for tool in openssl curl python3; do
    command -v "$tool" >/dev/null 2>&1 || skip "$tool is not available"
done
python3 -c 'import aioquic, sys; sys.exit(int(aioquic.__version__.split(".")[0]) < 1)' 2>/dev/null \
    || skip "the python aioquic library 1.0 or later is not installed (pip install aioquic)"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout "$T/key.pem" -out "$T/cert.pem" -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1

daemon_start "$BIN"
"$BIN" create storage stgh3k -p "$P1" --dir "$T/data" --anonymous --tls --cert "$T/cert.pem" --key "$T/key.pem" \
    --shards 1 -s >/dev/null 2>&1 || bad "create" "the runtime was not created"
for _ in $(seq 1 100); do [ "$(curl -s -m 5 --cacert "$T/cert.pem" -o /dev/null -w '%{http_code}' "https://localhost:$P1/")" = 200 ] && break; sleep 0.1; done

sum() { "$BIN" stats stgh3k 2>/dev/null | awk -F: -v k="$1" '$1==k {s+=$2} END {print s+0}'; }
for _ in $(seq 1 50); do [ "$(sum h3)" -ge 1 ] && break; sleep 0.1; done
[ "$(sum h3)" -ge 1 ] || skip "this build has no HTTP/3"

edge() { timeout 30 python3 "$HERE/lib_storage_http3_edge.py" critical "$P1" "$T/cert.pem" "$1" 2>&1 | tail -1; }

expect "the client's control stream reset closes it H3_CLOSED_CRITICAL_STREAM" "$(edge reset_ctrl)" "app 0x104"
expect "the client's control stream ended closes it so" "$(edge fin_ctrl)" "app 0x104"
expect "the server's control stream asked to stop closes it so" "$(edge stop_srv_ctrl)" "app 0x104"
expect "the client's QPACK encoder stream ended closes it so" "$(edge fin_enc)" "app 0x104"
expect "the client's QPACK decoder stream reset closes it so" "$(edge reset_dec)" "app 0x104"
expect "a second control stream closes it H3_STREAM_CREATION_ERROR" "$(edge dup_ctrl)" "app 0x103"
expect "a second QPACK encoder stream closes it so" "$(edge dup_enc)" "app 0x103"
expect "a second QPACK decoder stream closes it so" "$(edge dup_dec)" "app 0x103"

expect "the runtime still serves over HTTP/3" \
    "$(python3 "$HERE/lib_storage_http3_edge.py" peer "$P1" "$T/cert.pem" | awk '{print $NF}')" 200
for _ in $(seq 1 100); do [ "$(sum h3_open)" -eq 0 ] && break; sleep 0.1; done
expect "and holds no connection of them" "$(sum h3_open)" 0

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
