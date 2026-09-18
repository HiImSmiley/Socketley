#!/usr/bin/env bash
# ─── WHAT WENT WRONG ────────────────────────────────────────────────────────
#
# A cache closes a connection that accumulates past --read-buffer without ever
# completing a command.  The cleartext path said so in the log; the TLS path,
# with the same condition three hundred lines away, said nothing -- so whether
# a closed connection could be explained depended on whether the listener
# happened to be TLS.
#
# And the message that did exist named "1 MiB", which is the compiled-in
# default rather than the limit applied: on a runtime created with
# --read-buffer 8M it sent whoever read it looking in the wrong place.
#
# ─── WHAT IS ASSERTED ───────────────────────────────────────────────────────
#
# Both paths, with --read-buffer set to something that is NOT the default, so
# "names the limit" cannot pass by naming the number it was compiled with.
#
# And the count, separately: one line per connection.  Both checks re-enter --
# the TLS one sits inside the ssl_read loop, and a TLS connection walks the
# common check as well after the decryptor has run.  Measured while building
# this: four lines for one connection, then two, before the guards were right.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BIN="${BIN:-$HERE/../../bin/Release/socketley}"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"

if ! command -v openssl >/dev/null 2>&1; then
    echo "=== Integration: a cache says why it closed an overflowing connection ==="
    echo "  SKIP: openssl CLI not available (needed for the TLS half)"
    exit 0
fi

daemon_isolate ovflow
TMPD=$(mktemp -d)
PASS=0; FAIL=0; TOTAL=0
cleanup() {
    "$BIN" stop  ov_plain ov_tls >/dev/null 2>&1 || true
    "$BIN" remove ov_plain >/dev/null 2>&1 || true
    "$BIN" remove ov_tls   >/dev/null 2>&1 || true
    daemon_stop
    rm -rf "$TMPD"
}
trap cleanup EXIT

pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

echo "=== Integration: a cache says why it closed an overflowing connection ==="

openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=127.0.0.1" \
    -addext "subjectAltName=IP:127.0.0.1" \
    -keyout "$TMPD/key.pem" -out "$TMPD/cert.pem" >/dev/null 2>&1 || true
if [ -s "$TMPD/cert.pem" ]; then pass
else
    echo "  SKIP: openssl could not generate a certificate"
    exit 0
fi

# Deliberately not the 1 MiB default: a message that names its compiled-in
# figure would pass every assertion below if the limit under test were that
# figure.
RB=2097152
P=$((SL_PORT_BASE + 1101))
PLAIN=$P; TLS_P=$((P + 1))

daemon_start "$BIN"
RC=0
timeout 20 "$BIN" create cache ov_plain -p "$PLAIN" --read-buffer "$RB" -s >/dev/null 2>&1 || RC=$?
timeout 20 "$BIN" create cache ov_tls -p "$TLS_P" --read-buffer "$RB" --tls \
    --cert "$TMPD/cert.pem" --key "$TMPD/key.pem" -s >/dev/null 2>&1 || RC=$?
if [ "$RC" -eq 0 ]; then pass
else fail "both caches are created" "a create exited $RC"; fi

for port in "$PLAIN" "$TLS_P"; do
    BOUND=""
    for _ in $(seq 1 40); do
        ss -ltn 2>/dev/null | grep -q ":$port " && { BOUND=yes; break; }
        sleep 0.25
    done
    if [ "$BOUND" = yes ]; then pass
    else fail "the listener on :$port is bound" "nothing after 10s"; fi
done

# A command that never completes, past the limit: `set k xxx...` with no
# newline, which is not malformed -- only unfinished, and larger than allowed.
python3 -c "
import socket, ssl, time
n = $RB + 200000
s = socket.socket(); s.settimeout(10)
s.connect(('127.0.0.1', $PLAIN)); s.sendall(b'set k ' + b'x' * n)
try: s.recv(10)
except Exception: pass
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
t = ctx.wrap_socket(socket.socket()); t.settimeout(10)
t.connect(('127.0.0.1', $TLS_P)); t.sendall(b'set k ' + b'x' * n)
try: t.recv(10)
except Exception: pass
" >/dev/null 2>&1 || true
sleep 2

PLAIN_N=$(grep -c "ov_plain.*accumulated" "$SOCKETLEY_DLOG" 2>/dev/null || true)
TLS_N=$(grep -c "ov_tls.*accumulated" "$SOCKETLEY_DLOG" 2>/dev/null || true)

if [ "${PLAIN_N:-0}" -ge 1 ]; then pass
else fail "the cleartext close names its runtime and its limit" \
          "it did say something before this change -- without either"; fi
if [ "${TLS_N:-0}" -ge 1 ]; then pass
else fail "the TLS close is explained at all" \
          "the same condition as the cleartext one, and it said nothing"; fi

# Separately from presence, because a bound passes at zero and that is what
# keeps the counter-proof sharp.
if [ "${PLAIN_N:-0}" -le 1 ]; then pass
else fail "the cleartext path says it once per connection" "$PLAIN_N lines for 1 connection"; fi
if [ "${TLS_N:-0}" -le 1 ]; then pass
else fail "the TLS path says it once per connection" \
          "$TLS_N lines for 1 connection — both checks re-enter"; fi

# The limit applied, not the one it was compiled with.
for n in ov_plain ov_tls; do
    if grep -q "$n.*more than $RB bytes" "$SOCKETLEY_DLOG" 2>/dev/null; then pass
    else fail "$n names the limit it applied" \
              "--read-buffer was $RB" \
              "got: $(grep -m1 "$n.*accumulated" "$SOCKETLEY_DLOG" 2>/dev/null | sed 's/^.*cache /cache /' || echo '<no line>')"; fi
done
if ! grep -q "accumulated.*1 MiB" "$SOCKETLEY_DLOG" 2>/dev/null; then pass
else fail "and neither invents the compiled-in figure" \
          "got: $(grep -m1 '1 MiB' "$SOCKETLEY_DLOG" 2>/dev/null)"; fi

echo "  lines: cleartext $PLAIN_N, TLS $TLS_N, both naming $RB bytes"
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
