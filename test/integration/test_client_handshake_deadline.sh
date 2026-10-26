#!/usr/bin/env bash
# ─── WHAT WENT WRONG ────────────────────────────────────────────────────────
#
# A client whose TLS target accepted the connection and then said nothing sat
# there for ever.  --reconnect is driven by losing the socket, and a stalled
# handshake never loses it, so nothing re-dialled and nothing gave up.  `ls`
# reported CONN 1 and "Up 2 minutes" -- indistinguishable from a client that
# works, for a client that would never move a byte.
#
# Two causes, and the promise needed both fixed:
#
#   1. Nothing dropped the connection.  There is now a flat 30-second deadline
#      from the ClientHello going out; a handshake is bounded by round trips
#      rather than by data, so unlike a follower's dump it needs no progress
#      measure.
#   2. note_established() zeroed m_reconnect_attempt from a WRITE completion.
#      The ClientHello goes out fine -- the peer's kernel takes it -- so every
#      re-dial reset the limit and `--reconnect N` could never be reached.
#      Measured before the fix: six deadlines in three minutes, not one
#      refusal.  Its own comment says a completion proves "the peer accepted
#      the connection rather than that the kernel accepted the SQE", which is
#      exactly what a write completion does not.
#
# ─── WHAT IS ASSERTED ───────────────────────────────────────────────────────
#
# Read off the LISTENER's accept count, because an accept that happened is
# permanent while a state poll has to land in a window.  The holder outlasts
# the measurement by a wide margin and its liveness is asserted at the reading:
# a holder that had exited would have closed the sockets itself, and the client
# would have re-dialled for that reason instead of this one.
#
# Paired against a client pointed at a REAL TLS listener, which must connect
# and STAY connected -- a build that dropped every TLS client after thirty
# seconds would satisfy everything else here.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BIN="${BIN:-$HERE/../../bin/Release/socketley}"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"

if ! command -v openssl >/dev/null 2>&1; then
    echo "=== Integration: a client gives up on a target that never handshakes ==="
    echo "  NOT ASSERTED: openssl CLI not available (needed to generate a certificate)"
    echo "  Results: 0/0 passed (0 failed, 1 not asserted)"
    exit 0
fi

daemon_isolate clienths
TMPD=$(mktemp -d)
PASS=0; FAIL=0; TOTAL=0
HOLDER=""
cleanup() {
    [ -n "$HOLDER" ] && kill -9 "$HOLDER" 2>/dev/null
    "$BIN" stop  hs_cli hs_good hs_real >/dev/null 2>&1 || true
    "$BIN" remove hs_cli  >/dev/null 2>&1 || true
    "$BIN" remove hs_good >/dev/null 2>&1 || true
    "$BIN" remove hs_real >/dev/null 2>&1 || true
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
state_of() { "$BIN" ls 2>/dev/null | awk -v n="$1" '$2 == n {print tolower($0)}'; }

echo "=== Integration: a client gives up on a target that never handshakes ==="

openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=127.0.0.1" \
    -addext "subjectAltName=IP:127.0.0.1" \
    -keyout "$TMPD/key.pem" -out "$TMPD/cert.pem" >/dev/null 2>&1 || true
if [ -s "$TMPD/cert.pem" ] && [ -s "$TMPD/key.pem" ]; then pass
else
    echo "  NOT ASSERTED: openssl could not generate a certificate"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed, 1 not asserted)"
    exit 0
fi

P=$((SL_PORT_BASE + 1061))
STALL=$P; REAL=$((P + 1))

# Accepts and holds, speaking no TLS at all.  400 seconds, far past the ~70
# this measurement needs, so the holder letting go cannot be what it reads.
ACCEPTS="$TMPD/accepts"
: > "$ACCEPTS"
python3 -c "
import socket, sys, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $STALL)); s.listen(16); s.settimeout(1)
held = []; n = 0
end = time.time() + 400
while time.time() < end:
    try:
        c, _ = s.accept()
    except socket.timeout:
        continue
    held.append(c); n += 1
    with open('$ACCEPTS', 'w') as f:
        f.write(str(n) + '\n')
" >/dev/null 2>&1 &
HOLDER=$!
disown "$HOLDER" 2>/dev/null || true

READY=""
for _ in $(seq 1 40); do
    listeners=$(ss -ltn 2>/dev/null || true)
    [[ $listeners == *":$STALL "* ]] && { READY=yes; break; }
    sleep 0.25
done
if [ "$READY" = yes ]; then pass
else fail "the silent listener is bound" "nothing on :$STALL after 10s"; fi

daemon_start "$BIN"

# ─── The control: a real TLS listener of our own ────────────────────────────
RC=0
timeout 20 "$BIN" create server hs_real -p "$REAL" --tls \
    --cert "$TMPD/cert.pem" --key "$TMPD/key.pem" -s >/dev/null 2>&1 || RC=$?
timeout 20 "$BIN" create client hs_good -t "127.0.0.1:$REAL" --tls --ca "$TMPD/cert.pem" \
    --reconnect 1 -s >/dev/null 2>&1 || RC=$?
# --reconnect 1 is the initial dial plus one retry, so the limit is reached
# around 30 + 1 + 30 seconds rather than the 90 a limit of two would need.
timeout 20 "$BIN" create client hs_cli -t "127.0.0.1:$STALL" --tls --ca "$TMPD/cert.pem" \
    --reconnect 1 -s >/dev/null 2>&1 || RC=$?
if [ "$RC" -eq 0 ]; then pass
else fail "the pair and the stalled client are created" "a create exited $RC"; fi

sleep 2
A=$(cat "$ACCEPTS" 2>/dev/null || echo 0)
if [ "${A:-0}" -ge 1 ]; then pass
else fail "the client dialled the silent target at all" \
          "the listener saw ${A:-0} connections, so nothing below is measured"; fi

# ─── The re-dial, and then the limit ────────────────────────────────────────
GAVE_UP=never
for i in $(seq 1 40); do
    if grep -qE "failed" <<<"$(state_of hs_cli)"; then GAVE_UP="~$((i * 3 + 2))s"; break; fi
    sleep 3
done

# Before the readings are believed: the holder still holding is what makes this
# the deadline's doing rather than the sockets closing under the client.
if kill -0 "$HOLDER" 2>/dev/null; then pass
else fail "the silent peer was still held at the reading" \
          "the holder exited, so the client re-dialled for that reason"; fi

A=$(cat "$ACCEPTS" 2>/dev/null || echo 0)
if [ "${A:-0}" -ge 2 ]; then pass
else fail "a stalled handshake is dropped and the target dialled again" \
          "the listener saw ${A:-0} connections in 120s, expected at least 2" \
          "--reconnect was driven by losing the socket, and this never lost one"; fi

if [ "$GAVE_UP" != never ]; then pass
else fail "and --reconnect's limit is reached rather than reset every dial" \
          "hs_cli never reported failed in 120s" \
          "got: $(state_of hs_cli)"; fi

# ─── The control, read last so it has had the whole run to be dropped ───────
# Up with one connection, because an absent row or a client that never connected also lacks "failed".
GOOD=$(state_of hs_good)
if grep -q " up " <<<"$GOOD" && [ "$(awk '{print $5}' <<<"$GOOD")" = "1" ]; then pass
else fail "a client on a real TLS listener is connected and not dropped by the deadline" \
          "got: ${GOOD:-<no row>}" \
          "a build that dropped every TLS client would pass everything above"; fi
REALST=$(state_of hs_real)
if grep -q " up " <<<"$REALST"; then pass
else fail "and the listener it talks to is still up" "got: ${REALST:-<no row>}"; fi

echo "  the silent target was dialled $A time(s); the client gave up $GAVE_UP"
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
