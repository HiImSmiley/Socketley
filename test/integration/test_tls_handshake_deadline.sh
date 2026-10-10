#!/usr/bin/env bash
# ─── WHAT WENT WRONG ────────────────────────────────────────────────────────
#
# A peer that completed the TCP accept and then sent nothing sat in
# tls_conn_handshake forever.  It is in m_clients from the accept onward, and
# --max-connections counts that set, so N such peers refused every real client
# for as long as they kept the sockets open.  Nothing reclaimed them: the idle
# sweep is not armed unless --idle-timeout is set, and an idle timeout is a
# different question anyway -- a quiet connection that DID handshake is
# legitimate on a daemon built for long-living ones.
#
# Measured: control arm ok, two silent connections against --max-connections 2
# refused, and no reclaim in 120 seconds with the peers still held.
#
# ─── WHAT IS ASSERTED ───────────────────────────────────────────────────────
#
# Three arms per runtime, because the middle one alone proves nothing:
#
#   * control  -- a real client succeeds with no silent peers, so a refusal
#                 below is about the slots and not about the setup
#   * loaded   -- cap-many silent peers, and the real client is refused
#   * reclaim  -- the same client gets in WHILE THE SILENT PEERS ARE STILL
#                 HELD, which is the only reading that distinguishes a deadline
#                 from the holder having let go
#
# That last distinction is not hypothetical.  The first version of this
# measurement held the peers for 60 seconds against a 90-second window and
# reported the holder's own sleep -- the same ~63s figure the real deadline
# gives -- identically with and without the change.  So the holder outlasts the
# window by a wide margin here, and its liveness is asserted at the reading.
#
# All three runtimes at once: they are loaded together and the one wait is
# shared, because three waits of a minute apiece is three minutes of nothing.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BIN="${BIN:-$HERE/../../bin/Release/socketley}"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"

if ! command -v openssl >/dev/null 2>&1; then
    echo "=== Integration: a handshake that never finishes gives up its slot ==="
    echo "  SKIP: openssl CLI not available (needed for the certificate and the client)"
    exit 0
fi

daemon_isolate hsdeadline
TMPD=$(mktemp -d)
PASS=0; FAIL=0; TOTAL=0
HOLDER=""
cleanup() {
    [ -n "$HOLDER" ] && kill -9 "$HOLDER" 2>/dev/null
    "$BIN" stop  hs_srv hs_cache hs_proxy hs_drib >/dev/null 2>&1 || true
    "$BIN" remove hs_srv   >/dev/null 2>&1 || true
    "$BIN" remove hs_cache >/dev/null 2>&1 || true
    "$BIN" remove hs_proxy >/dev/null 2>&1 || true
    "$BIN" remove hs_drib  >/dev/null 2>&1 || true
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

echo "=== Integration: a handshake that never finishes gives up its slot ==="

openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=localhost \
    -keyout "$TMPD/key.pem" -out "$TMPD/cert.pem" >/dev/null 2>&1 || true
if [ -s "$TMPD/cert.pem" ] && [ -s "$TMPD/key.pem" ]; then pass
else
    echo "  SKIP: openssl could not generate a certificate"
    exit 0
fi

CAP=2
P=$((SL_PORT_BASE + 1041))
SRV=$P; CACHE=$((P + 1)); PROXY=$((P + 2)); BACKEND=$((P + 3)); DRIB=$((P + 4))

daemon_start "$BIN"

TLS="--tls --cert $TMPD/cert.pem --key $TMPD/key.pem --max-connections $CAP"
RC=0
# shellcheck disable=SC2086
timeout 20 "$BIN" create server hs_srv   -p "$SRV"   $TLS -s >/dev/null 2>&1 || RC=$?
# shellcheck disable=SC2086
timeout 20 "$BIN" create cache  hs_cache -p "$CACHE" $TLS -s >/dev/null 2>&1 || RC=$?
# shellcheck disable=SC2086
timeout 20 "$BIN" create proxy  hs_proxy -p "$PROXY" $TLS \
    --backend "127.0.0.1:$BACKEND" -s >/dev/null 2>&1 || RC=$?
# A fourth, differing only in --idle-timeout, which is the flag that used to
# decide what the deadline measured: last_activity is refreshed on every read
# but only when it is set, so a peer that dribbled inside an unfinished record
# kept resetting the deadline and the operator who configured a timeout got
# LESS reclamation than the one who did not.  Measured: never, against 63
# seconds without the flag.
# shellcheck disable=SC2086
timeout 20 "$BIN" create server hs_drib -p "$DRIB" $TLS --idle-timeout 300 -s \
    >/dev/null 2>&1 || RC=$?
if [ "$RC" -eq 0 ]; then pass
else fail "the four TLS runtimes are created" "a create exited $RC"; fi

for port in "$SRV" "$CACHE" "$PROXY" "$DRIB"; do
    BOUND=""
    for _ in $(seq 1 40); do
        ss -ltn 2>/dev/null | grep -q ":$port " && { BOUND=yes; break; }
        sleep 0.25
    done
    if [ "$BOUND" = yes ]; then pass
    else fail "the listener on :$port is bound" "nothing bound after 10s"; fi
done

# A real client, judged on the handshake and not on any reply: the question is
# whether the accept path let it in at all.
# The output is read whole first, since grep -q ends early and pipefail then blames openssl.
client() {  # port -> ok | refused
    local o
    o=$(timeout 8 openssl s_client -connect "127.0.0.1:$1" -brief </dev/null 2>&1) || true
    if grep -qiE "CONNECTION ESTABLISHED|Verification" <<<"$o"; then echo ok; else echo refused; fi
}

# ─── Arm one: the control ───────────────────────────────────────────────────
for pair in "server:$SRV" "cache:$CACHE" "proxy:$PROXY" "dribbled:$DRIB"; do
    kind=${pair%%:*}; port=${pair##*:}
    got=$(client "$port")
    if [ "$got" = ok ]; then pass
    else fail "control: a real client reaches the $kind with no silent peers" \
              "got '$got' — a refusal below would be about the setup, not the slots"; fi
done

# ─── Arm two: cap-many peers that connect and say nothing ───────────────────
#
# 400 seconds, which is far past the ~60 the deadline needs, so this cannot be
# what the reclaim below is measuring.
python3 -c "
import socket, sys, time
hold = []
for port in ($SRV, $CACHE, $PROXY):
    for _ in range($CAP):
        s = socket.socket()
        s.connect(('127.0.0.1', port))
        hold.append(s)
# The dribbling half.  A valid but incomplete TLS record -- handshake type,
# TLS 1.0, declaring 4095 bytes of body -- because random bytes make OpenSSL
# error out and the connection would then drop for a reason that is not this
# one.  Each later byte is a read completion on the runtime, which is what used
# to refresh last_activity and push the deadline out for ever.
drib = []
for _ in range($CAP):
    s = socket.socket()
    s.connect(('127.0.0.1', $DRIB))
    s.sendall(b'\x16\x03\x01\x0f\xff')
    drib.append(s)
with open('$TMPD/held', 'w') as f:
    f.write(str(len(hold) + len(drib)))
end = time.time() + 400
while time.time() < end:
    time.sleep(20)
    for s in drib:
        try:
            s.sendall(b'\x00')
        except Exception:
            pass
" >/dev/null 2>&1 &
HOLDER=$!
# bash announces a killed background job after the results line otherwise.
disown "$HOLDER" 2>/dev/null || true

HELD=0
for _ in $(seq 1 40); do
    HELD=$(cat "$TMPD/held" 2>/dev/null || echo 0)
    [ "${HELD:-0}" -ge $((CAP * 4)) ] && break
    sleep 0.25
done
if [ "${HELD:-0}" -eq $((CAP * 4)) ]; then pass
else fail "cap-many peers reached all four" \
          "connected ${HELD:-0} of $((CAP * 4))"; fi

for pair in "server:$SRV" "cache:$CACHE" "proxy:$PROXY" "dribbled:$DRIB"; do
    kind=${pair%%:*}; port=${pair##*:}
    got=$(client "$port")
    if [ "$got" = refused ]; then pass
    else fail "loaded: silent peers fill the $kind's cap" \
              "got '$got' — the cap did not count them, so nothing below is measured"; fi
done

# ─── Arm three: the reclaim, with the peers still held ──────────────────────
#
# One wait for all three.  The deadline is 30s on a sweep that ticks every 30s,
# so a slot comes back somewhere under 60; the budget is double that.
declare -A WHEN=()
for pair in "server:$SRV" "cache:$CACHE" "proxy:$PROXY" "dribbled:$DRIB"; do
    WHEN[${pair%%:*}]=never
done
for i in $(seq 1 40); do
    all_in=yes
    for pair in "server:$SRV" "cache:$CACHE" "proxy:$PROXY" "dribbled:$DRIB"; do
        kind=${pair%%:*}; port=${pair##*:}
        [ "${WHEN[$kind]}" != never ] && continue
        if [ "$(client "$port")" = ok ]; then WHEN[$kind]="~$((i * 3))s"; else all_in=no; fi
    done
    [ "$all_in" = yes ] && break
    sleep 3
done

# Asserted before the readings are believed: a holder that had exited would
# have freed the slots itself, which is the measurement this file's header
# records getting wrong.
if kill -0 "$HOLDER" 2>/dev/null; then pass
else fail "the silent peers were still held at the reading" \
          "the holder exited, so the slots were freed by it and not by a deadline"; fi

for kind in server cache proxy dribbled; do
    if [ "${WHEN[$kind]}" != never ]; then pass
    else fail "the $kind reclaims a slot from a handshake that never finished" \
              "no real client got in within 120s while the peers were held"; fi
done

# ─── And it leaves a record, once ───────────────────────────────────────────
#
# Nothing is said to a peer dropped this way -- there is no protocol yet to say
# it in -- so the log is the only evidence the deadline and not something else
# closed it.  Read before daemon_stop, which deletes it.
#
# The count matters as much as the presence: the attack this deadline exists
# for is many peers at once, so a line each would be a flood produced by the
# defence.  Six peers fell on the server, the cache and the proxy together, and
# each runtime must have said so exactly once per sweep.
DROP_LINES=$(grep -c "did not finish a TLS handshake" "$SOCKETLEY_DLOG" 2>/dev/null || true)
if [ "${DROP_LINES:-0}" -ge 1 ]; then pass
else fail "the drop is written down at all" \
          "nothing in the daemon log names a handshake deadline" \
          "an operator seeing connections fail has no way to reach the cause"; fi

# Two per runtime would mean per-connection logging, since each was loaded with
# two peers; four runtimes, so anything past four is a line per peer.
if [ "${DROP_LINES:-0}" -le 4 ]; then pass
else fail "and written down once per sweep, not once per peer" \
          "$DROP_LINES lines for $((CAP * 4)) peers across 4 runtimes"; fi

if grep -q "dropped $CAP connection(s) that did not finish" "$SOCKETLEY_DLOG" 2>/dev/null; then pass
else fail "and the line carries the count" \
          "got: $(grep -m1 'did not finish a TLS handshake' "$SOCKETLEY_DLOG" 2>/dev/null || echo '<no line>')"; fi

echo "  reclaimed: server ${WHEN[server]}, cache ${WHEN[cache]}, proxy ${WHEN[proxy]}, dribbled+idle-timeout ${WHEN[dribbled]}"
echo "  the drop was written down in $DROP_LINES line(s) for $((CAP * 4)) peers"
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
