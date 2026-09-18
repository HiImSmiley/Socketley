#!/usr/bin/env bash
# ─── WHAT WENT WRONG ────────────────────────────────────────────────────────
#
# parse_partial() bounds the SIZE of an HTTP head that has arrived in part --
# 16 KB, at two call sites -- and bounded the time at neither.  So a peer that
# sent "POST /x HTTP/1.1\r\nHost: x\r\n" and stopped sat in m_clients for as
# long as it kept the socket open, and --max-connections counts m_clients.
#
# Measured on a server with --max-connections 2: two such peers, control arm
# ok, loaded arm refused, and nothing reclaimed them in 75 seconds.
#
# The proxy already bounded it, at PROXY_HEADER_TIMEOUT_SEC = 10.  The server
# asks the same question of the same http_framing.h and had no answer, so the
# constant moved to shared/ where the length question already lives.
#
# ─── WHAT IS ASSERTED ───────────────────────────────────────────────────────
#
# Both call sites, because a GET and a POST do not take the same branch:
# parse_partial() sends any GET to proto_ws_upgrading (it might be an upgrade)
# and everything else to proto_http.  The first measurement of this change
# tested only GET and would have left half of it unmeasured.
#
# And a plain server whose peers sent a partial LINE, which must be untouched.
# That arm is not a nicety: a quiet half-message on a raw connection is
# legitimate on a daemon built for long-living ones, so a fix that bounded any
# non-empty buffer would break the thing the daemon is for -- and would pass
# every other assertion here.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BIN="${BIN:-$HERE/../../bin/Release/socketley}"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate headdl
TMPD=$(mktemp -d)
PASS=0; FAIL=0; TOTAL=0
HOLDER=""
cleanup() {
    [ -n "$HOLDER" ] && kill -9 "$HOLDER" 2>/dev/null
    "$BIN" stop  hd_post hd_get hd_raw >/dev/null 2>&1 || true
    "$BIN" remove hd_post >/dev/null 2>&1 || true
    "$BIN" remove hd_get  >/dev/null 2>&1 || true
    "$BIN" remove hd_raw  >/dev/null 2>&1 || true
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

echo "=== Integration: a head that arrives in part gives up its slot ==="

mkdir -p "$TMPD/www"
echo "HEAD-DEADLINE-BODY" > "$TMPD/www/probe.txt"

CAP=2
P=$((SL_PORT_BASE + 1081))
POST_P=$P; GET_P=$((P + 1)); RAW_P=$((P + 2))

daemon_start "$BIN"
RC=0
timeout 20 "$BIN" create server hd_post -p "$POST_P" --http "$TMPD/www" \
    --max-connections "$CAP" -s >/dev/null 2>&1 || RC=$?
timeout 20 "$BIN" create server hd_get  -p "$GET_P"  --http "$TMPD/www" \
    --max-connections "$CAP" -s >/dev/null 2>&1 || RC=$?
timeout 20 "$BIN" create server hd_raw  -p "$RAW_P" \
    --max-connections "$CAP" -s >/dev/null 2>&1 || RC=$?
if [ "$RC" -eq 0 ]; then pass
else fail "the three servers are created" "a create exited $RC"; fi

for port in "$POST_P" "$GET_P" "$RAW_P"; do
    BOUND=""
    for _ in $(seq 1 40); do
        ss -ltn 2>/dev/null | grep -q ":$port " && { BOUND=yes; break; }
        sleep 0.25
    done
    if [ "$BOUND" = yes ]; then pass
    else fail "the listener on :$port is bound" "nothing after 10s"; fi
done

served() {  # port -> ok | refused, judged on the body and not on a status line
    if timeout 6 python3 -c "
import socket
s = socket.socket(); s.settimeout(5)
try:
    s.connect(('127.0.0.1', $1))
    s.sendall(b'GET /probe.txt HTTP/1.0\r\n\r\n')
    print('ok' if b'HEAD-DEADLINE-BODY' in s.recv(400) else 'refused')
except Exception:
    print('refused')
" 2>/dev/null | grep -q ok; then echo ok; else echo refused; fi
}
raw_conns() { ss -tn 2>/dev/null | grep -c ":$RAW_P " || true; }

# ─── The control, before anything is loaded ─────────────────────────────────
for pair in "post:$POST_P" "get:$GET_P"; do
    kind=${pair%%:*}; port=${pair##*:}
    got=$(served "$port")
    if [ "$got" = ok ]; then pass
    else fail "control: the $kind server answers with nothing loaded" \
              "got '$got' — a refusal below would be about the setup"; fi
done

# ─── cap-many heads that stop one line short, and one raw arm ───────────────
python3 -c "
import socket, time
hold = []
# POST takes the plain http branch; GET takes proto_ws_upgrading, since
# parse_partial() cannot know an upgrade from a plain GET until the headers are
# in.  Two call sites, so two arms.
for port, verb in (($POST_P, b'POST'), ($GET_P, b'GET')):
    for _ in range($CAP):
        s = socket.socket(); s.connect(('127.0.0.1', port))
        s.sendall(verb + b' /probe.txt HTTP/1.1\r\nHost: x\r\n')
        hold.append(s)
# The arm that must survive: a raw connection with half a message in it.
for _ in range($CAP):
    s = socket.socket(); s.connect(('127.0.0.1', $RAW_P))
    s.sendall(b'partial-line-with-no-newline')
    hold.append(s)
with open('$TMPD/held', 'w') as f:
    f.write(str(len(hold)))
time.sleep(400)
" >/dev/null 2>&1 &
HOLDER=$!
disown "$HOLDER" 2>/dev/null || true

HELD=0
for _ in $(seq 1 40); do
    HELD=$(cat "$TMPD/held" 2>/dev/null || echo 0)
    [ "${HELD:-0}" -ge $((CAP * 3)) ] && break
    sleep 0.25
done
if [ "${HELD:-0}" -eq $((CAP * 3)) ]; then pass
else fail "the stalled peers reached all three servers" \
          "connected ${HELD:-0} of $((CAP * 3))"; fi

RAW_BEFORE=$(raw_conns)
for pair in "post:$POST_P" "get:$GET_P"; do
    kind=${pair%%:*}; port=${pair##*:}
    got=$(served "$port")
    if [ "$got" = refused ]; then pass
    else fail "loaded: half-sent heads fill the $kind server's cap" \
              "got '$got' — the cap did not count them, so nothing below is measured"; fi
done

# ─── The reclaim, one wait for both ─────────────────────────────────────────
#
# Ten seconds of deadline read by a sweep that ticks every thirty, so between
# ten and forty; the budget is triple.
declare -A WHEN=([post]=never [get]=never)
for i in $(seq 1 40); do
    all_in=yes
    for pair in "post:$POST_P" "get:$GET_P"; do
        kind=${pair%%:*}; port=${pair##*:}
        [ "${WHEN[$kind]}" != never ] && continue
        if [ "$(served "$port")" = ok ]; then WHEN[$kind]="~$((i * 3))s"; else all_in=no; fi
    done
    [ "$all_in" = yes ] && break
    sleep 3
done

if kill -0 "$HOLDER" 2>/dev/null; then pass
else fail "the stalled peers were still held at the reading" \
          "the holder exited, so it freed the slots and not a deadline"; fi

for kind in post get; do
    if [ "${WHEN[$kind]}" != never ]; then pass
    else fail "the $kind branch reclaims a slot from a head that stopped" \
              "no request got through in 120s while the peers were held"; fi
done

# ─── And the arm that had to survive ────────────────────────────────────────
RAW_AFTER=$(raw_conns)
if [ "${RAW_AFTER:-0}" -eq "${RAW_BEFORE:-0}" ] && [ "${RAW_AFTER:-0}" -gt 0 ]; then pass
else fail "a raw server's half-message peers are left alone" \
          "connections on :$RAW_P went from ${RAW_BEFORE:-0} to ${RAW_AFTER:-0}" \
          "a deadline on any non-empty buffer would break long-living connections"; fi
if [ "$(served "$POST_P")" = ok ]; then pass
else fail "and the http server still serves after the sweep ran" "got refused"; fi

echo "  reclaimed: post ${WHEN[post]}, get ${WHEN[get]}; raw untouched at $RAW_AFTER"
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
