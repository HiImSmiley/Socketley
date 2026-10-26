#!/usr/bin/env bash
# Integration test: a publish crosses only to the shards that can hold a
# subscriber of its channel, and never misses one that does.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
# Every shard holds its own subscribers, so a publish used to cross to every
# sibling whether or not one held anybody on the channel.  Measured with fifty
# channels over four shards, one subscriber each: three crossings per publish
# to produce one delivery, and three siblings woken to parse a publish for
# nobody.  The filter is a bit per channel bucket in the shared shard table,
# set by a shard before it answers the subscriber and cleared with the
# bucket's last channel; a publish crosses to the shards whose bit is set.
#
# The dangerous half of a filter is the clear: a bit cleared while a subscriber
# still exists is a subscriber that silently never hears again, which is the
# failure pub/sub cannot notice on its own.  So the assertions churn the
# subscriber set and check every delivery after every change.
#
# ─── WHAT EACH ASSERTION CATCHES ───────────────────────────────────────────
#
#   16/16 then 8/8    a bit cleared on the FIRST unsubscribe of a shard rather
#                     than the last loses the subscribers still there; sixteen
#                     over four shards puts several on each.
#   count == 0        with everybody gone the bit is clear and the count says
#                     so; a filter that never clears passes this too, which is
#                     why the crossing count below is asserted separately.
#   4/4 afterwards    a fresh subscriber re-sets a cleared bit before it is
#                     answered.
#   beta unmoved      churn on one channel does not touch another's bit.
#   crossings         300 sequential publishes to a channel with ONE
#                     subscriber cross at most 300 times; without the filter
#                     they cross 900.  This is the only assertion that fails
#                     on a build with no filter at all.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

daemon_isolate cacheshardfilter

P4=$((SL_PORT_BASE+1277))

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line; for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    "$BIN" stop filt4 >/dev/null 2>&1 || true
    sleep 0.4
    "$BIN" remove filt4 >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a publish crosses only to shards that can hold a subscriber ==="

daemon_start "$BIN"

if ! "$BIN" create cache filt4 -p "$P4" --shards 4 -s >/dev/null 2>&1; then
    echo "  FATAL: --shards on a cache was refused.  It is a supported"
    echo "         configuration now, so this is a defect and not a skip."
    exit 2
fi

ready() {
    local port=$1 want=$2 i
    for i in $(seq 1 80); do
        [ "$(ss -ltnH 2>/dev/null | awk -v p=":$port" '{ n = split($4, a, ":"); if (":" a[n] == p) c++ } END { print c+0 }')" -ge "$want" ] \
            && python3 - "$port" <<'PY' 2>/dev/null && return 0
import socket, sys
s = socket.create_connection(('127.0.0.1', int(sys.argv[1])), timeout=2)
s.sendall(b'set __r 1\n'); sys.exit(0 if s.recv(100).startswith(b'ok') else 1)
PY
        sleep 0.25
    done
    return 1
}
ready "$P4" 4 || { echo "  FATAL: the four-shard cache never answered"; exit 2; }

# Direct and relayed together, so a publish that goes round through the daemon is still counted.
crossings() {
    "$BIN" stats filt4 2>/dev/null | awk -F: '/^mesh_(direct|relayed):/ {s+=$2} END{print s+0}'
}

# Prints one line per round: name count reached-of-expected strays
CHURN=$(python3 - "$P4" <<'PY'
import socket, sys, time, random
port = int(sys.argv[1])
def conn():
    s = socket.create_connection(('127.0.0.1', port)); s.settimeout(3); return s
def sub(s, ch):
    s.sendall(b'subscribe %s\n' % ch); s.recv(100)
def drain(socks, want, deadline=2.0):
    got = {}
    end = time.time() + deadline
    for s in socks:
        buf = b''
        s.settimeout(0.05)
        lim = max(end, time.time() + 0.25)
        while time.time() < lim:
            try:
                d = s.recv(65536)
            except socket.timeout:
                if buf.count(b'message ') >= want: break
                continue
            if not d: break
            buf += d
            if buf.count(b'message ') >= want: break
        got[s] = buf
    return got
def publish(pub, ch, msg):
    pub.sendall(b'publish %s %s\n' % (ch, msg)); return int(pub.recv(100).strip() or -1)
def round_(name, pub, ch, subs, others, expect_count):
    time.sleep(0.2)
    n = publish(pub, ch, name.encode())
    got = drain(subs, 1)
    reached = sum(1 for s in subs if got[s].count(b'message %s %s' % (ch, name.encode())) == 1)
    stray = drain(others, 1) if others else {}
    strays = sum(1 for s in others if b'message ' in stray.get(s, b''))
    print('%s %d %d/%d %d' % (name, n, reached, len(subs), strays))
random.seed(7)
A = [conn() for _ in range(16)]; B = [conn() for _ in range(16)]
for s in A: sub(s, b'alpha')
for s in B: sub(s, b'beta')
pub = conn()
round_('r1', pub, b'alpha', A, B, 16)
random.shuffle(A); gone, A = A[:8], A[8:]
for s in gone: s.close()
round_('r2', pub, b'alpha', A, B, 8)
for s in A: s.sendall(b'unsubscribe alpha\n'); s.recv(100)
round_('r3', pub, b'alpha', [], A + B, 0)
A2 = [conn() for _ in range(4)]
for s in A2: sub(s, b'alpha')
round_('r4', pub, b'alpha', A2, A + B, 4)
round_('r5', pub, b'beta', B, A + A2, 16)
PY
)
echo "$CHURN" | sed 's/^/        /'

get_round() { echo "$CHURN" | awk -v r="$1" '$1 == r { print $2, $3, $4 }'; }

read -r N1 R1 S1 <<<"$(get_round r1)"
if [ "$N1" = "16" ] && [ "$R1" = "16/16" ] && [ "$S1" = "0" ]; then
    ok "sixteen subscribers over four shards are all reached and counted"
else
    bad "sixteen subscribers over four shards are all reached and counted" \
        "count $N1 reached $R1 strays $S1"
fi

read -r N2 R2 S2 <<<"$(get_round r2)"
if [ "$N2" = "8" ] && [ "$R2" = "8/8" ]; then
    ok "after half of them close, the other half are still reached ($R2)"
else
    bad "after half of them close, the other half are still reached" \
        "count $N2 reached $R2; a filter bit cleared on the first departure" \
        "rather than the last silences the subscribers that stayed"
fi

read -r N3 R3 S3 <<<"$(get_round r3)"
if [ "$N3" = "0" ] && [ "$S3" = "0" ]; then
    ok "with everybody unsubscribed the count is zero and nobody hears"
else
    bad "with everybody unsubscribed the count is zero and nobody hears" \
        "count $N3 strays $S3"
fi

read -r N4 R4 S4 <<<"$(get_round r4)"
if [ "$N4" = "4" ] && [ "$R4" = "4/4" ] && [ "$S4" = "0" ]; then
    ok "fresh subscribers on the emptied channel are reached again ($R4)"
else
    bad "fresh subscribers on the emptied channel are reached again" \
        "count $N4 reached $R4 strays $S4; a bit that is not re-set before" \
        "the subscriber is answered loses everything until somebody else arrives"
fi

read -r N5 R5 S5 <<<"$(get_round r5)"
if [ "$N5" = "16" ] && [ "$R5" = "16/16" ] && [ "$S5" = "0" ]; then
    ok "the channel that saw no churn is untouched ($R5)"
else
    bad "the channel that saw no churn is untouched" "count $N5 reached $R5 strays $S5"
fi

# ── the crossings, which is the only thing a build with no filter fails ────
# Every shard reports both counters, so a missing line is a count of zero that measures nothing.
MESH_LINES=$("$BIN" stats filt4 2>/dev/null | grep -cE '^mesh_(direct|relayed):')
if [ "$MESH_LINES" -eq 8 ]; then
    ok "every shard reports its crossings ($MESH_LINES counter lines)"
else
    bad "every shard reports its crossings" "$MESH_LINES mesh_direct/mesh_relayed lines over four shards"
fi
BEFORE=$(crossings)
COUNTS=$(python3 - "$P4" <<'PY'
import socket, sys
port = int(sys.argv[1])
s = socket.create_connection(('127.0.0.1', port)); s.settimeout(3)
s.sendall(b'subscribe gamma\n'); s.recv(100)
pub = socket.create_connection(('127.0.0.1', port)); pub.settimeout(3)
wrong = 0
for i in range(300):
    pub.sendall(b'publish gamma m%d\n' % i)
    if pub.recv(100).strip() != b'1': wrong += 1
print(wrong)
PY
)
sleep 0.3
AFTER=$(crossings)
DELTA=$((AFTER - BEFORE))
if [ "$COUNTS" = "0" ] && [ "$DELTA" -le 300 ]; then
    ok "300 publishes to a one-subscriber channel crossed $DELTA times, not 900"
else
    bad "300 publishes to a one-subscriber channel cross at most once each" \
        "crossed $DELTA times (before $BEFORE, after $AFTER), $COUNTS wrong counts;" \
        "without the filter every publish crosses to all three siblings"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
