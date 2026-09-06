#!/usr/bin/env bash
# Integration test: a pipeline queued behind a crossing is served, not dropped.
#
# ─── THE DEFECT ────────────────────────────────────────────────────────────
#
# A sharded cache runs one crossing per connection at a time: while a batch is
# out to the sibling shards the connection keeps reading but does not parse,
# so a client that pipelines is buffered in `partial` until the answer lands.
# handle_read has one ceiling on `partial`, MAX_PARTIAL_SIZE (1 MiB), written
# for a line that never ends -- and it could not tell that case from whole
# commands waiting on a crossing.  Past 1 MiB it marked the connection closing,
# which drops the buffered commands, the batch's replies AND the socket, with
# no log line and no error to the client.
#
# Measured on the build before the fix, four shards, 200 publishes of 8 KiB
# pipelined in one write (1.6 MB): 0 of 200 replies, the publisher's socket
# closed, 2 of 200 deliveries.  100 publishes (800 KB) were complete, and one
# shard was complete at every size, because an unsharded cache never gates.
#
# What removes it: behind a crossing the read is withdrawn instead, so the
# client waits in the kernel's socket buffer, and it comes back when the
# crossing is answered.  The ceiling itself stays for the case it was for.
#
# ─── WHAT EACH ASSERTION CATCHES ───────────────────────────────────────────
#
#   200 replies       the broken build answers none: the socket is closed
#                     with the commands still in the buffer.
#   every reply is 8  a build that resumed reading but lost the batch would
#                     answer, with the wrong count.
#   8 x 200 delivered the replies could be right while the deliveries the
#                     siblings owe were dropped downstream.
#   the ceiling holds a "fix" that raised or removed MAX_PARTIAL_SIZE passes
#                     the three above and lets one client park unbounded
#                     memory; a 1.5 MB line with no newline must still close.
#   one shard         the control: the same pipeline on an unsharded cache.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

daemon_isolate cacheshardpipe

P4=$((SL_PORT_BASE+1275))
P1=$((SL_PORT_BASE+1276))

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line; for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    for n in pipe4 pipe1; do "$BIN" stop "$n" >/dev/null 2>&1 || true; done
    sleep 0.4
    for n in pipe4 pipe1; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a pipeline behind a crossing is served ==="

daemon_start "$BIN"

if ! "$BIN" create cache pipe4 -p "$P4" --shards 4 -s >/dev/null 2>&1; then
    echo "  FATAL: --shards on a cache was refused.  It is a supported"
    echo "         configuration now, so this is a defect and not a skip."
    exit 2
fi
"$BIN" create cache pipe1 -p "$P1" --shards 1 -s >/dev/null 2>&1

# Waited for, not slept for: a sharded cache forks its workers after `create`
# answers, and a publish to a set that is half there is a different test.
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
ready "$P1" 1 || { echo "  FATAL: the one-shard cache never answered";  exit 2; }

# ── the pipeline, scored three ways ─────────────────────────────────────────
# Prints: replies distinct-reply-values deliveries-min deliveries-max
run_pipeline() {
    python3 - "$1" <<'PY'
import socket, sys, time
port = int(sys.argv[1]); nsub = 8; npub = 200; size = 8192
subs = []
for _ in range(nsub):
    s = socket.create_connection(('127.0.0.1', port)); s.settimeout(5)
    s.sendall(b'subscribe ch\n'); s.recv(100); subs.append(s)
pub = socket.create_connection(('127.0.0.1', port)); pub.settimeout(5)
# One write of 1.6 MB, which is what puts more than MAX_PARTIAL_SIZE behind
# the first crossing; a publisher that waited for each reply never would.
body = b'Y' * size
pub.sendall(b''.join(b'publish ch %s\n' % body for _ in range(npub)))
got = b''
try:
    while got.count(b'\n') < npub:
        d = pub.recv(1 << 20)
        if not d: break
        got += d
except socket.timeout:
    pass
replies = got.decode(errors='replace').split('\n')[:-1]
counts = []
deadline = time.time() + 8
for s in subs:
    buf = b''; n = 0
    while n < npub and time.time() < deadline:
        try:
            d = s.recv(1 << 20)
        except socket.timeout:
            break
        if not d: break
        buf += d; n = buf.count(b'message ch ')
    counts.append(n)
for s in subs: s.close()
pub.close()
print('%d %s %d %d' % (len(replies), ','.join(sorted(set(replies))) or '-', min(counts), max(counts)))
PY
}

read -r REPLIES VALUES DMIN DMAX <<<"$(run_pipeline "$P4")"

if [ "$REPLIES" = "200" ]; then
    ok "every publish pipelined behind a crossing is answered ($REPLIES/200)"
else
    bad "every publish pipelined behind a crossing is answered" \
        "$REPLIES of 200 replies; past 1 MiB of buffered pipeline the broken" \
        "build closed the socket with the commands still in it"
fi

if [ "$VALUES" = "8" ]; then
    ok "each reply is the subscriber count across all shards"
else
    bad "each reply is the subscriber count across all shards" \
        "reply values seen: $VALUES (expected only 8)"
fi

if [ "$DMIN" = "200" ] && [ "$DMAX" = "200" ]; then
    ok "every subscriber received all 200 deliveries"
else
    bad "every subscriber received all 200 deliveries" \
        "per-subscriber deliveries ranged $DMIN..$DMAX of 200"
fi

# ── the ceiling still stands ────────────────────────────────────────────────
CLOSED=$(python3 - "$P4" <<'PY'
import socket, sys
s = socket.create_connection(('127.0.0.1', int(sys.argv[1]))); s.settimeout(5)
try:
    s.sendall(b'x' * (1536 * 1024))
    print('closed' if s.recv(100) == b'' else 'answered')
except (ConnectionResetError, BrokenPipeError):
    print('closed')
except socket.timeout:
    print('open')
PY
)
if [ "$CLOSED" = "closed" ]; then
    ok "a line over 1 MiB with no newline still closes the connection"
else
    bad "a line over 1 MiB with no newline still closes the connection" \
        "the connection is '$CLOSED'; raising the ceiling instead of holding" \
        "the read lets one client park unbounded memory on a shard"
fi

# ── the control ─────────────────────────────────────────────────────────────
read -r C_REPLIES C_VALUES C_DMIN C_DMAX <<<"$(run_pipeline "$P1")"
if [ "$C_REPLIES" = "200" ] && [ "$C_VALUES" = "8" ] && [ "$C_DMIN" = "200" ]; then
    ok "the one-shard control answers and delivers the same pipeline"
else
    bad "the one-shard control answers and delivers the same pipeline" \
        "replies $C_REPLIES values $C_VALUES deliveries $C_DMIN..$C_DMAX;" \
        "this is not about sharding -- an unsharded pipeline is wrong"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
