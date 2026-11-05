#!/usr/bin/env bash
# Integration test: a publish on a sharded cache reaches every shard's
# subscribers, once each, and says how many it reached.
#
# ─── THIS RAN AS pending_ WHILE THE REFUSAL STOOD ──────────────────────────
#
# `--shards` on a cache was refused while this was being built, so the file was
# outside run_all.sh's glob and run against a scratch build.  Both are gone.
#
# The measurements below were taken then and are kept because they are what the
# assertions were written against:
#
# without the flag rather than failing.
#
# Measured on that build, four shards, 24 subscribers spread by SO_REUSEPORT:
#
#     before   publish reported 7, reached 7 of 24 sockets
#     after    publish reported 24, reached 24 of 24, one delivery each
#     control  one shard, 24 of 24 on both builds
#
# ─── THE DEFECT ────────────────────────────────────────────────────────────
#
# A subscriber's registration is a DESCRIPTOR in one process's store, so the
# subscribers of a runtime are spread across its shards exactly as its
# connections are.  publish() walked the shard it was asked on and returned that
# shard's count — the same shape as the dbsize that answered from a quarter of
# the keyspace, and worse, because pub/sub has no other way to notice: a
# subscriber that is never written to looks exactly like a channel with no
# traffic.
#
# What removes it: publish is a fan-out with a summed merge — the same machinery
# multi-key and keyspace-wide commands use — so each shard delivers to its own
# subscribers and returns its own count, and the client gets the total.
#
# ─── WHAT EACH ASSERTION CATCHES ───────────────────────────────────────────
#
#   reached 24/24     the broken build reaches one shard's share, about a
#                     quarter.  Asserting that the PUBLISHER's own socket got
#                     it would pass on the broken build, because the publisher
#                     is on the shard that handled the command.
#   deliveries == 24  a fan-out that both crosses AND rides the daemon's
#                     existing publish frame delivers to each socket twice.
#                     Counted per socket, not per socket-that-got-at-least-one.
#   reported == 24    the count is the aggregate, not the local share.  It is
#                     asserted separately from the delivery because a build can
#                     deliver correctly and still report a quarter.
#   non-subscribers   a `subscribe` fanned out to every shard would register
#                     this client's DESCRIPTOR NUMBER on shards that do not
#                     hold it, and a later publish would write into whatever
#                     connection those shards have at that index.  These
#                     sockets are connected and never subscribed; they must
#                     receive nothing.
#   lua fires once    the cross-runtime dispatch is per publish, not per shard.
#                     Without the guard each of the four shards dispatches, and
#                     a subscriber in another runtime fires four times for one
#                     PUBLISH.
#   the control       one shard, same numbers, on both builds.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

daemon_isolate cacheshardpub

# A sharded cache also binds base+1..base+N, its cluster-mode shard ports, so bases sit ten apart.
P4=$((SL_PORT_BASE+1260))
P1=$((SL_PORT_BASE+1270))
PR=$((SL_PORT_BASE+1280))
PSRV=$((SL_PORT_BASE+1290))
WORK=$(mktemp -d)

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line; for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    for n in pub4 pub1 pubr subsrv; do "$BIN" stop "$n" >/dev/null 2>&1 || true; done
    sleep 0.4
    for n in pub4 pub1 pubr subsrv; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    rm -rf "$WORK"
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a publish reaches every shard's subscribers ==="

daemon_start "$BIN"

if ! "$BIN" create cache pub4 -p "$P4" --shards 4 -s >/dev/null 2>&1; then
    echo "  FATAL: --shards on a cache was refused.  It is a supported"
    echo "         configuration now, so this is a defect and not a skip."
    exit 2
fi
"$BIN" create cache pub1 -p "$P1" --shards 1 -s        >/dev/null 2>&1
"$BIN" create cache pubr -p "$PR" --shards 4 --resp -s >/dev/null 2>&1

ready() {
    local port=$1 i
    for i in $(seq 1 60); do
        printf 'set __r 1\n' | timeout 2 nc -q1 127.0.0.1 "$port" 2>/dev/null \
            | grep -q '^ok$' && return 0
        sleep 0.25
    done
    return 1
}
ready "$P4" || { echo "  FATAL: the four-shard cache never answered"; exit 2; }
ready "$P1" || { echo "  FATAL: the one-shard cache never answered";  exit 2; }

# ── the fan-out, counted three ways ─────────────────────────────────────────
run_fanout() {
    python3 - "$1" <<'PY'
import socket, sys, time
port = int(sys.argv[1]); n = 24; quiet = 6
subs, idle = [], []
for _ in range(n):
    s = socket.create_connection(('127.0.0.1', port)); s.settimeout(2)
    s.sendall(b'subscribe ch\n'); s.recv(100); subs.append(s)
# Connected, never subscribed.  A subscribe that had been fanned out would have
# registered somebody else's descriptor number on the shards these landed on.
for _ in range(quiet):
    s = socket.create_connection(('127.0.0.1', port)); s.settimeout(2); idle.append(s)

pub = socket.create_connection(('127.0.0.1', port)); pub.settimeout(4)
pub.sendall(b'publish ch hello\n')
reported = pub.recv(100).decode().strip()
time.sleep(0.7)

reached = deliveries = 0
for s in subs:
    try:
        c = s.recv(65536).count(b'message ch hello')
    except socket.timeout:
        c = 0
    if c: reached += 1
    deliveries += c
strays = 0
for s in idle:
    try:
        if b'message' in s.recv(65536): strays += 1
    except socket.timeout:
        pass
for s in subs + idle: s.close()
pub.close()
print('%s %d %d %d %d' % (reported, reached, deliveries, strays, n))
PY
}

read -r REPORTED REACHED DELIV STRAYS NSUBS <<<"$(run_fanout "$P4")"

if [ "$REACHED" = "$NSUBS" ]; then
    ok "every shard's subscribers are reached ($REACHED/$NSUBS)"
else
    bad "every shard's subscribers are reached" \
        "reached $REACHED of $NSUBS — a publish that stops at one shard reaches" \
        "about a quarter of them and nothing reports it"
fi

if [ "$DELIV" = "$NSUBS" ]; then
    ok "each subscriber is delivered to exactly once ($DELIV deliveries)"
else
    bad "each subscriber is delivered to exactly once" \
        "$DELIV deliveries for $NSUBS subscribers; a fan-out that also rides the" \
        "daemon's publish frame delivers twice"
fi

if [ "$REPORTED" = "$NSUBS" ]; then
    ok "publish reports the runtime's total, not one shard's share ($REPORTED)"
else
    bad "publish reports the runtime's total, not one shard's share" \
        "reported '$REPORTED', reached $REACHED, expected $NSUBS"
fi

if [ "$STRAYS" = "0" ]; then
    ok "a connection that never subscribed receives nothing"
else
    bad "a connection that never subscribed receives nothing" \
        "$STRAYS of them got a message — a subscription is a descriptor, so" \
        "fanning one out registers a number another shard does not own"
fi

read -r C_REPORTED C_REACHED C_DELIV C_STRAYS C_N <<<"$(run_fanout "$P1")"
if [ "$C_REACHED" = "$C_N" ] && [ "$C_REPORTED" = "$C_N" ] && [ "$C_DELIV" = "$C_N" ]; then
    ok "the one-shard control reaches and reports all of them ($C_REACHED/$C_N)"
else
    bad "the one-shard control reaches and reports all of them" \
        "reported '$C_REPORTED' reached $C_REACHED deliveries $C_DELIV of $C_N" \
        "this is not about sharding — an unsharded publish is wrong"
fi

# ── the same over RESP ──────────────────────────────────────────────────────
if command -v redis-cli >/dev/null 2>&1; then
    for i in $(seq 1 60); do
        redis-cli -p "$PR" PING 2>/dev/null | grep -q PONG && break
        sleep 0.25
    done
    R=$(python3 - "$PR" <<'PY'
import socket, sys, time
port = int(sys.argv[1]); n = 16
subs = []
for _ in range(n):
    s = socket.create_connection(('127.0.0.1', port)); s.settimeout(2)
    s.sendall(b'*2\r\n$9\r\nsubscribe\r\n$2\r\nch\r\n'); s.recv(200); subs.append(s)
pub = socket.create_connection(('127.0.0.1', port)); pub.settimeout(4)
pub.sendall(b'*3\r\n$7\r\npublish\r\n$2\r\nch\r\n$5\r\nhello\r\n')
reported = pub.recv(100).decode().strip()
time.sleep(0.7)
reached = deliveries = 0
for s in subs:
    try: c = s.recv(65536).count(b'hello')
    except socket.timeout: c = 0
    if c: reached += 1
    deliveries += c
for s in subs: s.close()
pub.close()
print('%s %d %d %d' % (reported, reached, deliveries, n))
PY
)
    read -r RR RRE RDE RN <<<"$R"
    if [ "$RRE" = "$RN" ] && [ "$RR" = ":$RN" ] && [ "$RDE" = "$RN" ]; then
        ok "the RESP dispatch fans out and reports the total ($RRE/$RN)"
    else
        bad "the RESP dispatch fans out and reports the total" \
            "reported '$RR' reached $RRE deliveries $RDE of $RN"
    fi
fi

# ── the cross-runtime dispatch is per publish, not per shard ────────────────
#
# Without the guard each of the four shards dispatches to every other runtime,
# so a subscriber elsewhere fires four times for one PUBLISH.  In the daemon
# rather than a worker so the count is not also a test of the worker's frames.
cat > "$WORK/sub.lua" <<'LUAEOF'
function on_start()
    socketley.subscribe("pub4", "ch", function(chan, msg)
        socketley.log("SHARDPUB HIT " .. tostring(msg))
    end)
end
LUAEOF
"$BIN" create server subsrv -p "$PSRV" --lua "$WORK/sub.lua" -s >/dev/null 2>&1
sleep 1.5
printf 'publish ch once\n' | timeout 5 nc -q1 127.0.0.1 "$P4" >/dev/null 2>&1
sleep 1.5
# Read the daemon's log before cleanup deletes it; see lib_daemon.sh.
HITS=$(grep -c "SHARDPUB HIT once" "$SOCKETLEY_DLOG" 2>/dev/null || true)
if [ "$HITS" = "1" ]; then
    ok "a subscriber in another runtime fires once per publish, not once per shard"
else
    bad "a subscriber in another runtime fires once per publish" \
        "$HITS hits for one PUBLISH on a four-shard cache; each shard that" \
        "dispatches to other runtimes multiplies every cross-runtime callback"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
