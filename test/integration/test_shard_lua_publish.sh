#!/usr/bin/env bash
# Integration test: self.publish on a cache that is N processes.
#
# ─── THE DEFECT ────────────────────────────────────────────────────────────
#
# `self.publish(chan, msg)` forwarded to publish(), which is this PROCESS's
# subscriber table plus the cross-runtime half.  On four shards that is a
# quarter of the cache's socket subscribers -- delivered, counted, and wrong by
# nothing visible.
#
# The message does reach every sibling: publish() hands it to the daemon, which
# fans a publish frame out to every other worker.  But a sibling answers that
# frame in runtime_instance::on_publish_dispatch(), which runs Lua and never
# looks at a socket, and cache_instance did not override it.  So a Lua
# subscriber anywhere heard it and a SOCKET subscriber on another shard did not.
#
# The wire's own PUBLISH does not have this defect: it is classified fanout and
# goes through fan_publish(), which crosses to every shard that may hold a
# subscriber.  That is the road self.publish takes now, for the half publish()
# cannot do -- one mesh frame per sibling, no reply collected, because the
# count would arrive on a later turn and self.publish answers on this one.
#
# ─── WHAT WAS MEASURED, AND ON WHICH BUILD ─────────────────────────────────
#
# e8cf169, Release, four shards, forty subscribers spread over them by
# SO_REUSEPORT, one self.publish:
#
#   self.publish   17 of 40 sockets, 17 deliveries   -> fixed: 40 of 40, 40
#   wire PUBLISH   40 of 40 sockets, 40 deliveries   -> unchanged
#   one shard      40 of 40 for both, on both builds
#
# ─── HOW THIS IS ASSERTED ──────────────────────────────────────────────────
#
# Forty clients subscribe on the shared port and are spread across the shards
# by SO_REUSEPORT.  A separate connection triggers on_miss, which publishes.
# The test counts how many of the forty sockets carry the marker.
#
# It counts DELIVERIES and not sockets-that-got-at-least-one, for the reason
# test_shard_lua_fanout.sh counts them: a fan-out that also echoes the message
# back to the shard it came from reaches that shard's ten twice, and a count of
# sockets reads that as success.
#
# The wire PUBLISH arm is the control that says this file is about the Lua door
# and not about publishing: it is green on the broken build and must stay green.
# The one-shard arm is the control that says it is about sharding.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate shardluapub

P4=$((SL_PORT_BASE+1260))
P1=$((SL_PORT_BASE+1280))
NAMES="slp4 slp1"
N=40

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
}
assert_eq() {
    local label=$1 want=$2 got=$3
    if [ "$got" = "$want" ]; then pass; else fail "$label" "got '$got', wanted '$want'"; fi
}

cleanup() {
    for n in $NAMES; do "$BIN" stop   "$n" >/dev/null 2>&1 || true; done
    sleep 0.3
    for n in $NAMES; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: self.publish on a cache that is N processes ==="
daemon_start "$BIN"

W="$SOCKETLEY_TMPD"

wait_shards() {
    local base=$1 want=$2 i c
    for i in $(seq 1 120); do
        c=$(ss -ltnH 2>/dev/null | awk -v a="$base" -v d=$((base+want-1)) \
            '{n=split($4,x,":"); p=x[n]+0; if (p>=a && p<=d) c++} END {print c+0}')
        [ "$c" -ge "$want" ] && return 0
        sleep 0.2
    done
    return 1
}

cat > "$W/pub.lua" <<'LUAEOF'
-- on_miss is the door: a GET of `shout` runs in whichever shard owns it, once,
-- and that shard is the only one that publishes.
function on_miss(key)
    if key == "shout" then
        self.publish("chan", "FROMLUA")
        return "done"
    end
    return nil
end
LUAEOF

cat > "$W/count.py" <<'PYEOF'
import socket, sys, time

def enc(*parts):
    out = b"*%d\r\n" % len(parts)
    for p in parts:
        b = p.encode()
        out += b"$%d\r\n%s\r\n" % (len(b), b)
    return out

port, n = int(sys.argv[1]), int(sys.argv[2])
subs = []
for _ in range(n):
    c = socket.create_connection(("127.0.0.1", port), 5)
    c.sendall(enc("SUBSCRIBE", "chan"))
    subs.append(c)
time.sleep(1.0)                    # every shard has accepted its share

# Drain the subscribe confirmations, so what is counted below is the message.
for c in subs:
    c.settimeout(0.05)
    try:
        while c.recv(65536):
            pass
    except Exception:
        pass

def collect(tag):
    time.sleep(1.2)                # one daemon hop plus one mesh hop, not two
    reached = 0
    delivered = 0
    for c in subs:
        c.settimeout(0.4)
        buf = b""
        try:
            while True:
                d = c.recv(65536)
                if not d:
                    break
                buf += d
        except Exception:
            pass
        k = buf.count(tag)
        delivered += k
        if k:
            reached += 1
    return reached, delivered

t = socket.create_connection(("127.0.0.1", port), 5)
t.settimeout(5)
t.sendall(enc("GET", "shout"))
# Read on_miss's own answer off the socket before anything else is: leaving it
# there makes the next recv on this connection return it, and the PUBLISH count
# below then reads "$4" and blames the cache for it.
t.recv(64)
r, d = collect(b"FROMLUA")
print("lua %d %d" % (r, d))

t.sendall(enc("PUBLISH", "chan", "FROMWIRE"))
# The server's own count, read before the sockets are, so a row that reads zero
# says which side of the wire lost the message.
time.sleep(0.4)
said = t.recv(64).decode("latin-1").strip()
r, d = collect(b"FROMWIRE")
print("wire %d %d %s" % (r, d, said))
PYEOF

run_arm() {   # port shards label
    local port=$1 shards=$2 name=$3
    "$BIN" create cache "$name" -p "$port" --shards "$shards" --lua "$W/pub.lua" >/dev/null 2>&1
    "$BIN" start "$name" >/dev/null 2>&1
    wait_shards "$port" "$shards" || daemon_bail "$name" "not all $shards shard(s) bound their port"
    sleep 0.6
    python3 "$W/count.py" "$port" "$N"
}

echo "--- 1. four shards: the script's publish and the wire's, same runtime ---"
OUT=$(run_arm $P4 4 slp4) || daemon_required "four shards"
LR=$(echo "$OUT" | awk '/^lua/{print $2}');  LD=$(echo "$OUT" | awk '/^lua/{print $3}')
WR=$(echo "$OUT" | awk '/^wire/{print $2}'); WD=$(echo "$OUT" | awk '/^wire/{print $3}')
WS=$(echo "$OUT" | awk '/^wire/{print $4}')
echo "  observed: self.publish $LR of $N sockets, $LD deliveries"
echo "  observed: wire PUBLISH $WR of $N sockets, $WD deliveries, the cache said $WS"
# 17 of 40 on the broken build: the publishing shard's own clients and nobody
# else's.
assert_eq "self.publish reaches every subscriber of the runtime" "$N" "$LR"
# And exactly once: a fan-out that echoes back to the shard it came from
# reaches that shard's share twice, which a count of sockets cannot see.
assert_eq "and each of them exactly once"                        "$N" "$LD"
# Green on the broken build, and the control that says the file is about the
# Lua door rather than about publishing at all.
assert_eq "the wire's PUBLISH still reaches every subscriber"    "$N" "$WR"
assert_eq "and still exactly once"                               "$N" "$WD"
# The cache counting its own delivery, so a zero above is attributable to the
# reader rather than read as a product failure -- green on both builds.
assert_eq "and the cache counted the same forty"              ":$N" "$WS"

echo "--- 2. the one-shard control, same script ---"
OUT=$(run_arm $P1 1 slp1) || daemon_required "one shard"
LR=$(echo "$OUT" | awk '/^lua/{print $2}');  LD=$(echo "$OUT" | awk '/^lua/{print $3}')
WR=$(echo "$OUT" | awk '/^wire/{print $2}'); WD=$(echo "$OUT" | awk '/^wire/{print $3}')
WS=$(echo "$OUT" | awk '/^wire/{print $4}')
echo "  observed: self.publish $LR of $N sockets, $LD deliveries"
echo "  observed: wire PUBLISH $WR of $N sockets, $WD deliveries, the cache said $WS"
assert_eq "one shard reaches its own subscribers"      "$N" "$LR"
assert_eq "and does not double-deliver"                "$N" "$LD"
assert_eq "and the wire's PUBLISH agrees with it"      "$N" "$WR"
assert_eq "exactly once there too"                     "$N" "$WD"
assert_eq "and counts the same forty"               ":$N" "$WS"

echo ""
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  PASSED" || echo "  FAILED"
exit "$FAIL"
