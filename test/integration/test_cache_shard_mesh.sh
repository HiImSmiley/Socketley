#!/usr/bin/env bash
# Integration test: shard-to-shard links, and the two ways they can be absent.
#
# ─── WHY THIS IS NO LONGER pending_ ────────────────────────────────────────
#
# It was written while `--shards` on a cache was refused, and its header said to
# build with -DSOCKETLEY_SCRATCH_CACHE_SHARDS.  That flag never existed in the
# tree; what the test actually gates on is the `create` below succeeding, which
# is a RUNTIME check and not a compile-time one -- so there was no stale-binary
# hazard here, only a name that kept it out of run_all.sh's `test_*.sh` glob.
#
# --shards on a cache landed in 4ed9b13, so the gate now opens and the test
# runs.  Renamed so the suite picks it up: a mesh that ships with a test nobody
# runs is the same as a mesh with no test, and this file's whole argument is
# that the correctness assertions cannot tell a working mesh from an absent one.
#
# Verified rather than assumed, on the mesh build with the mesh forced off:
#
#   PASS: every key reads back over the mesh (40/40)
#   FAIL [crossings went shard-to-shard]: mesh_direct is 0
#   FAIL [none of them fell back to the daemon]: 12 of 12 relayed
#
# The correctness assertion stays green with no mesh at all.  Only the route
# assertions move, which is the reason they are the ones here.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
# The mesh has a fallback: a crossing with no usable link relays through the
# daemon, which is what keeps a dead link from being an outage.  That fallback
# is also what would let a mesh that never connects go unnoticed — it would
# serve every key correctly, pass every other test in this directory, and report
# the throughput of the build without it.
#
# "The mesh made no difference" and "the mesh was never used" have to be
# distinguishable or a measurement of it means nothing.  So the assertions here
# are about the ROUTE, not about the answers:
#
#   direct > 0        crossings really went shard-to-shard.  Asserting that the
#                     keys read back passes on a build with no mesh at all.
#   relayed == 0      and none of them fell back.  A mesh that connects and then
#                     quietly relays half its traffic reports direct > 0.
#   off: correct      with the mesh disabled the same keys still read back, over
#                     the daemon.  This is the arm every measurement compares
#                     against, so it has to be known-good.
#   the cap           N shards need N(N-1) descriptors at once while the set is
#                     forked.  RLIMIT_NOFILE here is 1,048,576, so the cap can
#                     never fire on this box and its branch would ship never
#                     having run.  The test lowers the limit in its own shell
#                     and watches the daemon refuse, say so, and relay.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

daemon_isolate cacheshardmesh

PORT=$((SL_PORT_BASE+1270))

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line; for line in "${@:3}"; do echo "        $line"; done
}

cleanup() { "$BIN" stop meshc >/dev/null 2>&1 || true; sleep 0.3
            "$BIN" remove meshc >/dev/null 2>&1 || true; daemon_stop; }
trap cleanup EXIT

echo "=== Integration: shard-to-shard links ==="

command -v redis-cli >/dev/null 2>&1 || { echo "  SKIP: redis-cli required"; exit 0; }

daemon_start "$BIN"
# Refused rather than skipped: shards_config_refusal() allows --shards on every
# listening type and refuses only a client, so a build that says no here is the
# regression this file exists to catch -- and exit 0 would have reported it as a
# pass.
if ! OUT=$("$BIN" create cache meshc -p "$PORT" --shards 4 --resp -s 2>&1); then
    bad "a cache takes --shards" "${OUT:-<silent refusal>}"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
    exit 1
fi
for i in $(seq 1 80); do
    redis-cli -p "$PORT" PING 2>/dev/null | grep -q PONG && break; sleep 0.25
done

# Enough keys that every shard both owns some and asks for others.
for i in $(seq 1 40); do redis-cli -p "$PORT" SET "x$i" "v$i" >/dev/null 2>&1; done
MISS=0
for i in $(seq 1 40); do
    [ "$(redis-cli -p "$PORT" GET "x$i" 2>/dev/null)" = "v$i" ] || MISS=$((MISS+1))
done
[ "$MISS" -eq 0 ] && ok "every key reads back over the mesh (40/40)" \
    || bad "every key reads back over the mesh" "$MISS of 40 missing"

sleep 3
ST=$("$BIN" stats meshc 2>&1 || true)
DIRECT=$(printf '%s\n' "$ST" | awk -F: '/^mesh_direct:/  {s+=$2} END{print s+0}')
RELAY=$( printf '%s\n' "$ST" | awk -F: '/^mesh_relayed:/ {s+=$2} END{print s+0}')

if [ "$DIRECT" -gt 0 ]; then
    ok "crossings went shard-to-shard ($DIRECT direct)"
else
    bad "crossings went shard-to-shard" \
        "mesh_direct is $DIRECT — every crossing relayed through the daemon," \
        "which answers correctly and measures as the build without a mesh"
fi
if [ "$RELAY" -eq 0 ]; then
    ok "none of them fell back to the daemon (relayed $RELAY)"
else
    bad "none of them fell back to the daemon" \
        "$RELAY of $((DIRECT+RELAY)) relayed; a link that connects and then" \
        "quietly gives up still reports direct > 0"
fi

# ── Large values, pipelined, over the mesh ─────────────────────────────────
#
# One turn of answers for a sibling passed the writer's 4 MiB cap before its
# flush and ended the link for good, and an answer past 8 MiB was a frame the
# sibling could not read: pipelined GETs of 64 KiB values answered "no such
# runtime", and an MGET of large values never answered.  Both go now, the
# second in pieces.
cat > "$SOCKETLEY_TMPD/big.py" <<'PY'
import socket, sys
port = int(sys.argv[1])
def cmd(*a):
    out = b"*%d\r\n" % len(a)
    for x in a:
        x = x if isinstance(x, bytes) else str(x).encode()
        out += b"$%d\r\n%s\r\n" % (len(x), x)
    return out
class R:
    def __init__(s, sock): s.s, s.b = sock, b""
    def need(s, n):
        while len(s.b) < n:
            d = s.s.recv(1 << 20)
            if not d: raise EOFError
            s.b += d
    def line(s):
        while b"\r\n" not in s.b:
            d = s.s.recv(1 << 20)
            if not d: raise EOFError
            s.b += d
        l, s.b = s.b.split(b"\r\n", 1)
        return l
    def reply(s):
        l = s.line()
        if l[:1] == b"$":
            n = int(l[1:])
            if n < 0: return None
            s.need(n + 2); v, s.b = s.b[:n], s.b[n + 2:]
            return v
        if l[:1] == b"*":
            return [s.reply() for _ in range(int(l[1:]))]
        return l
s = socket.create_connection(("127.0.0.1", port), timeout=30)
r = R(s)
val = lambda i: (b"%06d" % i) * (65536 // 6)
s.sendall(b"".join(cmd("SET", "big%d" % i, val(i)) for i in range(200)))
setok = sum(r.reply() == b"+OK" for _ in range(200))
s.sendall(b"".join(cmd("GET", "big%d" % (i % 200)) for i in range(600)))
gets = sum(r.reply() == val(i % 200) for i in range(600))
s.sendall(cmd("MGET", *["big%d" % i for i in range(200)]))
m = r.reply()
mget = sum(1 for i, v in enumerate(m or []) if v == val(i))
print(setok, gets, mget)
PY
read -r BIGSET BIGGET BIGMGET < <(timeout 120 python3 "$SOCKETLEY_TMPD/big.py" "$PORT" 2>/dev/null || echo "0 0 0")
check_big() { [ "$2" = "$3" ] && ok "$1 ($2)" || bad "$1" "$2 of $3"; }
check_big "two hundred 64 KiB values pipelined in are taken" "$BIGSET" 200
check_big "six hundred GETs of them pipelined come back whole" "$BIGGET" 600
check_big "and one MGET of all of them, 13 MB, answers every one" "$BIGMGET" 200
sleep 1
ST=$("$BIN" stats meshc 2>&1 || true)
RELAY2=$(printf '%s\n' "$ST" | awk -F: '/^mesh_relayed:/ {s+=$2} END{print s+0}')
DOWN=$(grep -cE 'the link to shard .* is down' "$SOCKETLEY_DLOG" 2>/dev/null || true)
[ "$RELAY2" -eq 0 ] && [ "${DOWN:-0}" -eq 0 ] && ok "no link went down under them (relayed $RELAY2)" \
    || bad "no link went down under them" "relayed $RELAY2, $DOWN link(s) down"

# ── and a link that went quiet gives back what they grew ──────────────────
#
# The read buffer doubled to 256 KiB and the writer kept its largest batch, for the life of the set: twelve links of
# four shards held what one burst grew for good.  Quiet five seconds, a link keeps its 16 KiB read and little else.
HELD1=$(printf '%s\n' "$ST" | awk -F: '/^mesh_held:/ {s+=$2} END{print s+0}')
HELD2=$HELD1
for _ in $(seq 1 40); do
    sleep 0.5
    HELD2=$("$BIN" stats meshc 2>/dev/null | awk -F: '/^mesh_held:/ {s+=$2} END{print s+0}')
    [ "$HELD2" -lt $((12 * 96 * 1024)) ] && break
done
[ "$HELD1" -gt $((8 << 20)) ] && ok "the burst grew the links' buffers ($HELD1 bytes over 12 links)" \
    || bad "the burst grew the links' buffers, or this measures nothing" "$HELD1 bytes"
[ "$HELD2" -lt $((12 * 96 * 1024)) ] && ok "quiet, the links give it back ($HELD2 bytes over 12 links)" \
    || bad "quiet, the links give back what the burst grew" "$HELD2 bytes over 12 links after 20 s"

# ── A clean stop says nothing about the mesh ──────────────────────────────
#
# Four shards leaving together means each one watches three siblings' ends
# close, and every one of those used to be a WARN naming a link that was down
# and crossings that would relay through the daemon.  On the live box that was
# 73 of 73 warnings in a day, all of them a stop: a mesh that really broke was
# indistinguishable from a deploy.
#
# The link going down is not what is asserted -- it is expected and it happens.
# What is asserted is that a shard on its own way out does not call a sibling's
# departure a fault, which is the only reading of this level anybody can use.
"$BIN" stop meshc >/dev/null 2>&1; sleep 0.6
STOPWARN=$(grep -cE '\[WARN\].*the link to shard' "$SOCKETLEY_DLOG" 2>/dev/null || true)
if [ "${STOPWARN:-0}" -eq 0 ]; then
    ok "a clean stop of four shards reports no mesh failure (0 warnings for 12 ends)"
else
    bad "a clean stop of four shards reports no mesh failure" \
        "$STOPWARN warning(s) about a link going down, from shards that were" \
        "themselves on the way out; a warning every stop produces is one" \
        "nobody can read a real mesh failure out of"
fi
"$BIN" remove meshc >/dev/null 2>&1

# ── A shard that really dies is still said ──────────────────────────────────
#
# A sibling's end is held for a moment before it is called a fault, since a stop reaches every shard in one turn
# and one can be gone before another has read that it is going too; a shard killed while the rest run has no stop
# behind it, so its siblings still say so, once the moment has passed.
"$BIN" create cache meshc -p "$PORT" --shards 4 --resp -s >/dev/null 2>&1
for i in $(seq 1 80); do redis-cli -p "$PORT" PING 2>/dev/null | grep -q PONG && break; sleep 0.25; done
BEFORE=$(grep -cE '\[WARN\].*the link to shard' "$SOCKETLEY_DLOG" 2>/dev/null || true)
VICTIM=$(ss -Hltnp "sport = :$PORT" 2>/dev/null | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
[ -n "$VICTIM" ] && kill -9 "$VICTIM"
for _ in $(seq 1 50); do
    [ "$(grep -cE '\[WARN\].*the link to shard' "$SOCKETLEY_DLOG" 2>/dev/null || true)" -gt "${BEFORE:-0}" ] && break; sleep 0.1
done
AFTER=$(grep -cE '\[WARN\].*the link to shard' "$SOCKETLEY_DLOG" 2>/dev/null || true)
if [ -n "$VICTIM" ] && [ "${AFTER:-0}" -gt "${BEFORE:-0}" ]; then
    ok "a shard killed while its siblings run is reported by them ($((AFTER - BEFORE)) warning(s))"
else
    bad "a shard killed while its siblings run is reported by them" "victim '${VICTIM:-none}', warnings ${BEFORE:-0} -> ${AFTER:-0}"
fi
"$BIN" remove meshc >/dev/null 2>&1

# ── eight shards: 56 links, and the assertion four shards cannot make ────
#
# The link for sibling j sits at a fixed descriptor slot, child_mesh_base + j.
# At four shards the widest slot in use is base+3; an arithmetic or ordering
# defect in that block can sit entirely inside the range four shards exercise
# and still be wrong for eight.
#
# So the assertion here is not "the total is above zero" — that stays true while
# one shard is deaf and the other seven carry it.  It is that EVERY shard
# reports a direct crossing.  A single shard stuck at zero while its siblings
# work is precisely the shape of a mis-wired slot, and it is invisible in a sum.
"$BIN" create cache meshc -p "$PORT" --shards 8 --resp -s >/dev/null 2>&1
for i in $(seq 1 80); do
    redis-cli -p "$PORT" PING 2>/dev/null | grep -q PONG && break; sleep 0.25
done
for i in $(seq 1 120); do redis-cli -p "$PORT" SET "z$i" "u$i" >/dev/null 2>&1; done
MISS=0
for i in $(seq 1 120); do
    [ "$(redis-cli -p "$PORT" GET "z$i" 2>/dev/null)" = "u$i" ] || MISS=$((MISS+1))
done
[ "$MISS" -eq 0 ] && ok "eight shards read every key back (120/120)" \
    || bad "eight shards read every key back" "$MISS of 120 missing"

sleep 3
ST8=$("$BIN" stats meshc 2>&1 || true)
SHARDS8=$(printf '%s\n' "$ST8" | grep -c '^\[shard')
# The denominator has to be counted, not assumed.  A shard that reports NO
# mesh_direct line at all contributes nothing to SILENT, so without this the
# "none silent" check passes precisely when a shard has gone missing -- which
# the mesh-off run exposed by reporting 7 of 8 where 8 were expected.
LINES8=$(printf '%s\n' "$ST8" | grep -c '^mesh_direct:')
# Eight shards means seven siblings each, so the link count is a fact with an
# exact expected value rather than a threshold.  It is also the assertion that
# says WHY a shard is silent: mesh_direct 0 is equally true of a shard that
# never connected and one that simply had no crossing to make, while
# mesh_links 0 can only be the first.
WRONGLINKS=$(printf '%s\n' "$ST8" | awk -F: '/^mesh_links:/ && $2+0 != 7 {n++} END{print n+0}')
LINKLINES=$(printf '%s\n' "$ST8" | grep -c '^mesh_links:')
SILENT=$(printf '%s\n' "$ST8" | awk -F: '/^mesh_direct:/ && $2+0 == 0 {n++} END{print n+0}')
D8=$(printf '%s\n' "$ST8" | awk -F: '/^mesh_direct:/  {s+=$2} END{print s+0}')
R8=$(printf '%s\n' "$ST8" | awk -F: '/^mesh_relayed:/ {s+=$2} END{print s+0}')

if [ "$SHARDS8" -eq 8 ]; then
    ok "eight shards came up (stats reports $SHARDS8)"
else
    bad "eight shards came up" "stats reports $SHARDS8 shard sections, expected 8"
fi
if [ "$SHARDS8" -eq 8 ] && [ "$LINES8" -eq "$SHARDS8" ] && [ "$SILENT" -eq 0 ] && [ "$D8" -gt 0 ]; then
    ok "every one of the eight crossed directly ($D8 direct over $LINES8 shards, none silent)"
else
    bad "every one of the eight crossed directly" \
        "$SILENT of $LINES8 shards report mesh_direct 0; total is $D8" \
        "($SHARDS8 shard sections, $LINES8 counter lines -- unequal means a shard reported nothing)" \
        "a sum above zero stays true while one slot is mis-wired and its shard is deaf"
fi
if [ "$LINKLINES" -eq 8 ] && [ "$WRONGLINKS" -eq 0 ]; then
    ok "each of the eight holds seven links (8 sections, 8 counters)"
else
    bad "each of the eight holds seven links" \
        "$LINKLINES mesh_links lines over $SHARDS8 shard sections," \
        "$WRONGLINKS of them not equal to 7"
fi
if [ "$R8" -eq 0 ]; then
    ok "eight shards, nothing fell back (relayed $R8)"
elif [ "$LINKLINES" -eq 8 ] && [ "$WRONGLINKS" -eq 0 ]; then
    # Links are all present and correctly counted, so this is not a wiring
    # fault -- it is the fallback doing its job.  Said explicitly because the
    # assertion is strict on purpose and the next person to see it red on a
    # busy box should not go looking for a defect in the mesh.
    bad "eight shards, nothing fell back" \
        "$R8 of $((D8+R8)) relayed, but all 8 shards hold their 7 links" \
        "so the mesh is wired and this is the daemon fallback, not a link fault;" \
        "a saturated box can produce it -- check load before suspecting the mesh"
else
    bad "eight shards, nothing fell back" \
        "$R8 of $((D8+R8)) relayed, and the link counts are wrong too" \
        "($LINKLINES lines, $WRONGLINKS not equal to 7) -- this is a wiring fault"
fi

"$BIN" stop meshc >/dev/null 2>&1; sleep 0.3; "$BIN" remove meshc >/dev/null 2>&1
daemon_stop

# ── the arm every measurement compares against ─────────────────────────────
daemon_isolate cacheshardmeshoff
export SOCKETLEY_NO_SHARD_MESH=1
daemon_start "$BIN"
"$BIN" create cache meshc -p "$PORT" --shards 4 --resp -s >/dev/null 2>&1
for i in $(seq 1 80); do
    redis-cli -p "$PORT" PING 2>/dev/null | grep -q PONG && break; sleep 0.25
done
for i in $(seq 1 20); do redis-cli -p "$PORT" SET "y$i" "w$i" >/dev/null 2>&1; done
MISS=0
for i in $(seq 1 20); do
    [ "$(redis-cli -p "$PORT" GET "y$i" 2>/dev/null)" = "w$i" ] || MISS=$((MISS+1))
done
if [ "$MISS" -eq 0 ] && grep -q "shard mesh disabled" "$SOCKETLEY_DLOG" 2>/dev/null; then
    ok "with the mesh disabled the daemon says so and still answers (20/20)"
else
    bad "with the mesh disabled the daemon says so and still answers" \
        "$MISS of 20 missing; log says: $(grep -c 'shard mesh disabled' "$SOCKETLEY_DLOG" 2>/dev/null || echo 0)"
fi

# ── and a child the daemon did not wire holds nothing ──────────────────────
#
# The descriptor block starts at a fixed number, and with no mesh the worker's
# own event-loop eventfd lands on it.  A worker that decides "the link to
# sibling j is there" from the number being open adopted that eventfd, armed a
# recv on it and then closed it on the first failure: measured, 7 of 8 shards.
# Both assertions are about the CLAIM, because answering correctly is what the
# fallback does either way and is therefore no evidence at all.
sleep 3
STOFF=$("$BIN" stats meshc 2>&1 || true)
OFFLINES=$(printf '%s\n' "$STOFF" | grep -c '^mesh_links:')
OFFHELD=$(printf '%s\n' "$STOFF" | awk -F: '/^mesh_links:/ && $2+0 != 0 {n++} END{print n+0}')
OFFDOWN=$(grep -c "the link to shard" "$SOCKETLEY_DLOG" 2>/dev/null || true)
if [ "$OFFLINES" -eq 4 ] && [ "$OFFHELD" -eq 0 ]; then
    ok "an unwired child claims no links (4 shards, 0 held)"
else
    bad "an unwired child claims no links" \
        "$OFFHELD of $OFFLINES shards report a link the daemon never gave them;" \
        "the descriptor at that slot is the worker's own, not a sibling's"
fi
if [ "${OFFDOWN:-0}" -eq 0 ]; then
    ok "and none of them reports a link going down (0 warnings)"
else
    bad "and none of them reports a link going down" \
        "$OFFDOWN 'link to shard ... is down' warnings with no mesh in play;" \
        "a link that was never given cannot go down -- it was somebody else's fd"
fi
unset SOCKETLEY_NO_SHARD_MESH
"$BIN" stop meshc >/dev/null 2>&1; sleep 0.3; "$BIN" remove meshc >/dev/null 2>&1
daemon_stop

# ── the descriptor cap, which cannot fire at this box's real limit ─────────
#
# Lowered in a subshell so nothing after it inherits the limit.  8 shards need
# 8*7 = 56 descriptors held at once; at a soft limit of 512 the budget is half
# of that less headroom, so the mesh is refused and the runtime relays.
(
    ulimit -n 512 2>/dev/null || { echo "  SKIP: cannot lower the open-file limit to 512 here"; exit 77; }
    daemon_isolate cacheshardcap
    daemon_start "$BIN"
    "$BIN" create cache capc -p $((PORT+1)) --shards 8 --resp -s >/dev/null 2>&1
    for i in $(seq 1 80); do
        redis-cli -p $((PORT+1)) PING 2>/dev/null | grep -q PONG && break; sleep 0.25
    done
    for i in $(seq 1 20); do redis-cli -p $((PORT+1)) SET "z$i" "u$i" >/dev/null 2>&1; done
    m=0
    for i in $(seq 1 20); do
        [ "$(redis-cli -p $((PORT+1)) GET "z$i" 2>/dev/null)" = "u$i" ] || m=$((m+1))
    done
    said=$(grep -c "open-file limit leaves room" "$SOCKETLEY_DLOG" 2>/dev/null || echo 0)
    "$BIN" stop capc >/dev/null 2>&1; sleep 0.3; "$BIN" remove capc >/dev/null 2>&1
    printf '%s %s\n' "$m" "$said" > /tmp/skl-cap-result.$$
    daemon_stop
)
CAPRC=$?
if [ ! -f /tmp/skl-cap-result.$$ ] && [ "$CAPRC" -ne 77 ]; then
    bad "under a low descriptor limit the mesh is refused out loud" \
        "the capped daemon run ended (rc=$CAPRC) before it reported anything"
fi
if [ -f /tmp/skl-cap-result.$$ ]; then
    read -r CAPMISS CAPSAID < /tmp/skl-cap-result.$$
    rm -f /tmp/skl-cap-result.$$
    if [ "${CAPSAID:-0}" -gt 0 ] && [ "${CAPMISS:-1}" -eq 0 ]; then
        ok "under a low descriptor limit the mesh is refused out loud and the cache still answers"
    else
        bad "under a low descriptor limit the mesh is refused out loud" \
            "log said it $CAPSAID time(s), $CAPMISS of 20 keys missing" \
            "a runtime that quietly stops meshing is indistinguishable from one" \
            "whose mesh did not help"
    fi
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
