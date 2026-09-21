#!/usr/bin/env bash
# Integration test: self.* on a cache that is N processes writes to its OWN slice.
#
# ─── THE DEFECT ────────────────────────────────────────────────────────────
#
# The twenty keyspace entries of the cache's Lua table -- self.get, self.set,
# self.del and the seventeen beside them -- reached `m_store` directly, in every
# one of the N workers, without ever asking cache_shard_of() who owns the key.
# Every other door into the store asks: process_command() calls itself "the one
# place the text interpreter asks who owns a key", and apply_replicated() drops
# what this shard does not own from the replication stream.  The Lua table was
# the one door that did not, and it broke in two different directions depending
# on which callback did the writing.
#
#   A replicated callback -- on_start, a timer -- runs in ALL N processes, so
#   each one wrote the whole keyspace into its own slice.  Twenty distinct keys
#   became eighty rows of store across four shards: four copies of every key,
#   three of them in a shard no read will ever route to, and DBSIZE and KEYS
#   counting all four.  The copies then diverge on the first write from the
#   wire, which goes to the owner alone.
#
#   A connection-driven callback -- on_miss, on_write, on_delete -- runs in
#   exactly ONE process, so every key it wrote that its own shard does not own
#   went into a slice no GET can reach.  KEYS listed twenty and GET found six,
#   from one connection, one second apart.
#
# ─── WHAT WAS MEASURED, AND ON WHICH BUILD ─────────────────────────────────
#
# e8cf169 (the parent of the fix), Release, four shards, twenty keys:
#
#   on_start writes k0..k19      DBSIZE 80, reads 20/20   -> fixed: DBSIZE 20
#   on_miss  writes m0..m19      KEYS 20, GET finds 6     -> fixed: KEYS 6, GET 6
#   one-shard control            DBSIZE 20, 20/20, KEYS 20 == GET 20, on both
#
# The one-shard control is what says this file is about sharding and not about
# self.set: it is green on the broken build and must stay green here.
#
# ─── THE ASSERTIONS, AND WHY NONE OF THEM IS FREE ──────────────────────────
#
#   1. DBSIZE after a replicated on_start is the number of DISTINCT keys.  A
#      build that drops the ownership check reads 80.  Asserting "the keys are
#      readable" instead passes on the broken build -- every shard has a copy,
#      so the owner does too, which is why 20/20 is kept as a companion and not
#      as the assertion.
#
#   2. KEYS and GET agree.  This one does not care which shard the triggering
#      key landed on, which is what makes it an equality and not a count: on the
#      broken build the store holds rows that no read can route to, and that is
#      a contradiction the cache can state about itself.
#
#   3. The owned subset is neither empty nor all twenty.  Without it assertion 2
#      passes on a build where the callback never ran, and passes on one shard.
#
#   4. self.owns() partitions the keyspace: summed over the four shards, each of
#      the twenty keys is owned exactly once.  A binding that answered true
#      everywhere -- the default on runtime_instance -- gives 80.  It runs on a
#      runtime of its own, because on the build this file was watched failing on
#      the binding does not exist and the script dies in on_start.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate shardluakeys

# 1200-1224, from a block nothing else in this directory uses: each four-shard
# cache binds base..base+3, so the runtimes are five apart and not four.
P4=$((SL_PORT_BASE+1200))
P1=$((SL_PORT_BASE+1205))
PM=$((SL_PORT_BASE+1210))
PM1=$((SL_PORT_BASE+1215))
PO=$((SL_PORT_BASE+1220))
NAMES="slk4 slk1 slm4 slm1 slo4"

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}
assert_eq() {
    local label=$1 want=$2 got=$3; shift 3
    if [ "$got" = "$want" ]; then pass; else
        fail "$label" "got '$got', wanted '$want'" "$@"
    fi
}
assert_between() {
    local label=$1 lo=$2 hi=$3 got=$4
    if [ "$got" -gt "$lo" ] && [ "$got" -lt "$hi" ]; then pass; else
        fail "$label" "got '$got', wanted strictly between $lo and $hi"
    fi
}

cleanup() {
    for n in $NAMES; do "$BIN" stop   "$n" >/dev/null 2>&1 || true; done
    sleep 0.3
    for n in $NAMES; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: the Lua table of a sharded cache writes its own slice ==="
daemon_start "$BIN"

W="$SOCKETLEY_TMPD"
N=20

# Every shard of a sharded runtime binds its own port, base..base+N-1, so the
# count of listeners in that range is how many of them are up.
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

# ─── the client ────────────────────────────────────────────────────────────
# One connection for the whole question, because "KEYS says one thing and GET
# says another" is only a contradiction if one client saw both.
cat > "$W/ask.py" <<'PYEOF'
import socket, sys

def enc(*parts):
    out = b"*%d\r\n" % len(parts)
    for p in parts:
        b = p.encode()
        out += b"$%d\r\n%s\r\n" % (len(b), b)
    return out

class Conn:
    def __init__(self, port):
        self.s = socket.create_connection(("127.0.0.1", port), 5)
        self.s.settimeout(5)
        self.buf = b""
    def _line(self):
        while b"\r\n" not in self.buf:
            c = self.s.recv(65536)
            if not c:
                raise EOFError("closed mid-reply")
            self.buf += c
        i = self.buf.index(b"\r\n")
        out, self.buf = self.buf[:i], self.buf[i+2:]
        return out
    def read(self):
        head = self._line()
        kind, rest = head[:1], head[1:]
        if kind in (b"+", b"-", b":"):
            return rest.decode("latin-1")
        if kind == b"$":
            n = int(rest)
            if n < 0:
                return None
            while len(self.buf) < n + 2:
                c = self.s.recv(65536)
                if not c:
                    raise EOFError("closed mid-bulk")
                self.buf += c
            out, self.buf = self.buf[:n], self.buf[n+2:]
            return out.decode("latin-1")
        if kind == b"*":
            n = int(rest)
            return [] if n < 0 else [self.read() for _ in range(n)]
        raise ValueError("unparsed reply %r" % head)
    def ask(self, *parts):
        self.s.sendall(enc(*parts))
        return self.read()

mode, port, n = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
c = Conn(port)

if mode == "replicated":
    # Written by on_start in every shard; nothing to trigger.
    hits = sum(1 for i in range(n) if c.ask("GET", "k%d" % i) == "v%d" % i)
    print("hits %d" % hits)
    print("dbsize %s" % c.ask("DBSIZE"))
else:
    # on_miss for this one key runs in whichever shard owns it, once.
    c.ask("GET", "trigger")
    keys = c.ask("KEYS", "m*")
    found = sum(1 for k in keys if c.ask("GET", k) is not None)
    print("keys %d" % len(keys))
    print("found %d" % found)
PYEOF

# ─── arm 1: a replicated callback ──────────────────────────────────────────
# on_start runs once per shard, so this script is executed four times over --
# and it asks nothing about ownership, which is what every script written
# before this change looks like: it writes all twenty keys in every shard and
# lets the store sort it out.  Deliberately, so this arm runs unchanged on the
# build that has the defect and the red below is about the store and not about
# a binding that is missing there.
cat > "$W/rep.lua" <<'LUAEOF'
function on_start()
    for i = 0, 19 do
        self.set("k" .. i, "v" .. i)
    end
end
LUAEOF

echo "--- 1. on_start runs in every shard: four shards, twenty keys ---"
"$BIN" create cache slk4 -p $P4 --shards 4 --lua "$W/rep.lua" >/dev/null 2>&1
assert_eq "a sharded cache with a script is accepted" "0" "$?"
"$BIN" start slk4 >/dev/null 2>&1
if ! wait_shards $P4 4; then
    daemon_bail "four shards" "only some of the four shards bound their port" \
        "every assertion below would be about a cache that is not four processes"
fi
sleep 0.6

OUT=$(python3 "$W/ask.py" replicated $P4 $N) || daemon_required "four shards"
HITS=$(echo "$OUT" | awk '/^hits/{print $2}')
DBS=$(echo  "$OUT" | awk '/^dbsize/{print $2}')
echo "  observed: DBSIZE $DBS, $HITS of $N keys readable"
# 80 on the broken build: four shards, each holding a copy of all twenty.
assert_eq "the store holds each key once, not once per shard" "$N" "$DBS" \
    "DBSIZE 80 is four copies of twenty keys, three of them unreachable"
# Green on the broken build too, and kept for what it would catch here: a fix
# that stopped the duplication by dropping the writes.
assert_eq "and every key is still readable from the wire" "$N" "$HITS"

echo "--- 2. the one-shard control, same script ---"
"$BIN" create cache slk1 -p $P1 --shards 1 --lua "$W/rep.lua" >/dev/null 2>&1
"$BIN" start slk1 >/dev/null 2>&1
wait_shards $P1 1 || daemon_bail "one shard" "the control cache never bound its port"
sleep 0.4
OUT=$(python3 "$W/ask.py" replicated $P1 $N) || daemon_required "one shard"
HITS=$(echo "$OUT" | awk '/^hits/{print $2}')
DBS=$(echo  "$OUT" | awk '/^dbsize/{print $2}')
echo "  observed: DBSIZE $DBS, $HITS of $N keys readable"
assert_eq "one shard stores twenty keys"    "$N" "$DBS"
assert_eq "and reads all twenty back"       "$N" "$HITS"

# ─── arm 2b: the question itself ───────────────────────────────────────────
# A separate runtime, because self.owns does not exist on the build this file
# was watched failing on and a script that calls it there dies in on_start --
# which would take arm 1's numbers with it and report the wrong red.
cat > "$W/owns.lua" <<LUAEOF
local OWNED = "$W/owned.log"
LUAEOF
cat >> "$W/owns.lua" <<'LUAEOF'

-- One line per key this process says it owns, so the shell can check that the
-- four shards partition the twenty rather than each claiming all of them.
function on_start()
    local f = io.open(OWNED, "a")
    for i = 0, 19 do
        local k = "k" .. i
        if self.owns(k) then
            if f then f:write(k .. "\n") end
        end
    end
    if f then f:close() end
end
LUAEOF
: > "$W/owned.log"

echo "--- 2b. self.owns is the question the refusal turns on ---"
"$BIN" create cache slo4 -p $PO --shards 4 --lua "$W/owns.lua" >/dev/null 2>&1
"$BIN" start slo4 >/dev/null 2>&1
wait_shards $PO 4 || daemon_bail "self.owns" "not all four shards bound"
sleep 0.6
OWNED_TOTAL=$(wc -l < "$W/owned.log")
OWNED_DISTINCT=$(sort -u "$W/owned.log" | wc -l)
echo "  observed: self.owns said yes $OWNED_TOTAL times over the four shards, $OWNED_DISTINCT distinct keys"
# 80 if self.owns answered true everywhere, which is the default it inherits
# from runtime_instance; 0 if the binding is not there at all.
assert_eq "self.owns partitions the keyspace: each key owned once" "$N" "$OWNED_TOTAL"
assert_eq "and the partition covers all of it"                     "$N" "$OWNED_DISTINCT"

# ─── arm 3: a callback that runs in ONE shard ──────────────────────────────
cat > "$W/miss.lua" <<'LUAEOF'
-- on_miss for `trigger` runs in the shard that owns `trigger`, once, and the
-- twenty keys it then writes are spread over all four.
function on_miss(key)
    if key == "trigger" then
        for i = 0, 19 do
            self.set("m" .. i, "w" .. i)
        end
        return "done"
    end
    return nil
end
LUAEOF

echo "--- 3. on_miss runs in one shard and writes keys three others own ---"
"$BIN" create cache slm4 -p $PM --shards 4 --lua "$W/miss.lua" >/dev/null 2>&1
"$BIN" start slm4 >/dev/null 2>&1
wait_shards $PM 4 || daemon_bail "on_miss four shards" "not all four shards bound"
sleep 0.6
OUT=$(python3 "$W/ask.py" driven $PM $N) || daemon_required "on_miss four shards"
KEYS=$(echo  "$OUT" | awk '/^keys/{print $2}')
FOUND=$(echo "$OUT" | awk '/^found/{print $2}')
echo "  observed: KEYS m* lists $KEYS, GET finds $FOUND of them"
# 20 against 6 on the broken build: fourteen rows of store that no read routes
# to, counted by KEYS and by DBSIZE, and invisible to every client.
assert_eq "what KEYS lists is what GET can find" "$KEYS" "$FOUND"
# Without this the equality above is satisfied by a callback that never ran,
# and by a cache that is one process.
assert_between "and this shard kept a proper part of the twenty" 0 "$N" "$KEYS"

echo "--- 4. the one-shard control for the same script ---"
"$BIN" create cache slm1 -p $PM1 --shards 1 --lua "$W/miss.lua" >/dev/null 2>&1
"$BIN" start slm1 >/dev/null 2>&1
wait_shards $PM1 1 || daemon_bail "on_miss one shard" "the control cache never bound"
sleep 0.4
OUT=$(python3 "$W/ask.py" driven $PM1 $N) || daemon_required "on_miss one shard"
KEYS=$(echo  "$OUT" | awk '/^keys/{print $2}')
FOUND=$(echo "$OUT" | awk '/^found/{print $2}')
echo "  observed: KEYS m* lists $KEYS, GET finds $FOUND of them"
assert_eq "one shard writes all twenty"  "$N" "$KEYS"
assert_eq "and finds all twenty"         "$N" "$FOUND"

echo ""
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  PASSED" || echo "  FAILED"
exit "$FAIL"
