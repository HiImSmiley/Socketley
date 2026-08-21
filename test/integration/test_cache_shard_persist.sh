#!/usr/bin/env bash
# Integration test: a sharded cache's dumps survive a changed shard count.
#
# ─── THIS RAN AS pending_ WHILE THE REFUSAL STOOD ──────────────────────────
#
# `--shards` on a cache was refused while this was being built, so the file was
# outside run_all.sh's glob and run against a scratch build.  Both are gone.
#
# ─── WHY THE ASSERTION IS NOT "DOES IT LOAD" ───────────────────────────────
#
# This is the step where a mistake loses data in silence, and a cache that has
# lost half its keys answers exactly like one that has not: it is up, it serves,
# and a GET for a key that is gone is a miss, which is a legal answer.  So
# "the cache answers" cannot fail here, and an assertion that cannot fail is not
# coverage.
#
# Every case below therefore writes N keys with known values, restarts under a
# different shard count, reads back EVERY ONE of them, and compares the total.
# The count catches wholesale loss; reading each key catches the case where the
# right number of keys survived in the wrong slices.
#
# ─── THE MATRIX, AND WHAT EACH ROW IS FOR ──────────────────────────────────
#
#   4 -> 4   the fast path: same split, each shard reads its own dump.
#   1 -> 4   the pre-shard dump, redistributed.  Also the upgrade path for a
#            cache that was --persistent before any of this existed.
#   4 -> 1   N dumps collapsed into one store.
#   4 -> 8   a split finer than the one written.
#   8 -> 4   coarser, and the one that found a defect: it leaves shard4..7 on
#            disk, which without cleanup makes the NEXT start refuse.  So this
#            row restarts twice.
#
# And two that must ABORT rather than serve what survived:
#
#   a missing dump          shard 2's file deleted.  Its keys are gone and
#                           nothing else can tell — so the start refuses.
#   a contradictory set     files from two runs claiming different counts.
#                           Loading either would be a guess.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

daemon_isolate cacheshardpersist
PORT=$((SL_PORT_BASE+1280))
WORK=$(mktemp -d)
KEYS=60

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"
        local l; for l in "${@:3}"; do echo "        $l"; done; }

cleanup() { "$BIN" stop pc >/dev/null 2>&1 || true; sleep 0.3
            "$BIN" remove pc >/dev/null 2>&1 || true; rm -rf "$WORK"; daemon_stop; }
trap cleanup EXIT

echo "=== Integration: a sharded cache's dumps survive a changed shard count ==="
command -v redis-cli >/dev/null 2>&1 || { echo "  SKIP: redis-cli required"; exit 0; }
daemon_start "$BIN"

DUMP="$WORK/c.rdb"

up() {   # shards -> bring pc up, wait for it
    "$BIN" create cache pc -p "$PORT" --shards "$1" --resp \
           --persistent "$DUMP" -s >/dev/null 2>&1
    local i
    for i in $(seq 1 100); do
        redis-cli -p "$PORT" PING 2>/dev/null | grep -q PONG && return 0
        sleep 0.25
    done
    return 1
}
down() { "$BIN" stop pc >/dev/null 2>&1; sleep 1.5; "$BIN" remove pc >/dev/null 2>&1; sleep 0.3; }

write_keys() { local i; for i in $(seq 1 $KEYS); do
                   redis-cli -p "$PORT" SET "k$i" "v$i" >/dev/null 2>&1; done; }
# Reads back every key and returns "<missing> <dbsize>".
verify() {
    local m=0 i
    for i in $(seq 1 $KEYS); do
        [ "$(redis-cli -p "$PORT" GET "k$i" 2>/dev/null)" = "v$i" ] || m=$((m+1))
    done
    printf '%s %s' "$m" "$(redis-cli -p "$PORT" DBSIZE 2>/dev/null)"
}

if ! up 4; then
    echo "  FATAL: --shards on a cache was refused.  It is a supported"
    echo "         configuration now, so this is a defect and not a skip."
    exit 2
fi

# ── the matrix ─────────────────────────────────────────────────────────────
matrix_case() {   # from to label
    local from=$1 to=$2 label=$3
    rm -f "$DUMP" "$DUMP".shard* 2>/dev/null
    up "$from" || { bad "$label" "the $from-shard cache never came up"; return; }
    write_keys
    down
    up "$to" || { bad "$label" "the $to-shard cache never came up after the dump"; return; }
    read -r MISS SIZE <<<"$(verify)"
    down
    if [ "$MISS" -eq 0 ] && [ "$SIZE" = "$KEYS" ]; then
        ok "$label — all $KEYS keys, dbsize $SIZE"
    else
        bad "$label" "$MISS of $KEYS keys missing, dbsize '$SIZE' (expected $KEYS)" \
            "a cache that lost keys answers exactly like one that did not"
    fi
}

matrix_case 4 4 "4 -> 4"
matrix_case 1 4 "1 -> 4"
matrix_case 4 1 "4 -> 1"
matrix_case 4 8 "4 -> 8"

# 8 -> 4, then 4 again.  The second restart is the assertion: the first leaves
# shard4..7 on disk, and without removing them the next start sees two sets.
rm -f "$DUMP" "$DUMP".shard* 2>/dev/null
up 8 || bad "8 -> 4" "the 8-shard cache never came up"
write_keys
down
up 4 || bad "8 -> 4" "the 4-shard cache never came up"
read -r MISS SIZE <<<"$(verify)"
down
if [ "$MISS" -eq 0 ] && [ "$SIZE" = "$KEYS" ]; then
    ok "8 -> 4 — all $KEYS keys, dbsize $SIZE"
else
    bad "8 -> 4" "$MISS missing, dbsize '$SIZE'"
fi
LEFT=$(ls "$DUMP".shard* 2>/dev/null | wc -l)
if up 4; then
    read -r MISS2 SIZE2 <<<"$(verify)"
    down
    if [ "$MISS2" -eq 0 ] && [ "$SIZE2" = "$KEYS" ]; then
        ok "and again at 4 — the superseded slices were removed ($LEFT files left)"
    else
        bad "and again at 4 — the superseded slices were removed" \
            "$MISS2 missing, dbsize '$SIZE2'; $LEFT dump files present" \
            "a shrink that leaves the old slices makes the NEXT start refuse"
    fi
else
    bad "and again at 4 — the superseded slices were removed" \
        "the cache refused to start; $LEFT dump files present, which is two" \
        "sets in one place left behind by the shrink"
fi

# ── the two that must abort ────────────────────────────────────────────────
serving() { redis-cli -p "$PORT" PING 2>/dev/null | grep -q PONG; }

rm -f "$DUMP" "$DUMP".shard* 2>/dev/null
up 4 || true; write_keys; down
rm -f "$DUMP".shard2
"$BIN" create cache pc -p "$PORT" --shards 4 --resp --persistent "$DUMP" -s >/dev/null 2>&1
sleep 3
if ! serving && grep -q "is missing beside" "$SOCKETLEY_DLOG" 2>/dev/null; then
    ok "a missing dump refuses the start and names the slice"
else
    bad "a missing dump refuses the start and names the slice" \
        "serving=$(serving && echo yes || echo no); the keys of slice 2 would be" \
        "gone with the cache reporting itself healthy"
fi
down

rm -f "$DUMP" "$DUMP".shard* 2>/dev/null
up 8 || true; write_keys; down
cp "$DUMP".shard7 "$WORK/stale7"            # a file from the 8-shard run
rm -f "$DUMP" "$DUMP".shard* 2>/dev/null
up 4 || true; write_keys; down
cp "$WORK/stale7" "$DUMP".shard7            # ...dropped beside the 4-shard set
"$BIN" create cache pc -p "$PORT" --shards 4 --resp --persistent "$DUMP" -s >/dev/null 2>&1
sleep 3
if ! serving && grep -qE "disagree about how many shards|not a slice that set has" \
        "$SOCKETLEY_DLOG" 2>/dev/null; then
    ok "a contradictory set refuses the start"
else
    bad "a contradictory set refuses the start" \
        "serving=$(serving && echo yes || echo no); loading either set is a guess" \
        "about which keys are current"
fi
down

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
