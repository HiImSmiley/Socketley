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

# ── a reshard holds its own slice, not a whole dump ─────────────────────────
#
# Every shard reads every dump of the old set and keeps what hashes to it; it loaded each one whole into a store of its
# own first, so four shards each held the whole 64 MB at once on top of their slice.  Now each keeps only its keys
# as it reads, and the dump is held only as the page cache of its mapping.
rm -f "$DUMP" "$DUMP".shard* 2>/dev/null
if up 1; then
    python3 - "$PORT" <<'PYW'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=30)
v = b"x" * 4096
s.sendall(b"".join(b"*3\r\n$3\r\nSET\r\n$%d\r\nbig%d\r\n$4096\r\n%s\r\n" % (len(b"big%d" % i), i, v) for i in range(16000)))
got = b""
while got.count(b"\r\n") < 16000:
    got += s.recv(1 << 20)
PYW
    redis-cli -p "$PORT" SET ttlkey v EX 1000 >/dev/null 2>&1
    down
    DSIZE=$(stat -c %s "$DUMP" 2>/dev/null || echo 0)
    if up 4; then
        HWM=0
        for p in $(ss -Hltnp "sport = :$PORT" 2>/dev/null | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u); do
            h=$(awk '/^VmHWM/ {print $2 * 1024}' "/proc/$p/status" 2>/dev/null || echo 0)
            [ "${h:-0}" -gt "$HWM" ] && HWM=$h
        done
        N=$(redis-cli -p "$PORT" DBSIZE 2>/dev/null); T=$(redis-cli -p "$PORT" TTL ttlkey 2>/dev/null)
        down
        [ "$N" = 16001 ] && [ "${T:-0}" -gt 900 ] && ok "1 -> 4 of 64 MB keeps every key and a deadline ($N keys, ttl $T)" \
            || bad "1 -> 4 of 64 MB keeps every key and a deadline" "dbsize '$N', ttl '$T'"
        if nm -C "$BIN" 2>/dev/null | grep '__asan_' >/dev/null; then
            echo "  SKIP [memory]: a peak resident size measures the sanitizer's shadow and quarantine, not the slice"
        else
            [ "$DSIZE" -gt 60000000 ] && [ "$HWM" -lt $((DSIZE * 18 / 10)) ] \
                && ok "and no shard held more than its slice beside the mapped dump (peak $HWM bytes, dump $DSIZE)" \
                || bad "and no shard held more than its slice beside the mapped dump" \
                       "a shard peaked at $HWM bytes over a dump of $DSIZE; each loaded the whole dump into a store of its own"
        fi
    else
        bad "1 -> 4 of 64 MB" "the 4-shard cache never came up"
    fi
else
    bad "1 -> 4 of 64 MB" "the 1-shard cache never came up"
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
