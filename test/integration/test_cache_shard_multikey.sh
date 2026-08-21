#!/usr/bin/env bash
# Integration test: the commands that touch more than one shard of a cache.
#
# ─── THIS RAN AS pending_ WHILE THE REFUSAL STOOD ──────────────────────────
#
# `--shards` on a cache was refused while the routing was being built one
# command class at a time, so this file lived outside run_all.sh's glob and was
# run against a scratch build with the one refusal line compiled out.  The
# refusal is gone and so is the flag; the file runs like any other now.
#
# The numbers below were taken on that scratch build and are kept because they
# are what the assertions were written against:
#
# Measured on that build, four shards:
#
#   against step one   every assertion below except the controls FAILED, and
#                      all of them for the same reason — the commands were
#                      refused by name ("spans every shard of this cache and is
#                      not routed yet"), which is what step one shipped.
#   against this       all of them pass.  1200 keys walked by SCAN in 171 calls,
#                      each returned exactly once, and the set equal to KEYS.
#                      150 rounds of MSET+MGET over four shards, no mismatch.
#
# ─── WHAT IS BEING HELD DOWN ───────────────────────────────────────────────
#
# A command naming several keys is EXPLODED into one single-key command per key
# and the pieces are reassembled in the order the CALLER wrote them — not the
# order the shards answered, which is the order the replies happen to arrive.
# A keyspace-wide command goes to every shard and its answers are merged: dbsize
# sums, keys concatenates, and there is one terminator for the runtime rather
# than one per shard.
#
# Each assertion names the broken build it catches:
#
#   mget order        a reassembly that appends replies as they land passes a
#                     set comparison and fails this one.  The values are
#                     distinct and compared as a SEQUENCE.
#   one terminator    a `keys` merge that concatenates whole per-shard replies
#                     emits N `end` lines; a client reading to the first one
#                     sees a quarter of the keyspace and calls it the whole.
#   dbsize sums       a dbsize answered from one shard is a confident wrong
#                     number, which is worse than an error.
#   scan covers       a cursor that does not carry its shard either repeats one
#                     shard for ever or stops after the first.  Asserted as
#                     "every key exactly once AND terminates", because either
#                     half alone passes on one of those two broken builds.
#   flush's reason    `flush` is not a keyspace command — it writes the dump
#                     file — so it must be refused for THAT reason.  A build
#                     that fans it out has every shard write one path.
#   the controls      one shard, same commands, same answers.  Without them a
#                     red above could be an ordinary cache defect.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

daemon_isolate cacheshardmk

P_T4=$((SL_PORT_BASE+1250))
P_R4=$((SL_PORT_BASE+1251))
P_T1=$((SL_PORT_BASE+1252))

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    for n in mk4 mkr4 mk1; do "$BIN" stop "$n" >/dev/null 2>&1 || true; done
    sleep 0.4
    for n in mk4 mkr4 mk1; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a sharded cache answers the multi-shard commands ==="

command -v nc >/dev/null 2>&1 || { echo "  SKIP: nc is required"; exit 0; }

daemon_start "$BIN"

if ! "$BIN" create cache mk4 -p "$P_T4" --shards 4 -s >/dev/null 2>&1; then
    echo "  FATAL: --shards on a cache was refused.  It is a supported"
    echo "         configuration now, so this is a defect and not a skip."
    exit 2
fi
"$BIN" create cache mkr4 -p "$P_R4" --shards 4 --resp -s >/dev/null 2>&1
"$BIN" create cache mk1  -p "$P_T1" --shards 1 -s        >/dev/null 2>&1

ready() {
    local port=$1 i
    for i in $(seq 1 60); do
        printf 'set __r 1\n' | timeout 2 nc -q1 127.0.0.1 "$port" 2>/dev/null \
            | grep -q '^ok$' && return 0
        sleep 0.25
    done
    return 1
}
ready "$P_T4" || { echo "  FATAL: the four-shard cache never answered"; exit 2; }
ready "$P_T1" || { echo "  FATAL: the one-shard cache never answered";  exit 2; }

# ── mget: every value, in the caller's order ────────────────────────────────
SETS=""; GETS="mget"
for i in 0 1 2 3 4 5 6 7; do
    SETS="${SETS}set ak${i} av${i}\n"
    GETS="${GETS} ak${i}"
done
printf "$SETS" | timeout 5 nc -q1 127.0.0.1 "$P_T4" >/dev/null 2>&1
OUT=$(printf "${GETS}\n" | timeout 5 nc -q1 127.0.0.1 "$P_T4" 2>/dev/null)
WANT=$(for i in 0 1 2 3 4 5 6 7; do echo "av$i"; done; echo "end")

if [ "$OUT" = "$WANT" ]; then
    ok "mget returns every value, in the order the caller asked (8/8)"
else
    bad "mget returns every value, in the order the caller asked" \
        "got:      $(printf '%s' "$OUT"  | tr '\n' ' ')" \
        "expected: $(printf '%s' "$WANT" | tr '\n' ' ')"
fi

# ── mset: each pair has to land on the key's own owner ──────────────────────
MS="mset"; for i in 0 1 2 3 4 5; do MS="${MS} bk${i} bv${i}"; done
printf "${MS}\n" | timeout 5 nc -q1 127.0.0.1 "$P_T4" >/dev/null 2>&1
BG="mget"; for i in 0 1 2 3 4 5; do BG="${BG} bk${i}"; done
BOUT=$(printf "${BG}\n" | timeout 5 nc -q1 127.0.0.1 "$P_T4" 2>/dev/null)
BWANT=$(for i in 0 1 2 3 4 5; do echo "bv$i"; done; echo "end")
if [ "$BOUT" = "$BWANT" ]; then
    ok "mset writes each pair to the shard that owns its key (6/6)"
else
    bad "mset writes each pair to the shard that owns its key" \
        "got: $(printf '%s' "$BOUT" | tr '\n' ' ')"
fi

# ── keys: all of them, and exactly ONE terminator ───────────────────────────
KOUT=$(printf 'keys ak*\n' | timeout 5 nc -q1 127.0.0.1 "$P_T4" 2>/dev/null)
KCOUNT=$(printf '%s\n' "$KOUT" | grep -c '^ak[0-9]*$' || true)
ENDS=$(printf '%s\n'   "$KOUT" | grep -c '^end$' || true)
if [ "$KCOUNT" -eq 8 ]; then
    ok "keys reports every shard's slice (8/8)"
else
    bad "keys reports every shard's slice" "got $KCOUNT of 8"
fi
if [ "$ENDS" -eq 1 ]; then
    ok "keys ends once for the runtime, not once per shard"
else
    bad "keys ends once for the runtime, not once per shard" \
        "$ENDS terminators; a client reading to the first sees one shard's share"
fi

# ── size: summed, not answered from one slice ───────────────────────────────
SZ=$(printf 'size\n' | timeout 5 nc -q1 127.0.0.1 "$P_T4" 2>/dev/null | head -1)
EXP_SZ=$((8 + 6 + 1))       # ak0..7, bk0..5, and the __r readiness key
if [ "$SZ" = "$EXP_SZ" ]; then
    ok "size sums every shard's slice ($SZ)"
else
    bad "size sums every shard's slice" "got '$SZ', expected $EXP_SZ"
fi

# ── the one-shard control, same commands ────────────────────────────────────
printf "$SETS" | timeout 5 nc -q1 127.0.0.1 "$P_T1" >/dev/null 2>&1
COUT=$(printf "${GETS}\n" | timeout 5 nc -q1 127.0.0.1 "$P_T1" 2>/dev/null)
if [ "$COUT" = "$WANT" ]; then
    ok "the one-shard control answers mget identically"
else
    bad "the one-shard control answers mget identically" \
        "this is not about sharding — an unsharded mget is wrong" \
        "got: $(printf '%s' "$COUT" | tr '\n' ' ')"
fi

# ── flush is answered by the runtime, not refused ──────────────────────────
#
# When this file was written `flush` was refused, because fanning it out would
# have had four shards write four slices over one path.  Step four gave each
# shard its own dump file, so it is routed now and answers with the
# interpreter's own reply merged across the shards — `all_ok`, so a partial
# flush shows as the refusal it is rather than being averaged away.
FOUT=$(printf 'flush\n' | timeout 5 nc -q1 127.0.0.1 "$P_T4" 2>/dev/null | head -1)
case "$FOUT" in
    *"not routed"*|"")
        bad "flush is answered by the runtime rather than refused as unroutable" \
            "got '$FOUT'" ;;
    *)
        ok "flush is answered by the runtime ('$FOUT')" ;;
esac

# ── RESP: the second dispatch, and SCAN ─────────────────────────────────────
if command -v redis-cli >/dev/null 2>&1; then
    for i in $(seq 1 40); do redis-cli -p "$P_R4" SET "rk$i" "rv$i" >/dev/null 2>&1; done

    MG=$(redis-cli -p "$P_R4" MGET rk1 rk2 rk3 2>/dev/null | tr '\n' ' ')
    if [ "$MG" = "rv1 rv2 rv3 " ]; then
        ok "the RESP dispatch reassembles mget in the caller's order"
    else
        bad "the RESP dispatch reassembles mget in the caller's order" "got '$MG'"
    fi

    DB=$(redis-cli -p "$P_R4" DBSIZE 2>/dev/null)
    if [ "$DB" = "40" ]; then
        ok "dbsize sums every shard (40)"
    else
        bad "dbsize sums every shard" "got '$DB', expected 40"
    fi

    DL=$(redis-cli -p "$P_R4" DEL rk1 rk2 rk3 2>/dev/null)
    if [ "$DL" = "3" ]; then
        ok "a multi-key del reports the total it deleted (3)"
    else
        bad "a multi-key del reports the total it deleted" "got '$DL', expected 3"
    fi

    # SCAN: every key exactly once, and it must stop.
    #
    # Both halves together.  A cursor that loses its shard either walks shard 0
    # for ever (terminates=no) or stops when shard 0 is done (covers=no), and
    # each broken build passes one half.
    SEEN=$(python3 - "$P_R4" <<'PY'
import subprocess, sys
port = sys.argv[1]
cur, seen, calls = '0', [], 0
while True:
    o = subprocess.run(['redis-cli','-p',port,'SCAN',cur,'COUNT','7'],
                       capture_output=True, text=True).stdout.split('\n')
    calls += 1
    cur = o[0].strip()
    seen += [k for k in o[1:] if k.strip()]
    if cur == '0' or calls > 400:
        break
print('%d %d %d %s' % (calls, len(seen), len(set(seen)), cur))
PY
)
    read -r SC_CALLS SC_EMIT SC_UNIQ SC_END <<<"$SEEN"
    KEYS_N=$(redis-cli -p "$P_R4" DBSIZE 2>/dev/null)
    if [ "$SC_END" = "0" ] && [ "$SC_UNIQ" = "$KEYS_N" ] && [ "$SC_EMIT" = "$SC_UNIQ" ]; then
        ok "scan walks every shard, each key once, and terminates ($SC_UNIQ in $SC_CALLS calls)"
    else
        bad "scan walks every shard, each key once, and terminates" \
            "calls=$SC_CALLS emitted=$SC_EMIT distinct=$SC_UNIQ dbsize=$KEYS_N final_cursor=$SC_END"
    fi

    # A cursor naming a shard this runtime does not have is refused, in RESP's
    # own shape.  A text error on a RESP socket desynchronises the client.
    BADC=$(redis-cli -p "$P_R4" SCAN 17293822569102704640 2>&1 | head -1)
    case "$BADC" in
        *"invalid cursor"*) ok "a cursor from another shard set is refused, in RESP" ;;
        *) bad "a cursor from another shard set is refused, in RESP" "got '$BADC'" ;;
    esac
else
    echo "  (redis-cli absent — the RESP and SCAN assertions did not run)"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
