#!/usr/bin/env bash
# Integration test: --persistent-interval journals writes a kill -9 cannot take.
#
# ─── WHY EVERY ASSERTION READS THE DATA BACK ────────────────────────────────
#
# The failure mode under test is silent loss: a cache that dropped its journal
# comes up, serves, and answers every GET for a vanished key with a legal miss.
# So each case writes keys with known values, kills the worker without a stop
# (the dump is never written, which is what makes the journal the only source),
# restarts, and reads every key back.
#
# ─── THE MATRIX ─────────────────────────────────────────────────────────────
#
#   refusal        --persistent-interval without --persistent exits 1, in
#                  either flag order, and a malformed duration is refused.
#   replay         kill -9 mid-run; every key is there after the restart,
#                  with no dump file on disk to explain it.
#   ttl            a live TTL survives the replay smaller than it started,
#                  and a TTL that lapsed while the runtime was dead is gone.
#   torn tail      garbage appended to the journal must not refuse the start
#                  or take the complete records in front of it.
#   truncation     a clean stop cuts the journal to its header, and the data
#                  is then served from the dump alone.
#   changed shards a journal holding records under one split refuses a start
#                  under another, and recovers under the split that wrote it.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

daemon_isolate cachejournal
PORT=$((SL_PORT_BASE+1310))
WORK=$(mktemp -d)
KEYS=30

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"
        local l; for l in "${@:3}"; do echo "        $l"; done; }

cleanup() { "$BIN" stop jc >/dev/null 2>&1 || true; sleep 0.3
            "$BIN" remove jc >/dev/null 2>&1 || true; rm -rf "$WORK"; daemon_stop; }
trap cleanup EXIT

echo "=== Integration: the cache journal survives what the dump cannot ==="
command -v redis-cli >/dev/null 2>&1 || { echo "  SKIP: redis-cli required"; exit 0; }
daemon_start "$BIN"

DUMP="$WORK/j.rdb"
# 8 magic + 4 owner length + 32 shard-dump header
JOURNAL_HEAD=44

wait_up() {
    local i
    for i in $(seq 1 100); do
        redis-cli -p "$PORT" PING 2>/dev/null | grep -q PONG && return 0
        sleep 0.25
    done
    return 1
}

# kill -9 every worker pid `stats` names, confirmed ours before signalling,
# because a pid can be reused between the read and the kill.
kill_workers() {
    local pids p
    pids=$("$BIN" stats jc 2>/dev/null | awk -F: '/^pid:/ {print $2}' | tr ',' ' ')
    [ -n "$pids" ] || return 1
    for p in $pids; do
        grep -qa 'socketley' "/proc/$p/cmdline" 2>/dev/null && kill -9 "$p" 2>/dev/null
    done
    # Gone means gone: wait for every corpse to be unreachable.
    local i
    for i in $(seq 1 40); do
        local alive=0
        for p in $pids; do kill -0 "$p" 2>/dev/null && alive=1; done
        [ "$alive" = 0 ] && return 0
        sleep 0.25
    done
    return 1
}

# Stop every worker, append a torn frame head to the journal, then kill them,
# so the next start is the first process to see the tear.
tear_and_kill() {
    local pids p
    pids=$("$BIN" stats jc 2>/dev/null | awk -F: '/^pid:/ {print $2}' | tr ',' ' ')
    [ -n "$pids" ] || return 1
    for p in $pids; do
        grep -qa 'socketley' "/proc/$p/cmdline" 2>/dev/null && kill -STOP "$p" 2>/dev/null
    done
    printf '\x40\x00\x00\x00\xde\xad\xbe\xefjunk' >> "$DUMP.journal"
    kill_workers
}

# Bring jc back after a kill, whether or not the daemon revived it itself.
revive() {
    wait_up && return 0
    "$BIN" start jc >/dev/null 2>&1
    wait_up
}

write_keys() { local i; for i in $(seq 1 $KEYS); do
                   redis-cli -p "$PORT" SET "jk$i" "jv$i" >/dev/null 2>&1; done; }

count_keys() { local i n=0 v
    for i in $(seq 1 $KEYS); do
        v=$(redis-cli -p "$PORT" GET "jk$i" 2>/dev/null)
        [ "$v" = "jv$i" ] && n=$((n+1))
    done
    echo "$n"; }

# ── 1. The refusal, both flag orders, and the duration grammar ──────────────
OUT=$("$BIN" create cache jr --persistent-interval 5s 2>&1); RC=$?
if [ "$RC" = 1 ] && echo "$OUT" | grep -q -- "--persistent"; then
    ok "an interval without --persistent is refused, exit 1"
else
    bad "interval without --persistent" "rc=$RC out=$OUT"
fi
"$BIN" remove jr >/dev/null 2>&1

OUT=$("$BIN" create cache jr --persistent-interval 5s --persistent "$WORK/r.rdb" 2>&1); RC=$?
if [ "$RC" = 0 ]; then
    ok "the pair is judged as a set, whichever flag comes first"
else
    bad "interval typed before --persistent" "rc=$RC out=$OUT"
fi
"$BIN" remove jr >/dev/null 2>&1

OUT=$("$BIN" create cache jr --persistent "$WORK/r.rdb" --persistent-interval 5x 2>&1); RC=$?
if [ "$RC" = 1 ]; then
    ok "a malformed duration is refused"
else
    bad "malformed duration" "rc=$RC out=$OUT"
fi
"$BIN" remove jr >/dev/null 2>&1

# ── 2. Replay after an unclean stop ─────────────────────────────────────────
"$BIN" create cache jc -p "$PORT" --resp --persistent "$DUMP" \
       --persistent-interval 1s -s >/dev/null 2>&1
wait_up || bad "setup" "cache never answered PING"
write_keys
redis-cli -p "$PORT" SET jttl long >/dev/null 2>&1
redis-cli -p "$PORT" EXPIRE jttl 300 >/dev/null 2>&1
redis-cli -p "$PORT" SET jdead soon >/dev/null 2>&1
redis-cli -p "$PORT" EXPIRE jdead 2 >/dev/null 2>&1

# Past the interval, so the buffer has reached the file.
sleep 2
JSZ=$(stat -c %s "$DUMP.journal" 2>/dev/null || echo 0)
if [ "$JSZ" -gt "$JOURNAL_HEAD" ]; then
    ok "the interval flush reaches the file while the cache runs ($JSZ bytes)"
else
    bad "interval flush" "journal is $JSZ bytes, expected > $JOURNAL_HEAD"
fi

kill_workers || bad "kill" "no worker pid to kill"
sleep 1.5   # jdead's 2s lapse while the runtime is down

if [ -e "$DUMP" ]; then
    bad "no dump before replay" "a dump exists, so this would not test the journal"
fi

revive || bad "restart" "cache never came back"
GOT=$(count_keys)
if [ "$GOT" = "$KEYS" ]; then
    ok "kill -9: all $KEYS keys replayed from the journal alone"
else
    bad "replay after kill -9" "$GOT of $KEYS keys survived"
fi

# ── 3. TTLs across the replay ───────────────────────────────────────────────
PTTL=$(redis-cli -p "$PORT" PTTL jttl 2>/dev/null)
if [ -n "$PTTL" ] && [ "$PTTL" -gt 0 ] && [ "$PTTL" -le 300000 ]; then
    ok "a live TTL survives replay, smaller than it started (${PTTL}ms of 300s)"
else
    bad "ttl survival" "PTTL jttl = $PTTL"
fi
# EXISTS rather than GET, because an unreachable cache also answers GET with nothing.
DEAD=$(redis-cli -p "$PORT" EXISTS jdead 2>/dev/null)
if [ "$DEAD" = "0" ]; then
    ok "a TTL that lapsed while the runtime was dead stays lapsed"
else
    bad "lapsed ttl" "EXISTS jdead = '$DEAD', wanted 0"
fi

# ── 4. A torn tail ──────────────────────────────────────────────────────────
redis-cli -p "$PORT" SET jtail kept >/dev/null 2>&1
sleep 2                       # flushed
# A frame head claiming 64 bytes with 4 bytes of payload: what a crash
# mid-write leaves -- appended while the worker is stopped and before it dies,
# because the daemon restarts a killed worker at once and garbage appended after
# that lands in the middle of a live journal, which is not the case under test.
tear_and_kill || bad "kill 2" "no worker pid to kill"
revive || bad "torn restart" "cache refused a journal with a torn tail"
GOT=$(count_keys)
V=$(redis-cli -p "$PORT" GET jtail 2>/dev/null)
if [ "$GOT" = "$KEYS" ] && [ "$V" = "kept" ] && grep -q 'ended mid-record' "$SOCKETLEY_DLOG"; then
    ok "a torn tail is dropped, the complete records in front of it are not"
else
    bad "torn tail" "$GOT of $KEYS keys, GET jtail = $V"
fi

# A write accepted after that recovery must survive the next crash, which it
# cannot if it was appended behind the garbage the replay stops at.
redis-cli -p "$PORT" SET jafter written >/dev/null 2>&1
sleep 2                       # flushed
JB=$(stat -c%s "$DUMP.journal" 2>/dev/null)
kill_workers || bad "kill 2b" "no worker pid to kill"
revive || bad "second torn restart" "cache never came back"
V=$(redis-cli -p "$PORT" GET jafter 2>/dev/null)
if [ "$V" = "written" ]; then
    ok "a write after a torn-tail recovery survives the next crash"
else
    bad "write behind a torn tail" "GET jafter = '$V' after the second kill -9" \
        "it was journaled behind the garbage, where replay stops (journal $JB bytes)" \
        "$(grep -iE 'journal|replay|torn' "$SOCKETLEY_DLOG" 2>/dev/null | tail -4)"
fi

# ── 5. Truncation behind the snapshot ───────────────────────────────────────
redis-cli -p "$PORT" SET jclean here >/dev/null 2>&1
"$BIN" stop jc >/dev/null 2>&1
sleep 1
JSZ=$(stat -c %s "$DUMP.journal" 2>/dev/null || echo missing)
if [ "$JSZ" = "$JOURNAL_HEAD" ]; then
    ok "a clean stop cuts the journal to its header"
else
    bad "truncation" "journal is $JSZ bytes after a clean stop, expected $JOURNAL_HEAD"
fi
[ -e "$DUMP" ] || bad "dump after stop" "no dump written by the clean stop"

"$BIN" start jc >/dev/null 2>&1
wait_up || bad "restart from dump" "cache never came back"
GOT=$(count_keys)
V=$(redis-cli -p "$PORT" GET jclean 2>/dev/null)
if [ "$GOT" = "$KEYS" ] && [ "$V" = "here" ]; then
    ok "after truncation the dump alone serves every key"
else
    bad "dump after truncation" "$GOT of $KEYS keys, GET jclean = $V"
fi

# ── 6. A stop after a crash absorbs the tail ────────────────────────────────
#
# The supervisor puts a killed worker back, which replays the journal and
# says Up in `ls`, so `stop` after a crash reaches that worker, and what must
# not happen there is the journal being cut without its records reaching the
# dump.
redis-cli -p "$PORT" SET jsplit written >/dev/null 2>&1
sleep 2                       # flushed, not snapshotted
kill_workers || bad "kill 3" "no worker pid to kill"

# The crash state, kept before the stop consumes it: a dump that does not know
# about jsplit and a journal that does.  Section 6b puts these two files back.
cp "$DUMP" "$WORK/crash.dump" 2>/dev/null
cp "$DUMP.journal" "$WORK/crash.journal" 2>/dev/null
CRASH_J=$(stat -c%s "$WORK/crash.journal" 2>/dev/null || echo 0)
if [ "$CRASH_J" -gt "$JOURNAL_HEAD" ]; then ok "the crash left records in the journal"; else
    bad "the crash left records in the journal" \
        "journal is $CRASH_J bytes, header is $JOURNAL_HEAD: nothing was captured"
fi

# Served again, because a stop that lands before the new worker's setup takes it
# down with nothing to dump, and leaves the journal whole for the next start.
for _ in $(seq 1 200); do [ "$(redis-cli -p "$PORT" GET jsplit 2>/dev/null)" = written ] && break; sleep 0.05; done

"$BIN" stop jc >/dev/null 2>&1
sleep 1
JSZ=$(stat -c%s "$DUMP.journal" 2>/dev/null || echo 0)
"$BIN" start jc >/dev/null 2>&1
wait_up || bad "restart after crash-stop" "cache never came back"
V=$(redis-cli -p "$PORT" GET jsplit 2>/dev/null)
if [ "$V" = "written" ] && [ "$JSZ" = "$JOURNAL_HEAD" ]; then
    ok "a stop after a crash moved the tail into the dump before cutting it"
else
    bad "a stop after a crash moved the tail into the dump before cutting it" \
        "journal cut to $JSZ (header $JOURNAL_HEAD), GET jsplit = '$V'"
fi

# ── 6b. A journal written under one split refuses another ───────────────────
#
# Reconstructed rather than reached: every honest route to a changed shard
# count goes through the stop above, and that stop absorbs the journal.  So
# the crash state kept before it is put back -- both files, so jsplit lives in
# the journal alone, exactly as after the kill -- and the split is changed
# underneath it.  The journal is the real one the running code wrote at one
# shard, not a fabrication.
"$BIN" stop jc >/dev/null 2>&1
sleep 0.5
if "$BIN" edit jc --shards 2 >/dev/null 2>&1; then ok "the shard count changed for the split case"; else
    bad "the shard count changed for the split case" \
        "edit --shards 2 was refused, so what follows would test a one-shard start"
fi
cp "$WORK/crash.dump" "$DUMP" 2>/dev/null
cp "$WORK/crash.journal" "$DUMP.journal" 2>/dev/null
split_refusals() { grep -c 'was not written by this shard split' "$SOCKETLEY_DLOG" 2>/dev/null || true; }
REFUSED0=$(split_refusals)
"$BIN" start jc >/dev/null 2>&1
for _ in $(seq 1 40); do [ "$(split_refusals)" -gt "$REFUSED0" ] && break; sleep 0.1; done
if redis-cli -p "$PORT" PING 2>/dev/null | grep -q PONG; then
    bad "changed split" "a 2-shard start served over a one-shard journal's records"
elif [ "$(split_refusals)" -le "$REFUSED0" ]; then
    bad "changed split" "the start did not come up, but the log never names the journal's split as the reason"
else
    ok "a journal with records refuses a start under a different shard count"
fi

# The recovery arm gets a runtime of its own rather than reusing the one that
# just refused to start.  A runtime whose sharded start failed does not come
# back on a stop/edit/start -- measured, with the journal deleted, so it is the
# lifecycle and not this feature -- and reusing it here would report that as a
# journal failure.
"$BIN" stop jc >/dev/null 2>&1
sleep 0.5
"$BIN" remove jc >/dev/null 2>&1
"$BIN" create cache jc -p "$PORT" --persistent "$DUMP" \
       --persistent-interval 1s -s >/dev/null 2>&1
"$BIN" stop jc >/dev/null 2>&1
sleep 0.5
cp "$WORK/crash.dump" "$DUMP" 2>/dev/null
cp "$WORK/crash.journal" "$DUMP.journal" 2>/dev/null
"$BIN" start jc >/dev/null 2>&1
if wait_up; then
    V=$(redis-cli -p "$PORT" GET jsplit 2>/dev/null)
    if [ "$V" = "written" ]; then
        ok "the split that wrote the journal absorbs it and nothing was lost"
    else
        bad "recovery under writer's split" "GET jsplit = '$V'"
    fi
else
    bad "recover under writer's split" "cache never came back"
fi

# ── 7. A write from another runtime is journaled too ────────────────────────
#
# `cache set` on a server is forwarded to the worker as a text command, which
# is a second way in and one no other case here uses: everything above arrives
# on the cache's own port.  Both must reach the same chokepoint.
#
# Not a control for the Lua write API, which this cannot reach: a cache takes
# no script, so cache.set() is reachable only from the daemon's CLI handler --
# and that one holds the placeholder, not the worker.  See the commit.
if command -v nc >/dev/null 2>&1; then
    "$BIN" create server jsrv -p $((PORT+1)) --cache jc -s >/dev/null 2>&1
    sleep 1.5
    BEFORE=$(stat -c%s "$DUMP.journal" 2>/dev/null || echo 0)
    printf 'cache set vialua lv\n' | timeout 5 nc -q1 127.0.0.1 $((PORT+1)) >/dev/null 2>&1
    sleep 2
    AFTER=$(stat -c%s "$DUMP.journal" 2>/dev/null || echo 0)
    V=$(redis-cli -p "$PORT" GET vialua 2>/dev/null)
    if [ "$V" = "lv" ] && [ "$AFTER" -gt "$BEFORE" ]; then
        ok "a write from another runtime reaches the journal ($BEFORE -> $AFTER bytes)"
    else
        bad "a write from another runtime reaches the journal" \
            "GET vialua = '$V', journal $BEFORE -> $AFTER bytes"
    fi
    "$BIN" stop jsrv >/dev/null 2>&1; "$BIN" remove jsrv >/dev/null 2>&1
else
    echo "  (nc absent - the cross-runtime arm did not run)"
fi

echo ""
echo "Results: $PASS/$TOTAL passed"
[ "$FAIL" = 0 ] || exit 1
exit 0
