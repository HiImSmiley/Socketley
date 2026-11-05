#!/usr/bin/env bash
# Integration test: --fsync always, interval and never
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# A put is answered once its body, its name and its directory are synced, which
# is most of what a small put costs.  --fsync interval answers without those
# syncs and syncs the filesystem every --fsync-interval instead; never leaves it
# to the kernel.  Either way a crash of the process loses nothing, because the
# page cache outlives the process, and a stop syncs everything before it says
# the stop was clean.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a mode or an interval that is no mode or interval taken at create
#   * --fsync and --fsync-interval missing from show, or changed by edit
#   * always skipping a sync, or interval and never still syncing every put
#     (fsyncs and fsyncs_skipped in stats)
#   * interval never syncing the filesystem (syncfs_rounds stays 0)
#   * an answered put lost to a SIGKILL of the worker under never
#   * a clean stop under never that did not sync, or left no clean marker (the
#     next start reads files)
# suite: isolated
set -uo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

echo "=== Integration: --fsync always, interval and never ==="
PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate stgfsync
trap 'daemon_stop' EXIT
daemon_start "$BIN"
P1=$((SL_PORT_BASE + 1871)); P2=$((SL_PORT_BASE + 1872)); P3=$((SL_PORT_BASE + 1873))

stat_now() { "$BIN" stats "$1" 2>/dev/null | awk -F: -v k="$2" '$1 == k { print $2; exit }'; }
# The worker's counters reach `stats` a moment late, so a reading waits for them to be there.
stat_of() { for _ in $(seq 1 50); do v=$(stat_now "$1" "$2"); [ -n "$v" ] && { echo "$v"; return; }; sleep 0.1; done; }
# And a count waits, up to five seconds, for the least it should be.
stat_atleast() { for _ in $(seq 1 50); do v=$(stat_now "$1" "$2"); [ "${v:-0}" -ge "$3" ] && { echo "$v"; return; }; sleep 0.1; done; echo "${v:-}"; }
up() { for _ in $(seq 1 100); do curl -s -o /dev/null "http://127.0.0.1:$1/" && return 0; sleep 0.1; done; return 1; }
puts() { # port bucket count
    curl -s -o /dev/null -X PUT "http://127.0.0.1:$1/$2"
    for i in $(seq 1 "$3"); do
        curl -s -o /dev/null -w '%{http_code}\n' -X PUT --data-binary "body-$i" "http://127.0.0.1:$1/$2/k$i"
    done | sort | uniq -c | awk '{ printf "%s:%s ", $2, $1 }'
}
reads() { # port bucket count: how many read back as written
    n=0
    for i in $(seq 1 "$3"); do
        [ "$(curl -s "http://127.0.0.1:$1/$2/k$i")" = "body-$i" ] && n=$((n+1))
    done
    echo "$n"
}

# ── what create takes ──
out=$("$BIN" create storage bad1 -p "$P1" --dir "$SOCKETLEY_TMPD/b1" --anonymous --fsync sometimes 2>&1); rc=$?
check "a mode that is none is refused" "$rc:$(echo "$out" | grep -c 'always, interval or never')" "1:1"
out=$("$BIN" create storage bad2 -p "$P1" --dir "$SOCKETLEY_TMPD/b2" --anonymous --fsync interval --fsync-interval 0 2>&1); rc=$?
check "an interval of nothing is refused" "$rc:$(echo "$out" | grep -c 'fsync-interval requires')" "1:1"

# ── always, the default ──
"$BIN" create storage fa -p "$P1" --dir "$SOCKETLEY_TMPD/fa" --anonymous -s >/dev/null 2>&1
up "$P1" || bad "the always runtime serves" "no answer on $P1"
check "always answers every put" "$(puts "$P1" alwaysb 20)" "200:20 "
sleep 1
check "and skips no sync" "$(stat_of fa fsyncs_skipped)" "0"
f=$(stat_atleast fa fsyncs 20)
[ "${f:-0}" -ge 20 ] && ok || bad "and syncs every put" "fsyncs $f for 20 puts"

# ── interval ──
"$BIN" create storage fi -p "$P2" --dir "$SOCKETLEY_TMPD/fi" --anonymous --fsync interval --fsync-interval 1s -s >/dev/null 2>&1
up "$P2" || bad "the interval runtime serves" "no answer on $P2"
show=$("$BIN" show fi 2>/dev/null)
check "show names the mode and its interval" "$(echo "$show" | grep -cE '"fsync": "interval"|"fsync_interval": 1\b')" "2"
check "interval answers every put" "$(puts "$P2" intervalb 20)" "200:20 "
s=$(stat_atleast fi fsyncs_skipped 20)
[ "${s:-0}" -ge 20 ] && ok || bad "and skips a put's syncs" "fsyncs_skipped $s for 20 puts"
sleep 2.5
r=$(stat_atleast fi syncfs_rounds 2)
[ "${r:-0}" -ge 2 ] && ok || bad "and syncs the filesystem every second" "syncfs_rounds $r after 2.5 s"
check "with none failing" "$(stat_of fi syncfs_failed)" "0"
check "and reads back what it answered" "$(reads "$P2" intervalb 20)" "20"
out=$("$BIN" edit fi --fsync always 2>&1)
check "edit does not change the mode" "$(echo "$out" | grep -c 'cannot be changed')" "1"

# ── never: a SIGKILL of the worker loses nothing ──
"$BIN" create storage fn -p "$P3" --dir "$SOCKETLEY_TMPD/fn" --anonymous --fsync never -s >/dev/null 2>&1
up "$P3" || bad "the never runtime serves" "no answer on $P3"
check "never answers every put" "$(puts "$P3" neverb 30)" "200:30 "
check "and runs no filesystem sync" "$(stat_of fn syncfs_rounds)" "0"
old=$(stat_of fn pid)
kill -9 "$old" 2>/dev/null
for _ in $(seq 1 100); do
    p=$(stat_of fn pid)
    [ -n "$p" ] && [ "$p" != "$old" ] && curl -s -o /dev/null "http://127.0.0.1:$P3/" && break
    sleep 0.1
done
check "a SIGKILL of the worker loses no answered put" "$(reads "$P3" neverb 30)" "30"

# ── never: a clean stop syncs and says so ──
"$BIN" stop fn >/dev/null 2>&1
for _ in $(seq 1 100); do [ -e "$SOCKETLEY_TMPD/fn/.clean.0" ] && break; sleep 0.1; done
[ -e "$SOCKETLEY_TMPD/fn/.clean.0" ] && ok || bad "a stop under never is clean" "no .clean.0 in $SOCKETLEY_TMPD/fn"
"$BIN" start fn >/dev/null 2>&1
up "$P3" || bad "the never runtime starts again" "no answer on $P3"
sleep 1
check "and the next start reads no file" "$(stat_of fn start_files_read)" "0"
check "and every put is there" "$(reads "$P3" neverb 30)" "30"

# ── interval under --shards: one round a second for the filesystem, not one a shard ──
P4=$((SL_PORT_BASE + 1874))
"$BIN" create storage fs4 -p "$P4" --dir "$SOCKETLEY_TMPD/fs4" --anonymous --fsync interval --fsync-interval 1s \
    --shards 4 -s >/dev/null 2>&1
up "$P4" || bad "the sharded interval runtime serves" "no answer on $P4"
sleep 3.5
# Every shard's rounds, read off its own [shard i] section.
rounds() { "$BIN" stats fs4 2>/dev/null | awk -F: '/^\[shard / { s = $0; gsub(/[^0-9]/, "", s) } $1 == "syncfs_rounds" { printf "s%s=%s ", s, $2 }'; }
for _ in $(seq 1 50); do r4=$(rounds); [[ "$r4" == *"s0="[2-9]* ]] && break; sleep 0.1; done
[[ "$r4" == *"s0="[2-9]* ]] && ok || bad "shard 0 syncs the filesystem every second" "$r4"
others=$(echo "$r4" | tr ' ' '\n' | grep -v '^s0=' | grep -c '=[1-9]')
check "and no other shard syncs it again ($r4)" "$others" "0"

for r in fa fi fn fs4; do "$BIN" stop "$r" >/dev/null 2>&1; done
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || { echo "  FAILED"; exit 1; }
