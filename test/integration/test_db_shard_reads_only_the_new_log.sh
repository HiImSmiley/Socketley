#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: a shard reading shard 0's log reads the records that came since it last looked, not a window of
# the zeroed room shard 0 keeps ahead of its records.
#
# What it would catch:
#   * a catch-up that reads a fixed window past the records: the active segment's size counts the room zeroed ahead of
#     the writes, so every request and every answer on a reading shard read a mebibyte of zeros, and a sharded
#     database's writes cost several times the CPU of one shard's; counted as the bytes the workers read per write,
#     which a busy box cannot blur
#
# The writes are a number, 1500, not what three seconds hold: at load 20-30 three seconds held 444 to 784 of them, and
# a check that more than a thousand came measured the box.  What is held is per write, so it needs enough of them to
# make the reads between writes small, not that they came fast.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a reading shard reads only the new part of shard 0's log ==="
command -v gcc >/dev/null 2>&1 || { echo "  SKIP: gcc is required"; exit 0; }
daemon_isolate dbshardread
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1945))
trap '"$BIN" stop data >/dev/null 2>&1; daemon_stop' EXIT
daemon_start "$BIN"

printf 'items private level\n' > "$T/schema"
printf 'backend readsecret0123456789\n' > "$T/keys"
chmod 600 "$T/keys"
"$BIN" create db data -p "$P" --bind 127.0.0.1 --schema "$T/schema" --keys "$T/keys" --shards 4 -s >/dev/null 2>&1 \
    || { echo "  FAIL [create]: a db runtime of four shards was not made: $(tail -3 "$SOCKETLEY_DLOG")"; exit 1; }
for _ in $(seq 1 100); do [ "$(ss -ltnH "sport = :$P" | wc -l)" -ge 4 ] && break; sleep 0.1; done
[ "$(ss -ltnH "sport = :$P" | wc -l)" -ge 4 ] || { echo "  FAIL [listeners]: $(ss -ltnH "sport = :$P" | wc -l) of 4 shards listen"; exit 1; }
sleep 1

if ! gcc -O2 -o "$T/load" "$(dirname "$0")/lib_db_put_load.c" 2>"$T/cc.log"; then
    echo "  FAIL [the load client builds]: $(head -3 "$T/cc.log")"; exit 1
fi
workers=$(pgrep -P "$SOCKETLEY_DPID" | tr '\n' ' ')
rchar() { for p in $workers; do awk '/^rchar:/ {print $2}' "/proc/$p/io" 2>/dev/null; done | awk '{s += $1} END {print s + 0}'; }

r0=$(rchar)
out=$("$T/load" "$P" 16 120 readsecret0123456789 1500)
r1=$(rchar)
written=$(echo "$out" | tr ' ' '\n' | awk -F: '$1 ~ /^2/ {s += $2} END {print s + 0}')
refused=$(echo "$out" | tr ' ' '\n' | awk -F: '$1 !~ /^2/ {s += $2} END {print s + 0}')
per=$(( written > 0 ? (r1 - r0) / written : 0 ))
echo "  $written writes answered ($out), the workers read $(( (r1 - r0) >> 10 )) KiB: $per bytes a write"
[ "$written" -ge 1500 ] && [ "$refused" -eq 0 ] && ok \
    || bad "1500 writes reach the database within two minutes" "$written answered, $refused otherwise: $out"
# A write is a few hundred bytes on the wire and in the log, read by three reading shards; a window of the room is a
# mebibyte a look.
[ "$per" -gt 0 ] && [ "$per" -lt 32768 ] && ok \
    || bad "a reading shard reads the new records, not the room past them" "$per bytes read a write"

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
