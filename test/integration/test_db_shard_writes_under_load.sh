#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# A db runtime of several shards answers every write under a steady load of them.
#
# Shard 0 used to send each reading shard a nudge after every sync, and each nudge held a ticket in the same table of
# 4096 the reading shards' writes wait in on shard 0, so tens of thousands of writes a second filled it with nudges and
# a write was answered 503 "shard 0, which writes, did not answer" -- what this test counts. Sixty-four writers,
# because more of them make each sync take more and the syncs, and the nudges with them, fewer.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
. "$(dirname "$0")/lib_verdicts.sh"

echo "=== Integration: a sharded db answers every write under load ==="
daemon_isolate dbshardload
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1990))
# The state on tmpfs, where a sync is as quick as a fast disk's: on a slow one each sync takes so many writes that the
# syncs, and the nudges, are too few to fill anything.
SHM=$(mktemp -d /dev/shm/socketley-dbshardload-XXXXXX)
export HOME="$SHM/home"
mkdir -p "$HOME"
trap 'daemon_stop; rm -rf "$SHM"' EXIT
daemon_start "$BIN"

printf 'items private level\n' > "$T/schema"
printf 'backend loadsecret0123456789\n' > "$T/keys"
chmod 600 "$T/keys"
"$BIN" create db data -p "$P" --bind 127.0.0.1 --schema "$T/schema" --keys "$T/keys" --shards 4 -s >/dev/null 2>&1 \
    && ok || bad "a db runtime of four shards is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$P/")" != 000 ] && break; sleep 0.1; done
sleep 1

# Sixty-four connections, each with one write outstanding and the next sent as its answer arrives: a client that
# keeps up, since the defect needs tens of thousands of syncs a second.
WORK=$T/load
mkdir -p "$WORK"
if ! gcc -O2 -o "$WORK/load" "$(dirname "$0")/lib_db_put_load.c" 2>"$WORK/cc.log"; then
    bad "the load client builds" "$(head -3 "$WORK/cc.log")"
    echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"; echo "  FAILED"; exit 1
fi
out=$("$WORK/load" "$P" 64 6 loadsecret0123456789)
echo "  answers: $out"
written=$(echo "$out" | tr ' ' '\n' | awk -F: '$1 ~ /^2/ {s += $2} END {print s + 0}')
refused=$(echo "$out" | tr ' ' '\n' | awk -F: '$1 !~ /^2/ {s += $2} END {print s + 0}')
# The sanitizer's build answers a tenth to a fifth as many, too few to fill anything: there the answers are checked, and
# the load that makes the check mean something is Release's.  Told by the binary, so BIN= alone picks the bound too.
MIN=100000; grep -q -m1 -a __asan_init "$BIN" && MIN=5000
[ "$written" -gt "$MIN" ] && ok || bad "the load reached the database" "only $written writes answered (want > $MIN)"
[ "$refused" -eq 0 ] && ok || bad "every write under load is taken" "$refused of $((written + refused)) answered otherwise: $out"

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
[ "$FAIL" -eq 0 ]
