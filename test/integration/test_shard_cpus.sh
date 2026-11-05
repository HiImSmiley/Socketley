#!/usr/bin/env bash
# Integration test: a shard set inside the daemon's CPU set gives each shard's
# loop a CPU of its own, and leaves the helper threads the whole set.
#
# Four shards floating over four CPUs made 0.89x the round trips of four pinned
# one to a CPU (six interleaved passes, five of them the same way), because the
# scheduler stacks two loops on a core while another idles.  A loop pinned
# alone must not take its helpers with it: threads inherit the creating thread's
# mask, and a scrypt or a gzip thread on the loop's own core is the loop's time.
#
#   distinct CPUs   a server and an idp of two shards each land on four CPUs, not on
#                   the first two twice -- the second set starts after the first
#   stats           `stats` says the CPU each shard runs on, not the set
#   helpers         a worker's other threads keep the daemon's whole set, and the
#                   idp counts them for the CPUs it has and not for its loop's one
#   one shard       a runtime of one shard keeps the set as before
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

PASS=0; FAIL=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
check(){ [[ "$2" == "$3" ]] && ok "$1 ($2)" || bad "$1: expected '$3', got '$2'"; }

if [ "$(nproc)" -lt 4 ]; then
    echo "  SKIP: four CPUs needed"
    exit 0
fi

daemon_isolate shardcpus
export SOCKETLEY_CPUS=0-3
daemon_start "$BIN"
unset SOCKETLEY_CPUS

cleanup() {
    for n in pa pb pc; do "$BIN" stop $n >/dev/null 2>&1 || true; done
    sleep 0.2
    for n in pa pb pc; do "$BIN" remove $n >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

# The CPUs a thread may run on, as the kernel says.
allowed() { awk '/^Cpus_allowed_list:/ {print $2}' "/proc/$1/task/$2/status" 2>/dev/null; }

"$BIN" create server pa -p $((SL_PORT_BASE+1410)) --shards 2 -s >/dev/null 2>&1
# An idp, because its password hashing is a pool of threads a shard starts at
# its first sign-in, two a shard here: four for four CPUs, shared out.
PB=$((SL_PORT_BASE+1411))
"$BIN" create idp pb -p $PB --issuer "http://127.0.0.1:$PB" --shards 2 -s >/dev/null 2>&1
"$BIN" create server pc -p $((SL_PORT_BASE+1412)) -s >/dev/null 2>&1
sleep 1.5
for _ in 1 2 3 4 5 6 7 8; do
    curl -s -o /dev/null -d 'username=nobody&password=not-the-password&rd=/' "http://127.0.0.1:$PB/login"
done
sleep 0.5

LOOPS=()
HELPERS_WIDE=0; HELPERS=0; SINGLE=""
for w in $(pgrep -P "$SOCKETLEY_DPID" -x socketley); do
    loop=$(allowed "$w" "$w")
    for t in /proc/$w/task/*; do
        t=${t##*/}
        [ "$t" = "$w" ] && continue
        HELPERS=$((HELPERS+1))
        [ "$(allowed "$w" "$t")" = "0-3" ] && HELPERS_WIDE=$((HELPERS_WIDE+1))
    done
    case "$loop" in
        *-*|*,*) SINGLE="$SINGLE $loop" ;;
        *)       LOOPS+=("$loop") ;;
    esac
done

check "four shard loops are each on one CPU" "${#LOOPS[@]}" "4"
check "and on four different ones" "$(printf '%s\n' "${LOOPS[@]}" | sort -u | tr '\n' ' ')" "0 1 2 3 "
check "the one-shard runtime keeps the whole set" "${SINGLE# }" "0-3"
[ "$HELPERS" -gt 0 ] || bad "a worker has helper threads to look at"
check "every helper thread of a worker keeps the whole set" "$HELPERS_WIDE of $HELPERS" "$HELPERS of $HELPERS"
check "and the idp's two shards start four hashing threads between them" "$HELPERS" "4"
check "stats names each shard's CPU" "$("$BIN" stats pa 2>&1 | awk -F: '/^cpus:/ {print $2}' | sort | tr '\n' ' ')" \
      "$(printf '%s\n' "${LOOPS[@]}" | sort | head -2 | tr '\n' ' ')"

echo
echo "shard cpus: PASS=$PASS FAIL=$FAIL"
[[ $FAIL -eq 0 ]]
