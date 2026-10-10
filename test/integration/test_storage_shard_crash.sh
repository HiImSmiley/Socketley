#!/usr/bin/env bash
# Integration test: a shard killed with SIGKILL leaves a storage runtime consistent.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   mid-commit   the owner of a key is killed between renaming the body into
#                place and appending its journal record (a test hook,
#                SOCKETLEY_STORAGE_KILL_AFTER_RENAME=<key prefix>, kills it at
#                exactly that step), while the put arrived through another
#                shard.  The client is told the put failed, the supervisor
#                restarts the shard, and afterwards every shard agrees about
#                the key: it is served whole or not at all, a listing through
#                any shard says the same as a GET, and tmp/ holds nothing
#   mid-upload   a shard is killed while an upload sits half received in a
#                tmp file of its own, while a sibling has an upload half
#                received too.  The restarted shard removes its own file and
#                only its own: the sibling's upload finishes and is served
#
# The first is what a journal that is the truth would get wrong (the object is
# in the directory and not in the index), and the second what a start that
# swept every tmp file would get wrong (the sibling's rename finds nothing).
set -uo pipefail

# Read by the workers the daemon starts, so it is set before the daemon is.
export SOCKETLEY_STORAGE_KILL_AFTER_RENAME="killme/"

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgshcrash

D="$SOCKETLEY_TMPD"
DATA="$D/objects"
SOCK="$D/stg.sock"
LIB="$HERE/lib_storage_shards.py"
SLOW_PIDS=""

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}
expect() {   # name got want
    if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi
}

cleanup() {
    local p
    for p in $SLOW_PIDS; do kill "$p" 2>/dev/null || true; done
    "$BIN" stop stg >/dev/null 2>&1 || true
    sleep 0.3
    "$BIN" remove stg >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

N=4
node() { echo "$D/stg#$1.sock"; }
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
# The process holding a shard's node, read from the socket table rather than a process list.
node_pid() { ss -lxpn 2>/dev/null | grep -F "$(node "$1") " | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | head -1; }
wait_node() {   # shard [pid it must not be]
    local t p
    for t in $(seq 1 150); do
        p=$(node_pid "$1")
        if [ -n "$p" ] && [ "$p" != "${2:-}" ] && [ "$(code --unix-socket "$(node "$1")" http://x/)" = 200 ]; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}
# An empty pid is no process identified, which is not a process that died.
dead() { [ -n "$1" ] || return 1; for _ in $(seq 1 100); do kill -0 "$1" 2>/dev/null || return 0; sleep 0.1; done; return 1; }
tmp_names() { ls "$DATA/$1/tmp" 2>/dev/null | tr '\n' ' '; }

echo "=== Integration: a killed shard leaves a consistent runtime ==="
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 is required"; exit 1; }
daemon_start "$BIN"
"$BIN" create storage stg --listen "unix:$SOCK" --dir "$DATA" --anonymous --shards $N -s >/dev/null 2>&1
expect "a sharded runtime is made" "$?" 0
for i in 0 1 2 3; do wait_node "$i" || bad "shard $i comes up" "no node"; done
expect "a bucket is made" "$(code --unix-socket "$(node 0)" -X PUT http://x/crash)" 200
for i in 0 1 2 3 4 5 6 7; do
    curl -s --unix-socket "$(node $((i % N)))" -X PUT --data-binary "before-$i" "http://x/crash/before$i" -o /dev/null
done

echo "== the owner is killed between the rename and the journal =="
key=""
for i in $(seq 1 50); do
    if [ "$(python3 "$LIB" owner crash "killme/k$i" $N)" = 2 ]; then key="killme/k$i"; break; fi
done
[ -n "$key" ] && ok "a key owned by shard 2: $key" || bad "no key" "owner"
OWNER_PID=$(node_pid 2)
[ -n "$OWNER_PID" ] && ok "shard 2 is process $OWNER_PID" || bad "shard 2 has no process" ""
head -c 300000 /dev/urandom > "$D/blob"
want=$(md5sum < "$D/blob" | cut -d' ' -f1)
# Through shard 3, which owns nothing of this key: it writes the body and asks shard 2 to commit.
got=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 --unix-socket "$(node 3)" -X PUT --data-binary @"$D/blob" "http://x/crash/$key")
[ "$got" != 200 ] && ok "the client is not told the put succeeded ($got)" || bad "the put was answered 200" "$got"
dead "$OWNER_PID" && ok "the owner died at the hook" || bad "the owner is still running" "$OWNER_PID"
wait_node 2 "$OWNER_PID" && ok "the supervisor restarted shard 2" || bad "shard 2 did not come back" ""
NEW_PID=$(node_pid 2)
[ -n "$NEW_PID" ] && [ "$NEW_PID" != "$OWNER_PID" ] && ok "as a new process" || bad "same process" "$NEW_PID"

# The rename happened, so the file is the object, and every shard must say so.
sts=""; sums=""; lists=""
for i in 0 1 2 3; do
    sts="$sts $(code --unix-socket "$(node $i)" "http://x/crash/$key")"
    sums="$sums $(curl -s --unix-socket "$(node $i)" "http://x/crash/$key" | md5sum | cut -d' ' -f1)"
    n=$(curl -s --unix-socket "$(node $i)" "http://x/crash?list-type=2&prefix=killme/" | grep -c "<Key>$key</Key>")
    lists="$lists $n"
done
expect "every shard gives the same answer for the key" "$(echo $sts | tr ' ' '\n' | sort -u | wc -l)" 1
expect "it is served" "$(echo $sts | cut -d' ' -f1)" 200
expect "whole, on every shard" "$(echo $sums | tr ' ' '\n' | sort -u | tr '\n' ' ')" "$want "
expect "and every shard lists it" "$(echo $lists | tr ' ' '\n' | sort -u | tr '\n' ' ')" "1 "
expect "tmp/ holds nothing" "$(tmp_names crash)" ""
for i in 0 1 2 3 4 5 6 7; do
    [ "$(curl -s --unix-socket "$(node $(((i + 1) % N)))" "http://x/crash/before$i")" = "before-$i" ] || bad "an earlier object survived" "before$i"
done
ok "the objects put before are all served"
total=$(curl -s --unix-socket "$(node 1)" "http://x/crash?list-type=2" | grep -o '<Key>' | wc -l)
expect "the listing has the earlier objects and the one" "$total" 9
sh=$("$BIN" stats stg 2>&1 | awk -F: '/^shard_peer_failures:/ {s+=$2} END {print s+0}')
[ "$sh" -ge 1 ] && ok "the shard that sent the commit counted the failure" || bad "no failure counted" "$sh"
expect "shard 2 takes a put through another shard again" \
    "$(code --unix-socket "$(node 0)" -X PUT --data-binary after "http://x/crash/after")" 200
expect "and serves it" "$(curl -s --unix-socket "$(node 2)" http://x/crash/after)" after

echo "== a shard is killed with an upload half received, and a sibling has one too =="
rm -f "$D/ready1" "$D/ready3" "$D/release"
python3 "$LIB" slow_put "$(node 1)" crash slow1 400000 "$D/ready1" "$D/release" > "$D/out1" 2>&1 &
SLOW_PIDS="$SLOW_PIDS $!"
python3 "$LIB" slow_put "$(node 3)" crash slow3 400000 "$D/ready3" "$D/release" > "$D/out3" 2>&1 &
SLOW_PIDS="$SLOW_PIDS $!"
for _ in $(seq 1 100); do [ -e "$D/ready1" ] && [ -e "$D/ready3" ] && break; sleep 0.1; done
sleep 0.5
ls "$DATA/crash/tmp" | grep -q '^1\.' && ok "shard 1 has a temporary file of an upload in flight" \
    || bad "no temporary file of shard 1" "$(tmp_names crash)"
ls "$DATA/crash/tmp" | grep -q '^3\.' && ok "and so has shard 3" || bad "no temporary file of shard 3" "$(tmp_names crash)"

P1=$(node_pid 1)
[ -n "$P1" ] && ok "shard 1 is process $P1" || bad "shard 1 has no process" ""
[ -n "$P1" ] && kill -9 "$P1"
dead "$P1" && ok "shard 1 is killed" || bad "shard 1 is alive" "$P1"
wait_node 1 "$P1" && ok "and restarted" || bad "shard 1 did not come back" ""
ls "$DATA/crash/tmp" | grep -q '^1\.' && bad "the restarted shard removes its own temporary file" "$(tmp_names crash)" \
    || ok "the restarted shard removed its own temporary file"
ls "$DATA/crash/tmp" | grep -q '^3\.' && ok "and left its sibling's alone" \
    || bad "the sibling's temporary file is gone" "$(tmp_names crash)"

touch "$D/release"
for _ in $(seq 1 100); do [ -s "$D/out3" ] && break; sleep 0.1; done
expect "the sibling's upload is answered 200" "$(head -1 "$D/out3" | cut -d' ' -f2)" 200
sum3=$(curl -s --unix-socket "$(node 0)" http://x/crash/slow3 | md5sum | cut -d' ' -f1)
want3=$(python3 -c "import sys; sys.stdout.write((b'slow-body-' * 40001)[:400000].decode())" | md5sum | cut -d' ' -f1)
expect "and read whole through another shard" "$sum3" "$want3"
expect "the killed shard's upload is not an object" "$(code --unix-socket "$(node 2)" http://x/crash/slow1)" 404
sleep 0.3
expect "tmp/ ends empty" "$(tmp_names crash)" ""

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
