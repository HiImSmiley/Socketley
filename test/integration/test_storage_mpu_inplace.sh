#!/usr/bin/env bash
# Integration test: multipart parts are written where the object needs them.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
# A part whose place in the object is known when it starts is written into the
# upload's data file at that place, and a completion whose parts all sit there
# commits that file as the object, so the worker writes an upload of equal parts
# once and not twice -- read from /proc/<pid>/io, on one shard and on four.
# Every other way of sending parts still makes the same object: out of order,
# the last first, unequal sizes, gaps, a part sent again at the same and at
# another size, two sends of one number at once, an abort, a restart between the
# parts and the completion, and every step through another shard's node.  Each
# object is read back whole, by range and by ETag.
#
# The assertions live in lib_storage_mpu_inplace.py, which prints one line each.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
export BIN
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgmpi

D="$SOCKETLEY_TMPD"
. "$HERE/lib_disk.sh"
# The objects where writes are counted, so the written-once checks run on a machine whose /tmp is tmpfs too.
DISK=$(disk_dir "$D")
SOCK1="$D/one.sock"
SOCK4="$D/four.sock"
export MPU_STATE="$D/state.json"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

cleanup() {
    for r in mpi mpi4; do "$BIN" stop "$r" >/dev/null 2>&1 || true; done
    sleep 0.3
    for r in mpi mpi4; do "$BIN" remove "$r" >/dev/null 2>&1 || true; done
    daemon_stop
    disk_dir_done "$DISK"
}
trap cleanup EXIT

code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
wait_node() {   # node
    for _ in $(seq 1 150); do
        [ "$(code --unix-socket "$1" http://x/)" = 200 ] && return 0
        sleep 0.1
    done
    return 1
}
node_pid() { ss -lxpn 2>/dev/null | grep -F "$1 " | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | head -1; }
run_lib() {   # label mode data nodes... [-- pids...]
    local label=$1; shift
    python3 "$HERE/lib_storage_mpu_inplace.py" "$@"
    local rc=$?
    if [ "$rc" -ne 0 ]; then bad "$label" "$rc assertions failed"; else ok "$label"; fi
}

echo "=== Integration: multipart parts written in place ==="
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 is required"; exit 1; }
daemon_start "$BIN"

# ── one shard ───────────────────────────────────────────────────────────────
DATA1="$DISK/objects-one"
"$BIN" create storage mpi --listen "unix:$SOCK1" --dir "$DATA1" --anonymous -s >/dev/null 2>&1 ||
    { echo "  FAIL [create]: the runtime was not created"; exit 1; }
wait_node "$SOCK1" || bad "the runtime comes up" "no answer on $SOCK1"
PID1=$(node_pid "$SOCK1")
[ -n "$PID1" ] || bad "the worker is found" "no pid listens on $SOCK1"

run_lib "an upload of equal parts is written once" bytes "$DATA1" "$SOCK1" -- "$PID1"
run_lib "every shape of upload makes the same object" shapes "$DATA1" "$SOCK1"
run_lib "parts are sent before a restart" before "$DATA1" "$SOCK1"
"$BIN" stop mpi >/dev/null 2>&1
sleep 0.5
"$BIN" start mpi >/dev/null 2>&1
wait_node "$SOCK1" || bad "the runtime comes back" "no answer on $SOCK1"
run_lib "and the upload completes after it" after "$DATA1" "$SOCK1"

# ── four shards ─────────────────────────────────────────────────────────────
DATA4="$DISK/objects-four"
"$BIN" create storage mpi4 --listen "unix:$SOCK4" --dir "$DATA4" --anonymous --shards 4 -s >/dev/null 2>&1 ||
    { bad "create with --shards 4" "the runtime was not created"; }
N4=()
P4=()
for i in 0 1 2 3; do
    N4+=("$D/four#$i.sock")
    wait_node "$D/four#$i.sock" || bad "shard $i comes up" "no answer on $D/four#$i.sock"
    P4+=("$(node_pid "$D/four#$i.sock")")
done
run_lib "every step through another shard makes the same object, written once" shards "$DATA4" "${N4[@]}" -- "${P4[@]}"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
