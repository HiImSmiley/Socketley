#!/usr/bin/env bash
# Integration test: the storage runtime's worker is killed with SIGKILL in the
# middle of uploads, over and over, and what comes back is whole.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
# Each round starts twelve large uploads that trickle (overwrites of stored keys
# and new ones) beside three streams of small puts and deletes, kills the worker
# at a random moment, waits for the supervisor's replacement, and holds the
# runtime to what a crash may leave: an operation acknowledged before the kill is
# in effect, a key that was in flight is its old whole object, its new whole one
# or absent, every listed key reads back as listed, every object file is listed
# and no temporary file remains.  The store's own crash test does this to the
# code in one process; this does it to the daemon, the supervisor, the socket and
# the recovery that runs at the worker's start.
#
# SOCKETLEY_STORAGE_KILL_ROUNDS (default 8) and SOCKETLEY_STORAGE_KILL_SEED
# (default random, printed) set the rounds and the kill schedule.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
export BIN
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgkill

PORT=$((SL_PORT_BASE+1641))
DATA="$SOCKETLEY_TMPD/objects"
ROUNDS=${SOCKETLEY_STORAGE_KILL_ROUNDS:-8}

cleanup() {
    "$BIN" stop stgk >/dev/null 2>&1 || true
    sleep 0.3
    "$BIN" remove stgk >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a storage worker killed mid-upload ==="
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 is required"; exit 1; }

daemon_start "$BIN"
# shellcheck disable=SC2086
if ! "$BIN" create storage stgk -p "$PORT" --dir "$DATA" ${SOCKETLEY_STORAGE_TEST_FLAGS:---anonymous} -s >/dev/null 2>&1; then
    echo "  FAIL [create]: the runtime was not created"
    exit 1
fi
for _ in $(seq 1 100); do
    curl -s -o /dev/null "http://127.0.0.1:$PORT/" 2>/dev/null && break
    sleep 0.1
done

python3 "$HERE/lib_storage_killput.py" "$PORT" "$DATA" stgk "$ROUNDS"
rc=$?
if [ "$rc" -ne 0 ]; then
    echo "  FAILED"
    exit "$rc"
fi
echo "  PASSED"
exit 0
