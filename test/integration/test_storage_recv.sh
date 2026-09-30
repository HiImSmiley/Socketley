#!/usr/bin/env bash
# Integration test: how the storage runtime's connections receive.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
# A connection's bytes are read into a buffer the ring lends for the length of
# one completion, by a recv armed once that keeps delivering, and into the
# put's own staging buffer for a body large enough to be worth it.  What that
# has to keep is what the client is owed: a request sent ahead of the answer
# to the one before is answered, in order; a peer that half-closes after its
# request is answered whole; what piles up behind an answer that is not being
# read is bounded and taken up again afterwards; a body is stored byte for byte
# whether it arrives with its head, in pieces, in chunks or after 100-continue;
# and a ring that runs dry, or is absent, or a kernel without the multishot
# recv, changes where the bytes land and nothing else.
#
# The same requests are made against four daemons: the default, one with
# SOCKETLEY_RECV_MULTISHOT=0, one whose ring holds two buffers, and one with no
# ring.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
export BIN
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

PORT=$((SL_PORT_BASE+1791))
NAME=stgrecv
FAILED=0

cleanup() {
    "$BIN" stop "$NAME" >/dev/null 2>&1 || true
    sleep 0.3
    "$BIN" remove "$NAME" >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: how the storage runtime's connections receive ==="
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 is required"; exit 1; }

for mode in default single tiny none; do
    daemon_isolate stgrecv
    case $mode in
        default) envs=() ;;
        single)  envs=(SOCKETLEY_RECV_MULTISHOT=0) ;;
        tiny)    envs=(SOCKETLEY_STORAGE_RECV_BUFS=2) ;;
        none)    envs=(SOCKETLEY_STORAGE_RECV_BUFS=0) ;;
    esac
    for kv in "${envs[@]}"; do export "$kv"; done
    daemon_start "$BIN"
    for kv in "${envs[@]}"; do unset "${kv%%=*}"; done
    if ! "$BIN" create storage "$NAME" -p "$PORT" --dir "$SOCKETLEY_TMPD/objects" --anonymous -s >/dev/null 2>&1; then
        echo "  FAIL [create]: the runtime was not created ($mode)"
        exit 1
    fi
    for _ in $(seq 1 100); do
        curl -s -o /dev/null "http://127.0.0.1:$PORT/" 2>/dev/null && break
        sleep 0.1
    done
    python3 "$HERE/lib_storage_recv.py" "$PORT" "$BIN" "$NAME" "$mode"
    rc=$?
    [ "$rc" -ne 0 ] && FAILED=$((FAILED+rc))
    "$BIN" stop "$NAME" >/dev/null 2>&1 || true
    sleep 0.3
    "$BIN" remove "$NAME" >/dev/null 2>&1 || true
    daemon_stop
done

if [ "$FAILED" -ne 0 ]; then
    echo "  FAILED"
    exit 1
fi
echo "  PASSED"
exit 0
