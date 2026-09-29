#!/usr/bin/env bash
# suite: quiet -- the worker's resident set and descriptor counts are read against fixed bounds, and a gigabyte moves
# Integration test: the storage runtime under clients that stall, leave and crowd.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   stalled    an upload that stops sending does not stop the runtime serving
#              others, and is let go after the body deadline with its temporary
#              file
#   cut off    uploads cut by FIN or RST in the head, after 100-continue, in a
#              body or in a chunk leave no key, no index entry and no temporary
#              file, and do not touch the object they were to replace
#   crowded    two hundred uploads at once, then 560 against the
#              runtime's bound of concurrent ones, then a thousand idle
#              connections three times over: descriptors and memory bounded and
#              given back
#   large      a gigabyte through boto3 with the worker's resident set sampled
#
# The assertions live in lib_storage_robust.py.  Takes about two minutes, most of
# it the body deadline.  SOCKETLEY_STORAGE_ROBUST_MIB and _RSS_MIB change the
# size (default 1024) and the growth bound (default 30).
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
export BIN
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgrobust

PORT=$((SL_PORT_BASE+1621))
DATA="$SOCKETLEY_TMPD/objects"
export SOCKETLEY_STORAGE_NAME=stgr

cleanup() {
    "$BIN" stop stgr >/dev/null 2>&1 || true
    sleep 0.3
    "$BIN" remove stgr >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: the storage runtime under stalled, cut off and crowded clients ==="
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 is required"; exit 1; }

daemon_start "$BIN"
# shellcheck disable=SC2086
if ! "$BIN" create storage stgr -p "$PORT" --dir "$DATA" ${SOCKETLEY_STORAGE_TEST_FLAGS:---anonymous} -s >/dev/null 2>&1; then
    echo "  FAIL [create]: the runtime was not created"
    exit 1
fi
for _ in $(seq 1 100); do
    curl -s -o /dev/null "http://127.0.0.1:$PORT/" 2>/dev/null && break
    sleep 0.1
done

WPID=""
for _ in $(seq 1 30); do
    WPID=$("$BIN" stats stgr 2>/dev/null | sed -n 's/^pid://p')
    [ -n "$WPID" ] && [ -d "/proc/$WPID" ] && break
    sleep 0.2
done
if [ -z "$WPID" ]; then
    echo "  FAIL [pid]: stats does not name the worker"
    exit 1
fi

python3 "$HERE/lib_storage_robust.py" "$PORT" "$DATA" "$WPID"
rc=$?
if [ "$rc" -ne 0 ]; then
    echo "  FAILED"
    exit "$rc"
fi
echo "  PASSED"
exit 0
