#!/usr/bin/env bash
# suite: quiet -- the peak of a worker's resident set over a gigabyte transfer, which a loaded box distorts
# Integration test: a 1 GiB object goes in and out of the storage runtime with a
# bounded worker, and every byte of the download takes the zero-copy path.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
# The plan's acceptance for the data path: PUT streams from the socket to disk
# in bounded chunks, hashing as it goes, and GET is spliced file to pipe to
# socket, so neither ever holds an object.  The measure is the worker's own
# VmHWM -- a whole-object buffer would show as a gigabyte -- and the counter is
# `zero_copy_bytes`, which counts what left through splice.
#
# SOCKETLEY_STORAGE_LARGE_MIB changes the size (default 1024) and
# SOCKETLEY_STORAGE_LARGE_RSS_MIB the bound (default 40).
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
export BIN
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stglarge

PORT=$((SL_PORT_BASE+1526))
DATA="$SOCKETLEY_TMPD/objects"
SIZE_MIB=${SOCKETLEY_STORAGE_LARGE_MIB:-1024}
RSS_MIB=${SOCKETLEY_STORAGE_LARGE_RSS_MIB:-40}

cleanup() {
    "$BIN" stop stg >/dev/null 2>&1 || true
    sleep 0.3
    "$BIN" remove stg >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a large object with a bounded worker ==="

# The object, its copy and the page cache are all on this disk.
free_mib=$(df -Pm "$SOCKETLEY_TMPD" | awk 'NR==2 {print $4}')
need_mib=$((SIZE_MIB * 2))
if [ "${free_mib:-0}" -lt "$need_mib" ]; then
    echo "  SKIP: needs $need_mib MiB free under $SOCKETLEY_TMPD and has ${free_mib:-0}"
    exit 0
fi

daemon_start "$BIN"
if ! "$BIN" create storage stg -p "$PORT" --dir "$DATA" --anonymous -s >/dev/null 2>&1; then
    echo "  FAIL [create]: the runtime was not created"
    exit 1
fi
for _ in $(seq 1 100); do
    curl -s -o /dev/null "http://127.0.0.1:$PORT/" 2>/dev/null && break
    sleep 0.1
done

WPID=""
for _ in $(seq 1 30); do
    WPID=$("$BIN" stats stg 2>/dev/null | sed -n 's/^pid://p')
    [ -n "$WPID" ] && [ -d "/proc/$WPID" ] && break
    sleep 0.2
done
if [ -z "$WPID" ]; then
    echo "  FAIL [pid]: stats does not name the worker"
    exit 1
fi

python3 "$HERE/lib_storage_large.py" "$PORT" "$WPID" "$SIZE_MIB" "$RSS_MIB"
rc=$?
if [ "$rc" -ne 0 ]; then
    echo "  FAILED"
    exit "$rc"
fi
echo "  PASSED"
exit 0
