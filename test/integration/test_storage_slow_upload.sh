#!/usr/bin/env bash
# Integration test: an upload that trickles in one TCP segment at a time.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
# A body sent over a slow uplink reaches the server a segment at a time, and the
# runtime used to pay a receive, a wakeup and a hop to a hashing thread for every
# one of them: about ten times the CPU per byte of the same body sent fast.  It
# now leaves a body that arrives slower than 4 MB/s to gather in the socket until
# a 10 ms pace tick, and hands the digests over 64 KiB at a time, so such a body
# is taken in a fraction of the receives and handoffs.  What that must not
# change is what the client is owed:
# every byte stored, the ETag, Content-MD5, x-amz-checksum and the signed payload
# hash checked as before, an answer the moment the last byte is in, and the next
# request on the connection read at once.  The counts are `stats` body_recvs and
# hash_handoffs; the requests are signed, with a hex payload hash, with
# UNSIGNED-PAYLOAD and as aws-chunked with a trailer, and a multipart part.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
export BIN
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

PORT=$((SL_PORT_BASE+1792))
NAME=stgslow
AK=AKSLOWUPLOAD
SK=slow-upload-secret

cleanup() {
    "$BIN" stop "$NAME" >/dev/null 2>&1 || true
    sleep 0.3
    "$BIN" remove "$NAME" >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: uploads that trickle in ==="
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 is required"; exit 1; }

daemon_isolate stgslow
daemon_start "$BIN"
if ! "$BIN" create storage "$NAME" -p "$PORT" --dir "$SOCKETLEY_TMPD/objects" \
        --access-key "$AK" --secret-key "$SK" -s >/dev/null 2>&1; then
    echo "  FAIL [create]: the runtime was not created"
    exit 1
fi
for _ in $(seq 1 100); do
    curl -s -o /dev/null "http://127.0.0.1:$PORT/" 2>/dev/null && break
    sleep 0.1
done

python3 "$HERE/lib_storage_slow_upload.py" "$PORT" "$BIN" "$NAME" "$AK" "$SK"
rc=$?
if [ "$rc" -ne 0 ]; then
    echo "  FAILED"
    exit 1
fi
echo "  PASSED"
exit 0
