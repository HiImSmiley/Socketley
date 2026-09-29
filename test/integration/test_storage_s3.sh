#!/usr/bin/env bash
# Integration test: the storage runtime answers the S3 API, raw and through boto3.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
# Every operation the runtime claims -- ListBuckets, CreateBucket, DeleteBucket,
# HeadBucket, PutObject, GetObject with Range and conditionals, HeadObject,
# DeleteObject, DeleteObjects, CopyObject, ListObjectsV2 and V1 -- against the
# bytes S3 clients read: status codes, XML element names and namespace, error
# codes, x-amz-request-id, ETags, stored headers and user metadata.  Raw HTTP
# because a client library hides the framing, and boto3 with botocore.UNSIGNED
# because a library is what people run.
#
# The assertions live in lib_storage_s3.py, which prints one line each; this
# file starts a daemon of its own, makes the runtime and reports.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgs3

PORT=$((SL_PORT_BASE+1511))
DATA="$SOCKETLEY_TMPD/objects"

cleanup() {
    "$BIN" stop stg >/dev/null 2>&1 || true
    sleep 0.3
    "$BIN" remove stg >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: the storage runtime speaks S3 ==="
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 is required"; exit 1; }

daemon_start "$BIN"
if ! "$BIN" create storage stg -p "$PORT" --dir "$DATA" --anonymous -s >/dev/null 2>&1; then
    echo "  FAIL [create]: the runtime was not created"
    exit 1
fi
for _ in $(seq 1 100); do
    curl -s -o /dev/null "http://127.0.0.1:$PORT/" 2>/dev/null && break
    sleep 0.1
done

python3 "$HERE/lib_storage_s3.py" "$PORT" "$DATA"
rc=$?
if [ "$rc" -ne 0 ]; then
    echo "  FAILED"
    exit "$rc"
fi

# The runtime is what answered, and the counters it keeps say so.
stats=$("$BIN" stats stg 2>&1)
for _ in $(seq 1 30); do
    case "$stats" in *"puts:0"*) sleep 0.2; stats=$("$BIN" stats stg 2>&1) ;; *) break ;; esac
done
case "$stats" in
    *"type:storage"*"puts:"*) echo "  PASS: stats reports the storage counters" ;;
    *) echo "  FAIL [stats]: $stats"; echo "  FAILED"; exit 1 ;;
esac
echo "  PASSED"
exit 0
