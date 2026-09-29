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

# A put refused on its headers -- here a create-only put over a key that is
# there -- is answered before its body is read, and the body is read off after:
# a client that sends the body once it has the headers out must hear 412 and
# keep its connection, not meet a reset (seen in the full suite through a shard).
refusal=$(python3 - "$PORT" <<'PY'
import socket, sys
port = int(sys.argv[1])
def one(req):
    s = socket.create_connection(("127.0.0.1", port), timeout=5); s.sendall(req); s.recv(65536); s.close()
one(b"PUT /refusal HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
one(b"PUT /refusal/k HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi")
s = socket.create_connection(("127.0.0.1", port), timeout=5)
import time
s.sendall(b"PUT /refusal/k HTTP/1.1\r\nHost: x\r\nIf-None-Match: *\r\nContent-Length: 65536\r\n\r\n")
time.sleep(0.3)   # long enough for a runtime that answers at the headers to have closed
try:
    s.sendall(b"z" * 65536)
    s.sendall(b"GET /refusal/k HTTP/1.1\r\nHost: x\r\n\r\n")
    got = b""
    while b"\r\n\r\nhi" not in got:
        d = s.recv(65536)
        if not d: break
        got += d
    first = got.split(b"\r\n", 1)[0].decode()
    print(first, "| then:", "200 on the same connection" if b"HTTP/1.1 200" in got else "no answer")
except OSError as e:
    print("sending the body:", type(e).__name__)
PY
)
case "$refusal" in
    *"412"*"200 on the same connection"*) echo "  PASS: a put refused on its headers hears 412 and keeps its connection" ;;
    *) echo "  FAIL [refusal before the body]: $refusal"; echo "  FAILED"; exit 1 ;;
esac
echo "  PASSED"
exit 0
