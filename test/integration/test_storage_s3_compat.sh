#!/usr/bin/env bash
# Integration test: the storage runtime against what S3 client libraries expect
# of a whole service, driven through boto3.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
# test_storage_s3 asks what each operation answers; this asks what a client
# library asks of the service as a whole, in lib_storage_compat.py:
#
#   errors      every error code the runtime has, with the status, the document
#               and the request id a client parses
#   ranges      every shape of Range against objects on both sides of the
#               splice threshold, GET and HEAD, against RFC 7233 as S3 applies it
#   keys        unicode, spaces, +, %, //, control characters, 1024 bytes, and
#               how they list, roll up and delete
#   listing     ten thousand keys paged by 1, 7, 137, 999 and 1000 with prefixes
#               and delimiters, compared with a model of S3's ordering, and
#               listed again while keys are put and deleted under it
#   headers     the round trip of every stored header and user metadata
#   copy        the COPY and REPLACE directives and the copy conditions, and a
#               copy onto itself that names a checksum algorithm
#   delete      DeleteObjects that half fails
#   races       twelve writers of one key against readers that must never see a
#               torn body, and acknowledged order that must be commit order
#
# S3_TEST_ACCESS_KEY and S3_TEST_SECRET_KEY, when set, are used to sign, and
# SOCKETLEY_STORAGE_TEST_FLAGS replaces `--anonymous` on the create.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgcompat

PORT=$((SL_PORT_BASE+1611))
DATA="$SOCKETLEY_TMPD/objects"

cleanup() {
    "$BIN" stop stgc >/dev/null 2>&1 || true
    sleep 0.3
    "$BIN" remove stgc >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: S3 compatibility through boto3 ==="
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 is required"; exit 1; }
python3 -c 'import boto3' 2>/dev/null || { echo "  SKIP: boto3 is not installed"; exit 0; }

daemon_start "$BIN"
# shellcheck disable=SC2086
if ! "$BIN" create storage stgc -p "$PORT" --dir "$DATA" ${SOCKETLEY_STORAGE_TEST_FLAGS:---anonymous} -s >/dev/null 2>&1; then
    echo "  FAIL [create]: the runtime was not created"
    exit 1
fi
for _ in $(seq 1 100); do
    curl -s -o /dev/null "http://127.0.0.1:$PORT/" 2>/dev/null && break
    sleep 0.1
done

python3 "$HERE/lib_storage_compat.py" "$PORT" "$DATA"
rc=$?
if [ "$rc" -ne 0 ]; then
    echo "  FAILED"
    exit "$rc"
fi
echo "  PASSED"
exit 0
