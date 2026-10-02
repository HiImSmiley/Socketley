#!/usr/bin/env bash
# Integration test: GetObject and HeadObject by partNumber on the storage runtime.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   parts       each part of a multipart object is a 206 of its bytes with
#               Content-Range, Content-Length, the whole object's ETag and
#               x-amz-mp-parts-count, for parts of one size (the in-place
#               layout) and of unequal sizes (assembled by copying), by GET,
#               HEAD and boto3
#   single      partNumber=1 of a single-part object is all of it, as a 206;
#               an empty object is a 200 of nothing
#   refusals    a part past the count is 416 InvalidPartNumber, a bad number
#               400 InvalidArgument, a Range beside it 400 InvalidRequest
#   conditions  If-Match, If-None-Match and If-Modified-Since still apply
#   copy        CopyObject of a multipart object is one part with the MD5 of
#               its bytes as ETag, under either metadata directive
#   legacy      an object whose header records no part sizes, as one completed
#               before they were, answers partNumber with 501 and is whole
#   long list   parts of nine sizes, whose list does not fit the header (made
#               small here by SOCKETLEY_STORAGE_PART_LIST_MAX), keep it after the
#               body and are answered from it, after restarts and on two shards
#   restart     the boundaries survive a restart, and a start with every journal
#               removed reads them from the object headers
#   shards      with --shards 2 every part is answered alike by the shard that
#               owns the key and the one that does not
#   checksums   an upload with a checksum algorithm keeps each part's own
#               checksum: GET and HEAD by partNumber with x-amz-checksum-mode
#               give it with the object's checksum type, GetObjectAttributes
#               lists it per part, paged too; kept in the header (CRC32) or after
#               the body (SHA-256 in place, SHA-1 copied), through restarts, on two
#               shards; a copy keeps none, a single-part object answers with its
#               own, and an object completed before they were kept with none
#   copy sums   a CopyObject's checksum is FULL_OBJECT of its own bytes, in the
#               algorithm x-amz-checksum-algorithm names or its source's: taken
#               again of a COMPOSITE source, kept from a whole one, under COPY and
#               REPLACE, in the CopyObjectResult, GET, HEAD and GetObjectAttributes,
#               none for a source with none, an unknown algorithm refused; through
#               restarts and through either of two shards; UploadPartCopy answers
#               the upload's algorithm of the bytes it copied
#
# The assertions live in lib_storage_part_number.py, which prints one line each.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
export BIN
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgpn

P1=$((SL_PORT_BASE+1595))

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

cleanup() {
    for r in pn pns; do "$BIN" stop "$r" >/dev/null 2>&1 || true; done
    sleep 0.3
    for r in pn pns; do "$BIN" remove "$r" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
wait_up() {   # port
    for _ in $(seq 1 100); do
        [ "$(code "http://127.0.0.1:$1/")" != 000 ] && return 0
        sleep 0.1
    done
    return 1
}
wait_nodes() {   # node...
    local node t
    for node in "$@"; do
        for t in $(seq 1 150); do
            [ "$(code --unix-socket "$node" http://x/)" = 200 ] && continue 2
            sleep 0.1
        done
        return 1
    done
}
run_lib() {   # label runtime mode args...
    local label=$1 rt=$2; shift 2
    local out rc p f
    out=$(RUNTIME=$rt python3 "$HERE/lib_storage_part_number.py" "$@" 2>&1); rc=$?
    echo "$out" | grep -E '^  (PASS|FAIL|SKIP)'
    p=$(echo "$out" | grep -c '^  PASS')
    f=$(echo "$out" | grep -c '^  FAIL')
    PASS=$((PASS+p)); FAIL=$((FAIL+f)); TOTAL=$((TOTAL+p+f))
    if [ "$rc" -ne 0 ] && [ "$f" -eq 0 ]; then bad "$label" "exit $rc: $out"; fi
}

echo "=== Integration: GetObject and HeadObject by partNumber ==="
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 is required"; exit 1; }
# Read by the workers the daemon starts: a part list over 48 bytes goes after the body.
export SOCKETLEY_STORAGE_PART_LIST_MAX=48
daemon_start "$BIN"

DATA="$SOCKETLEY_TMPD/objects"
if ! "$BIN" create storage pn -p "$P1" --dir "$DATA" --anonymous -s >/dev/null 2>&1; then
    echo "  FAIL [create]: the runtime was not created"
    exit 1
fi
wait_up "$P1" || bad "the runtime comes up" "no answer on $P1"
run_lib "the main half ran" pn main "$P1" "$DATA"
run_lib "the restart half ran" pn restart "$P1" "$DATA"
"$BIN" stop pn >/dev/null 2>&1

# ── two shards ──────────────────────────────────────────────────────────────
SDATA="$SOCKETLEY_TMPD/shardobjects"
SOCK="$SOCKETLEY_TMPD/pns.sock"
NODES=("$SOCKETLEY_TMPD/pns#0.sock" "$SOCKETLEY_TMPD/pns#1.sock")
if ! "$BIN" create storage pns --listen "unix:$SOCK" --dir "$SDATA" --anonymous --shards 2 -s >/dev/null 2>&1; then
    bad "create with --shards 2" "the runtime was not created"
else
    wait_nodes "${NODES[@]}" || bad "both shards answer" "no answer from ${NODES[*]}"
    run_lib "the shards half ran" pns shards "${NODES[@]}"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
