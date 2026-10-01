#!/usr/bin/env bash
# Integration test: S3 object tagging on the storage runtime, and lifecycle
# rules that filter on tags.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   tagging     Put/Get/DeleteObjectTagging through boto3 and raw; S3's limits
#               (ten tags, 128 and 256 characters, unique keys, the allowed
#               characters, no aws:) as BadRequest and InvalidTag, MalformedXML,
#               NoSuchKey, NoSuchBucket, BadDigest; x-amz-tagging-count on GET
#               and HEAD; a change keeps the object's bytes, ETag and time, in
#               its header's slots, and a set too big for them writes it again
#   headers     x-amz-tagging on PutObject, on CreateMultipartUpload (landing on
#               the completed object) and on CopyObject under
#               x-amz-tagging-directive COPY (the default) and REPLACE
#   lifecycle   with a lifecycle day of two seconds
#               (SOCKETLEY_STORAGE_LIFECYCLE_DAY_SECS): Filter by Tag, by And of
#               a prefix and tags, and by object size expire exactly the objects
#               they match, a tag changed after the put included; refusals
#   restart     tags and the tag filters survive a stop and a start
#   crash       tag changes answered before a SIGKILL of the worker are there
#               after it, and a start with every journal removed finds every
#               object's tags in its own file
#   shards      with --shards 2 a change through the shard that does not own the
#               key is seen by both at once, the headers they keep for a hot
#               object included
#
# The assertions live in lib_storage_tagging.py, which prints one line each.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
export BIN
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgtag

P1=$((SL_PORT_BASE+1594))
export AK="AKIATESTACCESSKEY01"
export SK="test/secret+key/for.storage.sigv4"
# Read by each shard's sweep alone, so a test sees days pass in seconds.
export SOCKETLEY_STORAGE_LIFECYCLE_DAY_SECS=2

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

cleanup() {
    for r in tg tgs; do "$BIN" stop "$r" >/dev/null 2>&1 || true; done
    sleep 0.3
    for r in tg tgs; do "$BIN" remove "$r" >/dev/null 2>&1 || true; done
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
    out=$(RUNTIME=$rt python3 "$HERE/lib_storage_tagging.py" "$@" 2>&1); rc=$?
    echo "$out" | grep -E '^  (PASS|FAIL)'
    p=$(echo "$out" | grep -c '^  PASS')
    f=$(echo "$out" | grep -c '^  FAIL')
    PASS=$((PASS+p)); FAIL=$((FAIL+f)); TOTAL=$((TOTAL+p+f))
    if [ "$rc" -ne 0 ] && [ "$f" -eq 0 ]; then bad "$label" "exit $rc: $out"; fi
}

echo "=== Integration: object tagging ==="
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 is required"; exit 1; }
python3 -c "import boto3" 2>/dev/null || { echo "  SKIP: boto3 is required"; exit 0; }
daemon_start "$BIN"

DATA="$SOCKETLEY_TMPD/objects"
if ! "$BIN" create storage tg -p "$P1" --dir "$DATA" --access-key "$AK" --secret-key "$SK" -s >/dev/null 2>&1; then
    echo "  FAIL [create]: the runtime was not created"
    exit 1
fi
wait_up "$P1" || bad "the runtime comes up" "no answer on $P1"
run_lib "the main half ran" tg main "$P1"

"$BIN" stop tg >/dev/null 2>&1
sleep 0.5
"$BIN" start tg >/dev/null 2>&1
wait_up "$P1" || bad "the runtime comes back" "no answer on $P1"
run_lib "the restart half ran" tg restart "$P1"
run_lib "the crash half ran" tg crash "$P1" "$DATA"
"$BIN" stop tg >/dev/null 2>&1

# ── two shards ──────────────────────────────────────────────────────────────
SDATA="$SOCKETLEY_TMPD/shardobjects"
SOCK="$SOCKETLEY_TMPD/tgs.sock"
NODES=("$SOCKETLEY_TMPD/tgs#0.sock" "$SOCKETLEY_TMPD/tgs#1.sock")
if ! "$BIN" create storage tgs --listen "unix:$SOCK" --dir "$SDATA" --anonymous --shards 2 -s >/dev/null 2>&1; then
    bad "create with --shards 2" "the runtime was not created"
else
    wait_nodes "${NODES[@]}" || bad "both shards answer" "no answer from ${NODES[*]}"
    run_lib "the shards half ran" tgs shards "${NODES[@]}"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
