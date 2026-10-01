#!/usr/bin/env bash
# Integration test: S3 bucket versioning on the storage runtime.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   config      GetBucketVersioning of a bucket never versioned is an empty
#               configuration, Enabled and Suspended are set and read back,
#               MFA delete and a bad status are refused
#   versions    every PUT, CopyObject and CompleteMultipartUpload of a versioned
#               bucket makes a version with its own x-amz-version-id; GET, HEAD,
#               DELETE and the tagging operations take ?versionId=, and GET
#               without one is the latest
#   markers     DELETE without a version id puts a delete marker in front, which
#               GET and HEAD answer 404 with x-amz-delete-marker and a GET of the
#               marker by its id 405; removing the marker undeletes the key, and
#               removing the latest version promotes the one behind it
#   suspended   a write is the null version, which the next one replaces, and
#               the versions written while enabled stay
#   listing     ListObjectVersions in S3's order, key ascending and newest first,
#               paged by key-marker and version-id-marker and by boto3's
#               paginator, with delimiter and prefix
#   batch       DeleteObjects with VersionId entries, and without one
#   lifecycle   with a lifecycle day of two seconds, NoncurrentVersionExpiration
#               removes the versions behind a latest and ExpiredObjectDeleteMarker
#               a marker with nothing behind it, and nothing outside their rules
#   recovery    a clean restart, and a SIGKILL with every journal removed, bring
#               every version and marker back from the files alone in the same
#               order; a version left under both its names by a crash is kept once
#   shards      with --shards 2 every version is read alike through the shard that
#               owns the key and the one that does not, and no held copy answers
#               a latest that a new version or a marker replaced
#
# The assertions live in lib_storage_versioning.py, which prints one line each.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
export BIN
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgver
export SOCKETLEY_STORAGE_LIFECYCLE_DAY_SECS=2

P1=$((SL_PORT_BASE+1599))

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

cleanup() {
    for r in ver vers; do "$BIN" stop "$r" >/dev/null 2>&1 || true; done
    sleep 0.3
    for r in ver vers; do "$BIN" remove "$r" >/dev/null 2>&1 || true; done
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
    out=$(RUNTIME=$rt python3 "$HERE/lib_storage_versioning.py" "$@" 2>&1); rc=$?
    echo "$out" | grep -E '^  (PASS|FAIL|SKIP)'
    p=$(echo "$out" | grep -c '^  PASS')
    f=$(echo "$out" | grep -c '^  FAIL')
    PASS=$((PASS+p)); FAIL=$((FAIL+f)); TOTAL=$((TOTAL+p+f))
    if [ "$rc" -ne 0 ] && [ "$f" -eq 0 ]; then bad "$label" "exit $rc: $out"; fi
}

echo "=== Integration: bucket versioning ==="
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 is required"; exit 1; }
daemon_start "$BIN"

DATA="$SOCKETLEY_TMPD/objects"
if ! "$BIN" create storage ver -p "$P1" --dir "$DATA" --anonymous -s >/dev/null 2>&1; then
    echo "  FAIL [create]: the runtime was not created"
    exit 1
fi
wait_up "$P1" || bad "the runtime comes up" "no answer on $P1"
run_lib "the main half ran" ver main "$P1" "$DATA"
run_lib "the recovery half ran" ver recovery "$P1" "$DATA"
"$BIN" stop ver >/dev/null 2>&1

# ── two shards ──────────────────────────────────────────────────────────────
SDATA="$SOCKETLEY_TMPD/shardobjects"
SOCK="$SOCKETLEY_TMPD/vers.sock"
NODES=("$SOCKETLEY_TMPD/vers#0.sock" "$SOCKETLEY_TMPD/vers#1.sock")
if ! "$BIN" create storage vers --listen "unix:$SOCK" --dir "$SDATA" --anonymous --shards 2 -s >/dev/null 2>&1; then
    bad "create with --shards 2" "the runtime was not created"
else
    wait_nodes "${NODES[@]}" || bad "both shards answer" "no answer from ${NODES[*]}"
    run_lib "the shards half ran" vers shards "${NODES[@]}"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
