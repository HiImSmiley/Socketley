#!/usr/bin/env bash
# Integration test: S3 bucket lifecycle on the storage runtime.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   config      PutBucketLifecycleConfiguration, Get and Delete, raw and through
#               boto3; NoSuchLifecycleConfiguration; every refusal (MalformedXML,
#               InvalidArgument, InvalidRequest for tag and size filters beside an
#               abort of uploads, InvalidStorageClass for a transition to no tier,
#               NotImplemented for two transitions in a rule and for newer noncurrent
#               versions, 1001 rules), each leaving the configuration that was there
#   sweep       with a lifecycle day of two seconds (SOCKETLEY_STORAGE_LIFECYCLE_DAY_SECS):
#               objects under an expiring prefix go and no earlier than a day
#               after their mtime, a past date expires at once, a disabled rule,
#               a future date and other prefixes keep theirs, an incomplete
#               upload under an abort rule is aborted, `stats` counts both
#   restart     the configuration survives a stop and a start, and so does the sweep
#   shards      with --shards 2 a configuration put through shard 1 is answered
#               by both, each shard expires the keys it owns, a delete reaches
#               both, and both have it after a stop and a start
#
# The assertions live in lib_storage_bucket_lifecycle.py, which prints one line each.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
export BIN
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgbktlc

P1=$((SL_PORT_BASE+1593))
export AK="AKIATESTACCESSKEY01"
export SK="test/secret+key/for.storage.sigv4"
# Read by each shard's sweep alone, so a test sees days pass in seconds.
export SOCKETLEY_STORAGE_LIFECYCLE_DAY_SECS=2

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

cleanup() {
    for r in lc lcs; do "$BIN" stop "$r" >/dev/null 2>&1 || true; done
    sleep 0.3
    for r in lc lcs; do "$BIN" remove "$r" >/dev/null 2>&1 || true; done
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
    out=$(RUNTIME=$rt python3 "$HERE/lib_storage_bucket_lifecycle.py" "$@" 2>&1); rc=$?
    echo "$out" | grep -E '^  (PASS|FAIL)'
    p=$(echo "$out" | grep -c '^  PASS')
    f=$(echo "$out" | grep -c '^  FAIL')
    PASS=$((PASS+p)); FAIL=$((FAIL+f)); TOTAL=$((TOTAL+p+f))
    if [ "$rc" -ne 0 ] && [ "$f" -eq 0 ]; then bad "$label" "exit $rc: $out"
    elif [ "$p" -eq 0 ] && [ "$f" -eq 0 ]; then bad "$label" "no PASS or FAIL line: $out"; fi
}

echo "=== Integration: bucket lifecycle ==="
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 is required"; exit 1; }
python3 -c "import boto3" 2>/dev/null || { echo "  SKIP: boto3 is required"; exit 0; }
daemon_start "$BIN"

DATA="$SOCKETLEY_TMPD/objects"
if ! "$BIN" create storage lc -p "$P1" --dir "$DATA" --access-key "$AK" --secret-key "$SK" -s >/dev/null 2>&1; then
    echo "  FAIL [create]: the runtime was not created"
    exit 1
fi
wait_up "$P1" || bad "the runtime comes up" "no answer on $P1"
run_lib "the main half ran" lc main "$P1"

"$BIN" stop lc >/dev/null 2>&1
sleep 0.5
"$BIN" start lc >/dev/null 2>&1
wait_up "$P1" || bad "the runtime comes back" "no answer on $P1"
run_lib "the restart half ran" lc restart "$P1"
"$BIN" stop lc >/dev/null 2>&1

# ── two shards ──────────────────────────────────────────────────────────────
SDATA="$SOCKETLEY_TMPD/shardobjects"
SOCK="$SOCKETLEY_TMPD/lcs.sock"
NODES=("$SOCKETLEY_TMPD/lcs#0.sock" "$SOCKETLEY_TMPD/lcs#1.sock")
if ! "$BIN" create storage lcs --listen "unix:$SOCK" --dir "$SDATA" --anonymous --shards 2 -s >/dev/null 2>&1; then
    bad "create with --shards 2" "the runtime was not created"
else
    wait_nodes "${NODES[@]}" || bad "both shards answer" "no answer from ${NODES[*]}"
    LC_DATA="$SDATA" run_lib "the shards half ran" lcs shards "${NODES[@]}"
    "$BIN" stop lcs >/dev/null 2>&1
    sleep 0.5
    "$BIN" start lcs >/dev/null 2>&1
    wait_nodes "${NODES[@]}" || bad "both shards come back" "no answer from ${NODES[*]}"
    run_lib "the shards restart half ran" lcs shards_restart "${NODES[@]}"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
