#!/usr/bin/env bash
# Integration test: S3 Object Lock on the storage runtime.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   config      CreateBucket with x-amz-bucket-object-lock-enabled turns versioning on for good, an existing
#               bucket takes object lock only while its versioning is Enabled, Put/GetObjectLockConfiguration
#               with S3's refusals, and Content-MD5 or a checksum required and checked
#   modes       COMPLIANCE refuses a DELETE of the version with or without the bypass and is only lengthened;
#               GOVERNANCE is lengthened freely and shortened, removed or made COMPLIANCE only with the bypass;
#               a DELETE without a version id still puts a delete marker; a retention that has run out holds
#               nothing, by the server's clock
#   bypass      a key a policy denies s3:BypassGovernanceRetention is refused what the other key may do, and an
#               anonymous caller needs an Allow of it
#   legal hold  ON refuses the removal whatever the retention or the bypass, OFF lets it go, and tags, a
#               retention and a hold kept in one header change without losing each other, also in a header
#               written again for want of room
#   default     a bucket's default retention, in Days and in calendar Years, and headers that override it
#   multipart   a lock asked of CreateMultipartUpload lands on the completed object; a copy takes its own lock
#               and never its source's
#   batch       DeleteObjects answers a locked version AccessDenied beside one it removes
#   lifecycle   noncurrent expiry passes over versions under retention or a legal hold; DeleteBucket refuses
#   recovery    a clean restart, a SIGKILL, and a SIGKILL with every journal removed bring back every lock,
#               set in the header, in a slot or in a header written again
#   shards      with --shards 2 every operation works and is enforced through the shard that does not own the
#               key, and the bucket's configuration is judged by shard 0
#
# The assertions live in lib_storage_object_lock.py, which prints one line each.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
export BIN
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stglock
export SOCKETLEY_STORAGE_LIFECYCLE_DAY_SECS=2

P1=$((SL_PORT_BASE+1611))
P2=$((SL_PORT_BASE+1612))

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

cleanup() {
    for r in olk olr ols; do "$BIN" stop "$r" >/dev/null 2>&1 || true; done
    sleep 0.3
    for r in olk olr ols; do "$BIN" remove "$r" >/dev/null 2>&1 || true; done
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
    out=$(RUNTIME=$rt python3 "$HERE/lib_storage_object_lock.py" "$@" 2>&1); rc=$?
    echo "$out" | grep -E '^  (PASS|FAIL|SKIP)'
    p=$(echo "$out" | grep -c '^  PASS')
    f=$(echo "$out" | grep -c '^  FAIL')
    PASS=$((PASS+p)); FAIL=$((FAIL+f)); TOTAL=$((TOTAL+p+f))
    if [ "$rc" -ne 0 ] && [ "$f" -eq 0 ]; then bad "$label" "exit $rc: $out"; fi
}

echo "=== Integration: object lock ==="
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 is required"; exit 1; }
daemon_start "$BIN"

export AK1="AKIALOCKKEYONE000001" SK1="lock/one/secret"
export AK2="AKIALOCKKEYTWO000002" SK2="lock/two/secret"
CREDS="$SOCKETLEY_TMPD/creds"
printf '%s:%s\n%s:%s\n' "$AK1" "$SK1" "$AK2" "$SK2" > "$CREDS"
chmod 600 "$CREDS"

DATA="$SOCKETLEY_TMPD/objects"
if ! "$BIN" create storage olk -p "$P1" --dir "$DATA" --credentials "$CREDS" -s >/dev/null 2>&1; then
    echo "  FAIL [create]: the runtime was not created"
    exit 1
fi
wait_up "$P1" || bad "the runtime comes up" "no answer on $P1"
run_lib "the main half ran" olk main "$P1" "$DATA"
"$BIN" stop olk >/dev/null 2>&1

RDATA="$SOCKETLEY_TMPD/recovery"
if ! "$BIN" create storage olr -p "$P2" --dir "$RDATA" --credentials "$CREDS" -s >/dev/null 2>&1; then
    bad "create the recovery runtime" "the runtime was not created"
else
    wait_up "$P2" || bad "the recovery runtime comes up" "no answer on $P2"
    run_lib "the recovery half ran" olr recovery "$P2" "$RDATA"
    "$BIN" stop olr >/dev/null 2>&1
fi

# ── two shards ──────────────────────────────────────────────────────────────
SDATA="$SOCKETLEY_TMPD/shardobjects"
SOCK="$SOCKETLEY_TMPD/ols.sock"
NODES=("$SOCKETLEY_TMPD/ols#0.sock" "$SOCKETLEY_TMPD/ols#1.sock")
if ! "$BIN" create storage ols --listen "unix:$SOCK" --dir "$SDATA" --anonymous --shards 2 -s >/dev/null 2>&1; then
    bad "create with --shards 2" "the runtime was not created"
else
    wait_nodes "${NODES[@]}" || bad "both shards answer" "no answer from ${NODES[*]}"
    run_lib "the shards half ran" ols shards "${NODES[@]}"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
