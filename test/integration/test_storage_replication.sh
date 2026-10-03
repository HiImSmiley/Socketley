#!/usr/bin/env bash
# Integration test: S3 bucket replication from one storage runtime to another.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   config      Put/Get/DeleteBucketReplication: ReplicationConfigurationNotFoundError,
#               a bucket that is not versioned refused, a Role that names no
#               --replication-targets target, a tag filter with delete marker
#               replication, existing object replication, MalformedXML; the
#               rules read back as given; versioning cannot be suspended while a
#               bucket replicates, and can once its configuration is deleted
#   copies      a prefix rule and a tag rule copy exactly the versions they name;
#               an overwrite is a new version on the replica, a delete marker is
#               copied where the rule says and not where it does not; the
#               replica keeps the ETag, type, cache control, disposition, user
#               metadata, tags, checksum and version id; a later tag change and
#               a tag removal follow the version; a multipart version is copied
#               in its parts (same multipart ETag, parts count, composite
#               checksum and version id); an SSE-S3 version is written SSE-S3
#   status      PENDING, then COMPLETED on the source, REPLICA on the replica,
#               FAILED for a destination user that may not replicate and for a
#               destination bucket that is not there; replication_pending,
#               _completed, _failed, _retries and _bytes in stats
#   policy      a destination user allowed s3:ReplicateObject,
#               s3:ReplicateDelete and s3:ReplicateTags only: its copies land, its own writes and
#               reads are refused; a user that may only read cannot write a
#               replica; a client cannot set another status
#   down        a destination stopped while versions are answered gets them
#               once it is back, after retries
#   crash       SIGKILL of the source worker while versions and a delete marker
#               wait for a stopped destination (the marker only in the outbox,
#               the versions also PENDING in the index), and while a slow copy
#               and an unanswered PUT are in
#               flight: everything answered is copied after the restart, the
#               unanswered PUT is on neither side, and no version is doubled
#   shards      with --shards 2 every version and delete marker through either
#               shard is copied once, by the shard that owns the key
#   loop        two buckets replicating to each other: nothing comes back
#   flag        --replication-targets refuses a file that does not parse, and
#               show names the file and never a secret
#
# The assertions live in lib_storage_replication.py, which prints one line each.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
export BIN
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgrepl

PS=$((SL_PORT_BASE+1941))
PD=$((SL_PORT_BASE+1942))
PSLOW=$((SL_PORT_BASE+1943))
PB=$((SL_PORT_BASE+1944))
export ADMIN_AK="AKIAREPLADMIN0000001"
export ADMIN_SK="repl/admin/secret"
export REPL_AK="AKIAREPLICATOR000001"
export REPL_SK="repl/user/secret/1"
export READ_AK="AKIAREPLREADER000001"
export READ_SK="repl/reader/secret/1"
# A test aid read by the resolver thread before the system resolver, so a target can be named by a host.
export SOCKETLEY_STORAGE_REPLICATION_HOSTS="$SOCKETLEY_TMPD/hosts"
echo "replica.test 127.0.0.1" > "$SOCKETLEY_STORAGE_REPLICATION_HOSTS"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

cleanup() {
    for r in rsrc rdst rshard; do "$BIN" stop "$r" >/dev/null 2>&1 || true; done
    sleep 0.3
    for r in rsrc rdst rshard rbad; do "$BIN" remove "$r" >/dev/null 2>&1 || true; done
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
run_lib() {   # label mode args...
    local label=$1; shift
    local out rc p f
    out=$(python3 "$HERE/lib_storage_replication.py" "$@" 2>&1); rc=$?
    echo "$out" | grep -E '^  (PASS|FAIL)'
    p=$(echo "$out" | grep -c '^  PASS')
    f=$(echo "$out" | grep -c '^  FAIL')
    PASS=$((PASS+p)); FAIL=$((FAIL+f)); TOTAL=$((TOTAL+p+f))
    if [ "$rc" -ne 0 ] && [ "$f" -eq 0 ]; then bad "$label" "exit $rc: $out"; fi
}

echo "=== Integration: bucket replication ==="
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 is required"; exit 1; }
python3 -c "import boto3" 2>/dev/null || { echo "  SKIP: boto3 is required"; exit 0; }
daemon_start "$BIN"

KEY="$SOCKETLEY_TMPD/master.key"
head -c 32 /dev/urandom > "$KEY"
chmod 600 "$KEY"
CREDS="$SOCKETLEY_TMPD/creds"
cat > "$CREDS" <<EOF
$ADMIN_AK:$ADMIN_SK

[replicator]
policy = {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:ReplicateObject","s3:ReplicateDelete","s3:ReplicateTags"],"Resource":"arn:aws:s3:::*/*"}]}
$REPL_AK:$REPL_SK

[reader]
policy = {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::*/*"}]}
$READ_AK:$READ_SK
EOF
TARGETS="$SOCKETLEY_TMPD/targets"
cat > "$TARGETS" <<EOF
# name  url                            region     access key   secret
dst     http://replica.test:$PD        us-east-1  $REPL_AK     $REPL_SK
weak    http://127.0.0.1:$PD           us-east-1  $READ_AK     $READ_SK
slow    http://127.0.0.1:$PSLOW        us-east-1  $REPL_AK     $REPL_SK
EOF
BACK="$SOCKETLEY_TMPD/back"
echo "back http://127.0.0.1:$PS us-east-1 AKIAANYBODY000000001 anybody/secret" > "$BACK"

# ── the flag ────────────────────────────────────────────────────────────────
echo "dst http://127.0.0.1:1/ us-east-1 onlyakey" > "$SOCKETLEY_TMPD/badtargets"
out=$("$BIN" create storage rbad -p "$PB" --dir "$SOCKETLEY_TMPD/bad" --anonymous \
      --replication-targets "$SOCKETLEY_TMPD/badtargets" -s 2>&1)
if [ $? -ne 0 ] && echo "$out" | grep -q "name url region access_key secret"; then
    ok "a targets file that does not parse is refused, saying why"
else
    bad "a targets file that does not parse is refused, saying why" "$out"
fi
"$BIN" remove rbad >/dev/null 2>&1
out=$("$BIN" create storage rbad -p "$PB" --dir "$SOCKETLEY_TMPD/bad" --anonymous --replication-targets 2>&1)
[ $? -eq 1 ] && ok "--replication-targets with no file is refused" || bad "--replication-targets with no file is refused" "$out"

# ── two runtimes ────────────────────────────────────────────────────────────
DATA="$SOCKETLEY_TMPD/src"
if ! "$BIN" create storage rsrc -p "$PS" --dir "$DATA" --anonymous --sse-key-file "$KEY" \
     --replication-targets "$TARGETS" -s >/dev/null 2>&1; then
    echo "  FAIL [create]: the source was not created"
    exit 1
fi
if ! "$BIN" create storage rdst -p "$PD" --dir "$SOCKETLEY_TMPD/dst" --credentials "$CREDS" --sse-key-file "$KEY" \
     --replication-targets "$BACK" -s >/dev/null 2>&1; then
    echo "  FAIL [create]: the destination was not created"
    exit 1
fi
wait_up "$PS" && wait_up "$PD" || bad "both runtimes come up" "no answer on $PS or $PD"
shown=$("$BIN" show rsrc 2>&1)
if echo "$shown" | grep -q "\"replication_targets\": \"$TARGETS\"" && ! echo "$shown" | grep -q "$REPL_SK"; then
    ok "show names the targets file and no secret in it"
else
    bad "show names the targets file and no secret in it" "$shown"
fi
grep -q "$REPL_SK" "$SOCKETLEY_DLOG" && bad "no secret reaches the log" "$(grep -n "$REPL_SK" "$SOCKETLEY_DLOG")" \
    || ok "no secret reaches the log"

run_lib "the main half ran" main "$PS" "$PD"
run_lib "the policy half ran" policy "$PD"
run_lib "the down half ran" down "$PS" "$PD"
run_lib "the crash half ran" crash "$PS" "$PD" "$PSLOW" "$DATA"
run_lib "the loop half ran" loop "$PS" "$PD"

# ── two shards ──────────────────────────────────────────────────────────────
SOCK="$SOCKETLEY_TMPD/rshard.sock"
NODES=("$SOCKETLEY_TMPD/rshard#0.sock" "$SOCKETLEY_TMPD/rshard#1.sock")
if ! "$BIN" create storage rshard --listen "unix:$SOCK" --dir "$SOCKETLEY_TMPD/shardobjects" --anonymous --shards 2 \
     --replication-targets "$TARGETS" -s >/dev/null 2>&1; then
    bad "create with --shards 2" "the runtime was not created"
else
    wait_nodes "${NODES[@]}" || bad "both shards answer" "no answer from ${NODES[*]}"
    run_lib "the shards half ran" shards "$PD" "${NODES[@]}"
fi

grep -q "$REPL_SK" "$SOCKETLEY_DLOG" && bad "and still none at the end" "$(grep -n "$REPL_SK" "$SOCKETLEY_DLOG")" \
    || ok "and still none at the end"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
