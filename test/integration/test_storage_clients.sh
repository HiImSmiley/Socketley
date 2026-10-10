#!/usr/bin/env bash
# suite: isolated -- a daemon, socket and port window of its own, so it runs beside the others
# Integration test: the storage runtime under real S3 clients and what Ceph's
# s3-tests found missing.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   boto3      each behaviour a real client or s3-tests once failed on, in
#              lib_storage_clients.py: DeleteBucket with an open upload, a Date
#              header in RFC 2822 form, an empty Content-MD5, aws-chunked named
#              on an empty body, ListBuckets in pages, GetObjectAttributes,
#              If-Match and If-None-Match on PutObject and on a completion, and a
#              completion sent twice, FULL_OBJECT checksums, x-amz-expiration,
#              ACLs as with ACLs disabled, a bucket's own tags, POST Object
#              forms signed V2 and V4, and object lock refused -- on one
#              process and again over two shards
#   aws        AWS CLI v2: mb, a 100 MiB multipart cp both ways, sync up and down
#              and again, ls, list-buckets --max-buckets, get-object-attributes,
#              presign, rm --recursive, and rb --force over an open upload
#   rclone     sync, check --download, a 100 MiB copy, server-side copy, purge
#   restic     init, two backups, check --read-data, restore, forget --prune
#   mc         cp -r, mirror both ways, ls -r, stat, tag, versioning, share
#              upload (a POST form, sent with curl), rm -r, rb
#
# A client that is not on PATH is skipped and said so; put the binaries on PATH
# (aws, rclone, restic, mc) to run them.  The boto3 half needs python3 and boto3.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgclients

PORT=$((SL_PORT_BASE+1615))
PORT2=$((SL_PORT_BASE+1616))
DATA="$SOCKETLEY_TMPD/objects"
DATA2="$SOCKETLEY_TMPD/objects2"
WORK="$SOCKETLEY_TMPD/work"
EP="http://127.0.0.1:$PORT"
AK=AKIACLIENTSTEST00001
SK='clients/test+secret/with=signs0123456789'

cleanup() {
    "$BIN" stop stgcl >/dev/null 2>&1 || true
    "$BIN" stop stgcl2 >/dev/null 2>&1 || true
    sleep 0.3
    "$BIN" remove stgcl >/dev/null 2>&1 || true
    "$BIN" remove stgcl2 >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL [$1]: ${2:-}"; }
SKIPPED=0
skip() { SKIPPED=$((SKIPPED + 1)); echo "  SKIP: $1"; }

# step NAME CMD... -- one client command, its output kept in $WORK/log and shown when it fails.
step() {
    local name=$1; shift
    if timeout 300 "$@" > "$WORK/log" 2>&1; then
        pass "$name"
    else
        fail "$name" "$(tail -3 "$WORK/log" | tr '\n' ' ')"
    fi
}

echo "=== Integration: the storage runtime under real S3 clients ==="

daemon_start "$BIN"
if ! "$BIN" create storage stgcl -p "$PORT" --dir "$DATA" --access-key "$AK" --secret-key "$SK" -s >/dev/null 2>&1; then
    echo "  FAIL [create]: the runtime was not created"
    exit 1
fi
for _ in $(seq 1 100); do
    curl -s -o /dev/null "$EP/" 2>/dev/null && break
    sleep 0.1
done

mkdir -p "$WORK/src/a/b" "$WORK/src/c" "$WORK/src/sp ace"
for i in $(seq 1 30); do head -c $((i * 1777)) /dev/urandom > "$WORK/src/a/f$i.bin"; done
for i in $(seq 1 5); do echo "hello $i" > "$WORK/src/a/b/t$i.txt"; done
head -c 3000000 /dev/urandom > "$WORK/src/c/three.bin"
echo x > "$WORK/src/sp ace/file with spaces.txt"
echo z > "$WORK/src/c/plus+and%percent.txt"
: > "$WORK/src/c/empty.txt"
head -c 104857600 /dev/urandom > "$WORK/big.bin"

# ─── boto3 ──────────────────────────────────────────────────────────────────
if command -v python3 >/dev/null 2>&1 && python3 -c 'import boto3' 2>/dev/null; then
    python3 "$HERE/lib_storage_clients.py" "$PORT" "$AK" "$SK"
    rc=$?
    [ "$rc" -eq 0 ] && pass "the boto3 half" || fail "the boto3 half" "$rc assertions failed"
    # Again over two shards, where a key's owner, an upload's and a document's are often another process.
    if "$BIN" create storage stgcl2 -p "$PORT2" --dir "$DATA2" --shards 2 --access-key "$AK" --secret-key "$SK" -s >/dev/null 2>&1; then
        for _ in $(seq 1 100); do
            curl -s -o /dev/null "http://127.0.0.1:$PORT2/" 2>/dev/null && break
            sleep 0.1
        done
        echo "--- the same over two shards ---"
        python3 "$HERE/lib_storage_clients.py" "$PORT2" "$AK" "$SK"
        rc=$?
        [ "$rc" -eq 0 ] && pass "the boto3 half over two shards" || fail "the boto3 half over two shards" "$rc assertions failed"
    else
        fail "create over two shards" "the sharded runtime was not created"
    fi
else
    skip "boto3 is not installed"
fi

# ─── AWS CLI v2 ─────────────────────────────────────────────────────────────
if command -v aws >/dev/null 2>&1; then
    export AWS_ACCESS_KEY_ID=$AK AWS_SECRET_ACCESS_KEY=$SK AWS_DEFAULT_REGION=us-east-1
    export AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null
    A="aws --endpoint-url $EP"
    step "aws: mb" $A s3 mb s3://awsb
    step "aws: cp of 100 MiB, multipart" $A s3 cp "$WORK/big.bin" s3://awsb/big.bin
    step "aws: and back, byte for byte" bash -c "$A s3 cp s3://awsb/big.bin '$WORK/big.back' && cmp '$WORK/big.bin' '$WORK/big.back'"
    step "aws: sync up" $A s3 sync "$WORK/src" s3://awsb/tree
    step "aws: sync up again copies nothing" bash -c "out=\$($A s3 sync '$WORK/src' s3://awsb/tree) && [ -z \"\$out\" ] || { printf '%s\n' \"\$out\"; exit 1; }"
    step "aws: sync down, identical" bash -c "$A s3 sync s3://awsb/tree '$WORK/aws-down' && diff -r '$WORK/src' '$WORK/aws-down'"
    step "aws: ls --recursive" bash -c "$A s3 ls --recursive s3://awsb/ | grep -q 'tree/sp ace/file with spaces.txt'"
    step "aws: s3api list-buckets --max-buckets 1" bash -c "$A s3 mb s3://awsc >/dev/null && [ \"\$($A s3api list-buckets --max-buckets 1 --no-paginate --query 'length(Buckets)')\" = 1 ]"
    step "aws: s3api get-object-attributes" bash -c "$A s3api get-object-attributes --bucket awsb --key big.bin --object-attributes ObjectSize ObjectParts | grep -q '\"ObjectSize\": 104857600'"
    step "aws: presign, read with curl" bash -c "curl -sf \"\$($A s3 presign s3://awsb/tree/a/b/t1.txt)\" | grep -q 'hello 1'"
    step "aws: rm --recursive" $A s3 rm --recursive s3://awsb/tree
    step "aws: rb --force over an open upload" bash -c "$A s3api create-multipart-upload --bucket awsb --key left >/dev/null && $A s3 rb --force s3://awsb"
    step "aws: rb" $A s3 rb s3://awsc
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_DEFAULT_REGION AWS_CONFIG_FILE AWS_SHARED_CREDENTIALS_FILE
else
    skip "aws is not on PATH"
fi

# ─── rclone ─────────────────────────────────────────────────────────────────
if command -v rclone >/dev/null 2>&1; then
    export RCLONE_CONFIG="$WORK/rclone.conf"
    printf '[sl]\ntype = s3\nprovider = Other\naccess_key_id = %s\nsecret_access_key = %s\nendpoint = %s\nregion = us-east-1\n' \
        "$AK" "$SK" "$EP" > "$RCLONE_CONFIG"
    R="rclone --retries 1 --low-level-retries 1"
    step "rclone: mkdir" $R mkdir sl:rcb
    step "rclone: sync up" $R sync "$WORK/src" sl:rcb/tree
    step "rclone: check --download" $R check --download "$WORK/src" sl:rcb/tree
    step "rclone: copy of 100 MiB, multipart" $R copyto "$WORK/big.bin" sl:rcb/big.bin
    step "rclone: its md5 is the file's" bash -c "[ \"\$($R md5sum sl:rcb/big.bin | cut -d' ' -f1)\" = \"\$(md5sum '$WORK/big.bin' | cut -d' ' -f1)\" ]"
    step "rclone: server-side copy" bash -c "$R copy sl:rcb/tree/a sl:rcb/copy-a && $R check sl:rcb/tree/a sl:rcb/copy-a"
    step "rclone: sync down, identical" bash -c "$R sync sl:rcb/tree '$WORK/rc-down' && diff -r '$WORK/src' '$WORK/rc-down'"
    step "rclone: purge" $R purge sl:rcb
    unset RCLONE_CONFIG
else
    skip "rclone is not on PATH"
fi

# ─── restic ─────────────────────────────────────────────────────────────────
if command -v restic >/dev/null 2>&1; then
    export AWS_ACCESS_KEY_ID=$AK AWS_SECRET_ACCESS_KEY=$SK RESTIC_PASSWORD=clients-test
    export RESTIC_REPOSITORY="s3:$EP/resticb/repo" RESTIC_CACHE_DIR="$WORK/restic-cache"
    step "restic: init" restic init
    step "restic: backup" restic backup "$WORK/src"
    head -c 2000000 /dev/urandom > "$WORK/src/a/new.bin"
    step "restic: a second backup" restic backup "$WORK/src"
    step "restic: check --read-data" restic check --read-data
    step "restic: restore, identical" bash -c "restic restore latest --target '$WORK/restic-out' && diff -r '$WORK/src' '$WORK/restic-out$WORK/src'"
    step "restic: forget --prune" restic forget --keep-last 1 --prune
    step "restic: check after the prune" restic check
    rm -f "$WORK/src/a/new.bin"
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY RESTIC_PASSWORD RESTIC_REPOSITORY RESTIC_CACHE_DIR
else
    skip "restic is not on PATH"
fi

# ─── MinIO mc ───────────────────────────────────────────────────────────────
if command -v mc >/dev/null 2>&1 && mc --version 2>/dev/null | grep -qi minio; then
    export MC_CONFIG_DIR="$WORK/mc"
    step "mc: alias set" mc alias set sl "$EP" "$AK" "$SK" --api S3v4 --path on
    step "mc: mb" mc mb sl/mcb
    step "mc: cp -r" mc cp -r "$WORK/src/" sl/mcb/tree/
    step "mc: cp of 100 MiB, multipart" mc cp "$WORK/big.bin" sl/mcb/big.bin
    step "mc: ls -r" bash -c "mc ls -r sl/mcb | grep -q 'tree/c/three.bin'"
    step "mc: stat" mc stat sl/mcb/big.bin
    step "mc: mirror up and down, identical" bash -c "mc mirror --overwrite '$WORK/src' sl/mcb/mirror && mc mirror sl/mcb/mirror '$WORK/mc-down' && diff -r '$WORK/src' '$WORK/mc-down'"
    step "mc: tag set and list" bash -c "mc tag set sl/mcb/tree/a/f1.bin 'k1=v1&k2=v2' && mc tag list sl/mcb/tree/a/f1.bin | grep -q k2"
    if command -v curl >/dev/null 2>&1; then
        step "mc: share upload, a POST form sent with curl" bash -c "cmd=\$(mc share upload --json sl/mcb/form.txt | python3 -c 'import sys,json; print(json.load(sys.stdin)[\"share\"])') && eval \"\${cmd/<FILE>/$WORK/src/a/b/t2.txt}\" && mc cat sl/mcb/form.txt | grep -q 'hello 2'"
    fi
    step "mc: version enable, two versions" bash -c "mc version enable sl/mcb && mc cp '$WORK/src/a/f2.bin' sl/mcb/v && mc cp '$WORK/src/a/f3.bin' sl/mcb/v && [ \"\$(mc ls --versions sl/mcb/v | wc -l)\" = 2 ]"
    step "mc: rm -r --force --versions" mc rm -r --force --versions sl/mcb
    step "mc: rb --force" mc rb --force sl/mcb
    unset MC_CONFIG_DIR
else
    skip "mc is not on PATH"
fi

echo ""
echo "  Results: $PASS passed, $FAIL failed, $SKIPPED clients skipped"
[ "$FAIL" -eq 0 ] || { echo "  FAILED"; exit 1; }
# Every client missing is a box without them, and that is said rather than called a pass.
[ "$PASS" -gt 0 ] || { echo "  SKIPPED: no S3 client ran, nothing was asserted"; exit 0; }
echo "  PASSED"
exit 0
