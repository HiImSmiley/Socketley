#!/usr/bin/env bash
# suite: isolated -- a daemon, socket and port window of its own, so it runs beside the others
# Integration test: virtual-hosted-style addressing on a storage runtime.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   flag       --domain takes DNS names separated by commas, refuses anything
#              else at create, is kept in the state file, and is not edited
#   boto3      every operation with addressing_style "virtual" and "path", each
#              request checked to have gone in the style asked for: buckets,
#              objects, listing, copy, multipart with its Location, presigned
#              GET and PUT, a form upload, CORS, DeleteObjects, a dotted bucket
#   raw        Hosts chosen by hand: the domain itself, an address, an unknown
#              name, upper case, a trailing dot, a second domain, and a
#              signature over the other style's path, which must not verify
#   restart    both styles still serve after a stop and start
#   aws        AWS CLI v2 with addressing_style = virtual
#   rclone     force_path_style = false
#   mc         --path off
#
# `<bucket>.localhost` resolves to the loopback, so no client needs a resolver
# of its own.  A client that is not in ~/socketley-perf/compat/bin or on PATH is
# skipped and said so.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
# Taken before daemon_isolate moves HOME.
COMPAT="${SOCKETLEY_COMPAT_BIN:-$HOME/socketley-perf/compat/bin}"
[ -d "$COMPAT" ] && PATH="$COMPAT:$PATH"
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgvhost

PORT=$((SL_PORT_BASE+1706))
PX=$((SL_PORT_BASE+1707))
DATA="$SOCKETLEY_TMPD/objects"
WORK="$SOCKETLEY_TMPD/work"
AK=AKIAVHOSTTEST0000001
SK='vhost/test+secret/with=signs0123456789'
EP="http://localhost:$PORT"
mkdir -p "$WORK"

cleanup() {
    "$BIN" stop stgvh >/dev/null 2>&1 || true
    sleep 0.3
    "$BIN" remove stgvh >/dev/null 2>&1 || true
    "$BIN" remove stgvhx >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }
contains() { case "$2" in *"$3"*) ok "$1" ;; *) bad "$1" "'$3' not in: $2" ;; esac; }

# step NAME CMD... -- one client command, its output kept in $WORK/log and shown when it fails.
step() {
    local name=$1; shift
    if timeout 300 "$@" > "$WORK/log" 2>&1; then ok "$name"; else bad "$name" "$(tail -3 "$WORK/log" | tr '\n' ' ')"; fi
}
run_py() {   # a mode of the library, whose lines are the test's
    local out rc p f
    out=$(python3 "$HERE/lib_storage_vhost.py" "$1" "$PORT" "$AK" "$SK" 2>&1); rc=$?
    echo "$out" | grep -E '^  (PASS|FAIL|SKIP)'
    p=$(echo "$out" | grep -c '^  PASS')
    f=$(echo "$out" | grep -c '^  FAIL')
    PASS=$((PASS+p)); FAIL=$((FAIL+f)); TOTAL=$((TOTAL+p+f))
    if [ "$rc" -ne 0 ] && [ "$f" -eq 0 ]; then
        bad "the library ran ($1)" "exit $rc: $(echo "$out" | tail -5)"
    fi
}
wait_port() {
    local t
    for t in $(seq 1 150); do
        curl -s -o /dev/null "http://127.0.0.1:$1/" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

echo "=== Integration: storage, virtual-hosted-style addressing ==="
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 is required"; exit 1; }
contains "<bucket>.localhost resolves to the loopback" \
    "$(python3 -c 'import socket; print(socket.gethostbyname("vh-bucket.localhost"))' 2>&1)" "127.0.0.1"
daemon_start "$BIN"

echo "== the flag =="
for d in "bad_name.test" "-lead.test" "a..b" "x,"; do
    out=$("$BIN" create storage stgvhx -p "$PX" --dir "$WORK/x" --anonymous --domain "$d" 2>&1); rc=$?
    expect "--domain '$d' is refused" "$rc" 1
    "$BIN" remove stgvhx >/dev/null 2>&1
done
contains "and says what a domain is" "$out" "DNS names separated by commas"
out=$("$BIN" create storage stgvhx -p "$PX" --dir "$WORK/x" --anonymous --domain 2>&1); rc=$?
expect "--domain with no value takes the runtime's name" "$rc" 0
contains "and show says so" "$("$BIN" show stgvhx 2>&1)" '"domain": "stgvhx"'
"$BIN" remove stgvhx >/dev/null 2>&1

"$BIN" create storage stgvh -p "$PORT" --dir "$DATA" --access-key "$AK" --secret-key "$SK" \
    --domain "LocalHost,s3.vh.test." -s >/dev/null 2>&1
expect "a runtime with two domains is made" "$?" 0
wait_port "$PORT" && ok "and answers" || bad "stgvh" "no answer on $PORT"
contains "show names the domains" "$("$BIN" show stgvh 2>&1)" '"domain": "LocalHost,s3.vh.test."'
out=$("$BIN" edit stgvh --domain example.com 2>&1); rc=$?
expect "edit --domain is refused" "$rc" 1
contains "and points at import" "$out" "import"

echo "== boto3 =="
run_py boto3
echo "== Hosts chosen by hand =="
run_py raw

echo "== a restart =="
"$BIN" stop stgvh >/dev/null 2>&1
sleep 0.3
"$BIN" start stgvh >/dev/null 2>&1
wait_port "$PORT" && ok "the runtime is back" || bad "restart" "no answer"
run_py after

head -c 12582912 /dev/urandom > "$WORK/big.bin"
mkdir -p "$WORK/src/d"
for i in 1 2 3; do echo "file $i" > "$WORK/src/d/f$i.txt"; done

# ─── AWS CLI v2 ─────────────────────────────────────────────────────────────
echo "== aws, addressing_style = virtual =="
if command -v aws >/dev/null 2>&1; then
    printf '[default]\nregion = us-east-1\ns3 =\n    addressing_style = virtual\n' > "$WORK/aws.conf"
    export AWS_ACCESS_KEY_ID=$AK AWS_SECRET_ACCESS_KEY=$SK AWS_DEFAULT_REGION=us-east-1
    export AWS_CONFIG_FILE="$WORK/aws.conf" AWS_SHARED_CREDENTIALS_FILE=/dev/null
    A="aws --endpoint-url $EP"
    step "aws: mb" $A s3 mb s3://awsvh
    step "aws: the requests went to awsvh.localhost" bash -c "$A --debug s3 ls s3://awsvh 2>&1 | grep -q 'awsvh.localhost:$PORT'"
    step "aws: cp of 12 MiB, multipart" $A s3 cp "$WORK/big.bin" s3://awsvh/big.bin
    step "aws: and back, byte for byte" bash -c "$A s3 cp s3://awsvh/big.bin '$WORK/aws.back' && cmp '$WORK/big.bin' '$WORK/aws.back'"
    step "aws: sync up and down" bash -c "$A s3 sync '$WORK/src' s3://awsvh/tree && $A s3 sync s3://awsvh/tree '$WORK/aws-down' && diff -r '$WORK/src' '$WORK/aws-down'"
    step "aws: s3api copy-object" bash -c "$A s3api copy-object --bucket awsvh --key copy.txt --copy-source awsvh/tree/d/f1.txt >/dev/null && $A s3 cp s3://awsvh/copy.txt - | grep -q 'file 1'"
    step "aws: presign is a virtual-hosted URL curl reads" bash -c "u=\$($A s3 presign s3://awsvh/tree/d/f2.txt) && case \"\$u\" in http://awsvh.localhost:$PORT/tree/d/f2.txt\?*) ;; *) exit 1 ;; esac && curl -sf \"\$u\" | grep -q 'file 2'"
    step "aws: rb --force" $A s3 rb --force s3://awsvh
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_DEFAULT_REGION AWS_CONFIG_FILE AWS_SHARED_CREDENTIALS_FILE
else
    echo "  SKIP: aws is not installed"
fi

# ─── rclone ─────────────────────────────────────────────────────────────────
echo "== rclone, force_path_style = false =="
if command -v rclone >/dev/null 2>&1; then
    export RCLONE_CONFIG="$WORK/rclone.conf"
    printf '[vh]\ntype = s3\nprovider = Other\naccess_key_id = %s\nsecret_access_key = %s\nendpoint = %s\nregion = us-east-1\nforce_path_style = false\n' \
        "$AK" "$SK" "$EP" > "$RCLONE_CONFIG"
    R="rclone --retries 1 --low-level-retries 1 --s3-upload-cutoff 5M --s3-chunk-size 5M"
    step "rclone: mkdir" $R mkdir vh:rcvh
    step "rclone: the requests went to rcvh.localhost" bash -c "$R -vv --dump headers lsf vh:rcvh 2>&1 | grep -qi 'Host: rcvh.localhost:$PORT'"
    step "rclone: sync up, check --download" bash -c "$R sync '$WORK/src' vh:rcvh/tree && $R check --download '$WORK/src' vh:rcvh/tree"
    step "rclone: copy of 12 MiB, multipart, md5 matches" bash -c "$R copyto '$WORK/big.bin' vh:rcvh/big.bin && [ \"\$($R md5sum vh:rcvh/big.bin | cut -d' ' -f1)\" = \"\$(md5sum '$WORK/big.bin' | cut -d' ' -f1)\" ]"
    step "rclone: server-side copy" bash -c "$R copy vh:rcvh/tree/d vh:rcvh/copy && $R check vh:rcvh/tree/d vh:rcvh/copy"
    step "rclone: purge" $R purge vh:rcvh
    unset RCLONE_CONFIG
else
    echo "  SKIP: rclone is not installed"
fi

# ─── MinIO mc ───────────────────────────────────────────────────────────────
echo "== mc, --path off =="
if command -v mc >/dev/null 2>&1 && mc --version 2>/dev/null | grep -qi minio; then
    export MC_CONFIG_DIR="$WORK/mc"
    step "mc: alias set" mc alias set vh "$EP" "$AK" "$SK" --api S3v4 --path off
    step "mc: mb" mc mb vh/mcvh
    step "mc: the requests went to mcvh.localhost" bash -c "mc --debug ls vh/mcvh 2>&1 | grep -qi 'Host: mcvh.localhost:$PORT'"
    step "mc: cp -r and ls -r" bash -c "mc cp -r '$WORK/src/' vh/mcvh/tree/ && mc ls -r vh/mcvh | grep -q 'tree/d/f3.txt'"
    step "mc: cp of 12 MiB and cat back" bash -c "mc cp '$WORK/big.bin' vh/mcvh/big.bin && mc cat vh/mcvh/big.bin | cmp - '$WORK/big.bin'"
    step "mc: share download, read with curl" bash -c "u=\$(mc share download --json vh/mcvh/tree/d/f1.txt | python3 -c 'import sys,json; print(json.load(sys.stdin)[\"share\"])') && case \"\$u\" in http://mcvh.localhost:$PORT/*) ;; *) exit 1 ;; esac && curl -sf \"\$u\" | grep -q 'file 1'"
    step "mc: rb --force" mc rb --force vh/mcvh
    unset MC_CONFIG_DIR
else
    echo "  SKIP: mc is not installed"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
