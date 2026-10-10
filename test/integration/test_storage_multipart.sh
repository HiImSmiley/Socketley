#!/usr/bin/env bash
# Integration test: multipart uploads on the storage runtime.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
# CreateMultipartUpload, UploadPart, UploadPartCopy, CompleteMultipartUpload,
# AbortMultipartUpload, ListParts and ListMultipartUploads through boto3 with
# credentials -- including boto3's own transfer manager forced into multipart
# by a low threshold, which is what people run -- and the refusals a client is
# written to expect: InvalidPart, InvalidPartOrder, EntityTooSmall,
# NoSuchUpload, InvalidArgument, BadDigest, MalformedXML, BucketNotEmpty.
# The ETag of the object is md5 of the part md5s with -N, and a checksum taken
# per part becomes the composite checksum of the whole.
#
# And what a stop leaves: an open upload and its parts survive a stop and a
# start, and a worker killed while a part is arriving leaves the whole parts
# and no half of the one that was cut.  An upload left open past --mpu-expire
# is aborted, at run time and at the next start.  Parts count against
# --max-bytes and give it back.  A big object is assembled from big parts with
# the worker's memory read.
#
# The assertions live in lib_storage_multipart.py, which prints one line each.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
export BIN
HERE=$(cd "$(dirname "$0")" && pwd)
export HERE
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgmpu

P1=$((SL_PORT_BASE+1581))
P2=$((SL_PORT_BASE+1582))
P3=$((SL_PORT_BASE+1583))
P4=$((SL_PORT_BASE+1584))
export AK="AKIATESTACCESSKEY01"
export SK="test/secret+key/for.storage.sigv4"
export MPU_STATE="$SOCKETLEY_TMPD/state.json"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
has() { case "$1" in *"$2"*) return 0;; *) return 1;; esac; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }
contains() { if has "$2" "$3"; then ok "$1"; else bad "$1" "no '$3' in: $2"; fi; }

cleanup() {
    for r in mp mpe mpq mpl; do "$BIN" stop "$r" >/dev/null 2>&1 || true; done
    sleep 0.3
    for r in mp mpe mpq mpl; do "$BIN" remove "$r" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
wait_up() {   # port -- any answer at all, since the runtime refuses an anonymous GET
    for _ in $(seq 1 100); do
        [ "$(code "http://127.0.0.1:$1/")" != 000 ] && return 0
        sleep 0.1
    done
    return 1
}
worker_pid() {
    local p=""
    for _ in $(seq 1 30); do
        p=$("$BIN" stats "$1" 2>/dev/null | sed -n 's/^pid://p')
        [ -n "$p" ] && [ -d "/proc/$p" ] && break
        sleep 0.2
    done
    echo "$p"
}
lib() {   # runtime port dir mode
    RUNTIME=$1 python3 "$HERE/lib_storage_multipart.py" "$2" "$3" "$4"
}
run_half() {   # label runtime port dir mode
    lib "$2" "$3" "$4" "$5"
    local rc=$?
    if [ "$rc" -ne 0 ]; then bad "$1" "$rc assertions failed"; else ok "$1"; fi
}

echo "=== Integration: multipart uploads ==="
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 is required"; exit 1; }
python3 -c "import boto3" 2>/dev/null || { echo "  SKIP: boto3 is required"; exit 0; }
daemon_start "$BIN"

DATA="$SOCKETLEY_TMPD/objects"
if ! "$BIN" create storage mp -p "$P1" --dir "$DATA" --access-key "$AK" --secret-key "$SK" -s >/dev/null 2>&1; then
    echo "  FAIL [create]: the runtime was not created"
    exit 1
fi
wait_up "$P1" || bad "the runtime comes up" "no answer on $P1"

run_half "the main half passed" mp "$P1" "$DATA" main

# ── a stop and a start ──────────────────────────────────────────────────────
"$BIN" stop mp >/dev/null 2>&1
sleep 0.5
"$BIN" start mp >/dev/null 2>&1
wait_up "$P1" || bad "the runtime comes back" "no answer on $P1"
run_half "the half after a stop and a start passed" mp "$P1" "$DATA" resume

# ── a kill while a part is arriving ─────────────────────────────────────────
python3 - "$P1" "$(python3 -c 'import json,os;print(json.load(open(os.environ["MPU_STATE"]))["u2"])')" <<'PYEOF' &
import os, socket, sys, time
sys.path.insert(0, os.environ["HERE"])
import lib_s3_signing as sig
port, uid = int(sys.argv[1]), sys.argv[2]
host = "127.0.0.1:%d" % port
body = b""
s = sig.sign("PUT", "/mpb/resume/two", "partNumber=3&uploadId=" + uid, host, os.environ["AK"], os.environ["SK"], "UNSIGNED-PAYLOAD")
hdrs = "".join("%s: %s\r\n" % kv for kv in s.headers.items())
c = socket.create_connection(("127.0.0.1", port))
c.sendall(("PUT /mpb/resume/two?partNumber=3&uploadId=%s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n%s\r\n" %
           (uid, host, 6 << 20, hdrs)).encode() + os.urandom(3 << 20))
time.sleep(60)
PYEOF
CUT_BG=$!
sleep 2
wpid=$(worker_pid mp)
if [ -n "$wpid" ]; then kill -9 "$wpid" 2>/dev/null
else bad "the worker is killed mid-upload" "stats gave no worker pid, so nothing was killed"; fi
kill "$CUT_BG" 2>/dev/null; wait "$CUT_BG" 2>/dev/null
for _ in $(seq 1 100); do
    np=$(worker_pid mp)
    [ -n "$np" ] && [ "$np" != "$wpid" ] && wait_up "$P1" && break
    sleep 0.2
done
if [ -n "$wpid" ] && [ -n "${np:-}" ] && [ "$np" != "$wpid" ]; then ok "the supervisor replaces the killed worker"; else bad "the supervisor replaces the killed worker" "old $wpid new ${np:-none}"; fi
run_half "the half after the kill passed" mp "$P1" "$DATA" killed

# ── expiry ──────────────────────────────────────────────────────────────────
EDATA="$SOCKETLEY_TMPD/expobjects"
if ! "$BIN" create storage mpe -p "$P2" --dir "$EDATA" --access-key "$AK" --secret-key "$SK" --mpu-expire 4s -s >/dev/null 2>&1; then
    bad "create with --mpu-expire" "the runtime was not created"
else
    wait_up "$P2" || bad "the expiring runtime comes up" "no answer on $P2"
    contains "show names the expiry" "$("$BIN" show mpe 2>&1)" '"mpu_expire": 4'
    RUNTIME=mpe run_half "the expiry half passed" mpe "$P2" "$EDATA" expire
    # An upload begun before a stop that outlives the expiry is gone at the next start.
    "$BIN" stop mpe >/dev/null 2>&1
    sleep 6
    "$BIN" start mpe >/dev/null 2>&1
    wait_up "$P2" || bad "the expiring runtime comes back" "no answer on $P2"
    run_half "the half after the expiry passed a stop passed" mpe "$P2" "$EDATA" reaped
fi

# ── the quota ───────────────────────────────────────────────────────────────
QDATA="$SOCKETLEY_TMPD/quotaobjects"
if ! "$BIN" create storage mpq -p "$P3" --dir "$QDATA" --access-key "$AK" --secret-key "$SK" --max-bytes 12M -s >/dev/null 2>&1; then
    bad "create with --max-bytes" "the runtime was not created"
else
    wait_up "$P3" || bad "the quota runtime comes up" "no answer on $P3"
    run_half "the quota half passed" mpq "$P3" "$QDATA" quota
fi

# ── a big object ────────────────────────────────────────────────────────────
LDATA="$SOCKETLEY_TMPD/largeobjects"
parts=${SOCKETLEY_STORAGE_MPU_PARTS:-6}
part_mib=${SOCKETLEY_STORAGE_MPU_PART_MIB:-64}
free_mib=$(df -Pm "$SOCKETLEY_TMPD" | awk 'NR==2 {print $4}')
need_mib=$((parts * part_mib * 3))
if [ "${free_mib:-0}" -lt "$need_mib" ] && [ -n "${SOCKETLEY_STORAGE_MPU_PARTS:-}${SOCKETLEY_STORAGE_MPU_PART_MIB:-}" ]; then
    # A size asked for by name is a run that wants the big object, so not running it is a failure.
    bad "the big object asked for runs" "it needs $need_mib MiB free under $SOCKETLEY_TMPD and has ${free_mib:-0}"
elif [ "${free_mib:-0}" -lt "$need_mib" ]; then
    echo "  SKIP: the big object needs $need_mib MiB free under $SOCKETLEY_TMPD and has ${free_mib:-0}; its half is not run"
elif ! "$BIN" create storage mpl -p "$P4" --dir "$LDATA" --access-key "$AK" --secret-key "$SK" -s >/dev/null 2>&1; then
    bad "create for the big object" "the runtime was not created"
else
    wait_up "$P4" || bad "the big-object runtime comes up" "no answer on $P4"
    WPID=$(worker_pid mpl)
    if [ -z "$WPID" ]; then bad "stats names the worker" "no pid"; else
        WPID=$WPID run_half "the big-object half passed" mpl "$P4" "$LDATA" large
    fi
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
