#!/usr/bin/env bash
# Integration test: the storage runtime authenticates with AWS Signature V4.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
# A runtime with --access-key/--secret-key serves only requests signed with
# them: through boto3 (which is what people run) and through a signer of our
# own (for the requests boto3 will not send -- a chosen clock, a payload hash
# that is wrong, signed chunks with a trailer, an aws-chunked body inside
# Transfer-Encoding: chunked).  Every x-amz-content-sha256 mode is verified
# against the body as it streams, presigned GET/PUT/HEAD/DELETE are honoured
# and refused as S3 does, checksums are taken and returned, and each failure
# is answered with the S3 error code a client is written to expect.
#
# --credentials FILE holds several pairs and is re-read when it changes.  A
# runtime with credentials and --anonymous serves both kinds of request.
#
# The assertions live in lib_storage_auth.py, which prints one line each.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
export BIN
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgauth

P1=$((SL_PORT_BASE+1571))
P2=$((SL_PORT_BASE+1572))
P3=$((SL_PORT_BASE+1573))
P4=$((SL_PORT_BASE+1574))
export AK="AKIATESTACCESSKEY01"
export SK="test/secret+key/for.storage.sigv4"
export CREDFILE="$SOCKETLEY_TMPD/credentials"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
has() { case "$1" in *"$2"*) return 0;; *) return 1;; esac; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }
contains() { if has "$2" "$3"; then ok "$1"; else bad "$1" "no '$3' in: $2"; fi; }

cleanup() {
    for r in sig cred both; do "$BIN" stop "$r" >/dev/null 2>&1 || true; done
    sleep 0.3
    for r in sig cred both; do "$BIN" remove "$r" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
wait_up() {   # port -- any answer at all, since a signed runtime refuses an anonymous GET
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

echo "=== Integration: the storage runtime authenticates with SigV4 ==="
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 is required"; exit 1; }
python3 -c "import boto3, requests" 2>/dev/null || { echo "  SKIP: boto3 and requests are required"; exit 0; }
daemon_start "$BIN"

# ── refusals ────────────────────────────────────────────────────────────────
out=$("$BIN" create storage r1 -p "$P4" --dir "$SOCKETLEY_TMPD/r1" --access-key "$AK" 2>&1); rc=$?
expect "an access key with no secret is refused" "$rc" 1
contains "and says the two go together" "$out" "go together"
printf 'this line has no colon\n' > "$SOCKETLEY_TMPD/badcreds"
out=$("$BIN" create storage r2 -p "$P4" --dir "$SOCKETLEY_TMPD/r2" --credentials "$SOCKETLEY_TMPD/badcreds" 2>&1); rc=$?
expect "a credentials file that does not parse is refused" "$rc" 1
contains "and names the line" "$out" "line 1"
out=$("$BIN" create storage r3 -p "$P4" --dir "$SOCKETLEY_TMPD/r3" --credentials "$SOCKETLEY_TMPD/nosuchfile" 2>&1); rc=$?
expect "a credentials file that is not there is refused" "$rc" 1
out=$("$BIN" create storage r4 -p "$P4" --dir "$SOCKETLEY_TMPD/r4" --mpu-expire abc --anonymous 2>&1); rc=$?
expect "--mpu-expire with a value that is not a duration is refused" "$rc" 1
: > "$SOCKETLEY_TMPD/emptycreds"
out=$("$BIN" create storage r5 -p "$P4" --dir "$SOCKETLEY_TMPD/r5" --credentials "$SOCKETLEY_TMPD/emptycreds" 2>&1); rc=$?
expect "a credentials file holding none is refused" "$rc" 1
out=$("$BIN" ls 2>&1)
if has "$out" "r1" || has "$out" "r2" || has "$out" "r3"; then bad "a refused create leaves nothing behind" "$out"; else ok "a refused create leaves nothing behind"; fi

# ── a runtime with one key pair ─────────────────────────────────────────────
if ! "$BIN" create storage sig -p "$P1" --dir "$SOCKETLEY_TMPD/objsig" --access-key "$AK" --secret-key "$SK" -s >/dev/null 2>&1; then
    bad "create with --access-key and --secret-key" "the runtime was not created"
else
    wait_up "$P1" || bad "the signed runtime comes up" "no answer on $P1"
    expect "an anonymous request to a signed runtime is 403" "$(code "http://127.0.0.1:$P1/")" 403
    WPID=$(worker_pid sig)
    [ -n "$WPID" ] || bad "stats names the worker" "no pid"
    python3 "$HERE/lib_storage_auth.py" "$P1" "$SOCKETLEY_TMPD/objsig" "${WPID:-0}" signed | tee "$SOCKETLEY_TMPD/signed.out"
    rc=${PIPESTATUS[0]}
    if [ "$rc" -ne 0 ]; then bad "the signed half" "$rc assertions failed"; else ok "the signed half passed"; fi

    shown=$("$BIN" show sig 2>&1)
    contains "show names the access key" "$shown" "\"access_key\": \"$AK\""

    # The keys come back after a stop and a start.
    "$BIN" stop sig >/dev/null 2>&1
    sleep 0.5
    "$BIN" start sig >/dev/null 2>&1
    wait_up "$P1" || bad "the signed runtime comes back" "no answer on $P1"
    got=$(python3 - "$P1" <<'PYEOF'
import boto3, os, sys
from botocore.config import Config
def lb(secret):
    c = boto3.client("s3", endpoint_url="http://127.0.0.1:%s" % sys.argv[1], aws_access_key_id=os.environ["AK"],
                     aws_secret_access_key=secret, region_name="us-east-1", config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1}))
    try:
        return [b["Name"] for b in c.list_buckets()["Buckets"]]
    except Exception as e:
        return type(e).__name__
print(lb(os.environ["SK"]), lb("wrong"))
PYEOF
)
    expect "after a stop and a start the key still signs and a wrong one still does not" "$got" "['authb'] ClientError"

    # The keys are not something an import can swap under a serving runtime.
    "$BIN" show sig > "$SOCKETLEY_TMPD/sig.json" 2>&1
    sed -i "s|\"secret_key\": \"[^\"]*\"|\"secret_key\": \"another-secret\"|" "$SOCKETLEY_TMPD/sig.json"
    out=$("$BIN" import sig < "$SOCKETLEY_TMPD/sig.json" 2>&1); rc=$?
    expect "import of another secret into a running runtime is refused" "$rc" 1
    contains "and says so" "$out" "while running"
    out=$("$BIN" edit sig --secret-key nope 2>&1); rc=$?
    expect "edit --secret-key is refused" "$rc" 1
fi

# ── several keys in a file that is rewritten under the runtime ──────────────
printf '# storage credentials\n\nAKA:secretA\nAKB:secretB\nAKC:sec:ret:c\n' > "$CREDFILE"
chmod 600 "$CREDFILE"
if ! "$BIN" create storage cred -p "$P2" --dir "$SOCKETLEY_TMPD/objcred" --credentials "$CREDFILE" -s >/dev/null 2>&1; then
    bad "create with --credentials" "the runtime was not created"
else
    wait_up "$P2" || bad "the credentials runtime comes up" "no answer on $P2"
    python3 "$HERE/lib_storage_auth.py" "$P2" "$SOCKETLEY_TMPD/objcred" 0 credfile
    rc=$?
    if [ "$rc" -ne 0 ]; then bad "the credentials-file half" "$rc assertions failed"; else ok "the credentials-file half passed"; fi
fi

# ── credentials and --anonymous ─────────────────────────────────────────────
if ! "$BIN" create storage both -p "$P3" --dir "$SOCKETLEY_TMPD/objboth" --access-key "$AK" --secret-key "$SK" --anonymous -s >/dev/null 2>&1; then
    bad "create with credentials and --anonymous" "the runtime was not created"
else
    wait_up "$P3" || bad "the mixed runtime comes up" "no answer on $P3"
    python3 "$HERE/lib_storage_auth.py" "$P3" "$SOCKETLEY_TMPD/objboth" 0 both
    rc=$?
    if [ "$rc" -ne 0 ]; then bad "the mixed half" "$rc assertions failed"; else ok "the mixed half passed"; fi
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
