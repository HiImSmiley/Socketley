#!/usr/bin/env bash
# Integration test: --tls-offloaded counts a connection from a proxy that terminated TLS as one made over TLS, for
# SSE-C and for aws:SecureTransport, and a connection from anywhere else as what it is.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * SSE-C over plain HTTP taken from an address no flag names, or refused
#     from the proxy's
#   * aws:SecureTransport false for the proxy's connections, or true for others
#   * a flag value that is no address taken
# suite: isolated
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
export BIN
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgoffload
P1=$((SL_PORT_BASE+1895))
P2=$((SL_PORT_BASE+1897))
export AK="AKIAOFFLOADADMIN0001" SK="offload/admin/secret"

cleanup() {
    for r in off1 off2 offx; do "$BIN" stop "$r" >/dev/null 2>&1; "$BIN" remove "$r" >/dev/null 2>&1; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: storage --tls-offloaded ==="
python3 -c "import boto3" 2>/dev/null || { echo "  SKIP: boto3 is required"; exit 0; }
daemon_start "$BIN"
T="$SOCKETLEY_TMPD"
printf '[admin]\n%s:%s\nadmin = true\n' "$AK" "$SK" > "$T/creds"
PASS=0; FAIL=0
out=$("$BIN" create storage offx -p "$P1" --dir "$T/x" --credentials "$T/creds" --tls-offloaded 10.0.0.300 2>&1)
if [ $? -ne 0 ] && echo "$out" | grep -q 'tls-offloaded'; then PASS=$((PASS+1)); echo "  PASS: an entry that is no address is refused"
else FAIL=$((FAIL+1)); echo "  FAIL [an entry that is no address is refused]: $out"; fi
"$BIN" remove offx >/dev/null 2>&1
"$BIN" create storage off1 -p "$P1" --dir "$T/one" --credentials "$T/creds" --tls-offloaded 10.9.0.0/16,127.0.0.1 -s \
    >/dev/null 2>&1 || { echo "  FAIL [create]: the runtime was not created"; exit 1; }
"$BIN" create storage off2 -p "$P2" --dir "$T/two" --credentials "$T/creds" --tls-offloaded 10.9.0.0/16 -s >/dev/null 2>&1 \
    || { echo "  FAIL [create]: the second runtime was not created"; exit 1; }
for p in "$P1" "$P2"; do for _ in $(seq 1 100); do curl -s -o /dev/null "http://127.0.0.1:$p/" && break; sleep 0.1; done; done

python3 - "$P1" "$P2" "$PASS" "$FAIL" <<'PY'
import base64, hashlib, json, os, sys
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
p1, p2 = int(sys.argv[1]), int(sys.argv[2])
passed, failed = int(sys.argv[3]), int(sys.argv[4])
def mk(port):
    return boto3.client("s3", endpoint_url="http://127.0.0.1:%d" % port, region_name="us-east-1",
                        aws_access_key_id=os.environ["AK"], aws_secret_access_key=os.environ["SK"],
                        config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1}))
def check(name, got, want):
    global passed, failed
    ok = got == want
    passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)
    print(("  PASS: " if ok else "  FAIL [%s]: " % name) + (name if ok else "got %r, want %r" % (got, want)), flush=True)
def code(f):
    try:
        f()
        return "ok"
    except ClientError as e:
        return e.response["Error"]["Code"]
key = os.urandom(32)
sse = {"SSECustomerAlgorithm": "AES256", "SSECustomerKey": base64.b64encode(key).decode(),
       "SSECustomerKeyMD5": base64.b64encode(hashlib.md5(key).digest()).decode()}
for port, trusted in ((p1, True), (p2, False)):
    c = mk(port)
    c.create_bucket(Bucket="off")
    what = "from the proxy" if trusted else "from an address no flag names"
    check("SSE-C over plain HTTP %s" % what,
          code(lambda: c.put_object(Bucket="off", Key="k", Body=b"secret", **sse)), "ok" if trusted else "InvalidRequest")
    if trusted:
        check("and reads back with its key", c.get_object(Bucket="off", Key="k", **sse)["Body"].read(), b"secret")
    c.put_bucket_policy(Bucket="off", Policy=json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": ["arn:aws:s3:::off", "arn:aws:s3:::off/*"],
        "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}))
    check("aws:SecureTransport is %s %s" % ("true" if trusted else "false", what),
          code(lambda: c.list_objects_v2(Bucket="off")), "ok" if trusted else "AccessDenied")
print("  Results: %d/%d passed (%d failed)" % (passed, passed + failed, failed))
sys.exit(failed)
PY
rc=$?
[ "$rc" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$rc"
