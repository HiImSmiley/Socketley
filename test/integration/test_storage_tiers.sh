#!/usr/bin/env bash
# Integration test: a lifecycle moves versions to a tier, another S3 endpoint named as a storage class, and every read
# of them goes there.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a transition to a class no tier names taken, or the rule not read back
#   * a version due not moved, moved under a key the sweep cannot read back,
#     or moved while its file here keeps its bytes
#   * a moved version answered, listed or read back other than it was written:
#     its class, ETag, size, bytes, a range, a part, a noncurrent version
#   * a copy of a moved version made from bytes that are not here
#   * what a deleted version left at the tier never swept
#   * a restart that loses where the bytes went, or a tiers file that does not
#     parse taken
# suite: isolated
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
export BIN
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgtiers
PS=$((SL_PORT_BASE+1991))
PT=$((SL_PORT_BASE+1993))
export ADMIN_AK="AKIATIERSADMIN000001"
export ADMIN_SK="tiers/admin/secret"
# A day of four seconds, so a transition after a day comes in a test's time.
export SOCKETLEY_STORAGE_LIFECYCLE_DAY_SECS=4

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

cleanup() {
    for r in tsrc ttier tbad; do "$BIN" stop "$r" >/dev/null 2>&1 || true; done
    sleep 0.2
    for r in tsrc ttier tbad; do "$BIN" remove "$r" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
wait_up() {
    for _ in $(seq 1 100); do [ "$(code "http://127.0.0.1:$1/")" != 000 ] && return 0; sleep 0.1; done
    return 1
}

echo "=== Integration: storage tiers ==="
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 is required"; exit 1; }
python3 -c "import boto3" 2>/dev/null || { echo "  SKIP: boto3 is required"; exit 0; }
daemon_start "$BIN"
T="$SOCKETLEY_TMPD"
printf '[admin]\n%s:%s\nadmin = true\n' "$ADMIN_AK" "$ADMIN_SK" > "$T/creds"

echo "COLD ftp://127.0.0.1/ us-east-1 a b" > "$T/badtiers"
out=$("$BIN" create storage tbad -p "$PS" --dir "$T/bad" --credentials "$T/creds" --tiers "$T/badtiers" 2>&1)
[ $? -ne 0 ] && ok "a tiers file that does not parse is refused" || bad "a tiers file that does not parse is refused" "$out"
"$BIN" remove tbad >/dev/null 2>&1

"$BIN" create storage ttier -p "$PT" --dir "$T/tier" --credentials "$T/creds" -s >/dev/null 2>&1 \
    || { echo "  FAIL [create]: the tier was not created"; exit 1; }
echo "COLD http://127.0.0.1:$PT/cold/arch us-east-1 $ADMIN_AK $ADMIN_SK" > "$T/tiers"
"$BIN" create storage tsrc -p "$PS" --dir "$T/src" --credentials "$T/creds" --tiers "$T/tiers" --compress 1s -s \
    >/dev/null 2>&1 || { echo "  FAIL [create]: the source was not created"; exit 1; }
wait_up "$PT" || bad "the tier comes up" "no answer on $PT"
wait_up "$PS" || bad "the source comes up" "no answer on $PS"

out=$(python3 "$HERE/lib_storage_tiers.py" "tsrc:$PS" "$T/src" "$PT" 2>&1); rc=$?
echo "$out" | grep -E '^  (PASS|FAIL)'
p=$(echo "$out" | grep -c '^  PASS'); f=$(echo "$out" | grep -c '^  FAIL')
PASS=$((PASS+p)); FAIL=$((FAIL+f)); TOTAL=$((TOTAL+p+f))
[ "$rc" -ne 0 ] && echo "$out" | grep -vE '^  (PASS|FAIL)' | tail -15
[ "$rc" -ne 0 ] && [ "$f" -eq 0 ] && bad "the tiers half ran" "exit $rc: $out"

"$BIN" stop tsrc >/dev/null 2>&1; "$BIN" start tsrc >/dev/null 2>&1
wait_up "$PS" || bad "the source comes back" "no answer on $PS"
got=$(python3 - "$PS" <<'PY'
import os, sys, boto3
from botocore.config import Config
c = boto3.client("s3", endpoint_url="http://127.0.0.1:%s" % sys.argv[1], region_name="us-east-1",
                 aws_access_key_id=os.environ["ADMIN_AK"], aws_secret_access_key=os.environ["ADMIN_SK"],
                 config=Config(s3={"addressing_style": "path"}))
h = c.head_object(Bucket="hot", Key="m")
print(h.get("StorageClass"), len(c.get_object(Bucket="hot", Key="m")["Body"].read()))
PY
)
[ "$got" = "COLD $((10 << 20))" ] && ok "a moved object is read from the tier after a restart" \
    || bad "a moved object is read from the tier after a restart" "$got"

[ "$FAIL" -ne 0 ] && grep -iE "tier|storage:" "$SOCKETLEY_DLOG" | tail -8
[ "$FAIL" -ne 0 ] && "$BIN" stats ttier 2>&1 | grep -E '^(requests|gets|deletes|lists|client_errors|error_)' | tr '\n' ' '
[ "$FAIL" -ne 0 ] && "$BIN" stats tsrc 2>&1 | grep -E '^tier_' | tr '\n' ' '
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
