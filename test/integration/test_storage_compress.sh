#!/usr/bin/env bash
# Integration test: --compress stores cold versions compressed where they lie, and every read gives back their bytes.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a version that should be compressed left, or one that should not be
#     (incompressible, small, multipart) rewritten
#   * a byte, a range across a chunk or a window, a copy, a noncurrent version
#     or an overwrite read back other than it was written
#   * a file that did not shrink, or an ETag or size that changed
#   * a compressed file whose bytes changed not found by the scrub
#   * a restart that loses what was compressed, or a flag value that is no
#     duration taken
#   * the counters missing from stats and from /metrics
# suite: isolated
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
export BIN
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgcompress
exec 2>&1
unset SOCKETLEY_CONFIG

P=$((SL_PORT_BASE+1981))
MPORT=$((SL_PORT_BASE+1983))
export ADMIN_AK="AKIACOMPRESSADMIN001"
export ADMIN_SK="compress/admin/secret"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

cleanup() {
    "$BIN" stop cz >/dev/null 2>&1 || true
    "$BIN" remove cz >/dev/null 2>&1 || true
    "$BIN" remove czx >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
wait_up() {
    for _ in $(seq 1 100); do [ "$(code "http://127.0.0.1:$1/")" != 000 ] && return 0; sleep 0.1; done
    return 1
}

echo "=== Integration: storage compression ==="
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 is required"; exit 1; }
python3 -c "import boto3" 2>/dev/null || { echo "  SKIP: boto3 is required"; exit 0; }
mkdir -p "$HOME/.config/socketley"
printf 'config = {\n    metrics_port = %s\n}\n' "$MPORT" > "$HOME/.config/socketley/config.lua"
daemon_start "$BIN"
T="$SOCKETLEY_TMPD"
printf '[admin]\n%s:%s\nadmin = true\n' "$ADMIN_AK" "$ADMIN_SK" > "$T/creds"

out=$("$BIN" create storage czx -p "$P" --dir "$T/x" --credentials "$T/creds" --compress soon 2>&1)
[ $? -eq 1 ] && echo "$out" | grep -q "duration" && ok "--compress refuses what is no duration" \
    || bad "--compress refuses what is no duration" "$out"

"$BIN" create storage cz -p "$P" --dir "$T/data" --credentials "$T/creds" --shards 2 --compress 1s --scrub 2s -s \
    >/dev/null 2>&1 || { echo "  FAIL [create]: the runtime was not created"; exit 1; }
wait_up "$P" || bad "the runtime comes up" "no answer on $P"
shown=$("$BIN" show cz 2>&1)
echo "$shown" | grep -q '"compress": 1' && ok "show names the age" || bad "show names the age" "$shown"

out=$(python3 "$HERE/lib_storage_compress.py" cz "$P" "$T/data" 2>&1); rc=$?
echo "$out" | grep -E '^  (PASS|FAIL)'
p=$(echo "$out" | grep -c '^  PASS'); f=$(echo "$out" | grep -c '^  FAIL')
PASS=$((PASS+p)); FAIL=$((FAIL+f)); TOTAL=$((TOTAL+p+f))
[ "$rc" -ne 0 ] && echo "$out" | grep -vE '^  (PASS|FAIL)' | tail -15
[ "$rc" -ne 0 ] && [ "$f" -eq 0 ] && bad "the compression half ran" "exit $rc: $out"

metrics=$(printf 'GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | timeout 8 nc 127.0.0.1 "$MPORT" 2>/dev/null)
n=$(awk '$1 ~ /^socketley_storage_compressed_objects_total/ {print $2; exit}' <<<"$metrics")
[ -n "$n" ] && [ "$n" -ge 5 ] 2>/dev/null && ok "/metrics counts the versions compressed" \
    || bad "/metrics counts the versions compressed" "$(echo "$metrics" | grep -c socketley_storage) storage lines, value '$n'"
grep -q '^socketley_storage_scrub_passes_total' <<<"$metrics" && ok "/metrics has the scrub's counters" \
    || bad "/metrics has the scrub's counters" "$(echo "$metrics" | grep scrub | head -3)"

# A restart reads what was compressed, and the passes go on from where they were rather than over every version.
# A stats that fails or names no counter reads "none", never a 0 that would pass below.
before=$("$BIN" stats cz 2>&1 | awk -F: '$1=="compressed_objects"{s+=$2; n++} END{print n ? s+0 : "none"}')
"$BIN" stop cz >/dev/null 2>&1; "$BIN" start cz >/dev/null 2>&1
wait_up "$P" || bad "the runtime comes back" "no answer on $P"
got=$(python3 - "$P" <<'PY'
import os, sys, boto3
from botocore.config import Config
c = boto3.client("s3", endpoint_url="http://127.0.0.1:%s" % sys.argv[1], region_name="us-east-1",
                 aws_access_key_id=os.environ["ADMIN_AK"], aws_secret_access_key=os.environ["ADMIN_SK"],
                 config=Config(s3={"addressing_style": "path"}))
print(len(c.get_object(Bucket="logs", Key="copied")["Body"].read()))
PY
)
[ "$got" = $((3 << 20)) ] && ok "a compressed object reads back whole after a restart" \
    || bad "a compressed object reads back whole after a restart" "$got bytes"
sleep 3
after=$("$BIN" stats cz 2>&1 | awk -F: '$1=="compressed_objects"{s+=$2; n++} END{print n ? s+0 : "none"}')
[ "$after" = 0 ] && [ "$before" != none ] && [ "$before" -gt 0 ] && ok "and the passes after it compress nothing again" \
    || bad "and the passes after it compress nothing again" "$after compressed after a restart, $before before"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
