#!/usr/bin/env bash
# Integration test: a user's own policy weighs aws:SourceIp against the address the request came from.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * an IpAddress condition in a credentials-file user's policy evaluated
#     before the client's address was looked up, so a Deny for a network lets
#     a request from it through
#   * the same with NotIpAddress, where the empty address is outside every
#     network and a Deny meant for strangers refuses the user at home
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate stgip
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1961))
trap 'daemon_stop' EXIT

echo "=== Integration: a user's policy sees the client's address ==="

daemon_start "$BIN"
OWN=AKIAIPPOLICYOWNER000; OSEC=ippolicyownersecretippolicyowner
CAR=AKIAIPPOLICYCAROL000; CSEC=ippolicycarolsecretippolicycarol
DAN=AKIAIPPOLICYDAN00000; DSEC=ippolicydansecretippolicydan0000
mkdir -p "$T/conf"
cat > "$T/conf/creds" <<EOF
$OWN:$OSEC

[carol]
policy = carol.json
$CAR:$CSEC

[dan]
policy = dan.json
$DAN:$DSEC
EOF
# Carol may read, except from loopback; Dan may read, except from anywhere but loopback.
cat > "$T/conf/carol.json" <<'EOF'
{"Version": "2012-10-17", "Statement": [
  {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::ipb/*"},
  {"Effect": "Deny", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::ipb/*",
   "Condition": {"IpAddress": {"aws:SourceIp": "127.0.0.0/8"}}}]}
EOF
cat > "$T/conf/dan.json" <<'EOF'
{"Version": "2012-10-17", "Statement": [
  {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::ipb/*"},
  {"Effect": "Deny", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::ipb/*",
   "Condition": {"NotIpAddress": {"aws:SourceIp": "127.0.0.0/8"}}}]}
EOF
"$BIN" create storage ip -p "$P" --dir "$T/stg" --credentials "$T/conf/creds" -s >/dev/null 2>&1
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$P/" && break; sleep 0.1; done
as() { local k=$1 s=$2; shift 2; curl -s --user "$k:$s" --aws-sigv4 'aws:amz:us-east-1:s3' "$@"; }
as "$OWN" "$OSEC" -o /dev/null -X PUT "http://127.0.0.1:$P/ipb"
printf 'x' | as "$OWN" "$OSEC" -o /dev/null -X PUT --data-binary @- "http://127.0.0.1:$P/ipb/o"

expect "a Deny for loopback refuses a user reading from loopback" \
    "$(as "$CAR" "$CSEC" -o /dev/null -w '%{http_code}' "http://127.0.0.1:$P/ipb/o")" 403
expect "and a Deny for everywhere else does not refuse one at home" \
    "$(as "$DAN" "$DSEC" -o /dev/null -w '%{http_code}' "http://127.0.0.1:$P/ipb/o")" 200

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
