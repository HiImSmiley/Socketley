#!/usr/bin/env bash
# suite: isolated -- a daemon, socket and port window of its own, so it runs beside the others
# Integration test: what a storage keeps under --dir is readable by its own account alone.
#
# ─── THE DEFECT (round 8b) ──────────────────────────────────────────────────
#
# Object bodies were written 0600, but each bucket's index (every key, its user metadata, tags and owner), its
# configuration files (policy, versioning, ...), the `created` marker and the folders holding them were 0644 and
# 0755.  Measured on dev 3b7db9690 under umask 022: private-hr/index.0 and private-hr/policy 644 in 518 folders
# anyone may enter, so any account on the machine read "salaries-2026-jane-doe.pdf", its x-amz-meta-employee and its
# tag, and who the bucket policy lets in.  New files are 0600 and new folders 0700 now, a --dir the runtime makes is
# 0700, and a bucket made before is narrowed to 0700 when the runtime starts.
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

daemon_isolate storage_modes
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1990))
trap 'daemon_stop' EXIT
umask 022

echo "=== Integration: a storage's files under --dir are its own ==="
daemon_start "$BIN"
KEY=AKIAMODESMODES000000; SEC=modessecretmodessecretmodessecre
"$BIN" create storage box -p "$P" --dir "$T/stg" --access-key "$KEY" --secret-key "$SEC" -s >/dev/null 2>&1
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$P/" && break; sleep 0.1; done
S() { curl -s --user "$KEY:$SEC" --aws-sigv4 'aws:amz:us-east-1:s3' "$@"; }
S -o /dev/null -X PUT "http://127.0.0.1:$P/private-hr"
S -o /dev/null -X PUT "http://127.0.0.1:$P/private-hr?versioning" \
  --data '<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>'
S -o /dev/null -X PUT "http://127.0.0.1:$P/private-hr?policy" --data '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam:::user/carol"]},"Action":"s3:GetObject","Resource":"arn:aws:s3:::private-hr/*"}]}'
S -o /dev/null -X PUT -H 'x-amz-meta-employee: Jane Doe' -H 'x-amz-tagging: reason=dismissal' --data 'body' \
  "http://127.0.0.1:$P/private-hr/salaries.pdf"
S -o /dev/null -X POST "http://127.0.0.1:$P/private-hr/big.bin?uploads"
sleep 1.5
expect "the object is there" "$(S "http://127.0.0.1:$P/private-hr/salaries.pdf")" body

others() { find "$1" \( -type f -perm /044 -o -type d -perm /055 \) -printf '%m %P\n' | sort | head -5 | tr '\n' ';'; }
expect "the --dir it made is its own" "$(stat -c %a "$T/stg")" 700
expect "no file or folder under it is open to the group or to others" "$(others "$T/stg")" ""

# A bucket made before, by a build that left it open, is narrowed when the runtime starts again.
"$BIN" stop box >/dev/null 2>&1
chmod 755 "$T/stg" "$T/stg/private-hr"; chmod 644 "$T/stg/private-hr/index.0" "$T/stg/private-hr/policy" 2>/dev/null
"$BIN" start box >/dev/null 2>&1
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$P/" && break; sleep 0.1; done
expect "an older bucket's folder is narrowed at start" "$(stat -c %a "$T/stg/private-hr")" 700
expect "and still serves what it holds" "$(S "http://127.0.0.1:$P/private-hr/salaries.pdf")" body

echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
