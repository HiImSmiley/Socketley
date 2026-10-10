#!/usr/bin/env bash
# Integration test: a value a client puts in a query never becomes a header line of its own.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * response-content-disposition (and the other response-* overrides) copied
#     into the answer with a CR LF in it, which ends the header and starts one
#     the client chose: a Set-Cookie on the storage's own origin, where its web
#     interface lives, or a body of its own after an empty line
#   * the same through a HEAD, and through a GET answered again from the hot
#     object cache, which renders its headers apart from the first answer
#   * an override without control characters no longer honoured, which a fix
#     that dropped them all would do
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

daemon_isolate stghdr
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1960))
trap 'daemon_stop' EXIT

echo "=== Integration: a storage answer takes no header from a query ==="

daemon_start "$BIN"
KEY=AKIAHEADERINJECT0000
SEC=headerinjectsecretheaderinject00
"$BIN" create storage hdr -p "$P" --dir "$T/stg" --access-key "$KEY" --secret-key "$SEC" -s >/dev/null 2>&1
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$P/" && break; sleep 0.1; done
S() { curl -s -m 10 --user "$KEY:$SEC" --aws-sigv4 'aws:amz:us-east-1:s3' "$@"; }
S -o /dev/null -X PUT "http://127.0.0.1:$P/bkt"
printf 'hello\n' | S -o /dev/null -X PUT --data-binary @- "http://127.0.0.1:$P/bkt/k"

Q='response-content-disposition=attachment%0D%0ASet-Cookie:%20sid%3Devil'
for round in first again; do
    head=$(S -s -D - -o /dev/null "http://127.0.0.1:$P/bkt/k?$Q" | tr -d '\r')
    expect "a CR LF in an override starts no header of its own ($round GET)" "$(grep -ci '^set-cookie' <<<"$head")" 0
    expect "and the object is still answered ($round GET)" "$(head -1 <<<"$head" | awk '{print $2}')" 200
done
head=$(S -s -I "http://127.0.0.1:$P/bkt/k?$Q" | tr -d '\r')
expect "nor through a HEAD" "$(grep -ci '^set-cookie' <<<"$head")" 0
body=$(S -s "http://127.0.0.1:$P/bkt/k?response-content-disposition=x%0D%0A%0D%0A%3Cscript%3E")
expect "nor a body of its own after an empty line" "$body" "hello"
head=$(S -s -D - -o /dev/null "http://127.0.0.1:$P/bkt/k?response-content-disposition=attachment%3B%20filename%3Da.txt" | tr -d '\r')
expect "an override without control characters is still honoured" \
    "$(grep -i '^content-disposition' <<<"$head")" "Content-Disposition: attachment; filename=a.txt"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
