#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: --http answers a range only of the copy the client holds, and --http-cache answers one at all.
#
# What each part would catch:
#   * If-Range ignored: a download resumed after the file was replaced gets the new file's bytes appended to the old
#     file's, a corrupt file with a 206 (RFC 9110 13.1.5 says the whole file, under 200)
#   * a weak or a date validator taken as a match, where only the strong ETag this server sends names a copy
#   * --http-cache answering a Range with the whole file under 200, and its answers not saying Accept-Ranges
#   * the storage's GET the same way, by the object's ETag or Last-Modified
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }

echo "=== Integration: If-Range, and ranges from --http-cache ==="
daemon_isolate ifrange
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1975))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
daemon_start "$BIN"
mkdir -p "$T/www" "$T/cached"
head -c 300000 /dev/urandom > "$T/www/v.bin"
head -c 300000 /dev/urandom > "$T/cached/c.bin"
"$BIN" create server disk -p "$P" --http "$T/www" -s >/dev/null 2>&1
"$BIN" create server mem -p $((P+1)) --http "$T/cached" --http-cache -s >/dev/null 2>&1
for port in "$P" $((P+1)); do
    for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$port/" && break; sleep 0.1; done
done
U="http://127.0.0.1:$P/v.bin"
code_of() { curl -s -o "$T/b" -w '%{http_code}' "$@"; }
slice() { head -c $(($3 + 1)) "$1" | tail -c $(($3 - $2 + 1)) | sha256sum | cut -c1-16; }
sha() { sha256sum < "$1" | cut -c1-16; }

etag=$(curl -sI "$U" | tr -d '\r' | awk -F': ' 'tolower($1)=="etag"{print $2}')
expect "a range under the file's own ETag is that range" "$(code_of -r 1000-1999 -H "If-Range: $etag" "$U") $(sha "$T/b")" \
    "206 $(slice "$T/www/v.bin" 1000 1999)"
expect "under another ETag it is the whole file" "$(code_of -r 1000-1999 -H 'If-Range: "nope"' "$U") $(sha "$T/b")" \
    "200 $(sha "$T/www/v.bin")"
expect "a weak one never matches" "$(code_of -r 1000-1999 -H "If-Range: W/$etag" "$U")" "200"
expect "nor a date, since no Last-Modified was given" \
    "$(code_of -r 1000-1999 -H 'If-Range: Sun, 01 Nov 2026 00:00:00 GMT' "$U")" "200"
head -c 300000 /dev/urandom > "$T/www/v.bin.new"; mv "$T/www/v.bin.new" "$T/www/v.bin"
expect "a resume after the file was replaced gets the new file whole" \
    "$(code_of -r 150000- -H "If-Range: $etag" "$U") $(sha "$T/b")" "200 $(sha "$T/www/v.bin")"

C="http://127.0.0.1:$((P+1))/c.bin"
expect "--http-cache answers a range with that range" "$(code_of -r 5000-5999 "$C") $(sha "$T/b")" \
    "206 $(slice "$T/cached/c.bin" 5000 5999)"
got=$(curl -s -D - -o /dev/null "$C" | tr -d '\r' | grep -ci '^accept-ranges: bytes')
expect "and says Accept-Ranges on the whole file" "$got" "1"

"$BIN" create storage objects -p $((P+2)) --dir "$T/stg" --anonymous -s >/dev/null 2>&1
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$((P+2))/" && break; sleep 0.1; done
S="http://127.0.0.1:$((P+2))/bkt/o.bin"
curl -s -X PUT "http://127.0.0.1:$((P+2))/bkt" >/dev/null
head -c 300000 /dev/urandom > "$T/o1"; curl -s -X PUT --data-binary @"$T/o1" "$S" >/dev/null
hdr=$(curl -sI "$S" | tr -d '\r')
setag=$(awk -F': ' 'tolower($1)=="etag"{print $2}' <<<"$hdr"); sdate=$(awk -F': ' 'tolower($1)=="last-modified"{print $2}' <<<"$hdr")
expect "storage: a range under the object's ETag is that range" "$(code_of -r 100-199 -H "If-Range: $setag" "$S") $(sha "$T/b")" \
    "206 $(slice "$T/o1" 100 199)"
expect "storage: and under its Last-Modified" "$(code_of -r 100-199 -H "If-Range: $sdate" "$S")" "206"
expect "storage: under another ETag the whole object" "$(code_of -r 100-199 -H 'If-Range: "nope"' "$S") $(sha "$T/b")" \
    "200 $(sha "$T/o1")"
head -c 300000 /dev/urandom > "$T/o2"; curl -s -X PUT --data-binary @"$T/o2" "$S" >/dev/null
expect "storage: a resume after the object was replaced gets the new one whole" \
    "$(code_of -r 150000- -H "If-Range: $setag" "$S") $(sha "$T/b")" "200 $(sha "$T/o2")"

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
