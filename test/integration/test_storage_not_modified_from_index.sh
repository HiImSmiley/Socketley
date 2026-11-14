#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a conditional GET of a cold object whose copy the client holds is answered 304 from the index,
# without opening the object's file; any other answer still comes from the file.
#
# What each part would catch:
#   * a 304 that opens and reads the file first, an open, a header read and a close for an answer of no body -- seen
#     here as the 500 an unreadable file gives, since the file's read permission is taken away for that request
#   * a 304 from the index without the validators a 304 carries, or for a client whose copy is not current
#   * an If-Modified-Since judged differently from the index than from the file
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

echo "=== Integration: a cold object's 304 is answered from the index ==="
daemon_isolate stg304
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 750))
unset SOCKETLEY_CONFIG
F=""
trap '[ -n "$F" ] && chmod 600 "$F" 2>/dev/null; daemon_stop' EXIT
daemon_start "$BIN"

"$BIN" create storage st -p "$P" --dir "$T/data" --anonymous -s >/dev/null 2>&1 || bad "the storage is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$P/" && break; sleep 0.1; done
U="http://127.0.0.1:$P/bkt/obj"
curl -s -o /dev/null -X PUT "http://127.0.0.1:$P/bkt"
head -c 100000 /dev/urandom > "$T/body"
curl -s -o /dev/null -X PUT --data-binary @"$T/body" "$U"
ETAG=$(curl -sI "$U" | awk -F': ' 'tolower($1)=="etag"{print $2}' | tr -d '\r')
[ -n "$ETAG" ] || bad "the object has an ETag" "HEAD gave none"
F=$(find "$T/data" -type f -size +90k | head -1)
[ -n "$F" ] || bad "the object's file is found" "no file of 100000 bytes under $T/data"

# The file cannot be read, so only an answer that never opens it can succeed.
chmod 000 "$F"
: > "$T/out"
head=$(curl -s -D - -o "$T/out" -H "If-None-Match: $ETAG" "$U" | tr -d '\r')
expect "a matching If-None-Match is 304 with the file unopened" "$(head -1 <<<"$head" | cut -d' ' -f2)" "304"
expect "the 304 carries the object's ETag" "$(awk -F': ' 'tolower($1)=="etag"{print $2}' <<<"$head")" "$ETAG"
grep -qi '^last-modified: ' <<<"$head" && ok || bad "the 304 carries Last-Modified" "$(head -5 <<<"$head")"
expect "a 304 has no body" "$(wc -c <"$T/out")" "0"
expect "an If-Modified-Since after the object's time is 304 with the file unopened" \
    "$(curl -s -o /dev/null -w '%{http_code}' -H "If-Modified-Since: $(date -u -d '+1 day' '+%a, %d %b %Y %H:%M:%S GMT')" "$U")" "304"
expect "a stale copy is not answered from the index" \
    "$(curl -s -o /dev/null -w '%{http_code}' -H 'If-None-Match: "0123456789abcdef0123456789abcdef"' "$U")" "500"
chmod 600 "$F"

# With the file readable again, a client whose copy is not current gets the object, whole.
expect "a stale copy gets the object" \
    "$(curl -s -H 'If-None-Match: "0123456789abcdef0123456789abcdef"' "$U" | cmp -s - "$T/body" && echo same)" "same"
expect "an If-Modified-Since before the object's time gets the object" \
    "$(curl -s -o /dev/null -w '%{http_code}' -H 'If-Modified-Since: Mon, 01 Jan 2001 00:00:00 GMT' "$U")" "200"

echo ""
echo "=== Results: $PASS/$((PASS+FAIL)) passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
