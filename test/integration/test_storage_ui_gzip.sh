#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: the storage's interface page goes gzipped to a browser that takes gzip.
#
# What it would catch: the page, a third of a megabyte, sent whole to every browser, which over a 10 Mbit link with a
# 50 ms round trip took 0.46 s against 0.19 gzipped; and a gzipped page under the plain one's ETag, which a cache
# would then answer for either, or one that does not inflate to the page.
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

echo "=== Integration: the storage interface goes gzipped ==="
daemon_isolate stguigz
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1984))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
daemon_start "$BIN"
"$BIN" create storage st -p "$P" --dir "$T/s" --anonymous -s >/dev/null 2>&1
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$P/~ui/" && break; sleep 0.1; done
U="http://127.0.0.1:$P/~ui/"

curl -s -D "$T/ph" -o "$T/plain" "$U"
curl -s -D "$T/gh" -o "$T/packed" -H 'Accept-Encoding: gzip, deflate, br' "$U"
hdr() { tr -d '\r' < "$1" | awk -F': ' -v k="$2" 'tolower($1)==k{print $2}'; }
expect "a browser that takes gzip gets the page gzipped" "$(hdr "$T/gh" content-encoding)" "gzip"
expect "which inflates to the page itself" "$(gunzip -c "$T/packed" 2>/dev/null | sha256sum | cut -c1-16)" \
    "$(sha256sum < "$T/plain" | cut -c1-16)"
expect "at under half its size" "$(( $(wc -c < "$T/packed") * 2 < $(wc -c < "$T/plain") ))" "1"
expect "under an ETag of its own" "$( [ "$(hdr "$T/gh" etag)" != "$(hdr "$T/ph" etag)" ] && echo own)" "own"
expect "and both say Vary" "$(hdr "$T/ph" vary)|$(hdr "$T/gh" vary)" "Accept-Encoding|Accept-Encoding"
expect "one that does not gets it as it is" "$(hdr "$T/ph" content-encoding)" ""
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Accept-Encoding: gzip' -H "If-None-Match: $(hdr "$T/gh" etag)" "$U")
expect "and the gzipped copy's ETag revalidates it" "$code" "304"

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
