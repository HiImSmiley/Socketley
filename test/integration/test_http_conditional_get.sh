#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: a client holding a file --http serves is told so with a 304, and a client holding a different one
# is not.
#
# What each part would catch:
#   * no validator on an answer, so a browser refetches every asset on every reload
#   * a 304 for a file that changed: in place, or replaced by one moved in with the old size and time (mv after
#     touch -r), which is why the inode is in the tag
#   * the --http-cache and the revalidation map answering 200 where the disk path answers 304, or the other way round
#   * a 304 with a body, or one that loses the connection's keep-alive
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate httpcond
WWW="$SOCKETLEY_TMPD/www"; CWWW="$SOCKETLEY_TMPD/cwww"; T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE+1961)); PC=$((SL_PORT_BASE+1962))

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }
trap 'daemon_stop' EXIT

mkdir -p "$WWW" "$CWWW"
printf 'body{color:red}\n' >"$WWW/a.css"
head -c 600000 /dev/urandom >"$WWW/big.bin"
printf '<html><body>hi</body></html>\n' >"$WWW/page.html"
printf 'cached\n' >"$CWWW/c.txt"

echo "=== Integration: a file the client holds is answered 304 ==="
daemon_start "$BIN"
"$BIN" create server cg -p "$P" --http "$WWW" -s >/dev/null
"$BIN" create server cgc -p "$PC" --http "$CWWW" --http-cache -s >/dev/null
for p in "$P" "$PC"; do for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$p/" && break; sleep 0.1; done; done

tag() { curl -s -D - -o /dev/null "$1" | tr -d '\r' | awk -F': ' 'tolower($1)=="etag"{print $2}'; }
code() { curl -s -o /dev/null -w '%{http_code} %{size_download}' "$@"; }

for f in a.css big.bin page.html; do
    U="http://127.0.0.1:$P/$f"
    t=$(tag "$U")
    if [ -n "$t" ]; then ok; else bad "$f is answered with an ETag" "none"; fi
    # The first answer reads the file; the second comes from the revalidation map for the small ones.
    expect "$f: a client holding it is answered 304, no body" "$(code -H "If-None-Match: $t" "$U")" "304 0"
    expect "$f: and again, from what the server kept" "$(code -H "If-None-Match: $t" "$U")" "304 0"
    expect "$f: a client holding another copy gets the file" "$(code -H 'If-None-Match: "other"' "$U" | cut -d' ' -f1)" 200
done

U="http://127.0.0.1:$P/a.css"; t=$(tag "$U")
printf 'body{color:blue}\n' >"$WWW/a.css"
expect "a file changed in place is not the client's copy" "$(code -H "If-None-Match: $t" "$U" | cut -d' ' -f1)" 200
t=$(tag "$U")
printf 'body{color:navy}\n' >"$T/next.css"; touch -r "$WWW/a.css" "$T/next.css"; mv "$T/next.css" "$WWW/a.css"
expect "nor one moved in under its name with the old size and time" "$(code -H "If-None-Match: $t" "$U" | cut -d' ' -f1)" 200
expect "a 304 keeps the connection: two on one" \
    "$(curl -s -o /dev/null -o /dev/null -w '%{http_code}%{num_connects} ' -H "If-None-Match: $(tag "$U")" "$U" "$U")" "3041 3040 "
expect "If-None-Match: * matches any file there is" "$(code -H 'If-None-Match: *' "$U")" "304 0"
expect "a range of a file the client holds is a 304 too" "$(code -r 0-3 -H "If-None-Match: $(tag "http://127.0.0.1:$P/big.bin")" "http://127.0.0.1:$P/big.bin")" "304 0"

UC="http://127.0.0.1:$PC/c.txt"; tc=$(tag "$UC")
if [ -n "$tc" ]; then ok; else bad "--http-cache answers carry an ETag" "none"; fi
expect "--http-cache: a client holding it is answered 304" "$(code -H "If-None-Match: $tc" "$UC")" "304 0"

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
