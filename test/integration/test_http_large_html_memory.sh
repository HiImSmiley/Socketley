#!/usr/bin/env bash
# Integration test: what serving one large .html costs in memory.
#
# A .bin goes out by splice and the worker never holds it: 400 MiB of file,
# 20 MiB of peak RSS.  A .html cannot, because the live-reload script has to go
# in, and the read path used to hold the same bytes three times over --- the
# malloc'd file_buf the kernel read into, an injected copy of it, and the
# response built by appending that copy after the headers.  Measured, 400 MiB
# file: 1219 MiB peak, 3.05x.  Ten concurrent downloads of a 500 MB page is
# 15 GiB on a box with 11.
#
# The script is now a third piece of the one response --- headers, the file up
# to </head>, the script, the rest --- so one copy of the file remains and not
# three.  Same file after: 773 MiB, 1.93x.
#
# The remaining copy is the response string itself, and it is not an oversight:
# the write queue holds contiguous strings and the bytes have to reach one.
# Getting below 1x needs the body streamed the way splice streams it, which is
# a larger change than this file pins.  So the threshold below is 2.5x: it sits
# between the two measurements with room on both sides, and it fails the day
# somebody puts a second copy back.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: a large .html is not held three times ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

P=$((SL_PORT_BASE+1493))
# 128 MiB: large enough that three copies and two are hundreds of megabytes
# apart, small enough that the worst case still fits beside a test suite.
SIZE=$((128 * 1024 * 1024))

WWW=$(mktemp -d)
cleanup() { rm -rf "$WWW"; daemon_stop 2>/dev/null || true; }

{ printf '<html><head></head><body>'
  head -c "$SIZE" /dev/zero | tr '\0' 'x'
  printf '</body></html>'; } > "$WWW/big.html"
cp "$WWW/big.html" "$WWW/big.bin"
FILE_BYTES=$(stat -c %s "$WWW/big.html")

daemon_isolate httpmem
trap cleanup EXIT
daemon_start "$BIN"

"$BIN" create server hm -p "$P" --http "$WWW" -s >/dev/null 2>&1
for _ in $(seq 1 50); do nc -z 127.0.0.1 "$P" 2>/dev/null && break; sleep 0.1; done
sleep 0.5

# The worker, not the daemon: the daemon holds a placeholder and reads none of
# this.  Identified as the process holding the port rather than by name, since
# a suite run has several.
WORKER=$(ss -ltnp 2>/dev/null | awk -v p=":$P" '$4 ~ p"$" {
    if (match($0, /pid=[0-9]+/)) print substr($0, RSTART+4, RLENGTH-4) }' | head -1)
if [ -z "${WORKER:-}" ] || [ ! -d "/proc/$WORKER" ]; then
    bad "the worker holding the port can be found" \
        "ss reported no pid for :$P, so there is nothing to sample"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
    exit 1
fi

# Peak RSS across one request, sampled: VmHWM is a high-water mark for the
# process's whole life and would carry over between the two requests below.
peak_rss_kb_during() {   # url -> peak KiB, and the response size on fd 3
    local url=$1 peak=0 r
    ( while :; do
        r=$(awk '/^VmRSS/{print $2}' "/proc/$WORKER/status" 2>/dev/null) || break
        [ -n "$r" ] && echo "$r"
        sleep 0.02
      done ) > "$WWW/samples" &
    local sampler=$!
    curl -s -o /dev/null -w '%{http_code} %{size_download}' "$url" >&3
    kill "$sampler" 2>/dev/null
    wait "$sampler" 2>/dev/null
    sort -n "$WWW/samples" | tail -1
}

exec 3>"$WWW/curl_bin"
BIN_PEAK=$(peak_rss_kb_during "http://127.0.0.1:$P/big.bin")
exec 3>&-
read -r BIN_CODE BIN_SIZE < "$WWW/curl_bin"

exec 3>"$WWW/curl_html"
HTML_PEAK=$(peak_rss_kb_during "http://127.0.0.1:$P/big.html")
exec 3>&-
read -r HTML_CODE HTML_SIZE < "$WWW/curl_html"

# Nothing below means anything if the bytes did not arrive.  The .html is
# longer than the file by exactly the injected script.
if [ "${BIN_CODE:-0}" = "200" ] && [ "${BIN_SIZE:-0}" -eq "$FILE_BYTES" ] &&
   [ "${HTML_CODE:-0}" = "200" ] && [ "${HTML_SIZE:-0}" -gt "$FILE_BYTES" ]; then
    ok "both files are served whole (.bin $BIN_SIZE, .html $HTML_SIZE of $FILE_BYTES)"
else
    bad "the request has to succeed before its memory means anything" \
        ".bin: ${BIN_CODE:-<none>} ${BIN_SIZE:-0} bytes, .html: ${HTML_CODE:-<none>} ${HTML_SIZE:-0} bytes," \
        "against a file of $FILE_BYTES"
fi

BIN_X=$(awk -v p="${BIN_PEAK:-0}" -v f="$FILE_BYTES" 'BEGIN{printf "%.2f", p*1024/f}')
HTML_X=$(awk -v p="${HTML_PEAK:-0}" -v f="$FILE_BYTES" 'BEGIN{printf "%.2f", p*1024/f}')

if awk -v x="$BIN_X" 'BEGIN{exit !(x < 0.5)}'; then
    ok "the splice path holds none of the file (peak ${BIN_X}x)"
else
    bad "a .bin is spliced and never held" \
        "peak RSS was ${BIN_X}x the file; splice was expected to keep it near zero," \
        "so this run measured the read path for both and the .html number below" \
        "no longer distinguishes anything"
fi

if awk -v x="$HTML_X" 'BEGIN{exit !(x < 2.5)}'; then
    ok "the read path holds the file once, not three times (peak ${HTML_X}x)"
else
    bad "one large .html is one copy of itself, plus the response" \
        "peak RSS was ${HTML_X}x the file, over the 2.5x threshold;" \
        "3.05x was file_buf, an injected copy and the response --- if a second" \
        "copy is back, the script belongs in the response as a third piece" \
        "rather than in a copy of the body"
fi

"$BIN" stop hm >/dev/null 2>&1; "$BIN" remove hm >/dev/null 2>&1
daemon_stop
trap - EXIT
rm -rf "$WWW"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
