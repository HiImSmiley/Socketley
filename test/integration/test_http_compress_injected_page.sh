#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: --compress sends a page that takes the injected script as gzip to a client that takes it, made from
# the page as served, from disk and from --http-cache alike.
#
# What each part would catch:
#   * a page never compressed under --compress, because no copy beside it can hold the script
#   * a gzip that is not the page as served: the script missing, or the file as it was before an edit
#   * the gzip and the plain page under one ETag, so a cache that holds one revalidates into the other
#   * a gzip sent to a client that refused it (q=0), or for a range, or without Vary
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

echo "=== Integration: --compress sends an injected page as gzip ==="
daemon_isolate gzpage
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 770))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
daemon_start "$BIN"

W="$T/www"; mkdir -p "$W"
page() {
    { printf '<!doctype html><html><head><title>%s</title></head><body>\n' "$1"
      for i in $(seq 1 1500); do printf '<p class="row">row %d of the %s page, which repeats itself a lot</p>\n' "$i" "$1"; done
      printf '</body></html>\n'; } > "$W/index.html"
}
page first
"$BIN" create server disk -p "$P" --http "$W" --compress -s >/dev/null 2>&1 || bad "the disk server is made" "$(tail -3 "$SOCKETLEY_DLOG")"
"$BIN" create server kept -p $((P+1)) --http "$W" --http-cache --compress -s >/dev/null 2>&1 \
    || bad "the --http-cache server is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for port in "$P" $((P+1)); do
    for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$port/index.html" && break; sleep 0.1; done
done

hdr() { awk -F': ' -v k="$(printf '%s' "$1" | tr A-Z a-z)" 'tolower($1)==k {sub(/\r$/, "", $2); print $2}' "$2"; }
check_server() {  # name port
    local n=$1 u="http://127.0.0.1:$2/index.html"
    curl -s -D "$T/$n.ph" -o "$T/$n.plain" "$u"
    curl -s -D "$T/$n.gh" -o "$T/$n.gz" -H 'Accept-Encoding: gzip, br;q=0' "$u"
    expect "$n: a client that takes gzip gets the page as gzip" "$(hdr Content-Encoding "$T/$n.gh")" "gzip"
    expect "$n: the gzip says it varies by Accept-Encoding" "$(hdr Vary "$T/$n.gh")" "Accept-Encoding"
    if gzip -dc < "$T/$n.gz" > "$T/$n.unz" 2>/dev/null && cmp -s "$T/$n.unz" "$T/$n.plain"; then ok
    else bad "$n: the gzip is the page as served" "$(wc -c < "$T/$n.gz") gzip bytes, $(wc -c < "$T/$n.plain") plain"; fi
    grep -q '<script' "$T/$n.plain" && ok || bad "$n: the page as served carries the script" "no <script> in it"
    local small big
    small=$(wc -c < "$T/$n.gz"); big=$(wc -c < "$T/$n.plain")
    [ "$small" -gt 0 ] && [ $((small * 4)) -lt "$big" ] && ok || bad "$n: the gzip is a fraction of the page" "$small of $big bytes"
    local tp tg
    tp=$(hdr ETag "$T/$n.ph"); tg=$(hdr ETag "$T/$n.gh")
    [ -n "$tg" ] && [ "$tp" != "$tg" ] && ok || bad "$n: the gzip and the plain page carry different tags" "plain $tp, gzip $tg"
    expect "$n: the gzip's tag revalidates the gzip" \
        "$(curl -s -o /dev/null -w '%{http_code}' -H 'Accept-Encoding: gzip' -H "If-None-Match: $tg" "$u")" "304"
    expect "$n: the gzip's tag is not the plain page's" \
        "$(curl -s -o /dev/null -w '%{http_code}' -H "If-None-Match: $tg" "$u")" "200"
    expect "$n: a client that refuses gzip gets the plain page" \
        "$(curl -s -D - -o /dev/null -H 'Accept-Encoding: gzip;q=0' "$u" | tr -d '\r' | grep -ci '^content-encoding')" "0"
    curl -s -D "$T/$n.gh2" -o "$T/$n.gz2" -H 'Accept-Encoding: gzip' "$u"
    cmp -s "$T/$n.gz" "$T/$n.gz2" && ok || bad "$n: the kept gzip is the one made first" "the second answer differs"
}
check_server disk "$P"
check_server kept $((P+1))

# A range of a page is declined either way, and never answered from the gzip.
expect "a range of a page is not the gzip" \
    "$(curl -s -D - -o /dev/null -H 'Accept-Encoding: gzip' -H 'Range: bytes=0-99' "http://127.0.0.1:$P/index.html" | tr -d '\r' | grep -ci '^content-encoding')" "0"

# An edit is in the next gzip, as it is in the next plain page.
sleep 1.1; page second
curl -s -o "$T/edit.gz" -H 'Accept-Encoding: gzip' "http://127.0.0.1:$P/index.html"
edited=$(gzip -dc < "$T/edit.gz" 2>/dev/null)
grep -q '<title>second</title>' <<<"$edited" && ok || bad "an edited page's gzip is of the edit" "still the old page"

echo ""
echo "=== Results: $PASS/$((PASS+FAIL)) passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
