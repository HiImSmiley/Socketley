#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: --no-inject on a server's --http sends a page as the file holds it, without the WebSocket script,
# and so as a file like any other: a range of it, its compressed copy, from the disk and from --http-cache alike.
#
# What each part would catch:
#   * the script still injected under the flag, on either path, or a byte of the page changed
#   * a range of a page still refused, or its Accept-Ranges still left out, once nothing moves the offsets
#   * a page's .br copy still never sent under --no-inject and --compress
#   * the flag lost on a restart, or --inject not putting the script back
#   * a server without the flag no longer injecting, which the pages that use the global `socketley` need
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
has() { if printf '%s' "$2" | grep -qiE -- "$3"; then ok; else bad "$1" "no /$3/ in: $(printf '%s' "$2" | head -c 400)"; fi; }
hasnt() { if printf '%s' "$2" | grep -qiE -- "$3"; then bad "$1" "/$3/ in: $(printf '%s' "$2" | head -c 400)"; else ok; fi; }

echo "=== Integration: --no-inject on --http serves a page as the file holds it ==="
daemon_isolate httpni
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1990))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
daemon_start "$BIN"

W="$T/www"
mkdir -p "$W/docs"
printf '<html><head><title>t</title></head><body>%s</body></html>\n' "$(head -c 3000 /dev/urandom | base64 -w0)" > "$W/index.html"
cp "$W/index.html" "$W/docs/page.htm"
head -c 80 /dev/urandom > "$W/index.html.br"
sha() { sha256sum < "$1" | cut -c1-16; }
get() { curl -s -D "$T/h" -o "$T/b" "$@"; sha256sum < "$T/b" | cut -c1-16; }
hdr() { tr -d '\r' < "$T/h"; }
up() { for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$1/index.html" && return; sleep 0.1; done; }
slice() { head -c $(($2 + 1)) "$1" | tail -c $(($2 - $3 + 1)) 2>/dev/null; }

"$BIN" create server plain -p "$P" --http "$W" -s >/dev/null 2>&1 || bad "a server without the flag is made" "$(tail -3 "$SOCKETLEY_DLOG")"
"$BIN" create server bare -p $((P+1)) --http "$W" --no-inject --compress -s >/dev/null 2>&1 || bad "a server with --no-inject is made" "$(tail -3 "$SOCKETLEY_DLOG")"
"$BIN" create server kept -p $((P+2)) --http "$W" --http-cache --no-inject --compress -s >/dev/null 2>&1 || bad "a cached server with --no-inject is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for port in "$P" $((P+1)) $((P+2)); do up "$port"; done

get "http://127.0.0.1:$P/" >/dev/null
has "without the flag a page gets the script" "$(cat "$T/b")" 'new WebSocket'
get -r 10-19 "http://127.0.0.1:$P/index.html" >/dev/null
has "and a range of it is the whole page" "$(hdr | head -1)" ' 200 '

rows() {
    local U=$1 how=$2
    for i in 1 2; do
        expect "$how: the page is the file, pass $i" "$(get "$U/")" "$(sha "$W/index.html")"
    done
    hasnt "$how: with no script" "$(cat "$T/b")" 'new WebSocket'
    has "$how: typed as a page" "$(hdr)" '^content-type: text/html'
    has "$how: and as long as the file" "$(hdr)" "^content-length: $(stat -c %s "$W/index.html")$"
    has "$how: offering ranges" "$(hdr)" '^accept-ranges: bytes$'
    expect "$how: an .htm too" "$(get "$U/docs/page.htm")" "$(sha "$W/docs/page.htm")"
    expect "$how: a range of a page is of the file" "$(get -r 100-199 "$U/index.html")" "$(slice "$W/index.html" 199 100 | sha256sum | cut -c1-16)"
    has "$how: and answered 206" "$(hdr | head -1)" ' 206 '
    has "$how: naming the file's length" "$(hdr)" "^content-range: bytes 100-199/$(stat -c %s "$W/index.html")$"
    expect "$how: the page's copy goes to a client that takes it" "$(get -H 'Accept-Encoding: br' "$U/")" "$(sha "$W/index.html.br")"
    has "$how: with its coding" "$(hdr)" '^content-encoding: br$'
    curl -s -I "$U/index.html" | tr -d '\r' > "$T/hh"
    has "$how: a HEAD says the file's length" "$(cat "$T/hh")" "^content-length: $(stat -c %s "$W/index.html")$"
}
rows "http://127.0.0.1:$((P+1))" disk
rows "http://127.0.0.1:$((P+2))" cache

has "--no-inject is kept in the runtime's state" "$(grep -rl '"name": *"bare"' "$HOME" 2>/dev/null | head -1 | xargs cat 2>/dev/null)" '"no_inject": *true'
hasnt "and not written for a server without it" "$(grep -rl '"name": *"plain"' "$HOME" 2>/dev/null | head -1 | xargs cat 2>/dev/null)" 'no_inject'

"$BIN" restart bare >/dev/null 2>&1 || bad "the server restarts" "$(tail -3 "$SOCKETLEY_DLOG")"
up $((P+1))
expect "after a restart the page is still the file" "$(get "http://127.0.0.1:$((P+1))/")" "$(sha "$W/index.html")"

"$BIN" edit bare --inject >/dev/null 2>&1 || bad "--inject is taken by edit" "$(tail -3 "$SOCKETLEY_DLOG")"
"$BIN" restart bare >/dev/null 2>&1 || bad "the server restarts again" "$(tail -3 "$SOCKETLEY_DLOG")"
up $((P+1))
get "http://127.0.0.1:$((P+1))/" >/dev/null
has "--inject puts the script back" "$(cat "$T/b")" 'new WebSocket'
hasnt "and drops the flag from the state" "$(grep -rl '"name": *"bare"' "$HOME" 2>/dev/null | head -1 | xargs cat 2>/dev/null)" 'no_inject'

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
