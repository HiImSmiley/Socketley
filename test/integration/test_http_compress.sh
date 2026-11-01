#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: --compress on a server's --http sends a file's .br or .gz copy, made by the site's build, to a
# client that takes it, from the disk and from --http-cache alike.
#
# What each part would catch:
#   * a copy sent to a client that did not ask for it or refused it with q=0, or without Content-Encoding and Vary
#   * a copy older than its file sent in its place, which is a build that changed one and not the other
#   * a copy for a range, for an image, or for a page, whose injected script a copy does not carry
#   * the copy's kept answer handed to a request for the copy by its own name, or the other way round
#   * the wrong bytes once the copy is kept in memory or sent by sendfile, and the flag lost on a restart
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

echo "=== Integration: --compress on --http sends a file's compressed copy to a client that takes it ==="
daemon_isolate httpgz
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1980))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
daemon_start "$BIN"

W="$T/www"
mkdir -p "$W/css"
head -c 4000 /dev/urandom | base64 > "$W/css/app.css"
head -c 600 /dev/urandom > "$W/css/app.css.br"
head -c 700 /dev/urandom > "$W/css/app.css.gz"
head -c 3000000 /dev/urandom | base64 > "$W/big.js"
head -c 300000 /dev/urandom > "$W/big.js.gz"
printf 'plain\n' > "$W/old.txt"
printf 'stale-copy' > "$W/old.txt.br"
touch -d '2020-01-01' "$W/old.txt.br"
head -c 5000 /dev/urandom > "$W/photo.png"
head -c 100 /dev/urandom > "$W/photo.png.br"
printf '<html><head></head><body>page</body></html>\n' > "$W/index.html"
head -c 50 /dev/urandom > "$W/index.html.br"
sha() { sha256sum < "$1" | cut -c1-16; }

"$BIN" create server plain -p "$P" --http "$W" -s >/dev/null 2>&1 || bad "a server without --compress is made" "$(tail -3 "$SOCKETLEY_DLOG")"
"$BIN" create server packed -p $((P+1)) --http "$W" --compress -s >/dev/null 2>&1 || bad "a server with --compress is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for port in "$P" $((P+1)); do
    for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$port/old.txt" && break; sleep 0.1; done
done
get() { curl -s -D "$T/h" -o "$T/b" "$@"; sha256sum < "$T/b" | cut -c1-16; }
hdr() { tr -d '\r' < "$T/h"; }

expect "without --compress the file itself goes" "$(get -H 'Accept-Encoding: br, gzip' "http://127.0.0.1:$P/css/app.css")" "$(sha "$W/css/app.css")"
hasnt "and says no coding" "$(hdr)" '^content-encoding'
hasnt "and no Vary" "$(hdr)" '^vary'

# Disk mode first, then the same rows against --http-cache, which keeps the copies at start.
rows() {
    local U=$1 how=$2
    expect "$how: br is taken before gzip" "$(get -H 'Accept-Encoding: gzip, deflate, br' "$U/css/app.css")" "$(sha "$W/css/app.css.br")"
    has "$how: with Content-Encoding: br" "$(hdr)" '^content-encoding: br$'
    has "$how: with Vary" "$(hdr)" '^vary: accept-encoding$'
    has "$how: typed as the file and not the copy" "$(hdr)" '^content-type: text/css'
    has "$how: and as long as the copy" "$(hdr)" "^content-length: $(stat -c %s "$W/css/app.css.br")$"
    expect "$how: again, the same bytes" "$(get -H 'Accept-Encoding: br' "$U/css/app.css")" "$(sha "$W/css/app.css.br")"
    has "$how: and the same coding" "$(hdr)" '^content-encoding: br$'
    expect "$how: gzip alone gets the .gz" "$(get -H 'Accept-Encoding: gzip' "$U/css/app.css")" "$(sha "$W/css/app.css.gz")"
    has "$how: with Content-Encoding: gzip" "$(hdr)" '^content-encoding: gzip$'
    expect "$how: br refused with q=0 gets the .gz" "$(get -H 'Accept-Encoding: br;q=0, gzip' "$U/css/app.css")" "$(sha "$W/css/app.css.gz")"
    expect "$how: no Accept-Encoding gets the file" "$(get "$U/css/app.css")" "$(sha "$W/css/app.css")"
    hasnt "$how: with no coding" "$(hdr)" '^content-encoding'
    has "$how: but with Vary" "$(hdr)" '^vary: accept-encoding$'
    expect "$how: the copy by its own name is the copy" "$(get -H 'Accept-Encoding: br' "$U/css/app.css.br")" "$(sha "$W/css/app.css.br")"
    hasnt "$how: and says no coding, being asked for as itself" "$(hdr)" '^content-encoding'
    expect "$how: and after it the file is still answered by its copy" "$(get -H 'Accept-Encoding: br' "$U/css/app.css")" "$(sha "$W/css/app.css.br")"
    has "$how: with its coding" "$(hdr)" '^content-encoding: br$'
    expect "$how: an image has no copy looked for" "$(get -H 'Accept-Encoding: br' "$U/photo.png")" "$(sha "$W/photo.png")"
    get -H 'Accept-Encoding: br' "$U/index.html" >/dev/null
    hasnt "$how: a page is never its copy, which lacks the injected script" "$(hdr)" '^content-encoding'
    has "$how: and keeps the script" "$(cat "$T/b")" 'new WebSocket'
    expect "$how: a copy older than its file is not sent" "$(get -H 'Accept-Encoding: br' "$U/old.txt")" "$(sha "$W/old.txt")"
    for i in 1 2; do
        expect "$how: a large copy goes whole, pass $i" "$(get -H 'Accept-Encoding: gzip' "$U/big.js")" "$(sha "$W/big.js.gz")"
    done
    has "$how: typed as script" "$(hdr)" '^content-type: (text|application)/javascript'
    has "$how: with its coding" "$(hdr)" '^content-encoding: gzip$'
    curl -s -I -H 'Accept-Encoding: br' "$U/css/app.css" | tr -d '\r' > "$T/hh"
    has "$how: a HEAD says the coding" "$(cat "$T/hh")" '^content-encoding: br$'
    etag=$(grep -i '^etag:' "$T/hh" | cut -d' ' -f2)
    curl -s -D "$T/h" -o /dev/null -H 'Accept-Encoding: br' -H "If-None-Match: $etag" "$U/css/app.css"
    has "$how: the copy's own ETag revalidates it" "$(hdr | head -1)" ' 304 '
    has "$how: and the 304 keeps the Vary" "$(hdr)" '^vary: accept-encoding$'
    curl -s -D "$T/h" -o /dev/null -H "If-None-Match: $etag" "$U/css/app.css"
    has "$how: but is not the file's" "$(hdr | head -1)" ' 200 '
}
rows "http://127.0.0.1:$((P+1))" disk
expect "disk: a range is of the file" "$(get -H 'Accept-Encoding: br' -r 10-19 "http://127.0.0.1:$((P+1))/css/app.css")" "$(head -c 20 "$W/css/app.css" | tail -c 10 | sha256sum | cut -c1-16)"
has "disk: and answered 206" "$(hdr | head -1)" ' 206 '
hasnt "disk: with no coding" "$(hdr)" '^content-encoding'
touch "$W/old.txt.br"
expect "disk: a copy made again is sent" "$(get -H 'Accept-Encoding: br' "http://127.0.0.1:$((P+1))/old.txt")" "$(sha "$W/old.txt.br")"
sleep 0.05; printf 'plain2\n' > "$W/old.txt"
expect "disk: and not after its file changed again, though it was kept" "$(get -H 'Accept-Encoding: br' "http://127.0.0.1:$((P+1))/old.txt")" "$(sha "$W/old.txt")"
touch -d '2020-01-01' "$W/old.txt.br"

"$BIN" create server cached -p $((P+2)) --http "$W" --http-cache --compress -s >/dev/null 2>&1 || bad "a cached server with --compress is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$((P+2))/old.txt" && break; sleep 0.1; done
rows "http://127.0.0.1:$((P+2))" cache

has "--compress is kept in the runtime's state" "$(grep -rl '"name": *"packed"' "$HOME" 2>/dev/null | head -1 | xargs cat 2>/dev/null)" '"compress": *true'

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
