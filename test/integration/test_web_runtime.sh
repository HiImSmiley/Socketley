#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: the web runtime serves a site of files to browsers and nothing else.
#
# What each part would catch:
#   * an address resolved wrong: a directory's index, its slash, /about for about.html, the 404 page, the fallback
#   * a file outside --root or a hidden one served: .., an escaped %2e%2e, a symlink out, .env, .git
#   * a method other than GET or HEAD answered with the file, or a WebSocket upgrade taken
#   * a revalidation, a range or If-Range answered wrong, or the cache fields a page and a stamped asset get
#   * a compressed copy wrong, missing, or sent for a range; a large file's bytes wrong through sendfile
#   * a change on the disk, or a new release swapped in under --root's name, not seen without a restart
#   * the settings lost on a restart, or a runtime made without what it needs
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

echo "=== Integration: the web runtime serves a site of files ==="
daemon_isolate webrt
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1970))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
daemon_start "$BIN"

R="$T/site"
W="$R/r1"
mkdir -p "$W/guide" "$W/assets" "$W/docs" "$W/.git" "$W/.well-known" "$R/r2"
printf '<!doctype html><html><head><title>home</title></head><body>home</body></html>\n' > "$W/index.html"
printf '<html><body>about</body></html>\n' > "$W/about.html"
printf '<html><body>guide</body></html>\n' > "$W/guide/index.html"
printf '<html><body>gone</body></html>\n' > "$W/404.html"
printf 'SECRET=1\n' > "$W/.env"
printf '[core]\n' > "$W/.git/config"
printf 'Contact: mailto:a@b.c\n' > "$W/.well-known/security.txt"
head -c 300000 /dev/urandom | base64 > "$W/assets/app.3f9a1c2b.js"
head -c 4000 /dev/urandom > "$W/assets/logo.png"
for i in $(seq 1 400); do printf '.rule-%d { color: #%06x; margin: %dpx; }\n' "$i" "$i" "$i"; done > "$W/style.css"
printf 'body{}\n' > "$W/pre.css"
head -c 60 /dev/urandom > "$W/pre.css.br"
head -c 70 /dev/urandom > "$W/pre.css.gz"
head -c 5000000 /dev/urandom > "$W/big.bin"
ln -s /etc/passwd "$W/passwd"
printf '<html><body>release two</body></html>\n' > "$R/r2/index.html"
ln -s r1 "$R/current"

sha() { sha256sum < "$1" | cut -c1-16; }
get() { curl -s -D "$T/h" -o "$T/b" "$@"; sha256sum < "$T/b" | cut -c1-16; }
hdr() { tr -d '\r' < "$T/h"; }
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
U="http://127.0.0.1:$P"

out=$("$BIN" create web nor -p $((P+5)) 2>&1); has "a web runtime without --root is refused" "$out" 'root is required'
out=$("$BIN" create web rel -p $((P+5)) --root site 2>&1); expect "a relative --root is made absolute by the cli" "$("$BIN" show rel 2>/dev/null | grep -c "\"root\": \"$PWD/site\"")" "1"
"$BIN" remove rel >/dev/null 2>&1
printf 'return {}\n' > "$T/x.lua"
out=$("$BIN" create web scripted -p $((P+5)) --root "$W" --lua "$T/x.lua" -s 2>&1); has "a script is refused" "$out" 'lua is not run'
"$BIN" remove scripted >/dev/null 2>&1

"$BIN" create web site -p "$P" --root "$R/current" -s >/dev/null 2>&1 || bad "a web runtime is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 50); do curl -s -o /dev/null "$U/" && break; sleep 0.1; done
has "ps lists it as web" "$("$BIN" ps 2>&1)" 'site +web'
has "without --bind it listens on this machine only" "$(ss -ltnH "( sport = :$P )")" "127\\.0\\.0\\.1:$P"

# ─── Addresses ──────────────────────────────────────────────────────────────
expect "/ is the index" "$(get "$U/")" "$(sha "$W/index.html")"
has "typed as a page" "$(hdr)" '^content-type: text/html; charset=utf-8$'
has "which is asked about on each use" "$(hdr)" '^cache-control: no-cache$'
has "with its tag" "$(hdr)" '^etag: "[0-9a-f]+-[0-9a-f]+-[0-9a-f]+"$'
has "its date" "$(hdr)" '^last-modified: [A-Z][a-z]{2}, '
has "the answer's date" "$(hdr)" '^date: '
has "and nosniff" "$(hdr)" '^x-content-type-options: nosniff$'
hasnt "and no script put in" "$(cat "$T/b")" 'WebSocket'
expect "a directory without its slash goes to it" "$(code "$U/guide")" "301"
has "with the slash" "$(curl -s -D - -o /dev/null "$U/guide" | tr -d '\r')" '^location: /guide/$'
has "and the query kept" "$(curl -s -D - -o /dev/null "$U/guide?a=1&b=2" | tr -d '\r')" '^location: /guide/\?a=1&b=2$'
expect "the directory's index" "$(get "$U/guide/")" "$(sha "$W/guide/index.html")"
expect "/about is about.html" "$(get "$U/about")" "$(sha "$W/about.html")"
expect "and about.html itself" "$(get "$U/about.html")" "$(sha "$W/about.html")"
expect "a double slash is one" "$(get "$U//guide//")" "$(sha "$W/guide/index.html")"
expect "an address with no file is the 404 page" "$(get "$U/nope")" "$(sha "$W/404.html")"
has "answered 404" "$(hdr | head -1)" ' 404 '
expect "a directory with no index lists nothing" "$(code "$U/docs/")" "404"

# ─── What is never served ───────────────────────────────────────────────────
for p in "/.env" "/.git/config" "/assets/../.env" "/%2e%2e/%2e%2e/etc/passwd" "/..%2f..%2fetc/passwd" "/passwd" "/%2eenv" "/guide/%2e%2e/.env"; do
    get "$U$p" >/dev/null
    hasnt "$p is not served" "$(cat "$T/b")" 'SECRET|root:|\[core\]'
    has "$p is a 404" "$(hdr | head -1)" ' 404 '
done
expect ".well-known is public" "$(get "$U/.well-known/security.txt")" "$(sha "$W/.well-known/security.txt")"
raw=$(printf 'GET ../../etc/passwd HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n' | timeout 3 nc -q1 127.0.0.1 "$P" 2>/dev/null | head -1 | tr -d '\r')
has "a target without its leading slash names nothing" "$raw" ' 404 '

# ─── Methods ────────────────────────────────────────────────────────────────
for m in POST PUT DELETE PATCH; do
    curl -s -X "$m" -d 'x=1' -D "$T/h" -o "$T/b" "$U/index.html"
    has "$m is refused" "$(hdr | head -1)" ' 405 '
    has "$m is told what is allowed" "$(hdr)" '^allow: GET, HEAD, OPTIONS$'
done
has "OPTIONS says the methods" "$(curl -s -X OPTIONS -D - -o /dev/null "$U/" | tr -d '\r')" '^allow: GET, HEAD, OPTIONS$'
curl -s -I "$U/index.html" | tr -d '\r' > "$T/hh"
has "HEAD has the file's length" "$(cat "$T/hh")" "^content-length: $(stat -c %s "$W/index.html")$"
up=$(printf 'GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n' | timeout 3 nc -q1 127.0.0.1 "$P" 2>/dev/null | head -1 | tr -d '\r')
has "a WebSocket upgrade is answered with the page" "$up" ' 200 '

# ─── Caching ────────────────────────────────────────────────────────────────
get "$U/" >/dev/null
etag=$(hdr | grep -i '^etag:' | cut -d' ' -f2)
lm=$(hdr | grep -i '^last-modified:' | cut -d' ' -f2-)
rm -f "$T/b"; curl -s -D "$T/h" -o "$T/b" -H "If-None-Match: $etag" "$U/"
has "its tag revalidates it" "$(hdr | head -1)" ' 304 '
has "the 304 keeps the tag" "$(hdr)" "^etag: $etag$"
has "and Cache-Control" "$(hdr)" '^cache-control: no-cache$'
hasnt "but no type" "$(hdr)" '^content-type'
expect "and no body" "$(cat "$T/b" 2>/dev/null | wc -c)" "0"
expect "its date revalidates it" "$(code -H "If-Modified-Since: $lm" "$U/")" "304"
expect "another tag is the page" "$(code -H 'If-None-Match: "x"' "$U/")" "200"
get "$U/assets/app.3f9a1c2b.js" >/dev/null
has "a stamped asset is kept a year" "$(hdr)" '^cache-control: public, max-age=31536000, immutable$'
get "$U/assets/logo.png" >/dev/null
has "an asset without a stamp is asked about" "$(hdr)" '^cache-control: no-cache$'
hasnt "and an image says no Vary" "$(hdr)" '^vary'

expect "a range is that range" "$(get -r 1000-1999 "$U/big.bin")" "$(head -c 2000 "$W/big.bin" | tail -c 1000 | sha256sum | cut -c1-16)"
has "answered 206" "$(hdr | head -1)" ' 206 '
has "naming the length" "$(hdr)" "^content-range: bytes 1000-1999/5000000$"
expect "a range of a page too" "$(get -r 5-9 "$U/index.html")" "$(head -c 10 "$W/index.html" | tail -c 5 | sha256sum | cut -c1-16)"
bigtag=$(curl -sI "$U/big.bin" | tr -d '\r' | grep -i '^etag:' | cut -d' ' -f2)
expect "If-Range with its tag is the range" "$(code -r 0-9 -H "If-Range: $bigtag" "$U/big.bin")" "206"
expect "If-Range with another is the whole" "$(code -r 0-9 -H 'If-Range: "old"' "$U/big.bin")" "200"
expect "a range past the end is 416" "$(code -r 9000000-9000010 "$U/big.bin")" "416"

# ─── Bodies ─────────────────────────────────────────────────────────────────
for i in 1 2 3; do
    expect "a large file is whole, pass $i" "$(get "$U/big.bin")" "$(sha "$W/big.bin")"
done
expect "a large text file is whole" "$(get "$U/assets/app.3f9a1c2b.js")" "$(sha "$W/assets/app.3f9a1c2b.js")"
expect "the .br beside a file goes to who takes br" "$(get -H 'Accept-Encoding: gzip, br' "$U/pre.css")" "$(sha "$W/pre.css.br")"
has "with its coding" "$(hdr)" '^content-encoding: br$'
expect "the .gz to who takes gzip" "$(get -H 'Accept-Encoding: gzip' "$U/pre.css")" "$(sha "$W/pre.css.gz")"
expect "neither to who takes none" "$(get "$U/pre.css")" "$(sha "$W/pre.css")"
has "which says it varies" "$(hdr)" '^vary: accept-encoding$'
# A text file without a copy is compressed once, by the helper, after its first answer.
for _ in $(seq 1 50); do
    get -H 'Accept-Encoding: gzip' "$U/style.css" >/dev/null
    hdr | grep -qi '^content-encoding: gzip' && break
    sleep 0.1
done
has "a text file without a copy is sent gzipped" "$(hdr)" '^content-encoding: gzip$'
expect "which is the file" "$(gunzip -c < "$T/b" | sha256sum | cut -c1-16)" "$(sha "$W/style.css")"
has "smaller" "$(hdr)" "^content-length: [0-9]{1,4}$"
for _ in $(seq 1 50); do
    get -H 'Accept-Encoding: gzip' "$U/assets/app.3f9a1c2b.js" >/dev/null
    hdr | grep -qi '^content-encoding: gzip' && break
    sleep 0.1
done
expect "a large one is too, from its descriptor" "$(gunzip -c < "$T/b" | sha256sum | cut -c1-16)" "$(sha "$W/assets/app.3f9a1c2b.js")"
expect "a range is of the file, never the copy" "$(get -H 'Accept-Encoding: gzip' -r 0-9 "$U/style.css")" "$(head -c 10 "$W/style.css" | sha256sum | cut -c1-16)"
hasnt "and says no coding" "$(hdr)" '^content-encoding'
expect "the copy's tag is its own" "$(code -H 'Accept-Encoding: gzip' -H "If-None-Match: $(curl -sI "$U/style.css" | tr -d '\r' | grep -i '^etag:' | cut -d' ' -f2)" "$U/style.css")" "200"

two=$(printf 'GET /about HTTP/1.1\r\nHost: x\r\n\r\nGET /guide/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n' | timeout 3 nc -q1 127.0.0.1 "$P" 2>/dev/null | tr -d '\r')
has "two pipelined requests are answered in order" "$(printf '%s' "$two" | grep -o 'about\|guide' | tr '\n' ' ')" '^about guide $'

# ─── Changes on the disk ────────────────────────────────────────────────────
printf '<html><body>home, changed</body></html>\n' > "$W/index.html"
for _ in $(seq 1 30); do get "$U/" >/dev/null; grep -q changed "$T/b" && break; sleep 0.1; done
has "a changed page is served at once" "$(cat "$T/b")" 'changed'
printf 'new\n' > "$W/new.txt"
for _ in $(seq 1 30); do [ "$(code "$U/new.txt")" = 200 ] && break; sleep 0.1; done
expect "a new file is served" "$(code "$U/new.txt")" "200"
rm "$W/new.txt"
for _ in $(seq 1 30); do [ "$(code "$U/new.txt")" = 404 ] && break; sleep 0.1; done
expect "a removed one is gone" "$(code "$U/new.txt")" "404"
mkdir -p "$W/later/deep"; printf 'deep\n' > "$W/later/deep/x.txt"
for _ in $(seq 1 30); do [ "$(code "$U/later/deep/x.txt")" = 200 ] && break; sleep 0.1; done
printf 'deeper\n' > "$W/later/deep/x.txt"
for _ in $(seq 1 30); do get "$U/later/deep/x.txt" >/dev/null; grep -q deeper "$T/b" && break; sleep 0.1; done
has "a file in a directory made since is watched too" "$(cat "$T/b")" 'deeper'
ln -s r2 "$R/next" && mv -T "$R/next" "$R/current"
for _ in $(seq 1 30); do get "$U/" >/dev/null; grep -q 'release two' "$T/b" && break; sleep 0.1; done
has "a new release swapped in under --root's name is served" "$(cat "$T/b")" 'release two'
printf '<html><body>release two, changed</body></html>\n' > "$R/r2/index.html"
for _ in $(seq 1 30); do get "$U/" >/dev/null; grep -q 'two, changed' "$T/b" && break; sleep 0.1; done
has "and a change in it is seen" "$(cat "$T/b")" 'two, changed'
for _ in $(seq 1 40); do "$BIN" stats site 2>&1 | grep -q '^reloads:1$' && break; sleep 0.1; done
has "the stats count the swap" "$("$BIN" stats site 2>&1)" '^reloads:1$'

mkdir -p "$R/r2/guide"
raw=$(printf 'GET /guide?a=1\x01Set-Cookie:x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n' | timeout 3 nc -q1 127.0.0.1 "$P" 2>/dev/null | tr -d '\r' | grep -i '^location:')
has "a query with a control byte is left off the redirect" "$raw" "^location: /guide/$"

truncate -s 8M "$R/r2/mid.bin"
printf 'x%.0s' $(seq 1 20000) > "$R/r2/twenty.txt"
for _ in $(seq 1 30); do [ "$(code "$U/twenty.txt")" = 200 ] && break; sleep 0.1; done
out=$(printf 'HEAD /nope HTTP/1.1\r\nHost: x\r\n\r\nGET /index.html HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n' | timeout 3 nc -q1 127.0.0.1 "$P" 2>/dev/null | tr -d '\r')
expect "a HEAD for a missing page has no body, so the next answer is whole" "$(printf '%s' "$out" | grep -c '^HTTP/1.1 ')" "2"
hasnt "and none of its text" "$out" '^Not Found$'
out=$(printf 'GET /mid.bin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\nGET /index.html HTTP/1.1\r\nHost: x\r\n\r\n' | timeout 8 nc -q3 127.0.0.1 "$P" 2>/dev/null | grep -ao 'HTTP/1.1 [0-9][0-9][0-9]' | wc -l)
expect "nothing after a Connection: close is answered, even after a large body" "$out" "1"
has "HTTP/1.0 asking to stay open is told so" "$(printf 'GET /index.html HTTP/1.0\r\nConnection: keep-alive\r\n\r\n' | timeout 3 nc -q1 127.0.0.1 "$P" 2>/dev/null | tr -d '\r')" '^connection: keep-alive$'
for i in $(seq 1 1500); do printf 'url = "http://127.0.0.1:%s/made-up-%s"\noutput = /dev/null\n' "$P" "$i"; done > "$T/flood.cfg"
curl -s -K "$T/flood.cfg"
for _ in $(seq 1 40); do "$BIN" stats site 2>&1 | grep -q '^not_found:[0-9]\{4,\}$' && break; sleep 0.1; done
st=$("$BIN" stats site 2>&1)
addr=$(printf '%s' "$st" | sed -n 's/^addresses://p')
if [ "${addr:-99999}" -lt 100 ]; then ok; else bad "made-up addresses keep nothing" "addresses:$addr"; fi
wpid=$(printf '%s' "$st" | sed -n 's/^pid://p')

# Releases under current/public, the deploy swapping current: the swap is above --root's own name.
mkdir -p "$T/deep/a/public" "$T/deep/b/public"
printf 'release a\n' > "$T/deep/a/public/index.html"; printf 'release b\n' > "$T/deep/b/public/index.html"
ln -s a "$T/deep/cur"
"$BIN" create web deep -p $((P+2)) --root "$T/deep/cur/public" -s >/dev/null 2>&1 || bad "a web runtime under a swapped name is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$((P+2))/" && break; sleep 0.1; done
expect "it serves the release named now" "$(curl -s "http://127.0.0.1:$((P+2))/")" "release a"
ln -s b "$T/deep/next" && mv -T "$T/deep/next" "$T/deep/cur"
for _ in $(seq 1 30); do [ "$(curl -s "http://127.0.0.1:$((P+2))/")" = "release b" ] && break; sleep 0.1; done
expect "and the one swapped in above --root's own name" "$(curl -s "http://127.0.0.1:$((P+2))/")" "release b"

# Three clients that stop: one mid-file, one pipelining requests it never reads, one that never asks. The last is on a
# runtime of its own with nothing else to answer, so only its own tick can let it go.
truncate -s 256M "$R/r2/huge.bin"
"$BIN" create web quiet -p $((P+3)) --root "$R/r2" -s >/dev/null 2>&1 || bad "a quiet web runtime is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 50); do ss -ltn | grep -q ":$((P+3)) " && break; sleep 0.1; done
rss0=$(awk '/^VmRSS/{print $2}' /proc/"$wpid"/status 2>/dev/null)
python3 - "$P" $((P+3)) <<'PY' &
import socket, sys, time
port, quiet = int(sys.argv[1]), int(sys.argv[2])
a = socket.socket(); a.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
a.connect(("127.0.0.1", port)); a.sendall(b"GET /huge.bin HTTP/1.1\r\nHost: x\r\n\r\n")
b = socket.socket(); b.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
b.connect(("127.0.0.1", port)); b.setblocking(False)
req = b"GET /twenty.txt HTTP/1.1\r\nHost: x\r\n\r\n" * 1000
end = time.time() + 5
sent = 0
while time.time() < end and sent < 40000 * 40:
    try:
        sent += b.send(req)
    except BlockingIOError:
        time.sleep(0.05)
q = socket.socket(); q.connect(("127.0.0.1", quiet))
time.sleep(300)
PY
stuck=$!
sleep 7
rss1=$(awk '/^VmRSS/{print $2}' /proc/"$wpid"/status 2>/dev/null)
if [ -n "$rss0" ] && [ -n "$rss1" ] && [ $((rss1 - rss0)) -lt 65536 ]; then ok; else bad "answers a client does not read are bounded" "RSS $rss0 -> $rss1 KiB"; fi
has "the readers that stopped hold connections" "$("$BIN" stats site 2>&1)" '^connections:[2-9]'
has "the silent one too" "$("$BIN" stats quiet 2>&1)" '^connections:1$'
for _ in $(seq 1 75); do "$BIN" stats site 2>&1 | grep -q '^connections:0$' && "$BIN" stats quiet 2>&1 | grep -q '^connections:0$' && break; sleep 1; done
has "and are let go when nothing moved for a minute" "$("$BIN" stats site 2>&1)" '^connections:0$'
has "the silent one as well" "$("$BIN" stats quiet 2>&1)" '^connections:0$'
kill "$stuck" 2>/dev/null; wait "$stuck" 2>/dev/null

# ─── Fallback, settings, restart ────────────────────────────────────────────
"$BIN" create web app -p $((P+1)) --root "$W" --fallback index.html --index about.html -s >/dev/null 2>&1 || bad "a web runtime with --fallback is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$((P+1))/" && break; sleep 0.1; done
expect "--index names a directory's page" "$(get "http://127.0.0.1:$((P+1))/")" "$(sha "$W/about.html")"
expect "a route with no file is the fallback" "$(get "http://127.0.0.1:$((P+1))/app/settings")" "$(sha "$W/index.html")"
has "with 200" "$(hdr | head -1)" ' 200 '
expect "a missing asset is not" "$(code "http://127.0.0.1:$((P+1))/app/missing.js")" "404"
state=$("$BIN" show app 2>/dev/null)
has "--root is kept" "$state" "\"root\": \"$W\""
has "--fallback is kept" "$state" '"fallback": "index.html"'
has "--index is kept" "$state" '"index": "about.html"'
out=$("$BIN" edit app --index index.html 2>&1); has "a running one is changed through a restart" "$out" 'when it starts'
"$BIN" edit app --index index.html --restart >/dev/null 2>&1 || bad "edit --restart takes it" "$out"
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$((P+1))/" && break; sleep 0.1; done
expect "and serves with it" "$(get "http://127.0.0.1:$((P+1))/")" "$(sha "$W/index.html")"
expect "the fallback survived the restart" "$(code "http://127.0.0.1:$((P+1))/app/settings")" "200"

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
