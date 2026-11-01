#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: --compress on a FastCGI proxy sends a file's .br or .gz copy, made by the site's build, to a
# client that takes it.
#
# What each part would catch:
#   * a copy sent to a client that did not ask for it, or refused it with q=0, or without Content-Encoding and Vary
#   * a copy older than its file sent in its place, which is a build that changed one and not the other
#   * a copy sent for a range, which is of the file, or for a file kept from the public, or with no file beside it,
#     or for an image or a video, whose format compresses itself
#   * the wrong bytes once the copy is kept in memory or its descriptor kept open, and the flag lost on a restart
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

echo "=== Integration: --compress sends a file's compressed copy to a client that takes it ==="
daemon_isolate proxyfcgz
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 720))
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
printf 'orphan' > "$W/orphan.css.br"
head -c 5000 /dev/urandom > "$W/photo.png"
head -c 100 /dev/urandom > "$W/photo.png.br"
printf 'DB_PASSWORD=x\n' > "$W/dump.sql"
printf 'DB_PASSWORD=gz\n' > "$W/dump.sql.gz"
printf 'DB_PASSWORD=br\n' > "$W/config.inc.br"
sha() { sha256sum < "$1" | cut -c1-16; }

"$BIN" create proxy plain -p "$P" --domain plain --backend "fastcgi://unix:$T/none.sock" --root "$W" -s >/dev/null 2>&1 \
    || bad "a proxy without --compress is made" "$(tail -3 "$SOCKETLEY_DLOG")"
"$BIN" create proxy packed -p $((P+1)) --domain packed --backend "fastcgi://unix:$T/none.sock" --root "$W" --compress -s >/dev/null 2>&1 \
    || bad "a proxy with --compress is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for port in "$P" $((P+1)); do
    for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$port/old.txt" && break; sleep 0.1; done
done
U0="http://127.0.0.1:$P"; U="http://127.0.0.1:$((P+1))"
get() { curl -s -D "$T/h" -o "$T/b" "$@"; sha256sum < "$T/b" | cut -c1-16; }
hdr() { tr -d '\r' < "$T/h"; }

# ── without the flag nothing changes ────────────────────────────────────────
expect "without --compress the file itself goes" "$(get -H 'Accept-Encoding: br, gzip' "$U0/css/app.css")" "$(sha "$W/css/app.css")"
hasnt "and says no coding" "$(hdr)" '^content-encoding'
hasnt "and no Vary" "$(hdr)" '^vary'

# ── a client that takes a coding gets the copy in it ────────────────────────
expect "br is taken before gzip" "$(get -H 'Accept-Encoding: gzip, deflate, br' "$U/css/app.css")" "$(sha "$W/css/app.css.br")"
has "with Content-Encoding: br" "$(hdr)" '^content-encoding: br$'
has "with Vary" "$(hdr)" '^vary: accept-encoding$'
has "typed as the file and not the copy" "$(hdr)" '^content-type: text/css'
has "and as long as the copy" "$(hdr)" "^content-length: $(stat -c %s "$W/css/app.css.br")$"
expect "again from memory, the same bytes" "$(get -H 'Accept-Encoding: br' "$U/css/app.css")" "$(sha "$W/css/app.css.br")"
has "and the same coding" "$(hdr)" '^content-encoding: br$'
expect "gzip alone gets the .gz" "$(get -H 'Accept-Encoding: gzip' "$U/css/app.css")" "$(sha "$W/css/app.css.gz")"
has "with Content-Encoding: gzip" "$(hdr)" '^content-encoding: gzip$'
expect "br refused with q=0 gets the .gz" "$(get -H 'Accept-Encoding: br;q=0, gzip' "$U/css/app.css")" "$(sha "$W/css/app.css.gz")"
expect "* takes the first copy" "$(get -H 'Accept-Encoding: *' "$U/css/app.css")" "$(sha "$W/css/app.css.br")"
expect "* with br;q=0 skips br" "$(get -H 'Accept-Encoding: br;q=0.000, *' "$U/css/app.css")" "$(sha "$W/css/app.css.gz")"
expect "BR in capitals is br" "$(get -H 'Accept-Encoding: BR' "$U/css/app.css")" "$(sha "$W/css/app.css.br")"

# ── and anyone else the file itself ─────────────────────────────────────────
expect "no Accept-Encoding gets the file" "$(get "$U/css/app.css")" "$(sha "$W/css/app.css")"
hasnt "with no coding" "$(hdr)" '^content-encoding'
has "but with Vary, since another client gets a copy" "$(hdr)" '^vary: accept-encoding$'
expect "identity gets the file" "$(get -H 'Accept-Encoding: identity' "$U/css/app.css")" "$(sha "$W/css/app.css")"
expect "a coding with no copy gets the file" "$(get -H 'Accept-Encoding: zstd' "$U/css/app.css")" "$(sha "$W/css/app.css")"
expect "a range is of the file" "$(get -H 'Accept-Encoding: br' -r 10-19 "$U/css/app.css")" "$(head -c 20 "$W/css/app.css" | tail -c 10 | sha256sum | cut -c1-16)"
has "and answered 206 with no coding" "$(hdr | head -1)" ' 206 '
hasnt "no coding on the range" "$(hdr)" '^content-encoding'

# ── a copy that is not the file's is never sent ─────────────────────────────
expect "a copy older than its file is not sent" "$(get -H 'Accept-Encoding: br' "$U/old.txt")" "$(sha "$W/old.txt")"
touch "$W/old.txt.br"
expect "and is once the build has made it again" "$(get -H 'Accept-Encoding: br' "$U/old.txt")" "$(sha "$W/old.txt.br")"
sleep 0.05; printf 'plain2\n' > "$W/old.txt"
expect "and not after the file changed again, though the copy was kept" "$(get -H 'Accept-Encoding: br' "$U/old.txt")" "$(sha "$W/old.txt")"
expect "a format compressed already has no copy looked for" "$(get -H 'Accept-Encoding: br' "$U/photo.png")" "$(sha "$W/photo.png")"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Accept-Encoding: br' "$U/orphan.css")
expect "a copy with no file beside it answers for nothing" "$code" "404"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Accept-Encoding: gzip' "$U/dump.sql")
expect "a file kept from the public has no copy sent" "$code" "404"
for f in dump.sql.gz config.inc.br; do
    code=$(curl -s -o /dev/null -w '%{http_code}' "$U0/$f")
    expect "nor is its copy served by name: $f" "$code" "404"
done

# ── HEAD, a revalidation and a large copy ───────────────────────────────────
curl -s -I -H 'Accept-Encoding: br' "$U/css/app.css" | tr -d '\r' > "$T/hh"
has "a HEAD says the coding" "$(cat "$T/hh")" '^content-encoding: br$'
has "and the copy's length" "$(cat "$T/hh")" "^content-length: $(stat -c %s "$W/css/app.css.br")$"
etag=$(grep -i '^etag:' "$T/hh" | cut -d' ' -f2)
curl -s -D "$T/h" -o /dev/null -H 'Accept-Encoding: br' -H "If-None-Match: $etag" "$U/css/app.css"
has "the copy's own ETag revalidates it" "$(hdr | head -1)" ' 304 '
has "and the 304 keeps the Vary" "$(hdr)" '^vary: accept-encoding$'
curl -s -D "$T/h" -o /dev/null -H "If-None-Match: $etag" "$U/css/app.css"
has "but is not the file's" "$(hdr | head -1)" ' 200 '
for i in 1 2; do
    expect "a large copy goes whole, pass $i" "$(get -H 'Accept-Encoding: gzip' "$U/big.js")" "$(sha "$W/big.js.gz")"
done
has "typed as script" "$(hdr)" '^content-type: (text|application)/javascript'
expect "and the large file itself to who takes no copy" "$(get "$U/big.js")" "$(sha "$W/big.js")"

# ── the flag outlives a restart ─────────────────────────────────────────────
has "--compress is kept in the runtime's state" "$(cat "$HOME"/.local/state/socketley/runtimes/packed.json 2>/dev/null || grep -rl '"name": *"packed"' "$HOME" | head -1 | xargs cat)" '"compress": *true'

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
