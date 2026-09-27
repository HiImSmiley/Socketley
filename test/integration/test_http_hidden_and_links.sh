#!/usr/bin/env bash
# Integration test: a static root does not serve its hidden files, and a link
# does not reach outside it, in either serving mode.
#
# ─── WHY ────────────────────────────────────────────────────────────────────
#
# Both modes served any path under the root, dotfiles included -- .env,
# .git/config, .htpasswd, which is where a site's secrets sit beside its
# pages.  And --http-cache read every regular file the directory walk found,
# following a symlink to wherever it pointed: a link to /etc/hostname was
# loaded into memory at start and served to anyone, where disk mode's
# openat2(RESOLVE_BENEATH) refuses the same link.
#
# ─── WHAT KEEPS IT HONEST ───────────────────────────────────────────────────
#
# .well-known must still be served, because ACME certificate challenges live
# there, and a relative link that stays inside the root must still work, by its
# own name -- --http-cache filed every link under its target's until this file;
# each row runs against both modes.
#
# ─── THE NAME AS THE REQUEST SPELLS IT ──────────────────────────────────────
#
# The path is looked up and opened without being copied when it has no
# percent escape, and from one decoded copy when it has, which the file system
# then reads as a C string.  So a name is asked for plainly, with an escape,
# with a query string, and with a %3F that decoding turns into one -- and
# again long enough to leave the small-string buffer.  A decode skipped, or a
# decoded name cut at its '?' by shortening the view instead of the string,
# sends the open a name that is not the file's, and answers 404.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate httphidden

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1))
        if [ "$1" = "$2" ]; then PASS=$((PASS+1)); echo "  PASS: $3"
        else FAIL=$((FAIL+1)); echo "  FAIL [$3]: got '$1', want '$2'"; fi; }
cleanup() { daemon_stop; }
trap cleanup EXIT

echo "=== Integration: hidden files and outward links are not served ==="
WWW="$SOCKETLEY_TMPD/www"
mkdir -p "$WWW/.git" "$WWW/.well-known/acme-challenge"
echo page > "$WWW/index.txt"
echo SECRET=1 > "$WWW/.env"
echo "[core]" > "$WWW/.git/config"
echo token > "$WWW/.well-known/acme-challenge/tok"
echo token2 > "$WWW/.well-known/acme-challenge/second-token"
echo outside > "$SOCKETLEY_TMPD/outside.txt"
ln -s "$SOCKETLEY_TMPD/outside.txt" "$WWW/out.txt"
ln -s index.txt "$WWW/in.txt"
# Absolute, and pointing inside the root all the same: RESOLVE_BENEATH refuses
# an absolute target outright, and the two modes must agree about it.
ln -s "$WWW/index.txt" "$WWW/abs.txt"

daemon_start "$BIN"
P=$((SL_PORT_BASE + 1940))
"$BIN" create server hd -p "$P" --http "$WWW" -s >/dev/null 2>&1
"$BIN" create server hc -p $((P + 1)) --http "$WWW" --http-cache -s >/dev/null 2>&1
for p in "$P" $((P + 1)); do
    for _ in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$p " && break; sleep 0.1; done
done

code() { curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$1$2"; }

for mode in "disk:$P" "cache:$((P + 1))"; do
    m=${mode%%:*}; port=${mode#*:}
    ok "$(code "$port" /index.txt)" "200" "$m: an ordinary file is served"
    ok "$(code "$port" /.env)" "404" "$m: .env is not served"
    ok "$(code "$port" /.git/config)" "404" "$m: .git/config is not served"
    ok "$(code "$port" /%2eenv)" "404" "$m: nor .env spelled with a percent escape"
    ok "$(code "$port" /.well-known/acme-challenge/tok)" "200" "$m: .well-known is served"
    ok "$(code "$port" /out.txt)" "404" "$m: a link to a file outside the root is not followed"
    ok "$(code "$port" /in.txt)" "200" "$m: a relative link that stays inside the root is"
    ok "$(code "$port" /abs.txt)" "404" "$m: an absolute link is refused, as openat2 refuses it"
    ok "$(code "$port" /in%64ex.txt)" "200" "$m: a percent escape in an ordinary name is decoded"
    ok "$(code "$port" '/index.txt?v=1')" "200" "$m: a query string is not part of the name"
    ok "$(code "$port" /index.txt%3Fv=1)" "200" "$m: nor is a query string spelled %3F, once decoded"
    # A file nothing asked for yet, twice: in disk mode the first is opened
    # with openat2() and the second is the revalidating hit, named to statx().
    for n in 1 2; do
        ok "$(code "$port" /.well-known/acme-challenge/second-t%6fken%3Fx)" "200" \
           "$m: a long name decoded and cut at its %3F, request $n"
    done
done

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
