#!/usr/bin/env bash
# Integration test: an object a browser reads runs nothing on the origin the web interface is served from.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * an object answered without nosniff or a sandboxing Content-Security-Policy,
#     so a browser runs what it holds as a page of the web interface's origin
#   * an HTML, SVG or XML object, or one of no type, shown inline rather than
#     saved, by a signed GET, an anonymous one a policy admits, or a share link,
#     a stored inline disposition or a response-* override included
#   * an image or a text shown as a download, or a PDF put in a sandbox that keeps
#     a browser from showing it
#   * a response-* override taken from a request with no credentials
#   * a website endpoint's page saved or sandboxed, or the head a website answer
#     was given kept for an S3 GET of the same object
# suite: isolated
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate stgorigin
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1938))
U="http://127.0.0.1:$P"
trap 'daemon_stop' EXIT

echo "=== Integration: an object runs nothing on its origin ==="

daemon_start "$BIN"
KEY=AKIAORIGINSAFE000000
SEC=originsafesecretoriginsafesecret00
if ! "$BIN" create storage origin -p "$P" --dir "$T/stg" --access-key "$KEY" --secret-key "$SEC" \
     --website-domain site.test -s >/dev/null 2>&1; then
    echo "  FAIL [create]: the runtime was not created"
    exit 1
fi
for _ in $(seq 1 50); do curl -s -o /dev/null "$U/" && break; sleep 0.1; done
S() { curl -s -m 10 --user "$KEY:$SEC" --aws-sigv4 'aws:amz:us-east-1:s3' "$@"; }
# The value of header $1 in the answer to the rest, as one line per time it is given.
H() { local name=$1; shift; curl -s -m 10 -D - -o /dev/null "$@" | tr -d '\r' | grep -i "^$name:" | cut -d' ' -f2- | paste -sd'|'; }
SH() { local name=$1; shift; H "$name" --user "$KEY:$SEC" --aws-sigv4 'aws:amz:us-east-1:s3' "$@"; }

S -o /dev/null -X PUT "$U/web"
put() { printf '%s' "$3" | S -o /dev/null -X PUT -H "Content-Type: $2" "${@:4}" --data-binary @- "$U/web/$1"; }
put x.html text/html '<script>fetch("/~ui/iam")</script>'
put inline.html 'text/html; charset=utf-8' '<script>1</script>' -H 'Content-Disposition: inline'
put s.svg image/svg+xml '<svg xmlns="http://www.w3.org/2000/svg"><script>1</script></svg>'
put d.xml application/xml '<x/>'
put p.png image/png 'png'
put t.txt 'text/plain; charset=utf-8' 'text'
put a.txt text/plain 'saved' -H 'Content-Disposition: attachment; filename="a.txt"'
put doc.pdf application/pdf '%PDF-1.4'

expect "an object is never sniffed" "$(SH x-content-type-options "$U/web/x.html")" nosniff
expect "and runs in a sandbox with nothing it may load" "$(SH content-security-policy "$U/web/x.html")" "default-src 'none'; sandbox"
expect "an HTML object is saved, not shown" "$(SH content-disposition "$U/web/x.html")" attachment
expect "and keeps its type" "$(SH content-type "$U/web/x.html")" text/html
expect "however often it is read from memory" "$(for _ in 1 2 3; do SH content-disposition "$U/web/x.html"; done | paste -sd' ')" \
       "attachment attachment attachment"
expect "an inline disposition it was stored with is not given" "$(SH content-disposition "$U/web/inline.html")" attachment
expect "an SVG is saved" "$(SH content-disposition "$U/web/s.svg")" attachment
expect "and XML" "$(SH content-disposition "$U/web/d.xml")" attachment
expect "an image is shown" "$(SH content-disposition "$U/web/p.png")" ""
expect "in a sandbox still" "$(SH content-security-policy "$U/web/p.png")" "default-src 'none'; sandbox"
expect "and so is a text" "$(SH content-disposition "$U/web/t.txt")" ""
expect "a text stored as an attachment keeps its name" "$(SH content-disposition "$U/web/a.txt")" 'attachment; filename="a.txt"'
expect "a PDF is shown, in no sandbox a viewer cannot work in" "$(SH content-disposition "$U/web/doc.pdf")|$(SH content-security-policy "$U/web/doc.pdf")|$(SH x-content-type-options "$U/web/doc.pdf")" \
       "||nosniff"
expect "a signed override to HTML is saved" \
       "$(SH content-disposition "$U/web/p.png?response-content-type=text%2Fhtml&response-content-disposition=inline")" attachment
expect "and one to an image shown as asked" \
       "$(SH content-disposition "$U/web/t.txt?response-content-type=image%2Fpng&response-content-disposition=inline")" inline

# Anybody, as a public bucket lets in.
printf '%s' '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::web/*"}]}' |
    S -o /dev/null -X PUT --data-binary @- "$U/web?policy"
expect "an anonymous read of HTML is saved" "$(H content-disposition "$U/web/x.html")" attachment
expect "and sandboxed" "$(H content-security-policy "$U/web/x.html")" "default-src 'none'; sandbox"
expect "an anonymous read takes no response-* override" \
       "$(curl -s -m 10 -o /dev/null -w '%{http_code}' "$U/web/p.png?response-content-type=text%2Fhtml")" 400
expect "saying why" "$(curl -s -m 10 "$U/web/p.png?response-content-disposition=inline" | grep -c '<Code>InvalidRequest</Code>')" 1

# A share link.
id=$(curl -s -m 10 -u "$KEY:$SEC" -X POST -d '{"bucket":"web","key":"x.html"}' "$U/~share" |
     python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' 2>/dev/null)
expect "a share link's HTML is saved" "$(H content-disposition "$U/~share/$id")" attachment
expect "and sandboxed" "$(H content-security-policy "$U/~share/$id")" "default-src 'none'; sandbox"
fid=$(curl -s -m 10 -u "$KEY:$SEC" -X POST -d '{"bucket":"web","key":"up/","upload":true}' "$U/~share" |
      python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' 2>/dev/null)
printf '<script>1</script>' | curl -s -m 10 -o /dev/null -X PUT -H 'Content-Type: text/html' --data-binary @- "$U/~share/$fid/drop.html"
expect "an HTML file a visitor uploaded through a link is saved when read" \
       "$(SH content-disposition "$U/web/up/drop.html")|$(H content-disposition "$U/~share/$fid/drop.html")" "attachment|attachment"

# A website endpoint is the site's own origin, whose pages are shown as they are.
S -o /dev/null -X PUT --data-binary '<WebsiteConfiguration><IndexDocument><Suffix>x.html</Suffix></IndexDocument></WebsiteConfiguration>' "$U/web?website"
W() { H "$1" -H "Host: web.site.test:$P" "$U/"; }
expect "a website's page is shown" "$(for _ in 1 2 3; do W content-disposition; done | paste -sd'|')" "||"
expect "with no sandbox" "$(W content-security-policy)" ""
expect "as HTML" "$(W content-type)" text/html
expect "and an S3 read of it after is still saved" "$(SH content-disposition "$U/web/x.html")" attachment

echo ""
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
