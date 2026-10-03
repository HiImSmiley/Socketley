#!/usr/bin/env bash
# Integration test: static website hosting (?website and --website-domain)
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# A request whose Host names a bucket under --website-domain is a browser's:
# it signs nothing, is answered from the bucket's WebsiteConfiguration with an
# object, its index document, a redirect or an HTML error page, and may read
# only what the bucket's policy lets anyone read.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a configuration S3 refuses taken, or one taken and not read back
#   * a folder or the root not answered with its index document, or a folder
#     named without its slash not sent to it
#   * a missing key answered without the error document, or with it and a
#     status other than the failure's
#   * a routing rule, by prefix or by error code, not redirecting where it says
#   * an object stored as a redirect served as itself
#   * RedirectAllRequestsTo not redirecting every request
#   * a write accepted, or an error answered in XML
#   * the S3 API on the same port answered as a website
#   * a website served to anyone without a policy that lets anyone read it,
#     or the error document served to someone it was not readable by
#   * a configuration lost by a restart, or still served after DELETE ?website
# suite: isolated
set -uo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

echo "=== Integration: static website hosting ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate stgweb
trap 'daemon_stop' EXIT
daemon_start "$BIN"
P1=$((SL_PORT_BASE + 1895)); P2=$((SL_PORT_BASE + 1896))
up() { for _ in $(seq 1 100); do curl -s -o /dev/null "http://127.0.0.1:$1/" && return 0; sleep 0.1; done; return 1; }
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
body() { curl -s "$@"; }

"$BIN" create storage web -p "$P1" --dir "$SOCKETLEY_TMPD/web" --anonymous --website-domain web.test -s >/dev/null 2>&1
up "$P1" || bad "the runtime serves" "no answer on $P1"
U="http://127.0.0.1:$P1"
check "show names the website's domain" "$("$BIN" show web 2>&1 | grep -c '"website_domain": "web.test"')" 1
check "a name that is no domain is refused" \
    "$("$BIN" create storage bad -p "$P2" --dir "$SOCKETLEY_TMPD/bad" --anonymous --website-domain 'no domain' >/dev/null 2>&1; echo $?)" 1
# A request to bucket $1's website for path $2, with curl's options after it.
W() { local b=$1 p=$2; shift 2; curl -s -H "Host: $b.web.test:$P1" "$@" "http://127.0.0.1:$P1$p"; }
wcode() { local b=$1 p=$2; shift 2; W "$b" "$p" -o /dev/null -w '%{http_code}' "$@"; }
whead() { local b=$1 h=$2 p=$3; shift 3; W "$b" "$p" -o /dev/null -D - "$@" | tr -d '\r' | grep -i "^$h:" | cut -d' ' -f2-; }

curl -s -X PUT "$U/site" -o /dev/null
curl -s -X PUT "$U/plain" -o /dev/null

# ── the document ──
check "a document that is no WebsiteConfiguration is MalformedXML" \
    "$(code -X PUT "$U/site?website" --data '<Website/>')" 400
check "one with no IndexDocument is refused" \
    "$(code -X PUT "$U/site?website" --data '<WebsiteConfiguration><ErrorDocument><Key>e.html</Key></ErrorDocument></WebsiteConfiguration>')" 400
check "one that redirects everything and names an index is refused" \
    "$(code -X PUT "$U/site?website" --data '<WebsiteConfiguration><RedirectAllRequestsTo><HostName>x.test</HostName></RedirectAllRequestsTo><IndexDocument><Suffix>i.html</Suffix></IndexDocument></WebsiteConfiguration>')" 400
check "a bucket without one answers NoSuchWebsiteConfiguration" "$(code "$U/site?website")" 404
check "and so does its website" "$(wcode site /)" 404
check "in HTML" "$(whead site content-type /)" "text/html; charset=utf-8"
check "naming the error" "$(W site / | grep -c '<li>Code: NoSuchWebsiteConfiguration</li>')" 1

CFG='<WebsiteConfiguration><IndexDocument><Suffix>index.html</Suffix></IndexDocument><ErrorDocument><Key>error.html</Key></ErrorDocument><RoutingRules><RoutingRule><Condition><KeyPrefixEquals>old/</KeyPrefixEquals></Condition><Redirect><ReplaceKeyPrefixWith>new/</ReplaceKeyPrefixWith></Redirect></RoutingRule><RoutingRule><Condition><KeyPrefixEquals>gone/</KeyPrefixEquals><HttpErrorCodeReturnedEquals>404</HttpErrorCodeReturnedEquals></Condition><Redirect><HostName>elsewhere.test</HostName><Protocol>https</Protocol><HttpRedirectCode>302</HttpRedirectCode></Redirect></RoutingRule></RoutingRules></WebsiteConfiguration>'
check "a configuration is set" "$(code -X PUT "$U/site?website" --data "$CFG")" 200
got=$(body "$U/site?website")
check "and read back" "$(echo "$got" | grep -c '<IndexDocument><Suffix>index.html</Suffix></IndexDocument><ErrorDocument><Key>error.html</Key></ErrorDocument>')" 1
check "with its rules" "$(echo "$got" | grep -c '<ReplaceKeyPrefixWith>new/</ReplaceKeyPrefixWith>')" 1
check "an object has no website" "$(code "$U/site/k?website")" 501

curl -s -X PUT "$U/site/index.html" --data-binary home -H 'Content-Type: text/html' -o /dev/null
curl -s -X PUT "$U/site/docs/index.html" --data-binary docs -o /dev/null
curl -s -X PUT "$U/site/error.html" --data-binary oops -H 'Content-Type: text/html' -o /dev/null
curl -s -X PUT "$U/site/page.html" --data-binary page-body -o /dev/null
curl -s -X PUT "$U/site/moved" --data-binary x -H 'x-amz-website-redirect-location: /page.html' -o /dev/null

# ── objects, index documents and folders ──
check "the root is its index document" "$(W site /)" home
check "with the object's type" "$(whead site content-type /)" text/html
check "a folder is its index document" "$(W site /docs/)" docs
check "a folder without its slash is sent to it" "$(wcode site /docs)" 302
check "at /docs/" "$(whead site location /docs)" /docs/
check "an object is itself" "$(W site /page.html)" page-body
check "a HEAD is answered without a body" "$(W site /page.html -I | tr -d '\r' | grep -i '^content-length:' | cut -d' ' -f2)" 9
check "a range is a range" "$(W site /page.html -H 'Range: bytes=0-3')" page
check "a query does not turn a read into another operation" "$(W site '/page.html?tagging')" page-body

# ── errors ──
check "a missing key is the error document" "$(W site /missing)" oops
check "with the failure's status" "$(wcode site /missing)" 404
check "and a HEAD of it has the status" "$(W site /missing -I -o /dev/null -w '%{http_code}')" 404
check "a write is MethodNotAllowed" "$(wcode site /new -X PUT --data x)" 405
check "and stores nothing" "$(code "$U/site/new")" 404
check "a bucket that is not there is NoSuchBucket" "$(W nobucket / | grep -c '<li>Code: NoSuchBucket</li>')" 1
check "a bucket with no website is NoSuchWebsiteConfiguration" "$(wcode plain /)" 404

# ── redirects ──
check "an object stored as a redirect sends there" "$(wcode site /moved)" 301
check "to its location" "$(whead site location /moved)" /page.html
check "a prefix rule redirects before the object is looked for" "$(wcode site /old/a/b.html)" 301
check "with the prefix replaced" "$(whead site location /old/a/b.html)" "http://site.web.test:$P1/new/a/b.html"
check "an error rule redirects a failure it matches" "$(wcode site /gone/x)" 302
check "where it says" "$(whead site location /gone/x)" "https://elsewhere.test/gone/x"

# ── the S3 API is still the S3 API ──
check "a path-style read on the same port is S3's" "$(body "$U/site/page.html")" page-body
check "and its missing key is S3's XML" "$(body "$U/site/missing" | grep -c '<Code>NoSuchKey</Code>')" 1

# ── no error document ──
curl -s -X DELETE "$U/site/error.html" -o /dev/null
check "an error document that is not there gives the failure's page" "$(W site /missing | grep -c '<li>Code: NoSuchKey</li>')" 1
check "with the failure's status" "$(wcode site /missing)" 404

# ── redirect everything ──
curl -s -X PUT "$U/plain?website" --data '<WebsiteConfiguration><RedirectAllRequestsTo><HostName>example.org</HostName><Protocol>https</Protocol></RedirectAllRequestsTo></WebsiteConfiguration>' -o /dev/null
check "RedirectAllRequestsTo redirects every request" "$(wcode plain /a/b)" 301
check "keeping the key" "$(whead plain location /a/b)" "https://example.org/a/b"

# ── a restart keeps it, a delete takes it away ──
"$BIN" stop web >/dev/null 2>&1; "$BIN" start web >/dev/null 2>&1; up "$P1"
check "a restart keeps the configuration" "$(W site /)" home
check "DELETE ?website removes it" "$(code -X DELETE "$U/site?website")" 204
check "after which the website is gone" "$(wcode site /)" 404
check "and the bucket has none" "$(code "$U/site?website")" 404

# ── a policy says who may read it ──
CREDS="$SOCKETLEY_TMPD/creds"
echo "AKIAWEBSITEADMIN0000:websiteadminsecretwebsiteadminsecret000" > "$CREDS"
"$BIN" create storage webp -p "$P2" --dir "$SOCKETLEY_TMPD/webp" --credentials "$CREDS" --website-domain web.test -s >/dev/null 2>&1
up "$P2" || bad "the runtime with credentials serves" "no answer on $P2"
python3 - "$P2" "$HERE" <<'PY'
import http.client, sys
sys.path.insert(0, sys.argv[2])
import lib_s3_signing as sig
port = int(sys.argv[1])
def req(method, path, query="", body=b""):
    s = sig.sign(method, path, query, "127.0.0.1:%d" % port, "AKIAWEBSITEADMIN0000",
                 "websiteadminsecretwebsiteadminsecret000", sig.sha256hex(body))
    c = http.client.HTTPConnection("127.0.0.1", port)
    c.request(method, path + ("?" + query if query else ""), body=body, headers=s.headers)
    r = c.getresponse(); r.read(); c.close()
    if r.status >= 300:
        print("setup %s %s?%s: %d" % (method, path, query, r.status))
req("PUT", "/pub")
req("PUT", "/pub", "website", b"<WebsiteConfiguration><IndexDocument><Suffix>index.html</Suffix></IndexDocument>"
                              b"<ErrorDocument><Key>error.html</Key></ErrorDocument></WebsiteConfiguration>")
req("PUT", "/pub/index.html", body=b"public")
req("PUT", "/pub/error.html", body=b"public-oops")
req("PUT", "/pub/private/error.html", body=b"x")
PY
PW() { local p=$1; shift; curl -s -H "Host: pub.web.test:$P2" "$@" "http://127.0.0.1:$P2$p"; }
check "without a policy nobody may read the website" "$(PW / -o /dev/null -w '%{http_code}')" 403
check "nor its error document" "$(PW / | grep -c '<li>Code: AccessDenied</li>')" 1
check "nor with credentials of its own" \
    "$(PW / -o /dev/null -w '%{http_code}' -H 'Authorization: AWS4-HMAC-SHA256 Credential=AKIAWEBSITEADMIN0000/20260101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=00')" 403
python3 - "$P2" "$HERE" <<'PY'
import http.client, sys
sys.path.insert(0, sys.argv[2])
import lib_s3_signing as sig
port = int(sys.argv[1])
policy = (b'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject",'
          b'"Resource":"arn:aws:s3:::pub/*"},{"Effect":"Deny","Principal":"*","Action":"s3:GetObject",'
          b'"Resource":"arn:aws:s3:::pub/private/*"}]}')
s = sig.sign("PUT", "/pub", "policy", "127.0.0.1:%d" % port, "AKIAWEBSITEADMIN0000",
             "websiteadminsecretwebsiteadminsecret000", sig.sha256hex(policy))
c = http.client.HTTPConnection("127.0.0.1", port)
c.request("PUT", "/pub?policy", body=policy, headers=s.headers)
r = c.getresponse(); r.read()
if r.status >= 300:
    print("setup policy: %d" % r.status)
PY
check "a policy that lets anyone read lets the website be read" "$(PW /)" public
check "a missing key, which nobody may list, is AccessDenied" "$(PW /nothing -o /dev/null -w '%{http_code}')" 403
check "answered with the error document" "$(PW /nothing)" public-oops
check "a key the policy denies is refused" "$(PW /private/error.html -o /dev/null -w '%{http_code}')" 403
check "and the S3 API answers to the same policy" "$(code "http://127.0.0.1:$P2/pub/index.html")" 200

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || { echo "  FAILED"; exit 1; }
