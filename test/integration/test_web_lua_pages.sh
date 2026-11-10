#!/usr/bin/env bash
# Integration test: with --lua-pages a .lua file under a web runtime's --root answers its address as a page
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# A page is compiled once for each version of its file and run in an
# environment of its own a request, with the request read for it and the
# helpers it answers with.  What would be wrong and quiet: a page's source sent
# as a file, a global one request set seen by the next, an edited page answered
# by the old version, a page past the root or one a request may not name run, a
# raise answered with a 200, a file shadowed by a page, a POST refused where
# a page takes it, or a page that waits on socketley.http holding every other
# request of the runtime until it is answered.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate webpages

P=$((SL_PORT_BASE+1976)); P2=$((SL_PORT_BASE+1977)); P3=$((SL_PORT_BASE+1978)); P4=$((SL_PORT_BASE+1979))
PH=$((SL_PORT_BASE+1980))
NAMES="pages plainweb router sharded"
W="$SOCKETLEY_TMPD/www"
mkdir -p "$W/sub" "$W/both" "$W/_lib" "$W/_next" "$W/_parts"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "expected '$2', got '$3'"; fi; }

HOST_PID=""
cleanup() {
    [ -n "$HOST_PID" ] && kill "$HOST_PID" 2>/dev/null
    for n in $NAMES; do "$BIN" stop "$n"   >/dev/null 2>&1 || true; done
    sleep 0.3
    for n in $NAMES; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: Lua pages (web --lua-pages) ==="

get()  { curl -s --max-time 5 "http://127.0.0.1:$P$1" "${@:2}"; }
code() { curl -s --max-time 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$P$1" "${@:2}"; }

cat > "$W/index.lua" <<'EOF'
seen = (seen or 0) + 1
echo("index ", req.method, " ", req.path, " seen=", seen)
EOF
cat > "$W/table.lua" <<'EOF'
header("X-From", "header()")
return { status = 201, headers = { ["Content-Type"] = "text/plain" }, body = "made" }
EOF
echo 'local x; return x.field' > "$W/raises.lua"
echo 'this is ( not lua' > "$W/syntax.lua"
echo 'echo("v1")' > "$W/edit.lua"
echo 'echo("sub index")' > "$W/sub/index.lua"
echo 'echo("a page beside the file")' > "$W/both/index.lua"
echo 'the static index' > "$W/both/index.html"
echo 'echo("about ", req.path)' > "$W/about.lua"
echo 'echo("never run")' > "$W/_lib/inc.lua"
echo 'echo("never run")' > "$W/_hidden.lua"
echo 'a build asset' > "$W/_next/chunk.js"
echo 'a static file' > "$W/file.txt"
echo 'secret' > "$SOCKETLEY_TMPD/secret.txt"
cat > "$W/form.lua" <<'EOF'
local g, p, f, c = req.get, req.post, req.files, req.cookies
echo("a=", g.a or "-", " tags=", g.tag and table.concat(g.tag, ",") or "-",
     " name=", escape(p.name or "-"), " sid=", c.sid or "-", " ua=", req:header("USER-AGENT") or "-")
if f.up then echo(" up=", f.up.filename, ":", f.up.size, ":", f.up.data) end
set_cookie("a", "1")
set_cookie("b", "2", { max_age = 60, secure = true })
EOF
echo 'redirect("/index.lua", 303)' > "$W/go.lua"
cat > "$W/api.lua" <<'EOF'
return json({ sha = socketley.sha256("abc"), mac = socketley.hmac_sha256("k", "m"), n = #socketley.random_hex(8) }, 202)
EOF
echo 'echo(req.method, " ", #req.body)' > "$W/len.lua"
echo 'for i = 1, 400 do echo("line ", i, "\n") end' > "$W/long.lua"
cat > "$W/hdr.lua" <<'EOF'
return { headers = { ["X-Bad"] = "a\r\nInjected: yes", ["Content-Length"] = "1", ["X-Ok"] = "fine" }, body = "hdr" }
EOF
echo 'echo("route ", req.method, " ", req.path)' > "$W/app.lua"
cat > "$W/esc.lua" <<'EOF'
echo(escape([[a&b<c>d"e'f]]), "|", escape(42), "|", escape("plain"))
echo("|", url_decode("a+b%41%4a%zz%4"), "|", url_decode("plain"))
EOF
cat > "$W/_parts/head.lua" <<'EOF'
local title = ...
echo("<h1>", escape(title), "</h1>")
return #title
EOF
cat > "$W/withhead.lua" <<'EOF'
local n = include("_parts/head.lua", "A & B")
echo(" n=", n, " ", req.path)
EOF
echo 'include("../outside.lua")' > "$W/badinclude.lua"
mkdir -p "$W/_views"
cat > "$W/_views/list.tpl" <<'EOF'
<h1>{{ title }}</h1>
{% for _, it in ipairs(items) do %}
<li>{{ it.name }}{{ it.note|none }}</li>
{% end %}
{{{ html }}} {{ raw(req.path) }} {{ #items }}
EOF
cat > "$W/view.lua" <<'EOF'
return render("_views/list.tpl", { title = "A<B", items = { { name = "x" }, { name = "y", note = "!" } },
                                   html = "<b>b</b>" })
EOF
cat > "$W/slowid.lua" <<LUAEOF
local me = req.get.n
local r = socketley.http{ url = "http://127.0.0.1:$PH/slow" }
echo(me, "=", req.get.n, " ", r.body)
LUAEOF
cat > "$W/slow.lua" <<LUAEOF
local a = socketley.http{ url = "http://127.0.0.1:$PH/slow" }
local b = socketley.http{ url = "http://127.0.0.1:$PH/fast" }
echo(a.body, "+", b.body)
LUAEOF

# A host that answers /slow after a second and a half and anything else at once.
python3 -I - "$PH" > "$SOCKETLEY_TMPD/host.log" 2>&1 <<'PY' &
import http.server, socketserver, sys, time
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/slow":
            time.sleep(1.5)
        body = (self.path.strip("/") + "-done").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
S(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
HOST_PID=$!

daemon_start "$BIN"
create_ok "a web runtime with pages" "$BIN" create web pages -p "$P" --root "$W" --lua-pages -s
create_ok "a web runtime without --lua-pages" "$BIN" create web plainweb -p "$P2" --root "$W" -s
create_ok "a web runtime whose fallback is a page" "$BIN" create web router -p "$P3" --root "$W" --lua-pages --fallback app.lua -s
for _ in $(seq 1 50); do [ "$(code /file.txt)" = 200 ] && break; sleep 0.1; done

check "/ runs index.lua" "index GET / seen=1" "$(get /)"
check "a global set by one request is not the next one's" "index GET / seen=1" "$(get /)"
check "a returned table is the response" "201|made" "$(code /table.lua)|$(get /table.lua)"
check "and a header() it does not set is sent" "1" "$(curl -s -D - -o /dev/null "http://127.0.0.1:$P/table.lua" | grep -ci '^X-From: header()')"
check "a page that raises is a 500" "500" "$(code /raises.lua)"
check "a page that does not compile is a 500" "500" "$(code /syntax.lua)"
check "a directory's index.lua" "sub index" "$(get /sub/)"
check "a directory named without its slash goes to it" "301" "$(code /sub)"
check "an index.html beside an index.lua answers first" "the static index" "$(get /both/)"
check "an address without .lua runs the page it names" "about /about" "$(get /about)"
check "a file that is not a page is served" "a static file" "$(get /file.txt)"
check "a page that is not there is a 404" "404" "$(code /none.lua)"
check "escape() makes entities of all five characters, and url_decode() leaves a % that is not one as it is" \
    "a&amp;b&lt;c&gt;d&quot;e&#39;f|42|plain|a bAJ%zz%4|plain" "$(get /esc.lua)"
check "include runs a file under the root in the page's environment, with its arguments and what it returns" \
    "<h1>A &amp; B</h1> n=5 /withhead.lua" "$(get /withhead.lua)"
check "and a path out of the root is a 500, never a read" "500" "$(code /badinclude.lua)"
check "render fills a template: escaped values, a loop, a default, raw HTML and the page's helpers" \
    "$(printf '<h1>A&lt;B</h1>\n<li>xnone</li>\n<li>y!</li>\n<b>b</b> /view.lua 2')" "$(get /view.lua)"
check "a template is never sent as it lies" "404" "$(code /_views/list.tpl)"
check "a page under a _ directory or named with _ is never run" "404|404|404" \
    "$(code /_lib/inc.lua)|$(code /_hidden.lua)|$(code /_lib/inc)"
check "a file under a _ directory is still served" "a build asset" "$(get /_next/chunk.js)"
check "nothing past the root" "404|404" "$(code /../secret.txt)|$(code /%2e%2e/secret.txt)"
check "a page's source is never sent" "0" "$(get /index.lua | grep -c 'seen = ')"
check "without --lua-pages the same file is a file" "1" "$(curl -s "http://127.0.0.1:$P2/index.lua" | grep -c 'seen = ')"
check "and a POST is refused there" "405" "$(curl -s -o /dev/null -w '%{http_code}' -d x=1 "http://127.0.0.1:$P2/index.lua")"

check "v1 before the edit" "v1" "$(get /edit.lua)"
sleep 1.1   # a second apart, so the mtime differs on a filesystem that keeps whole seconds
echo 'echo("v2, longer")' > "$W/edit.lua"
check "an edited page is compiled again" "v2, longer" "$(get /edit.lua)"

check "query, form, cookies and headers are read" "a=1 tags=x,y name=- sid=abc ua=probe/1" \
    "$(get '/form.lua?a=1&tag%5B%5D=x&tag[]=y' -H 'Cookie: sid=abc; other=z' -A probe/1)"
check "a posted field is escaped by escape()" "a=- tags=- name=&lt;b&gt;bob&lt;/b&gt; sid=- ua=curl" \
    "$(get /form.lua --data-urlencode 'name=<b>bob</b>' -A curl)"
printf 'file body' > "$SOCKETLEY_TMPD/up.txt"
check "a multipart upload is a field and a file" "a=- tags=- name=al sid=- ua=curl up=up.txt:9:file body" \
    "$(get /form.lua -F name=al -F "up=@$SOCKETLEY_TMPD/up.txt" -A curl)"
check "set_cookie sends a line each" \
    "Set-Cookie: a=1; Path=/; HttpOnly; SameSite=Lax|Set-Cookie: b=2; Path=/; Max-Age=60; HttpOnly; Secure; SameSite=Lax" \
    "$(curl -s -D - -o /dev/null "http://127.0.0.1:$P/form.lua" | grep -i '^Set-Cookie' | tr -d '\r' | paste -sd'|')"
check "redirect" "303|/index.lua" \
    "$(code /go.lua)|$(curl -s -D - -o /dev/null "http://127.0.0.1:$P/go.lua" | grep -i '^Location' | tr -d '\r' | cut -d' ' -f2)"
SHA=$(printf abc | sha256sum | cut -d' ' -f1); MAC=$(printf m | openssl dgst -sha256 -hmac k | awk '{print $2}')
check "json() and the digests" "202|{\"mac\":\"$MAC\",\"n\":16,\"sha\":\"$SHA\"}" "$(code /api.lua)|$(get /api.lua)"

# The body a page is given, the methods it takes, and the framing this end keeps.
head -c 200000 /dev/zero > "$SOCKETLEY_TMPD/big.bin"
check "a body past a file's 64 KiB reaches a page whole" "POST 200000" \
    "$(get /len.lua --data-binary "@$SOCKETLEY_TMPD/big.bin" -H 'Content-Type: application/octet-stream')"
check "PUT and DELETE reach a page" "PUT 3|DELETE 0" "$(get /len.lua -X PUT -d abc)|$(get /len.lua -X DELETE)"
head -c $((9 * 1024 * 1024)) /dev/zero > "$SOCKETLEY_TMPD/huge.bin"
check "a body past 8 MiB is a 413" "413" \
    "$(code /len.lua --data-binary "@$SOCKETLEY_TMPD/huge.bin" -H 'Content-Type: application/octet-stream')"
# A HEAD and a GET in one write: the HEAD's length is the GET's body, and none of its body is sent.
HG=$(printf 'HEAD /len.lua HTTP/1.1\r\nHost: x\r\n\r\nGET /len.lua HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n' |
     timeout 5 nc -q 3 127.0.0.1 "$P" | tr -d '\r')
check "a HEAD runs the page and sends its length and no body" "2|6|0|GET 0" \
    "$(echo "$HG" | grep -c '^HTTP/1.1 200')|$(echo "$HG" | grep -i '^Content-Length' | head -1 | awk '{print $2}')|$(echo "$HG" | grep -c '^HEAD 0')|$(echo "$HG" | tail -1)"
LONG=$(curl -s -D "$SOCKETLEY_TMPD/long.h" -H 'Accept-Encoding: gzip' "http://127.0.0.1:$P/long.lua" | gzip -dc 2>/dev/null | tail -1)
check "a page's text goes gzipped to a client that takes it" "1|1|line 400" \
    "$(grep -ci '^Content-Encoding: gzip' "$SOCKETLEY_TMPD/long.h")|$(grep -ci '^Vary: Accept-Encoding' "$SOCKETLEY_TMPD/long.h")|$LONG"
check "and as it is to one that does not" "0|line 400" \
    "$(curl -s -D - -o /dev/null "http://127.0.0.1:$P/long.lua" | grep -ci '^Content-Encoding')|$(get /long.lua | tail -1)"
HDR=$(curl -s -D - -o /dev/null "http://127.0.0.1:$P/hdr.lua" | tr -d '\r')
check "a header with a line break is left out, the framing is this end's" "0|0|1|3" \
    "$(echo "$HDR" | grep -ci '^Injected')|$(echo "$HDR" | grep -ci '^X-Bad')|$(echo "$HDR" | grep -ci '^X-Ok: fine')|$(echo "$HDR" | grep -i '^Content-Length' | awk '{print $2}')"
# Two requests in one write: a page's answer and a file's, in order.
PIPE=$(printf 'GET /about HTTP/1.1\r\nHost: x\r\n\r\nGET /file.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n' |
       timeout 5 nc -q 3 127.0.0.1 "$P" | tr -d '\r' | grep -oE 'about /about|a static file')
check "a pipelined page and file answer in order" "about /about|a static file" "$(echo "$PIPE" | paste -sd'|')"

# A page that waits on socketley.http lets the runtime answer the rest meanwhile.
for _ in $(seq 1 50); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PH/fast")" = 200 ] && break; sleep 0.1; done
curl -s --max-time 10 "http://127.0.0.1:$P/slow.lua" > "$SOCKETLEY_TMPD/slow.out" &
SLOW=$!
sleep 0.3
T0=$(date +%s%N)
QUICK=$(get /about)
T1=$(date +%s%N)
wait "$SLOW" || true
check "a page that waits twice gets both answers" "slow-done+fast-done" "$(cat "$SOCKETLEY_TMPD/slow.out")"
if [ "$QUICK" = "about /about" ] && [ $(( (T1 - T0) / 1000000 )) -lt 700 ]; then ok; else
    bad "a page is answered while another waits on its host" "'$QUICK' after $(( (T1 - T0) / 1000000 ))ms"; fi
# Two requests waiting in the same page at once: each finds its own request when it goes on.
curl -s --max-time 10 "http://127.0.0.1:$P/slowid.lua?n=1" > "$SOCKETLEY_TMPD/id1.out" &
I1=$!
sleep 0.2
curl -s --max-time 10 "http://127.0.0.1:$P/slowid.lua?n=2" > "$SOCKETLEY_TMPD/id2.out" &
I2=$!
wait "$I1" "$I2" || true
check "two requests waiting in one page each keep their own request" "1=1 slow-done|2=2 slow-done" \
    "$(cat "$SOCKETLEY_TMPD/id1.out")|$(cat "$SOCKETLEY_TMPD/id2.out")"
PIPE=$(printf 'GET /slow.lua HTTP/1.1\r\nHost: x\r\n\r\nGET /file.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n' |
       timeout 8 nc -q 6 127.0.0.1 "$P" | tr -d '\r' | grep -oE 'slow-done\+fast-done|a static file')
check "a request behind a waiting page is answered after it" "slow-done+fast-done|a static file" "$(echo "$PIPE" | paste -sd'|')"

R="http://127.0.0.1:$P3"
check "a .lua fallback routes an address nothing answers" "route GET /shop/item/7" "$(curl -s "$R/shop/item/7")"
check "and takes a POST" "route POST /api/save" "$(curl -s -d x=1 "$R/api/save")"
check "a file still answers first" "a static file" "$(curl -s "$R/file.txt")"
check "a missing asset is not routed" "404" "$(curl -s -o /dev/null -w '%{http_code}' "$R/missing.css")"

# Every shard runs pages in its own state.
create_ok "a sharded web runtime with pages" "$BIN" create web sharded -p "$P4" --root "$W" --lua-pages --shards 2 -s
for _ in $(seq 1 50); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$P4/file.txt")" = 200 ] && break; sleep 0.1; done
SH=""
for _ in $(seq 1 20); do SH="$SH$(curl -s "http://127.0.0.1:$P4/sub/")|"; done
check "each shard answers a page" "sub index" "$(echo "$SH" | tr '|' '\n' | grep -v '^$' | sort -u | paste -sd'|')"

# The flag is kept with the runtime.
kill "$SOCKETLEY_DPID" 2>/dev/null || true
wait "$SOCKETLEY_DPID" 2>/dev/null || true
daemon_start "$BIN"
for _ in $(seq 1 50); do [ "$(code /file.txt)" = 200 ] && break; sleep 0.1; done
check "pages after a daemon restart" "index GET / seen=1" "$(get /)"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
