#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# A tunnel edge asking each visitor of a protected service for its auth, as a proxy's --auth does, before any byte of
# the request reaches the machine at home.
#
# What each part would catch:
#   * a protected service reached with no credential, or an open one asking for one
#   * only a connection's first request asked, when the entrance hands one connection from visitor to visitor
#   * a body, chunked or not, read as the next request's head, or the request behind it carried unasked
#   * an upgrade the service refused leaving the connection unasked from then on
#   * a browser not sent to sign in at the idp, or a signed-in one refused
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
tally() { while IFS= read -r line; do case "$line" in ok\ *) ok ;; bad\ *) bad "${line#bad }" "" ;; *) echo "  $line" ;; esac; done; }

echo "=== Integration: a tunnel edge asks a protected service's visitors for its auth ==="
daemon_isolate tunnelvis
T=$SOCKETLEY_TMPD
PE=$((SL_PORT_BASE + 1970))
PB=$((SL_PORT_BASE + 1971))
PI=$((SL_PORT_BASE + 1972))
PM=$((SL_PORT_BASE + 1973))
I="http://127.0.0.1:$PI"
# The daemon's config is read at startup and names the metrics port; the variable would name another file.
unset SOCKETLEY_CONFIG
mkdir -p "$HOME/.config/socketley"
printf 'config = {\n    metrics_port = %s\n}\n' "$PM" > "$HOME/.config/socketley/config.lua"
python3 - "$PB" "$T/hits" <<'PY' &
import http.server, socketserver, sys
pb, hits = int(sys.argv[1]), sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def hit(self):
        with open(hits, "a") as f:
            f.write(self.path + "\n")
    def answer(self, status, body):
        self.send_response(status); self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        self.hit()
        if self.path == "/up-ok":
            self.send_response(101); self.send_header("Upgrade", "echo"); self.send_header("Connection", "Upgrade")
            self.end_headers(); self.wfile.flush()
            while True:
                d = self.rfile.read1(65536)
                if not d:
                    break
                self.wfile.write(d); self.wfile.flush()
            self.close_connection = True
            return
        if self.path == "/up-no":
            self.answer(400, b"no upgrade here")
            return
        self.answer(200, ("home %s" % self.path).encode())
    def do_POST(self):
        self.hit()
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            body = b""
            while True:
                n = int(self.rfile.readline().strip(), 16)
                if n == 0:
                    self.rfile.readline()
                    break
                body += self.rfile.read(n); self.rfile.readline()
        else:
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.answer(200, ("got %d" % len(body)).encode())
    def log_message(self, *a): pass
class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
S(("127.0.0.1", pb), H).serve_forever()
PY
BACKEND=$!
trap 'kill $BACKEND 2>/dev/null; daemon_stop' EXIT
daemon_start "$BIN"

echo "s3cret-token" > "$T/tokens"
"$BIN" create idp auth -p "$PI" --issuer "$I" -s >/dev/null 2>&1 || bad "the idp is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$I/jwks")" = 200 ] && break; sleep 0.1; done
"$BIN" idp-user auth add alice --password alicepassword1 >/dev/null 2>&1
"$BIN" create tunnel t --mode edge -p "$PE" -s >/dev/null 2>&1 || bad "an edge is made" "$(tail -3 "$SOCKETLEY_DLOG")"

out=$("$BIN" tunnel t invite pi --http "open,x=bogus" 2>&1); rc=$?
[ "$rc" -eq 1 ] && case "$out" in *"--http x: --auth takes"*) true ;; *) false ;; esac && ok || bad "an auth no proxy would take is refused" "rc $rc: $out"
INV=$("$BIN" tunnel t invite pi --http "open,tok=bearer:$T/tokens,web=idp:auth" 2>&1)
case "$INV" in pi.*) ok ;; *) bad "an invitation with protected services is printed" "$INV" ;; esac
[ "$("$BIN" tunnel t list)" = "$(printf 'pi\tinvited\topen,tok=bearer:%s,web=idp:auth' "$T/tokens")" ] && ok \
    || bad "list shows what each service asks" "$("$BIN" tunnel t list 2>&1)"
"$BIN" create tunnel home --mode agent --to "http://127.0.0.1:$PE" --join "$INV" \
    --offer "open=127.0.0.1:$PB,tok=127.0.0.1:$PB,web=127.0.0.1:$PB" -s >/dev/null 2>&1 || bad "an agent is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 50); do "$BIN" tunnel t list | grep -q joined && break; sleep 0.1; done
sock_of() {
    local p; p=$(dirname "$(find "$HOME/.local/share" -path '*tunnel/t/agents' 2>/dev/null | head -1)")/$1.sock
    [ ${#p} -ge 100 ] && p="/tmp/skl-$(printf '%s' "$p" | sha256sum | cut -c1-16).sock"
    echo "$p"
}
for _ in $(seq 1 50); do [ -S "$(sock_of web)" ] && [ "$(curl -s -m 2 --unix-socket "$(sock_of open)" http://open/ready)" = "home /ready" ] && break; sleep 0.1; done

COOKIE=$(python3 - "$PI" <<'PY'
import sys, urllib.request, urllib.parse, urllib.error
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None
r = urllib.request.Request("http://127.0.0.1:%s/login" % sys.argv[1], method="POST",
    data=urllib.parse.urlencode({"username": "alice", "password": "alicepassword1"}).encode(),
    headers={"Content-Type": "application/x-www-form-urlencoded"})
try:
    h = urllib.request.build_opener(NoRedirect).open(r).headers
except urllib.error.HTTPError as e:
    h = e.headers
print((h.get("Set-Cookie") or "").split(";")[0])
PY
)
case "$COOKIE" in skl_idp=?*) ok ;; *) bad "alice signs in at the idp" "$COOKIE" ;; esac

tally < <(python3 - "$(sock_of open)" "$(sock_of tok)" "$(sock_of web)" "$T/hits" "$COOKIE" 2>&1 <<'PY' || echo "bad the visitor checks ran to their end"
import sys, socket, time
open_s, tok_s, web_s, hits, cookie = sys.argv[1:6]
def check(name, cond, detail=""):
    print(("ok " if cond else "bad ") + name + ("" if cond else ": " + detail))
def conn(path):
    s = socket.socket(socket.AF_UNIX); s.settimeout(10); s.connect(path); return s
left = {}
def read_answer(s):
    # One answer whole: its head, and a body by its Content-Length, what came behind it kept for the next.
    buf = left.pop(s.fileno(), b"")
    while b"\r\n\r\n" not in buf:
        d = s.recv(65536)
        if not d:
            return buf
        buf += d
    head, _, rest = buf.partition(b"\r\n\r\n")
    n = 0
    for line in head.split(b"\r\n")[1:]:
        k, _, v = line.partition(b":")
        if k.strip().lower() == b"content-length":
            n = int(v)
    while len(rest) < n:
        d = s.recv(65536)
        if not d:
            break
        rest += d
    left[s.fileno()] = rest[n:]
    return head + b"\r\n\r\n" + rest[:n]
def status(a):
    return a.split(b"\r\n", 1)[0].decode(errors="replace")
def closed(s):
    try:
        return s.recv(1) == b""
    except socket.timeout:
        return False
    except OSError:
        return True
def hit(path):
    try:
        return path in open(hits).read().split("\n")
    except FileNotFoundError:
        return False
def req(path, extra="", method="GET", body=b""):
    h = "%s %s HTTP/1.1\r\nHost: svc.t.example.com\r\n%s" % (method, path, extra)
    if body:
        h += "Content-Length: %d\r\n" % len(body)
    return h.encode() + b"\r\n" + body
TOK = "Authorization: Bearer s3cret-token\r\n"

s = conn(open_s); s.sendall(req("/o1")); a = read_answer(s)
check("an open service lets a visitor through with nothing asked", a.endswith(b"home /o1"), repr(a[:200]))

s = conn(tok_s); s.sendall(req("/t-none")); a = read_answer(s)
check("a protected service refuses a visitor with no token", status(a) == "HTTP/1.1 401 Unauthorized" and b"WWW-Authenticate: Bearer" in a, repr(a[:300]))
check("and the request never reached home", not hit("/t-none"))
s = conn(tok_s); s.sendall(req("/t-bad", "Authorization: Bearer wrong\r\n")); a = read_answer(s)
check("a wrong token is refused", status(a) == "HTTP/1.1 401 Unauthorized", repr(a[:200]))

s = conn(tok_s); s.sendall(req("/t1", TOK)); a = read_answer(s)
check("the right token lets it through", a.endswith(b"home /t1"), repr(a[:200]))
s.sendall(req("/t2-none")); a = read_answer(s)
check("the next request on that connection is asked again, and refused without one", status(a) == "HTTP/1.1 401 Unauthorized", repr(a[:200]))
check("and is not carried", not hit("/t2-none"))
check("and the connection is closed behind the refusal", closed(s))

# Pipelined in one write, as an entrance on a reused connection may: a request with a body, then one asking nothing.
s = conn(tok_s); s.sendall(req("/p1", TOK, "POST", b"GET /smuggled HTTP/1.1\r\n\r\n") + req("/p2-none"))
a1 = read_answer(s); a2 = read_answer(s)
check("a body is carried as the body", a1.endswith(b"got 26"), repr(a1[:200]))
check("and what follows it is asked as a request of its own", status(a2) == "HTTP/1.1 401 Unauthorized", repr(a2[:200]))
check("so neither a request in the body nor the one behind it reaches home", not hit("/smuggled") and not hit("/p2-none"))

s = conn(tok_s)
s.sendall(b"POST /c1 HTTP/1.1\r\nHost: x\r\n" + TOK.encode() + b"Transfer-Encoding: chunked\r\n\r\n"
          b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n" + req("/c2-none"))
a1 = read_answer(s); a2 = read_answer(s)
check("a chunked body is carried whole", a1.endswith(b"got 11"), repr(a1[:200]))
check("and the request after its last chunk is asked", status(a2) == "HTTP/1.1 401 Unauthorized" and not hit("/c2-none"), repr(a2[:200]))

s = conn(tok_s); s.sendall(req("/up-no", TOK + "Connection: Upgrade\r\nUpgrade: echo\r\n")); a = read_answer(s)
check("an upgrade the service refuses is answered", status(a) == "HTTP/1.1 400 Bad Request", repr(a[:200]))
try:
    s.sendall(req("/after-up-none"))
except OSError:
    pass
time.sleep(0.5)
check("and nothing after it goes on unasked", not hit("/after-up-none"))
s = conn(tok_s); s.sendall(req("/up-ok", TOK + "Connection: Upgrade\r\nUpgrade: echo\r\n")); a = read_answer(s)
check("an upgrade the service takes is switched", status(a).startswith("HTTP/1.1 101"), repr(a[:200]))
s.sendall(b"GET /raw-is-the-service's HTTP/1.1\r\n\r\n")
got = b""
while len(got) < 38:
    d = s.recv(65536)
    if not d:
        break
    got += d
check("after which the bytes are the service's own, carried unasked", got == b"GET /raw-is-the-service's HTTP/1.1\r\n\r\n", repr(got))

s = conn(web_s); s.sendall(req("/w-browser", "Accept: text/html\r\n")); a = read_answer(s)
loc = [l for l in a.split(b"\r\n") if l.lower().startswith(b"location:")]
check("a browser with no sign-in is sent to sign in at the idp", status(a) == "HTTP/1.1 302 Found" and loc and b"/login" in loc[0] and b"svc.t.example.com" in loc[0], repr(a[:400]))
s = conn(web_s); s.sendall(req("/w-api")); a = read_answer(s)
check("anything else with no sign-in is told 401", status(a) == "HTTP/1.1 401 Unauthorized", repr(a[:200]))
s = conn(web_s); s.sendall(req("/w-in", "Cookie: %s\r\n" % cookie)); a = read_answer(s)
check("a signed-in visitor is let through", a.endswith(b"home /w-in"), repr(a[:300]))
check("and no refused request reached home", not any(hit(p) for p in ("/w-browser", "/w-api")))
PY
)

case "$("$BIN" stats t)" in *visitors_refused:[1-9]*) ok ;; *) bad "the refusals are counted" "$("$BIN" stats t 2>&1 | tr '\n' ' ')" ;; esac
for _ in $(seq 1 50); do curl -s "http://127.0.0.1:$PM/metrics" | grep -q '^socketley_tunnel_visitors_refused_total{name="t"} [1-9]' && break; sleep 0.2; done
M=$(curl -s "http://127.0.0.1:$PM/metrics")
grep -q '^socketley_tunnel_visitors_refused_total{name="t"} [1-9]' <<<"$M" && grep -q '^socketley_tunnel_links{name="t"} 1$' <<<"$M" &&
    grep -q '^socketley_tunnel_bytes_out_total{name="home"} [1-9]' <<<"$M" && ok \
    || bad "the metrics carry the tunnel's figures" "$(grep socketley_tunnel <<<"$M" | head -12 | tr '\n' ' ')"

out=$("$BIN" tunnel t set pi --http "open,tok,web=idp:auth" 2>&1); rc=$?
[ "$rc" -eq 0 ] && ok || bad "a service is opened by set" "rc $rc: $out"
for _ in $(seq 1 50); do [ "$(curl -s -m 2 --unix-socket "$(sock_of tok)" http://tok/opened)" = "home /opened" ] && break; sleep 0.1; done
[ "$(curl -s -m 2 --unix-socket "$(sock_of tok)" http://tok/opened)" = "home /opened" ] && ok || bad "and asks nothing from then on" "$(curl -s -m 2 -i --unix-socket "$(sock_of tok)" http://tok/opened 2>&1 | head -1)"

echo "  Results: $PASS/$((PASS+FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
