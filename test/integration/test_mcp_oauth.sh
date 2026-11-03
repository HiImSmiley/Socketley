#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: a person signs an MCP client in to an mcp runtime through an idp runtime, as the MCP revisions have
# it -- protected resource metadata, a client known by the address of its metadata document, a token for the resource.
#
# What each part would catch:
#   * a client not told where to sign in, or the idp not saying it takes clients by their metadata document
#   * a metadata document of another address, or a redirect it does not list, taken; or one fetched on every request
#   * an application nobody registered given a code without the person allowing it, or allowed from another site
#   * a token for no resource, or for another, taken by the server; or a code or refresh moved to another resource
#   * the admin bit or the account's id not reaching the script, or a disabled account still let in
#   * a loopback redirect refused for the port the application took
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: an MCP client signs in to an mcp runtime through an idp ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
command -v openssl >/dev/null 2>&1 || { echo "  SKIP: openssl is required"; exit 0; }
daemon_isolate mcpoauth
T=$SOCKETLEY_TMPD
PI=$((SL_PORT_BASE + 1980)); PM=$((SL_PORT_BASE + 1981)); PC=$((SL_PORT_BASE + 1982))
unset SOCKETLEY_CONFIG

# The applications' metadata documents, served over TLS as https://client.test/..., under a CA the idp is told of.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=ca -keyout "$T/ca.key" \
    -out "$T/ca.pem" -addext basicConstraints=critical,CA:TRUE >/dev/null 2>&1
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj /CN=client.test -keyout "$T/c.key" \
    -out "$T/c.csr" >/dev/null 2>&1
printf 'subjectAltName=DNS:client.test\n' > "$T/c.ext"
openssl x509 -req -in "$T/c.csr" -CA "$T/ca.pem" -CAkey "$T/ca.key" -CAcreateserial -days 2 -extfile "$T/c.ext" \
    -out "$T/c.pem" >/dev/null 2>&1
python3 - "$PC" "$T" <<'PY' > "$T/docs.log" 2>&1 &
import http.server, json, ssl, sys
port, d = int(sys.argv[1]), sys.argv[2]
fetches = {}
def doc(path, cid=None, **more):
    o = {"client_id": cid or "https://client.test" + path, "client_name": "Test Agent",
         "redirect_uris": ["http://127.0.0.1/callback"], "grant_types": ["authorization_code", "refresh_token"],
         "response_types": ["code"], "token_endpoint_auth_method": "none"}
    o.update(more)
    return o
docs = {"/agent.json": doc("/agent.json"), "/other.json": doc("/other.json", cid="https://client.test/agent.json"),
        "/secret.json": doc("/secret.json", token_endpoint_auth_method="client_secret_basic")}
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/count":
            b = json.dumps(fetches).encode()
        elif self.path in docs:
            fetches[self.path] = fetches.get(self.path, 0) + 1
            b = json.dumps(docs[self.path]).encode()
        else:
            self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers(); return
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "max-age=600"); self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
s = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(d + "/c.pem", d + "/c.key")
s.socket = ctx.wrap_socket(s.socket, server_side=True)
s.serve_forever()
PY
DOCS=$!
trap 'kill $DOCS 2>/dev/null; daemon_stop' EXIT
export SOCKETLEY_IDP_CLIENT_CA="$T/ca.pem" SOCKETLEY_IDP_CLIENT_CONNECT="127.0.0.1:$PC"
daemon_start "$BIN"

cat > "$T/clients" <<EOF
# a command line tool registered here, which needs no one's leave
cli - http://127.0.0.1/cb
EOF
cat > "$T/tools.lua" <<'EOF'
mcp.tool{ name = "whoami", read_only = true,
  handler = function(args, who) return { structured = { name = who.name, admin = who.admin, sub = who.sub or "" } } end }
mcp.tool{ name = "reboot", admin = true, handler = function() return "rebooting" end }
EOF
cat > "$T/keys" <<EOF
robot robotsecretrobotsecret1
EOF

out=$("$BIN" create idp bad -p $((PI + 10)) --issuer "http://127.0.0.1:$PI" --resources "http://mcp.test/mcp" 2>&1); rc=$?
[ "$rc" -eq 1 ] && ok || bad "a resource that is no https address is refused" "rc $rc: $out"
out=$("$BIN" create mcp bad -p $((PM + 10)) --idp auth 2>&1); rc=$?
[ "$rc" -ne 0 ] && case "$out" in *"--domain"*) true ;; *) false ;; esac && ok \
    || bad "--idp without a --domain to name the server by is refused" "rc $rc: $out"
out=$("$BIN" create mcp bad -p $((PM + 10)) --idp auth --domain shop 2>&1); rc=$?
[ "$rc" -ne 0 ] && case "$out" in *"whole name"*) true ;; *) false ;; esac && ok \
    || bad "--idp with a first --domain of no dot, a name under every zone, is refused" "rc $rc: $out"
out=$("$BIN" create mcp bad -p $((PM + 10)) --anonymous --idp auth --domain mcp.test 2>&1); rc=$?
[ "$rc" -ne 0 ] && ok || bad "--anonymous with --idp is refused" "rc $rc: $out"
"$BIN" remove bad >/dev/null 2>&1

"$BIN" create idp auth -p "$PI" --issuer "http://127.0.0.1:$PI" --clients "$T/clients" \
    --resources "HTTPS://MCP.test/mcp" -s >/dev/null 2>&1 && ok || bad "the idp is made" "$(tail -3 "$SOCKETLEY_DLOG")"
"$BIN" create mcp shop -p "$PM" --domain mcp.test --idp auth --keys "$T/keys" --lua "$T/tools.lua" -s >/dev/null 2>&1 \
    && ok || bad "the mcp server is made with --domain and --idp" "$(tail -3 "$SOCKETLEY_DLOG")"
ALICE=$("$BIN" idp-user auth add alice --password alicepassword1 --groups admins 2>&1)
"$BIN" idp-user auth add bob --password bobpassword123 >/dev/null 2>&1
for p in "$PI/jwks" "$PM/mcp"; do
    for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p")" != 000 ] && break; sleep 0.1; done
done

flow() {
    timeout 120 python3 - "$PI" "$PM" "$PC" "$ALICE" "$1" "$T" <<'PY' || echo "bad the $1 checks ran to their end"
import base64, hashlib, html.parser, json, os, re, ssl, sys, time, urllib.parse, urllib.request, urllib.error
pi, pm, pc, alice_id, phase, tmpd = sys.argv[1:7]
I = "http://127.0.0.1:%s" % pi
M = "http://127.0.0.1:%s" % pm
RES = "https://mcp.test/mcp"
AGENT = "https://client.test/agent.json"
CB = "http://127.0.0.1:43123/callback"
rows = []
def check(what, cond, got=""):
    print(("ok " if cond else "bad ") + what + ("" if cond else ": " + str(got)[:300]))

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None
op = urllib.request.build_opener(NoRedirect)
def at(url, method="GET", form=None, headers=None, data=None):
    h = dict(headers or {})
    if form is not None:
        data = urllib.parse.urlencode(form).encode(); h["Content-Type"] = "application/x-www-form-urlencoded"
    try:
        with op.open(urllib.request.Request(url, data=data, method=method, headers=h), timeout=15) as r:
            return r.status, r.read().decode(), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), e.headers
def q(**kw): return "?" + urllib.parse.urlencode(kw)
def loc(h): return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(h.get("Location", "")).query))
def claims(tok):
    p = tok.split(".")[1]; return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
class Inputs(html.parser.HTMLParser):
    def __init__(self): super().__init__(); self.f = {}
    def handle_starttag(self, tag, a):
        a = dict(a)
        if tag == "input" and a.get("type") == "hidden": self.f[a["name"]] = a.get("value", "")
def hidden(page):
    p = Inputs(); p.feed(page); return p.f
FORM = {"Origin": I}
def mcp(token, method, params=None, name=None):
    p = dict(params or {}); p["_meta"] = {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                                          "io.modelcontextprotocol/clientCapabilities": {}}
    h = {"Content-Type": "application/json", "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": method}
    if name: h["Mcp-Name"] = name
    if token: h["Authorization"] = "Bearer " + token
    st, body, hh = at(M + "/mcp", "POST", data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": p}).encode(), headers=h)
    return st, (json.loads(body) if body else None), hh
def pkce():
    v = base64.urlsafe_b64encode(os.urandom(40)).rstrip(b"=").decode()
    return v, base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()
def ask(client=AGENT, redirect=CB, resource=RES, **more):
    v, ch = pkce()
    a = dict(client_id=client, redirect_uri=redirect, response_type="code", scope="openid offline_access", state="st1",
             code_challenge=ch, code_challenge_method="S256")
    if resource is not None: a["resource"] = resource
    a.update(more)
    return a, v
def sign_in(a, user, password):
    st, body, h = at(I + "/authorize" + q(**a))
    if st != 200: return st, body, h, None
    st, body, h = at(I + "/authorize", "POST", dict(a, username=user, password=password), FORM)
    return st, body, h, (h.get("Set-Cookie") or "").split(";")[0]
def allow(page, cookie, answer="1", origin=I):
    return at(I + "/consent", "POST", dict(hidden(page), allow=answer), {"Origin": origin, "Cookie": cookie})
def exchange(code, v, client=AGENT, redirect=CB, resource=RES):
    f = dict(grant_type="authorization_code", code=code, redirect_uri=redirect, client_id=client, code_verifier=v)
    if resource: f["resource"] = resource
    st, body, _ = at(I + "/token", "POST", f)
    return st, json.loads(body)
def login(user, password):
    a, v = ask()
    st, page, h, cookie = sign_in(a, user, password)
    st, _, h = allow(page, cookie)
    st, tok = exchange(loc(h).get("code", ""), v)
    return tok

if phase == "main":
    # The way in, as a client finds it with nothing but the server's address.
    st, d, h = mcp(None, "tools/list")
    www = h.get("WWW-Authenticate", "")
    check("a client with no token is told where the server's metadata is, and the scopes to ask",
          st == 401 and 'resource_metadata="https://mcp.test/.well-known/oauth-protected-resource/mcp"' in www
          and 'scope="openid offline_access"' in www, (st, www))
    st, body, h = at(M + "/.well-known/oauth-protected-resource/mcp")
    prm = json.loads(body) if st == 200 else {}
    check("the protected resource metadata names the server as its tokens do and the idp it signs in at",
          prm.get("resource") == RES and prm.get("authorization_servers") == [I], (st, body))
    st, body, _ = at(M + "/.well-known/oauth-protected-resource")
    check("and is at the host's own well-known address too", st == 200 and json.loads(body).get("resource") == RES, st)
    st, body, _ = at(I + "/.well-known/oauth-authorization-server")
    asm = json.loads(body) if st == 200 else {}
    check("the idp's metadata is at the address an MCP client asks first, and says it takes metadata documents",
          asm.get("client_id_metadata_document_supported") is True and asm.get("code_challenge_methods_supported") == ["S256"], body)

    # Alice signs the agent in, at a port the agent took and its document names no port of.
    a, v = ask()
    st, page, h, cookie = sign_in(a, "alice", "alicepassword1")
    check("an application known by its address is let in only once the person allows it",
          st == 200 and "Test Agent" in page and "client.test" in page and RES in page and "alice" in page
          and "program on this computer" in page and "Location" not in h, (st, page[-600:]))
    st, _, h = allow(page, cookie, origin="https://evil.test")
    check("an allowing posted from another site is refused", st == 403, st)
    st, body, _ = at(I + "/consent", "POST", dict(hidden(page), allow="1"), FORM)
    check("and so is one with no sign-in", st == 400, st)
    st, _, h = allow(page, cookie)
    got = loc(h)
    check("allowed, the code goes to the loopback port the agent took",
          st == 302 and h.get("Location", "").startswith(CB + "?") and got.get("state") == "st1" and got.get("code"), (st, h.get("Location")))
    st, tok = exchange(got.get("code", ""), v, resource="https://other.test/mcp")
    check("a code is not exchanged for another resource", st == 400 and tok.get("error") == "invalid_target", tok)
    a, v = ask()
    st, page, _ = at(I + "/authorize" + q(**a), headers={"Cookie": cookie})
    st, _, h = allow(page, cookie)
    st, tok = exchange(loc(h).get("code", ""), v)
    at_ = claims(tok.get("access_token", "x.e30.x"))
    check("the access token is for the resource, given to the agent, with a refresh token",
          st == 200 and at_.get("aud") == RES and at_.get("client_id") == AGENT and tok.get("refresh_token"), tok)
    check("the id token is still the agent's own", claims(tok.get("id_token", "x.e30.x")).get("aud") == AGENT, tok)
    st, d, _ = mcp(tok["access_token"], "tools/call", {"name": "whoami"}, "whoami")
    sc = d["result"]["structuredContent"] if st == 200 else {}
    check("the server takes it, and the script is told who by name, admin bit and the account's id",
          sc == {"name": "alice", "admin": True, "sub": alice_id}, (st, d))
    st, d, _ = mcp(tok["access_token"], "tools/list")
    check("an admin is shown the admin's tools", st == 200 and "reboot" in [t["name"] for t in d["result"]["tools"]], d)
    st, body, _ = at(I + "/token", "POST", dict(grant_type="refresh_token", refresh_token=tok["refresh_token"], client_id=AGENT,
                                                 resource="https://other.test/mcp"))
    check("a refresh is not moved to another resource", st == 400 and "invalid_target" in body, body)
    st, body, _ = at(I + "/token", "POST", dict(grant_type="refresh_token", refresh_token=tok["refresh_token"], client_id=AGENT))
    fresh = json.loads(body) if st == 200 else {}
    check("a refresh gives a token for the same resource", claims(fresh.get("access_token", "x.e30.x")).get("aud") == RES, body)
    st, d, _ = mcp(fresh.get("access_token"), "tools/call", {"name": "whoami"}, "whoami")
    check("which the server takes", st == 200, st)
    json.dump({"refreshed": fresh.get("access_token", "")}, open(tmpd + "/tokens.json", "w"))

    # Bob, who is no admin, and the key that still works beside sign-ins.
    bob = login("bob", "bobpassword123")
    st, d, _ = mcp(bob.get("access_token"), "tools/list")
    names = [t["name"] for t in d["result"]["tools"]] if st == 200 else []
    check("one who is no admin is not shown the admin's tools", names == ["whoami"], (st, names))
    st, d, _ = mcp("robotsecretrobotsecret1", "tools/call", {"name": "whoami"}, "whoami")
    check("a key of --keys is taken beside the sign-ins, with no account id",
          st == 200 and d["result"]["structuredContent"] == {"name": "robot", "admin": False, "sub": ""}, d)
    json.dump({"refreshed": fresh.get("access_token", ""), "bob": bob.get("access_token", "")}, open(tmpd + "/tokens.json", "w"))

    # What is refused.
    a, v = ask()
    st, page, _ = at(I + "/authorize" + q(**a), headers={"Cookie": cookie})
    st, _, h = allow(page, cookie, answer="0")
    check("denied, the agent is told so at its redirect", st == 302 and loc(h).get("error") == "access_denied", h.get("Location"))
    a, _ = ask(resource="https://other.test/mcp")
    st, _, h = at(I + "/authorize" + q(**a), headers={"Cookie": cookie})
    check("a resource the idp gives no tokens for is refused", st == 302 and loc(h).get("error") == "invalid_target", h.get("Location"))
    a, _ = ask(resource=None)
    st, _, h = at(I + "/authorize" + q(**a), headers={"Cookie": cookie})
    check("an application known by its address that names no resource is refused",
          st == 302 and loc(h).get("error") == "invalid_target", h.get("Location"))
    a, _ = ask(resource=RES)
    a["resource"] = [RES, RES]
    st, _, h = at(I + "/authorize?" + urllib.parse.urlencode(a, doseq=True), headers={"Cookie": cookie})
    check("as is one that names two", st == 302 and loc(h).get("error") == "invalid_target", h.get("Location"))
    a, _ = ask(redirect="http://127.0.0.1:43123/elsewhere")
    st, _, h = at(I + "/authorize" + q(**a), headers={"Cookie": cookie})
    check("a redirect the document does not list is refused, and nobody is sent there", st == 400 and "Location" not in h, st)
    a, _ = ask(client="https://client.test/other.json")
    st, _, h = at(I + "/authorize" + q(**a), headers={"Cookie": cookie})
    check("a document naming another address than its own is refused", st == 400 and "Location" not in h, st)
    a, _ = ask(client="https://client.test/secret.json")
    st, _, _ = at(I + "/authorize" + q(**a), headers={"Cookie": cookie})
    check("a document asking for a client secret is refused", st == 400, st)
    a, _ = ask(client="https://client.test/missing.json")
    st, _, _ = at(I + "/authorize" + q(**a), headers={"Cookie": cookie})
    check("an address with no document is refused", st == 400, st)
    count = json.loads(urllib.request.urlopen("https://127.0.0.1:%s/count" % pc,
                                              context=ssl._create_unverified_context()).read())
    check("a document is fetched once while its Cache-Control holds", count.get("/agent.json") == 1, count)

    # A tool registered with the idp gets a token for the resource with no page between, and its own token no more.
    v, ch = pkce()
    a = dict(client_id="cli", redirect_uri="http://127.0.0.1:5000/cb", response_type="code", scope="openid", state="s",
             code_challenge=ch, code_challenge_method="S256", resource=RES)
    st, _, h = at(I + "/authorize" + q(**a), headers={"Cookie": cookie})
    st, tok = exchange(loc(h).get("code", ""), v, client="cli", redirect="http://127.0.0.1:5000/cb")
    st2, _, _ = mcp(tok.get("access_token"), "tools/list")
    check("a registered client asking for the resource needs nobody's leave, and its token is taken", st == 200 and st2 == 200, (st, tok, st2))
    a.pop("resource")
    v, a["code_challenge"] = pkce()
    st, _, h = at(I + "/authorize" + q(**a), headers={"Cookie": cookie})
    st, tok = exchange(loc(h).get("code", ""), v, client="cli", redirect="http://127.0.0.1:5000/cb", resource=None)
    st2, _, hh = mcp(tok.get("access_token"), "tools/list")
    check("a token for the client itself is not the server's, and the client is told it is invalid",
          st == 200 and st2 == 401 and 'error="invalid_token"' in hh.get("WWW-Authenticate", ""), (st, st2))

if phase == "disabled":
    t = json.load(open(tmpd + "/tokens.json"))
    ok_ = False
    for _ in range(50):
        st, _, _ = mcp(t["bob"], "tools/list")
        if st == 401: ok_ = True; break
        time.sleep(0.1)
    check("a disabled account's token is no longer taken", ok_, st)

if phase == "restart":
    t = json.load(open(tmpd + "/tokens.json"))
    st = 0
    for _ in range(100):
        try:
            st, _, _ = mcp(t["refreshed"], "tools/list")
        except Exception:
            st = 0
        if st == 200: break
        time.sleep(0.1)
    check("after a restart the server and the idp come back as they were, a token given before still taken", st == 200, st)
PY
}

verdicts() {
    while IFS= read -r line; do
        case "$line" in
            "ok "*) ok ;;
            "bad "*) bad "${line#bad }" "" ;;
            *) [ -n "$line" ] && echo "  $line" ;;
        esac
    done
}

verdicts < <(flow main)
"$BIN" idp-user auth disable bob >/dev/null 2>&1 || bad "bob is disabled" "rc $?"
verdicts < <(flow disabled)
stats=""
for _ in $(seq 1 50); do
    stats=$("$BIN" stats auth 2>&1)
    case "$stats" in *"consents:"[1-9]*"client_fetches:"[1-9]*"client_fetch_failures:"[1-9]*) break ;; esac
    sleep 0.1
done
case "$stats" in *"consents:"[1-9]*"client_fetches:"[1-9]*"client_fetch_failures:"[1-9]*) ok ;;
    *) bad "the idp counts what it allowed, fetched and refused" "$stats" ;; esac
kill "$SOCKETLEY_DPID" 2>/dev/null; wait "$SOCKETLEY_DPID" 2>/dev/null
daemon_start "$BIN"
verdicts < <(flow restart)

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
