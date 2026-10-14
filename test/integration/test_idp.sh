#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# The idp runtime: an OpenID Connect provider that keeps its own accounts, and what trusts its sign-in.
#
# What each part would catch:
#   * an account losing a field it was given, or its id changing, across a restart
#   * a client or redirect it does not know being sent a code, or an error sent to an address nobody registered
#   * a wrong password, an unknown or disabled account, or a sixth failure in a row signing in
#   * a code redeemed twice, by another client, for another redirect, or without its PKCE verifier
#   * a token that does not verify against the published key, or names the account by anything but its id
#   * a refresh for an account disabled, signed out everywhere or made to reset its password since
#   * a password that must be reset letting the account in before it is
#   * the signing key changing across a restart, which would sign every user out
#   * a storage's users not coming over with the passwords they have there
#   * a proxy, a storage or the dashboard not taking the sign-in, or a client naming itself someone else
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
tally() { while IFS= read -r line; do case "$line" in ok\ *) ok ;; bad\ *) bad "${line#bad }" "" ;; *) echo "  $line" ;; esac; done; }
expect() { [ "$2" = "$3" ] && ok || bad "$1" "got '$2', want '$3'"; }

echo "=== Integration: the idp runtime keeps accounts and signs them in everywhere ==="
daemon_isolate idp
T=$SOCKETLEY_TMPD
PS=$((SL_PORT_BASE + 1960))
PI=$((SL_PORT_BASE + 1961))
PP=$((SL_PORT_BASE + 1962))
PB=$((SL_PORT_BASE + 1963))
PM=$((SL_PORT_BASE + 1964))
cat > "$T/daemon.lua" <<EOF
daemon = { metrics_port = $PM, dashboard_idp = "auth" }
EOF
export SOCKETLEY_CONFIG="$T/daemon.lua"
python3 -c '
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = ("%s|%s" % (self.headers.get("X-Forwarded-User") or "-", self.headers.get("X-Forwarded-Preferred-Username") or "-")).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
' "$PB" &
BACKEND=$!
trap 'kill $BACKEND 2>/dev/null; daemon_stop' EXIT
daemon_start "$BIN"

cat > "$T/creds" <<EOF
[root]
admin = true
AKIAIDPROOT000000000:idprootsecretidprootsecretidprootsecret0
EOF
cat > "$T/clients" <<EOF
# a confidential web app, and a single-page app with no secret
wiki wikisecret http://127.0.0.1:9/cb
spa - http://localhost:5173/cb
EOF

out=$("$BIN" create idp x2 -p "$PI" --issuer "ftp://x" 2>&1); rc=$?
[ "$rc" -ne 0 ] && ok || bad "an issuer that is no http address is refused" "rc $rc: $out"
out=$("$BIN" create idp x3 -p "$PI" --issuer "http://127.0.0.1:$PI" --shards 2 2>&1); rc=$?
[ "$rc" -ne 0 ] && ok || bad "--shards is refused" "rc $rc: $out"
out=$("$BIN" create idp x4 -p "$PI" --issuer "http://127.0.0.1:$PI" --tls 2>&1); rc=$?
[ "$rc" -ne 0 ] && ok || bad "--tls is refused, since the entrance terminates it" "rc $rc: $out"

"$BIN" create idp auth -p "$PI" --clients "$T/clients" --issuer "http://127.0.0.1:$PI" -s >/dev/null 2>&1 \
    && ok || bad "the idp runtime is made and started" "$(tail -3 "$SOCKETLEY_DLOG")"
"$BIN" create storage ui -p "$PS" --dir "$T/ui" --credentials "$T/creds" --idp auth -s >/dev/null 2>&1 \
    && ok || bad "a storage taking the idp's sign-in is made" "$(tail -3 "$SOCKETLEY_DLOG")"
"$BIN" create proxy gate -p "$PP" --backend "127.0.0.1:$PB" --auth idp:auth -s >/dev/null 2>&1 \
    && ok || bad "a proxy with --auth idp: is made" "$(tail -3 "$SOCKETLEY_DLOG")"
out=$("$BIN" create proxy gx -p $((PP + 10)) --backend "127.0.0.1:$PB" --auth "idp:a/b" 2>&1); rc=$?
[ "$rc" -ne 0 ] && ok || bad "an --auth idp: that names no runtime is refused" "rc $rc: $out"
for p in "$PI/jwks" "$PS/" "$PP/"; do
    for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p")" != 000 ] && break; sleep 0.1; done
done

# ── Accounts, from the command line ──────────────────────────────────────────
ALICE=$("$BIN" idp-user auth add alice --password alicepassword1 --name "Alice A" --email alice@example.com \
        --groups admins --set game.class=mage 2>&1); rc=$?
[ "$rc" -eq 0 ] && [ ${#ALICE} -eq 22 ] && ok || bad "an account is made and named by a fixed id" "rc $rc: $ALICE"
out=$(echo "carolpassword1" | "$BIN" idp-user auth add carol --password - 2>&1); rc=$?
[ "$rc" -eq 0 ] && ok || bad "a password is taken from stdin" "rc $rc: $out"
out=$("$BIN" idp-user auth add ALICE --password otherpassword1 2>&1); rc=$?
[ "$rc" -eq 1 ] && ok || bad "a username taken, case aside, is refused with exit 1" "rc $rc: $out"
out=$("$BIN" idp-user auth add eve --password short 2>&1); rc=$?
[ "$rc" -eq 1 ] && ok || bad "a weak password is refused" "rc $rc: $out"
SHOW=$("$BIN" idp-user auth show alice 2>&1)
case "$SHOW" in *"game.class: mage"*"password: (set)"*) ok ;; *) bad "show lists the fields, the password as set and not its hash" "$SHOW" ;; esac
case "$SHOW" in *'$scrypt$'*) bad "show never prints the hash" "$SHOW" ;; *) ok ;; esac
LIST=$("$BIN" idp-user auth list 2>&1)
case "$LIST" in alice*carol*) ok ;; *) bad "list names every account" "$LIST" ;; esac
out=$("$BIN" idp-user nosuch list 2>&1); rc=$?
[ "$rc" -eq 1 ] && ok || bad "idp-user on no idp runtime is refused" "rc $rc: $out"

# ── A storage's users, taken over with the passwords they have there ───────
python3 - "$PS" <<'PY' >/dev/null 2>&1
import sys, boto3
from botocore.config import Config
iam = boto3.client("iam", endpoint_url="http://127.0.0.1:%s" % sys.argv[1], region_name="", aws_access_key_id="AKIAIDPROOT000000000",
                   aws_secret_access_key="idprootsecretidprootsecretidprootsecret0", config=Config(retries={"max_attempts": 1}))
iam.create_user(UserName="dora")
iam.create_login_profile(UserName="dora", Password="dorapassword1")
iam.create_user(UserName="alice")
PY
sleep 0.3
IMP=$("$BIN" idp-user auth import ui 2>&1); rc=$?
case "$IMP" in "2 imported, 1 already here"*) ok ;; *) bad "a storage's users are imported, an account of the same name kept" "rc $rc: $IMP" ;; esac

run() {
    python3 - "$PI" "$1" "$T" "$PS" "$PP" "$PM" "$ALICE" 2>&1 <<'PY'
import sys, json, time, base64, hashlib, re, urllib.request, urllib.error, urllib.parse
import jwt
pi, phase, tmpd, ps, pp, pm, alice_id = sys.argv[1:8]
I = "http://127.0.0.1:%s" % pi
CB = "http://127.0.0.1:9/cb"
def check(name, got, want):
    print(("ok " if got == want else "bad ") + name + ("" if got == want else ": got %r, want %r" % (got, want)))

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None
op = urllib.request.build_opener(NoRedirect)
def at(base, method, path, form=None, headers=None, cookie=None):
    h = dict(headers or {})
    if cookie:
        h["Cookie"] = cookie
    data = urllib.parse.urlencode(form).encode() if form is not None else None
    if data is not None:
        h["Content-Type"] = "application/x-www-form-urlencoded"
    r = urllib.request.Request(base + path, data=data, method=method, headers=h)
    try:
        with op.open(r) as resp:
            return resp.status, resp.read().decode(), resp.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), e.headers
def req(method, path, form=None, headers=None, cookie=None):
    return at(I, method, path, form, headers, cookie)
def q(**kw):
    return "?" + urllib.parse.urlencode(kw)
def code_of(headers):
    loc = headers.get("Location", "")
    return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(loc).query)), loc
def cookie_of(headers):
    return (headers.get("Set-Cookie") or "").split(";")[0]
def basic(i, s):
    return {"Authorization": "Basic " + base64.b64encode(("%s:%s" % (i, s)).encode()).decode()}
def keys():
    jw = json.loads(req("GET", "/jwks")[1])
    return {k["kid"]: jwt.algorithms.ECAlgorithm.from_jwk(json.dumps(k)) for k in jw["keys"]}
def verify(tok, aud):
    kid = jwt.get_unverified_header(tok)["kid"]
    return jwt.decode(tok, keys()[kid], algorithms=["ES256"], audience=aud, issuer=I)
auth = dict(client_id="wiki", redirect_uri=CB, response_type="code", scope="openid profile", state="xyz", nonce="n-123")
def exchange(code, cl="wiki", secret="wikisecret", extra=None):
    f = dict(grant_type="authorization_code", code=code, redirect_uri=CB)
    f.update(extra or {})
    return req("POST", "/token", f, basic(cl, secret) if secret else None)

state_file = tmpd + "/py.json"
if phase == "main":
    st, body, _ = req("GET", "/.well-known/openid-configuration")
    d = json.loads(body) if st == 200 else {}
    check("discovery names the issuer and its endpoints", (d.get("issuer"), d.get("token_endpoint"), d.get("code_challenge_methods_supported")),
          (I, I + "/token", ["S256"]))
    k = json.loads(req("GET", "/jwks")[1])["keys"][0]
    check("the key is published as a P-256 JWK with its thumbprint as kid", (k["kty"], k["crv"], k["alg"], len(k["kid"])), ("EC", "P-256", "ES256", 43))

    st, body, h = req("GET", "/authorize" + q(client_id="nobody", redirect_uri=CB, response_type="code", scope="openid"))
    check("a client it does not know is shown an error, not sent one", (st, h.get("Location")), (400, None))
    st, body, h = req("GET", "/authorize" + q(client_id="wiki", redirect_uri="http://127.0.0.1:9/other", response_type="code", scope="openid"))
    check("nor is a redirect the client did not register", (st, h.get("Location")), (400, None))
    st, body, h = req("GET", "/authorize" + q(client_id="wiki", redirect_uri=CB, response_type="token", scope="openid", state="s1"))
    check("an implicit flow is refused at the client's address", (code_of(h)[0].get("error"), code_of(h)[0].get("state")), ("unsupported_response_type", "s1"))

    st, body, _ = req("GET", "/authorize" + q(**auth))
    check("a sign-in page is shown, carrying the request", (st, 'name="password"' in body, 'value="n-123"' in body), (200, True, True))
    check("a wrong password is refused", req("POST", "/authorize", dict(auth, username="alice", password="wrongpassword"))[0], 401)
    check("so is an account that is none", req("POST", "/authorize", dict(auth, username="nobody", password="alicepassword1"))[0], 401)
    st, body, h = req("POST", "/authorize", dict(auth, username="ALICE", password="alicepassword1"))
    p, loc = code_of(h)
    cookie = cookie_of(h)
    check("the right one is sent back with a code, its state and the issuer, the username's case aside",
          (st, loc.startswith(CB + "?"), bool(p.get("code")), p.get("state"), p.get("iss")), (302, True, True, "xyz", I))
    check("and signed in", cookie.startswith("skl_idp="), True)

    st, body, _ = exchange(p.get("code"), secret="nope")
    check("a wrong client secret gets no token", (st, json.loads(body).get("error")), (401, "invalid_client"))
    st, body, _ = exchange(p.get("code"))
    t = json.loads(body) if st == 200 else {}
    check("the code is redeemed for tokens", (st, "id_token" in t, "refresh_token" in t), (200, True, True))
    try:
        idt = verify(t["id_token"], "wiki")
        check("the id token names the account by its fixed id, with its profile",
              (idt["sub"], idt["preferred_username"], idt["name"], idt["email"], idt["groups"], idt["nonce"]),
              (alice_id, "alice", "Alice A", "alice@example.com", ["admins"], "n-123"))
    except Exception as e:
        check("the id token verifies against the published key", repr(e), "")
    check("a code is good once", exchange(p.get("code"))[0], 400)

    st, body, _ = req("GET", "/userinfo", headers={"Authorization": "Bearer " + t.get("access_token", "")})
    check("userinfo answers for the access token", (st, json.loads(body).get("sub") if st == 200 else None), (200, alice_id))

    st, body, h = req("GET", "/authorize" + q(**dict(auth, state="again")), cookie=cookie)
    check("a signed-in browser is sent straight back with a code", (st, bool(code_of(h)[0].get("code"))), (302, True))

    # A public client: PKCE or nothing.
    pub = dict(client_id="spa", redirect_uri="http://localhost:5173/cb", response_type="code", scope="openid offline_access")
    st, body, h = req("GET", "/authorize" + q(**pub), cookie=cookie)
    check("a public client without a code challenge is refused", code_of(h)[0].get("error"), "invalid_request")
    verifier = "v" * 64
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    pk = dict(pub, code_challenge=challenge, code_challenge_method="S256")
    pcode = code_of(req("GET", "/authorize" + q(**pk), cookie=cookie)[2])[0].get("code")
    st, body, _ = req("POST", "/token", dict(grant_type="authorization_code", code=pcode, redirect_uri=pub["redirect_uri"], client_id="spa", code_verifier="w" * 64))
    check("a wrong verifier gets nothing", st, 400)
    pcode = code_of(req("GET", "/authorize" + q(**pk), cookie=cookie)[2])[0].get("code")
    st, body, _ = req("POST", "/token", dict(grant_type="authorization_code", code=pcode, redirect_uri=pub["redirect_uri"], client_id="spa", code_verifier=verifier))
    pt = json.loads(body) if st == 200 else {}
    check("the right one gets tokens, a refresh one for offline_access", (st, "refresh_token" in pt), (200, True))
    refresh = lambda tok, cl="spa": req("POST", "/token", dict(grant_type="refresh_token", refresh_token=tok, client_id=cl))
    st, body, _ = refresh(pt.get("refresh_token", ""))
    rt = json.loads(body) if st == 200 else {}
    check("a refresh token gives new tokens", (st, bool(rt.get("access_token"))), (200, True))
    check("but not to another client", req("POST", "/token", dict(grant_type="refresh_token", refresh_token=rt.get("refresh_token", "")), basic("wiki", "wikisecret"))[0], 400)

    # The account page: a name changed there is what userinfo says next.
    st, body, _ = req("GET", "/account", cookie=cookie)
    check("the account page shows the signed-in account", (st, "alice" in body), (200, True))
    check("and sends one signed out to sign in", req("GET", "/account")[2].get("Location", "").startswith("/login"), True)
    st, body, _ = req("POST", "/account", dict(name="Alice B", email="alice@example.com"), cookie=cookie)
    st, body, _ = req("GET", "/userinfo", headers={"Authorization": "Bearer " + rt.get("access_token", "")})
    check("a name changed on the account page is what userinfo says", json.loads(body).get("name") if st == 200 else st, "Alice B")

    # The imported storage user signs in with the password it had there.
    st, body, h = req("POST", "/login", dict(rd="/", username="dora", password="dorapassword1"))
    dora = cookie_of(h)
    check("an imported user signs in with the password it had in the storage", (st, h.get("Location"), dora.startswith("skl_idp=")), (302, "/", True))

    # The storage, signed in by the idp: dora is the storage's dora.
    S = "http://127.0.0.1:%s" % ps
    st, body, h = at(S, "GET", "/~ui/session", headers={"X-Socketley-UI": "1"})
    check("a storage not signed in offers the idp's sign-in", (st, (h.get("X-Socketley-Idp-Login") or "").startswith(I + "/login?rd=")), (401, True))
    st, body, h = at(S, "GET", "/~ui/session", headers={"X-Socketley-UI": "1"}, cookie=dora)
    s = json.loads(body) if st == 200 else {}
    check("and takes it: the account's user there, with the way to sign out at the idp",
          (st, s.get("user"), (s.get("idp_logout") or "").startswith(I + "/logout")), (200, "dora", True))
    st, body, h = at(S, "GET", "/~ui/session", headers={"X-Socketley-UI": "1"}, cookie=cookie_of(req("POST", "/login", dict(rd="/", username="carol", password="carolpassword1"))[2]))
    check("an account that is no user of the storage is let in to nothing there", st, 403)

    # The proxy: the backend is told the account's id and username, never what the client says.
    P = "http://127.0.0.1:%s" % pp
    st, body, h = at(P, "GET", "/gate/page?x=1", headers={"Accept": "text/html"})
    check("a browser without a sign-in is sent to sign in at the idp, and back here after",
          (st, h.get("Location")), (302, I + "/login?rd=" + urllib.parse.quote("http://127.0.0.1:%s/gate/page?x=1" % pp, safe="")))
    check("anything else is told 401", at(P, "GET", "/gate/page", headers={"Accept": "application/json"})[0], 401)
    st, body, h = at(P, "GET", "/gate/who", headers={"X-Forwarded-User": "root", "X-Forwarded-Preferred-Username": "root"}, cookie=dora)
    check("a signed-in request reaches the backend, told who and not what the client claims", (st, body.split("|")[1]), (200, "dora"))
    forged = dora[:-4] + ("AAAA" if not dora.endswith("AAAA") else "BBBB")
    check("a forged cookie is refused", at(P, "GET", "/gate/who", headers={"Accept": "application/json"}, cookie=forged)[0], 401)

    # The dashboard: an admin of the idp signs in, an account that is none does not.
    M = "http://127.0.0.1:%s" % pm
    s = json.loads(at(M, "GET", "/api/session")[1])
    check("the dashboard offers the idp's sign-in", (s.get("configured"), (s.get("idp_login") or "").startswith(I)), (True, True))
    s = json.loads(at(M, "GET", "/api/session", cookie=cookie)[1])
    check("and takes an admin's", s.get("user"), "alice")
    s = json.loads(at(M, "GET", "/api/session", cookie=dora)[1])
    check("but not an account that is no admin", s.get("user"), None)

    json.dump({"kid": k["kid"], "id_token": t.get("id_token", ""), "cookie": cookie, "refresh": rt.get("refresh_token", ""),
               "dora": dora}, open(state_file, "w"))

elif phase == "after_cli":
    s = json.load(open(state_file))
    check("a disabled account cannot sign in", req("POST", "/login", dict(rd="/", username="carol", password="carolpassword1"))[0], 401)
    st, body, _ = req("POST", "/token", dict(grant_type="refresh_token", refresh_token=s["refresh"], client_id="spa"))
    check("an account signed out everywhere refreshes into nothing", (st, json.loads(body).get("error")), (400, "invalid_grant"))
    st, body, _ = req("GET", "/authorize" + q(**auth), cookie=s["cookie"])
    check("and its browser session is over too", (st, 'name="password"' in body), (200, True))
    # A password set with --reset lets the account in only after it is set again.
    st, body, h = req("POST", "/authorize", dict(auth, username="alice", password="tempPassword99"))
    check("a password that must be reset is asked for again before anything else", (st, "Set a new password" in body, h.get("Set-Cookie")), (200, True, None))
    st, body, h = req("POST", "/account/password", dict(auth, username="alice", current="tempPassword99", new="Fresh-pass-2026x"))
    check("set again, the account goes on to its application", (st, bool(code_of(h)[0].get("code")), cookie_of(h).startswith("skl_idp=")), (302, True, True))
    check("and the old password is no longer it", req("POST", "/authorize", dict(auth, username="alice", password="tempPassword99"))[0], 401)
    # Six failures from one address and the seventh try waits, right password or not.
    for _ in range(6):
        req("POST", "/authorize", dict(auth, username="dora", password="wrongpassword"), headers={"X-Forwarded-For": "198.51.100.7"})
    check("an address that failed five times is barred for a while",
          req("POST", "/authorize", dict(auth, username="dora", password="dorapassword1"), headers={"X-Forwarded-For": "198.51.100.7"})[0], 429)
    check("and another is not",
          req("POST", "/authorize", dict(auth, username="dora", password="dorapassword1"), headers={"X-Forwarded-For": "198.51.100.8"})[0], 302)

elif phase == "restarted":
    s = json.load(open(state_file))
    k = json.loads(req("GET", "/jwks")[1])["keys"][0]
    check("the signing key survives a restart, so tokens given before still verify", k["kid"], s["kid"])
    try:
        verify(s["id_token"], "wiki")
        check("an id token from before the restart verifies", "ok", "ok")
    except Exception as e:
        check("an id token from before the restart verifies", repr(e), "ok")
    st, body, h = req("POST", "/login", dict(rd="/", username="dora", password="dorapassword1"))
    check("and the accounts are there, passwords and all", st, 302)
PY
}

tally < <(run main)

"$BIN" idp-user auth disable carol >/dev/null 2>&1 && ok || bad "disable takes" "rc $?"
"$BIN" idp-user auth logout alice >/dev/null 2>&1 && ok || bad "logout takes" "rc $?"
"$BIN" idp-user auth passwd alice --password tempPassword99 --reset >/dev/null 2>&1 && ok || bad "passwd --reset takes" "rc $?"
tally < <(run after_cli)

"$BIN" stop auth >/dev/null 2>&1
"$BIN" start auth >/dev/null 2>&1
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PI/jwks")" = 200 ] && break; sleep 0.1; done
tally < <(run restarted)
AFTER=$("$BIN" idp-user auth show alice 2>&1)
case "$AFTER" in "id: $ALICE"*"game.class: mage"*) ok ;; *) bad "an account keeps its id and its fields across a restart" "$AFTER" ;; esac

SHOWJ=$("$BIN" show auth 2>/dev/null)
case "$SHOWJ" in *'"issuer": "http://127.0.0.1:'*) ok ;; *) bad "show names the issuer" "$SHOWJ" ;; esac
STATS=$("$BIN" stats auth 2>/dev/null)
case "$STATS" in *"accounts:4"*) ok ;; *) bad "stats counts the accounts" "$STATS" ;; esac

echo "  Results: $PASS/$((PASS+FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
