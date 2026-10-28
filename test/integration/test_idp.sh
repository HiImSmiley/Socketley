#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# The idp runtime: an OpenID Connect provider that keeps its own accounts, and what trusts its sign-in.
#
# What each part would catch:
#   * an account losing a field it was given, or its id changing, across a restart
#   * a client or redirect it does not know being sent a code, or an error sent to an address nobody registered
#   * a wrong password, an unknown or disabled account, or a sixth failure in a row signing in
#   * guesses sent together, spread over an IPv6 /64 or over many addresses at one account, or wrong codes, passing
#     the bars on them
#   * a code redeemed twice, by another client, for another redirect, or without its PKCE verifier
#   * a token that does not verify against the published key, or names the account by anything but its id
#   * a refresh for an account disabled, signed out everywhere or made to reset its password since
#   * a refresh token good more than once, or one used again leaving its sign-in standing
#   * a password that must be reset letting the account in before it is
#   * the signing key changing across a restart, which would sign every user out
#   * a code of the second step taken again after a restart
#   * a session replacing a second step that is on, or one turned on meanwhile, without a code of it
#   * a storage's users not coming over with the passwords they have there
#   * a proxy, a storage or the dashboard not taking the sign-in, or a client naming itself someone else
#   * a proxy handing its backend the provider's session cookie, which signs in wherever the provider is trusted
#   * a return address a browser reads as another host's, by a backslash in its host
#   * a sign-in or an account's change posted from another site's page
#   * an e-mail a user gave themselves taken as vouched for, another account's, or able to split a line
#   * one of them still taking a cookie of an account disabled, removed, signed out everywhere or made to reset since,
#     or the admin bit of one taken out of admins since; or a code given before a sign-out redeemed after it
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
. "$(dirname "$0")/lib_verdicts.sh"
expect() { [ "$2" = "$3" ] && ok || bad "$1" "got '$2', want '$3'"; }

echo "=== Integration: the idp runtime keeps accounts and signs them in everywhere ==="
# The account every sign-in below uses is a storage's IAM user, made with boto3 and imported.
python3 -c 'import boto3, jwt' 2>/dev/null || { echo "  SKIP: boto3 and PyJWT are required"; exit 0; }
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
        b = ("%s|%s|%s" % (self.headers.get("X-Forwarded-User") or "-", self.headers.get("X-Forwarded-Preferred-Username") or "-",
                           self.headers.get("Cookie") or "-")).encode()
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
out=$("$BIN" create idp x3 -p "$PI" --issuer "http://localhost.example.org" 2>&1); rc=$?
[ "$rc" -ne 0 ] && ok || bad "plain http for a public name that begins with localhost is refused" "rc $rc: $out"
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
# Accounts the command line changes after the first checks, each signed in before it does.
for u in frank gina hank; do
    g=; [ "$u" = frank ] && g="--groups admins"
    "$BIN" idp-user auth add "$u" --password "${u}password1" $g >/dev/null 2>&1 || bad "$u is made" "rc $?"
done
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
    python3 - "$PI" "$1" "$T" "$PS" "$PP" "$PM" "$ALICE" "$BIN" 2>&1 <<'PY' || echo "bad the $1 checks ran to their end"
import sys, json, time, base64, hashlib, re, subprocess, urllib.request, urllib.error, urllib.parse
import jwt
pi, phase, tmpd, ps, pp, pm, alice_id, bin_ = sys.argv[1:9]
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
    st, body, h = req("GET", "/login" + q(**dict(auth, redirect_uri="https://attacker.example/cb")), cookie=cookie)
    check("/login sends no code to an address the client did not register", (st, "code=" in (h.get("Location") or "")), (400, False))
    st, body, h = req("POST", "/login", dict(auth, redirect_uri="https://attacker.example/cb", username="alice", password="alicepassword1"))
    check("nor does a sign-in posted to /login", (st, "code=" in (h.get("Location") or "")), (400, False))

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
    # A refresh token is good once: each refresh gives the next, and one used again ends the sign-in it is of.
    pcode = code_of(req("GET", "/authorize" + q(**pk), cookie=cookie)[2])[0].get("code")
    st, body, _ = req("POST", "/token", dict(grant_type="authorization_code", code=pcode, redirect_uri=pub["redirect_uri"], client_id="spa", code_verifier=verifier))
    r0 = json.loads(body).get("refresh_token", "") if st == 200 else ""
    st, body, _ = refresh(r0)
    r1 = json.loads(body).get("refresh_token", "") if st == 200 else ""
    check("a refresh gives a refresh token of its own", (st, bool(r1) and r1 != r0), (200, True))
    st, body, _ = refresh(r1)
    r2 = json.loads(body).get("refresh_token", "") if st == 200 else ""
    check("which refreshes in turn", (st, bool(r2)), (200, True))
    st, body, _ = refresh(r0)
    check("one used before is refused", (st, json.loads(body).get("error")), (400, "invalid_grant"))
    check("and ends its sign-in, its newest token too", refresh(r2)[0], 400)
    st, body, _ = refresh(rt.get("refresh_token", ""))
    check("while another sign-in's token still refreshes", st, 200)
    rt = json.loads(body) if st == 200 else {}

    # The account page: a name changed there is what userinfo says next.
    st, body, _ = req("GET", "/account", cookie=cookie)
    check("the account page shows the signed-in account", (st, "alice" in body), (200, True))
    check("and sends one signed out to sign in", req("GET", "/account")[2].get("Location", "").startswith("/login"), True)
    st, body, h = req("GET", "/login")
    check("the sign-in page wears the storage interface's look, its aurora let in and still no script",
          (st, 'class="lcard"' in body and "--grad:" in body, "img-src data:" in (h.get("Content-Security-Policy") or ""),
           "<script" in body), (200, True, True, False))
    st, body, _ = req("POST", "/account/totp", dict(do="start"), cookie=cookie)
    check("turning two-step sign-in on shows the key as a code to scan, beside the link it encodes",
          (st, "<svg" in body and "h1v1h-1z" in body, "otpauth://totp/" in body), (200, True, True))
    st, body, _ = req("POST", "/account", dict(name="Alice B", email="alice@example.com"), cookie=cookie)
    st, body, _ = req("GET", "/userinfo", headers={"Authorization": "Bearer " + rt.get("access_token", "")})
    check("a name changed on the account page is what userinfo says", json.loads(body).get("name") if st == 200 else st, "Alice B")
    # An e-mail an admin gave is vouched for; one the holder gives themselves is not, nor may it be another's or no address.
    check("an e-mail an admin gave is vouched for", json.loads(body).get("email_verified") if st == 200 else st, True)
    dc = cookie_of(req("POST", "/login", dict(rd="/", username="dora", password="dorapassword1"))[2])
    check("one may not give themselves another account's e-mail",
          req("POST", "/account", dict(name="Dora", email="ALICE@example.com"), cookie=dc)[0], 400)
    check("nor one whose name is another username on this provider's host",
          req("POST", "/account", dict(name="Dora", email="carol@127.0.0.1"), cookie=dc)[0], 400)
    for bad in ("dora@example.com\t9G", "dora@example.com\nx", "dora", "do ra@example.com"):
        check("nor one that is no plain address: %r" % bad, req("POST", "/account", dict(name="Dora", email=bad), cookie=dc)[0], 400)
    check("but one of their own", req("POST", "/account", dict(name="Dora", email="dora@else.example"), cookie=dc)[0], 200)
    dcode = code_of(req("GET", "/authorize" + q(**dict(auth, scope="openid email")), cookie=dc)[2])[0].get("code")
    st, body, _ = exchange(dcode)
    try:
        dt = verify(json.loads(body)["id_token"], "wiki")
        check("which a token carries as not vouched for", (dt.get("email"), dt.get("email_verified")), ("dora@else.example", False))
    except Exception as e:
        check("which a token carries as not vouched for", repr(e), "")
    try:
        dsess = jwt.decode(cookie_of(req("POST", "/login", dict(rd="/", username="dora", password="dorapassword1"))[2]).split("=", 1)[1],
                           options={"verify_signature": False})
        check("and the session cookie, which a mail runtime trusts, does not name", (dsess.get("email"), dsess.get("email_verified")), ("", False))
    except Exception as e:
        check("and the session cookie does not name it", repr(e), "")

    # The imported storage user signs in with the password it had there.
    st, body, h = req("POST", "/login", dict(rd="/", username="dora", password="dorapassword1"))
    dora = cookie_of(h)
    check("an imported user signs in with the password it had in the storage", (st, h.get("Location"), dora.startswith("skl_idp=")), (302, "/", True))

    # A form posted from another site signs nobody in and changes nothing; one from the provider's page, or a client
    # that names no page, is taken.
    df = dict(rd="/", username="dora", password="dorapassword1")
    for name, hd in (("a sign-in posted from another site is refused and signs nobody in", {"Origin": "https://evil.example"}),
                     ("so is one whose page hid its origin", {"Origin": "null"}),
                     ("and one a Referer says came from another site", {"Referer": "https://evil.example/page"})):
        st, _, h = req("POST", "/login", df, headers=hd)
        check(name, (st, h.get("Set-Cookie")), (403, None))
    st, _, h = req("POST", "/login", df, headers={"Origin": I, "Referer": "https://evil.example/"})
    check("one from the provider's own page is taken", (st, cookie_of(h).startswith("skl_idp=")), (302, True))
    st, _, h = req("POST", "/login", df, headers={"Referer": I + "/login"})
    check("as is one whose Referer is the provider's page", (st, cookie_of(h).startswith("skl_idp=")), (302, True))
    check("the provider's pages tell a browser to post their forms with their origin",
          req("GET", "/login")[2].get("Referrer-Policy"), "same-origin")
    st, _, _ = req("POST", "/account", dict(name="Mallory", email="alice@example.com"), cookie=cookie, headers={"Origin": "https://evil.example"})
    st2, body, _ = req("GET", "/userinfo", headers={"Authorization": "Bearer " + rt.get("access_token", "")})
    check("an account changed from another site is refused", (st, json.loads(body).get("name") if st2 == 200 else st2), (403, "Alice B"))
    for path, form in (("/account/password", dict(current="alicepassword1", new="Evil-pass-2026q")), ("/account/totp", dict(do="start")),
                       ("/account/everywhere", {}), ("/device", dict(user_code="ABCD-EFGH", do="allow"))):
        check("so is a post to " + path, req("POST", path, form, cookie=cookie, headers={"Origin": "https://evil.example"})[0], 403)

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
    st, body, h = at(P, "GET", "/gate/who", cookie=dora + "; theme=dark; skl_idp_known=k")
    sent = body.split("|")[2] if body.count("|") >= 2 else body
    check("the backend is handed its own cookies and not the provider's, which would sign it in elsewhere as the user",
          (st, "skl_idp" in sent, "theme=dark" in sent), (200, False, True))
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

    # Sign-ins the command line takes back, or takes the admin bit of, before the next phase.
    signed = lambda u: cookie_of(req("POST", "/login", dict(rd="/", username=u, password=u + "password1"))[2])
    later = {u: signed(u) for u in ("carol", "frank", "gina", "hank")}
    check("another admin takes the dashboard", json.loads(at(M, "GET", "/api/session", cookie=later["frank"])[1]).get("user"), "frank")
    check("and every one of them the proxy, before the command line changes them",
          [at(P, "GET", "/gate/who", cookie=c)[0] for c in later.values()], [200] * 4)
    check("alice's sign-in reaches the proxy too", at(P, "GET", "/gate/who", cookie=cookie)[0], 200)
    later_code = code_of(req("GET", "/authorize" + q(**dict(auth, state="later")), cookie=cookie)[2])[0].get("code", "")

    json.dump({"kid": k["kid"], "id_token": t.get("id_token", ""), "cookie": cookie, "refresh": rt.get("refresh_token", ""),
               "dora": dora, "later": later, "later_code": later_code}, open(state_file, "w"))

elif phase == "after_cli":
    s = json.load(open(state_file))
    # What the command line took back is refused where the sign-in is verified without asking the idp, which reads
    # the accounts' standing again once a second.
    def eventually(fn, want):
        end = time.time() + 3
        got = fn()
        while got != want and time.time() < end:
            time.sleep(0.1)
            got = fn()
        return got
    P, S, M = ("http://127.0.0.1:%s" % x for x in (pp, ps, pm))
    gate = lambda c: at(P, "GET", "/gate/who", headers={"Accept": "application/json"}, cookie=c)[0]
    store = lambda c: at(S, "GET", "/~ui/session", headers={"X-Socketley-UI": "1"}, cookie=c)[0]
    board = lambda c: json.loads(at(M, "GET", "/api/session", cookie=c)[1]).get("user")
    later = s["later"]
    check("the proxy refuses a cookie from before its account was signed out everywhere", eventually(lambda: gate(s["cookie"]), 401), 401)
    check("and the dashboard takes it for no admin", eventually(lambda: board(s["cookie"]), None), None)
    check("the storage refuses one from before its account was signed out everywhere", eventually(lambda: store(s["dora"]), 401), 401)
    check("the proxy refuses a disabled account's cookie", eventually(lambda: gate(later["carol"]), 401), 401)
    check("and a removed account's", eventually(lambda: gate(later["hank"]), 401), 401)
    check("and that of an account made to set its password again", eventually(lambda: gate(later["gina"]), 401), 401)
    st, _, h = req("GET", "/account", cookie=later["gina"])
    check("as the idp's own pages do", (st, (h.get("Location") or "").startswith("/login")), (302, True))
    check("an admin taken out of admins is no admin at the dashboard", eventually(lambda: board(later["frank"]), None), None)
    check("but still signed in at the proxy", gate(later["frank"]), 200)
    st, body, _ = exchange(s["later_code"])
    check("a code given before its account was signed out everywhere is redeemed for nothing", (st, json.loads(body).get("error")), (400, "invalid_grant"))
    dora = cookie_of(req("POST", "/login", dict(rd="/", username="dora", password="dorapassword1"))[2])
    check("a sign-in after the sign-out is taken at the proxy and the storage", (gate(dora), store(dora)), (200, 200))
    check("a disabled account cannot sign in", req("POST", "/login", dict(rd="/", username="carol", password="carolpassword1"))[0], 401)
    st, body, _ = req("POST", "/token", dict(grant_type="refresh_token", refresh_token=s["refresh"], client_id="spa"))
    check("an account signed out everywhere refreshes into nothing", (st, json.loads(body).get("error")), (400, "invalid_grant"))
    st, body, _ = req("GET", "/authorize" + q(**auth), cookie=s["cookie"])
    check("and its browser session is over too", (st, 'name="password"' in body), (200, True))
    # A password set with --reset lets the account in only after it is set again.
    st, body, h = req("POST", "/authorize", dict(auth, username="alice", password="tempPassword99"))
    check("a password that must be reset is asked for again before anything else", (st, "Set a new password" in body, h.get("Set-Cookie")), (200, True, None))
    reset_token = (re.search(r'name="reset_token" value="([0-9a-f]+)"', body) or [None, ""])[1]
    # Without the token a sign-in that passed every step left, a password alone sets nothing and signs nobody in.
    st, _, h = req("POST", "/account/password", dict(auth, username="alice", current="tempPassword99", new="Other-pass-2026y"))
    check("a reset without the sign-in's token is refused", (st, h.get("Set-Cookie")), (401, None))
    st, body, h = req("POST", "/account/password", dict(reset_token=reset_token, current="tempPassword99", new="Fresh-pass-2026x"))
    check("set again, the account goes on to its application", (st, bool(code_of(h)[0].get("code")), cookie_of(h).startswith("skl_idp=")), (302, True, True))
    st, _, h = req("POST", "/account/password", dict(reset_token=reset_token, current="Fresh-pass-2026x", new="Third-pass-2026z"))
    check("and its token is spent", (st, h.get("Set-Cookie")), (401, None))
    check("and the old password is no longer it", req("POST", "/authorize", dict(auth, username="alice", password="tempPassword99"))[0], 401)
    # An account with a second step and a reset: the code is asked for first, and only then is the password set.
    import hmac, struct
    def totp_now(key):
        k = base64.b32decode(key.replace(" ", "").upper() + "=" * (-len(key.replace(" ", "")) % 8))
        h = hmac.new(k, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
        o = h[-1] & 15
        return "%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % 1000000)
    E = {"X-Forwarded-For": "198.51.100.20"}   # an address of its own, the failures before have barred this one
    erin_key = open(tmpd + "/erin.key").read().strip()
    st, body, h = req("POST", "/login", dict(rd="/", username="erin", password="erinTemp12345"), headers=E)
    pending = (re.search(r'name="pending" value="([0-9a-f]+)"', body) or [None, ""])[1]
    check("a reset is asked for only after the code", (st, bool(pending), "reset_token" in body, h.get("Set-Cookie")), (200, True, False, None))
    st, body, h = req("POST", "/login", dict(rd="/", pending=pending, code=totp_now(erin_key)), headers=E)
    erin_token = (re.search(r'name="reset_token" value="([0-9a-f]+)"', body) or [None, ""])[1]
    check("and the code right, the password is asked for", (st, bool(erin_token), h.get("Set-Cookie")), (200, True, None))
    st, body, h = req("POST", "/login", dict(rd="/", pending=erin_token, code=totp_now(erin_key)), headers=E)
    check("a reset's token is taken for no second step", (st, h.get("Set-Cookie")), (401, None))
    st, body, h = req("POST", "/login", dict(rd="/", username="erin", password="erinTemp12345"), headers=E)
    pending = (re.search(r'name="pending" value="([0-9a-f]+)"', body) or [None, ""])[1]
    time.sleep(max(0.0, 30 - time.time() % 30 + 0.5))
    st, body, h = req("POST", "/login", dict(rd="/", pending=pending, code=totp_now(erin_key)), headers=E)
    erin_token = (re.search(r'name="reset_token" value="([0-9a-f]+)"', body) or [None, ""])[1]
    st, body, h = req("POST", "/account/password", dict(reset_token=erin_token, current="erinTemp12345", new="Erin-fresh-2026x"), headers=E)
    check("and set, it signs in where it was going", (st, h.get("Location"), cookie_of(h).startswith("skl_idp=")), (302, "/", True))
    # A return address with a line break writes no header of its own.
    st, body, h = req("POST", "/login", dict(rd="/x\r\nSet-Cookie: injected=1", username="dora", password="dorapassword1"), headers=E)
    check("a return address with a line break sets no header", ("injected" in (h.get("Set-Cookie") or ""), st in (302, 400)), (False, True))
    # Six failures from one address and the seventh try waits, right password or not.
    for _ in range(6):
        req("POST", "/authorize", dict(auth, username="dora", password="wrongpassword"), headers={"X-Forwarded-For": "198.51.100.7"})
    check("an address that failed five times is barred for a while",
          req("POST", "/authorize", dict(auth, username="dora", password="dorapassword1"), headers={"X-Forwarded-For": "198.51.100.7"})[0], 429)
    check("and another is not",
          req("POST", "/authorize", dict(auth, username="dora", password="dorapassword1"), headers={"X-Forwarded-For": "198.51.100.8"})[0], 302)
    # A second step is replaced only by turning it off, which takes a code of it, and never by a session alone.
    O = {"X-Forwarded-For": "198.51.100.80"}
    oc = cookie_of(req("POST", "/login", dict(rd="/", username="omar", password="omarpassword12"), headers=O)[2])
    st, body, _ = req("POST", "/account/totp", dict(do="start"), cookie=oc, headers=O)
    k1 = "".join((re.search(r"<p><code>([A-Z2-7 ]+)</code>", body) or [None, ""])[1].split())
    check("a second step begun shows its key", (st, bool(k1)), (200, True))
    on = subprocess.run([bin_, "idp-user", "auth", "totp", "omar", "on"], capture_output=True, text=True).stdout
    check("and an admin turns one on meanwhile", bool(re.search(r"key: \S+", on)), True)
    st, body, _ = req("POST", "/account/totp", dict(do="confirm", code=totp_now(k1)), cookie=oc, headers=O)
    check("the key begun before replaces nothing", (st, "Two-step sign-in is on." in body), (400, False))
    st, body, _ = req("POST", "/account/totp", dict(do="start"), cookie=oc, headers=O)
    check("and with one on, a session is shown no key to replace it with", (st, "otpauth://" in body), (400, False))

elif phase == "limits":
    import threading, hmac, struct
    def totp_now(key):
        k = base64.b32decode(key.replace(" ", "").upper() + "=" * (-len(key.replace(" ", "")) % 8))
        h = hmac.new(k, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
        o = h[-1] & 15
        return "%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % 1000000)
    def login(user, password, addr, cookie=None):
        return req("POST", "/login", dict(rd="/", username=user, password=password), headers={"X-Forwarded-For": addr}, cookie=cookie)
    # Many guesses sent at once from one address: five are checked, and the rest refused before any is answered.
    got = []
    def one():
        got.append(login("gus", "wrongpassword", "198.51.100.30")[0])
    ts = [threading.Thread(target=one) for _ in range(20)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    check("twenty guesses sent at once from one address are five checked and the rest refused",
          (got.count(401), got.count(429)), (5, 15))
    # An IPv6 host has its /64, so failures there count for the whole of it.
    for i in range(5):
        login("ivy", "wrongpassword", "2001:db8:1:2::%x" % (i + 1))
    check("five failures from one IPv6 /64 bar every address in it", login("ivy", "ivypassword123", "2001:db8:1:2:ffff::9")[0], 429)
    check("and not the next /64", login("ivy", "ivypassword123", "2001:db8:1:3::1")[0], 302)
    # Guesses at one account from many addresses hold it up a while, but not in a browser it signed in on.
    st, _, h = login("jon", "jonpassword123", "198.51.100.40")
    known = [c.split(";")[0] for c in (h.get_all("Set-Cookie") or []) if c.startswith("skl_idp_known=")]
    check("a sign-in marks the browser as one the account signed in on", (st, len(known)), (302, 1))
    for i in range(10):
        login("jon", "wrongpassword", "203.0.113.%d" % (i + 1))
    st, body, _ = login("JON", "jonpassword123", "203.0.113.50")
    wait = int((re.search(r"try again in (\d+) seconds", body) or [None, "0"])[1])
    check("ten failures at one account from ten addresses hold up the next from any other, for half a minute",
          (st, 0 < wait <= 30), (429, True))
    check("but not from a browser the account signed in on", login("jon", "jonpassword123", "203.0.113.51", known[0] if known else None)[0], 302)
    # Wrong codes: three end the password step, and five at the account hold its code step up.
    kim_key = open(tmpd + "/kim.key").read().strip()
    def pending_of(addr):
        body = login("kim", "kimpassword123", addr)[1]
        return (re.search(r'name="pending" value="([0-9a-f]+)"', body) or [None, ""])[1]
    def code(pending, c, addr):
        return req("POST", "/login", dict(rd="/", pending=pending, code=c), headers={"X-Forwarded-For": addr})
    wrong = "%06d" % ((int(totp_now(kim_key)) + 500000) % 1000000)
    p1 = pending_of("198.51.100.60")
    answers = [code(p1, wrong, "198.51.100.60") for _ in range(3)]
    check("two wrong codes ask again, and the third ends the sign-in",
          [(st, "sign in again" in body) for st, body, _ in answers], [(401, False), (401, False), (401, True)])
    st, body, h = code(p1, totp_now(kim_key), "198.51.100.60")
    check("whose right code then signs nobody in", (st, h.get("Set-Cookie")), (401, None))
    p2 = pending_of("198.51.100.61")
    code(p2, wrong, "198.51.100.61")
    code(p2, wrong, "198.51.100.61")
    p3 = pending_of("198.51.100.62")
    st, body, h = code(p3, totp_now(kim_key), "198.51.100.62")
    check("five wrong codes at an account hold up its next code, a right one too",
          (st, "wrong codes" in body, h.get("Set-Cookie")), (429, True, None))

elif phase == "replay":
    import hmac, struct, hashlib, time, re
    def totp_now(key):
        k = base64.b32decode(key.replace(" ", "").upper() + "=" * (-len(key.replace(" ", "")) % 8))
        h = hmac.new(k, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
        o = h[-1] & 15
        return "%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % 1000000)
    # Early in a step, so the code still holds once the runtime is back.
    if time.time() % 30 > 10:
        time.sleep(30 - time.time() % 30 + 0.5)
    key = open(tmpd + "/lea.key").read().strip()
    E = {"X-Forwarded-For": "198.51.100.70"}
    body = req("POST", "/login", dict(rd="/", username="lea", password="leapassword123"), headers=E)[1]
    pending = (re.search(r'name="pending" value="([0-9a-f]+)"', body) or [None, ""])[1]
    code = totp_now(key)
    st, _, h = req("POST", "/login", dict(rd="/", pending=pending, code=code), headers=E)
    check("a code signs in", (st, (h.get("Set-Cookie") or "").startswith("skl_idp=")), (302, True))
    json.dump({"code": code}, open(tmpd + "/lea.json", "w"))

elif phase == "restarted":
    # First, while the code taken before the restart still holds.
    E = {"X-Forwarded-For": "198.51.100.71"}
    body = req("POST", "/login", dict(rd="/", username="lea", password="leapassword123"), headers=E)[1]
    pending = (re.search(r'name="pending" value="([0-9a-f]+)"', body) or [None, ""])[1]
    st, _, h = req("POST", "/login", dict(rd="/", pending=pending, code=json.load(open(tmpd + "/lea.json"))["code"]), headers=E)
    check("a code taken before a restart is not taken again after it", (st, h.get("Set-Cookie")), (401, None))
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
"$BIN" idp-user auth logout dora >/dev/null 2>&1 && ok || bad "logout takes dora" "rc $?"
"$BIN" idp-user auth set frank groups=staff >/dev/null 2>&1 && ok || bad "set takes frank out of admins" "rc $?"
"$BIN" idp-user auth set gina reset=1 >/dev/null 2>&1 && ok || bad "set makes gina's password one to set again" "rc $?"
"$BIN" idp-user auth remove hank >/dev/null 2>&1 && ok || bad "remove takes hank" "rc $?"
# An account with a second step whose password must be set again, its key kept for the checks to make codes.
"$BIN" idp-user auth add erin --password erinpassword1 >/dev/null 2>&1
"$BIN" idp-user auth totp erin on 2>&1 | sed -n 's/^key: //p' > "$T/erin.key"
"$BIN" idp-user auth passwd erin --password erinTemp12345 --reset >/dev/null 2>&1
"$BIN" idp-user auth add omar --password omarpassword12 >/dev/null 2>&1 || bad "omar is made" "rc $?"
[ -s "$T/erin.key" ] && ok || bad "a second step is turned on for the reset checks" "no key"
tally < <(run after_cli)

for u in gus ivy jon kim; do "$BIN" idp-user auth add "$u" --password "${u}password123" >/dev/null 2>&1; done
"$BIN" idp-user auth totp kim on 2>&1 | sed -n 's/^key: //p' > "$T/kim.key"
[ -s "$T/kim.key" ] && ok || bad "a second step is turned on for the limits' checks" "no key"
tally < <(run limits)

"$BIN" idp-user auth add lea --password leapassword123 >/dev/null 2>&1
"$BIN" idp-user auth totp lea on 2>&1 | sed -n 's/^key: //p' > "$T/lea.key"
tally < <(run replay)

"$BIN" stop auth >/dev/null 2>&1
"$BIN" start auth >/dev/null 2>&1
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PI/jwks")" = 200 ] && break; sleep 0.1; done
tally < <(run restarted)
AFTER=$("$BIN" idp-user auth show alice 2>&1)
case "$AFTER" in "id: $ALICE"*"game.class: mage"*) ok ;; *) bad "an account keeps its id and its fields across a restart" "$AFTER" ;; esac

# ── A provider sharing its sign-in under a cookie domain sends a browser nowhere outside it ──
P2=$((SL_PORT_BASE + 1965))
"$BIN" create idp auth2 -p "$P2" --issuer "https://auth.example.com" --cookie-domain example.com -s >/dev/null 2>&1 \
    && ok || bad "an idp with --cookie-domain is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$P2/jwks")" = 200 ] && break; sleep 0.1; done
EVIL='https%3A%2F%2Fevil.example%5C.example.com%2F'
expect "a return address whose host a backslash ends, which a browser reads as a slash, is refused" \
    "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$P2/login?rd=$EVIL")" 400
expect "one on a name under the cookie domain is not" \
    "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$P2/login?rd=https%3A%2F%2Fapp.example.com%2Fx")" 200
expect "a sign-out sends a browser to no such address" \
    "$(curl -s -o /dev/null -w '%{redirect_url}' "http://127.0.0.1:$P2/logout?post_logout_redirect_uri=$EVIL")" ""
expect "but to one under the cookie domain" \
    "$(curl -s -o /dev/null -w '%{redirect_url}' "http://127.0.0.1:$P2/logout?post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2Fx")" \
    "https://app.example.com/x"

SHOWJ=$("$BIN" show auth 2>/dev/null)
case "$SHOWJ" in *'"issuer": "http://127.0.0.1:'*) ok ;; *) bad "show names the issuer" "$SHOWJ" ;; esac
STATS=$("$BIN" stats auth 2>/dev/null)
case "$STATS" in *"accounts:13"*) ok ;; *) bad "stats counts the accounts" "$STATS" ;; esac

echo "  Results: $PASS/$((PASS+FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
