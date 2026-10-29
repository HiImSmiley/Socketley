#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# The idp's device grant (RFC 8628), which `socketley login` signs in with, and the bar on guessed client secrets.
#
# What each part would catch:
#   * a client not marked `device` in --clients getting a device code
#   * a token handed out before the person allowed the code, or after they refused it, or twice
#   * a device polling too fast not being told to slow down
#   * the confirmation page reachable without a session, or a code decided twice
#   * a code the address carried allowed without a page saying which application asks and what it may do
#   * a device code redeemed by a client it was not given to
#   * a grant kept by one shard and allowed or polled at another going astray
#   * a sign-in or a device decision missing from the log
#   * guessed client secrets at /token never barring the address
#   * one address taking every device grant a shard keeps, as anyone may ask for one with no secret
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
. "$(dirname "$0")/lib_verdicts.sh"

echo "=== Integration: the idp signs a device in by a code a person allows ==="
daemon_isolate idpdevice
T=$SOCKETLEY_TMPD
P1=$((SL_PORT_BASE + 1966))
P4=$((SL_PORT_BASE + 1967))
trap 'daemon_stop' EXIT
daemon_start "$BIN"

cat > "$T/clients" <<EOF
wiki wikisecret http://127.0.0.1:9/cb
spa - http://localhost:5173/cb
cli - device
EOF
"$BIN" create idp one -p "$P1" --clients "$T/clients" --issuer "http://127.0.0.1:$P1" -s >/dev/null 2>&1 \
    && ok || bad "an idp of one shard is made" "$(tail -3 "$SOCKETLEY_DLOG")"
"$BIN" create idp four -p "$P4" --clients "$T/clients" --issuer "http://127.0.0.1:$P4" --shards 4 -s >/dev/null 2>&1 \
    && ok || bad "an idp of four shards is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for p in "$P1" "$P4"; do
    for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p/jwks")" = 200 ] && break; sleep 0.1; done
done
ALICE1=$("$BIN" idp-user one add alice --password alicepassword1 2>&1) || bad "an account is made at one" "$ALICE1"
ALICE4=$("$BIN" idp-user four add alice --password alicepassword1 2>&1) || bad "an account is made at four" "$ALICE4"
for r in one four; do
    "$BIN" idp-user "$r" add bob --password bobpassword12 >/dev/null 2>&1 || bad "bob is made at $r" "rc $?"
done

run() {
    python3 - "$1" "$2" "$3" "$BIN" "$4" 2>&1 <<'PY' || echo "bad the checks against $1 ran to their end"
import sys, json, re, time, subprocess, urllib.request, urllib.error, urllib.parse
import jwt
port, alice_id, grants, bin_, runtime = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5]
I = "http://127.0.0.1:%s" % port
def check(name, got, want):
    print(("ok " if got == want else "bad ") + name + ("" if got == want else ": got %r, want %r" % (got, want)))
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None
op = urllib.request.build_opener(NoRedirect)
def req(method, path, form=None, cookie=None, headers=None):
    h = dict(headers or {})
    if cookie:
        h["Cookie"] = cookie
    data = urllib.parse.urlencode(form).encode() if form is not None else None
    if data is not None:
        h["Content-Type"] = "application/x-www-form-urlencoded"
    r = urllib.request.Request(I + path, data=data, method=method, headers=h)
    try:
        with op.open(r) as resp:
            return resp.status, resp.read().decode(), resp.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), e.headers
def token(form):
    st, body, _ = req("POST", "/token", form)
    try:
        return st, json.loads(body)
    except ValueError:
        return st, {"raw": body}
def poll(code, client="cli"):
    return token({"grant_type": "urn:ietf:params:oauth:grant-type:device_code", "client_id": client, "device_code": code})

st, body, _ = req("GET", "/.well-known/openid-configuration")
disc = json.loads(body)
check("discovery names the device endpoint", disc.get("device_authorization_endpoint"), I + "/device_authorization")
check("and the grant", "urn:ietf:params:oauth:grant-type:device_code" in disc.get("grant_types_supported", []), True)

st, body, _ = req("POST", "/device_authorization", {"client_id": "wiki", "client_secret": "wikisecret"})
check("a client not marked device gets no device code", (st, json.loads(body).get("error")), (400, "unauthorized_client"))

def start():
    st, body, _ = req("POST", "/device_authorization", {"client_id": "cli", "scope": "openid offline_access"})
    return st, json.loads(body)
st, a = start()
check("a device client gets a device code", st, 200)
check("a user code a person can read", bool(re.fullmatch(r"[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}", a.get("user_code", ""))), True)
check("the page it is allowed on", (a.get("verification_uri"), a.get("verification_uri_complete")),
      (I + "/device", I + "/device?user_code=" + a.get("user_code", "")))
check("and how long and how often", (a.get("expires_in"), a.get("interval")), (600, 5))
others = [start()[1] for _ in range(grants)]
refused = start()[1]
# Anyone may ask for a grant, so one address holds twenty waiting at a shard and another is not held up by it.
if runtime == "one":
    many = [req("POST", "/device_authorization", {"client_id": "cli"}, headers={"X-Forwarded-For": "198.51.100.70"})[0]
            for _ in range(21)]
    check("twenty grants wait for one address, and the next is refused", many, [200] * 20 + [429])
    st, _, _ = req("POST", "/device_authorization", {"client_id": "cli"}, headers={"X-Forwarded-For": "198.51.100.71"})
    check("while another address gets one", st, 200)

st, r = poll(a["device_code"])
check("a code nobody allowed yet is pending", (st, r.get("error")), (400, "authorization_pending"))
st, r = poll(a["device_code"])
check("asked again at once, the device is told to slow down", (st, r.get("error")), (400, "slow_down"))
st, r = poll(a["device_code"], "wiki")
check("another client cannot redeem it", (st, r.get("error")), (401, "invalid_client"))
st, r = token({"grant_type": "urn:ietf:params:oauth:grant-type:device_code", "client_id": "wiki",
               "client_secret": "wikisecret", "device_code": a["device_code"]})
check("not even with its own secret", (st, r.get("error")), (400, "expired_token"))

st, body, h = req("GET", "/device?user_code=" + a["user_code"])
check("the page sends a stranger to sign in first, the code kept",
      (st, h.get("Location")), (302, "/login?rd=" + urllib.parse.quote("/device?user_code=" + a["user_code"], safe="")))
st, body, _ = req("POST", "/device", {"user_code": a["user_code"], "action": "allow"})
check("nor does a post without a session allow anything; it is sent to sign in", st, 302)
st, body, h = req("POST", "/login", {"username": "alice", "password": "alicepassword1", "rd": "/device"})
cookie = (h.get("Set-Cookie") or "").split(";")[0]
check("signing in brings the person back to the page", (st, h.get("Location"), cookie.startswith("skl_idp=")), (302, "/device", True))
st, body, _ = req("GET", "/device?user_code=" + a["user_code"], cookie=cookie)
check("signed in, the page fills the code in and allows nothing yet",
      (st, 'value="%s"' % a["user_code"] in body, 'value="allow"' in body, 'value="look"' in body), (200, True, False, True))
st, body, _ = req("POST", "/device", {"user_code": a["user_code"], "action": "look"}, cookie=cookie)
check("given, the code shows which application asks and what allowing it gives, and only then the button",
      (st, "<b>cli</b>" in body, "until you sign out everywhere" in body, 'value="allow"' in body, "SSH" in body,
       'name="password"' in body), (200, True, True, True, False, False))
# From an address of its own, as the misses below bring this one to the bar.
st, body, _ = req("POST", "/device", {"user_code": "BBBB-BBBB", "action": "look"}, cookie=cookie, headers={"X-Forwarded-For": "198.51.100.90"})
check("a code nobody was given shows nothing to allow", (st, "not known" in body, 'value="allow"' in body), (400, True, False))

# Typed the way a person might: lower case, a space for the dash.
typed = a["user_code"].lower().replace("-", " ")
st, body, _ = req("POST", "/device", {"user_code": typed, "action": "allow"}, cookie=cookie)
check("the code allowed, however it was typed", (st, "The device is signed in." in body), (200, True))
st, body, _ = req("POST", "/device", {"user_code": a["user_code"], "action": "deny"}, cookie=cookie)
check("and decided once: it cannot be refused after", (st, "not known" in body), (400, True))
for o in others:
    st, body, _ = req("POST", "/device", {"user_code": o["user_code"], "action": "allow"}, cookie=cookie)
    check("each of the other codes is allowed wherever the page is served", (st, "signed in" in body), (200, True))
st, body, _ = req("POST", "/device", {"user_code": refused["user_code"], "action": "deny"}, cookie=cookie)
check("a code is refused", (st, "refused" in body), (200, True))
st, body, _ = req("POST", "/device", {"user_code": "BBBB-BBBB", "action": "allow"}, cookie=cookie)
check("a code nobody was given is not known", (st, "not known" in body), (400, True))
st, body, _ = req("POST", "/device", {"user_code": "AEIO-0000", "action": "allow"}, cookie=cookie)
check("nor is one of letters a code never has", (st, "not known" in body), (400, True))

# A device bob allowed, after which bob must set a new password: it gets nothing until bob has.
bobs = start()[1]
st, body, h = req("POST", "/login", {"username": "bob", "password": "bobpassword12", "rd": "/device"})
bob = (h.get("Set-Cookie") or "").split(";")[0]
st, body, _ = req("POST", "/device", {"user_code": bobs["user_code"], "action": "allow"}, cookie=bob)
check("bob allows a device", (st, "signed in" in body), (200, True))
check("and bob is then made to set a new password",
      subprocess.run([bin_, "idp-user", runtime, "set", "bob", "reset=1"], capture_output=True).returncode, 0)

# Past the slow-down the first device was given: five seconds and five more.
time.sleep(10.5)
st, r = poll(a["device_code"])
check("the allowed device gets its tokens", (st, sorted(k for k in r if k.endswith("_token"))),
      (200, ["access_token", "id_token", "refresh_token"]))
st, body, _ = req("GET", "/jwks")
key = jwt.PyJWK(json.loads(body)["keys"][0]).key
claims = jwt.decode(r.get("access_token", ""), key, algorithms=["ES256"], audience="cli")
check("its access token is the account's, for the client", (claims.get("sub"), claims.get("client_id")), (alice_id, "cli"))
st, r = poll(a["device_code"])
check("a device code is good once", (st, r.get("error")), (400, "expired_token"))
for o in others:
    st, r = poll(o["device_code"])
    check("every other allowed device gets its tokens", (st, "access_token" in r), (200, True))
st, r = poll(refused["device_code"])
check("the refused device is told so", (st, r.get("error")), (400, "access_denied"))
st, r = poll(bobs["device_code"])
check("a device allowed by an account made to reset since gets no token", (st, r.get("error")), (400, "invalid_grant"))

# Secrets guessed from one address bar it, and the bar does not reach another address.
far = {"X-Forwarded-For": "203.0.113.9"}
codes = []
for _ in range(6):
    st, body, _ = req("POST", "/token", {"grant_type": "authorization_code", "client_id": "wiki", "client_secret": "guess"}, headers=far)
    codes.append(st)
check("five guessed secrets, then the address is barred", codes, [401] * 5 + [429])
st, body, _ = req("POST", "/token", {"grant_type": "authorization_code", "client_id": "wiki", "client_secret": "wikisecret", "code": "x"}, headers=far)
check("even with the right secret", st, 429)
st, body, _ = req("POST", "/token", {"grant_type": "authorization_code", "client_id": "wiki", "client_secret": "wikisecret", "code": "x"})
check("while another address is not barred", st, 400)
PY
}

tally < <(run "$P1" "$ALICE1" 2 one)
tally < <(run "$P4" "$ALICE4" 8 four)

# ── socketley login, the device grant from the command line ─────────────────
export XDG_CONFIG_HOME="$T/config"
"$BIN" login "http://127.0.0.1:$P1" --client cli > "$T/login.out" 2>&1 &
LOGIN=$!
for _ in $(seq 1 50); do grep -q "allow the code" "$T/login.out" && break; sleep 0.1; done
CODE=$(sed -n 's/^and allow the code //p' "$T/login.out")
case "$(head -1 "$T/login.out")" in "Open http://127.0.0.1:$P1/device?user_code=$CODE") ok ;;
    *) bad "login says where to allow the code" "$(cat "$T/login.out")" ;; esac
python3 - "$P1" "$CODE" <<'PY' >/dev/null 2>&1
import sys, urllib.request, urllib.parse
I = "http://127.0.0.1:%s" % sys.argv[1]
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None
op = urllib.request.build_opener(NoRedirect)
def post(path, form, cookie=None):
    r = urllib.request.Request(I + path, data=urllib.parse.urlencode(form).encode(), method="POST",
                               headers={"Content-Type": "application/x-www-form-urlencoded", **({"Cookie": cookie} if cookie else {})})
    try:
        with op.open(r) as resp: return resp.headers
    except urllib.error.HTTPError as e: return e.headers
cookie = (post("/login", {"username": "alice", "password": "alicepassword1"}).get("Set-Cookie") or "").split(";")[0]
post("/device", {"user_code": sys.argv[2], "action": "allow"}, cookie)
PY
for _ in $(seq 1 150); do kill -0 "$LOGIN" 2>/dev/null || break; sleep 0.1; done
wait "$LOGIN"; rc=$?
TOK="$T/config/socketley/tokens/127.0.0.1_$P1.json"
[ "$rc" -eq 0 ] && [ -f "$TOK" ] && ok || bad "login ends once the code is allowed and keeps the tokens" "rc $rc: $(cat "$T/login.out")"
[ "$(stat -c %a "$TOK" 2>/dev/null)" = 600 ] && ok || bad "readable by their owner alone" "$(stat -c %a "$TOK" 2>&1)"
grep -q '"refresh_token":"[^"]' "$TOK" && grep -q "\"issuer\":\"http://127.0.0.1:$P1\"" "$TOK" && ok \
    || bad "with a refresh token and the issuer" "$(cat "$TOK" 2>&1)"
out=$("$BIN" login "http://127.0.0.1:$P1" --client spa 2>&1); rc=$?
[ "$rc" -eq 1 ] && case "$out" in *"may not use the device grant"*) true ;; *) false ;; esac && ok \
    || bad "a client the provider does not allow the grant is refused" "rc $rc: $out"
"$BIN" logout "http://127.0.0.1:$P1" && [ ! -f "$TOK" ] && ok || bad "logout forgets the tokens" "$(ls "$T/config/socketley/tokens" 2>&1)"

grep -q 'idp one: "alice" signed in with password from 127.0.0.1' "$SOCKETLEY_DLOG" && ok \
    || bad "a sign-in is said in the log with who and from where" "$(grep 'idp one' "$SOCKETLEY_DLOG" | tail -3)"
grep -q 'idp one: "alice" allowed a device sign-in from 127.0.0.1' "$SOCKETLEY_DLOG" && ok \
    || bad "and so is a device allowed" "$(grep 'idp one' "$SOCKETLEY_DLOG" | tail -3)"
grep -q 'idp four: "alice" refused a device sign-in' "$SOCKETLEY_DLOG" && ok \
    || bad "and one refused" "$(grep 'idp four' "$SOCKETLEY_DLOG" | tail -3)"

echo "  Results: $PASS/$((PASS+FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
