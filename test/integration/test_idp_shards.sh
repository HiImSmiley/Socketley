#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# An idp runtime of several shards: shard 0 writes the accounts, every shard reads them and signs in on the one port.
#
# What each part would catch:
#   * a code given by one shard not redeemed at another, or redeemed twice by two
#   * the shards signing with different keys, so a token one gives does not verify against the published key
#   * a change made with idp-user, or on the account page at a reading shard, not seen at once by every shard
#   * a reading shard losing the accounts when shard 0 folds its journal into a snapshot
#   * an address barred at one shard trying its five again at each of the others
#   * the accounts or the key lost when the runtime restarts with another number of shards
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
up() { for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$1/jwks")" = 200 ] && return 0; sleep 0.1; done; return 1; }
# A worker's figures come every 250 ms, so the lines a test reads are waited for.
stats_of() { sleep 0.6; "$BIN" stats "$1" 2>/dev/null; }
sum_of() { awk -F: -v k="$1" '$1 == k { n += $2 } END { print n + 0 }'; }

echo "=== Integration: an idp runtime of several shards, one writing the accounts and every one signing in ==="
daemon_isolate idpshards
T=$SOCKETLEY_TMPD
PI=$((SL_PORT_BASE + 1995))
trap 'daemon_stop' EXIT
daemon_start "$BIN"

cat > "$T/clients" <<EOF
wiki wikisecret http://127.0.0.1:9/cb
EOF

"$BIN" create idp auth -p "$PI" --clients "$T/clients" --issuer "http://127.0.0.1:$PI" --shards 4 -s >/dev/null 2>&1 \
    && ok || bad "an idp runtime of four shards is made" "$(tail -3 "$SOCKETLEY_DLOG")"
up "$PI" || bad "and answers" "$(tail -3 "$SOCKETLEY_DLOG")"
s=$(stats_of auth)
expect "one shard writes the accounts" "$(echo "$s" | grep -c '^role:writer')" 1
expect "and three read them" "$(echo "$s" | grep -c '^role:reader$')" 3

ALICE=$("$BIN" idp-user auth add alice --password alicepassword1 --name "Alice A" 2>&1) \
    && ok || bad "an account is made at shard 0" "$ALICE"
"$BIN" idp-user auth add bob --password bobpassword12 >/dev/null 2>&1 && ok || bad "and another" "rc $?"

run() {
    python3 - "$PI" "$1" "$T" "$ALICE" 2>&1 <<'PY' || echo "bad the $1 checks ran to their end"
import sys, json, base64, http.client, urllib.request, urllib.error, urllib.parse
import jwt
pi, phase, tmpd, alice_id = sys.argv[1:5]
I = "http://127.0.0.1:%s" % pi
CB = "http://127.0.0.1:9/cb"
def check(name, got, want):
    print(("ok " if got == want else "bad ") + name + ("" if got == want else ": got %r, want %r" % (got, want)))
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None
op = urllib.request.build_opener(NoRedirect)
def req(method, path, form=None, headers=None, cookie=None):
    # A connection of its own each time, so the kernel hands the requests to every shard.
    h = dict(headers or {})
    if cookie:
        h["Cookie"] = cookie
    data = urllib.parse.urlencode(form).encode() if form is not None else None
    if data is not None:
        h["Content-Type"] = "application/x-www-form-urlencoded"
    r = urllib.request.Request(I + path, data=data, method=method, headers=h)
    try:
        with op.open(r, timeout=10) as resp:
            return resp.status, resp.read().decode(), resp.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), e.headers
def q(**kw):
    return "?" + urllib.parse.urlencode(kw)
def code_of(h):
    return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(h.get("Location", "")).query)).get("code")
def cookie_of(h):
    return (h.get("Set-Cookie") or "").split(";")[0]
BASIC = {"Authorization": "Basic " + base64.b64encode(b"wiki:wikisecret").decode()}
auth = dict(client_id="wiki", redirect_uri=CB, response_type="code", scope="openid profile", state="s")
def exchange(code):
    st, body, _ = req("POST", "/token", dict(grant_type="authorization_code", code=code, redirect_uri=CB), BASIC)
    return st, (json.loads(body) if st == 200 else {})
def userinfo(tok):
    st, body, _ = req("GET", "/userinfo", headers={"Authorization": "Bearer " + tok})
    return json.loads(body).get("name") if st == 200 else st
def keys():
    jw = json.loads(req("GET", "/jwks")[1])
    return {k["kid"]: jwt.algorithms.ECAlgorithm.from_jwk(json.dumps(k)) for k in jw["keys"]}
state_file = tmpd + "/py.json"

if phase == "main":
    check("every shard publishes the one key", len({json.loads(req("GET", "/jwks")[1])["keys"][0]["kid"] for _ in range(16)}), 1)
    # Signed in by password at whichever shard, each code exchanged at whichever shard.
    codes, cookie = [], None
    for _ in range(8):
        st, body, h = req("POST", "/authorize", dict(auth, username="alice", password="alicepassword1"))
        codes.append(code_of(h))
        cookie = cookie_of(h) or cookie
    check("a sign-in at every shard gives a code", all(codes), True)
    # The browser signed in once, sent back with a code by every shard.
    for _ in range(24):
        codes.append(code_of(req("GET", "/authorize" + q(**auth), cookie=cookie)[2]))
    check("a signed-in browser is given a code at every shard", all(codes), True)
    got = [exchange(c) for c in codes]
    check("every code is redeemed, whichever shard gave it", [st for st, _ in got], [200] * len(codes))
    check("and good once, at every shard", [exchange(c)[0] for c in codes[:12]], [400] * 12)
    ks = keys()
    tokens = [t for _, t in got]
    bad_sig = 0
    for t in tokens:
        try:
            jwt.decode(t["id_token"], ks[jwt.get_unverified_header(t["id_token"])["kid"]], algorithms=["ES256"], audience="wiki", issuer=I)
        except Exception:
            bad_sig += 1
    check("every shard's tokens verify against the published key", bad_sig, 0)
    check("a forged code is known nowhere", exchange("2.forged")[0], 400)
    check("nor one naming a shard there is none of", exchange("9.forged")[0], 400)
    check("every shard answers userinfo", [userinfo(tokens[i]["access_token"]) for i in range(12)], ["Alice A"] * 12)

    # Changed on the account page, at whichever shard; every shard answers with the change at once.
    for n in range(8):
        st, body, _ = req("POST", "/account", dict(name="Alice %d" % n, email="a@example.com"), cookie=cookie)
        check("the account page saves at every shard", (st, "Saved." in body), (200, True))
        check("a change on the account page is what every shard says next",
              [userinfo(tokens[i]["access_token"]) for i in range(8)], ["Alice %d" % n] * 8)
    json.dump({"cookie": cookie, "access": tokens[0]["access_token"], "refresh": tokens[1]["refresh_token"],
               "kid": jwt.get_unverified_header(tokens[0]["id_token"])["kid"], "id_token": tokens[0]["id_token"]},
              open(state_file, "w"))

elif phase == "after_cli":
    s = json.load(open(state_file))
    check("a name set with idp-user is what every shard says at once", [userinfo(s["access"]) for _ in range(8)], ["Set By CLI"] * 8)

elif phase == "compact":
    s = json.load(open(state_file))
    # More changes than the journal holds before it is folded into a snapshot, over one connection to one shard.
    c = http.client.HTTPConnection("127.0.0.1", int(pi), timeout=10)
    failed = 0
    for n in range(1100):
        c.request("POST", "/account", urllib.parse.urlencode(dict(name="N%d" % n, email="a@example.com")),
                  {"Cookie": s["cookie"], "Content-Type": "application/x-www-form-urlencoded"})
        r = c.getresponse()
        r.read()
        failed += r.status != 200
    c.close()
    check("a thousand changes are taken", failed, 0)
    check("and every shard reads the last of them past the snapshot", [userinfo(s["access"]) for _ in range(8)], ["N1099"] * 8)

elif phase == "barred":
    for _ in range(5):
        req("POST", "/authorize", dict(auth, username="bob", password="wrongpassword"), headers={"X-Forwarded-For": "198.51.100.7"})
    check("an address that failed five times is barred at every shard",
          [req("POST", "/authorize", dict(auth, username="bob", password="bobpassword12"), headers={"X-Forwarded-For": "198.51.100.7"})[0] for _ in range(8)],
          [429] * 8)
    check("and another is not", req("POST", "/authorize", dict(auth, username="bob", password="bobpassword12"),
                                    headers={"X-Forwarded-For": "198.51.100.8"})[0], 302)

elif phase == "after_logout":
    s = json.load(open(state_file))
    check("an account disabled with idp-user is refused at every shard at once", [userinfo(s["access"]) for _ in range(8)], [401] * 8)
    st, body, _ = req("POST", "/token", dict(grant_type="refresh_token", refresh_token=s["refresh"]), BASIC)
    check("and refreshes into nothing", st, 400)

elif phase == "restarted":
    s = json.load(open(state_file))
    check("the key survives a restart with another number of shards", {json.loads(req("GET", "/jwks")[1])["keys"][0]["kid"] for _ in range(8)}, {s["kid"]})
    st, body, h = req("POST", "/authorize", dict(auth, username="bob", password="bobpassword12"))
    code = code_of(h)
    check("and the accounts are there, passwords and all", (st, bool(code)), (302, True))
    check("signing in as before", exchange(code)[0] if code else None, 200)
PY
}

tally < <(run main)
s=$(stats_of auth)
served=$(echo "$s" | sum_of crossings_served)
[ "$served" -gt 0 ] && ok || bad "codes and changes cross between the shards" "crossings_served $served"
expect "every shard holds every account" "$(echo "$s" | awk -F: '/^accounts:/ { print $2 }' | sort -u | tr '\n' ' ')" "2 "

"$BIN" idp-user auth set alice name="Set By CLI" >/dev/null 2>&1 && ok || bad "idp-user set takes" "rc $?"
tally < <(run after_cli)

tally < <(run compact)
s=$(stats_of auth)
r=$(echo "$s" | sum_of reopened)
[ "$r" -gt 0 ] && ok || bad "the reading shards read the accounts again after the snapshot" "reopened $r"
out=$("$BIN" idp-user auth show alice 2>&1)
case "$out" in *"name: N1099"*) ok ;; *) bad "shard 0 keeps the last change" "$out" ;; esac

tally < <(run barred)

"$BIN" idp-user auth disable alice >/dev/null 2>&1 && ok || bad "disable takes" "rc $?"
tally < <(run after_logout)
"$BIN" idp-user auth enable alice >/dev/null 2>&1

"$BIN" stop auth >/dev/null 2>&1
"$BIN" edit auth --shards 2 >/dev/null 2>&1 && ok || bad "the number of shards is changed while stopped" "$(tail -3 "$SOCKETLEY_DLOG")"
"$BIN" start auth >/dev/null 2>&1 && up "$PI" && ok || bad "and the runtime starts again" "$(tail -3 "$SOCKETLEY_DLOG")"
expect "with two shards" "$(stats_of auth | grep -c '^shard:')" 2
tally < <(run restarted)

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
