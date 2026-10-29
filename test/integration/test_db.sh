#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# The db runtime: JSON documents for applications, owned by the accounts of an idp runtime.
#
# What each part would catch:
#   * a document answered before its change is on the disk, or a pipelined read answered before the write ahead of it
#   * a version that does not grow, or an If-Match / If-None-Match that does not hold a write back
#   * an account reading or writing another's document, or anybody writing without signing in
#   * a page of another site writing with the browser's cookie, or an origin not named getting CORS
#   * an access token of the provider not taken as the account it names, or a key's secret matched loosely
#   * a transaction made in part, or a unique value taken twice
#   * the documents, the schema or the keys lost across a restart of the runtime or of the daemon
#   * a script's socketley.db not reaching the documents, or answering before the change is kept
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

echo "=== Integration: the db runtime keeps documents for applications and their accounts ==="
daemon_isolate db
T=$SOCKETLEY_TMPD
PI=$((SL_PORT_BASE + 1970))
PD=$((SL_PORT_BASE + 1971))
PS=$((SL_PORT_BASE + 1972))
trap 'daemon_stop' EXIT
daemon_start "$BIN"

cat > "$T/clients" <<EOF
spa - http://localhost:5173/cb
other - http://localhost:5174/cb
EOF
cat > "$T/schema" <<EOF
# collection access   indexes
chars        owner    level unique:name
posts        shared
scores       public   score
products     catalog  unique:sku
EOF
cat > "$T/keys" <<EOF
backend dbbackendsecret0123456789
EOF
chmod 600 "$T/keys"

out=$("$BIN" create db x1 -p "$PD" 2>&1); rc=$?
[ "$rc" -ne 0 ] && ok || bad "a database no key nor account can write is refused" "rc $rc: $out"
out=$("$BIN" create db x3 -p "$PD" --keys relative.keys 2>&1); rc=$?
case "$("$BIN" show x3 2>&1)" in *"$PWD/relative.keys"*) [ "$rc" -eq 0 ] && ok || bad "a relative --keys is made absolute by the CLI" "rc $rc: $out" ;; *) bad "a relative --keys is made absolute by the CLI" "rc $rc: $out" ;; esac
"$BIN" remove x3 >/dev/null 2>&1
printf 'chars everyone\n' > "$T/badschema"
out=$("$BIN" create db x4 -p "$PD" --keys "$T/keys" --schema "$T/badschema" -s 2>&1); rc=$?
st=$("$BIN" ls 2>/dev/null | awk '$2=="x4"{print $NF}')
case "$(tail -20 "$SOCKETLEY_DLOG")" in *"access is private, owner, shared, public or catalog"*) ok ;; *) bad "a schema that does not read stops the start and says why" "rc $rc: $out" ;; esac
"$BIN" remove x4 >/dev/null 2>&1

"$BIN" create idp auth -p "$PI" --clients "$T/clients" --issuer "http://127.0.0.1:$PI" -s >/dev/null 2>&1 \
    && ok || bad "the idp runtime is made" "$(tail -3 "$SOCKETLEY_DLOG")"
"$BIN" create db data -p "$PD" --schema "$T/schema" --keys "$T/keys" --idp auth --idp-audience spa --origins "http://app.test" -s >/dev/null 2>&1 \
    && ok || bad "the db runtime is made and started" "$(tail -3 "$SOCKETLEY_DLOG")"
for p in "$PI/jwks" "$PD/"; do
    for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p")" != 000 ] && break; sleep 0.1; done
done
ALICE=$("$BIN" idp-user auth add alice --password alicepassword1 2>&1)
BOB=$("$BIN" idp-user auth add bob --password bobpassword12 2>&1)
[ ${#ALICE} -eq 22 ] && [ ${#BOB} -eq 22 ] && ok || bad "two accounts are made" "$ALICE / $BOB"

cat > "$T/server.lua" <<'LUA'
local function say(id, ...) self.send(id, table.concat({...}, " ")) end
function on_client_message(client_id, msg)
    local w = {}
    for x in msg:gmatch("%S+") do w[#w + 1] = x end
    if w[1] == "put" then
        local d, code, message = socketley.db.put("data", "notes", w[2], { text = w[3], n = 1 })
        if not d then return say(client_id, "err", tostring(code), tostring(message)) end
        say(client_id, "ok", d._id, d._v)
    elseif w[1] == "inc" then
        local d, code = socketley.db.patch("data", "notes", w[2], { inc = { n = 5 } })
        if not d then return say(client_id, "err", tostring(code)) end
        say(client_id, "n", d.n, d._v)
    elseif w[1] == "get" then
        local d, code = socketley.db.get("data", "notes", w[2])
        if not d then return say(client_id, "err", tostring(code)) end
        say(client_id, "text", d.text)
    elseif w[1] == "query" then
        local r, code = socketley.db.query("data", "notes", { where = { n = { gte = 1 } }, sort = "-n" })
        if not r then return say(client_id, "err", tostring(code)) end
        local ids = {}
        for _, d in ipairs(r.docs) do ids[#ids + 1] = d._id end
        say(client_id, "ids", table.concat(ids, ","))
    elseif w[1] == "cb" then
        socketley.db.get("data", "notes", w[2], function(d, code)
            say(client_id, "cb", d and d.text or tostring(code))
        end)
    elseif w[1] == "nodb" then
        local d, code = socketley.db.get("nosuchdb", "notes", "x")
        say(client_id, "nodb", tostring(d), tostring(code))
    end
end
LUA
"$BIN" create server sv -p "$PS" --lua "$T/server.lua" -s >/dev/null 2>&1 \
    && ok || bad "a server whose script uses socketley.db is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 50); do (exec 3<>/dev/tcp/127.0.0.1/$PS) 2>/dev/null && break; sleep 0.1; done

run() {
    python3 - "$1" "$PI" "$PD" "$PS" "$ALICE" "$BOB" "$T" 2>&1 <<'PY'
import sys, json, socket, base64, hashlib, os, time, urllib.request, urllib.error, urllib.parse
phase, pi, pd, ps, alice, bob, tmpd = sys.argv[1:8]
I = "http://127.0.0.1:%s" % pi
D = "http://127.0.0.1:%s" % pd
KEY = {"Authorization": "Bearer dbbackendsecret0123456789"}
def check(name, got, want):
    print(("ok " if got == want else "bad ") + name + ("" if got == want else ": got %r, want %r" % (got, want)))

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None
op = urllib.request.build_opener(NoRedirect)
def at(base, method, path, body=None, headers=None, form=None):
    h = dict(headers or {})
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        h["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        h.setdefault("Content-Type", "application/json")
    r = urllib.request.Request(base + path, data=data, method=method, headers=h)
    try:
        with op.open(r) as resp:
            return resp.status, resp.read().decode(), resp.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), e.headers
def db(method, path, body=None, headers=None):
    st, text, h = at(D, method, path, body, headers)
    try:
        return st, json.loads(text) if text else None, h
    except ValueError:
        return st, text, h
def sign_in(user, password):
    st, _, h = at(I, "POST", "/login", form={"username": user, "password": password, "rd": I + "/account"})
    return (h.get("Set-Cookie") or "").split(";")[0]
def access_token(user, password, client="spa", cb="http://localhost:5173/cb"):
    verifier = base64.urlsafe_b64encode(os.urandom(40)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    st, _, h = at(I, "POST", "/authorize", form=dict(client_id=client, redirect_uri=cb, response_type="code", scope="openid",
                  state="s", code_challenge=challenge, code_challenge_method="S256", username=user, password=password))
    code = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(h.get("Location", "")).query)).get("code")
    st, body, _ = at(I, "POST", "/token", form=dict(grant_type="authorization_code", code=code, redirect_uri=cb,
                     client_id=client, code_verifier=verifier))
    return json.loads(body).get("access_token") if st == 200 else None
def lines(port, msgs):
    s = socket.create_connection(("127.0.0.1", int(port)), 5)
    s.settimeout(5)
    out = []
    buf = b""
    for m in msgs:
        s.sendall((m + "\n").encode())
        while b"\n" not in buf:
            d = s.recv(4096)
            if not d:
                break
            buf += d
        line, _, buf = buf.partition(b"\n")
        out.append(line.decode())
    s.close()
    return out

if phase == "main":
    # ── A key: every collection, versions and preconditions ────────────────────
    st, d, h = db("PUT", "/c/notes/n1", {"text": "hello", "tags": ["a"]}, KEY)
    check("a key makes a document in a collection no schema names", (st, d.get("_id"), d.get("_v"), h.get("ETag")), (201, "n1", 1, '"1"'))
    st, d, h = db("GET", "/c/notes/n1", headers=KEY)
    check("and reads it back with its version", (st, d.get("text"), d.get("_v"), h.get("ETag")), (200, "hello", 1, '"1"'))
    st, d, h = db("PUT", "/c/notes/n1", {"text": "again"}, dict(KEY, **{"If-Match": '"1"'}))
    check("a replacement at the version named is made, and the version grows", (st, d.get("_v")), (200, 2))
    st, d, _ = db("PUT", "/c/notes/n1", {"text": "late"}, dict(KEY, **{"If-Match": '"1"'}))
    check("one at a version gone is refused", (st, d.get("error")), (412, "version"))
    st, d, _ = db("PUT", "/c/notes/n1", {"text": "x"}, dict(KEY, **{"If-None-Match": "*"}))
    check("If-None-Match: * makes a document only where none is", (st, d.get("error")), (412, "exists"))
    st, d, _ = db("PATCH", "/c/notes/n1", {"set": {"meta.by": "key"}, "inc": {"count": 2}, "push": {"tags": "b"}}, KEY)
    check("a patch changes fields in place", (st, d.get("meta"), d.get("count"), d.get("_v")), (200, {"by": "key"}, 2, 3))
    st, d, _ = db("POST", "/c/notes", {"text": "made"}, KEY)
    made = d.get("_id", "")
    check("a POST to the collection makes a document under a new id", (st, len(made)), (201, 22))
    st, d, _ = db("DELETE", "/c/notes/" + made, headers=KEY)
    check("a document is deleted", (st, d.get("deleted")), (200, True))
    check("and is gone", db("GET", "/c/notes/" + made, headers=KEY)[0], 404)
    check("a path that is no collection is refused", db("GET", "/c/Notes/x", headers=KEY)[0], 400)
    check("an id the API's own paths take is refused", db("PUT", "/c/notes/_x", {}, KEY)[0], 400)
    check("a body that is no JSON object is refused", db("PUT", "/c/notes/n2", b"[1]", KEY)[0], 400)
    st, d, _ = db("GET", "/", headers=KEY)
    check("a key sees the collections", (st, "notes" in d.get("collections", [])), (200, True))

    # ── Who asks ───────────────────────────────────────────────────────────────
    check("nobody reads a private collection", db("GET", "/c/notes/n1")[0], 401)
    check("a bearer that is no key and no token is refused",
          db("GET", "/c/notes/n1", headers={"Authorization": "Bearer dbbackendsecret012345678X"})[0], 401)
    check("nor is half a key's secret one", db("GET", "/c/notes/n1", headers={"Authorization": "Bearer dbbackendsecret"})[0], 401)
    check("Basic is no way in", db("GET", "/c/notes/n1", headers={"Authorization": "Basic YTpi"})[0], 401)

    ca = sign_in("alice", "alicepassword1")
    cb = sign_in("bob", "bobpassword12")
    check("both sign in at the provider", (ca.startswith("skl_idp="), cb.startswith("skl_idp=")), (True, True))
    A = {"Cookie": ca}
    B = {"Cookie": cb}
    st, d, _ = db("GET", "/me", headers=A)
    check("the database knows the account by its id", (st, d.get("sub")), (200, alice))
    st, d, _ = db("PUT", "/c/chars/c1", {"name": "Merlin", "level": 3}, A)
    check("an account makes a document in an owner collection, owned by it", (st, d.get("_owner")), (201, alice))
    check("another account is told it is not there", db("GET", "/c/chars/c1", headers=B)[0], 404)
    check("nor may it replace it", db("PUT", "/c/chars/c1", {"name": "x"}, B)[0], 404)
    check("nor delete it", db("DELETE", "/c/chars/c1", headers=B)[0], 404)
    st, d, _ = db("PATCH", "/c/chars/c1", {"set": {"level": 1}}, dict(B, **{"If-Match": '"7"'}))
    check("nor does a condition on it say its version", (st, d.get("error"), "version" in json.dumps(d)), (404, "not_found", False))
    st, d, _ = db("PUT", "/c/chars/c1", {"name": "x"}, dict(B, **{"If-None-Match": "*"}))
    check("or answer before the account is judged", (st, d.get("error")), (404, "not_found"))
    check("a name another holds is refused: it is unique", db("PUT", "/c/chars/c2", {"name": "Merlin"}, B)[0], 409)
    db("PUT", "/c/chars/c3", {"name": "Arthur", "level": 7}, B)
    db("PUT", "/c/chars/c4", {"name": "Nimue", "level": 9}, A)
    st, d, _ = db("POST", "/c/chars/_query", {"sort": "-level"}, A)
    check("a query sees the account's own documents alone", (st, [x["_id"] for x in d.get("docs", [])]), (200, ["c4", "c1"]))
    st, d, _ = db("POST", "/c/chars/_query", {"where": {"level": {"gt": 1}}, "count": True}, KEY)
    check("a key's query sees them all", d, {"count": 3})
    st, d, _ = db("PUT", "/c/chars/c5", {"name": "Morgana", "_owner": bob}, A)
    check("an account cannot hand a document to another", d.get("_owner"), alice)

    check("a shared collection is written by its account", db("PUT", "/c/posts/p1", {"t": "hi"}, A)[0], 201)
    check("read by another", db("GET", "/c/posts/p1", headers=B)[0], 200)
    check("but not written by it", db("PUT", "/c/posts/p1", {"t": "mine"}, B)[0], 403)
    check("and not read by nobody", db("GET", "/c/posts/p1")[0], 401)
    db("PUT", "/c/scores/s1", {"score": 10}, A)
    db("PUT", "/c/scores/s2", {"score": 30}, B)
    st, d, _ = db("POST", "/c/scores/_query", {"sort": "-score", "limit": 1})
    check("a public collection is queried by nobody", (st, [x["_id"] for x in d.get("docs", [])], d.get("next")), (200, ["s2"], 1))
    check("but nobody writes there", db("PUT", "/c/scores/s3", {"score": 1})[0], 401)
    check("a catalog is not written by an account", db("PUT", "/c/products/p1", {"sku": "a"}, A)[0], 403)
    check("but by a key", db("PUT", "/c/products/p1", {"sku": "a"}, KEY)[0], 201)
    check("and read by nobody", db("GET", "/c/products/p1")[0], 200)

    # ── Another site's page ───────────────────────────────────────────────────
    check("a write by cookie that is no JSON is refused, as a form would send it",
          db("PUT", "/c/chars/c6", b"{}", dict(A, **{"Content-Type": "text/plain"}))[0], 415)
    check("so is one from an origin not named", db("PUT", "/c/chars/c6", {}, dict(A, Origin="http://evil.test"))[0], 403)
    check("one from a named origin is taken", db("PUT", "/c/chars/c6", {"name": "Vivien"}, dict(A, Origin="http://app.test"))[0], 201)
    st, _, h = at(D, "OPTIONS", "/c/chars/c6", headers={"Origin": "http://app.test", "Access-Control-Request-Method": "PUT"})
    check("a named origin's preflight is answered with its credentials",
          (st, h.get("Access-Control-Allow-Origin"), h.get("Access-Control-Allow-Credentials"), "If-Match" in (h.get("Access-Control-Allow-Headers") or "")),
          (204, "http://app.test", "true", True))
    st, _, h = at(D, "OPTIONS", "/c/chars/c6", headers={"Origin": "http://evil.test"})
    check("another's is not", h.get("Access-Control-Allow-Origin"), None)

    # ── An access token, as a game or an app outside the cookie's domain sends ──
    tok = access_token("bob", "bobpassword12")
    check("the provider gives an access token", bool(tok), True)
    T = {"Authorization": "Bearer %s" % tok}
    st, d, _ = db("POST", "/c/chars/_query", {}, T)
    check("the database takes it as the account it names", (st, [x["_id"] for x in d.get("docs", [])]), (200, ["c3"]))
    check("and writes as that account", db("PATCH", "/c/chars/c3", {"inc": {"level": 1}}, T)[1].get("level"), 8)
    check("a token changed by a byte is refused", db("GET", "/me", headers={"Authorization": "Bearer %sx" % tok})[0], 401)
    # A token the provider gave another of its applications is that application's, and no key to this database.
    other = access_token("bob", "bobpassword12", "other", "http://localhost:5174/cb")
    check("the provider gives the other application a token too", bool(other), True)
    check("which a database that names only spa refuses", db("GET", "/me", headers={"Authorization": "Bearer %s" % other})[0], 401)

    # ── A transaction ─────────────────────────────────────────────────────────
    st, d, _ = db("POST", "/tx", {"ops": [{"op": "put", "c": "notes", "id": "t1", "doc": {"a": 1}},
                                          {"op": "delete", "c": "notes", "id": "nothing"}]}, KEY)
    check("a transaction one change of which cannot be made is refused", (st, d.get("error")), (404, "not_found"))
    check("and the change before it is not made", db("GET", "/c/notes/t1", headers=KEY)[0], 404)
    st, d, _ = db("POST", "/tx", {"ops": [{"op": "put", "c": "notes", "id": "t1", "doc": {"a": 1}},
                                          {"op": "patch", "c": "notes", "id": "n1", "changes": {"set": {"linked": "t1"}}, "if": 3},
                                          {"op": "insert", "c": "notes", "doc": {"a": 2}}]}, KEY)
    check("a whole one is made, each change answered", (st, len(d.get("results", [])), d["results"][1].get("linked") if st == 200 else None),
          (200, 3, "t1"))

    # ── Pipelined: a read behind a write is answered after it, with what it wrote ──
    s = socket.create_connection(("127.0.0.1", int(pd)), 5)
    s.settimeout(5)
    req = ""
    for i in range(3):
        b = json.dumps({"i": i})
        req += "PUT /c/notes/pipe HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer dbbackendsecret0123456789\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s" % (len(b), b)
    req += "GET /c/notes/pipe HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer dbbackendsecret0123456789\r\nConnection: close\r\n\r\n"
    s.sendall(req.encode())
    got = b""
    while True:
        x = s.recv(65536)
        if not x:
            break
        got += x
    s.close()
    bodies = [p.split(b"\r\n\r\n", 1)[1][:200] for p in got.split(b"HTTP/1.1 ")[1:]]
    check("four pipelined answers come in order, the read seeing the last write",
          [json.loads(b.decode()).get("_v") for b in bodies], [1, 2, 3, 3])

    # ── An answer is a promise: the change is in the journal on the disk before it ──
    import glob
    def on_disk():
        return b"".join(open(f, "rb").read() for f in glob.glob(tmpd + "/home/.local/share/socketley/*/db/data/seg-*.log"))
    seen = []
    for i in range(20):
        mark = "durable-%d-%s" % (i, os.urandom(6).hex())
        db("PUT", "/c/notes/d%d" % i, {"m": mark}, KEY)
        seen.append(mark.encode() in on_disk())
    check("every write answered is already in the journal file", seen, [True] * 20)

    # ── A script ──────────────────────────────────────────────────────────────
    r = lines(ps, ["put l1 fromlua", "inc l1", "get l1", "query", "cb l1", "nodb"])
    check("socketley.db writes, patches and reads from a script", r[:3], ["ok l1 1", "n 6 2", "text fromlua"])
    check("and queries", r[3], "ids l1")
    check("and calls back where it cannot wait", r[4], "cb fromlua")
    check("a database that is not there is said", r[5].startswith("nodb nil"), True)
    check("what it wrote is the database's", db("GET", "/c/notes/l1", headers=KEY)[1].get("n"), 6)

elif phase == "after":
    st, d, _ = db("GET", "/c/notes/n1", headers=KEY)
    check("a document keeps its fields and version across a restart", (st, d.get("text"), d.get("_v"), d.get("linked")), (200, "again", 4, "t1"))
    check("so does a script's", db("GET", "/c/notes/l1", headers=KEY)[1].get("n"), 6)
    st, d, _ = db("POST", "/c/chars/_query", {"where": {"_owner": alice}}, KEY)
    check("and every account's", sorted(x["_id"] for x in d.get("docs", [])), ["c1", "c4", "c5", "c6"])
    check("the unique index is the schema's again", db("PUT", "/c/chars/c9", {"name": "Merlin"}, KEY)[0], 409)

elif phase == "schema":
    check("a unique index the documents break is not taken; the one before stays",
          db("PUT", "/c/products/p2", {"sku": "a"}, KEY)[0], 409)
    check("a key added to the file while running is taken",
          db("GET", "/c/notes/n1", headers={"Authorization": "Bearer seconddbsecret0123456789"})[0], 200)
PY
    local rc=$?
    [ "$rc" -eq 0 ] || echo "bad the checker ran to its end: exit $rc"
}

tally < <(run main)

st=$("$BIN" stats data 2>&1)
case "$st" in *"documents:"*"writes:"*"syncs:"*) ok ;; *) bad "stats name the documents, the writes and the syncs" "$st" ;; esac
sy=$(echo "$st" | sed -n 's/^syncs://p'); wr=$(echo "$st" | sed -n 's/^writes://p')
[ -n "$sy" ] && [ "$sy" -gt 0 ] && [ "$sy" -le "$wr" ] && ok || bad "every write is synced, a turn's writes together" "syncs $sy writes $wr"
cfg=$("$BIN" show data 2>&1)
case "$cfg" in *'"schema"'*'"keys"'*'"idp": "auth"'*'"origins"'*) ok ;; *) bad "show carries the schema, keys, idp and origins" "$cfg" ;; esac

out=$("$BIN" edit data --origins "http://other.test" 2>&1); rc=$?
case "$out" in *"cannot be changed with \`edit\`"*"import"*) [ "$rc" -eq 1 ] && ok || bad "edit refuses a db's own flag with exit 1" "rc $rc" ;;
    *) bad "edit sends a db's own flag to import" "rc $rc: $out" ;; esac
echo "$cfg" | sed 's|"origins": "http://app.test"|"origins": "http://app.test,http://other.test"|' > "$T/cfg.json"
"$BIN" import data --restart < "$T/cfg.json" >/dev/null 2>&1 && ok || bad "import --restart takes a db's changed field" "rc $?"
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PD/")" != 000 ] && break; sleep 0.1; done
acao=$(curl -s -o /dev/null -D - -X OPTIONS -H "Origin: http://other.test" "http://127.0.0.1:$PD/c/x/y" | tr -d '\r' | sed -n 's/^Access-Control-Allow-Origin: //Ip')
expect "and the new origin is answered" "$acao" "http://other.test"

"$BIN" stop data >/dev/null 2>&1 && "$BIN" start data >/dev/null 2>&1
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PD/")" != 000 ] && break; sleep 0.1; done
tally < <(run after)

# The daemon itself restarted, its state directory kept: the database comes back running, as it was.
kill "$SOCKETLEY_DPID" 2>/dev/null
wait "$SOCKETLEY_DPID" 2>/dev/null
daemon_start "$BIN"
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PD/")" != 000 ] && break; sleep 0.1; done
tally < <(run after)

# The files are read again while the database runs: a unique index two documents break, which keeps the schema
# before it, and a key added.
for doc in 'p3 {"sku":"b","dup":1}' 'p4 {"sku":"c","dup":1}'; do
    curl -s -o /dev/null -X PUT -H "Authorization: Bearer dbbackendsecret0123456789" -H "Content-Type: application/json" \
        -d "${doc#* }" "http://127.0.0.1:$PD/c/products/${doc%% *}"
done
cat > "$T/schema" <<EOF
chars        owner    level unique:name
posts        shared
scores       public   score
products     catalog  sku unique:dup
EOF
printf 'backend dbbackendsecret0123456789\nsecond seconddbsecret0123456789\n' > "$T/keys"
sleep 1.2
tally < <(run schema)
sleep 1.5
case "$("$BIN" stats data 2>&1)" in *"schema_error:"*"dup cannot be unique"*) ok ;; *) bad "stats say why the schema was not taken" "$("$BIN" stats data 2>&1 | grep -i schema)" ;; esac

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
