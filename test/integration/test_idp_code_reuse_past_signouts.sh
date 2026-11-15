#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: a code exchanged a second time revokes what the first exchange gave even when the account already
# keeps the most sign-outs it keeps, and the two exchanges are taken in the same turn of the provider's loop.
#
# What it would catch: past the 32 signed-out sids an account keeps, a sign-out fell back to ending every session
# before now (revoked_before) and kept no field for the grant it revoked.  A token given after that moment -- the
# first exchange's, answered once its family is on the disk, after the second exchange was taken in the same turn --
# was newer than the floor and named a grant nothing said was revoked: its access token was taken at /userinfo for an
# hour, and a refresh family written after the fallback would refresh for thirty days.
#
# The window is hit by stopping the provider's processes -- each runtime runs in a process of its own, each shard in one,
# not in the daemon's -- sending both exchanges, waiting until both lie whole in the sockets' receive queues, and letting
# them go on: two connections held by one process are then read in one turn, the second's revocation made before the
# first's answer, whichever of the two the loop takes first, and exactly one exchange is refused.  On --shards the
# two connections are placed on purpose: on one shard (the same turn), and on two shards, where either shard's word
# can reach shard 0 first; when the revocation does, the family is not written and the first exchange is refused as
# well (`?so.<grant>`), which is as right as its tokens being revoked after.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a code used again past the sign-outs an account keeps still revokes what it gave ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
daemon_isolate idpreuse
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1927))
PS=$((SL_PORT_BASE + 1928))
unset SOCKETLEY_CONFIG
# The providers' processes are stopped for a moment below; they are let go on whatever ends the test.
let_go() {
    [ -n "${SOCKETLEY_DPID:-}" ] || return 0
    local p
    for p in $(ps -o pid= --ppid "$SOCKETLEY_DPID" 2>/dev/null); do kill -CONT "$p" 2>/dev/null; done
}
trap 'let_go; daemon_stop' EXIT
daemon_start "$BIN"
printf 'wiki wikisecret http://127.0.0.1:9/cb\n' > "$T/clients"
# One provider on one loop, and one on four shards, where the two exchanges may be taken at different shards and the
# family is written at shard 0 by a call that can come after the revocation's.
"$BIN" create idp auth -p "$P" --clients "$T/clients" --issuer "http://127.0.0.1:$P" -s >/dev/null 2>&1
"$BIN" create idp auth4 -p "$PS" --clients "$T/clients" --issuer "http://127.0.0.1:$PS" --shards 4 -s >/dev/null 2>&1
for port in "$P" "$PS"; do
    for _ in $(seq 1 100); do curl -s -o /dev/null "http://127.0.0.1:$port/jwks" && break; sleep 0.1; done
done
for u in ann bea; do "$BIN" idp-user auth add "$u" --password "${u}password1" >/dev/null 2>&1 || bad "$u is made" "rc $?"; done
for u in cid dee eli fay; do "$BIN" idp-user auth4 add "$u" --password "${u}password1" >/dev/null 2>&1 || bad "$u is made" "rc $?"; done

cat > "$T/reuse.py" <<'PY'
import base64, http.client, json, os, signal, socket, sys, time, urllib.parse
port, pid, user = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
CB = "http://127.0.0.1:9/cb"
BASIC = "Basic " + base64.b64encode(b"wiki:wikisecret").decode()
def check(name, got, want):
    print(("ok " if got == want else "bad ") + name + ("" if got == want else ": got %r, want %r" % (got, want)))
def req(method, path, form=None, cookie=None, auth=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
    h = {}
    if form is not None: h["Content-Type"] = "application/x-www-form-urlencoded"
    if cookie: h["Cookie"] = cookie
    if auth: h["Authorization"] = auth
    c.request(method, path, body=urllib.parse.urlencode(form) if form is not None else None, headers=h)
    r = c.getresponse(); d = r.read(); hs = r.msg; c.close()
    return r.status, d, hs
ask = dict(client_id="wiki", redirect_uri=CB, response_type="code", scope="openid offline_access", state="s")
def code_of(h):
    return urllib.parse.parse_qs(urllib.parse.urlparse(h.get("Location", "")).query).get("code", [""])[0]
def exchange_form(code):
    return dict(grant_type="authorization_code", code=code, redirect_uri=CB)
def exchange(code):
    st, body, _ = req("POST", "/token", exchange_form(code), auth=BASIC)
    return st, json.loads(body or b"{}")

# Signed in once; every code after is the session's, so no password is hashed again.
st, _, h = req("POST", "/authorize", dict(ask, username=user, password=user + "password1"))
cookie = next((c.split(";")[0] for c in h.get_all("Set-Cookie") or [] if c.startswith("skl_idp=")), "")
first = code_of(h)
codes = [first]
# 32 codes each exchanged twice: 32 grants revoked, each kept as a signed-out sid, the most an account keeps.
for i in range(32):
    code = codes[i] if i < len(codes) else code_of(req("GET", "/authorize?" + urllib.parse.urlencode(ask), cookie=cookie)[2])
    a, _ = exchange(code)
    b, why = exchange(code)
    if (a, b) != (200, 400):
        check("sign-out %d by a code used again" % (i + 1), (a, b, why.get("error")), (200, 400, "invalid_grant"))
        sys.exit(0)
print("ok 32 codes used again, 32 grants revoked")
code = code_of(req("GET", "/authorize?" + urllib.parse.urlencode(ask), cookie=cookie)[2])
check("a 33rd code is given", bool(code), True)

# Which process holds each of our connections' far ends, by the socket's inode; the runtime's processes are the
# daemon's children, one per shard, and listen on the port.
def children():
    out = []
    for t in os.listdir("/proc/%d/task" % pid):
        try:
            out += [int(x) for x in open("/proc/%d/task/%s/children" % (pid, t)).read().split()]
        except OSError:
            pass
    return out
def far_ends(locals_):
    out = {}
    for line in open("/proc/net/tcp").read().splitlines()[1:]:
        f = line.split()
        if int(f[1].split(":")[1], 16) == port and int(f[2].split(":")[1], 16) in locals_ and f[3] == "01":
            out[int(f[2].split(":")[1], 16)] = (int(f[9]), int(f[4].split(":")[1], 16))
    return out
def holders():
    by_inode = {}
    for p in children():
        try:
            for fd in os.listdir("/proc/%d/fd" % p):
                try:
                    t = os.readlink("/proc/%d/fd/%s" % (p, fd))
                except OSError:
                    continue
                if t.startswith("socket:["):
                    by_inode[int(t[8:-1])] = p
        except OSError:
            pass
    return by_inode
def holder_of(c):
    me = c.sock.getsockname()[1]
    end = far_ends({me}).get(me)
    return holders().get(end[0]) if end else None
def opened():
    # Answered once, so the provider has taken the connection when it is stopped.
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
    c.request("GET", "/jwks"); r = c.getresponse(); r.read()
    return c

# Two connections held by one process, or with place == "apart" by two; the first found that fit are kept.
place = sys.argv[4] if len(sys.argv) > 4 else "together"
conns, spare = [], []
for _ in range(64):
    c = opened()
    h = holder_of(c)
    if h is None:
        spare.append(c); continue
    if not conns or (h == holder_of(conns[0])) == (place == "together"):
        conns.append(c)
    else:
        spare.append(c)
    if len(conns) == 2:
        break
for c in spare:
    c.close()
check("two connections are held as asked (%s)" % place, len(conns), 2)
if len(conns) != 2:
    sys.exit(0)
body = urllib.parse.urlencode(exchange_form(code)).encode()
ask_bytes = ("POST /token HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nAuthorization: %s\r\n"
             "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n"
             % (port, BASIC, len(body))).encode() + body
stopped = children()
def all_stopped():
    for p in stopped:
        try:
            st = open("/proc/%d/stat" % p).read()
        except OSError:
            continue
        if st[st.rindex(")") + 2] not in "Tt":
            return False
    return True
mine = {c.sock.getsockname()[1] for c in conns}
queued = False
for p in stopped:
    os.kill(p, signal.SIGSTOP)
try:
    end = time.time() + 10
    while not all_stopped() and time.time() < end:
        time.sleep(0.002)
    for c in conns:
        c.sock.sendall(ask_bytes)
    # Not let go before both exchanges lie whole in their sockets, however slowly this box moves them.
    while time.time() < end:
        q = far_ends(mine)
        if len(q) == 2 and all(rx == len(ask_bytes) for _, rx in q.values()):
            queued = True
            break
        time.sleep(0.002)
finally:
    for p in stopped:
        os.kill(p, signal.SIGCONT)
check("both exchanges were queued whole while the provider was stopped", queued, True)
answers = []
for c in conns:
    r = http.client.HTTPResponse(c.sock, method="POST"); r.begin()
    answers.append((r.status, json.loads(r.read() or b"{}"))); c.close()
given = [a for st, a in answers if st == 200]
refused = [a.get("error") for st, a in answers if st == 400]
if place == "together":
    check("of the code exchanged twice in one turn, one exchange is refused", refused, ["invalid_grant"])
else:
    # Across two shards: the other gives tokens, revoked below, or is refused too when the revocation came first.
    check("of the code exchanged at two shards at once, no more than one gives tokens",
          (len(given) <= 1, len(given) + len(refused), set(refused)), (True, 2, {"invalid_grant"}))
t = given[0] if given else {}
if given:
    # Whatever the exchange that won gave is revoked: its access token and its refresh family.
    st, _, _ = req("GET", "/userinfo", auth="Bearer " + t.get("access_token", ""))
    check("the access token the other exchange gave is not taken", st, 401)
    st, b, _ = req("POST", "/token", dict(grant_type="refresh_token", refresh_token=t.get("refresh_token", "")), auth=BASIC)
    check("nor does its refresh token refresh", (st, json.loads(b or b"{}").get("error")), (400, "invalid_grant"))
else:
    print("ok neither exchange gave tokens")
PY

for pu in "$P ann together" "$P bea together" "$PS cid together" "$PS dee together" "$PS eli apart" "$PS fay apart"; do
    set -- $pu; u=$2
    out=$(timeout 120 python3 "$T/reuse.py" "$1" "$SOCKETLEY_DPID" "$u" "$3" 2>&1)
    while IFS= read -r line; do
        case "$line" in
            "ok "*) ok ;;
            "bad "*) bad "$u: ${line#bad }" "" ;;
            *) echo "  $u: $line" ;;
        esac
    done <<<"$out"
    [ -n "$out" ] || bad "$u: the checks ran" "no output"
done
kill -0 "$SOCKETLEY_DPID" 2>/dev/null && ok || bad "the daemon goes on after the stop" "gone"

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
