#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Who may connect to an mqtt runtime, and what each may publish and read: a users file, the accounts of an idp
# runtime and access rules, and the same over WebSocket; TLS and client certificates are test_mqtt_tls.sh.
#
# What each part would catch:
#   * a wrong password, an unknown user or a forged token let in, or a right one refused
#   * mqtt-passwd writing a file the broker does not read, or one others can read
#   * a users or rules file changed while running and not taken
#   * a publish the rules refuse delivered anyway, or a subscription widened past what the rules grant
#   * a message a deny rule covers delivered to a subscription it covers only in part
#   * a browser's WebSocket client refused, or a frame boundary cutting a packet wrong
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
. "$HERE/lib_ready.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
tally() { while IFS= read -r line; do case "$line" in ok\ *) ok ;; bad\ *) bad "${line#bad }" "" ;; *) echo "  $line" ;; esac; done; }
expect() { [ "$2" = "$3" ] && ok || bad "$1" "got '$2', want '$3'"; }

echo "=== Integration: an mqtt runtime lets in who it should and gives each what the rules say ==="
daemon_isolate mqttauth
T=$SOCKETLEY_TMPD
PI=$((SL_PORT_BASE + 1931))
PA=$((SL_PORT_BASE + 1932))
PW=$((SL_PORT_BASE + 1933))
trap 'daemon_stop' EXIT
daemon_start "$BIN"

# ── mqtt-passwd ─────────────────────────────────────────────────────────────
printf 'alicepass1\n' | "$BIN" mqtt-passwd "$T/users" alice >/dev/null 2>&1 && ok || bad "mqtt-passwd adds a user" "rc $?"
printf 'bobpass22\n' | "$BIN" mqtt-passwd "$T/users" bob >/dev/null 2>&1
printf 'carolpass3\n' | "$BIN" mqtt-passwd "$T/users" carol >/dev/null 2>&1
printf 'zedpass\n' | "$BIN" mqtt-passwd "$T/users" zed >/dev/null 2>&1
expect "the users file is the owner's alone" "$(stat -c %a "$T/users")" "600"
case "$(grep '^alice:' "$T/users")" in 'alice:$scrypt$'*) ok ;; *) bad "a user's line is user:hash" "$(cat "$T/users")" ;; esac
"$BIN" mqtt-passwd "$T/users" zed --delete >/dev/null 2>&1
grep -q '^zed:' "$T/users" && bad "mqtt-passwd --delete removes a user" "$(cat "$T/users")" || ok
out=$("$BIN" mqtt-passwd "$T/users" nobody --delete 2>&1); rc=$?
expect "deleting a user the file does not hold is exit 1" "$rc" "1"
out=$(printf 'x\n' | "$BIN" mqtt-passwd "$T/users" 'bad:name' 2>&1); rc=$?
expect "a user name with a colon is refused" "$rc" "1"
out=$(printf '' | "$BIN" mqtt-passwd "$T/users" emptypw 2>&1); rc=$?
expect "an empty password is refused" "$rc" "1"
expect "and nothing else in the file moved" "$(cut -d: -f1 "$T/users" | tr '\n' ' ')" "alice bob carol "

cat > "$T/acl" <<'EOF'
# nothing for clients without a user
user alice
topic readwrite home/alice/#
topic read public/#
user carol
topic deny secret/#
topic #
user bob
topic write public/#
pattern readwrite users/%u/#
pattern write devices/%c/state
EOF

# ── the idp's accounts ──────────────────────────────────────────────────────
cat > "$T/clients" <<EOF
spa - http://localhost:5173/cb
EOF
"$BIN" create idp auth -p "$PI" --clients "$T/clients" --issuer "http://127.0.0.1:$PI" -s >/dev/null 2>&1 \
    && ok || bad "an idp runtime is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PI/jwks")" != 000 ] && break; sleep 0.1; done
DAVE=$("$BIN" idp-user auth add dave --password davepassword1 2>&1)
[ ${#DAVE} -eq 22 ] && ok || bad "an account is made" "$DAVE"

"$BIN" create mqtt a -p "$PA" --users "$T/users" --acl "$T/acl" --idp auth --ws "$PW" -s >/dev/null 2>&1 \
    && ok || bad "a broker with users, rules, an idp and WebSocket is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for p in "$PA" "$PW"; do ready_tcp 127.0.0.1 "$p" || bad "port $p listens" "$(tail -5 "$SOCKETLEY_DLOG")"; done

run() {
    PYTHONPATH="$HERE" python3 - "$1" "$PA" "$PW" "$PI" "$BIN" "$T" 2>&1 <<'PY'
import base64, hashlib, json, os, ssl, struct, subprocess, sys, time, urllib.error, urllib.parse, urllib.request
from lib_mqtt import *
phase = sys.argv[1]
pa, pw, pi = (int(x) for x in sys.argv[2:5])
binary, tmpd = sys.argv[5], sys.argv[6]

def check(name, got, want):
    print(("ok " if got == want else "bad ") + name + ("" if got == want else ": got %r, want %r" % (got, want)))

def truth(name, cond, detail=""):
    print(("ok " if cond else "bad ") + name + ("" if cond else ": " + str(detail)))

def guarded(name, fn):
    try:
        fn()
    except Exception as e:
        print("bad %s: %s %s" % (name, type(e).__name__, e))

def code_of(port, version=5, **kw):
    opts = {k: kw.pop(k) for k in ("tls", "ws") if k in kw}
    c = Client(port, version=version, **opts)
    try:
        return c.connect(kw.pop("client_id", ""), **kw)[1]
    finally:
        c.close()

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None
op = urllib.request.build_opener(NoRedirect)
I = "http://127.0.0.1:%d" % pi
def at(method, path, form):
    r = urllib.request.Request(I + path, data=urllib.parse.urlencode(form).encode(), method=method,
                               headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with op.open(r) as resp:
            return resp.status, resp.read().decode(), resp.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), e.headers
def access_token(user, password):
    verifier = base64.urlsafe_b64encode(os.urandom(40)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    cb = "http://localhost:5173/cb"
    st, _, h = at("POST", "/authorize", dict(client_id="spa", redirect_uri=cb, response_type="code", scope="openid",
                  state="s", code_challenge=challenge, code_challenge_method="S256", username=user, password=password))
    code = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(h.get("Location", "")).query)).get("code")
    st, body, _ = at("POST", "/token", dict(grant_type="authorization_code", code=code, redirect_uri=cb,
                     client_id="spa", code_verifier=verifier))
    return json.loads(body).get("access_token") if st == 200 else None

if phase == "main":
    def passwords():
        check("the right password lets a user in", code_of(pa, client_id="a1", username="alice", password="alicepass1"), 0)
        check("a wrong one is refused as bad user name or password",
              code_of(pa, client_id="a2", username="alice", password="nope"), 0x86)
        check("so is a user the file does not hold", code_of(pa, client_id="a3", username="mallory", password="x"), 0x86)
        check("and a client with no credentials, the broker taking no anonymous ones",
              code_of(pa, client_id="a4"), 0x86)
        check("a 3.1.1 client with a wrong password is answered 4",
              code_of(pa, version=4, client_id="a5", username="alice", password="nope"), 4)
        check("and with the right one is let in", code_of(pa, version=4, client_id="a6", username="bob", password="bobpass22"), 0)
    guarded("passwords", passwords)

    def tokens():
        tok = access_token("dave", "davepassword1")
        truth("the provider gives an access token", bool(tok))
        check("an access token given as the password lets its account in", code_of(pa, client_id="d1", password=tok), 0)
        check("with the account's name as user name too", code_of(pa, client_id="d2", username="dave", password=tok), 0)
        check("but not under another's name", code_of(pa, client_id="d3", username="eve", password=tok), 0x86)
        check("and a token changed by a byte not at all", code_of(pa, client_id="d4", password=tok[:-2] + "xx"), 0x86)
        c = connected(pa, "dave-dev", password=tok)
        c.subscribe(("users/dave/#", 1))
        c.publish("users/dave/inbox", "hi", qos=1)
        m = c.message(2)
        check("the account's name is its user for the rules", m.payload if m else None, b"hi")
        c.disconnect()
    guarded("tokens", tokens)

    def rules():
        al = connected(pa, "alice-1", username="alice", password="alicepass1")
        bo = connected(pa, "bob-1", username="bob", password="bobpass22")
        ca = connected(pa, "carol-1", username="carol", password="carolpass3")
        check("a subscription the rules grant is granted", al.subscribe(("home/alice/#", 1), ("public/#", 1)), [1, 1])
        check("one wider than they grant is refused not authorized", al.subscribe(("home/#", 1)), [0x87])
        check("and one they do not grant at all", al.subscribe(("secret/x", 0)), [0x87])
        check("a pattern's %u grants the user's own subtree", al.subscribe(("users/alice/#", 1)), [1])
        check("and not another's", al.subscribe(("users/bob/#", 1)), [0x87])
        check("a publish the rules grant is acknowledged", al.publish("home/alice/lamp", "on", qos=1), 0)
        m = al.message(2)
        check("and delivered", m.payload if m else None, b"on")
        check("one they do not grant is refused not authorized", al.publish("public/news", "from alice", qos=1), 0x87)
        truth("and delivered to nobody", al.quiet(0.5))
        check("a write-only grant publishes", bo.publish("public/news", "from bob", qos=1), 0)
        m = al.message(2)
        check("to who may read it", m.payload if m else None, b"from bob")
        check("but cannot read", bo.subscribe(("public/#", 1)), [0x87])
        check("carol's # is granted though secret/# is denied her", ca.subscribe(("#", 1)), [1])
        ca.messages(100, 0.3)
        bo2 = connected(pa, "dev9", username="bob", password="bobpass22")
        check("a pattern's %c grants the client's own topic", bo2.publish("devices/dev9/state", "up", qos=1), 0)
        check("and not another client's", bo2.publish("devices/dev8/state", "spoof", qos=1), 0x87)
        got = [m.topic for m in ca.messages(5, 1.0)]
        truth("carol hears what she may read", "devices/dev9/state" in got, got)
        dave = connected(pa, "sec-writer", password=access_token("dave", "davepassword1"))
        dave.disconnect()
        al.disconnect()
        # carol may write everywhere but read nothing of secret/#.
        ca2 = connected(pa, "carol-2", username="carol", password="carolpass3")
        ca2.publish("secret/plans", "hidden", qos=1)
        ca2.publish("open/plans", "visible", qos=1)
        got = [m.topic for m in ca.messages(3, 1.0)]
        check("a deny rule holds back what it covers from a subscription it covers in part", got, ["open/plans"])
        for c in (bo, ca, bo2, ca2):
            c.disconnect()
        no = Client(pa)
        check("anonymous clients are not taken without --anonymous", no.connect("anon")[1], 0x86)
        no.close()
    guarded("rules", rules)

    def websocket():
        w = Client(pw, ws="/mqtt")
        check("a WebSocket client offering mqtt is let in", w.connect("ws-1", username="alice", password="alicepass1")[1], 0)
        truth("and was given the mqtt subprotocol", "Sec-WebSocket-Protocol: mqtt" in w.sock.headers, w.sock.headers)
        t = connected(pa, "tcp-1", username="alice", password="alicepass1")
        w.subscribe(("home/alice/ws", 1))
        t.publish("home/alice/ws", "tcp to ws", qos=1)
        m = w.message(2)
        check("a TCP client's message reaches a WebSocket client", m.payload if m else None, b"tcp to ws")
        t.subscribe(("home/alice/tcp", 1))
        big = os.urandom(50000)
        w.publish("home/alice/tcp", big, qos=1)
        m = t.message(3)
        check("and a WebSocket client's large one reaches a TCP client whole", m.payload if m else None, big)
        # One MQTT packet cut across two WebSocket frames, and two packets in one frame.
        pkt = bytes([0x30]) + varint(len(s("home/alice/tcp")) + 6) + s("home/alice/tcp") + b"\x00split"
        w.sock.sendall(pkt[:5])
        w.sock.sendall(pkt[5:])
        two = bytes([0x30]) + varint(len(s("home/alice/tcp")) + 2) + s("home/alice/tcp") + b"\x001"
        w.sock.sendall(two + two)
        got = [m.payload for m in t.messages(3, 2)]
        check("a packet over two frames and two packets in one frame are each a message", got, [b"split", b"1", b"1"])
        w.disconnect()
        t.disconnect()
        import socket as so
        raw = so.create_connection(("127.0.0.1", pw), 3)
        old = WS(raw, "127.0.0.1", "/mqtt", proto="mqttv3.1")
        truth("the older subprotocol name mqttv3.1 is taken too", "Sec-WebSocket-Protocol: mqttv3.1" in old.headers,
              old.headers)
        old.close()
        try:
            raw = so.create_connection(("127.0.0.1", pw), 3)
            WS(raw, "127.0.0.1", "/mqtt", proto="chat")
            truth("a WebSocket offering only other subprotocols is refused", False, "upgraded")
        except Closed as e:
            truth("a WebSocket offering only other subprotocols is refused", "400" in str(e), e)
        c = Client(pa)
        c.send_raw(b"GET /mqtt HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\r\n")
        truth("an upgrade on the MQTT port itself is no MQTT and closed on", c.closed_within(2))
    guarded("websocket", websocket)


if phase == "reread":
    def reread():
        check("a password changed in the file is taken while running",
              code_of(pa, client_id="r1", username="alice", password="alicenew9"), 0)
        check("and the old one refused", code_of(pa, client_id="r2", username="alice", password="alicepass1"), 0x86)
        al = connected(pa, "alice-r", username="alice", password="alicenew9")
        check("rules changed in the file are taken while running", al.subscribe(("public/#", 1), ("granted/now", 1)),
              [0x87, 1])
        al.disconnect()
    guarded("reread", reread)
PY
}

tally < <(run main)

printf 'alicenew9\n' | "$BIN" mqtt-passwd "$T/users" alice >/dev/null 2>&1
sed -i 's|^topic read public/#|topic read granted/now|' "$T/acl"
sleep 2.5
tally < <(run reread)

st=$("$BIN" stats a 2>&1)
case "$st" in *"auth_refused:"*) ok ;; *) bad "stats count the refused sign-ins" "$st" ;; esac

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
