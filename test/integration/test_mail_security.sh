#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a mail runtime's defences -- an account a spray of guesses from many addresses aims at refused to
# all but the addresses it signs in from, kept across a restart; each sign-in logged; OAuth's XOAUTH2 and OAUTHBEARER
# with the idp's tokens; attachments that run refused; and what clamd finds refused.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * guesses spread over addresses never refusing the account, or refusing the owner's own device with it
#   * the refusal forgotten by a restart
#   * a sign-in not in the log
#   * a token the idp gave refused over SMTP or IMAP, or a forged one taken
#   * an .exe or a macro document taken, an ordinary attachment refused, or a virus clamd names taken
#   * an app password not signing a mail app in, or one removed still doing so; with the second step on, the password
#     alone signing a mail app in, or the web sign-in not asking the code, taking a wrong one, or taking one twice
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ready.sh"

command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
command -v openssl >/dev/null 2>&1 || { echo "  SKIP: openssl is required"; exit 0; }

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

daemon_isolate mail_security
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1930)); SUB=$((P+1)); IM=$((P+2)); PI=$((P+3)); PS=$((P+4)); NS=$((P+5)); CLAM=$((P+6))
PIDS=()
trap 'for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; daemon_stop' EXIT

echo "=== Integration: a mail runtime's defences ==="

python3 "$HERE/lib_fake_dns.py" "$NS" 0 normal >/dev/null 2>&1 &
PIDS+=($!)
printf 'nameserver 127.0.0.1\noptions timeout:1 attempts:1 port:%s\n' "$NS" > "$T/resolv.conf"
export SOCKETLEY_RESOLV_CONF="$T/resolv.conf"
# A clamd that finds the EICAR test string, and nothing in the rest.
python3 - "$CLAM" <<'PY' &
import socket, struct, sys, threading
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", int(sys.argv[1]))); srv.listen(8)
def serve(c):
    data = b""
    while not data.startswith(b"zINSTREAM\0") or len(data) < 10:
        b = c.recv(4096)
        if not b: return
        data += b
    rest, body = data[10:], b""
    while True:
        while len(rest) < 4:
            rest += c.recv(65536)
        n = struct.unpack(">I", rest[:4])[0]; rest = rest[4:]
        if n == 0: break
        while len(rest) < n:
            rest += c.recv(65536)
        body += rest[:n]; rest = rest[n:]
    c.sendall(b"stream: Eicar-Test-Signature FOUND\0" if b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in body else b"stream: OK\0")
    c.close()
while True:
    c, _ = srv.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PY
PIDS+=($!)
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=mail.example.test" -keyout "$T/key.pem" -out "$T/cert.pem" >/dev/null 2>&1
daemon_start "$BIN"
printf 'spa - http://localhost:5173/cb\n' > "$T/clients"
"$BIN" create idp auth -p "$PI" --clients "$T/clients" --issuer "http://127.0.0.1:$PI" -s >/dev/null 2>&1
"$BIN" create storage st -p "$PS" --dir "$T/data" --anonymous -s >/dev/null 2>&1
for p in "$PI/jwks" "$PS/"; do
    for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p")" != 000 ] && break; sleep 0.1; done
done
"$BIN" idp-user auth add alice --password alicepassword1 --email alice@example.test >/dev/null 2>&1
"$BIN" create mail m -p "$P" --mail-domain example.test --idp auth --idp-audience spa --storage st/mail --submission "$SUB" --imap "$IM" \
    --tls --cert "$T/cert.pem" --key "$T/key.pem" --clamav "127.0.0.1:$CLAM" -s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$IM" || bad "the IMAP port listens" "$(tail -3 "$SOCKETLEY_DLOG")"

cat > "$T/imap.py" <<'PY'
import imaplib, ssl, sys
port, src, user, secret = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
mech = sys.argv[5] if len(sys.argv) > 5 else "LOGIN"
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
class M(imaplib.IMAP4):
    def _create_socket(self, timeout):
        import socket
        return socket.create_connection((self.host, self.port), timeout, source_address=(src, 0))
try:
    m = M("127.0.0.1", port); m.starttls(ssl_context=ctx)
    if mech == "LOGIN":
        m.login(user, secret)
    else:
        if mech == "XOAUTH2":
            blob = "user=%s\x01auth=Bearer %s\x01\x01" % (user, secret)
        else:
            blob = "n,a=%s,\x01auth=Bearer %s\x01\x01" % (user, secret)
        m.authenticate(mech, lambda _: blob.encode())
    print("ok")
except imaplib.IMAP4.error as e:
    print("refused: %s" % e)
PY
imap() { python3 "$T/imap.py" "$IM" "$@" 2>&1 | tail -1; }

# ─── sign-ins ───────────────────────────────────────────────────────────────
[ "$(imap 127.0.0.5 alice alicepassword1)" = ok ] && ok "alice signs in from her own device" || bad "alice signs in" "$(imap 127.0.0.5 alice alicepassword1)"
grep -q "alice signed in over IMAP from 127.0.0.5" "$SOCKETLEY_DLOG" && ok "and the sign-in is logged, with its address" \
    || bad "the sign-in is logged" "$(grep -c 'signed in' "$SOCKETLEY_DLOG")"
# Seven wrong guesses from each of three addresses: none of them is refused by its own count, the account is.
for src in 127.0.0.2 127.0.0.3 127.0.0.4; do
    for _ in $(seq 1 7); do imap "$src" alice wrong-guess >/dev/null; done
done
case "$(imap 127.0.0.6 alice alicepassword1)" in refused*) ok "guesses at an account from three addresses refuse it to a new one, its password right" ;;
    *) bad "an account sprayed at is refused to a new address" "$(imap 127.0.0.6 alice alicepassword1)" ;; esac
[ "$(imap 127.0.0.5 alice alicepassword1)" = ok ] && ok "and not to the address it signs in from" || bad "its own address" "$(imap 127.0.0.5 alice alicepassword1)"
grep -q "alice was failed at" "$SOCKETLEY_DLOG" && ok "which the log says" || bad "the log says" "-"
"$BIN" restart m >/dev/null 2>&1
ready_tcp 127.0.0.1 "$IM" >/dev/null 2>&1
case "$(imap 127.0.0.6 alice alicepassword1)" in refused*) ok "and the refusal outlasts a restart" ;;
    *) bad "the refusal outlasts a restart" "$(imap 127.0.0.6 alice alicepassword1)" ;; esac

# ─── OAuth ──────────────────────────────────────────────────────────────────
tok=$(python3 - "$PI" <<'PY'
import base64, hashlib, json, os, sys, urllib.parse, urllib.request
I = "http://127.0.0.1:" + sys.argv[1]
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None
op = urllib.request.build_opener(NoRedirect)
def post(path, form):
    r = urllib.request.Request(I + path, data=urllib.parse.urlencode(form).encode(), method="POST",
                               headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with op.open(r) as resp: return resp.status, resp.read().decode(), resp.headers
    except urllib.error.HTTPError as e: return e.code, e.read().decode(), e.headers
v = base64.urlsafe_b64encode(os.urandom(40)).rstrip(b"=").decode()
ch = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()
cb = "http://localhost:5173/cb"
st, _, h = post("/authorize", dict(client_id="spa", redirect_uri=cb, response_type="code", scope="openid", state="s",
                code_challenge=ch, code_challenge_method="S256", username="alice", password="alicepassword1"))
code = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(h.get("Location", "")).query)).get("code")
st, body, _ = post("/token", dict(grant_type="authorization_code", code=code, redirect_uri=cb, client_id="spa", code_verifier=v))
print(json.loads(body).get("access_token", "") if st == 200 else "")
PY
)
[ -n "$tok" ] || bad "the idp gives a token" "-"
[ "$(imap 127.0.0.5 alice "$tok" XOAUTH2)" = ok ] && ok "IMAP takes the idp's token by XOAUTH2" || bad "IMAP XOAUTH2" "$(imap 127.0.0.5 alice "$tok" XOAUTH2)"
[ "$(imap 127.0.0.5 alice "$tok" OAUTHBEARER)" = ok ] && ok "and by OAUTHBEARER" || bad "IMAP OAUTHBEARER" "$(imap 127.0.0.5 alice "$tok" OAUTHBEARER)"
case "$(imap 127.0.0.5 alice "${tok}x" XOAUTH2)" in refused*) ok "and refuses a token the idp did not give" ;;
    *) bad "a forged token" "$(imap 127.0.0.5 alice "${tok}x" XOAUTH2)" ;; esac
smtp_oauth=$(python3 - "$SUB" "$tok" <<'PY'
import base64, smtplib, ssl, sys
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
s = smtplib.SMTP("127.0.0.1", int(sys.argv[1]), source_address=("127.0.0.5", 0)); s.ehlo("x"); s.starttls(context=ctx); s.ehlo("x")
blob = base64.b64encode(("user=alice\x01auth=Bearer %s\x01\x01" % sys.argv[2]).encode()).decode()
print(s.esmtp_features.get("auth", ""), "|", s.docmd("AUTH", "XOAUTH2 " + blob)[0])
PY
)
case "$smtp_oauth" in *"XOAUTH2 OAUTHBEARER"*"| 235") ok "submission offers XOAUTH2 and OAUTHBEARER, and takes the token" ;;
    *) bad "SMTP XOAUTH2" "$smtp_oauth" ;; esac

# ─── app passwords and a second step ────────────────────────────────────────
app=$("$BIN" idp-user auth app-password alice add phone 2>&1)
case "$app" in [a-z][a-z][a-z][a-z]-[a-z][a-z][a-z][a-z]-[a-z][a-z][a-z][a-z]-[a-z][a-z][a-z][a-z]) ok "an app password is made and shown once" ;;
    *) bad "an app password" "$app" ;; esac
[ "$(imap 127.0.0.5 alice "$app")" = ok ] && ok "and a mail app signs in with it" || bad "IMAP with the app password" "$(imap 127.0.0.5 alice "$app")"
[ "$("$BIN" idp-user auth app-password alice list 2>&1)" = phone ] && ok "the list names it, not its password" || bad "the list" "$("$BIN" idp-user auth app-password alice list 2>&1)"
key=$("$BIN" idp-user auth totp alice on 2>&1 | sed -n 's/^key: //p')
[ -n "$key" ] && ok "a second step is turned on, its key given" || bad "totp on" "-"
case "$(imap 127.0.0.5 alice alicepassword1)" in refused*) ok "with it on, the password alone signs no mail app in" ;;
    *) bad "the password alone with totp" "$(imap 127.0.0.5 alice alicepassword1)" ;; esac
[ "$(imap 127.0.0.5 alice "$app")" = ok ] && ok "an app password still does" || bad "the app password with totp" "$(imap 127.0.0.5 alice "$app")"
web=$(python3 - "$PI" "$key" <<'PY'
import base64, hashlib, hmac, re, struct, sys, time, urllib.parse, urllib.request
I, key = "http://127.0.0.1:" + sys.argv[1], sys.argv[2]
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None
op = urllib.request.build_opener(NoRedirect)
def post(form):
    r = urllib.request.Request(I + "/login", data=urllib.parse.urlencode(form).encode(), method="POST",
                               headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with op.open(r) as resp: return resp.status, resp.read().decode(), resp.headers
    except urllib.error.HTTPError as e: return e.code, e.read().decode(), e.headers
def code(k, step):
    d = hmac.new(base64.b32decode(k + "=" * (-len(k) % 8)), struct.pack(">Q", step), hashlib.sha1).digest()
    o = d[-1] & 15
    return "%06d" % ((struct.unpack(">I", d[o:o + 4])[0] & 0x7fffffff) % 1000000)
st, body, h = post({"username": "alice", "password": "alicepassword1", "rd": "/account"})
m = re.search(r'name="pending" value="([0-9a-f]+)"', body)
if not m or "set-cookie" in {k.lower() for k in h.keys()}:
    print("no code asked", st); sys.exit()
st2, body2, h2 = post({"pending": m.group(1), "code": "000000" if code(key, int(time.time()) // 30) != "000000" else "111111"})
st3, _, h3 = post({"pending": m.group(1), "code": code(key, int(time.time()) // 30)})
st4, _, _ = post({"pending": m.group(1), "code": code(key, int(time.time()) // 30)})
print(st, st2, st3, "cookie" if "skl_idp" in (h3.get("Set-Cookie") or "") else "no-cookie", st4)
PY
)
case "$web" in "200 401 302 cookie 401") ok "the web sign-in asks the code after the password, refuses a wrong one, signs in with the right one, once" ;;
    *) bad "the web second step" "$web" ;; esac
"$BIN" idp-user auth app-password alice remove phone >/dev/null 2>&1
case "$(imap 127.0.0.5 alice "$app")" in refused*) ok "an app password removed signs nothing in" ;; *) bad "a removed app password" "$(imap 127.0.0.5 alice "$app")" ;; esac
"$BIN" idp-user auth totp alice off >/dev/null 2>&1
[ "$(imap 127.0.0.5 alice alicepassword1)" = ok ] && ok "with the second step off, the password signs in again" || bad "totp off" "$(imap 127.0.0.5 alice alicepassword1)"

# ─── what a message carries ─────────────────────────────────────────────────
send() { # send <attachment name> <content>
    python3 - "$P" "$1" "$2" <<'PY'
import smtplib, sys
name, content = sys.argv[2], sys.argv[3]
msg = ("From: x@else.test\r\nTo: alice@example.test\r\nSubject: s\r\nMIME-Version: 1.0\r\n"
       "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n"
       "--b\r\nContent-Type: application/octet-stream; name=\"%s\"\r\nContent-Disposition: attachment; filename=\"%s\"\r\n\r\n%s\r\n--b--\r\n"
       % (name, name, content))
s = smtplib.SMTP("127.0.0.1", int(sys.argv[1]), source_address=("127.0.0.2", 0)); s.ehlo("x")
try:
    s.sendmail("x@else.test", ["alice@example.test"], msg); print(250)
except smtplib.SMTPDataError as e:
    print(e.smtp_code, e.smtp_error.decode())
PY
}
case "$(send setup.exe MZ-not-really)" in "554 5.7.1 Message refused: attachments such as setup.exe are not taken") ok "an .exe attachment is refused" ;;
    *) bad "an .exe" "$(send setup.exe MZ-not-really)" ;; esac
case "$(send invoice.docm macros)" in 554*) ok "and a document with macros" ;; *) bad "a .docm" "$(send invoice.docm macros)" ;; esac
[ "$(send report.pdf %PDF-1.4)" = 250 ] && ok "an ordinary attachment is taken" || bad "a .pdf" "$(send report.pdf %PDF-1.4)"
case "$(send eicar.txt 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')" in *"554 5.7.1 Message refused: it carries Eicar-Test-Signature"*) \
    ok "what clamd finds is refused, by its name" ;; *) bad "the virus" "$(send eicar.txt 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE')" ;; esac

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
