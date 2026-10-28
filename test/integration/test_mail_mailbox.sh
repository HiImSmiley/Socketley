#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a mail runtime whose users are an idp runtime's keeps their mail in a storage runtime, checks
# what comes from elsewhere by SPF, DKIM and DMARC, and lets its users send with their idp password.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a user of the idp runtime refused as unknown, or an unknown address taken
#   * mail not in the user's mailbox, or there without the lines that say where it came from and what was checked
#   * an Authentication-Results a sender wrote under this host's name kept, as if this host had said it
#   * a DMARC reject taken, a quarantine put in the inbox
#   * a message over a mebibyte stored cut, or not at all
#   * an idp password not taken, a wrong one taken, or a user sending as another's address
#   * an e-mail a user gave themselves at the idp taken as theirs to send from or sign in by, or taking another's
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ready.sh"

command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
command -v curl >/dev/null 2>&1 || { echo "  SKIP: curl is required"; exit 0; }

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate mailbox
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1960))
SUB=$((SL_PORT_BASE+1961))
PI=$((SL_PORT_BASE+1962))
PS=$((SL_PORT_BASE+1963))
SINK=$((SL_PORT_BASE+1964))
NS=$((SL_PORT_BASE+1965))
HOOK=$((SL_PORT_BASE+1966))
PIDS=()
cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: mailboxes of an idp runtime's users in a storage runtime ==="

# else.test may send from 127.0.0.2; evil.test says reject, junk.test quarantine, and neither lets 127.0.0.2 send.
python3 "$HERE/lib_fake_dns.py" "$NS" 0 normal \
    "else.test=TXT:v=spf1 ip4:127.0.0.2 -all" \
    "evil.test=TXT:v=spf1 -all" "_dmarc.evil.test=TXT:v=DMARC1; p=reject" \
    "junk.test=TXT:v=spf1 -all" "_dmarc.junk.test=TXT:v=DMARC1; p=quarantine" \
    remote.test=MX:10:mx.remote.test mx.remote.test=127.0.0.1 >/dev/null 2>&1 &
PIDS+=($!)
printf 'nameserver 127.0.0.1\noptions timeout:1 attempts:1 port:%s\n' "$NS" > "$T/resolv.conf"
export SOCKETLEY_RESOLV_CONF="$T/resolv.conf" SOCKETLEY_MAIL_MX_PORT="$SINK"
mkdir -p "$T/sink"
python3 "$HERE/lib_smtp_sink.py" "$SINK" "$T/sink" >/dev/null 2>&1 &
PIDS+=($!)
ready_tcp 127.0.0.1 "$SINK" || bad "the sink listens" "-"
python3 - "$HOOK" "$T/hook.log" <<'PY' &
import http.server, sys
out = open(sys.argv[2], "a")
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        b = self.rfile.read(int(self.headers.get("content-length", 0)))
        out.write(b.decode(errors="replace").replace("\n", " ") + "\n"); out.flush()
        self.send_response(204); self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
PIDS+=($!)
printf 'hook http://127.0.0.1:%s/mail\n' "$HOOK" > "$T/targets"
daemon_start "$BIN"

openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=mail.example.test" \
    -keyout "$T/key.pem" -out "$T/cert.pem" >/dev/null 2>&1
printf 'spa - http://localhost:5173/cb\n' > "$T/clients"
"$BIN" create idp auth -p "$PI" --clients "$T/clients" --issuer "http://127.0.0.1:$PI" -s >/dev/null 2>&1
"$BIN" create storage st -p "$PS" --dir "$T/data" --anonymous -s >/dev/null 2>&1
for p in "$PI/jwks" "$PS/"; do
    for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p")" != 000 ] && break; sleep 0.1; done
done
"$BIN" idp-user auth add alice --password alicepassword1 --email alice@example.test >/dev/null 2>&1
printf 'team@example.test alice@example.test\n' > "$T/aliases"
"$BIN" create mail m -p "$P" --mail-domain example.test --idp auth --storage st/mail --submission "$SUB" \
    --notify-targets "$T/targets" --aliases "$T/aliases" \
    --tls --cert "$T/cert.pem" --key "$T/key.pem" -s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$P" || bad "the mail runtime listens" "$(tail -3 "$SOCKETLEY_DLOG")"

cat > "$T/smtp.py" <<'PY'
import smtplib, ssl, sys
port, frm, to, path = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
login = sys.argv[5:7]
s = smtplib.SMTP("127.0.0.1", port, source_address=("127.0.0.2", 0), timeout=20)
try:
    s.ehlo("client.else.test")
    if login:
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        s.starttls(context=ctx); s.ehlo("client.else.test")
        s.login(login[0], login[1])
    s.sendmail(frm, [to], open(path, "rb").read())
    print("sent")
except smtplib.SMTPAuthenticationError as e:
    print("auth %d" % e.smtp_code)
except smtplib.SMTPRecipientsRefused as e:
    print("rcpt %d" % list(e.recipients.values())[0][0])
except smtplib.SMTPSenderRefused as e:
    print("sender %d" % e.smtp_code)
except smtplib.SMTPDataError as e:
    print("data %d" % e.smtp_code)
PY
smtp() { python3 "$T/smtp.py" "$@" 2>&1 | tail -1; }
# The keys of a mailbox's folder, waited for until `n` are there.
keys() { curl -s "http://127.0.0.1:$PS/mail?list-type=2&prefix=$1/" | grep -o '<Key>[^<]*</Key>' | sed 's/<Key>//; s/<\/Key>//'; }
wait_keys() { for _ in $(seq 1 100); do [ "$(keys "$1" | wc -l)" -ge "$2" ] && return 0; sleep 0.1; done; return 1; }
obj() { curl -s "http://127.0.0.1:$PS/mail/$1"; }

# ─── its users ──────────────────────────────────────────────────────────────
printf 'From: Carol <carol@else.test>\r\nTo: alice@example.test\r\nSubject: hello alice\r\nAuthentication-Results: mail.example.test; dkim=pass (forged)\r\n\r\nfirst mail\r\n' > "$T/m1"
check "mail for an idp user's address is taken" "$(smtp "$P" carol@else.test alice@example.test "$T/m1")" "sent"
check "mail for an address no user has is refused" "$(smtp "$P" carol@else.test nobody@example.test "$T/m1")" "rcpt 550"
wait_keys alice/INBOX 1 && ok "and it is in the user's inbox in the storage" || bad "and it is in the user's inbox in the storage" "$(keys alice/INBOX)"
k=$(keys alice/INBOX | head -1)
body=$(obj "$k")
case "$body" in *"first mail"*) ok "whole" ;; *) bad "whole" "${body:0:200}" ;; esac
printf '%s' "$body" | grep -q '^Return-Path: <carol@else.test>' && printf '%s' "$body" | grep -q '^Delivered-To: alice@example.test' \
    && ok "under the lines that say whence and to whom" || bad "under the lines that say whence and to whom" "$(printf '%s' "$body" | head -4)"
printf '%s' "$body" | grep -q '^Authentication-Results: mail.example.test; spf=pass smtp.mailfrom=else.test; dkim=none; dmarc=none' \
    && ok "with what SPF, DKIM and DMARC said" || bad "with what SPF, DKIM and DMARC said" "$(printf '%s' "$body" | grep Authentication-Results)"
check "and none forged under this host's name" "$(printf '%s' "$body" | grep -c 'forged')" "0"
for _ in $(seq 1 50); do grep -q 'hello alice' "$T/hook.log" 2>/dev/null && break; sleep 0.1; done
grep -q '"event":"mail.received".*"mailbox":"alice","folder":"INBOX".*"subject":"hello alice"' "$T/hook.log" 2>/dev/null \
    && ok "and a webhook of --notify-targets is told of it" || bad "and a webhook of --notify-targets is told of it" "$(cat "$T/hook.log" 2>&1)"

# ─── DMARC ──────────────────────────────────────────────────────────────────
printf 'From: boss@evil.test\r\nTo: alice@example.test\r\nSubject: wire money\r\n\r\nplease\r\n' > "$T/m2"
check "mail whose From domain says reject, failing it, is refused" "$(smtp "$P" boss@evil.test alice@example.test "$T/m2")" "data 550"
printf 'From: promo@junk.test\r\nTo: alice@example.test\r\nSubject: offer\r\n\r\nbuy\r\n' > "$T/m3"
check "mail whose From domain says quarantine is taken" "$(smtp "$P" promo@junk.test alice@example.test "$T/m3")" "sent"
wait_keys alice/Junk 1 && ok "into the Junk folder" || bad "into the Junk folder" "$(keys alice)"
check "and the inbox has only the first" "$(keys alice/INBOX | wc -l)" "1"

# ─── a large one ────────────────────────────────────────────────────────────
python3 - "$T/m4" <<'PY'
import sys
lines = "".join("line %07d %s\r\n" % (i, "x" * 60) for i in range(40000))
open(sys.argv[1], "w").write("From: carol@else.test\r\nTo: alice@example.test\r\nSubject: big\r\n\r\n" + lines + "the end\r\n")
PY
check "a message of three mebibytes is taken" "$(smtp "$P" carol@else.test alice@example.test "$T/m4")" "sent"
wait_keys alice/INBOX 2 || true
# Its head alone, read as a range: a grep that stops reading would leave curl a SIGPIPE pipefail counts.
big=$(for k in $(keys alice/INBOX); do curl -s -r 0-4095 "http://127.0.0.1:$PS/mail/$k" | grep -c 'Subject: big' >/dev/null && echo "$k"; done | head -1)
got=$(obj "$big" | tail -c 9 | od -An -tx1 | tr -d ' \n')
size=$(obj "$big" | wc -c)
[ -n "$big" ] && [ "$got" = "74686520656e640d0a" ] && [ "$size" -gt 3000000 ] && ok "and stored whole, in pieces" \
    || bad "and stored whole, in pieces" "key '$big' size $size tail '$got'"

# ─── its users send ─────────────────────────────────────────────────────────
printf 'From: alice@example.test\r\nTo: dan@remote.test\r\nSubject: from alice\r\n\r\nalice sends\r\n' > "$T/m5"
check "an idp user signs in with their password and sends" "$(smtp "$SUB" alice@example.test dan@remote.test "$T/m5" alice alicepassword1)" "sent"
for _ in $(seq 1 100); do grep -l "alice sends" "$T"/sink/*.eml >/dev/null 2>&1 && break; sleep 0.1; done
grep -l "alice sends" "$T"/sink/*.eml >/dev/null 2>&1 && ok "which is delivered" || bad "which is delivered" "nothing at the sink"
check "a wrong idp password is refused" "$(smtp "$SUB" alice@example.test dan@remote.test "$T/m5" alice wrong)" "auth 535"
check "a user may not send as another's address" "$(smtp "$SUB" mallory@example.test dan@remote.test "$T/m5" alice alicepassword1)" "sender 553"
check "nor as an address elsewhere" "$(smtp "$SUB" alice@other.test dan@remote.test "$T/m5" alice alicepassword1)" "sender 553"

# ─── an address a user gave themselves at the idp ───────────────────────────
for u in bob carl ceo; do "$BIN" idp-user auth add "$u" --password "${u}password123" >/dev/null 2>&1; done
# A user signs in at the idp and sets their own e-mail there; the status of the save.
self_email() {
    python3 - "$PI" "$1" "$2" <<'PY' 2>&1 | tail -1
import sys, urllib.request, urllib.parse, urllib.error
I = "http://127.0.0.1:%s" % sys.argv[1]
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None
op = urllib.request.build_opener(NoRedirect)
def post(path, form, cookie=None):
    r = urllib.request.Request(I + path, data=urllib.parse.urlencode(form).encode(), method="POST",
                               headers={"Cookie": cookie} if cookie else {})
    try:
        with op.open(r) as resp:
            return resp.status, resp.headers
    except urllib.error.HTTPError as e:
        return e.code, e.headers
_, h = post("/login", dict(rd="/", username=sys.argv[2], password=sys.argv[2] + "password123"))
print(post("/account", dict(name=sys.argv[2], email=sys.argv[3]), (h.get("Set-Cookie") or "").split(";")[0])[0])
PY
}
# A message from `$1`, so its header says the sender the envelope does.
msg_from() { printf 'From: %s\r\nTo: dan@remote.test\r\nSubject: from %s\r\n\r\nhello\r\n' "$1" "$1" > "$T/from-$1"; echo "$T/from-$1"; }
check "a user may not give themselves another account's address" "$(self_email bob alice@example.test)" "400"
check "nor one a username here would have in a domain an admin gave an address in" "$(self_email carl ceo@example.test)" "400"
check "but may give themselves one no account has" "$(self_email bob boss@example.test)" "200"
check "which they may not send from" "$(smtp "$SUB" boss@example.test dan@remote.test "$(msg_from boss@example.test)" bob bobpassword123)" "sender 553"
check "nor sign in by" "$(smtp "$SUB" bob@example.test dan@remote.test "$(msg_from bob@example.test)" boss@example.test bobpassword123)" "auth 535"
check "the account an address names signs in by it" \
    "$(smtp "$SUB" ceo@example.test dan@remote.test "$(msg_from ceo@example.test)" ceo@example.test ceopassword123)" "sent"
check "and a user still sends from their own" "$(smtp "$SUB" bob@example.test dan@remote.test "$(msg_from bob@example.test)" bob bobpassword123)" "sent"
"$BIN" idp-user auth set bob email=robert@example.test >/dev/null 2>&1
check "and from one an admin gave them" \
    "$(smtp "$SUB" robert@example.test dan@remote.test "$(msg_from robert@example.test)" bob bobpassword123)" "sent"

for k in mail_stored mail_checked mail_dmarc_rejected mail_quarantined; do
    v=""
    for _ in $(seq 1 30); do v=$("$BIN" stats m 2>/dev/null | sed -n "s/^$k://p"); [ "${v:-0}" -ge 1 ] && break; sleep 0.2; done
    [ "${v:-0}" -ge 1 ] && ok "stats count $k" || bad "stats count $k" "${v:-absent}"
done

# ─── what a sender may not say for this host ────────────────────────────────
n0=$(keys alice/INBOX | wc -l)
printf 'Return-Path: <forged@evil.test>\r\nAuthentication-Results: (a comment) mail.example.test; dkim=pass header.d=forged.test\r\nAuthentication-Results: "mail.example.test"; spf=pass smtp.mailfrom=forged.test\r\nFrom: carol@else.test\r\nSubject: forged results\r\n\r\nforged\r\n' > "$T/m7"
check "a message with results forged under this host's name is taken" "$(smtp "$P" carol@else.test alice@example.test "$T/m7")" "sent"
wait_keys alice/INBOX $((n0 + 1))
k=$(for x in $(keys alice/INBOX); do obj "$x" | grep -q 'forged results' && echo "$x"; done | head -1)
body=$(obj "$k" | tr -d '\r')
check "and keeps none of them, behind a comment or in quotes" "$(printf '%s\n' "$body" | grep -c 'forged.test')" "0"
check "nor the sender's Return-Path beside its own" "$(printf '%s\n' "$body" | grep -c '^Return-Path:')" "1"

# ─── an alias of a user here ────────────────────────────────────────────────
n0=$(keys alice/INBOX | wc -l)
printf 'From: carol@else.test\r\nTo: team@example.test\r\nSubject: to the team\r\n\r\nfor the team\r\n' > "$T/m6"
check "mail for an alias of a user here is taken" "$(smtp "$P" carol@else.test team@example.test "$T/m6")" "sent"
wait_keys alice/INBOX $((n0 + 1)) && ok "and filed in that user's mailbox, not sent out" \
    || bad "and filed in that user's mailbox, not sent out" "$(keys alice/INBOX) $(ls "$T/sink")"
k=$(for x in $(keys alice/INBOX); do obj "$x" | grep -q 'for the team' && echo "$x"; done | head -1)
check "under the address it came for" "$(obj "$k" | tr -d '\r' | sed -n 's/^Delivered-To: //p' | head -1)" "alice@example.test"

# ─── the idp runtime away ───────────────────────────────────────────────────
"$BIN" stop auth >/dev/null 2>&1
check "with the idp runtime stopped, a recipient it would decide is answered 451" \
    "$(smtp "$P" carol@else.test someone@example.test "$T/m1")" "rcpt 451"
check "and a password it would check 454" "$(smtp "$SUB" alice@example.test dan@remote.test "$T/m5" alice alicepassword1)" \
    "auth 454"
"$BIN" start auth >/dev/null 2>&1

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
