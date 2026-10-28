#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a mail runtime takes mail for its domains and from its users, keeps it in its spool and hands it
# on by SMTP, signed, tried again and bounced as it should be.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
# A mail server is judged by the mail it takes that it should not, and the mail it loses:
#   * mail for an alias not handed to the alias's domain's exchanger, or handed on without a Received line
#   * a stranger let relay through it, or mail taken for a user that does not exist
#   * a message submitted without a Date or Message-ID sent on without them
#   * send of "-1" to a server taken as mail flags, a message past the channel's bound lost, a colon path misread
#   * --sieve without its idp and storage, or a --hostname that is no name, taken as it is made
#   * show printing a smarthost's password, or an import of it losing it
#   * a rename by import leaving the spool and keys under the old name, or renaming a running one
#   * STARTTLS that leaves the session in the clear, or a submission port that takes mail unsigned in, or a password
#     tried as fast as a script can guess
#   * `socketley send` and socketley.mail.send not queuing, or sending unsigned from a domain with a key
#   * a recipient refused for good not bounced to its sender, one refused for now not tried again
#   * a queued message lost by a restart
#   * the end of a message read where another server would not see one (SMTP smuggling), or a message past the size
#   * mail taken from an address a --dnsbl list names, or refused from one it does not, or for its error answer
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
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate mail
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1980))
SUB=$((SL_PORT_BASE+1981))
SINK=$((SL_PORT_BASE+1982))
NS=$((SL_PORT_BASE+1983))
PIDS=()
cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a mail runtime takes, keeps, signs, sends, retries and bounces mail ==="

python3 "$HERE/lib_fake_dns.py" "$NS" 0 normal remote.test=MX:10:mx.remote.test mx.remote.test=127.0.0.1 \
    2.0.0.127.bl.test=127.0.0.2 4.0.0.127.bl.test=127.255.255.254 listed-host.test=127.0.0.2 \
    2.0.0.127.in-addr.arpa=PTR:other-host.test named-host.test=127.0.0.3 3.0.0.127.in-addr.arpa=PTR:named-host.test \
    >/dev/null 2>&1 &
PIDS+=($!)
printf 'nameserver 127.0.0.1\noptions timeout:1 attempts:1 port:%s\n' "$NS" > "$T/resolv.conf"
export SOCKETLEY_RESOLV_CONF="$T/resolv.conf" SOCKETLEY_MAIL_MX_PORT="$SINK"
mkdir -p "$T/sink"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=mail.example.test" \
    -keyout "$T/key.pem" -out "$T/cert.pem" >/dev/null 2>&1
python3 "$HERE/lib_smtp_sink.py" "$SINK" "$T/sink" --tls "$T/cert.pem" "$T/key.pem" \
    --reply bad@remote.test 550 --reply later@remote.test '451!' >/dev/null 2>&1 &
PIDS+=($!)
printf 'alicepass1\n' | "$BIN" mqtt-passwd "$T/users" alice >/dev/null 2>&1
# A users file is the CLI's to write, and asks for no daemon: one started here would hold this test's socket.
[ -s "$T/users" ] && [ ! -S "$SOCKETLEY_SOCKET" ] && ok "mqtt-passwd writes the users file and starts no daemon" \
    || bad "mqtt-passwd writes the users file and starts no daemon" "socket $(ls -la "$SOCKETLEY_SOCKET" 2>&1)"
printf 'info@example.test bob@remote.test\n' > "$T/aliases"
ready_tcp 127.0.0.1 "$SINK" || bad "the sink listens" "-"
daemon_start "$BIN"

# A message at the sink whose file holds `pat`, waited for; the file's name, or nothing.
mail_with() {
    for _ in $(seq 1 100); do
        f=$(grep -l -- "$1" "$T"/sink/*.eml 2>/dev/null | head -1)
        [ -n "$f" ] && { echo "$f"; return 0; }
        sleep 0.1
    done
    return 1
}
# An SMTP conversation from 127.0.0.2, a stranger to the runtime: smtp.py <port> <from> <to> <body> [starttls] [user pw]
cat > "$T/smtp.py" <<'PY'
import smtplib, ssl, sys, time
port, frm, to, body = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
opts = sys.argv[5:]
s = smtplib.SMTP("127.0.0.1", port, source_address=("127.0.0.2", 0), timeout=10)
try:
    s.ehlo("client.test")
    if "starttls" in opts:
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        s.starttls(context=ctx); s.ehlo("client.test")
    if "login" in opts:
        i = opts.index("login")
        t0 = time.time()
        try:
            s.login(opts[i + 1], opts[i + 2])
        except smtplib.SMTPAuthenticationError as e:
            print("auth %d %.1f" % (e.smtp_code, time.time() - t0)); sys.exit(0)
    s.sendmail(frm, [to], body)
    print("sent")
except smtplib.SMTPRecipientsRefused as e:
    print("rcpt %d" % list(e.recipients.values())[0][0])
except smtplib.SMTPSenderRefused as e:
    print("sender %d" % e.smtp_code)
except smtplib.SMTPResponseException as e:
    print("refused %d" % e.smtp_code)
PY
smtp() { python3 "$T/smtp.py" "$@" 2>&1 | tail -1; }

# ─── its settings ───────────────────────────────────────────────────────────
out=$("$BIN" create mail nodomain -p $((SL_PORT_BASE+1984)) 2>&1)
"$BIN" start nodomain >/dev/null 2>&1
st=$("$BIN" ls 2>/dev/null | awk '$2=="nodomain"{print $7}')
case "$out$("$BIN" start nodomain 2>&1)" in
    *"say whose mail this is"*) ok "a mail runtime that names no domain says what it needs" ;;
    *) bad "a mail runtime that names no domain says what it needs" "$out" ;;
esac
"$BIN" remove nodomain >/dev/null 2>&1

"$BIN" create mail m -p "$P" --mail-domain example.test --aliases "$T/aliases" --tls --cert "$T/cert.pem" \
    --key "$T/key.pem" --submission "$SUB" --users "$T/users" -s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$P" || bad "the mail runtime listens" "$(tail -3 "$SOCKETLEY_DLOG")"

# ─── mail for its domains ───────────────────────────────────────────────────
check "a stranger's mail to an alias is taken" "$(smtp "$P" carol@else.test info@example.test 'Subject: one

alias body')" "sent"
f=$(mail_with "alias body") && ok "and handed to the alias's domain's exchanger" || bad "and handed to the alias's domain's exchanger" "nothing at the sink"
[ -n "$f" ] && grep -q '^rcpt bob@remote.test' "$f" && ok "for the alias's address" || bad "for the alias's address" "$(head -3 "$f" 2>/dev/null)"
[ -n "$f" ] && grep -q 'by mail.example.test (socketley) with ESMTP id' "$f" && ok "under a Received line of its own" \
    || bad "under a Received line of its own" "$(grep -m2 Received "$f" 2>/dev/null)"
check "a stranger may not relay through it" "$(smtp "$P" carol@else.test dave@other.test 'Subject: x

x')" "rcpt 554"
check "mail for a user that does not exist is refused" "$(smtp "$P" carol@else.test nobody@example.test 'Subject: x

x')" "rcpt 550"
check "STARTTLS takes mail inside TLS" "$(smtp "$P" carol@else.test info@example.test 'Subject: tls

over tls' starttls)" "sent"
f=$(mail_with "over tls")
[ -n "$f" ] && grep -q 'with ESMTPS id' "$f" && ok "and says so in its Received line" || bad "and says so in its Received line" "$(grep -m2 Received "$f" 2>/dev/null)"

# ─── its users ──────────────────────────────────────────────────────────────
check "a submission port takes nothing in the clear from a stranger" "$(smtp "$SUB" alice@example.test carol@remote.test 'x')" "sender 530"
check "a user signed in sends to another domain" "$(smtp "$SUB" alice@example.test carol@remote.test 'Subject: sub

from alice' starttls login alice alicepass1)" "sent"
f=$(mail_with "from alice") && ok "which is delivered there" || bad "which is delivered there" "nothing at the sink"
[ -n "$f" ] && grep -q '^Date: ' "$f" && grep -q '^Message-ID: <.*@mail.example.test>' "$f" \
    && ok "given the Date and Message-ID it was submitted without" \
    || bad "given the Date and Message-ID it was submitted without" "$(head -12 "$f" 2>/dev/null)"
f=$(mail_with "alias body")
[ -n "$f" ] && ! grep -q '^Message-ID: ' "$f" && ok "while a stranger's message is passed on as it came" \
    || bad "while a stranger's message is passed on as it came" "$(head -12 "$f" 2>/dev/null)"
r=$(smtp "$SUB" alice@example.test carol@remote.test 'x' starttls login alice wrongpass)
case "$r" in
    "auth 535 "1.*|"auth 535 "2.*) ok "a wrong password is refused a second later" ;;
    *) bad "a wrong password is refused a second later" "$r" ;;
esac
check "a user of --users may not send as another's address" \
    "$(smtp "$SUB" bob@example.test carol@remote.test 'x' starttls login alice alicepass1)" "sender 553"
check "nor under a From header of another" "$(smtp "$SUB" alice@example.test carol@remote.test 'From: ceo@example.test
Subject: forged

the ceo says' starttls login alice alicepass1)" "refused 553"
check "nor under a second From of another, written with a space before its colon" \
    "$(smtp "$SUB" alice@example.test carol@remote.test 'From: alice@example.test
From : ceo@example.test
Subject: forged

the ceo says too' starttls login alice alicepass1)" "refused 553"
check "nor under one From of another written so" "$(smtp "$SUB" alice@example.test carol@remote.test 'From : ceo@example.test
Subject: forged

the ceo says once more' starttls login alice alicepass1)" "refused 553"
long_head=$(python3 -c 'print("\n".join("X-Pad-%d: %s" % (i, "a" * 76) for i in range(900)))')
check "nor under a From of another past 64 KiB of header" "$(smtp "$SUB" alice@example.test carol@remote.test "$long_head
From: ceo@example.test
Subject: forged

the ceo says late" starttls login alice alicepass1)" "refused 552"
check "while a long body under a short header is still taken" "$(smtp "$SUB" alice@example.test carol@remote.test "Subject: long

$long_head" starttls login alice alicepass1)" "sent"

# ─── socketley send ─────────────────────────────────────────────────────────
id=$("$BIN" send m --from alice@example.test --to dave@remote.test --subject "Hello from the CLI" --text "cli body" 2>&1)
case "$id" in queued\ *) ok "socketley send queues a message" ;; *) bad "socketley send queues a message" "$id" ;; esac
f=$(mail_with "cli body")
[ -n "$f" ] && grep -q '^DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.test; s=skl;' "$f" \
    && ok "and it arrives signed for its domain" || bad "and it arrives signed for its domain" "$(head -12 "$f" 2>/dev/null)"
r=$("$BIN" send m --subject x 2>&1); rc=$?
check "a message with no recipient is refused, and said why" "$rc ${r%%:*}" "1 send to a mail runtime needs a recipient"

# ─── what the other side refuses ────────────────────────────────────────────
"$BIN" send m --from erin@remote.test --to bad@remote.test --subject "will bounce" --text "bounced body" >/dev/null 2>&1
f=$(mail_with "Undelivered Mail Returned to Sender")
[ -n "$f" ] && grep -q '^rcpt erin@remote.test' "$f" && grep -q 'Final-Recipient: rfc822; bad@remote.test' "$f" \
    && ok "a recipient refused for good is bounced to the sender, with a delivery status" \
    || bad "a recipient refused for good is bounced to the sender, with a delivery status" "$(head -5 "$f" 2>/dev/null)"
[ -n "$f" ] && grep -q '^from $' "$f" && ok "from the null sender" || bad "from the null sender" "$(head -2 "$f" 2>/dev/null)"
id=$("$BIN" send m --from erin@remote.test --to later@remote.test --subject "later" --text "later body" 2>&1 | sed -n 's/^queued //p')
for _ in $(seq 1 50); do "$BIN" mail m show "$id" 2>/dev/null | grep -q '451' && break; sleep 0.1; done
"$BIN" mail m show "$id" 2>/dev/null | grep -q 'rcpt: later@remote.test	waiting	451' \
    && ok "a recipient refused for now waits, its answer kept" || bad "a recipient refused for now waits, its answer kept" "$("$BIN" mail m show "$id" 2>&1)"
"$BIN" mail m flush >/dev/null 2>&1
mail_with "later body" >/dev/null && ok "and a flush delivers it" || bad "and a flush delivers it" "$("$BIN" mail m show "$id" 2>&1)"
for _ in $(seq 1 50); do [ -z "$("$BIN" mail m queue 2>/dev/null)" ] && break; sleep 0.1; done
check "and the queue is empty after" "$("$BIN" mail m queue 2>/dev/null)" ""

# ─── its own script ─────────────────────────────────────────────────────────
cat > "$T/hooks.lua" <<'LUA'
function on_rcpt(r, default)
    if r.to == "hook@example.test" then return true end
    if r.to == "blocked@example.test" then return false end
    return nil
end
function on_message(m)
    socketley.mail.send("ml", {from = "alice@example.test", to = {"watch@remote.test"},
                               subject = "seen " .. m.id, text = "to " .. m.to[1] .. ": " .. (m.subject or "")})
end
LUA
printf 'blocked@example.test bob@remote.test\n' > "$T/aliases2"
"$BIN" create mail ml -p $((SL_PORT_BASE+1986)) --mail-domain example.test --aliases "$T/aliases2" --lua "$T/hooks.lua" -s >/dev/null 2>&1
ready_tcp 127.0.0.1 $((SL_PORT_BASE+1986)) || bad "the scripted runtime listens" "$(tail -3 "$SOCKETLEY_DLOG")"
check "on_rcpt takes an address no mailbox has" "$(smtp $((SL_PORT_BASE+1986)) carol@else.test hook@example.test 'Subject: for the script

x')" "sent"
f=$(mail_with "to hook@example.test: for the script")
[ -n "$f" ] && ok "and on_message is told of it, and may send on" || bad "and on_message is told of it, and may send on" "nothing at the sink"
check "on_rcpt refuses one an alias would take" "$(smtp $((SL_PORT_BASE+1986)) carol@else.test blocked@example.test 'Subject: x

x')" "rcpt 550"
check "and keeps the default where it says nothing" "$(smtp $((SL_PORT_BASE+1986)) carol@else.test nobody@example.test 'Subject: x

x')" "rcpt 550"

# ─── what it counted, before a restart sets it to nothing ─────────────────────────────────────────────────────────
s=$("$BIN" stats m 2>/dev/null)
for k in mail_received mail_delivered mail_bounced mail_refused_relay auth_failed starttls; do
    v=$(printf '%s\n' "$s" | sed -n "s/^$k://p")
    [ "${v:-0}" -ge 1 ] 2>/dev/null && ok "stats count $k" || bad "stats count $k" "${v:-absent}"
done
# ─── a restart ──────────────────────────────────────────────────────────────
kill "${PIDS[1]}" 2>/dev/null; wait "${PIDS[1]}" 2>/dev/null
"$BIN" send m --from erin@remote.test --to frank@remote.test --subject "kept" --text "kept body" >/dev/null 2>&1
sleep 1
"$BIN" stop m >/dev/null 2>&1; "$BIN" start m >/dev/null 2>&1
ready_tcp 127.0.0.1 "$P" >/dev/null
check "a message waiting is kept across a restart" "$("$BIN" mail m queue 2>/dev/null | grep -c 'erin@remote.test')" "1"
python3 "$HERE/lib_smtp_sink.py" "$SINK" "$T/sink" >/dev/null 2>&1 &
PIDS[1]=$!
ready_tcp 127.0.0.1 "$SINK" >/dev/null
"$BIN" mail m flush >/dev/null 2>&1
mail_with "kept body" >/dev/null && ok "and delivered once it can be" || bad "and delivered once it can be" "$("$BIN" mail m queue 2>&1)"

# ─── the end of a message, and its size ─────────────────────────────────────
python3 - "$P" > "$T/smuggle.out" 2>&1 <<'PY'
import socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
f = s.makefile("rb")
def say(x): s.sendall(x)
f.readline()
say(b"EHLO x\r\n")
while not f.readline().startswith(b"250 "): pass
say(b"MAIL FROM:<carol@else.test>\r\nRCPT TO:<info@example.test>\r\nDATA\r\n")
for _ in range(3): f.readline()
say(b"Subject: smuggle\r\n\r\nfirst\n.\nMAIL FROM:<evil@else.test>\r\nRCPT TO:<info@example.test>\r\nDATA\r\nsmuggled\r\n.\r\nQUIT\r\n")
print(f.readline().decode().strip())
PY
f=$(mail_with "smuggled")
[ -n "$f" ] && grep -q 'MAIL FROM:<evil@else.test>' "$f" && ok "a dot between bare LFs ends no message: what follows is the body" \
    || bad "a dot between bare LFs ends no message: what follows is the body" "$(cat "$T/smuggle.out")"
check "and only one message was taken" "$(grep -l 'smuggled' "$T"/sink/*.eml 2>/dev/null | wc -l)" "1"
r=$(python3 - "$P" <<'PY'
import smtplib, sys
s = smtplib.SMTP("127.0.0.1", int(sys.argv[1]), source_address=("127.0.0.2", 0))
s.ehlo("x")
print(s.docmd("MAIL FROM:<carol@else.test> SIZE=99999999")[0])
PY
)
check "a message said to be past the size is refused at MAIL" "$r" "552"

# ─── a script ───────────────────────────────────────────────────────────────
cat > "$T/send.lua" <<'LUA'
function on_start()
    socketley.mail.send("m", {from = "alice@example.test", to = {"gina@remote.test"}, subject = "from lua",
                              text = "lua body"}, function(id, err) end)
end
LUA
"$BIN" create server luasend -p $((SL_PORT_BASE+1985)) --lua "$T/send.lua" -s >/dev/null 2>&1
mail_with "lua body" >/dev/null && ok "socketley.mail.send from another runtime's script queues and sends" \
    || bad "socketley.mail.send from another runtime's script queues and sends" "$(tail -3 "$SOCKETLEY_DLOG")"

r=$("$BIN" mail m show nosuchid 2>&1); rc=$?
check "show of a message not queued says so" "$rc $r" "1 error: no message nosuchid is queued"

# ─── a blocklist ────────────────────────────────────────────────────────────
"$BIN" create mail mb -p $((SL_PORT_BASE+1987)) --mail-domain example.test --aliases "$T/aliases" --dnsbl bl.test -s \
    >/dev/null 2>&1
ready_tcp 127.0.0.1 $((SL_PORT_BASE+1987)) || bad "the runtime with a blocklist listens" "$(tail -3 "$SOCKETLEY_DLOG")"
from_ip() { # from_ip <ip>: what MAIL is answered from that address
    python3 - "$1" $((SL_PORT_BASE+1987)) <<'PY'
import smtplib, sys
s = smtplib.SMTP("127.0.0.1", int(sys.argv[2]), source_address=(sys.argv[1], 0), timeout=10)
s.ehlo("x")
c, m = s.docmd("MAIL FROM:<carol@else.test>")
print(c, m.decode().split(";")[-1].strip() if c != 250 else "")
PY
}
check "an address the list names sends nothing" "$(from_ip 127.0.0.2)" "554 127.0.0.2 is listed by bl.test"
check "one it does not name is taken" "$(from_ip 127.0.0.3)" "250 "
check "and a list's error answer names nobody" "$(from_ip 127.0.0.4)" "250 "
# A runtime whose own address the list names says so, in its summary and to the alerts.
"$BIN" create mail mlisted -p $((SL_PORT_BASE+1979)) --mail-domain other.test --hostname listed-host.test --dnsbl bl.test -s \
    >/dev/null 2>&1
for _ in $(seq 1 50); do "$BIN" mail mlisted 2>/dev/null | grep -q BLOCKLISTED && break; sleep 0.1; done
case "$("$BIN" mail mlisted 2>&1)" in *"BLOCKLISTED its address is on bl.test (127.0.0.2)"*) ok "a runtime whose own address a blocklist names says so" ;;
    *) bad "a runtime whose own address a blocklist names says so" "$("$BIN" mail mlisted 2>&1 | head -4)" ;; esac
case "$("$BIN" mail mb 2>&1)" in *BLOCKLISTED*) bad "one whose address no list names says nothing" "$("$BIN" mail mb 2>&1)" ;;
    *) ok "one whose address no list names says nothing" ;; esac
# And whose address does not name it back: the PTR of 127.0.0.2 is other-host.test, that of 127.0.0.3 named-host.test.
case "$("$BIN" mail mlisted 2>&1)" in *"REVERSE DNS 127.0.0.2's PTR names other-host.test, not listed-host.test"*) ok "a runtime whose address's PTR names another says so" ;;
    *) bad "a runtime whose address's PTR names another says so" "$("$BIN" mail mlisted 2>&1 | head -5)" ;; esac
"$BIN" create mail mnamed -p $((SL_PORT_BASE+1978)) --mail-domain third.test --hostname named-host.test -s >/dev/null 2>&1
for _ in $(seq 1 30); do "$BIN" stats mnamed 2>/dev/null | grep -q mail_complaints && break; sleep 0.1; done
sleep 1
case "$("$BIN" mail mnamed 2>&1)" in *"REVERSE DNS"*) bad "one whose PTR names it back says nothing" "$("$BIN" mail mnamed 2>&1 | head -5)" ;;
    *) ok "one whose PTR names it back says nothing" ;; esac

# ─── the CLI and the daemon ─────────────────────────────────────────────────
"$BIN" send luasend -1 >/dev/null 2>&1; check "send of a message that begins with - to a server reaches it" "$?" "0"
head -c 6000000 /dev/urandom > "$T/big.bin"
id=$("$BIN" send m --from alice@example.test --to dave@remote.test --subject "big one" --text "big body" \
    --attach "$T/big.bin" 2>&1)
case "$id" in queued\ *) ok "a message past what the channel carries is sent by the outbox" ;;
    *) bad "a message past what the channel carries is sent by the outbox" "$id" ;; esac
f=$(mail_with "^Subject: big one")
[ -n "$f" ] && [ "$(stat -c %s "$f")" -gt 8000000 ] && ok "and arrives whole" || bad "and arrives whole" "$(stat -c %s "$f" 2>&1)"
outbox=$(find "$HOME/.local/share" -type d -name 'm.outbox' 2>/dev/null | head -1)
check "and leaves nothing in the outbox" "$(ls "$outbox" 2>/dev/null | wc -l)" "0"
mkdir -p "$T/a:b"; printf 'colon dir\n' > "$T/a:b/x.txt"
"$BIN" send m --from alice@example.test --to dave@remote.test --subject "colon path" --text t --attach "$T/a:b/x.txt" >/dev/null 2>&1
f=$(mail_with "^Subject: colon path")
[ -n "$f" ] && grep -q 'filename="x.txt"' "$f" && ok "an attachment under a directory with a colon is read from its path" \
    || bad "an attachment under a directory with a colon is read from its path" "${f:-nothing sent}"
r=$("$BIN" create mail sv1 -p $((SL_PORT_BASE+1988)) --mail-domain example.test --sieve $((SL_PORT_BASE+1989)) 2>&1)
case "$r" in *"--sieve keeps the filters"*) ok "--sieve without --idp and --storage is refused as it is made" ;;
    *) bad "--sieve without --idp and --storage is refused as it is made" "$r" ;; esac
r=$("$BIN" create mail hn -p $((SL_PORT_BASE+1988)) --mail-domain example.test --hostname bad_name.test 2>&1)
case "$r" in *"--hostname requires"*) ok "a --hostname that is no DNS name is refused" ;; *) bad "a --hostname that is no DNS name is refused" "$r" ;; esac
"$BIN" create mail rl -p $((SL_PORT_BASE+1988)) --mail-domain example.test --relay smtps://user:pw123secret@relay.test:465 >/dev/null 2>&1
check "show writes a smarthost's password as ***" "$("$BIN" show rl 2>/dev/null | grep -c 'pw123secret')" "0"
check "and the record it shows carries the mask" "$("$BIN" show rl 2>/dev/null | grep -q 'user:\*\*\*@relay.test' && echo yes)" "yes"
"$BIN" show rl > "$T/rl.json" 2>/dev/null
"$BIN" import rl < "$T/rl.json" >/dev/null 2>&1
# The state is written by the daemon's writer thread, so it is waited for rather than read at once.
kept=""
for _ in $(seq 1 50); do
    state=$(find "$HOME/.local/share" -name 'rl.json' -path '*runtimes*' 2>/dev/null | head -1)
    kept=$(grep -c 'pw123secret' "$state" 2>/dev/null)
    [ "$kept" = "1" ] && break
    sleep 0.1
done
check "and an import of what it showed keeps the password" "$kept" "1"
"$BIN" create mail ren -p $((SL_PORT_BASE+1988)) --mail-domain example.test -s >/dev/null 2>&1
ready_tcp 127.0.0.1 $((SL_PORT_BASE+1988)) >/dev/null
"$BIN" show ren 2>/dev/null | sed 's/"name": "ren"/"name": "ren2"/' > "$T/ren.json"
r=$("$BIN" import ren < "$T/ren.json" 2>&1)
case "$r" in *"cannot rename while running"*) ok "a running mail runtime is not renamed" ;; *) bad "a running mail runtime is not renamed" "$r" ;; esac
"$BIN" stop ren >/dev/null 2>&1
"$BIN" import ren < "$T/ren.json" >/dev/null 2>&1
mail_dir=$(dirname "$(find "$HOME/.local/share" -name 'm.outbox' -type d 2>/dev/null | head -1)")
[ -e "$mail_dir/ren2" ] && [ -e "$mail_dir/ren2.dkim.skl.key" ] && [ ! -e "$mail_dir/ren" ] \
    && ok "a stopped one renamed by import takes its spool and keys along" \
    || bad "a stopped one renamed by import takes its spool and keys along" "$(ls "$mail_dir" 2>&1 | tr '\n' ' ')"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
