#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a mail runtime's users filter their mail with Sieve (RFC 5228), put over ManageSieve
# (RFC 5804) or with `socketley mail ... sieve`.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a password taken in the clear from a stranger, or a script put by someone not signed in
#   * a script that does not compile kept, or kept without the line its error is on
#   * a literal past a script's size read as commands, or the active script deleted
#   * fileinto not filing, its imap4flags lost, discard keeping, reject not telling the sender
#   * fileinto of a folder not there without :create making it, mailboxexists not seeing one made
#   * size or body reading only a message's first mebibyte
#   * editheader's changes not in what is kept, an include :global not run, duplicate keeping a message twice
#   * notify not mailing its URI, or not as an automatic message
#   * HAVESPACE answering OK for a name PUTSCRIPT refuses, a script that no longer compiles made active
#   * redirect :copy not sending a copy, or not keeping one
#   * a message past a mebibyte a filter sends on lost, or sent on again by every try of the copy it keeps
#   * a command of literals before sign-in held in memory past what any command takes
#   * a vacation answered twice to one sender, or not at all, or from a sender a bounce could answer
#   * a script deactivated still run
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ready.sh"

command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
command -v openssl >/dev/null 2>&1 || { echo "  SKIP: openssl is required"; exit 0; }
command -v curl >/dev/null 2>&1 || { echo "  SKIP: curl is required"; exit 0; }

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate mail_sieve
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1940))
IM=$((SL_PORT_BASE+1941))
SV=$((SL_PORT_BASE+1942))
PI=$((SL_PORT_BASE+1943))
PS=$((SL_PORT_BASE+1944))
SINK=$((SL_PORT_BASE+1945))
NS=$((SL_PORT_BASE+1946))
PIDS=()
cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: Sieve filters and ManageSieve ==="

python3 "$HERE/lib_fake_dns.py" "$NS" 0 normal remote.test=MX:10:mx.remote.test mx.remote.test=127.0.0.1 \
    >/dev/null 2>&1 &
PIDS+=($!)
printf 'nameserver 127.0.0.1\noptions timeout:1 attempts:1 port:%s\n' "$NS" > "$T/resolv.conf"
export SOCKETLEY_RESOLV_CONF="$T/resolv.conf" SOCKETLEY_MAIL_MX_PORT="$SINK"
mkdir -p "$T/sink"
python3 "$HERE/lib_smtp_sink.py" "$SINK" "$T/sink" >/dev/null 2>&1 &
PIDS+=($!)
ready_tcp 127.0.0.1 "$SINK" || bad "the sink listens" "-"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=mail.example.test" \
    -keyout "$T/key.pem" -out "$T/cert.pem" >/dev/null 2>&1
daemon_start "$BIN"
printf 'spa - http://localhost:5173/cb\n' > "$T/clients"
"$BIN" create idp auth -p "$PI" --clients "$T/clients" --issuer "http://127.0.0.1:$PI" -s >/dev/null 2>&1
"$BIN" create storage st -p "$PS" --dir "$T/data" --anonymous -s >/dev/null 2>&1
for p in "$PI/jwks" "$PS/"; do
    for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p")" != 000 ] && break; sleep 0.1; done
done
"$BIN" idp-user auth add alice --password alicepassword1 --email alice@example.test >/dev/null 2>&1
"$BIN" create mail m -p "$P" --mail-domain example.test --idp auth --storage st/mail --imap "$IM" --sieve "$SV" \
    --tls --cert "$T/cert.pem" --key "$T/key.pem" -s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$SV" || bad "the ManageSieve port listens" "$(tail -3 "$SOCKETLEY_DLOG")"

# ─── ManageSieve ────────────────────────────────────────────────────────────
cat > "$T/script.sieve" <<'SIEVE'
require ["fileinto", "imap4flags", "vacation", "reject", "copy", "mailbox"];
if header :contains "subject" "invoice" { fileinto :create :flags "\\Flagged" "Bills"; stop; }
if header :contains "subject" "spam" { discard; stop; }
if address :is "from" "pest@remote.test" { reject "Not from you"; stop; }
if header :contains "subject" "share" { redirect :copy "friend@remote.test"; }
if header :contains "subject" "large" { redirect "big@remote.test"; stop; }
if header :contains "subject" "twice" { redirect :copy "copy@remote.test"; stop; }
if header :contains "subject" "lower inbox" { fileinto "inbox"; stop; }
vacation :days 1 :subject "Away" "I am away until Monday.";
SIEVE
python3 - "$SV" "$T/script.sieve" > "$T/ms.out" 2>&1 <<'PY'
import base64, socket, ssl, sys
port, script = int(sys.argv[1]), open(sys.argv[2], "rb").read()
def session(src):
    s = socket.create_connection(("127.0.0.1", port), timeout=10, source_address=(src, 0))
    return s, s.makefile("rb")
def response(f):
    # The lines up to and with the one that begins with OK, NO or BYE.
    lines = []
    while True:
        l = f.readline()
        if not l: return lines
        lines.append(l.decode(errors="replace").rstrip("\r\n"))
        if l[:2] in (b"OK", b"NO", b"BY"): return lines
def say(name, cond, why=""):
    print(("ok " if cond else "bad ") + name + ("" if cond else ": " + str(why)))
plain = lambda u, p: base64.b64encode(b"\0" + u + b"\0" + p).decode()
# A stranger in the clear is offered no password mechanism, and asked for STARTTLS.
s, f = session("127.0.0.2")
caps = response(f)
say("a stranger in the clear is offered STARTTLS and no SASL mechanism",
    '"STARTTLS"' in caps and '"SASL" ""' in caps and any(c.startswith('"SIEVE" "') and "vacation" in c for c in caps), caps)
s.sendall(('AUTHENTICATE "PLAIN" "%s"\r\n' % plain(b"alice", b"alicepassword1")).encode())
r = response(f)
say("and a password in the clear is refused", r[-1].startswith("NO (ENCRYPT-NEEDED)"), r)
s.sendall(b"STARTTLS\r\n")
r = response(f)
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
t = ctx.wrap_socket(s); f = t.makefile("rb")
caps = response(f)
say("after STARTTLS the capabilities come again, PLAIN among them", '"SASL" "PLAIN"' in caps and caps[-1].startswith("OK"), caps)
t.sendall(('AUTHENTICATE "PLAIN" "%s"\r\n' % plain(b"alice", b"wrong")).encode())
say("a wrong password is refused", response(f)[-1].startswith("NO"))
t.sendall(b'AUTHENTICATE "PLAIN"\r\n')
f.readline()
t.sendall(('"%s"\r\n' % plain(b"alice", b"alicepassword1")).encode())
say("PLAIN over TLS, its response on a line of its own, signs in", response(f)[-1].startswith("OK"))
broken = b"if true { fileinto 1; }"
t.sendall(b'PUTSCRIPT "broken" {%d+}\r\n%s\r\n' % (len(broken), broken))
r = response(f)
say("a script that does not compile is refused with where", r[-1].startswith("NO") and "line" in r[-1], r)
t.sendall(b'PUTSCRIPT "main" {%d+}\r\n%s\r\n' % (len(script), script))
r = response(f)
say("one that does is kept", r[-1].startswith("OK"), r)
t.sendall(b'HAVESPACE "big" 999999\r\n')
r = response(f)
say("HAVESPACE says what is too large", r[-1].startswith("NO (QUOTA/MAXSIZE)"), r)
t.sendall(b'HAVESPACE "a/b" 10\r\n')
r = response(f)
say("and refuses a name PUTSCRIPT would", r[-1].startswith("NO"), r)
t.sendall(b'PUTSCRIPT "huge" {200000+}\r\n' + b"#" * 200000 + b'\r\nNOOP "x"\r\n')
r = response(f); r2 = response(f)
say("a script past the size is refused and read past, the next command answered",
    r[-1].startswith("NO (QUOTA/MAXSIZE)") and r2[-1].startswith('OK (TAG "x")'), (r, r2))
t.sendall(b'SETACTIVE "main"\r\nLISTSCRIPTS\r\n')
response(f)
r = response(f)
say("LISTSCRIPTS says which is active", '"main" ACTIVE' in r and not any("broken" in x for x in r), r)
t.sendall(b'GETSCRIPT "main"\r\n')
r = response(f)
say("GETSCRIPT gives it back as it was put", r[0] == "{%d}" % len(script) and r[-1].startswith("OK"), r[:2])
t.sendall(b'DELETESCRIPT "main"\r\n')
r = response(f)
say("the active script is not deleted", r[-1].startswith("NO (ACTIVE)"), r)
t.sendall(b"LOGOUT\r\n")
say("LOGOUT", response(f)[-1].startswith("OK"))
PY
while read -r verdict name; do
    case "$verdict" in ok) ok "$name" ;; bad) bad "${name%%:*}" "${name#*:}" ;; esac
done < <(grep -E '^(ok|bad) ' "$T/ms.out" || echo "bad the ManageSieve client ran: $(tail -3 "$T/ms.out")")

# ─── what the script does with mail ─────────────────────────────────────────
send() { # send <from> <subject>: a message for alice, from a stranger's server
    python3 - "$P" "$1" "$2" <<'PY'
import smtplib, sys
s = smtplib.SMTP("127.0.0.1", int(sys.argv[1]), source_address=("127.0.0.1", 0))
s.ehlo("x")
s.sendmail(sys.argv[2], ["alice@example.test"],
           "From: %s\r\nTo: alice@example.test\r\nSubject: %s\r\nMessage-ID: <%s@remote.test>\r\n\r\nbody of %s\r\n"
           % (sys.argv[2], sys.argv[3], sys.argv[3].replace(" ", "."), sys.argv[3]))
PY
}
keys() { curl -s "http://127.0.0.1:$PS/mail?list-type=2&prefix=alice/$1/" | grep -o '<Key>[^<]*</Key>'; }
at_sink() {
    for _ in $(seq 1 60); do
        f=$(grep -l -- "$1" "$T"/sink/*.eml 2>/dev/null | head -1)
        [ -n "$f" ] && { echo "$f"; return 0; }
        sleep 0.1
    done
    return 1
}
send bob@remote.test "your invoice"
send bob@remote.test "cheap spam"
send pest@remote.test "hello"
send bob@remote.test "please share"
send bob@remote.test "first plain"
send bob@remote.test "second plain"
for _ in $(seq 1 60); do [ -n "$(keys Bills)" ] && [ "$(keys INBOX | wc -l)" -ge 3 ] && break; sleep 0.1; done
case "$(keys Bills)" in *",F.eml</Key>") ok "fileinto files into its folder, its \\Flagged in the key" ;;
    *) bad "fileinto files into its folder, its \\Flagged in the key" "$(keys Bills)" ;; esac
r=$(python3 - "$IM" <<'PY'
import imaplib, sys
M = imaplib.IMAP4("127.0.0.1", int(sys.argv[1]))
M.login("alice", "alicepassword1")
M.select("Bills")
print(M.fetch("1", "(FLAGS)")[1][0].decode())
M.select("INBOX")
typ, data = M.fetch("1:*", "(BODY.PEEK[HEADER.FIELDS (SUBJECT)])")
print(" | ".join(d[1].decode().strip() for d in data if isinstance(d, tuple)))
PY
)
case "$r" in *'\Flagged'*) ok "and IMAP tells the flag" ;; *) bad "and IMAP tells the flag" "$r" ;; esac
inbox=$(printf '%s\n' "$r" | tail -1)
case "$inbox" in *spam*) bad "discard keeps nothing" "$inbox" ;; *) ok "discard keeps nothing" ;; esac
case "$inbox" in *"Subject: hello"*) bad "reject keeps nothing" "$inbox" ;; *) ok "reject keeps nothing" ;; esac
f=$(at_sink "Not from you")
[ -n "$f" ] && grep -q '^rcpt pest@remote.test' "$f" && ok "and the sender is told why" \
    || bad "and the sender is told why" "$(ls "$T/sink")"
f=$(at_sink "body of please share")
[ -n "$f" ] && grep -q '^rcpt friend@remote.test' "$f" && grep -q '^from alice@example.test' "$f" \
    && ok "redirect sends a copy on, from the user's own address" || bad "redirect sends a copy on, from the user's own address" "$(head -4 "$f" 2>/dev/null)"
case "$inbox" in *"please share"*) ok "and :copy keeps one" ;; *) bad "and :copy keeps one" "$inbox" ;; esac
for _ in $(seq 1 30); do [ "$(grep -l '^Subject: Away' "$T"/sink/*.eml 2>/dev/null | wc -l)" -ge 1 ] && break; sleep 0.1; done
sleep 0.5
v=$(grep -l '^Subject: Away' "$T"/sink/*.eml 2>/dev/null)
check "a vacation answers bob once for his messages" "$(printf '%s\n' "$v" | grep -c .)" "1"
f=$(printf '%s\n' "$v" | head -1)
[ -n "$f" ] && grep -q '^from $' "$f" && grep -q '^Auto-Submitted: auto-replied' "$f" && grep -q '^In-Reply-To: <' "$f" \
    && ok "from the null sender, auto-replied, in reply to his message" \
    || bad "from the null sender, auto-replied, in reply to his message" "$(head -12 "$f" 2>/dev/null)"

# ─── what is sent on ────────────────────────────────────────────────────────
# Past a mebibyte the message is a file of its own, read back to be sent on before the spool lets it go.
python3 - "$P" <<'PY'
import smtplib, sys
s = smtplib.SMTP("127.0.0.1", int(sys.argv[1])); s.ehlo("x")
body = "".join("large line %06d %s\r\n" % (i, "z" * 60) for i in range(20000))
s.sendmail("dave@remote.test", ["alice@example.test"],
           "From: dave@remote.test\r\nTo: alice@example.test\r\nSubject: large one\r\n\r\n" + body)
PY
f=$(at_sink "^Subject: large one")
[ -n "$f" ] && grep -q '^rcpt big@remote.test' "$f" && [ "$(grep -c '^large line ' "$f")" = 20000 ] \
    && ok "a message past a mebibyte that a filter only sends on arrives whole" \
    || bad "a message past a mebibyte that a filter only sends on arrives whole" "${f:-none} $(grep -c '^large line ' "$f" 2>/dev/null)"
# The copy kept fails while the storage is down and is tried three times; the one sent on goes once.
"$BIN" stop st >/dev/null 2>&1
send erin@remote.test "twice over"
for _ in $(seq 1 50); do "$BIN" mail m queue 2>/dev/null | grep -q erin@remote.test && break; sleep 0.1; done
sleep 1; "$BIN" mail m flush >/dev/null 2>&1; sleep 1; "$BIN" mail m flush >/dev/null 2>&1; sleep 1
"$BIN" start st >/dev/null 2>&1
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PS/")" != 000 ] && break; sleep 0.1; done
"$BIN" mail m flush >/dev/null 2>&1
for _ in $(seq 1 100); do "$BIN" mail m queue 2>/dev/null | grep -q erin@remote.test || break; sleep 0.1; done
sleep 0.5
check "a message whose kept copy is tried again is sent on once" \
    "$(grep -l '^rcpt copy@remote.test' "$T"/sink/*.eml 2>/dev/null | xargs -r grep -l 'body of twice over' | wc -l)" "1"
# Three hundred literals of a command before sign-in: what is held stays near a script's size, and it is refused.
pid=$(ss -ltnpH "sport = :$SV" | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2)
r=$(python3 - "$SV" "$pid" <<'PY'
import socket, sys, time
port, pid = int(sys.argv[1]), sys.argv[2]
def rss():
    for l in open("/proc/%s/status" % pid):
        if l.startswith("VmRSS:"):
            return int(l.split()[1])
s = socket.create_connection(("127.0.0.1", port), timeout=10); f = s.makefile("rb")
while not f.readline().startswith(b"OK"): pass
before = rss()
s.sendall(b"NOOP {60000+}\r\n")
for _ in range(299):
    s.sendall(b"a" * 60000 + b" {60000+}\r\n")
s.sendall(b"a" * 60000)
time.sleep(1)
grown = rss() - before
s.sendall(b'\r\nNOOP "after"\r\n')
r1 = f.readline()
while r1[:2] not in (b"OK", b"NO", b"BY"):
    r1 = f.readline()
print(grown < 8192, r1[:2].decode(), f.readline()[:2].decode())
PY
)
check "a command of three hundred literals before sign-in is held small, refused, and the next one answered" "$r" "True NO OK"
r=$(python3 - "$SV" <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5); f = s.makefile("rb")
while not f.readline().startswith(b"OK"): pass
s.sendall(b'NOOP "' + b"a" * 9000 + b'"\r\nNOOP "next"\r\n')
r1 = f.readline()
while r1[:2] not in (b"OK", b"NO", b"BY"): r1 = f.readline()
print(r1[:2].decode(), f.readline()[:2].decode())
PY
)
check "a line past the limit that comes whole is refused, the next one answered" "$r" "NO OK"

# INBOX is one name whatever its case, so fileinto "inbox" files where IMAP lists it.
n0=$(keys INBOX | wc -l)
send bob@remote.test "lower inbox"
for _ in $(seq 1 60); do [ "$(keys INBOX | wc -l)" -gt "$n0" ] && break; sleep 0.1; done
check "fileinto \"inbox\" files into INBOX" "$(keys INBOX | wc -l)" "$((n0 + 1))"

# ─── the CLI ────────────────────────────────────────────────────────────────
check "socketley mail sieve lists a user's scripts" "$("$BIN" mail m sieve alice list 2>&1)" "main	active"
printf 'require "fileinto";\nfileinto "Elsewhere"\n' > "$T/bad.sieve"
out=$("$BIN" mail m sieve alice put other "$T/bad.sieve" 2>&1); rc=$?
case "$out" in error*line*) [ $rc = 1 ] && ok "and refuses one that does not compile, saying where" \
    || bad "and refuses one that does not compile" "rc $rc" ;; *) bad "and refuses one that does not compile, saying where" "$out" ;; esac
"$BIN" mail m sieve alice deactivate >/dev/null 2>&1
n0=$(keys INBOX | wc -l)
send carol@remote.test "after deactivate"
for _ in $(seq 1 60); do [ "$(keys INBOX | wc -l)" -gt "$n0" ] && break; sleep 0.1; done
sleep 0.5
check "a script deactivated is no longer run" \
    "$(grep -l '^Subject: Away' "$T"/sink/*.eml 2>/dev/null | xargs -r grep -l '^rcpt carol@remote.test' | wc -l)" "0"
{ printf 'require "fileinto";\n'; for i in $(seq 1 400); do printf '# a line of comment to make the script long %04d\n' "$i"; done
  printf 'keep;\n'; } > "$T/long.sieve"
out=$("$BIN" mail m sieve alice put long "$T/long.sieve" 2>&1)
check "a script of 20 KB is put by the CLI" "$out" ""
dir=$(find "$HOME/.local/share" -type d -path '*m.sieve/alice' 2>/dev/null | head -1)
printf 'if true { nope; }\n' > "$dir/edited.sieve"
out=$("$BIN" mail m sieve alice activate edited 2>&1); rc=$?
case "$out" in error*) [ $rc = 1 ] && ok "a script that no longer compiles is not made active" \
    || bad "a script that no longer compiles is not made active" "rc $rc" ;;
    *) bad "a script that no longer compiles is not made active" "$out" ;; esac
rm -f "$dir/edited.sieve"

# ─── the extensions ─────────────────────────────────────────────────────────
printf 'require "editheader";\naddheader "X-Global" "seen";\n' > "$T/global.sieve"
"$BIN" mail m sieve .global put tag "$T/global.sieve" >/dev/null 2>&1
cat > "$T/ext.sieve" <<'SIEVE'
require ["fileinto", "mailbox", "editheader", "duplicate", "enotify", "include"];
include :global "tag";
deleteheader "X-Remove";
addheader "X-Sieve" "filtered";
if size :over 1500K { fileinto :create "Big"; stop; }
if header :contains "subject" "notify me" { notify :message "You have mail" "mailto:watcher@remote.test"; }
if duplicate { discard; stop; }
if header :contains "subject" "nowhere" { fileinto "Missing"; stop; }
if allof (mailboxexists "Big", header :contains "subject" "check exists") { fileinto "Big"; stop; }
SIEVE
out=$("$BIN" mail m sieve alice put ext "$T/ext.sieve" 2>&1; "$BIN" mail m sieve alice activate ext 2>&1)
check "a script that includes a global one is put and made active" "$out" ""
n0=$(keys INBOX | wc -l)
python3 - "$P" <<'PY'
import smtplib, sys
s = smtplib.SMTP("127.0.0.1", int(sys.argv[1])); s.ehlo("x")
s.sendmail("gil@remote.test", ["alice@example.test"], "From: gil@remote.test\r\nTo: alice@example.test\r\n"
           "Subject: edited\r\nX-Remove: me\r\nMessage-ID: <edited@remote.test>\r\n\r\nbody of edited\r\n")
body = "".join("big line %06d %s\r\n" % (i, "y" * 60) for i in range(25000))
s.sendmail("gil@remote.test", ["alice@example.test"], "From: gil@remote.test\r\nTo: alice@example.test\r\n"
           "Subject: huge one\r\nMessage-ID: <huge@remote.test>\r\n\r\n" + body)
PY
send gil@remote.test "dup one"
send gil@remote.test "dup one"
send gil@remote.test "nowhere"
send gil@remote.test "notify me"
for _ in $(seq 1 80); do [ "$(keys INBOX | wc -l)" -ge "$((n0 + 4))" ] && [ -n "$(keys Big)" ] && break; sleep 0.1; done
send gil@remote.test "check exists"
for _ in $(seq 1 60); do [ "$(keys Big | wc -l)" -ge 2 ] && break; sleep 0.1; done
sleep 0.5
r=$(python3 - "$IM" <<'PY'
import imaplib, sys
M = imaplib.IMAP4("127.0.0.1", int(sys.argv[1])); M.login("alice", "alicepassword1")
M.select("INBOX")
typ, data = M.search(None, 'HEADER Message-ID "<edited@remote.test>"')
n = data[0].split()[-1]
h = M.fetch(n, "(BODY.PEEK[HEADER])")[1][0][1].decode()
print("X-Sieve: filtered" in h, "X-Global: seen" in h, "X-Remove" in h)
print(len(M.search(None, 'SUBJECT "dup one"')[1][0].split()), len(M.search(None, 'SUBJECT "nowhere"')[1][0].split()))
print(M.status("Missing", "(MESSAGES)")[0])
M.select("Big")
print(" | ".join(d[1].decode().strip() for d in M.fetch("1:*", "(BODY.PEEK[HEADER.FIELDS (SUBJECT)])")[1] if isinstance(d, tuple)))
PY
)
check "editheader's header is the one kept, a global include's among it" "$(sed -n 1p <<<"$r")" "True True False"
check "duplicate keeps a message the second time it comes not again, and fileinto of a folder not there files into INBOX" \
    "$(sed -n 2p <<<"$r")" "1 1"
check "and makes no folder for it" "$(sed -n 3p <<<"$r")" "NO"
case "$(sed -n 4p <<<"$r")" in *"huge one"*"check exists"*) ok "size reads a message past a mebibyte whole, and mailboxexists sees the folder made" ;;
    *) bad "size reads a message past a mebibyte whole, and mailboxexists sees the folder made" "$(sed -n 4p <<<"$r")" ;; esac
f=$(at_sink "You have mail")
[ -n "$f" ] && grep -q '^rcpt watcher@remote.test' "$f" && grep -q '^Auto-Submitted: auto-notified' "$f" && grep -q '^from $' "$f" \
    && ok "notify mails the mailto URI, auto-notified, from the null sender" \
    || bad "notify mails the mailto URI, auto-notified, from the null sender" "$(head -8 "$f" 2>/dev/null)"

caps=$(python3 - "$IM" <<'PY'
import imaplib, sys
print(" ".join(imaplib.IMAP4("127.0.0.1", int(sys.argv[1])).capabilities))
PY
)
case " ${caps,,} " in *" imapsieve=sieve://"*":$SV "*) ok "IMAP names where imapsieve's scripts are put (RFC 6785)" ;;
    *) bad "IMAP names where imapsieve's scripts are put (RFC 6785)" "$caps" ;; esac
r=$(printf 'CAPABILITY\r\nLOGOUT\r\n' | timeout 3 nc -q1 127.0.0.1 "$SV" 2>/dev/null | grep '^"SIEVE"')
case "$r" in *imapsieve*) ok "and ManageSieve lists imapsieve among its extensions" ;;
    *) bad "and ManageSieve lists imapsieve among its extensions" "$r" ;; esac

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
