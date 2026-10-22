#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a mail runtime's IMAP, as a mail client reads and keeps its mailbox with it.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a password taken in the clear from a stranger, or not taken over TLS
#   * the folders a client expects (Sent, Drafts, Junk, Trash) missing, or without their special use
#   * a FETCH a client makes (UID, flags, size, the headers it lists, BODYSTRUCTURE, the body) answered wrong
#   * \Seen not set by reading, a flag not kept, a search not finding what it should
#   * APPEND, COPY and MOVE without the UIDs UIDPLUS gives, or EXPUNGE leaving the object in the storage
#   * new mail not told by NOOP or IDLE, or told only when the bucket is next listed
#   * flags and UIDs lost by a restart
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

daemon_isolate mailimap
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1950))
IM=$((SL_PORT_BASE+1951))
PI=$((SL_PORT_BASE+1952))
PS=$((SL_PORT_BASE+1953))
trap daemon_stop EXIT

echo "=== Integration: IMAP on a mail runtime's mailboxes ==="

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
"$BIN" create mail m -p "$P" --mail-domain example.test --idp auth --storage st/mail --imap "$IM" \
    --tls --cert "$T/cert.pem" --key "$T/key.pem" -s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$IM" || bad "the IMAP port listens" "$(tail -3 "$SOCKETLEY_DLOG")"

# Before any mail came, so the storage has no bucket yet: a client's first act may be to put a message in.
"$BIN" idp-user auth add bob --password bobpassword12 --email bob@example.test >/dev/null 2>&1
got=$(python3 - "$IM" <<'PY'
import imaplib, sys
M = imaplib.IMAP4("127.0.0.1", int(sys.argv[1]))
M.login("bob", "bobpassword12")
typ, data = M.append("INBOX", None, None, b"From: bob@example.test\r\nSubject: kept\r\n\r\nfirst of all\r\n")
print(typ, data[0].decode(errors="replace"))
print(M.select("INBOX")[1][0].decode())
PY
)
[[ "$got" == "OK [APPENDUID "*" 1] "*$'\n'1 ]] && ok "APPEND to a mailbox the storage has no bucket for yet" \
    || bad "APPEND before any mail" "$got"

# Three messages for alice, one of them a multipart.
python3 - "$P" <<'PY'
import smtplib, sys
s = smtplib.SMTP("127.0.0.1", int(sys.argv[1]))
s.ehlo("x")
s.sendmail("carol@else.test", ["alice@example.test"], "From: Carol <carol@else.test>\r\nTo: alice@example.test\r\nSubject: one\r\nMessage-ID: <one@else.test>\r\n\r\nfirst body\r\n")
s.sendmail("dave@else.test", ["alice@example.test"], "From: dave@else.test\r\nTo: alice@example.test\r\nSubject: two\r\n\r\nsecond body with needle\r\n")
s.sendmail("erin@else.test", ["alice@example.test"], "From: erin@else.test\r\nTo: alice@example.test\r\nSubject: three\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nthe text\r\n--b\r\nContent-Type: application/octet-stream; name=x.bin\r\nContent-Transfer-Encoding: base64\r\n\r\nAAEC\r\n--b--\r\n")
PY
for _ in $(seq 1 100); do [ "$(curl -s "http://127.0.0.1:$PS/mail?list-type=2&prefix=alice/INBOX/" | grep -c '<Key>')" -ge 3 ] && break; sleep 0.1; done

cat > "$T/client.py" <<'PY'
import imaplib, socket, ssl, sys, time
port, smtp_port = int(sys.argv[1]), int(sys.argv[2])
step = sys.argv[3]
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
def say(name, cond, why=""):
    print(("ok " if cond else "bad ") + name + ("" if cond else ": " + str(why)))
class Stranger(imaplib.IMAP4):
    # From 127.0.0.2, a client that is not this machine.
    def _create_socket(self, timeout):
        return socket.create_connection((self.host, self.port), timeout, source_address=("127.0.0.2", 0))
M = Stranger("127.0.0.1", port)
if step == "first":
    say("LOGINDISABLED is said before STARTTLS", b"LOGINDISABLED" in M.capability()[1][0])
    try:
        M.login("alice", "alicepassword1")
        say("a password is refused in the clear", False, "it was taken")
    except imaplib.IMAP4.error:
        say("a password is refused in the clear", True)
M.starttls(ssl_context=ctx)
typ, _ = M.login("alice", "alicepassword1")
if step == "first":
    say("and taken over TLS", typ == "OK")
    typ, boxes = M.list()
    names = b" ".join(boxes)
    say("LIST has INBOX, Sent, Drafts, Junk and Trash, with their special use",
        all(x in names for x in [b'"INBOX"', b'\\Sent) "/" "Sent"', b'\\Drafts', b'\\Junk', b'\\Trash']), names)
    typ, data = M.select("INBOX")
    say("SELECT tells three messages", data == [b"3"], data)
    typ, data = M.uid("FETCH", "1:*", "(UID RFC822.SIZE FLAGS BODY.PEEK[HEADER.FIELDS (From To Subject Date Message-ID)])")
    heads = [d for d in data if isinstance(d, tuple)]
    say("the headers a client lists come for each", len(heads) == 3 and b"Subject: one" in heads[0][1] and
        b"Received" not in heads[0][1], data)
    say("unread", all(b"\\Seen" not in h[0] for h in heads), [h[0] for h in heads])
    typ, data = M.fetch("3", "(BODYSTRUCTURE)")
    say("BODYSTRUCTURE of the multipart", b'"TEXT" "PLAIN"' in data[0] and b'"APPLICATION" "OCTET-STREAM"' in data[0]
        and b'"MIXED"' in data[0], data)
    typ, data = M.fetch("3", "(BODY.PEEK[2])")
    say("its second part", data[0][1] == b"AAEC", data)
    typ, data = M.fetch("1", "(BODY[])")
    say("a body read whole", b"first body" in data[0][1] and b"Return-Path: <carol@else.test>" in data[0][1], data)
    typ, data = M.fetch("1", "(FLAGS)")
    say("and reading it sets \\Seen", b"\\Seen" in data[0], data)
    typ, data = M.fetch("1", "(ENVELOPE)")
    say("ENVELOPE names the sender", b'("Carol" NIL "carol" "else.test")' in data[0], data)
    M.store("2", "+FLAGS", "(\\Flagged)")
    typ, data = M.search(None, "FLAGGED")
    say("a flag set is found by SEARCH", data == [b"2"], data)
    typ, data = M.search(None, "UNSEEN")
    say("SEARCH UNSEEN", data == [b"2 3"], data)
    typ, data = M.search(None, "BODY", "needle")
    say("SEARCH BODY", data == [b"2"], data)
    typ, data = M.search(None, "OR", "SUBJECT", "one", "SUBJECT", "three")
    say("SEARCH OR SUBJECT", data == [b"1 3"], data)
    typ, data = M.uid("SEARCH", "UID", "2:*")
    say("UID SEARCH", data == [b"2 3"], data)
    typ, data = M.append("Sent", "(\\Seen)", None, b"From: alice@example.test\r\nTo: x@remote.test\r\nSubject: sent one\r\n\r\nhi\r\n")
    say("APPEND answers APPENDUID", typ == "OK" and b"APPENDUID" in data[0], data)
    typ, data = M.copy("1", "Trash")
    say("COPY answers COPYUID", typ == "OK" and b"COPYUID" in data[0], data)
    typ, data = M.uid("MOVE", "3", "Junk") if hasattr(M, "uid") else ("NO", [])
    say("MOVE moves it", typ == "OK", data)
    typ, data = M.select("INBOX")
    say("and the inbox has two left", data == [b"2"], data)
    M.store("1", "+FLAGS", "(\\Deleted)")
    typ, data = M.expunge()
    say("EXPUNGE takes what is deleted", data == [b"1"], data)
    typ, data = M.select("INBOX")
    say("leaving one", data == [b"1"], data)
    # Mail that comes while the folder is selected is told by NOOP.
    s = __import__("smtplib").SMTP("127.0.0.1", smtp_port); s.ehlo("x")
    s.sendmail("fred@else.test", ["alice@example.test"], "From: fred@else.test\r\nSubject: four\r\n\r\nfourth\r\n")
    told = False
    for _ in range(40):
        typ, data = M.noop()
        if any(b"EXISTS" in d for d in M.untagged_responses.get("EXISTS", [])) or M.untagged_responses.get("EXISTS"):
            told = True
            break
        time.sleep(0.25)
    say("new mail is told by NOOP", told, M.untagged_responses)
    typ, data = M.select("Sent")
    say("Sent holds what was appended", data == [b"1"], data)
    M.logout()
elif step == "idle":
    M.select("INBOX")
    tag = M._new_tag().decode()
    M.send(("%s IDLE\r\n" % tag).encode())
    first = M.readline()
    s = __import__("smtplib").SMTP("127.0.0.1", smtp_port); s.ehlo("x")
    s.sendmail("gina@else.test", ["alice@example.test"], "From: gina@else.test\r\nSubject: five\r\n\r\nfifth\r\n")
    M.sock.settimeout(8)
    line = b""
    try:
        while b"EXISTS" not in line:
            line = M.readline()
    except Exception as e:
        line = repr(e).encode()
    say("IDLE tells new mail as it comes", first.startswith(b"+") and b"EXISTS" in line, (first, line))
    M.send(b"DONE\r\n")
    M.readline()
    # Just after a listing of the bucket, so only the index can tell what came since.
    n = int(M.select("INBOX")[1][0])
    s.sendmail("hal@else.test", ["alice@example.test"], "From: hal@else.test\r\nSubject: six\r\n\r\nsixth\r\n")
    time.sleep(0.5)
    M.noop()
    exists = M.untagged_responses.get("EXISTS", [b"0"])[-1]
    say("a delivery is told by the next NOOP, not by the next listing of the bucket", int(exists) == n + 1, (n, exists))
    M.logout()
elif step == "after":
    typ, data = M.select("INBOX")
    typ, data = M.fetch("1", "(FLAGS BODY.PEEK[HEADER.FIELDS (SUBJECT)])")
    whole = b"".join(x if isinstance(x, bytes) else b"".join(x) for x in data)
    say("flags are kept across a restart", b"\\Flagged" in whole and b"Subject: two" in whole, data)
    typ, data = M.status("Sent", "(MESSAGES UIDNEXT UIDVALIDITY)")
    say("STATUS after a restart", b"MESSAGES 1" in data[0], data)
    open(sys.argv[4], "w").write(data[0].decode())
    M.logout()
PY
tally() { while read -r verdict rest; do case "$verdict" in ok) ok "$rest" ;; bad) bad "${rest%%:*}" "${rest#*:}" ;; esac; done; }
tally < <(timeout 120 python3 "$T/client.py" "$IM" "$P" first 2>&1 | grep -E '^(ok|bad) ' || echo "bad the client ran: $(timeout 60 python3 "$T/client.py" "$IM" "$P" first 2>&1 | tail -2)")
for _ in $(seq 1 30); do [ -z "$(curl -s "http://127.0.0.1:$PS/mail?list-type=2&prefix=alice/INBOX/" | grep -o '<Key>[^<]*one[^<]*</Key>')" ] && break; sleep 0.1; done
n=$(curl -s "http://127.0.0.1:$PS/mail?list-type=2&prefix=alice/" | grep -o '<Key>' | wc -l)
[ "$n" -ge 4 ] && ok "the folders are objects in the storage, the expunged one gone" || bad "the folders are objects in the storage, the expunged one gone" "$n objects"
tally < <(timeout 60 python3 "$T/client.py" "$IM" "$P" idle 2>&1 | grep -E '^(ok|bad) ')
before=$(timeout 60 python3 - "$IM" <<'PY'
import imaplib, ssl, sys
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
M = imaplib.IMAP4("127.0.0.1", int(sys.argv[1])); M.starttls(ssl_context=ctx); M.login("alice", "alicepassword1")
print(M.status("Sent", "(UIDVALIDITY)")[1][0].decode()); M.logout()
PY
)
"$BIN" stop m >/dev/null 2>&1; "$BIN" start m >/dev/null 2>&1
ready_tcp 127.0.0.1 "$IM" >/dev/null
tally < <(timeout 60 python3 "$T/client.py" "$IM" "$P" after "$T/status.after" 2>&1 | grep -E '^(ok|bad) ')
v1=$(printf '%s' "$before" | grep -o 'UIDVALIDITY [0-9]*'); v2=$(grep -o 'UIDVALIDITY [0-9]*' "$T/status.after" 2>/dev/null)
[ -n "$v1" ] && [ "$v1" = "$v2" ] && ok "UIDVALIDITY is the same after a restart" || bad "UIDVALIDITY is the same after a restart" "$v1 / $v2"

# Over TLS, a reply larger than what the record layer holds at once goes out whole.
r=$(timeout 60 python3 - "$IM" <<'PY'
import imaplib, ssl, sys
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
M = imaplib.IMAP4("127.0.0.1", int(sys.argv[1]), timeout=30); M.starttls(ssl_context=ctx); M.login("alice", "alicepassword1")
big = b"Subject: large over tls\r\n\r\n" + (b"t" * 78 + b"\r\n") * 30000
M.create("Large"); M.append("Large", None, None, big); M.select("Large")
typ, data = M.fetch("1", "(BODY.PEEK[])")
print(len(data[0][1]) == len(big))
PY
)
check "a body past 2 MiB is fetched whole over TLS" "$r" "True"

# A literal sent as Python's imaplib sends it, its line end in a write of its own that Nagle holds until the literal is
# acknowledged: the ACK must not wait for the 40 ms delayed-ACK timer.
acked=$(timeout 60 python3 - "$IM" <<'PY'
import socket, struct, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1]))); f = s.makefile("rb"); f.readline()
s.sendall(b"a LOGIN bob bobpassword12\r\n")
while not f.readline().startswith(b"a "): pass
took = []
for i in range(5):
    msg = b"From: bob@example.test\r\nSubject: acked\r\n\r\n" + b"line\r\n" * 200
    s.sendall(b"b%d APPEND Trash {%d}\r\n" % (i, len(msg)))
    assert f.readline().startswith(b"+")
    s.sendall(msg)
    t = time.perf_counter()
    # tcpi_unacked, after the eight bytes and four words that come before it in struct tcp_info.
    while struct.unpack_from("I", s.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 104), 24)[0] and time.perf_counter() - t < 0.5:
        time.sleep(0.0005)
    took.append(time.perf_counter() - t)
    s.sendall(b"\r\n")
    while not f.readline().startswith(b"b%d " % i): pass
took.sort(); print("%.1f" % (took[2] * 1000))
PY
)
[ -n "$acked" ] && awk -v t="$acked" 'BEGIN{exit !(t < 20)}' && ok "a literal is acknowledged at once, not after the delayed-ACK timer (${acked} ms)" \
    || bad "a literal is acknowledged at once" "median ${acked:-?} ms to the ACK"

# A FETCH of more than the socket holds, to a client that does not read: the runtime reads from the storage only as
# fast as the client takes it, not the whole folder into memory at once.
timeout 60 python3 - "$IM" <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1]))); f = s.makefile("rb"); f.readline()
def cmd(line, data=b""):
    s.sendall(line + data)
    tag = line.split(b" ")[0]
    while True:
        l = f.readline()
        if l.startswith(tag + b" "):
            assert b" OK" in l, l
            return
cmd(b"a LOGIN bob bobpassword12\r\n")
cmd(b"c CREATE Big\r\n")
for i in range(24):
    body = b"From: bob@example.test\r\nSubject: big %d\r\n\r\n" % i + (b"%07d" % i + b"x" * 1015 + b"\r\n") * 1024
    cmd(b"p%d APPEND Big {%d+}\r\n" % (i, len(body)), body + b"\r\n")
PY
"$BIN" stop m >/dev/null 2>&1; "$BIN" start m >/dev/null 2>&1
ready_tcp 127.0.0.1 "$IM" >/dev/null
read -r held whole < <(timeout 60 python3 - "$IM" "$BIN" <<'PY'
import socket, subprocess, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1]))); f = s.makefile("rb"); f.readline()
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 16)
s.sendall(b"a LOGIN bob bobpassword12\r\nb SELECT Big\r\n")
while not f.readline().startswith(b"b "): pass
s.sendall(b"f UID FETCH 1:* (BODY.PEEK[])\r\n")
time.sleep(2)
st = subprocess.run([sys.argv[2], "stats", "m"], capture_output=True, text=True).stdout
held = next((l.split(":")[1].strip() for l in st.splitlines() if l.startswith("imap_reads:")), "?")
got = 0
while True:
    l = f.readline()
    got += len(l)
    if l.startswith(b"f "):
        break
print(held, got)
PY
)
[ -n "$held" ] && [ "$held" != "?" ] && [ "$held" -lt 20 ] && ok "a FETCH to a client that does not read waits for it ($held of 24 read)" \
    || bad "a FETCH to a client that does not read waits for it" "${held:-?} of 24 read from the storage"
[ "${whole:-0}" -gt 24000000 ] && ok "and the whole folder comes once it does" || bad "and the whole folder comes once it does" "${whole:-0} bytes"

# ─── a bucket that encrypts what it keeps ───────────────────────────────────
# A message over a mebibyte is written in pieces and read back a range at a time: both through the encryption.
PSX=$((SL_PORT_BASE+1954)); PX=$((SL_PORT_BASE+1955)); IMX=$((SL_PORT_BASE+1956))
head -c 32 /dev/urandom > "$T/sse.key"; chmod 600 "$T/sse.key"
"$BIN" create storage sx -p "$PSX" --dir "$T/datax" --anonymous --sse-key-file "$T/sse.key" -s >/dev/null 2>&1
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PSX/")" != 000 ] && break; sleep 0.1; done
curl -s -X PUT "http://127.0.0.1:$PSX/mail" >/dev/null
curl -s -X PUT "http://127.0.0.1:$PSX/mail?encryption" -d '<ServerSideEncryptionConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>' >/dev/null
"$BIN" create mail mx -p "$PX" --mail-domain example.test --idp auth --storage sx/mail --imap "$IMX" -s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$IMX" || bad "the runtime on the encrypting bucket listens" "$(tail -3 "$SOCKETLEY_DLOG")"
r=$(python3 - "$PX" "$IMX" "$T/datax" <<'PY'
import hashlib, imaplib, os, smtplib, sys, time
body = b"".join(b"sealed line %07d of a message larger than a mebibyte\r\n" % i for i in range(40000))
msg = b"From: carol@else.test\r\nTo: alice@example.test\r\nSubject: sealed\r\n\r\n" + body
s = smtplib.SMTP("127.0.0.1", int(sys.argv[1])); s.ehlo("x"); s.sendmail("carol@else.test", ["alice@example.test"], msg); s.quit()
M = imaplib.IMAP4("127.0.0.1", int(sys.argv[2]))
M.login("alice", "alicepassword1")
got = None
for _ in range(100):
    n = int(M.select("INBOX")[1][0])
    if n:
        typ, data = M.fetch("1", "(BODY.PEEK[TEXT])")
        got = [d for d in data if isinstance(d, tuple)][0][1]
        break
    time.sleep(0.1)
plain_on_disk = False
for root, _, files in os.walk(sys.argv[3]):
    for f in files:
        with open(os.path.join(root, f), "rb") as fh:
            plain_on_disk = plain_on_disk or b"sealed line 0000001" in fh.read()
print(len(body), len(got or b""), got == body, plain_on_disk)
PY
)
set -- $r
[ "${3:-}" = True ] && ok "a message over a mebibyte in a bucket that encrypts is read back whole ($2 bytes)" \
    || bad "a message over a mebibyte in a bucket that encrypts is read back whole" "$r"
[ "${4:-}" = False ] && ok "and is kept encrypted" || bad "and is kept encrypted" "$r"

# ─── every shard serves IMAP ────────────────────────────────────────────────
# Three shards share alice's mailbox: what one gives a UID or a flag, the others see the same.
PSH=$((SL_PORT_BASE+1957)); IMSH=$((SL_PORT_BASE+1958))
"$BIN" create mail msh -p "$PSH" --mail-domain example.test --idp auth --storage st/mail --imap "$IMSH" --shards 3 \
    -s >/dev/null 2>&1
for _ in $(seq 1 100); do [ "$(ss -ltnpH "sport = :$IMSH" | grep -o 'pid=[0-9]*' | sort -u | wc -l)" -ge 3 ] && break; sleep 0.1; done
check_shards=$(ss -ltnpH "sport = :$IMSH" | grep -o 'pid=[0-9]*' | sort -u | wc -l)
[ "$check_shards" -ge 3 ] && ok "IMAP listens on every shard ($check_shards)" || bad "IMAP listens on every shard" "$check_shards"
r=$(python3 - "$IMSH" <<'PY'
import imaplib, sys, threading
port = int(sys.argv[1])
def conn():
    M = imaplib.IMAP4("127.0.0.1", port); M.login("alice", "alicepassword1"); return M
errs = []
def appender(i):
    try:
        M = conn()
        for k in range(5):
            typ, data = M.append("Shared", None, None, b"From: x@else.test\r\nSubject: s%d-%d\r\n\r\nb\r\n" % (i, k))
            if typ != "OK": errs.append(data)
        M.logout()
    except Exception as e:
        errs.append(repr(e))
M0 = conn(); M0.create("Shared"); M0.logout()
ts = [threading.Thread(target=appender, args=(i,)) for i in range(8)]
[t.start() for t in ts]; [t.join() for t in ts]
views = []
for _ in range(6):
    M = conn(); M.select("Shared")
    typ, data = M.uid("FETCH", "1:*", "(BODY.PEEK[HEADER.FIELDS (SUBJECT)])")
    view = {}
    for d in data:
        if isinstance(d, tuple):
            uid = int(d[0].split(b"UID ")[1].split()[0])
            view[uid] = d[1].strip()
    views.append((M, view))
same = all(v == views[0][1] for _, v in views)
unique = len(set(views[0][1].values())) == 40 and len(views[0][1]) == 40
# A flag one connection sets, every other sees after a NOOP.
first = min(views[0][1])
views[0][0].uid("STORE", str(first), "+FLAGS", "(\\Flagged)")
seen = 0
for M, _ in views[1:]:
    M.noop()
    typ, data = M.uid("FETCH", str(first), "(FLAGS)")
    seen += b"\\Flagged" in data[0]
print(len(errs), same, unique, seen)
PY
)
set -- $r
check "forty APPENDs from eight connections across the shards fail none" "${1:-x}" "0"
[ "${2:-}" = True ] && [ "${3:-}" = True ] && ok "and every connection sees the same forty UIDs, each one message" \
    || bad "and every connection sees the same forty UIDs, each one message" "$r"
check "a flag one shard sets the others see" "${4:-x}" "5"
# A FETCH that marks \Seen as it reads, while other shards append and unmark: what they log, and the snapshot their
# flood folds the journal into, move the folder's messages under it.
r=$(python3 - "$IMSH" <<'PY'
import imaplib, sys, threading, time
port = int(sys.argv[1])
errs = []
stop = threading.Event()
def conn():
    # A shard that stops answering is a failure here, not a test that never ends.
    M = imaplib.IMAP4("127.0.0.1", port, timeout=60); M.login("alice", "alicepassword1"); return M
def appender(i):
    try:
        M = conn()
        for k in range(70):
            M.append("Shared", None, None, b"From: y@else.test\r\nSubject: more %d-%d\r\n\r\nm\r\n" % (i, k))
        M.logout()
    except Exception as e:
        errs.append(repr(e))
def unmarker():
    try:
        U = conn(); U.select("Shared")
        i = 0
        while not stop.is_set():
            U.uid("STORE", "1:*", "-FLAGS.SILENT" if i % 2 == 0 else "+FLAGS.SILENT",
                  "(\\Seen \\Flagged)" if i % 2 == 0 else "(\\Flagged)")
            i += 1
    except Exception as e:
        errs.append(repr(e))
R = conn(); R.select("Shared")
ts = [threading.Thread(target=appender, args=(i,)) for i in range(6)] + \
     [threading.Thread(target=unmarker) for _ in range(2)]
[t.start() for t in ts]
reads = loops = 0
end = time.time() + 8
try:
    while time.time() < end:
        loops += 1
        typ, data = R.fetch("1:*", "(BODY[])")
        reads += typ == "OK"
except Exception as e:
    errs.append(repr(e))
stop.set(); [t.join() for t in ts]
typ, data = conn().uid("SEARCH", "UNSEEN") if errs else R.uid("SEARCH", "UNSEEN")
print(len(errs), reads == loops, typ)
PY
)
check "a FETCH that marks \\Seen while other shards append and unmark runs to its end" "$r" "0 True OK"
# APPENDs of large messages, each logged once the storage has it, while other shards flood the journal past the size
# it is folded at: a shard that finds the journal folded as it logs reads the new one under the lock it holds.
r=$(python3 - "$IMSH" <<'PY'
import imaplib, sys, threading, time
port = int(sys.argv[1])
errs = []
stop = threading.Event()
def conn():
    M = imaplib.IMAP4("127.0.0.1", port, timeout=30); M.login("alice", "alicepassword1"); return M
M = conn(); M.create("Bulk"); M.create("Flood")
for k in range(60):
    M.append("Flood", None, None, b"Subject: flood %d\r\n\r\nf\r\n" % k)
big = b"Subject: bulk\r\n\r\n" + (b"b" * 78 + b"\r\n") * 25000
appended = []
def appender():
    try:
        A = conn()
        for _ in range(8):
            appended.append(A.append("Bulk", None, None, big)[0])
    except Exception as e:
        errs.append(repr(e))
def flooder():
    try:
        F = conn(); F.select("Flood")
        i = 0
        while not stop.is_set():
            F.uid("STORE", "1:*", "+FLAGS.SILENT" if i % 2 == 0 else "-FLAGS.SILENT", "(\\Answered)")
            i += 1
    except Exception as e:
        errs.append(repr(e))
fs = [threading.Thread(target=flooder) for _ in range(3)]
aps = [threading.Thread(target=appender) for _ in range(4)]
[t.start() for t in fs + aps]
[t.join() for t in aps]
stop.set(); [t.join() for t in fs]
print(len(errs), appended.count("OK"), errs[:1])
PY
)
check "thirty-two large APPENDs while three shards flood the journal past its fold all go in" "$r" "0 32 []"
# MOVE and DELETE while other shards change the same messages' flags: what they log must not undo what goes.
r=$(python3 - "$IMSH" <<'PY'
import imaplib, sys, threading
port = int(sys.argv[1])
def conn():
    M = imaplib.IMAP4("127.0.0.1", port, timeout=60); M.login("alice", "alicepassword1"); return M
def count(M, folder):
    typ, data = M.status(folder, "(MESSAGES)")
    return int(data[0].split(b"MESSAGES ")[1].split(b")")[0]) if typ == "OK" else -1
M = conn()
for f in ("Src", "Dst", "Doomed"):
    M.create(f)
for k in range(30):
    M.append("Src", None, None, b"From: m@else.test\r\nSubject: move %d\r\n\r\nm\r\n" % k)
    M.append("Doomed", None, None, b"From: m@else.test\r\nSubject: doomed %d\r\n\r\nd\r\n" % k)
def flagger(folder, stop, going):
    try:
        F = conn(); F.select(folder)
        i = 0
        while not stop.is_set():
            F.uid("STORE", "1:*", "+FLAGS.SILENT" if i % 2 == 0 else "-FLAGS.SILENT", "(\\Flagged)")
            i += 1
            going.release()
    except Exception:
        pass
def flip(folder):
    stop, going = threading.Event(), threading.Semaphore(0)
    ts = [threading.Thread(target=flagger, args=(folder, stop, going)) for _ in range(2)]
    [t.start() for t in ts]
    # Both are flipping before the folder's messages go.
    for _ in range(4):
        going.acquire(timeout=10)
    return stop, ts
stop, ts = flip("Src")
M.select("Src")
for u in M.uid("SEARCH", "ALL")[1][0].split():
    M.uid("MOVE", u, "Dst")
stop.set(); [t.join() for t in ts]
moved = (count(M, "Src"), count(M, "Dst"))
M.select("INBOX")
stop, ts = flip("Doomed")
typ, _ = M.delete("Doomed")
stop.set(); [t.join() for t in ts]
N = conn()
listed = any(b"Doomed" in l for l in N.list()[1])
print(moved[0], moved[1], typ, listed)
PY
)
check "thirty MOVEs and a DELETE while two shards flip the messages' flags leave none behind" "$r" "0 30 OK False"
# A sequence set of an empty folder names nothing, its * included.
r=$(python3 - "$IMSH" <<'PY'
import imaplib, sys
M = imaplib.IMAP4("127.0.0.1", int(sys.argv[1])); M.login("alice", "alicepassword1"); M.create("Empty")
M.select("Empty")
try:
    print(M.fetch("1:*", "(FLAGS)")[0], M.fetch("*", "(FLAGS)")[0], M.store("1:*", "+FLAGS", "(\\Seen)")[0], M.noop()[0])
except Exception as e:
    print("gone", repr(e))
PY
)
check "FETCH 1:*, FETCH * and STORE 1:* of an empty folder answer OK" "$r" "OK OK OK OK"
# Thousands of changes outgrow the journal, which is folded into a snapshot; every shard reads on from it.
r=$(python3 - "$IMSH" <<'PY'
import imaplib, sys, time
port = int(sys.argv[1])
M = imaplib.IMAP4("127.0.0.1", port); M.login("alice", "alicepassword1"); M.select("Shared")
for i in range(400):
    M.uid("STORE", "1:*", "+FLAGS.SILENT" if i % 2 == 0 else "-FLAGS.SILENT", "(\\Seen)")
M.uid("STORE", "1:*", "+FLAGS.SILENT", "(\\Answered)")
time.sleep(3)
flags = set()
for _ in range(6):
    N = imaplib.IMAP4("127.0.0.1", port); N.login("alice", "alicepassword1"); N.select("Shared")
    typ, data = N.uid("FETCH", "1:*", "(FLAGS)")
    flags.add(tuple(sorted(d.decode() for d in data)))
print(len(flags), all("Answered" in x for x in next(iter(flags))))
PY
)
idx=$(find "$HOME/.local/share" -path '*/mail/msh.imap/alice' 2>/dev/null | head -1)
[ "$(head -c 10 "$idx" 2>/dev/null)" = "SKLIMAP2 1" ] || [ "$(head -c 9 "$idx" 2>/dev/null)" = "SKLIMAP2 " ] \
    && [ "$(stat -c %s "$idx.log" 2>/dev/null)" -lt 262144 ] && ok "a journal past a quarter of a mebibyte is folded into its snapshot" \
    || bad "a journal past a quarter of a mebibyte is folded into its snapshot" "$(head -c 20 "$idx" 2>/dev/null) $(stat -c %s "$idx.log" 2>/dev/null)"
check "and every shard reads the same flags after" "$r" "1 True"

# A literal's marker glued to an atom is no literal, so the bytes after it are never taken as one; a length that wraps
# past the end of what came is refused before sign-in, and the connection answers on.
r=$(python3 - "$IM" <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=3); f = s.makefile("rb"); f.readline()
s.sendall(b"a X Y{27}\r\n")
try:
    first = f.readline()[:5].decode(errors="replace")
    s.sendall(b"c X {18446744073709551580}\r\nb NOOP\r\n")
    print(first, " ".join(f.readline()[:5].decode(errors="replace") for _ in range(2)))
except Exception as e:
    print("no answer", repr(e))
PY
)
check "a literal's marker glued to an atom is no literal, a huge one is refused, and the next command answered" "$r" "a BAD c NO  b OK "
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
