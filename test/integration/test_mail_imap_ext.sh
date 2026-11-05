#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: the IMAP extensions a mail client leans on beyond IMAP4rev1: CONDSTORE and QRESYNC (RFC 7162),
# ESEARCH (RFC 4731), LIST-EXTENDED and LIST-STATUS (RFC 5258, 5819), STATUS=SIZE (RFC 8438), QUOTA (RFC 9208),
# SORT and THREAD (RFC 5256), WITHIN (RFC 5032), SAVEDATE (RFC 8514), PREVIEW (RFC 8970) and AUTHENTICATE LOGIN.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a flag change that does not raise the mod-sequence, or a FETCH CHANGEDSINCE that misses one
#   * a STORE UNCHANGEDSINCE that overwrites what changed since, without MODIFIED
#   * a QRESYNC SELECT that does not say what vanished and what changed, or EXPUNGE where VANISHED is due
#   * an ESEARCH whose MIN, MAX, COUNT or ALL is not the search's
#   * LIST RETURN (STATUS) without each folder's STATUS, a STATUS SIZE that is not the bytes
#   * a quota not told, or a message delivered or appended past it
#   * SORT out of the criteria's order, a base subject that keeps its Re:, THREAD not tying a reply to its parent
#   * OLDER or YOUNGER not counting from now, SAVEDBEFORE reading the internal date, a PREVIEW not of the text
#   * AUTHENTICATE LOGIN not asking for the password after the user, or taking a wrong one
#   * SETQUOTA taken over the account's quota, an UNSELECT that expunges
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

daemon_isolate mail_imap_ext
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1930))
IM=$((SL_PORT_BASE+1931))
PI=$((SL_PORT_BASE+1932))
PS=$((SL_PORT_BASE+1933))
trap daemon_stop EXIT

echo "=== Integration: IMAP's CONDSTORE, QRESYNC, ESEARCH, LIST-STATUS, QUOTA, SORT and THREAD ==="

daemon_start "$BIN"
printf 'spa - http://localhost:5173/cb\n' > "$T/clients"
"$BIN" create idp auth -p "$PI" --clients "$T/clients" --issuer "http://127.0.0.1:$PI" -s >/dev/null 2>&1
"$BIN" create storage st -p "$PS" --dir "$T/data" --anonymous -s >/dev/null 2>&1
for p in "$PI/jwks" "$PS/"; do
    for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p")" != 000 ] && break; sleep 0.1; done
done
"$BIN" idp-user auth add alice --password alicepassword1 --email alice@example.test --set mail_quota=40K >/dev/null 2>&1
"$BIN" create mail m -p "$P" --mail-domain example.test --idp auth --storage st/mail --imap "$IM" -s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$IM" || bad "the IMAP port listens" "$(tail -3 "$SOCKETLEY_DLOG")"

# Five messages for alice: a thread of three by References, a second subject, and a reply to it by subject alone.
# Each is in the mailbox before the next is sent, so their UIDs follow the order they were sent in.
python3 - "$P" "$PS" <<'PY'
import smtplib, sys, time, urllib.request
s = smtplib.SMTP("127.0.0.1", int(sys.argv[1])); s.ehlo("x")
sent = 0
def send(frm, subj, date, mid, extra=""):
    global sent
    s.sendmail(frm, ["alice@example.test"], "From: %s\r\nTo: alice@example.test\r\nSubject: %s\r\nDate: %s\r\n"
               "Message-ID: <%s>\r\n%s\r\nbody of %s\r\n" % (frm, subj, date, mid, extra, mid))
    sent += 1
    for _ in range(100):
        try:
            got = urllib.request.urlopen("http://127.0.0.1:%s/mail?list-type=2&prefix=alice/INBOX/" % sys.argv[2]).read()
            if got.count(b"<Key>") >= sent:
                return
        except Exception:
            pass
        time.sleep(0.05)
send("zed@else.test", "Lunch", "Mon, 19 Oct 2026 10:00:00 +0000", "a@else")
send("amy@else.test", "Re: Lunch", "Mon, 19 Oct 2026 11:00:00 +0000", "b@else", "References: <a@else>\r\n")
send("bob@else.test", "Budget", "Sun, 18 Oct 2026 09:00:00 +0000", "c@else")
send("cat@else.test", "[list] Re: Fwd: Lunch", "Mon, 19 Oct 2026 12:00:00 +0000", "d@else", "References: <a@else> <b@else>\r\n")
send("dan@else.test", "RE: Budget", "Tue, 20 Oct 2026 09:00:00 +0000", "e@else")
PY
for _ in $(seq 1 100); do [ "$(curl -s "http://127.0.0.1:$PS/mail?list-type=2&prefix=alice/INBOX/" | grep -c '<Key>')" -ge 5 ] && break; sleep 0.1; done

python3 - "$IM" "$P" > "$T/ext.out" 2>&1 <<'PY'
import base64, re, smtplib, socket, sys, time
def crashed(kind, value, tb):
    print("bad the client ran to its end: " + repr(value))
sys.excepthook = crashed
port, smtp_port = int(sys.argv[1]), int(sys.argv[2])
def say(name, cond, why=""):
    print(("ok " if cond else "bad ") + name + ("" if cond else ": " + str(why)[:600]))
class C:
    def __init__(self):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=10); self.f = self.s.makefile("rb"); self.n = 0
        self.f.readline()
    def cmd(self, text):
        self.n += 1; tag = "t%d" % self.n
        self.s.sendall(("%s %s\r\n" % (tag, text)).encode())
        out = []
        while True:
            l = self.f.readline().decode(errors="replace").rstrip("\r\n")
            if not l: out.append("<closed>"); return out
            out.append(l)
            if l.startswith(tag + " "): return out
a = C(); a.cmd("LOGIN alice alicepassword1")
r = a.cmd("CAPABILITY")
say("CAPABILITY offers what is tested", all(x in r[0] for x in ["CONDSTORE", "QRESYNC", "ESEARCH", "LIST-STATUS",
    "STATUS=SIZE", "QUOTA", "SORT", "THREAD=REFERENCES"]), r[0])
r = a.cmd("SELECT INBOX (CONDSTORE)")
hms = int(re.search(r"HIGHESTMODSEQ (\d+)", "\n".join(r)).group(1))
say("SELECT (CONDSTORE) says HIGHESTMODSEQ", hms >= 5, r)
r = a.cmd("UID STORE 1 +FLAGS (\\Flagged)")
m1 = int(re.search(r"MODSEQ \((\d+)\)", "\n".join(r)).group(1))
say("STORE gives the message the next mod-sequence, and says it", m1 > hms, r)
r = a.cmd("UID FETCH 1:* (FLAGS) (CHANGEDSINCE %d)" % hms)
say("FETCH CHANGEDSINCE gives what changed since, and only that", len([x for x in r if x.startswith("* ") and " FETCH " in x]) == 1 and
    "MODSEQ (%d)" % m1 in r[0], (m1, hms, r))
r = a.cmd("UID STORE 1 (UNCHANGEDSINCE %d) +FLAGS (\\Seen)" % hms)
say("STORE UNCHANGEDSINCE leaves what changed since, and says MODIFIED", "[MODIFIED 1]" in r[-1] and
    not any("\\Seen" in x for x in r[:-1]), r)
r = a.cmd("UID SEARCH MODSEQ %d" % m1)
say("SEARCH MODSEQ finds it, with the highest mod-sequence", r[0].startswith("* SEARCH 1 (MODSEQ %d)" % m1), r)
r = a.cmd("SEARCH RETURN (MIN MAX COUNT ALL) FROM else.test")
say("ESEARCH answers MIN, MAX, COUNT and ALL", r[0] == '* ESEARCH (TAG "t%d") MIN 1 MAX 5 COUNT 5 ALL 1:5' % a.n, r)
r = a.cmd("STATUS INBOX (MESSAGES SIZE HIGHESTMODSEQ)")
size = int(re.search(r"SIZE (\d+)", r[0]).group(1))
say("STATUS SIZE is the bytes of the folder, HIGHESTMODSEQ its last change", 1000 < size < 6000 and
    "HIGHESTMODSEQ %d" % m1 in r[0], r)
r = a.cmd('LIST "" "*" RETURN (STATUS (MESSAGES UNSEEN))')
lines = [x for x in r if x.startswith("* ")]
say("LIST RETURN (STATUS) says each folder's STATUS after it", any(x.startswith('* STATUS "INBOX" (MESSAGES 5 UNSEEN 5)') for x in lines)
    and len([x for x in lines if x.startswith("* STATUS")]) == len([x for x in lines if x.startswith("* LIST")]), r)
# SORT and THREAD
r = a.cmd("SORT (DATE) UTF-8 ALL")
say("SORT (DATE) orders by the Date header", r[0] == "* SORT 3 1 2 4 5", r)
r = a.cmd("SORT (REVERSE SUBJECT DATE) UTF-8 ALL")
say("SORT (REVERSE SUBJECT) by the base subject, its Re: and [list] taken off", r[0] == "* SORT 1 2 4 3 5", r)
r = a.cmd("SORT (FROM) UTF-8 SEARCH-NOTHING") if False else a.cmd("UID SORT (FROM) UTF-8 ALL")
say("UID SORT (FROM) by the sender's mailbox", r[0] == "* SORT 2 3 4 5 1", r)
r = a.cmd("THREAD REFERENCES UTF-8 ALL")
say("THREAD REFERENCES ties the replies to what they answer", r[0] == "* THREAD (3 5)(1 2 4)", r)
r = a.cmd("THREAD ORDEREDSUBJECT UTF-8 ALL")
say("THREAD ORDEREDSUBJECT gathers each base subject", r[0] == "* THREAD (3 5)(1 (2)(4))", r)
# QRESYNC: a second session expunges, the first reconnects with what it knew.
r = a.cmd("SELECT INBOX")
uv = int(re.search(r"UIDVALIDITY (\d+)", "\n".join(r)).group(1))
known = int(re.search(r"HIGHESTMODSEQ (\d+)", "\n".join(r)).group(1))
b = C(); b.cmd("LOGIN alice alicepassword1"); b.cmd("SELECT INBOX")
b.cmd("UID STORE 2 +FLAGS (\\Deleted)"); b.cmd("UID STORE 3 +FLAGS (\\Answered)"); b.cmd("EXPUNGE")
c = C(); c.cmd("LOGIN alice alicepassword1")
r = c.cmd("ENABLE QRESYNC")
say("ENABLE QRESYNC", "* ENABLED QRESYNC" in r, r)
r = c.cmd("SELECT INBOX (QRESYNC (%d %d 1:5))" % (uv, known))
say("SELECT (QRESYNC) says what vanished since", "* VANISHED (EARLIER) 2" in r, r)
say("and what changed", any(" FETCH (UID 3 FLAGS (\\Answered) MODSEQ" in x for x in r) and
    not any("UID 1 " in x and " FETCH " in x for x in r), r)
r = c.cmd("UID FETCH 1:5 (FLAGS) (CHANGEDSINCE %d VANISHED)" % known)
say("UID FETCH VANISHED says it too", r[0] == "* VANISHED (EARLIER) 2", r)
b.cmd("UID STORE 4 +FLAGS (\\Deleted)"); b.cmd("EXPUNGE")
r = c.cmd("NOOP")
say("an expunge another session made is VANISHED under QRESYNC, not EXPUNGE", "* VANISHED 4" in r and
    not any("EXPUNGE" in x for x in r), r)
r = a.cmd("NOOP")
say("and the flags another session changed are told as FETCH", any(" FETCH (UID 3 FLAGS (\\Answered)" in x for x in r), r)
# QUOTA: 40K for alice.
r = a.cmd("GETQUOTAROOT INBOX")
say("GETQUOTAROOT names the root and its storage", r[0] == '* QUOTAROOT "INBOX" ""' and
    re.match(r'\* QUOTA "" \(STORAGE \d+ 40\)', r[1] or ""), r)
big = "x" * 45000
lit = "Subject: big\r\n\r\n" + big
r = a.cmd("APPEND INBOX {%d+}\r\n%s" % (len(lit), lit))
say("an APPEND past the quota is refused OVERQUOTA", "[OVERQUOTA]" in r[-1], r[-1])
s = smtplib.SMTP("127.0.0.1", smtp_port); s.ehlo("x")
s.sendmail("zed@else.test", ["alice@example.test"], "Subject: too big\r\n\r\n" + big + "\r\n")
# Past the two seconds a folder's listing is kept, so the NOOP looks in the bucket again.
time.sleep(2.5)
a.cmd("NOOP")
r = a.cmd("SEARCH SUBJECT \"too big\"")
say("and a delivery past it is not kept", r[0] == "* SEARCH", r)
# WITHIN, SAVEDATE and PREVIEW (RFC 5032, 8514, 8970).
r = a.cmd("CAPABILITY")
say("CAPABILITY offers WITHIN, SAVEDATE, PREVIEW and AUTH=LOGIN", all(x in r[0] for x in
    ["WITHIN", "SAVEDATE", "PREVIEW", "AUTH=LOGIN"]), r[0])
r = a.cmd("UID FETCH 1 (PREVIEW SAVEDATE)")
say("FETCH PREVIEW is the start of the message's text", 'PREVIEW "body of a@else"' in r[0], r)
say("FETCH SAVEDATE is a date", re.search(r'SAVEDATE "[ \d]\d-[A-Z][a-z]{2}-\d{4} \d\d:\d\d:\d\d [+-]\d{4}"', r[0]), r)
r = a.cmd("UID FETCH 1 (UID PREVIEW (LAZY))")
say("PREVIEW (LAZY) is taken", " OK " in r[-1] and "PREVIEW" in r[0], r)
every = a.cmd("UID SEARCH ALL")[0]
r = a.cmd("UID SEARCH YOUNGER 3600")
say("SEARCH YOUNGER 3600 finds what came this hour", r[0] == every and every != "* SEARCH", (r, every))
r = a.cmd("SEARCH OLDER 3600")
say("and OLDER 3600 none of it", r[0] == "* SEARCH", r)
lit = "Subject: old one\r\n\r\nfrom long ago\r\n"
a.cmd('APPEND INBOX "01-Jan-2020 00:00:00 +0000" {%d+}\r\n%s' % (len(lit), lit))
a.cmd("NOOP")
r = a.cmd("UID SEARCH BEFORE 1-Jan-2021")
r2 = a.cmd("UID SEARCH SAVEDBEFORE 1-Jan-2021 SAVEDATESUPPORTED")
say("SAVEDBEFORE reads when a message was saved, not its internal date", r[0] != "* SEARCH" and r2[0] == "* SEARCH", (r, r2))
r = a.cmd("UID SEARCH SAVEDSINCE 1-Jan-2021 SUBJECT \"old one\"")
say("and SAVEDSINCE finds it", r[0] != "* SEARCH", r)
r = a.cmd("SEARCH OLDER 86400 SUBJECT \"old one\"")
say("OLDER counts back from the internal date", r[0] != "* SEARCH", r)
# AUTHENTICATE LOGIN: the user and then the password, each a continuation of its own.
d = C()
d.s.sendall(b"L AUTHENTICATE LOGIN\r\n"); l1 = d.f.readline()
d.s.sendall(base64.b64encode(b"alice") + b"\r\n"); l2 = d.f.readline()
d.s.sendall(base64.b64encode(b"alicepassword1") + b"\r\n"); l3 = d.f.readline()
say("AUTHENTICATE LOGIN asks for the user, then the password, and signs in", l1.startswith(b"+ VXNlcm5hbWU6") and
    l2.startswith(b"+ UGFzc3dvcmQ6") and l3.startswith(b"L OK"), (l1, l2, l3))
e = C()
e.s.sendall(b"L AUTHENTICATE LOGIN YWxpY2U=\r\n"); l1 = e.f.readline()
e.s.sendall(base64.b64encode(b"wrongpassword") + b"\r\n"); l2 = e.f.readline()
say("and with the user given at once, a wrong password is refused", l1.startswith(b"+ UGFzc3dvcmQ6") and
    l2.startswith(b"L NO"), (l1, l2))
# SETQUOTA, the quota being the idp account's; UNSELECT, which unlike CLOSE expunges nothing.
r = a.cmd('SETQUOTA "" (STORAGE 100)')
say("SETQUOTA is refused, the quota being the account's", "[NOPERM]" in r[-1], r)
a.cmd("SELECT INBOX")
before = a.cmd("UID SEARCH ALL")[0]
first = before.split()[2]
a.cmd("UID STORE %s +FLAGS (\\Deleted)" % first)
r = a.cmd("UNSELECT")
a.cmd("SELECT INBOX")
after = a.cmd("UID SEARCH ALL")[0]
say("UNSELECT leaves a \\Deleted message where it is", " OK " in r[-1] and after == before, (r, before, after))
r = a.cmd("UNSELECT"); r2 = a.cmd("UNSELECT")
say("and a second one, with nothing selected, is refused", " OK " in r[-1] and " BAD " in r2[-1], (r, r2))
a.cmd("SELECT INBOX"); a.cmd("UID STORE %s -FLAGS (\\Deleted)" % first)
PY
# COMPRESS=DEFLATE: what one session reads compressed is what another reads in the clear.
python3 - "$IM" >> "$T/ext.out" 2>&1 <<'PY'
import socket, sys, zlib
port = int(sys.argv[1])
def say(name, cond, why=""):
    print(("ok " if cond else "bad ") + name + ("" if cond else ": " + str(why)[:400]))
def session(compress):
    s = socket.create_connection(("127.0.0.1", port), timeout=10); f = s.makefile("rb"); f.readline()
    s.sendall(b"a LOGIN alice alicepassword1\r\n")
    while not f.readline().startswith(b"a "): pass
    if not compress:
        s.sendall(b"b SELECT INBOX\r\nc FETCH 1:* (BODY.PEEK[])\r\nd LOGOUT\r\n")
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk: break
            data += chunk
        return data, 0, None
    s.sendall(b"z COMPRESS DEFLATE\r\n")
    ok = f.readline()
    co = zlib.compressobj(wbits=-15); do = zlib.decompressobj(-15)
    def send(b): s.sendall(co.compress(b) + co.flush(zlib.Z_SYNC_FLUSH))
    send(b"b SELECT INBOX\r\nc FETCH 1:* (BODY.PEEK[])\r\ny COMPRESS DEFLATE\r\nd LOGOUT\r\n")
    data, wire = b"", 0
    while True:
        chunk = s.recv(65536)
        if not chunk: break
        wire += len(chunk); data += do.decompress(chunk)
    return data, wire, ok
try:
    plain, _, _ = session(False)
    got, wire, ok = session(True)
except Exception as e:
    say("the COMPRESS client ran", False, repr(e)); sys.exit(0)
say("COMPRESS DEFLATE is answered in the clear, then speaks DEFLATE", ok.startswith(b"z OK"), ok)
strip = lambda d: [l for l in d.split(b"\r\n") if not l.startswith(b"* OK [HIGHESTMODSEQ") and not l.startswith(b"y ")]
say("and what comes compressed is what comes in the clear", strip(got) == strip(plain) and b"c OK" in got,
    (len(got), len(plain)))
say("smaller on the wire", 0 < wire < len(plain), (wire, len(plain)))
say("a second COMPRESS is refused", b"y NO [COMPRESSIONACTIVE]" in got, got[-300:])
PY
# A FETCH that reads six messages under CONDSTORE marks them \Seen in one write to the journal, and tells each the
# MODSEQ it then has.
python3 - "$IM" "$BIN" >> "$T/ext.out" 2>&1 <<'PY'
import re, socket, subprocess, sys, time
port, binary = int(sys.argv[1]), sys.argv[2]
def say(name, cond, why=""):
    print(("ok " if cond else "bad ") + name + ("" if cond else ": " + str(why)[:600]))
def writes():
    # The runtime's figures reach the daemon a moment after they change.
    time.sleep(1.5)
    out = subprocess.run([binary, "stats", "m"], capture_output=True, timeout=30).stdout.decode()
    return sum(int(l.split(":")[1]) for l in out.splitlines() if l.startswith("imap_journal_writes:"))
s = socket.create_connection(("127.0.0.1", port), timeout=10); f = s.makefile("rb"); f.readline(); n = [0]
def cmd(text, lit=None):
    n[0] += 1; tag = "r%d" % n[0]
    s.sendall(("%s %s\r\n" % (tag, text)).encode())
    if lit is not None:
        f.readline(); s.sendall(lit + b"\r\n")
    out = []
    while True:
        l = f.readline()
        if not l: return out + ["<closed>"]
        l = l.decode(errors="replace").rstrip("\r\n")
        out.append(l)
        if l.startswith(tag + " "): return out
cmd("LOGIN alice alicepassword1"); cmd("CREATE Reads")
for i in range(6):
    body = b"From: x@else.test\r\nSubject: r%d\r\n\r\nread me\r\n" % i
    cmd("APPEND Reads {%d}" % len(body), body)
cmd("SELECT Reads (CONDSTORE)")
before = writes()
r = cmd("FETCH 1:* (BODY[])")
told = [int(m.group(1)) for m in (re.search(r"MODSEQ \((\d+)\)", x) for x in r) if m]
seen = len([x for x in r if "FLAGS (\\Seen)" in x])
after = writes()
r2 = cmd("FETCH 1:* (MODSEQ)")
now = [int(m.group(1)) for m in (re.search(r"MODSEQ \((\d+)\)", x) for x in r2) if m]
say("a FETCH of six under CONDSTORE marks them \\Seen in one journal write", after - before == 1 and seen == 6,
    (before, after, seen, r))
say("and tells each the MODSEQ it has after", len(told) == 6 and told == now and len(set(told)) == 6, (told, now))
PY
while read -r verdict name; do
    case "$verdict" in ok) ok "$name" ;; bad) bad "${name%%:*}" "${name#*:}" ;; esac
done < <(grep -E '^(ok|bad) ' "$T/ext.out" || echo "bad the client ran: $(tail -5 "$T/ext.out")")
s=$("$BIN" stats m 2>/dev/null | sed -n 's/^mail_over_quota://p')
[ "${s:-0}" -ge 1 ] && ok "stats count mail_over_quota" || bad "stats count mail_over_quota" "${s:-absent}"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
