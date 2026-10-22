#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: what a mail runtime's IMAP index keeps and how a session answers from it -- keywords, the quota
# as a running total, COPY whole or not at all, folder names and their hierarchy, and the searches a client makes.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a keyword a client set ($Forwarded, its own) not kept, not searched, or lost by a restart
#   * UID EXPUNGE taken in a folder opened read-only, ENABLE before a login, an authzid not the user's taken
#   * a delivery the quota does not count until the bucket is next listed
#   * a COPY past the quota that leaves part of itself behind, or one without TRYCREATE for a missing folder
#   * a COPY of hundreds whose UIDs or order are not the source's
#   * RENAME of nothing making its destination, DELETE of Trash taken, CREATE a/b without a, or of a//b or ../x taken
#   * a folder made again under its old name given its old UIDVALIDITY
#   * APPEND's date-time read as a day, SENTBEFORE by the arrival rather than the Date header
#   * SEARCH missing a word in a base64 part, an encoded subject, or a header's second occurrence
#   * a message the storage lost answered as empty, or an empty one without a BODYSTRUCTURE
#   * an EXPUNGE that swallows what another session added meanwhile
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
tally() { while read -r verdict rest; do [ "$verdict" = ok ] && ok "$rest" || bad "${rest%%: *}" "${rest#*: }"; done; }

daemon_isolate mail_imap_index
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1905))
IM=$((SL_PORT_BASE+1906))
PI=$((SL_PORT_BASE+1907))
PS=$((SL_PORT_BASE+1908))
trap daemon_stop EXIT

echo "=== Integration: the IMAP index -- keywords, quota, COPY, folders and searches ==="

daemon_start "$BIN"
printf 'spa - http://localhost:5173/cb\n' > "$T/clients"
"$BIN" create idp auth -p "$PI" --clients "$T/clients" --issuer "http://127.0.0.1:$PI" -s >/dev/null 2>&1
"$BIN" create storage st -p "$PS" --dir "$T/data" --anonymous -s >/dev/null 2>&1
for p in "$PI/jwks" "$PS/"; do
    for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p")" != 000 ] && break; sleep 0.1; done
done
"$BIN" idp-user auth add bob --password bobpassword12 --email bob@example.test >/dev/null 2>&1
"$BIN" idp-user auth add alice --password alicepassword1 --email alice@example.test --set mail_quota=40K >/dev/null 2>&1
"$BIN" create mail m -p "$P" --mail-domain example.test --idp auth --storage st/mail --imap "$IM" -s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$IM" || bad "the IMAP port listens" "$(tail -3 "$SOCKETLEY_DLOG")"

cat > "$T/client.py" <<'PY'
import base64, re, smtplib, socket, sys, time
def crashed(kind, value, tb):
    print("bad the client ran to its end: " + repr(value))
sys.excepthook = crashed
port, smtp_port, storage_port, step = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
def say(name, cond, why=""):
    print(("ok " if cond else "bad ") + name + ("" if cond else ": " + str(why)[:600]))
class C:
    def __init__(self, login=None):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=20); self.f = self.s.makefile("rb"); self.n = 0
        self.f.readline()
        if login:
            self.cmd("LOGIN %s %s" % login)
    def send(self, raw):
        self.n += 1; tag = "t%d" % self.n
        self.s.sendall(tag.encode() + b" " + raw)
        out = []
        while True:
            l = self.f.readline()
            if not l:
                out.append("<closed>"); return out
            l = l.decode(errors="replace").rstrip("\r\n")
            if l.endswith("}") and "{" in l:
                n = int(l[l.rindex("{") + 1:-1]); l += self.f.read(n).decode(errors="replace") + self.f.readline().decode(errors="replace").rstrip("\r\n")
            out.append(l)
            if l.startswith(tag + " "): return out
    def cmd(self, text):
        return self.send(text.encode() + b"\r\n")
    def append(self, folder, data, flags="", date=""):
        head = "APPEND %s%s%s {%d+}\r\n" % (folder, " (%s)" % flags if flags else "", ' "%s"' % date if date else "", len(data))
        return self.send(head.encode() + data + b"\r\n")
def mail(to, text):
    s = smtplib.SMTP("127.0.0.1", smtp_port); s.ehlo("x"); s.sendmail("x@else.test", [to], text); s.quit()
def msg(subject, body="text\r\n", extra=""):
    return ("From: x@else.test\r\nSubject: %s\r\n%s\r\n%s" % (subject, extra, body)).encode()

if step == "first":
    b = C(("bob", "bobpassword12"))
    # Keywords
    r = b.append("INBOX", msg("kw"))
    uid = int(re.search(r"APPENDUID \d+ (\d+)", r[-1]).group(1))
    r = b.cmd("SELECT INBOX")
    say("SELECT lets a client make its own keywords", any("PERMANENTFLAGS" in x and "\\*" in x for x in r), r)
    r = b.cmd("UID STORE %d +FLAGS ($Forwarded project-x)" % uid)
    say("STORE takes a keyword", any("$Forwarded" in x and "project-x" in x for x in r) and r[-1].split()[1] == "OK", r)
    r = b.cmd("UID SEARCH KEYWORD project-x")
    say("SEARCH KEYWORD finds it", r[0] == "* SEARCH %d" % uid, r)
    r = b.cmd("UID SEARCH UNKEYWORD project-x")
    say("and UNKEYWORD leaves it out", str(uid) not in r[0].split()[2:], r)
    r = b.append("INBOX", msg("kw2"), flags="\\Seen $Junk")
    r2 = C(("bob", "bobpassword12")).cmd("EXAMINE INBOX")
    say("another session's SELECT names the keywords in FLAGS", any(x.startswith("* FLAGS") and "project-x" in x and "$Junk" in x for x in r2), r2)
    r = b.cmd("UID STORE %d -FLAGS ($Forwarded)" % uid)
    r = b.cmd("UID FETCH %d (FLAGS)" % uid)
    say("STORE -FLAGS takes one away and keeps the other", "project-x" in r[0] and "$Forwarded" not in r[0], r)
    # Read-only, ENABLE, authzid
    r = b.cmd("EXAMINE INBOX")
    r = b.cmd("UID EXPUNGE %d" % uid)
    say("UID EXPUNGE is refused in a folder opened read-only", r[-1].split()[1] in ("NO", "BAD"), r)
    c = C()
    r = c.cmd("ENABLE QRESYNC")
    say("ENABLE before a login is refused", r[-1].split()[1] in ("NO", "BAD") and not any("ENABLED" in x for x in r), r)
    r = c.cmd("AUTHENTICATE PLAIN " + base64.b64encode(b"alice\0bob\0bobpassword12").decode())
    say("an authzid that is not the user is refused", r[-1].split()[1] == "NO", r)
    # TRYCREATE, RENAME, DELETE, CREATE
    b.cmd("SELECT INBOX")
    r = b.cmd("UID COPY %d Nowhere" % uid)
    say("COPY to a folder not there says TRYCREATE", "[TRYCREATE]" in r[-1], r)
    r = b.cmd("RENAME Nope Other")
    r2 = b.cmd('LIST "" "*"')
    say("RENAME of a folder not there is refused and makes nothing", r[-1].split()[1] == "NO" and not any('"Other"' in x or " Other" in x for x in r2), (r, r2))
    r = b.cmd("DELETE Trash")
    say("DELETE of Trash is refused", r[-1].split()[1] == "NO", r)
    r = b.cmd("CREATE Work/2026")
    r2 = b.cmd('LIST "" "*"')
    say("CREATE Work/2026 makes Work, which has children", r[-1].split()[1] == "OK" and
        any(x.endswith(' "/" "Work"') and "\\HasChildren" in x for x in r2) and any(x.endswith(' "/" "Work/2026"') for x in r2), r2)
    r = [b.cmd("CREATE a//b")[-1].split()[1], b.cmd("CREATE x/../y")[-1].split()[1], b.cmd("CREATE ..")[-1].split()[1]]
    say("CREATE of an empty or dotted level is refused", r == ["NO", "NO", "NO"], r)
    # UIDVALIDITY
    b.cmd("CREATE Tmp"); v1 = int(re.search(r"UIDVALIDITY (\d+)", b.cmd("STATUS Tmp (UIDVALIDITY)")[0]).group(1))
    b.cmd("DELETE Tmp"); b.cmd("CREATE Tmp"); v2 = int(re.search(r"UIDVALIDITY (\d+)", b.cmd("STATUS Tmp (UIDVALIDITY)")[0]).group(1))
    say("a folder made again under its name has a new UIDVALIDITY", v2 > v1, (v1, v2))
    # Dates
    r = b.append("INBOX", msg("dated", extra="Date: Tue, 01 Jan 2019 10:00:00 +0000\r\n"), date="19-Oct-2026 10:30:00 +0200")
    d = int(re.search(r"APPENDUID \d+ (\d+)", r[-1]).group(1))
    r = b.cmd("UID FETCH %d (INTERNALDATE)" % d)
    say("APPEND keeps the time and zone of its date-time", "19-Oct-2026 08:30:00 +0000" in r[0] or "19-Oct-2026 10:30:00 +0200" in r[0], r)
    r = b.cmd("UID SEARCH SENTBEFORE 1-Jan-2020")
    say("SENTBEFORE reads the Date header, not the arrival", r[0].split()[2:] == [str(d)], r)
    r = b.cmd("UID SEARCH BEFORE 1-Jan-2020")
    say("and BEFORE the arrival", str(d) not in r[0].split()[2:], r)
    # Searches of what is encoded
    enc = base64.b64encode(b"the hidden needle is here\r\n").decode()
    r = b.append("INBOX", ("From: x@else.test\r\nSubject: =?utf-8?b?%s?=\r\nX-Tag: first\r\nX-Tag: second\r\nMIME-Version: 1.0\r\n"
                           "Content-Type: multipart/mixed; boundary=bb\r\n\r\n--bb\r\nContent-Type: text/plain\r\n"
                           "Content-Transfer-Encoding: base64\r\n\r\n%s\r\n--bb--\r\n" % (base64.b64encode(b"lunch menu").decode(), enc)).encode())
    e = int(re.search(r"APPENDUID \d+ (\d+)", r[-1]).group(1))
    say("SEARCH BODY finds a word in a base64 part", b.cmd("UID SEARCH BODY needle")[0].split()[2:] == [str(e)])
    say("SEARCH SUBJECT finds a word of an encoded subject", b.cmd('UID SEARCH SUBJECT "lunch menu"')[0].split()[2:] == [str(e)])
    say("SEARCH HEADER finds a header's second occurrence", b.cmd("UID SEARCH HEADER X-Tag second")[0].split()[2:] == [str(e)])
    # An empty message, and one the storage lost
    r = b.append("INBOX", b"")
    z = int(re.search(r"APPENDUID \d+ (\d+)", r[-1]).group(1))
    r = b.cmd("UID FETCH %d (BODYSTRUCTURE)" % z)
    say("an empty message has a BODYSTRUCTURE", '("TEXT" "PLAIN"' in r[0].upper(), r)
    r = b.append("INBOX", msg("lost"))
    lost = int(re.search(r"APPENDUID \d+ (\d+)", r[-1]).group(1))
    print("lost-uid %d" % lost)
elif step == "lost":
    import urllib.request
    b = C(("bob", "bobpassword12")); b.cmd("SELECT INBOX")
    # Taken from the storage after SELECT listed the folder, as a disk that lost it would.
    req = urllib.request.Request("http://127.0.0.1:%d/mail/%s" % (storage_port, sys.argv[6]), method="DELETE")
    urllib.request.urlopen(req).read()
    r = b.cmd("UID FETCH %s (BODY.PEEK[])" % sys.argv[5])
    say("a message the storage lost is answered NO [UNAVAILABLE], not as empty", "[UNAVAILABLE]" in r[-1], r)
elif step == "quota":
    a = C(("alice", "alicepassword1")); a.cmd("SELECT INBOX")
    used = lambda: int(re.search(r"STORAGE (\d+)", "\n".join(a.cmd("GETQUOTAROOT INBOX"))).group(1))
    before = used()
    mail("alice@example.test", "From: x@else.test\r\nSubject: big\r\n\r\n" + ("q" * 76 + "\r\n") * 200)
    time.sleep(0.5)
    after = used()
    say("a delivery counts against the quota at once", after >= before + 14, (before, after))
    mail("alice@example.test", "From: x@else.test\r\nSubject: big2\r\n\r\n" + ("q" * 76 + "\r\n") * 200)
    time.sleep(0.5)
    a.cmd("CREATE Archive")
    a.cmd("SELECT INBOX")
    r = a.cmd("COPY 1:* Archive")
    st = a.cmd("STATUS Archive (MESSAGES)")
    say("a COPY past the quota says OVERQUOTA and leaves nothing behind", "[OVERQUOTA]" in r[-1] and "MESSAGES 0" in st[0], (r, st))
elif step == "copy":
    b = C(("bob", "bobpassword12"))
    b.cmd("CREATE Many"); b.cmd("CREATE Copied"); b.cmd("SELECT Many")
    for i in range(300):
        b.append("Many", msg("n%03d" % i))
    b.cmd("SELECT Many")
    r = b.cmd("UID COPY 1:* Copied")
    m = re.search(r"COPYUID \d+ (\S+) (\S+)\]", r[-1])
    b.cmd("SELECT Copied")
    subj = b.cmd("FETCH 1:* (BODY.PEEK[HEADER.FIELDS (SUBJECT)])")
    got = re.findall(r"Subject: (n\d+)", "\n".join(subj))
    say("a COPY of 300 keeps their order and says each UID", m is not None and m.group(1) == "1:300" and
        got == ["n%03d" % i for i in range(300)], (r[-1], got[:5]))
    # Another session appends while this one expunges.
    b.cmd("SELECT Many")
    o = C(("bob", "bobpassword12")); o.append("Many", msg("late"))
    r = b.cmd("EXPUNGE")
    r += b.cmd("NOOP")
    ex = [int(x.split()[1]) for x in r if x.endswith(" EXISTS")]
    say("an EXPUNGE tells what another session added meanwhile", ex and ex[-1] == 301, r)
elif step == "after":
    b = C(("bob", "bobpassword12")); b.cmd("SELECT INBOX")
    r = b.cmd("UID SEARCH KEYWORD project-x")
    say("a keyword is kept across a restart", len(r[0].split()) == 3, r)
PY

run() { timeout 120 python3 "$T/client.py" "$IM" "$P" "$PS" "$@" 2>&1; }
out=$(run first)
tally < <(grep -E '^(ok|bad) ' <<<"$out")
lost=$(sed -n 's/^lost-uid //p' <<<"$out")
key=
# The object of the message appended last, found by what it says.
for k in $(curl -s "http://127.0.0.1:$PS/mail?list-type=2&prefix=bob/INBOX/" | grep -o '<Key>[^<]*</Key>' | sed 's/<[^>]*>//g'); do
    [ "$(curl -s "http://127.0.0.1:$PS/mail/$k" | grep -c 'Subject: lost')" = 1 ] && key=$k
done
tally < <(run lost "$lost" "$key" | grep -E '^(ok|bad) ')
tally < <(run quota | grep -E '^(ok|bad) ')
tally < <(run copy | grep -E '^(ok|bad) ')
"$BIN" stop m >/dev/null 2>&1; "$BIN" start m >/dev/null 2>&1; ready_tcp 127.0.0.1 "$IM" >/dev/null
tally < <(run after | grep -E '^(ok|bad) ')

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || { echo "  FAILED"; exit 1; }
