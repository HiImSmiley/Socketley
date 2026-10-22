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
#   * MULTIAPPEND taking part of what it was given, or not saying every UID
#   * a UTF-8 folder name under UTF8=ACCEPT kept as other than modified UTF-7, or a literal8 message refused
#   * RENAME leaving the folders under it behind, or RENAME INBOX refused or leaving its messages
#   * CREATE taking a special use its name does not have
#   * a MAILBOXID a RENAME changes, an EMAILID SEARCH cannot find
#   * METADATA not kept, not kept across a restart, or past its bounds; DEPTH and MAXSIZE not followed
#   * imapsieve not run for what a client APPENDs or COPYs into a folder that names a script, or its fileinto,
#     discard and addflag not done there
#   * BINARY giving a part still encoded, a NUL in a plain literal, or an encoding it cannot undo answered OK
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
elif step == "ext":
    b = C(("bob", "bobpassword12"))
    caps = b.cmd("CAPABILITY")[0].split()
    say("CAPABILITY offers MULTIAPPEND, UTF8=ACCEPT, CREATE-SPECIAL-USE and APPENDLIMIT",
        all(c in caps for c in ("MULTIAPPEND", "UTF8=ACCEPT", "CREATE-SPECIAL-USE")) and any(c.startswith("APPENDLIMIT=") for c in caps), caps)
    r = b.cmd("STATUS INBOX (APPENDLIMIT)")
    say("STATUS answers APPENDLIMIT", re.search(r"APPENDLIMIT \d+", r[0]) is not None, r)
    b.cmd("CREATE Multi")
    m1, m2 = msg("multi one"), msg("multi two")
    r = b.send(("APPEND Multi (\\Seen) {%d+}\r\n" % len(m1)).encode() + m1 + (" {%d+}\r\n" % len(m2)).encode() + m2 + b"\r\n")
    st = b.cmd("STATUS Multi (MESSAGES)")
    say("MULTIAPPEND puts both in and says both UIDs", re.search(r"APPENDUID \d+ 1:2\]", r[-1]) is not None and "MESSAGES 2" in st[0], (r, st))
    r = b.cmd("CREATE Foo (USE (\\Sent))")
    say("CREATE with a special use the name does not have says USEATTR", "[USEATTR]" in r[-1], r)
    r = b.cmd("ENABLE UTF8=ACCEPT")
    say("ENABLE UTF8=ACCEPT is enabled", any(x == "* ENABLED UTF8=ACCEPT" for x in r), r)
    r = b.send('CREATE "Entwürfe-ä"\r\n'.encode())
    say("and a folder is made under its UTF-8 name", r[-1].split()[1] == "OK", r)
    r = b.cmd('LIST "" "Entw*"')
    say("which LIST says in UTF-8 to it", any("Entwürfe-ä" in x for x in r), r)
    r = C(("bob", "bobpassword12")).cmd('LIST "" "Entw*"')
    say("and in modified UTF-7 to a client that did not enable it", any("Entw&APw-rfe-&AOQ-" in x for x in r), r)
    m3 = "From: x@else.test\r\nSubject: Grüße\r\n\r\nüber\r\n".encode()
    r = b.send(("APPEND INBOX UTF8 (~{%d+}\r\n" % len(m3)).encode() + m3 + b")\r\n")
    say("APPEND takes a message as UTF8 (~{n}...)", r[-1].split()[1] == "OK" and "APPENDUID" in r[-1], r)
    raw = bytes(range(256))
    m4 = ("From: x@else.test\r\nSubject: bin\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=zz\r\n\r\n"
          "--zz\r\nContent-Type: text/plain\r\n\r\nhi\r\n--zz\r\nContent-Type: application/octet-stream\r\n"
          "Content-Transfer-Encoding: base64\r\n\r\n%s\r\n--zz\r\nContent-Type: text/plain\r\n"
          "Content-Transfer-Encoding: x-uuencode\r\n\r\nbegin 644 x\r\n--zz--\r\n" % base64.b64encode(raw).decode()).encode()
    r = b.send(("APPEND INBOX {%d+}\r\n" % len(m4)).encode() + m4 + b"\r\n")
    u4 = int(re.search(r"APPENDUID \d+ (\d+)", r[-1]).group(1))
    b.cmd("SELECT INBOX")
    b.s.sendall(b"bin1 UID FETCH %d (BINARY.SIZE[2] BINARY.PEEK[2])\r\n" % u4)
    got = b""
    while True:
        got += b.s.recv(65536)
        i = got.find(b"\r\nbin1 ")
        if i >= 0 and got.find(b"\r\n", i + 2) >= 0:
            break
    say("BINARY.SIZE says a base64 part's size decoded", b"BINARY.SIZE[2] 256" in got, got[:200])
    say("and BINARY gives its bytes decoded, as a literal8 since a NUL is among them", b"BINARY[2] ~{256}\r\n" + raw in got, got[:200])
    r = b.cmd("UID FETCH %d (BINARY.PEEK[3])" % u4)
    say("a part of an encoding none decodes is NO [UNKNOWN-CTE]", "[UNKNOWN-CTE]" in r[-1], r)
    r = b.cmd("UID FETCH %d (EMAILID THREADID)" % u4)
    eid = re.search(r"EMAILID \((\w+)\)", r[0])
    say("FETCH gives an EMAILID and a THREADID of NIL", eid is not None and "THREADID NIL" in r[0], r)
    r = b.cmd("UID SEARCH EMAILID %s" % (eid.group(1) if eid else "x"))
    say("and SEARCH EMAILID finds that message alone", r[0].split()[2:] == [str(u4)], r)
    b.cmd("CREATE Work/2026/Q1")
    before = re.search(r"MAILBOXID \((\w+)\)", b.cmd("STATUS Work/2026 (MAILBOXID)")[0])
    sel = b.cmd("SELECT Work")
    say("SELECT says the folder's MAILBOXID", any("[MAILBOXID (" in x for x in sel), sel)
    r = b.cmd("RENAME Work Job")
    l = b.cmd('LIST "" "*"')
    names = [x.rsplit(" ", 1)[1].strip('"') for x in l if x.startswith("* LIST")]
    say("RENAME takes the folders under it along", r[-1].split()[1] == "OK" and "Job/2026" in names and "Job/2026/Q1" in names
        and not any(n.startswith("Work") for n in names), (r, names))
    after = re.search(r"MAILBOXID \((\w+)\)", b.cmd("STATUS Job/2026 (MAILBOXID)")[0])
    say("and each keeps its MAILBOXID", before is not None and after is not None and before.group(1) == after.group(1), (before, after))
    a = C(("alice", "alicepassword1"))
    n = int(re.search(r"MESSAGES (\d+)", a.cmd("STATUS INBOX (MESSAGES)")[0]).group(1))
    r = a.cmd("RENAME INBOX Old")
    s1, s2 = a.cmd("STATUS Old (MESSAGES)")[0], a.cmd("STATUS INBOX (MESSAGES)")[0]
    say("RENAME INBOX moves its messages and leaves it empty", n > 0 and r[-1].split()[1] == "OK" and
        "MESSAGES %d" % n in s1 and "MESSAGES 0" in s2, (n, r, s1, s2))
    a.cmd("CREATE Atom")
    small, big = msg("small"), msg("big", body="z" * 60000 + "\r\n")
    r = a.send(("APPEND Atom {%d+}\r\n" % len(small)).encode() + small + (" {%d+}\r\n" % len(big)).encode() + big + b"\r\n")
    st = a.cmd("STATUS Atom (MESSAGES)")
    say("a MULTIAPPEND one of which is refused puts none of them in", "[OVERQUOTA]" in r[-1] and "MESSAGES 0" in st[0], (r, st))
elif step == "meta":
    b = C(("bob", "bobpassword12"))
    say("CAPABILITY offers METADATA", "METADATA" in b.cmd("CAPABILITY")[0].split())
    r = b.cmd('SETMETADATA "" (/private/comment "hello there")')
    g = b.cmd('GETMETADATA "" /private/comment')
    say("a server entry is set and read back", r[-1].split()[1] == "OK" and any('/private/comment "hello there"' in x for x in g), (r, g))
    b.cmd('SETMETADATA INBOX (/shared/comment "inbox note" /shared/vendor/x/y "deep")')
    g = b.cmd("GETMETADATA (DEPTH infinity) INBOX /shared")
    say("DEPTH infinity gives every entry under a name", any("/shared/comment" in x and "/shared/vendor/x/y" in x for x in g), g)
    g = b.cmd("GETMETADATA (DEPTH 1) INBOX /shared")
    say("and DEPTH 1 those one level down", any("/shared/comment" in x and "/shared/vendor/x/y" not in x for x in g), g)
    g = b.cmd("GETMETADATA (MAXSIZE 3) \"\" /private/comment")
    say("an entry past MAXSIZE is left out and said LONGENTRIES", "[METADATA LONGENTRIES 11]" in g[-1] and not g[0].startswith("* METADATA"), g)
    b.cmd("SETMETADATA INBOX (/shared/comment NIL)")
    g = b.cmd("GETMETADATA INBOX /shared/comment")
    say("NIL takes an entry away", any("/shared/comment NIL" in x for x in g), g)
    r = b.cmd('SETMETADATA Nowhere (/shared/comment "x")')
    say("an entry of a folder not there is refused", "[NONEXISTENT]" in r[-1], r)
    r = b.cmd('SETMETADATA INBOX (/other/comment "x")')
    say("and one not under /private or /shared", r[-1].split()[1] == "BAD", r)
    # imapsieve
    b.cmd("CREATE Filtered")
    r = b.cmd('SETMETADATA Filtered (/shared/imapsieve/script "onfile")')
    for subject in ("to-archive", "flag-me", "drop-me"):
        b.append("Filtered", msg(subject))
    b.cmd("SELECT INBOX")
    b.append("INBOX", msg("copied-one"))
    b.cmd("SELECT INBOX")
    uidc = int(b.cmd("UID SEARCH SUBJECT copied-one")[0].split()[-1])
    b.cmd("UID COPY %d Filtered" % uidc)
    time.sleep(1.5)
    st = b.cmd("STATUS Archive2 (MESSAGES)")
    say("imapsieve files what a client put into its folder where the script says", "MESSAGES 1" in st[0], st)
    b.cmd("SELECT Filtered")
    lines = b.cmd("FETCH 1:* (FLAGS BODY.PEEK[HEADER.FIELDS (SUBJECT)])")
    say("and takes it out of the folder, and what it discards", not any("to-archive" in x or "drop-me" in x for x in lines), lines)
    say("and sets the flags it adds", any("flag-me" in x and "\\Flagged" in x for x in lines), lines)
    say("and runs for a COPY into it too, with cause COPY", any("copied-one" in x and "$Copied" in x for x in lines), lines)
elif step == "after":
    b = C(("bob", "bobpassword12")); b.cmd("SELECT INBOX")
    r = b.cmd("UID SEARCH KEYWORD project-x")
    say("a keyword is kept across a restart", len(r[0].split()) == 3, r)
    g = b.cmd('GETMETADATA "" /private/comment')
    say("and METADATA too", any('"hello there"' in x for x in g), g)
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
tally < <(run ext | grep -E '^(ok|bad) ')
cat > "$T/onfile.sieve" <<'SV'
require ["imapsieve", "environment", "fileinto", "imap4flags", "mailbox"];
if environment :is "imap.cause" "APPEND" {
    if header :contains "subject" "to-archive" { fileinto :create "Archive2"; }
    elsif header :contains "subject" "flag-me" { addflag "\\Flagged"; }
    elsif header :contains "subject" "drop-me" { discard; }
}
if environment :is "imap.cause" "COPY" { addflag "$Copied"; }
SV
out=$("$BIN" mail m sieve bob put onfile "$T/onfile.sieve" 2>&1) || bad "the imapsieve script is put" "$out"
tally < <(run meta | grep -E '^(ok|bad) ')
"$BIN" stop m >/dev/null 2>&1; "$BIN" start m >/dev/null 2>&1; ready_tcp 127.0.0.1 "$IM" >/dev/null
tally < <(run after | grep -E '^(ok|bad) ')

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || { echo "  FAILED"; exit 1; }
