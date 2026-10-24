#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a mailbox written out as mbox files and read back into another (socketley mail export and
# import), and a Google Takeout's mbox read into the folders its labels say.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * an export missing a folder or a message, its flags or keywords, or a "From " line in a body left unescaped
#   * an export over a directory that holds files already
#   * an import that loses a message's bytes, its folder, its flags or its keywords
#   * a Takeout's labels not making the folders, or its read and starred not the flags
#   * a file that is no mbox taken for one
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

daemon_isolate mail_transfer
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1940))
IM=$((SL_PORT_BASE+1941))
PI=$((SL_PORT_BASE+1942))
PS=$((SL_PORT_BASE+1943))
trap daemon_stop EXIT

echo "=== Integration: a mailbox exported as mbox and imported again ==="

daemon_start "$BIN"
printf 'spa - http://localhost:5173/cb\n' > "$T/clients"
"$BIN" create idp auth -p "$PI" --clients "$T/clients" --issuer "http://127.0.0.1:$PI" -s >/dev/null 2>&1
"$BIN" create storage st -p "$PS" --dir "$T/data" --anonymous -s >/dev/null 2>&1
for p in "$PI/jwks" "$PS/"; do
    for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p")" != 000 ] && break; sleep 0.1; done
done
for u in alice bob carol; do
    "$BIN" idp-user auth add "$u" --password "${u}password1" --email "$u@example.test" >/dev/null 2>&1
done
"$BIN" create mail m -p "$P" --mail-domain example.test --idp auth --storage st/mail --imap "$IM" -s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$IM" || bad "the IMAP port listens" "$(tail -3 "$SOCKETLEY_DLOG")"

# Alice's mailbox: three in the inbox, one of them with a "From " line in its body, and one in a folder of a folder,
# read, flagged and with a keyword.
python3 - "$P" "$PS" <<'PY'
import smtplib, sys, time, urllib.request
s = smtplib.SMTP("127.0.0.1", int(sys.argv[1])); s.ehlo("x")
for i, body in enumerate(["first", "From the start of a line\r\n>From quoted", "third"]):
    s.sendmail("zed@else.test", ["alice@example.test"], "From: zed@else.test\r\nTo: alice@example.test\r\n"
               "Subject: m%d\r\nMessage-ID: <m%d@else>\r\n\r\n%s\r\n" % (i, i, body))
    for _ in range(100):
        try:
            got = urllib.request.urlopen("http://127.0.0.1:%s/mail?list-type=2&prefix=alice/INBOX/" % sys.argv[2]).read()
            if got.count(b"<Key>") > i:
                break
        except Exception:
            pass
        time.sleep(0.05)
PY
python3 - "$IM" > "$T/setup.out" 2>&1 <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=10); f = s.makefile("rb"); f.readline()
n = 0
def cmd(t):
    global n
    n += 1; tag = "s%d" % n
    s.sendall(("%s %s\r\n" % (tag, t)).encode())
    while True:
        l = f.readline().decode()
        if l.startswith(tag + " "): return l
cmd("LOGIN alice alicepassword1")
cmd("CREATE Work/Projects")
lit = "Subject: plan\r\n\r\nthe plan\r\n"
print(cmd('APPEND Work/Projects (\\Seen \\Flagged $Label1) "02-Mar-2026 09:30:00 +0000" {%d+}\r\n%s' % (len(lit), lit)))
cmd("SELECT INBOX")
print(cmd("STORE 1 +FLAGS (\\Seen \\Answered)"))
PY

out=$("$BIN" mail m export alice "$T/out" 2>&1); rc=$?
case "$out" in "exported 4 messages of alice's "*" folders to $T/out") [ "$rc" -eq 0 ] && ok "export writes every message, and says where" \
    || bad "export's status" "rc $rc: $out" ;; *) bad "export" "rc $rc: $out" ;; esac
[ -f "$T/out/INBOX.mbox" ] && [ -f "$T/out/Work/Projects.mbox" ] && [ -f "$T/out/Trash.mbox" ] \
    && ok "a file a folder, a folder of a folder under a directory, an empty folder an empty file" \
    || bad "the files" "$(cd "$T/out" 2>/dev/null && find . -type f | sort | tr '\n' ' ')"
[ "$(grep -c '^From ' "$T/out/INBOX.mbox")" = 3 ] && grep -qx '>From the start of a line' "$T/out/INBOX.mbox" \
    && grep -qx '>>From quoted' "$T/out/INBOX.mbox" && ok "a body's From lines are given a '>' more" \
    || bad "the escaping" "$(grep -n 'From' "$T/out/INBOX.mbox")"
head -3 "$T/out/INBOX.mbox" | grep -qx 'Status: RO' && head -4 "$T/out/INBOX.mbox" | grep -qx 'X-Status: A' \
    && ok "the flags go as Status and X-Status" || bad "the flags" "$(head -5 "$T/out/INBOX.mbox")"
case "$(head -4 "$T/out/Work/Projects.mbox")" in "From MAILER-DAEMON Mon Mar  2 09:30:00 2026"*"X-Status: F"*"X-Keywords: \$Label1"*) \
    ok "and the date and the keywords" ;; *) bad "the date and keywords" "$(head -5 "$T/out/Work/Projects.mbox")" ;; esac
[ "$(stat -c %a "$T/out")" = 700 ] && ok "the directory is the daemon's alone" || bad "the directory's mode" "$(stat -c %a "$T/out")"
out=$("$BIN" mail m export alice "$T/out" 2>&1); rc=$?
[ "$rc" -eq 1 ] && case "$out" in *"holds files already"*) true ;; *) false ;; esac && ok "an export over files is refused" \
    || bad "an export over files" "rc $rc: $out"

out=$("$BIN" mail m import bob "$T/out" 2>&1); rc=$?
[ "$rc" -eq 0 ] && [ "$out" = "imported 4 messages into bob's mailbox" ] && ok "import reads every file of the directory" \
    || bad "import" "rc $rc: $out"

# Takeout: one file, the folder in each message's labels.
python3 - "$T/takeout.mbox" <<'PY'
import sys
m = lambda labels, subj: ("From 1234@xxx Mon Oct 19 10:00:00 +0000 2026\r\nX-GM-THRID: 1\r\nX-Gmail-Labels: %s\r\n"
                          "From: someone@else.test\r\nSubject: %s\r\n\r\nabout %s\r\n\r\n") % (labels, subj, subj)
open(sys.argv[1], "w", newline="").write(m("Inbox,Opened", "read one") + m("Spam,Unread", "spam one") +
                                         m("Clients,Starred,Opened,Important", "client one"))
PY
out=$("$BIN" mail m import carol "$T/takeout.mbox" 2>&1); rc=$?
[ "$rc" -eq 0 ] && [ "$out" = "imported 3 messages into carol's mailbox" ] && ok "a Takeout's mbox is imported" || bad "the Takeout" "rc $rc: $out"
printf 'just text\n' > "$T/notes.mbox"
out=$("$BIN" mail m import carol "$T/notes.mbox" 2>&1); rc=$?
[ "$rc" -eq 1 ] && case "$out" in *"is no mbox"*) true ;; *) false ;; esac && ok "a file that is no mbox is refused" \
    || bad "a file that is no mbox" "rc $rc: $out"
out=$("$BIN" mail m import carol 2>&1); rc=$?
[ "$rc" -eq 1 ] && case "$out" in *"usage:"*) true ;; *) false ;; esac && ok "import without a path is told its usage" \
    || bad "import's usage" "rc $rc: $out"

python3 - "$IM" > "$T/check.out" 2>&1 <<'PY'
import re, socket, sys
port = int(sys.argv[1])
def say(name, cond, why=""):
    print(("ok " if cond else "bad ") + name + ("" if cond else ": " + str(why)[:600]))
class C:
    def __init__(self, user):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=10); self.f = self.s.makefile("rb"); self.n = 0
        self.f.readline(); self.cmd("LOGIN %s %spassword1" % (user, user))
    def cmd(self, text):
        self.n += 1; tag = "t%d" % self.n
        self.s.sendall(("%s %s\r\n" % (tag, text)).encode())
        out = b""
        while True:
            l = self.f.readline()
            out += l
            m = re.search(rb"\{(\d+)\}\r\n$", l)
            if m: out += self.f.read(int(m.group(1)))
            if l.startswith((tag + " ").encode()): return out.decode(errors="replace")
def bodies(c, folder):
    c.cmd('SELECT "%s"' % folder)
    r = c.cmd("FETCH 1:* (FLAGS BODY.PEEK[])")
    return r
a, b, k = C("alice"), C("bob"), C("carol")
for folder in ["INBOX", "Work/Projects"]:
    ra, rb = bodies(a, folder), bodies(b, folder)
    strip = lambda r: re.sub(r"\* \d+ FETCH \(FLAGS \([^)]*\) ", "", r).rsplit("\r\nt", 1)[0]
    say("bob's %s holds alice's messages, byte for byte" % folder, strip(ra) == strip(rb) and "BODY[]" in ra, (ra[:300], rb[:300]))
    fa = re.findall(r"FLAGS \(([^)]*)\)", ra); fb = re.findall(r"FLAGS \(([^)]*)\)", rb)
    say("and their flags and keywords", sorted(map(lambda x: sorted(x.split()), fa)) == sorted(map(lambda x: sorted(x.split()), fb)), (fa, fb))
r = k.cmd('LIST "" "*"')
say("the labels made the folders", '"Clients"' in r and '"Junk"' in r, r)
r = k.cmd("SELECT INBOX"); r = k.cmd("FETCH 1:* (FLAGS BODY.PEEK[HEADER.FIELDS (SUBJECT X-GMAIL-LABELS)])")
say("a read one in the inbox, read, its labels' header taken out", "Subject: read one" in r and "\\Seen" in r and
    "X-Gmail-Labels" not in r, r)
k.cmd("SELECT Junk"); r = k.cmd("FETCH 1:* (FLAGS BODY.PEEK[HEADER.FIELDS (SUBJECT)])")
say("spam in Junk, unread", "Subject: spam one" in r and "\\Seen" not in r, r)
k.cmd("SELECT Clients"); r = k.cmd("FETCH 1:* (FLAGS INTERNALDATE)")
say("a label of the user's its folder, starred flagged, the date the From line's", "\\Flagged" in r and
    '19-Oct-2026 10:00:00 +0000' in r, r)
PY
while read -r verdict name; do
    case "$verdict" in ok) ok "$name" ;; bad) bad "${name%%:*}" "${name#*:}" ;; esac
done < <(grep -E '^(ok|bad) ' "$T/check.out" || echo "bad the client ran: $(tail -5 "$T/check.out")")

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
