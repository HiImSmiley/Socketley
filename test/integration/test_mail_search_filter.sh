#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: IMAP SEARCH and JMAP's text filters find the same messages, decoded, whether a message's trigram
# filter rules it out or it is read, on two shards, after a restart and past a damaged filter file.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a search that a filter answers differently from one that reads every message, NOT and OR included
#   * a word split by a quoted-printable soft break, or in a base64 text part, not found
#   * what only an attachment holds found as if it were text, decoded or as written
#   * no filter file kept for the next search, or one a restart or a damaged record makes a search answer wrongly
#   * the kept filters not found by the messages they are for after a restart, so a search reads every message again
#   * a message delivered or APPENDed without its filter, so the first search reads it to make one
#   * JMAP's text or body filter reading the message as written, or answering otherwise than IMAP
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ready.sh"

command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
tally() { while read -r verdict rest; do [ "$verdict" = ok ] && ok "$rest" || bad "${rest%%: *}" "${rest#*: }"; done; }

daemon_isolate mail_search_filter
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1940))
IM=$((SL_PORT_BASE+1941))
JM=$((SL_PORT_BASE+1942))
PI=$((SL_PORT_BASE+1943))
PS=$((SL_PORT_BASE+1944))
trap daemon_stop EXIT

echo "=== Integration: search through trigram filters finds what reading every message finds ==="

daemon_start "$BIN"
printf 'spa - http://localhost:5173/cb\n' > "$T/clients"
"$BIN" create idp auth -p "$PI" --clients "$T/clients" --issuer "http://127.0.0.1:$PI" -s >/dev/null 2>&1
"$BIN" create storage st -p "$PS" --dir "$T/data" --anonymous -s >/dev/null 2>&1
for p in "$PI/jwks" "$PS/"; do
    for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p")" != 000 ] && break; sleep 0.1; done
done
"$BIN" idp-user auth add alice --password alicepassword1 --email alice@example.test >/dev/null 2>&1
"$BIN" create mail m -p "$P" --mail-domain example.test --idp auth --storage st/mail --imap "$IM" --jmap "$JM" \
    --shards 2 -s >/dev/null 2>&1
for p in "$P" "$IM" "$JM"; do ready_tcp 127.0.0.1 "$p" || bad "port $p listens" "$(tail -3 "$SOCKETLEY_DLOG")"; done

LATIN=$(printf 'Ein Zebrafish und sch\xf6ne G\xe4ste' | base64)
python3 - "$P" "$LATIN" <<'PY'
import smtplib, sys
s = smtplib.SMTP("127.0.0.1", int(sys.argv[1])); s.ehlo("x")
def send(subject, body, extra=""):
    s.sendmail("carol@else.test", ["alice@example.test"],
        "From: Carol <carol@else.test>\r\nTo: alice@example.test\r\nSubject: %s\r\nMessage-ID: <%s@else.test>\r\n"
        "Date: Tue, 20 Oct 2026 10:00:00 +0200\r\nMIME-Version: 1.0\r\n%s\r\n%s" % (subject, subject.replace(" ", "."), extra, body))
send("quoted", "the long word is extraordin=\r\narily split\r\n",
     "Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n")
send("latin", sys.argv[2] + "\r\n", "Content-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: base64\r\n")
send("attached", "--b\r\nContent-Type: text/plain\r\n\r\nsee the file\r\n--b\r\nContent-Type: application/octet-stream\r\n"
     "Content-Transfer-Encoding: base64\r\n\r\nc2VjcmV0aW5zaWRldGhlYXR0YWNobWVudA==\r\n--b--\r\n",
     "Content-Type: multipart/mixed; boundary=b\r\n")
send("plain", "a needle in a haystack\r\n")
for i in range(40):
    s.sendmail("dave@else.test", ["alice@example.test"],
        "From: dave@else.test\r\nTo: alice@example.test\r\nSubject: filler %d\r\n\r\nnothing much in number %d\r\n" % (i, i))
PY
for _ in $(seq 1 100); do [ "$(curl -s "http://127.0.0.1:$PS/mail?list-type=2&prefix=alice/INBOX/" | grep -c '<Key>')" -ge 44 ] && break; sleep 0.1; done

cat > "$T/search.py" <<'PY'
import base64, http.client, imaplib, json, sys
im, jm, label = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
def say(name, cond, why=""):
    print(("ok " if cond else "bad ") + label + ": " + name + ("" if cond else ": " + str(why)[:400]))
M = imaplib.IMAP4("127.0.0.1", im); M.login("alice", "alicepassword1"); M.select("INBOX")
def subjects(*crit):
    typ, data = M.uid("SEARCH", *crit)
    uids = data[0].split()
    if not uids:
        return []
    typ, d = M.uid("FETCH", b",".join(uids), "(BODY.PEEK[HEADER.FIELDS (SUBJECT)])")
    return sorted(x[1].decode().split(":", 1)[1].strip() for x in d if isinstance(x, tuple))
say("BODY finds a word a soft break splits", subjects("BODY", "extraordinarily") == ["quoted"], subjects("BODY", "extraordinarily"))
say("BODY finds a word in a base64 Latin-1 part", subjects("BODY", "zebrafish") == ["latin"], subjects("BODY", "zebrafish"))
say("TEXT does not find what only an attachment holds", subjects("TEXT", "secretinside") == [], subjects("TEXT", "secretinside"))
say("TEXT does not find an attachment's base64 as written", subjects("TEXT", "c2VjcmV0aW5z") == [], subjects("TEXT", "c2VjcmV0aW5z"))
say("BODY finds plain text", subjects("BODY", "haystack") == ["plain"], subjects("BODY", "haystack"))
say("TEXT finds a header's text", len(subjects("TEXT", "carol@else")) == 4, subjects("TEXT", "carol@else"))
say("NOT BODY leaves the rest", len(subjects("NOT", "BODY", "zebrafish")) == 43, len(subjects("NOT", "BODY", "zebrafish")))
say("OR finds either", subjects("OR", "BODY", "zebrafish", "BODY", "haystack") == ["latin", "plain"],
    subjects("OR", "BODY", "zebrafish", "BODY", "haystack"))
say("a word nowhere is found nowhere", subjects("BODY", "xylophonic") == [], subjects("BODY", "xylophonic"))
AUTH = "Basic " + base64.b64encode(b"alice:alicepassword1").decode()
def jcall(calls):
    c = http.client.HTTPConnection("127.0.0.1", jm, timeout=20)
    c.request("POST", "/jmap/api", json.dumps({"using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
              "methodCalls": calls}).encode(), {"Authorization": AUTH, "Content-Type": "application/json"})
    return json.loads(c.getresponse().read())["methodResponses"]
c = http.client.HTTPConnection("127.0.0.1", jm, timeout=20)
c.request("GET", "/.well-known/jmap", headers={"Authorization": AUTH}); acct = json.loads(c.getresponse().read())["primaryAccounts"]["urn:ietf:params:jmap:mail"]
def jsubjects(flt):
    r = jcall([["Email/query", {"accountId": acct, "filter": flt}, "q"],
               ["Email/get", {"accountId": acct, "#ids": {"resultOf": "q", "name": "Email/query", "path": "/ids"},
                              "properties": ["subject"]}, "g"]])
    return sorted(x["subject"] for x in r[1][1]["list"])
say("JMAP text finds a word a soft break splits", jsubjects({"text": "extraordinarily"}) == ["quoted"], jsubjects({"text": "extraordinarily"}))
say("JMAP body finds a word in a base64 Latin-1 part", jsubjects({"body": "zebrafish"}) == ["latin"], jsubjects({"body": "zebrafish"}))
say("JMAP text does not find what only an attachment holds", jsubjects({"text": "secretinside"}) == [], jsubjects({"text": "secretinside"}))
say("JMAP's NOT leaves the rest, the five notes too", len(jsubjects({"operator": "NOT", "conditions": [{"body": "zebrafish"}]})) == 48,
    len(jsubjects({"operator": "NOT", "conditions": [{"body": "zebrafish"}]})))
PY

# A shard's figures reach the daemon a quarter of a second after they change, so each read waits a little longer.
touched() { sleep 1.5; "$BIN" stats m 2>/dev/null | awk -F: '/^imap_(reads|cache_hits):/ {n += $2} END {print n + 0}'; }
# Mail delivered or APPENDed is given its filter as it is stored, so even the first search touches none of it; the
# filters reach the other shard through the file, written at the next tick.
python3 - "$IM" <<'PY' >/dev/null 2>&1
import imaplib, sys
M = imaplib.IMAP4("127.0.0.1", int(sys.argv[1])); M.login("alice", "alicepassword1"); M.create("Notes")
for i in range(5):
    M.append("Notes", None, None, ("From: alice@example.test\r\nSubject: note %d\r\n\r\na note of mine, %d\r\n" % (i, i)).encode())
PY
sleep 3
T0=$(touched)
HITS=$(python3 - "$IM" 2>&1 <<'PY'
import imaplib, sys
M = imaplib.IMAP4("127.0.0.1", int(sys.argv[1])); M.login("alice", "alicepassword1")
n = []
for box in ("INBOX", "Notes"):
    M.select(box); n.append(len(M.uid("SEARCH", "BODY", "xylophonic")[1][0].split()))
print(" ".join(map(str, n)))
PY
)
T1=$(touched)
if [ "$HITS" = "0 0" ] && [ "$T1" = "$T0" ]; then ok "the first search touches no message delivered or APPENDed"
else bad "the first search touches no message delivered or APPENDed" "found $HITS, touched $((T1 - T0))"; fi
tally < <(python3 "$T/search.py" "$IM" "$JM" "first" 2>&1)
# The filters a search made are written at the store's next tick.
sleep 3
FTS=$(find "$T" -name 'alice.fts' 2>/dev/null | head -1)
if [ -n "$FTS" ] && [ "$(stat -c %s "$FTS")" -gt 1000 ]; then ok "the filters are kept in a file every shard reads"
else bad "the filters are kept in a file every shard reads" "${FTS:-no alice.fts under $T}"; fi
tally < <(python3 "$T/search.py" "$IM" "$JM" "again, through the filters" 2>&1)

"$BIN" stop m >/dev/null 2>&1; "$BIN" start m >/dev/null 2>&1
for p in "$IM" "$JM"; do ready_tcp 127.0.0.1 "$p" || bad "port $p listens again" "$(tail -3 "$SOCKETLEY_DLOG")"; done
# The first search after the restart has every message ruled out by the filters the file kept, and touches none.
T0=$(touched)
HITS=$(python3 - "$IM" 2>&1 <<'PY'
import imaplib, sys
M = imaplib.IMAP4("127.0.0.1", int(sys.argv[1])); M.login("alice", "alicepassword1"); M.select("INBOX")
print(len(M.uid("SEARCH", "BODY", "xylophonic")[1][0].split()))
PY
)
T1=$(touched)
if [ "$HITS" = 0 ] && [ "$T0" = 0 ] && [ "$T1" = 0 ]; then ok "a search after a restart touches no message its kept filter rules out"
else bad "a search after a restart touches no message its kept filter rules out" "found $HITS, touched $T0 then $T1"; fi
tally < <(python3 "$T/search.py" "$IM" "$JM" "after a restart" 2>&1)

# A record torn in the middle of the file and garbage at its end are passed over.
if [ -n "$FTS" ]; then
    python3 - "$FTS" <<'PY'
import sys
p = sys.argv[1]; b = bytearray(open(p, "rb").read())
b[len(b) // 2] ^= 0xFF
open(p, "wb").write(bytes(b) + b"SKFT\xff\xff\x00\x00garbage")
PY
fi
# Read from its start again by a runtime started anew.
"$BIN" stop m >/dev/null 2>&1; "$BIN" start m >/dev/null 2>&1
for p in "$IM" "$JM"; do ready_tcp 127.0.0.1 "$p" || bad "port $p listens again" "$(tail -3 "$SOCKETLEY_DLOG")"; done
tally < <(python3 "$T/search.py" "$IM" "$JM" "past a damaged file" 2>&1)

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && [ "$TOTAL" -eq 55 ] || exit 1
