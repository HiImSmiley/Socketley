#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a mail runtime's JMAP (RFC 8620, RFC 8621), as a web client reads, files, writes and sends mail
# with it, and what it does seen over IMAP at once.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * the session resource missing, unauthenticated, or naming no account and no API
#   * Mailbox/get or query not giving the INBOX its role and counts, Mailbox/set not making a folder IMAP sees
#   * Email/query not finding by mailbox, keyword or text, or its back-reference not feeding Email/get
#   * Email/get without the header, preview, body values or attachments a client shows
#   * a keyword JMAP sets not a flag IMAP reads, a move changing an Email's id, a destroy leaving it
#   * an upload not imported, an attachment part not downloaded whole
#   * Email/set create and EmailSubmission/set not sending the draft, or not filing it in Sent after
#   * */changes on the current state not empty, on an old one not cannotCalculateChanges
#   * an EventSource not told of new mail
#   * a password taken in the clear from another machine
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

daemon_isolate mail_jmap
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1920))
IM=$((SL_PORT_BASE+1921))
JM=$((SL_PORT_BASE+1922))
PI=$((SL_PORT_BASE+1923))
PS=$((SL_PORT_BASE+1924))
NS=$((SL_PORT_BASE+1925))
SINK=$((SL_PORT_BASE+1926))
PIDS=()
cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: JMAP on a mail runtime's mailboxes ==="

python3 "$HERE/lib_fake_dns.py" "$NS" 0 normal remote.test=MX:10:mx.remote.test mx.remote.test=127.0.0.1 >/dev/null 2>&1 &
PIDS+=($!)
printf 'nameserver 127.0.0.1\noptions timeout:1 attempts:1 port:%s\n' "$NS" > "$T/resolv.conf"
export SOCKETLEY_RESOLV_CONF="$T/resolv.conf" SOCKETLEY_MAIL_MX_PORT="$SINK"
mkdir -p "$T/sink"
python3 "$HERE/lib_smtp_sink.py" "$SINK" "$T/sink" >/dev/null 2>&1 &
PIDS+=($!)
ready_tcp 127.0.0.1 "$SINK" || bad "the sink listens" "-"

daemon_start "$BIN"
printf 'spa - http://localhost:5173/cb\n' > "$T/clients"
"$BIN" create idp auth -p "$PI" --clients "$T/clients" --issuer "http://127.0.0.1:$PI" -s >/dev/null 2>&1
"$BIN" create storage st -p "$PS" --dir "$T/data" --anonymous -s >/dev/null 2>&1
for p in "$PI/jwks" "$PS/"; do
    for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p")" != 000 ] && break; sleep 0.1; done
done
"$BIN" idp-user auth add alice --password alicepassword1 --email alice@example.test >/dev/null 2>&1
"$BIN" create mail m -p "$P" --mail-domain example.test --idp auth --storage st/mail --imap "$IM" --jmap "$JM" -s \
    >/dev/null 2>&1
for p in "$P" "$IM" "$JM"; do ready_tcp 127.0.0.1 "$p" || bad "port $p listens" "$(tail -3 "$SOCKETLEY_DLOG")"; done

python3 - "$P" <<'PY'
import smtplib, sys
s = smtplib.SMTP("127.0.0.1", int(sys.argv[1])); s.ehlo("x")
s.sendmail("carol@else.test", ["alice@example.test"],
    "From: Carol <carol@else.test>\r\nTo: alice@example.test\r\nSubject: first one\r\nMessage-ID: <one@else.test>\r\n"
    "Date: Tue, 20 Oct 2026 10:00:00 +0200\r\n\r\nhello with a needle in it\r\n")
s.sendmail("dave@else.test", ["alice@example.test"],
    "From: dave@else.test\r\nTo: alice@example.test\r\nSubject: with a file\r\nMIME-Version: 1.0\r\n"
    "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nsee the file\r\n"
    "--b\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=x.bin\r\n"
    "Content-Transfer-Encoding: base64\r\n\r\nAAECAwQF\r\n--b--\r\n")
PY
for _ in $(seq 1 100); do [ "$(curl -s "http://127.0.0.1:$PS/mail?list-type=2&prefix=alice/INBOX/" | grep -c '<Key>')" -ge 2 ] && break; sleep 0.1; done

cat > "$T/client.py" <<'PY'
import base64, http.client, imaplib, json, os, socket, sys, time, traceback
def crashed(kind, value, tb):
    print("bad the client ran to its end: " + repr(value) + " at " + "|".join(traceback.format_tb(tb)[-2:]).replace("\n", " "))
sys.excepthook = crashed
jm, im, sink = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
AUTH = "Basic " + base64.b64encode(b"alice:alicepassword1").decode()
def say(name, cond, why=""):
    print(("ok " if cond else "bad ") + name + ("" if cond else ": " + str(why)[:700]))
def call(method, path, body=None, headers=None, auth=AUTH, source=None):
    c = http.client.HTTPConnection("127.0.0.1", jm, timeout=20, source_address=(source, 0) if source else None)
    h = dict(headers or {})
    if auth: h["Authorization"] = auth
    if body is not None and not isinstance(body, (bytes, bytearray)): body = json.dumps(body).encode(); h["Content-Type"] = "application/json"
    c.request(method, path, body=body, headers=h)
    r = c.getresponse(); data = r.read(); c.close()
    return r.status, r.getheader("WWW-Authenticate"), data
st, www, _ = call("GET", "/.well-known/jmap", auth=None)
say("the session resource needs credentials", st == 401 and www and "Basic" in www, (st, www))
st, _, data = call("GET", "/.well-known/jmap")
s = json.loads(data) if st == 200 else {}
acct = s.get("primaryAccounts", {}).get("urn:ietf:params:jmap:mail")
say("the session names the account and the API", st == 200 and acct in s.get("accounts", {}) and s.get("apiUrl", "").endswith("/jmap/api"), data[:300])
USING = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:submission"]
def api(*calls):
    st, _, data = call("POST", "/jmap/api", {"using": USING, "methodCalls": [list(c) for c in calls]})
    if st != 200: return {"_status": st, "_body": data.decode(errors="replace")}
    out = {}
    for name, args, cid in json.loads(data)["methodResponses"]:
        out.setdefault(cid, []).append((name, args))
    return out
r = api(["Mailbox/get", {"accountId": acct, "ids": None}, "m"])
boxes = {b["role"] or b["name"]: b for b in r["m"][0][1]["list"]}
inbox = boxes.get("inbox", {})
say("Mailbox/get gives the INBOX its role and counts", inbox.get("totalEmails") == 2 and inbox.get("unreadEmails") == 2, r)
say("and the folders every mailbox has", all(k in boxes for k in ("sent", "drafts", "trash", "junk")), list(boxes))
r = api(["Mailbox/query", {"accountId": acct, "filter": {"role": "inbox"}}, "q"])
say("Mailbox/query finds a folder by its role", r["q"][0][1]["ids"] == [inbox.get("id")], r)
r = api(["Email/query", {"accountId": acct, "filter": {"inMailbox": inbox["id"]}, "sort": [{"property": "receivedAt", "isAscending": False}]}, "q"],
        ["Email/get", {"accountId": acct, "#ids": {"resultOf": "q", "name": "Email/query", "path": "/ids"},
                       "properties": ["subject", "from", "preview", "hasAttachment", "textBody", "attachments", "bodyValues",
                                      "keywords", "mailboxIds", "sentAt", "messageId"],
                       "fetchTextBodyValues": True}, "g"])
ids = r["q"][0][1]["ids"]
emails = {e["subject"]: e for e in r["g"][0][1]["list"]} if "g" in r else {}
say("Email/query finds the INBOX's two, and its result feeds Email/get", len(ids) == 2 and len(emails) == 2, r)
one, two = emails.get("first one", {}), emails.get("with a file", {})
say("Email/get reads the header", one.get("from") == [{"name": "Carol", "email": "carol@else.test"}] and
    one.get("messageId") == ["one@else.test"] and one.get("sentAt") == "2026-10-20T10:00:00+02:00", one)
say("and the preview and the text's value", one.get("preview", "").startswith("hello with a needle") and
    any(v["value"].startswith("hello with") for v in one.get("bodyValues", {}).values()), one)
att = two.get("attachments", [])
say("and an attachment, apart from the text", two.get("hasAttachment") is True and len(att) == 1 and att[0].get("name") == "x.bin"
    and att[0].get("size") == 6, two)
r = api(["Email/query", {"accountId": acct, "filter": {"text": "needle"}}, "q"])
say("Email/query finds by text", r["q"][0][1]["ids"] == [one.get("id")], r)
st, _, data = call("GET", "/jmap/download/%s/%s/x.bin?type=application/octet-stream" % (acct, att[0]["blobId"]) if att else "/")
say("an attachment is downloaded whole, its encoding undone", st == 200 and data == bytes(range(6)), (st, data[:40]))
# Keywords, seen over IMAP
r = api(["Email/set", {"accountId": acct, "update": {one["id"]: {"keywords/$seen": True, "keywords/$flagged": True}}}, "s"])
M = imaplib.IMAP4("127.0.0.1", im); M.login("alice", "alicepassword1"); M.select("INBOX")
typ, data = M.search(None, "SEEN FLAGGED")
say("a keyword JMAP sets is a flag IMAP reads", r["s"][0][1].get("updated") == {one["id"]: None} and len(data[0].split()) == 1, (r, data))
# A mailbox made, an Email moved there keeping its id
r = api(["Mailbox/set", {"accountId": acct, "create": {"p": {"name": "Prüfung", "parentId": None}}}, "c"],
        ["Email/set", {"accountId": acct, "update": {one["id"]: {"mailboxIds": {"#p": True}}}}, "mv"],
        ["Email/get", {"accountId": acct, "ids": [one["id"]], "properties": ["mailboxIds"]}, "g"])
made = r["c"][0][1].get("created", {}).get("p", {}).get("id")
typ, lst = M.list()
say("Mailbox/set makes a folder, kept in modified UTF-7 for IMAP", made and any(b"Pr&APw-fung" in x for x in lst), (r["c"], lst))
moved = r["g"][0][1]["list"]
say("an Email moved keeps its id, now in the new mailbox", r["mv"][0][1].get("updated") == {one["id"]: None} and
    moved and moved[0]["mailboxIds"] == {made: True}, r)
# Upload and import
raw = b"From: erin@else.test\r\nTo: alice@example.test\r\nSubject: imported\r\n\r\nfrom an upload\r\n"
st, _, data = call("POST", "/jmap/upload/%s/" % acct, raw, {"Content-Type": "message/rfc822"})
up = json.loads(data) if st == 201 else {}
r = api(["Email/import", {"accountId": acct, "emails": {"i": {"blobId": up.get("blobId"), "mailboxIds": {inbox["id"]: True}, "keywords": {"$seen": True}}}}, "imp"],
        ["Email/get", {"accountId": acct, "ids": ["#i"], "properties": ["subject", "keywords"]}, "g"])
got = r["g"][0][1]["list"]
say("an upload is imported as an Email", st == 201 and got and got[0]["subject"] == "imported" and got[0]["keywords"] == {"$seen": True}, (st, r))
# A draft written, sent, and filed in Sent
st, _, data = call("POST", "/jmap/upload/%s/" % acct, b"attached bytes", {"Content-Type": "text/plain"})
blob = json.loads(data).get("blobId") if st == 201 else None
r = api(["Email/set", {"accountId": acct, "create": {"d": {
            "mailboxIds": {boxes["drafts"]["id"]: True}, "keywords": {"$draft": True},
            "from": [{"name": "Alice", "email": "alice@example.test"}], "to": [{"email": "bob@remote.test"}],
            "subject": "sent by jmap", "textBody": [{"partId": "t", "type": "text/plain"}],
            "bodyValues": {"t": {"value": "the body of it"}},
            "attachments": [{"blobId": blob, "type": "text/plain", "name": "note.txt"}]}}}, "d"],
        ["EmailSubmission/set", {"accountId": acct, "create": {"s": {"identityId": "i0", "emailId": "#d"}},
            "onSuccessUpdateEmail": {"#s": {"mailboxIds": {boxes["sent"]["id"]: True}, "keywords/$draft": None}}}, "sub"])
names = [n for n, _ in r.get("sub", [])]
say("Email/set creates a draft and EmailSubmission/set sends it", r["d"][0][1].get("created", {}).get("d") and
    r["sub"][0][1].get("created", {}).get("s") and names == ["EmailSubmission/set", "Email/set"], r)
f = None
for _ in range(100):
    for n in os.listdir(sink):
        if not n.startswith(".") and b"sent by jmap" in open(os.path.join(sink, n), "rb").read(): f = os.path.join(sink, n)
    if f: break
    time.sleep(0.1)
body = open(f, "rb").read() if f else b""
say("and the message reaches its recipient, with its attachment", b"rcpt bob@remote.test" in body and b"note.txt" in body
    and b"the body of it" in body, body[:300])
r = api(["Email/query", {"accountId": acct, "filter": {"inMailbox": boxes["sent"]["id"]}}, "q"])
say("and the draft is now in Sent", len(r["q"][0][1]["ids"]) == 1, r)
# Destroy, changes
r = api(["Email/set", {"accountId": acct, "destroy": [up and got and got[0]["id"] or "x"]}, "x"])
say("Email/set destroy takes an Email away", len(r["x"][0][1].get("destroyed", [])) == 1, r)
state = api(["Email/get", {"accountId": acct, "ids": []}, "g"])["g"][0][1]["state"]
r = api(["Email/changes", {"accountId": acct, "sinceState": state}, "c1"], ["Email/changes", {"accountId": acct, "sinceState": "s0"}, "c2"])
say("*/changes on the current state is empty, on another cannotCalculateChanges", r["c1"][0][1].get("created") == [] and
    r["c2"][0][0] == "error" and r["c2"][0][1]["type"] == "cannotCalculateChanges", r)
r = api(["Nope/get", {"accountId": acct}, "u"], ["Mailbox/get", {"accountId": "other"}, "w"])
say("an unknown method and another account are errors", r["u"][0][1]["type"] == "unknownMethod" and r["w"][0][1]["type"] == "accountNotFound", r)
r = api(["SearchSnippet/get", {"accountId": acct, "emailIds": [one["id"], "Mnone"]}, "sn"])
say("SearchSnippet/get answers for each Email it knows", [x["emailId"] for x in r["sn"][0][1]["list"]] == [one["id"]] and
    r["sn"][0][1]["notFound"] == ["Mnone"], r)
r = api(["Identity/get", {"accountId": acct}, "i"])
say("Identity/get gives the user's address", r["i"][0][1]["list"][0]["email"] == "alice@example.test", r)
# EventSource
es = socket.create_connection(("127.0.0.1", jm), timeout=10)
es.sendall(("GET /jmap/eventsource?types=*&closeafter=state&ping=0 HTTP/1.1\r\nHost: x\r\nAuthorization: %s\r\n\r\n" % AUTH).encode())
time.sleep(0.5)
import smtplib
sm = smtplib.SMTP("127.0.0.1", int(sys.argv[4])); sm.ehlo("x")
sm.sendmail("x@else.test", ["alice@example.test"], "From: x@else.test\r\nSubject: pushed\r\n\r\nhi\r\n"); sm.quit()
got = b""; end = time.time() + 6
while time.time() < end and b"event: state" not in got:
    try:
        chunk = es.recv(65536)
        if not chunk: break
        got += chunk
    except socket.timeout:
        break
say("an EventSource is told of new mail", b"text/event-stream" in got and b"event: state" in got and b"StateChange" in got, got[:300])
# The clear from elsewhere
st, _, _ = call("GET", "/.well-known/jmap", source="127.0.0.2")
say("a password in the clear from another machine is refused", st == 403, st)
PY
tally < <(timeout 120 python3 "$T/client.py" "$JM" "$IM" "$T/sink" "$P" 2>&1 | grep -E '^(ok|bad) ')

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || { echo "  FAILED"; exit 1; }
