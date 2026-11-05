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
#   * Email/parse not reading an upload as an Email
#   * a preview with runs of white space or HTML's tags in it, longer than 256 bytes, or cut inside a character
#   * a VacationResponse not answering, answering a sender twice, or answering a list
#   * a PushSubscription pushed before it is verified, its verification not readable by the keys it gave, a
#     StateChange not sent when mail comes, or its URL and keys told back
#   * a push user with no verified subscription read every second by the shard that pushes for it, so that shard
#     never lets the user go; or one let go and verified later not pushed to
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
PUSH=$((SL_PORT_BASE+1927))
P2=$((SL_PORT_BASE+1928))
JM2=$((SL_PORT_BASE+1929))
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
# A push service of the test's: HTTPS for push.test under a CA of its own, each POST written down as it came.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=test CA" -keyout "$T/ca.key" -out "$T/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=push.test" -keyout "$T/push.key" -out "$T/push.csr" >/dev/null 2>&1
printf 'subjectAltName=DNS:push.test\n' > "$T/push.ext"
openssl x509 -req -in "$T/push.csr" -CA "$T/ca.pem" -CAkey "$T/ca.key" -CAcreateserial -days 2 -extfile "$T/push.ext" \
    -out "$T/push.pem" >/dev/null 2>&1
mkdir -p "$T/pushes"
python3 - "$PUSH" "$T/push.pem" "$T/push.key" "$T/pushes" >/dev/null 2>&1 <<'PY' &
import http.server, os, ssl, sys, time
port, cert, key, out = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        name = os.path.join(out, "%f-%s" % (time.time(), self.path.strip("/").replace("/", "_")))
        with open(name + ".tmp", "wb") as f:
            f.write(("encoding %s\n" % self.headers.get("Content-Encoding", "")).encode() + body)
        os.rename(name + ".tmp", name)
        self.send_response(201); self.send_header("Content-Length", "0"); self.end_headers()
    def log_message(self, *a): pass
srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, key)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
PY
PIDS+=($!)
export SOCKETLEY_MAIL_PUSH_CONNECT="127.0.0.1:$PUSH" SOCKETLEY_MAIL_PUSH_CA="$T/ca.pem"
# A shard other than the first lets a user go 1.5 s after nothing there asked for it.
export SOCKETLEY_MAIL_LET_GO_MS=1500
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
"$BIN" idp-user auth add alice --password alicepassword1 --email alice@example.test --set mail_quota=1M >/dev/null 2>&1
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
# A draft whose From is another's is not sent, whatever envelope sender it is given.
r = api(["Email/set", {"accountId": acct, "create": {"f": {
            "mailboxIds": {boxes["drafts"]["id"]: True}, "keywords": {"$draft": True},
            "from": [{"email": "ceo@example.test"}], "to": [{"email": "bob@remote.test"}],
            "subject": "forged by jmap", "textBody": [{"partId": "t", "type": "text/plain"}],
            "bodyValues": {"t": {"value": "the ceo says by jmap"}}}}}, "f"],
        ["EmailSubmission/set", {"accountId": acct, "create": {"s": {"identityId": "i0", "emailId": "#f",
            "envelope": {"mailFrom": {"email": "alice@example.test"}, "rcptTo": [{"email": "bob@remote.test"}]}}}}, "fs"])
nc = r["fs"][0][1].get("notCreated", {}).get("s", {})
say("EmailSubmission/set refuses a draft whose From header is another's", nc.get("type") == "forbiddenFrom", r)
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
r = api(["Identity/set", {"accountId": acct, "update": {"i0": {"name": "Alice A.", "textSignature": "-- \nAlice"}},
         "create": {"n": {"email": "someone@else.test"}}}, "is"], ["Identity/get", {"accountId": acct}, "ig"])
ident = r["ig"][0][1]["list"][0]
say("Identity/set keeps a name and a signature, and makes no other address", r["is"][0][1]["updated"] == {"i0": None} and
    "n" in r["is"][0][1]["notCreated"] and ident["name"] == "Alice A." and ident["textSignature"] == "-- \nAlice", r)
before = r["ig"][0][1]["state"]
r = api(["Identity/set", {"accountId": acct, "update": {"i0": {"name": "Alice B."}}}, "is"], ["Identity/get", {"accountId": acct}, "ig"])
say("an Identity changed to a name of the same length is a new state", r["is"][0][1]["oldState"] == before and
    r["is"][0][1]["newState"] == r["ig"][0][1]["state"] and r["ig"][0][1]["state"] != before, r)
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
# Email/parse
st, _, data = call("POST", "/jmap/upload/%s/" % acct, b"From: zoe@else.test\r\nSubject: only parsed\r\n\r\nnot kept\r\n",
                   {"Content-Type": "message/rfc822"})
pb = json.loads(data).get("blobId") if st == 201 else None
r = api(["Email/parse", {"accountId": acct, "blobIds": [pb, "Unone"], "properties": ["subject", "from", "id"]}, "p"])
pr = r["p"][0][1]
say("Email/parse reads an upload as an Email that is not the account's", pr["parsed"].get(pb, {}).get("subject") == "only parsed"
    and pr["parsed"][pb].get("id") is None and pr["notFound"] == ["Unone"], pr)
# A preview is the text's start with each run of white space one space and HTML's tags taken out, cut where a character
# begins: here the 256th byte is the first of a "ü".
def preview_of(head, body):
    st, _, data = call("POST", "/jmap/upload/%s/" % acct, head + b"\r\n\r\n" + body, {"Content-Type": "message/rfc822"})
    b = json.loads(data).get("blobId") if st == 201 else None
    r = api(["Email/parse", {"accountId": acct, "blobIds": [b], "properties": ["preview"]}, "p"])
    return r["p"][0][1]["parsed"].get(b, {}).get("preview")
long_text = preview_of(b"From: zoe@else.test\r\nContent-Type: text/plain; charset=utf-8",
                       b"  lead\r\n\r\n\t" + b"x" * 250 + "ü".encode() * 40 + b"\r\n")
say("a preview is cut where a character begins", long_text == "lead " + "x" * 250, long_text)
html = preview_of(b"From: zoe@else.test\r\nContent-Type: text/html; charset=utf-8",
                  b"<html><body><p>Hello</p>\r\n\r\n<b>big</b>   world " + b"<i>word</i> " * 80 + b"</body></html>")
want = ("Hello big world " + "word " * 80)[:256].rstrip()
say("and an HTML one has its tags taken out", html == want, (html, want))
# VacationResponse
r = api(["VacationResponse/get", {"accountId": acct}, "g0"],
        ["VacationResponse/set", {"accountId": acct, "update": {"singleton": {"isEnabled": True, "subject": "Away now",
         "textBody": "Back on Monday."}}}, "v"], ["VacationResponse/get", {"accountId": acct}, "g"])
vr = r["g"][0][1]["list"][0]
say("VacationResponse/set turns it on, and get says so", r["v"][0][1].get("updated") == {"singleton": None} and
    vr["isEnabled"] is True and vr["textBody"] == "Back on Monday.", r)
vs = r["v"][0][1]
say("and its oldState is the state before, its newState the one get gives after", vs["oldState"] == r["g0"][0][1]["state"]
    and vs["newState"] == r["g"][0][1]["state"] and vs["oldState"] != vs["newState"], r)
r = api(["VacationResponse/set", {"accountId": acct, "update": {"singleton": {"subject": "Away w0w"}}}, "v"])
w0w = r["v"][0][1]["newState"]
r = api(["VacationResponse/set", {"accountId": acct, "update": {"singleton": {"subject": "Away now"}}}, "v"])
say("a change of the same length is a new state, and the same text again the same state", r["v"][0][1]["oldState"] == w0w
    and w0w != vs["newState"] and r["v"][0][1]["newState"] == vs["newState"], r)
sm = smtplib.SMTP("127.0.0.1", int(sys.argv[4])); sm.ehlo("x")
for subject in ("first while away", "second while away"):
    sm.sendmail("vera@remote.test", ["alice@example.test"], "From: vera@remote.test\r\nSubject: %s\r\n\r\nhi\r\n" % subject)
sm.sendmail("list@remote.test", ["alice@example.test"], "From: list@remote.test\r\nList-Id: <l.remote.test>\r\nSubject: digest\r\n\r\nhi\r\n")
sm.quit()
def sink_with(text, n=1, secs=8):
    end = time.time() + secs
    while time.time() < end:
        hits = [x for x in os.listdir(sink) if not x.startswith(".") and text in open(os.path.join(sink, x), "rb").read()]
        if len(hits) >= n: return hits
        time.sleep(0.1)
    return [x for x in os.listdir(sink) if not x.startswith(".") and text in open(os.path.join(sink, x), "rb").read()]
away = sink_with(b"Subject: Away now")
time.sleep(1.5)
away = sink_with(b"Subject: Away now", 2, 0)
body = open(os.path.join(sink, away[0]), "rb").read() if away else b""
say("a VacationResponse answers a sender once, from the user, auto-replied", len(away) == 1 and b"rcpt vera@remote.test" in body
    and b"Auto-Submitted: auto-replied" in body and b"Back on Monday." in body, (away, body[:300]))
say("and answers no list", not sink_with(b"rcpt list@remote.test", 1, 0), "a list was answered")
api(["VacationResponse/set", {"accountId": acct, "update": {"singleton": {"isEnabled": False}}}, "off"])
# Quota (RFC 9425): the octets the account's mail takes of its bound.
say("the session offers quota", "urn:ietf:params:jmap:quota" in s.get("capabilities", {}) and
    s.get("primaryAccounts", {}).get("urn:ietf:params:jmap:quota") == acct, s.get("capabilities"))
r = api(["Quota/get", {"accountId": acct, "ids": None}, "q"], ["Quota/get", {"accountId": acct, "ids": ["mail", "nope"]}, "n"])
q = r["q"][0][1]["list"]
say("Quota/get tells the octets used of the account's bound", len(q) == 1 and q[0]["resourceType"] == "octets" and
    q[0]["hardLimit"] in (1000000, 1048576) and 0 < q[0]["used"] < q[0]["hardLimit"] and q[0]["scope"] == "account" and
    q[0]["types"] == ["Mail"], r)
say("and an id it does not have as notFound", r["n"][0][1]["notFound"] == ["nope"] and len(r["n"][0][1]["list"]) == 1, r)
r = api(["Quota/changes", {"accountId": acct, "sinceState": r["q"][0][1]["state"]}, "c"], ["Quota/query", {"accountId": acct}, "y"],
        ["Quota/changes", {"accountId": acct, "sinceState": "0-1"}, "old"])
say("Quota/changes since now is none, Quota/query finds the one", r["c"][0][1]["created"] == [] and r["y"][0][1]["ids"] == ["mail"], r)
say("and changes since another state are to be fetched again", r["old"][0][0] == "error" and
    r["old"][0][1]["type"] == "cannotCalculateChanges", r)
# Mailbox/changes: a state is a digest of the folders, the same one nothing changed.
st = api(["Mailbox/get", {"accountId": acct, "ids": []}, "g"])["g"][0][1]["state"]
r = api(["Mailbox/changes", {"accountId": acct, "sinceState": st}, "c"],
        ["Mailbox/set", {"accountId": acct, "create": {"n": {"name": "Changes", "parentId": None}}}, "s"],
        ["Mailbox/changes", {"accountId": acct, "sinceState": st}, "after"])
say("Mailbox/changes since now is none, its updatedProperties null", r["c"][0][1].get("created") == [] and
    r["c"][0][1].get("updatedProperties", 1) is None and r["c"][0][1]["newState"] == st, r)
say("and after a folder is made, it is to be fetched again", r["after"][0][0] == "error" and
    r["after"][0][1]["type"] == "cannotCalculateChanges", r)
# PushSubscription, its pushes read with the keys it gave
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
ua = ec.generate_private_key(ec.SECP256R1())
ua_pub = ua.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
secret = os.urandom(16)
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def mac(k, m):
    h = hmac.HMAC(k, hashes.SHA256()); h.update(m); return h.finalize()
def opened(raw):
    salt, keyid = raw[:16], raw[21:86]
    shared = ua.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), keyid))
    ikm = mac(mac(secret, shared), b"WebPush: info\0" + ua_pub + keyid + b"\x01")
    prk = mac(salt, ikm)
    cek, nonce = mac(prk, b"Content-Encoding: aes128gcm\0\x01")[:16], mac(prk, b"Content-Encoding: nonce\0\x01")[:12]
    return json.loads(AESGCM(cek).decrypt(nonce, raw[86:], None).rstrip(b"\0")[:-1])
def pushes(path, n, secs=8):
    end = time.time() + secs
    while True:
        got = sorted(x for x in os.listdir(pushdir) if x.endswith(path) and not x.endswith(".tmp"))
        if len(got) >= n or time.time() > end:
            out = []
            for x in got:
                raw = open(os.path.join(pushdir, x), "rb").read()
                head, _, rest = raw.partition(b"\n")
                out.append(opened(rest) if head.endswith(b"aes128gcm") else json.loads(rest))
            return out
        time.sleep(0.1)
pushdir = sys.argv[5]
r = api(["PushSubscription/set", {"create": {"a": {"deviceClientId": "dev1", "url": "https://push.test/one",
         "keys": {"p256dh": b64(ua_pub), "auth": b64(secret)}},
         "b": {"deviceClientId": "dev2", "url": "https://push.test/two"},
         "c": {"deviceClientId": "dev3", "url": "http://push.test/three"}}}, "ps"])
made = r["ps"][0][1]
say("PushSubscription/set takes https URLs and refuses another", "a" in made["created"] and "b" in made["created"] and
    "c" in made["notCreated"], made)
v1 = pushes("one", 1)
say("its PushVerification is sent encrypted for the keys it gave", v1 and v1[0].get("@type") == "PushVerification" and
    v1[0].get("pushSubscriptionId") == made["created"]["a"]["id"], v1)
r = api(["PushSubscription/set", {"update": {made["created"]["a"]["id"]: {"verificationCode": "wrong"}}}, "w"])
say("a wrong verificationCode is refused", made["created"]["a"]["id"] in r["w"][0][1]["notUpdated"], r)
r = api(["PushSubscription/set", {"update": {made["created"]["a"]["id"]: {"verificationCode": v1[0]["verificationCode"]}}}, "u"],
        ["PushSubscription/get", {"ids": None}, "g"])
lst = r["g"][0][1]["list"]
say("and the right one verifies it; get tells neither URL nor keys", r["u"][0][1].get("updated") == {made["created"]["a"]["id"]: None}
    and len(lst) == 2 and not any("url" in x or "keys" in x or "verificationCode" in x for x in lst), r)
sm = smtplib.SMTP("127.0.0.1", int(sys.argv[4])); sm.ehlo("x")
sm.sendmail("x@else.test", ["alice@example.test"], "From: x@else.test\r\nSubject: pushed by state\r\n\r\nhi\r\n"); sm.quit()
p1 = pushes("one", 2)
say("new mail is pushed as a StateChange to the verified one", len(p1) >= 2 and p1[1].get("@type") == "StateChange" and
    "Email" in p1[1].get("changed", {}).get(acct, {}), p1)
p2 = pushes("two", 2, 2)
say("and only its verification to the one not verified", len(p2) == 1 and p2[0].get("@type") == "PushVerification", p2)
# The clear from elsewhere
st, _, _ = call("GET", "/.well-known/jmap", source="127.0.0.2")
say("a password in the clear from another machine is refused", st == 403, st)
PY
tally < <(timeout 180 python3 "$T/client.py" "$JM" "$IM" "$T/sink" "$P" "$T/pushes" 2>&1 | grep -E '^(ok|bad) ')

# Two shards, alice's pushes on the second (FNV-1a of her name, odd): with only a subscription not verified she is
# nothing to push to, so that shard lets her go; verified, she is read again and pushed to.
"$BIN" create mail mp -p "$P2" --mail-domain example.test --idp auth --storage st/mailp --jmap "$JM2" --shards 2 -s \
    >/dev/null 2>&1
for p in "$P2" "$JM2"; do ready_tcp 127.0.0.1 "$p" || bad "port $p listens" "$(tail -3 "$SOCKETLEY_DLOG")"; done
cat > "$T/sharded_push.py" <<'PY'
import base64, http.client, json, os, re, smtplib, subprocess, sys, time
jm, smtp, binary, pushdir = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
AUTH = {"Authorization": "Basic " + base64.b64encode(b"alice:alicepassword1").decode(), "Content-Type": "application/json"}
def say(name, cond, why=""):
    print(("ok " if cond else "bad ") + name + ("" if cond else ": " + str(why)[:500]))
def pid(flags, q):
    m = re.search(r"pid=(\d+)", subprocess.run(["ss", flags, q], capture_output=True).stdout.decode())
    return m.group(1) if m else None
first = pid("-ltnpH", "sport = :%d" % smtp)
def held():
    out = subprocess.run([binary, "stats", "mp"], capture_output=True, timeout=30).stdout.decode()
    return sum(int(l.split(":")[1]) for l in out.splitlines() if l.startswith("imap_users_held:"))
def second_shard():
    for _ in range(200):
        c = http.client.HTTPConnection("127.0.0.1", jm, timeout=20); c.connect()
        if pid("-tnpH", "sport = :%d and dport = :%d" % (jm, c.sock.getsockname()[1])) not in (None, first):
            return c
        c.close()
    raise SystemExit("bad a session reached the second shard")
def api(c, *calls):
    c.request("POST", "/jmap/api", body=json.dumps({"using": ["urn:ietf:params:jmap:core"], "methodCalls": list(calls)}),
              headers=AUTH)
    return {cid: args for name, args, cid in json.loads(c.getresponse().read())["methodResponses"]}
def pushes(n, secs=8):
    end = time.time() + secs
    while True:
        got = sorted(x for x in os.listdir(pushdir) if x.endswith("sharded"))
        if len(got) >= n or time.time() > end:
            return [json.loads(open(os.path.join(pushdir, x), "rb").read().partition(b"\n")[2]) for x in got]
        time.sleep(0.1)
c = second_shard()
made = api(c, ["PushSubscription/set", {"create": {"a": {"deviceClientId": "d", "url": "https://push.test/sharded"}}}, "s"])["s"]
# Stats come a quarter second late at most, and the user is let go 1.5 s after the session asked.
time.sleep(0.6)
during = held()
c.close()
v = pushes(1)
say("a subscription is made on the second shard and its verification sent", "a" in made.get("created", {}) and v and
    v[0].get("@type") == "PushVerification", (made, v))
for _ in range(80):
    if held() == 0:
        break
    time.sleep(0.1)
after = held()
say("the second shard holds alice after her session asked, and lets her go with nothing to push to",
    during >= 1 and after == 0, (during, after))
c = second_shard()
api(c, ["PushSubscription/set", {"update": {made["created"]["a"]["id"]: {"verificationCode": v[0]["verificationCode"]}}}, "u"])
c.close()
time.sleep(1.5)
sm = smtplib.SMTP("127.0.0.1", smtp); sm.ehlo("x")
sm.sendmail("x@else.test", ["alice@example.test"], "From: x@else.test\r\nSubject: sharded push\r\n\r\nhi\r\n"); sm.quit()
p = pushes(2)
say("verified, she is read again by that shard and the new mail pushed", len(p) >= 2 and p[1].get("@type") == "StateChange", p)
PY
tally < <(timeout 120 python3 "$T/sharded_push.py" "$JM2" "$P2" "$BIN" "$T/pushes" 2>&1 | grep -E '^(ok|bad) ')

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || { echo "  FAILED"; exit 1; }
