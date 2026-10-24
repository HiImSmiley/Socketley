#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a mail runtime's webmail, on the port --web opens for the entrance --domain names it through, as a
# browser signed in at the idp reads, writes and sends mail with it.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * the page not served, served without its CSP, nosniff or ETag, or with a CSP whose hash is not its script's
#   * a page not signed in asked for a password by the browser rather than sent to the idp
#   * the idp's session cookie not taken, a change it signs not refused without the page's header, or a cookie's
#     answer readable by another origin
#   * a password taken in the clear behind an entrance that did not forward HTTPS, or a client the entrance forwards
#     never locked out, or locked out with every other
#   * an upload or a download refused to the cookie, or a download a browser would render
#   * Email/set dropping a recipient's name or a Bcc, refusing a draft with no recipient or with its own Message-ID,
#     or a move refused when its mailbox's null comes first
#   * a message sent from the page not reaching its recipients, a Bcc not reaching its own, or showing in the copy
#   * an EventSource refused to the cookie, or not told of new mail
#   * the entrance given no route to the webmail, or not serving the page through it
#   * a reply not in the conversation it answers, Thread/get or collapseThreads not grouping it across mailboxes, or a
#     conversation lost when the index's lines of it are, as an older binary's compaction drops them
#   * an image the HTML shows, sent inline, counted as an attachment
#   * --domain on a mail runtime without --web taken
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

daemon_isolate mail_webmail
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1940))
W=$((SL_PORT_BASE+1941))
PI=$((SL_PORT_BASE+1942))
PS=$((SL_PORT_BASE+1943))
NS=$((SL_PORT_BASE+1944))
GATE=$((SL_PORT_BASE+1945))
trap daemon_stop EXIT

echo "=== Integration: the webmail of a mail runtime ==="

daemon_start "$BIN"
"$BIN" create idp auth -p "$PI" --issuer "http://127.0.0.1:$PI" -s >/dev/null 2>&1
"$BIN" create storage st -p "$PS" --dir "$T/data" --anonymous -s >/dev/null 2>&1
for p in "$PI/jwks" "$PS/"; do
    for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p")" != 000 ] && break; sleep 0.1; done
done
"$BIN" idp-user auth add alice --password alicepassword1 --name "Alice A" --email alice@example.test >/dev/null 2>&1
"$BIN" idp-user auth add bob --password bobpassword12 --email bob@example.test >/dev/null 2>&1
"$BIN" idp-user auth add carol --password carolpassword1 --email carol@example.test >/dev/null 2>&1

out=$("$BIN" create mail bare -p $((P+9)) --mail-domain example.test --domain webmail 2>&1); rc=$?
[ "$rc" -ne 0 ] && case "$out" in *"--web"*) true ;; *) false ;; esac && ok "--domain without --web is refused, naming --web" \
    || bad "--domain without --web is refused" "rc $rc: $out"

"$BIN" create dns ns -p "$NS" --zone example.test --publish 127.0.0.1 --proxy-port "$GATE" -s >/dev/null 2>&1
"$BIN" create mail m -p "$P" --mail-domain example.test --idp auth --storage st/mail --web "$W" --domain webmail -s \
    >/dev/null 2>&1
for p in "$P" "$W"; do ready_tcp 127.0.0.1 "$p" || bad "port $p listens" "$(tail -3 "$SOCKETLEY_DLOG")"; done
ss -ltnH "sport = :$W" | grep -q "127.0.0.1:$W" && ok "the webmail port listens on 127.0.0.1 alone" \
    || bad "the webmail port listens on 127.0.0.1 alone" "$(ss -ltnH "sport = :$W")"

python3 - "$P" <<'PY'
import smtplib, sys
s = smtplib.SMTP("127.0.0.1", int(sys.argv[1])); s.ehlo("x")
s.sendmail("dave@else.test", ["alice@example.test"],
    "From: Dave <dave@else.test>\r\nTo: alice@example.test\r\nSubject: hello alice\r\nMessage-ID: <one@else.test>\r\n"
    "Date: Tue, 20 Oct 2026 10:00:00 +0200\r\n\r\nthe first message\r\n")
s.quit()
PY

tally < <(python3 - "$W" "$PI" "$P" <<'PY'
import base64, hashlib, http.client, json, re, smtplib, socket, sys, time, urllib.parse
W, PI, P = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
def check(name, ok, info=""):
    print(("ok " if ok else "bad ") + name + ("" if ok else ": " + str(info)[:400].replace("\n", " ")))
def http_(port, method, path, body=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request(method, path, body=body, headers=headers or {})
    r = c.getresponse(); data = r.read(); hs = {k.lower(): v for k, v in r.getheaders()}; c.close()
    return r.status, hs, data
def web(method, path, body=None, headers=None):
    return http_(W, method, path, body, headers)
def basic(user, pw):
    return "Basic " + base64.b64encode((user + ":" + pw).encode()).decode()
USING = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:submission"]

# The page.
st, h, page = web("GET", "/")
csp = h.get("content-security-policy", "")
script = page.split(b"<script>", 1)[1].split(b"</script>", 1)[0] if b"<script>" in page else b""
want = "'sha256-" + base64.b64encode(hashlib.sha256(script).digest()).decode() + "'"
check("the page is served as HTML with nosniff and an ETag", st == 200 and h.get("content-type", "").startswith("text/html")
      and h.get("x-content-type-options") == "nosniff" and h.get("etag"), (st, h))
check("its CSP lets its one script run by that script's hash, and no frame embed it", want in csp
      and "frame-ancestors 'none'" in csp and "unsafe-inline" not in csp.split("script-src", 1)[1].split(";", 1)[0], csp)
st2, _, body2 = web("GET", "/", headers={"If-None-Match": h.get("etag", "x")})
check("a browser's copy is answered 304", st2 == 304 and not body2, st2)

# Not signed in: the page is sent to the idp, a JMAP client asked for Basic.
st, h, _ = web("GET", "/~mail/session", headers={"X-Socketley-UI": "1"})
login = h.get("x-socketley-idp-login", "")
check("the page not signed in is told where the idp signs it in, with no prompt for a password", st == 401 and
      login.startswith("http://127.0.0.1:%d/login?rd=" % PI) and "www-authenticate" not in h, (st, h))
st, h, _ = web("GET", "/jmap/session")
check("a JMAP client with no credentials is still asked for Basic", st == 401 and h.get("www-authenticate", "").startswith("Basic"), (st, h))

# Signed in at the idp.
def sign_in(user, pw):
    form = urllib.parse.urlencode({"username": user, "password": pw, "rd": "http://127.0.0.1:%d/" % W})
    st, h, _ = http_(PI, "POST", "/login", form, {"Content-Type": "application/x-www-form-urlencoded"})
    return (h.get("set-cookie") or "").split(";")[0]
cookie = sign_in("alice", "alicepassword1")
C = {"Cookie": cookie, "X-Socketley-UI": "1"}
st, h, d = web("GET", "/~mail/session", headers=C)
me = json.loads(d) if st == 200 else {}
check("the idp's session cookie signs the page in as its user", cookie.startswith("skl_idp=") and me.get("user") == "alice"
      and me.get("address") == "alice@example.test" and "/logout?" in me.get("logout", ""), (st, d[:200]))
acct = me.get("account", "")
def api(*calls, headers=None):
    st, h, d = web("POST", "/jmap/api", json.dumps({"using": USING, "methodCalls": list(calls)}),
                   dict(headers or C, **{"Content-Type": "application/json"}))
    r = {}
    if st == 200:
        for name, args, cid in json.loads(d)["methodResponses"]:
            r.setdefault(cid, []).append((name, args))
    return st, h, r
st, h, _ = web("POST", "/jmap/api", json.dumps({"using": USING, "methodCalls": []}),
               {"Cookie": cookie, "Content-Type": "application/json"})
check("a change signed by the cookie alone, without the page's header, is refused", st == 403, st)
# The first message is delivered after its 250, so a busy machine may not have it in the mailbox yet.
for _ in range(50):
    st, h, r = api(["Mailbox/get", {"accountId": acct}, "b"])
    boxes = {b.get("role") or b["name"]: b for b in (r.get("b", [[None, {}]])[0][1].get("list") or [])} if st == 200 else {}
    if st != 200 or boxes.get("inbox", {}).get("totalEmails") == 1:
        break
    time.sleep(0.1)
check("with it the API answers for the cookie's user", st == 200 and "inbox" in boxes and boxes["inbox"]["totalEmails"] == 1, (st, r))
check("and the answer is not readable by another origin", "access-control-allow-origin" not in h, h)
st, h, _ = web("GET", "/~mail/session", headers={"Cookie": "skl_idp=eyJhbGciOiJFUzI1NiJ9.e30.AAAA", "X-Socketley-UI": "1"})
check("a cookie the idp did not sign is refused", st == 401, st)

# A password behind the entrance: only over the HTTPS it forwards, and locked out by the client it forwards.
B = {"Authorization": basic("bob", "bobpassword12"), "Content-Type": "application/json"}
mb = json.dumps({"using": USING, "methodCalls": [["Mailbox/get", {"accountId": "x"}, "b"]]})
st, h, _ = web("POST", "/jmap/api", mb, B)
check("a password the entrance did not forward over HTTPS is refused", st == 403, st)
st, h, _ = web("POST", "/jmap/api", mb, dict(B, **{"X-Forwarded-Proto": "https"}))
check("one it forwarded over HTTPS is taken, readable by a client of another origin", st == 200
      and h.get("access-control-allow-origin") == "*", (st, h))
bad_pw = {"Authorization": basic("bob", "wrong"), "X-Forwarded-Proto": "https", "X-Forwarded-For": "198.51.100.1, 203.0.113.7"}
for _ in range(10):
    web("POST", "/jmap/api", mb, bad_pw)
st, _, _ = web("POST", "/jmap/api", mb, dict(B, **{"X-Forwarded-Proto": "https", "X-Forwarded-For": "203.0.113.7"}))
st2, _, _ = web("POST", "/jmap/api", mb, dict(B, **{"X-Forwarded-Proto": "https", "X-Forwarded-For": "203.0.113.8"}))
check("ten failures from the client the entrance forwards lock it out, and only it", st == 503 and st2 == 200, (st, st2))

# Uploads, drafts, a move, and sending.
st, h, d = web("POST", "/jmap/upload/%s/" % acct, b"attached text", {"Cookie": cookie, "X-Socketley-UI": "1", "Content-Type": "text/plain"})
blob = json.loads(d).get("blobId") if st in (200, 201) else None
check("the page uploads with its cookie", bool(blob), (st, d[:200]))
drafts, sent = boxes.get("drafts", {}).get("id"), boxes.get("sent", {}).get("id")
st, h, r = api(["Email/set", {"accountId": acct, "create": {
    "d": {"mailboxIds": {drafts: True}, "keywords": {"$draft": True}, "from": [{"name": "Alice A", "email": "alice@example.test"}],
          "to": [{"name": "Bob \"the\" Builder", "email": "bob@example.test"}], "bcc": [{"email": "carol@example.test"}],
          "subject": "from the webmail", "messageId": ["own-id@example.test"],
          "textBody": [{"partId": "t", "type": "text/plain"}], "bodyValues": {"t": {"value": "hello bob"}},
          "attachments": [{"blobId": blob, "type": "text/plain", "name": "a.txt"}]},
    "e": {"mailboxIds": {drafts: True}, "keywords": {"$draft": True}, "subject": "nobody yet",
          "textBody": [{"partId": "t", "type": "text/plain"}], "bodyValues": {"t": {"value": "later"}}}}}, "c"])
made = r.get("c", [[None, {}]])[0][1].get("created", {}) if st == 200 else {}
check("Email/set keeps a draft with its own Message-ID, and one with no recipient yet", "d" in made and "e" in made, r)
did = made.get("d", {}).get("id")
st, h, r = api(["Email/get", {"accountId": acct, "ids": [did], "properties": ["to", "bcc", "messageId", "from"]}, "g"])
got = (r.get("g", [[None, {}]])[0][1].get("list") or [{}])[0] if st == 200 else {}
check("and writes the recipient's name, the Bcc and the Message-ID it was given",
      (got.get("to") or [{}])[0].get("name") == "Bob \"the\" Builder" and (got.get("bcc") or [{}])[0].get("email") == "carol@example.test"
      and got.get("messageId") == ["own-id@example.test"] and (got.get("from") or [{}])[0].get("name") == "Alice A", got)
eid = made.get("e", {}).get("id")
st, h, r = api(["Email/set", {"accountId": acct, "update": {eid: {"mailboxIds/" + drafts: None, "mailboxIds/" + sent: True}}}, "u"])
st2, _, r2 = api(["Email/query", {"accountId": acct, "filter": {"inMailbox": sent}}, "q"])
check("a move whose old mailbox's null comes first is made", eid in (r.get("u", [[None, {}]])[0][1].get("updated") or {})
      and eid in r2.get("q", [[None, {}]])[0][1].get("ids", []), (r, r2))
st, h, r = api(["EmailSubmission/set", {"accountId": acct, "create": {"s": {"identityId": "i0", "emailId": did}},
                "onSuccessUpdateEmail": {"#s": {"mailboxIds/" + drafts: None, "mailboxIds/" + sent: True, "keywords/$draft": None}}}, "s"])
check("the page sends the draft, which goes to Sent", "s" in (r.get("s", [[None, {}]])[0][1].get("created") or {}), r)
def inbox_of(user, pw, subject):
    H = {"Authorization": basic(user, pw), "X-Forwarded-Proto": "https", "Content-Type": "application/json", "X-Forwarded-For": "192.0.2.%d" % len(user)}
    a = "a" + base64.urlsafe_b64encode(user.encode()).decode().rstrip("=")
    for _ in range(100):
        st, _, d = web("POST", "/jmap/api", json.dumps({"using": USING, "methodCalls": [
            ["Email/query", {"accountId": a, "filter": {"subject": subject}}, "q"],
            ["Email/get", {"accountId": a, "#ids": {"resultOf": "q", "name": "Email/query", "path": "/ids"},
                           "properties": ["to", "bcc", "hasAttachment", "header:Bcc"]}, "g"]]}), H)
        if st == 200:
            lst = json.loads(d)["methodResponses"][1][1].get("list") or []
            if lst:
                return lst[0]
        time.sleep(0.1)
    return None
b = inbox_of("bob", "bobpassword12", "from the webmail")
c = inbox_of("carol", "carolpassword1", "from the webmail")
check("the recipient has it, with its attachment and without the Bcc", b is not None and b.get("hasAttachment") and not b.get("bcc")
      and not b.get("header:Bcc"), b)
check("and the Bcc recipient has it too", c is not None, c)

# A download, and the EventSource, by the cookie.
st, h, d = web("GET", "/jmap/download/%s/%s/a.txt?type=text/html" % (acct, blob), headers={"Cookie": cookie})
check("a download goes to the cookie as an attachment the browser does not sniff", st == 200 and d == b"attached text"
      and h.get("content-disposition", "").startswith("attachment") and h.get("x-content-type-options") == "nosniff", (st, h))
es = socket.create_connection(("127.0.0.1", W), 10)
es.sendall(("GET /jmap/eventsource?types=*&closeafter=state&ping=0 HTTP/1.1\r\nHost: x\r\nCookie: %s\r\n\r\n" % cookie).encode())
es.settimeout(10)
head = es.recv(4096)
time.sleep(0.5)
s = smtplib.SMTP("127.0.0.1", P); s.sendmail("dave@else.test", ["alice@example.test"], "Subject: live\r\n\r\nnew\r\n"); s.quit()
seen = head
try:
    while b"event: state" not in seen:
        x = es.recv(4096)
        if not x:
            break
        seen += x
except socket.timeout:
    pass
es.close()
check("the EventSource takes the cookie and tells of new mail", head.startswith(b"HTTP/1.1 200") and b"event: state" in seen, seen[:300])
PY
)

# Conversations: what a reply's References tie together is one Thread across mailboxes, collapsed in a query, kept
# across a restart, and read again for messages whose index lines lost it, as an older binary's compaction drops them.
thread_check() {
python3 - "$W" "$PI" "$P" "$1" "$T/thread" <<'PY'
import base64, http.client, json, smtplib, sys, time, urllib.parse
W, PI, P, phase, saved = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), sys.argv[4], sys.argv[5]
def check(name, ok, info=""):
    print(("ok " if ok else "bad ") + name + ("" if ok else ": " + str(info)[:400].replace("\n", " ")))
H = {"Authorization": "Basic " + base64.b64encode(b"alice:alicepassword1").decode(), "X-Forwarded-Proto": "https",
     "X-Forwarded-For": "192.0.2.50", "Content-Type": "application/json"}
USING = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:submission"]
A = "a" + base64.urlsafe_b64encode(b"alice").decode().rstrip("=")
def api(*calls):
    c = http.client.HTTPConnection("127.0.0.1", W, timeout=20)
    c.request("POST", "/jmap/api", json.dumps({"using": USING, "methodCalls": list(calls)}), H)
    r = c.getresponse(); d = r.read(); c.close()
    out = {}
    if r.status == 200:
        for name, args, cid in json.loads(d)["methodResponses"]:
            out.setdefault(cid, args)
    return out
boxes = {b.get("role"): b["id"] for b in api(["Mailbox/get", {"accountId": A}, "b"])["b"]["list"]}
def find(subject):
    for _ in range(100):
        r = api(["Email/query", {"accountId": A, "filter": {"subject": subject}}, "q"],
                ["Email/get", {"accountId": A, "#ids": {"resultOf": "q", "name": "Email/query", "path": "/ids"}, "properties": ["threadId", "subject"]}, "g"])
        if r.get("g", {}).get("list"):
            return r["g"]["list"]
        time.sleep(0.1)
    return []
if phase == "first":
    s = smtplib.SMTP("127.0.0.1", P)
    s.sendmail("eve@else.test", ["alice@example.test"], "From: Eve <eve@else.test>\r\nTo: alice@example.test\r\nSubject: plans\r\n"
               "Message-ID: <t1@else.test>\r\nDate: Wed, 21 Oct 2026 09:00:00 +0000\r\n\r\nshall we?\r\n")
    s.sendmail("eve@else.test", ["alice@example.test"], "From: Eve <eve@else.test>\r\nTo: alice@example.test\r\nSubject: Re: plans\r\n"
               "Message-ID: <t3@else.test>\r\nIn-Reply-To: <t2@example.test>\r\nReferences: <t1@else.test> <t2@example.test>\r\n"
               "Date: Wed, 21 Oct 2026 11:00:00 +0000\r\n\r\nyes\r\n")
    s.quit()
    t1, t3 = find("plans"), find("Re: plans")
    r = api(["Email/set", {"accountId": A, "create": {"r": {"mailboxIds": {boxes["sent"]: True}, "keywords": {"$seen": True},
        "from": [{"email": "alice@example.test"}], "to": [{"email": "eve@else.test"}], "subject": "Re: plans",
        "messageId": ["t2@example.test"], "inReplyTo": ["t1@else.test"], "references": ["t1@else.test"],
        "textBody": [{"partId": "t", "type": "text/plain"}], "bodyValues": {"t": {"value": "maybe"}}}}}, "c"])
    mine = r.get("c", {}).get("created", {}).get("r", {})
    ids = {m["threadId"] for m in t1 + t3 if "plans" in m["subject"]} | {mine.get("threadId")}
    check("a message, a reply filed in Sent and the answer to it are one conversation", len(ids) == 1 and None not in ids, (t1, t3, mine))
    tid = ids.pop() if len(ids) == 1 else ""
    open(saved, "w").write(tid)
    r = api(["Thread/get", {"accountId": A, "ids": [tid]}, "t"])
    check("Thread/get gives all three, across Inbox and Sent, oldest first",
          len((r.get("t", {}).get("list") or [{}])[0].get("emailIds", [])) == 3, r)
    r = api(["Email/query", {"accountId": A, "filter": {"text": "plans"}, "collapseThreads": True}, "q"],
            ["Email/query", {"accountId": A, "filter": {"text": "plans"}}, "a"])
    check("collapsed, a query answers the conversation once", r.get("q", {}).get("collapseThreads") is True and
          len(r["q"]["ids"]) == 1 and len(r.get("a", {}).get("ids", [])) == 3, r)
else:
    tid = open(saved).read()
    r = api(["Thread/get", {"accountId": A, "ids": [tid]}, "t"])
    check("after a restart, with the index's thread lines gone, the conversation is read again as it was",
          len((r.get("t", {}).get("list") or [{}])[0].get("emailIds", [])) == 3, (tid, r))
PY
}
tally < <(thread_check first)
"$BIN" stop m >/dev/null 2>&1
idx=$(find "$HOME" -path '*.imap/alice*' -type f ! -name '*.fts' ! -name '*.lock' 2>/dev/null)
had=$(cat $idx 2>/dev/null | grep -c '^H ')
sed -i '/^H /d' $idx 2>/dev/null
[ "$had" -gt 0 ] && ok "the index keeps each message's conversation ($had lines)" || bad "the index keeps each message's conversation" "$idx"
"$BIN" start m >/dev/null 2>&1
ready_tcp 127.0.0.1 "$W" || bad "the webmail port listens again" "$(tail -3 "$SOCKETLEY_DLOG")"
tally < <(thread_check again)

# An image only the HTML shows, sent inside the message, is no attachment to download.
printf '\x89PNG\r\n\x1a\nlogo' > "$T/logo.png"
printf '<p>logo:</p><img src="cid:logo.png">' > "$T/inline.html"
"$BIN" send m --to alice@example.test --from shop@example.test --subject 'inline only' --html "$T/inline.html" \
    --inline "$T/logo.png" --text 'logo' </dev/null >/dev/null 2>&1
inline=$(python3 - "$W" <<'PY'
import base64, http.client, json, sys, time
W = int(sys.argv[1])
H = {"Authorization": "Basic " + base64.b64encode(b"alice:alicepassword1").decode(), "X-Forwarded-Proto": "https",
     "X-Forwarded-For": "192.0.2.60", "Content-Type": "application/json"}
A = "a" + base64.urlsafe_b64encode(b"alice").decode().rstrip("=")
for _ in range(100):
    c = http.client.HTTPConnection("127.0.0.1", W, timeout=20)
    c.request("POST", "/jmap/api", json.dumps({"using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"], "methodCalls": [
        ["Email/query", {"accountId": A, "filter": {"subject": "inline only"}}, "q"],
        ["Email/get", {"accountId": A, "#ids": {"resultOf": "q", "name": "Email/query", "path": "/ids"}, "properties": ["hasAttachment"]}, "g"],
        ["Email/query", {"accountId": A, "filter": {"subject": "inline only", "hasAttachment": True}}, "a"]]}), H)
    r = json.loads(c.getresponse().read()); c.close()
    got = r["methodResponses"][1][1].get("list") or []
    if got:
        print(got[0].get("hasAttachment"), len(r["methodResponses"][2][1].get("ids", [])))
        break
    time.sleep(0.1)
PY
)
[ "$inline" = "False 0" ] && ok "an image the HTML shows inline is no attachment, to hasAttachment and its filter" \
    || bad "an image the HTML shows inline is no attachment" "$inline"

# The entrance's route to the webmail, and the page through it.
route=$(find "$HOME" -path '*.dns*' -name 'routes-*' -exec cat {} + 2>/dev/null | grep '^route webmail.example.test ')
[ "$route" = "route webmail.example.test 127.0.0.1:$W" ] && ok "the entrance routes webmail.example.test to the webmail port" \
    || bad "the entrance routes webmail.example.test to the webmail port" "$route / $(find "$HOME" -name 'routes-*' -exec cat {} + 2>/dev/null)"
# The entrance speaks TLS, with a certificate of its own until a CA gives it one.
via() { curl -sk --resolve "webmail.example.test:$GATE:127.0.0.1" "$@"; }
code=""
for _ in $(seq 1 100); do
    code=$(via -o "$T/via" -w '%{http_code}' "https://webmail.example.test:$GATE/")
    [ "$code" = 200 ] && break
    sleep 0.1
done
[ "$code" = 200 ] && grep -q '<title>Mail</title>' "$T/via" && ok "the entrance serves the page under the name" \
    || bad "the entrance serves the page under the name" "$code $(head -c 200 "$T/via" 2>/dev/null)"
# The page in German where the browser asks for it: every word it says through say() has its German, with as many
# places for what goes in.
words=$(python3 - "$T/via" <<'PY'
import json, re, sys
page = open(sys.argv[1], encoding="utf-8").read()
table = re.search(r"Object\.assign\(SAY, \{\n(.*?)\n\}\);", page, re.S)
if not table:
    print("no table"); sys.exit()
de = json.loads("{" + table.group(1) + "}")
used = set(re.findall(r"say\('((?:[^'\\]|\\.)*)'", page)) | set(re.findall(r"field\('([^']*)'", page))
missing = sorted(u for u in used if u not in de)
uneven = sorted(k for k, v in de.items() if k.count("%") != v.count("%"))
unused = sorted(k for k in de if k not in used and ">" + k + "<" not in page and 'placeholder="%s"' % k not in page)
print("ok" if not missing and not uneven and not unused and len(used) > 150 else
      "missing %s uneven %s unused %s of %d" % (missing, uneven, unused, len(used)))
PY
)
[ "$words" = ok ] && ok "every word of the page has its German, with its places for what goes in" || bad "the German words" "$words"
session=$(via -H "Authorization: Basic $(printf 'bob:bobpassword12' | base64)" "https://webmail.example.test:$GATE/jmap/session")
case "$session" in *'"apiUrl":"https://webmail.example.test'*) ok "behind it the session's URLs are the HTTPS it was reached over" ;;
    *) bad "behind it the session's URLs are the HTTPS it was reached over" "$(printf '%s' "$session" | head -c 300)" ;; esac

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
