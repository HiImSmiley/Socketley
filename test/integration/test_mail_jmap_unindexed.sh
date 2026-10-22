#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: JMAP shows the messages a mailbox's bucket holds and its runtime's index has no line for, as a
# runtime whose state was lost or that shares another's bucket finds them, without an IMAP client listing them first.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * Email/query counting only what the journal names, so the mailbox reads empty to a web client
#   * Mailbox/get giving the INBOX no messages while Email/query finds them
#   * Email/get not reading a message taken up from the bucket
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

daemon_isolate mail_jmap_unindexed
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1930))
P2=$((SL_PORT_BASE+1931))
JM=$((SL_PORT_BASE+1932))
PI=$((SL_PORT_BASE+1933))
PS=$((SL_PORT_BASE+1934))
trap daemon_stop EXIT

echo "=== Integration: JMAP finds what the bucket holds and the index does not name ==="

daemon_start "$BIN"
printf 'spa - http://localhost:5173/cb\n' > "$T/clients"
"$BIN" create idp auth -p "$PI" --clients "$T/clients" --issuer "http://127.0.0.1:$PI" -s >/dev/null 2>&1
"$BIN" create storage st -p "$PS" --dir "$T/data" --anonymous -s >/dev/null 2>&1
for p in "$PI/jwks" "$PS/"; do
    for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p")" != 000 ] && break; sleep 0.1; done
done
"$BIN" idp-user auth add alice --password alicepassword1 --email alice@example.test >/dev/null 2>&1
"$BIN" create mail m -p "$P" --mail-domain example.test --idp auth --storage st/mail -s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$P" || bad "port $P listens" "$(tail -3 "$SOCKETLEY_DLOG")"

python3 - "$P" <<'PY'
import smtplib, sys
s = smtplib.SMTP("127.0.0.1", int(sys.argv[1])); s.ehlo("x")
for i in range(3):
    s.sendmail("carol@else.test", ["alice@example.test"],
        "From: Carol <carol@else.test>\r\nTo: alice@example.test\r\nSubject: number %d\r\nMessage-ID: <%d@else.test>\r\n"
        "Date: Tue, 20 Oct 2026 10:00:00 +0200\r\n\r\nbody %d\r\n" % (i, i, i))
PY
for _ in $(seq 1 100); do [ "$(curl -s "http://127.0.0.1:$PS/mail?list-type=2&prefix=alice/INBOX/" | grep -c '<Key>')" -ge 3 ] && break; sleep 0.1; done

# A second runtime on the same bucket, whose index has never heard of alice's mail; a listing takes up only what is a
# minute old, since a younger object is its writer's to log.
"$BIN" create mail m2 -p "$P2" --mail-domain example.test --idp auth --storage st/mail --jmap "$JM" -s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$JM" || bad "port $JM listens" "$(tail -3 "$SOCKETLEY_DLOG")"
sleep 62

cat > "$T/client.py" <<'PY'
import base64, http.client, json, sys
jm = int(sys.argv[1])
AUTH = "Basic " + base64.b64encode(b"alice:alicepassword1").decode()
def say(name, cond, why=""):
    print(("ok " if cond else "bad ") + name + ("" if cond else ": " + str(why)[:500]))
def call(body):
    c = http.client.HTTPConnection("127.0.0.1", jm, timeout=20)
    c.request("POST", "/jmap/api", json.dumps(body).encode(), {"Authorization": AUTH, "Content-Type": "application/json"})
    r = c.getresponse(); d = r.read(); c.close()
    return json.loads(d)["methodResponses"]
c = http.client.HTTPConnection("127.0.0.1", jm, timeout=20)
c.request("GET", "/.well-known/jmap", headers={"Authorization": AUTH}); s = json.loads(c.getresponse().read())
acct = s["primaryAccounts"]["urn:ietf:params:jmap:mail"]
U = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"]
r = call({"using": U, "methodCalls": [
    ["Email/query", {"accountId": acct, "calculateTotal": True, "sort": [{"property": "subject"}]}, "q"],
    ["Email/get", {"accountId": acct, "#ids": {"resultOf": "q", "name": "Email/query", "path": "/ids"},
                   "properties": ["subject"]}, "g"],
    ["Mailbox/get", {"accountId": acct, "properties": ["role", "totalEmails"]}, "m"]]})
q, g, m = r[0][1], r[1][1], r[2][1]
say("Email/query finds the three messages the bucket holds", q.get("total") == 3, q)
inbox = [x for x in m.get("list", []) if x.get("role") == "inbox"]
say("Mailbox/get counts them in the INBOX", inbox and inbox[0].get("totalEmails") == 3, m)
say("Email/get reads them", [x.get("subject") for x in g.get("list", [])] == ["number 0", "number 1", "number 2"], g)
PY
tally < <(python3 "$T/client.py" "$JM" 2>&1)

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && [ "$TOTAL" -eq 3 ] || exit 1
