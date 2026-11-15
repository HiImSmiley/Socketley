#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: --rate-limit holds a signed-in user to so many messages a second however they send them: SMTP
# submission, JMAP's EmailSubmission/set, and an imapsieve script that sends on what they put into a folder.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * SMTP submission past --rate-limit taken
#   * EmailSubmission/set past --rate-limit sending every message, or refusing with no rateLimit SetError
#   * an imapsieve redirect past --rate-limit sending every message a user APPENDs, or losing the one it holds back
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

daemon_isolate mail_rate_every_way
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1950))
IM=$((SL_PORT_BASE+1951))
JM=$((SL_PORT_BASE+1952))
PI=$((SL_PORT_BASE+1953))
PS=$((SL_PORT_BASE+1954))
SINK=$((SL_PORT_BASE+1955))
NS=$((SL_PORT_BASE+1956))
PIDS=()
cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: --rate-limit holds a user however they send ==="

python3 "$HERE/lib_fake_dns.py" "$NS" 0 normal remote.test=MX:10:mx.remote.test mx.remote.test=127.0.0.1 >/dev/null 2>&1 &
PIDS+=($!)
printf 'nameserver 127.0.0.1\noptions timeout:1 attempts:1 port:%s\n' "$NS" > "$T/resolv.conf"
export SOCKETLEY_RESOLV_CONF="$T/resolv.conf" SOCKETLEY_MAIL_MX_PORT="$SINK" SOCKETLEY_MAIL_LOCAL_EXCHANGERS=1
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
# One message every ten seconds, so what the test sends in a second or two is the first and no more.
"$BIN" create mail m -p "$P" --mail-domain example.test --idp auth --storage st/mail --imap "$IM" --jmap "$JM" \
    --rate-limit 0.1 -s >/dev/null 2>&1
for p in "$P" "$IM" "$JM"; do ready_tcp 127.0.0.1 "$p" || bad "port $p listens" "$(tail -3 "$SOCKETLEY_DLOG")"; done
printf 'redirect "onward@remote.test";\n' > "$T/fwd.sieve"
"$BIN" mail m sieve alice put fwd "$T/fwd.sieve" >/dev/null 2>&1 || bad "the imapsieve script is put" "-"

r=$(python3 - "$P" "$JM" "$IM" <<'PY'
import base64, http.client, imaplib, json, smtplib, sys
smtp, jm, im = (int(a) for a in sys.argv[1:4])
# SMTP submission: the first message taken, the second told 450.
s = smtplib.SMTP("127.0.0.1", smtp); s.ehlo("x"); s.login("alice", "alicepassword1")
codes = []
for i in range(2):
    try:
        s.sendmail("alice@example.test", ["smtp%d@remote.test" % i], "From: alice@example.test\r\nSubject: smtp %d\r\n\r\nx\r\n" % i)
        codes.append(250)
    except smtplib.SMTPResponseException as e:
        codes.append(e.smtp_code)
    except smtplib.SMTPRecipientsRefused as e:
        codes.append(list(e.recipients.values())[0][0])
    except smtplib.SMTPSenderRefused as e:
        codes.append(e.smtp_code)
s.quit()
print("smtp", " ".join(map(str, codes)))
# JMAP: five drafts and their submissions in one request, past the limit.
AUTH = "Basic " + base64.b64encode(b"alice:alicepassword1").decode()
U = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:submission"]
def api(calls):
    c = http.client.HTTPConnection("127.0.0.1", jm, timeout=60)
    c.request("POST", "/jmap/api", body=json.dumps({"using": U, "methodCalls": calls}).encode(),
              headers={"Authorization": AUTH, "Content-Type": "application/json"})
    r = c.getresponse(); d = json.loads(r.read()); c.close()
    return {cid: a for _, a, cid in d["methodResponses"]}
r = api([["Mailbox/get", {"ids": None}, "m"]])
box = [b["id"] for b in r["m"]["list"] if b.get("role") == "drafts"] or [r["m"]["list"][0]["id"]]
drafts = {"d%d" % i: {"mailboxIds": {box[0]: True}, "from": [{"email": "alice@example.test"}],
                      "to": [{"email": "jmap%d@remote.test" % i}], "subject": "jmap %d" % i,
                      "textBody": [{"partId": "t", "type": "text/plain"}], "bodyValues": {"t": {"value": "x"}}}
          for i in range(5)}
subs = {"s%d" % i: {"identityId": "i0", "emailId": "#d%d" % i} for i in range(5)}
r = api([["Email/set", {"create": drafts}, "d"], ["EmailSubmission/set", {"create": subs}, "s"]])
types = sorted(set(e.get("type") for e in (r["s"].get("notCreated") or {}).values()))
print("jmap", len(r["s"].get("created") or {}), len(r["s"].get("notCreated") or {}), ",".join(types) or "-")
# imapsieve: five messages APPENDed into a folder whose script sends each on.
imaplib.Commands["SETMETADATA"] = ("AUTH", "SELECTED")
M = imaplib.IMAP4("127.0.0.1", im); M.login("alice", "alicepassword1")
M.create("Onward"); M._simple_command("SETMETADATA", "Onward", '(/shared/imapsieve/script "fwd")')
for i in range(5):
    M.append("Onward", None, None, ("From: alice@example.test\r\nSubject: onward %d\r\n\r\nx\r\n" % i).encode())
PY
)
case "$(sed -n 1p <<<"$r")" in "smtp 250 450") ok "SMTP submission takes one message and tells the next 450" ;;
    *) bad "SMTP submission takes one message and tells the next 450" "$r" ;; esac
set -- $(sed -n 2p <<<"$r")
[ "${1:-}" = jmap ] && [ "${2:-9}" -le 1 ] && [ "${3:-0}" -ge 4 ] && [ "${4:-}" = rateLimit ] \
    && ok "EmailSubmission/set past --rate-limit is refused rateLimit" \
    || bad "EmailSubmission/set past --rate-limit is refused rateLimit" "$(sed -n 2p <<<"$r") (created, notCreated, types)"
sleep 3
onward=$(grep -l 'Subject: onward' "$T"/sink/*.eml 2>/dev/null | wc -l)
kept=$(python3 - "$IM" <<'PY'
import imaplib, sys
M = imaplib.IMAP4("127.0.0.1", int(sys.argv[1])); M.login("alice", "alicepassword1")
M.select("Onward"); print(len(M.search(None, "ALL")[1][0].split()))
PY
)
[ "$onward" -le 1 ] && [ "$((onward + kept))" -ge 5 ] \
    && ok "an imapsieve redirect past --rate-limit sends none on, and keeps what it did not send" \
    || bad "an imapsieve redirect past --rate-limit sends none on, and keeps what it did not send" "sent $onward, kept $kept"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
