#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a large attachment downloaded over JMAP is parsed out of its message and decoded off the mail
# runtime's loop, and arrives whole.
#
# What each part would catch:
#   * the message parsed and the part's base64 undone on the loop for every download: beside downloads of a 16 MiB
#     attachment a JMAP request waited 60 to 70 ms
#   * a part decoded wrong, or handed out before the pool is done with it: a download that is not the attachment
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
. "$HERE/lib_ready.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a JMAP download of a large attachment is made off the loop ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
if nm -C "$BIN" 2>/dev/null | grep -q '__asan_'; then
    echo "  SKIP: a stall in milliseconds measures the sanitizer, not the download"; exit 0
fi
daemon_isolate jmapdl
T=$SOCKETLEY_TMPD
PI=$((SL_PORT_BASE + 1981)); PS=$((SL_PORT_BASE + 1982)); P=$((SL_PORT_BASE + 1983))
IM=$((SL_PORT_BASE + 1984)); JM=$((SL_PORT_BASE + 1985))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
daemon_start "$BIN"
printf 'spa - http://localhost:5173/cb\n' > "$T/clients"
"$BIN" create idp auth -p "$PI" --clients "$T/clients" --issuer "http://127.0.0.1:$PI" -s >/dev/null 2>&1
"$BIN" create storage st -p "$PS" --dir "$T/data" --anonymous -s >/dev/null 2>&1
for p in "$PI/jwks" "$PS/"; do
    for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p")" != 000 ] && break; sleep 0.1; done
done
"$BIN" idp-user auth add alice --password alicepassword1 --email alice@example.test --set mail_quota=200M >/dev/null 2>&1
"$BIN" create mail m -p "$P" --mail-domain example.test --idp auth --storage st/mail --imap "$IM" --jmap "$JM" -s \
    >/dev/null 2>&1
for p in "$P" "$JM"; do ready_tcp 127.0.0.1 "$p" || bad "port $p listens" "$(tail -3 "$SOCKETLEY_DLOG")"; done

out=$(timeout 240 python3 - "$P" "$JM" <<'PY'
import base64, http.client, json, os, smtplib, sys, threading, time
p, jm = int(sys.argv[1]), int(sys.argv[2])
blob = os.urandom(16 << 20)
s = smtplib.SMTP("127.0.0.1", p); s.ehlo("x")
s.sendmail("dave@else.test", ["alice@example.test"],
    "From: dave@else.test\r\nTo: alice@example.test\r\nSubject: big file\r\nMIME-Version: 1.0\r\n"
    "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nsee\r\n"
    "--b\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=x.bin\r\n"
    "Content-Transfer-Encoding: base64\r\n\r\n" + base64.encodebytes(blob).decode().replace("\n", "\r\n") + "--b--\r\n")
s.quit()
AUTH = "Basic " + base64.b64encode(b"alice:alicepassword1").decode()
def call(method, path, body=None):
    c = http.client.HTTPConnection("127.0.0.1", jm, timeout=60)
    h = {"Authorization": AUTH}
    if body is not None:
        body = json.dumps(body).encode(); h["Content-Type"] = "application/json"
    c.request(method, path, body=body, headers=h); r = c.getresponse(); d = r.read(); c.close()
    return r.status, d
acct = list(json.loads(call("GET", "/.well-known/jmap")[1])["accounts"])[0]
U = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"]
att = None
for _ in range(150):
    r = json.loads(call("POST", "/jmap/api", {"using": U, "methodCalls": [["Email/query", {"accountId": acct}, "q"],
        ["Email/get", {"accountId": acct, "#ids": {"resultOf": "q", "name": "Email/query", "path": "/ids"},
                       "properties": ["attachments"]}, "g"]]})[1])["methodResponses"]
    got = r[1][1].get("list", [])
    if got and got[0].get("attachments"):
        att = got[0]["attachments"][0]["blobId"]; break
    time.sleep(0.2)
if not att:
    print("none 0 0"); sys.exit(0)
worst = [0.0]; stop = [False]
def probe():
    c = http.client.HTTPConnection("127.0.0.1", jm, timeout=60)
    while not stop[0]:
        t = time.perf_counter(); c.request("GET", "/.well-known/jmap", headers={"Authorization": AUTH}); c.getresponse().read()
        worst[0] = max(worst[0], (time.perf_counter() - t) * 1000); time.sleep(0.002)
th = threading.Thread(target=probe); th.start()
# The probe's first request checks the password, which is meant to be slow, and says nothing of the loop.
time.sleep(2); worst[0] = 0.0
whole = 0
for _ in range(5):
    st, d = call("GET", "/jmap/download/%s/%s/x.bin" % (acct, att))
    whole += st == 200 and d == blob
stop[0] = True; th.join()
print("%s %d %.1f" % (att, whole, worst[0]))
PY
)
read -r att whole worst <<<"$out"
echo "  five downloads of a 16 MiB attachment: ${whole:-0} whole, the worst JMAP request beside them ${worst:-none} ms"
[ "${att:-none}" != none ] && ok || bad "the message and its attachment arrive" "$out"
[ "${whole:-0}" = 5 ] && ok || bad "every download is the attachment, whole" "${whole:-0} of 5"
if awk -v w="${worst:-999}" 'BEGIN{exit !(w < 25)}'; then ok
else bad "a request beside them never waits behind the parse and the decoding" "${worst:-none} ms"; fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
