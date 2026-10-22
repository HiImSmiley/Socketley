#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: what a mail runtime does beside SMTP and IMAP -- POP3, LMTP, greylisting, the Sender Rewriting
# Scheme, its MTA-STS policy, sub-addresses, a quota warning -- and how it treats a server that is busy or takes
# few recipients at once.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * POP3 not answering STAT/LIST/UIDL/RETR/TOP as RFC 1939 says, or DELE not removing the message at QUIT
#   * LMTP answering once for all recipients rather than once each, or taking EHLO
#   * a stranger let in on its first try under --greylist, or kept out once it came back
#   * forwarded mail sent on under the stranger's own address, so SPF at the far end fails it
#   * a bounce to the rewritten address not taken, or a forged one taken
#   * the MTA-STS policy not served, or served for a domain not its own
#   * mail to user+tag@ refused rather than delivered to user
#   * no warning once a mailbox passes --quota-warn of its quota
#   * a server's LIMITS RCPTMAX ignored, so recipients past it are put off to a retry
#   * a server that said 421 connected to again at once by the next message
#   * what Rspamd says to reject taken, what it says to mark kept in INBOX, or its score not told to the mailbox
#   * mail taken by a sharded runtime's shards not all delivered, or not listed together as it waits
#   * a quiet connection, or a TLS handshake that never comes, held open for ever
#   * a message refused for now not tried again by itself, or kept past --queue-lifetime rather than given up
#     and bounced; a server that answers 354 to a pipelined DATA after refusing every RCPT left waiting for the
#     data, so the connection hangs and the retry never comes
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ready.sh"

command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
command -v openssl >/dev/null 2>&1 || { echo "  SKIP: openssl is required"; exit 0; }

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate mail_more
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1900))
POP=$((SL_PORT_BASE+1901))
LMTP=$((SL_PORT_BASE+1902))
STS=$((SL_PORT_BASE+1903))
PI=$((SL_PORT_BASE+1904))
PS=$((SL_PORT_BASE+1905))
PG=$((SL_PORT_BASE+1906))
NS=$((SL_PORT_BASE+1907))
SINK=$((SL_PORT_BASE+1908))
PB=$((SL_PORT_BASE+1909))
POPS=$((SL_PORT_BASE+1910))
RSP=$((SL_PORT_BASE+1911))
PLT=$((SL_PORT_BASE+1913))
PSH=$((SL_PORT_BASE+1914))
PSP=$((SL_PORT_BASE+1912))
PIDS=()
cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: POP3, LMTP, greylisting, SRS, MTA-STS, sub-addresses, quotas and busy servers ==="

# remote.test takes mail at the sink; busy.test at a server that says 421; few.test at one that takes two at a time.
python3 "$HERE/lib_fake_dns.py" "$NS" 0 normal remote.test=MX:10:mx.remote.test mx.remote.test=127.0.0.1 \
    busy.test=MX:10:mx.busy.test mx.busy.test=127.0.0.3 few.test=MX:10:mx.few.test mx.few.test=127.0.0.4 \
    temp.test=MX:10:mx.temp.test mx.temp.test=127.0.0.5 \
    "b.test=TXT:v=spf1 ip4:127.0.0.2 -all" >/dev/null 2>&1 &
PIDS+=($!)
printf 'nameserver 127.0.0.1\noptions timeout:1 attempts:1 port:%s\n' "$NS" > "$T/resolv.conf"
export SOCKETLEY_RESOLV_CONF="$T/resolv.conf" SOCKETLEY_MAIL_MX_PORT="$SINK" SOCKETLEY_MAIL_BUSY_HOLD_MS=3000 \
    SOCKETLEY_MAIL_QUEUE_SCALE=60 SOCKETLEY_MAIL_IDLE_MS=3000
mkdir -p "$T/sink"
python3 "$HERE/lib_smtp_sink.py" "$SINK" "$T/sink" >/dev/null 2>&1 &
PIDS+=($!)

# The servers of busy.test and few.test, on the sink's port of their own addresses, writing a line per connection
# and per transaction.
cat > "$T/servers.py" <<'PY'
import socket, sys, threading
port, log = int(sys.argv[1]), sys.argv[2]
lock = threading.Lock()
def note(s):
    with lock:
        with open(log, "a") as f: f.write(s + "\n")
def serve(conn, kind):
    f = conn.makefile("rb")
    def say(x): conn.sendall(x.encode())
    note(kind + " connect")
    if kind == "busy":
        say("421 4.7.0 busy, try later\r\n"); conn.close(); return
    say("220 %s ESMTP\r\n" % kind)
    rcpts = 0
    while True:
        line = f.readline()
        if not line: break
        v = line.decode(errors="replace").rstrip("\r\n").upper()
        if v.startswith("EHLO"): say("250-few\r\n250-PIPELINING\r\n250 LIMITS RCPTMAX=2\r\n")
        elif v.startswith("MAIL"): rcpts = 0; say("250 ok\r\n")
        elif v.startswith("RCPT"):
            rcpts += 1
            if kind == "temp": say("451 4.3.0 not now\r\n")
            else: say("250 ok\r\n" if rcpts <= 2 else "452 4.5.3 too many recipients\r\n")
        elif v == "DATA":
            say("354 go\r\n")
            while f.readline() not in (b".\r\n", b""): pass
            note("few transaction %d" % min(rcpts, 2)); say("250 ok\r\n")
        elif v == "QUIT": say("221 bye\r\n"); break
        else: say("250 ok\r\n")
    conn.close()
def listen(addr, kind):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind((addr, port)); s.listen(16)
    while True:
        c, _ = s.accept(); threading.Thread(target=serve, args=(c, kind), daemon=True).start()
threading.Thread(target=listen, args=("127.0.0.3", "busy"), daemon=True).start()
threading.Thread(target=listen, args=("127.0.0.5", "temp"), daemon=True).start()
listen("127.0.0.4", "few")
PY
: > "$T/servers.log"
python3 "$T/servers.py" "$SINK" "$T/servers.log" >/dev/null 2>&1 &
PIDS+=($!)
ready_tcp 127.0.0.1 "$SINK" || bad "the sink listens" "-"
ready_tcp 127.0.0.4 "$SINK" || bad "few.test's server listens" "-"
ready_tcp 127.0.0.5 "$SINK" || bad "temp.test's server listens" "-"

openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=mail.example.test" \
    -keyout "$T/key.pem" -out "$T/cert.pem" >/dev/null 2>&1
daemon_start "$BIN"
printf 'spa - http://localhost:5173/cb\n' > "$T/clients"
"$BIN" create idp auth -p "$PI" --clients "$T/clients" --issuer "http://127.0.0.1:$PI" -s >/dev/null 2>&1
"$BIN" create storage st -p "$PS" --dir "$T/data" --anonymous -s >/dev/null 2>&1
for p in "$PI/jwks" "$PS/"; do
    for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p")" != 000 ] && break; sleep 0.1; done
done
"$BIN" idp-user auth add alice --password alicepassword1 --email alice@example.test >/dev/null 2>&1
"$BIN" idp-user auth add carl --password carlpassword12 --email carl@example.test >/dev/null 2>&1
printf 'info@example.test bob@remote.test\n' > "$T/aliases"
"$BIN" create mail m -p "$P" --mail-domain example.test --idp auth --storage st/mail --aliases "$T/aliases" \
    --pop3 "$POP" --pop3s "$POPS" --lmtp "$LMTP" --mta-sts enforce --mta-sts-port "$STS" --tls-rpt tlsrpt@example.test \
    --default-quota 4K --quota-warn 50 --tls --cert "$T/cert.pem" --key "$T/key.pem" -s >/dev/null 2>&1
"$BIN" create mail g -p "$PG" --mail-domain example.test --aliases "$T/aliases" --greylist 1s -s >/dev/null 2>&1
"$BIN" create mail b -p "$PB" --mail-domain example.test -s >/dev/null 2>&1
"$BIN" create mail lt -p "$PLT" --mail-domain example.test --queue-lifetime 1m -s >/dev/null 2>&1
"$BIN" create mail sh -p "$PSH" --mail-domain example.test --shards 3 -s >/dev/null 2>&1
for p in "$P" "$POP" "$POPS" "$LMTP" "$STS" "$PG" "$PB" "$PLT" "$PSH"; do
    ready_tcp 127.0.0.1 "$p" || bad "port $p listens" "$(tail -3 "$SOCKETLEY_DLOG")"
done

inbox_count() {
    curl -s "http://127.0.0.1:$PS/mail?list-type=2&prefix=$1/INBOX/" | grep -o '<Key>' | wc -l
}
wait_inbox() {
    for _ in $(seq 1 100); do [ "$(inbox_count "$1")" -ge "$2" ] && break; sleep 0.1; done
}

# ─── sub-addresses ──────────────────────────────────────────────────────────
r=$(python3 - "$P" <<'PY'
import smtplib, sys
s = smtplib.SMTP("127.0.0.1", int(sys.argv[1])); s.ehlo("x")
print(s.sendmail("dave@else.test", ["alice+news@example.test"],
      "From: dave@else.test\r\nTo: alice+news@example.test\r\nSubject: tagged\r\n\r\nfor the tag\r\n"))
PY
)
check "mail to user+tag@ is taken" "$r" "{}"
wait_inbox alice 1
check "and lands in user's own INBOX" "$(inbox_count alice)" "1"

# ─── POP3 ───────────────────────────────────────────────────────────────────
python3 - "$P" <<'PY'
import smtplib, sys
s = smtplib.SMTP("127.0.0.1", int(sys.argv[1])); s.ehlo("x")
s.sendmail("erin@else.test", ["alice@example.test"],
           "From: erin@else.test\r\nTo: alice@example.test\r\nSubject: second\r\n\r\n.a line that starts with a dot\r\nend\r\n")
PY
wait_inbox alice 2
r=$(python3 - "$POP" <<'PY'
import poplib, sys
M = poplib.POP3("127.0.0.1", int(sys.argv[1]), timeout=5)
M.user("alice"); M.pass_("alicepassword1")
n, size = M.stat()
print("stat", n)
print("list", len(M.list()[1]))
uidl = [l.decode().split()[1] for l in M.uidl()[1]]
print("uidl", len(set(uidl)))
body = b"\n".join(M.retr(2)[1])
print("retr", b".a line that starts with a dot" in body and b"Subject: second" in body)
top = b"\n".join(M.top(1, 0)[1])
print("top", b"Subject: tagged" in top and b"for the tag" not in top)
M.dele(1)
M.quit()
M = poplib.POP3("127.0.0.1", int(sys.argv[1]), timeout=5)
M.user("alice"); M.pass_("alicepassword1")
print("after", M.stat()[0])
print("same", [l.decode().split()[1] for l in M.uidl()[1]] == uidl[1:])
M.quit()
PY
)
check "POP3 STAT counts the maildrop" "$(sed -n 's/^stat //p' <<<"$r")" "2"
check "and LIST lists each" "$(sed -n 's/^list //p' <<<"$r")" "2"
check "and UIDL names each apart" "$(sed -n 's/^uidl //p' <<<"$r")" "2"
check "and RETR gives the message whole, a leading dot undone" "$(sed -n 's/^retr //p' <<<"$r")" "True"
check "and TOP n 0 gives the header alone" "$(sed -n 's/^top //p' <<<"$r")" "True"
check "a message DELE marked is gone after QUIT" "$(sed -n 's/^after //p' <<<"$r")" "1"
check "and the one left keeps its UIDL" "$(sed -n 's/^same //p' <<<"$r")" "True"
check "and it is gone from the storage" "$(inbox_count alice)" "1"
r=$(python3 - "$POPS" <<'PY'
import poplib, ssl, sys
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
M = poplib.POP3_SSL("127.0.0.1", int(sys.argv[1]), context=ctx, timeout=5)
M.user("alice"); M.pass_("alicepassword1")
print(M.stat()[0]); M.quit()
PY
)
check "POP3 over TLS from its first byte reads the same maildrop" "$r" "1"
r=$(python3 - "$POP" <<'PY'
import poplib, sys
M = poplib.POP3("127.0.0.1", int(sys.argv[1]), timeout=5)
try:
    M.user("alice"); M.pass_("wrong-password"); print("in")
except poplib.error_proto as e:
    print(e.args[0].decode().split()[0])
PY
)
check "and a wrong password is -ERR" "$r" "-ERR"

# ─── LMTP ───────────────────────────────────────────────────────────────────
r=$(python3 - "$LMTP" <<'PY'
import smtplib, sys
s = smtplib.LMTP("127.0.0.1", int(sys.argv[1]))
print("ehlo", s.docmd("EHLO", "x")[0])
s.ehlo_resp = None
print("lhlo", s.docmd("LHLO", "x")[0])
s.helo_resp = s.ehlo_resp = b"x"; s.esmtp_features = {}
s.mail("frank@else.test")
print("rcpt", s.rcpt("carl@example.test")[0], s.rcpt("info@example.test")[0])
print("rcpt2", s.rcpt("alice@example.test")[0])
s.putcmd("DATA"); s.getreply()
s.send(b"From: frank@else.test\r\nSubject: lmtp\r\n\r\nby lmtp\r\n.\r\n")
print("replies", s.getreply()[0], s.getreply()[0])
PY
)
check "LMTP refuses EHLO" "$(sed -n 's/^ehlo //p' <<<"$r")" "500"
check "and greets LHLO" "$(sed -n 's/^lhlo //p' <<<"$r")" "250"
check "and takes only a mailbox, not an alias that goes elsewhere" "$(sed -n 's/^rcpt //p' <<<"$r")" "250 550"
check "and answers the data once per recipient it took" "$(sed -n 's/^replies //p' <<<"$r")" "250 250"
wait_inbox carl 1
check "and the mailbox has it" "$(inbox_count carl)" "1"

# ─── quota warning ──────────────────────────────────────────────────────────
python3 - "$P" <<'PY'
import smtplib, sys
s = smtplib.SMTP("127.0.0.1", int(sys.argv[1])); s.ehlo("x")
s.sendmail("gus@else.test", ["carl@example.test"],
           "From: gus@else.test\r\nTo: carl@example.test\r\nSubject: big\r\n\r\n" + "x" * 2500 + "\r\n")
PY
wait_inbox carl 3
check "a mailbox past --quota-warn of its quota is told once" "$(inbox_count carl)" "3"
warn=$(python3 - "$PI" "$PS" <<'PY'
import sys, urllib.request, re
lst = urllib.request.urlopen("http://127.0.0.1:%s/mail?list-type=2&prefix=carl/INBOX/" % sys.argv[2]).read().decode()
for k in re.findall("<Key>([^<]*)</Key>", lst):
    body = urllib.request.urlopen("http://127.0.0.1:%s/mail/%s" % (sys.argv[2], k)).read().decode(errors="replace")
    if "full" in body and "Auto-Submitted" in body:
        print(re.search("Subject: (.*)", body).group(1).strip()); break
PY
)
[[ "$warn" == "Your mailbox is "*"% full" ]] && ok "and the warning says how full it is" || bad "the warning" "$warn"

# ─── MTA-STS ────────────────────────────────────────────────────────────────
r=$(curl -sk --resolve "mta-sts.example.test:$STS:127.0.0.1" "https://mta-sts.example.test:$STS/.well-known/mta-sts.txt")
check "its MTA-STS policy is served for its domain" "$(printf '%s' "$r" | tr -d '\r' | head -2 | tr '\n' ' ')" \
    "version: STSv1 mode: enforce "
[[ "$r" == *"mx: "* ]] && ok "and names its exchanger" || bad "and names its exchanger" "$r"
check "and not for another" "$(curl -sk -o /dev/null -w '%{http_code}' --resolve "mta-sts.else.test:$STS:127.0.0.1" \
    "https://mta-sts.else.test:$STS/.well-known/mta-sts.txt")" "404"
recs=$("$BIN" mail m dns 2>/dev/null)
[[ "$recs" == *'_mta-sts.example.test. 300 IN TXT "v=STSv1; id='* ]] && ok "and its record is published" \
    || bad "and its record is published" "$recs"
[[ "$recs" == *'_smtp._tls.example.test. 300 IN TXT "v=TLSRPTv1; rua=mailto:tlsrpt@example.test"'* ]] \
    && ok "and where TLS reports go" || bad "and where TLS reports go" "$recs"
[[ "$recs" == *"mta-sts.example.test. 300 IN CNAME mail.example.test."* ]] && ok "and the policy's host" \
    || bad "and the policy's host" "$recs"
[[ "$recs" == *"_pop3._tcp.example.test. 300 IN SRV 0 1 $POP "* ]] && ok "and its POP3 port" \
    || bad "and its POP3 port" "$recs"

# ─── greylisting ────────────────────────────────────────────────────────────
cat > "$T/grey.py" <<'PY'
import smtplib, sys, time
def once(rcpt, src):
    s = smtplib.SMTP("127.0.0.1", int(sys.argv[1]), source_address=(src, 0)); s.ehlo("x")
    s.mail("hal@b.test"); c = s.rcpt(rcpt)[0]; s.quit(); return c
print(once("info@example.test", "127.0.0.2"), once("info@example.test", "127.0.0.2"))
time.sleep(1.3)
print(once("info@example.test", "127.0.0.2"), once("info@example.test", "127.0.0.2"))
print(once("info@example.test", "127.0.0.1"))
PY
r=$(python3 "$T/grey.py" "$PG")
check "a stranger's first tries are put off" "$(sed -n 1p <<<"$r")" "451 451"
check "and once it comes back after the delay it is taken, and from then on" "$(sed -n 2p <<<"$r")" "250 250"
check "and this machine's own programs are never greylisted" "$(sed -n 3p <<<"$r")" "250"

# ─── SRS ────────────────────────────────────────────────────────────────────
python3 - "$P" <<'PY'
import smtplib, sys
s = smtplib.SMTP("127.0.0.1", int(sys.argv[1]), source_address=("127.0.0.2", 0)); s.ehlo("x")
s.sendmail("hal@b.test", ["info@example.test"], "From: hal@b.test\r\nTo: info@example.test\r\nSubject: fwd\r\n\r\nforwarded on\r\n")
PY
f=""
for _ in $(seq 1 100); do f=$(grep -l "forwarded on" "$T"/sink/* 2>/dev/null | head -1); [ -n "$f" ] && break; sleep 0.1; done
srs=$(sed -n 's/^from //p' "$f" 2>/dev/null | head -1)
[[ "$srs" == SRS0=*=b.test=hal@example.test ]] && ok "forwarded mail goes on from an SRS address of this domain" \
    || bad "forwarded mail goes on from an SRS address of this domain" "$srs"
r=$(python3 - "$P" "$srs" <<'PY'
import smtplib, sys
s = smtplib.SMTP("127.0.0.1", int(sys.argv[1]), source_address=("127.0.0.2", 0)); s.ehlo("x")
s.mail("")
good = s.rcpt(sys.argv[2])[0]
forged = sys.argv[2].replace("SRS0=", "SRS0=x", 1)
print(good, s.rcpt(forged)[0])
PY
)
check "a bounce to it is taken, and one to a forged one refused" "$r" "250 550"

# ─── LIMITS ─────────────────────────────────────────────────────────────────
r=$(python3 - "$P" <<'PY'
import smtplib, sys
s = smtplib.SMTP("127.0.0.1", int(sys.argv[1])); s.ehlo("x")
print(s.has_extn("limits"), s.esmtp_features.get("limits", ""))
PY
)
[[ "$r" == "True RCPTMAX="* ]] && ok "EHLO says how many recipients a transaction takes (RFC 9422)" || bad "LIMITS" "$r"
"$BIN" send b --from ops@example.test --to a@few.test --to b@few.test --to c@few.test --to d@few.test --to e@few.test --subject five \
    --text "to five" >/dev/null 2>&1
for _ in $(seq 1 100); do [ "$(grep -c 'few transaction' "$T/servers.log")" -ge 3 ] && break; sleep 0.1; done
check "a server's RCPTMAX=2 has five recipients sent in three transactions, not put off" \
    "$(grep 'few transaction' "$T/servers.log" | awk '{s+=$3} END {print NR, s}')" "3 5"

# ─── a server that says 421 ─────────────────────────────────────────────────
"$BIN" send b --from ops@example.test --to x@busy.test --subject one --text one >/dev/null 2>&1
for _ in $(seq 1 50); do grep -q 'busy connect' "$T/servers.log" && break; sleep 0.1; done
"$BIN" send b --from ops@example.test --to y@busy.test --subject two --text two >/dev/null 2>&1
sleep 1.5
check "after a 421 the next message does not connect again at once" "$(grep -c 'busy connect' "$T/servers.log")" "1"
for _ in $(seq 1 60); do [ "$(grep -c 'busy connect' "$T/servers.log")" -ge 2 ] && break; sleep 0.1; done
check "but once the pause is over it does" "$([ "$(grep -c 'busy connect' "$T/servers.log")" -ge 2 ] && echo yes)" "yes"

# ─── quiet connections ──────────────────────────────────────────────────────
r=$(python3 - "$PB" "$POPS" <<'PY'
import socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=10)
f = s.makefile("rb"); f.readline()
t0 = time.time(); said = f.readline().decode(errors="replace").strip(); gone = s.recv(1) == b""
print(said.split()[0] if said else "-", gone, 2 <= time.time() - t0 <= 8)
# A TLS port whose client never begins the handshake.
p = socket.create_connection(("127.0.0.1", int(sys.argv[2])), timeout=10)
t0 = time.time()
try:
    closed = p.recv(1) == b""
except OSError:
    closed = True
print(closed, 2 <= time.time() - t0 <= 8)
PY
)
check "a quiet SMTP connection is told 421 and closed, once its time is up" "$(sed -n 1p <<<"$r")" "421 True True"
check "and a TLS handshake that never begins is closed" "$(sed -n 2p <<<"$r")" "True True"

# ─── tried again, and given up ──────────────────────────────────────────────
"$BIN" send lt --from ops@remote.test --to x@temp.test --subject "never taken" --text "never taken" >/dev/null 2>&1
f=""
for _ in $(seq 1 100); do f=$(grep -l "5.4.7 given up after" "$T"/sink/* 2>/dev/null | head -1); [ -n "$f" ] && break; sleep 0.1; done
tries=$(grep -c 'temp connect' "$T/servers.log")
[ "$tries" -ge 2 ] && ok "a message refused for now is tried again by itself ($tries tries)" \
    || bad "a message refused for now is tried again by itself" "$tries tries"
[ -n "$f" ] && grep -q '^Action: failed' "$f" && grep -q 'x@temp.test' "$f" \
    && ok "and past --queue-lifetime it is given up and bounced to its sender" \
    || bad "and past --queue-lifetime it is given up and bounced to its sender" \
           "$(ls "$T/sink" | wc -l) at the sink, queue: $("$BIN" mail lt queue 2>&1 | head -3 | tr '\n' ' ')"

# ─── a runtime of three shards ──────────────────────────────────────────────
for _ in $(seq 1 50); do [ "$(ss -ltnpH "sport = :$PSH" | grep -o 'pid=[0-9]*' | sort -u | wc -l)" -ge 3 ] && break; sleep 0.1; done
r=$(python3 - "$PSH" <<'PY'
import smtplib, sys
# Each a connection of its own, so the kernel spreads them over the shards.
for i in range(12):
    s = smtplib.SMTP("127.0.0.1", int(sys.argv[1])); s.ehlo("x")
    s.sendmail("ops@remote.test", ["good%d@remote.test" % i], "From: ops@remote.test\r\nSubject: sharded %d\r\n\r\nsharded body\r\n" % i)
    s.sendmail("shard@remote.test", ["held%d@temp.test" % i], "From: shard@remote.test\r\nSubject: held %d\r\n\r\nheld\r\n" % i)
    s.quit()
print("sent")
PY
)
for _ in $(seq 1 100); do [ "$(grep -l 'sharded body' "$T"/sink/* 2>/dev/null | wc -l)" -ge 12 ] && break; sleep 0.1; done
check "twelve messages over connections the shards share are all delivered" "$(grep -l 'sharded body' "$T"/sink/* 2>/dev/null | wc -l)" "12"
check "and twelve that wait are each in a shard's queue, listed together" "$("$BIN" mail sh queue 2>/dev/null | grep -c $'\tshard@remote.test\t')" "12"

# ─── Rspamd ─────────────────────────────────────────────────────────────────
python3 - "$RSP" >/dev/null 2>&1 <<'PY' &
import http.server, json, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.path != "/checkv2": self.send_response(404); self.end_headers(); return
        act, score = ("reject", 20.0) if b"spammy" in body else ("add header", 7.5) if b"junky" in body else ("no action", 0.5)
        out = json.dumps({"action": act, "score": score, "required_score": 15.0}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
PIDS+=($!)
ready_tcp 127.0.0.1 "$RSP" || bad "the fake Rspamd listens" "-"
"$BIN" create mail sp -p "$PSP" --mail-domain example.test --idp auth --storage st/mail --rspamd "http://127.0.0.1:$RSP" \
    -s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$PSP" || bad "the scanned runtime listens" "$(tail -3 "$SOCKETLEY_DLOG")"
r=$(python3 - "$PSP" <<'PY'
import smtplib, sys
def send(subject):
    s = smtplib.SMTP("127.0.0.1", int(sys.argv[1]), source_address=("127.0.0.2", 0)); s.ehlo("x")
    try:
        s.sendmail("hal@b.test", ["carl@example.test"], "From: hal@b.test\r\nTo: carl@example.test\r\nSubject: %s\r\n\r\nbody\r\n" % subject)
        return "250"
    except smtplib.SMTPDataError as e:
        return str(e.smtp_code)
print(send("spammy"), send("junky"), send("clean"))
PY
)
check "Rspamd's reject is refused, its add header and no action taken" "$r" "554 250 250"
for _ in $(seq 1 100); do [ "$(curl -s "http://127.0.0.1:$PS/mail?list-type=2&prefix=carl/Junk/" | grep -c '<Key>')" -ge 1 ] && break; sleep 0.1; done
check "what it marks is filed in Junk" "$(curl -s "http://127.0.0.1:$PS/mail?list-type=2&prefix=carl/Junk/" | grep -o '<Key>' | wc -l)" "1"
clean=""
for _ in $(seq 1 100); do
    for k in $(curl -s "http://127.0.0.1:$PS/mail?list-type=2&prefix=carl/INBOX/" | grep -o '<Key>[^<]*</Key>' | sed 's/<[^>]*>//g'); do
        b=$(curl -s "http://127.0.0.1:$PS/mail/$k"); [[ "$b" == *"Subject: clean"* ]] && clean=$b
    done
    [ -n "$clean" ] && break; sleep 0.1
done
[[ "$clean" == *"x-spam=no"* ]] && ok "and the mailbox is told its score in Authentication-Results" \
    || bad "and the mailbox is told its score in Authentication-Results" "$(grep -i 'authentication-results' <<<"$clean")"

echo ""
echo "Results: $PASS/$TOTAL passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
