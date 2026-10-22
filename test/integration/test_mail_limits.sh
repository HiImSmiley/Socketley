#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: what a mail runtime refuses a client that asks too much of it, and the bytes it will not take as
# they come.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * one address holding every connection, or a full runtime closing a connection without a word
#   * more recipients taken in one message than --max-recipients
#   * input a client pipelines while a command waits, or replies it never reads, held in memory without bound
#   * passwords guessed from one address without end, spread over connections
#   * --rate-limit accepted and not applied
#   * a lone CR relayed as it came, so the next server can end the message where this one did not
#   * the tail of a line past the limit, cut across reads, run as a command
#   * an EHLO name with control bytes, an ORCPT whose type is not an atom, taken
#   * a recipient given twice sent the message twice
#   * no listener over IPv6
#   * a From of authors of two domains passing DMARC by neither
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

daemon_isolate mail_limits
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1970))
SUB=$((SL_PORT_BASE+1971))
SINK=$((SL_PORT_BASE+1972))
NS=$((SL_PORT_BASE+1973))
PF=$((SL_PORT_BASE+1974))
PR=$((SL_PORT_BASE+1975))
PRC=$((SL_PORT_BASE+1976))
PIDS=()
cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a mail runtime's limits and the bytes it will not take as they come ==="

python3 "$HERE/lib_fake_dns.py" "$NS" 0 normal remote.test=MX:10:mx.remote.test mx.remote.test=127.0.0.1 \
    "a.test=TXT:v=spf1 -all" "_dmarc.a.test=TXT:v=DMARC1; p=reject" \
    "b.test=TXT:v=spf1 ip4:127.0.0.2 -all" "_dmarc.b.test=TXT:v=DMARC1; p=none" >/dev/null 2>&1 &
PIDS+=($!)
printf 'nameserver 127.0.0.1\noptions timeout:1 attempts:1 port:%s\n' "$NS" > "$T/resolv.conf"
export SOCKETLEY_RESOLV_CONF="$T/resolv.conf" SOCKETLEY_MAIL_MX_PORT="$SINK"
mkdir -p "$T/sink"
python3 "$HERE/lib_smtp_sink.py" "$SINK" "$T/sink" >/dev/null 2>&1 &
PIDS+=($!)
ready_tcp 127.0.0.1 "$SINK" || bad "the sink listens" "-"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=mail.example.test" \
    -keyout "$T/key.pem" -out "$T/cert.pem" >/dev/null 2>&1
printf 'alicepass1\n' | "$BIN" mqtt-passwd "$T/users" alice >/dev/null 2>&1
printf 'info@example.test bob@remote.test\n' > "$T/aliases"
daemon_start "$BIN"

"$BIN" create mail m -p "$P" --mail-domain example.test --submission "$SUB" --users "$T/users" --aliases "$T/aliases" --tls \
    --cert "$T/cert.pem" --key "$T/key.pem" --max-size 1000000 -s >/dev/null 2>&1
"$BIN" create mail full -p "$PF" --mail-domain example.test --max-connections 3 -s >/dev/null 2>&1
"$BIN" create mail rated -p "$PR" --mail-domain example.test --rate-limit 2 -s >/dev/null 2>&1
"$BIN" create mail capped -p "$PRC" --mail-domain example.test --aliases "$T/aliases" --max-recipients 3 -s >/dev/null 2>&1
for p in "$P" "$SUB" "$PF" "$PR" "$PRC"; do ready_tcp 127.0.0.1 "$p" || bad "port $p listens" "$(tail -3 "$SOCKETLEY_DLOG")"; done

# ─── connections ────────────────────────────────────────────────────────────
r=$(python3 - "$P" <<'PY'
import socket, sys
port = int(sys.argv[1])
held = []
for i in range(50):
    s = socket.create_connection(("127.0.0.2", port), timeout=5, source_address=("127.0.0.2", 0))
    s.recv(100); held.append(s)
s = socket.create_connection(("127.0.0.1", port), timeout=5, source_address=("127.0.0.2", 0))
print(s.recv(200).decode(errors="replace").split("\r\n")[0][:31])
PY
)
check "the 51st connection of one address is told 421" "$r" "421 4.7.0 mail.example.test too"
r=$(python3 - "$PF" <<'PY'
import socket, sys
port = int(sys.argv[1])
held = [socket.create_connection(("127.0.0.1", port), timeout=5) for _ in range(3)]
for s in held: s.recv(100)
s = socket.create_connection(("127.0.0.1", port), timeout=5)
print(s.recv(200).decode(errors="replace")[:9])
PY
)
check "a runtime at --max-connections tells the next one 421 rather than closing it unsaid" "$r" "421 4.7.0"
if python3 -c "import socket; socket.create_connection(('::1', $P), timeout=3).recv(4)" >/dev/null 2>&1; then
    ok "SMTP is taken over IPv6 as well"
else
    bad "SMTP is taken over IPv6 as well" "no connection to [::1]:$P"
fi

# ─── recipients of one message ──────────────────────────────────────────────
r=$(python3 - "$PRC" <<'PY'
import smtplib, sys
s = smtplib.SMTP("127.0.0.1", int(sys.argv[1])); s.ehlo("x"); s.mail("a@remote.test")
print(*[s.rcpt("info@example.test")[0] if i == 0 else s.rcpt("r%d@remote.test" % i)[0] for i in range(4)])
s.rset(); s.mail("a@remote.test")
print(s.rcpt("info@example.test")[0])
PY
)
check "past --max-recipients a RCPT is told 452, the ones before it taken" "$(sed -n 1p <<<"$r")" "250 250 250 452"
check "and the next transaction starts with none" "$(sed -n 2p <<<"$r")" "250"

# ─── what a client sends and does not read ──────────────────────────────────
# A wrong password holds the session a second, while three mebibytes are pipelined behind it.
r=$(python3 - "$SUB" <<'PY'
import base64, socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=10); f = s.makefile("rb"); f.readline()
s.sendall(b"EHLO x\r\n")
while not f.readline().startswith(b"250 "): pass
s.sendall(b"AUTH PLAIN " + base64.b64encode(b"\0alice\0wrong") + b"\r\n" + b"NOOP\r\n" * 500000)
f.readline()
print(f.readline().decode(errors="replace")[:9])
PY
)
check "input pipelined past a message's size while a command waits is answered 421" "$r" "421 4.7.0"
r=$(python3 - "$P" <<'PY'
import socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=20); s.recv(200)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
for _ in range(20):
    s.sendall(b"EHLO x\r\n" * 20000)
time.sleep(1)
got, start = 0, time.time()
try:
    while time.time() - start < 15:
        b = s.recv(1 << 20)
        if not b: print("closed"); break
        got += len(b)
    else: print("open")
except ConnectionResetError: print("closed")
except Exception as e: print("error", e)
PY
)
check "a client that reads none of its replies is closed" "$r" "closed"

# ─── passwords ──────────────────────────────────────────────────────────────
r=$(python3 - "$SUB" <<'PY'
import base64, smtplib, ssl, sys, threading
port = int(sys.argv[1])
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
def attempt(out, i):
    try:
        s = smtplib.SMTP("127.0.0.1", port, source_address=("127.0.0.3", 0), timeout=20)
        s.starttls(context=ctx); s.ehlo("x")
        code, _ = s.docmd("AUTH", "PLAIN " + base64.b64encode(b"\0alice\0wrong%d" % i).decode())
        out.append(code)
    except Exception as e:
        out.append(repr(e))
codes = []
ts = [threading.Thread(target=attempt, args=(codes, i)) for i in range(10)]
[t.start() for t in ts]; [t.join() for t in ts]
last = []
attempt(last, 99)
s = smtplib.SMTP("127.0.0.1", port, source_address=("127.0.0.3", 0), timeout=20)
s.starttls(context=ctx); s.ehlo("x")
right = s.docmd("AUTH", "PLAIN " + base64.b64encode(b"\0alice\0alicepass1").decode())[0]
print(sorted(set(codes)), last[0], right)
PY
)
check "ten wrong passwords from one address lock it out, the right one too, for now" "$r" "[535] 454 454"

# ─── --rate-limit ───────────────────────────────────────────────────────────
r=$(python3 - "$PR" <<'PY'
import smtplib, sys
s = smtplib.SMTP("127.0.0.1", int(sys.argv[1]), source_address=("127.0.0.2", 0)); s.ehlo("x")
codes = []
for i in range(5):
    codes.append(s.mail("s%d@remote.test" % i)[0]); s.rset()
print(" ".join(map(str, codes)))
PY
)
check "--rate-limit 2 takes two messages a second from an address and tells the rest 450" "$r" "250 250 450 450 450"

# ─── the bytes of a message ─────────────────────────────────────────────────
python3 - "$P" <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1]))); f = s.makefile("rb"); f.readline()
s.sendall(b"EHLO x\r\n")
while not f.readline().startswith(b"250 "): pass
s.sendall(b"MAIL FROM:<s@remote.test>\r\nRCPT TO:<cr@remote.test>\r\nRCPT TO:<cr@remote.test>\r\nDATA\r\n")
for _ in range(4): f.readline()
s.sendall(b"Subject: lone cr\r\n\r\nabc\r.\r\nafter the dot\r\n.\r\n"); f.readline()
PY
for _ in $(seq 1 50); do f=$(grep -l 'lone cr' "$T"/sink/*.eml 2>/dev/null | head -1); [ -n "$f" ] && break; sleep 0.1; done
python3 - "$f" <<'PY' && ok "a lone CR is relayed as a line's end, so a dot after it is a line of its own" \
    || bad "a lone CR is relayed as a line's end, so a dot after it is a line of its own" "$(od -c "$f" 2>/dev/null | tail -4)"
import sys
b = open(sys.argv[1], "rb").read()
sys.exit(0 if b"abc\r\n.\r\nafter the dot" in b and b"abc\r." not in b else 1)
PY
check "a recipient given twice gets the message once" "$(grep -c '^rcpt cr@remote.test' "$f" 2>/dev/null)" "1"
r=$(python3 - "$P" <<'PY'
import socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=3); f = s.makefile("rb"); f.readline()
s.sendall(b"X" * 4200); time.sleep(0.3); s.sendall(b"RSET\r\nNOOP\r\n")
out = []
try:
    for _ in range(3): out.append(f.readline()[:3].decode())
except Exception: pass
print(" ".join(o for o in out if o))
PY
)
check "the tail of a line past the limit, cut across reads, is not run as a command" "$r" "500 250"
r=$(python3 - "$P" <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=3); f = s.makefile("rb"); f.readline()
s.sendall(b"EHLO bad\rname\r\n"); print(f.readline()[:3].decode(), end=" ")
s.sendall(b"EHLO good.name\r\n")
while True:
    l = f.readline()
    if l.startswith(b"250 "): break
s.sendall(b"MAIL FROM:<s@remote.test>\r\nRCPT TO:<x@remote.test> ORCPT=a\x01b;x@y\r\n")
f.readline(); print(f.readline()[:3].decode())
PY
)
check "an EHLO name with a control byte and an ORCPT type that is no atom are refused 501" "$r" "501 501"

# ─── DMARC ──────────────────────────────────────────────────────────────────
r=$(python3 - "$P" <<'PY'
import smtplib, sys
s = smtplib.SMTP("127.0.0.1", int(sys.argv[1]), source_address=("127.0.0.2", 0)); s.ehlo("x")
try:
    s.sendmail("x@b.test", ["info@example.test"],
               "From: ceo@a.test, someone@b.test\r\nSubject: two authors\r\n\r\nb\r\n")
    print("sent")
except smtplib.SMTPDataError as e:
    print(e.smtp_code)
except smtplib.SMTPRecipientsRefused as e:
    print("rcpt", list(e.recipients.values())[0][0])
PY
)
check "a From of authors of two domains is refused as DMARC would refuse one" "$r" "550"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
