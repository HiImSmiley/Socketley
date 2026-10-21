#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a mail runtime takes a message in BDAT chunks (RFC 3030) and sends one so, and does what a
# sender's delivery status notifications ask (RFC 3461).
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a chunk's bytes read as commands, or a CRLF.CRLF inside one taken as the message's end
#   * a chunk refused at BDAT whose bytes are then not skipped, so the client's data runs as commands
#   * a message relayed by DATA after it came by BDAT, unstuffed, so a line of one dot ends it early there
#   * BDAT not used toward a server that offers it, or its body not the message
#   * NOTIFY, ORCPT, RET and ENVID lost on the way to a server that takes them, or a report sent where that
#     server will send its own
#   * no "relayed" report where the next hop takes no DSN and SUCCESS was asked, or no "delayed" one where DELAY was
#   * a bounce for a recipient whose NOTIFY said NEVER, or RET=FULL answered with the header only
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
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate mail_dsn
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1995))
SINK=$((SL_PORT_BASE+1996))
NS=$((SL_PORT_BASE+1997))
PIDS=()
cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a mail runtime's BDAT chunks and delivery status notifications ==="

# remote.test's exchanger takes CHUNKING and DSN; plain.test's, on another address, neither.
python3 "$HERE/lib_fake_dns.py" "$NS" 0 normal remote.test=MX:10:mx.remote.test mx.remote.test=127.0.0.1 \
    plain.test=MX:10:mx.plain.test mx.plain.test=127.0.0.3 >/dev/null 2>&1 &
PIDS+=($!)
printf 'nameserver 127.0.0.1\noptions timeout:1 attempts:1 port:%s\n' "$NS" > "$T/resolv.conf"
export SOCKETLEY_RESOLV_CONF="$T/resolv.conf" SOCKETLEY_MAIL_MX_PORT="$SINK" SOCKETLEY_MAIL_DELAY_NOTICE_MS=0
mkdir -p "$T/rich" "$T/plain"
python3 "$HERE/lib_smtp_sink.py" "$SINK" "$T/rich" --chunking --dsn >/dev/null 2>&1 &
PIDS+=($!)
FAKESINK_ADDR=127.0.0.3 python3 "$HERE/lib_smtp_sink.py" "$SINK" "$T/plain" --reply bad@plain.test 550 \
    --reply never@plain.test 550 --reply later@plain.test 451 >/dev/null 2>&1 &
PIDS+=($!)
ready_tcp 127.0.0.1 "$SINK" || bad "the sinks listen" "-"
ready_tcp 127.0.0.3 "$SINK" || bad "the sinks listen" "-"
daemon_start "$BIN"
"$BIN" create mail d -p "$P" --mail-domain example.test --max-size 2000000 -s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$P" || bad "the mail runtime listens" "$(tail -3 "$SOCKETLEY_DLOG")"

# The file at a sink whose message holds `pat`: mail_in <dir> <pat>.
mail_in() {
    for _ in $(seq 1 100); do
        f=$(grep -l -- "$2" "$T/$1"/*.eml 2>/dev/null | head -1)
        [ -n "$f" ] && { echo "$f"; return 0; }
        sleep 0.1
    done
    return 1
}
# A conversation in raw bytes from this machine's programs, which may relay: the replies, one a line.
talk() {
    python3 - "$P" "$1" <<'PY'
import socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=10)
f = s.makefile("rb")
f.readline()
s.sendall(sys.argv[2].encode().decode("unicode_escape").encode("latin-1"))
out = []
s.settimeout(3)
try:
    while True:
        l = f.readline()
        if not l: break
        out.append(l.decode().rstrip())
        if l.startswith(b"221"): break
except socket.timeout:
    pass
print("\n".join(out))
PY
}

# ─── BDAT taken ─────────────────────────────────────────────────────────────
r=$(talk 'EHLO c\r\n')
case "$r" in *CHUNKING*DSN*) ok "EHLO offers CHUNKING and DSN" ;; *) bad "EHLO offers CHUNKING and DSN" "$r" ;; esac
# The first chunk holds what DATA would take for its end, and a bare LF; the second ends with LAST.
body1='Subject: chunked\r\n\r\nfirst\r\n.\r\nnot the end\nbare\r\n'
n1=$(printf "$body1" | wc -c)
r=$(talk "EHLO c\r\nMAIL FROM:<a@example.test>\r\nRCPT TO:<x@remote.test>\r\nBDAT $n1\r\n${body1}BDAT 6 LAST\r\nlast\r\nQUIT\r\n")
check "a message in two chunks is taken" "$(printf '%s\n' "$r" | grep -c '^250 2.0.0')" "2"
f=$(mail_in rich "not the end")
[ -n "$f" ] && grep -q '^last' "$f" && ok "a CRLF.CRLF inside a chunk is no end of the message" \
    || bad "a CRLF.CRLF inside a chunk is no end of the message" "$(cat "$f" 2>/dev/null | head -20)"
[ -n "$f" ] && python3 - "$f" <<'PY' && ok "a bare LF in a chunk is kept as CRLF" || bad "a bare LF in a chunk is kept as CRLF" "-"
import sys
b = open(sys.argv[1], "rb").read()
sys.exit(0 if b"not the end\r\nbare\r\n" in b else 1)
PY
r=$(talk "EHLO c\r\nBDAT 10\r\nRSET\r\nXX\r\nNOOP\r\nQUIT\r\n")
check "a chunk refused at BDAT is skipped whole" "$(printf '%s\n' "$r" | tail -3 | cut -c1-3 | tr '\n' ' ')" \
    "503 250 221 "
r=$(python3 - "$P" <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=10); f = s.makefile("rb"); f.readline()
s.sendall(b"EHLO c\r\nMAIL FROM:<a@example.test>\r\nRCPT TO:<x@remote.test>\r\n")
seen = 0
while seen < 3:
    seen += f.readline().startswith(b"250 ")
s.sendall(b"BDAT 2100000 LAST\r\n" + b"z" * 2100000 + b"NOOP\r\n")
print(f.readline().decode()[:3], f.readline().decode()[:3])
PY
)
check "a message past --max-size in chunks is refused, and the next command runs" "$r" "552 250"

# ─── relayed: DATA where BDAT came in ───────────────────────────────────────
r=$(talk "EHLO c\r\nMAIL FROM:<a@example.test>\r\nRCPT TO:<y@plain.test>\r\nBDAT 33 LAST\r\nSubject: dots\r\n\r\nup\r\n.\r\ndown\r\nQUIT\r\n")
f=$(mail_in plain "Subject: dots")
[ -n "$f" ] && grep -q '^via DATA' "$f" && grep -q '^down' "$f" \
    && ok "a chunked message relayed by DATA is stuffed, so a line of one dot ends nothing" \
    || bad "a chunked message relayed by DATA is stuffed, so a line of one dot ends nothing" "$(cat "$f" 2>/dev/null)"

# ─── BDAT sent ──────────────────────────────────────────────────────────────
head -c 600000 /dev/zero | tr '\0' 'q' | fold -w 76 > "$T/att.txt"
"$BIN" send d --from a@example.test --to z@remote.test --subject "sent chunked" --text "chunk body" \
    --attach "$T/att.txt" </dev/null >/dev/null 2>&1
f=$(mail_in rich "sent chunked")
[ -n "$f" ] && grep -q '^via BDAT' "$f" && ok "a server that offers CHUNKING is sent BDAT" \
    || bad "a server that offers CHUNKING is sent BDAT" "$(head -8 "$f" 2>/dev/null)"
[ -n "$f" ] && grep -q '^DKIM-Signature:' "$f" && python3 - "$f" "$T/att.txt" <<'PY' \
    && ok "with its signature and every byte of its body" || bad "with its signature and every byte of its body" "-"
import email, sys
raw = open(sys.argv[1], "rb").read().split(b"\n\n", 1)[1]
m = email.message_from_bytes(raw)
parts = [p.get_payload(decode=True) for p in m.walk() if p.get_filename()]
sys.exit(0 if parts and parts[0] == open(sys.argv[2], "rb").read() else 1)
PY

# ─── DSN passed on ──────────────────────────────────────────────────────────
talk "EHLO c\r\nMAIL FROM:<s@remote.test> RET=HDRS ENVID=env+2B1\r\nRCPT TO:<w@remote.test> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;orig@remote.test\r\nDATA\r\nSubject: passed\r\n\r\nx\r\n.\r\nQUIT\r\n" >/dev/null
f=$(mail_in rich "Subject: passed")
grep -q '^mailparams .*RET=HDRS' "$f" 2>/dev/null && grep -q '^mailparams .*ENVID=env+2B1' "$f" \
    && ok "RET and ENVID go on to a server that takes DSN" || bad "RET and ENVID go on to a server that takes DSN" "$(grep params "$f" 2>/dev/null)"
grep -q '^rcptparams w@remote.test NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;orig@remote.test' "$f" 2>/dev/null \
    && ok "and NOTIFY and ORCPT with each recipient" || bad "and NOTIFY and ORCPT with each recipient" "$(grep params "$f" 2>/dev/null)"
sleep 0.5
check "and no report is made here for what that server reports" \
    "$(grep -l 'Successful Mail Delivery Report' "$T"/rich/*.eml 2>/dev/null | wc -l)" "0"

# ─── reports made here ──────────────────────────────────────────────────────
talk "EHLO c\r\nMAIL FROM:<s@remote.test> ENVID=e2\r\nRCPT TO:<v@plain.test> NOTIFY=SUCCESS ORCPT=rfc822;first+40plain.test\r\nDATA\r\nSubject: told\r\n\r\nx\r\n.\r\nQUIT\r\n" >/dev/null
f=$(mail_in rich "Successful Mail Delivery Report")
[ -n "$f" ] && grep -q '^Action: relayed' "$f" && grep -q 'Original-Recipient: rfc822; first@plain.test' "$f" && \
    grep -q '^Original-Envelope-Id: e2' "$f" \
    && ok "SUCCESS toward a server without DSN is told as relayed, with ORCPT and ENVID" \
    || bad "SUCCESS toward a server without DSN is told as relayed, with ORCPT and ENVID" "$(cat "$f" 2>/dev/null | head -30)"
talk "EHLO c\r\nMAIL FROM:<s@remote.test>\r\nRCPT TO:<never@plain.test> NOTIFY=NEVER\r\nDATA\r\nSubject: never told\r\n\r\nx\r\n.\r\nQUIT\r\n" >/dev/null
talk "EHLO c\r\nMAIL FROM:<s@remote.test> RET=FULL\r\nRCPT TO:<bad@plain.test>\r\nDATA\r\nSubject: full back\r\n\r\nthe whole body\r\n.\r\nQUIT\r\n" >/dev/null
f=$(mail_in rich "bad@plain.test")
[ -n "$f" ] && grep -q '^Content-Type: message/rfc822' "$f" && grep -q '^the whole body' "$f" \
    && ok "RET=FULL is answered with the whole message" || bad "RET=FULL is answered with the whole message" "$(cat "$f" 2>/dev/null | tail -12)"
sleep 0.5
check "NOTIFY=NEVER is bounced to nobody" "$(grep -l 'never@plain.test' "$T"/rich/*.eml 2>/dev/null | wc -l)" "0"
talk "EHLO c\r\nMAIL FROM:<s@remote.test>\r\nRCPT TO:<later@plain.test> NOTIFY=DELAY,FAILURE\r\nDATA\r\nSubject: late\r\n\r\nx\r\n.\r\nQUIT\r\n" >/dev/null
f=$(mail_in rich "Delayed Mail")
[ -n "$f" ] && grep -q '^Action: delayed' "$f" && grep -q '^Will-Retry-Until:' "$f" \
    && ok "DELAY is told once the message is late" || bad "DELAY is told once the message is late" "$(cat "$f" 2>/dev/null | head -30)"
"$BIN" mail d flush >/dev/null 2>&1; sleep 1
check "and told once" "$(grep -l 'Delayed Mail' "$T"/rich/*.eml 2>/dev/null | wc -l)" "1"
s=$("$BIN" stats d 2>/dev/null | sed -n 's/^mail_reports://p')
[ "${s:-0}" -ge 2 ] && ok "stats count mail_reports ($s)" || bad "stats count mail_reports" "${s:-absent}"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
