#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: what a mail runtime makes of the answers other servers give it, final only where they are.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a MAIL refused for now taken as every recipient refused for good, by the 503s the RCPTs that followed it got
#   * an alias's target that took the message sent it again when another target is tried later
#   * an exchanger that greets with 554 ending the message rather than the next exchanger being tried, or a lone
#     such exchanger's refusal tried for days rather than final
#   * a domain once found not to exist bounced for good, never looked up again
#   * a smarthost's 454 to AUTH bouncing everything queued for it; AUTH LOGIN not spoken; credentials in a URL
#     not percent-decoded
#   * a script's on_rcpt that fails refusing the recipient for good
#   * a recipient refused for good told only once the others are over
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

daemon_isolate mail_delivery
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1960))
SINK=$((SL_PORT_BASE+1961))
NS=$((SL_PORT_BASE+1962))
PR=$((SL_PORT_BASE+1963)); RELAY=$((SL_PORT_BASE+1964))
PR2=$((SL_PORT_BASE+1965)); RELAY2=$((SL_PORT_BASE+1966))
PR3=$((SL_PORT_BASE+1967)); RELAY3=$((SL_PORT_BASE+1968))
PL=$((SL_PORT_BASE+1969))
PIDS=()
cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a mail runtime's deliveries, final only where the answers are ==="

# remote.test's exchanger is a sink on 127.0.0.1; two.test's first exchanger greets 554, its second takes mail;
# one554.test has only the 554 one; later.test does not exist for two seconds from the first question about it.
python3 "$HERE/lib_fake_dns.py" "$NS" 0 normal remote.test=MX:10:mx.remote.test mx.remote.test=127.0.0.1 \
    two.test=MX:10:mx1.two.test two.test=MX:20:mx2.two.test mx1.two.test=127.0.0.4 mx2.two.test=127.0.0.5 \
    one554.test=MX:10:mx1.two.test later.test=NXFOR:2 later.test=MX:10:mx.remote.test >/dev/null 2>&1 &
PIDS+=($!)
printf 'nameserver 127.0.0.1\noptions timeout:1 attempts:1 port:%s\n' "$NS" > "$T/resolv.conf"
# The resolver keeps no answer, so a domain looked up again is asked again.
export SOCKETLEY_RESOLV_CONF="$T/resolv.conf" SOCKETLEY_MAIL_MX_PORT="$SINK" SOCKETLEY_MAIL_DEAD_DOMAIN_MS=1000 \
    SOCKETLEY_DNS_CACHE_MS=0
mkdir -p "$T/sink" "$T/sink5" "$T/relay" "$T/relay2" "$T/relay3"
python3 "$HERE/lib_smtp_sink.py" "$SINK" "$T/sink" --mail held@remote.test 451 --reply b@remote.test '451!' \
    --reply gone@remote.test 550 --reply slow@remote.test 451 >/dev/null 2>&1 &
PIDS+=($!)
FAKESINK_ADDR=127.0.0.4 python3 "$HERE/lib_smtp_sink.py" "$SINK" "$T/sink4" --greet 554 >/dev/null 2>&1 &
PIDS+=($!)
FAKESINK_ADDR=127.0.0.5 python3 "$HERE/lib_smtp_sink.py" "$SINK" "$T/sink5" >/dev/null 2>&1 &
PIDS+=($!)
# Smarthosts: one that wants the percent-decoded credentials, one that speaks only AUTH LOGIN, one that says 454.
python3 "$HERE/lib_smtp_sink.py" "$RELAY" "$T/relay" --auth 'us@er:p/w' >/dev/null 2>&1 &
PIDS+=($!)
python3 "$HERE/lib_smtp_sink.py" "$RELAY2" "$T/relay2" --auth 'login:secret' --auth-login >/dev/null 2>&1 &
PIDS+=($!)
python3 "$HERE/lib_smtp_sink.py" "$RELAY3" "$T/relay3" --auth 'x:y' --auth-code 454 >/dev/null 2>&1 &
PIDS+=($!)
for p in "$SINK" "$RELAY" "$RELAY2" "$RELAY3"; do ready_tcp 127.0.0.1 "$p" || bad "the sink on $p listens" "-"; done
ready_tcp 127.0.0.4 "$SINK" || bad "the 554 sink listens" "-"
ready_tcp 127.0.0.5 "$SINK" || bad "the second exchanger listens" "-"
daemon_start "$BIN"

printf 'list@example.test a@remote.test,b@remote.test\n' > "$T/aliases"
"$BIN" create mail m -p "$P" --mail-domain example.test --aliases "$T/aliases" -s >/dev/null 2>&1
"$BIN" create mail r1 -p "$PR" --mail-domain example.test --relay "smtp://us%40er:p%2Fw@127.0.0.1:$RELAY" -s \
    >/dev/null 2>&1
"$BIN" create mail r2 -p "$PR2" --mail-domain example.test --relay "smtp://login:secret@127.0.0.1:$RELAY2" -s \
    >/dev/null 2>&1
"$BIN" create mail r3 -p "$PR3" --mail-domain example.test --relay "smtp://x:y@127.0.0.1:$RELAY3" -s >/dev/null 2>&1
cat > "$T/broken.lua" <<'LUA'
function on_rcpt(rcpt, default) error("the script broke") end
LUA
"$BIN" create mail ml -p "$PL" --mail-domain example.test --aliases "$T/aliases" --lua "$T/broken.lua" -s \
    >/dev/null 2>&1
for p in "$P" "$PR" "$PR2" "$PR3" "$PL"; do
    ready_tcp 127.0.0.1 "$p" || bad "the mail runtime on $p listens" "$(tail -3 "$SOCKETLEY_DLOG")"
done

# A message from this machine: send <port> <from> <to>...; prints its queue id, or what refused it.
send() {
    python3 - "$@" <<'PY'
import re, smtplib, sys
port, frm, tos = int(sys.argv[1]), sys.argv[2], sys.argv[3:]
s = smtplib.SMTP("127.0.0.1", port); s.ehlo("t")
s.mail(frm)
codes = [s.rcpt(t)[0] for t in tos]
if not any(c // 100 == 2 for c in codes):
    print("refused", *codes); sys.exit(0)
code, text = s.data(("From: %s\r\nSubject: to %s\r\n\r\nbody for %s\r\n" % (frm, " ".join(tos), " ".join(tos))).encode())
m = re.search(rb"queued as (\S+)", text)
print(m.group(1).decode() if m else "refused %d" % code)
PY
}
# state <runtime> <id> <addr>: what the queue says of one recipient, or "gone" once the message is.
state() { "$BIN" mail "$1" show "$2" 2>/dev/null | awk -F'\t' -v a="rcpt: $3" '$1 == a {print $2; f=1} END {if (!f) print "gone"}'; }
at() { grep -l -- "$2" "$T/$1"/*.eml 2>/dev/null | wc -l; }
wait_for() { for _ in $(seq 1 100); do [ "$(eval "$1")" = "$2" ] && return 0; sleep 0.1; done; return 1; }

# ─── a refused MAIL ─────────────────────────────────────────────────────────
id=$(send "$P" held@remote.test x@remote.test y@remote.test)
wait_for "\"\$BIN\" mail m show $id 2>/dev/null | grep -c 'tries: [1-9]'" 1
check "a MAIL refused for now leaves its recipients waiting" "$(state m "$id" x@remote.test) $(state m "$id" y@remote.test)" \
    "waiting waiting"
"$BIN" mail m show "$id" 2>/dev/null | grep -q '451 4.0.0 told to' && ok "with MAIL's own answer as why" \
    || bad "with MAIL's own answer as why" "$("$BIN" mail m show "$id" 2>&1 | grep rcpt)"
check "and no bounce is made of it" "$(at sink 'Undelivered Mail')" "0"

# ─── an alias's targets, one of them tried again ────────────────────────────
id=$(send "$P" s@remote.test list@example.test)
wait_for "at sink 'rcpt a@remote.test'" 1
wait_for "\"\$BIN\" mail m show $id 2>/dev/null | grep -c 'tries: [1-9]'" 1
"$BIN" mail m flush "$id" >/dev/null 2>&1
wait_for "at sink 'rcpt b@remote.test'" 1
sleep 0.5
check "the alias's target that took it is not sent it again" "$(at sink 'rcpt a@remote.test')" "1"
check "the one refused for now gets it on the next try" "$(at sink 'rcpt b@remote.test')" "1"
check "and the recipient is then delivered" "$(state m "$id" list@example.test)" "gone"

# ─── exchangers that refuse at the door ─────────────────────────────────────
id=$(send "$P" s@remote.test t@two.test)
wait_for "at sink5 'rcpt t@two.test'" 1 && ok "an exchanger greeting with 554 is passed over for the next" \
    || bad "an exchanger greeting with 554 is passed over for the next" "$("$BIN" mail m show "$id" 2>&1 | grep rcpt)"
id=$(send "$P" s@remote.test t@one554.test)
wait_for "at sink 'greeted with 554'" 1
check "a lone exchanger's 554 is final, and bounced" "$(state m "$id" t@one554.test) $(at sink 'greeted with 554')" "gone 1"

# ─── a domain that did not exist for a moment ───────────────────────────────
id=$(send "$P" s@remote.test n@later.test)
wait_for "state m $id n@later.test" gone
wait_for "at sink 'later.test does not exist'" 1
check "a domain that does not exist is bounced" "$(at sink 'later.test does not exist')" "1"
sleep 2.5
id=$(send "$P" s@remote.test n2@later.test)
wait_for "at sink 'rcpt n2@later.test'" 1 && ok "a domain found not to exist is looked up again" \
    || bad "a domain found not to exist is looked up again" "$("$BIN" mail m show "$id" 2>&1 | grep rcpt)"

# ─── a recipient refused for good beside one that waits ─────────────────────
id=$(send "$P" told@remote.test gone@remote.test slow@remote.test)
wait_for "at sink 'Final-Recipient: rfc822; gone@remote.test'" 1 && ok "a recipient refused for good is told at once" \
    || bad "a recipient refused for good is told at once" "$("$BIN" mail m show "$id" 2>&1 | grep rcpt)"
check "while the other still waits" "$(state m "$id" slow@remote.test)" "waiting"
"$BIN" mail m flush "$id" >/dev/null 2>&1
sleep 1
check "and the refused one is not told twice" "$(at sink 'Final-Recipient: rfc822; gone@remote.test')" "1"

# ─── smarthosts ─────────────────────────────────────────────────────────────
send "$PR" s@example.test p@far.test >/dev/null
wait_for "at relay 'rcpt p@far.test'" 1 && ok "percent-encoded credentials in --relay are decoded" \
    || bad "percent-encoded credentials in --relay are decoded" "$(ls "$T/relay")"
send "$PR2" s@example.test l@far.test >/dev/null
wait_for "at relay2 'rcpt l@far.test'" 1 && ok "a smarthost that offers only AUTH LOGIN is signed in to" \
    || bad "a smarthost that offers only AUTH LOGIN is signed in to" "$(ls "$T/relay2")"
id=$(send "$PR3" s@example.test q@far.test)
wait_for "\"\$BIN\" mail r3 show $id 2>/dev/null | grep -c 'tries: [1-9]'" 1
check "a smarthost's 454 to AUTH leaves the mail waiting" "$(state r3 "$id" q@far.test)" "waiting"

# ─── a script that fails ────────────────────────────────────────────────────
r=$(python3 - "$PL" <<'PY'
import smtplib, sys
s = smtplib.SMTP("127.0.0.1", int(sys.argv[1])); s.ehlo("t"); s.mail("s@remote.test")
print(s.rcpt("list@example.test")[0])
PY
)
check "an on_rcpt that fails answers 451, not 550" "$r" "451"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
