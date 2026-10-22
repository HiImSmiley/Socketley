#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a mail runtime given a dns runtime takes its zones as its domains and gives them their MX, SPF,
# DKIM and DMARC records, and with --no-reply sends from no-reply@ and learns from the bounces sent there.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a record of the four missing from the zone, or the host the MX names left without an address
#   * a DKIM record that is not the key the runtime signs with
#   * a message without a sender not sent from no-reply@, or mail to no-reply@ taken from anyone
#   * a bounce to no-reply@ dropped unread, so a dead address is mailed again and again, after a restart or by
#     another shard
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ready.sh"

command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
command -v openssl >/dev/null 2>&1 || { echo "  SKIP: openssl is required"; exit 0; }
command -v dig >/dev/null 2>&1 || { echo "  SKIP: dig is required"; exit 0; }

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate maildns
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1990))
DNSP=$((SL_PORT_BASE+1991))
SINK=$((SL_PORT_BASE+1992))
NS=$((SL_PORT_BASE+1993))
PIDS=()
cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a mail runtime's records in a dns runtime, and its no-reply sender ==="

python3 "$HERE/lib_fake_dns.py" "$NS" 0 normal remote.test=MX:10:mx.remote.test mx.remote.test=127.0.0.1 \
    >/dev/null 2>&1 &
PIDS+=($!)
printf 'nameserver 127.0.0.1\noptions timeout:1 attempts:1 port:%s\n' "$NS" > "$T/resolv.conf"
export SOCKETLEY_RESOLV_CONF="$T/resolv.conf" SOCKETLEY_MAIL_MX_PORT="$SINK"
mkdir -p "$T/sink"
python3 "$HERE/lib_smtp_sink.py" "$SINK" "$T/sink" --reply dead@remote.test 550 >/dev/null 2>&1 &
PIDS+=($!)
ready_tcp 127.0.0.1 "$SINK" || bad "the sink listens" "-"
daemon_start "$BIN"

mail_with() {
    for _ in $(seq 1 100); do
        f=$(grep -l -- "$1" "$T"/sink/*.eml 2>/dev/null | head -1)
        [ -n "$f" ] && { echo "$f"; return 0; }
        sleep 0.1
    done
    return 1
}
q() { dig +short +time=2 +tries=1 -p "$DNSP" @127.0.0.1 "$@" 2>/dev/null; }

"$BIN" create dns ns -p "$DNSP" --zone example.test --publish 192.0.2.10 --proxy none -s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$DNSP" >/dev/null 2>&1 || true
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=mail.example.test" -keyout "$T/key.pem" \
    -out "$T/cert.pem" >/dev/null 2>&1
"$BIN" create mail m -p "$P" --dns ns --no-reply --tls --cert "$T/cert.pem" --key "$T/key.pem" \
    --submissions $((P+5)) -s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$P" || bad "the mail runtime listens" "$(tail -3 "$SOCKETLEY_DLOG")"

# ─── its records ────────────────────────────────────────────────────────────
for _ in $(seq 1 50); do [ -n "$(q example.test MX)" ] && break; sleep 0.2; done
check "the zone has its MX, naming its host" "$(q example.test MX)" "10 mail.example.test."
check "and its host the dns runtime's address" "$(q mail.example.test A)" "192.0.2.10"
check "and SPF for its exchanger" "$(q example.test TXT)" '"v=spf1 mx -all"'
check "and DMARC" "$(q _dmarc.example.test TXT)" '"v=DMARC1; p=quarantine; adkim=r; aspf=r"'
served=$(q skl._domainkey.example.test TXT | tr -d '" \n')
want=$("$BIN" mail m dns 2>/dev/null | sed -n 's/^skl._domainkey.example.test. 300 IN TXT "\(.*\)"$/\1/p' | tr -d ' ')
[ -n "$want" ] && [ "$served" = "$want" ] && ok "and its DKIM key, whole across the 255-byte strings" \
    || bad "and its DKIM key, whole across the 255-byte strings" "served ${served:0:60}..., want ${want:0:60}..."
check "and its Ed25519 key beside it (RFC 8463)" "$(q skl-ed._domainkey.example.test TXT | tr -d '" ' | cut -c1-20)" \
    "v=DKIM1;k=ed25519;p="
check "and where a mail client sends from" "$(q _submissions._tcp.example.test SRV)" "0 1 $((P+5)) mail.example.test."
check "and no SRV for a port it does not open" "$(q _imap._tcp.example.test SRV)" ""
tlsa=$("$BIN" mail m dns 2>/dev/null | sed -n 's/^_25._tcp.mail.example.test. 300 IN TLSA 3 1 1 //p')
want=$(openssl x509 -in "$T/cert.pem" -noout -pubkey | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)
check "and DANE's TLSA for its certificate's key (RFC 7672)" "$tlsa" "$want"
check "which the dns runtime serves" "$(q _25._tcp.mail.example.test TLSA | tr -d ' ' | tr 'A-F' 'a-f')" "311$want"
check "socketley mail dns prints the seven for a zone kept elsewhere" "$("$BIN" mail m dns 2>/dev/null | wc -l)" "7"

# ─── no-reply ───────────────────────────────────────────────────────────────
"$BIN" send m --to amy@remote.test --subject "notice" --text "noreply body" >/dev/null 2>&1
f=$(mail_with "noreply body")
[ -n "$f" ] && grep -q '^from no-reply+[0-9a-f]\{16\}@example.test$' "$f" && grep -q '^From: no-reply@example.test' "$f" \
    && ok "a message without a sender goes from no-reply@ its domain, tagged for the domain it goes to" \
    || bad "a message without a sender goes from no-reply@ its domain, tagged for the domain it goes to" "$(head -3 "$f" 2>/dev/null)"
tagged=$(sed -n 's/^from //p' "$f" 2>/dev/null | head -1)
r=$(python3 - "$P" <<'PY'
import smtplib, sys
s = smtplib.SMTP("127.0.0.1", int(sys.argv[1]), source_address=("127.0.0.2", 0))
s.ehlo("x"); s.mail("someone@else.test")
print(s.rcpt("no-reply@example.test")[0])
PY
)
check "mail to no-reply@ is refused" "$r" "550"

# A recipient that refuses for good: the bounce goes to no-reply@, which learns from it.
"$BIN" send m --to dead@remote.test --subject "to the dead" --text "dead body" >/dev/null 2>&1
for _ in $(seq 1 100); do [ -n "$("$BIN" mail m suppressed 2>/dev/null)" ] && break; sleep 0.1; done
check "the bounce to no-reply@ suppresses the address it says failed" "$("$BIN" mail m suppressed 2>/dev/null)" "dead@remote.test"
# The stats are the worker's, pushed a moment after.
for _ in $(seq 1 30); do s=$("$BIN" stats m 2>/dev/null | sed -n 's/^mail_bounces_taken://p'); [ "${s:-0}" -ge 1 ] && break; sleep 0.2; done
[ "${s:-0}" -ge 1 ] && ok "and is counted taken" || bad "and is counted taken" "${s:-absent}"
id=$("$BIN" send m --to dead@remote.test --subject "again" --text "again body" 2>&1 | sed -n 's/^queued //p')
# Its attempt is over once it is out of the queue, after which what it sent would be at the sink.
for _ in $(seq 1 100); do "$BIN" mail m show "$id" >/dev/null 2>&1 || break; sleep 0.1; done
"$BIN" mail m show "$id" >/dev/null 2>&1 && bad "a suppressed address's message is over at once" "still queued" \
    || ok "a suppressed address's message is over at once"
grep -l "again body" "$T"/sink/*.eml >/dev/null 2>&1 && bad "a suppressed address is not mailed again" "it was sent" \
    || ok "a suppressed address is not mailed again"
"$BIN" mail m forgive dead@remote.test >/dev/null 2>&1; check "forgive lets it go" "$?" "0"
check "and the list is empty after" "$("$BIN" mail m suppressed 2>/dev/null)" ""
"$BIN" mail m forgive dead@remote.test >/dev/null 2>&1; check "forgiving one not there says so" "$?" "1"

# A bounce from elsewhere counts only under the tag mail went out with, and only for that tag's domain.
bounce() { # bounce <to> <failed address>
    python3 - "$P" "$1" "$2" <<'PY'
import smtplib, sys
s = smtplib.SMTP("127.0.0.1", int(sys.argv[1]), source_address=("127.0.0.2", 0)); s.ehlo("x")
s.sendmail("", [sys.argv[2]], "From: MAILER-DAEMON@remote.test\r\nSubject: failed\r\n\r\n"
           "Final-Recipient: rfc822; %s\r\nAction: failed\r\nStatus: 5.1.1\r\n" % sys.argv[3])
PY
}
bounce no-reply@example.test victim@remote.test
bounce "$tagged" victim2@else.test
bounce "$tagged" amy@remote.test
for _ in $(seq 1 50); do "$BIN" mail m suppressed 2>/dev/null | grep -q amy@ && break; sleep 0.1; done
check "a bounce under the tag for remote.test suppresses an address there" "$("$BIN" mail m suppressed 2>/dev/null | grep -c '^amy@remote.test$')" "1"
check "but not one under no tag, nor one of another domain" "$("$BIN" mail m suppressed 2>/dev/null | grep -c 'victim')" "0"

# What was learned is kept across a restart, and every shard knows it.
"$BIN" stop m >/dev/null 2>&1; "$BIN" start m >/dev/null 2>&1
ready_tcp 127.0.0.1 "$P" >/dev/null
check "a suppressed address is still suppressed after a restart" "$("$BIN" mail m suppressed 2>/dev/null | grep -c '^amy@remote.test$')" "1"
PSH=$((SL_PORT_BASE+1994))
"$BIN" create mail msh -p "$PSH" --mail-domain example.test --no-reply --shards 3 -s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$PSH" || bad "the sharded runtime listens" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 50); do [ "$(ss -ltnpH "sport = :$PSH" | grep -o 'pid=[0-9]*' | sort -u | wc -l)" -ge 3 ] && break; sleep 0.1; done
"$BIN" send msh --to tagme@remote.test --subject "for the tag" --text "shard tag body" >/dev/null 2>&1
f=$(mail_with "shard tag body")
tag2=$(sed -n 's/^from //p' "$f" 2>/dev/null | head -1)
python3 - "$PSH" "$tag2" <<'PY'
import smtplib, sys
s = smtplib.SMTP("127.0.0.1", int(sys.argv[1]), source_address=("127.0.0.2", 0)); s.ehlo("x")
s.sendmail("", [sys.argv[2]], "From: MAILER-DAEMON@remote.test\r\nSubject: failed\r\n\r\n"
           "Final-Recipient: rfc822; zed@remote.test\r\nAction: failed\r\nStatus: 5.1.1\r\n")
PY
for _ in $(seq 1 50); do "$BIN" mail msh suppressed 2>/dev/null | grep -q zed@ && break; sleep 0.1; done
ids=()
for i in 1 2 3 4 5 6; do
    ids+=("$("$BIN" send msh --to zed@remote.test --subject "zed $i" --text "zed body $i" 2>&1 | sed -n 's/^queued //p')")
done
for id in "${ids[@]}"; do
    for _ in $(seq 1 100); do "$BIN" mail msh show "$id" >/dev/null 2>&1 || break; sleep 0.1; done
done
check "an address one shard learned is suppressed by every shard" "$(grep -l 'zed body' "$T"/sink/*.eml 2>/dev/null | wc -l)" "0"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
