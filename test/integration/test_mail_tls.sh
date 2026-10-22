#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a mail runtime sends over TLS that is checked where the receiving domain asks it to be: DANE
# (RFC 7672) where DNSSEC signed its MX and TLSA records, MTA-STS (RFC 8461) where it publishes a policy.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a certificate its TLSA records do not name accepted, or one they name refused
#   * mail sent in the clear to an exchanger whose TLSA records or whose domain's enforced policy ask for TLS
#   * TLSA records believed that DNSSEC did not validate, so a forged answer could turn TLS off or on
#   * an exchanger an enforced policy does not name tried, or a certificate for another name taken
#   * a policy in testing mode acted on rather than only told of
#   * a fetched policy not kept for the next start
#   * a policy that never ends read to its end
#   * REQUIRETLS offered or taken outside TLS, or its mail sent on to a server DANE or MTA-STS did not vouch for, or
#     to one that does not keep the requirement on, or without saying REQUIRETLS
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

daemon_isolate mail_tls
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1960))
SINK=$((SL_PORT_BASE+1961))
NS=$((SL_PORT_BASE+1962))
WEB=$((SL_PORT_BASE+1963))
PIDS=()
cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a mail runtime's DANE and MTA-STS ==="

# ─── a CA of the test's, and the certificates it signs ──────────────────────
cd "$T" || exit 2
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=test CA" -keyout ca.key -out ca.pem >/dev/null 2>&1
leaf() { # leaf <file> <name>...: a certificate the CA signs for the names
    local f=$1; shift
    local san; san=$(printf 'DNS:%s,' "$@"); san=${san%,}
    openssl req -newkey rsa:2048 -nodes -subj "/CN=$1" -keyout "$f.key" -out "$f.csr" >/dev/null 2>&1
    printf 'subjectAltName=%s\n' "$san" > "$f.ext"
    openssl x509 -req -in "$f.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile "$f.ext" \
        -out "$f.pem" >/dev/null 2>&1
}
leaf dane mx.dane.test
leaf sts mx.sts.test
leaf wrong some.other.name
leaf web mta-sts.sts.test mta-sts.sts2.test mta-sts.sts3.test mta-sts.stt.test mta-sts.slow.test mta-sts.huge.test
spki() { openssl x509 -in "$1" -noout -pubkey | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | cut -c1-64; }
DANE=$(spki dane.pem)
OTHER=$(spki wrong.pem)
cd - >/dev/null || exit 2

# ─── the zone: which answers DNSSEC signed ──────────────────────────────────
python3 "$HERE/lib_fake_dns.py" "$NS" 0 normal \
    dane.test=MX:10:mx.dane.test dane.test=AD mx.dane.test=127.0.0.4 \
    _${SINK}._tcp.mx.dane.test=TLSA:3:1:1:$DANE _${SINK}._tcp.mx.dane.test=AD \
    danebad.test=MX:10:mx.danebad.test danebad.test=AD mx.danebad.test=127.0.0.4 \
    _${SINK}._tcp.mx.danebad.test=TLSA:3:1:1:$OTHER _${SINK}._tcp.mx.danebad.test=AD \
    daneclear.test=MX:10:mx.daneclear.test daneclear.test=AD mx.daneclear.test=127.0.0.5 \
    _${SINK}._tcp.mx.daneclear.test=TLSA:3:1:1:$DANE _${SINK}._tcp.mx.daneclear.test=AD \
    unsigned.test=MX:10:mx.unsigned.test mx.unsigned.test=127.0.0.4 \
    _${SINK}._tcp.mx.unsigned.test=TLSA:3:1:1:$OTHER \
    sts.test=MX:10:mx.sts.test mx.sts.test=127.0.0.6 "_mta-sts.sts.test=TXT:v=STSv1; id=one" \
    sts2.test=MX:10:mx.elsewhere.test mx.elsewhere.test=127.0.0.6 "_mta-sts.sts2.test=TXT:v=STSv1; id=one" \
    sts3.test=MX:10:mx.sts3.test mx.sts3.test=127.0.0.7 "_mta-sts.sts3.test=TXT:v=STSv1; id=one" \
    stt.test=MX:10:mx.stt.test mx.stt.test=127.0.0.7 "_mta-sts.stt.test=TXT:v=STSv1; id=one" \
    slow.test=MX:10:mx.sts.test "_mta-sts.slow.test=TXT:v=STSv1; id=one" \
    huge.test=MX:10:mx.sts.test "_mta-sts.huge.test=TXT:v=STSv1; id=one" \
    plain.test=MX:10:mx.plain.test mx.plain.test=127.0.0.6 \
    >/dev/null 2>&1 &
PIDS+=($!)
printf 'nameserver 127.0.0.1\noptions timeout:1 attempts:1 port:%s\n' "$NS" > "$T/resolv.conf"

# ─── the exchangers and the policies' server ────────────────────────────────
mkdir -p "$T/s4" "$T/s5" "$T/s6" "$T/s7"
FAKESINK_ADDR=127.0.0.4 python3 "$HERE/lib_smtp_sink.py" "$SINK" "$T/s4" --tls "$T/dane.pem" "$T/dane.key" >/dev/null 2>&1 &
PIDS+=($!)
FAKESINK_ADDR=127.0.0.5 python3 "$HERE/lib_smtp_sink.py" "$SINK" "$T/s5" >/dev/null 2>&1 &
PIDS+=($!)
FAKESINK_ADDR=127.0.0.6 python3 "$HERE/lib_smtp_sink.py" "$SINK" "$T/s6" --tls "$T/sts.pem" "$T/sts.key" --requiretls \
    >/dev/null 2>&1 &
PIDS+=($!)
FAKESINK_ADDR=127.0.0.7 python3 "$HERE/lib_smtp_sink.py" "$SINK" "$T/s7" --tls "$T/wrong.pem" "$T/wrong.key" >/dev/null 2>&1 &
PIDS+=($!)
python3 - "$WEB" "$T/web.pem" "$T/web.key" "$T/fetches" >/dev/null 2>&1 <<'PY' &
import http.server, ssl, sys, time
policies = {
    "mta-sts.slow.test": "version: STSv1\nmode: enforce\nmx: mx.sts.test\nmax_age: 86400\n",
    "mta-sts.sts.test": "version: STSv1\nmode: enforce\nmx: mx.sts.test\nmax_age: 86400\n",
    "mta-sts.sts2.test": "version: STSv1\nmode: enforce\nmx: mx.sts2.test\nmax_age: 86400\n",
    "mta-sts.sts3.test": "version: STSv1\nmode: enforce\nmx: *.sts3.test\nmax_age: 86400\n",
    "mta-sts.stt.test": "version: STSv1\nmode: testing\nmx: mx.stt.test\nmax_age: 86400\n",
}
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        host = self.headers.get("Host", "").split(":")[0]
        with open(sys.argv[4], "a") as f: f.write(host + "\n")
        # One policy takes two seconds to come, as a slow server's would.
        if host == "mta-sts.slow.test": time.sleep(2)
        # One never ends: what was taken of it before the fetch gave up is written down.
        if host == "mta-sts.huge.test":
            self.send_response(200); self.send_header("Content-Type", "text/plain"); self.end_headers()
            sent = 0
            try:
                while sent < (256 << 20):
                    self.wfile.write(b"x" * 65536); sent += 65536
            except Exception:
                pass
            with open(sys.argv[4] + ".huge", "w") as f: f.write(str(sent))
            return
        body = policies.get(host)
        if self.path != "/.well-known/mta-sts.txt" or body is None:
            self.send_response(404); self.end_headers(); return
        self.send_response(200); self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body.encode())
    def log_message(self, *a): pass
s = http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(sys.argv[2], sys.argv[3])
s.socket = ctx.wrap_socket(s.socket, server_side=True)
s.serve_forever()
PY
PIDS+=($!)
for a in 4 5 6 7; do ready_tcp 127.0.0.$a "$SINK" || bad "the exchangers listen" "127.0.0.$a"; done
ready_tcp 127.0.0.1 "$WEB" || bad "the policies' server listens" "-"

export SOCKETLEY_RESOLV_CONF="$T/resolv.conf" SOCKETLEY_MAIL_MX_PORT="$SINK" SOCKETLEY_MAIL_TLS_CA="$T/ca.pem" \
    SOCKETLEY_MAIL_STS_CA="$T/ca.pem" SOCKETLEY_MAIL_STS_CONNECT="127.0.0.1:$WEB"
daemon_start "$BIN"
"$BIN" create mail t -p "$P" --mail-domain example.test -s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$P" || bad "the mail runtime listens" "$(tail -3 "$SOCKETLEY_DLOG")"

send_to() { "$BIN" send t --from a@example.test --to "$1" --subject "to $1" --text "for $1" </dev/null 2>&1 | sed -n 's/^queued //p'; }
at_sink() { # at_sink <dir> <text>: the file there whose message holds the text
    for _ in $(seq 1 60); do
        f=$(grep -l -- "$2" "$T/$1"/*.eml 2>/dev/null | head -1)
        [ -n "$f" ] && { echo "$f"; return 0; }
        sleep 0.1
    done
    return 1
}
# The last answer kept for a message's recipient, once it was tried.
why_of() {
    for _ in $(seq 1 60); do
        w=$("$BIN" mail t show "$1" 2>/dev/null | sed -n 's/^rcpt: [^\t]*\twaiting\t//p')
        [ -n "$w" ] && { echo "$w"; return 0; }
        sleep 0.1
    done
    echo "none"
}
stat_of() { "$BIN" stats t 2>/dev/null | sed -n "s/^$1://p"; }

# ─── DANE ───────────────────────────────────────────────────────────────────
send_to u@dane.test >/dev/null
f=$(at_sink s4 "for u@dane.test")
[ -n "$f" ] && grep -q '^tls 1' "$f" && ok "a certificate its TLSA records name is taken" \
    || bad "a certificate its TLSA records name is taken" "$(tail -3 "$SOCKETLEY_DLOG")"
id=$(send_to u@danebad.test)
case "$(why_of "$id")" in *4.7.5*TLSA*) ok "one they do not name is refused, and the mail waits" ;;
    *) bad "one they do not name is refused, and the mail waits" "$(why_of "$id")" ;; esac
at_sink s4 "for u@danebad.test" >/dev/null && bad "and is not sent" "sent" || ok "and is not sent"
id=$(send_to u@daneclear.test)
case "$(why_of "$id")" in *4.7.5*STARTTLS*) ok "an exchanger with TLSA records that offers no STARTTLS is sent nothing" ;;
    *) bad "an exchanger with TLSA records that offers no STARTTLS is sent nothing" "$(why_of "$id")" ;; esac
send_to u@unsigned.test >/dev/null
at_sink s4 "for u@unsigned.test" >/dev/null && ok "TLSA records DNSSEC did not validate are not believed" \
    || bad "TLSA records DNSSEC did not validate are not believed" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 30); do [ "$(stat_of mail_out_dane_verified)" = 1 ] && break; sleep 0.1; done
check "stats count mail_out_dane_verified" "$(stat_of mail_out_dane_verified)" "1"

# ─── MTA-STS ────────────────────────────────────────────────────────────────
send_to u@sts.test >/dev/null
f=$(at_sink s6 "for u@sts.test")
[ -n "$f" ] && grep -q '^tls 1' "$f" && ok "under an enforced policy, an exchanger it names with a good certificate is sent the mail" \
    || bad "under an enforced policy, an exchanger it names with a good certificate is sent the mail" "$(tail -3 "$SOCKETLEY_DLOG")"
id=$(send_to u@sts2.test)
case "$(why_of "$id")" in *"MTA-STS policy names"*) ok "an exchanger the policy does not name is not tried" ;;
    *) bad "an exchanger the policy does not name is not tried" "$(why_of "$id")" ;; esac
id=$(send_to u@sts3.test)
case "$(why_of "$id")" in *4.7.5*) ok "a certificate for another name is refused under an enforced policy" ;;
    *) bad "a certificate for another name is refused under an enforced policy" "$(why_of "$id")" ;; esac
send_to u@stt.test >/dev/null
at_sink s7 "for u@stt.test" >/dev/null && ok "a policy in testing mode only tells, and the mail goes" \
    || bad "a policy in testing mode only tells, and the mail goes" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 30); do [ "${n:-0}" -ge 1 ] && break; n=$(stat_of mail_sts_testing_failures); sleep 0.1; done
[ "${n:-0}" -ge 1 ] && ok "and the failure is counted" || bad "and the failure is counted" "${n:-absent}"
cache=$(find "$HOME/.local/share" -name mta-sts -path '*/mail/t/*' 2>/dev/null | head -1)
grep -q '^sts.test one enforce [0-9]* mx.sts.test$' "$cache" 2>/dev/null && ok "a fetched policy is kept for the next start" \
    || bad "a fetched policy is kept for the next start" "$(cat "$cache" 2>&1)"

# A policy that takes its time is fetched once while the mail for its domain waits on it.
for i in 1 2 3 4 5; do send_to "u$i@slow.test" >/dev/null; done
for i in 1 2 3 4 5; do at_sink s6 "for u$i@slow.test" >/dev/null || break; done
check "five messages waiting on a slow policy have it fetched once" "$(grep -c '^mta-sts.slow.test$' "$T/fetches")" "1"
check "and go once it is there" "$(grep -l 'for u[1-5]@slow.test' "$T"/s6/*.eml 2>/dev/null | wc -l)" "5"

# A policy that never ends is given up past 64 KiB, and the mail goes as it would with none.
send_to "u@huge.test" >/dev/null
at_sink s6 "for u@huge.test" >/dev/null && ok "a policy that never ends is no policy, and the mail goes" \
    || bad "a policy that never ends is no policy, and the mail goes" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 50); do [ -s "$T/fetches.huge" ] && break; sleep 0.1; done
taken=$(cat "$T/fetches.huge" 2>/dev/null || echo 0)
[ "$taken" -gt 0 ] && [ "$taken" -lt $((32 << 20)) ] && ok "and is read no further than its bound and the kernel's buffers" \
    || bad "and is read no further than its bound and the kernel's buffers" "$taken bytes sent"

# ─── REQUIRETLS ─────────────────────────────────────────────────────────────
notice_for() { # the notice at s6 that mail for $1 was refused for REQUIRETLS
    for _ in $(seq 1 60); do
        f=$(grep -l '5\.7\.10' "$T"/s6/*.eml 2>/dev/null | xargs -r grep -l -- "$1" | head -1)
        [ -n "$f" ] && { echo "$f"; return 0; }
        sleep 0.1
    done
}
P2=$((SL_PORT_BASE+1964))
"$BIN" create mail t2 -p "$P2" --mail-domain example.test --tls --cert "$T/web.pem" --key "$T/web.key" -s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$P2" || bad "the second mail runtime listens" "$(tail -3 "$SOCKETLEY_DLOG")"
r=$(python3 - "$P2" <<'PY'
import smtplib, ssl, sys
s = smtplib.SMTP("127.0.0.1", int(sys.argv[1])); s.ehlo("x")
print("clear", s.has_extn("requiretls"), s.docmd("MAIL FROM:<back@sts.test> REQUIRETLS")[0])
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
s.starttls(context=ctx); s.ehlo("x")
print("tls", s.has_extn("requiretls"))
msg = "From: back@sts.test\r\nSubject: required\r\n\r\nonly over checked tls %s\r\n"
for to in ("v@sts.test", "v@dane.test", "v@plain.test"):
    s.mail("back@sts.test", ["REQUIRETLS"]); s.rcpt(to); s.data(msg % to)
print("sent")
PY
)
check "REQUIRETLS is not offered in the clear, and is refused there" "$(sed -n 's/^clear //p' <<<"$r")" "False 530"
check "and is offered inside TLS" "$(sed -n 's/^tls //p' <<<"$r")" "True"
f=$(at_sink s6 "only over checked tls v@sts.test")
[ -n "$f" ] && grep -q '^mailparams.*REQUIRETLS' "$f" && ok "its mail goes on to a server an enforced policy vouched for, still REQUIRETLS" \
    || bad "its mail goes on to a server an enforced policy vouched for, still REQUIRETLS" "$(head -5 "$f" 2>/dev/null)"
b=$(notice_for v@dane.test)
[ -n "$b" ] && grep -q 'does not offer REQUIRETLS' "$b" && ok "and is returned by one DANE vouched for that does not keep it on" \
    || bad "and is returned by one DANE vouched for that does not keep it on" "$(ls "$T/s6" | wc -l)"
at_sink s4 "only over checked tls v@dane.test" >/dev/null && bad "and not sent there" "sent" || ok "and not sent there"
b=$(notice_for v@plain.test)
[ -n "$b" ] && grep -q 'vouched for' "$b" && ok "and by one reached over TLS that nothing vouched for" \
    || bad "and by one reached over TLS that nothing vouched for" "$(grep -l 'v@plain.test' "$T"/s6/*.eml 2>/dev/null)"
[ -n "$b" ] && ! grep -q 'only over checked tls v@plain' "$b" && ok "a notice of REQUIRETLS mail carries no more than its header" \
    || bad "a notice of REQUIRETLS mail carries no more than its header" "$b"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
