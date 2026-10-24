#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a mail runtime given --tls and --dns with no certificate of its own takes its dns runtime's
# entrance's, and one made before that certificate is written takes mail meanwhile and offers TLS once it is there.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * --tls without --cert refused, or given some other certificate than the entrance's, or a setup that has to name
#     the ACME directory's files to say it
#   * a mail runtime whose certificate is still to come failing to start, or taking passwords on submission without
#     TLS meanwhile
#   * the certificate, once written, not taken up: no STARTTLS, submission still closed
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

daemon_isolate mail_entrance_cert
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1980))
SMTP=$P; SUB=$((P+1)); WEB=$((P+2)); NS=$((P+3)); GATE=$((P+4)); PI=$((P+5)); PS=$((P+6))
trap daemon_stop EXIT

echo "=== Integration: a mail runtime takes its entrance's certificate, and waits for it ==="

daemon_start "$BIN"
"$BIN" create idp auth -p "$PI" --bind 127.0.0.1 --issuer "http://127.0.0.1:$PI" -s >/dev/null 2>&1
"$BIN" create storage st -p "$PS" --bind 127.0.0.1 --dir "$T/data" --anonymous -s >/dev/null 2>&1
# Made before its dns runtime, so the certificate it is to take is not written yet.
out=$("$BIN" create mail m -p "$SMTP" --dns ns --idp auth --storage st/mail --tls --submission "$SUB" --web "$WEB" \
      --domain mail -s 2>&1); rc=$?
cert=$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('cert_path',''))" "$("$BIN" show m)" 2>/dev/null)
case "$cert" in */.acme/entrance-ns-proxy/fullchain.pem) [ "$rc" -eq 0 ] && ok "--tls with --dns and no certificate takes the dns runtime's entrance's" \
    || bad "--tls with --dns" "rc $rc: $out" ;; *) bad "--tls with --dns and no certificate takes the dns runtime's entrance's" "rc $rc: $out / $cert" ;; esac

ready_tcp 127.0.0.1 "$SMTP" && "$BIN" ls | grep -qE ' m .* Up ' && ok "a mail runtime whose certificate is still to come takes mail" \
    || bad "it takes mail meanwhile" "$("$BIN" ls) $(tail -3 "$SOCKETLEY_DLOG")"
ehlo() {
    python3 - "$1" <<'PY'
import smtplib, sys
try:
    s = smtplib.SMTP("127.0.0.1", int(sys.argv[1]), timeout=5)
    s.ehlo("t.test")
    print("starttls" if s.has_extn("starttls") else "plain")
    s.quit()
except Exception as e:
    print("closed: %s" % e)
PY
}
[ "$(ehlo "$SMTP")" = "plain" ] && ok "with no STARTTLS offered" || bad "no STARTTLS meanwhile" "$(ehlo "$SMTP")"
case "$(ehlo "$SUB")" in closed*) ok "and submission, which takes passwords, closed until it is there" ;;
    *) bad "submission closed meanwhile" "$(ehlo "$SUB")" ;; esac

# The dns runtime and its entrance: the entrance writes its certificate for the webmail's name, and mail takes it up.
"$BIN" create dns ns -p "$NS" --zone example.test --publish 127.0.0.1 --proxy-port "$GATE" -s >/dev/null 2>&1
for _ in $(seq 1 100); do [ "$(ehlo "$SMTP")" = "starttls" ] && break; sleep 0.1; done
[ "$(ehlo "$SMTP")" = "starttls" ] && ok "once the entrance has written it, STARTTLS is offered" \
    || bad "STARTTLS once it is there" "$(ehlo "$SMTP") / $(ls -la "$(dirname "$cert")" 2>&1 | head -3) $(grep -i 'certificate' "$SOCKETLEY_DLOG" | tail -3)"
ready_tcp 127.0.0.1 "$SUB" && [ "$(ehlo "$SUB")" = "starttls" ] && ok "and submission opens, with TLS" \
    || bad "submission opens" "$(ehlo "$SUB")"
"$BIN" restart m >/dev/null 2>&1
ready_tcp 127.0.0.1 "$SUB" && [ "$(ehlo "$SMTP")" = "starttls" ] && ok "and a restart finds it at once" || bad "a restart" "$(ehlo "$SMTP")"

"$BIN" export "$T/exp" > "$T/exp.out" 2>&1; rc=$?
[ "$rc" -eq 0 ] && grep -q 'tls = true' "$T/exp/runtimes/m.lua" && ! grep -qE '^ *(cert|key) =' "$T/exp/runtimes/m.lua" \
    && ok "its export says tls and no certificate, which the entrance's is again" || bad "its export" "rc $rc: $(cat "$T/exp.out" "$T/exp/runtimes/m.lua")"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
