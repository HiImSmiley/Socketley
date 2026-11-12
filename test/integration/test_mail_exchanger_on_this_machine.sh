#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# A mail runtime does not deliver to an exchanger whose address is this machine's own: mail that arrives from
# 127.0.0.1 is taken as this machine's and may relay, so a stranger's domain with such an MX had it mail itself.
#
# What each part would catch:
#   * a domain whose only exchanger is 127.0.0.1, ::1 or 0.0.0.0 delivered to, instead of bounced as a loop
#   * the guard refusing an exchanger that is not this machine, or giving up on a domain that has another one
#   * the bounce not saying why
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ready.sh"

command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
# An address of this machine that is not loopback, where a test's exchanger is somebody else's as far as the guard goes.
OUTER=$(python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.connect(("192.0.2.1", 9)); print(s.getsockname()[0])
except OSError:
    pass')
case "$OUTER" in ""|127.*) echo "  SKIP: this machine has no address beside loopback"; exit 0 ;; esac

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }

echo "=== Integration: a mail runtime refuses an exchanger that is this machine ==="
daemon_isolate mailself
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1960))
SINK=$((SL_PORT_BASE+1961))
NS=$((SL_PORT_BASE+1962))
PIDS=()
cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
    daemon_stop
}
trap cleanup EXIT

python3 "$HERE/lib_fake_dns.py" "$NS" 0 normal \
    back.test=MX:10:mx.back.test "mx.back.test=$OUTER" \
    loop.test=MX:10:mx.loop.test mx.loop.test=127.0.0.1 \
    other.test=MX:10:mx.other.test mx.other.test=127.0.0.9 \
    zero.test=MX:10:mx.zero.test mx.zero.test=0.0.0.0 \
    both.test=MX:10:mx.loop.test both.test=MX:20:mx.back.test \
    >/dev/null 2>&1 &
PIDS+=($!)
printf 'nameserver 127.0.0.1\noptions timeout:1 attempts:1 port:%s\n' "$NS" > "$T/resolv.conf"
# The setting the other mail tests give their sinks on 127.0.0.1 is left off: this is what an operator runs.
unset SOCKETLEY_MAIL_LOCAL_EXCHANGERS
export SOCKETLEY_RESOLV_CONF="$T/resolv.conf" SOCKETLEY_MAIL_MX_PORT="$SINK" SOCKETLEY_DNS_CACHE_MS=0
mkdir -p "$T/inner" "$T/inner9" "$T/outer"
python3 "$HERE/lib_smtp_sink.py" "$SINK" "$T/inner" >/dev/null 2>&1 &
PIDS+=($!)
FAKESINK_ADDR=127.0.0.9 python3 "$HERE/lib_smtp_sink.py" "$SINK" "$T/inner9" >/dev/null 2>&1 &
PIDS+=($!)
FAKESINK_ADDR=$OUTER python3 "$HERE/lib_smtp_sink.py" "$SINK" "$T/outer" >/dev/null 2>&1 &
PIDS+=($!)
ready_tcp 127.0.0.1 "$SINK" || bad "the exchanger on 127.0.0.1 listens" "-"
ready_tcp 127.0.0.9 "$SINK" || bad "the exchanger on 127.0.0.9 listens" "-"
ready_tcp "$OUTER" "$SINK" || bad "the exchanger on $OUTER listens" "-"
daemon_start "$BIN"
"$BIN" create mail m -p "$P" --mail-domain example.test -s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$P" || bad "the mail runtime listens" "$(tail -3 "$SOCKETLEY_DLOG")"

send() {
    python3 - "$P" "$@" <<'PY'
import smtplib, sys
port, frm, to = int(sys.argv[1]), sys.argv[2], sys.argv[3]
s = smtplib.SMTP("127.0.0.1", port); s.ehlo("t")
s.sendmail(frm, [to], ("From: %s\r\nSubject: to %s\r\n\r\nbody for %s\r\n" % (frm, to, to)).encode())
PY
}
at() { grep -l -- "$2" "$T/$1"/*.eml 2>/dev/null | wc -l; }
wait_for() { for _ in $(seq 1 100); do [ "$(eval "$1")" = "$2" ] && return 0; sleep 0.1; done; return 1; }

# The control: an exchanger elsewhere is delivered to, so what follows is the guard and not a runtime that sends nothing.
send s@back.test c@back.test
wait_for "at outer 'rcpt c@back.test'" 1
check "an exchanger that is not this machine is delivered to" "$(at outer 'rcpt c@back.test')" "1"

for d in loop other zero; do
    send s@back.test "v@$d.test"
    wait_for "at outer 'v@$d.test.*is this machine'" 1
    check "$d.test: the sender is told the exchanger is this machine" "$(at outer "5.4.6 the exchanger mx.$d.test of $d.test is this machine")" "1"
done
check "and nothing was handed to 127.0.0.1" "$(at inner 'rcpt v@')" "0"
check "nor to another address of 127/8" "$(at inner9 'rcpt v@')" "0"

send s@back.test v@both.test
wait_for "at outer 'rcpt v@both.test'" 1
check "a domain with another exchanger gets its mail there" "$(at outer 'rcpt v@both.test') $(at inner 'rcpt v@both.test')" "1 0"

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
