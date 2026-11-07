#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a burst of mail faster than its store answers waits on the store, and none of it is deferred.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * every mailbox delivery of a burst asked the store at once, so past the 3,072 requests a runtime may have out
#     for background work the mail runtime's own request channel answered the rest "overloaded" and they were deferred
#     "451 4.3.0 the mailbox store st does not answer" for a minute, while the store sat idle (here it is held still
#     for a few seconds, which is any store slower than the burst)
#   * a bound on deliveries that never lets the held ones go: all of them must be delivered once the store answers
#   * a bound that is never reached, which would make the first assertion hold on any build: mail_local_waited
#   * the bound that refused not being named: `stats` lists every requests_overloaded_<bound> line
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

daemon_isolate mail_burst_store
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1920))
SMTP=$P; PI=$((P+1)); PS=$((P+2))
HELD=""
cleanup() {
    [ -n "$HELD" ] && kill -CONT "$HELD" 2>/dev/null
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a burst of mail waits on a store slower than it, and none is deferred ==="

stat_of() { "$BIN" stats "$1" 2>/dev/null | grep -oP "^$2:\K[0-9]+" | head -1; }

daemon_start "$BIN"
"$BIN" create idp auth -p "$PI" --bind 127.0.0.1 --issuer "http://127.0.0.1:$PI" -s >/dev/null 2>&1
"$BIN" create storage st -p "$PS" --bind 127.0.0.1 --dir "$T/data" --anonymous -s >/dev/null 2>&1
USERS=40
for i in $(seq 0 $((USERS-1))); do
    echo "pw-u$i-0123456789" | "$BIN" idp-user auth add "u$i" --password - >/dev/null 2>&1
done
"$BIN" create mail m -p "$SMTP" --bind 127.0.0.1 --mail-domain example.test --idp auth --storage st -s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$SMTP" || bad "the mail runtime takes SMTP" "$(tail -5 "$SOCKETLEY_DLOG")"

send() {
    python3 - "$SMTP" "$USERS" "$1" <<'PY'
import smtplib, sys, threading
port, users, msgs = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
rcpts = ["u%d@example.test" % k for k in range(users)]
body = "From: a@client.test\r\nSubject: burst\r\n\r\n" + "x" * 1000 + "\r\n"
sent = [0]
def one(n):
    s = smtplib.SMTP("127.0.0.1", port, timeout=30)
    s.ehlo("client.test")
    for _ in range(n):
        s.sendmail("a@client.test", rcpts, body)
        sent[0] += 1
    s.quit()
ts = [threading.Thread(target=one, args=(msgs // 4,)) for _ in range(4)]
[t.start() for t in ts]
[t.join() for t in ts]
print(sent[0])
PY
}

# One message first, so the bucket is made and every account is known before the store is held.
[ "$(send 4)" = 4 ] || bad "a first message is taken" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 100); do [ "$(stat_of m mail_delivered)" = $((4 * USERS)) ] && break; sleep 0.1; done
[ "$(stat_of m mail_delivered)" = $((4 * USERS)) ] || bad "the first messages are delivered" "$("$BIN" stats m | grep -E 'mail_(delivered|deferred)')"

# A hundred messages to forty mailboxes is 4,000 deliveries, every one held by a store that does not answer yet.
MSGS=100
HELD=$("$BIN" stats st | grep -oP '^pid:\K[0-9]+' | head -1)
kill -STOP "$HELD"
sent=$(send $MSGS)
sleep 2
kill -CONT "$HELD"; HELD=""
[ "$sent" = "$MSGS" ] && ok "a burst of $MSGS messages to $USERS mailboxes is taken while the store is held" \
    || bad "the burst is taken" "sent ${sent:-0} of $MSGS"
want=$(( (4 + MSGS) * USERS ))
for _ in $(seq 1 300); do [ "$(stat_of m mail_delivered)" = "$want" ] && break; sleep 0.1; done
delivered=$(stat_of m mail_delivered); deferred=$(stat_of m mail_deferred)
echo "  delivered ${delivered:-?} of $want, deferred ${deferred:-?}"
[ "${deferred:-1}" = 0 ] && ! grep -q ': deferred (' "$SOCKETLEY_DLOG" \
    && ok "none of the burst is deferred" \
    || bad "none of the burst is deferred" "$(grep -m3 ': deferred (' "$SOCKETLEY_DLOG")"
[ "$delivered" = "$want" ] && ok "and every one is delivered once the store answers" \
    || bad "every delivery is made" "${delivered:-?} of $want"
waited=$(stat_of m mail_local_waited)
[ "${waited:-0}" -gt 0 ] && ok "the burst outran the deliveries let out at once ($waited waited for a place)" \
    || bad "the burst reaches the bound on deliveries out at once" "mail_local_waited ${waited:-?}"
lines=$("$BIN" stats m | grep -c '^requests_overloaded_')
over=$("$BIN" stats m | grep -E '^requests_overloaded_' | awk -F: '{s+=$2} END {print s+0}')
[ "$lines" -ge 6 ] && [ "$over" = 0 ] && ok "stats lists every bound that answers overloaded, and none did" \
    || bad "stats names the bounds" "$("$BIN" stats m | grep -E '^requests_')"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
