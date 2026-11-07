#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: the daemon's watchdog says a runtime "has answered nothing" only while it answers nothing, counting
# from its last answer.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * an idp answering a mail runtime's IMAP sign-ins over the peer link, its scrypt on its hash threads, reported as
#     running and not serving: those answers moved none of its own figures, so it sent the daemon no frame, and the
#     daemon measured silence from the last frame (the load is checked to have spent half a core, without which the
#     report could not come at all and the assertion would hold on any build)
#   * a runtime truly stuck in a callback no longer reported
#   * a stuck runtime said to be "answering again" because its cpu dipped while it answered nothing, and then reported
#     again with a figure that only grows -- a SIGSTOP of a few seconds is that dip
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

daemon_isolate watchdog_answers
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1900))
SMTP=$P; IMAP=$((P+1)); PI=$((P+2)); PS=$((P+3)); SPIN=$((P+4))
SPUN=""
cleanup() {
    [ -n "$SPUN" ] && kill -CONT "$SPUN" 2>/dev/null
    [ -n "$SPUN" ] && kill -9 "$SPUN" 2>/dev/null
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: the watchdog counts silence from a runtime's last answer ==="

worker_pid() { "$BIN" stats "$1" 2>/dev/null | grep -oP '^pid:\K[0-9]+' | head -1; }
ticks() { awk '{print $14+$15}' "/proc/$1/stat" 2>/dev/null || echo 0; }

daemon_start "$BIN"
"$BIN" create idp auth -p "$PI" --bind 127.0.0.1 --issuer "http://127.0.0.1:$PI" -s >/dev/null 2>&1
"$BIN" create storage st -p "$PS" --bind 127.0.0.1 --dir "$T/data" --anonymous -s >/dev/null 2>&1
USERS=16
for i in $(seq 0 $((USERS-1))); do
    echo "pw-u$i-0123456789" | "$BIN" idp-user auth add "u$i" --password - >/dev/null 2>&1
done
"$BIN" create mail m -p "$SMTP" --bind 127.0.0.1 --mail-domain example.test --idp auth --storage st \
    --imap "$IMAP" -s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$IMAP" || bad "the mail runtime takes IMAP" "$(tail -5 "$SOCKETLEY_DLOG")"

# ── An idp answering only through the peer link, its hashing on its own threads ──
# One sign-in first, so the daemon introduces the two and the load's answers no longer pass through it.
python3 -c "import imaplib,sys; M=imaplib.IMAP4('127.0.0.1', int(sys.argv[1]), timeout=10); M.login('u0','pw-u0-0123456789'); M.logout()" \
    "$IMAP" >/dev/null 2>&1
for _ in $(seq 1 100); do
    grep -E 'peer links: (m and auth|auth and m) now cross directly' "$SOCKETLEY_DLOG" >/dev/null && break
    sleep 0.1
done
grep -E 'peer links: (m and auth|auth and m) now cross directly' "$SOCKETLEY_DLOG" >/dev/null \
    && ok "the mail runtime asks the idp over a link of their own" \
    || bad "the mail runtime and the idp are introduced" "$(grep 'peer links' "$SOCKETLEY_DLOG" | tail -3)"
AUTH=$(worker_pid auth)
before=$(ticks "$AUTH")
start=$(date +%s.%N)
logins=$(python3 - "$IMAP" "$USERS" 22 <<'PY'
import imaplib, sys, threading, time
port, users, secs = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3])
end = time.time() + secs
done = [0]
def one(k):
    while time.time() < end:
        try:
            M = imaplib.IMAP4("127.0.0.1", port, timeout=10)
            M.login("u%d" % k, "pw-u%d-0123456789" % k)
            M.logout()
            done[0] += 1
        except Exception:
            time.sleep(0.05)
ts = [threading.Thread(target=one, args=(k,)) for k in range(users)]
[t.start() for t in ts]
[t.join() for t in ts]
print(done[0])
PY
)
after=$(ticks "$AUTH")
cores=$(python3 -c "import os,sys; print('%.2f' % ((int(sys.argv[2])-int(sys.argv[1]))/os.sysconf('SC_CLK_TCK')/(float(sys.argv[4])-float(sys.argv[3]))))" \
        "$before" "$after" "$start" "$(date +%s.%N)")
echo "  sign-ins over IMAP: ${logins:-0} in 22s, the idp spending $cores cores"
if [ "${logins:-0}" -gt 100 ] && python3 -c "import sys; sys.exit(0 if float(sys.argv[1]) >= 0.6 else 1)" "$cores"; then
    ok "the load is one the watchdog would report if it counted no answer: sign-ins answered, over half a core"
else
    bad "the load spends half a core" "${logins:-0} sign-ins, $cores cores; a lighter load proves nothing below"
fi
if grep -E "runtime 'auth'.*answered nothing" "$SOCKETLEY_DLOG" >/dev/null; then
    bad "an idp answering sign-ins is not reported as answering nothing" \
        "$(grep -E "runtime 'auth'.*(answered nothing|answering again)" "$SOCKETLEY_DLOG" | head -3)"
else
    ok "an idp answering sign-ins over the peer link, from its hash threads, is never reported"
fi
"$BIN" ls | grep -E ' auth .*NOT RESPONDING' >/dev/null && bad "ls says the idp is not responding" "$("$BIN" ls)" \
    || ok "and ls does not say it is not responding"

# ── A runtime truly stuck ───────────────────────────────────────────────────
cat > "$T/spin.lua" <<'LUA'
callback_timeout_ms = 0
function on_message(msg) end
function on_client_message(id, msg)
    local x = 0
    while true do x = x + 1 end
end
LUA
"$BIN" create server spin -p "$SPIN" --bind 127.0.0.1 --mode in --lua "$T/spin.lua" -s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$SPIN" || bad "the spinning server takes connections" "$(tail -5 "$SOCKETLEY_DLOG")"
SPUN=$(worker_pid spin)
( printf 'go\n' | timeout 3 nc -q 1 127.0.0.1 "$SPIN" >/dev/null 2>&1 ) || true
wedged=""
for _ in $(seq 1 300); do
    grep -E "runtime 'spin'.*answered nothing" "$SOCKETLEY_DLOG" >/dev/null && { wedged=1; break; }
    sleep 0.1
done
[ -n "$wedged" ] && ok "a runtime spinning in a callback is reported as answering nothing" \
    || bad "a stuck runtime is reported" "$(grep -E "runtime 'spin'" "$SOCKETLEY_DLOG" | tail -3)"
"$BIN" ls | grep -E ' spin .*NOT RESPONDING' >/dev/null && ok "and ls says it is not responding" \
    || bad "ls says the stuck runtime is not responding" "$("$BIN" ls)"

# Its cpu gone for four seconds, which is no answer.
kill -STOP "$SPUN" 2>/dev/null; sleep 4; kill -CONT "$SPUN" 2>/dev/null; sleep 4
lines=$(grep -E "runtime 'spin'.*(answered nothing|answering again)" "$SOCKETLEY_DLOG")
if echo "$lines" | grep -q 'answering again'; then
    bad "a stuck runtime whose cpu dipped is not said to be answering" "$lines"
elif [ "$(echo "$lines" | grep -c 'answered nothing')" -ne 1 ]; then
    bad "a stuck runtime is reported once, not again with a figure that only grows" "$lines"
else
    ok "a dip in a stuck runtime's cpu says nothing: it is reported once, and not as answering again"
fi
"$BIN" ls | grep -E ' spin .*NOT RESPONDING' >/dev/null && ok "and ls still says it is not responding" \
    || bad "ls still says the stuck runtime is not responding" "$("$BIN" ls)"

# Its cpu gone for longer than the silence the report waits for, which is a worker idle or blocked, not spinning.
kill -STOP "$SPUN" 2>/dev/null
quiet=""
for _ in $(seq 1 250); do
    grep -E "runtime 'spin'.*no longer spends cpu" "$SOCKETLEY_DLOG" >/dev/null && { quiet=1; break; }
    sleep 0.1
done
[ -n "$quiet" ] && ! "$BIN" ls | grep -E ' spin .*NOT RESPONDING' >/dev/null \
    && ok "a stuck runtime that stops spending cpu for fifteen seconds is no longer reported, and not as answering" \
    || bad "a reported runtime idle for fifteen seconds is let go" \
           "$(grep -E "runtime 'spin'" "$SOCKETLEY_DLOG" | tail -3) / $("$BIN" ls | grep spin)"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
