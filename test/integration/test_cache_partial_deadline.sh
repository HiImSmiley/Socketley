#!/usr/bin/env bash
# ─── WHAT WENT WRONG ────────────────────────────────────────────────────────
#
# A cache holds a command that has arrived in part until the rest comes.  There
# was no bound on how long that could take.  Measured with --max-connections 2:
# two peers each sending "set k xxx" without the newline refused every real
# client and were never reclaimed in 90 seconds.
#
# ─── WHY THE DEADLINE IS NOT FLAT ───────────────────────────────────────────
#
# A flat one would cut a client writing a large value over a slow link, which
# is legitimate; a deadline that any byte renews is defeated by dribbling,
# which was measured on the TLS handshake the same week -- one byte every
# twenty seconds held a slot for ever.
#
# So the allowance grows with what has been delivered:
#
#     allowed = 10s + partial.size() / 10 KB/s
#
# A client sustaining the floor always has ten seconds of slack; one below it
# falls behind its own allowance; one sending nothing gets ten seconds.
#
# ─── WHAT IS ASSERTED ───────────────────────────────────────────────────────
#
# Three arms, loaded together and sharing one wait, because the second is what
# stops the first from being a fix that breaks the product:
#
#   stalled      -- peers holding a half-command give their slots back
#   above floor  -- 700 kB at 20 KB/s, running past a sweep, must COMPLETE
#   below floor  -- 300 kB at 5 KB/s must be dropped, and said so once
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BIN="${BIN:-$HERE/../../bin/Release/socketley}"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate partialdl
TMPD=$(mktemp -d)
PASS=0; FAIL=0; TOTAL=0
HOLDER=""; FAST=""; SLOW=""
cleanup() {
    for p in "$HOLDER" "$FAST" "$SLOW"; do
        [ -n "$p" ] && kill -9 "$p" 2>/dev/null || true
    done
    "$BIN" stop  pd_cap pd_free >/dev/null 2>&1 || true
    "$BIN" remove pd_cap  >/dev/null 2>&1 || true
    "$BIN" remove pd_free >/dev/null 2>&1 || true
    daemon_stop
    rm -rf "$TMPD"
}
trap cleanup EXIT

pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

echo "=== Integration: a command that stops arriving gives its slot back ==="

CAP=2
P=$((SL_PORT_BASE + 1121))
CAPPED=$P; FREE=$((P + 1))

daemon_start "$BIN"
RC=0
timeout 20 "$BIN" create cache pd_cap  -p "$CAPPED" --max-connections "$CAP" -s >/dev/null 2>&1 || RC=$?
timeout 20 "$BIN" create cache pd_free -p "$FREE" -s >/dev/null 2>&1 || RC=$?
if [ "$RC" -eq 0 ]; then pass
else fail "both caches are created" "a create exited $RC"; fi
for port in "$CAPPED" "$FREE"; do
    BOUND=""
    for _ in $(seq 1 40); do
        ss -ltn 2>/dev/null | grep -q ":$port " && { BOUND=yes; break; }
        sleep 0.25
    done
    if [ "$BOUND" = yes ]; then pass
    else fail "the listener on :$port is bound" "nothing after 10s"; fi
done

served() {  # -> ok | refused
    if timeout 6 python3 -c "
import socket
s = socket.socket(); s.settimeout(5)
try:
    s.connect(('127.0.0.1', $1)); s.sendall(b'set probe v\n')
    print('ok' if b'ok' in s.recv(50) else 'refused')
except Exception:
    print('refused')
" 2>/dev/null | grep -q ok; then echo ok; else echo refused; fi
}

if [ "$(served "$CAPPED")" = ok ]; then pass
else fail "control: the capped cache answers with nothing loaded" \
          "a refusal below would be about the setup, not the slots"; fi

# ─── Arm one: peers holding a half-command ──────────────────────────────────
python3 -c "
import socket, time
hold = []
for _ in range($CAP):
    s = socket.socket(); s.connect(('127.0.0.1', $CAPPED))
    s.sendall(b'set halfkey halfvalue')      # no newline: never a command
    hold.append(s)
with open('$TMPD/held', 'w') as f:
    f.write(str(len(hold)))
time.sleep(400)
" >/dev/null 2>&1 &
HOLDER=$!
disown "$HOLDER" 2>/dev/null || true
HELD=0
for _ in $(seq 1 40); do
    HELD=$(cat "$TMPD/held" 2>/dev/null || echo 0)
    [ "${HELD:-0}" -ge "$CAP" ] && break
    sleep 0.25
done
if [ "${HELD:-0}" -eq "$CAP" ]; then pass
else fail "the stalled peers filled the cap" "connected ${HELD:-0} of $CAP"; fi
if [ "$(served "$CAPPED")" = refused ]; then pass
else fail "loaded: half-arrived commands fill the cap" \
          "the cap did not count them, so nothing below is measured"; fi

# ─── Arms two and three: the writers, started now so the one wait covers all ─
writer() {  # rate_kBps total_kB outfile
    python3 -c "
import socket, time
rate = $1 * 1024; total = $2 * 1024
s = socket.socket(); s.settimeout(25)
try:
    s.connect(('127.0.0.1', $FREE)); s.sendall(b'set slow$1 ')
    sent = 0
    while sent < total:
        chunk = min(rate // 4, total - sent)
        s.sendall(b'x' * chunk); sent += chunk
        time.sleep(0.25)
    s.sendall(b'\n')
    r = s.recv(20)
    open('$3','w').write('ok' if b'ok' in r else 'no-ok')
except Exception as e:
    open('$3','w').write(type(e).__name__)
" >/dev/null 2>&1
}
writer 20 700 "$TMPD/fast" & FAST=$!
writer 5  300 "$TMPD/slow" & SLOW=$!
disown "$FAST" 2>/dev/null || true; disown "$SLOW" 2>/dev/null || true

# ─── One wait ───────────────────────────────────────────────────────────────
WHEN=never
for i in $(seq 1 30); do
    [ "$(served "$CAPPED")" = ok ] && { WHEN="~$((i * 3))s"; break; }
    sleep 3
done
for _ in $(seq 1 40); do
    [ -s "$TMPD/fast" ] && [ -s "$TMPD/slow" ] && break
    sleep 1
done

if kill -0 "$HOLDER" 2>/dev/null; then pass
else fail "the stalled peers were still held at the reading" \
          "the holder exited, so it freed the slots and not a deadline"; fi
if [ "$WHEN" != never ]; then pass
else fail "a half-arrived command gives its slot back" \
          "no real client got in within 90s while the peers were held"; fi

FASTR=$(cat "$TMPD/fast" 2>/dev/null || echo "<none>")
SLOWR=$(cat "$TMPD/slow" 2>/dev/null || echo "<none>")
if [ "$FASTR" = ok ]; then pass
else fail "a slow writer ABOVE the floor still completes" \
          "700 kB at 20 KB/s, past at least one sweep, got: $FASTR" \
          "this arm is what stops the deadline from breaking a real client"; fi
# Only a closed connection counts as a drop, not a writer that has not reported yet.
if [[ "$SLOWR" =~ ^(no-ok|ConnectionResetError|BrokenPipeError|ConnectionAbortedError)$ ]]; then pass
else fail "a writer below the floor is dropped" \
          "300 kB at 5 KB/s should fall behind its own allowance, got: $SLOWR"; fi

DROPS=$(grep -c "stopped arriving" "$SOCKETLEY_DLOG" 2>/dev/null || true)
if [ "${DROPS:-0}" -ge 1 ]; then pass
else fail "the drop is written down" "nothing in the log names the allowance"; fi
if grep -q "one second per 10240 bytes" "$SOCKETLEY_DLOG" 2>/dev/null; then pass
else fail "and the line states the rule rather than only the fact" \
          "got: $(grep -m1 'stopped arriving' "$SOCKETLEY_DLOG" 2>/dev/null | sed 's/^.*cache /cache /' || echo '<no line>')"; fi

echo "  slot back $WHEN; above floor: $FASTR; below floor: $SLOWR; $DROPS log line(s)"
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
