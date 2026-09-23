#!/usr/bin/env bash
# ─── WHAT WENT WRONG ────────────────────────────────────────────────────────
#
#     -t 127.0.0.1:abc        the port was replaced, not refused
#     -t api.internal         the HOST was replaced, and never mentioned again
#
# try_connect() parsed the target and kept its defaults whenever the parse did
# not work out.  Two ways for that to end badly, and both were silent:
#
#   * a port that cannot work became whichever port -p had set, or 8000
#   * a target with no ":port" in it skipped the parse entirely, so host stayed
#     "127.0.0.1" and the client dialled the loopback -- under the name of
#     somebody else, and with that name also going into TLS verification
#
# The second one is the composition -p's own manual offers: "Set listener port
# (server, proxy, cache) or target port (client)".  Every test in this tree
# spelled the target "host:port", so nothing covered it.
#
# ─── WHAT IS ASSERTED ───────────────────────────────────────────────────────
#
# The refusal, the reason being findable, and two probes aimed at the specific
# substitutions: that a bad port is not quietly served by -p's port, and that a
# named host is not quietly served by the loopback.  Paired with a control,
# because a build that refused every target would pass all of it.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate client_target
PASS=0; FAIL=0; TOTAL=0
cleanup() { daemon_stop; }
trap cleanup EXIT

pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}
conns() {  # how many connections a runtime reports, 0 when it says nothing
    "$BIN" stats "$1" 2>/dev/null | grep -m1 '^connections:' | cut -d: -f2 | tr -d ' ' || true
}

echo "=== Integration: a client dials the address it was given ==="

daemon_start "$BIN"
P=$((SL_PORT_BASE + 870))
SVR_PORT=$((P + 20))

# One live server, used as the thing a substitution would land on.
"$BIN" create server ct_svr -p "$SVR_PORT" --mode inout -s >/dev/null 2>&1 || true
sleep 0.4

# ─── The spellings that were taken and quietly replaced ─────────────────────
i=0
for bad in "127.0.0.1:abc" "127.0.0.1:" "127.0.0.1:99999" "127.0.0.1:0" ":8080"; do
    i=$((i + 1))
    "$BIN" remove badcli >/dev/null 2>&1 || true
    RC=0
    OUT=$(timeout 20 "$BIN" create client badcli -t "$bad" -s 2>&1) || RC=$?
    if [ "$RC" -ne 0 ]; then pass
    else fail "-t $bad is refused" \
              "create exited 0 for an address that cannot be dialled" \
              "said: ${OUT:-<nothing>}"; fi
done

# The reason has to name the port, and the flag is where the operator hears it.
"$BIN" remove badcli >/dev/null 2>&1 || true
OUT=$(timeout 20 "$BIN" create client badcli -t "127.0.0.1:abc" -s 2>&1 || true)
if grep -q "the port is not a number" <<<"$OUT"; then pass
else fail "the flag names the port" \
          "the refusal did not say which part of the address is wrong" \
          "said: ${OUT:-<nothing>}"; fi

# ─── The doors the flag does not stand in ───────────────────────────────────
#
# A target reaches a client four other ways -- a configuration document, the
# boot restore, a Lua create, the API -- and none of them is a flag.  `import`
# is one of them and judges nothing, which is what makes it the probe for the
# refusal in try_connect(): the one place every door passes through.
"$BIN" remove badcli >/dev/null 2>&1 || true
"$BIN" remove imp_cli >/dev/null 2>&1 || true
"$BIN" create client imp_cli -t "127.0.0.1:$SVR_PORT" >/dev/null 2>&1 || true
"$BIN" show imp_cli 2>/dev/null | tr -d '\n' \
  | sed 's|"target"[[:space:]]*:[[:space:]]*"[^"]*"|"target": "127.0.0.1:abc"|' \
  > "$SOCKETLEY_TMPD/imp.json"
"$BIN" import imp_cli "$(cat "$SOCKETLEY_TMPD/imp.json")" >/dev/null 2>&1 || true
RC=0
timeout 20 "$BIN" start imp_cli >/dev/null 2>&1 || RC=$?
if [ "$RC" -ne 0 ] && grep -q "the port is not a number" "$SOCKETLEY_DLOG" 2>/dev/null; then pass
else fail "the dial refuses what no flag saw" \
          "start exited $RC and nothing in the log names the port" \
          "import judges nothing, so try_connect() is what has to."; fi

# ─── Probe 1: a bad port is not served by -p's port ─────────────────────────
#
# This is the substitution itself.  On the tree this file was written for, the
# client below came up and connected to ct_svr, because -p had set that port
# and the failed parse left it standing.
"$BIN" remove badcli >/dev/null 2>&1 || true
BEFORE=$(conns ct_svr)
RC=0
timeout 20 "$BIN" create client maskcli -t "127.0.0.1:abc" -p "$SVR_PORT" -s >/dev/null 2>&1 || RC=$?
sleep 0.4
AFTER=$(conns ct_svr)
if [ "$RC" -ne 0 ] && [ "${AFTER:-0}" -eq "${BEFORE:-0}" ]; then pass
else fail "a bad port is not served by -p's port" \
          "create exited $RC and the server went from ${BEFORE:-?} to ${AFTER:-?} connections" \
          "a typo in -t must not be answered by the port in -p."; fi

# ─── Probe 2: a named host is not served by the loopback ───────────────────
#
# .invalid cannot resolve (RFC 2606), so a client that reaches ct_svr here
# reached it by dropping the name -- which is exactly what used to happen.
"$BIN" remove maskcli >/dev/null 2>&1 || true
BEFORE=$(conns ct_svr)
RC=0
timeout 30 "$BIN" create client hostcli -t "no.such.host.invalid" -p "$SVR_PORT" -s >/dev/null 2>&1 || RC=$?
sleep 0.4
AFTER=$(conns ct_svr)
if [ "$RC" -ne 0 ] && [ "${AFTER:-0}" -eq "${BEFORE:-0}" ]; then pass
else fail "a named host is not served by the loopback" \
          "create exited $RC and the server went from ${BEFORE:-?} to ${AFTER:-?} connections" \
          "the target named a host that does not exist; connecting anywhere is wrong."; fi

# ─── Control: an ordinary target still connects, and can send ──────────────
#
# Load-bearing: everything above passes on a build that refuses every target.
"$BIN" remove hostcli >/dev/null 2>&1 || true
RC=0
OUT=$(timeout 20 "$BIN" create client ct_cli -t "127.0.0.1:$SVR_PORT" -s 2>&1) || RC=$?
if [ "$RC" -eq 0 ]; then pass
else fail "an ordinary target is still accepted" \
          "create exited $RC for a perfectly good address" \
          "said: ${OUT:-<nothing>}"; fi

sleep 0.4
RC=0
timeout 10 "$BIN" send ct_cli "hello" >/dev/null 2>&1 || RC=$?
if [ "$RC" -eq 0 ]; then pass
else fail "the accepted client can send" \
          "send exited $RC, so the client is not connected to anything"; fi

# And the server it named is the one that has it.
if [ "$(conns ct_svr)" -gt 0 ]; then pass
else fail "the client reached the server it named" \
          "the server reports no connection while the client reports being up"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] || exit 1
