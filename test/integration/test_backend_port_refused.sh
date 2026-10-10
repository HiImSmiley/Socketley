#!/usr/bin/env bash
# Integration test: a backend port that cannot work is refused at create time.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# resolve_backend() split "host:port" and threw the from_chars result away, so
# every one of these left resolved_port at 0:
#
#     --backend host:abc      --backend host:      --backend host:99999
#
# An address that provably cannot work.  Nothing said so at `create`: the proxy
# came up, `ls` showed it running, and the first request through it answered
# 503.  The daemon knew at configuration time and reported it at traffic time,
# which is the longest possible distance between a typo and its symptom.
#
# ─── WHAT IS ASSERTED ───────────────────────────────────────────────────────
#
# The refusal, and — paired with it, because a build that refused every backend
# would pass the refusal — that an ordinary backend is still accepted and the
# proxy still serves through it.  Without that second half this file would go
# green on a proxy that can no longer reach anything.

set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate backend_port
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

echo "=== Integration: a backend port that cannot work is refused ==="

if ! command -v curl >/dev/null 2>&1; then
    echo "  SKIP: curl is required"; exit 0
fi

daemon_start "$BIN"
P=$((SL_PORT_BASE + 850))

# ─── The four spellings that used to be accepted ────────────────────────────
i=0
for bad in "127.0.0.1:abc" "127.0.0.1:" "127.0.0.1:99999" "127.0.0.1:0"; do
    i=$((i + 1))
    "$BIN" remove badpx >/dev/null 2>&1 || true
    RC=0
    OUT=$("$BIN" create proxy badpx -p $((P + i)) --backend "$bad" -s 2>&1) || RC=$?
    if [ "$RC" -ne 0 ]; then pass
    else fail "--backend $bad is refused" \
              "create exited 0 for an address that cannot connect" \
              "said: ${OUT:-<nothing>}"; fi
done

# The reason has to be findable.  The proxy runs out of process by default, so
# the CLI gets the worker's generic refusal and the specific line goes to the
# log — which is exactly where the operator is told to look.
if grep -q "the port is not a number" "$SOCKETLEY_DLOG" 2>/dev/null; then pass
else fail "the log names the port as the problem" \
          "no line in the daemon log says which part of the address is wrong" \
          "the CLI's own message points at the log, so it has to be there."; fi

# ─── Control: an ordinary backend still works end to end ────────────────────
#
# Load-bearing.  Everything above passes on a build where resolve_backend()
# refuses unconditionally, and that would be a proxy that can never reach a
# backend at all.
"$BIN" remove badpx >/dev/null 2>&1 || true

BACKEND_PORT=$((P + 20))
PROXY_PORT=$((P + 21))

WWW="$SOCKETLEY_TMPD/www"; mkdir -p "$WWW"
printf 'BACKEND-%s\n' "$BACKEND_PORT" > "$WWW/index.html"
RC=0
OUT=$("$BIN" create server be_srv -p "$BACKEND_PORT" --http "$WWW" -s 2>&1) || RC=$?
if [ "$RC" -eq 0 ]; then pass
else fail "the control backend is created" \
          "create server exited $RC" "said: ${OUT:-<nothing>}"; fi
RC=0
OUT=$("$BIN" create proxy good_px -p "$PROXY_PORT" \
        --backend "127.0.0.1:$BACKEND_PORT" -s 2>&1) || RC=$?
if [ "$RC" -eq 0 ]; then pass
else fail "an ordinary backend is still accepted" \
          "create exited $RC for a perfectly good address" \
          "said: ${OUT:-<nothing>}"; fi

# And it actually reaches the backend, which "create exited 0" and a listening port do not prove.
BODY=""
for _ in $(seq 1 30); do
    BODY=$(curl -s --max-time 2 "http://127.0.0.1:$PROXY_PORT/good_px/" 2>/dev/null || true)
    [[ "$BODY" == *"BACKEND-$BACKEND_PORT"* ]] && break
    sleep 0.2
done
if [[ "$BODY" == *"BACKEND-$BACKEND_PORT"* ]]; then pass
else fail "the accepted proxy serves through its backend" \
          "GET /good_px/ on $PROXY_PORT answered '${BODY:-<nothing>}', not the backend's page" \
          "a create that returns 0 without a working path is the failure this" \
          "whole file is about, in the other direction."; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
if [ "$FAIL" -eq 0 ]; then echo "  OK"; else echo "  FAILED"; fi
exit "$FAIL"
