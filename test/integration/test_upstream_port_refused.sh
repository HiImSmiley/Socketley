#!/usr/bin/env bash
# Integration test: an upstream port that cannot work is refused at create time.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# add_upstream_target() split "host:port" and threw the from_chars result away,
# so `--upstream host:abc`, `--upstream host:` and any port above 65535 left
# resolved_port at 0 and were stored anyway.  A target that can never be
# connected to sat in the list looking exactly like one that could, and
# upstream_try_connect() discovered it at traffic time.
#
# The same defect the proxy's --backend had (test_backend_port_refused.sh), and
# it is refused the same way.
#
# ─── THE ONE SPELLING THAT IS NOT AN ERROR ──────────────────────────────────
#
# An address with no colon at all stores port 0 deliberately — it is the
# documented form for a target whose port comes from elsewhere.  Only an
# address that ASKED for a port and gave an unusable one is refused, and the
# control below is what keeps that distinction honest: a fix that refused every
# port-0 upstream would pass every refusal here and break the documented case.

set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate upstream_port
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

echo "=== Integration: an upstream port that cannot work is refused ==="

daemon_start "$BIN"
P=$((SL_PORT_BASE + 870))

# ─── Refused ────────────────────────────────────────────────────────────────
i=0
for bad in "127.0.0.1:abc" "127.0.0.1:" "127.0.0.1:99999" "127.0.0.1:0"; do
    i=$((i + 1))
    "$BIN" remove up_bad >/dev/null 2>&1 || true
    RC=0
    OUT=$("$BIN" create server up_bad -p $((P + i)) --upstream "$bad" 2>&1) || RC=$?
    if [ "$RC" -ne 0 ]; then pass
    else fail "--upstream $bad is refused" \
              "create exited 0 for an address that cannot connect" \
              "said: ${OUT:-<nothing>}"; fi

    # And the message names the address, not just "invalid".  With a
    # semicolon list there is no other way to tell which element was wrong.
    if grep -qF "$bad" <<<"$OUT"; then pass
    else fail "the refusal names $bad" "said: ${OUT:-<nothing>}"; fi
done

# ─── A list where only the second element is bad ────────────────────────────
#
# The interesting case: `--upstream a:8080;b:xyz` asked for two targets, and
# coming up with one of them is the silent half-configuration the refusal
# exists to stop.
"$BIN" remove up_bad >/dev/null 2>&1 || true
RC=0
OUT=$("$BIN" create server up_bad -p $((P + 10)) --upstream "127.0.0.1:8080;127.0.0.1:xyz" 2>&1) || RC=$?
if [ "$RC" -ne 0 ]; then pass
else fail "a list with one bad element is refused whole" \
          "create exited 0 and configured only the good half" \
          "said: ${OUT:-<nothing>}"; fi

if grep -qF "127.0.0.1:xyz" <<<"$OUT"; then pass
else fail "the refusal names the bad element of the list" "said: ${OUT:-<nothing>}"; fi

if [ -z "$("$BIN" ls --name 2>/dev/null | grep -x up_bad || true)" ]; then pass
else fail "a refused create leaves no runtime" "up_bad exists anyway"; fi

# ─── Controls: the forms that must keep working ─────────────────────────────
"$BIN" remove up_ok >/dev/null 2>&1 || true
RC=0
OUT=$("$BIN" create server up_ok -p $((P + 20)) --upstream "127.0.0.1:$((P + 21))" 2>&1) || RC=$?
if [ "$RC" -eq 0 ]; then pass
else fail "an ordinary upstream is accepted" "exit $RC, said: ${OUT:-<nothing>}"; fi

"$BIN" remove up_multi >/dev/null 2>&1 || true
RC=0
OUT=$("$BIN" create server up_multi -p $((P + 22)) \
        --upstream "127.0.0.1:$((P + 23));127.0.0.1:$((P + 24))" 2>&1) || RC=$?
if [ "$RC" -eq 0 ]; then pass
else fail "a two-element list is accepted" "exit $RC, said: ${OUT:-<nothing>}"; fi

# The documented port-less form.  A fix that simply refused resolved_port == 0
# would break this and pass everything above it.
"$BIN" remove up_bare >/dev/null 2>&1 || true
RC=0
OUT=$("$BIN" create server up_bare -p $((P + 25)) --upstream "somehost" 2>&1) || RC=$?
if [ "$RC" -eq 0 ]; then pass
else fail "an address with no port at all is still accepted" \
          "exit $RC for the documented port-less form" \
          "said: ${OUT:-<nothing>}" \
          "only an address that ASKED for a port and gave a bad one is refused."; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
if [ "$FAIL" -eq 0 ]; then echo "  OK"; else echo "  FAILED"; fi
exit "$FAIL"
