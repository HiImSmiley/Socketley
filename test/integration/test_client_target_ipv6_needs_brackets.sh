#!/usr/bin/env bash
# Integration test: an IPv6 target is written in brackets, and a bare one is refused rather than read as host:port.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * the last colon taken as the port's: `::1` was host ":" port 1, and
#     `fe80::1:8080` was host fe80::1 port 8080, both accepted without a word
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

daemon_isolate v6target
trap 'daemon_stop' EXIT
echo "=== Integration: an IPv6 target needs brackets ==="
daemon_start "$BIN"

refused() {   # refused NAME TARGET
    local rc=0 out
    out=$("$BIN" create client "$1" -t "$2" 2>&1) || rc=$?
    if [ "$rc" -eq 1 ] && printf '%s' "$out" | grep -q "brackets"; then ok "-t $2 is refused, saying how to write it"
    else bad "-t $2 is refused" "exit $rc, said '$out'"; fi
}
refused v1 "::1"
refused v2 "fe80::1:8080"
rc=0; out=$("$BIN" create client v3 -t "[::1]:9" 2>&1) || rc=$?
if [ "$rc" -eq 0 ]; then ok "-t [::1]:9 is taken"; else bad "-t [::1]:9 is taken" "exit $rc, said '$out'"; fi
rc=0; out=$("$BIN" create client v4 -t "127.0.0.1:9" 2>&1) || rc=$?
if [ "$rc" -eq 0 ]; then ok "and an IPv4 host:port still is"; else bad "an IPv4 target is taken" "exit $rc, said '$out'"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
