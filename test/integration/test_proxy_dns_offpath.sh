#!/usr/bin/env bash
# Integration test: a backend's DNS is never resolved on the request path.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# connect_to_backend() called getaddrinfo() whenever a hostname backend had no
# cached address — per request, on the event loop thread, which is the one
# thread serving every runtime in the daemon.  A backend whose DNS hung
# therefore froze the whole daemon for the resolver's timeout on every request
# through it: not just that proxy's clients, but every server, cache and client
# runtime the daemon holds.
#
# Resolution runs on the idle sweep now.  The trade is deliberate: a name that
# starts resolving is picked up within one sweep instead of on the very next
# request, and in exchange nothing the daemon serves can be stopped by somebody
# else's DNS.
#
# ─── WHY ONE OF THESE ASSERTIONS READS THE SOURCE ───────────────────────────
#
# The improvement is a timing one and cannot be shown from outside without a
# resolver that hangs, which this suite cannot arrange portably: an unresolvable
# name like `nonexistent.invalid` answers NXDOMAIN immediately, so a stopwatch
# would report the same number before and after and prove nothing.  Rather than
# dress that up as a measurement, the property is checked where it is decided —
# connect_to_backend must contain no resolver call.
# test_worker_config_coverage.sh reads sources for the same kind of reason.
#
# Two things about that check are the way they are because the first version got
# them wrong, and reported a failure identically with and without the fix:
#
#   * the function's extent is found by matching braces.  A regex that stopped
#     at "the next definition" swallowed 366 lines and the function after it.
#   * comments are stripped first.  The comment explaining why the call is gone
#     contains the word getaddrinfo, so grepping raw text finds the explanation
#     and reports it as the thing it explains.

set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate proxydns
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

echo "=== Integration: backend DNS is off the request path ==="

SRC="$ROOT/socketley/runtime/proxy/proxy_instance.cpp"
EXTRACT="$ROOT/test/integration/lib_extract_fn.py"
if [ ! -f "$SRC" ] || [ ! -f "$EXTRACT" ]; then
    echo "  SKIP: sources not present"
    exit 0
fi

BODY=$(python3 "$EXTRACT" "$SRC" "bool proxy_instance::connect_to_backend" || true)

if [ -n "$BODY" ]; then pass
else fail "connect_to_backend was found in the source" \
          "the extraction returned nothing, so the assertion below is vacuous"; fi

# The extraction has to be the function and not the file: a check that grabbed
# everything would find a resolver call wherever it lives and look like a pass
# for the wrong reason when it did not.
LINES=$(wc -l <<<"$BODY")
if [ "$LINES" -gt 20 ] && [ "$LINES" -lt 500 ]; then pass
else fail "the extraction is one function" \
          "$LINES lines — too short to be the function, or long enough to be several"; fi

if grep -q "getaddrinfo(" <<<"$BODY"; then
    fail "connect_to_backend does not resolve" \
         "a getaddrinfo call appears in the request path" \
         "a resolver call here blocks the thread that serves every runtime."
else pass; fi

# And the sweep still does it somewhere, or a hostname backend never comes up.
if grep -q "getaddrinfo(" "$SRC"; then pass
else fail "the proxy still resolves somewhere" \
          "no getaddrinfo left in the file — a hostname backend can never come up"; fi

# ─── Behaviour: an unresolvable backend answers rather than hanging ──────────
daemon_start "$BIN"
P=$((SL_PORT_BASE + 950))

"$BIN" create cache dns_witness -p $((P + 1)) -s >/dev/null 2>&1 || true
"$BIN" create proxy dns_prox -p $((P + 2)) \
    --backend "nonexistent.invalid:80" -s >/dev/null 2>&1 || true
sleep 0.8

RC=0
timeout 8 python3 -c "
import socket, sys
s = socket.create_connection(('127.0.0.1', $((P + 2))), timeout=5)
s.sendall(b'GET /dns_prox/ HTTP/1.1\r\nHost: x\r\n\r\n')
s.settimeout(5)
# An answer is an error status or the connection closed; a read that times out is the hang this is about.
try:
    d = s.recv(4096)
except socket.timeout:
    sys.exit(3)
s.close()
sys.exit(0 if d == b'' or d.startswith(b'HTTP/1.1 5') else 4)
" || RC=$?
if [ "$RC" -eq 0 ]; then pass
else fail "a request to an unresolvable backend is answered" \
          "the request did not complete within 8s (exit $RC)"; fi

# The witness: another runtime in the same daemon still answers.  This is the
# thing the old blocking call took away.
RC=0
OUT=$(timeout 5 python3 -c "
import socket, time
s = socket.create_connection(('127.0.0.1', $((P + 1))), timeout=3)
s.sendall(b'set witness ok\n'); time.sleep(0.1)
s.settimeout(3)
print(s.recv(256).decode(errors='replace').strip())
s.close()
" || true)
if grep -q "ok" <<<"$OUT"; then pass
else fail "another runtime still answers" "said '${OUT:-<nothing>}'"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
if [ "$FAIL" -eq 0 ]; then echo "  OK"; else echo "  FAILED"; fi
exit "$FAIL"
