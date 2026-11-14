#!/usr/bin/env bash
# Integration test: a worker that has started, and a daemon that has answered a create, keep only the code they serve
# with mapped, not everything their start-up ran.
# suite: isolated
#
# ─── WHAT THIS GUARDS ───────────────────────────────────────────────────────
#
# A worker is an exec of the whole binary, and configuring it, loading its script and starting the runtime touch code
# all over the image, which the kernel maps 64 KiB around every fault.  Measured on the docs benchmark's held row (a
# client holding 200 idle connections, PSS of daemon and worker over 200): 62.1 KiB a connection, of which 1.3 was the
# connections and the rest two processes' fixed cost, mostly image pages nothing touches again -- a worker's code
# mapping at 4.6-6.0 MiB resident of 19, the daemon's at 6.2.  image_trim::release() drops them from the page tables
# once start-up is over (they stay in the page cache): 39.9 KiB a connection.
#
# ─── WHAT KEEPS IT HONEST ───────────────────────────────────────────────────
#
# The share of the code mapping resident, not a size, so a larger build moves both sides: 25-26% before, 13% (worker)
# and 6-9% (daemon) after, and the bound is 20%.  Read straight after the start and after the create's reply, and the runtime then has
# to serve, so a trim that took a page it still needed -- the relro, say -- crashes here rather than passing.
#
# Seen red on the commit before image_trim existed: the worker at 25% and the daemon at 26%.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_ready.sh"
daemon_isolate imagetrim
exec 2>&1

P=$((SL_PORT_BASE+1002))
BOUND=20

PASS=0; FAIL=0; TOTAL=0
ok()    { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad()   { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "expected '$2', got '$3'"; fi; }

cleanup() {
    "$BIN" stop it >/dev/null 2>&1 || true
    sleep 0.3
    "$BIN" remove it >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

# The percentage of the executable's code mapping this process has resident.
code_share() {
    awk -v exe="$(readlink "/proc/$1/exe")" '
        /^[0-9a-f]+-[0-9a-f]+ / { inside = ($2 == "r-xp" && $NF == exe); next }
        inside && /^Size:/ { size += $2 }
        inside && /^Rss:/  { rss += $2 }
        END { if (size > 0) printf "%d", rss * 100 / size; else print "none" }' "/proc/$1/smaps" 2>/dev/null
}

echo "=== Integration: start-up code is released once start-up is over ==="
daemon_start "$BIN"
create_ok "a cache" "$BIN" create cache it -p "$P" -s
ready_resp 127.0.0.1 "$P" 15 || true

WORKER=""
for p in $(pgrep -x socketley 2>/dev/null); do
    grep -qz "SOCKETLEY_SOCKET=$SOCKETLEY_SOCKET" "/proc/$p/environ" 2>/dev/null || continue
    ss -ltnpH "sport = :$P" 2>/dev/null | grep -q "pid=$p," && { WORKER=$p; break; }
done
if [ -n "$WORKER" ]; then ok; else bad "the worker was found" "none listening on $P"; fi
[ -n "$WORKER" ] || { echo; echo "  $PASS/$TOTAL passed"; exit 1; }

W=$(code_share "$WORKER")
D=$(code_share "$SOCKETLEY_DPID")
echo "  code resident: worker ${W}%, daemon ${D}% (bound ${BOUND}%)"
check "the worker keeps under ${BOUND}% of its code mapped" "yes" "$( [ "$W" != none ] && [ "$W" -lt "$BOUND" ] && echo yes || echo "no ($W%)")"
check "the daemon keeps under ${BOUND}% of its code mapped" "yes" "$( [ "$D" != none ] && [ "$D" -lt "$BOUND" ] && echo yes || echo "no ($D%)")"

# And both still work: the worker answers a connection, and the daemon a command it had not run since the trim.
REPLY=$(printf '*1\r\n$4\r\nPING\r\n' | timeout 5 nc -q0 127.0.0.1 "$P" 2>/dev/null | tr -d '\r\n')
check "the worker still serves" "+PONG" "$REPLY"
check "the daemon still answers" "it" "$("$BIN" ls 2>/dev/null | awk '$0 ~ /(^| )it( |$)/ {print "it"; exit}')"
check "the worker is still the one that started" "$WORKER" "$(ss -ltnpH "sport = :$P" 2>/dev/null | sed -n 's/.*pid=\([0-9]*\),.*/\1/p' | head -1)"

echo
echo "  $PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ]
