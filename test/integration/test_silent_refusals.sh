#!/usr/bin/env bash
# Integration test: two refusals that used to be silence.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
# Both are the same shape: a door said no somewhere the operator could not see
# it, and the command they ran reported success.
#
#   A name containing '..'.  valid_name() refused a LEADING '.' and allowed
#   '.' anywhere else, so `a..b` was accepted and the runtime ran.
#   state_persistence::config_path() refuses '..' too -- by returning an empty
#   path, silently -- so nothing was ever written down and the runtime
#   disappeared at the next daemon start with nothing having said no.  Two
#   rules, two doors, and only one of them could still answer the operator.
#
#   `socketley daemon` on a socket it may not connect to.  is_running()
#   answered one boolean for "a daemon of ours is already serving" and "that
#   path belongs to somebody else", and the caller exits 0 on it.  So the
#   command printed nothing, returned 0, and left the operator with no daemon
#   at all.  The EACCES case must still not unlink the path -- that would take
#   the socket from the daemon that owns it -- so the two answers had to be
#   told apart rather than merged the other way.
#
# The foreign socket is made with chmod rather than a second user: connect(2)
# checks write permission on the socket file, so 0000 gives EACCES to everyone
# who is not root.  A test that needed two accounts would not run anywhere.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: refusals that used to be silence ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

if [ "$(id -u)" = "0" ]; then
    echo "  FAIL [not running as root]: connect(2) ignores permissions for root,"
    echo "        so the foreign-socket half of this file cannot be produced."
    echo "  Results: 0/1 passed (1 failed)"
    exit 1
fi

P=$((SL_PORT_BASE+1400))

daemon_isolate silentrefusals
trap 'chmod 0755 "${SOCKETLEY_SOCKET:-/dev/null}" 2>/dev/null; daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

# ── 1. A name with '..' is refused at the door that can still answer ───────
RC=0
OUT=$("$BIN" create server 'sr..bad' -p "$P" -s 2>&1) || RC=$?
LISTED=$("$BIN" ls 2>/dev/null | grep -c 'sr\.\.bad' || true)
if [ "$RC" -ne 0 ] && [ "${LISTED:-0}" -eq 0 ]; then
    ok "a name containing '..' is refused (rc $RC) and no runtime is left behind"
else
    bad "a name that cannot be written down is refused when it is asked for" \
        "create returned $RC and said '${OUT:-<nothing>}'; ls found it ${LISTED} time(s);" \
        "accepted means it runs now and is gone after the next daemon start," \
        "because config_path() answers an empty path for '..' and says nothing"
fi

if grep -q "invalid runtime name" <<<"$OUT"; then
    ok "and the refusal names the rule"
else
    bad "the refusal names the rule" "said: '${OUT:-<nothing>}'"
fi

# The neighbouring name still works, so a build that refused everything would
# not pass the assertion above.
"$BIN" create server sr.good -p "$P" -s >/dev/null 2>&1
GOODRC=$?
if [ "$GOODRC" -eq 0 ]; then ok "a single '.' inside a name is still allowed"
else bad "the rule is '..' and not '.'" "create server sr.good returned $GOODRC"; fi
"$BIN" stop sr.good >/dev/null 2>&1; "$BIN" remove sr.good >/dev/null 2>&1

# ── 2. A daemon socket this user may not connect to ────────────────────────
chmod 0000 "$SOCKETLEY_SOCKET"
DOUT=$("$BIN" daemon 2>&1); DRC=$?
chmod 0755 "$SOCKETLEY_SOCKET"

if [ "$DRC" -ne 0 ] && [ -n "$DOUT" ]; then
    ok "starting a daemon on a socket it may not connect to fails (rc $DRC) and says why"
else
    bad "a daemon that did not start does not report success" \
        "socketley daemon returned $DRC and said '${DOUT:-<nothing>}';" \
        "rc 0 with an empty terminal is what an operator reads as a daemon that came up"
fi

# And the socket is still there and still served, because the whole reason the
# EACCES case is not treated as `free` is that unlinking it would take the path
# from the daemon that owns it.
STILL=$("$BIN" ls >/dev/null 2>&1 && echo yes || echo no)
if [ "$STILL" = "yes" ] && [ -S "$SOCKETLEY_SOCKET" ]; then
    ok "the running daemon still owns its socket"
else
    bad "the refusal did not disturb the daemon that owns the path" \
        "ls answered '$STILL' and the socket exists: $([ -S "$SOCKETLEY_SOCKET" ] && echo yes || echo no)"
fi

daemon_stop
trap - EXIT

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
