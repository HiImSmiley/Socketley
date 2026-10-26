#!/usr/bin/env bash
# Integration test: attach and add refuse bad input, and with the right code.
#
# ─── WHY ────────────────────────────────────────────────────────────────────
#
# cmd_attach's flag loop was a chain of `if`s with no `else`, so an unknown
# flag -- and `--pid` or `--owner` typed with nothing after them -- fell out of
# it silently and the command went on to create, start, save and exit 0.  The
# check above it in the same loop exists because "`--pid abc` left pid at 0 and
# was silently ignored, so a mistyped pid produced a runtime the daemon could
# never stop"; `--pid` with no value did exactly that, past the check.
#
# And both verbs answered a name the daemon will not spell with exit 2, which
# this project reserves for fatal.  cmd_create tells the two apart and returns
# 1 for the same name.
#
# ─── WHAT KEEPS IT HONEST ───────────────────────────────────────────────────
#
# The codes are compared numerically.  `-ne 0` would pass on the defective
# build for the two name cases, which differ only by 2 against 1.  And the
# three controls at the end: a build that refused every attach and add would
# pass the whole table above.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate attachcodes

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"
         local l; for l in "${@:3}"; do echo "        $l"; done; }
cleanup() { daemon_stop; }
trap cleanup EXIT

echo "=== Integration: attach and add refuse bad input, with exit 1 ==="
daemon_start "$BIN"
P=$((SL_PORT_BASE + 1560))

# refuses LABEL WANT_RC WANT_TEXT -- CMD...
refuses() {
    local label=$1 want=$2 text=$3; shift 3
    local rc=0 out
    out=$("$@" 2>&1) || rc=$?
    if [ "$rc" -eq "$want" ] && { [ -z "$text" ] || case "$out" in *"$text"*) true ;; *) false ;; esac; }; then
        pass
    else
        fail "$label" "exit $rc (wanted $want), said: ${out:-<nothing>}"
    fi
}

refuses "an unknown attach flag is refused" 1 "" \
        "$BIN" attach server ax_bogus "$P" --bogus
if "$BIN" ls --name 2>/dev/null | grep -qx ax_bogus; then
    fail "and no runtime is left behind by it" "ax_bogus exists"
else pass; fi

refuses "--owner with nothing after it is refused" 1 "requires a value" \
        "$BIN" attach server ax_ownerless $((P+1)) --owner
refuses "--pid with nothing after it is refused" 1 "requires a value" \
        "$BIN" attach server ax_pidless $((P+2)) --pid

refuses "add --name with nothing after it is refused" 1 "requires a value" \
        "$BIN" add /bin/true --name
refuses "add -n with nothing after it is refused" 1 "requires a value" \
        "$BIN" add /bin/true -n
# The other half of the same rule: a token that is itself a flag is the next
# flag, not the value.  This used to blame the name -- "invalid runtime name:
# -s" -- and drop the -s.
refuses "add --name followed by another flag is refused" 1 "requires a value" \
        "$BIN" add /bin/true --name -s
if "$BIN" ls --name 2>/dev/null | grep -qx -- '-s'; then
    fail "and no runtime named after the dropped flag is left behind" "-s exists"
else pass; fi

refuses "attach answers a bad name with 1, not 2" 1 "invalid runtime name" \
        "$BIN" attach server 'ax..bad' $((P+3))
refuses "add answers a bad name with 1, not 2" 1 "invalid runtime name" \
        "$BIN" add /bin/true --name 'ax..bad'

# ─── The controls ───────────────────────────────────────────────────────────
RC=0; OUT=$("$BIN" create server ax_par -p $((P+7)) 2>&1) || RC=$?
if [ "$RC" -ne 0 ]; then fail "the owner runtime for the controls is created" "exit $RC: ${OUT:-<nothing>}"; fi
RC=0; OUT=$("$BIN" attach server ax_ok $((P+4)) --owner ax_par 2>&1) || RC=$?
if [ "$RC" -eq 0 ]; then pass
else fail "an ordinary attach still works" "exit $RC: ${OUT:-<nothing>}"; fi

OWN=$("$BIN" owner ax_ok 2>/dev/null | sed -n 's/^owner: *//p' | head -1)
if [ "$OWN" = "ax_par" ]; then pass
else fail "and --owner still takes" "owner reads '${OWN:-<nothing>}'"; fi

RC=0; OUT=$("$BIN" add /bin/true --name ax_add 2>&1) || RC=$?
if [ "$RC" -eq 0 ] && "$BIN" ls --name 2>/dev/null | grep -qx ax_add; then pass
else fail "an ordinary add still works" "exit $RC: ${OUT:-<nothing>}"; fi

# A path relative to where the command is typed, which the daemon would read against its own directory.
mkdir -p "$SOCKETLEY_TMPD/here"
printf '#!/bin/sh\nexec sleep 30\n' > "$SOCKETLEY_TMPD/here/tool.sh"
chmod +x "$SOCKETLEY_TMPD/here/tool.sh"
RC=0; OUT=$(cd "$SOCKETLEY_TMPD/here" && "$BIN" add ./tool.sh --name ax_rel 2>&1) || RC=$?
if [ "$RC" -eq 0 ] && "$BIN" ls --name 2>/dev/null | grep -qx ax_rel; then pass
else fail "add takes a path relative to the caller's directory" "exit $RC: ${OUT:-<nothing>}"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
