#!/usr/bin/env bash
# Integration test: two commands that answered the wrong question.
#
# ─── restart ────────────────────────────────────────────────────────────────
#
# Its comment said "preserving all flags" and it forwarded every argument to
# `start`.  `start` reads one flag, -i, and hands the rest to resolve_names(),
# which skips anything beginning with '-' and treats what follows as a RUNTIME
# NAME.  So a flag's VALUE was looked up as a runtime, and when it happened to
# name one, that runtime was started:
#
#     $ socketley restart r1 --some-flag victim
#     $ socketley ls --name --status
#     r1      Up 0 seconds
#     victim  Up 0 seconds        <- nothing asked for this
#
# Exit 0 throughout, unknown flag accepted in silence.
#
# ─── create ─────────────────────────────────────────────────────────────────
#
# create() answered a bare bool and cmd_create reported every false as "runtime
# already exists" — measured on a daemon holding NOTHING:
#
#     $ socketley create server 'q"uote' -p 18722
#     runtime already exists: q"uote
#
# which sends the operator looking for a runtime that is not there, while the
# actual problem is a character in the name.
#
# Both halves are asserted in each case: the refusal AND the ordinary path it
# must not have broken.

set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate cmddiag
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
state_of() { "$BIN" ls --name --status 2>/dev/null | awk -F'\t' -v n="$1" '$1==n{print $2}'; }

echo "=== Integration: restart and create say what is actually wrong ==="

daemon_start "$BIN"
P=$((SL_PORT_BASE + 930))

# ─── create: a name it will not take, on an empty daemon ────────────────────
RC=0
OUT=$("$BIN" create server 'q"uote' -p $((P + 1)) 2>&1) || RC=$?
if [ "$RC" -ne 0 ]; then pass
else fail "an unusable name is refused" "create exited 0"; fi

if grep -q "invalid runtime name" <<<"$OUT"; then pass
else fail "the refusal names the rule, not a collision" \
          "said: ${OUT:-<nothing>}" \
          "'runtime already exists' on a daemon with nothing in it sends the" \
          "operator looking for a runtime that is not there."; fi

# The other reason still reports as itself.  Without this, a build that always
# said "invalid name" would pass the assertion above.
"$BIN" create server cd_taken -p $((P + 2)) >/dev/null 2>&1 || true
RC=0
OUT=$("$BIN" create server cd_taken -p $((P + 3)) 2>&1) || RC=$?
if [ "$RC" -ne 0 ] && grep -q "already exists" <<<"$OUT"; then pass
else fail "a genuinely taken name still reports as taken" \
          "exit $RC, said: ${OUT:-<nothing>}"; fi

# And an ordinary create still works.
RC=0
"$BIN" create server cd_fine -p $((P + 4)) >/dev/null 2>&1 || RC=$?
if [ "$RC" -eq 0 ]; then pass
else fail "an ordinary create still works" "exit $RC"; fi

# ─── restart: a flag value must not start a runtime ─────────────────────────
"$BIN" create server cd_victim -p $((P + 5)) >/dev/null 2>&1 || true
"$BIN" create server cd_r1     -p $((P + 6)) -s >/dev/null 2>&1 || true

BEFORE=$(state_of cd_victim)
if [ -n "$BEFORE" ]; then pass
else fail "the runtime the flag value names exists before the restart" "cd_victim is not listed"; fi
RC=0
OUT=$("$BIN" restart cd_r1 --some-flag cd_victim 2>&1) || RC=$?

if [ "$RC" -ne 0 ]; then pass
else fail "restart refuses a flag it cannot honour" "exit 0 for --some-flag"; fi

# The load-bearing one: the named runtime must be untouched.
if [ "$(state_of cd_victim)" = "$BEFORE" ]; then pass
else fail "the flag's value was not started as a runtime" \
          "cd_victim went from '$BEFORE' to '$(state_of cd_victim)'" \
          "resolve_names() treated the value as a name."; fi

# restart now takes edit's own flags, so the refusal names the flag rather than another command to go to.
if grep -q -- "--some-flag" <<<"$OUT"; then pass
else fail "the refusal names the flag it cannot honour" \
          "said: ${OUT:-<nothing>}"; fi

# ─── And restart itself still restarts ──────────────────────────────────────
#
# Load-bearing.  A build that refused every restart would pass both assertions
# above.
pid_of() { "$BIN" stats "$1" 2>/dev/null | awk -F: '/^pid:/ {gsub(/[^0-9]/,"",$2); print $2}' | head -1; }
BEFORE_PID=$(pid_of cd_r1)
RC=0
"$BIN" restart cd_r1 >/dev/null 2>&1 || RC=$?
if [ "$RC" -eq 0 ]; then pass
else fail "a plain restart still works" "exit $RC"; fi

# It really went down and up: the worker is a new process, which a second boundary in an uptime string cannot fake.
AFTER_PID=$(pid_of cd_r1)
if [ -n "$BEFORE_PID" ] && [ -n "$AFTER_PID" ] && [ "$AFTER_PID" != "$BEFORE_PID" ]; then pass
else fail "the restart actually cycled the runtime" \
          "worker pid '${BEFORE_PID:-<none>}' -> '${AFTER_PID:-<none>}' — the stop/start did nothing"; fi

# A runtime that is not there is reported once, by name.
RC=0
OUT=$("$BIN" restart cd_nosuch 2>&1) || RC=$?
if [ "$RC" -ne 0 ] && grep -q "cd_nosuch" <<<"$OUT"; then pass
else fail "restart of a missing runtime names it" "exit $RC, said: ${OUT:-<nothing>}"; fi

# ─── edit on a cache: the flag exists, this command does not take it ────────
#
# There is no parse_cache_edit_flags, so every cache-specific flag fell through
# to "unknown flag" — which reads as a typo, and the answer to a typo is to try
# a different spelling.  No spelling works: `import` is the command that applies
# these.  The message has to distinguish the two, or it sends the operator in a
# circle.
"$BIN" create cache cd_cache -p $((P + 30)) >/dev/null 2>&1 || true

RC=0
OUT=$("$BIN" edit cd_cache --maxmemory 50M 2>&1) || RC=$?
if [ "$RC" -ne 0 ]; then pass
else fail "a cache flag is refused by edit" "exit 0"; fi

if grep -q "import" <<<"$OUT"; then pass
else fail "the refusal names the command that does take it" \
          "said: ${OUT:-<nothing>}" \
          "'unknown flag' reads as a typo; no spelling of it works."; fi

# A real typo still reads as one.  Without this, a build that answered the
# import message for everything would pass the assertion above.
RC=0
OUT=$("$BIN" edit cd_cache --maxmemry 50M 2>&1) || RC=$?
if [ "$RC" -ne 0 ] && grep -q "unknown flag" <<<"$OUT"; then pass
else fail "a misspelled flag still reads as unknown" "said: ${OUT:-<nothing>}"; fi

# And the same flag on a runtime that has no such setting is unknown, not
# redirected: --maxmemory means nothing on a server.
RC=0
OUT=$("$BIN" edit cd_r1 --maxmemory 50M 2>&1) || RC=$?
if [ "$RC" -ne 0 ] && grep -q "unknown flag" <<<"$OUT"; then pass
else fail "a cache flag on a server is unknown, not redirected" \
          "said: ${OUT:-<nothing>}"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
if [ "$FAIL" -eq 0 ]; then echo "  OK"; else echo "  FAILED"; fi
exit "$FAIL"
