#!/usr/bin/env bash
# Integration test: nonsense typed at the CLI is refused, not acknowledged.
#
# The contract is three words long -- exit 0 ok, 1 bad input, 2 fatal -- and
# four commands broke it the same way: they matched nothing, fell out of the
# bottom of their loop and returned 0.  A silent success on bad input is worse
# than an error, because the operator goes away believing it happened.
#
# ─── daemon --name, with the value forgotten ────────────────────────────────
#
#     $ socketley daemon --name
#     $                                   <- exit 0, not a word
#     $ socketley ls
#     ID  NAME  ...                       <- and a daemon is running now
#
# `if ((arg == "--name" || arg == "-n") && i + 1 < argc)` with no else, under
# an ensure_daemon() that had already forked.  The same line with `--bogus`
# beside it swallowed that too -- while `socketley daemon --bogus` on its own
# went through parse_daemon_flags and said "unknown daemon flag", exit 1.  The
# same nonsense, two opposite answers, decided by what happened to stand next
# to it.
#
# ─── ls and ps, with a flag neither of them has ─────────────────────────────
#
#     $ socketley ls --grp
#     ID  NAME  ...                       <- the whole table, exit 0
#
# Two switch statements with no default:.  `--grp` is a typo for nothing;
# `--format` with its value forgotten is a question the table does not answer.
#
# ─── --reconnect -1, which turns reconnect off ──────────────────────────────
#
# -1 is the stored "disabled", 0 is "infinite", and the flag parsed into an int
# and took whatever it got.  So the flag whose only purpose is to switch
# reconnection ON switched it off, silently, at exit 0 -- and `show` then
# printed no reconnect line at all, because -1 is the default.
#
# ─── <verb> --help, for a verb nobody listed ────────────────────────────────
#
#     $ socketley stats --help
#     $                                   <- exit 0, zero bytes
#
# command_usage::for_verb knew nine verbs.  Asking any other one for help got
# silence, or -- worse -- the command itself: `ls --help` listed the runtimes
# and `ping --help` pinged.
#
# Each case asserts the refusal AND the ordinary path it must not have broken.

set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate cliinput
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

# Refused: exit 1 and a message that contains WHAT_TO_DO.  Not "exit non-zero":
# 2 is fatal and would mean the daemon died, which is a different finding.
state_of() { "$BIN" ls --name --status 2>/dev/null | awk -F'\t' -v n="$1" '$1==n{print $2}'; }

refuses() {
    local label=$1 want=$2; shift 2
    local out rc=0
    out=$("$@" 2>&1) || rc=$?
    if [ "$rc" -eq 1 ]; then pass
    else fail "$label exits 1" "got exit $rc, said: ${out:-<nothing>}"; fi
    if grep -qF "$want" <<<"$out"; then pass
    else fail "$label says what to do instead" \
              "wanted to find: $want" \
              "said: ${out:-<nothing>}"; fi
}

echo "=== Integration: the CLI refuses what it cannot honour ==="

# ─── daemon --name with no value, BEFORE any daemon exists ──────────────────
#
# Order is load-bearing: the defect was that ensure_daemon() had already forked
# one by the time the argument was looked at, so the assertion is only worth
# anything on a socket nothing is serving yet.
if daemon_alive "$SOCKETLEY_SOCKET"; then
    daemon_bail "a private socket" "something is already serving $SOCKETLEY_SOCKET"
fi

refuses "daemon --name with no value" "socketley daemon --name <name>" \
        "$BIN" daemon --name

# The one that matters: the refusal came before the fork, not after it.
if ! daemon_alive "$SOCKETLEY_SOCKET"; then pass
else fail "a refused daemon command starts no daemon" \
          "a daemon is now serving $SOCKETLEY_SOCKET" \
          "the operator was told the command failed and got a daemon anyway."; fi

refuses "daemon -n with no value" "socketley daemon -n <name>" \
        "$BIN" daemon -n
refuses "daemon --cluster with no value" "socketley daemon --cluster <dir>" \
        "$BIN" daemon --cluster

# A flag typed where its value should be is a forgotten value, not a name: this
# used to rename the daemon to "--cluster" and drop the directory.
refuses "daemon --name followed by another flag" "requires a value" \
        "$BIN" daemon --name --cluster "$SOCKETLEY_TMPD/cl"

# --bogus beside --name got the answer --bogus alone already got.
refuses "daemon --name x --bogus" "unknown daemon flag: --bogus" \
        "$BIN" daemon --name x --bogus

# Still nothing serving: none of the four forked a daemon.
if ! daemon_alive "$SOCKETLEY_SOCKET"; then pass
else fail "no refused form started a daemon" \
          "a daemon is serving $SOCKETLEY_SOCKET after four refusals"; fi

# And the form that was always wrong still answers as it did -- without this, a
# build that refused every `daemon` line would pass everything above.
RC=0
OUT=$("$BIN" daemon --bogus 2>&1) || RC=$?
if [ "$RC" -eq 1 ] && grep -q "unknown daemon flag" <<<"$OUT"; then pass
else fail "daemon --bogus alone is unchanged" "exit $RC, said: ${OUT:-<nothing>}"; fi

# ─── <verb> --help, still with nothing serving the socket ───────────────────
#
# The no-daemon assertion is the point of running this here: the answer used to
# come from the daemon, so asking `stats --help` forked one whose entire job
# was to be asked a question it then did not answer.
for verb in create attach add start stop restart remove owner send edit show \
            import stats reload reload-lua ls ps ping dashboard cluster; do
    RC=0
    OUT=$("$BIN" "$verb" --help 2>&1) || RC=$?
    if [ "$RC" -eq 0 ] && grep -q "^usage: $verb" <<<"$OUT"; then pass
    else fail "$verb --help answers with its usage" \
              "exit $RC, said: ${OUT:-<nothing>}"; fi
done

# The short form is the same question.
RC=0
OUT=$("$BIN" stats -h 2>&1) || RC=$?
if [ "$RC" -eq 0 ] && grep -q "^usage: stats" <<<"$OUT"; then pass
else fail "-h is the same question as --help" "exit $RC, said: ${OUT:-<nothing>}"; fi

if ! daemon_alive "$SOCKETLEY_SOCKET"; then pass
else fail "a usage request starts no daemon" \
          "asking twenty verbs for help left a daemon serving $SOCKETLEY_SOCKET"; fi

# ─── and the documented form still configures a daemon ──────────────────────
#
# Load-bearing for the whole block above.
daemon_start "$BIN"
mkdir -p "$SOCKETLEY_TMPD/cluster"

RC=0
OUT=$("$BIN" daemon --name cli_input_node --cluster "$SOCKETLEY_TMPD/cluster" 2>&1) || RC=$?
if [ "$RC" -eq 0 ]; then pass
else fail "daemon --name <name> --cluster <dir> still works" \
          "exit $RC, said: ${OUT:-<nothing>}"; fi

# Both took, rather than being accepted and dropped: the name is the one asked
# for, and cluster mode is on, which is the half `--cluster` was carrying.
RC=0
OUT=$("$BIN" cluster ls 2>&1) || RC=$?
if [ "$RC" -eq 0 ] && grep -q "cli_input_node" <<<"$OUT"; then pass
else fail "the name it accepted is the name it holds" \
          "exit $RC, cluster ls said: ${OUT:-<nothing>}"; fi

# ─── the verbs whose --help was intercepted still do their job ──────────────
#
# Load-bearing for the block above: a build where `ls` printed its usage and
# stopped would have passed every assertion up to here.
"$BIN" create server cli_input_srv -p $((SL_PORT_BASE + 940)) >/dev/null 2>&1 || true

RC=0
OUT=$("$BIN" ls --name 2>&1) || RC=$?
if [ "$RC" -eq 0 ] && grep -q "cli_input_srv" <<<"$OUT"; then pass
else fail "ls still lists runtimes" "exit $RC, said: ${OUT:-<nothing>}"; fi

RC=0
OUT=$("$BIN" ping 2>&1) || RC=$?
if [ "$RC" -eq 0 ] && grep -q "socketley-daemon" <<<"$OUT"; then pass
else fail "ping still pings" "exit $RC, said: ${OUT:-<nothing>}"; fi

# `restart` with nothing after it is the same sentence as `restart --help`, so
# the two cannot drift -- but it is an error and exits 1.
RC=0
OUT=$("$BIN" restart 2>&1) || RC=$?
if [ "$RC" -eq 1 ] && grep -q "^usage: restart" <<<"$OUT"; then pass
else fail "restart with no name exits 1 with the usage line" \
          "exit $RC, said: ${OUT:-<nothing>}"; fi

# ─── ls and ps: a flag neither of them has ──────────────────────────────────
#
# The runtime created above is what makes these assertions worth anything: the
# defect printed a TABLE at exit 0, and on an empty daemon there is no table to
# print, so a build with the defect would look identical to a build without.
refuses "ls with a flag it does not have" "columns:" "$BIN" ls --grp
refuses "ps with a flag it does not have" "columns:" "$BIN" ps --grp

# A value forgotten is not a question the table answers.
refuses "ls --format with no value" "the only one is json" "$BIN" ls --format
refuses "ps --format with no value" "the only one is json" "$BIN" ps --format

# Neither takes a runtime name, and the operator who typed one wants `show`.
refuses "ls with a runtime name" "socketley show cli_input_srv" \
        "$BIN" ls cli_input_srv

# The refusal that was already there still reads as itself.
refuses "ls --format with a format that is not json" "unknown format: yaml" \
        "$BIN" ls --format yaml

# ─── and every flag they DO have still works ────────────────────────────────
#
# Load-bearing: a `default:` one case too high would refuse a real column and
# every assertion above would still pass.
for args in "--json" "--format json" "-s" "--silent" "--name --port --status" \
            "--name --id --type --conn --owner --created --group"; do
    RC=0
    OUT=$("$BIN" ls $args 2>&1) || RC=$?
    if [ "$RC" -eq 0 ] && grep -q "cli_input_srv" <<<"$OUT"; then pass
    else fail "ls $args still answers" "exit $RC, said: ${OUT:-<nothing>}"; fi
done

for args in "-a" "--all" "-a --json" "-a -s" "-a --name --uptime" \
            "-a --name --id --type --port --conn --owner --created"; do
    RC=0
    OUT=$("$BIN" ps $args 2>&1) || RC=$?
    if [ "$RC" -eq 0 ] && grep -q "cli_input_srv" <<<"$OUT"; then pass
    else fail "ps $args still answers" "exit $RC, said: ${OUT:-<nothing>}"; fi
done

# ─── --reconnect, the flag that turned reconnect off ────────────────────────
#
# -1 is the stored "disabled" and 0 is "infinite", so a negative count switched
# off the one thing this flag exists to switch on.  `show` said nothing either
# way, because a field sitting at its default is not printed -- which is why
# the assertion below is on the CREATE, not on the field.
RP=$((SL_PORT_BASE + 950))

refuses "--reconnect -1" "turns reconnection ON" \
        "$BIN" create client ci_neg -t 127.0.0.1:$((RP + 1)) --reconnect -1
refuses "--reconnect -5" "turns reconnection ON" \
        "$BIN" create client ci_neg5 -t 127.0.0.1:$((RP + 2)) --reconnect -5
refuses "--reconnect with a count no int holds" "out of range" \
        "$BIN" create client ci_big -t 127.0.0.1:$((RP + 3)) --reconnect 99999999999999

# A refused flag must not leave the runtime behind it: the name has to be free.
RC=0
OUT=$("$BIN" ls -s 2>&1) || RC=$?
if ! grep -qE '^ci_(neg|neg5|big)$' <<<"$OUT"; then pass
else fail "a refused --reconnect creates nothing" \
          "ls -s lists: ${OUT:-<nothing>}"; fi

# ─── and every value it DOES take still takes ───────────────────────────────
#
# Load-bearing twice over: a build that refused every --reconnect would pass
# the three above, and the optional value is what makes `--reconnect -s` the
# flag with no value followed by the autostart flag rather than "-s" as a count.
rc_field() { "$BIN" show "$1" 2>/dev/null | grep -o '"reconnect": [-0-9]*' | head -1; }

"$BIN" create client ci_bare -t 127.0.0.1:$((RP + 4)) --reconnect >/dev/null 2>&1 || true
if [ "$(rc_field ci_bare)" = '"reconnect": 0' ]; then pass
else fail "--reconnect with no value is unlimited" \
          "show says: $(rc_field ci_bare)"; fi

"$BIN" create client ci_five -t 127.0.0.1:$((RP + 5)) --reconnect 5 >/dev/null 2>&1 || true
if [ "$(rc_field ci_five)" = '"reconnect": 5' ]; then pass
else fail "--reconnect 5 is five attempts" "show says: $(rc_field ci_five)"; fi

"$BIN" create client ci_as -t 127.0.0.1:$((RP + 6)) --reconnect -s >/dev/null 2>&1 || true
if [ "$(rc_field ci_as)" = '"reconnect": 0' ]; then pass
else fail "--reconnect -s is the flag, then -s" "show says: $(rc_field ci_as)"; fi

# and -s did its own job rather than being eaten as the count.
if [ "$(state_of ci_as)" != "Created" ] && [ -n "$(state_of ci_as)" ]; then pass
else fail "-s after a valueless --reconnect still autostarts" \
          "ci_as is '$(state_of ci_as)'"; fi

# ─── a list of names with a typo in it ──────────────────────────────────────
#
# resolve_names skips a name that matches nothing, and check_empty_names only
# fires when the WHOLE list came back empty, so `stop a gibtsnicht` stopped a,
# said nothing and exited 0.  On `remove` that is the worst of the set: an
# operator clearing two runtimes and misspelling one has every reason to
# believe both are gone.
NP=$((SL_PORT_BASE + 960))
"$BIN" create server ci_keep -p $((NP + 1)) -s >/dev/null 2>&1 || true
"$BIN" create server ci_drop -p $((NP + 2)) >/dev/null 2>&1 || true
"$BIN" create server ci_also -p $((NP + 3)) >/dev/null 2>&1 || true

refuses "stop with a name that is not there" "runtime not found: ci_nosuch" \
        "$BIN" stop ci_keep ci_nosuch

# The message has to say that the rest DID happen, or "runtime not found" reads
# as if the whole command was refused.
RC=0
OUT=$("$BIN" remove ci_drop ci_nosuch 2>&1) || RC=$?
if [ "$RC" -eq 1 ] && grep -q "remove ran for the rest of the list" <<<"$OUT"; then pass
else fail "the refusal says the rest of the list happened" \
          "exit $RC, said: ${OUT:-<nothing>}"; fi

# And it did happen: the named runtime is gone. This is the half that decides
# the design -- a refusal that also undid the removal would leave a script
# whose cleanup names a runtime a failed test never created unable to clean up
# anything at all.
if [ -z "$(state_of ci_drop)" ]; then pass
else fail "the name that resolved was still acted on" \
          "ci_drop is '$(state_of ci_drop)' -- the typo beside it undid the removal"; fi

# Two typos are two lines, and the closing sentence agrees with itself.
RC=0
OUT=$("$BIN" stop ci_keep ci_no1 ci_no2 2>&1) || RC=$?
if [ "$RC" -eq 1 ] && grep -q "ci_no1" <<<"$OUT" && grep -q "ci_no2" <<<"$OUT" \
   && grep -q "not for these names" <<<"$OUT"; then pass
else fail "every name that is not there is named" "exit $RC, said: ${OUT:-<nothing>}"; fi

# ─── what must NOT have changed ─────────────────────────────────────────────
#
# A glob is a query and "no match" is an answer to one, not a typo in it: a
# script running `stop 'api*'` on a box with no api runtimes asked a question
# and got the truth.
RC=0
OUT=$("$BIN" stop ci_also 'ci_zzz*' 2>&1) || RC=$?
if [ "$RC" -eq 0 ] && [ -z "$OUT" ]; then pass
else fail "a glob that matches nothing is not a typo" \
          "exit $RC, said: ${OUT:-<nothing>}"; fi

# A list where every name is good is still silent at exit 0.
RC=0
OUT=$("$BIN" stop ci_keep ci_also 2>&1) || RC=$?
if [ "$RC" -eq 0 ] && [ -z "$OUT" ]; then pass
else fail "a list with no typo in it is still silent" \
          "exit $RC, said: ${OUT:-<nothing>}"; fi

# A list where NOTHING resolved is check_empty_names' case and its message is
# unchanged: one line, and not the new closing sentence, because nothing was
# acted on.
RC=0
OUT=$("$BIN" stop ci_nosuch 2>&1) || RC=$?
if [ "$RC" -eq 1 ] && grep -q "runtime not found: ci_nosuch" <<<"$OUT" \
   && ! grep -q "ran for the rest of the list" <<<"$OUT"; then pass
else fail "a list where nothing resolved reads as it always did" \
          "exit $RC, said: ${OUT:-<nothing>}"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
if [ "$FAIL" -eq 0 ]; then echo "  OK"; else echo "  FAILED"; fi
exit "$FAIL"
