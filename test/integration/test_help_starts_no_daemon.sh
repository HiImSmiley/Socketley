#!/usr/bin/env bash
# Integration test: asking a verb for its usage does not start a daemon.
#
# Only `help`, `--help` and `-h` as the FIRST word were answered in the CLI.
# Everything else fell through to "all other commands need the daemon", so
# `socketley create --help` forked a daemon, forwarded the argv, and was told
# the usage by a process that then stayed up -- measured on the parent commit:
#
#     create --help    rc=1   daemons 0 -> 1
#
# The daemon owned the wording, which is why the CLI could not answer on its
# own.  It now reads the same table the daemon prints from, so the two cannot
# drift apart; the last arm is what would catch them drifting.
#
# Every invocation is bounded and takes stdin from /dev/null, because on the
# parent commit two of these verbs did not return: `send --help` read a message
# from stdin, and `edit --help` opened an EDITOR on a runtime called `--help`.
# A test that hangs hangs the whole suite, so a command that does not return is
# a failed assertion here rather than a stuck one.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate helpnod

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

# Whatever this file started, and on a build with the defect that includes the
# daemons the usage requests left behind.
cleanup() {
    daemon_stop
    local pid
    for pid in $(daemon_starting_pids "$SOCKETLEY_SOCKET"); do
        kill -9 "$pid" 2>/dev/null
    done
}
trap cleanup EXIT

echo "=== Integration: a usage request starts no daemon ==="

# The nine verbs the daemon prints a usage line for, which are exactly the ones
# the CLI can now answer without it.
VERBS="create start stop remove owner send edit show import"

echo "--- 1. <verb> --help and -h are answered locally ---"
for v in $VERBS; do
    for flag in --help -h; do
        before=$(daemon_starting_pids "$SOCKETLEY_SOCKET" | wc -w)
        out=$(timeout 10 "$BIN" "$v" "$flag" </dev/null 2>&1); rc=$?
        after=$(daemon_starting_pids "$SOCKETLEY_SOCKET" | wc -w)

        # A daemon left behind is the defect, and it outlives the question.
        if [ "$after" -eq "$before" ]; then ok; else
            bad "$v $flag starts no daemon" "daemons went $before -> $after"
        fi

        # Exit 0, because asking how a command is spelled is not bad input --
        # and 124 is the timeout above, which is how a verb that opened an
        # editor instead of answering shows up.
        if [ "$rc" -eq 0 ]; then ok; else
            bad "$v $flag exits 0" "got exit $rc"
        fi

        # And it must actually be that verb's usage, not the general help: the
        # cheapest way to pass the two assertions above is to print nothing.
        if printf '%s' "$out" | head -1 | grep -q "^usage: $v "; then ok; else
            bad "$v $flag prints its own usage" "got '${out:-<silence>}'"
        fi
    done
done

echo "--- 2. the one verb that also reads a pipe still says so ---"
out=$(timeout 10 "$BIN" send --help </dev/null 2>&1)
if printf '%s' "$out" | grep -q "echo 'msg' | socketley send <name>"; then ok; else
    bad "send --help keeps its pipe form" "got '$out'"
fi

echo "--- 3. a short argv is still bad input, not a help request ---"
# The control: without this, deleting the forwarding path entirely would pass
# every assertion above.  A daemon is needed here, so one is started -- unless
# the arms above already left one on this socket, which is the defect and would
# otherwise abort the file before it reported a count.
if [ -z "$(daemon_starting_pids "$SOCKETLEY_SOCKET")" ]; then
    daemon_start "$BIN"
fi
for v in create start stop remove owner edit show import; do
    out=$(timeout 10 "$BIN" "$v" </dev/null 2>&1); rc=$?
    if [ "$rc" -eq 1 ]; then ok; else
        bad "bare $v is exit 1" "got exit $rc"
    fi
    if printf '%s' "$out" | head -1 | grep -q "^usage: $v "; then ok; else
        bad "bare $v prints usage" "got '${out:-<silence>}'"
    fi
done

echo "--- 4. both ends print the same sentence ---"
# The CLI answers from the table and the daemon prints from it; if one copy is
# ever reintroduced, these two strings stop matching.
for v in create start stop remove owner edit show import; do
    local_out=$(timeout 10 "$BIN" "$v" --help </dev/null 2>&1 | head -1)
    daemon_out=$(timeout 10 "$BIN" "$v" </dev/null 2>&1 | head -1)
    if [ "$local_out" = "$daemon_out" ]; then ok; else
        bad "$v: CLI and daemon agree" "CLI '$local_out' vs daemon '$daemon_out'"
    fi
done

echo
echo "=============================="
echo " Summary: $PASS passed, $FAIL failed (of $TOTAL)"
echo "=============================="
[ "$FAIL" -eq 0 ]
