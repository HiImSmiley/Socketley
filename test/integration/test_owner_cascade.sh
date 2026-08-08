#!/usr/bin/env bash
# Integration test: the owner cascade, and what it does when the graph has a cycle.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# `stop` cascades to a runtime's children: runtime_manager::stop() collects
# get_children(), and stop_children()/remove_children() recurse through the
# graph.  Nothing in any of the three remembers where it has already been, and
# nothing anywhere validates that an owner cannot point back at its own
# subtree — set_owner() is a plain setter.
#
# A runtime that owns itself is therefore its own child, and the recursion has
# no bottom.  Measured on the parent commit, two commands and no traffic:
#
#     socketley attach server selfown 18760 --owner selfown
#     socketley stop selfown
#     failed to connect to daemon           <- SIGSEGV, core dumped
#
# The daemon dies, and every other runtime it was holding dies with it.  A
# two-runtime cycle (a owns b, b owns a) does the same; `remove` on such a cycle
# does not crash but hangs, which is the same loss by a slower route.
#
# The owner is written to the state file and restored at boot, so the cycle
# survives a restart: a daemon that has met one is permanently one command away
# from dying again.
#
# ─── WHAT IS ASSERTED, AND WHY IT IS NOT ONE ASSERTION ──────────────────────
#
# "The daemon is still alive afterwards" is true of a build that fixed this and
# equally true of a build that deleted the cascade — and deleting the cascade
# would be a silent regression for every runtime whose parent is stopped.  So
# every cycle case below is paired with a control that must still DO something:
# a normal parent/child pair where stopping the parent has to stop the child.
#
# Without that pair, `on_parent_stop` could stop working entirely and this file
# would report OK.

set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate owner_cascade
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

# assert_daemon_survives LABEL COMMAND...
#
# Three things have to be true afterwards, and none of them implies the others.
# Asking only the first — which is what this did at first draft — reports a pass
# for two of the three ways this defect actually presents.
#
#   1. A daemon is serving the socket.  Necessary, and nowhere near sufficient:
#      every CLI command except `daemon`, `version` and `help` AUTO-STARTS a
#      daemon when the socket does not answer, so the very next command after a
#      crash silently forks a replacement — and that replacement restores the
#      cycle out of the state file and is serving by the time anything looks.
#
#   2. It is the SAME daemon.  This is what catches the crash, now that (1)
#      cannot: the replacement has a different pid.  Compared by pid rather than
#      by "did it die", because the death and the resurrection happen inside one
#      CLI command and there is no moment in between to observe.
#
#      Not a check on $SOCKETLEY_DPID: the daemon under test may legitimately be
#      a later one (cycle 3 restarts it on purpose), so the baseline is taken
#      here, per call.
#
#   3. It still ANSWERS.  `remove` on a cycle does not crash — it recurses
#      through remove_children() and stops replying while holding its socket, so
#      both (1) and (2) stay true for a daemon that is gone for every practical
#      purpose.  Measured: `remove` on a self-owning runtime never returned and
#      the process had to be killed.
#
# The `timeout` on the command is part of the assertion rather than a
# convenience: without it a hung daemon hangs the suite instead of reporting.
assert_daemon_survives() {
    local label=$1; shift
    local before after
    before=$(daemon_pids "$SOCKETLEY_SOCKET")

    timeout 15 "$@" >/dev/null 2>&1 || true

    after=$(daemon_pids "$SOCKETLEY_SOCKET")

    if [ -z "$after" ]; then
        fail "$label" "no daemon is serving the socket any more" \
             "command: $*" \
             "the cycle recursed until the stack ran out."
        return
    fi

    if [ "$before" != "$after" ]; then
        fail "$label" "the daemon was replaced, so the original one died" \
             "command: $*" \
             "serving before: ${before:-<none>}   after: $after" \
             "a CLI command auto-starts a daemon, so 'something is serving'" \
             "is true again within milliseconds of the crash."
        return
    fi

    if ! timeout 5 "$BIN" ping >/dev/null 2>&1; then
        fail "$label" "the daemon holds its socket but no longer answers" \
             "command: $*" \
             "pid $after is still there and did not reply to ping within 5s;" \
             "this is the cycle recursing without exhausting the stack."
        return
    fi

    pass
}

state_of() {
    # The STATUS column for one runtime, or the empty string when the daemon
    # cannot answer at all.  `ls --name --status` is tab separated.
    "$BIN" ls --name --status 2>/dev/null | awk -F'\t' -v n="$1" '$1 == n { print $2 }'
}

# daemon_recover
#
# Put a healthy, answering daemon on the socket before the next case.
#
# Each case below has to measure its own command.  Without this, a case that
# runs after a crash starts with nothing serving, and its assertion reports
# "the daemon was replaced" about the PREVIOUS case's death — four failures
# where there were two findings, and the two echoes look exactly like the two
# findings.  A red test that overcounts is a red test nobody can act on.
# The condition is "OUR daemon is serving and answering", not "a daemon
# answers".  `ping` is a CLI command, and every CLI command auto-starts a daemon
# when the socket does not answer — so the obvious spelling, `ping || restart`,
# silently forks a replacement while asking the question, returns success, and
# leaves $SOCKETLEY_DPID naming a process that is no longer the one serving.
# The next daemon_start then finds the socket taken, exits 0, and lib_daemon's
# liveness check reports FATAL about a daemon that is up.  That is what ended
# this file's first two runs.
#
# Checking the serving pid first is what makes the ping below safe: it only runs
# when something is already serving, so it cannot fork anything.
daemon_recover() {
    local serving; serving=$(daemon_pids "$SOCKETLEY_SOCKET")
    if [ -n "$serving" ] && [ "$serving" = "${SOCKETLEY_DPID:-}" ] \
       && timeout 5 "$BIN" ping >/dev/null 2>&1; then
        return 0
    fi
    daemon_sweep "$SOCKETLEY_SOCKET"
    if [ -n "${SOCKETLEY_DPID:-}" ]; then wait "$SOCKETLEY_DPID" 2>/dev/null || true; fi

    # And then wait for the socket to actually be free.  `kill -9` returns as
    # soon as the signal is queued, not when the process is gone, and a daemon
    # asks `is_running()` — a real connect() — before it binds.  Starting inside
    # that window makes the new daemon decide one is already running and exit 0,
    # which lib_daemon then reports as FATAL.  This is the same race the sweep
    # exists to close, one step later.
    local i
    for i in $(seq 1 50); do
        [ -z "$(daemon_pids "$SOCKETLEY_SOCKET")" ] && break
        sleep 0.1
    done

    # The log is emptied first, and it is load-bearing rather than tidiness:
    # daemon_start waits by grepping this file for "daemon started", and the
    # line from the PREVIOUS daemon is still in it.  Without this the wait
    # returns immediately and daemon_start's own liveness check then fails on a
    # daemon that simply had not bound yet — the FATAL that ended this file's
    # first run.  test_state_file_permissions.sh:205 has the same line with the
    # measurement behind it (3 FATALs in 6 runs before, 0 in 12 after).
    : > "$SOCKETLEY_DLOG"
    daemon_start "$BIN"
}

echo "=== Integration: owner cascade and owner cycles ==="

daemon_start "$BIN"

P=$((SL_PORT_BASE + 760))

# ─── Control: the cascade has to keep working ───────────────────────────────
#
# First, because if this does not hold there is no point asking the rest: a
# build where stopping a parent does nothing would "survive" every cycle below
# for the wrong reason.
"$BIN" attach server parent   $((P + 0)) >/dev/null 2>&1 || true
"$BIN" attach server child    $((P + 1)) --owner parent >/dev/null 2>&1 || true

if [ -n "$(state_of parent)" ] && [ -n "$(state_of child)" ]; then pass
else fail "control pair exists" "attach did not produce both runtimes" \
          "parent='$(state_of parent)' child='$(state_of child)'"; fi

timeout 15 "$BIN" stop parent >/dev/null 2>&1 || true

if [ "$(state_of parent)" = "Stopped" ]; then pass
else fail "control: parent stopped" "expected Stopped, got '$(state_of parent)'"; fi

# The load-bearing half.  A fix that removes the cascade passes everything
# below and fails exactly here.
if [ "$(state_of child)" = "Stopped" ]; then pass
else fail "control: the cascade reached the child" \
          "expected the child to be Stopped, got '$(state_of child)'" \
          "stopping a parent must still stop its children — without this," \
          "every cycle assertion below would pass on a build that simply" \
          "deleted the cascade."; fi

"$BIN" remove parent >/dev/null 2>&1 || true
"$BIN" remove child  >/dev/null 2>&1 || true

# ─── Cycle 1a: a runtime that owns itself, stopped ──────────────────────────
daemon_recover
"$BIN" attach server selfown $((P + 10)) --owner selfown >/dev/null 2>&1 || true
assert_daemon_survives "self-owning runtime survives stop" "$BIN" stop selfown

# And it really stopped.  Paired with the survival assertion for the reason
# given at the top: "the daemon is still up" is also true of a build that never
# ran the cascade at all.
if timeout 5 "$BIN" ping >/dev/null 2>&1; then
    if [ "$(state_of selfown)" = "Stopped" ]; then pass
    else fail "self-owning runtime actually stopped" \
              "expected Stopped, got '$(state_of selfown)'"; fi
fi

# ─── Cycle 1b: the same runtime, removed ────────────────────────────────────
#
# A separate case with its own fresh daemon, because `remove` fails differently
# from `stop`: remove_children() recurses without exhausting the stack, so the
# daemon keeps its socket and stops answering instead of dying.
daemon_recover
"$BIN" attach server selfrm $((P + 11)) --owner selfrm >/dev/null 2>&1 || true
assert_daemon_survives "self-owning runtime survives remove" "$BIN" remove selfrm

# ─── Cycle 2: two runtimes owning each other ────────────────────────────────
daemon_recover
"$BIN" attach server cyc_a $((P + 20)) --owner cyc_b >/dev/null 2>&1 || true
"$BIN" attach server cyc_b $((P + 21)) --owner cyc_a >/dev/null 2>&1 || true
assert_daemon_survives "two-runtime cycle survives stop" "$BIN" stop cyc_a

if timeout 5 "$BIN" ping >/dev/null 2>&1; then
    if [ "$(state_of cyc_a)" = "Stopped" ]; then pass
    else fail "two-runtime cycle: cyc_a stopped" \
              "expected Stopped, got '$(state_of cyc_a)'"; fi
fi

daemon_recover
"$BIN" attach server cyc_c $((P + 22)) --owner cyc_d >/dev/null 2>&1 || true
"$BIN" attach server cyc_d $((P + 23)) --owner cyc_c >/dev/null 2>&1 || true
assert_daemon_survives "two-runtime cycle survives remove" "$BIN" remove cyc_c

# ─── Cycle 3: the cycle a state file brings back ────────────────────────────
#
# The owner is persisted, so a daemon that restarts meets the cycle again
# without anyone typing `attach` a second time.  This is what makes the defect
# permanent rather than a one-off, and it is why validating set_owner alone
# would not be a fix: the cycles already written to disk still arrive.
daemon_recover
"$BIN" attach server persist_cyc $((P + 30)) --owner persist_cyc >/dev/null 2>&1 || true

# SIGTERM and not daemon_sweep's SIGKILL.  State is written by a background
# thread, and a killed daemon leaves `persist_cyc.json.tmp` behind — the rename
# never happens, the restore finds no `.json`, and the runtime does not come
# back.  The assertion below would then fail for a reason that has nothing to do
# with what it is about.  Measured: with kill -9 the state directory held only
# a .tmp file.
kill -TERM "$SOCKETLEY_DPID" 2>/dev/null || true
for _ in $(seq 1 50); do kill -0 "$SOCKETLEY_DPID" 2>/dev/null || break; sleep 0.1; done
daemon_sweep "$SOCKETLEY_SOCKET"
wait "$SOCKETLEY_DPID" 2>/dev/null || true
: > "$SOCKETLEY_DLOG"   # see daemon_recover
daemon_start "$BIN"

# The case only means something if the restore actually brought the cycle back.
if [ "$("$BIN" owner persist_cyc 2>/dev/null | awk -F: '$1=="owner"{print $2}')" = "persist_cyc" ]; then pass
else fail "the cycle came back from the state file" \
          "persist_cyc's owner did not survive the restart, so the case this" \
          "assertion is about was never exercised."; fi

# ─── And it has to be RUNNING, or the stop below measures nothing ───────────
#
# runtime_manager::stop() returns false at `if (!inst->stop(loop))` — which is
# BEFORE it collects get_children() — so a runtime that is not running never
# reaches the cascade at all.  `attach` does not set was_running, so a restored
# runtime comes back `Created`: measured, [Up 0 seconds] before the restart and
# [Created] after it.
#
# Written first without this, the case passed against a build that crashes on
# every other cycle in this file — a green assertion for a stop that returned
# early and did nothing.  That is the one failure mode a regression test must
# not have, so the state is asserted rather than assumed.
"$BIN" start persist_cyc >/dev/null 2>&1 || true
case "$(state_of persist_cyc)" in
    Up*) pass ;;
    *)   fail "restored runtime is running before the stop" \
              "expected an uptime, got '$(state_of persist_cyc)'" \
              "a stop on a non-running runtime returns before the cascade," \
              "so the assertion below would pass without executing anything." ;;
esac

assert_daemon_survives "restored cycle survives stop" "$BIN" stop persist_cyc

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
if [ "$FAIL" -eq 0 ]; then echo "  OK"; else echo "  FAILED"; fi
exit "$FAIL"
