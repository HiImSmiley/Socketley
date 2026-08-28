#!/usr/bin/env bash
# Integration test: an on_start that raises is reported by whoever asked for it.
#
# ─── WHAT THIS IS ABOUT ─────────────────────────────────────────────────────
#
# on_start is the one callback in this tree that runs inside a command rather
# than on traffic: `create -s`, `start` and `reload-lua` each call it
# synchronously, with a caller still waiting.  `reload-lua` reports a raise —
# exit 1, naming the callback and the reason — and the other two did not.  The
# same script, the same callback and the same error answered differently
# depending on which command reached it:
#
#     $ socketley create server c1 -p ... --lua boom.lua --daemon-process -s
#                                                        ^ the flag is gone now
#     $ echo $?
#     0                                   <- and not one character of output
#     $ socketley reload-lua c1
#     reload-lua c1: on_start error: boom.lua:2: on_start blew up on purpose
#     $ echo $?
#     1
#
# What the operator was left with is a runtime `ls` reports as Up, serving
# traffic, with none of what on_start was supposed to establish — no
# subscriptions, no timers, no upstream connection — and a command that said
# nothing at all.  The reason existed the whole time, in the daemon's log, one
# process away.
#
# ─── WHY 1, AND WHY THE RUNTIME STAYS UP ────────────────────────────────────
#
# These are two separate questions and this file pins both.
#
# The runtime stays up because start() will not fail on a raise, deliberately:
# the listener is armed and the state is `running` several lines before on_start
# is called, and turning a script's error into `failed` would take a live
# listener down over a callback the tree reports and carries on from everywhere
# else.  So `ls` must still say Up afterwards, and that is asserted.
#
# The exit code is 1 because the fault is in the file the operator named, which
# is this tree's definition of bad input — and because `create` already answers
# 1 when that same file will not PARSE.  A script that compiles and then raises
# in its set-up is the same fault one step later in the same script's life, and
# giving it a different code would be the arbitrary part.
#
# Together they are what lets an operator tell the two apart without opening the
# daemon's log: exit 0 and silence means the runtime is up and its script's
# set-up ran; exit 1 with a named reason means the runtime is up and it did not.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate luaonstart

PB=$((SL_PORT_BASE+1120))

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

NAMES="os_boom os_ok os_restart os_pair1 os_pair2 os_wboom os_wok"
cleanup() {
    # shellcheck disable=SC2086
    "$BIN" stop $NAMES >/dev/null 2>&1 || true
    sleep 0.2
    # shellcheck disable=SC2086
    "$BIN" remove $NAMES >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: an on_start that raises reaches the caller ==="

daemon_start "$BIN"

BOOM="$SOCKETLEY_TMPD/boom.lua"
cat > "$BOOM" <<'LUAEOF'
function on_start()
    error("on_start blew up on purpose")
end
LUAEOF

GOOD="$SOCKETLEY_TMPD/good.lua"
cat > "$GOOD" <<'LUAEOF'
function on_start()
    socketley.log("GOOD on_start ran")
end
LUAEOF

# state NAME — what `ls` says in the STATUS column, first word only.
state() { "$BIN" ls 2>/dev/null | awk -v n="$1" '$2 == n { print $7 }'; }

# ── create -s, in the daemon ────────────────────────────────────────────────
set +e
OUT=$("$BIN" create server os_boom -p $((PB + 0)) --lua "$BOOM" -s 2>&1)
RC=$?
set -e
# Exit 1 specifically, not merely non-zero.  2 is the fatal code, and a build
# that refused the create outright — removing the runtime, which is what the
# unparseable-script path does — would also be non-zero while being a different
# answer to a different question.
if [ "$RC" = "1" ]; then pass; else
    fail "create -s exits 1 when on_start raises" \
         "exit was $RC, wanted 1" \
         "output: ${OUT:-<nothing>}" \
         "reload-lua has answered 1 with the reason since it began re-running" \
         "on_start; the same raise through create -s answered 0 and said nothing"
fi
if printf '%s' "$OUT" | grep -qa "on_start error" &&
   printf '%s' "$OUT" | grep -qa "on_start blew up on purpose"; then pass; else
    fail "create -s names the callback and the reason" \
         "output: ${OUT:-<nothing>}" \
         "the callback's name and the script's own message are what make this" \
         "actionable; 'could not start runtime' would not be"
fi
# And the operator is told which of the two situations they are in.
if printf '%s' "$OUT" | grep -qa "running"; then pass; else
    fail "create -s says the runtime is nonetheless up" \
         "output: ${OUT:-<nothing>}" \
         "exit 1 with a live listener is unusual enough to have to be stated:" \
         "the alternative reading, that nothing was created, is wrong"
fi
if [ "$(state os_boom)" = "Up" ]; then pass; else
    fail "the runtime is created and running anyway" \
         "ls says '$(state os_boom)', wanted 'Up'" \
         "start() does not fail on a raise, and must not: the listener is armed" \
         "and the state is running before on_start is ever called"
fi

# ── Control: a script whose on_start returns ────────────────────────────────
#
# Silence is golden is a rule here, so "the reason now reaches the caller" must
# not have become "every create prints something".
set +e
OUT=$("$BIN" create server os_ok -p $((PB + 1)) --lua "$GOOD" -s 2>&1)
RC=$?
set -e
if [ "$RC" = "0" ] && [ -z "$OUT" ]; then pass; else
    fail "control: a clean on_start creates silently and exits 0" \
         "exit $RC, output: ${OUT:-<nothing>}"
fi

# ── The same create again, which is now the only one there is ──────────────
#
# This was "the same create with no --daemon-process, which is the ordinary
# one": the command above was the exception and this was what an operator
# actually typed.  There is no exception left, so the two are the same command
# and this arm is the one that still has a reason to exist -- the script runs in
# the child, so the reason has to cross the control socket to get here, and a
# fix that only covered an in-daemon leg would now cover nothing at all.
set +e
OUT=$("$BIN" create server os_wboom -p $((PB + 5)) --lua "$BOOM" -s 2>&1)
RC=$?
set -e
if [ "$RC" = "1" ]; then pass; else
    fail "create -s in a worker exits 1 when on_start raises" \
         "exit was $RC, wanted 1" "output: ${OUT:-<nothing>}" \
         "the child's start() does not fail on a raise either, so its state" \
         "frame says running and await_startup answers 'serving': without a" \
         "frame carrying the reason this side cannot know anything went wrong"
fi
if printf '%s' "$OUT" | grep -qa "on_start blew up on purpose"; then pass; else
    fail "create -s in a worker names the reason" "output: ${OUT:-<nothing>}"
fi
if [ "$(state os_wboom)" = "Up" ]; then pass; else
    fail "the worker-backed runtime is running anyway" \
         "ls says '$(state os_wboom)', wanted 'Up'"
fi

set +e
OUT=$("$BIN" create server os_wok -p $((PB + 6)) --lua "$GOOD" -s 2>&1)
RC=$?
set -e
if [ "$RC" = "0" ] && [ -z "$OUT" ]; then pass; else
    fail "control: a clean on_start in a worker creates silently and exits 0" \
         "exit $RC, output: ${OUT:-<nothing>}"
fi

# ── start, on a runtime whose script raises ─────────────────────────────────
"$BIN" create server os_restart -p $((PB + 2)) --lua "$BOOM" \
    >/dev/null 2>&1 || true
set +e
OUT=$("$BIN" start os_restart 2>&1)
RC=$?
set -e
if [ "$RC" = "1" ]; then pass; else
    fail "start exits 1 when on_start raises" \
         "exit was $RC, wanted 1" "output: ${OUT:-<nothing>}"
fi
if printf '%s' "$OUT" | grep -qa "on_start blew up on purpose"; then pass; else
    fail "start names the reason" "output: ${OUT:-<nothing>}"
fi
if [ "$(state os_restart)" = "Up" ]; then pass; else
    fail "the runtime started by 'start' is running anyway" \
         "ls says '$(state os_restart)', wanted 'Up'"
fi

# ── Control: start of a clean runtime ───────────────────────────────────────
"$BIN" stop os_ok >/dev/null 2>&1 || true
sleep 0.3
set +e
OUT=$("$BIN" start os_ok 2>&1)
RC=$?
set -e
if [ "$RC" = "0" ] && [ -z "$OUT" ]; then pass; else
    fail "control: starting a clean runtime is silent and exits 0" \
         "exit $RC, output: ${OUT:-<nothing>}"
fi

# ── One bad script does not stop the runtimes named beside it ───────────────
#
# `start a b c` counts failures and carries on, exactly as it does for a TLS
# refusal.  A build that returned at the raise would leave os_pair2 down while
# reporting only os_pair1, which is the shape this tree has already been fixed
# for once (`start myproxy -i` started the proxy and then exited 1).
"$BIN" create server os_pair1 -p $((PB + 3)) --lua "$BOOM" >/dev/null 2>&1 || true
"$BIN" create server os_pair2 -p $((PB + 4)) --lua "$GOOD" >/dev/null 2>&1 || true
set +e
OUT=$("$BIN" start os_pair1 os_pair2 2>&1)
RC=$?
set -e
if [ "$RC" = "1" ]; then pass; else
    fail "start of a pair exits 1 when one of them raised" \
         "exit was $RC, wanted 1" "output: ${OUT:-<nothing>}"
fi
if printf '%s' "$OUT" | grep -qa "os_pair1"; then pass; else
    fail "the failing one is named" "output: ${OUT:-<nothing>}" \
         "'start a b c' has to say which of them it is talking about"
fi
if [ "$(state os_pair2)" = "Up" ]; then pass; else
    fail "the runtime named beside it still started" \
         "ls says '$(state os_pair2)', wanted 'Up'"
fi

# ── reload, which is a stop and a start ─────────────────────────────────────
#
# The third command that runs on_start, and the one it would be easiest to
# leave out: cmd_reload's own comment says "reload is a stop followed by a
# start, so it is a start", and if that is true for the TLS refusal above it is
# true for this.  Leaving it would recreate the inconsistency this whole file
# is about, one command along.
set +e
OUT=$("$BIN" reload os_restart 2>&1)
RC=$?
set -e
if [ "$RC" = "1" ] && printf '%s' "$OUT" | grep -qa "on_start blew up on purpose"; then pass; else
    fail "reload reports an on_start raise too" \
         "exit $RC, output: ${OUT:-<nothing>}"
fi
set +e
OUT=$("$BIN" reload os_ok 2>&1)
RC=$?
set -e
if [ "$RC" = "0" ] && [ -z "$OUT" ]; then pass; else
    fail "control: reload of a clean runtime is silent and exits 0" \
         "exit $RC, output: ${OUT:-<nothing>}"
fi

# ── The log still has it: a tee, not a redirect ─────────────────────────────
if grep -qa "on_start error" "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    fail "the daemon's log still carries the reason" \
         "no 'on_start error' line in the daemon log" \
         "an operator reading the log afterwards must not have lost anything"
fi

# ── reload-lua, unchanged ──────────────────────────────────────────────────
#
# The command this behaviour is being made consistent WITH.  If a change here
# had moved it, the consistency being claimed would not exist.
set +e
OUT=$("$BIN" reload-lua os_boom 2>&1)
RC=$?
set -e
if [ "$RC" = "1" ] && printf '%s' "$OUT" | grep -qa "on_start error"; then pass; else
    fail "control: reload-lua still reports an on_start raise" \
         "exit $RC, output: ${OUT:-<nothing>}"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
