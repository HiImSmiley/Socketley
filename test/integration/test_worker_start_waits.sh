#!/usr/bin/env bash
# Integration test: `start` and `reload` answer for the worker they fork.
#
# ─── WHAT THIS IS ABOUT ─────────────────────────────────────────────────────
#
# A runtime lives in a worker process unless it was created with
# --daemon-process, so the script runs there, the port is bound there and the
# TLS pair is checked there.  `create -s` waits for the child's verdict and
# turns it into an exit status, and its comment says why: returning on the
# strength of having forked a process is not the same as that process having
# accepted anything.
#
# `start` forks exactly the same child and did not wait.  Measured on the
# parent commit, one runtime whose script declares `path = "no-slash"` —
# faultless Lua, so the daemon-side compile check passes it and only the worker
# discovers it is not a path:
#
#     create -s   exit 1   "the worker did not accept its configuration"
#     start       exit 0   (silence)        ls, 2s later: Failed
#
# Same runtime, same configuration, same refusal, and the answer depended on
# which command reached it.  That is not a missing detail about a start that
# happened; it is success reported for one that did not.
#
# ─── AND `reload` NEVER REACHED THE CHILD AT ALL ────────────────────────────
#
# The larger half, found while fixing the first.  `reload` is a stop followed
# by a start, and both of those move the PLACEHOLDER's state; reconciliation is
# what turns a placeholder's state into a live child.  Reconciling only after
# both had run saw `running` — the same thing it saw before — and left the
# original child alone.  Measured on the parent, a worker-backed server whose
# script was edited under it:
#
#     reload   exit 0   (silence)   ls: Up   — and the OLD script still serving
#
# So the last section of this file is not about exit codes.  It edits a script
# to something that must be refused, reloads, and requires the refusal: the only
# way to see one is for the child to have been restarted and to have read the
# new file.  The control beside it edits to a script that must be ACCEPTED and
# requires that its new marker appears, so that "reload reaches the worker" is
# proved in the direction where nothing is broken as well as in the one where
# something is.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate wkstart

PB=$((SL_PORT_BASE+1150))
PORT_OK=$((PB + 0))
PORT_BAD=$((PB + 1))
PORT_BOOM=$((PB + 2))
PORT_RL=$((PB + 3))

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

NAMES="wks_ok wks_bad wks_boom wks_rl"
cleanup() {
    # shellcheck disable=SC2086
    "$BIN" stop $NAMES >/dev/null 2>&1 || true
    sleep 0.2
    # shellcheck disable=SC2086
    "$BIN" remove $NAMES >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: start and reload answer for the worker they fork ==="

daemon_start "$BIN"

GOOD="$SOCKETLEY_TMPD/good.lua"
cat > "$GOOD" <<'LUAEOF'
function on_start() socketley.log("GOOD on_start ran") end
LUAEOF
BAD="$SOCKETLEY_TMPD/bad.lua"
cat > "$BAD" <<'LUAEOF'
routes = { { path = "no-slash", methods = { "GET" } } }
LUAEOF
BOOM="$SOCKETLEY_TMPD/boom.lua"
cat > "$BOOM" <<'LUAEOF'
function on_start() error("on_start blew up on purpose") end
LUAEOF

# state NAME — the STATUS column's first word.
state() { "$BIN" ls 2>/dev/null | awk -v n="$1" '$2 == n { print $7 }'; }

# ── `start` returns when the child is serving, not when it was forked ───────
#
# No sleep between the two, deliberately.  cmd_start's own comment has always
# claimed that reconciling there "makes `start` followed immediately by a
# request work"; without the wait the child had not bound yet and it did not.
create_ok "worker runtime created" "$BIN" create server wks_ok -p "$PORT_OK" \
    --lua "$GOOD" -s
ready_tcp 127.0.0.1 "$PORT_OK" 10 || echo "  NOTE: the worker never accepted"
"$BIN" stop wks_ok >/dev/null 2>&1 || true
for _ in $(seq 1 50); do nc -z 127.0.0.1 "$PORT_OK" 2>/dev/null || break; sleep 0.1; done

set +e
OUT=$("$BIN" start wks_ok 2>&1); RC=$?
nc -z 127.0.0.1 "$PORT_OK" 2>/dev/null; IMMEDIATE=$?
set -e
if [ "$RC" = "0" ] && [ -z "$OUT" ]; then pass; else
    fail "control: starting a healthy worker runtime is silent and exits 0" \
         "exit $RC, output: ${OUT:-<nothing>}" \
         "silence is golden covers success, and this one is a success"
fi
if [ "$IMMEDIATE" = "0" ]; then pass; else
    fail "the port is accepting the moment start returns" \
         "nothing was listening on $PORT_OK immediately after start returned" \
         "start forked the child and returned without waiting for it, so the" \
         "next command in a script raced a process that had not bound yet"
fi

# ── A configuration only the child can judge ───────────────────────────────
create_ok "refused-config runtime created" "$BIN" create server wks_bad \
    -p "$PORT_BAD" --lua "$BAD"
set +e
OUT=$("$BIN" start wks_bad 2>&1); RC=$?
set -e
if [ "$RC" = "1" ]; then pass; else
    fail "start exits 1 when the worker refuses its configuration" \
         "exit was $RC, wanted 1" "output: ${OUT:-<nothing>}" \
         "create -s has answered 1 for this exact configuration since the wait" \
         "was added to it; start forks the same child"
fi
case "$OUT" in
    *wks_bad*) pass ;;
    *) fail "the refusal names the runtime" "output: ${OUT:-<nothing>}" ;;
esac
if [ "$(state wks_bad)" = "Failed" ]; then pass; else
    fail "control: the runtime really did fail" \
         "ls says '$(state wks_bad)', wanted 'Failed'" \
         "without this the exit code above could be a message about nothing"
fi

# ── An on_start that raises, in the worker ─────────────────────────────────
create_ok "raising-on_start runtime created" "$BIN" create server wks_boom \
    -p "$PORT_BOOM" --lua "$BOOM"
set +e
OUT=$("$BIN" start wks_boom 2>&1); RC=$?
set -e
if [ "$RC" = "1" ] && printf '%s' "$OUT" | grep -qa "on_start blew up on purpose"; then pass; else
    fail "start carries an on_start raise out of the worker" \
         "exit $RC, output: ${OUT:-<nothing>}" \
         "the child does not fail its start on a raise either, so its state" \
         "frame says running and the wait alone would answer 'serving'; the" \
         "reason comes up as its own frame"
fi
if [ "$(state wks_boom)" = "Up" ]; then pass; else
    fail "the runtime whose on_start raised is running anyway" \
         "ls says '$(state wks_boom)', wanted 'Up'"
fi

# ── `reload` reaches the child ─────────────────────────────────────────────
#
# The script is edited under a running worker-backed runtime and reloaded.  On
# the parent nothing happened at all: the placeholder's state went down and up,
# the child was never touched, and the command said nothing.
RL="$SOCKETLEY_TMPD/rl.lua"
cat > "$RL" <<'LUAEOF'
function on_start() socketley.log("RL VERSION ONE") end
LUAEOF
create_ok "reload subject created" "$BIN" create server wks_rl -p "$PORT_RL" \
    --lua "$RL" -s
ready_tcp 127.0.0.1 "$PORT_RL" 10 || echo "  NOTE: the reload subject never accepted"

# Control first, and in the direction where nothing is broken: a new script that
# must be ACCEPTED, whose marker only exists if the child re-read the file.
cat > "$RL" <<'LUAEOF'
function on_start() socketley.log("RL VERSION TWO") end
LUAEOF
set +e
OUT=$("$BIN" reload wks_rl 2>&1); RC=$?
set -e
if [ "$RC" = "0" ] && [ -z "$OUT" ]; then pass; else
    fail "control: reloading a healthy worker runtime is silent and exits 0" \
         "exit $RC, output: ${OUT:-<nothing>}"
fi
for _ in $(seq 1 60); do
    grep -qa "RL VERSION TWO" "$SOCKETLEY_DLOG" 2>/dev/null && break
    sleep 0.1
done
if grep -qa "RL VERSION TWO" "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    fail "reload reaches the worker and the new script takes effect" \
         "no 'RL VERSION TWO' line — the child is still running version one" \
         "reload moved the placeholder's state down and up and reconciled once" \
         "at the end, which saw 'running' and left the original child alone"
fi

# And in the direction where something is: a script the child must refuse.  The
# only way to see this refusal is for the child to have restarted and read it.
cat > "$RL" <<'LUAEOF'
routes = { { path = "no-slash", methods = { "GET" } } }
LUAEOF
set +e
OUT=$("$BIN" reload wks_rl 2>&1); RC=$?
set -e
if [ "$RC" = "1" ]; then pass; else
    fail "reload exits 1 when the reloaded script is refused by the worker" \
         "exit was $RC, wanted 1" "output: ${OUT:-<nothing>}" \
         "reload is a stop followed by a start, so it is a start, and a start" \
         "answers for its child"
fi
if [ "$(state wks_rl)" = "Failed" ]; then pass; else
    fail "control: the refused reload really did fail the runtime" \
         "ls says '$(state wks_rl)', wanted 'Failed'"
fi

# ── The daemon survived all of that ────────────────────────────────────────
TOTAL=$((TOTAL+1))
if kill -0 "$SOCKETLEY_DPID" 2>/dev/null && daemon_alive "$SOCKETLEY_SOCKET"; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL: the daemon did not survive starting and reloading workers"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
