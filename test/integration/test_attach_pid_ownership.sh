#!/usr/bin/env bash
# Integration test: `attach --pid` only accepts a process the caller owns.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# --pid is how an embedded process registers a runtime it serves itself; the
# SDK example passes getpid().  The daemon remembers it and sends it SIGTERM
# when the runtime is stopped — that is the feature, not a side effect.
#
# Nothing checked whose pid it was.  Measured on the parent commit against a
# process the daemon had nothing to do with:
#
#     $ sleep 300 &                       # pid 1328283
#     $ socketley attach server bystander 18790 --pid 1328283
#     $ socketley stop bystander
#     [2]+  Terminated              sleep 300
#
# On a single-user daemon that crosses no boundary: whoever may open the socket
# could have signalled the process themselves, and this file deliberately does
# NOT change that — the same-uid case below must keep working, because it is
# the documented one.
#
# The boundary is the packaged daemon.  Its socket is 0660 socketley:socketley
# so operators can reach a daemon running as its own user — as root in the
# container image — and any member of that group could make it signal anything
# that uid could.  So the pid has to belong to the caller: SO_PEERCRED gives the
# uid on the other end, /proc/<pid> is owned by whoever runs it, and equal means
# the caller could have done it without the daemon's help.
#
# A test cannot become two users, so the refusal is exercised the other way
# round: from an unprivileged caller against a pid that is root's.  pid 1 is
# always there and is never ours.

set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate attach_pid
PASS=0; FAIL=0; TOTAL=0

VICTIM=""
cleanup() {
    [ -n "$VICTIM" ] && kill "$VICTIM" 2>/dev/null
    daemon_stop
}
trap cleanup EXIT

pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

echo "=== Integration: attach --pid ownership ==="

daemon_start "$BIN"
P=$((SL_PORT_BASE + 830))

# ─── A pid that will not parse is refused, not ignored ──────────────────────
#
# It used to be read with an unchecked from_chars and left at 0, so `--pid abc`
# produced a runtime the daemon could never stop and said nothing.  The port
# six lines above it in cmd_attach has always been checked.
OUT=$("$BIN" attach server badpid $((P + 0)) --pid abc 2>&1) && RC=0 || RC=$?
if [ "${RC:-0}" -ne 0 ]; then pass
else fail "a pid that will not parse is refused" \
          "attach exited 0 for --pid abc" \
          "said: $OUT"; fi

# And nothing was created by the refused command.
if [ -z "$("$BIN" ls --name 2>/dev/null | grep -x badpid || true)" ]; then pass
else fail "a refused attach creates nothing" "badpid exists anyway"; fi

# ─── The documented case still works ────────────────────────────────────────
#
# First, and load-bearing: a fix that refused every --pid would pass the
# refusal assertion below and break the only spelling anybody uses.
sleep 300 & VICTIM=$!
OUT=$("$BIN" attach server mine $((P + 1)) --pid "$VICTIM" 2>&1) && RC=0 || RC=$?
if [ "${RC:-0}" -eq 0 ]; then pass
else fail "attaching a pid we own is still accepted" \
          "exit $RC for a process this user started" \
          "said: $OUT"; fi

# And the feature it exists for: stopping the runtime signals that process.
"$BIN" stop mine >/dev/null 2>&1 || true
sleep 0.5
if ! kill -0 "$VICTIM" 2>/dev/null; then
    pass
    VICTIM=""
else
    fail "stopping the runtime still signals the process it owns" \
         "the process is still running, so --pid no longer does anything" \
         "this is the feature, not a side effect — see the SDK example."
fi

# ─── A pid belonging to another user is refused ─────────────────────────────
if [ "$(id -u)" -eq 0 ]; then
    echo "  SKIP [a pid we do not own is refused]: running as root, which may"
    echo "        signal anything and is deliberately not restricted."
else
    OUT=$("$BIN" attach server notmine $((P + 2)) --pid 1 2>&1) && RC=0 || RC=$?
    if [ "${RC:-0}" -ne 0 ]; then pass
    else fail "a pid we do not own is refused" \
              "attach accepted --pid 1, which belongs to root" \
              "said: $OUT" \
              "the daemon would signal it on stop, on behalf of a caller who" \
              "cannot signal it themselves."; fi

    if [ -z "$("$BIN" ls --name 2>/dev/null | grep -x notmine || true)" ]; then pass
    else fail "the refused attach created nothing" "notmine exists anyway"; fi

    # The reason has to name what is wrong.  An exit code with no sentence is
    # the defect half this review is about.
    if grep -qi "another user" <<<"$OUT"; then pass
    else fail "the refusal says why" "said: $OUT"; fi
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
if [ "$FAIL" -eq 0 ]; then echo "  OK"; else echo "  FAILED"; fi
exit "$FAIL"
