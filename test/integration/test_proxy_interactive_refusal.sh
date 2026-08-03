#!/usr/bin/env bash
# Integration test: `start <proxy> -i` refuses, and refuses before it starts it.
#
# Interactive mode is a stream.  For a server, what is typed is broadcast to its
# clients; for a client it is sent to its server; for a cache it is executed and
# the reply comes back.  A proxy has none of that — it relays between a client
# and a backend and speaks for neither — so there is nothing for typed input to
# mean, and offering it would mean inventing a semantics rather than exposing
# one.  It stays refused, on both the in-process and the out-of-process path.
#
# What was wrong was where the refusal happened.  The check sat BELOW the start
# loop, so the command started the proxy, persisted was_running, and then exited
# 1 saying interactive mode was not supported.  The operator is told the command
# failed; the listener is up; and the state file will bring it back on the next
# daemon restart.  A refusal that performs the thing it is refusing is not a
# refusal.
#
# ─── WHY THE EXIT CODE IS NOT THE ORACLE ────────────────────────────────────
#
# It cannot be: it was already 1 before this change and it is 1 after.  Asserting
# it proves nothing about the defect.  The oracle is the runtime's state after
# the refused command — `created`, untouched — with the exit code kept only as a
# control that the command is still refusing at all.
#
# ─── THE CONTROLS ───────────────────────────────────────────────────────────
#
#   * `start <proxy>` without -i must still start it.  Without this, "the proxy
#     is not running after start -i" also passes on a build where start is
#     broken for proxies entirely.
#   * `start <server> -i` must still be accepted.  Without this, the refusal
#     could have been widened to every runtime type and nothing here would
#     notice.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"

daemon_isolate proxyinteractive

BE_PORT=19480
PX_PORT=19481
PX_OOP_PORT=19482
SRV_PORT=19483

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    "$BIN" stop   px px_oop plainsrv backend 2>/dev/null || true
    sleep 0.3
    "$BIN" remove px px_oop plainsrv backend 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: start -i on a proxy refuses without starting it ==="

daemon_start "$BIN"

# `ls`, not `ps`: ps lists only what is running, so it cannot tell `created`
# from `failed` from `never existed`.
state() {
    "$BIN" ls 2>/dev/null | awk -v n="$1" '$2 == n { print tolower($7) }' | head -1
}

# Created and deliberately NOT started -- that is the whole point.
create_ok "backend created" "$BIN" create server backend -p "$BE_PORT" -s
create_ok "proxy created (not started)" "$BIN" create proxy px -p "$PX_PORT" \
    --backend "127.0.0.1:$BE_PORT" --protocol http
create_ok "out-of-process proxy created (not started)" "$BIN" create proxy px_oop \
    -p "$PX_OOP_PORT" --backend "127.0.0.1:$BE_PORT" --protocol http
create_ok "server created (not started)" "$BIN" create server plainsrv -p "$SRV_PORT"

BEFORE=$(state px)
if [ "$BEFORE" = "created" ]; then pass; else
    fail "setup: the proxy starts out created" \
         "it is '$BEFORE', wanted 'created'" \
         "nothing below can tell a refusal from a no-op if it was already running"
fi

# ── The refusal, in-process ─────────────────────────────────────────────────
RC=0
OUT=$("$BIN" start px -i </dev/null 2>&1) || RC=$?

if [ "$RC" -eq 1 ]; then pass; else
    fail "control: start -i on a proxy still exits 1" \
         "exit was $RC, wanted 1 — output: '$OUT'"
fi

case "$OUT" in
    *"not offered for a proxy"*) pass ;;
    *) fail "the refusal names what it refused" \
            "said '$OUT'" \
            "an operator has to be able to tell this from a runtime that is missing" ;;
esac

case "$OUT" in
    *"Nothing was started"*) pass ;;
    *) fail "the refusal says the runtime was left alone" \
            "said '$OUT'" \
            "the message is the only place this is visible at the terminal" ;;
esac

# ── The assertion: it did not start it ──────────────────────────────────────
AFTER=$(state px)
if [ "$AFTER" = "created" ]; then pass; else
    fail "a refused start -i leaves the proxy alone" \
         "the proxy is '$AFTER' after a command that exited 1, wanted 'created'" \
         "the check used to run after the start loop, so the command started the" \
         "proxy, persisted was_running, and then reported failure — and a daemon" \
         "restart would bring back a runtime the operator was told had not started"
fi

# ── And the same on the out-of-process path ─────────────────────────────────
RC=0
OUT_OOP=$("$BIN" start px_oop -i </dev/null 2>&1) || RC=$?
AFTER_OOP=$(state px_oop)
if [ "$RC" -eq 1 ] && [ "$AFTER_OOP" = "created" ]; then pass; else
    fail "the same holds for an out-of-process proxy" \
         "exit $RC, state '$AFTER_OOP' — wanted exit 1 and 'created'" \
         "output: '$OUT_OOP'"
fi

# ── Control: start without -i still works ───────────────────────────────────
RC=0
"$BIN" start px >/dev/null 2>&1 || RC=$?
sleep 0.5
RUNNING=$(state px)
if [ "$RC" -eq 0 ] && [ "$RUNNING" = "up" ]; then pass; else
    fail "control: start without -i still starts the proxy" \
         "exit $RC, state '$RUNNING' — wanted exit 0 and up" \
         "if start is simply broken for proxies, the assertion above is vacuous"
fi

# ── Control: -i is still offered where it means something ───────────────────
RC=0
"$BIN" start plainsrv -i </dev/null >/dev/null 2>&1 || RC=$?
sleep 0.5
SRV_STATE=$(state plainsrv)
if [ "$RC" -eq 0 ] && [ "$SRV_STATE" = "up" ]; then pass; else
    fail "control: start -i on a server is still accepted" \
         "exit $RC, state '$SRV_STATE' — wanted exit 0 and up" \
         "the refusal has been widened past the proxy it was written for"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
