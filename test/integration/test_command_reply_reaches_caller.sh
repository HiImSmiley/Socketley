#!/usr/bin/env bash
# Integration test: a command that refuses says so on the caller's terminal.
#
# ─── WHAT THIS IS ABOUT ─────────────────────────────────────────────────────
#
# The daemon answers a CLI command with two things: an exit code and a reply
# body.  The body is conn->write_buf, and cout_to_reply is the object that
# borrows std::cout for the length of a command so that a handler can simply
# print.  Its own comment says it is "the one that reaches every one of them at
# once" — and it was then installed on exactly two commands, create and edit.
#
# Every other handler printed into the daemon's own stdout, which is /dev/null
# once it has daemonised.  Measured against a daemon whose stdout AND stderr
# were both redirected to a file, so that nothing could be hiding on the other
# stream:
#
#     $ socketley send nosuchruntime hello ; echo $?
#     1                          <- and not one word, anywhere
#     $ socketley start ; echo $?
#     1                          <- the usage line, likewise gone
#
# The messages exist. `runtime not found: nosuchruntime` is written by
# cmd_send, and `usage: start <name|pattern>... [-i]` by cmd_start. Nobody can
# read either. An exit code with no sentence behind it is the same defect as a
# Lua script that will not load and will not say why, one command family over.
#
# ─── THE CONTROLS ───────────────────────────────────────────────────────────
#
# Two, and they are what stop this file passing against a build that simply
# prints something on every command:
#
#   * a command that succeeds must stay SILENT and exit 0.  Silence is golden
#     is a rule here, and reaching the caller must not become chattering at it.
#   * `create` must still report its refusals.  It had a guard of its own and
#     now relies on the shared one; if moving it lost the message, this catches
#     it.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"

daemon_isolate cmdreply

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    "$BIN" stop  cr_up cr_down 2>/dev/null || true
    sleep 0.3
    "$BIN" remove cr_up cr_down 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a refused command answers on the caller's terminal ==="

daemon_start "$BIN"

# says LABEL NEEDLE WANT_RC -- run the rest as a command, and require both the
# exit code and a reply carrying NEEDLE.
#
# Both halves are asserted because either alone passes against the defect: the
# exit code was always right, and it was the only thing that was.
says() {
    local label=$1 needle=$2 want_rc=$3; shift 3
    local rc=0 out
    out=$("$@" 2>&1) || rc=$?
    if [ "$rc" = "$want_rc" ]; then pass; else
        fail "$label: exit code" "got $rc, wanted $want_rc" \
             "the command said: ${out:-<nothing>}"
    fi
    case "$out" in
        *"$needle"*) pass ;;
        *) fail "$label: the reply says why" \
                "wanted the reply to carry: $needle" \
                "the CLI got: ${out:-<nothing>}" \
                "the message is written — it goes to the daemon's own stdout," \
                "which is /dev/null once it has daemonised" ;;
    esac
}

# ── send, the command with no ipc_connection in its signature at all ────────
says "send to an unknown runtime" "runtime not found: nosuchruntime" 1 \
     "$BIN" send nosuchruntime hello

says "send with too few arguments" "usage: send" 1 \
     "$BIN" send

# ── start, whose usage line went nowhere ────────────────────────────────────
says "start with no arguments" "usage: start" 1 \
     "$BIN" start

# ── send to a runtime that exists but is not running ────────────────────────
create_ok "stopped runtime created" "$BIN" create server cr_down -p 21901
says "send to a stopped runtime" "runtime is not running: cr_down" 1 \
     "$BIN" send cr_down hello

# ── Control 1: a command that works is silent ───────────────────────────────
create_ok "running runtime created" "$BIN" create server cr_up -p 21902 -s
sleep 0.4
OK_RC=0
OK_OUT=$("$BIN" send cr_up hello 2>&1) || OK_RC=$?
if [ "$OK_RC" = "0" ] && [ -z "$OK_OUT" ]; then pass; else
    fail "control: a send that works says nothing and exits 0" \
         "send exited $OK_RC and said '${OK_OUT:-<nothing>}'" \
         "silence is golden — a refusal reaching the caller must not turn into" \
         "every command printing something"
fi

# ── Control 2: create still reports, with its own guard removed ─────────────
BROKEN="$SOCKETLEY_TMPD/broken.lua"
printf 'function on_message(m)\n  print(m\nend\n' > "$BROKEN"
says "create still reports a refusal" "could not load Lua script" 1 \
     "$BIN" create server cr_never -p 21903 --lua "$BROKEN" --daemon-process -s
"$BIN" remove cr_never >/dev/null 2>&1 || true

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
