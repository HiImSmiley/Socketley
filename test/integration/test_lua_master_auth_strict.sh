#!/usr/bin/env bash
# Integration test: on_master_auth is read strictly, and a hook that failed denies.
#
# ─── WHAT THIS IS ABOUT ─────────────────────────────────────────────────────
#
# `on_master_auth(client_id, password)` is the whole master gate when a script
# defines one: server_instance's mode_master branch tries the callback FIRST and
# only falls back to --master-pw with an `else if`, so a script that defines the
# hook has replaced the password, not supplemented it.
#
# It was read with `result.get<bool>()`, which is lua_toboolean.  In Lua every
# value except `false` and `nil` is true, so the hook granted master for
#
#     return "denied"      -- a string, the obvious way to say no
#     return 0             -- zero is true in Lua, unlike C
#     return {}            -- an empty table, what a script returns by accident
#
# and the only two answers that refused were the two nobody writes by mistake.
# A hook that raised was worse: the error was swallowed by a bare `catch (...)
# {}` and nothing anywhere said so, so an auth callback with a typo in it was
# indistinguishable from one that had made a decision.
#
# One file away `invoke_on_auth` had this right the whole time — sol::optional
# <bool>, value_or(false), and the message printed — so the tree carried two
# authentication callbacks with opposite conventions.
#
# ─── THE CONTROLS ───────────────────────────────────────────────────────────
#
# Two, and they are what stop this file from passing against a build where
# on_master_auth is simply broken and denies everything:
#
#   * `return true` must still GRANT.  Without it, every assertion below is
#     satisfied by a hook that never works.
#   * `return false` must deny.  The pair of them proves the hook is read as a
#     boolean rather than ignored.
#
# A runtime of its own per case, deliberately.  A denial is recorded against the
# source address, and ten within a minute lock the address out of the server
# entirely — so six denial cases sharing one port would start being refused at
# accept time partway through, and the later assertions would pass for a reason
# that has nothing to do with the callback.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"

daemon_isolate masterauthstrict

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

NAMES="ma_string ma_zero ma_table ma_raise ma_true ma_false"

cleanup() {
    # shellcheck disable=SC2086
    "$BIN" stop $NAMES 2>/dev/null || true
    sleep 0.3
    # shellcheck disable=SC2086
    "$BIN" remove $NAMES 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: on_master_auth is strict and fails closed ==="

daemon_start "$BIN"

# ask PORT -> what the server answered to `master hunter2`, CR stripped.
#
# `|| true` on the pipeline: a runtime that never came up leaves nothing on the
# port, nc exits non-zero, pipefail promotes it, and the capture below is a
# simple command whose status is exactly that — which would end this file
# silently at the first case rather than reporting it.  An empty answer is not
# "master: ok", and the assertion is what says so.
ask() {
    printf 'master hunter2\n' | nc -q 1 127.0.0.1 "$1" 2>/dev/null | tr -d '\r' || true
}

# case NAME PORT BODY — a master-mode server whose on_master_auth is BODY.
case_server() {
    local name=$1 port=$2 body=$3
    local lua="$SOCKETLEY_TMPD/$name.lua"
    printf 'function on_master_auth(client_id, password)\n%s\nend\n' "$body" > "$lua"
    create_ok "$name created" "$BIN" create server "$name" -p "$port" \
        --mode master --lua "$lua" --daemon-process -s
}

case_server ma_string 21801 '    return "denied"'
case_server ma_zero   21802 '    return 0'
case_server ma_table  21803 '    return {}'
case_server ma_raise  21804 '    error("auth backend unreachable")'
case_server ma_true   21805 '    return true'
case_server ma_false  21806 '    return false'

sleep 0.5

# ── Control 1: a hook that says yes still grants ────────────────────────────
GOT_TRUE=$(ask 21805)
if [ "$GOT_TRUE" = "master: ok" ]; then pass; else
    fail "control: return true grants master" \
         "port 21805 answered '${GOT_TRUE:-<nothing>}', wanted 'master: ok'" \
         "every denial asserted below is also produced by a build where" \
         "on_master_auth never grants at all, so without this they prove nothing"
fi

# ── Control 2: a hook that says no denies ───────────────────────────────────
GOT_FALSE=$(ask 21806)
if [ "$GOT_FALSE" = "master: denied" ]; then pass; else
    fail "control: return false denies" \
         "port 21806 answered '${GOT_FALSE:-<nothing>}', wanted 'master: denied'"
fi

# ── The three truthy non-booleans ───────────────────────────────────────────
for spec in "ma_string:21801:a string" "ma_zero:21802:the number 0" \
            "ma_table:21803:an empty table"; do
    name=${spec%%:*}; rest=${spec#*:}; port=${rest%%:*}; what=${rest#*:}
    GOT=$(ask "$port")
    if [ "$GOT" = "master: denied" ]; then pass; else
        fail "on_master_auth returning $what does not grant master" \
             "$name on $port answered '${GOT:-<nothing>}', wanted 'master: denied'" \
             "lua_toboolean says every value but false and nil is true, so this" \
             "handed the master role to a script that returned anything at all —" \
             "and this hook overrides --master-pw, so it is the entire gate"
    fi
done

# ── A hook that raised denies, and says why ─────────────────────────────────
GOT_RAISE=$(ask 21804)
if [ "$GOT_RAISE" = "master: denied" ]; then pass; else
    fail "an on_master_auth that raises denies" \
         "ma_raise on 21804 answered '${GOT_RAISE:-<nothing>}', wanted 'master: denied'" \
         "an auth hook that could not run has not authenticated anybody"
fi

if grep -q 'on_master_auth error.*auth backend unreachable' "$SOCKETLEY_DLOG" 2>/dev/null
then pass; else
    fail "an on_master_auth that raises says so" \
         "the daemon log carries no on_master_auth error" \
         "the catch was \`catch (...) {}\` — a typo in an auth callback looked" \
         "exactly like an auth callback that had made a decision" \
         "last lines: $(tail -3 "$SOCKETLEY_DLOG" 2>/dev/null | tr '\n' '|')"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
