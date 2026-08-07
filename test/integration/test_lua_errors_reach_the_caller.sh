#!/usr/bin/env bash
# Integration test: a Lua script that will not load says why, on the terminal
# that asked it to.
#
# ─── WHAT THIS IS ABOUT ─────────────────────────────────────────────────────
#
# daemon_handler borrows std::cout for the length of a command and hands back
# whatever was printed as the CLI's reply.  std::cerr is not borrowed — it
# cannot be, the metrics endpoint has a thread of its own and logs there — and
# every Lua diagnostic in the tree is written to cerr.  So the reasons went to
# the daemon's log and the operator got a sentence with no content in it:
#
#     $ socketley create server s1 -p 21810 --lua broken.lua -s
#     could not load Lua script
#     $ echo $?
#     1
#
# while the daemon's log, one process away and not usually open, held
#
#     [lua] script error: broken.lua:3: ')' expected (to close '(' at line 2)
#
# The validators are worse, because they were written as sentences addressed to
# the person editing the file — "a chain is an ordered array, not a keyed
# table", "`path` must start with '/'" — and every one of them was dropped.
#
# `reload-lua` had the other half of it: the return value of reload_lua_script()
# was discarded, so a script that no longer compiled was reported as success
# with an empty reply and exit 0.  For a runtime in a worker there was no reply
# frame at all.
#
# ─── THE CONTROLS ───────────────────────────────────────────────────────────
#
# Three, and they are what stop this file from passing against a build that
# simply prints something on every command:
#
#   * A script that loads must stay silent and exit 0.  Silence is golden is a
#     rule here, and "the reason now reaches the caller" must not become "every
#     create prints a paragraph".
#   * A reload that works must stay silent and exit 0.
#   * The daemon's log must STILL carry the reason.  This is a tee, not a
#     redirect: an operator reading the log afterwards has not lost anything.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"

daemon_isolate luaerrreport

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

NAMES="ok_srv rl_srv rl_be rl_wrk"

cleanup() {
    # shellcheck disable=SC2086
    "$BIN" stop $NAMES 2>/dev/null || true
    sleep 0.3
    # shellcheck disable=SC2086
    "$BIN" remove $NAMES 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a Lua load failure names its reason to the caller ==="

daemon_start "$BIN"

BROKEN="$SOCKETLEY_TMPD/broken.lua"
KEYED="$SOCKETLEY_TMPD/keyed.lua"
BADROUTE="$SOCKETLEY_TMPD/badroute.lua"
printf 'function on_message(m)\n  print(m\nend\n'                > "$BROKEN"
printf 'filters = { auth = function(req) end }\n'                > "$KEYED"
printf 'routes = { { path = "noslash", methods = { "GET" } } }\n' > "$BADROUTE"

# refuse LABEL PORT SCRIPT NEEDLE — a create that must be refused, exit 1, and
# whose CLI output must carry NEEDLE.
#
# Exit 1 specifically, not merely non-zero: 2 is the fatal code and "unknown
# flag" is a refusal too, so an oracle that took any failure would pass against
# a build that refused for a reason with nothing to do with the script.
refuse() {
    local label=$1 port=$2 script=$3 needle=$4 rc=0 out
    out=$("$BIN" create server "sl_$label" -p "$port" --lua "$script" \
              --daemon-process -s 2>&1) || rc=$?
    "$BIN" remove "sl_$label" >/dev/null 2>&1 || true

    if [ "$rc" = "1" ]; then pass; else
        fail "create is refused for $label" \
             "create exited $rc, wanted 1" \
             "create said: ${out:-<nothing>}"
    fi
    case "$out" in
        *"$needle"*) pass ;;
        *) fail "the refusal for $label names the reason" \
                "wanted the reply to carry: $needle" \
                "the CLI said: ${out:-<nothing>}" \
                "the reason exists — it is in the daemon's log — but it was" \
                "written to stderr, and the reply channel is cout" ;;
    esac
}

# ── The script that does not parse ──────────────────────────────────────────
refuse parse 21810 "$BROKEN" "')' expected"

# ── The two declaration validators ──────────────────────────────────────────
refuse keyedfilters 21811 "$KEYED"    "an ordered array, not a keyed table"
refuse badroute     21812 "$BADROUTE" "must start with '/'"

# ── Control 3: the log still has it ─────────────────────────────────────────
#
# Asserted before the reload cases so it is about the creates above, whose
# reasons are known exactly.
if grep -q "an ordered array, not a keyed table" "$SOCKETLEY_DLOG" 2>/dev/null
then pass; else
    fail "control: the daemon's log still carries the reason" \
         "no validator line in $SOCKETLEY_DLOG" \
         "this is meant to be a tee, not a redirect — an operator reading the" \
         "log has not lost anything by the CLI gaining it"
fi

# ── Control 1: a script that loads is silent and succeeds ───────────────────
GOOD="$SOCKETLEY_TMPD/good.lua"
printf 'function on_message(m) end\n' > "$GOOD"

OK_RC=0
OK_OUT=$("$BIN" create server ok_srv -p 21813 --lua "$GOOD" --daemon-process -s 2>&1) || OK_RC=$?
if [ "$OK_RC" = "0" ] && [ -z "$OK_OUT" ]; then pass; else
    fail "control: a script that loads says nothing and exits 0" \
         "create exited $OK_RC and said '${OK_OUT:-<nothing>}'" \
         "silence is golden — the reason reaching the caller must not turn" \
         "into every create printing a paragraph"
fi

# ── reload-lua, for a runtime in the daemon ─────────────────────────────────
RL="$SOCKETLEY_TMPD/reload.lua"
printf 'function on_message(m) end\n' > "$RL"
create_ok "reload subject created" "$BIN" create server rl_srv -p 21814 \
    --lua "$RL" --daemon-process -s

# Control 2: a reload that works is silent and succeeds.
RLOK_RC=0
RLOK_OUT=$("$BIN" reload-lua rl_srv 2>&1) || RLOK_RC=$?
if [ "$RLOK_RC" = "0" ] && [ -z "$RLOK_OUT" ]; then pass; else
    fail "control: a reload that works says nothing and exits 0" \
         "reload-lua exited $RLOK_RC and said '${RLOK_OUT:-<nothing>}'"
fi

printf 'function on_message(m)\n  print(m\nend\n' > "$RL"
RLBAD_RC=0
RLBAD_OUT=$("$BIN" reload-lua rl_srv 2>&1) || RLBAD_RC=$?
if [ "$RLBAD_RC" = "1" ]; then pass; else
    fail "reload-lua reports a script that would not load" \
         "reload-lua exited $RLBAD_RC, wanted 1" \
         "the bool from reload_lua_script() was discarded, so the command" \
         "returned 0 with an empty reply for a reload that did not happen" \
         "reload-lua said: ${RLBAD_OUT:-<nothing>}"
fi
case "$RLBAD_OUT" in
    *rl_srv*"')' expected"*) pass ;;
    *) fail "the reload refusal names the runtime and the reason" \
            "wanted the reply to carry 'rl_srv' and \"')' expected\"" \
            "reload-lua said: ${RLBAD_OUT:-<nothing>}" ;;
esac

# ── reload-lua, for a runtime in a worker ───────────────────────────────────
#
# The other half, and the one be1c057 left open by name: the daemon's copy of an
# out-of-process runtime is a placeholder, the script belongs to the worker, and
# the worker had no frame in which to say the reload had failed.  It logged a
# WARN and the command still exited 0.
WRL="$SOCKETLEY_TMPD/wreload.lua"
printf 'function on_message(m) end\n' > "$WRL"
create_ok "worker backend created" "$BIN" create server rl_be -p 21815 -s
create_ok "worker-backed proxy created" "$BIN" create proxy rl_wrk -p 21816 \
    --backend "127.0.0.1:21815" --protocol http --lua "$WRL" -s
sleep 1

printf 'function on_message(m)\n  print(m\nend\n' > "$WRL"
WRL_RC=0
WRL_OUT=$("$BIN" reload-lua rl_wrk 2>&1) || WRL_RC=$?
if [ "$WRL_RC" = "1" ]; then pass; else
    fail "reload-lua reports a worker's script that would not load" \
         "reload-lua exited $WRL_RC, wanted 1" \
         "the worker logged 'the previous one is still in force' and the" \
         "command that asked for the reload reported success" \
         "reload-lua said: ${WRL_OUT:-<nothing>}"
fi
case "$WRL_OUT" in
    *rl_wrk*"')' expected"*) pass ;;
    *) fail "the worker's reload refusal names the runtime and the reason" \
            "wanted the reply to carry 'rl_wrk' and \"')' expected\"" \
            "reload-lua said: ${WRL_OUT:-<nothing>}" ;;
esac

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
