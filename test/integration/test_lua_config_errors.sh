#!/usr/bin/env bash
# Integration test: `socketley --lua <config>` reports what the daemon said.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# Every create in cli_config was sent with `if (ipc_send(...) < 0)`, which asks
# only whether the socket answered.  The exit code and the daemon's sentence
# were both dropped, the loop went on, and the function returned 0.  A config
# file whose every runtime failed reported success and printed nothing:
#
#     $ socketley --lua badconf.lua ; echo $?
#     0                                     <- silence
#
#     $ socketley create server conf_a -p 18703 --lua /nonexistent/x.lua -s
#     could not load Lua script: /nonexistent/x.lua
#     script error: cannot open /nonexistent/x.lua: No such file or directory
#     1
#
# Same daemon, same refusal, same two lines written — and only one of the two
# callers read them.
#
# The failure is collected rather than returned at the first one: a config file
# is a set of runtimes and the ones that came up are worth having.  Both halves
# are asserted, because "it exits 1" alone would pass on a build that gave up
# at the first entry.

set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate luaconf
PASS=0; FAIL=0; TOTAL=0

WORK="/tmp/test-luaconf-$$"
cleanup() { rm -rf "$WORK"; daemon_stop; }
trap cleanup EXIT

pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

echo "=== Integration: --lua config reports refusals ==="

mkdir -p "$WORK"
daemon_start "$BIN"
P=$((SL_PORT_BASE + 900))

# ─── Control first: a config that is fine stays silent and exits 0 ──────────
#
# This project's convention is that success prints nothing, and every assertion
# below is only meaningful if that still holds.
cat > "$WORK/good.lua" <<EOF
runtimes = {
  { type = "server", name = "lc_ok1", port = $((P + 1)) },
  { type = "server", name = "lc_ok2", port = $((P + 2)) },
}
EOF
RC=0
OUT=$("$BIN" --lua "$WORK/good.lua" 2>&1) || RC=$?
if [ "$RC" -eq 0 ]; then pass
else fail "a good config exits 0" "exit $RC, said: ${OUT:-<nothing>}"; fi
if [ -z "$OUT" ]; then pass
else fail "a good config stays silent" "said: $OUT"; fi
if [ -n "$("$BIN" ls --name 2>/dev/null | grep -x lc_ok1 || true)" ]; then pass
else fail "the good config actually created its runtimes" "lc_ok1 is missing"; fi

# ─── A config with one entry the daemon refuses ─────────────────────────────
cat > "$WORK/bad.lua" <<EOF
runtimes = {
  { type = "server", name = "lc_a", port = $((P + 10)) },
  { type = "server", name = "lc_bad", port = $((P + 11)),
    lua = "/nonexistent/definitely-not-here.lua", start = true },
  { type = "server", name = "lc_c", port = $((P + 12)) },
}
EOF
RC=0
OUT=$("$BIN" --lua "$WORK/bad.lua" 2>&1) || RC=$?

if [ "$RC" -ne 0 ]; then pass
else fail "a config with a refused runtime exits non-zero" \
          "exit 0 — the daemon refused an entry and nobody read the answer"; fi

if grep -q "lc_bad" <<<"$OUT"; then pass
else fail "the refused runtime is named" "said: ${OUT:-<nothing>}"; fi

# The daemon's own diagnosis, not just "something failed".  This is the whole
# point: the sentence existed and was thrown away.
if grep -q "definitely-not-here.lua" <<<"$OUT"; then pass
else fail "the daemon's reason reaches the operator" \
          "the message does not mention the script that could not be loaded" \
          "said: ${OUT:-<nothing>}"; fi

# ─── The other half: the good entries still came up ─────────────────────────
#
# Without this a build that stopped at the first refusal would pass everything
# above, and a config file is a set rather than a sequence.
if [ -n "$("$BIN" ls --name 2>/dev/null | grep -x lc_c || true)" ]; then pass
else fail "entries after the refused one are still applied" \
          "lc_c was never created, so the loop gave up at lc_bad"; fi

# ─── An entry with no name at all ───────────────────────────────────────────
#
# type and name used to be read as plain std::string.  sol2's safety checks
# follow NDEBUG, so in Release they do not throw — they convert whatever is
# there, which is undefined behaviour in the build everybody runs.
cat > "$WORK/noname.lua" <<EOF
runtimes = {
  { type = "server", port = $((P + 20)) },
}
EOF
RC=0
OUT=$("$BIN" --lua "$WORK/noname.lua" 2>&1) || RC=$?
if [ "$RC" -ne 0 ]; then pass
else fail "an entry with no name is refused" "exit 0 for a nameless entry"; fi
if grep -qi "name" <<<"$OUT"; then pass
else fail "the refusal says the name is missing" "said: ${OUT:-<nothing>}"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
if [ "$FAIL" -eq 0 ]; then echo "  OK"; else echo "  FAILED"; fi
exit "$FAIL"
