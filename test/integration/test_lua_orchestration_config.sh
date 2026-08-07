#!/usr/bin/env bash
# Integration test: `socketley --lua <file>`, the orchestration config.
#
# ─── WHAT THIS IS ABOUT ─────────────────────────────────────────────────────
#
# cli_config.cpp turns a `runtimes = { ... }` table into a series of create
# commands.  Nothing in this directory ran it — the CLI's own `--lua` is a
# different feature from a runtime's `--lua`, and only the second had tests —
# so nineteen reads of optional config fields went unexercised.
#
# Every one of them was written as
#
#     sol::optional<T> x = t["field"];
#
# which does not mean "if present".  sol2's safety checks follow NDEBUG, so
# they are on in every Debug and Sanitize build; with them on, reading a key
# that is absent throws, and the throw unwinds out of a Lua C boundary into
# std::terminate.  Measured, on a config whose second entry omits `mode`,
# `start` and `log`:
#
#     Release   ->  rc 0, both runtimes created
#     Sanitize  ->  rc 134, "terminate called without an active exception"
#
# A config file that works for a developer and aborts under the sanitizer is
# also a config file one field away from aborting in Release, since the
# unchecked read is only accidentally survivable.
#
# ─── WHY THE SECOND ENTRY MATTERS ───────────────────────────────────────────
#
# It is the assertion, not filler.  A config where every entry sets every field
# never reads an absent key and passes against the defect.  The minimal entry
# omits everything optional, which is what an operator writes first and what
# every example in examples/lua-config/ shows.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"

daemon_isolate orchcfg

PB=${SOCKETLEY_PORT_BASE:-21920}
FULL_PORT=$((PB + 0))
MIN_PORT=$((PB + 1))

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    "$BIN" stop  orch_full orch_min 2>/dev/null || true
    sleep 0.3
    "$BIN" remove orch_full orch_min 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: socketley --lua, the orchestration config ==="

daemon_start "$BIN"

ORCH="$SOCKETLEY_TMPD/orch.lua"
cat > "$ORCH" <<LUAEOF
daemon = { name = "orchcfgtest" }
runtimes = {
    -- Every optional field set.
    {
        type = "server", name = "orch_full", port = $FULL_PORT,
        mode = "in", start = true, log = "$SOCKETLEY_TMPD/full.log",
    },
    -- Nothing optional set at all.  This entry is the assertion: it is what
    -- every example writes, and it is the one that reads absent keys.
    {
        type = "server", name = "orch_min", port = $MIN_PORT,
    },
}
LUAEOF

RC=0
OUT=$("$BIN" --lua "$ORCH" 2>&1) || RC=$?

# ── The command completes rather than aborting ──────────────────────────────
#
# 134 is SIGABRT, which is what the unchecked read produced. Asserted by name
# because "non-zero" would also accept an honest refusal, and those are
# different findings.
if [ "$RC" = "0" ]; then pass; else
    fail "the orchestration config is applied" \
         "socketley --lua exited $RC, wanted 0" \
         "134 is SIGABRT — an absent optional key throwing out of a Lua C" \
         "boundary and landing in std::terminate" \
         "it said: ${OUT:-<nothing>}"
fi

state() { "$BIN" ls 2>/dev/null | awk -v n="$1" '$2 == n { print tolower($7) }' | head -1; }
listed() { "$BIN" ls 2>/dev/null | awk -v n="$1" '$2 == n { print $2 }' | head -1; }

# ── Both runtimes exist ─────────────────────────────────────────────────────
if [ "$(listed orch_full)" = "orch_full" ]; then pass; else
    fail "the fully-specified entry was created" "not in ls"
fi
if [ "$(listed orch_min)" = "orch_min" ]; then pass; else
    fail "the minimal entry was created" \
         "not in ls — this is the entry that reads absent optional keys"
fi

# ── start = true is honoured, and its absence is not ────────────────────────
#
# The pair is the point: one entry asked to be started and one did not, so a
# build that started everything or nothing fails one of them.
FULL_STATE=$(state orch_full)
if [ "$FULL_STATE" = "up" ] || [ "$FULL_STATE" = "running" ]; then pass; else
    fail "start = true started the runtime" \
         "orch_full is '${FULL_STATE:-<absent>}', wanted to be up"
fi

MIN_STATE=$(state orch_min)
if [ "$MIN_STATE" = "created" ] || [ "$MIN_STATE" = "stopped" ]; then pass; else
    fail "an entry with no start field is not started" \
         "orch_min is '${MIN_STATE:-<absent>}', wanted created" \
         "if this says up, 'start = true' is not being read at all and the" \
         "assertion above passes for the wrong reason"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
