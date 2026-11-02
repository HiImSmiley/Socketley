#!/usr/bin/env bash
# Integration test: reload-lua spends one deadline for the command, not one per
# runtime the pattern names.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
# `reload-lua` takes a PATTERN, and its route-declaration wait handed every
# runtime that pattern matched its own two-second bound:
#
#     for (auto& [sup, prev, name] : pending)
#         sup->await_routes(prev, worker_startup_bound);      // a bound EACH
#
# await_routes() computes its deadline from now, so the bound was per call.  It
# is a ::poll inside a command handler, which is to say the whole daemon is
# blocked for the duration: N runtimes with a wedged worker blocked it N x 2 s.
#
# Measured on 04ceac98 with the workers SIGSTOPped -- exactly linear, until the
# CLI's own five-second read deadline cut in:
#
#     1 runtime   2.01s rc=0        3 runtimes  5.25s rc=2
#     2 runtimes  4.01s rc=0        4 runtimes  5.19s rc=2
#
# A hundred lines above in the same file, the restart loop shares one deadline
# across its children with the reason written beside it: "sharing one deadline
# so a wedged child cannot multiply the bound."  Same file, same hazard,
# opposite discipline.
#
# ─── HOW IT IS ASSERTED ────────────────────────────────────────────────────
#
# SIGSTOP is the wedge because it is the one that cannot be argued with: the
# child is alive, its control socket is open, and it will never answer.  The
# threshold is coarse on purpose -- what matters is that the number does not
# grow with N, and 3.5 s sits between "one bound" (~2 s) and "a bound each"
# (>= 8 s at four runtimes) with room on both sides.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: reload-lua waits once for the command ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

N=4
STOPPED=""
daemon_isolate reloaddeadline
trap 'for p in ${STOPPED:-}; do kill -CONT "$p" 2>/dev/null; done
      daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

cat > "$SOCKETLEY_TMPD/s.lua" <<'LUAEOF'
function on_client_message(id, msg) self.send(id, msg) end
LUAEOF

for i in $(seq 1 "$N"); do
    "$BIN" create server "rd$i" -p $((SL_PORT_BASE + 1484 + i)) \
        --lua "$SOCKETLEY_TMPD/s.lua" -s >/dev/null 2>&1
done
sleep 2.5

UP=0
for i in $(seq 1 "$N"); do
    p=$("$BIN" stats "rd$i" 2>/dev/null | awk -F: '$1=="pid"{print $2;exit}')
    [ -n "$p" ] && [ "$p" != "0" ] && { UP=$((UP+1)); STOPPED="$STOPPED $p"; }
done
if [ "$UP" -eq "$N" ]; then
    ok "$N runtimes each have a worker to wedge"
else
    bad "the setup put $N workers up" \
        "only $UP of $N reported a pid; with nothing to wedge the timing below is meaningless"
fi

secs() { python3 -c "print(f'{$2 - $1:.2f}')"; }

# Warm first, so the frozen number is about the WAIT and not about reloading.
S=$(mono_s); "$BIN" reload-lua '*' >/dev/null 2>&1; E=$(mono_s)
WARM=$(secs "$S" "$E")
if python3 -c "import sys; sys.exit(0 if $WARM < 1.0 else 1)"; then
    ok "a reload with every worker answering costs nothing (${WARM}s)"
else
    bad "the bound is a bound and not a cost" \
        "a warm reload-lua of $N runtimes took ${WARM}s;" \
        "if a healthy reload already waits, the frozen reading below is not about wedging"
fi

for p in $STOPPED; do kill -STOP "$p" 2>/dev/null; done
S=$(mono_s); OUT=$("$BIN" reload-lua '*' 2>&1); RC=$?; E=$(mono_s)
FROZEN=$(secs "$S" "$E")
for p in $STOPPED; do kill -CONT "$p" 2>/dev/null; done
STOPPED=""

if python3 -c "import sys; sys.exit(0 if $FROZEN < 3.5 else 1)"; then
    ok "$N wedged workers cost one deadline, not $N (${FROZEN}s)"
else
    bad "reload-lua spends one deadline for the command" \
        "it took ${FROZEN}s for $N wedged runtimes, warm ${WARM}s, rc $RC;" \
        "2 s x $N is the defect -- await_routes() takes a BOUND and computes its own" \
        "deadline from now, so every name the pattern matched added two seconds of a" \
        "daemon that answers nothing at all.  Its output was: ${OUT:-<none>}"
fi

# The runtimes survive being frozen and thawed, so a build that passed the line
# above by giving up on them would not pass this one.
sleep 2
ALIVE=$("$BIN" ls 2>/dev/null | awk '$2 ~ /^rd[0-9]$/ && $7 == "Up"' | wc -l)
if [ "$ALIVE" -eq "$N" ]; then
    ok "and all $N are still running afterwards"
else
    bad "wedging and thawing leaves the runtimes up" "$ALIVE of $N read Up"
fi

for i in $(seq 1 "$N"); do
    "$BIN" stop "rd$i" >/dev/null 2>&1; "$BIN" remove "rd$i" >/dev/null 2>&1
done
daemon_stop
trap - EXIT

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
