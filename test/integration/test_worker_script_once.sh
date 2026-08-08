#!/usr/bin/env bash
# Integration test: an out-of-process proxy runs its Lua script's top level once.
#
# ─── WHAT A "PLACEHOLDER" IS FOR, AND WHAT IT IS NOT FOR ────────────────────
#
# A proxy created with exists twice: as the worker process that
# owns the listening socket and serves every byte, and as a placeholder inside
# the daemon that holds its name, port, group and state so that `ls`, `stats`
# and the endpoint table have something to answer with.
#
# The placeholder used to load the script as well.  Everything a Lua chunk does
# at its top level therefore happened twice -- and the two copies do not even do
# the same thing, because the daemon's copy holds the runtime manager and the
# worker's does not.  A script whose top level called socketley.create() created
# a runtime FROM THE PLACEHOLDER, in the daemon, while the same line in the
# worker was refused.  That is the inverse of the intended asymmetry.
#
# ─── WHY THE ORACLE IS A FILE AND NOT A LOG LINE ────────────────────────────
#
# The obvious probe -- "the script printed something twice" -- cannot separate
# the two copies: they share the daemon's stdout, one of them through a pipe,
# and a duplicate line is indistinguishable from a line the log repeated.  A
# file appended to by the top level counts executions with no ambiguity about
# who wrote them, and `wc -l` is the whole assertion.
#
# The second oracle is sharper still and is the one that shows the cost.  A
# top-level socketley.create() succeeds only where a runtime manager exists,
# which is the daemon.  So if the placeholder ran the script, a runtime nobody
# asked for appears in `ls` -- and that is a side effect the operator never
# wrote a command for.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
# shellcheck source=lib_daemon.sh
. "$(dirname "$0")/lib_daemon.sh"
# shellcheck source=lib_create.sh
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

echo "=== Integration: an out-of-process proxy loads its script once ==="

PASS=0; FAIL=0; TOTAL=0

ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
        echo "  FAIL [$1]: $2"; }
assert_eq() {
    if [ "$1" = "$2" ]; then ok; else bad "$3" "got '$1', wanted '$2'"; fi
}

daemon_isolate wkscript
trap 'daemon_stop; rm -rf "$SOCKETLEY_TMPD"' EXIT

MARK="$SOCKETLEY_TMPD/toplevel.count"
: > "$MARK"

# The top level appends one line per execution and, separately, asks for a
# runtime.  The create is the part that can only succeed inside the daemon.
cat > "$SOCKETLEY_TMPD/s.lua" <<EOF
local f = io.open("$MARK", "a")
f:write("ran\n")
f:close()
pcall(function() socketley.create("server", "ghost_from_toplevel", $((SL_PORT_BASE+1488))) end)
EOF

daemon_start "$BIN"

BE_PORT=$((SL_PORT_BASE+8499))
PROXY_PORT=$((SL_PORT_BASE+8487))

# ── the control: an in-process proxy, which must run its script exactly once ──
create_ok "in-process proxy created" \
    "$BIN" create proxy inproc -p "$PROXY_PORT" --backend "127.0.0.1:$BE_PORT" \
    --lua "$SOCKETLEY_TMPD/s.lua" -s
sleep 1
IN_RUNS=$(wc -l < "$MARK")
assert_eq "$IN_RUNS" "1" "in-process: the top level runs once"
"$BIN" remove inproc >/dev/null 2>&1
"$BIN" remove ghost_from_toplevel >/dev/null 2>&1
sleep 0.3

# ── the subject ──────────────────────────────────────────────────────────────
: > "$MARK"
create_ok "out-of-process proxy created" \
    "$BIN" create proxy oop -p $((PROXY_PORT+1)) --backend "127.0.0.1:$BE_PORT" \
    --lua "$SOCKETLEY_TMPD/s.lua" -s
sleep 2

OOP_RUNS=$(wc -l < "$MARK")
assert_eq "$OOP_RUNS" "1" "out-of-process: the top level runs once, not twice"

# The runtime the placeholder would have created if it had run the script.  The
# worker cannot create it -- 294f927 refuses cross-runtime calls there -- so any
# appearance of this name means the daemon ran the top level.
GHOST=$("$BIN" ls 2>/dev/null | grep -c "ghost_from_toplevel" || true)
assert_eq "$GHOST" "0" "no runtime is created from inside the daemon's placeholder"

# The proxy itself still works: this is a placeholder that stopped running a
# script, not a proxy that stopped being configured.
# `ls` prints a STATUS column; "Up ..." is the running state.  Read it rather
# than `stats`, which has no state field at all.
STATE=$("$BIN" ls 2>/dev/null | awk '$2=="oop"{print $7}' | head -1)
assert_eq "$STATE" "Up" "the out-of-process proxy is up"

# And it is still the worker that serves, so the figures still say `pushed`.
FIG=$("$BIN" stats oop 2>/dev/null | sed -n 's/^figures:\(.*\)$/\1/p' | head -1)
assert_eq "$FIG" "pushed" "its figures still come from the worker"

"$BIN" remove oop >/dev/null 2>&1
"$BIN" remove ghost_from_toplevel >/dev/null 2>&1

# ── a script that cannot compile is still refused at create time ─────────────
# Not running the top level must not mean not looking at the file: a syntax
# error is the one thing `create` could always tell an operator immediately,
# and moving that report to "the worker exited, the runtime is failed" would be
# a worse message for a mistake that is usually a typo.
cat > "$SOCKETLEY_TMPD/broken.lua" <<'EOF'
this is not lua (
EOF
OUT=$("$BIN" create proxy broken -p $((PROXY_PORT+2)) --backend "127.0.0.1:$BE_PORT" \
      --lua "$SOCKETLEY_TMPD/broken.lua" -s 2>&1) || true
case "$OUT" in
    *"Lua"*|*"lua"*) ok ;;
    *) bad "a script that cannot compile is refused at create" "said: '$OUT'" ;;
esac
LEFT=$("$BIN" ls 2>/dev/null | grep -c "broken" || true)
assert_eq "$LEFT" "0" "the refused proxy is not left behind"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
