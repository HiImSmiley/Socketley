#!/usr/bin/env bash
# Integration test: reload-lua keeps the previous script when the new one will
# not compile, and genuinely replaces it when it will.
#
# ─── WHAT THIS PINS ─────────────────────────────────────────────────────────
#
# reload_lua_script() used to reset the interpreter and then load into the empty
# slot.  A file that no longer compiled therefore did not leave the previous one
# in force — it left NOTHING: every callback stopped firing, the runtime went on
# accepting traffic, and reload-lua reported success.  Two places in the tree
# state the contract that broke (proxy_worker's reload warning, and
# cmd_reload_lua reading the route declaration back afterwards on the strength
# of it), so it was written down twice and kept nowhere.  be1c057 builds the
# replacement first and swaps only on success.
#
# ─── WHY THE COUNTER ────────────────────────────────────────────────────────
#
# The script counts the messages it has seen and logs the running total.  That
# one detail is what makes every assertion here able to fail:
#
#   * After a refused reload the count must CONTINUE (…3 then 4).  "A callback
#     still fired" would also be satisfied by a build that quietly reloaded the
#     last good file into a fresh interpreter — which is a different behaviour
#     with a different bug in it, and a bare did-it-fire check cannot see the
#     difference.  A continuing count means the same interpreter, which is what
#     "the previous one is still in force" actually claims.
#   * After an accepted reload the count must RESTART (…4 then 1).  Without it,
#     "the new tag appeared" is satisfied by a build that loads the new file's
#     callbacks into the old state — and a reload that keeps a script's state
#     alive across an edit is a different promise from the one made here.
#
# The pair is deliberate: an assertion that only says "unchanged afterwards"
# stays green when the operation does nothing at all.
#
# ─── BOTH SIDES OF THE BOUNDARY ─────────────────────────────────────────────
#
# The same sequence runs against a runtime in the daemon and one in a worker.
# The defect was not boundary-specific — the same function serves both — but the
# worker is where reload-lua prints the claim, and a fix that held in one
# process and not the other would pass a file that only looked at one.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_create.sh"

daemon_isolate luareload

PB=${SOCKETLEY_PORT_BASE:-19120}
IN_PORT=$((PB + 0))     # the runtime in the daemon
OOP_PORT=$((PB + 1))    # the runtime in a worker

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}
assert_eq() {
    local label=$1 want=$2 got=$3; shift 3
    if [ "$got" = "$want" ]; then pass; else
        fail "$label" "got '$got', wanted '$want'" "$@"
    fi
}

cleanup() {
    "$BIN" stop  rl_in rl_oop 2>/dev/null || true
    sleep 0.3
    "$BIN" remove rl_in rl_oop 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: reload-lua keeps a script it cannot replace ==="

daemon_start "$BIN"

IN_LUA="$SOCKETLEY_TMPD/in.lua"
OOP_LUA="$SOCKETLEY_TMPD/oop.lua"

# write_script FILE TAG — a script that counts what it has seen and says so.
write_script() {
    cat > "$1" <<LUAEOF
local seen = 0
function on_client_message(id, msg)
    seen = seen + 1
    socketley.log("RL $2 n=" .. tostring(seen))
end
LUAEOF
}
# write_broken FILE — parses nowhere: one closing paren short, which is the edit
# the defect was measured with.
write_broken() {
    cat > "$1" <<'LUAEOF'
function on_client_message(id, msg)
    socketley.log("RL BROKEN"
end
LUAEOF
}

# poke PORT — one line, then close.
poke() { printf 'ping\n' | timeout 5 nc -q 1 127.0.0.1 "$1" >/dev/null 2>&1 || true; }

# last_line TAG — the last "RL <TAG> n=<k>" the log carries, or empty.
last_line() {
    { grep -aoE "RL $1 n=[0-9]+" "$SOCKETLEY_DLOG" 2>/dev/null || true; } | tail -1
}
# await LINE — wait for one exact line to appear.  A reload is asynchronous for a
# worker, so this is a wait rather than a sleep-and-look.
await() {
    local want=$1 deadline=$(( $(date +%s) + ${2:-8} ))
    while [ "$(date +%s)" -le "$deadline" ]; do
        grep -qaF "$want" "$SOCKETLEY_DLOG" 2>/dev/null && return 0
        sleep 0.05
    done
    return 1
}

# Each case gets markers of its own.  Both runtimes log to the same file — the
# worker inherits the daemon's stderr — so a shared V1/V2 would make "the last
# V1 line" mean whichever runtime spoke most recently.
write_script "$IN_LUA"  IN-V1
write_script "$OOP_LUA" OOP-V1

create_ok "in-daemon runtime created with a script" "$BIN" create server rl_in \
    -p "$IN_PORT" --mode in --lua "$IN_LUA" --daemon-process -s
create_ok "worker-backed runtime created with a script" "$BIN" create server rl_oop \
    -p "$OOP_PORT" --mode in --lua "$OOP_LUA" -s
ready_tcp 127.0.0.1 "$IN_PORT" 8  || echo "  NOTE: rl_in never accepted"
ready_tcp 127.0.0.1 "$OOP_PORT" 8 || echo "  NOTE: rl_oop never accepted"

# run_case NAME PORT SCRIPT WHERE TAG — the whole sequence against one runtime.
run_case() {
    local name=$1 port=$2 script=$3 where=$4 tag=$5

    # ── the script is running at all ────────────────────────────────────────
    poke "$port"
    await "RL $tag-V1 n=1" 8 || true
    assert_eq "control: $where the script runs before any reload" \
              "RL $tag-V1 n=1" "$(last_line "$tag-V1")" \
              "every assertion below is about what a reload does to a running" \
              "script; if none was running they are all vacuous"
    poke "$port"; await "RL $tag-V1 n=2" 8 || true
    poke "$port"; await "RL $tag-V1 n=3" 8 || true
    assert_eq "control: $where the count follows the traffic" \
              "RL $tag-V1 n=3" "$(last_line "$tag-V1")"

    # ── a reload that cannot compile ────────────────────────────────────────
    write_broken "$script"
    "$BIN" reload-lua "$name" >/dev/null 2>&1 || true
    sleep 0.6

    poke "$port"
    await "RL $tag-V1 n=4" 8 || true
    assert_eq "$where a reload that will not compile leaves the old script running" \
              "RL $tag-V1 n=4" "$(last_line "$tag-V1")" \
              "the reload reset the interpreter and then failed to fill it, so" \
              "the runtime went on taking traffic with no script at all — and" \
              "reload-lua reported success.  n=4 rather than merely 'a line'" \
              "is what says it is the SAME interpreter and not a fresh one" \
              "loaded from the last good file"

    # ── a reload that can ───────────────────────────────────────────────────
    write_script "$script" "$tag-V2"
    "$BIN" reload-lua "$name" >/dev/null 2>&1 || true
    sleep 0.6

    poke "$port"
    await "RL $tag-V2 n=1" 8 || true
    assert_eq "$where a reload that compiles swaps the script and resets its state" \
              "RL $tag-V2 n=1" "$(last_line "$tag-V2")" \
              "the new file's tag proves the swap; n=1 rather than n=5 proves" \
              "the state went with it, which is what a new interpreter means"
}

run_case rl_in  "$IN_PORT"  "$IN_LUA"  "in the daemon," IN
run_case rl_oop "$OOP_PORT" "$OOP_LUA" "in a worker,"   OOP

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
