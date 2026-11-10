#!/usr/bin/env bash
# Integration test: --lua-ffi hands a runtime's script the ffi module, and nothing else does
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# The ffi module is opened in every state for socketley's own FFI calls and is
# kept out of package.loaded, so require("ffi") finds nothing: a wrong pointer
# through it ends the runtime's process where a Lua error would be caught, which
# is a cost the operator takes on by name.  What would be wrong and quiet: a
# script given the module without the flag, the flag lost on a daemon restart,
# or an edit that sets it and is never applied.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate luaffi

P1=$((SL_PORT_BASE+1971)); P2=$((SL_PORT_BASE+1972)); P3=$((SL_PORT_BASE+1973))
NAMES="ffi_no ffi_yes ffi_cli"
LUA="$SOCKETLEY_TMPD/probe.lua"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "expected '$2', got '$3'"; fi; }

cleanup() {
    for n in $NAMES; do "$BIN" stop "$n"   >/dev/null 2>&1 || true; done
    sleep 0.3
    for n in $NAMES; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: --lua-ffi ==="

# Each runtime says what require("ffi") gave it, with the name so the lines can be told apart.
cat > "$LUA" <<'LUAEOF'
local ok, ffi = pcall(require, "ffi")
if ok and ffi then
    ffi.cdef("int getpid(void);")
    socketley.log("FFI " .. self.name .. " yes " .. tostring(ffi.C.getpid() > 0))
else
    socketley.log("FFI " .. self.name .. " no")
end
LUAEOF

said() {   # name -> its last line, waited for
    local line=""
    for _ in $(seq 1 50); do
        line=$(grep -o "FFI $1 [a-z ]*" "$SOCKETLEY_DLOG" | tail -1) || true
        [ -n "$line" ] && break
        sleep 0.1
    done
    echo "$line"
}

daemon_start "$BIN"
create_ok "a server without the flag" "$BIN" create server ffi_no -p "$P1" --lua "$LUA" -s
create_ok "a server with it" "$BIN" create server ffi_yes -p "$P2" --lua "$LUA" --lua-ffi -s
create_ok "a client with it" "$BIN" create client ffi_cli -t "127.0.0.1:$P2" --lua "$LUA" --lua-ffi -s

check "without the flag require(\"ffi\") finds nothing" "FFI ffi_no no" "$(said ffi_no)"
check "with it the script has the module and calls into C" "FFI ffi_yes yes true" "$(said ffi_yes)"
check "a client's script too" "FFI ffi_cli yes true" "$(said ffi_cli)"

# Kept across a daemon restart, which restores the runtimes from their state files.
: > "$SOCKETLEY_DLOG"
kill "$SOCKETLEY_DPID" 2>/dev/null || true
wait "$SOCKETLEY_DPID" 2>/dev/null || true
daemon_start "$BIN"
check "the flag is kept across a daemon restart" "FFI ffi_yes yes true" "$(said ffi_yes)"
check "and its absence too" "FFI ffi_no no" "$(said ffi_no)"

# An edit takes effect when the script is next loaded, which a restart does, and a running runtime is told so.
OUT=$("$BIN" edit ffi_no --lua-ffi 2>&1) || true
check "edit on a running runtime sends it to restart" "--lua-ffi is given to the script when it starts: socketley restart ffi_no --lua-ffi" "$OUT"
"$BIN" restart ffi_no --lua-ffi >/dev/null 2>&1 || true
check "restart with --lua-ffi gives the script the module" "FFI ffi_no yes true" "$(said ffi_no)"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
