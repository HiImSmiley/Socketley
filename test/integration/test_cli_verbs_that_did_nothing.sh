#!/usr/bin/env bash
# Integration test: two CLI verbs that answered 0 and did nothing.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
#   `socketley NAME send MSG` -- the action form -- reached nobody.  It called
#   broadcast()/lua_send() on the PLACEHOLDER, and every CLI-created runtime is
#   one, so the connection table it broadcast into was empty.  Exit code 0, no
#   output, nothing delivered.  `socketley send NAME MSG` takes the same words
#   and goes through deliver_to_runtime() to the worker: two spellings of one
#   verb, and only one of them worked.
#
#   `socketley edit NAME -r` edited the file and reloaded the OLD script.  That
#   command is dump, editor, import, reload-lua -- the documented way to change
#   a runtime's Lua -- and import changes the script path on the placeholder.
#   The reload frame carried no payload, so the worker reloaded the path it was
#   spawned with.  The operator saw `show` reporting the new file and the
#   runtime running the old one.
#
# Both assertions are about what ARRIVED, never about the exit code: the exit
# code was 0 in both cases on the broken build, which is the whole complaint.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: CLI verbs that reported success and did nothing ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

PA=$((SL_PORT_BASE+1418))
PB=$((SL_PORT_BASE+1419))

daemon_isolate cliverbs
trap 'daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

# ── 1. The action form of send reaches the runtime's clients ───────────────
"$BIN" create server cv_s -p "$PA" --mode inout -s >/dev/null 2>&1
sleep 1.5

hold_and_read() {   # a client that is connected BEFORE the send and reports what came
    python3 -c "
import socket
s = socket.create_connection(('127.0.0.1', $PA), timeout=5); s.settimeout(4)
open('$SOCKETLEY_TMPD/ready', 'w').write('1')
try:    print('GOT:' + s.recv(64).decode().strip())
except Exception: print('GOT:<nothing>')
s.close()" > "$SOCKETLEY_TMPD/client.txt" 2>/dev/null &
    CLIENT_PID=$!
    : > "$SOCKETLEY_TMPD/ready"
    for _ in $(seq 1 40); do [ -s "$SOCKETLEY_TMPD/ready" ] && break; sleep 0.1; done
    sleep 0.3
}

hold_and_read
"$BIN" cv_s send ACTION-FORM >/dev/null 2>&1
ARC=$?
wait "$CLIENT_PID" 2>/dev/null
GOT=$(cat "$SOCKETLEY_TMPD/client.txt" 2>/dev/null)

if [ "$GOT" = "GOT:ACTION-FORM" ]; then
    ok "the action form delivered ($GOT, rc $ARC)"
else
    bad "socketley NAME send MSG reaches the runtime's clients" \
        "the client saw '${GOT:-<no output>}' and the command returned $ARC;" \
        "rc 0 with nothing delivered is the whole complaint -- the action form" \
        "broadcast into the placeholder's empty connection table while" \
        "\`socketley send NAME MSG\` went to the worker"
fi

# The other spelling still works, so a build that broke both would not pass the
# assertion above by having changed nothing.
hold_and_read
"$BIN" send cv_s PLAIN-FORM >/dev/null 2>&1
wait "$CLIENT_PID" 2>/dev/null
GOT2=$(cat "$SOCKETLEY_TMPD/client.txt" 2>/dev/null)
if [ "$GOT2" = "GOT:PLAIN-FORM" ]; then
    ok "and the spelling that always worked still does"
else
    bad "socketley send NAME MSG is unchanged" "the client saw '${GOT2:-<no output>}'"
fi

# ── 2. import + reload-lua runs the script that was imported ───────────────
cat > "$SOCKETLEY_TMPD/a.lua" <<'LUAEOF'
function on_client_message(id, msg) self.send(id, "SCRIPT-A") end
LUAEOF
cat > "$SOCKETLEY_TMPD/b.lua" <<'LUAEOF'
function on_client_message(id, msg) self.send(id, "SCRIPT-B") end
LUAEOF

"$BIN" create server cv_r -p "$PB" --lua "$SOCKETLEY_TMPD/a.lua" -s >/dev/null 2>&1
sleep 1.5
ask() {
    python3 -c "
import socket
try:
    s = socket.create_connection(('127.0.0.1', $PB), timeout=3)
    s.sendall(b'x\n'); print(s.recv(32).decode().strip()); s.close()
except Exception: print('ERR')" 2>/dev/null
}

BEFORE=$(ask)
if [ "$BEFORE" = "SCRIPT-A" ]; then ok "the runtime starts on the script it was given"
else bad "the runtime starts on the script it was given" "it answered '$BEFORE'"; fi

# The documented path, spelled out rather than shelled through `edit -r`, so
# the assertion is about the daemon and not about which editor is installed.
"$BIN" show cv_r 2>/dev/null \
    | sed "s#$SOCKETLEY_TMPD/a.lua#$SOCKETLEY_TMPD/b.lua#" \
    | "$BIN" import cv_r >/dev/null 2>&1
"$BIN" reload-lua cv_r >/dev/null 2>&1
RRC=$?
sleep 1
AFTER=$(ask)

if [ "$AFTER" = "SCRIPT-B" ]; then
    ok "import + reload-lua runs the imported script"
else
    bad "reload-lua reloads the script that was imported, not the one at spawn" \
        "the runtime answered '$AFTER' after the import, and reload-lua returned $RRC;" \
        "SCRIPT-A is the defect: import moves the path on the placeholder and the" \
        "reload frame carried no payload, so the worker reloaded the file it already had" \
        "-- which makes \`socketley edit NAME -r\` a documented way to edit nothing"
fi

for n in cv_s cv_r; do
    "$BIN" stop "$n" >/dev/null 2>&1; "$BIN" remove "$n" >/dev/null 2>&1
done
daemon_stop
trap - EXIT

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
