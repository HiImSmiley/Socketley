#!/usr/bin/env bash
# Integration test: what `edit` on a RUNNING runtime actually does.
#
# ─── WHY THIS PINS A LIMITATION RATHER THAN A FIX ──────────────────────────
#
# A runtime lives in its own process, and that process reads its configuration
# exactly once --- proxy_supervisor writes the config frame in spawn(), and
# worker_main's on_config() refuses a second one outright, with the reason
# beside it: "A second config for a proxy that is already up would have to
# rebuild it, and the daemon does not send one."
#
# So `socketley edit api --max-connections 1` on a running runtime writes the
# placeholder and the state file, answers 0, and `show` reports the new value
# --- while the worker holding the port goes on enforcing the old one.  Nothing
# said so.  Measured, four connections against --max-connections 10 edited down
# to 1:
#
#     before the edit            4 of 4 stayed open
#     after  edit ... 1, rc 0    4 of 4 stayed open   <- show already said 1
#     after  restart             1 of 4 stayed open
#
# The manual made that worse rather than merely omitting it: it gave "take
# effect at the runtime's next start" as the TLS flags' EXCEPTION, which reads
# as a promise that the others do not wait.  Both it and --help now state the
# general rule, and this file is what holds them to it.
#
# ─── SO READ THIS FILE AS THE CONTRACT, NOT AS APPROVAL ────────────────────
#
# The last two assertions are a limitation written down, and they are meant to
# FAIL the day somebody makes an edit reach a live worker.  That is the point:
# when they do, this file and the two places in man/ change in the same commit,
# and the documented behaviour cannot drift away from the real one quietly.
# Delivering the change live is the larger fix and needs a worker that can be
# reconfigured mid-life; nothing here argues against it.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: edit on a running runtime is stored, not delivered ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

P=$((SL_PORT_BASE+1492))

daemon_isolate edittiming
trap 'daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

"$BIN" create server et -p "$P" --max-connections 10 -s >/dev/null 2>&1
for _ in $(seq 1 50); do nc -z 127.0.0.1 "$P" 2>/dev/null && break; sleep 0.1; done
sleep 0.5

# How many of four simultaneous connections the runtime keeps.  A refused one
# is closed at once, so a read that returns b'' is the refusal; a timeout means
# the connection is open and the server simply has nothing to say, which is the
# normal state for a server with no script.
open_count() {
python3 -c "
import socket, time
kept, held = 0, []
for _ in range(4):
    try:
        s = socket.create_connection(('127.0.0.1', $P), timeout=2)
        s.settimeout(0.6)
        s.sendall(b'x\n')
        try:    d = s.recv(16)
        except socket.timeout: d = b'-'
        if d != b'': kept += 1
        held.append(s)
    except Exception:
        pass
    time.sleep(0.1)
print(kept)
for s in held: s.close()
" 2>/dev/null
}

BEFORE=$(open_count)
if [ "${BEFORE:-0}" -eq 4 ]; then
    ok "with --max-connections 10 all four connections are kept"
else
    bad "the limit starts where the flag put it" \
        "only ${BEFORE:-<none>} of 4 were kept before any edit;" \
        "nothing below distinguishes anything if the limit is already biting"
fi

"$BIN" edit et --max-connections 1 >/dev/null 2>&1
ERC=$?
SHOWN=$("$BIN" show et 2>/dev/null | grep -o '"max_connections"[^,]*' | head -1)
sleep 0.5
AFTER=$(open_count)

if [ "$ERC" -eq 0 ] && printf '%s' "$SHOWN" | grep -q '1'; then
    ok "the edit is accepted and stored (rc $ERC, show: $SHOWN)"
else
    bad "edit stores the new value" "rc $ERC and show reads '${SHOWN:-<none>}'"
fi

# ── The limitation, stated as an assertion so it cannot drift ──────────────
if [ "${AFTER:-0}" -eq 4 ]; then
    ok "and the running worker still enforces the old limit ($AFTER of 4 kept)"
else
    bad "edit on a running runtime is stored and not delivered" \
        "the running worker kept ${AFTER:-<none>} of 4 after the edit, where it kept $BEFORE before;" \
        "if an edit now REACHES a live worker that is an improvement, not a" \
        "regression --- but man/socketley.1 and man/socketley-help.sh say it does" \
        "not, and they have to change in the same commit as this line"
fi

"$BIN" restart et >/dev/null 2>&1
sleep 2
RESTARTED=$(open_count)
if [ "${RESTARTED:-0}" -eq 1 ]; then
    ok "and a restart applies it ($RESTARTED of 4 kept)"
else
    bad "the stored value takes effect at the next start" \
        "after a restart the runtime kept ${RESTARTED:-<none>} of 4, expected 1;" \
        "without this line the assertion above would also pass for a value that" \
        "was never stored at all"
fi

"$BIN" stop et >/dev/null 2>&1; "$BIN" remove et >/dev/null 2>&1
daemon_stop
trap - EXIT

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
