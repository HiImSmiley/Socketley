#!/usr/bin/env bash
# Integration test: --master-pw outside --mode master, and the boot restore.
#
# The "master " prefix is read in exactly ONE place, the mode_master case of
# process_message().  In every other mode a client that types its password sends
# an ordinary message, and an ordinary message on a server with no script is
# relayed to the other connections.  Measured before this fix, on a private
# daemon:
#
#     create server x -p P --master-pw hunter2 -s   -> exit 0, nothing printed
#     stats                                          -> mode:0
#     connection A sends "master hunter2"
#     connection B receives                          -> "master hunter2"
#
# No flag was rejected, no warning was logged, and the password was on the wire.
#
# ─── THE DOOR THAT WAS STILL OPEN AFTER THE OBVIOUS ONES ────────────────────
#
# `create` and `start` are two of FIVE routes to a live runtime.  The others are
# `edit` (which has its own parser and accepted --mode, --send-to, --udp and
# --master-pw with no set check at all), a script's socketley.create, and the
# daemon's own boot restore -- which reads a state file, calls manager.start()
# directly, and walks past every check written in a command handler.
#
# The boot restore is the one that matters, because it is where a pair that is
# already ON DISK comes back.  Measured with mode 0, master_pw and
# was_running planted into a state file and the daemon restarted:
#
#     ls          -> Up 1 second           (it came up)
#     daemon log  -> nothing at all
#     probe       -> the other connection received "master hunter2"
#
# So the rule now lives in server_mode_config_refusal() and is asked by
# runtime_instance::start() through config_refusal(), which every one of the
# five routes ends at.  The command handlers still ask it first, so a refusal
# names the runtime and reaches the terminal instead of only the log.
#
# ─── WHY THERE IS A --no-master-pw ──────────────────────────────────────────
#
# The pair is refused as a SET, and only one half was removable: `edit --mode
# inout` on a master server was refused because the password was still there,
# and `--master-pw ""` cannot remove it, because the daemon receives one line
# and splits it on whitespace so an empty argument does not survive the wire.
# Without a spelling of its own a server that once had a password could never
# be edited to another mode again.  The last three cases are that escape hatch.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_ready.sh"
daemon_isolate masterpw
P_OK=$((SL_PORT_BASE+1975))
P_REF=$((SL_PORT_BASE+1976))
P_BOOT=$((SL_PORT_BASE+1977))
MPW=hunter2
PASS=0; FAIL=0; TOTAL=0
NAMES="mp_ok mp_boot"

cleanup() {
    for n in $NAMES; do "$BIN" stop "$n" 2>/dev/null || true; done
    sleep 0.3
    for n in $NAMES; do "$BIN" remove "$n" 2>/dev/null || true; done
    daemon_stop
}
trap cleanup EXIT

ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

check() {   # label expected actual
    if [ "$2" = "$3" ]; then ok; else bad "$1" "expected '$2', got '$3'"; fi
}

refused() {   # label needle -- then the command
    local label=$1 needle=$2; shift 2
    local out
    out=$("$@" 2>&1) || true
    if grep -q "$needle" <<<"$out"; then ok; else
        bad "$label" "expected a refusal naming '$needle', got '$out'"; fi
}

# A restart that keeps the isolation: daemon_stop deletes SOCKETLEY_TMPD, which
# is where the state file being planted lives.  The log is truncated because
# daemon_start waits for "daemon started" and would otherwise match the previous
# run's line and return before the new daemon had read anything.
daemon_restart() {
    if [ -n "${SOCKETLEY_DPID:-}" ]; then
        for c in $(pgrep -P "$SOCKETLEY_DPID" 2>/dev/null); do kill -9 "$c" 2>/dev/null || true; done
        kill -9 "$SOCKETLEY_DPID" 2>/dev/null || true
        wait "$SOCKETLEY_DPID" 2>/dev/null || true
    fi
    for _ in $(seq 1 50); do [ -S "$SOCKETLEY_SOCKET" ] || break; sleep 0.1; done
    rm -f "$SOCKETLEY_SOCKET"
    : > "$SOCKETLEY_DLOG"
    daemon_start "$BIN"
}

# Two clients: A sends the password, and the answer says whether B heard it.
# One client cannot tell "relayed" from "answered nobody", which is exactly why
# this was invisible.
probe_leak() {
    python3 - "$1" "$MPW" <<'PYEOF' 2>/dev/null || echo "PROBE-FAILED"
import socket, sys, time
port, pw = int(sys.argv[1]), sys.argv[2]
a = socket.create_connection(("127.0.0.1", port), 5); a.settimeout(1.5)
b = socket.create_connection(("127.0.0.1", port), 5); b.settimeout(1.5)
time.sleep(0.3)
a.sendall(("master %s\n" % pw).encode())
try:    heard = b.recv(256).decode().strip()
except Exception: heard = ""
print(heard or "-")
PYEOF
}

# The password claims the master role, which is the behaviour that must survive
# every refusal added here.
probe_auth() {
    python3 - "$1" "$MPW" <<'PYEOF' 2>/dev/null || echo "PROBE-FAILED"
import socket, sys
port, pw = int(sys.argv[1]), sys.argv[2]
m = socket.create_connection(("127.0.0.1", port), 5); m.settimeout(1.5)
m.sendall(("master %s\n" % pw).encode())
try:    print(m.recv(64).decode().strip() or "-")
except Exception: print("-")
PYEOF
}

echo "=== Integration: --master-pw is refused outside --mode master ==="

daemon_start "$BIN"

# ─── create ─────────────────────────────────────────────────────────────────
refused "create refuses the pair" "needs --mode master" \
    "$BIN" create server mp_bad0 -p "$P_REF" --master-pw "$MPW"

# Both orders, because the check is made as a set once every flag is seen.
refused "create, --mode typed first" "needs --mode master" \
    "$BIN" create server mp_bad1 -p "$P_REF" --mode in --master-pw "$MPW"

# And the runtime is not left behind half-created.
OUT=$("$BIN" stats mp_bad0 2>&1) || true
if grep -q "not found" <<<"$OUT"; then ok; else
    bad "a refused create leaves nothing" "stats answered: $OUT"; fi

# ─── the legal pair still works ─────────────────────────────────────────────
create_ok "master mode with a password" \
    "$BIN" create server mp_ok -p "$P_OK" --mode master --master-pw "$MPW" -s
ready_tcp 127.0.0.1 "$P_OK" || echo "  WARN: nothing listening on $P_OK"
sleep 0.4
check "the password still claims master" "master: ok" "$(probe_auth "$P_OK")"

# ─── edit ───────────────────────────────────────────────────────────────────
# `edit` has its own parser and took --mode with no set check, so a legally
# created master server could be walked into the refused pair one flag at a
# time -- and that is the shape the leak actually reached in the field.
refused "edit cannot walk out of master mode" "needs --mode master" \
    "$BIN" edit mp_ok --mode inout

# Rolled back as a set rather than half-applied: the daemon's own record, not
# `stats`, because a running worker keeps its mode until the next start.
MODE_AFTER=$("$BIN" show mp_ok 2>/dev/null | grep '"mode"' | tr -d ' ",' | cut -d: -f2)
check "the refused edit rolled the mode back" "master" "$MODE_AFTER"

# ─── the boot restore ───────────────────────────────────────────────────────
# The route no command handler covers.  `start` restarts from the in-memory
# instance and never re-reads the file, so the pair has to be planted and the
# DAEMON restarted for this to test anything.
create_ok "a runtime to plant the pair into" \
    "$BIN" create server mp_boot -p "$P_BOOT"
# Polled, not slept for: state_persistence enqueues onto a writer thread, so the
# file appears a moment after `create` returns.
SF=""
for _ in $(seq 1 60); do
    SF=$(find "${HOME}/.local/share/socketley" -name 'mp_boot.json' 2>/dev/null | head -1)
    [ -n "$SF" ] && break
    sleep 0.1
done
if [ -z "$SF" ]; then
    bad "the state file exists to plant into" "no mp_boot.json found"
else
    python3 - "$SF" "$MPW" <<'PYJSON'
import json, sys
d = json.load(open(sys.argv[1]))
d["mode"] = 0; d["master_pw"] = sys.argv[2]; d["was_running"] = True
json.dump(d, open(sys.argv[1], "w"), indent=4)
PYJSON
    daemon_restart
    sleep 1.2

    # It must not be listening, and the reason must be in the log -- the boot
    # restore has no terminal to refuse to.
    if ready_tcp 127.0.0.1 "$P_BOOT" 1 2>/dev/null; then
        bad "the boot restore refuses the planted pair" \
            "it is listening on $P_BOOT; leak probe says: $(probe_leak "$P_BOOT")"
    else
        ok
    fi

    if grep -q "master-pw needs --mode master" "$SOCKETLEY_DLOG" 2>/dev/null; then ok; else
        bad "the boot restore says why" "nothing in the daemon log names the pair"; fi

    # And it is `failed`, not `created`, so `ls` shows something is wrong rather
    # than a runtime that merely was not asked to start.
    STATE=$("$BIN" ls 2>/dev/null | awk '$2=="mp_boot"{print $NF}')
    LSLINE=$("$BIN" ls 2>/dev/null | grep -c "mp_boot" || true)
    if [ "$LSLINE" -ge 1 ] && "$BIN" ls 2>/dev/null | grep mp_boot | grep -qi "failed"; then
        ok
    else
        bad "a refused restore is reported as failed" \
            "ls says: $("$BIN" ls 2>/dev/null | grep mp_boot || echo '<not listed>')"
    fi
fi

# ─── the escape hatch ───────────────────────────────────────────────────────
# `--master-pw ""` cannot express this: the daemon splits one line on
# whitespace, so the empty argument arrives as the flag with nothing after it.
refused "an empty --master-pw is not an unset" "requires a password" \
    "$BIN" edit mp_ok --master-pw ""

OUT=$("$BIN" edit mp_ok --no-master-pw 2>&1) || true
if [ -z "$OUT" ]; then ok; else bad "--no-master-pw is accepted" "got '$OUT'"; fi

OUT=$("$BIN" edit mp_ok --mode inout 2>&1) || true
if [ -z "$OUT" ]; then ok; else
    bad "and then the mode can change" "got '$OUT'"; fi

MODE_END=$("$BIN" show mp_ok 2>/dev/null | grep '"mode"' | tr -d ' ",' | cut -d: -f2)
check "the mode really moved" "inout" "$MODE_END"

# The password is gone from the record, not merely unused -- a state file is
# read back at every boot.
if "$BIN" show mp_ok 2>/dev/null | grep -q 'master_pw'; then
    bad "--no-master-pw clears the record" "master_pw is still in \`show\`"
else
    ok
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
[ "$FAIL" -eq 0 ]
