#!/usr/bin/env bash
# Integration test: a state file that cannot be written says so.
#
# write_state_file() has four ways to fail -- open, write, close, rename -- and
# had a word for none of them, while both callers drop the bool it returns:
# writer_loop's `write_json(j.cfg); break;` and the was_running flip's
# `if (!write_state_file(path, json)) {}`.
#
# So a state directory that was full, read-only or over quota produced a daemon
# that accepted `create`, answered 0, showed the runtime in `ls`, served its
# traffic -- and had never heard of it at the next start, with nothing anywhere
# saying why. Measured before the fix, with the state directory at mode 500:
#
#     create server x -p P   -> exit 0, nothing printed
#     ls                     -> x, created
#     daemon log             -> not one line about the state directory
#
# The sibling check three hundred lines up already logs, and for this exact
# reason: a runtime whose state cannot be stored will not come back.
#
# ─── WHAT IS AND IS NOT FIXED ───────────────────────────────────────────────
#
# The failure is reported, at ERROR, naming the path, the step and the errno.
# `create` still exits 0, and that is not an oversight: the write happens on the
# persistence writer's own thread, long after the command has answered. Making
# the command wait for it is a different change with a different cost, and this
# one is about the silence.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate statewrite

P=$((SL_PORT_BASE+1890))
NAMES="sw_ok sw_ro sw_two"

PASS=0; FAIL=0; TOTAL=0

STATE_DIR=""
cleanup() {
    # Put the mode back before daemon_stop, which has to delete the tree.
    [ -n "$STATE_DIR" ] && chmod 700 "$STATE_DIR" 2>/dev/null
    for n in $NAMES; do "$BIN" stop "$n"   >/dev/null 2>&1 || true; done
    sleep 0.3
    for n in $NAMES; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

check() {   # label expected actual
    if [ "$2" = "$3" ]; then ok; else bad "$1" "expected '$2', got '$3'"; fi
}

# `grep -c` prints 0 AND exits 1 on no match, so `|| true` and never `|| echo 0`.
complaints() { grep -c "state file" "$SOCKETLEY_DLOG" 2>/dev/null || true; }

echo "=== Integration: a state file that cannot be written says so ==="
daemon_start "$BIN"

# The daemon names its own state directory at startup, which is the
# authoritative answer to which one is in use.
STATE_DIR=$(sed -n 's/.*state directory: \(.*\)$/\1/p' "$SOCKETLEY_DLOG" | tail -1)
if [ -n "$STATE_DIR" ] && [ -d "$STATE_DIR" ]; then ok; else
    bad "the daemon named its state directory" "got '${STATE_DIR:-<nothing>}'"; fi

# ─── 1. A writable directory says nothing ───────────────────────────────────
# The control: a complaint on every save would be as useless as none.
BEFORE=$(complaints)
create_ok "a runtime that can be persisted" "$BIN" create server sw_ok -p "$P"
sleep 0.8
check "a good save is silent" "$BEFORE" "$(complaints)"

if [ -f "$STATE_DIR/sw_ok.json" ]; then ok; else
    bad "and the file is really there" "$STATE_DIR/sw_ok.json is missing"; fi

# ─── 2. An unwritable directory says which file, which step and why ─────────
chmod 500 "$STATE_DIR"
BEFORE=$(complaints)
create_ok "a runtime that cannot be" "$BIN" create server sw_ro -p $((P+1))
sleep 1

AFTER=$(complaints)
if [ "$((AFTER - BEFORE))" -ge 1 ]; then ok; else
    bad "the failure is reported at all" \
        "no new 'state file' line in the daemon log after a refused write"; fi

LINE=$(grep "state file" "$SOCKETLEY_DLOG" | tail -1 || true)
case "$LINE" in
    *"sw_ro.json"*) ok ;;
    *) bad "the line names the file" "got '${LINE:-<nothing>}'" ;;
esac
case "$LINE" in
    *"open failed"*) ok ;;
    *) bad "and which step failed" "got '${LINE:-<nothing>}'" ;;
esac
case "$LINE" in
    *"Permission denied"*) ok ;;
    *) bad "and the reason" "got '${LINE:-<nothing>}'" ;;
esac
case "$LINE" in
    *"will not come back"*) ok ;;
    *) bad "and what it costs the operator" "got '${LINE:-<nothing>}'" ;;
esac
case "$LINE" in
    *ERROR*) ok ;;
    *) bad "at ERROR, not at INFO" "got '${LINE:-<nothing>}'" ;;
esac

# The runtime is still there and still usable: a state file that could not be
# written is a problem for the next boot, not for this one.
STATE=$("$BIN" ps -a 2>/dev/null | awk '$2=="sw_ro" { print $7 }')
if [ -n "$STATE" ]; then ok; else
    bad "the runtime still exists in this daemon" "ps does not list sw_ro"; fi

# ─── 3. Every refused write is reported, not just the first ─────────────────
# Latching would be wrong here, unlike -w and --log: those write per message
# and would flood, while a state save happens per change and each one is a
# runtime that will not come back.
BEFORE=$(complaints)
create_ok "a second one" "$BIN" create server sw_two -p $((P+2))
sleep 1
if [ "$(( $(complaints) - BEFORE ))" -ge 1 ]; then ok; else
    bad "the second failure is reported too" \
        "only the first refused write was logged"; fi

chmod 700 "$STATE_DIR"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
[ "$FAIL" -eq 0 ]
