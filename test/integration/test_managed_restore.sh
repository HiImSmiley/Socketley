#!/usr/bin/env bash
# Integration test: a managed runtime is still running after the daemon restarts.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# `add` is how the daemon owns a process it forked itself: it records the
# executable, execs it, and re-execs it when it comes back up.  That last part
# did not happen.
#
# cmd_add and cmd_attach call mark_managed()/mark_external() and nothing else.
# The restore path called mark_out_of_process() unconditionally at daemon.cpp,
# eighteen lines before it noticed the state file said external -- and start()
# reads out_of_process first, returning as a placeholder before it ever reaches
# the fork.
#
# So nothing was exec'd, and nothing said so.  Measured on the parent commit:
#
#     $ socketley add /tmp/svc.sh --name m1 -s
#     $ ls /tmp/svc-ran                       # the script ran
#     $ # restart the daemon, with the marker deleted and the child killed
#     $ ls /tmp/svc-ran                       # No such file or directory
#     $ socketley ls
#     ID      NAME  TYPE    ...  STATUS
#     0c53ec  m1    server  ...  Up 2 seconds
#
# "Up", with the stale pid of a process that no longer exists.  A restart that
# silently stops running what it was told to run is the failure this file
# exists to catch, and the reason it asserts on the process rather than on the
# status column: the status column was the thing that lied.
#
# The invariant now lives in runtime_instance rather than at either caller,
# because the marks arrive in no fixed order; the flag half of that is in
# test/unit/test_managed_runtime.cpp and the process half is here.

set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate mgrestore
PASS=0; FAIL=0; TOTAL=0

pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

MARKER="$SOCKETLEY_TMPD/svc-ran"
SVC="$SOCKETLEY_TMPD/svc.sh"

cleanup() {
    [ -n "${LIVE_PID:-}" ] && kill -9 "$LIVE_PID" 2>/dev/null
    [ -n "${FIRST_PID:-}" ] && kill -9 "$FIRST_PID" 2>/dev/null
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a managed runtime survives a daemon restart ==="

# Touching the marker is what proves an exec happened; sleeping keeps the
# process alive so the daemon has something to hold.
cat > "$SVC" <<EOF
#!/bin/bash
touch "$MARKER"
exec sleep 300
EOF
chmod +x "$SVC"

daemon_start "$BIN"

"$BIN" add "$SVC" --name mr1 -s </dev/null 2>&1
for _ in $(seq 1 40); do [ -f "$MARKER" ] && break; sleep 0.25; done

if [ -f "$MARKER" ]; then pass
else fail "add execs the program it was given" "no $MARKER"; fi

FIRST_PID=$("$BIN" show mr1 </dev/null 2>/dev/null | sed -n 's/.*"pid": \([0-9]*\).*/\1/p')
if [ -n "$FIRST_PID" ] && kill -0 "$FIRST_PID" 2>/dev/null; then pass
else fail "the daemon reports the pid it forked" "pid '${FIRST_PID:-<none>}'"; fi

# ─── The restart ────────────────────────────────────────────────────────────
#
# The child is killed and the marker deleted, so what is observed afterwards
# can only have come from the restore path re-execing the program.
kill "$SOCKETLEY_DPID" 2>/dev/null || true
for _ in $(seq 1 60); do kill -0 "$SOCKETLEY_DPID" 2>/dev/null || break; sleep 0.1; done
wait "$SOCKETLEY_DPID" 2>/dev/null || true
kill -9 "$FIRST_PID" 2>/dev/null || true
FIRST_PID=""
rm -f "$MARKER"

: > "$SOCKETLEY_DLOG"
"$BIN" daemon >>"$SOCKETLEY_DLOG" 2>&1 &
SOCKETLEY_DPID=$!
for _ in $(seq 1 100); do
    grep -q "daemon started" "$SOCKETLEY_DLOG" 2>/dev/null && break
    sleep 0.1
done

for _ in $(seq 1 40); do [ -f "$MARKER" ] && break; sleep 0.25; done

if [ -f "$MARKER" ]; then pass
else fail "the restore path execs the program again" \
          "no $MARKER, so nothing ran" \
          "$("$BIN" ls </dev/null 2>&1 | grep mr1 || true)"; fi

LIVE_PID=$("$BIN" show mr1 </dev/null 2>/dev/null | sed -n 's/.*"pid": \([0-9]*\).*/\1/p')
if [ -n "$LIVE_PID" ] && kill -0 "$LIVE_PID" 2>/dev/null; then pass
else fail "the pid it reports after the restart is alive" \
          "pid '${LIVE_PID:-<none>}'"; fi

# The status column said Up throughout the bug, so it is worth asserting only
# now that the two above have established there is something behind it.
STATUS=$("$BIN" ls </dev/null 2>/dev/null | awk '$2 == "mr1" { print $7 }')
if [ "$STATUS" = "Up" ]; then pass
else fail "and it is reported as running" "ls said '${STATUS:-<nothing>}'"; fi

SHOW=$("$BIN" show mr1 </dev/null 2>/dev/null)
if grep -q '"managed": true' <<<"$SHOW"; then pass
else fail "it comes back managed rather than as a placeholder" "$SHOW"; fi

# ─── stop still owns the process it forked ──────────────────────────────────
#
# Asked of the process state and not of kill -0, which succeeds on a zombie:
# the daemon reaps with WNOHANG straight after the signal, so a child that has
# only just died is still a pid.
child_state() { ps -o stat= -p "$1" 2>/dev/null | tr -d ' '; }

"$BIN" stop mr1 </dev/null 2>&1
for _ in $(seq 1 40); do
    case "$(child_state "$LIVE_PID")" in ''|Z*) break;; esac
    sleep 0.25
done
case "$(child_state "$LIVE_PID")" in
    ''|Z*) pass;;
    *)     fail "stop signals the restored child" \
                "pid $LIVE_PID is $(child_state "$LIVE_PID")";;
esac
LIVE_PID=""

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
if [ "$FAIL" -eq 0 ]; then echo "  OK"; else echo "  FAILED"; fi
exit "$FAIL"
