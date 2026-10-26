#!/usr/bin/env bash
# Integration test: a boot restore does not start a runtime whose script is gone.
#
# ─── THE FIFTH ROUTE, ANSWERING DIFFERENTLY ─────────────────────────────────
#
# Three routes to a runtime with a --lua script refuse outright when it will not
# load. `create --lua` prints the reason, removes the runtime and exits 1;
# `import` answers 1 with the reason; and a script's own socketley.create
# returns it, under a comment that says why:
#
#     "a runtime with no callbacks is indistinguishable from a working one
#      until traffic arrives"
#
# The boot restore logged a WARN and started it anyway. Measured, with a
# working on_http_request replaced by a syntax error and the daemon restarted:
#
#     ps -a        ->  Up
#     GET /        ->  HTTP/1.1 404 Not Found
#     daemon log   ->  [WARN] restore: could not load lua script
#
# `Up`, serving 404s to whoever was calling it, and one WARN with no runtime
# name, no reason and no consequence in it. A script that becomes unreadable
# between two boots -- moved, renamed, on a mount that came up late -- brings
# the runtime back as a different runtime.
#
# ─── WHY REFUSED AND NOT REPAIRED ───────────────────────────────────────────
#
# Not coming back is visible in `ls` and fixable in one command. Coming back
# without callbacks is neither: the port answers, the health check passes, and
# nothing says the thing behind it is gone. The runtime is left `failed` with
# an ERROR naming the script, the reason and what to do about it.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_ready.sh"
daemon_isolate restorebroken

P_BROKEN=$((SL_PORT_BASE+1984))
P_OK=$((SL_PORT_BASE+1986))
NAMES="rb_broken rb_ok"
LUA_BROKEN="$SOCKETLEY_TMPD/broken.lua"
LUA_OK="$SOCKETLEY_TMPD/fine.lua"

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

daemon_restart() {
    if [ -n "${SOCKETLEY_DPID:-}" ]; then
        for c in $(pgrep -P "$SOCKETLEY_DPID" 2>/dev/null); do
            kill -9 "$c" 2>/dev/null || true
        done
        kill -9 "$SOCKETLEY_DPID" 2>/dev/null || true
        wait "$SOCKETLEY_DPID" 2>/dev/null || true
    fi
    for _ in $(seq 1 50); do [ -S "$SOCKETLEY_SOCKET" ] || break; sleep 0.1; done
    rm -f "$SOCKETLEY_SOCKET"
    : > "$SOCKETLEY_DLOG"
    daemon_start "$BIN"
}

# `|| true` because nc's status is not the assertion -- a port with nothing on
# it is one of the answers this file is looking for, and under `set -e` a
# non-zero nc ends the file at the command substitution instead.
http_get() { printf 'GET / HTTP/1.0\r\n\r\n' | timeout 5 nc -q1 127.0.0.1 "$1" 2>/dev/null || true; }
state()    { "$BIN" ps -a 2>/dev/null | awk -v n="$1" '$2==n { print $7 }'; }

echo "=== Integration: a restore will not start a runtime with no script ==="
daemon_start "$BIN"

cat > "$LUA_BROKEN" <<'LUA'
function on_http_request(req)
  return { status = 200, body = "FROM-THE-SCRIPT" }
end
LUA
cat > "$LUA_OK" <<'LUA'
function on_http_request(req)
  return { status = 200, body = "STILL-HERE" }
end
LUA

create_ok "a scripted server"           "$BIN" create server rb_broken -p "$P_BROKEN" --lua "$LUA_BROKEN" -s
create_ok "and one beside it, untouched" "$BIN" create server rb_ok    -p "$P_OK"     --lua "$LUA_OK"     -s
ready_tcp 127.0.0.1 "$P_BROKEN" >/dev/null 2>&1 || true
ready_tcp 127.0.0.1 "$P_OK"     >/dev/null 2>&1 || true

# The callbacks really are in force before anything is broken, or the assertion
# after the reboot is about a runtime that never worked.
case "$(http_get "$P_BROKEN")" in *FROM-THE-SCRIPT*) ok ;;
    *) bad "the script answers before the reboot" "got '$(http_get "$P_BROKEN" | tail -1)'" ;; esac

# ─── The script goes, the daemon restarts ───────────────────────────────────
printf 'function on_http_request(req)\n  return {\nend\n' > "$LUA_BROKEN"
daemon_restart
sleep 2

# ─── 1. It is not up ────────────────────────────────────────────────────────
STATE=$(state rb_broken)
if [ "$STATE" != "Up" ]; then ok; else
    bad "the runtime with the broken script is not running" \
        "ps says Up -- it came back with no callbacks at all, which is what a" \
        "404 on its port then looks like"; fi

# ─── 2. And nothing is on its port ──────────────────────────────────────────
# The sharper half: `Up` alone could be argued about, an answering port cannot.
BODY=$(http_get "$P_BROKEN")
case "$BODY" in
    "") ok ;;
    *404*) bad "and nothing answers on its port" \
               "it answered '$(printf '%s' "$BODY" | head -1)' -- the callback is gone" \
               "and the static-file fallback is serving in its place" ;;
    *) bad "and nothing answers on its port" "it answered '$(printf '%s' "$BODY" | head -1)'" ;;
esac

# ─── 3. The log says which, why and what to do ──────────────────────────────
LINE=$(grep -i "did not load" "$SOCKETLEY_DLOG" | tail -1 || true)
case "$LINE" in *rb_broken*) ok ;;
    *) bad "the log names the runtime" "got '${LINE:-<nothing>}'" ;; esac
case "$LINE" in *broken.lua*) ok ;;
    *) bad "and the script" "got '${LINE:-<nothing>}'" ;; esac
case "$LINE" in *ERROR*) ok ;;
    *) bad "at ERROR, not at WARN" "got '${LINE:-<nothing>}'" ;; esac
case "$LINE" in *"start rb_broken"*) ok ;;
    *) bad "and what to do about it" "got '${LINE:-<nothing>}'" ;; esac

# ─── 4. The one beside it is untouched ──────────────────────────────────────
# A restore that refused everything would satisfy all of the above.
check "the other runtime came back up" "Up" "$(state rb_ok)"
case "$(http_get "$P_OK")" in *STILL-HERE*) ok ;;
    *) bad "and its script is still in force" \
           "got '$(http_get "$P_OK" | tail -1)'" ;; esac

# ─── 5. And it can be fixed and started ─────────────────────────────────────
# `failed` is a state `start` gets a runtime out of, which is what makes this
# recoverable in one command rather than a reason to have started it anyway.
cp "$LUA_OK" "$LUA_BROKEN"
if "$BIN" start rb_broken >/dev/null 2>&1; then ok; else
    bad "a fixed script can be started" "start still refuses it"; fi
ready_tcp 127.0.0.1 "$P_BROKEN" >/dev/null 2>&1 || true
case "$(http_get "$P_BROKEN")" in *STILL-HERE*) ok ;;
    *) bad "and the callbacks are back" "got '$(http_get "$P_BROKEN" | tail -1)'" ;; esac

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
[ "$FAIL" -eq 0 ]
