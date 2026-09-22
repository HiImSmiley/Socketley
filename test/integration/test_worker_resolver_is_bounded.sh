#!/usr/bin/env bash
# Integration test: a worker is exec'd with a bounded resolver, and an operator
# who set one keeps theirs.
#
# ─── WHY THIS EXISTS ────────────────────────────────────────────────────────
#
# getaddrinfo blocks the thread that calls it, and in every runtime here that
# thread is the event loop -- with the control socket armed on the same ring,
# so a daemon's `stop` and `stats` frames go unread for the whole wait.
#
# glibc's default is five seconds, twice.  Measured against a nameserver that
# drops packets rather than refusing them (203.0.113.1, TEST-NET-3, in a mount
# namespace of its own): one getaddrinfo held its caller for 10,010 ms.  A
# client re-resolves on every reconnect once its cached address stops accepting
# -- which is the container case client_instance.cpp documents -- so that is
# ten seconds of an unanswerable runtime per attempt, repeating.
#
#     RES_OPTIONS unset           10,010 ms
#     timeout:1 attempts:1         1,002 ms
#     timeout:1 attempts:2         2,002 ms   <- chosen
#     timeout:2 attempts:1         2,002 ms
#
# The last two cost the same and only the first of them retries a lost packet.
#
# ─── WHY IT IS ASSERTED ON THE ENVIRONMENT AND NOT ON A CLOCK ───────────────
#
# It could not be set by the process itself.  glibc reads RES_OPTIONS on the
# first name the process looks up and never again, so a setenv() one line after
# some other resolve is silently nothing -- measured too: setenv before the
# first lookup gave 2,002 ms, the same setenv after one lookup gave 10,010 ms.
# That is why it lives in the exec'd environment, and why /proc/<pid>/environ
# is the right place to read it back: that file shows what the process was
# handed at exec and is not moved by a later setenv.
#
# What this does NOT assert is the duration, because on a box whose resolver
# answers -- this one replies NXDOMAIN in 0.6 ms -- there is no wait to
# measure, and a test that manufactured one would be asserting a mount
# namespace rather than this daemon.  The numbers above are the measurement;
# this file is the wiring.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   worker has the bound        the append was dropped, or moved into the
#                               child where glibc has stopped listening
#   the operator's survives     the append stopped looking at what is already
#                               there and overwrote a deliberate setting
#   the runtime still serves    a malformed entry that broke execve's envp
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_ready.sh"

OURS="timeout:1 attempts:2"
THEIRS="timeout:7 attempts:3"

PASS=0; FAIL=0; TOTAL=0
ok()    { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad()   { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "expected '$2', got '$3'"; fi; }

cleanup() {
    "$BIN" stop   rb_srv >/dev/null 2>&1 || true
    "$BIN" remove rb_srv >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a worker's resolver is bounded, and an operator's is not overruled ==="

# The worker behind the port, not "some socketley": picking the daemon or a
# stranger is how this would pass for the wrong reason.
# Nothing here ends a pipeline in `grep -q`: under `set -o pipefail` that
# reports the pipeline as failed whenever grep exits at the first hit and the
# writer behind it takes a SIGPIPE, and this directory has been caught by that
# four times.  One `ss`, held in a variable, then matched with `case`.
worker_on_port() {
    local port=$1 p holders
    holders=$(ss -ltnpH "sport = :$port" 2>/dev/null || true)
    for p in $(pgrep -x socketley 2>/dev/null || true); do
        grep -qz "SOCKETLEY_SOCKET=$SOCKETLEY_SOCKET" "/proc/$p/environ" 2>/dev/null || continue
        [ "$(awk '{print $4}' "/proc/$p/stat" 2>/dev/null)" = "$SOCKETLEY_DPID" ] || continue
        case "$holders" in
            *"pid=$p,"*) echo "$p"; return 0 ;;
        esac
    done
    echo ""
}

# The value as the process was handed it, which is what glibc read.
res_options_of() {
    local p=$1 entry
    [ -n "$p" ] || { echo "no-worker"; return; }
    while IFS= read -r entry; do
        case "$entry" in
            RES_OPTIONS=*) printf '%s\n' "${entry#RES_OPTIONS=}"; return ;;
        esac
    done <<< "$(tr '\0' '\n' < "/proc/$p/environ" 2>/dev/null || true)"
    echo ""
}

# One phase: a daemon, a server on it, and the worker's RES_OPTIONS, left in
# PHASE_RES rather than written to stdout.  A phase that answered through a
# command substitution ran in a subshell, so the daemon it started was one this
# shell did not know the pid of -- it could not be stopped in cleanup, and the
# assertion that reads the daemon's own environment compared an empty string
# with an empty string and passed without looking at anything.
PHASE_RES=""
start_phase() {
    local tag=$1 port=$2
    daemon_isolate "$tag"
    daemon_start "$BIN"
    "$BIN" create server rb_srv -p "$port" >/dev/null 2>&1
    "$BIN" start rb_srv >/dev/null 2>&1 || true
    ready_tcp 127.0.0.1 "$port" 15 || true
    local worker
    worker=$(worker_on_port "$port")
    if [ -z "$worker" ]; then
        bad "the worker behind port $port was found" \
            "no child of daemon $SOCKETLEY_DPID is listening there"
    else
        ok
    fi
    PHASE_RES=$(res_options_of "$worker")
}

# ── the default ─────────────────────────────────────────────────────────────
start_phase resbound1 $((SL_PORT_BASE+1770))
check "a worker is exec'd with a bounded resolver" "$OURS" "$PHASE_RES"

# A malformed envp does not usually fail loudly; it fails by the runtime not
# being there, and every check above would read "no-worker" without saying why.
SERVES=$(ready_tcp 127.0.0.1 $((SL_PORT_BASE+1770)) 5 && echo yes || echo no)
check "and the runtime it belongs to is serving" "yes" "$SERVES"

# The daemon is not a worker, so it must not have picked this up from a
# setenv() somewhere global -- skipped if this run's own shell has one, since
# then the daemon inherits it honestly and the assertion means nothing.
if [ -z "${RES_OPTIONS:-}" ]; then
    check "the daemon itself was not given one" "" "$(res_options_of "${SOCKETLEY_DPID:?no daemon pid}")"
else
    echo "  SKIP [the daemon itself was not given one]: this shell exports RES_OPTIONS"
fi

# ── the operator's ──────────────────────────────────────────────────────────
"$BIN" stop rb_srv >/dev/null 2>&1 || true
"$BIN" remove rb_srv >/dev/null 2>&1 || true
daemon_stop

export RES_OPTIONS="$THEIRS"
start_phase resbound2 $((SL_PORT_BASE+1772))
check "an operator's own resolver settings reach the worker unchanged" "$THEIRS" "$PHASE_RES"

echo
echo "  $PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || exit 1
