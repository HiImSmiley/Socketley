#!/usr/bin/env bash
# Integration test: the owner cascade, and what it does when the graph has a cycle.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
# Nothing in the stop/remove recursion remembers where it has been and
# set_owner is a plain setter, so a runtime that owns itself is its own child
# and `stop` takes the daemon and every runtime in it -- a cycle that survives
# a restart, because the owner is persisted; every cycle case is paired with a
# control where stopping a parent must still stop its child, since "the daemon
# is still alive" is equally true of a build that deleted the cascade.

set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate owner_cascade
PASS=0; FAIL=0; TOTAL=0

cleanup() { daemon_stop; }
trap cleanup EXIT

pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

# Three things have to be true afterwards and none implies the others: a daemon
# is serving, which the CLI's auto-start makes nearly worthless; it is the same
# daemon, compared by a pid baseline taken per call because the death and the
# resurrection happen inside one command; and it still answers, because
# `remove` on a cycle recurses without crashing and holds its socket -- with
# the `timeout` part of the assertion rather than a convenience.
assert_daemon_survives() {
    local label=$1; shift
    local before after
    before=$(daemon_pids "$SOCKETLEY_SOCKET")

    timeout 15 "$@" >/dev/null 2>&1 || true

    after=$(daemon_pids "$SOCKETLEY_SOCKET")

    if [ -z "$after" ]; then
        fail "$label" "no daemon is serving the socket any more" \
             "command: $*" \
             "the cycle recursed until the stack ran out."
        return
    fi

    if [ "$before" != "$after" ]; then
        fail "$label" "the daemon was replaced, so the original one died" \
             "command: $*" \
             "serving before: ${before:-<none>}   after: $after" \
             "a CLI command auto-starts a daemon, so 'something is serving'" \
             "is true again within milliseconds of the crash."
        return
    fi

    if ! timeout 5 "$BIN" ping >/dev/null 2>&1; then
        fail "$label" "the daemon holds its socket but no longer answers" \
             "command: $*" \
             "pid $after is still there and did not reply to ping within 5s;" \
             "this is the cycle recursing without exhausting the stack."
        return
    fi

    pass
}

state_of() {
    # The status column for one runtime, empty when the daemon cannot answer at
    # all.
    "$BIN" ls --name --status 2>/dev/null | awk -F'\t' -v n="$1" '$1 == n { print $2 }'
}

# Put a healthy daemon on the socket before the next case, or a case that runs
# after a crash reports the previous case's death and two findings read as four
# -- and the condition is that our daemon is serving, checked by pid first,
# because `ping` is itself a CLI command that would fork a replacement while
# asking the question.
daemon_recover() {
    local serving; serving=$(daemon_pids "$SOCKETLEY_SOCKET")
    if [ -n "$serving" ] && [ "$serving" = "${SOCKETLEY_DPID:-}" ] \
       && timeout 5 "$BIN" ping >/dev/null 2>&1; then
        return 0
    fi
    daemon_sweep "$SOCKETLEY_SOCKET"
    if [ -n "${SOCKETLEY_DPID:-}" ]; then wait "$SOCKETLEY_DPID" 2>/dev/null || true; fi

    # Wait for the socket to actually be free, because `kill -9` returns as
    # soon as the signal is queued and a new daemon starting inside that window
    # decides one is already running and exits 0.
    local i
    for i in $(seq 1 50); do
        [ -z "$(daemon_pids "$SOCKETLEY_SOCKET")" ] && break
        sleep 0.1
    done

    # The log is emptied first because daemon_start waits by grepping it for a
    # line the previous daemon already wrote, and without this the liveness
    # check fails on a daemon that simply had not bound yet.
    : > "$SOCKETLEY_DLOG"
    daemon_start "$BIN"
}

echo "=== Integration: owner cascade and owner cycles ==="

daemon_start "$BIN"

P=$((SL_PORT_BASE + 760))

# ─── Control: the cascade has to keep working ───────────────────────────────
#
# First, because if this does not hold there is no point asking the rest: a
# build where stopping a parent does nothing would "survive" every cycle below
# for the wrong reason.
"$BIN" attach server parent   $((P + 0)) >/dev/null 2>&1 || true
"$BIN" attach server child    $((P + 1)) --owner parent >/dev/null 2>&1 || true

if [ -n "$(state_of parent)" ] && [ -n "$(state_of child)" ]; then pass
else fail "control pair exists" "attach did not produce both runtimes" \
          "parent='$(state_of parent)' child='$(state_of child)'"; fi

timeout 15 "$BIN" stop parent >/dev/null 2>&1 || true

if [ "$(state_of parent)" = "Stopped" ]; then pass
else fail "control: parent stopped" "expected Stopped, got '$(state_of parent)'"; fi

# The load-bearing half: a fix that removes the cascade passes everything below
# and fails exactly here.
if [ "$(state_of child)" = "Stopped" ]; then pass
else fail "control: the cascade reached the child" \
          "expected the child to be Stopped, got '$(state_of child)'" \
          "stopping a parent must still stop its children — without this," \
          "every cycle assertion below would pass on a build that simply" \
          "deleted the cascade."; fi

"$BIN" remove parent >/dev/null 2>&1 || true
"$BIN" remove child  >/dev/null 2>&1 || true

# ─── A grandchild's policy holds however the stop arrives ────────────────────
# r's script makes c (gone with r as a stop), c's makes g (removed with its parent): stopping r reached g through a
# walk that never read g's policy, so g was stopped and kept, where stopping c itself removed it.
D="$SOCKETLEY_TMPD"
cat > "$D/r.lua" <<LUA
function on_start() socketley.create("server", "gc_c", { port = $((P + 41)), lua = "$D/c.lua", start = true }) end
LUA
cat > "$D/c.lua" <<LUA
function on_start() socketley.create("server", "gc_g", { port = $((P + 42)), on_parent_stop = "remove", start = true }) end
LUA
"$BIN" create server gc_r -p $((P + 40)) --lua "$D/r.lua" -s >/dev/null 2>&1 || true
for _ in $(seq 1 40); do [ -n "$(state_of gc_g)" ] && break; sleep 0.25; done
if [ -n "$(state_of gc_g)" ]; then pass
else fail "the three-level chain is built" "gc_c='$(state_of gc_c)' gc_g='$(state_of gc_g)'"; fi
timeout 15 "$BIN" stop gc_r >/dev/null 2>&1 || true
sleep 0.5
if [ -z "$(state_of gc_g)" ] && [ "$(state_of gc_c)" = "Stopped" ]; then pass
else fail "a grandchild that goes with its parent goes when the stop came from above" \
          "gc_c='$(state_of gc_c)' gc_g='$(state_of gc_g)', want Stopped and gone"; fi
"$BIN" remove gc_r >/dev/null 2>&1 || true; "$BIN" remove gc_c >/dev/null 2>&1 || true

# ─── A renamed parent keeps its children ────────────────────────────────────
"$BIN" attach server rn_p $((P + 50)) >/dev/null 2>&1 || true
"$BIN" attach server rn_k $((P + 51)) --owner rn_p >/dev/null 2>&1 || true
"$BIN" stop rn_p >/dev/null 2>&1 || true
"$BIN" start rn_k >/dev/null 2>&1 || true
"$BIN" import rn_p '{"name":"rn_q"}' >/dev/null 2>&1 || true
if [ "$("$BIN" owner rn_k 2>/dev/null | awk -F: '$1=="owner"{print $2}')" = "rn_q" ]; then pass
else fail "a child names its parent's new name after an import renamed it" \
          "rn_k's owner is '$("$BIN" owner rn_k 2>/dev/null | awk -F: '$1=="owner"{print $2}')'"; fi
"$BIN" remove rn_q >/dev/null 2>&1 || true; "$BIN" remove rn_k >/dev/null 2>&1 || true

# ─── Cycle 1a: a runtime that owns itself, stopped ──────────────────────────
daemon_recover
"$BIN" attach server selfown $((P + 10)) --owner selfown >/dev/null 2>&1 || true
assert_daemon_survives "self-owning runtime survives stop" "$BIN" stop selfown

# And it really stopped, paired with the survival assertion because "the daemon
# is still up" is also true of a build that never ran the cascade at all.
if timeout 5 "$BIN" ping >/dev/null 2>&1; then
    if [ "$(state_of selfown)" = "Stopped" ]; then pass
    else fail "self-owning runtime actually stopped" \
              "expected Stopped, got '$(state_of selfown)'"; fi
fi

# ─── Cycle 1b: the same runtime, removed ────────────────────────────────────
#
# A separate case with its own fresh daemon, because `remove` fails differently
# from `stop`: remove_children() recurses without exhausting the stack, so the
# daemon keeps its socket and stops answering instead of dying.
daemon_recover
"$BIN" attach server selfrm $((P + 11)) --owner selfrm >/dev/null 2>&1 || true
assert_daemon_survives "self-owning runtime survives remove" "$BIN" remove selfrm

# ─── Cycle 2: two runtimes owning each other ────────────────────────────────
daemon_recover
"$BIN" attach server cyc_a $((P + 20)) --owner cyc_b >/dev/null 2>&1 || true
"$BIN" attach server cyc_b $((P + 21)) --owner cyc_a >/dev/null 2>&1 || true
assert_daemon_survives "two-runtime cycle survives stop" "$BIN" stop cyc_a

if timeout 5 "$BIN" ping >/dev/null 2>&1; then
    if [ "$(state_of cyc_a)" = "Stopped" ]; then pass
    else fail "two-runtime cycle: cyc_a stopped" \
              "expected Stopped, got '$(state_of cyc_a)'"; fi
fi

daemon_recover
"$BIN" attach server cyc_c $((P + 22)) --owner cyc_d >/dev/null 2>&1 || true
"$BIN" attach server cyc_d $((P + 23)) --owner cyc_c >/dev/null 2>&1 || true
assert_daemon_survives "two-runtime cycle survives remove" "$BIN" remove cyc_c

# The owner is persisted, so a restarted daemon meets the cycle again without
# anyone typing `attach` twice -- which is why validating set_owner alone would
# not be a fix.
daemon_recover
"$BIN" attach server persist_cyc $((P + 30)) --owner persist_cyc >/dev/null 2>&1 || true

# SIGTERM rather than a SIGKILL, because state is written by a background
# thread and a killed daemon leaves only a .tmp behind, so the runtime does not
# come back and the assertion fails for the wrong reason.
kill -TERM "$SOCKETLEY_DPID" 2>/dev/null || true
for _ in $(seq 1 50); do kill -0 "$SOCKETLEY_DPID" 2>/dev/null || break; sleep 0.1; done
daemon_sweep "$SOCKETLEY_SOCKET"
wait "$SOCKETLEY_DPID" 2>/dev/null || true
: > "$SOCKETLEY_DLOG"   # see daemon_recover
daemon_start "$BIN"

# The case only means something if the restore actually brought the cycle back.
if [ "$("$BIN" owner persist_cyc 2>/dev/null | awk -F: '$1=="owner"{print $2}')" = "persist_cyc" ]; then pass
else fail "the cycle came back from the state file" \
          "persist_cyc's owner did not survive the restart, so the case this" \
          "assertion is about was never exercised."; fi

# runtime_manager::stop() returns early for a runtime that is not running,
# before it collects any children, and `attach` does not set was_running -- so
# the state is asserted rather than assumed, since without it this passed
# against a build that crashes on every other cycle in the file.
"$BIN" start persist_cyc >/dev/null 2>&1 || true
case "$(state_of persist_cyc)" in
    Up*) pass ;;
    *)   fail "restored runtime is running before the stop" \
              "expected an uptime, got '$(state_of persist_cyc)'" \
              "a stop on a non-running runtime returns before the cascade," \
              "so the assertion below would pass without executing anything." ;;
esac

assert_daemon_survives "restored cycle survives stop" "$BIN" stop persist_cyc

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
if [ "$FAIL" -eq 0 ]; then echo "  OK"; else echo "  FAILED"; fi
exit "$FAIL"
