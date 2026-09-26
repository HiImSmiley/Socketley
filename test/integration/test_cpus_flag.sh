#!/usr/bin/env bash
# suite: isolated -- a daemon, socket and port window of its own, so it runs beside the others
# Its own daemons on their own socket and state directory, because the CPU set
# is fixed when a ring is created so seeing two values takes two daemons -- and
# every one of them is killed by the pid this script started, never by name,
# since other agents have socketley daemons on this machine.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_ports.sh"
WORK=$(mktemp -d /tmp/socketley-cpus-XXXXXX)
export SOCKETLEY_SOCKET="$WORK/s.sock"
export HOME="$WORK/home"
mkdir -p "$HOME"

PASS=0; FAIL=0; TOTAL=0
DPID=""

cleanup() {
    [ -n "$DPID" ] && kill "$DPID" 2>/dev/null
    sleep 0.3
    rm -rf "$WORK"
}
trap cleanup EXIT

NCPU=$(nproc)

ok()   { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad()  { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL: $1"; }

DLOG="$WORK/daemon.log"

# Anything before `--` goes in the daemon's environment and anything after on
# its command line, which are the two routes the same setting can arrive by,
# with KEEP_STATE=1 for the sections about what a runtime carries over a
# restart.
KEEP_STATE=0
start_daemon() {
    local envs=() flags=() after=0 a
    for a in "$@"; do
        if [ "$a" = "--" ]; then after=1; continue; fi
        if [ "$after" -eq 0 ]; then envs+=("$a"); else flags+=("$a"); fi
    done

    [ -n "$DPID" ] && { kill "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null; }
    DPID=""
    rm -f "$SOCKETLEY_SOCKET"
    [ "$KEEP_STATE" -eq 1 ] || { rm -rf "$HOME"; mkdir -p "$HOME"; }
    : > "$DLOG"
    env ${envs[@]+"${envs[@]}"} "$BIN" daemon ${flags[@]+"${flags[@]}"} >"$DLOG" 2>&1 &
    DPID=$!
    for _ in $(seq 1 60); do
        [ -S "$SOCKETLEY_SOCKET" ] && "$BIN" ls >/dev/null 2>&1 && return 0
        sleep 0.1
    done
    echo "  FAIL: daemon did not come up"
    return 1
}

# The state file a runtime was persisted to, wherever paths.h decided to put it.
state_file() { find "$HOME" -name "$1.json" -print -quit 2>/dev/null; }

# The reason is checked as well as the failure, because a build without the
# flag answers "unknown flag: --cpus" with exit 1 and would satisfy an oracle
# that stopped at those two.
refuses() {
    local why=$1 expect=$2; shift 2
    local out rc=0
    out=$("$BIN" create server "cpus_$RANDOM" -p $((SL_PORT_BASE+960)) "$@" 2>&1) || rc=$?
    if [ "$rc" -eq 0 ];  then bad "$why: create succeeded, expected refusal"; return; fi
    if [ -z "$out" ];    then bad "$why: refused with exit $rc but printed nothing"; return; fi
    case "$out" in
        *"unknown flag"*)
            bad "$why: refused as an unknown flag — the feature is missing, not working"
            return ;;
    esac
    case "$out" in
        *"$expect"*) ok ;;
        *) bad "$why: refused, but for the wrong reason: $out" ;;
    esac
}

accepts() {
    local why=$1; shift
    local name="cpus_$RANDOM"
    local out rc=0
    out=$("$BIN" create server "$name" -p $((SL_PORT_BASE+961)) "$@" 2>&1) || rc=$?
    "$BIN" remove "$name" >/dev/null 2>&1
    if [ "$rc" -ne 0 ]; then bad "$why: create failed (rc=$rc): $out"; return; fi
    ok
}

stat_field() {   # <runtime> <field>
    "$BIN" stats "$1" 2>/dev/null | grep "^$2:" | head -1 | cut -d: -f2-
}

echo "=== Integration: --cpus ($NCPU CPUs online) ==="

# ─── 1. A daemon nobody pinned ──────────────────────────────────────────────
start_daemon SOCKETLEY_TEST=1 || exit 1

"$BIN" create server cpus_base -p $((SL_PORT_BASE+951)) -s >/dev/null 2>&1
sleep 0.3

[ "$(stat_field cpus_base cpus)" = "max" ]   && ok || bad "default: stats says cpus=$(stat_field cpus_base cpus), expected max"

# ─── 2. Sets this machine cannot satisfy ────────────────────────────────────
refuses "a CPU that does not exist"     "does not exist on this machine" --cpus "$NCPU-$NCPU"
refuses "a range past the last CPU"     "does not exist on this machine" --cpus "0-$NCPU"
refuses "a descending range"            "descending CPU range"           --cpus 3-1
refuses "a non-numeric CPU"             "not a CPU number"               --cpus abc
refuses "an empty element"              "empty element in CPU set"       --cpus 0,,1
refuses "a trailing comma"              "trailing comma in CPU set"      --cpus 0,
refuses "no value at all"               "--cpus requires a CPU set"      --cpus
refuses "an absurd CPU number"          "not a CPU number"               --cpus 999

accepts "max on any machine"            --cpus max

if [ "$NCPU" -ge 2 ]; then
    refuses "a CPU set the shared I/O thread is not pinned to" "already pinned to" --cpus 0
fi

# ─── 3. edit cannot change it ───────────────────────────────────────────────
# The reason is checked rather than the exit code, because "unknown flag" is
# also a refusal with a message and is what a build without the feature
# answers.
rc=0
out=$("$BIN" edit cpus_base --cpus max 2>&1) || rc=$?
if [ "$rc" -eq 0 ]; then
    bad "edit --cpus max: succeeded, but a ring's CPU set cannot be changed"
else
    case "$out" in
        *"fixed when the ring is created"*) ok ;;
        *) bad "edit --cpus max: refused for the wrong reason: '$out'" ;;
    esac
fi

# ─── 4. A pinned daemon ─────────────────────────────────────────────────────
if [ "$NCPU" -ge 2 ]; then
    SET="0-1"
    start_daemon SOCKETLEY_CPUS="$SET" || exit 1
    "$BIN" create server cpus_pin -p $((SL_PORT_BASE+957)) -s >/dev/null 2>&1
    sleep 0.3

    REPORTED=$(stat_field cpus_pin cpus)
    [ "$REPORTED" = "$SET" ] && ok || bad "SOCKETLEY_CPUS=$SET: stats says cpus=$REPORTED"

    # Reported is not the same as applied.  Ask the kernel.
    AFF=$(taskset -pc "$DPID" 2>/dev/null | sed 's/.*list: //')
    case "$AFF" in
        0-1|0,1) ok ;;
        *) bad "SOCKETLEY_CPUS=$SET: the I/O thread's real affinity is '$AFF'" ;;
    esac

    accepts "a request that matches the ring" --cpus "$SET"
    refuses "a request that does not"         "already pinned to" --cpus max
else
    echo "  SKIP: pinning checks need at least 2 CPUs"
fi

# ─── 5. The daemon's own command line ───────────────────────────────────────
# `socketley daemon` used to ignore argv entirely, so each oracle here runs
# under `timeout` and reaching it is the failure -- a daemon that discarded the
# argument never returns -- and each names the reason it expects, since exit 1
# with text is what an unknown flag produces.

stop_daemon() {
    [ -n "$DPID" ] && { kill "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null; }
    DPID=""
    for _ in $(seq 1 50); do [ -S "$SOCKETLEY_SOCKET" ] || break; sleep 0.1; done
    rm -f "$SOCKETLEY_SOCKET"
}

# daemon_refuses <why> <expected-substring> <args...>
daemon_refuses() {
    local why=$1 expect=$2; shift 2
    local out rc=0
    out=$(timeout 5 "$BIN" daemon "$@" 2>&1) || rc=$?
    if [ "$rc" -eq 124 ]; then
        bad "$why: the daemon started and ran on — the argument was ignored, not refused"
        return
    fi
    if [ "$rc" -eq 0 ]; then bad "$why: exited 0, expected a refusal"; return; fi
    if [ -z "$out" ]; then bad "$why: refused with exit $rc but printed nothing"; return; fi
    case "$out" in
        *"$expect"*) ok ;;
        *) bad "$why: refused, but not for the expected reason: $out" ;;
    esac
}

# No daemon on this socket: these have to be refused on the real startup path,
# not merely by the "one is already running" check further down it.
stop_daemon
daemon_refuses "a flag the daemon has never heard of" "unknown daemon flag" --not-a-real-flag
daemon_refuses "--cpus with nothing after it"         "--cpus requires a CPU set" --cpus
daemon_refuses "a descending range on the daemon"     "descending CPU range" --cpus 3-1
daemon_refuses "a CPU this machine does not have"     "does not exist on this machine" --cpus "$NCPU-$NCPU"

# --cpus as a flag does what SOCKETLEY_CPUS does, read back from the kernel and
# not from the daemon's own report.
if [ "$NCPU" -ge 2 ]; then
    start_daemon -- --cpus 0-1 || exit 1
    "$BIN" create server cpus_flagpin -p $((SL_PORT_BASE+963)) -s >/dev/null 2>&1
    sleep 0.3
    [ "$(stat_field cpus_flagpin cpus)" = "0-1" ] && ok \
        || bad "daemon --cpus 0-1: stats says cpus=$(stat_field cpus_flagpin cpus)"
    AFF=$(taskset -pc "$DPID" 2>/dev/null | sed 's/.*list: //')
    case "$AFF" in
        0-1|0,1) ok ;;
        *) bad "daemon --cpus 0-1: the I/O thread's real affinity is '$AFF'" ;;
    esac
    # And a runtime asking for the same set is now accepted, which is the whole
    # point of being able to say it on the command line.
    accepts "a runtime request the flag satisfies" --cpus 0-1
fi

# A flag beats the environment, because SOCKETLEY_CPUS is exported once and
# forgotten while --cpus is typed for this run.
if [ "$NCPU" -ge 2 ]; then
    start_daemon SOCKETLEY_CPUS=max -- --cpus 0-1 || exit 1
    "$BIN" create server cpus_over -p $((SL_PORT_BASE+964)) -s >/dev/null 2>&1
    sleep 0.3
    [ "$(stat_field cpus_over cpus)" = "0-1" ] && ok \
        || bad "--cpus 0-1 under SOCKETLEY_CPUS=max: stats says cpus=$(stat_field cpus_over cpus)"
fi

# What was lost by not persisting these was the requirement rather than the
# placement, so a runtime created with --cpus 0 came back on an unpinned ring
# reporting cpus:max -- and both halves are checked, since a build could write
# the request to the file and do nothing with what it read.
SET7=0
start_daemon SOCKETLEY_CPUS="$SET7" || exit 1
"$BIN" create server cpus_keep   -p $((SL_PORT_BASE+965)) --cpus "$SET7" -s >/dev/null 2>&1
"$BIN" create server cpus_plain  -p $((SL_PORT_BASE+967)) -s >/dev/null 2>&1
sleep 0.5

F=$(state_file cpus_keep)
if [ -z "$F" ]; then
    bad "persistence: cpus_keep has no state file at all"
else
    grep -q "\"cpus\": \"$SET7\"" "$F" && ok \
        || bad "persistence: --cpus $SET7 is not in the state file: $(tr -d '\n' <"$F")"
fi

# A runtime that asked for nothing must carry nothing, or every plain `create`
# becomes an explicit CPU set on the next boot.
F=$(state_file cpus_plain)
if [ -z "$F" ]; then
    bad "persistence: cpus_plain has no state file at all"
elif grep -qE '"cpus"' "$F"; then
    bad "persistence: a runtime that asked for nothing carries a request: $(tr -d '\n' <"$F")"
else
    ok
fi

# Restart onto a ring that cannot meet the persisted request.
KEEP_STATE=1 start_daemon || exit 1
sleep 0.5

LINE=$("$BIN" ls 2>/dev/null | grep -E "[[:space:]]cpus_keep[[:space:]]")
case "$LINE" in
    *Failed*) ok ;;
    "")       bad "restore refusal: cpus_keep is not listed at all after the restart" ;;
    *)        bad "restore refusal: cpus_keep came up anyway — '$LINE'" ;;
esac

# The reason rather than merely the failure, because a build that failed every
# restore would satisfy the check above.
grep -q "already pinned to" "$DLOG" && ok \
    || bad "restore refusal: the daemon never said why — log: $(tr '\n' '|' <"$DLOG")"

# A runtime that asked for nothing must still come back up, without which every
# assertion above is satisfied by a daemon that restores nothing at all.
LINE=$("$BIN" ls 2>/dev/null | grep -E "[[:space:]]cpus_plain[[:space:]]")
case "$LINE" in
    *Up*) ok ;;
    *)    bad "restore: a runtime with no ring request did not come back — '$LINE'" ;;
esac

# And onto a ring that does meet it, by the flag this time rather than the
# environment it was created under.
KEEP_STATE=1 start_daemon -- --cpus "$SET7" || exit 1
sleep 0.5
LINE=$("$BIN" ls 2>/dev/null | grep -E "[[:space:]]cpus_keep[[:space:]]")
case "$LINE" in
    *Up*) ok ;;
    *)    bad "restore: cpus_keep did not come back on a ring that meets its request — '$LINE'" ;;
esac

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
