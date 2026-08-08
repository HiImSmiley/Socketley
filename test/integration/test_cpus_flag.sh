#!/usr/bin/env bash
# Integration test: --cpus and --sqpoll.
#
# Runs its own daemons on their own socket and state directory rather than the
# shared one the rest of the suite uses.  It has to: the two things under test
# are fixed when a ring is created, so the only way to see both values is to
# start a daemon for each, and starting one on the shared socket would take the
# suite's daemon down with it.
#
# Every daemon here is killed by the pid this script started, never by name.
# Other agents and other suites have socketley daemons on the same machine and a
# name-matched kill takes them too.
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

# start_daemon [env assignments...] [-- daemon flags...]
#
# Anything before `--` is put in the daemon's environment, anything after it on
# its command line.  The two halves are the same two settings arriving by the
# two routes that exist, and section 6 is about them disagreeing.
#
# KEEP_STATE=1 leaves the state directory alone across the restart, for the
# sections that are about what a runtime carries over one.  It defaults to 0
# because every section before those wants a daemon with nothing restored.
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

# How many io_uring submission-polling kernel threads the daemon process holds.
# This is the figure the whole change is about: it used to be one per ring
# unconditionally, and a ring exists per process.
iou_threads() {
    local n=0 t
    for t in /proc/"$DPID"/task/*; do
        [ -r "$t/comm" ] || continue
        case "$(cat "$t/comm" 2>/dev/null)" in iou-sqp-*) n=$((n+1));; esac
    done
    echo "$n"
}

# refuses <reason> <expected-substring> <flags...>
#
# create must fail, say something, and say the right thing.  The last part is
# not decoration: a build in which --cpus does not exist at all answers "unknown
# flag: --cpus" with exit 1 and would satisfy an oracle that only checked those
# first two.  Checking for "unknown flag" explicitly is what stops this whole
# file passing against a binary that has none of the feature in it.
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

echo "=== Integration: --cpus / --sqpoll ($NCPU CPUs online) ==="

# ─── 1. A daemon nobody asked for a poller ──────────────────────────────────
start_daemon SOCKETLEY_TEST=1 || exit 1

"$BIN" create server cpus_base -p $((SL_PORT_BASE+951)) -s >/dev/null 2>&1
sleep 0.3

[ "$(stat_field cpus_base sqpoll)" = "off" ] && ok || bad "default: stats says sqpoll=$(stat_field cpus_base sqpoll), expected off"
[ "$(stat_field cpus_base cpus)" = "max" ]   && ok || bad "default: stats says cpus=$(stat_field cpus_base cpus), expected max"
[ "$(stat_field cpus_base sq_thread_cpu)" = "-" ] && ok || bad "default: sq_thread_cpu should be - with no poller"

# The claim, measured: no poller means no polling kernel thread.
N=$(iou_threads)
[ "$N" -eq 0 ] && ok || bad "default: $N io_uring polling kernel thread(s), expected 0"

# A second and third runtime add no rings, so they add no threads either.  This
# is the whole reason the switch is not per runtime.
"$BIN" create cache cpus_c1 -p $((SL_PORT_BASE+952)) -s >/dev/null 2>&1
"$BIN" create server cpus_s2 -p $((SL_PORT_BASE+953)) -s >/dev/null 2>&1
sleep 0.3
N=$(iou_threads)
[ "$N" -eq 0 ] && ok || bad "three runtimes, no poller: $N polling thread(s), expected 0"

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
accepts "--no-sqpoll on a poller-less ring" --no-sqpoll

# A ring without a poller cannot be given one after the fact, and saying so is
# the point — this must not silently succeed and do nothing.
refuses "--sqpoll against a ring that has none" "created without a submission poller" --sqpoll

if [ "$NCPU" -ge 2 ]; then
    refuses "a CPU set the shared I/O thread is not pinned to" "already pinned to" --cpus 0
fi

# ─── 3. edit cannot change either ───────────────────────────────────────────
# The reason is checked, not just the exit code: "unknown flag" is also a
# refusal with a message, and it is the answer a build without the feature
# gives.  What edit must say is why the kernel will not let it happen.
for f in "--cpus max" "--sqpoll" "--no-sqpoll"; do
    rc=0
    out=$("$BIN" edit cpus_base $f 2>&1) || rc=$?
    if [ "$rc" -eq 0 ]; then
        bad "edit $f: succeeded, but a ring's flags cannot be changed"
    else
        case "$out" in
            *"fixed when the ring is created"*) ok ;;
            *) bad "edit $f: refused for the wrong reason: '$out'" ;;
        esac
    fi
done

# ─── 4. A daemon that was asked for a poller ────────────────────────────────
start_daemon SOCKETLEY_SQPOLL=1 || exit 1
"$BIN" create server cpus_sq -p $((SL_PORT_BASE+954)) -s >/dev/null 2>&1
sleep 0.3

MODE=$(stat_field cpus_sq sqpoll)
if [ "$MODE" = "off(refused)" ]; then
    echo "  SKIP: this kernel refuses an SQPOLL ring; the on-path cannot be checked here"
else
    [ "$MODE" = "on" ] && ok || bad "SOCKETLEY_SQPOLL=1: stats says sqpoll=$MODE, expected on"

    # Exactly one, not one per runtime: the thread belongs to the ring.
    N=$(iou_threads)
    [ "$N" -eq 1 ] && ok || bad "SOCKETLEY_SQPOLL=1: $N polling thread(s), expected exactly 1"

    "$BIN" create cache cpus_c2 -p $((SL_PORT_BASE+955)) -s >/dev/null 2>&1
    "$BIN" create server cpus_s3 -p $((SL_PORT_BASE+956)) -s >/dev/null 2>&1
    sleep 0.3
    N=$(iou_threads)
    [ "$N" -eq 1 ] && ok || bad "three runtimes on one ring: $N polling thread(s), expected 1"

    accepts "--sqpoll against a ring that has one" --sqpoll
    refuses "--no-sqpoll against a ring that has one" "created with a submission poller" --no-sqpoll
fi

# ─── 5. A pinned daemon ─────────────────────────────────────────────────────
if [ "$NCPU" -ge 2 ]; then
    SET="0-1"
    start_daemon SOCKETLEY_SQPOLL=1 SOCKETLEY_CPUS="$SET" || exit 1
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

    if [ "$(stat_field cpus_pin sqpoll)" = "on" ]; then
        # Documented behaviour: io_uring takes one CPU for the poller, not a
        # mask, so it lands on the lowest member of the set.
        [ "$(stat_field cpus_pin sq_thread_cpu)" = "0" ] && ok \
            || bad "poller should be on CPU 0, stats says $(stat_field cpus_pin sq_thread_cpu)"
    fi

    accepts "a request that matches the ring" --sqpoll --cpus "$SET"
    refuses "a request that does not"         "already pinned to" --sqpoll --cpus max
else
    echo "  SKIP: pinning checks need at least 2 CPUs"
fi

# ─── 6. The daemon's own command line ───────────────────────────────────────
# `socketley daemon` used to ignore argv entirely.  --sqpoll, --cpus and a plain
# misspelling all started a daemon and exited 0, so the two settings could only
# be given through the environment and an operator who typed them as flags was
# told nothing at all.
#
# Every oracle below has to tell "refused" apart from "started a daemon and
# discarded the argument", which an oracle reading only stdout and an exit code
# cannot do: a daemon that ignores its command line never returns.  So each runs
# under `timeout`, and a run that reaches the timeout is the failure — the
# daemon came up.  Each also names the reason it expects, because exit 1 with
# text on stdout is what a build with none of this answers to an unknown flag.

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

# A flag beats the environment.  Without this the two routes fight and the one
# that wins is the one nobody typed: SOCKETLEY_SQPOLL is usually exported once
# and forgotten, --no-sqpoll is typed for this run.
start_daemon SOCKETLEY_SQPOLL=1 -- --no-sqpoll || exit 1
"$BIN" create server cpus_over -p $((SL_PORT_BASE+964)) -s >/dev/null 2>&1
sleep 0.3
[ "$(stat_field cpus_over sqpoll)" = "off" ] && ok \
    || bad "--no-sqpoll under SOCKETLEY_SQPOLL=1: stats says sqpoll=$(stat_field cpus_over sqpoll)"
N=$(iou_threads)
[ "$N" -eq 0 ] && ok || bad "--no-sqpoll under SOCKETLEY_SQPOLL=1: $N polling thread(s), expected 0"

# ─── 7. A request survives the daemon that accepted it ──────────────────────
# --cpus and --sqpoll were not written to the state file.  Because a ring
# belongs to a process, losing them never moved a restored runtime's I/O — it
# was always going to run wherever the new daemon's ring runs.  What was lost
# was the requirement, and with it the refusal: a runtime created with
# --cpus 0 came back on an unpinned ring, reported cpus:max, and said nothing.
#
# Both halves are checked, and they are different claims.  That the request is
# in the file is one; that a restored runtime whose request the new ring cannot
# meet fails loudly is the other, and a build could pass the first while doing
# nothing with what it read.
SET7=0
start_daemon SOCKETLEY_CPUS="$SET7" || exit 1
"$BIN" create server cpus_keep   -p $((SL_PORT_BASE+965)) --cpus "$SET7" -s >/dev/null 2>&1
"$BIN" create server cpus_nosq   -p $((SL_PORT_BASE+966)) --no-sqpoll -s >/dev/null 2>&1
"$BIN" create server cpus_plain  -p $((SL_PORT_BASE+967)) -s >/dev/null 2>&1
sleep 0.5

F=$(state_file cpus_keep)
if [ -z "$F" ]; then
    bad "persistence: cpus_keep has no state file at all"
else
    grep -q "\"cpus\": \"$SET7\"" "$F" && ok \
        || bad "persistence: --cpus $SET7 is not in the state file: $(tr -d '\n' <"$F")"
fi

F=$(state_file cpus_nosq)
if [ -z "$F" ]; then
    bad "persistence: cpus_nosq has no state file at all"
else
    grep -q '"sqpoll": false' "$F" && ok \
        || bad "persistence: --no-sqpoll is not in the state file: $(tr -d '\n' <"$F")"
fi

# A runtime that asked for neither must carry neither.  Writing the default
# value of a flag nobody typed would turn every plain `create` into an explicit
# --no-sqpoll on the next boot, and a daemon whose ring has a poller would then
# refuse to restore runtimes that never had an opinion about one.
F=$(state_file cpus_plain)
if [ -z "$F" ]; then
    bad "persistence: cpus_plain has no state file at all"
elif grep -qE '"(cpus|sqpoll)"' "$F"; then
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

# The reason, not merely the failure.  A build that failed every restore for any
# reason would satisfy the check above.
grep -q "already pinned to" "$DLOG" && ok \
    || bad "restore refusal: the daemon never said why — log: $(tr '\n' '|' <"$DLOG")"

# Vacuity guard, and the more important half of it: a runtime that asked for
# nothing must still come back up.  Without this every assertion above is also
# satisfied by a daemon that restores nothing at all.
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
