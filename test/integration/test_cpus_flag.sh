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

# start_daemon [env assignments...]
start_daemon() {
    [ -n "$DPID" ] && { kill "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null; }
    DPID=""
    rm -f "$SOCKETLEY_SOCKET"
    rm -rf "$HOME"; mkdir -p "$HOME"
    env "$@" "$BIN" daemon >/dev/null 2>&1 &
    DPID=$!
    for _ in $(seq 1 60); do
        [ -S "$SOCKETLEY_SOCKET" ] && "$BIN" ls >/dev/null 2>&1 && return 0
        sleep 0.1
    done
    echo "  FAIL: daemon did not come up"
    return 1
}

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
    out=$("$BIN" create server "cpus_$RANDOM" -p 19960 "$@" 2>&1) || rc=$?
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
    out=$("$BIN" create server "$name" -p 19961 "$@" 2>&1) || rc=$?
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

"$BIN" create server cpus_base -p 19951 -s >/dev/null 2>&1
sleep 0.3

[ "$(stat_field cpus_base sqpoll)" = "off" ] && ok || bad "default: stats says sqpoll=$(stat_field cpus_base sqpoll), expected off"
[ "$(stat_field cpus_base cpus)" = "max" ]   && ok || bad "default: stats says cpus=$(stat_field cpus_base cpus), expected max"
[ "$(stat_field cpus_base sq_thread_cpu)" = "-" ] && ok || bad "default: sq_thread_cpu should be - with no poller"

# The claim, measured: no poller means no polling kernel thread.
N=$(iou_threads)
[ "$N" -eq 0 ] && ok || bad "default: $N io_uring polling kernel thread(s), expected 0"

# A second and third runtime add no rings, so they add no threads either.  This
# is the whole reason the switch is not per runtime.
"$BIN" create cache cpus_c1 -p 19952 -s >/dev/null 2>&1
"$BIN" create server cpus_s2 -p 19953 -s >/dev/null 2>&1
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
"$BIN" create server cpus_sq -p 19954 -s >/dev/null 2>&1
sleep 0.3

MODE=$(stat_field cpus_sq sqpoll)
if [ "$MODE" = "off(refused)" ]; then
    echo "  SKIP: this kernel refuses an SQPOLL ring; the on-path cannot be checked here"
else
    [ "$MODE" = "on" ] && ok || bad "SOCKETLEY_SQPOLL=1: stats says sqpoll=$MODE, expected on"

    # Exactly one, not one per runtime: the thread belongs to the ring.
    N=$(iou_threads)
    [ "$N" -eq 1 ] && ok || bad "SOCKETLEY_SQPOLL=1: $N polling thread(s), expected exactly 1"

    "$BIN" create cache cpus_c2 -p 19955 -s >/dev/null 2>&1
    "$BIN" create server cpus_s3 -p 19956 -s >/dev/null 2>&1
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
    "$BIN" create server cpus_pin -p 19957 -s >/dev/null 2>&1
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

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
