#!/usr/bin/env bash
# Integration test: `stats` says how old an out-of-process runtime's figures are.
#
# ─── WHY THE AGE IS REPORTED AND NOT REMOVED ────────────────────────────────
#
# A worker's figures are pushed, not read.  The child publishes them every 250ms
# and the daemon drains the control socket before any command that prints them,
# so what `stats` shows is recent — but it is not read at the moment of the
# question, the way an in-process runtime's counters are.  Making it live would
# mean the daemon asking the child and waiting for the answer, on its event-loop
# thread, on a process it does not control: the synchronous cross-runtime call
# this design says no to everywhere else.
#
# So the difference stays, and is stated.  Every other figure is deliberately
# identical on both paths — that is the property the split was built to have —
# which is exactly what makes this one invisible without a label.
#
# ─── WHY THE STOPPED WORKER ─────────────────────────────────────────────────
#
# `figures_age_ms:0` is what a correct implementation prints most of the time,
# and it is also what `printf("figures_age_ms:0")` prints always.  A test that
# only reads the field cannot tell a measurement from a constant.  So the worker
# is stopped with SIGSTOP — it holds its figures and pushes nothing — and the
# number must be seen to grow by roughly the time it was stopped for, then to
# collapse again once it is resumed.  Three readings, and the shape of them is
# the assertion.
#
# The worker is found by walking /proc for a process whose /proc/PID/exe is this
# binary and whose parent is this test's daemon.  Never by a command-line
# pattern: an -f match one character too broad reaches the shell doing the
# matching.
#
# ─── THE CONTROL ────────────────────────────────────────────────────────────
#
# An in-process proxy must print NEITHER field.  Its counters are read live, so
# an age would be a fiction, and a build that printed the label unconditionally
# would be making exactly the claim this file exists to make honest.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"

daemon_isolate workerstatsage

BE_PORT=19490
PX_IN_PORT=19491
PX_OOP_PORT=19492
STOP_MS=1500

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

WORKER_PID=""
cleanup() {
    # Resume before anything else: a SIGSTOPped process cannot act on a SIGTERM,
    # and leaving one behind is exactly the leaked process this suite forbids.
    [ -n "$WORKER_PID" ] && kill -CONT "$WORKER_PID" 2>/dev/null || true
    "$BIN" stop   px_oop px_in backend 2>/dev/null || true
    sleep 0.3
    "$BIN" remove px_oop px_in backend 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: stats labels the age of a worker's figures ==="

daemon_start "$BIN"

# field NAME KEY -> the value, or the empty string.  Never a substituted zero:
# 0 is a legitimate reading of the age and "the field is not there" must not
# compare equal to it.
field() {
    "$BIN" stats "$1" 2>/dev/null | sed -n "s/^$2:\(.*\)$/\1/p" | head -1
}

# worker_pid -> the pid of the daemon's proxy-worker child, or the empty string.
#
# Identified by exe and by parent, never by a command-line pattern.  The exe test
# is a device+inode comparison through the symlink, which a shell can never
# satisfy; the parent test pins it to this test's own daemon, so a worker
# belonging to another run on this machine cannot be picked up — or signalled.
worker_pid() {
    local dpids p ppid
    # The runtime's own worker, named by the runtime.
    #
    # This used to walk /proc for the first child of this daemon whose exe is
    # $BIN, which was exact while a worker was the unusual case.  It stopped
    # being exact when a worker became the ordinary one: `backend` is created
    # first and is a worker too, so the walk found it, the test suspended the
    # backend, and px_oop went on publishing — its age stayed at 228 ms for a
    # 1500 ms stop, which reads as "the age does not grow" and is really "the
    # wrong process was stopped".
    #
    # `stats` prints pid: for a runtime with a process of its own, so the answer
    # is available by name.  Still checked against this daemon's children, which
    # is what keeps a stale pid from another test's daemon out.
    p=$(field "$1" pid)
    [ -n "$p" ] || return 0
    [ "/proc/$p/exe" -ef "$BIN" ] || return 0
    dpids=$(daemon_pids "$SOCKETLEY_SOCKET")
    ppid=$(awk '{ print $4 }' "/proc/$p/stat" 2>/dev/null) || return 0
    case " $dpids " in *" $ppid "*) printf '%s' "$p" ;; esac
}

create_ok "backend created" "$BIN" create server backend -p "$BE_PORT" -s
create_ok "in-process proxy created" "$BIN" create proxy px_in -p "$PX_IN_PORT" \
    --backend "127.0.0.1:$BE_PORT" --protocol http --daemon-process -s
create_ok "out-of-process proxy created" "$BIN" create proxy px_oop -p "$PX_OOP_PORT" \
    --backend "127.0.0.1:$BE_PORT" --protocol http -s

# Wait for the first push: before one has arrived the placeholder has nothing to
# be the age of, and that is a different thing from a stale one.
for _ in $(seq 1 60); do
    [ -n "$(field px_oop figures_age_ms)" ] && break
    sleep 0.1
done

# ── The label exists on the out-of-process path ─────────────────────────────
KIND=$(field px_oop figures)
if [ "$KIND" = "pushed" ]; then pass; else
    fail "stats says the figures were pushed" \
         "'figures' is '$KIND', wanted 'pushed'" \
         "an operator comparing this proxy's byte count against a backend's has" \
         "no way to know these were not read at the moment they were asked for"
fi

A0=$(field px_oop figures_age_ms)
if [ -n "$A0" ] && [ "$A0" -ge 0 ] 2>/dev/null; then pass; else
    fail "stats reports an age" \
         "'figures_age_ms' is '$A0', wanted a non-negative number"
fi

# ── Control: an in-process runtime claims nothing of the sort ───────────────
IN_KIND=$(field px_in figures)
IN_AGE=$(field px_in figures_age_ms)
if [ -z "$IN_KIND" ] && [ -z "$IN_AGE" ]; then pass; else
    fail "control: an in-process proxy reports no age" \
         "it printed figures='$IN_KIND' figures_age_ms='$IN_AGE'" \
         "its counters are read live, so an age is a fiction — and a build that" \
         "prints the label unconditionally is making the very claim this file" \
         "exists to make honest"
fi

# ── The number is a measurement, not a constant ─────────────────────────────
WORKER_PID=$(worker_pid px_oop)
if [ -n "$WORKER_PID" ]; then pass; else
    fail "setup: the worker process was found" \
         "no child of this daemon has $BIN as its exe" \
         "the three readings below cannot be taken"
fi

if [ -n "$WORKER_PID" ]; then
    kill -STOP "$WORKER_PID" 2>/dev/null || true
    sleep "$(awk "BEGIN { print $STOP_MS / 1000 }")"
    A_STOPPED=$(field px_oop figures_age_ms)
    kill -CONT "$WORKER_PID" 2>/dev/null || true
    sleep 0.6
    A_RESUMED=$(field px_oop figures_age_ms)

    # Grew by roughly the stop, allowing for the quarter-second publish interval
    # at each end.  A lower bound only: the box may be busy and the number may
    # legitimately be larger.
    if [ -n "$A_STOPPED" ] && [ "$A_STOPPED" -ge $((STOP_MS - 400)) ] 2>/dev/null; then
        pass
    else
        fail "the age grows while the worker is not publishing" \
             "after ${STOP_MS}ms stopped it read '$A_STOPPED', wanted at least $((STOP_MS - 400))" \
             "a field that does not move when the thing it measures does not" \
             "move is a constant with a name, not a measurement"
    fi

    # And collapses again — otherwise the number could be counting since the
    # worker started rather than since it last spoke.
    if [ -n "$A_RESUMED" ] && [ "$A_RESUMED" -lt 1000 ] 2>/dev/null; then
        pass
    else
        fail "the age collapses when the worker publishes again" \
             "after resuming it read '$A_RESUMED', wanted under 1000" \
             "an age that only ever grows is measuring the worker's lifetime," \
             "not the freshness of what it last said"
    fi
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
