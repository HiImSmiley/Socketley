#!/usr/bin/env bash
# suite: quiet -- one assertion times a `stats` round trip against a SIGSTOPped
# worker, which is a bound on wall-clock delay and not on the code under test.
# Integration test: an out-of-process runtime's figures are read when they are
# printed.
#
# ─── WHAT THIS REPLACED ─────────────────────────────────────────────────────
#
# This file used to assert the opposite property and was right to.  A worker's
# figures were PUSHED: the child published them every 250 ms and the daemon
# drained the control socket before any command that printed them, so what
# `stats` showed was recent but was not read at the moment of the question the
# way an in-process runtime's counters are.  `stats` said so, in figures:pushed
# and figures_age_ms, and this file made that label honest by stopping the
# worker and watching the age grow.
#
# The counters moved into a shared-memory region — shard_stats.h.  Each worker
# stores its line once per turn of its event loop; the daemon sums the slots as
# it prints.  There is no interval left between the reading and the printing, so
# the two labels have nothing to say and are gone, and what has to be pinned
# instead is the property that took their place.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
# 1  the labels are gone, on BOTH paths.  A build that reintroduces a pushed
#    figure has to print an age again; one that pushes without printing an age
#    is worse than the build this change replaced, because the staleness is then
#    unlabelled.  Asserted of the in-process proxy too, which is the control:
#    the two paths now print the same shape, which is the whole claim.
#
# 2  the first read already sees it.  The discriminating assertion, and the one
#    a slower publish cannot pass: a connection is opened and `stats` is asked
#    once, immediately.  Measured on this box before the change, 253 ms median
#    to see a new connection; after it, 4 ms, which is the CLI round trip.  Ten
#    attempts, because a single one is a coin toss against a publish whose phase
#    this script does not control.
#
# 3  a stopped worker does not stop `stats`.  The obvious way to make figures
#    live is to ask the child and wait for the answer, which is the synchronous
#    cross-runtime call this design refuses everywhere else — and the failure it
#    produces is not a wrong number, it is a CLI that hangs.  So the worker is
#    SIGSTOPped and `stats` has to answer anyway, out of the line that worker
#    last wrote.  A reader that cannot be delayed by a writer is the property
#    shard_stats.h is built on and this is where it is exercised.
#
# 4  and the figure it answers with is the one that was true.  A wait-free read
#    that returned zero when the writer was descheduled would pass 3 and be
#    useless; the count taken before the stop has to survive it.
#
# The worker is found by walking /proc for a process whose /proc/PID/exe is this
# binary and whose parent is this test's daemon.  Never by a command-line
# pattern: an -f match one character too broad reaches the shell doing the
# matching.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate workerstatslive

BE_PORT=$((SL_PORT_BASE+490))
PX_IN_PORT=$((SL_PORT_BASE+491))
PX_OOP_PORT=$((SL_PORT_BASE+492))

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

echo "=== Integration: a worker's figures are read when they are printed ==="

daemon_start "$BIN"

# field NAME KEY -> the value, or the empty string.  Never a substituted zero:
# 0 is a legitimate reading and "the field is not there" must not compare equal
# to it.
field() {
    "$BIN" stats "$1" 2>/dev/null | sed -n "s/^$2:\(.*\)$/\1/p" | head -1
}

# worker_pid -> the pid of the named runtime's worker, or the empty string.
#
# Identified by exe and by parent, never by a command-line pattern.  The exe test
# is a device+inode comparison through the symlink, which a shell can never
# satisfy; the parent test pins it to this test's own daemon, so a worker
# belonging to another run on this machine cannot be picked up — or signalled.
#
# By NAME and not "the first worker of this daemon": `backend` is created first
# and is a worker too, so a walk of the daemon's children finds it, and a test
# that stopped the wrong process measured a figure that never moved and read it
# as a property of the build.
worker_pid() {
    local dpids p ppid
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

# Wait for the worker to be answering for itself.  Before its first frame the
# placeholder is not worker-backed and prints its own empty containers, which is
# a different state from the one under test.
for _ in $(seq 1 100); do
    [ -n "$(field px_oop pid)" ] && break
    sleep 0.1
done

# ── 1: neither path claims an age, because neither has one ──────────────────
OOP_LABEL=$("$BIN" stats px_oop 2>/dev/null | grep -c '^figures:\|^figures_age_ms:')
IN_LABEL=$("$BIN"  stats px_in  2>/dev/null | grep -c '^figures:\|^figures_age_ms:')
if [ "$OOP_LABEL" -eq 0 ] && [ "$IN_LABEL" -eq 0 ]; then pass; else
    fail "no figure on either path is labelled as pushed" \
         "out-of-process printed $OOP_LABEL such line(s), in-process $IN_LABEL" \
         "those labels exist only where a figure is pushed on a timer.  A build" \
         "that prints one is pushing again; a build that pushes and prints none" \
         "is stale without saying so, which is worse than what this replaced"
fi

# ── 2: the first read already sees a new connection ─────────────────────────
#
# bash's own /dev/tcp, so the connection is held by this shell and closes with
# the descriptor rather than with somebody else's process.
FRESH=0; ATTEMPTS=10
for _ in $(seq 1 $ATTEMPTS); do
    if exec 8<>"/dev/tcp/127.0.0.1/$PX_OOP_PORT" 2>/dev/null; then
        SEEN=$(field px_oop connections)
        [ "$SEEN" = "1" ] && FRESH=$((FRESH+1))
        exec 8>&-
        # Back to zero before the next attempt, so each one asks the same
        # question.  Bounded: a reap this loop never sees would otherwise make
        # every later attempt read 1 for the wrong reason.
        for _ in $(seq 1 60); do
            [ "$(field px_oop connections)" = "0" ] && break
            sleep 0.05
        done
    fi
done
if [ "$FRESH" -ge $((ATTEMPTS - 1)) ]; then pass; else
    fail "the first stats after a connection sees it" \
         "it did on $FRESH of $ATTEMPTS attempts, wanted at least $((ATTEMPTS - 1))" \
         "a figure summed at print time cannot be behind the loop turn that" \
         "counted the accept.  A score near zero is a pushed figure back in" \
         "front of these counters — see runtime_instance::worker_figures()"
fi

# ── 3 & 4: a worker that cannot run does not hold up the answer ─────────────
WORKER_PID=$(worker_pid px_oop)
if [ -n "$WORKER_PID" ]; then pass; else
    fail "setup: the worker process was found" \
         "stats printed no pid: for px_oop, or it is not a child of this daemon" \
         "the two readings below cannot be taken"
fi

if [ -n "$WORKER_PID" ]; then
    # One connection, seen, and only then is the worker stopped: the figure the
    # stopped worker has to keep answering with must be one it was ever asked
    # about.  An identity assertion over 0 passes on a build that answers 0 to
    # everything.
    exec 8<>"/dev/tcp/127.0.0.1/$PX_OOP_PORT" 2>/dev/null || true
    BEFORE=""
    for _ in $(seq 1 60); do
        BEFORE=$(field px_oop connections)
        [ "$BEFORE" = "1" ] && break
        sleep 0.05
    done

    kill -STOP "$WORKER_PID" 2>/dev/null || true
    S=$(date +%s%3N)
    STOPPED=$(field px_oop connections)
    E=$(date +%s%3N)
    MS=$((E - S))
    kill -CONT "$WORKER_PID" 2>/dev/null || true
    exec 8>&-

    # 1000 ms.  A `stats` that is answered out of shared memory takes the same
    # few milliseconds it always does; one that asks the child and waits does
    # not come back at all while the child is stopped, and whatever timeout it
    # eventually hits is longer than this.  The bound is loose on purpose — it
    # is separating "answered" from "did not answer", not timing a fast path.
    if [ "$MS" -le 1000 ]; then pass; else
        fail "stats answers while the worker is stopped" \
             "it took ${MS} ms against a SIGSTOPped worker" \
             "a reader of this table cannot be delayed by a writer that is not" \
             "running; a number this large means the daemon is waiting for one"
    fi

    if [ "$BEFORE" = "1" ] && [ "$STOPPED" = "1" ]; then pass; else
        fail "and answers with the figure that was true" \
             "before the stop it read '$BEFORE', during it '$STOPPED', wanted 1 and 1" \
             "the stopped worker's line is still in the region and is still the" \
             "last thing that was true of it.  A 0 here is a reader that treats" \
             "a descheduled writer as an absent one"
    fi
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
