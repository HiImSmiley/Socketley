#!/usr/bin/env bash
# suite: quiet -- one assertion times a `stats` round trip against a SIGSTOPped
# worker, which is a bound on wall-clock delay rather than on the code under
# test.
# ─── WHAT THIS REPLACED ─────────────────────────────────────────────────────
# This file used to assert the opposite property and was right to, but the
# counters moved into a shared-memory region each worker stores into once per
# loop turn and the daemon sums as it prints -- so there is no interval left
# between the reading and the printing, the figures:pushed and figures_age_ms
# labels are gone, and what has to be pinned is the property that took their
# place.
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
# Four claims: the labels are gone on both paths, with the in-process proxy as
# the control since the two now print the same shape; how long after a
# connection the runtime says so, taken as the median of ten because a single
# attempt against a publish whose phase this script does not control is a coin
# toss; a SIGSTOPped worker does not stop `stats`, because the obvious way to
# make figures live is to ask the child and wait, whose failure is a CLI that
# hangs; and the figure it answers with is the one that was true, since a
# wait-free read returning zero would pass the third and be useless -- with the
# worker found by walking /proc for an exe and a parent, never by a
# command-line pattern.
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

# Never a substituted zero, because 0 is a legitimate reading and "the field is
# not there" must not compare equal to it.
field() {
    "$BIN" stats "$1" 2>/dev/null | sed -n "s/^$2:\(.*\)$/\1/p" | head -1
}

# Identified by exe and by parent so a worker belonging to another run cannot
# be picked up or signalled, and by name rather than "the first worker of this
# daemon" -- since stopping the wrong process measures a figure that never
# moved and reads it as a property of the build.
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
    --backend "127.0.0.1:$BE_PORT" --protocol http -s
create_ok "out-of-process proxy created" "$BIN" create proxy px_oop -p "$PX_OOP_PORT" \
    --backend "127.0.0.1:$BE_PORT" --protocol http -s

# Wait for the worker to be answering for itself, on `mesh_links:` rather than
# on `pid:` -- which the supervisor writes at the fork, so reading the labels
# in the window before the first frame passed against a build that does print
# figures:pushed.
for _ in $(seq 1 100); do
    "$BIN" stats px_oop 2>/dev/null | grep -q '^mesh_links:' && break
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

# The discriminating measurement, timing the interval between a connection and
# the count moving, as the median of ten with the first attempt discarded
# because it is the one that makes this proxy dial its backend -- with 9999 the
# sentinel for a count that never moved, which against a pushed figure is a
# real reading, since a reap and an accept landing in the same publish alias to
# no change at all.
lag_once() {                       # -> milliseconds, or 9999 if it never moved
    local base t0 v i
    base=$(field px_oop connections)
    case "$base" in ''|*[!0-9]*) printf '9999'; return ;; esac
    exec 8<>"/dev/tcp/127.0.0.1/$PX_OOP_PORT" 2>/dev/null || { printf '9999'; return; }
    t0=$(date +%s%3N)
    v="$base"
    for i in $(seq 1 400); do
        v=$(field px_oop connections)
        [ "$v" != "$base" ] && break
    done
    if [ "$v" = "$base" ]; then printf '9999'
    else printf '%s' "$(( $(date +%s%3N) - t0 ))"; fi
    exec 8>&-
    # Back to the baseline before the next attempt and bounded, because a reap
    # this loop never sees would leave the count high and make the next attempt
    # time the wrong transition.
    for i in $(seq 1 60); do
        [ "$(field px_oop connections)" = "$base" ] && break
        sleep 0.05
    done
}

lag_once >/dev/null                # warm-up: the backend handshake, see above
LAGS=""
for _ in $(seq 1 10); do LAGS="$LAGS $(lag_once)"; done
MEDIAN=$(printf '%s\n' $LAGS | sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}')
echo "  lag from connection to stats reporting it: median ${MEDIAN} ms ($LAGS )"

# 100 ms separates two mechanisms rather than timing a fast path, so the margin
# is what matters and not the tightness.
if [ "$MEDIAN" -le 100 ] 2>/dev/null; then pass; else
    fail "a connection is visible as soon as it is asked about" \
         "the median lag over ten attempts was ${MEDIAN} ms, bound 100" \
         "a figure summed at print time cannot be behind the loop turn that" \
         "counted the accept.  A median near a publish period is a pushed" \
         "figure back in front of these counters — see worker_figures()"
fi

# ── 3 & 4: a worker that cannot run does not hold up the answer ─────────────
WORKER_PID=$(worker_pid px_oop)
if [ -n "$WORKER_PID" ]; then pass; else
    fail "setup: the worker process was found" \
         "stats printed no pid: for px_oop, or it is not a child of this daemon" \
         "the two readings below cannot be taken"
fi

if [ -n "$WORKER_PID" ]; then
    # One connection, seen, and only then is the worker stopped, because an
    # identity assertion over 0 passes on a build that answers 0 to everything.
    HELD_BASE=$(field px_oop connections)
    exec 8<>"/dev/tcp/127.0.0.1/$PX_OOP_PORT" 2>/dev/null || true
    WANT=$((HELD_BASE + 1))
    BEFORE=""
    for _ in $(seq 1 60); do
        BEFORE=$(field px_oop connections)
        [ "$BEFORE" = "$WANT" ] && break
        sleep 0.05
    done

    kill -STOP "$WORKER_PID" 2>/dev/null || true
    S=$(date +%s%3N)
    STOPPED=$(field px_oop connections)
    E=$(date +%s%3N)
    MS=$((E - S))
    kill -CONT "$WORKER_PID" 2>/dev/null || true
    exec 8>&-

    # A loose 1000 ms, separating "answered" from "did not answer": a read out
    # of shared memory takes its usual few milliseconds while one that asks a
    # stopped child does not come back at all.
    if [ "$MS" -le 1000 ]; then pass; else
        fail "stats answers while the worker is stopped" \
             "it took ${MS} ms against a SIGSTOPped worker" \
             "a reader of this table cannot be delayed by a writer that is not" \
             "running; a number this large means the daemon is waiting for one"
    fi

    if [ "$BEFORE" = "$WANT" ] && [ "$STOPPED" = "$WANT" ]; then pass; else
        fail "and answers with the figure that was true" \
             "before the stop it read '$BEFORE', during it '$STOPPED', wanted $WANT and $WANT" \
             "the stopped worker's line is still in the region and is still the" \
             "last thing that was true of it.  A 0 here is a reader that treats" \
             "a descheduled writer as an absent one"
    fi
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
