#!/bin/bash
# =============================================================================
# I/O tuning: --cpus and --sqpoll
# =============================================================================
# Where a runtime's I/O runs, and whether its io_uring ring carries a
# submission-polling kernel thread.
#
# The one thing to understand first: a ring is a queue between one thread and
# the kernel, and a ring belongs to a PROCESS.  Every runtime inside one daemon
# shares that daemon's ring.  io_uring fixes a ring's polling mode and its
# poller's CPU when the ring is created — which happens at daemon startup,
# before any `create` command has been read — so those two things are set on the
# daemon, and the per-runtime flags state what a runtime REQUIRES.  `create`
# refuses a requirement the ring cannot meet instead of accepting it and doing
# nothing.
#
# This is also why there is no --rings flag.  "How many rings" only ever means
# "how many I/O threads", and two rings on one thread are strictly worse than
# one.
#
# USAGE:
#   ./io-tuning.sh
# =============================================================================

set -e

echo "=== I/O tuning ==="
echo ""

# ── 1. The default: no polling thread ────────────────────────────────────────
# SQPOLL used to be on unconditionally, which meant a kernel thread spinning on
# the submission queue of every daemon, busy or idle.  It is off unless asked
# for now.
socketley create server api -p 9000 -s
socketley stats api | grep -E '^(sqpoll|cpus|sq_thread_cpu):'
echo ""
echo "Kernel polling threads in the daemon:"
pgrep -x socketley | head -1 | while read -r pid; do
    grep -c . /dev/null
    ls /proc/"$pid"/task/*/comm 2>/dev/null | while read -r c; do cat "$c"; done | grep -c '^iou-sqp-' || true
done
echo ""

# ── 2. Asking for a CPU set this machine does not have ───────────────────────
# Refused when the runtime is created, never rounded up to "all".  A config
# written for a sixteen-core machine and deployed on a four-core one would
# otherwise run nowhere near where its author believes.
echo "A CPU set this machine cannot satisfy:"
socketley create server bad -p 9001 --cpus 0-63 || echo "  (refused, as it should be)"
echo ""

# ── 3. Asking for a poller the daemon's ring does not have ───────────────────
echo "Asking for a poller on a daemon that has none:"
socketley create server hot -p 9002 --sqpoll || echo "  (refused, and it names the fix)"
echo ""

socketley remove api 2>/dev/null || true

# ── 4. Turning it on, for a daemon that will actually saturate a link ────────
# Restart the daemon with the poller and a CPU set.  Under SQPOLL the lowest
# CPU in the set carries the polling thread; the set bounds the loop thread.
cat <<'NOTE'
To run a daemon with a poller, pinned to CPUs 0 and 1:

    socketley daemon stop
    socketley daemon --sqpoll --cpus 0-1 &

    socketley create cache hot -p 9100 --sqpoll --cpus 0-1 -s
    socketley stats hot | grep -E '^(sqpoll|cpus|sq_thread_cpu):'
    #   sqpoll:on
    #   cpus:0-1
    #   sq_thread_cpu:0

The environment says the same thing and is what a supervised worker process
inherits, since a worker has no command line of its own:

    SOCKETLEY_SQPOLL=1 SOCKETLEY_CPUS=0-1 socketley daemon &

A flag wins when both are given.  `socketley daemon` refuses an argument it does
not understand rather than starting and ignoring it, which is what it used to do
— `socketley daemon --sqpoll` once started a daemon with no poller and exited 0.

Worth it for a runtime that is saturating a link: submitting work becomes a
store to a queue tail with no system call at all.  Worth nothing for a runtime
waiting for its next connection, which is what the kernel thread would be
spinning for.

Both flags are stored with the runtime, so the requirement outlives the daemon
that accepted it.  Restart the daemon without --sqpoll/--cpus and `hot` does not
come back up: it lands in `failed` with the reason in the log, rather than
starting on a ring that does not meet what it asked for.
NOTE
