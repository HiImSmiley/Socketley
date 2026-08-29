#!/bin/bash
# =============================================================================
# I/O tuning: --cpus
# =============================================================================
# Where a runtime's I/O runs.
#
# The one thing to understand first: a ring is a queue between one thread and
# the kernel, and a ring belongs to a PROCESS.  Every runtime inside one daemon
# shares that daemon's ring.  io_uring fixes a ring's CPU set when the ring is
# created — which happens at daemon startup, before any `create` command has
# been read — so the set is chosen on the daemon, and the per-runtime flag
# states what a runtime REQUIRES.  `create` refuses a requirement the ring
# cannot meet instead of accepting it and doing nothing.
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

# ── 1. The default: unpinned ─────────────────────────────────────────────────
socketley create server api -p 9000 -s
socketley stats api | grep -E '^cpus:'
echo ""

# ── 2. Asking for a CPU set this machine does not have ───────────────────────
# Refused when the runtime is created, never rounded up to "all".  A config
# written for a sixteen-core machine and deployed on a four-core one would
# otherwise run nowhere near where its author believes.
echo "A CPU set this machine cannot satisfy:"
socketley create server bad -p 9001 --cpus 0-63 || echo "  (refused, as it should be)"
echo ""

# ── 3. Asking for a set the daemon's ring is not pinned to ───────────────────
echo "Asking for CPUs 0-1 on an unpinned daemon:"
socketley create server hot -p 9002 --cpus 0-1 || echo "  (refused, and it names the fix)"
echo ""

socketley remove api 2>/dev/null || true

# ── 4. Pinning, for a daemon that will actually saturate a link ──────────────
cat <<'NOTE'
To run a daemon pinned to CPUs 0 and 1:

    # There is no `socketley daemon stop`: signal the process you started.
    kill "$DAEMON_PID"
    socketley daemon --cpus 0-1 &

    socketley create cache hot -p 9100 --cpus 0-1 -s
    socketley stats hot | grep -E '^cpus:'
    #   cpus:0-1

The environment says the same thing and is what a supervised worker process
inherits, since a worker has no command line of its own:

    SOCKETLEY_CPUS=0-1 socketley daemon &

A flag wins when both are given.  `socketley daemon` refuses an argument it does
not understand rather than starting and ignoring it, which is what it used to do
— `socketley daemon --cpus 0-1` once started an unpinned daemon and exited 0.

The set is stored with the runtime, so the requirement outlives the daemon that
accepted it.  Restart the daemon without --cpus and `hot` does not come back up:
it lands in `failed` with the reason in the log, rather than starting on a ring
that does not meet what it asked for.

`stats` reports the set the ring actually got, not the one that was asked for,
with `(not applied)` appended when the pinning was attempted and refused — a
runtime whose real CPU set cannot be read back is one nobody can debug.
NOTE
