#!/bin/sh
# One cluster member, as a deployed one actually looks.
#
# Bind-mounted rather than baked into the image: this is the file the test
# iterates on, and it sits above the compile in the Dockerfile's COPY, so
# baking it in would mean rebuilding the whole tree with LTO to change a wait
# loop.  (.dockerignore keeps test/docker out of the build context for the same
# reason.)
#
# ─── THE DEFAULT SOCKET IS THE POINT ─────────────────────────────────────────
#
# Nothing here sets SOCKETLEY_SOCKET.  That variable exists to let several
# daemons share one filesystem namespace, which is the development and test
# situation and nothing else; a deployed member is a container, has a namespace
# to itself, and answers on the path a deployed daemon answers on.  Every node
# in this compose is /run/socketley/socketley.sock, and the only things that
# tell them apart are the network and the mounted volume — which is exactly the
# arrangement test/integration/test_cluster.sh cannot reach and this file
# exists to cover.
#
# ─── READINESS, NOT A GUESS ──────────────────────────────────────────────────
#
# The compose commands this replaces read
#
#     socketley daemon &
#     sleep 1 &&
#     socketley daemon --name api1 --cluster /cluster && ...
#
# and the second line is not a second daemon.  Since 3295e9a `daemon --name`
# and `daemon --cluster` are configuration commands against a daemon that is
# already up, and like every other CLI command they auto-start a detached
# daemon of their own when the socket does not answer.  So that `sleep 1` was a
# race, and losing it did not fail — it forked a second daemon, whereupon the
# backgrounded one found the socket taken and exited 0, `wait` returned at once
# and the container went down with a zero exit status and no message.  A
# container that flaps like that reads as "the image is broken" to whoever
# meets it and as nothing at all to CI.
#
# The daemon prints "daemon started" after the IPC socket is bound and after
# persisted state is restored, so it means serving rather than alive.  Waiting
# for that line removes the race instead of widening it, which is what
# 3ffde3c did for the shell cluster tests.
set -eu

: "${NODE_NAME:?NODE_NAME must be set}"
: "${NODE_ROLE:?NODE_ROLE must be set (backend|gateway)}"
CLUSTER_DIR="${CLUSTER_DIR:-/cluster}"
LOG=/var/log/socketley.log

: >"$LOG"
socketley daemon >"$LOG" 2>&1 &
DPID=$!

i=0
while ! grep -q "daemon started" "$LOG" 2>/dev/null; do
    i=$((i + 1))
    if [ "$i" -gt 300 ]; then
        echo "FATAL: no daemon on the default socket after 30s" >&2
        cat "$LOG" >&2
        exit 1
    fi
    # Not only "has the line appeared": a daemon that died on startup would
    # otherwise be waited on for the full thirty seconds and then reported as
    # slow rather than as dead.
    if ! kill -0 "$DPID" 2>/dev/null; then
        echo "FATAL: the daemon exited before it was serving" >&2
        cat "$LOG" >&2
        exit 1
    fi
    sleep 0.1
done

# The daemon's log belongs in `docker compose logs` too — it is the first place
# anyone looks when a node misbehaves, and the readiness file above would
# otherwise swallow all of it.
tail -f -n +1 "$LOG" &

# PID 1 is this shell, so SIGTERM arrives here and not at the daemon.  Without
# forwarding it, `docker compose stop` would kill the shell, leave the daemon
# to be SIGKILLed at the end of the grace period, and turn every graceful
# shutdown into an ungraceful one — which would quietly delete the difference
# between the two rows of the stale-detection table in the man page.
TERMED=0
trap 'TERMED=1; kill -TERM "$DPID" 2>/dev/null || true' TERM INT

# Not guarded, on purpose.  The daemon name and the cluster directory are not
# persisted, so this runs on every boot including a restart.
#
# A node killed and brought back inside the 10s staleness window finds its own
# file still fresh in the cluster directory.  It reclaims it: the entry carries
# the writer's advertised host, control socket path and kernel boot id, and this
# container comes back with all three the same, which is only true of a daemon
# that no longer exists — a unix socket path admits one process at a time.  The
# daemon logs the reclaim at WARN and carries on.
#
# What is still refused, and must be, is a genuinely different daemon claiming a
# name a live one holds: it exits non-zero here and takes the node down under
# `set -e`, which is the loud half and the one worth having.  It never comes up
# with cluster mode quietly off.
socketley daemon --name "$NODE_NAME" --cluster "$CLUSTER_DIR"

# ─── The second boot is not the first ────────────────────────────────────────
#
# `docker compose start` on a container that was stopped or killed is the same
# container with the same filesystem, so the daemon's state directory is still
# there and it restores what it had — including was_running, which starts the
# runtime again before this script gets a word in.  A plain `create` then fails
# with "runtime already exists", and under `set -e` that took the node down on
# every restart: the rejoin half of the docker cluster test could never pass,
# and a real node that was merely restarted would never come back.
#
# So: create if it is not there, start if it is there and stopped, and treat
# "already running" as the success it is.
ensure_runtime() {
    name=$1; shift
    if socketley ls 2>/dev/null | awk '{print $2}' | grep -qx "$name"; then
        socketley start "$name" >/dev/null 2>&1 || true
    else
        "$@"
    fi
}

case "$NODE_ROLE" in
    backend)
        # Same port on every backend: they are on different hosts, and the
        # address a peer dials comes from the cluster file, not from a port
        # that has to be unique across the deployment.  Distinct runtime NAMES,
        # because the name is what the reply carries and therefore what says
        # which container answered — and deliberately not the daemon name, so
        # that an assertion about who answered a request cannot be satisfied by
        # a daemon name appearing in some unrelated listing.
        : "${NODE_RUNTIME:?NODE_RUNTIME must be set for a backend}"
        ensure_runtime "$NODE_RUNTIME" \
            socketley create server "$NODE_RUNTIME" -p 9001 -g api \
                --lua /identity.lua -s
        ;;
    gateway)
        ensure_runtime gw \
            socketley create proxy gw -p 8080 --backend @api \
                --protocol tcp --strategy round-robin -s
        ;;
    *)
        echo "FATAL: unknown NODE_ROLE: $NODE_ROLE" >&2
        exit 1
        ;;
esac

# The line the test waits on.  Everything a node has to do before it can be
# measured has happened by here: it is serving, it is publishing under its
# name, and its runtime exists and is started.
echo "node $NODE_NAME ready"

# ─── Why this is not just `wait` ─────────────────────────────────────────────
#
# `wait` returns as soon as a trapped signal has been handled, whether or not
# the process being waited on has finished.  So the SIGTERM that arrives on
# `docker compose stop` runs the trap, wait returns, this script reaches its
# end and exits — and the container tears down around a daemon that is three
# lines into its shutdown.  From the volume's point of view the result is
# indistinguishable from `docker kill`: the node's file is still there, and its
# peers age it out over ten seconds instead of seeing it deleted.  Both rows of
# the stale-detection table in the man page then look like the second one.
#
# So wait, and then keep waiting until the daemon is actually gone.
RC=0
while :; do
    wait "$DPID" 2>/dev/null
    RC=$?
    kill -0 "$DPID" 2>/dev/null || break
    sleep 0.1
done
# A daemon that died without our TERM is a crash, and the container must say so.
[ "$TERMED" -eq 1 ] && exit 0
exit "$RC"
