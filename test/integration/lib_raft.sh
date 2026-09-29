# Several daemons of one Raft cluster on one host -- only ever sourced, since run_all.sh globs test_*.sh.
#
# The caller sets BIN, T (a temp directory every daemon's socket lies under, watched by daemon_watch) and NODES=(),
# and keeps its own pass and fail counts.  A node is a name: its state lives in $T/<name>/home, its socket is
# $T/<name>.sock, its log $T/<name>.log and its pid $T/<name>.pid.

sock() { echo "$T/$1.sock"; }

# Start node $1 with the remaining flags, its own HOME, socket and log.
node_start() {
    local n=$1; shift
    mkdir -p "$T/$n/home"
    # A restart appends to the same log, so it waits for one more "daemon started" than the log already holds.
    local before
    before=$(grep -c "daemon started" "$T/$n.log" 2>/dev/null || true)
    HOME="$T/$n/home" SOCKETLEY_SOCKET="$(sock "$n")" SOCKETLEY_RAFT_COMPACT_EVERY="${RAFT_COMPACT_EVERY:-4}" \
        "$BIN" daemon "$@" >>"$T/$n.log" 2>&1 &
    echo $! >"$T/$n.pid"
    NODES+=("$n")
    local i
    for i in $(seq 1 100); do
        [ "$(grep -c "daemon started" "$T/$n.log" 2>/dev/null || true)" -gt "${before:-0}" ] && return 0
        kill -0 "$(cat "$T/$n.pid")" 2>/dev/null || break
        sleep 0.1
    done
    echo "  FATAL: node $n never came up"; tail -5 "$T/$n.log" | sed 's/^/         /'
    exit 2
}

# The socketley CLI as node $1, which is what an operator on that host would type.
as() {
    local n=$1; shift
    HOME="$T/$n/home" SOCKETLEY_SOCKET="$(sock "$n")" "$BIN" "$@"
}

# Only a live node is asked, because the CLI starts a daemon on a dead socket; its pid, since daemon_alive walks every fd on the machine and costs seconds per poll.
status() {
    kill -0 "$(cat "$T/$1.pid" 2>/dev/null)" 2>/dev/null || return 0
    as "$1" cluster raft-status 2>/dev/null || true
}
field() { status "$1" | awk -v k="$2:" '$1 == k { $1 = ""; sub(/^ /, ""); print; exit }'; }
role()   { field "$1" role; }
leader() { field "$1" leader | awk '{ print substr($1, 1, 16) }'; }
myid()   { field "$1" node | awk '{ print substr($1, 1, 16) }'; }
voters() { field "$1" voters | sed 's/^none$//' | wc -w; }

# Poll `cond` every 0.2 s for at most $1 seconds.
wait_for() {
    local secs=$1; shift
    local i
    for i in $(seq 1 $((secs * 5))); do
        if eval "$*"; then return 0; fi
        sleep 0.2
    done
    return 1
}

leader_of() {
    local n
    for n in "$@"; do
        [ "$(role "$n")" = "leader" ] && { echo "$n"; return 0; }
    done
    return 1
}

count_of() { local w=($1); echo "${#w[@]}"; }

# Whether the output of a command matches a pattern, read whole first because grep -q ends early and pipefail then blames the writer.
saw() {
    local pat=$1 o; shift
    o=$("$@" 2>&1) || true
    grep -qE -- "$pat" <<<"$o"
}

ms_since() { echo $(( ($(date +%s%N) - $1) / 1000000 )); }

# A node's death as a machine losing power: its daemon is killed and so are its workers, which the kernel does anyway when their parent goes.
node_kill() {
    local n=$1 kids
    kids=$(pgrep -P "$(cat "$T/$n.pid")" 2>/dev/null || true)
    kill -9 "$(cat "$T/$n.pid")" 2>/dev/null || true
    wait "$(cat "$T/$n.pid")" 2>/dev/null || true
    local k
    for k in $kids; do
        wait_for 3 "! kill -0 $k 2>/dev/null" || { echo "  NOTE: worker $k outlived its daemon; killed"; kill -9 "$k" 2>/dev/null || true; }
    done
}
