# A cluster cache on several daemons of one host -- only ever sourced, since run_all.sh globs test_*.sh.
#
# The caller has sourced lib_daemon.sh and lib_raft.sh and set HERE (this directory), T, CB (a port block whose last digit is free: replica n of a cache
# spec written -p "$((CB / 10)){node}" listens on $((CB / 10))n) and PB (the Raft port block).  The nodes are named 1, 2 and 3, and the cache is c.
. "$(dirname "${BASH_SOURCE[0]}")/lib_clock.sh"

CLIENT="$HERE/lib_cache_client.py"
raft_port() { echo $((PB + $1 - 1)); }
cport() { echo "$((CB / 10))$1"; }
target() { echo "127.0.0.1:$(cport "$1")"; }
start_member() {   # start_member <node> [--raft-join addr | --raft-init]
    local n=$1; shift
    node_start "$n" --raft-listen 127.0.0.1:"$(raft_port "$n")" --raft-insecure --raft-name "$n" "$@"
}
alive() { kill -0 "$(cat "$T/$1.pid" 2>/dev/null)" 2>/dev/null; }

# Three daemons that agree on three voters and one leader.
form_cluster() {
    start_member 1 --raft-init
    start_member 2 --raft-join 127.0.0.1:"$PB"
    start_member 3 --raft-join 127.0.0.1:"$PB"
    formed() { [ "$(voters 1)" = 3 ] && [ "$(voters 2)" = 3 ] && [ "$(voters 3)" = 3 ] \
               && [ -n "$(leader 1)" ] && [ "$(leader 1)" = "$(leader 2)" ] && [ "$(leader 2)" = "$(leader 3)" ]; }
    wait_for 25 formed
}

# What the replica of cache c on node $1 says about itself in its stats, or nothing when the node is down or has no replica.
cstat() {
    alive "$1" || return 0
    as "$1" stats c 2>/dev/null | awk -F: -v k="$2" '$1 == k { print $2; exit }' || true
}
crole() { cstat "$1" cluster_role; }

# The nodes among $@ whose replica of c leads, according to their own workers.
leading() {
    local n out=""
    for n in "$@"; do [ "$(crole "$n")" = primary ] && out="$out $n"; done
    echo "${out# }"
}

# The nodes among $@ that accept a write right now: the probe writes one key to each replica and reports who said ok.
takers() {
    local tag=$1; shift
    local nodes=("$@") targets=() n out=""
    for n in "${nodes[@]}"; do targets+=("$(target "$n")"); done
    local line i=0
    while read -r line; do
        [[ "$line" == *" ok" ]] && out="$out ${nodes[$i]}"
        i=$((i+1))
    done < <(timeout 10 python3 "$CLIENT" probe "$tag" "${targets[@]}")
    echo "${out# }"
}

cmd() { timeout 10 python3 "$CLIENT" cmd "$@"; }
now_ns() { mono_ns; }

# Every node in $@ that is up holds a replica that follows the primary $1 in epoch $2 and has finished its first sync.
settled_on() {
    local lead=$1 epoch=$2 n; shift 2
    [ "$(crole "$lead")" = primary ] || return 1
    for n in "$@"; do
        alive "$n" || continue
        [ "$n" = "$lead" ] && continue
        [ "$(crole "$n")" = follower ] && [ "$(cstat "$n" cluster_epoch)" = "$epoch" ] \
            && [ "$(cstat "$n" master_link)" = 1 ] && [ "$(cstat "$n" master_sync_in_progress)" = 0 ] || return 1
    done
    return 0
}

placement_primary() {   # "<node> <epoch>" as node $1's placement reports it, or nothing
    alive "$1" || return 0
    as "$1" cluster placement 2>/dev/null | sed -n 's/^c  primary \([^ ]*\) (epoch \([0-9]*\)).*/\1 \2/p' | head -1 || true
}
