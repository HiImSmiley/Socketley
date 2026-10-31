# What run_all.sh and run_group.sh both decide about a test file -- only ever
# sourced.

# A file that measures time or CPU, or that shares the suite's daemon, runs
# alone: the first measures nothing under load, the second has no daemon of
# its own to run beside anybody.  A file that isolates without daemon_isolate
# says so with `# suite: isolated`, which is a claim checked by reading it: 30
# such files ran alone for 350 s a suite, most of the serial phase.
suite_wants_serial() {   # file -> 0 when it must run alone
    grep -q '^# suite: quiet' "$1" && return 0
    grep -q '^# suite: isolated' "$1" && return 1
    grep -q 'daemon_isolate' "$1" || return 0
    return 1
}

# How many of lib_ports.sh's windows another test could claim right now, which
# is the parallelism the machine allows -- a job past it fails in a second with
# "no free 2000-port window", and xargs hands its slot the next file, which
# fails the same way until the list is gone.
suite_free_windows() {
    local listening w p busy n=0
    listening=$(ss -ltnH 2>/dev/null | awk '{ n = split($4, a, ":"); print a[n] }')
    . "$(dirname "${BASH_SOURCE[0]}")/integration/lib_windows.sh"
    for w in $(sl_port_windows); do
        flock -n "/tmp/socketley-ports-$w.lock" true 2>/dev/null || continue
        busy=""
        for p in $listening; do
            case "$p" in ''|*[!0-9]*) continue ;; esac
            if [ "$p" -ge "$w" ] && [ "$p" -lt $((w + 2000)) ]; then busy=1; break; fi
        done
        [ -z "$busy" ] && n=$((n + 1))
    done
    echo "$n"
}

# How many jobs of the given bytes fit beside what is already held, at least
# one: past it the box thrashes rather than fails.  A cgroup's memory.high
# throttles below what the machine has free, so its headroom counts too,
# against what its processes hold, since its page cache is given back first.
suite_mem_slots() {   # bytes per job -> how many fit
    local free cg lim l u n
    free=$(awk '/^MemAvailable:/ { print $2 * 1024 }' /proc/meminfo)
    cg="/sys/fs/cgroup$(awk -F: '$1 == "0" { print $3 }' /proc/self/cgroup)"
    while [ -d "$cg" ] && [ "$cg" != /sys/fs/cgroup ]; do
        for lim in memory.high memory.max; do
            l=$(cat "$cg/$lim" 2>/dev/null); u=$(awk '$1 == "anon" { print $2 }' "$cg/memory.stat" 2>/dev/null)
            case "$l$u" in ''|*[!0-9]*) continue ;; esac
            [ $((l - u)) -lt "$free" ] && free=$((l - u))
        done
        cg=$(dirname "$cg")
    done
    n=$((free / $1)); [ "$n" -lt 1 ] && n=1
    echo "$n"
}

# How many sanitizer files run at once: each holds about 2 GiB, and its binary's pages are counted beside it.
suite_sanitize_slots() {
    suite_mem_slots 2684354560
}

# Where the last run's per-file seconds are kept, so the longest files start
# first and the run does not end on one 85-second file started last.
SUITE_DURATIONS="${SUITE_DURATIONS:-/tmp/socketley-test-durations-$(id -u)-${SOCKETLEY_CONFIG:-Release}}"

suite_longest_first() {   # list-file -> the same paths, slowest last run first
    awk -v d="$SUITE_DURATIONS" '
        BEGIN { while ((getline l < d) > 0) { split(l, a, " "); secs[a[2]] = a[1] } }
        { n = split($0, p, "/"); s = ($0 in secs) ? secs[$0] : ((p[n] in secs) ? secs[p[n]] : 30)
          printf "%d %s\n", s, $0 }' "$1" | sort -rn | cut -d' ' -f2-
}

suite_save_durations() {   # dir -> its <file>.secs merged into the record
    local dir=$1 tmp
    tmp=$(mktemp "${SUITE_DURATIONS}.XXXXXX") || return 0
    { cat "$SUITE_DURATIONS" 2>/dev/null
      for f in "$dir"/*.secs; do [ -f "$f" ] && echo "$(cat "$f") $(basename "$f" .secs)"; done
    } | awk '{ secs[$2] = $1 } END { for (k in secs) print secs[k], k }' > "$tmp"
    mv -f "$tmp" "$SUITE_DURATIONS"
}

# ─── Namespaces of a file's own ─────────────────────────────────────────────
# A file run in a user, network, mount and process namespace of its own has a
# loopback with every port, a /tmp of its own and a process table of its own:
# no port window, no shared socket and no other file's daemon can reach it, and
# the kernel ends every process it left when it ends.  A file that needs the
# host's own processes or files as root owns them says `# suite: host` and runs
# on the host beside the others, in a port window as before.  Where the machine forbids
# unprivileged user namespaces (Ubuntu's AppArmor default), files share the host
# as before.
suite_ns_ok() {
    unshare --user --map-current-user --keep-caps --net --mount --pid --fork --mount-proc \
        sh -c 'ip link set lo up && mount --bind /var/tmp /tmp && setpriv --inh-caps=-all --ambient-caps=-all true' \
        2>/dev/null
}

suite_ns_run() {   # root file -> the file's exit, run in namespaces of its own with its /tmp under root
    local dir="$1/$(basename "$2" .sh)"
    rm -rf "$dir"; mkdir -p "$dir"
    # The capabilities the namespace gives are kept for bringing the loopback up and mounting /tmp, and given up
    # before the file runs, so it is the user it would be on the host: a file of mode 000 is refused to it.
    unshare --user --map-current-user --keep-caps --net --mount --pid --fork --mount-proc --kill-child -- bash -c '
        ip link set lo up || exit 2
        # An address that is not loopback, which a test of what reaches this machine from elsewhere needs, in the
        # benchmarking range no test names: 192.0.2.x is what tests use for an address the host does not have.
        ip link add sl0 type dummy 2>/dev/null && ip addr add 198.18.0.1/24 dev sl0 && ip link set sl0 up
        mount --bind "$1" /tmp || exit 2
        export HOME=/tmp/home SOCKETLEY_SOCKET=/tmp/suite.sock
        mkdir -p "$HOME"
        exec setpriv --inh-caps=-all --ambient-caps=-all bash "$2"' _ "$dir" "$2"
}

# ─── A memory budget the suites on the machine share ────────────────────────
# A sanitizer process grows to some 400 MiB in its first seconds, so memory free
# at a job's start says nothing about what it will hold: twenty-eight files let
# in at once grew past the machine and the OOM killer took the gate.  So a job
# reserves what it held at its peak the last time, or a default for its build,
# from a budget of the machine's memory less a margin, and starts only once the
# reservations held fit; the first is always let in.  A sampler records each
# job's peak (its processes' anonymous memory and swap, found by the tag they
# inherit) for the next run.
SUITE_MEM_RECORD="${SUITE_MEM_RECORD:-/var/tmp/socketley-test-memory-$(id -u)-${SOCKETLEY_CONFIG:-Release}}"
SUITE_BUDGET_FILE="/tmp/socketley-suite-budget-$(id -u)"

suite_mem_need() {   # name -> kB to reserve
    local kb
    kb=$(awk -v n="$1" '$2 == n { print $1; exit }' "$SUITE_MEM_RECORD" 2>/dev/null)
    [ -n "$kb" ] || { [ "${SOCKETLEY_CONFIG:-Release}" = Sanitize ] && kb=1600000 || kb=500000; }
    echo $(( kb + kb / 5 + 50000 ))
}

suite_budget_reserve() {   # kB
    local budget held
    budget=$(awk '/^MemTotal:/ { print $2 - 3145728 }' /proc/meminfo)
    exec 8>"$SUITE_BUDGET_FILE.lock"
    while :; do
        flock 8
        held=$(cat "$SUITE_BUDGET_FILE" 2>/dev/null || echo 0)
        if [ "$held" -le 0 ] || [ $((held + $1)) -le "$budget" ]; then
            echo $((held + $1)) > "$SUITE_BUDGET_FILE"
            flock -u 8; exec 8>&-
            return 0
        fi
        flock -u 8
        sleep 0.5
    done
}

suite_budget_release() {   # kB
    local held
    exec 8>"$SUITE_BUDGET_FILE.lock"
    flock 8
    held=$(cat "$SUITE_BUDGET_FILE" 2>/dev/null || echo 0)
    held=$((held - $1)); [ "$held" -lt 0 ] && held=0
    echo "$held" > "$SUITE_BUDGET_FILE"
    flock -u 8; exec 8>&-
}

# Every two seconds, each tagged job's processes summed and its peak kept in `dir`/<tag>.mem.
suite_mem_sampler() {   # dir
    local dir=$1 d tag kb
    while :; do
        declare -A now=()
        for d in /proc/[0-9]*; do
            tag=$( { tr '\0' '\n' <"$d/environ"; } 2>/dev/null | sed -n 's/^SUITE_FILE_TAG=//p' )
            [ -n "$tag" ] || continue
            kb=$(awk '/^(RssAnon|VmSwap):/ { s += $2 } END { print s + 0 }' "$d/status" 2>/dev/null)
            now[$tag]=$(( ${now[$tag]:-0} + ${kb:-0} ))
        done
        for tag in "${!now[@]}"; do
            [ "${now[$tag]}" -gt "$(cat "$dir/$tag.mem" 2>/dev/null || echo 0)" ] && echo "${now[$tag]}" > "$dir/$tag.mem"
        done
        unset now
        sleep 2
    done
}

suite_save_memory() {   # dir -> its <tag>.mem merged into the record
    local tmp
    tmp=$(mktemp "${SUITE_MEM_RECORD}.XXXXXX") || return 0
    { cat "$SUITE_MEM_RECORD" 2>/dev/null
      for f in "$1"/*.mem; do [ -f "$f" ] && echo "$(cat "$f") $(basename "$f" .mem)"; done
    } | awk '{ kb[$2] = $1 } END { for (k in kb) print kb[k], k }' > "$tmp"
    mv -f "$tmp" "$SUITE_MEM_RECORD"
}

# Commands run side by side, a line of the list each, `name<TAB>command`, the
# command's output, exit and seconds left in `dir` under its name.
suite_run_jobs() {   # list dir parallel
    local list=$1 dir=$2 par=$3
    export SUITE_JOB_DIR="$dir"
    export -f suite_mem_need suite_budget_reserve suite_budget_release
    export SUITE_MEM_RECORD SUITE_BUDGET_FILE SOCKETLEY_CONFIG
    awk -F'\t' '{ print $1 }' "$list" | while IFS= read -r name; do
        printf '%s\0' "$name"
    done | xargs -0 -I{} -P"$par" bash -c '
        name=$1
        cmd=$(awk -F"\t" -v n="$name" "\$1 == n { print \$2; exit }" "$2")
        need=$(suite_mem_need "$name"); suite_budget_reserve "$need"
        t0=$(date +%s)
        SUITE_FILE_TAG="$name" bash -c "$cmd" > "$SUITE_JOB_DIR/$name.log" 2>&1
        echo $? > "$SUITE_JOB_DIR/$name.rc"
        suite_budget_release "$need"
        echo $(( $(date +%s) - t0 )) > "$SUITE_JOB_DIR/$name.secs"' _ {} "$list"
}
