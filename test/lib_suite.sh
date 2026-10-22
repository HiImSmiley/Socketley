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
    for w in 19000 21000 23000 25000 27000 29000 5000 7000 9000 11000 13000 15000 17000; do
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
SUITE_DURATIONS="${SUITE_DURATIONS:-/tmp/socketley-test-durations-$(id -u)}"

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
