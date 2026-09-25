# What run_all.sh and run_group.sh both decide about a test file -- only ever
# sourced.

# A file that measures time or CPU, or that shares the suite's daemon, runs
# alone: the first measures nothing under load, the second has no daemon of
# its own to run beside anybody.
suite_wants_serial() {   # file -> 0 when it must run alone
    grep -q '^# suite: quiet' "$1" && return 0
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
