#!/bin/bash
# Paired A/B measurement — the machinery, without any particular protocol.
#
# bench_proxy_vs_haproxy.sh worked out what it takes to get a believable ratio
# out of this machine, and bench_proxy_http_vs_haproxy.sh needs exactly the same
# thing for a different protocol.  It lives here rather than in both because two
# copies of a statistical argument drift, and the one that drifts is the one
# nobody is reading when it gives the wrong answer.
#
# The argument, in four parts:
#
#   Runs are timed rather than counted, so the window cannot shrink as the code
#   under test gets faster.  A count of operations picked for today's speed is a
#   window that quietly narrows until it is measuring the scheduler.
#
#   The two arms are interleaved, alternating which one leads, and the answer is
#   the median of the per-pair ratios.  This box drifts by tens of percent inside
#   a minute; run all of A and then all of B and that drift arrives as a
#   difference between A and B.  A pair shares its weather.
#
#   A pair measured while somebody else was using the machine is discarded
#   whole, never one leg of it — a pair with one leg dropped is precisely the
#   unpaired comparison this exists to replace.
#
#   Every case reports the smallest difference it could have resolved, and the
#   caller is expected to refuse the ratio when that is wider than the question.
#
# ─── What the caller provides ───────────────────────────────────────────────
#
#   PAIRS         pairs to keep
#   RUN_MS        milliseconds per measured run (informational here)
#   QUIET_CORES   discard a pair if the box's own load exceeded this, in cores
#   TARGET_PCT    the difference the reader came to ask about
#   BE_PID        pid of the shared backend, for the backend-bound check
#
#   arm_measure ARM MODE A B
#       ARM is "a" or "b".  Echoes three fields -- rate, proxy cores, backend
#       cores -- or FOUR, the fourth being the load generator's own cores.
#       Resolving ARM to a port, a pid and whatever else differs between the two
#       sides is the caller's job, because that is the part that is not shared:
#       the HTTP arms need different request paths to reach the same resource,
#       and pretending otherwise measures a 404 against a file.
#
#       The fourth field is optional so that the two callers written before it
#       keep working, and it reads as zero for them.  It is worth supplying: a
#       cell whose client is at its ceiling reports the load generator, and that
#       has been mistaken for parity in this directory more than once -- two
#       builds within a few percent of each other is the tell, and a cache once
#       measured 106,213 against Redis's 108,342 because one redis-benchmark
#       caps this box near 90k.

HZ=$(getconf CLK_TCK)

# CPU a process has burned, in ticks, threads included.  /proc/PID/stat's utime
# and stime are the whole thread group's, which is the point: socketley's proxy
# creates and reaps io_uring workers inside a run, and their time lands here
# even though counting threads afterwards never sees them.
cpu_ticks_of() { awk '{print $14+$15}' "/proc/$1/stat" 2>/dev/null || echo 0; }

# Busy CPU across the box, in ticks.  Deliberately without iowait: iowait is
# idle time that happens to have I/O outstanding, and on this box it runs to
# four cores' worth during a benchmark.  Counting it as busy was how an earlier
# version of this instrument reported a saturated machine with seven idle cores.
box_busy_ticks() { awk '/^cpu /{print $2+$3+$4+$7+$8+$9}' /proc/stat; }

# What the rest of the machine is doing, in cores, measured with nothing of ours
# running.  Sampled either side of a pair: a build that starts halfway through
# would not be caught by a sample taken only before.
box_load_cores() {
    local t0 t1 w0 w1
    t0=$(box_busy_ticks); w0=$(date +%s%N)
    sleep 0.15
    t1=$(box_busy_ticks); w1=$(date +%s%N)
    awk -v d=$((t1 - t0)) -v hz="$HZ" -v ns=$((w1 - w0)) \
        'BEGIN { printf "%.3f", d / hz / (ns / 1e9) }'
}

# The process burning the most CPU over a moment, as "name cores", so a pass
# refused for load can say whose load it was: a table of "measured nothing"
# with no reason took an evening to trace to a guest agent spinning a core.
box_busiest() {
    local t0 t1
    _busiest_snap() { cat /proc/[0-9]*/stat 2>/dev/null | awk '{
        i = index($0, "("); j = match($0, /\) [A-Za-z] /)
        if (!i || !j) next
        comm = substr($0, i + 1, j - i - 1); gsub(/ /, "_", comm)
        split(substr($0, j + 2), f, " ")
        print $1, f[12] + f[13], comm }'; }
    t0=$(_busiest_snap); sleep 0.3; t1=$(_busiest_snap)
    awk -v hz="$HZ" 'NR == FNR { a[$1] = $2; next }
        ($1 in a) && $2 - a[$1] > best { best = $2 - a[$1]; name = $3 }
        END { if (best > 0) printf "%s %.2f", name, best / hz / 0.3 }' \
        <(echo "$t0") <(echo "$t1")
}

# ─── Small statistics, in awk ───────────────────────────────────────────────

median_of() {
    tr ' ' '\n' <<<"$1" | grep -E '^[0-9.]+$' | sort -g | awk '
        {v[n++] = $1}
        END { if (n == 0) { print 0; exit }
              printf "%.6g", (n % 2) ? v[int(n/2)] : (v[n/2 - 1] + v[n/2]) / 2 }'
}
mean_of() {
    tr ' ' '\n' <<<"$1" | grep -E '^[0-9.]+$' | awk \
        '{s += $1; n++} END { printf "%.2f", n ? s / n : 0 }'
}
# Half-width of the 95% confidence interval of the mean, as a percentage of it.
# Student's t, because at the five to nine repetitions a benchmark actually runs
# the asymptotic 1.96 understates the interval by a fifth to a third — which is
# the difference between "this resolves 15%" and "it does not".
ci_pct_of() {
    tr ' ' '\n' <<<"$1" | grep -E '^[0-9.]+$' | awk '
        {v[n++] = $1; s += $1}
        END {
            if (n < 2 || s == 0) { print "0"; exit }
            m = s / n
            for (i = 0; i < n; i++) ss += (v[i] - m) ^ 2
            sd = sqrt(ss / (n - 1))
            split("0 0 12.706 4.303 3.182 2.776 2.571 2.447 2.365 2.306 2.262 " \
                  "2.228 2.201 2.179 2.160 2.145 2.131 2.120 2.110 2.101 2.093 2.086", t, " ")
            tv = (n <= 21) ? t[n + 1] : 1.96
            printf "%.1f", 100 * tv * sd / sqrt(n) / m
        }'
}

# ─── One case, as interleaved pairs ─────────────────────────────────────────
#
# Sets: C_A C_B C_RATIO C_CI C_A_CI C_APX C_BPX C_ABE C_BBE C_BE C_KEPT C_DROPPED
#       C_BADRUN
# All of them, every time, so a caller cannot read a stale value from the case
# before when this one fails.
paired_run_case() {
    local mode=$1 a=$2 b=$3
    local av=() bv=() rv=() apx=() bpx=() abe=() bbe=() acl=() bcl=()
    local a_rate a_px a_be a_cl b_rate b_px b_be b_cl
    local kept=0 dropped=0 badrun=0 attempt=0 max_attempts=$((PAIRS * 2 + 2))

    # A discarded warm-up pair.  The first run against a proxy that has just
    # been left alone pays for a cold accept path on whichever arm goes first.
    arm_measure a "$mode" "$a" "$b" >/dev/null
    arm_measure b "$mode" "$a" "$b" >/dev/null

    while (( kept < PAIRS && attempt < max_attempts )); do
        attempt=$((attempt + 1))
        local before after ra rb
        before=$(box_load_cores)

        # Alternate which arm leads.  Whatever the leading arm pays that the
        # trailing one does not is then charged to each of them in turn.
        if (( attempt % 2 == 1 )); then
            ra=$(arm_measure a "$mode" "$a" "$b")
            rb=$(arm_measure b "$mode" "$a" "$b")
        else
            rb=$(arm_measure b "$mode" "$a" "$b")
            ra=$(arm_measure a "$mode" "$a" "$b")
        fi
        after=$(box_load_cores)

        # Four fields where the caller supplies them, three where it does not:
        # a_cl then reads empty, and the client check below is skipped rather
        # than being fed a zero it would treat as an idle client.
        read -r a_rate a_px a_be a_cl <<<"$ra"
        read -r b_rate b_px b_be b_cl <<<"$rb"

        if awk -v x="$before" -v y="$after" -v lim="$QUIET_CORES" \
               'BEGIN { exit !(x > lim || y > lim) }'; then
            dropped=$((dropped + 1)); continue
        fi
        # Counted apart from the quiet gate, because they mean opposite things.
        # A busy box is the machine's fault and waiting it out is the right
        # answer; a leg that came back with nothing is the thing under test
        # failing, and if every pair goes this way the case must not report
        # "the box was never quiet" — it must say the requests did not work.
        if [[ "${a_rate:-0}" -le 0 || "${b_rate:-0}" -le 0 ]]; then
            badrun=$((badrun + 1)); continue
        fi

        av+=("$a_rate"); bv+=("$b_rate")
        apx+=("$a_px");  bpx+=("$b_px")
        abe+=("$a_be");  bbe+=("$b_be")
        acl+=("${a_cl:-0}"); bcl+=("${b_cl:-0}")
        rv+=("$(awk -v x="$a_rate" -v y="$b_rate" 'BEGIN { printf "%.6f", x / y }')")
        kept=$((kept + 1))
    done

    C_KEPT=$kept
    C_DROPPED=$dropped
    C_BADRUN=$badrun
    C_A=0; C_B=0; C_RATIO=0; C_CI=0; C_A_CI=0; C_APX=0; C_BPX=0
    C_ABE=0; C_BBE=0; C_BE=0; C_ACLI=0; C_BCLI=0; C_CLI=0
    if (( kept == 0 )); then return 0; fi

    C_A=$(median_of "${av[*]}")
    C_B=$(median_of "${bv[*]}")
    C_APX=$(mean_of "${apx[*]}")
    C_BPX=$(mean_of "${bpx[*]}")
    # Per arm, and the median rather than the worst leg.  The question is
    # whether the backend was the limit in the run this line reports, not
    # whether it ever touched a whole core once in forty legs — with enough
    # pairs a maximum finds an outlier every time.  Either arm saturating is
    # enough to spoil the ratio: it is the faster arm that hits the ceiling
    # first, and once it does, its number is the backend's and not its own.
    C_ABE=$(median_of "${abe[*]}")
    C_BBE=$(median_of "${bbe[*]}")
    C_BE=$(awk -v x="$C_ABE" -v y="$C_BBE" 'BEGIN { print (x > y) ? x : y }')
    # The load generator, on the same argument as the backend above: either arm
    # hitting the ceiling is enough to spoil the ratio, and it is the FASTER arm
    # that reaches it first -- so a client cap does not read as noise, it reads
    # as the two proxies being level.
    C_ACLI=$(median_of "${acl[*]}")
    C_BCLI=$(median_of "${bcl[*]}")
    C_CLI=$(awk -v x="$C_ACLI" -v y="$C_BCLI" 'BEGIN { print (x > y) ? x : y }')
    C_RATIO=$(median_of "${rv[*]}")
    C_CI=$(ci_pct_of "${rv[*]}")
    C_A_CI=$(ci_pct_of "${av[*]}")
}

# The verdict column, not the ratio, is the thing to read first.  A ratio whose
# interval is wider than the difference it claims is not a weaker result, it is
# not a result.
# The client cap, its ceiling and the backend's ceiling are all optional, for
# the two callers that predate them.  A CEILING is what that side could hold at
# most: one core per connection the load generator drives, one core per process
# the backend runs in, each capped at the machine's.
#
# The backend ceiling is not cosmetic.  It defaulted to one core and a four-
# process round-robin backend at 1.252 cores -- 31% of each -- was reported as
# `backend-bound`, which is the opposite of what those numbers say.  A check
# that fires on a fixture with two thirds of its capacity idle costs the rows it
# fires on, and it fired on the two rows that fixture existed for.
paired_verdict() {   # ci kept be_cores [cli_cores] [cli_ceiling] [be_ceiling] -> text
    local ci=$1 kept=$2 be=$3 cli=${4:-} ceil=${5:-} be_ceil=${6:-1}
    if (( kept == 0 )); then
        if (( ${C_BADRUN:-0} > 0 )); then
            echo "no pair survived — ${C_BADRUN} had a leg that returned nothing"
        else
            echo "no pair survived — the box was never quiet"
        fi
        return
    fi
    if (( kept < 3 )); then echo "only $kept pair(s) survived — no interval"; return; fi
    if awk -v b="$be" -v k="$be_ceil" 'BEGIN { exit !(k > 0 && b > 0.85 * k) }'; then
        echo "backend-bound (${be} of ${be_ceil} cores) — measures the backend"
        return
    fi
    if [[ -n "$cli" && -n "$ceil" ]] && \
       awk -v c="$cli" -v k="$ceil" 'BEGIN { exit !(k > 0 && c >= k * 0.95) }'; then
        echo "client-bound (${cli} of ${ceil} cores) — measures the load generator"
        return
    fi
    if awk -v c="$ci" -v t="$TARGET_PCT" 'BEGIN { exit !(c > t) }'; then
        echo "cannot resolve ${TARGET_PCT}% — only ${ci}% and coarser"
        return
    fi
    echo "resolves ${TARGET_PCT}%"
}
