#!/bin/bash
# Fan-out: self.broadcast against a --mode inout relay against a cache's pub/sub
#
# The question this answers had never been asked here.  The tree has nine
# correctness tests for pub/sub and none of them is a measurement, and no
# benchmark in this directory sends a PUBLISH at all -- so "is the cache's
# fan-out as fast as the server's" had no answer, only a plausible one.
#
# Reading the code first gave a prediction worth trying to break: the server's
# write queue holds shared_ptr<const string> (server_instance.h:87), so one
# broadcast is one payload and N refcounts, while the cache's holds owned
# strings (cache_instance.h:45, with a comment saying so) and one publish is N
# copies of the payload.  A per-delivery difference, constant in N, and possibly
# far below what a box that is 95% kernel can resolve.
#
# Three arms rather than two, because with two the answer would be "the cache is
# slower" and not "by what".  self.broadcast and mode_inout differ in the Lua
# hop and in one write; mode_inout and the cache differ in the queue.  The
# middle arm is what makes each difference attributable, which is the shape the
# benchmarking skill asks for and the shape that turned "something regressed"
# into "this setsockopt" once before.
#
# Interleaved and rotated, never one arm after another: this box drifts by tens
# of percent inside a minute, and the answer is the median of the per-pass
# ratios.
#
# What the arms do not share, stated because it does not cancel:
#   - self.broadcast excludes nobody, so its arm writes N+1 times per publish
#     where the other two write N.  At 50 subscribers that is 2%.
#   - the cache prefixes `message <channel> ` to every delivery, so at the same
#     payload it carries 10 more bytes per delivery.  MB/s is reported from the
#     delivered length so that this is visible rather than hidden.

source "$(dirname "$0")/utils.sh"
source "$(dirname "$0")/lib_paired.sh"

BC_PORT=19741      # server, --lua fanout.lua, self.broadcast
RL_PORT=19742      # server, --mode inout, no Lua
PS_PORT=19743      # cache, publish/subscribe
RESULTS_FILE="${RESULTS_DIR}/fanout_${TIMESTAMP}${BENCH_FANOUT_TLS:+_tls}.json"

PASSES=${1:-${BENCH_FANOUT_PASSES:-5}}
RUN_MS=${BENCH_FANOUT_RUN_MS:-3000}
MSG_SIZE=${BENCH_FANOUT_SIZE:-200}
SUB_CASES=${BENCH_FANOUT_SUBS:-"50 200"}
QUIET_CORES=${BENCH_QUIET_CORES:-1.0}
# Fifteen percent, not the five the Redis comparison uses.  The prediction here
# is a memcpy of 200 bytes per delivery against a refcount, on a machine whose
# proxy worker profiles at 95% kernel; an instrument that promised to resolve 5%
# of that would be promising something this box does not have.
TARGET_PCT=${BENCH_RESOLUTION_TARGET:-15}

ARMS="broadcast relay pubsub"

# TLS, which had no benchmark anywhere in this directory before this line.
#
# It is the same three arms over the record layer, and it is here because of a
# prediction the plaintext measurement leaves behind: tls_flush() drives one
# SSL_write per queue entry, so an entry costs a record header and an AEAD tag
# on top of what it costs in segments.  Coalescing should therefore be worth
# more here than it is in the clear.  If it is not, the model of the write path
# that produced it is wrong, which is the only kind of measurement worth the
# certificate.
TLS=${BENCH_FANOUT_TLS:-0}
TLS_ARG=""; TLS_FLAGS=""

declare -A ARM_PORT=( [broadcast]=$BC_PORT [relay]=$RL_PORT [pubsub]=$PS_PORT )
declare -A ARM_NAME=( [broadcast]=fbc     [relay]=frl      [pubsub]=fps )
declare -A ARM_PID

# ─── One arm, once ──────────────────────────────────────────────────────────
#
# Echoes: rate  worker_cores  client_cores  p50_us  complete
#
# The two core figures are averaged over the whole invocation, which includes
# connecting the subscribers and the 300 ms the server arms spend letting their
# priming line settle.  So they are a floor on the load's real cost, not an
# estimate of it -- which is the direction that cannot turn a saturated client
# into a comfortable one.
arm_run() {
    local arm=$1 subs=$2
    local port=${ARM_PORT[$arm]} wpid=${ARM_PID[$arm]}
    local w0 w1 t0 t1 out rc bpid peak cur

    w0=$(cpu_ticks_of "$wpid"); t0=$(date +%s%N)
    "$SOCKETLEY_BENCH" -j -r 1 -W 0 -w 0 -d "$RUN_MS" $TLS_ARG \
        fanout "$arm" 127.0.0.1 "$port" "$subs" 2000000 "$MSG_SIZE" \
        >"$TMPDIR_BENCH/$arm.out" 2>"$TMPDIR_BENCH/$arm.err" &
    bpid=$!
    # Sampled while it runs and not after it exits, because /proc/PID/stat is
    # gone the moment it does -- and a client-CPU figure that is silently zero
    # is exactly the reading that cannot tell a capped client from a fast one.
    #
    # read and not cpu_ticks_of, and a quarter second and not a tenth: this loop
    # runs *inside* the window it is measuring, and an instrument that forks
    # during a benchmark charges the benchmark.  bench_cache_resp.sh learned the
    # expensive version of this -- a pgrep every 100 ms widened its interval from
    # 2% to 23% -- and the cheap version is not free either.  `read` from one
    # /proc file is a builtin and forks nothing; only the sleep does.
    peak=0
    local -a f
    while kill -0 "$bpid" 2>/dev/null; do
        # Past the last ')', because a comm field can contain spaces and
        # parentheses and field numbers before it cannot be trusted.  After it
        # the fields start at state, so utime and stime are 11 and 12.
        if read -r cur < "/proc/$bpid/stat" 2>/dev/null; then
            f=(${cur#*') '})
            peak=$(( ${f[11]:-0} + ${f[12]:-0} ))
        fi
        sleep 0.25
    done
    wait "$bpid"; rc=$?
    t1=$(date +%s%N); w1=$(cpu_ticks_of "$wpid")
    out=$(cat "$TMPDIR_BENCH/$arm.out" 2>/dev/null)

    local wc cc rate p50 complete
    wc=$(socketley_cores_since "$w0" "$w1" "$t0" "$t1")
    # From zero, because this process was forked for this run: its whole life
    # is the window being divided by.
    cc=$(awk -v c="$peak" -v hz="$HZ" -v ns=$((t1 - t0)) \
             'BEGIN { printf "%.2f", (ns > 0 ? c / hz / (ns / 1e9) : 0) }')

    rate=$(json_field "$out" median_deliveries_per_sec)
    p50=$(json_field  "$out" delivery_p50_us)
    complete=$(json_field "$out" complete)
    # An exit of 2 is socketley_bench's own INCOMPLETE, which here means
    # deliveries went missing -- and a fan-out that lost messages is faster than
    # one that did not, so this must never reach a median.
    [ "$rc" = "0" ] || complete=0

    echo "${rate:-0} ${wc:-0} ${cc:-0} ${p50:-0} ${complete:-0}"
}

# One value out of socketley_bench's single-line JSON.
json_field() {
    printf '%s' "$1" | tr ',' '\n' | grep -m1 "\"$2\":" | sed 's/.*: *//; s/[}"]//g'
}

# ─── Setup ──────────────────────────────────────────────────────────────────

TMPDIR_BENCH=$(mktemp -d)
trap 'rm -rf "$TMPDIR_BENCH"' EXIT

log_section "Fan-out: broadcast vs inout relay vs cache pub/sub"

check_binary || exit 1
ensure_socketley_bench || exit 1
bench_check_port_range $BC_PORT $RL_PORT $PS_PORT

if (( PASSES < 3 )); then
    log_error "PASSES=$PASSES: a comparison with fewer than three passes has no interval"
    exit 1
fi

start_daemon || exit 1
cleanup_runtimes >/dev/null 2>&1

if [ "$TLS" = "1" ]; then
    command -v openssl >/dev/null 2>&1 || { log_error "BENCH_FANOUT_TLS=1 needs the openssl CLI"; stop_daemon; exit 1; }
    CERTS="$TMPDIR_BENCH/certs"; mkdir -p "$CERTS"
    # Two days and no passphrase, the same throwaway the TLS integration tests
    # generate; the client is told not to verify it.
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
        -keyout "$CERTS/k.pem" -out "$CERTS/c.pem" \
        -subj "/CN=localhost" >/dev/null 2>&1 \
        || { log_error "could not generate a certificate"; stop_daemon; exit 1; }
    TLS_FLAGS="--tls --cert $CERTS/c.pem --key $CERTS/k.pem"
    TLS_ARG="-S"
    log_info "TLS: the same three arms over the record layer"
fi

socketley_cmd create server "${ARM_NAME[broadcast]}" -p $BC_PORT --mode inout \
    --lua "${SCRIPT_DIR}/fanout.lua" $TLS_FLAGS -s >/dev/null 2>&1
socketley_cmd create server "${ARM_NAME[relay]}"     -p $RL_PORT --mode inout $TLS_FLAGS -s >/dev/null 2>&1
socketley_cmd create cache  "${ARM_NAME[pubsub]}"    -p $PS_PORT $TLS_FLAGS -s >/dev/null 2>&1

for arm in $ARMS; do
    wait_for_port "${ARM_PORT[$arm]}" || { log_error "$arm never bound ${ARM_PORT[$arm]}"; stop_daemon; exit 1; }
    # The process actually holding the port, from the daemon's own record.  All
    # three runtimes are up for the whole run so that an arm is never measured
    # against a freshly forked worker, and that makes a whole-tree CPU reading
    # useless: it would carry two idle runtimes as well as the one under load.
    ARM_PID[$arm]=$(socketley_cmd stats "${ARM_NAME[$arm]}" | sed -n 's/^pid://p')
    [ -n "${ARM_PID[$arm]}" ] || { log_error "no worker pid for $arm"; stop_daemon; exit 1; }
done

echo "[" > "$RESULTS_FILE"
FIRST_RESULT=true

# ─── The measurement ────────────────────────────────────────────────────────

for SUBS in $SUB_CASES; do
    log_info "── $SUBS subscribers, ${MSG_SIZE} B payload, ${RUN_MS} ms per run ──"

    # A discarded pass, so that no arm is measured on the first contact of the
    # run: the first invocation against a runtime that has been idle pays for a
    # cold accept path, and whichever arm leads pays it.
    for arm in $ARMS; do arm_run "$arm" "$SUBS" >/dev/null; done

    declare -A RATES WC CC P50
    for arm in $ARMS; do RATES[$arm]=""; WC[$arm]=""; CC[$arm]=""; P50[$arm]=""; done
    R_BC=""; R_RL=""; U_BC=""; U_RL=""
    kept=0; dropped=0; badrun=0; attempt=0
    max_attempts=$((PASSES * 2 + 2))

    while (( kept < PASSES && attempt < max_attempts )); do
        attempt=$((attempt + 1))
        before=$(box_load_cores)

        # Rotated, not alternated: with three arms, swapping two of them leaves
        # the third always last.
        case $((attempt % 3)) in
            1) order="broadcast relay pubsub" ;;
            2) order="relay pubsub broadcast" ;;
            *) order="pubsub broadcast relay" ;;
        esac

        declare -A pr pw pc pp
        pass_ok=1
        for arm in $order; do
            read -r r w c p done_ok <<<"$(arm_run "$arm" "$SUBS")"
            pr[$arm]=$r; pw[$arm]=$w; pc[$arm]=$c; pp[$arm]=$p
            if [ "$done_ok" != "1" ] || awk -v x="$r" 'BEGIN{exit !(x <= 0)}'; then
                pass_ok=0
            fi
        done
        after=$(box_load_cores)

        if awk -v x="$before" -v y="$after" -v lim="$QUIET_CORES" \
               'BEGIN { exit !(x > lim || y > lim) }'; then
            dropped=$((dropped + 1)); continue
        fi
        # Counted apart from the quiet gate, because they mean opposite things:
        # a busy box says nothing about the code, a lost delivery says the run
        # was not a fan-out.
        if (( ! pass_ok )); then badrun=$((badrun + 1)); continue; fi

        for arm in $ARMS; do
            RATES[$arm]="${RATES[$arm]} ${pr[$arm]}"
            WC[$arm]="${WC[$arm]} ${pw[$arm]}"
            CC[$arm]="${CC[$arm]} ${pc[$arm]}"
            P50[$arm]="${P50[$arm]} ${pp[$arm]}"
        done
        # The per-pass ratio, which is the only comparison that survives this
        # box.  Never the ratio of the two medians: that is the unpaired
        # comparison wearing a median's clothes.
        # The parentheses are load-bearing.  awk reads `printf fmt, a > b` as a
        # redirection into the file named by b, so the unbracketed form is a
        # syntax error and every ratio came out empty -- the same trap
        # bench_cache_resp.sh documents, met again one file later.
        R_BC="$R_BC $(awk -v a="${pr[broadcast]}" -v b="${pr[pubsub]}" 'BEGIN{printf "%.4f", (b > 0 ? a / b : 0)}')"
        R_RL="$R_RL $(awk -v a="${pr[relay]}"     -v b="${pr[pubsub]}" 'BEGIN{printf "%.4f", (b > 0 ? a / b : 0)}')"
        # And the same pair on worker CPU per delivery, which is the headline:
        # pubsub's cost over the arm's, so above 1 the arm is the cheaper one.
        U_BC="$U_BC $(awk -v wa="${pw[broadcast]}" -v ra="${pr[broadcast]}" -v wb="${pw[pubsub]}" -v rb="${pr[pubsub]}" \
                         'BEGIN{printf "%.4f", ((wa > 0 && rb > 0) ? (wb / rb) / (wa / ra) : 0)}')"
        U_RL="$U_RL $(awk -v wa="${pw[relay]}" -v ra="${pr[relay]}" -v wb="${pw[pubsub]}" -v rb="${pr[pubsub]}" \
                         'BEGIN{printf "%.4f", ((wa > 0 && rb > 0) ? (wb / rb) / (wa / ra) : 0)}')"
        kept=$((kept + 1))
    done

    if (( kept < 3 )); then
        log_error "$SUBS subscribers: $kept usable passes ($dropped dropped for box load, $badrun for lost deliveries) — no interval, nothing reported"
        continue
    fi

    # Worker CPU per delivery is the headline, not the rate.  It is a
    # proportion, so it survives the governor moving under it -- and it keeps
    # its meaning when the client and not the runtime is what ended the run: a
    # worker handed less work still says what each delivery cost it.
    declare -A UPD
    printf '\n  %-10s %14s %9s %12s %9s %9s %10s\n' \
        arm deliveries/s ±CI% us_of_worker worker_c client_c queue_p50
    for arm in $ARMS; do
        UPD[$arm]=$(awk -v w="$(median_of "${WC[$arm]}")" -v r="$(median_of "${RATES[$arm]}")" \
                        'BEGIN { printf "%.3f", (r > 0 ? w * 1e6 / r : 0) }')
        printf '  %-10s %14.0f %8s%% %12s %9s %9s %10s\n' \
            "$arm" "$(median_of "${RATES[$arm]}")" "$(ci_pct_of "${RATES[$arm]}")" \
            "${UPD[$arm]}" "$(median_of "${WC[$arm]}")" "$(median_of "${CC[$arm]}")" \
            "$(median_of "${P50[$arm]}")"
    done
    printf '  queue_p50 is publish to receipt under a saturating publisher: queueing depth, not service latency\n'

    M_BC=$(median_of "$U_BC"); C_BC=$(ci_pct_of "$U_BC")
    M_RL=$(median_of "$U_RL"); C_RL=$(ci_pct_of "$U_RL")
    printf '\n  worker cost per delivery, pubsub over the arm (above 1: the arm is cheaper)\n'
    printf '  broadcast  %sx  ±%s%%\n' "$M_BC" "$C_BC"
    printf '  relay      %sx  ±%s%%\n' "$M_RL" "$C_RL"
    printf '  rate, the arm over pubsub (the client decides it when a worker is under 1.0)\n'
    printf '  broadcast  %sx  ±%s%%\n' "$(median_of "$R_BC")" "$(ci_pct_of "$R_BC")"
    printf '  relay      %sx  ±%s%%\n' "$(median_of "$R_RL")" "$(ci_pct_of "$R_RL")"
    printf '  %d passes kept, %d dropped for box load, %d for lost deliveries\n' \
        "$kept" "$dropped" "$badrun"

    # The verdict names what limited the run, because a fan-out benchmark has
    # two ceilings of its own before it reaches the runtime's.  The client runs
    # four reader threads and a publisher, so five cores is its wall; and a
    # worker that is not at 1.0 was waiting for the client rather than working.
    CLIENT_MAX=$(median_of "${CC[pubsub]} ${CC[broadcast]} ${CC[relay]}")
    WORK_MIN=$(printf '%s\n' "$(median_of "${WC[broadcast]}")" "$(median_of "${WC[relay]}")" \
                             "$(median_of "${WC[pubsub]}")" | sort -g | head -1)
    if awk -v c="$CLIENT_MAX" 'BEGIN{exit !(c >= 4.0)}'; then
        log_warn "the client held $CLIENT_MAX cores across four readers and a publisher — this is its ceiling, not the runtimes'"
    elif awk -v w="$WORK_MIN" 'BEGIN{exit !(w < 0.85)}'; then
        log_warn "the slowest arm's worker sat at $WORK_MIN cores — it was waiting for the client, so these are not saturated rates"
    fi
    if awk -v c="$C_BC" -v t="$TARGET_PCT" 'BEGIN{exit !(c > t)}'; then
        log_warn "the broadcast ratio resolves only ±${C_BC}%, wider than the ${TARGET_PCT}% asked of it — report the range, not the ratio"
    fi

    $FIRST_RESULT || echo "," >> "$RESULTS_FILE"
    FIRST_RESULT=false
    {
        printf '{"subs":%d,"msg_size":%d,"run_ms":%d,"passes":%d,"dropped":%d,"badrun":%d' \
            "$SUBS" "$MSG_SIZE" "$RUN_MS" "$kept" "$dropped" "$badrun"
        for arm in $ARMS; do
            printf ',"%s_deliveries_per_sec":%s,"%s_ci_pct":%s,"%s_worker_cores":%s,"%s_client_cores":%s,"%s_p50_us":%s' \
                "$arm" "$(median_of "${RATES[$arm]}")" "$arm" "$(ci_pct_of "${RATES[$arm]}")" \
                "$arm" "$(median_of "${WC[$arm]}")"    "$arm" "$(median_of "${CC[$arm]}")" \
                "$arm" "$(median_of "${P50[$arm]}")"
            printf ',"%s_us_of_worker_per_delivery":%s' "$arm" "${UPD[$arm]}"
        done
        printf ',"broadcast_cost_advantage":%s,"broadcast_cost_advantage_ci_pct":%s' "$M_BC" "$C_BC"
        printf ',"relay_cost_advantage":%s,"relay_cost_advantage_ci_pct":%s}\n'      "$M_RL" "$C_RL"
    } >> "$RESULTS_FILE"
done

echo "]" >> "$RESULTS_FILE"
cleanup_runtimes >/dev/null 2>&1
stop_daemon
log_success "results: $RESULTS_FILE"
