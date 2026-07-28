#!/bin/bash
# Compare two benchmark runs and print the per-metric delta.
#
# Benchmark results land in results/<suite>_<TIMESTAMP>.json, where each file is
# a stream of JSON objects carrying a "test" key plus arbitrary numeric metrics
# (nested objects are supported — cache_resp nests per-operation results).
# This script flattens both runs to "test.path = value" pairs, joins them, and
# reports the change.
#
# Whether an increase is good depends on the metric, so the direction is derived
# from the metric name: throughput-style names (ops, rps, throughput, ...) are
# better when they go up, cost-style names (latency, cpu, time, overhead, ...)
# when they go down.
#
# Usage:
#   bench_compare.sh --list                    show available run timestamps
#   bench_compare.sh <baseline>                compare baseline against newest run
#   bench_compare.sh <baseline> <current>      compare two specific runs
#   bench_compare.sh <baseline> <current> -v   also list unchanged metrics

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/results"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; DIM='\033[2m'; NC='\033[0m'

# Threshold below which a change is treated as noise rather than a real move.
#
# Calibrated by comparing two back-to-back runs of the *same* binary on the
# 4-vCPU dev VM: redis-benchmark at pipeline depth 1 moved by up to 13% and
# socketley by up to 7% with no code change at all.  5% is therefore a floor,
# not a guarantee — a single run can only demonstrate large effects.  For
# anything smaller, take the median of several runs and raise this via
# BENCH_NOISE_PCT rather than trusting a lone measurement.
NOISE_PCT=${BENCH_NOISE_PCT:-5}

command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 1; }

# All run timestamps that have at least one result file, oldest first.
list_timestamps() {
    find "$RESULTS_DIR" -maxdepth 1 -name '*.json' -printf '%f\n' 2>/dev/null \
        | sed -n 's/.*_\([0-9]\{8\}_[0-9]\{6\}\)\.json$/\1/p' \
        | sort -u
}

# Flatten every result file of one run into "metric<TAB>value" lines.
# Metric is "<suite>.<test>.<json path>", e.g. "cache_resp.cache_resp_vs_redis.SET.socketley_ops".
flatten_run() {
    local ts=$1 f suite
    for f in "$RESULTS_DIR"/*_"$ts".json; do
        [[ -f "$f" ]] || continue
        suite=$(basename "$f" | sed "s/_${ts}\.json$//")

        # A suite killed by its timeout leaves a half-written file behind.  jq
        # cannot parse it, which without this check would silently contribute
        # zero metrics — the run would look complete and merely "unmatched",
        # hiding the fact that a whole suite never finished.
        if ! jq -e . "$f" >/dev/null 2>&1; then
            echo "WARN: $(basename "$f") is not valid JSON (suite crashed or timed out) — skipped" >&2
            continue
        fi
        # Two result shapes exist in this repo: write_json_result() emits a
        # concatenated stream of objects, while bench_cache_resp.sh writes a
        # single top-level array.  Slurping handles the stream; the inner
        # flatten unwraps the array case so both end up as a list of objects.
        #
        # A "test" name is not unique on its own — bench_cache.sh runs "cache
        # set" once per payload size and bench_cache_resp.sh writes one record
        # per pipeline depth, all under the same name.  Without a discriminator
        # the join below degenerates into a cross product.
        #
        # The discriminator is built from the fields that describe *how* a test
        # was configured, never from what it measured.  Position within the file
        # is deliberately not used: a run that dies partway through shifts every
        # later index, which silently pairs unrelated records and manufactures
        # six-digit percentage swings out of nothing.
        jq -rs --arg suite "$suite" '
            def ident:
                [ "operations", "msg_size", "runs", "clients", "pipeline",
                  "scenario", "duration_sec", "category" ] as $keys
                | . as $o
                | [ $keys[] | select($o[.] != null) | "\(.)=\($o[.])" ]
                | if length == 0 then "" else "[" + join(",") + "]" end;

            [ .[] | if type == "array" then .[] else . end ]
            | [ .[] | select(type == "object") ] as $objs
            | [ $objs[] | { o: ., k: ((.test // "unknown") + (. | ident)) } ] as $recs
            # Records that are still identical after the identity key — older
            # result files predating msg_size, for instance — get an ordinal
            # within their own group.  Scoping it to the group matters: a
            # global index would shift for every later record whenever one test
            # is added or fails to write.
            | reduce range(0; $recs | length) as $i
                ({ seen: {}, out: [] };
                  $recs[$i].k as $k
                  | (.seen[$k] // 0) as $n
                  | .seen[$k] = $n + 1
                  | .out += [{ o: $recs[$i].o, k: $k, ord: $n }])
            | .out[]
            | .o as $o | .k as $k | .ord as $ord
            | $o
            | paths(type == "number") as $p
            | "\($suite).\($k)#\($ord).\($p | join("."))\t\(getpath($p))"
        ' "$f" 2>/dev/null
    done | sort -u
}

# Is a bigger number better for this metric? Echoes "up" or "down".
direction_of() {
    case "${1,,}" in
        *latency*|*_ms*|*ms_*|*cpu*|*time*|*overhead*|*p50*|*p95*|*p99*|*errors*|*failed*)
            echo down ;;
        *)
            echo up ;;
    esac
}

usage() {
    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
    echo
    echo "Available runs:"
    list_timestamps | tail -20 | sed 's/^/  /'
}

VERBOSE=0
ARGS=()
for a in "$@"; do
    case "$a" in
        -v|--verbose) VERBOSE=1 ;;
        --list) list_timestamps; exit 0 ;;
        -h|--help) usage; exit 0 ;;
        *) ARGS+=("$a") ;;
    esac
done

if [[ ${#ARGS[@]} -lt 1 ]]; then
    usage
    exit 1
fi

BASE_TS="${ARGS[0]}"
CUR_TS="${ARGS[1]:-$(list_timestamps | tail -1)}"

if [[ -z "$CUR_TS" ]]; then
    echo "No benchmark runs found in $RESULTS_DIR" >&2
    exit 1
fi
if [[ "$BASE_TS" == "$CUR_TS" ]]; then
    echo "Baseline and current are the same run ($BASE_TS)" >&2
    exit 1
fi

BASE_F=$(mktemp); CUR_F=$(mktemp)
trap 'rm -f "$BASE_F" "$CUR_F"' EXIT

flatten_run "$BASE_TS" > "$BASE_F"
flatten_run "$CUR_TS"  > "$CUR_F"

if [[ ! -s "$BASE_F" ]]; then
    echo "No result data for baseline $BASE_TS" >&2
    exit 1
fi
if [[ ! -s "$CUR_F" ]]; then
    echo "No result data for current $CUR_TS" >&2
    exit 1
fi

echo ""
echo -e "${CYAN}Benchmark comparison${NC}"
echo -e "  baseline: ${DIM}$BASE_TS${NC}  ($(wc -l < "$BASE_F") metrics)"
echo -e "  current:  ${DIM}$CUR_TS${NC}  ($(wc -l < "$CUR_F") metrics)"
echo -e "  noise threshold: ±${NOISE_PCT}%"
echo ""

printf "  %-62s %14s %14s %10s\n" "Metric" "Baseline" "Current" "Delta"
printf "  %-62s %14s %14s %10s\n" \
    "──────────────────────────────────────────────────────────────" \
    "──────────────" "──────────────" "──────────"

# Join on the metric name; only metrics present in both runs are comparable.
improved=0; regressed=0; unchanged=0; shown=0
while IFS=$'\t' read -r metric base cur; do
    [[ -z "$metric" ]] && continue

    pct=$(awk -v b="$base" -v c="$cur" 'BEGIN {
        if (b == 0) { print (c == 0) ? 0 : 9999; exit }
        printf "%.2f", ((c - b) / b) * 100
    }')

    dir=$(direction_of "$metric")
    abs=${pct#-}
    is_noise=$(awk -v a="$abs" -v n="$NOISE_PCT" 'BEGIN { print (a < n) ? 1 : 0 }')

    if [[ "$is_noise" == "1" ]]; then
        unchanged=$((unchanged + 1))
        [[ $VERBOSE -eq 0 ]] && continue
        color=$DIM; mark="="
    else
        better=$(awk -v p="$pct" -v d="$dir" 'BEGIN {
            print (d == "up") ? (p > 0 ? 1 : 0) : (p < 0 ? 1 : 0)
        }')
        if [[ "$better" == "1" ]]; then
            improved=$((improved + 1)); color=$GREEN; mark="▲"
        else
            regressed=$((regressed + 1)); color=$RED; mark="▼"
        fi
    fi

    shown=$((shown + 1))
    # Truncate from the left: the distinguishing part of a metric path is its
    # tail (…GET.redis_ops vs …GET.redis_p50_ms), so cutting the head keeps
    # long names readable where cutting the tail would make them ambiguous.
    disp="$metric"
    [[ ${#disp} -gt 62 ]] && disp="…${disp: -61}"
    printf "  %-62s %14s %14s ${color}%8s%% %s${NC}\n" \
        "$disp" "$base" "$cur" "$pct" "$mark"
done < <(join -t$'\t' -j1 "$BASE_F" "$CUR_F")

if [[ $shown -eq 0 ]]; then
    echo -e "  ${DIM}(no metrics differ by more than ±${NOISE_PCT}%)${NC}"
fi

echo ""
echo -e "  ${GREEN}improved: $improved${NC}   ${RED}regressed: $regressed${NC}   ${DIM}within noise: $unchanged${NC}"

# Metrics that exist in only one of the runs — usually a renamed or newly added
# test, but also what you see when a suite crashed and wrote nothing.
only_base=$(comm -23 <(cut -f1 "$BASE_F") <(cut -f1 "$CUR_F") | wc -l)
only_cur=$(comm -13 <(cut -f1 "$BASE_F") <(cut -f1 "$CUR_F") | wc -l)
if [[ $only_base -gt 0 || $only_cur -gt 0 ]]; then
    echo -e "  ${YELLOW}unmatched: $only_base only in baseline, $only_cur only in current${NC}"
    if [[ $VERBOSE -eq 1 ]]; then
        comm -23 <(cut -f1 "$BASE_F") <(cut -f1 "$CUR_F") | sed 's/^/    - /'
        comm -13 <(cut -f1 "$BASE_F") <(cut -f1 "$CUR_F") | sed 's/^/    + /'
    fi
fi
echo ""

[[ $regressed -gt 0 ]] && exit 2
exit 0
