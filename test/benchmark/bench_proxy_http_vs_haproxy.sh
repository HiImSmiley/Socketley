#!/bin/bash
# HTTP proxying vs HAProxy — keep-alive and connection-per-request.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# bench_proxy_vs_haproxy.sh compares the two proxies on `--protocol tcp` over
# loopback with no TLS.  That is the narrowest slice of what a proxy does, and
# it is the slice where an HTTP proxy is least itself: nothing is parsed, no
# request is routed, no connection is reused on the reader's behalf.  HAProxy is
# written for the mode this file measures, and until now that mode had never
# been compared with anything.
#
# bench_proxy.sh does drive HTTP, but through a Python raw-socket backend, and
# the 6329 req/s it reported is far more likely to be Python's ceiling than the
# proxy's.  3032189 fixed that test's client and left the fixture question open
# on purpose.  This is the answer to it.
#
# ─── THE BACKEND, WHICH IS THE REAL DECISION ────────────────────────────────
#
# A socketley server runtime with `--http <dir> --http-cache`, serving one small
# static file out of memory.  It was chosen by measuring it rather than by
# assuming, because a backend that caps both arms equally measures nothing and
# looks exactly like a result:
#
#   Direct, no proxy, keep-alive: 72241 req/s on one connection, 145430 on two,
#   and 152497..211007 from four connections upward, at which point it is at
#   1.00 cores and that is its ceiling.
#
#   Through either proxy, the same backend sits at 0.26..0.72 cores.  The proxies
#   are the limit, not it, in every case this file runs — and where that stops
#   being true the case is labelled backend-bound and its ratio is withheld,
#   using the same test as the TCP file.
#
# `--http-cache` is not optional here.  Without it every request is a disk read,
# and the case that would then be measured is the page cache.
#
# Lua is deliberately absent from the backend.  The TCP file's echo.lua fixture
# runs an interpreter per message; this one answers from a byte buffer, which is
# what leaves the headroom above.
#
# ─── THE TRAP THIS FILE EXISTS TO NOT FALL INTO ─────────────────────────────
#
# The two proxies need *different request paths* to reach the same file.
# socketley's HTTP proxy routes on a leading `/<runtime-name>/` and strips it
# before forwarding; haproxy is given the bare path.  Point both arms at the
# same URL, as anybody would, and socketley answers
#
#   HTTP/1.1 404 Not Found ... Connection: close
#
# which it produces faster than haproxy serves the file, and then closes the
# connection so the keep-alive case silently becomes something else.  Measured
# that way socketley "did" 6656 req/s on one connection and every worker thread
# ended in an error that no throughput number mentions.
#
# So each arm gets its own path, and before any measurement both are fetched and
# required to return 200 with the same body length.  A benchmark whose fairness
# rests on a URL convention has to check the URL.
#
# ─── WHAT KEEP-ALIVE AND CONNECTION-PER-REQUEST ARE FOR ─────────────────────
#
# They are not two settings of one benchmark; they are the two halves of what
# separates HTTP proxies, and running only the first flatters whichever one
# pools connections better.  With keep-alive the connection exists already and
# the proxy's per-request cost is all that is left.  Without it every request
# pays an accept, a backend connection, and two teardowns — and whether the
# proxy pools its backend side is exactly the difference being looked for.
#
# On this box the two cases disagree about who is faster, which is the whole
# argument for measuring both.
#
# ─── WINDOW LENGTH ──────────────────────────────────────────────────────────
#
# Twice the TCP file's, and the backend is why.  A socketley server has a
# periodic cost that a short window either catches or misses.  Measured on the
# backend directly, interleaving the two window lengths so both see the same
# machine, seven each: one-second windows spanned 154872..237487 req/s
# (coefficient of variation 16.0%), eight-second windows 153385..194082 (8.9%),
# with medians of 170707 and 169763.  The same work, sampled better.
#
# It carries through the proxy, though diluted — behind a proxy the backend runs
# at 0.3..0.7 cores rather than at 1.00, so it contributes less of the total.
# Through the socketley proxy at eight connections, eleven interleaved runs
# each: 1500 ms gave a coefficient of variation of 14.1% and a spread of 1.69x,
# 3000 ms gave 8.5% and 1.42x, medians 75275 and 75876.  Hence the 3000 below.
#
# A first attempt at this measurement, nine runs of 1500 against 2500, said the
# longer window was *worse* — 16.3% against 26.9%.  That was the box drifting
# under both series at once, with too few runs to tell.  It is recorded here
# because it is the shape of the mistake this whole harness is built to avoid,
# and it very nearly went into this comment as a fact.
#
# Measuring a server runtime *directly* is the undiluted case and wants a much
# longer window still: BENCH_SERVER_RUN_MS in utils.sh carries that default.
#
# ─── WHAT IT DOES NOT COVER ─────────────────────────────────────────────────
#
# No TLS on either leg, which is the next thing worth doing and a larger job:
# socketley_bench has no TLS client at all today, so it is a build change before
# it is a benchmark change.  One backend, so no load balancing and no health
# checking.  One small file, so no streaming and no chunked bodies of interest.
# Loopback, so no NIC and no real RTT.  And GET only — socketley's `--http`
# serves nothing else.

source "$(dirname "$0")/utils.sh"
source "$(dirname "$0")/lib_paired.sh"

BENCH_PORT_BASE=${BENCH_PORT_BASE:-23000}
BACKEND_PORT=$((BENCH_PORT_BASE + 20))
SK_PORT=$((BENCH_PORT_BASE + 21))
HA_PORT=$((BENCH_PORT_BASE + 22))

SK_NAME=hb_prox
BE_NAME=hb_backend

PAIRS=${1:-${BENCH_HTTP_RUNS:-7}}
if (( PAIRS < 3 )); then
    log_warn "raising pairs from $PAIRS to 3: fewer cannot produce an interval"
    PAIRS=3
fi

CONNS=${BENCH_HTTP_CONNS:-"1 8 32"}
RUN_MS=${BENCH_HTTP_RUN_MS:-3000}
OPS_CAP=100000000
TARGET_PCT=${BENCH_RESOLUTION_TARGET:-15}
QUIET_CORES=${BENCH_QUIET_CORES:-1.0}

RESULTS_FILE="${RESULTS_DIR}/proxy_http_vs_haproxy_${TIMESTAMP}.json"
WORK=$(mktemp -d)
HA_PID=""

cleanup() {
    [[ -n "$HA_PID" ]] && kill "$HA_PID" 2>/dev/null
    socketley_cmd stop  "$SK_NAME" 2>/dev/null
    socketley_cmd stop  "$BE_NAME" 2>/dev/null
    sleep 0.4
    socketley_cmd remove "$SK_NAME" 2>/dev/null
    socketley_cmd remove "$BE_NAME" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

if ! command -v haproxy >/dev/null 2>&1; then
    log_error "haproxy not installed — nothing to compare against"
    exit 0
fi
HA_VERSION=$(haproxy -v 2>&1 | head -1 | sed 's/[",]/ /g')

echo "[" > "$RESULTS_FILE"
FIRST_RESULT=true
append_result() {
    if [[ $FIRST_RESULT == true ]]; then FIRST_RESULT=false; else echo "," >> "$RESULTS_FILE"; fi
}

pid_on_port() {
    ss -ltnp 2>/dev/null | awk -v p=":$1\$" '$4 ~ p' \
        | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2
}

log_section "HTTP proxying vs HAProxy — keep-alive and connection-per-request"
log_info "$HA_VERSION"
log_info "ports ${BACKEND_PORT}/${SK_PORT}/${HA_PORT}  ${PAIRS} pairs  ${RUN_MS} ms per run"

# ─── Fixtures ───────────────────────────────────────────────────────────────

mkdir -p "$WORK/www"
printf 'ok' > "$WORK/www/small.txt"
# A body big enough that forwarding it costs something, and not an .html file:
# `--http` injects a WebSocket script into every .html and .htm response it
# serves, so an HTML fixture would be measuring a rewrite as well as a send.
head -c 16384 /dev/zero | tr '\0' 'x' > "$WORK/www/large.txt"
chmod -R a+rX "$WORK"

ensure_clean() {
    socketley_cmd stop  "$SK_NAME" >/dev/null 2>&1
    socketley_cmd stop  "$BE_NAME" >/dev/null 2>&1
    sleep 0.4
    socketley_cmd remove "$SK_NAME" >/dev/null 2>&1
    socketley_cmd remove "$BE_NAME" >/dev/null 2>&1
}

ensure_clean
socketley_cmd create server "$BE_NAME" -p "$BACKEND_PORT" \
    --http "$WORK/www" --http-cache -s
wait_for_port "$BACKEND_PORT" || { log_error "backend did not come up"; exit 1; }

socketley_cmd create proxy "$SK_NAME" -p "$SK_PORT" \
    --backend "127.0.0.1:$BACKEND_PORT" --protocol http -s
wait_for_port "$SK_PORT" || { log_error "socketley proxy did not come up"; exit 1; }

# A haproxy left behind by an earlier run holds this port and answers on it, and
# wait_for_port below would be satisfied by it — so the whole comparison would
# run against somebody else's configuration, pointed at somebody else's backend,
# and say nothing about it.  Refuse instead.
if [[ -n "$(pid_on_port "$HA_PORT")" ]]; then
    log_error "port $HA_PORT is already listening before we started haproxy"
    log_error "held by pid $(pid_on_port "$HA_PORT") — a stale haproxy would be measured as ours"
    exit 1
fi

cat > "$WORK/haproxy.cfg" <<EOF
global
    nbthread 1
    maxconn 8192

defaults
    mode http
    timeout connect 5s
    timeout client  30s
    timeout server  30s

frontend fe
    bind 127.0.0.1:$HA_PORT
    default_backend be

backend be
    server s1 127.0.0.1:$BACKEND_PORT
EOF

haproxy -f "$WORK/haproxy.cfg" -db > "$WORK/haproxy.out" 2>&1 &
HA_PID=$!
wait_for_port "$HA_PORT" || { log_error "haproxy did not come up: $(cat "$WORK/haproxy.out")"; exit 1; }
sleep 0.5

SK_PID=$(pid_on_port "$SK_PORT")
BE_PID=$(pid_on_port "$BACKEND_PORT")
B_PID=$(pid_on_port "$HA_PORT")
if [[ -z "$SK_PID" || -z "$BE_PID" || -z "$B_PID" ]]; then
    log_error "could not identify a process under test (sk=$SK_PID be=$BE_PID hap=$B_PID)"
    exit 1
fi
log_info "socketley proxy pid=$SK_PID  haproxy pid=$B_PID  backend pid=$BE_PID"

# ─── The fairness check ─────────────────────────────────────────────────────
#
# Both arms must answer 200 with the same number of bytes before anything is
# timed.  Without this the socketley arm's 404 — cheaper to produce than the
# file, and followed by a close — is measured and reported as throughput.
fetch_status_len() {   # port path -> "status bodylen"
    python3 - "$1" "$2" <<'PY' 2>/dev/null || echo "ERR 0"
import socket, sys
port, path = int(sys.argv[1]), sys.argv[2]
req = ("GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n" % path).encode()
try:
    s = socket.create_connection(("127.0.0.1", port), 5); s.settimeout(5)
    s.sendall(req)
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(65536)
        if not d: break
        buf += d
    head, rest = buf.split(b"\r\n\r\n", 1)
    status = head.split(b"\r\n")[0].split(b" ")[1].decode()
    cl = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            cl = int(line.split(b":")[1])
    s.close()
    print(status, cl)
except Exception:
    print("ERR", 0)
PY
}

check_arms() {   # file
    local f=$1 sk hap
    sk=$(fetch_status_len "$SK_PORT" "/$SK_NAME/$f")
    hap=$(fetch_status_len "$HA_PORT" "/$f")
    if [[ "$sk" != "$hap" ]]; then
        log_error "the two arms do not serve the same thing for $f:"
        log_error "  socketley /$SK_NAME/$f -> $sk"
        log_error "  haproxy   /$f          -> $hap"
        log_error "a ratio between these would compare an error page with a file"
        return 1
    fi
    if [[ "${sk%% *}" != "200" ]]; then
        log_error "both arms answered ${sk%% *} for $f, not 200 — nothing is being served"
        return 1
    fi
    log_info "both arms serve $f identically: HTTP ${sk%% *}, ${sk##* } bytes"
    return 0
}

check_arms small.txt || exit 1
check_arms large.txt || exit 1

# ─── One measured run, per arm ──────────────────────────────────────────────
#
# MODE is the bench test name; A is the connection count; B is the file.  The
# request path differs per arm and that is the point of routing it here.
measure() {
    local port=$1 mode=$2 conns=$3 path=$4 px_pid=$5
    local p0 p1 e0 e1 w0 w1 out rate

    p0=$(cpu_ticks_of "$px_pid"); e0=$(cpu_ticks_of "$BE_PID"); w0=$(date +%s%N)
    out=$(timeout "$BENCH_TIMEOUT_CMD" "$SOCKETLEY_BENCH" -r 1 -d "$RUN_MS" \
          -u "$path" proxy "$mode" 127.0.0.1 "$port" "$conns" "$OPS_CAP" 2>/dev/null)
    w1=$(date +%s%N); p1=$(cpu_ticks_of "$px_pid"); e1=$(cpu_ticks_of "$BE_PID")

    rate=$(grep -oE '^\s*Median:\s+[0-9]+' <<<"$out" | grep -oE '[0-9]+' | head -1)
    # A run with any failed request is not a slower run, it is a different one:
    # a thread that gave up early stopped contributing load, and the rate that
    # comes out is for however many were still going.  Reported as zero, which
    # the pairing then discards.
    local failed
    failed=$(grep -oE 'Failed: [0-9]+' <<<"$out" | grep -oE '[0-9]+' | head -1)
    if [[ "${failed:-0}" -gt 0 ]]; then rate=0; fi

    awk -v r="${rate:-0}" -v px=$((p1 - p0)) -v be=$((e1 - e0)) \
        -v hz="$HZ" -v ns=$((w1 - w0)) \
        'BEGIN { s = ns / 1e9; printf "%s %.3f %.3f", r, px / hz / s, be / hz / s }'
}

arm_measure() {
    local arm=$1 mode=$2 conns=$3 file=$4
    if [[ $arm == a ]]; then measure "$SK_PORT" "$mode" "$conns" "/$SK_NAME/$file" "$SK_PID"
    else                     measure "$HA_PORT" "$mode" "$conns" "/$file" "$B_PID"; fi
}

# ─── Reporting ──────────────────────────────────────────────────────────────

WORST_CI=0

emit() {   # label mode conns file
    local label=$1 mode=$2 conns=$3 file=$4
    paired_run_case "$mode" "$conns" "$file"
    local v; v=$(paired_verdict "$C_CI" "$C_KEPT" "$C_BE")
    awk -v c="$C_CI" -v w="$WORST_CI" 'BEGIN { exit !(c > w) }' && WORST_CI=$C_CI

    local pa pb pr
    pa=$(printf '%.0f' "$C_A"); pb=$(printf '%.0f' "$C_B")
    pr=$(printf '%.2f' "$C_RATIO")
    printf "  %-13s %8s %8s   %6sx  ±%-6s %s\n" \
        "$label" "$pa" "$pb" "$pr" "${C_CI}%" "$v"

    append_result
    cat >> "$RESULTS_FILE" <<EOF
  {"test": "proxy_http_vs_haproxy", "case": "$label",
   "mode": "$mode", "connections": $conns, "file": "$file",
   "pairs_kept": $C_KEPT, "pairs_discarded_unquiet": $C_DROPPED,
   "pairs_discarded_failed": ${C_BADRUN:-0},
   "run_ms": $RUN_MS,
   "socketley_req_sec": ${C_A:-0}, "haproxy_req_sec": ${C_B:-0},
   "ratio_socketley_over_haproxy": ${C_RATIO:-0},
   "ratio_ci95_half_width_pct": ${C_CI:-0},
   "socketley_ci95_half_width_pct": ${C_A_CI:-0},
   "socketley_proxy_cores": ${C_APX:-0}, "haproxy_proxy_cores": ${C_BPX:-0},
   "backend_cores_during_socketley": ${C_ABE:-0},
   "backend_cores_during_haproxy": ${C_BBE:-0},
   "resolution_target_pct": $TARGET_PCT,
   "verdict": "$v",
   "haproxy_version": "$(sed 's/"/ /g' <<<"$HA_VERSION")"}
EOF
}

echo ""
log_info "keep-alive — the connection exists already, so this is per-request cost"
printf "  %-13s %8s %8s   %7s  %-7s %s\n" "conns" "sk" "hap" "sk/hap" "±95%CI" "verdict"
printf "  %-13s %8s %8s   %7s  %-7s %s\n" "───────────" "───────" "───────" "───────" "──────" "───────"
for c in $CONNS; do
    emit "$c" http-keepalive "$c" small.txt
done
emit "8, 16 KB" http-keepalive 8 large.txt

echo ""
log_info "connection per request — every request pays an accept and a backend connect"
printf "  %-13s %8s %8s   %7s  %-7s %s\n" "conns" "sk" "hap" "sk/hap" "±95%CI" "verdict"
printf "  %-13s %8s %8s   %7s  %-7s %s\n" "───────────" "───────" "───────" "───────" "──────" "───────"
for c in $CONNS; do
    emit "$c" http-close "$c" small.txt
done

echo "" >> "$RESULTS_FILE"
echo "]" >> "$RESULTS_FILE"

echo ""
log_info "the widest interval in this run was ±${WORST_CI}% — a difference smaller"
log_info "than that, in any case above, is this machine and not the proxy"
if awk -v w="$WORST_CI" -v t="$TARGET_PCT" 'BEGIN { exit !(w > t) }'; then
    log_warn "at least one case could not resolve ${TARGET_PCT}%; raise the pair count"
    log_warn "(first argument, currently $PAIRS) — the interval narrows as 1/sqrt(pairs)"
fi
log_info "results: $RESULTS_FILE"
