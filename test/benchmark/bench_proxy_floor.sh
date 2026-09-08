#!/usr/bin/env bash
# What a proxied round trip costs when nothing in the middle is ours.
#
# ─── WHY THIS IS THE NUMBER THAT DECIDES WHERE TO WORK ──────────────────────
#
# The matrix says we forward a 64-byte round trip at 1.05x HAProxy.  That is a
# ranking and not a budget: it says which of two programs is ahead, and nothing
# at all about whether either has anything left to give.  Both could be spending
# 95% of the round trip in the kernel, in which case 1.05x is the whole of the
# available difference and a week of work would move it by nothing.
#
# floor_relay.c is the budget.  It is a C program that accepts, connects to the
# backend, and pumps bytes: no io_uring, no framing, no routing, no pooling, no
# statistics, no configuration.  A round trip through it is what the kernel and
# the scheduler charge for four handoffs -- client to proxy to backend and back
# -- and everything above that line is what a proxy adds.
#
# It has existed in this directory the whole time and nothing has ever driven
# it.  bench_server_floor.sh does this for the server runtime against
# floor_server.c; there was no equivalent for the proxy, so every proxy number
# in this tree has been a ratio against another proxy and never a distance from
# the floor.
#
# ─── WHAT MAKES THE THREE ARMS COMPARABLE ───────────────────────────────────
#
# One backend object, one client binary, one message size, one connection, and
# the three arms rotated within every pass so a drifting box moves all of them
# together.  This box drifts by tens of percent inside a minute -- sixteen
# consecutive runs against one unchanged proxy fell from 77,000 to 59,000 round
# trips a second -- so measuring all of arm A and then all of arm B turns that
# drift into a difference between the arms.
#
# The backend is floor_server, not a socketley server with echo.lua: a Lua
# interpreter per message made the eight-connection row of the matrix
# backend-bound, and a fixture that is the ceiling puts every arm at the same
# rate and calls it parity.
#
# floor_relay runs `-m block` for the single-connection case, deliberately.  With
# one connection there is nothing to multiplex, so an epoll_wait would be a
# syscall the floor never has to pay -- and a floor that pays it is a floor set
# too high, which flatters everything measured against it.
#
# ─── READING IT ─────────────────────────────────────────────────────────────
#
# Microseconds per round trip, and the distance above the floor.  Quote the
# distance, never the rate: this box is a guest, `/sys/.../cpufreq` does not
# exist and /proc/cpuinfo reports a constant 2995.200 MHz whatever the host is
# doing, so an absolute rate is not comparable with one taken an hour ago.  The
# floor moves with the same clock, so "+4.1 us over the floor" keeps its meaning
# where "41,992/s" does not.
#
# CPU per round trip is beside it because the two come apart, and which one
# moves decides what a change is worth: a serial round trip on one connection
# waits on wakeups rather than on work, so freed CPU has nowhere to go and stays
# off the clock.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/utils.sh"
source "$HERE/lib_paired.sh"      # median_of, ci_pct_of, box_load_cores, HZ

PASSES=${FLOOR_PASSES:-7}
RUN_MS=${FLOOR_RUN_MS:-1500}
SIZES=${FLOOR_SIZES:-"64 1024 16384"}
QUIET_CORES=${BENCH_QUIET_CORES:-1.0}

B=${FLOOR_PORT_BASE:-26400}
P_BE=$((B+0)); P_FL=$((B+1)); P_SK=$((B+2)); P_HA=$((B+3))

W=$(mktemp -d /tmp/pfloor.XXXXXX)
export HOME=$W/home
export SOCKETLEY_SOCKET=$W/d.sock
unset SOCKETLEY_CONFIG
mkdir -p "$HOME"
DPID=""; HAP=""; KIDS=""

sweep() {
    local p c
    for p in $(pgrep -x socketley 2>/dev/null); do
        grep -qz "SOCKETLEY_SOCKET=$W/d.sock" "/proc/$p/environ" 2>/dev/null || continue
        for c in $(pgrep -P "$p" 2>/dev/null); do kill -9 "$c" 2>/dev/null; done
        kill -9 "$p" 2>/dev/null
    done
    return 0
}
cleanup() {
    local p
    for p in $KIDS; do kill -9 "$p" 2>/dev/null; done
    [ -n "$HAP" ] && kill -9 "$HAP" 2>/dev/null
    sweep; sleep 0.3; sweep
    [ -n "$DPID" ] && kill -9 "$DPID" 2>/dev/null
    rm -rf "$W"
    return 0
}
trap cleanup EXIT INT TERM

FLOOR_SRV=$PROJECT_ROOT/bin/Release/floor_server
FLOOR_RLY=$PROJECT_ROOT/bin/Release/floor_relay
for f in "$FLOOR_SRV" "$FLOOR_RLY" "$SOCKETLEY_BENCH"; do
    [ -x "$f" ] || { log_error "$f is not built (make -C make config=release_x64)"; exit 1; }
done
command -v haproxy >/dev/null || { log_error "haproxy is not installed"; exit 1; }

# Refused on CPU rather than on existence: an idle daemon holding no runtimes
# costs nothing, a socketley burning a core lands in every number below.
BUSY=$(
  ps=$(pgrep -x socketley 2>/dev/null | tr '\n' ' '); t0=0; t1=0
  for p in $ps; do t0=$((t0 + $(awk '{print $14+$15}' /proc/$p/stat 2>/dev/null || echo 0))); done
  sleep 0.3
  for p in $ps; do t1=$((t1 + $(awk '{print $14+$15}' /proc/$p/stat 2>/dev/null || echo 0))); done
  awk -v d=$((t1-t0)) -v hz="$(getconf CLK_TCK)" 'BEGIN{printf "%.2f", d/hz/0.3}')
awk -v b="$BUSY" 'BEGIN{exit !(b > 0.05)}' && {
    log_error "refusing: socketley processes are burning $BUSY cores"; exit 2; }

log_section "A proxied round trip, against the floor of four handoffs"

"$FLOOR_SRV" "$P_BE" -m epoll & KIDS="$KIDS $!"
sleep 0.4
# -m block: one connection, no readiness syscall.  See the header.
"$FLOOR_RLY" "$P_FL" 127.0.0.1 "$P_BE" -m block & KIDS="$KIDS $!"

"$SOCKETLEY_BIN" daemon >"$W/d.log" 2>&1 & DPID=$!
for _ in $(seq 1 100); do [ -S "$SOCKETLEY_SOCKET" ] && break; sleep 0.1; done
[ -S "$SOCKETLEY_SOCKET" ] || { log_error "the private daemon did not come up"; exit 1; }
socketley_cmd create proxy pf -p "$P_SK" --backend "127.0.0.1:$P_BE" --protocol tcp -s >/dev/null 2>&1

cat > "$W/h.cfg" <<CFG
global
    nbthread 1
    maxconn 8192
defaults
    mode tcp
    timeout connect 5s
    timeout client 30s
    timeout server 30s
listen l
    bind 127.0.0.1:$P_HA
    server s1 127.0.0.1:$P_BE
CFG
haproxy -f "$W/h.cfg" -db >"$W/h.log" 2>&1 & HAP=$!

for p in "$P_BE" "$P_FL" "$P_SK" "$P_HA"; do
    wait_for_port "$p" || { log_error "nothing came up on $p"; exit 1; }
done
sleep 0.5

pid_on() { ss -ltnp 2>/dev/null | awk -v p=":$1\$" '$4 ~ p' \
           | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2; }
FL_PID=$(pid_on "$P_FL"); SK_PID=$(pid_on "$P_SK"); HA_PID=$(pid_on "$P_HA")
BE_PID=$(pid_on "$P_BE")
for v in "$FL_PID" "$SK_PID" "$HA_PID" "$BE_PID"; do
    [ -n "$v" ] || { log_error "could not identify every process under test"; exit 1; }
done

# Every arm must actually forward before anything is timed.  A relay that
# refuses the connection is faster than one that carries it, and the difference
# does not appear in a throughput number.
probe() {
    python3 - "$1" <<'PY' 2>/dev/null
import socket, sys
try:
    s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5); s.settimeout(3)
    s.sendall(b"ping\n"); sys.stdout.write(s.recv(64).decode("latin1").strip())
except Exception:
    pass
PY
}
for p in "$P_FL" "$P_SK" "$P_HA"; do
    [ -n "$(probe "$p")" ] || { log_error "port $p forwarded nothing"; exit 1; }
done
log_info "floor pid=$FL_PID  socketley pid=$SK_PID  haproxy pid=$HA_PID  backend pid=$BE_PID"

# One run: rate, and the arm's own CPU per round trip.
leg() {   # port pid size -> "rate us_cpu_per_rt"
    local port=$1 pid=$2 size=$3 t0 t1 w0 w1 out rate
    t0=$(cpu_ticks_of "$pid"); w0=$(date +%s%N)
    out=$(timeout "$BENCH_TIMEOUT_CMD" "$SOCKETLEY_BENCH" -r 1 -d "$RUN_MS" \
          proxy tcp 127.0.0.1 "$port" 100000000 "$size" 2>/dev/null)
    w1=$(date +%s%N); t1=$(cpu_ticks_of "$pid")
    rate=$(grep -oE '^\s*Median:\s+[0-9]+' <<<"$out" | grep -oE '[0-9]+' | head -1)
    awk -v r="${rate:-0}" -v d=$((t1-t0)) -v hz="$HZ" -v ns=$((w1-w0)) \
        'BEGIN{ s = ns/1e9; n = r*s; printf "%s %.2f", r, (n>0 ? (d/hz)*1e6/n : 0) }'
}

printf '\n  %-7s %-10s %10s %9s %9s %9s  %s\n' \
    size arm 'rt/sec' 'us/rt' 'over floor' 'cpu us/rt' verdict
printf '  %s\n' "$(printf '%.0s─' {1..86})"

for size in $SIZES; do
    fv=""; sv=""; hv=""; fc=""; sc=""; hc=""
    for ((pass = 1; pass <= PASSES; pass++)); do
        before=$(box_load_cores)
        # Rotated, not a fixed order: whatever the leading arm pays that the
        # others do not is then charged to each of them in turn.
        case $((pass % 3)) in
            1) order="f s h" ;;
            2) order="s h f" ;;
            *) order="h f s" ;;
        esac
        for a in $order; do
            case $a in
                f) read -r r c <<<"$(leg "$P_FL" "$FL_PID" "$size")"; fv="$fv $r"; fc="$fc $c" ;;
                s) read -r r c <<<"$(leg "$P_SK" "$SK_PID" "$size")"; sv="$sv $r"; sc="$sc $c" ;;
                h) read -r r c <<<"$(leg "$P_HA" "$HA_PID" "$size")"; hv="$hv $r"; hc="$hc $c" ;;
            esac
        done
        after=$(box_load_cores)
        # A pass measured while somebody else was on the box is discarded whole,
        # never one arm of it: a pass with one arm dropped is exactly the
        # unpaired comparison the rotation exists to replace.
        if awk -v x="$before" -v y="$after" -v l="$QUIET_CORES" \
               'BEGIN{exit !(x > l || y > l)}'; then
            fv=${fv% *}; sv=${sv% *}; hv=${hv% *}
            fc=${fc% *}; sc=${sc% *}; hc=${hc% *}
        fi
    done

    fr=$(median_of "$fv"); sr=$(median_of "$sv"); hr=$(median_of "$hv")
    fu=$(median_of "$fc"); su=$(median_of "$sc"); hu=$(median_of "$hc")
    fci=$(ci_pct_of "$fv"); sci=$(ci_pct_of "$sv"); hci=$(ci_pct_of "$hv")

    row() {  # label rate ci cpu
        awk -v sz="$1" -v lab="$2" -v r="$3" -v f="$fr" -v ci="$4" -v cpu="$5" \
            'BEGIN{
                if (r <= 0 || f <= 0) { printf "  %-7s %-10s %10s %9s %9s %9s  %s\n",
                                        sz, lab, "—","—","—","—", "measured nothing"; exit }
                us = 1e6 / r; fus = 1e6 / f
                printf "  %-7s %-10s %10d %9.2f %+9.2f %9.2f  ±%.1f%%\n",
                       sz, lab, r, us, us - fus, cpu, ci }'
    }
    row "$size" floor     "$fr" "$fci" "$fu"
    row ""      socketley "$sr" "$sci" "$su"
    row ""      haproxy   "$hr" "$hci" "$hu"
    printf '\n'
done

log_info "quote the distance over the floor, not the rate: this box's clock moves"
log_info "under it invisibly and the floor moves with it, so the difference survives"
log_info "what the absolute number does not"
