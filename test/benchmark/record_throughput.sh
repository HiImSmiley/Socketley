#!/usr/bin/env bash
# Record the throughput numbers the README publishes, with the discipline that
# makes them mean something.
#
#   ./test/benchmark/record_throughput.sh [reps]      (default 3)
#
# Writes CSV to throughput-<date>.csv and prints the markdown tables ready to
# paste.  Nothing here decides pass or fail — that is what test/load/ is for.
# This exists so that "the README says X" can be checked against a number
# somebody actually took, instead of against a five-month-old memory of one.
#
# ─── WHY IT IS THIS SLOW ────────────────────────────────────────────────────
#
# Three things, each of which was learned by getting a wrong answer first:
#
#   PINNING.  Daemon on one pair of cores, load generator on the other.  Without
#   it the two share cores and the number is about the scheduler.  The load
#   harnesses print a warning to that effect and this script simply refuses.
#
#   TIME_WAIT.  A 2000-connection run leaves ~10000 sockets in TIME_WAIT for a
#   full 2*MSL.  Measured on this tree, same binary, same test:
#
#       TIME_WAIT 0     -> per_run [75693, 77662, 77764, 71824, 68492]  (+-9%)
#       TIME_WAIT ~10k  -> per_run [70549, 35205, 11048, 77462, 13634]  (7x)
#
#   and because the connection tests run first, they hand that state to every
#   test after them unless something waits in between.  So this waits before
#   every single measurement, not once per pass.
#
#   REPETITION.  Several of these move by more than 20% between runs on a
#   4-core box.  A single run cannot tell a change from the machine.  The
#   spread is printed next to every median for exactly that reason: anything
#   inside it is unchanged.
set -uo pipefail

REPS="${1:-3}"
# One pass produces a spread of 0% for every row, which is not a measurement of
# stability — it is the absence of one, and it reads exactly like a very stable
# result.  Said out loud rather than left for the reader to notice.
[ "$REPS" -lt 2 ] && echo "note: $REPS pass(es) — the spread column will read 0% and means nothing." >&2
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${SOCKETLEY_BIN:-$ROOT/bin/Release/socketley}"
BENCH="${SOCKETLEY_BENCH:-$ROOT/bin/Release/socketley_bench}"
OUT="${OUT:-throughput-$(date +%Y%m%d-%H%M).csv}"
BASEPORT="${BASEPORT:-24000}"

for f in "$BIN" "$BENCH"; do
    [ -x "$f" ] || { echo "missing: $f — build Release first" >&2; exit 2; }
done

NPROC=$(nproc)
if ! command -v taskset >/dev/null 2>&1 || [ "$NPROC" -lt 4 ]; then
    echo "refusing to measure: needs taskset and at least 4 cores." >&2
    echo "Fewer than that means the daemon and the load generator share a core," >&2
    echo "and the result is a statement about the scheduler." >&2
    exit 2
fi

# The split follows the machine instead of being written down for one of them.
# It used to be a hardcoded 0,1 / 2,3, which on a ten-core box would have
# measured four cores and called it a result — the two aggregate tests are
# exactly the ones that were unmeasurable (spread over 100%) because the load
# generator was fighting the daemon for two cores.
#
# A third to the daemon, the rest to the load generator.  The daemon's event
# loop is one thread and cannot use more than one core for itself, but it also
# carries the SQPOLL poller when that is on and the state writer thread, and
# leaving it room is cheaper than discovering it was boxed in.  The generator is
# the side that scales with client count and gets the majority.
#
# The workers count against the daemon's share, and that is meant.  taskset
# sets an affinity mask, and a forked child inherits it, so since a runtime
# gets a process of its own unless it asks not to, every worker this daemon
# spawns is confined to DCPU along with it.  That is the honest reading of
# "the server side gets a third": what is being budgeted is the whole server,
# not one process of it.  It does mean these numbers cannot be compared with
# ones recorded before runtimes moved out of the daemon — the same mask now
# holds more processes.
DCORES=$(( NPROC / 3 )); [ "$DCORES" -lt 2 ] && DCORES=2
DCPU=$(seq -s, 0 $((DCORES - 1)))
LCPU=$(seq -s, "$DCORES" $((NPROC - 1)))
echo "pinning: daemon on CPU $DCPU, load on CPU $LCPU (${NPROC} cores)" >&2

sweep() { pkill -x socketley 2>/dev/null; sleep 0.5; }
trap 'sweep; [ -n "${W:-}" ] && rm -rf "$W"' EXIT

tw() { ss -tan 2>/dev/null | grep -c TIME-WAIT; }
settle() {
    local i n
    for i in $(seq 1 90); do
        n=$(tw); [ "$n" -lt 1000 ] && return 0
        sleep 1
    done
    echo "  warning: still $n in TIME_WAIT after 90s" >&2
}

: > "$OUT"

for rep in $(seq 1 "$REPS"); do
    echo "=== pass $rep of $REPS ===" >&2
    sweep
    W=$(mktemp -d /tmp/socketley-throughput-XXXXXX)
    export HOME="$W/home"; mkdir -p "$HOME"
    export SOCKETLEY_SOCKET="$W/sock"

    taskset -c "$DCPU" "$BIN" daemon >/dev/null 2>&1 &
    sleep 1.5

    SRV=$((BASEPORT + rep * 10 + 1))
    PRX=$((BASEPORT + rep * 10 + 2))
    WS=$((BASEPORT  + rep * 10 + 3))
    "$BIN" create server bsrv -p "$SRV" -s >/dev/null 2>&1
    "$BIN" create proxy  bprx -p "$PRX" --backend "127.0.0.1:$SRV" --protocol tcp -s >/dev/null 2>&1
    # A plain server: WebSocket is detected from the Upgrade header, not enabled
    # by a flag.  Creating it with --websocket fails silently and every ws
    # measurement then reports 100% failures against a port nothing serves.
    "$BIN" create server bws -p "$WS" -s >/dev/null 2>&1
    sleep 1.2

    one() {  # one <label> <port> <category> <test> <params...>
        local label="$1" port="$2" cat="$3" test="$4"; shift 4
        settle
        # category test HOST PORT params — host and port sit in the middle, and
        # getting that wrong is silent: the bench reads the port as its
        # operation count and reports every one of them failed.
        local out thr fail
        out=$(taskset -c "$LCPU" "$BENCH" -j "$cat" "$test" 127.0.0.1 "$port" "$@" 2>/dev/null | tail -1)
        thr=$(sed -n 's/.*"median_throughput":\([0-9.]*\).*/\1/p' <<<"$out")
        fail=$(sed -n 's/.*"failed":\([0-9]*\).*/\1/p' <<<"$out")
        printf '%s,%s,%s\n' "$label" "${thr:-0}" "${fail:-NA}" >> "$OUT"
        printf '  %-30s %12s  failed=%s\n' "$label" "${thr:-0}" "${fail:-NA}" >&2
    }

    one "connection rate 2000"        "$SRV" server conn 2000
    one "burst 5000"                  "$SRV" server burst 5000
    one "single client 64B"           "$SRV" server msg 100000 64
    one "single client 1KB"           "$SRV" server msg 100000 1024
    one "100 clients x 500 msgs"      "$SRV" server concurrent 100 500
    one "proxy tcp 128B"              "$PRX" proxy tcp 100000 128
    one "proxy 20 concurrent"         "$PRX" proxy concurrent 20 100
    one "ws handshakes 200"           "$WS"  ws handshake 200
    one "ws frames 64B"               "$WS"  ws echo 100000 64
    one "ws 20 concurrent"            "$WS"  ws concurrent 20 100

    sweep
    rm -rf "$W"; W=""
done

echo >&2
python3 - "$OUT" <<'PY'
import csv, statistics, collections, sys
d = collections.defaultdict(list)
bad = collections.defaultdict(int)
for row in csv.reader(open(sys.argv[1])):
    if len(row) < 3: continue
    label, thr, fail = row
    try: v = float(thr)
    except ValueError: continue
    if fail != "0": bad[label] += 1
    d[label].append(v)

def unit(v): return f"{v/1e6:.2f}M" if v >= 1e6 else f"{v/1e3:.0f}K"

print("| Test | Result | Spread |")
print("|------|--------|--------|")
for label, vals in d.items():
    vals = sorted(vals)
    med = statistics.median(vals)
    spread = (vals[-1] - vals[0]) / med * 100 if med else 0
    note = f" — {bad[label]} run(s) reported failures" if bad[label] else ""
    # Over a fifth of movement between runs is not a number to publish; say so
    # in the table rather than letting a reader take the median at face value.
    emph = "" if spread > 20 else "**"
    print(f"| {label} | {emph}{unit(med)}{emph} | ±{spread:.0f}%{note} |")
PY
