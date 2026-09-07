#!/usr/bin/env bash
# Every cache command under the profiler, ranked by what is OURS in it.
#
# ─── WHY A RANKING AND NOT SEVENTY PROFILES ─────────────────────────────────
#
# A profile is a proportion.  Profiled one at a time at saturation, every
# command on this box gives back the same answer -- the network path dominates,
# our own symbols are a rounding error -- and a directory of seventy files all
# saying that is a directory nobody opens twice.
#
# The finding is in the COMPARISON.  When SET spends 3% of the worker in
# socketley's own code and one other command spends 60%, that command is doing
# something the others are not, and it is worth a morning.  So this writes one
# ranked file, with a threshold, and says plainly how many rows were below it.
#
# ─── AND THE AXIS THAT ACTUALLY FOUND THINGS ────────────────────────────────
#
# Both real defects found this way were invisible to a single-client profile.
#
#   WATCH read as a normal O(1) command until a SECOND connection was holding
#   watches; then a write walked every watched key and one client with twenty
#   thousand of them cost every other client's EVAL a factor of 113.
#
#   BLPOP read as nothing at all until a second connection was BLOCKED on it;
#   the waiter list was empty otherwise.  With a thousand idle workers -- an
#   ordinary queue, not an attack -- memcmp was 35% of the worker and pushing
#   clients lost 74% of their throughput.
#
# Neither is a property of the command.  Both are properties of the command
# WITH SOMEBODY ELSE'S STATE PRESENT, so that is the second axis: a holder
# connection parks waiters, watchers, patterns or subscribers, and the same
# commands are profiled again beside it.  A row that moves between the two
# passes is the interesting kind of row.
#
# ─── WHAT MAKES THE OUTPUT MEAN ANYTHING ────────────────────────────────────
#
# Three refusals, each of which has already produced a worthless run by hand:
#
#   * A STRIPPED BINARY.  Release links with -s, so perf resolves nothing and
#     the report is a list of hex offsets.  This links its own copy WITH
#     symbols, into its own directory, and still calls it `socketley` so the
#     cleanup sweep can find it.
#   * perf_event_paranoid.  The hardened default denies profiling even your own
#     process, and fails with rc=255 and no useful message.
#   * A CLIENT AT ITS CEILING.  A cell whose load generator is saturated is
#     profiling an idle server.  The client's own reported rate is checked
#     against the previous cell's, and a cell that could not load the server is
#     marked rather than ranked.
#
# Usage:
#   bash test/benchmark/profile_cache_commands.sh                 # both passes
#   PROF_SECS=4 PROF_ONLY='GET SET BLPOP' bash .../profile_cache_commands.sh
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
cd "$ROOT" || exit 2

PROF_SECS=${PROF_SECS:-3}          # sampling window per cell
PROF_FREQ=${PROF_FREQ:-997}        # Hz, prime so it does not beat with a timer
PROF_PORT=${PROF_PORT:-19871}
PROF_SOCK=/tmp/socketley-profile-$$.sock
PROF_HOME=/tmp/socketley-profile-$$-home
PROF_ONLY=${PROF_ONLY:-}           # space separated names, empty = all
PROF_HOLD=${PROF_HOLD:-1000}       # how much state the holder parks
# A row is printed when our own share reaches this, or when the loaded pass
# moves it by this much.  Everything under it is counted, not listed.
PROF_MIN_OURS=${PROF_MIN_OURS:-8}
PROF_MIN_MOVE=${PROF_MIN_MOVE:-5}

TS=$(date +%Y%m%d_%H%M%S)
OUT=${PROF_OUT:-$ROOT/test/benchmark/results/cache_profile_$TS.md}
TMPD=$(mktemp -d /tmp/sklprof.XXXXXX)
# Counted in files and not in variables: pass one runs behind a pipe, so its
# loop is a subshell and every increment made there is discarded at its end.
# A counter that silently reads zero is how a blind run passes for a clean one.
BLIND_F=$TMPD/blind.count
CELLS_F=$TMPD/cells.count

say()  { printf '%s\n' "$*"; }
die()  { printf 'profile: %s\n' "$*" >&2; exit 2; }

# Only this run's processes: they carry its private socket in their
# environment, and matching on that leaves other agents' daemons alone.  Never
# `pgrep -f`, which matches the shell doing the matching.
sweep() {
    local p c
    # Workers outlive the daemon that forked them, so children go first.
    for p in $(pgrep -x socketley 2>/dev/null); do
        grep -qz "SOCKETLEY_SOCKET=$PROF_SOCK" "/proc/$p/environ" 2>/dev/null || continue
        for c in $(pgrep -P "$p" 2>/dev/null); do kill -9 "$c" 2>/dev/null; done
        kill -9 "$p" 2>/dev/null
    done
    [ -n "${DAEMON_PID:-}" ] && kill -9 "$DAEMON_PID" 2>/dev/null
    return 0
}
cleanup() {
    [ -n "${HOLDER_PID:-}" ] && kill -9 "$HOLDER_PID" 2>/dev/null
    [ -n "${BENCH_PID:-}"  ] && kill -9 "$BENCH_PID"  2>/dev/null
    pkill -x redis-benchmark 2>/dev/null
    sweep; sleep 0.3; sweep
    # Verified, not assumed.  A first run of this script left a daemon and a
    # worker holding the port, and the next run refused to start because of it.
    local left=0 p
    for p in $(pgrep -x socketley 2>/dev/null); do
        grep -qz "SOCKETLEY_SOCKET=$PROF_SOCK" "/proc/$p/environ" 2>/dev/null && left=$((left + 1))
    done
    [ "$left" -gt 0 ] && printf 'profile: WARNING %d of this run processes survived cleanup\n' "$left" >&2
    rm -rf "$TMPD" "$PROF_HOME" "$PROF_SOCK"
    return 0
}

# ─── 1. refusals ────────────────────────────────────────────────────────────

[ "$(pgrep -x socketley 2>/dev/null | wc -l)" -eq 0 ] \
    || die "socketley is already running; a profile taken beside another run is not attributable"
ss -ltn 2>/dev/null | awk '{print $4}' | grep -q ":$PROF_PORT\$" \
    && die "port $PROF_PORT is held"

PERF=${PERF:-}
if [ -z "$PERF" ]; then
    # The wrapper refuses when the running kernel has no matching package, which
    # is the normal state on this box after a kernel bump; the binary itself is
    # fine, so it is found directly.
    PERF=$(ls -d /usr/lib/linux-tools/*/perf 2>/dev/null | tail -1)
    [ -z "$PERF" ] && PERF=$(command -v perf)
fi
[ -x "${PERF:-}" ] || die "no perf binary found (looked in /usr/lib/linux-tools/*/perf and \$PATH)"

PARANOID=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo 4)
if [ "$PARANOID" -gt 1 ]; then
    sudo -n sysctl -q -w kernel.perf_event_paranoid=1 kernel.kptr_restrict=0 2>/dev/null
    PARANOID=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo 4)
fi
[ "$PARANOID" -le 1 ] \
    || die "perf_event_paranoid=$PARANOID denies profiling; run: sudo sysctl -w kernel.perf_event_paranoid=1 kernel.kptr_restrict=0"

command -v redis-benchmark >/dev/null || die "redis-benchmark not found"

# ─── 2. a binary perf can read ──────────────────────────────────────────────

BIN=$ROOT/bin/Profile/socketley
if [ ! -x "$BIN" ] || [ "$ROOT/bin/Release/socketley" -nt "$BIN" ]; then
    say "linking a symbol-bearing build (Release strips, so perf would see only offsets)"
    ./bin/premake5 gmake2 >/dev/null 2>&1 || die "premake failed"
    # Same objects, same optimisation, same LTO -- only the strip flag differs,
    # so what is measured is the shipped code and not a debug build.
    sed -i 's/-m64 -s -flto=auto/-m64 -flto=auto/' make/socketley.make
    rm -f "$ROOT/bin/Release/socketley"
    if ! make -C make config=release_x64 -j"$(nproc)" >"$TMPD/build.log" 2>&1; then
        ./bin/premake5 gmake2 >/dev/null 2>&1
        die "build failed, see $TMPD/build.log"
    fi
    mkdir -p "$ROOT/bin/Profile"
    cp "$ROOT/bin/Release/socketley" "$BIN"
    # Put the tree back the way it is packaged, and rebuild the stripped one so
    # nobody inherits an unstripped Release from having profiled once.
    ./bin/premake5 gmake2 >/dev/null 2>&1
    rm -f "$ROOT/bin/Release/socketley"
    make -C make config=release_x64 -j"$(nproc)" >>"$TMPD/build.log" 2>&1 \
        || die "restoring the stripped Release failed, see $TMPD/build.log"
fi
file "$BIN" | grep -q 'not stripped' \
    || die "$BIN is stripped; perf would report offsets and the ranking would be empty"

# ─── 3. the command table, from the matrix and not a copy of it ─────────────

BENCH_MATRIX_TABLE_ONLY=1
export BENCH_MATRIX_TABLE_ONLY
# shellcheck disable=SC1090
source "$HERE/bench_resp_matrix.sh"

# AFTER the source, and not before it.  bench_resp_matrix.sh installs its own
# `trap cleanup_all_arms EXIT`, which silently REPLACES any trap set earlier --
# so the first version of this script cleaned up nothing and left a daemon and
# a worker holding the port, while the matrix's handler shut down ports this
# run never opened.  A trap is global state; sourcing takes it over.
trap cleanup EXIT INT TERM

ROWS=$(printf '%s\n' "$CMDS" | grep -cE '^[A-Z][A-Z0-9]*\|' || true)
[ "${ROWS:-0}" -ge 40 ] \
    || die "read only ${ROWS:-0} command rows from bench_resp_matrix.sh; the table moved and this would silently profile nothing"

# ─── 4. the cache under test ────────────────────────────────────────────────

mkdir -p "$PROF_HOME" "$(dirname "$OUT")"
export HOME=$PROF_HOME
export SOCKETLEY_SOCKET=$PROF_SOCK
unset SOCKETLEY_CONFIG            # it is a config PATH, not a build selector

"$BIN" daemon >/dev/null 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 60); do [ -S "$PROF_SOCK" ] && break; sleep 0.2; done
[ -S "$PROF_SOCK" ] || die "daemon did not come up"
"$BIN" create cache prof -p "$PROF_PORT" -s >/dev/null 2>&1
for _ in $(seq 1 100); do
    [ "$(redis-cli -p "$PROF_PORT" ping 2>/dev/null)" = "PONG" ] && break; sleep 0.1
done
[ "$(redis-cli -p "$PROF_PORT" ping 2>/dev/null)" = "PONG" ] || die "cache did not answer"

emit_load > "$TMPD/load.txt"
load_arm "$PROF_PORT" "$TMPD/load.txt"
KEYS=$(redis-cli -p "$PROF_PORT" dbsize 2>/dev/null | tr -dc '0-9')
[ "${KEYS:-0}" -gt 0 ] || die "no keys loaded; every read below would profile the miss path"
say "cache up on $PROF_PORT with ${KEYS} keys"

WPID=$(ss -ltnp 2>/dev/null | sed -n "s/.*:$PROF_PORT .*pid=\([0-9]*\).*/\1/p" | head -1)
[ -n "$WPID" ] && [ -d "/proc/$WPID" ] || die "could not find the worker pid for port $PROF_PORT"
say "worker pid $WPID, sampling ${PROF_SECS}s per cell at ${PROF_FREQ}Hz"

# ─── 5. one cell ────────────────────────────────────────────────────────────

# Sums the report by where the sample landed: kernel, our binary, or a library.
# --percent-limit 0 because a ranking built from a truncated report would put a
# command with one fat symbol above a command with fifty thin ones.
# perf record runs under sudo, so perf.data lands root-owned and 0600.  Read as
# the invoking user it fails with "Permission denied", awk sums an empty stream,
# and every cell reports 0.0% -- a complete, plausible, entirely blind table.
# That happened on the first run of this script; hence both the sudo here and
# the sample check in profile_cell.
parse_report() {   # parse_report FILE -> "kernel ours libs top1 pct1 top2 pct2"
    sudo -n "$PERF" report -i "$1" --stdio --no-children -g none --percent-limit 0 2>/dev/null \
    | awk '
        /^[[:space:]]*[0-9.]+%/ {
            pct = $1; sub(/%/, "", pct)
            dso = $3; sym = ""
            for (i = 5; i <= NF; i++) sym = sym (i > 5 ? " " : "") $i
            # Cut at the argument list and squeeze what is left: a demangled
            # C++ name carries spaces, and a space in a field shifts every
            # column behind it in the tables built from this line.
            sub(/\(.*/, "", sym); gsub(/[ \t]+/, "_", sym)
            # And a demangled template instantiation runs to eight hundred
            # characters, which is one table cell nobody can read.  The tail is
            # the interesting half of a C++ name, so the middle goes.
            if (length(sym) > 64)
                sym = substr(sym, 1, 24) "..." substr(sym, length(sym) - 33)
            if (dso ~ /kallsyms/)            { k += pct }
            else if (dso == "socketley")     { o += pct; if (pct > b1p) { b2 = b1; b2p = b1p; b1 = sym; b1p = pct }
                                               else if (pct > b2p)     { b2 = sym; b2p = pct } }
            else                             { l += pct; if (pct > b1p) { b2 = b1; b2p = b1p; b1 = sym "@" dso; b1p = pct }
                                               else if (pct > b2p)     { b2 = sym "@" dso; b2p = pct } }
        }
        END { printf "%.1f %.1f %.1f %s %.1f %s %.1f",
                     k, o, l, (b1 == "" ? "-" : b1), b1p, (b2 == "" ? "-" : b2), b2p }'
}

# The keyspace substitution redis-benchmark does not do for us: the matrix's
# templates carry KEYTAG, which is only meaningful when sharded.
strip_tag() { printf '%s' "${1//KEYTAG/}"; }

profile_cell() {   # profile_cell NAME RANGE TEMPLATE... -> "kernel ours libs t1 p1 t2 p2 rate"
    local name=$1 range=$2; shift 2
    local tmpl=("$@") i
    for i in "${!tmpl[@]}"; do tmpl[$i]=$(strip_tag "${tmpl[$i]}"); done

    # -r is not optional.  Without it redis-benchmark replaces every
    # __rand_int__ with the SAME number, so a cell profiles one key instead of
    # a working set: the lookups stay in L1 and every hash and compare share in
    # the table reads low.  It also made LSET address a list that does not
    # exist, and the server error killed the client mid-cell.
    redis-benchmark -p "$PROF_PORT" -r "$range" -c 50 -P 16 -n 100000000 -q \
        "${tmpl[@]}" >"$TMPD/cell.txt" 2>&1 &
    BENCH_PID=$!
    sleep 0.7                                    # past connection setup
    if ! kill -0 "$BENCH_PID" 2>/dev/null; then
        BENCH_PID=""
        # Counted and named.  A client that died on a server error is not a
        # cheap command, and leaving it out of both counters is how two rows
        # read "-" under a summary that said nothing was wrong.
        echo "$name" >> "$TMPD/refused.txt"
        printf -- "- - - refused - - - 0"; return
    fi
    rm -f "$TMPD/p.data"
    sudo -n "$PERF" record -e cpu-clock -F "$PROF_FREQ" -g -p "$WPID" \
        -o "$TMPD/p.data" -- sleep "$PROF_SECS" >/dev/null 2>&1
    local last
    last=$(tr '\r' '\n' < "$TMPD/cell.txt" | grep -o 'rps=[0-9.]*' | tail -1 | cut -d= -f2)
    kill -9 "$BENCH_PID" 2>/dev/null; wait "$BENCH_PID" 2>/dev/null; BENCH_PID=""
    # A cell whose three shares sum to nothing profiled nothing, and it must say
    # so rather than print zeroes: a blind run otherwise writes a complete,
    # plausible table that sorts every command to the bottom as if it were
    # cheap.  That is what the first run of this script produced -- perf.data
    # was root-owned and unreadable -- and nothing in the output said so.
    local rep sum
    rep=$(parse_report "$TMPD/p.data")
    sum=$(awk '{print ($1 + $2 + $3 > 0.5) ? 1 : 0}' <<<"$rep")
    if [ "$sum" != "1" ]; then
        echo x >> "$BLIND_F"
        printf -- "- - - no-samples - - - %s" "${last:-0}"; return
    fi
    echo x >> "$CELLS_F"
    printf '%s %s' "$rep" "${last:-0}"
}

# ─── 6. the holder, for the second pass ─────────────────────────────────────

cat > "$TMPD/hold.py" <<'PYEOF'
import socket, sys, time
def enc(a):
    return (('*%d\r\n' % len(a)) + ''.join('$%d\r\n%s\r\n' % (len(x), x) for x in a)).encode()
kind, port, n = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
socks = []
if kind == 'blpop':
    for i in range(n):                       # a connection can only block once
        s = socket.create_connection(('127.0.0.1', port), timeout=10)
        s.sendall(enc(['BLPOP', 'hold:%d' % i, '0'])); socks.append(s)
    time.sleep(0.5 + n / 2000.0)
else:
    verb, fmt, ack = {
        'watch': ('WATCH',      'hold:%d',    b'+OK'),
        'psub':  ('PSUBSCRIBE', 'hold:%d:*',  b'psubscribe'),
        'sub':   ('SUBSCRIBE',  'hold:%d',    b'subscribe'),
    }[kind]
    s = socket.create_connection(('127.0.0.1', port), timeout=20)
    s.sendall(b''.join(enc([verb, fmt % i]) for i in range(n)))
    s.settimeout(20); buf = bytearray()
    # Counted on the whole buffer: a needle straddling a recv boundary is
    # missed by a per-chunk count, and then the wait times out on a reply that
    # arrived long ago.
    while buf.count(ack) < n:
        x = s.recv(1 << 20)
        if not x: break
        buf += x
    if buf.count(ack) < n:
        print('HOLDER FAILED %d of %d' % (buf.count(ack), n), flush=True); sys.exit(1)
    socks.append(s)
print('held', flush=True)
time.sleep(3600)
PYEOF

start_holder() {   # start_holder KIND N -> 0 established, 1 not
    HOLDER_LOG=$TMPD/holder.txt
    python3 "$TMPD/hold.py" "$1" "$PROF_PORT" "$2" >"$HOLDER_LOG" 2>&1 &
    HOLDER_PID=$!
    local i
    for i in $(seq 1 400); do
        grep -q '^held' "$HOLDER_LOG" 2>/dev/null && return 0
        grep -qE 'FAILED|Traceback' "$HOLDER_LOG" 2>/dev/null && break
        kill -0 "$HOLDER_PID" 2>/dev/null || break
        sleep 0.2
    done
    kill -9 "$HOLDER_PID" 2>/dev/null; HOLDER_PID=""
    return 1
}
stop_holder() {
    [ -n "${HOLDER_PID:-}" ] && { kill -9 "$HOLDER_PID" 2>/dev/null; wait "$HOLDER_PID" 2>/dev/null; }
    HOLDER_PID=""
}

# ─── 7. pass one: every command, nobody else on the cache ───────────────────

say ""
say "pass 1/2: idle cache, $ROWS commands"
: > "$TMPD/idle.txt"
printf '%s\n' "$CMDS" | grep -E '^[A-Z][A-Z0-9]*\|' | while IFS='|' read -r name range tmpl _; do
    if [ -n "$PROF_ONLY" ] && ! grep -qw "$name" <<<"$PROF_ONLY"; then continue; fi
    # shellcheck disable=SC2086
    r=$(profile_cell "$name" "$range" $tmpl)
    printf '%s %s\n' "$name" "$r" >> "$TMPD/idle.txt"
    printf '  %-14s %s\n' "$name" "$(awk '{printf "kernel %5s%%  ours %5s%%  libs %5s%%  %s %s%%", $1,$2,$3,$4,$5}' <<<"$r")"
done

# ─── 8. pass two: the same commands with somebody else's state present ──────

say ""
say "pass 2/2: with a holder parked ($PROF_HOLD each)"
: > "$TMPD/loaded.txt"
# Only the commands a holder can plausibly interact with are re-run, because
# the second pass costs the same as the first and a row that cannot move is a
# row not worth the minutes.
declare -A HOLD_FOR=(
    [blpop]='RPUSH LPUSH LPOP RPOP LLEN LRANGE'
    [watch]='SET MSET DEL INCR EVAL EVALKEY GET'
    [psub]='PUBLISH SET'
    [sub]='PUBLISH'
)
for kind in blpop watch psub sub; do
    if ! start_holder "$kind" "$PROF_HOLD"; then
        say "  $kind: HOLDER DID NOT ESTABLISH -- $(head -1 "$HOLDER_LOG" 2>/dev/null)"
        continue
    fi
    for name in ${HOLD_FOR[$kind]}; do
        if [ -n "$PROF_ONLY" ] && ! grep -qw "$name" <<<"$PROF_ONLY"; then continue; fi
        row=$(printf '%s\n' "$CMDS" | grep -E "^$name\|" | head -1)
        [ -n "$row" ] || continue
        range=$(cut -d'|' -f2 <<<"$row"); tmpl=$(cut -d'|' -f3 <<<"$row")
        # shellcheck disable=SC2086
        r=$(profile_cell "$name" "$range" $tmpl)
        printf '%s %s %s\n' "$kind" "$name" "$r" >> "$TMPD/loaded.txt"
        printf '  %-6s %-12s %s\n' "$kind" "$name" \
            "$(awk '{printf "kernel %5s%%  ours %5s%%  %s %s%%", $1,$2,$4,$5}' <<<"$r")"
    done
    stop_holder
done

# ─── 9. the file ────────────────────────────────────────────────────────────

{
say "# Cache command profile — $TS"
say ""
say "\`cpu-clock\` at ${PROF_FREQ}Hz, ${PROF_SECS}s per cell, one worker, ${KEYS} keys loaded,"
say "50 connections and pipeline 16 per cell.  Hardware counters are not exposed"
say "to this guest, so this is a share of time and not cycles or cache misses."
say ""
say "\`ours\` is the share of samples that landed in socketley's own binary."
say "The rest is the kernel's network path and libc.  A high \`ours\` is not"
say "automatically wrong — it can mean the command is cheap enough that what is"
say "left is us — but it is where a defect can be, and every one found so far"
say "was found in a row that stood out from its neighbours."
say ""
say "## Ranked by our own share, idle cache"
say ""
say '| command | ours | kernel | libs | top symbol | % | rate |'
say '|---|---|---|---|---|---|---|'
sort -k3 -gr "$TMPD/idle.txt" | awk -v min="$PROF_MIN_OURS" '
    $3 >= min { printf "| %s | %s%% | %s%% | %s%% | `%s` | %s | %s |\n", $1,$3,$2,$4,$5,$6,$9 ; shown++ }
    $3 <  min { hidden++ }
    END { print ""; printf "%d rows above %s%%, %d below and not listed.\n", shown, min, hidden }'
say ""
say "## Moved by another connection's state"
say ""
say "The axis that found every real defect so far.  A command whose profile"
say "changes when somebody else is holding waiters, watchers or patterns is"
say "paying for their state on its own path."
say ""
say '| holder | command | ours idle | ours loaded | move | top symbol loaded | rate idle | rate loaded |'
say '|---|---|---|---|---|---|---|---|'
awk -v min="$PROF_MIN_MOVE" '
    NR == FNR { idle[$1] = $3; irate[$1] = $9; next }
    {
        d = $4 - idle[$2]
        if (d >= min || d <= -min || (irate[$2] > 0 && $10 < irate[$2] * 0.75))
            printf "| %s | %s | %s%% | %s%% | %+.1f | `%s` | %s | %s |\n",
                   $1, $2, idle[$2], $4, d, $6, irate[$2], $10
        else hidden++
    }
    END { print ""; printf "%d rows moved less than %s points and are not listed.\n", hidden, min }' \
    "$TMPD/idle.txt" "$TMPD/loaded.txt"
say ""
say "## Raw"
say ""
say '```'
say "idle:   name kernel% ours% libs% top1 pct1 top2 pct2 rate"
cat "$TMPD/idle.txt"
say ""
say "loaded: holder name kernel% ours% libs% top1 pct1 top2 pct2 rate"
cat "$TMPD/loaded.txt"
say '```'
} > "$OUT"

say ""
say "wrote $OUT"
# The whole point of the counter: a run where nothing was sampled writes a file
# full of zeroes that looks like a finding.  It is an error, not a result.
BLIND=$( [ -f "$BLIND_F" ] && wc -l < "$BLIND_F" || echo 0)
CELLS=$( [ -f "$CELLS_F" ] && wc -l < "$CELLS_F" || echo 0)
if [ "${BLIND:-0}" -gt 0 ]; then
    say "WARNING: $BLIND cells produced no samples"
fi
if [ -s "$TMPD/refused.txt" ]; then
    say "WARNING: the client died inside these cells (server error?): $(tr '\n' ' ' < "$TMPD/refused.txt")"
fi
if [ "${CELLS:-0}" -eq 0 ]; then
    die "every cell was blind; the profile is worthless (check sudo, perf_event_paranoid, and that the worker pid was right)"
fi
say "$CELLS cells sampled, $BLIND blind"
