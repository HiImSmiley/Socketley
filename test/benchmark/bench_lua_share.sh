#!/bin/bash
# How much of a server round trip Lua actually eats, measured as a proportion.
#
# The question this answers: under the echo.lua workload the server sits
# +1.62 us over the bare C floor, and that gap contains Lua dispatch, runtime
# state and stats together.  Nothing so far separates them.  A profile is a
# proportion, so it survives the host clock moving under this guest; this
# script profiles the worker that serves the load and buckets every sample by
# symbol, which is what turns "+1.62 us of something" into "N% of the worker's
# CPU is LuaJIT, M% is sol2 glue, and the rest never touches Lua".
#
# Method, in one paragraph.  Start a private daemon (own socket, own HOME, own
# port window), create one server with test/benchmark/echo.lua, drive it with
# echoload (single connection, exact-length replies only), and while the load
# is steady take a 10 s cpu-clock profile of the worker plus a /proc/<pid>/stat
# reading over the same window.  The stat delta gives CPU-us per message; the
# profile gives Lua's share of it; the product is Lua's cost in microseconds,
# stated beside the proportion that produced it.  Two arms, interleaved A B A B:
# the default deadline (count hook installed, which keeps LuaJIT in the
# interpreter -- a compiled trace cannot call the hook back), and
# SOCKETLEY_LUA_TIMEOUT_MS=0 (no hook, JIT allowed).  Same binary, so the pair
# prices the hook itself without a rebuild.
#
# Why the binary is relinked first.  Release links with -s, so the shipped
# binary carries no symbol table and a profile of it is a list of addresses.
# -s is a link flag only -- the LTO objects are untouched -- so relinking them
# without it yields the same machine code with names, and the script verifies
# that claim by comparing the .text section of both binaries byte for byte
# before believing a single sample.  Running the -syms binary also gives this
# run a unique /proc/<pid>/exe, so cleanup can sweep by exact exe path without
# ever touching another agent's daemon built from the same tree.
#
# What the numbers can and cannot say.  Leaf buckets (--no-children) are exact
# per symbol but split Lua's kernel work (the write() behind self.send) into
# the kernel bucket.  Inclusive numbers for invoke_on_client_message /
# invoke_on_message need DWARF unwinding through .eh_frame, and the unwinder
# dies inside LuaJIT's assembly interpreter frames, so the inclusive figure is
# a floor, not a ceiling.  Both are reported; where they disagree, the leaf
# buckets are the ones to argue from.
#
# Port window: claims 27000 under the same flock protocol lib_ports.sh uses
# (the lock file is the reservation; a brief is not).  Refuses to run if the
# window is locked or occupied.
#
# Usage: bench_lua_share.sh [--payload N] [--depth N] [--secs N] [--reps N]
#        [--skip-relink]   (accept an existing -syms binary without relinking)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN_STRIPPED="$PROJECT_ROOT/bin/Release/socketley"
BIN="$PROJECT_ROOT/bin/Release/socketley-syms"
ECHO_LUA="$SCRIPT_DIR/echo.lua"
ECHOLOAD="${ECHOLOAD:-$HOME/ringab/echo/echoload}"

PAYLOAD=64          # bytes; matches the run that produced the +1.62 us figure
DEPTH=1             # ping-pong, same reason
SECS=16             # load window; the 10 s profile sits inside it
PROF_SECS=10
REPS=2              # per arm, interleaved
SKIP_RELINK=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --payload) PAYLOAD=$2; shift 2 ;;
        --depth)   DEPTH=$2;   shift 2 ;;
        --secs)    SECS=$2;    shift 2 ;;
        --reps)    REPS=$2;    shift 2 ;;
        --skip-relink) SKIP_RELINK=1; shift ;;
        # The fixture is a parameter because the hook's cost is a property of
        # the script, not of the runtime: see echo_compute.lua.  Give each
        # fixture its own OUT_DIR so two runs do not overwrite each other's
        # perf.data.
        --lua)     ECHO_LUA=$2; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done
[[ $SECS -ge $((PROF_SECS + 5)) ]] || { echo "--secs must be >= PROF_SECS+5" >&2; exit 1; }

# ─── Preconditions ──────────────────────────────────────────────────────────

[[ -x $BIN_STRIPPED ]] || { echo "no Release binary at $BIN_STRIPPED" >&2; exit 1; }
[[ -x $ECHOLOAD ]] || { echo "no echoload at $ECHOLOAD (set ECHOLOAD=)" >&2; exit 1; }
[[ -f $ECHO_LUA ]] || { echo "no echo.lua at $ECHO_LUA" >&2; exit 1; }

# perf itself.  The distro wrapper /usr/bin/perf dispatches on `uname -r` and
# refuses outright when the running kernel has no linux-tools package -- which
# is the state after a kernel upgrade the tools have not caught up with (here:
# running 7.0.0-30, tools installed for 7.0.0-28).  A perf built for a nearby
# kernel samples cpu-clock fine, so fall back to the newest one installed
# rather than reporting "no perf" on a box that has three of them.
PERF="${PERF:-}"
if [[ -z $PERF ]]; then
    if perf --version >/dev/null 2>&1; then
        PERF=perf
    else
        PERF=$(ls -d /usr/lib/linux-tools/*/perf /usr/lib/linux-tools-*/perf 2>/dev/null \
               | sort -V | tail -1 || true)
        [[ -n $PERF && -x $PERF ]] || { echo "no usable perf (set PERF=)" >&2; exit 1; }
        echo "[perf] /usr/bin/perf declines kernel $(uname -r); using $PERF"
    fi
fi

paranoid=$(cat /proc/sys/kernel/perf_event_paranoid)
if [[ $paranoid -gt 1 ]]; then
    sudo -n sysctl -q -w kernel.perf_event_paranoid=1 kernel.kptr_restrict=0 \
        || { echo "perf_event_paranoid=$paranoid and sudo -n failed" >&2; exit 1; }
fi

# ─── The port window: 27000, claimed the way lib_ports.sh claims ────────────
# flock on the window's lock file, held on fd 9 for the life of this shell,
# then the machine's own opinion: no listener anywhere in [27000, 29000).

WINDOW=27000
( : >"/tmp/socketley-ports-$WINDOW.lock" ) 2>/dev/null
exec 9>"/tmp/socketley-ports-$WINDOW.lock"
flock -n 9 || { echo "window $WINDOW is locked by another run" >&2; exit 2; }
busy=$(ss -ltnH 2>/dev/null | awk -v lo=$WINDOW -v hi=$((WINDOW+2000)) \
    '{ n=split($4,a,":"); p=a[n]+0; if (p>=lo && p<hi) { print p; exit } }')
[[ -z $busy ]] || { echo "port $busy is already listening inside window $WINDOW" >&2; exit 2; }
PORT=$((WINDOW + 100))

# ─── Private daemon environment ─────────────────────────────────────────────

RUN_TAG="lua-share-$$"
RUN_HOME="/tmp/skl-$RUN_TAG-home"
export SOCKETLEY_SOCKET="/tmp/skl-$RUN_TAG.sock"
OUT_DIR="${OUT_DIR:-/tmp/skl-$RUN_TAG-out}"
mkdir -p "$RUN_HOME" "$OUT_DIR"

DAEMON_PID=""
LOAD_PID=""

# Sweep by exact exe path -- and it is the -syms path, which nothing else on
# this box runs.  Never pgrep -f: it matches the whole command line, so it also
# matches the shell that merely carries the string in its own arguments -- which
# is the one doing the matching.  It has killed the killer here.
sweep_mine() {
    local p exe
    for p in $(pgrep -x socketley-syms 2>/dev/null || true); do
        exe=$(readlink "/proc/$p/exe" 2>/dev/null || true)
        [[ $exe == "$BIN" ]] && kill -9 "$p" 2>/dev/null || true
    done
}

cleanup() {
    [[ -n $LOAD_PID ]] && kill "$LOAD_PID" 2>/dev/null || true
    if [[ -n $DAEMON_PID ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        HOME="$RUN_HOME" "$BIN" stop lua_share_srv >/dev/null 2>&1 || true
        HOME="$RUN_HOME" "$BIN" remove lua_share_srv >/dev/null 2>&1 || true
        kill "$DAEMON_PID" 2>/dev/null || true
        ( wait "$DAEMON_PID" ) 2>/dev/null || true
    fi
    sweep_mine
    rm -f "$SOCKETLEY_SOCKET"
    rm -rf "$RUN_HOME"
}
trap cleanup EXIT

# ─── Relink Release without -s ──────────────────────────────────────────────
# Same objects, same flags minus the strip; then prove .text identical.

relink_syms() {
    if [[ $SKIP_RELINK -eq 1 && -x $BIN ]]; then return 0; fi
    local objdir="$PROJECT_ROOT/make/obj/x64/Release/socketley"
    [[ -d $objdir ]] || { echo "no Release objects at $objdir" >&2; exit 1; }
    # Objects newer than the shipped binary mean a half-built tree; refuse
    # rather than measure a binary nobody ships.
    local newer
    newer=$(find "$objdir" -name '*.o' -newer "$BIN_STRIPPED" | head -1)
    [[ -z $newer ]] || { echo "objects newer than $BIN_STRIPPED -- rebuild Release first" >&2; exit 1; }
    echo "[relink] LTO relink without -s (a few minutes)..."
    c++ -o "$BIN" "$objdir"/*.o \
        -L"$PROJECT_ROOT/thirdparty/luajit" -L"$PROJECT_ROOT/thirdparty/liburing" -L/usr/lib64 \
        -m64 -flto=auto -Wl,-z,relro,-z,now -Wl,--as-needed \
        -lluajit -luring -lssl -lcrypto
    local a b
    a=$(objcopy -O binary --only-section=.text "$BIN_STRIPPED" /dev/stdout | md5sum | cut -d' ' -f1)
    b=$(objcopy -O binary --only-section=.text "$BIN" /dev/stdout | md5sum | cut -d' ' -f1)
    if [[ $a == "$b" ]]; then
        echo "[relink] .text identical to shipped Release ($a)"
    else
        echo "[relink] WARNING: .text differs from shipped Release -- the profile"
        echo "         is of the -syms binary only; say so in the report."
    fi
    # Not a pipeline: this check failed once against a binary that provably had
    # the symbol (lj_str_new was present in nm's output when the same command
    # was rerun by hand, 240 times, all clean).  SIGPIPE is ruled out -- only
    # 25 KB follow the match and the pipe buffer is 64 KB -- so the mechanism is
    # NOT established.  Capturing nm separately means the next failure prints
    # nm's own exit status and stderr instead of asserting a conclusion.
    local nm_out nm_rc
    nm_out=$(nm "$BIN" 2>&1) && nm_rc=0 || nm_rc=$?
    if [[ $nm_rc -ne 0 ]]; then
        echo "nm $BIN failed (rc=$nm_rc): $(head -3 <<<"$nm_out")" >&2; exit 1
    fi
    if ! grep -q '\blj_str_new$' <<<"$nm_out"; then
        echo "relink produced no LuaJIT symbols ($(wc -l <<<"$nm_out") symbols, $(grep -c '\blj_' <<<"$nm_out" || true) lj_*)" >&2
        exit 1
    fi
}

# ─── One rep: daemon up, load on, profile, tear down ────────────────────────

wait_port() {  # bounded: 5 s, then fail
    local i
    for i in $(seq 50); do
        ss -ltnH "sport = :$PORT" 2>/dev/null | grep -q . && return 0
        sleep 0.1
    done
    return 1
}

proc_cpu_s() {  # utime+stime in seconds; parse after the ") " so a comm
                # with spaces cannot shift the fields (14->12, 15->13)
    awk -v clk="$(getconf CLK_TCK)" \
        '{ sub(/^[^)]*\) /, ""); n = split($0, f, " "); print (f[12] + f[13]) / clk }' \
        "/proc/$1/stat"
}

run_rep() {
    local arm=$1 rep=$2 tag="${arm}_r${rep}"
    local envs=()
    [[ $arm == nohook ]] && envs=(SOCKETLEY_LUA_TIMEOUT_MS=0)

    # Each rep gets an empty state directory.  The reps share one RUN_HOME, and
    # a daemon persists its runtimes there and restores them on the next start,
    # so rep 2 met a lua_share_srv the daemon had brought back from rep 1 and
    # `create` refused it -- "runtime already exists", mid-run, after two arms
    # had already been measured.  Loud rather than silent, but the reps are only
    # independent if nothing survives between them.
    rm -rf "$RUN_HOME"
    mkdir -p "$RUN_HOME"

    HOME="$RUN_HOME" env "${envs[@]}" "$BIN" daemon >"$OUT_DIR/daemon_$tag.log" 2>&1 &
    DAEMON_PID=$!
    local i
    for i in $(seq 50); do [[ -S $SOCKETLEY_SOCKET ]] && break; sleep 0.1; done
    [[ -S $SOCKETLEY_SOCKET ]] || { echo "daemon never made $SOCKETLEY_SOCKET" >&2; exit 2; }

    HOME="$RUN_HOME" "$BIN" create server lua_share_srv -p $PORT --mode in --lua "$ECHO_LUA" -s
    wait_port || { echo "server never listened on $PORT" >&2; exit 2; }

    # The worker that owns the listener, from the socket itself.
    local wpid
    wpid=$(ss -ltnpH "sport = :$PORT" | grep -oP 'pid=\K[0-9]+' | head -1)
    [[ -n $wpid ]] || { echo "no pid on port $PORT" >&2; exit 2; }

    # Warmup, discarded: connection setup, allocator, and (nohook arm) traces.
    "$ECHOLOAD" 127.0.0.1 $PORT $PAYLOAD 3000 $DEPTH >/dev/null

    "$ECHOLOAD" 127.0.0.1 $PORT $PAYLOAD $((SECS * 1000)) $DEPTH >"$OUT_DIR/load_$tag.txt" &
    LOAD_PID=$!
    sleep 2   # let it settle before the window opens

    local cpu0 cpu1
    cpu0=$(proc_cpu_s "$wpid")
    "$PERF" record -q -e cpu-clock -F 997 --call-graph dwarf,16384 \
        -p "$wpid" -o "$OUT_DIR/perf_$tag.data" -- sleep $PROF_SECS
    cpu1=$(proc_cpu_s "$wpid")

    wait "$LOAD_PID"; LOAD_PID=""
    echo "cpu_s=$(awk "BEGIN{print $cpu1-$cpu0}") window_s=$PROF_SECS" >>"$OUT_DIR/load_$tag.txt"

    HOME="$RUN_HOME" "$BIN" stop lua_share_srv >/dev/null 2>&1 || true
    HOME="$RUN_HOME" "$BIN" remove lua_share_srv >/dev/null 2>&1 || true
    kill "$DAEMON_PID" 2>/dev/null || true
    ( wait "$DAEMON_PID" ) 2>/dev/null || true
    DAEMON_PID=""
    sweep_mine
    rm -f "$SOCKETLEY_SOCKET"
}

# ─── Buckets from the leaf profile ──────────────────────────────────────────
# lua_vm   : the interpreter/JIT itself       (lj_* except gc/str, lua_* C API)
# lua_gc   : collector                        (lj_gc_*)  -- candidate 1's number
# lua_str  : string interning                 (lj_str_*) -- the per-msg push
# sol_glue : sol2 + lua_context + invoke_on_* (candidates 2 and 3)
# alloc    : malloc/free/new/delete           (feeds candidate 1; attribution
#            is by caller, so some of it belongs to Lua -- see the call graph)
# kernel   : [k] samples
# user_rest: everything else in userspace
report_rep() {
    local tag=$1
    "$PERF" report -i "$OUT_DIR/perf_$tag.data" --stdio --no-children -g none \
        --percent-limit 0 2>/dev/null | awk '
        /^#/ || NF < 4 { next }
        {
            pct = $1 + 0
            sym = $5
            for (i = 6; i <= NF; i++) sym = sym " " $(i)  # symbols with spaces, in order
            if ($4 == "[k]" || $3 ~ /kallsyms|vmlinux/)      k += pct
            else if (sym ~ /^lj_gc_/)                         gc += pct
            else if (sym ~ /^lj_str_/)                        str += pct
            else if (sym ~ /^(lj_|lua_[a-z]|luaJIT|luaopen_)/) vm += pct
            else if (sym ~ /sol::|lua_context|lua_deadline|invoke_on_|api_(yes|why|count)/) glue += pct
            else if (sym ~ /malloc|_int_free|cfree|^free$|operator new|operator delete|arena/) al += pct
            else                                              rest += pct
        }
        END { printf "kernel=%.1f lua_vm=%.1f lua_gc=%.1f lua_str=%.1f sol_glue=%.1f alloc=%.1f user_rest=%.1f lua_leaf_total=%.1f\n",
              k, vm, gc, str, glue, al, rest, vm+gc+str+glue }'
}

inclusive_rep() {  # floor, not ceiling: DWARF dies inside LuaJIT asm frames
    local tag=$1
    "$PERF" report -i "$OUT_DIR/perf_$tag.data" --stdio --children \
        --percent-limit 0.2 2>/dev/null \
        | grep -E 'invoke_on_client_message|invoke_on_message|send_to' \
        | head -6 || true
}

# ─── Run ────────────────────────────────────────────────────────────────────

relink_syms

echo "== bench_lua_share  payload=$PAYLOAD depth=$DEPTH secs=$SECS reps=$REPS port=$PORT"
echo "   out: $OUT_DIR"

for rep in $(seq "$REPS"); do          # interleaved: hook nohook hook nohook
    for arm in hook nohook; do
        echo "-- $arm rep $rep"
        run_rep "$arm" "$rep"
    done
done

echo
echo "== results =="
for rep in $(seq "$REPS"); do
    for arm in hook nohook; do
        tag="${arm}_r${rep}"
        line=$(head -1 "$OUT_DIR/load_$tag.txt")
        cpu=$(grep -oP 'cpu_s=\K[0-9.]+' "$OUT_DIR/load_$tag.txt" | tail -1)
        rate=$(grep -oP 'msgs_per_s=\K[0-9]+' <<<"$line")
        cores=$(grep -oP 'cores=\K[0-9.]+' <<<"$line")
        # worker CPU-us per message over the profile window; rate assumed
        # steady across the load run (single client, fixed depth).
        cpu_us=$(awk "BEGIN{ if ($rate>0) printf \"%.2f\", $cpu*1e6/($rate*$PROF_SECS); else print \"nan\" }")
        echo "[$tag] $line"
        echo "[$tag] worker_cpu_us_per_msg=$cpu_us  client_cores=$cores  (client at 1.0 means the client is the ceiling)"
        echo "[$tag] $(report_rep "$tag")"
        echo "[$tag] inclusive (floor, DWARF breaks in LuaJIT asm):"
        inclusive_rep "$tag" | sed "s/^/[$tag]   /"
        echo
    done
done
echo "perf.data kept in $OUT_DIR for by-hand inspection."
