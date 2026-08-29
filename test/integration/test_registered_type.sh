#!/usr/bin/env bash
# Integration test: a runtime type the daemon has never heard of, delivered as
# a manifest plus a worker binary.
#
# The daemon learns the type's schema from a declarative manifest and never
# loads its code: the behaviour lives in a binary the supervisor forks and
# execs, built here against libsocketley_sdk from the tree under test.  What
# this file holds down is the whole seam: the type's flags come from the
# manifest, a misspelled key is refused by name, the runtime starts and is
# visible everywhere a built-in is, its fields persist under "extra", and a
# daemon restart brings it back running with those fields applied -- proved by
# an edit whose effect can only be observed after the restart re-reads disk.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
ROOT=$(cd "$HERE/../.." && pwd)
BINDIR=$(dirname "$BIN")

daemon_isolate regtype

PORT=$((SL_PORT_BASE+1360))

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}
has() { case "$1" in *"$2"*) return 0;; *) return 1;; esac; }

cleanup() {
    "$BIN" stop hi 2>/dev/null || true
    sleep 0.3
    "$BIN" remove hi 2>/dev/null || true
    "$BIN" remove hi2 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a registered runtime type (manifest + worker binary) ==="

if ! command -v g++ >/dev/null 2>&1; then
    echo "  SKIP: g++ is required to build the example worker"
    exit 0
fi
if [ ! -f "$BINDIR/libsocketley_sdk.a" ]; then
    echo "  SKIP: $BINDIR/libsocketley_sdk.a is not built"
    exit 0
fi

# ── The worker binary, from the example and the tree under test ─────────────
#
# The sanitizer runtimes must match the library's, because libsocketley_sdk.a
# from a Sanitize tree carries __asan_* references.
SANFLAGS=""
case "$BINDIR" in *Sanitize*) SANFLAGS="-fsanitize=address,undefined";; esac

WORKER="$SOCKETLEY_TMPD/greeter-worker"
if g++ -std=c++23 $SANFLAGS \
       "$ROOT/sdk/examples/custom-type/greeter_worker.cpp" \
       -I"$ROOT" -I"$ROOT/include/linux" \
       -isystem "$ROOT/thirdparty/sol2" -isystem "$ROOT/thirdparty/luajit" \
       -L"$BINDIR" -L"$ROOT/thirdparty/luajit" -L"$ROOT/thirdparty/liburing" \
       -lsocketley_sdk -lluajit -luring -lssl -lcrypto -pthread \
       -o "$WORKER" 2>"$SOCKETLEY_TMPD/gxx.err"; then
    ok
else
    bad "the example worker builds against the SDK" \
        "$(tail -5 "$SOCKETLEY_TMPD/gxx.err")"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
    exit 1
fi

# ── The manifest, in the isolated daemon's types directory ──────────────────
mkdir -p "$HOME/.config/socketley/types"
cat > "$HOME/.config/socketley/types/greeter.toml" <<EOF
name = "greeter"
exec = "$WORKER"
manifest_version = 1

[config.greeting]
kind = "string"
required = true

[config.repeat]
kind = "int"
default = "1"

[config.shout]
kind = "bool"
default = "false"
EOF

daemon_start "$BIN"

# ── The schema is the flag set ──────────────────────────────────────────────
OUT=$("$BIN" create greeter typo -p $((PORT+1)) --greting hello 2>&1)
if [ $? -ne 0 ] && has "$OUT" "--greting"; then ok; else
    bad "a misspelled key is refused by name" "said: $OUT"
fi

OUT=$("$BIN" create greeter noreq -p $((PORT+2)) 2>&1)
if [ $? -ne 0 ] && has "$OUT" "--greeting is required"; then ok; else
    bad "a missing required key is refused by name" "said: $OUT"
fi

OUT=$("$BIN" create greeter badint -p $((PORT+3)) --greeting x --repeat abc 2>&1)
if [ $? -ne 0 ] && has "$OUT" "--repeat takes an integer"; then ok; else
    bad "a value of the wrong kind is refused" "said: $OUT"
fi

if "$BIN" create greeter hi -p "$PORT" --greeting bonjour --repeat 2 -s >/dev/null 2>&1; then
    ok
else
    bad "a registered type is created with its own flags" \
        "$("$BIN" create greeter hi -p "$PORT" --greeting bonjour --repeat 2 -s 2>&1)"
fi

# ── Visible everywhere a built-in is ────────────────────────────────────────
LS=$("$BIN" ls 2>/dev/null)
if has "$LS" "hi" && has "$LS" "greeter"; then ok; else
    bad "ls names the runtime and its type" "$LS"
fi

PS=$("$BIN" ps 2>/dev/null)
if has "$PS" "hi"; then ok; else
    bad "ps lists it" "$PS"
fi

SHOW=$("$BIN" show hi 2>/dev/null)
if has "$SHOW" '"type": "greeter"'; then ok; else
    bad "show reports the type by name" "$SHOW"
fi
if has "$SHOW" '"greeting": "bonjour"' && has "$SHOW" '"repeat": "2"'; then ok; else
    bad "show carries the type's own fields under extra" "$SHOW"
fi
if has "$SHOW" '"shout": "false"'; then ok; else
    bad "a declared default is filled in at create" "$SHOW"
fi

# ── It serves, from a process that is not the daemon ────────────────────────
if command -v nc >/dev/null 2>&1; then
    ANSWER=""
    for _ in $(seq 1 40); do
        ANSWER=$(printf 'x\n' | nc -q1 127.0.0.1 "$PORT" 2>/dev/null)
        [ -n "$ANSWER" ] && break
        sleep 0.25
    done
    if [ "$ANSWER" = "bonjourbonjour" ]; then ok; else
        bad "the worker answers from its config" "got '${ANSWER:-<nothing>}'"
    fi
else
    echo "  (nc absent -- the traffic assertions did not run)"
fi

# ── Stats: the daemon's prefix plus the worker's own detail ─────────────────
STATS=""
for _ in $(seq 1 20); do
    STATS=$("$BIN" stats hi 2>/dev/null)
    has "$STATS" "greetings:" && break
    sleep 0.25
done
if has "$STATS" "type:greeter"; then ok; else
    bad "stats reports the type by name" "$STATS"
fi
if command -v nc >/dev/null 2>&1; then
    if has "$STATS" "greetings:1"; then ok; else
        bad "the worker's stats_extra() reaches the daemon" "$STATS"
    fi
fi

# ── The same schema through a --lua configuration ───────────────────────────
cat > "$SOCKETLEY_TMPD/reg.lua" <<EOF
runtimes = {
  { type = "greeter", name = "hi2", port = $((PORT+5)), greeting = "hey", shout = true },
}
EOF
if "$BIN" --lua "$SOCKETLEY_TMPD/reg.lua" >/dev/null 2>&1; then ok; else
    bad "a configuration file creates a registered type" \
        "$("$BIN" --lua "$SOCKETLEY_TMPD/reg.lua" 2>&1)"
fi
SHOW2=$("$BIN" show hi2 2>/dev/null)
if has "$SHOW2" '"greeting": "hey"' && has "$SHOW2" '"shout": "true"'; then ok; else
    bad "the table's keys reach the runtime" "$SHOW2"
fi

cat > "$SOCKETLEY_TMPD/regbad.lua" <<EOF
runtimes = {
  { type = "greeter", name = "hi3", port = $((PORT+6)), greting = "x" },
}
EOF
OUT=$("$BIN" --lua "$SOCKETLEY_TMPD/regbad.lua" 2>&1)
if [ $? -ne 0 ] && has "$OUT" "greting"; then ok; else
    bad "a misspelled key in a configuration is refused by name" "said: $OUT"
fi
"$BIN" remove hi2 >/dev/null 2>&1

# ── Persists, edits, and comes back across a restart ────────────────────────
#
# --shout flips behaviour only through the state file: the running worker was
# configured without it, so uppercase after the restart proves the field was
# persisted, restored, and handed to a fresh worker.
if "$BIN" edit hi --shout >/dev/null 2>&1; then ok; else
    bad "a schema key is editable" "$("$BIN" edit hi --shout 2>&1)"
fi

kill "$SOCKETLEY_DPID" 2>/dev/null || true
for i in $(seq 1 60); do kill -0 "$SOCKETLEY_DPID" 2>/dev/null || break; sleep 0.1; done
wait "$SOCKETLEY_DPID" 2>/dev/null || true
: > "$SOCKETLEY_DLOG"
"$BIN" daemon >>"$SOCKETLEY_DLOG" 2>&1 &
SOCKETLEY_DPID=$!
for i in $(seq 1 100); do
    grep -q "daemon started" "$SOCKETLEY_DLOG" 2>/dev/null && break
    sleep 0.1
done

STATUS=$("$BIN" ls 2>/dev/null | awk '$2 == "hi" { print $7 }')
if [ "$STATUS" = "Up" ]; then ok; else
    bad "was_running brings a registered type back" \
        "ls reports '${STATUS:-<nothing>}' after the restart"
fi

SHOW=$("$BIN" show hi 2>/dev/null)
if has "$SHOW" '"greeting": "bonjour"' && has "$SHOW" '"shout": "true"'; then ok; else
    bad "extra fields survive the restart, edit included" "$SHOW"
fi

if command -v nc >/dev/null 2>&1; then
    ANSWER=""
    for _ in $(seq 1 40); do
        ANSWER=$(printf 'x\n' | nc -q1 127.0.0.1 "$PORT" 2>/dev/null)
        [ -n "$ANSWER" ] && break
        sleep 0.25
    done
    if [ "$ANSWER" = "BONJOURBONJOUR" ]; then ok; else
        bad "the restored worker runs the edited config" \
            "got '${ANSWER:-<nothing>}', wanted BONJOURBONJOUR"
    fi
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
