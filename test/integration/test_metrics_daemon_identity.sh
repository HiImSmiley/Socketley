#!/usr/bin/env bash
# Integration test: metrics and the dashboard answer for a named daemon.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# `ls` was taught to say which daemon answered.  Everything else that is
# daemon-wide was not, and metrics was the worst of it, because a scrape is
# read later by someone who was not there when it was taken.
#
# The dashboard was the silent one.  metrics_port came from the config file and
# was handed to the handler whether or not the endpoint could bind it, so a
# second daemon that lost the bind still answered
#
#     Dashboard: http://127.0.0.1:9100/
#
# naming the FIRST daemon's endpoint.  The operator reads another daemon's
# numbers and nothing anywhere says so; the only trace was a WARN line in a
# stderr that `daemon stop` deletes.
#
# The scrape itself named no daemon at all.  Every series is spelled the same
# on every daemon, and the `instance` label exists only for whoever configured
# the scrape -- not for anyone reading the endpoint directly.
#
# ─── AND THE PLUGIN HALF ────────────────────────────────────────────────────
#
# socketley_runtime_connections carried type= from a switch over the four
# built-in enumerators.  A registered type has no enumerator, so every custom
# runtime in the tree was scraped as type="unknown" -- the one place that
# hardcoded the four instead of asking the registry, and the one place an
# operator would go to see whether their own runtime is carrying traffic.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
BINDIR=$(dirname "$BIN")
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_sdk.sh"

daemon_isolate mdid

P=$((SL_PORT_BASE+1450))
MPORT=$((P+1))
PASS=0; FAIL=0; TOTAL=0

ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

B_PID=""
cleanup() {
    if [ -n "$B_PID" ]; then
        kill -9 "$B_PID" 2>/dev/null
        wait "$B_PID" 2>/dev/null || true
    fi
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: metrics say which daemon they came from ==="

# ── A registered type, so the scrape has something the registry alone knows ──
#
# The example worker rather than a stub: a type whose worker refuses its
# configuration never reaches runtime_running and so never reaches the
# per-runtime series this file is about.
WORKER=""
if command -v g++ >/dev/null 2>&1 && [ -f "$BINDIR/libsocketley_sdk.a" ]; then
    SANFLAGS=""
    case "$BINDIR" in *Sanitize*) SANFLAGS="-fsanitize=address,undefined";; esac
    if sdk_cxx \
           "$ROOT/sdk/examples/custom-type/greeter_worker.cpp" \
           -I"$ROOT" -I"$ROOT/include/linux" \
           -isystem "$ROOT/thirdparty/sol2" -isystem "$ROOT/thirdparty/luajit" \
           -L"$ROOT/thirdparty/liburing" $("$ROOT/sdk/socketley-config" --config "$(basename "$BINDIR")" --cflags --libs) \
           -o "$SOCKETLEY_TMPD/greeter-worker" 2>"$SOCKETLEY_TMPD/gxx.err"
    then
        WORKER="$SOCKETLEY_TMPD/greeter-worker"
        mkdir -p "$HOME/.config/socketley/types"
        cat > "$HOME/.config/socketley/types/greeter.toml" <<EOF
name = "greeter"
exec = $WORKER
manifest_version = 1
[config.greeting]
kind = "string"
default = "hello"
EOF
    else
        # With the toolchain and the SDK both here, an example that does not build is the SDK broken.
        bad "the example worker builds against this SDK" "g++ said: $(tail -3 "$SOCKETLEY_TMPD/gxx.err")" \
            "the registered-type assertions below are skipped"
    fi
else
    echo "  (no g++ or no libsocketley_sdk.a -- the registered-type assertions are skipped)"
fi

cat > "$SOCKETLEY_TMPD/daemon.lua" <<EOF
daemon = { metrics_port = $MPORT }
EOF
export SOCKETLEY_CONFIG="$SOCKETLEY_TMPD/daemon.lua"

daemon_start "$BIN"

if [ -z "$WORKER" ] || grep -q "registered 1 runtime type" "$SOCKETLEY_DLOG"; then ok; else
    bad "the manifest was read" "daemon log: $(tail -3 "$SOCKETLEY_DLOG")"
fi

OUT=$("$BIN" dashboard </dev/null 2>&1 || true)
if grep -q "http://127.0.0.1:$MPORT/" <<<"$OUT"; then ok; else
    bad "the daemon that bound the port prints its URL" "said: $OUT"
fi

[ -n "$WORKER" ] && "$BIN" create greeter st1 -p "$P" -s </dev/null >/dev/null 2>&1
"$BIN" create server sv1 -p $((P+2)) -s </dev/null >/dev/null 2>&1
sleep 1

SCRAPE=$(curl -s --max-time 5 "http://127.0.0.1:$MPORT/metrics" 2>/dev/null)
if [ -z "$SCRAPE" ]; then
    SCRAPE=$(printf 'GET /metrics HTTP/1.0\r\n\r\n' | timeout 5 nc 127.0.0.1 "$MPORT" 2>/dev/null)
fi

if grep -q "socketley_runtimes_total" <<<"$SCRAPE"; then ok; else
    bad "the endpoint answers a scrape at all" "got: $(head -c 200 <<<"$SCRAPE")"
fi

# ── Which daemon these numbers are from ─────────────────────────────────────
INFO=$(grep -m1 '^socketley_daemon_info' <<<"$SCRAPE")
if [ -n "$INFO" ]; then ok; else
    bad "the scrape names the daemon it came from" \
        "no socketley_daemon_info series" \
        "every other series is spelled the same on every daemon"
fi

if grep -qF "pid=\"$SOCKETLEY_DPID\"" <<<"$INFO"; then ok; else
    bad "and it is this daemon's pid" "said: $INFO" "expected pid $SOCKETLEY_DPID"
fi

if grep -qF "socket=\"$SOCKETLEY_SOCKET\"" <<<"$INFO"; then ok; else
    bad "and the socket it serves" "said: $INFO" "expected $SOCKETLEY_SOCKET"
fi

# The binary, because with a custom daemon that differs per socket and is the
# one thing a version string cannot answer.
if grep -qF "exe=\"$BIN\"" <<<"$INFO"; then ok; else
    bad "and the executable serving it" "said: $INFO" "expected $BIN"
fi

# ── A registered type is not "unknown" ──────────────────────────────────────
if [ -n "$WORKER" ]; then
    ROW=$(grep '^socketley_runtime_connections{name="st1"' <<<"$SCRAPE")
    if grep -q 'type="greeter"' <<<"$ROW"; then ok; else
        bad "a registered type is scraped under its own name" \
            "said: ${ROW:-<no series for st1>}" \
            "a switch over the four built-ins reported every custom runtime as unknown"
    fi
fi

if grep -q 'type="server"' <<<"$(grep '^socketley_runtime_connections{name="sv1"' <<<"$SCRAPE")"
then ok; else
    bad "and a built-in type still reads as before" \
        "said: $(grep '^socketley_runtime_connections{name="sv1"' <<<"$SCRAPE")"
fi

if ! grep -q 'type="unknown"' <<<"$SCRAPE"; then ok; else
    bad "nothing in the scrape is typed unknown" \
        "$(grep 'type="unknown"' <<<"$SCRAPE" | head -3)"
fi

# ── A second daemon that loses the metrics bind must say so ─────────────────
B_SOCK="$SOCKETLEY_TMPD/b.sock"
SOCKETLEY_SOCKET="$B_SOCK" "$BIN" daemon >"$SOCKETLEY_TMPD/b.log" 2>&1 &
B_PID=$!
for _ in $(seq 1 100); do
    grep -q "daemon started" "$SOCKETLEY_TMPD/b.log" 2>/dev/null && break
    sleep 0.1
done

RC=0
OUT=$(SOCKETLEY_SOCKET="$B_SOCK" "$BIN" dashboard </dev/null 2>&1) || RC=$?
if [ "$RC" -ne 0 ] && ! grep -q "http://127.0.0.1:$MPORT/" <<<"$OUT"; then ok; else
    bad "a daemon that could not bind the port does not print its URL" \
        "exit $RC, said: $OUT" \
        "that URL is the FIRST daemon's dashboard, and reading it is the bug"
fi

if grep -q "could not bind" <<<"$OUT" && grep -q "$MPORT" <<<"$OUT"; then ok; else
    bad "and says which port it lost, by name" "said: $OUT"
fi

# The first daemon is untouched by any of that.
OUT=$("$BIN" dashboard </dev/null 2>&1 || true)
if grep -q "http://127.0.0.1:$MPORT/" <<<"$OUT"; then ok; else
    bad "the daemon that holds the port still answers with it" "said: $OUT"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
if [ "$FAIL" -eq 0 ]; then echo "  OK"; else echo "  FAILED"; fi
exit "$FAIL"
