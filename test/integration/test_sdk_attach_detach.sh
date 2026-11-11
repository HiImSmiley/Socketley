#!/usr/bin/env bash
# Integration test: an attached process detaching itself, and an operator
# removing it from outside.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# daemon_detach() killed the program that called it.
#
# Removing an external runtime SIGTERMs the pid it attached with -- deliberate,
# and right when an operator types `socketley remove`: the entry stands for a
# process, and deleting the entry should take the process.  attach.h's
# daemon_detach() sends that same `remove`, so the signal landed on the caller
# while it sat waiting for the reply.  A program with no SIGTERM handler died
# inside its own detach; one with a handler saw signal 15 arrive during it.
#
# Worse, daemon_attach() registers the same call with std::atexit, so this
# reached every SDK program that had ever attached, at exit, whether or not it
# ever called detach.
#
# Measured before the fix: `detach returned; signal received during it = 15`
# with a handler installed, and the process terminated outright without one.
#
# ─── WHY BOTH ARMS ──────────────────────────────────────────────────────────
#
# The fix is a guard on who is asking, not the removal of the signal, so this
# file has to show the signal still lands for everyone else.  A one-armed
# version of this test passes just as well against a daemon that stopped
# signalling altogether -- which would leave `socketley remove` unable to stop
# the process its entry stands for.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_sdk.sh"
ROOT=$(cd "$HERE/../.." && pwd)
BINDIR=$(dirname "$BIN")

daemon_isolate sdkatt

PORT=$((SL_PORT_BASE+1490))
PASS=0; FAIL=0; TOTAL=0
HOLD_PID=""

ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    if [ -n "$HOLD_PID" ]; then
        kill -9 "$HOLD_PID" 2>/dev/null
        wait "$HOLD_PID" 2>/dev/null || true
    fi
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: attaching, detaching, and being removed ==="

if ! command -v g++ >/dev/null 2>&1; then echo "  SKIP: g++ is required"; exit 0; fi

SANFLAGS=""
case "$BINDIR" in *Sanitize*) SANFLAGS="-fsanitize=address,undefined";; esac

# A SIGTERM handler rather than letting it kill us: without one the old
# behaviour is a dead process and an empty file, which reads the same as a
# build that never ran.
cat > "$SOCKETLEY_TMPD/detach.cpp" <<'EOF'
#include <socketley/attach.h>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
static volatile sig_atomic_t got_signal = 0;
static void on_term(int s) { got_signal = s; }
int main(int argc, char** argv)
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    struct sigaction sa{};
    sa.sa_handler = on_term;
    sigaction(SIGTERM, &sa, nullptr);
    bool a = socketley::daemon_attach("att_self", "server",
                                      (uint16_t)atoi(argv[1]), "");
    printf("attach=%d\n", (int)a);
    if (!a) { printf("err=%s\n", socketley::attach_error().c_str()); return 1; }
    socketley::daemon_detach("att_self");
    printf("detach_returned=1 signal=%d\n", (int)got_signal);
    return 0;
}
EOF

cat > "$SOCKETLEY_TMPD/hold.cpp" <<'EOF'
#include <socketley/attach.h>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
int main(int argc, char** argv)
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    if (!socketley::daemon_attach("att_hold", "server", (uint16_t)atoi(argv[1]), ""))
    { printf("attach failed: %s\n", socketley::attach_error().c_str()); return 1; }
    printf("attached\n");
    for (int i = 0; i < 300; ++i) sleep(1);
    return 0;
}
EOF

BUILT=1
for f in detach hold; do
    sdk_cxx "$SOCKETLEY_TMPD/$f.cpp" \
        -I"$ROOT" -I"$ROOT/sdk/include/linux" \
        -isystem "$ROOT/thirdparty/sol2" -isystem "$ROOT/thirdparty/luajit" \
        -o "$SOCKETLEY_TMPD/$f" 2>>"$SOCKETLEY_TMPD/gxx.err" || BUILT=0
done
if [ "$BUILT" -eq 1 ]; then ok; else
    bad "both probes build against attach.h" "$(tail -5 "$SOCKETLEY_TMPD/gxx.err")"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
    exit 1
fi

daemon_start "$BIN"

# ── A process detaching itself ──────────────────────────────────────────────
RC=0
OUT=$(timeout 20 "$SOCKETLEY_TMPD/detach" "$PORT" 2>&1) || RC=$?

if [ "$RC" -ne 124 ]; then ok; else
    bad "daemon_detach() returns at all" \
        "the probe was still running after 20 s" \
        "it is waiting for the reply to a remove that killed it"
fi

case "$OUT" in *attach=1*) ok;; *) bad "the probe attached" "said: $OUT";; esac

case "$OUT" in
    *detach_returned=1*) ok;;
    *) bad "and daemon_detach() came back" "said: $OUT";;
esac

case "$OUT" in
    *"signal=0"*) ok;;
    *) bad "without signalling the process that asked" \
           "said: $OUT" \
           "signal=15 is the daemon terminating the caller inside its own detach";;
esac

if kill -0 "$SOCKETLEY_DPID" 2>/dev/null &&
   ! "$BIN" ls </dev/null 2>/dev/null | awk '$2=="att_self"{f=1} END{exit !f}'; then ok; else
    bad "and the entry is gone afterwards" \
        "$("$BIN" ls </dev/null 2>&1)" \
        "a detach that does not unregister is not a detach"
fi

# ── An operator removing it from outside, which must still stop it ──────────
"$SOCKETLEY_TMPD/hold" $((PORT+1)) >"$SOCKETLEY_TMPD/hold.out" 2>&1 &
HOLD_PID=$!
for _ in $(seq 1 100); do
    grep -q attached "$SOCKETLEY_TMPD/hold.out" 2>/dev/null && break
    sleep 0.1
done

if "$BIN" ls </dev/null 2>/dev/null | awk '$2=="att_hold"{f=1} END{exit !f}'; then ok; else
    bad "the second probe is attached and listed" "$("$BIN" ls </dev/null 2>&1)"
fi

"$BIN" remove att_hold </dev/null >/dev/null 2>&1
for _ in $(seq 1 60); do kill -0 "$HOLD_PID" 2>/dev/null || break; sleep 0.1; done

if ! kill -0 "$HOLD_PID" 2>/dev/null; then ok; else
    bad "removing it from outside still stops the process" \
        "pid $HOLD_PID survived a socketley remove" \
        "the guard is on who is asking, not on the signal itself"
fi
wait "$HOLD_PID" 2>/dev/null || true
HOLD_PID=""

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
if [ "$FAIL" -eq 0 ]; then echo "  OK"; else echo "  FAILED"; fi
exit "$FAIL"
