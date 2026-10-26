#!/usr/bin/env bash
# Integration test: finding the daemons that are running, and stopping one.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# Several daemons could serve one machine and nothing could say so.
# SOCKETLEY_SOCKET moves the socket AND keys the state directory to it, so a
# second daemon left no trace anywhere a CLI would look: `ls` answers from
# whichever one the environment happens to point at and never says which, and
# the state directory's key spells `/` as `_`, so it cannot be turned back into
# a socket path to probe.
#
# Ending one was worse.  There was no `socketley daemon stop` -- the string
# appears in the tree's own example, where it answers
#
#     unknown daemon flag: stop
#
# so the documented way to stop a daemon was to find its pid and kill it, which
# on a box with several is the problem this file is about, twice.
#
# ─── WHAT THE ASSERTIONS ARE FOR ────────────────────────────────────────────
#
# The registry is a file per daemon, written after the socket is served.  A
# daemon killed outright cannot remove its own file, so the list must never
# trust it: every entry is probed, and `dead` has to appear for a daemon that
# was SIGKILLed.  That is asserted directly, because a list that reported
# whatever the files said would look identical on the day it was wrong.
#
# The custom daemon is here rather than in test_sdk_daemon.sh because the point
# is that the registry is written by daemon_start and therefore by ANY binary
# built on the SDK -- a discovery mechanism that only found the packaged daemon
# would miss exactly the daemons an operator is least likely to remember.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_sdk.sh"
ROOT=$(cd "$HERE/../.." && pwd)
BINDIR=$(dirname "$BIN")

daemon_isolate dvis

PORT=$((SL_PORT_BASE+1420))
PASS=0; FAIL=0; TOTAL=0

ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}
has() { case "$1" in *"$2"*) return 0;; *) return 1;; esac; }

A_SOCK="$SOCKETLEY_TMPD/a.sock"
B_SOCK="$SOCKETLEY_TMPD/b.sock"
A_PID=""; B_PID=""

cleanup() {
    [ -n "$A_PID" ] && kill -9 "$A_PID" 2>/dev/null
    [ -n "$B_PID" ] && kill -9 "$B_PID" 2>/dev/null
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: which daemons are running, and stopping one ==="

# ── Nothing running is an answer, not an empty table ────────────────────────
OUT=$(SOCKETLEY_SOCKET="$A_SOCK" "$BIN" daemons </dev/null 2>&1)
if has "$OUT" "no daemon has registered"; then ok; else
    bad "with none running it says so" "said: $OUT"
fi

# ── Two daemons, one packaged and one built on the SDK ──────────────────────
SOCKETLEY_SOCKET="$A_SOCK" "$BIN" daemon >"$SOCKETLEY_TMPD/a.log" 2>&1 &
A_PID=$!

SDK_BIN=""
if command -v g++ >/dev/null 2>&1 && [ -f "$BINDIR/libsocketley_sdk.a" ]; then
    SANFLAGS=""
    case "$BINDIR" in *Sanitize*) SANFLAGS="-fsanitize=address,undefined";; esac
    cat > "$SOCKETLEY_TMPD/mine.cpp" <<'EOF'
#include <socketley/daemon.h>
int main(int argc, char** argv)
{
    runtime_manager manager;
    event_loop loop;
    return socketley::daemon_start(manager, loop, argc, argv);
}
EOF
    if sdk_cxx "$SOCKETLEY_TMPD/mine.cpp" \
         -I"$ROOT" -I"$ROOT/include/linux" \
         -isystem "$ROOT/thirdparty/sol2" -isystem "$ROOT/thirdparty/luajit" \
         -L"$ROOT/thirdparty/liburing" $("$ROOT/sdk/socketley-config" --config "$(basename "$BINDIR")" --cflags --libs) \
         -o "$SOCKETLEY_TMPD/mine" 2>"$SOCKETLEY_TMPD/gxx.err"; then
        SDK_BIN="$SOCKETLEY_TMPD/mine"
        SOCKETLEY_SOCKET="$B_SOCK" "$SDK_BIN" daemon >"$SOCKETLEY_TMPD/b.log" 2>&1 &
        B_PID=$!
    else
        # g++ and the SDK archive are both here, so a failed compile is the SDK's regression and not the box's.
        bad "the SDK daemon builds" "$(head -5 "$SOCKETLEY_TMPD/gxx.err")" \
            "the second-daemon assertions did not run"
    fi
else
    echo "  (no g++ or no libsocketley_sdk.a -- the second-daemon assertions are skipped)"
fi

for _ in $(seq 1 100); do
    [ -S "$A_SOCK" ] && { [ -z "$SDK_BIN" ] || [ -S "$B_SOCK" ]; } && break
    sleep 0.1
done

OUT=$(SOCKETLEY_SOCKET="$A_SOCK" "$BIN" daemons </dev/null 2>&1)
if has "$OUT" "$A_SOCK"; then ok; else
    bad "the running daemon is listed" "said: $OUT"
fi

# The one this CLI would talk to, which is the question underneath the list.
if grep -q "^\* .*$A_SOCK" <<<"$OUT"; then ok; else
    bad "and the one this CLI uses is marked" "said: $OUT"
fi

# The binary, because with a custom daemon "which socketley is this" has a
# different answer per socket.
if has "$OUT" "$BIN"; then ok; else
    bad "the binary serving it is named" "said: $OUT"
fi

if [ -n "$SDK_BIN" ]; then
    if has "$OUT" "$SDK_BIN"; then ok; else
        bad "a daemon built on the SDK registers too" \
            "said: $OUT" \
            "the registry is written by daemon_start, so any SDK binary is in it"
    fi

    # Asked from the other side: the mark moves, the list does not.
    OUT2=$(SOCKETLEY_SOCKET="$B_SOCK" "$BIN" daemons </dev/null 2>&1)
    if grep -q "^\* .*$B_SOCK" <<<"$OUT2"; then ok; else
        bad "the mark follows SOCKETLEY_SOCKET" "said: $OUT2"
    fi

    # ── The hint in `ls`, which is where the question is actually asked ─────
    #
    # `socketley daemons` answers it only for someone who already suspects a
    # second daemon.  The person who does not is looking at `ls`, and the two
    # cases below are the ones that mislead: a listing that is right for the
    # wrong daemon, and an empty one that reads as an idle machine.
    A() { SOCKETLEY_SOCKET="$A_SOCK" "$BIN" "$@" </dev/null 2>&1; }
    A create server dv_hint -p $((PORT+5)) -s >/dev/null
    OUT=$(A ls)
    if grep -q "2 daemons are running" <<<"$OUT"; then ok; else
        bad "ls says how many daemons are running" "said: $OUT"
    fi
    if grep -qF "$A_SOCK" <<<"$OUT"; then ok; else
        bad "and names the one that answered" "said: $OUT"
    fi

    # The empty listing, from the daemon that has nothing -- the case where
    # there is no table for the line to hang under.
    OUT=$(SOCKETLEY_SOCKET="$B_SOCK" "$BIN" ls </dev/null 2>&1)
    if grep -q "2 daemons are running" <<<"$OUT"; then ok; else
        bad "an empty ls still says which daemon answered" \
            "said: [$OUT]" \
            "nothing listed on the wrong daemon looks like an idle machine"
    fi

    # Anything a script reads must be untouched, or the hint has traded one
    # silent wrong answer for another.
    if [ -z "$(SOCKETLEY_SOCKET="$B_SOCK" "$BIN" ls --json </dev/null 2>&1)" ] &&
       ! grep -q daemons <<<"$(A ls --json)" &&
       ! grep -q daemons <<<"$(A ls -s)" &&
       ! grep -q daemons <<<"$(A ls --name --port)"
    then ok; else
        bad "--json, -s and named columns carry no hint" \
            "json: $(A ls --json)" "-s:   $(A ls -s)"
    fi

    A remove dv_hint >/dev/null

    # ── A daemon that cannot clean up after itself ──────────────────────────
    kill -9 "$B_PID" 2>/dev/null
    # Reaped here so the shell does not print its own "Killed" line into the
    # suite's output for a death this file arranged on purpose.
    wait "$B_PID" 2>/dev/null || true
    B_PID=""
    sleep 0.5
    OUT=$(SOCKETLEY_SOCKET="$A_SOCK" "$BIN" daemons </dev/null 2>&1)
    if grep -qE "$B_SOCK.*dead" <<<"$OUT"; then ok; else
        bad "a SIGKILLed daemon is reported dead, not listed as up" \
            "said: $OUT" \
            "the file it left behind must not be taken for a running daemon"
    fi

    # One daemon is the ordinary case, and a line about it on every listing
    # would be read past by the time it mattered.
    A create server dv_solo -p $((PORT+6)) -s >/dev/null
    if ! grep -q "daemons are running" <<<"$(A ls)"; then ok; else
        bad "with one daemon left the hint is gone" "said: $(A ls)"
    fi

    # ── A daemon that is dead but not yet reaped ────────────────────────────
    #
    # kill(pid, 0) succeeds on a zombie, so a corpse whose parent has not
    # waited on it counted as a running daemon and the hint said two.  The
    # parent here is a shell blocked in sleep, which is what keeps the entry
    # in Z rather than letting bash reap it the moment it dies.
    C_SOCK="$SOCKETLEY_TMPD/c.sock"
    bash -c "SOCKETLEY_SOCKET=$C_SOCK '$BIN' daemon >/dev/null 2>&1 & echo \$! > $SOCKETLEY_TMPD/cpid; exec sleep 25" &
    C_PARENT=$!
    for _ in $(seq 1 60); do [ -S "$C_SOCK" ] && break; sleep 0.1; done
    C_PID=$(cat "$SOCKETLEY_TMPD/cpid" 2>/dev/null || echo "")
    if [ -n "$C_PID" ] && kill -9 "$C_PID" 2>/dev/null; then
        sleep 0.7
        # Asserted, because without a zombie there is nothing to measure and
        # the check below would pass on any build.
        if [ "$(ps -o stat= -p "$C_PID" 2>/dev/null | tr -d ' ')" = "Z" ]; then ok; else
            bad "the corpse is actually a zombie" \
                "state: $(ps -o stat= -p "$C_PID" 2>/dev/null | tr -d ' ')" \
                "without one in Z the assertion below proves nothing"
        fi
        if ! grep -q "daemons are running" <<<"$(A ls)"; then ok; else
            bad "a zombie daemon is not counted as running" \
                "said: $(A ls)" \
                "kill(pid, 0) succeeds on a zombie; the state has to be read too"
        fi
    else
        bad "the zombie daemon starts" "no pid in $SOCKETLEY_TMPD/cpid or it was already gone" \
            "the zombie assertion did not run"
    fi
    kill -9 "$C_PARENT" 2>/dev/null
    wait "$C_PARENT" 2>/dev/null || true

    A remove dv_solo >/dev/null
fi

# ── Stopping one, over the socket rather than by pid ────────────────────────
if SOCKETLEY_SOCKET="$A_SOCK" "$BIN" create server dv_web -p "$PORT" -s </dev/null >/dev/null 2>&1; then ok
else bad "the daemon serves before it is stopped" \
         "$(SOCKETLEY_SOCKET="$A_SOCK" "$BIN" create server dv_web2 -p $((PORT+1)) -s </dev/null 2>&1)"; fi

RC=0
SOCKETLEY_SOCKET="$A_SOCK" timeout 10 "$BIN" daemon stop </dev/null >/dev/null 2>&1 || RC=$?
if [ "$RC" -eq 0 ]; then ok; else bad "daemon stop is accepted" "exit $RC"; fi

for _ in $(seq 1 60); do kill -0 "$A_PID" 2>/dev/null || break; sleep 0.1; done
if ! kill -0 "$A_PID" 2>/dev/null; then ok; else
    bad "and the daemon actually exits" "pid $A_PID is still running"
fi
A_PID=""

# A stop that stopped nothing would satisfy the two above if the runtime kept
# its port through a supervisor that was gone.
if ! ss -ltn 2>/dev/null | awk -v p=":$PORT\$" '$4 ~ p' | grep -q .; then ok; else
    bad "its runtime's port is released" "something is still listening on $PORT"
fi

# ── Stopping nothing says so rather than exiting 0 ──────────────────────────
RC=0
OUT=$(SOCKETLEY_SOCKET="$A_SOCK" timeout 10 "$BIN" daemon stop </dev/null 2>&1) || RC=$?
if [ "$RC" -ne 0 ] && has "$OUT" "$A_SOCK"; then ok; else
    bad "stopping a socket nobody serves is refused by name" "exit $RC, said: $OUT"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
if [ "$FAIL" -eq 0 ]; then echo "  OK"; else echo "  FAILED"; fi
exit "$FAIL"
