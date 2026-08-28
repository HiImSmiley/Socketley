#!/usr/bin/env bash
# ensure_daemon decided a daemon existed by connect()ing and believing the
# answer, which tells you only that something is listening -- while the test
# side of this tree stopped identifying by the wrong property long ago.
# ─── WHY THE FAILURE IS ASYMMETRIC ──────────────────────────────────────────
# A false negative forks one wasted daemon, while a false positive writes the
# operator's whole command to a stranger -- and a stranger that answers two
# zero bytes makes the CLI report exit 0 with no text, which in this shell
# means it worked.
# ─── WHAT IS ASSERTED ───────────────────────────────────────────────────────
# The oracle is what the impostor received rather than the exit code, which was
# already non-zero against the mute one -- with two impostors, a mute program
# that has the path open for its own reasons and a yes-man whose well-formed
# reply frame turns a misdelivered command into a reported success.
# ─── THE CONTROLS ───────────────────────────────────────────────────────────
# Three assertions in the other direction, because a probe that refuses
# everything would pass every assertion above: a real daemon is still found,
# still auto-started from cold, and a stale socket file left by a killed daemon
# still auto-starts one.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate identity

SRV_PORT=$((SL_PORT_BASE+860))

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

# A case statement rather than `grep -q`, which exits at its first match and
# under pipefail takes the no-match branch precisely when it matched.
has() { case "$1" in *"$2"*) return 0;; *) return 1;; esac; }

IMP_PID=""

# Kill the impostor and take the path back to empty between scenarios, because
# every scenario below starts from nothing being bound here.
clear_socket() {
    if [ -n "$IMP_PID" ]; then
        kill "$IMP_PID" 2>/dev/null || true
        wait "$IMP_PID" 2>/dev/null || true
        IMP_PID=""
    fi
    # Anything the CLI auto-started during a scenario goes too, because a
    # daemon left on this run's socket outliving the test is the one thing this
    # file may not do.
    daemon_sweep "$SOCKETLEY_SOCKET"
    rm -f "$SOCKETLEY_SOCKET"
}

cleanup() {
    clear_socket
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: the CLI identifies the daemon before it talks to it ==="

# ─── the impostor ────────────────────────────────────────────────────────────
# Binds the daemon's socket path and writes down every byte it is handed,
# answering with a frame the CLI parses as success or with nothing at all.
IMPOSTOR_PY=$SOCKETLEY_TMPD/impostor.py
cat > "$IMPOSTOR_PY" <<'PY'
import os, socket, sys, threading

path, mode, log = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    os.unlink(path)
except FileNotFoundError:
    pass

srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(path)
srv.listen(16)

# The readiness handshake: the parent waits for this file, so no CLI command
# can run against a path that is only half bound.
with open(log + ".ready", "w") as f:
    f.write("ready\n")

def serve(c):
    c.settimeout(5)
    try:
        while True:
            b = c.recv(65536)
            if not b:
                break
            with open(log, "ab") as f:
                f.write(b)
                f.flush()
            if mode == "yes":
                # exit code 0, no data, NUL terminator -- exactly the frame
                # ipc_client.cpp reads back from the daemon on success.
                c.sendall(b"\x00\x00")
    except Exception:
        pass
    try:
        c.close()
    except Exception:
        pass

while True:
    try:
        c, _ = srv.accept()
    except Exception:
        break
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PY

start_impostor() {
    local mode=$1
    IMP_LOG=$SOCKETLEY_TMPD/impostor-$mode.log
    rm -f "$IMP_LOG" "$IMP_LOG.ready"
    python3 "$IMPOSTOR_PY" "$SOCKETLEY_SOCKET" "$mode" "$IMP_LOG" &
    IMP_PID=$!
    local i
    for i in $(seq 1 100); do
        [ -f "$IMP_LOG.ready" ] && return 0
        sleep 0.05
    done
    echo "  FATAL: the impostor never bound $SOCKETLEY_SOCKET; nothing below"
    echo "         would be measuring anything."
    exit 2
}

# What the impostor was handed, or empty.
heard() { [ -f "$IMP_LOG" ] && cat "$IMP_LOG" || true; }

# The probe is itself a message, so what has to be true is that the question is
# all the impostor heard -- stated as an exact match, so a probe that asks and
# then sends the command anyway is caught.
only_the_probe() {
    [ "$(heard | tr -d '\n')" = "ping" ]
}

# ─── 1. the yes-man ──────────────────────────────────────────────────────────
# The dangerous one: it answers every connection with a success frame, so a CLI
# that believes connect() reports a runtime created on a machine where nothing
# was.
clear_socket
start_impostor yes

set +e
OUT=$("$BIN" create server idsrv -p "$SRV_PORT" 2>&1)
RC=$?
set -e

HEARD=$(heard)
if only_the_probe; then ok; else
    bad "a listener that has not identified itself is asked, and told nothing" \
        "the CLI wrote the operator's command to a program that is not socketley;" \
        "it should have heard the identity probe and nothing else.  It heard:" \
        "  $(printf '%s' "$HEARD" | head -c 200 | tr -d '\000')"
fi

if [ "$RC" -ne 0 ]; then ok; else
    bad "a create that was never delivered does not report success" \
        "exit 0 from a create whose only listener was an impostor; by this" \
        "shell's convention that reads as 'a server is up on port $SRV_PORT'"
fi

if has "$OUT" "$SOCKETLEY_SOCKET"; then ok; else
    bad "the refusal names the path it refused" \
        "an operator has to be told WHICH socket is occupied to fix it; got:" \
        "  ${OUT:-<nothing>}"
fi

# ─── 2. the mute impostor ────────────────────────────────────────────────────
# The exit code proves nothing here because it was already non-zero, so the
# oracle is whether the command text left the CLI at all.
clear_socket
start_impostor mute

set +e
"$BIN" create server idsrv2 -p "$SRV_PORT" >/dev/null 2>&1
set -e

HEARD=$(heard)
if only_the_probe; then ok; else
    bad "a listener that never answers is told nothing either" \
        "the CLI wrote the operator's command to a program that is not socketley;" \
        "it should have heard the identity probe and nothing else.  It heard:" \
        "  $(printf '%s' "$HEARD" | head -c 200 | tr -d '\000')"
fi

# Nothing above is worth anything if the probe simply refuses everything, so
# this is the cold path: no socket file, no daemon, one CLI command that must
# fork a daemon and then use it.
clear_socket

if [ ! -e "$SOCKETLEY_SOCKET" ]; then ok; else
    bad "the path starts empty" "something is still bound to $SOCKETLEY_SOCKET"
fi

set +e
OUT=$("$BIN" create server realsrv -p "$SRV_PORT" -s 2>&1)
RC=$?
set -e

if [ "$RC" -eq 0 ]; then ok; else
    bad "a cold CLI command still auto-starts a daemon and is served by it" \
        "exit $RC: ${OUT:-<no output>}"
fi

if daemon_alive "$SOCKETLEY_SOCKET"; then ok; else
    bad "the auto-started daemon is serving the socket" \
        "no process holds the listening inode for $SOCKETLEY_SOCKET"
fi

LS=$("$BIN" ls 2>&1 || true)
if has "$LS" "realsrv"; then ok; else
    bad "the runtime the auto-started daemon was asked for exists" \
        "ls does not list realsrv:" "  ${LS:-<nothing>}"
fi

# A SIGKILLed daemon leaves the socket file behind while its listening row goes
# in the same instant, so this case was already right and has to stay right --
# because the obvious way to write a stricter probe is to look at the file.
"$BIN" remove realsrv >/dev/null 2>&1 || true
DPIDS=$(daemon_pids "$SOCKETLEY_SOCKET")
for p in $DPIDS; do kill -9 "$p" 2>/dev/null || true; done
sleep 0.4

if [ -S "$SOCKETLEY_SOCKET" ]; then ok; else
    bad "a SIGKILLed daemon leaves its socket file behind" \
        "no file at $SOCKETLEY_SOCKET, so the stale-file case is not being tested"
fi

set +e
OUT=$("$BIN" create server stalesrv -p "$SRV_PORT" 2>&1)
RC=$?
set -e

if [ "$RC" -eq 0 ]; then ok; else
    bad "a stale socket file still auto-starts a daemon" \
        "exit $RC: ${OUT:-<no output>}" \
        "a stale file is not an occupied path and must not be refused as one"
fi

clear_socket

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
