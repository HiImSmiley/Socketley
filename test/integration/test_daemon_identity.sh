#!/usr/bin/env bash
# Integration test: the CLI identifies the daemon before it talks to it.
#
# `ensure_daemon()` in cli.cpp decided whether a daemon existed by connect()ing
# to the socket path and believing the answer.  connect() answers one question —
# "is anything listening here" — and the CLI was reading it as the answer to a
# different one: "is the thing listening here the daemon I am about to hand a
# command to".  Any AF_UNIX listener on that path collects the answer yes.
#
# The test side of this tree stopped identifying by the wrong property a while
# ago.  81dcf4a rewrote lib_daemon.sh to find a daemon by the inode of the
# socket it serves rather than by the process's name, because a binary copied
# under another name was being reported dead while it was serving.  f6670f8
# gave a cluster node an identity triple so it could tell "me, again" from
# "somebody else".  Production still asked connect().
#
# ─── WHY THE FAILURE IS ASYMMETRIC ──────────────────────────────────────────
#
# A false negative — "no daemon" while one is serving — forks a spare daemon,
# which finds the socket taken and exits 0.  One wasted process.
#
# A false positive — "a daemon" while something else is bound — means every
# command in the session is delivered to a stranger.  `create server db -p 9000`
# is written, in full, to whatever accepted the connection, and if that thing
# writes back so much as two zero bytes the CLI reads a framed reply of exit
# code 0 with no text and reports success, in a shell whose convention is that
# silence means it worked.  Nothing was created.  The operator is told it was.
#
# ─── WHAT IS ASSERTED ───────────────────────────────────────────────────────
#
# Not the exit code alone.  Against the mute impostor the exit code was already
# non-zero before this change — ipc_send's read timeout expires and the CLI
# says "failed to connect to daemon" — so an exit-code assertion there passes
# on the broken build and proves nothing.  The oracle is what the impostor
# RECEIVED: a command that was never sent cannot have been misdelivered.
#
# The impostors:
#
#   mute     accepts, reads, never writes.  A program that has the path open
#            for its own reasons.
#   yes-man  accepts, reads, writes \x00\x00 — a well-formed socketley reply
#            frame meaning "exit 0, no output".  This is the one that turns a
#            misdelivered command into a reported success.
#
# ─── THE CONTROLS ───────────────────────────────────────────────────────────
#
# A probe that refuses everything would pass every assertion above, so three
# assertions have to hold in the other direction:
#
#   * a real daemon is still found, and a `create` against it still works;
#   * a real daemon is still AUTO-STARTED from cold, which is the whole point
#     of ensure_daemon and the thing a stricter probe is most likely to break;
#   * a stale socket file left by a killed daemon still auto-starts a daemon,
#     rather than being mistaken for an occupied path.
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

# Does HAYSTACK contain NEEDLE.
#
# NOT `printf '%s' "$x" | grep -q "$n"`.  This file runs under `set -o
# pipefail` and `grep -q` exits at its first match, which hands the writer a
# SIGPIPE; the pipeline then reports 141 and the `if` takes the "no match"
# branch precisely when it matched.  lib_daemon.sh carries the same warning
# over daemon_starting_pids; test_ps_failed_visible.sh carries the account of
# it actually happening.  A case statement has no pipeline and cannot do it.
has() { case "$1" in *"$2"*) return 0;; *) return 1;; esac; }

IMP_PID=""

# Kill the impostor and take the path back to empty.  Between scenarios, not
# only at the end: every scenario below starts from "nothing is bound here".
clear_socket() {
    if [ -n "$IMP_PID" ]; then
        kill "$IMP_PID" 2>/dev/null || true
        wait "$IMP_PID" 2>/dev/null || true
        IMP_PID=""
    fi
    # Anything the CLI auto-started during a scenario goes too.  A daemon left
    # on this run's socket outlives the test and is the one thing this file is
    # not allowed to do.
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
#
# Binds the daemon's socket path and writes down every byte it is handed.  In
# `yes` mode it answers each connection with a framed reply the CLI parses as
# success; in `mute` mode it answers nothing at all.
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

# The identity probe is itself a message, so "the impostor heard nothing" is the
# wrong oracle — it can never be true of a probe that asks a question.  What has
# to be true is that the question is ALL it heard: the operator's command, with
# the runtime's name, its type and its port in it, must not be written to a
# program that has not answered the question.
#
# Stated as an exact match rather than "does not contain create", so that a
# probe which asks its question and then sends the command anyway is caught, and
# so is one that leaks any other command on the way.
only_the_probe() {
    [ "$(heard | tr -d '\n')" = "ping" ]
}

# ─── 1. the yes-man ──────────────────────────────────────────────────────────
#
# The dangerous one.  It answers every connection with a success frame, so a
# CLI that believes connect() reports that a runtime was created on a machine
# where nothing was.
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
#
# Exit code proves nothing here — it was already non-zero.  The oracle is
# whether the command text left the CLI at all.
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

# ─── 3. CONTROL: a real daemon is still found, and still auto-started ────────
#
# Nothing above is worth anything if the probe simply refuses everything.  This
# is the cold path: no socket file, no daemon, one CLI command, which must fork
# a daemon of its own and then use it.
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

# ─── 4. CONTROL: a stale socket file still auto-starts ───────────────────────
#
# A daemon killed with SIGKILL leaves the socket file behind and its listening
# row in /proc/net/unix goes in the same instant.  connect() to it fails, so
# this case was already right — and it has to stay right, because the obvious
# way to write a stricter probe is to look at the file.
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
