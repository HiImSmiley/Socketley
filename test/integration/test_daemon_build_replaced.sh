#!/usr/bin/env bash
# `socketley version` compares a literal that CLI and daemon are both compiled
# from, so its arm fires only across a version bump -- while the case it was
# written for, a same-version rebuild against a daemon still holding its
# runtimes, was reported nowhere.
# ─── WHAT MAKES THIS DECIDABLE ──────────────────────────────────────────────
# Both sides can name their own executable exactly through /proc/self/exe, and
# the comparison is only sound when both name the same path -- a different path
# says nothing, because every agent in this tree runs the CLI from a copy and a
# build report on each of those is noise that trains people to ignore the
# message.
# ─── WHY THE PAIR ───────────────────────────────────────────────────────────
# "A different path says nothing" is green on a build with no feature at all,
# so it is stated only next to "a genuine replacement at the same path is
# reported" -- and the replacement is a real one, renamed over the path,
# because the kernel refuses `cp` over a running executable with ETXTBSY and
# rename is what a linker falls back to for the same reason.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"

daemon_isolate buildswap

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
cleanup() {
    if [ -n "$IMP_PID" ]; then
        kill "$IMP_PID" 2>/dev/null || true
        wait "$IMP_PID" 2>/dev/null || true
    fi
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a daemon whose executable was rebuilt under it says so ==="

# The daemon runs from a path of this test's own, so that replacing the file
# there cannot disturb the binary the rest of the suite is running.
RUNDIR=$SOCKETLEY_TMPD/run
ALTDIR=$SOCKETLEY_TMPD/alt
mkdir -p "$RUNDIR" "$ALTDIR"
cp "$BIN" "$RUNDIR/socketley"
cp "$BIN" "$ALTDIR/socketley"

daemon_start "$RUNDIR/socketley"

# First, because if this is not silent then every assertion below is measuring
# a message that is always printed.
ERR=$("$RUNDIR/socketley" version 2>&1 >/dev/null || true)
if [ -z "$ERR" ]; then ok; else
    bad "a daemon running the very file the CLI is running says nothing" \
        "this message would be printed on every command in an ordinary session:" \
        "  $ERR"
fi

OUT_BEFORE=$("$RUNDIR/socketley" version 2>/dev/null)
if [ "$OUT_BEFORE" = "$("$BIN" version 2>/dev/null)" ]; then ok; else
    bad "stdout is the version number and nothing else" \
        "got [$OUT_BEFORE]"
fi

# ─── 2. the rebuild ──────────────────────────────────────────────────────────
# A new file renamed over the path the daemon is executing, so the daemon keeps
# the inode it started from and the path holds the file the CLI will be run
# from.
cp "$BIN" "$SOCKETLEY_TMPD/staged"
mv "$SOCKETLEY_TMPD/staged" "$RUNDIR/socketley"

# The premise: the daemon survived being rebuilt under, and the two files
# really are different inodes.
if daemon_alive "$SOCKETLEY_SOCKET"; then ok; else
    bad "the daemon survives its executable being replaced" \
        "no process is serving $SOCKETLEY_SOCKET after the rename"
fi

DPID=$(daemon_pids "$SOCKETLEY_SOCKET" | awk '{print $1}')
DEXE=$({ readlink "/proc/$DPID/exe"; } 2>/dev/null || true)
if [ "$DEXE" != "$RUNDIR/socketley" ] && [ -n "$DEXE" ]; then ok; else
    bad "the premise: the daemon is executing a file that is no longer at that path" \
        "/proc/$DPID/exe reads [$DEXE]; the rename did not detach it, so there is" \
        "no replaced executable to report"
fi

ERR=$("$RUNDIR/socketley" version 2>&1 >/dev/null || true)
if has "$ERR" "$RUNDIR/socketley"; then ok; else
    bad "the daemon's executable having been rebuilt is reported" \
        "the daemon is running a file that no longer exists at the path the CLI" \
        "was just run from, and nothing said so.  stderr was:" \
        "  ${ERR:-<empty>}"
fi

OUT_AFTER=$("$RUNDIR/socketley" version 2>/dev/null)
if [ "$OUT_AFTER" = "$OUT_BEFORE" ]; then ok; else
    bad "stdout stays byte-identical while the report goes to stderr" \
        "before [$OUT_BEFORE] after [$OUT_AFTER]"
fi

# The half that is green today and has to stay green: a byte-identical copy at
# another path is the arrangement every agent works in and is not evidence
# about anybody's build.
ERR=$("$ALTDIR/socketley" version 2>&1 >/dev/null || true)
if [ -z "$ERR" ]; then ok; else
    bad "a CLI run from a different path than the daemon's says nothing" \
        "a copy of the binary elsewhere on disk is not evidence that the" \
        "daemon's build is stale; 81dcf4a is what happens when a copy is" \
        "misidentified.  stderr was:" \
        "  $ERR"
fi

daemon_stop
daemon_isolate buildswap2

# A daemon too terse to answer is not accused, which is a guard against
# treating "the daemon did not say" as "the daemon said no" -- stood in for by
# a listener replying exactly that frame, with its control directly below.
TERSE_PY=$SOCKETLEY_TMPD/terse.py
cat > "$TERSE_PY" <<'PY'
import os, socket, sys
path, reply = sys.argv[1], sys.argv[2]
try:
    os.unlink(path)
except FileNotFoundError:
    pass
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(path); srv.listen(8)
open(path + ".ready", "w").write("x")
frame = b"\x00" + reply.encode() + b"\n\x00"
while True:
    try:
        c, _ = srv.accept()
    except Exception:
        break
    try:
        c.recv(4096); c.sendall(frame)
    except Exception:
        pass
    c.close()
PY

start_terse() {
    rm -f "$SOCKETLEY_SOCKET" "$SOCKETLEY_SOCKET.ready"
    python3 "$TERSE_PY" "$SOCKETLEY_SOCKET" "$1" &
    IMP_PID=$!
    local i
    for i in $(seq 1 100); do [ -f "$SOCKETLEY_SOCKET.ready" ] && return 0; sleep 0.05; done
    echo "  FATAL: the stand-in never bound $SOCKETLEY_SOCKET"; exit 2
}
stop_terse() {
    kill "$IMP_PID" 2>/dev/null || true
    wait "$IMP_PID" 2>/dev/null || true
    IMP_PID=""
    rm -f "$SOCKETLEY_SOCKET" "$SOCKETLEY_SOCKET.ready"
}

VER=$("$BIN" version 2>/dev/null)

start_terse "socketley-daemon $VER 424242"
ERR=$("$BIN" version 2>&1 >/dev/null || true)
if [ -z "$ERR" ]; then ok; else
    bad "a daemon that reports no executable is not accused of being a different build" \
        "it answered with a version and a pid and stopped there, which is what a" \
        "daemon built before this change does.  stderr was:" \
        "  $ERR"
fi
stop_terse

# The control, without which "the terse daemon is not accused" is also green on
# a build where `version` never probes the socket at all.
start_terse "socketley-daemon 0.0.1 424242"
ERR=$("$BIN" version 2>&1 >/dev/null || true)
if has "$ERR" "0.0.1"; then ok; else
    bad "a daemon reporting a different version is still reported" \
        "the terse-daemon assertion above is only worth something if this path" \
        "reaches the reporting code at all.  stderr was:" \
        "  ${ERR:-<empty>}"
fi
stop_terse

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
