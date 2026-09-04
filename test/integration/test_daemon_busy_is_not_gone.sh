#!/usr/bin/env bash
# Integration test: a daemon that is busy is not reported as a daemon that is
# gone.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
# ipc_send() puts a five-second SO_RCVTIMEO on the daemon's answer and returned
# -1 for the deadline expiring and for a socket nothing answers alike.  Eighteen
# call sites read that -1 and printed "failed to connect to daemon" -- for a
# daemon that had accepted the connection, taken the command, and was working on
# it.  The one thing that was certainly untrue.
#
# It is not a hypothetical deadline.  Every command that waits on a worker is a
# ::poll inside a command handler, so the daemon answers nothing at all while it
# waits, and `reload-lua` used to multiply that wait by however many runtimes
# its pattern named -- 5.25s at three runtimes on 04ceac98, measured, and this
# is the sentence the operator got for it.
#
# ─── WHY `daemon stop` PUTS THE QUESTION ───────────────────────────────────
#
# Because it is the one verb that reaches ipc_send with no identity probe in
# front of it.  Every other command goes through daemon_probe() first, which
# answers `mute` for a silent socket and prints its own sentence, so the read
# deadline is never reached.  A socket that accepts and stays quiet therefore
# asks exactly this question, and asks it in two seconds of setup rather than by
# arranging a daemon slow enough to be a nuisance.
#
# `daemon stop` cannot succeed against that socket either way.  What is being
# read is WHICH failure it names.
#
# The second assertion is the one that keeps the first honest: a path with
# nothing on it must still read as absent.  Trading "failed to connect" for
# "busy" everywhere would be one wrong sentence for another.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: a busy daemon is not a missing one ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

daemon_isolate daemonbusy
trap 'kill ${LPID:-0} 2>/dev/null; daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

secs() { python3 -c "print(f'{$2 - $1:.2f}')"; }

# A socket that accepts and never answers.  It holds the accepted connections
# rather than closing them, because a close is a different failure -- an EOF
# arrives at once and never reaches the deadline this file is about.
QUIET="$SOCKETLEY_TMPD/quiet.sock"
python3 -c "
import socket, time
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind('$QUIET'); s.listen(4); s.settimeout(1.0)
held = []
end = time.time() + 30
while time.time() < end:
    try: held.append(s.accept()[0])
    except socket.timeout: pass
" >/dev/null 2>&1 &
LPID=$!
for _ in $(seq 1 60); do [ -S "$QUIET" ] && break; sleep 0.1; done

if [ -S "$QUIET" ]; then
    ok "the silent listener is on its socket"
else
    bad "the instrument is up" "no socket at $QUIET; nothing below can be asked"
fi

S=$(date +%s.%N)
QOUT=$(SOCKETLEY_SOCKET="$QUIET" "$BIN" daemon stop 2>&1); QRC=$?
E=$(date +%s.%N)
QSECS=$(secs "$S" "$E")
kill "$LPID" 2>/dev/null; LPID=""

# The deadline has to be the thing that ended it, or the sentence below is
# about some other failure.
if python3 -c "import sys; sys.exit(0 if 4.0 < $QSECS < 12.0 else 1)"; then
    ok "the command spent its read deadline waiting (${QSECS}s)"
else
    bad "the five-second read deadline is what ended the command" \
        "it returned after ${QSECS}s, which is neither the deadline nor close to it"
fi

if [ "$QRC" -ne 0 ] && printf '%s' "$QOUT" | grep -q "has not answered"; then
    ok "and it is named as busy, not as unreachable (rc $QRC)"
else
    bad "the CLI says which of the two failures it hit" \
        "it answered rc $QRC with: ${QOUT:-<nothing>};" \
        "the socket was connected and the command was delivered, so both 'no daemon" \
        "is serving' and 'failed to connect to daemon' are false -- ipc_send returned" \
        "-1 for the read deadline and for an unanswered socket alike, and eighteen" \
        "call sites could not tell them apart"
fi

# The other direction, which is what stops this from being a rename: nothing is
# listening at all, and that must still read as absent.
GOUT=$(SOCKETLEY_SOCKET="$SOCKETLEY_TMPD/nothing.sock" "$BIN" daemon stop 2>&1); GRC=$?
if [ "$GRC" -ne 0 ] && ! printf '%s' "$GOUT" | grep -q "has not answered"; then
    ok "a socket nothing holds still reads as absent (rc $GRC)"
else
    bad "the two failures stay apart" \
        "an absent daemon answered rc $GRC with: ${GOUT:-<nothing>};" \
        "reporting 'busy' for a path with nothing on it trades one wrong sentence" \
        "for another"
fi

# And an ordinary command against the real daemon is untouched by any of it.
if "$BIN" ls >/dev/null 2>&1; then
    ok "and the daemon on this test's own socket still answers"
else
    bad "the reporter did not change the working path" "ls failed against a live daemon"
fi

daemon_stop
trap - EXIT

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
