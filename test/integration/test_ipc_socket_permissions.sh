#!/usr/bin/env bash
# Integration test: the daemon's control socket is not open to the machine.
#
# ─── WHAT THIS IS ABOUT ─────────────────────────────────────────────────────
#
# daemon_handler::setup() used to finish its bind with
#
#     // Allow all users to connect
#     chmod(socket_path, 0666);
#
# and that is what it did.  Everything the CLI can ask for arrives on this
# socket, so "may connect" is "may administer": stop a runtime, read stats,
# rewrite a configuration with edit — and, because `create --lua` takes a script
# and a handler runs with the daemon's privileges (which is a property of the
# design, stated as such in lua_context.cpp and in the man page, not a defect
# to be patched in the interpreter), run code as whoever the daemon is.
#
# Measured on the parent commit, dev mode, daemon started by uid 1000:
#
#     socket                                  srw-rw-rw-  (0666)
#     uid nobody: connect + "ping"            answered
#     uid nobody: create --lua + start        both accepted
#     the handler's io.popen("id -un") wrote  the daemon's user, not nobody
#     the file it created was owned by        the daemon's user
#
# One local user, no privileges of their own, running commands as another.
#
# ─── THE RULE THIS PINS ─────────────────────────────────────────────────────
#
#     /run/socketley/socketley.sock   0660  socketley:socketley
#     any other path                  0600  the user who started the daemon
#
# Only the second line is reachable from here: the first needs root, a /run
# this suite must not write to, and a second account.  What that half rests on
# is checked by hand and written down in daemon_handler::setup().
#
# ─── WHY THE DIRECTORY IS OPENED ON PURPOSE ─────────────────────────────────
#
# daemon_isolate puts the socket inside a mktemp -d, which is 0700, so a second
# uid cannot reach the path at all — and a test that stopped there would pass
# against the 0666 build, for a reason that has nothing to do with the socket.
# The directory is widened to 0711 (traverse, do not list) so that the socket's
# own mode is the only thing left standing between another uid and the daemon.
# That is also the honest shape of the deployed case: /run/socketley is 0755.
#
# ─── THE CONTROL ────────────────────────────────────────────────────────────
#
# Closing this by making the daemon unreachable would be no fix at all, so the
# last assertion is that the user who started it still drives it with no
# ceremony whatsoever.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"

daemon_isolate ipcperm

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    "$BIN" stop   ipcperm_probe >/dev/null 2>&1 || true
    "$BIN" remove ipcperm_probe >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: the IPC socket is not open to every local user ==="

# The socket's own mode is the subject; the directory must not be the thing
# doing the work.  See the note above.
chmod 0711 "$SOCKETLEY_TMPD"

daemon_start "$BIN"

# ── 1. The mode the daemon created it with ──────────────────────────────────
#
# Checkable with no second account anywhere, and it is the whole rule for this
# path: 0600 is "the owner and nobody else" whether or not this machine has
# somebody else to prove it with.
MODE=$(stat -c '%a' "$SOCKETLEY_SOCKET" 2>/dev/null || echo "?")
if [ "$MODE" = "600" ]; then pass; else
    fail "the socket is 0600" \
         "got mode $MODE on $SOCKETLEY_SOCKET" \
         "0666 was the parent commit: every local uid could send this daemon" \
         "any command, including create --lua, which runs as the daemon's user"
fi

# ── 2. A second uid, if this machine has one to lend ────────────────────────
#
# sudo without a password and a python3 to connect with.  Where either is
# missing the half is skipped and said out loud, rather than passing quietly:
# a skipped assertion that looks like a passing one is how a suite reports
# green for something it never ran.
SECOND_UID=0
if command -v python3 >/dev/null 2>&1 && sudo -n true 2>/dev/null &&
   id -u nobody >/dev/null 2>&1; then
    SECOND_UID=1
fi

if [ "$SECOND_UID" = "1" ]; then
    OUT=$(sudo -n -u nobody python3 - "$SOCKETLEY_SOCKET" <<'PY' 2>&1 || true
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect(sys.argv[1])
except OSError as e:
    print("REFUSED %s" % e.errno)
    raise SystemExit(0)
s.sendall(b"ping\n")
print("ACCEPTED %r" % s.recv(200)[:120])
PY
)
    # Three outcomes, not two.  Only ACCEPTED is a failure of this build; a
    # sudoers that permits `sudo -n true` but not `-u nobody` produces neither
    # word, and counting that as a failed assertion would be this file
    # reporting on the machine's sudo policy instead of on the socket.
    case "$OUT" in
        ACCEPTED*)
            fail "another uid cannot open the socket" \
                 "uid nobody got: $OUT" \
                 "connecting is administering: stop, edit, stats, and create --lua," \
                 "whose handler runs with THIS daemon's privileges" ;;
        REFUSED*)
            pass ;;
        *)
            echo "  NOTE: the second-uid probe could not run (${OUT%%$'\n'*})."
            echo "        Skipped, not passed.  The mode assertion above holds"
            echo "        on its own: 0600 admits exactly one uid." ;;
    esac
else
    echo "  NOTE: no passwordless sudo / python3 / nobody here — the"
    echo "        second-uid half is skipped.  The mode assertion above holds"
    echo "        on its own: 0600 admits exactly one uid."
fi

# ── 3. Control: the owner still drives their own daemon, unchanged ──────────
#
# The whole point.  A socket nobody can open is not a fix, it is an outage.
#
# The port is 24610 rather than the 230xx this directory otherwise uses: it was
# picked out of a block reserved for the work that added this file, so that it
# cannot collide with a test landing from another branch at the same time.
if "$BIN" create server ipcperm_probe -p "${PB:-24610}" >/dev/null 2>&1 &&
   "$BIN" ls 2>/dev/null | grep -qa ipcperm_probe
then pass; else
    fail "control: the owning user still drives the daemon" \
         "create+ls did not work for the uid that started the daemon" \
         "tightening the socket must cost the ordinary case nothing"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
