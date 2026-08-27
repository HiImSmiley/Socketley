#!/usr/bin/env bash
# Integration test: a runtime's record is not readable by the rest of the machine.
#
# ─── WHAT THIS IS ABOUT ─────────────────────────────────────────────────────
#
# Both writers in state_persistence.cpp used std::ofstream, which creates with
# 0666 & ~umask.  That is not a mode, it is whatever the daemon inherited — and
# the file it applies to is the runtime's whole record: --master-pw verbatim,
# the paths of the TLS and mTLS private keys, the --lua script the daemon runs
# with its own privileges.
#
# Measured on the parent commit, packaged shape — daemon as `socketley`,
# /var/lib/socketley/runtimes at 0755 as packaging/install.sh created it:
#
#     daemon's umask 002   file 0664   uid nobody read  "master_pw": "s3cr3t..."
#     daemon's umask 0     file 0666   uid nobody REWROTE the record
#
# The second line is why this is not merely disclosure.  The daemon restores
# every runtime from these files at startup, so a writable record is a way to
# choose what the daemon runs — the same escalation the IPC socket's 0666 was,
# closed in 8e4cff7, arriving through the filesystem instead.
#
# ─── WHAT IS PINNED, AND WHY EACH ONE ───────────────────────────────────────
#
#   1. The mode of a file the daemon just wrote.  0600.
#   2. The same file after a start and a stop.  set_was_running rewrites the
#      whole record on every transition through a second writer; a fix that
#      covered only write_json would pass assertion 1 and undo itself here.
#   3. The daemon is started with `umask 0` on purpose.  If the mode came from
#      the umask again this is the assertion that says so, and it is the one
#      the 0666 case above needs.
#   4. A second uid cannot read the password out of it.  Skipped, loudly, where
#      the machine has no second account to lend.
#   5. The upgrade path: files an older version already wrote at 0644 are
#      narrowed at startup, and the runtime still loads afterwards.
#
# ─── THE CONTROL ────────────────────────────────────────────────────────────
#
# "The password cannot be read" is also true of a daemon that stopped storing
# it, and that would be a broken daemon rather than a fixed one.  So the last
# assertion reads the record back as its owner and requires the password to
# still be in it, with the right value, after a restart.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate stateperm

PORT=$((SL_PORT_BASE + 1200))
PW="pin-me-$$"

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    "$BIN" stop   sp_srv >/dev/null 2>&1 || true
    "$BIN" remove sp_srv sp_legacy >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a runtime's record is not the machine's to read ==="

# The daemon is started under the worst umask there is.  The whole point is
# that the mode must not come from it.
#
# In this shell rather than in a `( umask 0; daemon_start )` subshell.  The
# subshell form was written first and is wrong twice: daemon_start's bookkeeping
# — the pid it records, the binary it remembers — would be set inside it and
# lost, and the daemon it backgrounds becomes a job of a shell that is about to
# exit, which killed it about half the time.  A test that fails half the time is
# not a stricter test.
OLD_UMASK=$(umask)
umask 0
daemon_start "$BIN"
umask "$OLD_UMASK"

# Which directory this daemon chose, from the daemon itself rather than from a
# copy of paths.cpp's keying rule living in a test.
STATE_DIR=$(grep -a "state directory: " "$SOCKETLEY_DLOG" | tail -1 | sed 's/.*state directory: //')
if [ -z "$STATE_DIR" ] || [ ! -d "$STATE_DIR" ]; then
    echo "  FATAL: the daemon did not say which state directory it is using;"
    echo "         nothing below would be measuring this build."
    exit 2
fi

# Everything above the file is opened on purpose.  daemon_isolate works in a
# mktemp 0700, so a second uid cannot reach the path at all — and a test that
# stopped there would pass against the 0644 build for a reason that has nothing
# to do with the file.  The deployed shape is a 0755 state directory, which is
# what this reproduces.
chmod 0711 "$SOCKETLEY_TMPD" "$SOCKETLEY_TMPD/home" 2>/dev/null || true
chmod -R o+rX "$SOCKETLEY_TMPD/home/.local" 2>/dev/null || true
chmod 0755 "$STATE_DIR" 2>/dev/null || true

REC="$STATE_DIR/sp_srv.json"

"$BIN" create server sp_srv -p "$PORT" --mode master --master-pw "$PW" >/dev/null 2>&1
for _ in $(seq 1 40); do [ -f "$REC" ] && break; sleep 0.1; done

# ── 1. the mode it was created with ─────────────────────────────────────────
MODE=$(stat -c '%a' "$REC" 2>/dev/null || echo "?")
if [ "$MODE" = "600" ]; then pass; else
    fail "the record is created 0600" \
         "got mode $MODE on $REC" \
         "the daemon was started with umask 0; 0666 is what the parent commit" \
         "wrote there, and uid nobody could rewrite it"
fi

# ── 2. and after a start and a stop ─────────────────────────────────────────
#
# Separate because it is a separate writer.  set_was_running rewrites the whole
# record — password included — through its own path.
"$BIN" start sp_srv >/dev/null 2>&1 || true
sleep 0.8
MODE_START=$(stat -c '%a' "$REC" 2>/dev/null || echo "?")
"$BIN" stop sp_srv >/dev/null 2>&1 || true
sleep 0.8
MODE_STOP=$(stat -c '%a' "$REC" 2>/dev/null || echo "?")
if [ "$MODE_START" = "600" ] && [ "$MODE_STOP" = "600" ]; then pass; else
    fail "the record stays 0600 across start and stop" \
         "after start: $MODE_START, after stop: $MODE_STOP" \
         "set_was_running rewrites the whole record on every transition; a fix" \
         "that covered only write_json passes the assertion above and fails here"
fi

# ── 3. a second uid, if this machine has one to lend ────────────────────────
SECOND_UID=0
if sudo -n true 2>/dev/null && id -u nobody >/dev/null 2>&1; then SECOND_UID=1; fi

if [ "$SECOND_UID" = "1" ]; then
    OUT=$(sudo -n -u nobody sh -c "cat '$REC'" 2>&1 || true)
    case "$OUT" in
        *"$PW"*)
            fail "another uid cannot read the password out of the record" \
                 "uid nobody read the file and it contains the master password" \
                 "the record also carries key_path and lua_script; the daemon" \
                 "restores runtimes from these files at startup" ;;
        *"ermission denied"*|*"No such file"*)
            pass ;;
        *)
            echo "  NOTE: the second-uid probe could not run (${OUT%%$'\n'*})."
            echo "        Skipped, not passed.  Assertion 1 holds on its own:"
            echo "        0600 admits exactly one uid." ;;
    esac
else
    echo "  NOTE: no passwordless sudo / nobody here — the second-uid half is"
    echo "        skipped.  Assertion 1 holds on its own: 0600 admits one uid."
fi

# ── 4. the upgrade path ─────────────────────────────────────────────────────
#
# A record an older version wrote, at the mode an older version wrote it.  The
# .tmp beside it is a write a killed daemon never finished — same record, same
# password, and nothing else ever cleans it up.
cat > "$STATE_DIR/sp_legacy.json" <<J
{
    "name": "sp_legacy",
    "id": "5be9a1",
    "type": "server",
    "port": $((PORT + 1)),
    "was_running": false,
    "mode": "master",
    "master_pw": "$PW"
}
J
cp "$STATE_DIR/sp_legacy.json" "$STATE_DIR/sp_leftover.json.tmp"
chmod 644 "$STATE_DIR/sp_legacy.json" "$STATE_DIR/sp_leftover.json.tmp"

# ── and a symlink, which the repair must not follow ─────────────────────────
#
# The repair walks this directory and changes the mode of what it finds.  Done
# through the path — stat() then chmod(), which is how it was first written —
# a name here pointing anywhere else is a mode change of whatever it points at,
# and the daemon runs as root under `sudo socketley daemon`.
#
# It is not reachable while the packaged directory is 0750, because nobody else
# can create a name in it.  That is the reason to pin it rather than to leave
# it: the file layer would be resting on the directory mode, and a later
# loosening of that mode — or a state directory somewhere else — moves the
# whole risk back here with nothing watching.
#
# The target is deliberately outside the state directory and deliberately not
# valid runtime JSON, so the only thing that could change its mode is the
# repair following the link.
SYM_TARGET="$SOCKETLEY_TMPD/not-a-runtime.txt"
echo "this file is not socketley's" > "$SYM_TARGET"
chmod 644 "$SYM_TARGET"
ln -sf "$SYM_TARGET" "$STATE_DIR/sp_link.json"

# The daemon goes down and comes back on the same state directory, which is
# what an upgrade is.  daemon_stop is not used here: it deletes the directory.
kill "$SOCKETLEY_DPID" 2>/dev/null || true
for _ in $(seq 1 50); do kill -0 "$SOCKETLEY_DPID" 2>/dev/null || break; sleep 0.1; done

# The log is emptied first, and that is load-bearing rather than tidiness.
# daemon_start waits by grepping this file for "daemon started", and the line
# the FIRST daemon wrote is still in it — so without this the wait returns
# immediately, the assertions below race a daemon that has not bound yet, and
# the file fails about half the time it is run.  Measured: 3 FATALs in 6 runs
# before this line existed, 0 in 12 after.
: > "$SOCKETLEY_DLOG"
daemon_start "$BIN"

L_MODE=$(stat -c '%a' "$STATE_DIR/sp_legacy.json" 2>/dev/null || echo "?")
T_MODE=$(stat -c '%a' "$STATE_DIR/sp_leftover.json.tmp" 2>/dev/null || echo "?")
if [ "$L_MODE" = "600" ] && [ "$T_MODE" = "600" ]; then pass; else
    fail "files an older version left are narrowed at startup" \
         "sp_legacy.json: $L_MODE, sp_leftover.json.tmp: $T_MODE" \
         "writing new files at 0600 does nothing for an install that already" \
         "has a directory of 0644 ones, and those are the ones with passwords"
fi

# ── the symlink was not followed ────────────────────────────────────────────
#
# Two things, because either alone is weak.  The target's mode is what a
# followed link would have changed; the link still being a link is what says
# the daemon did not replace it with a regular file on the way past.
S_MODE=$(stat -c '%a' "$SYM_TARGET" 2>/dev/null || echo "?")
if [ "$S_MODE" = "644" ] && [ -L "$STATE_DIR/sp_link.json" ]; then pass; else
    fail "a symlink in the state directory is not followed" \
         "target mode $S_MODE (wanted 644), link is $([ -L "$STATE_DIR/sp_link.json" ] && echo 'still a link' || echo 'NO LONGER A LINK')" \
         "the repair changes the mode of what it finds; through the path that" \
         "is the mode of whatever the link points at, and the daemon can be root"
fi

# And that the daemon said the symlink was there, rather than passing it over
# in silence — socketley does not create these, so its presence is news.
if grep -qa "symlink(s) in" "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    fail "the daemon reports the symlink it declined to follow" \
         "no 'symlink(s) in ...' line in this daemon's log" \
         "a name socketley did not create, in the directory it repairs, is" \
         "worth one line to whoever has to explain it later"
fi

# And that the repair is what did it, rather than the modes having arrived at
# 0600 by some other route.  The log was emptied above, so this line can only
# have come from the daemon that just started.
if grep -qa "state: tightened 2 file(s)" "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    fail "the repair says what it did" \
         "no 'state: tightened 2 file(s)' line in this daemon's log" \
         "an operator whose files were readable by the machine until this" \
         "startup has no other way to find that out"
fi

# ── 5. control: the record still says what it is for ────────────────────────
#
# Read as its owner, which the daemon's user always could.  Without this, a
# daemon that had simply stopped persisting master_pw would pass every
# assertion above — and would be a broken daemon, not a fixed one.
if grep -qF "\"master_pw\": \"$PW\"" "$STATE_DIR/sp_srv.json" 2>/dev/null &&
   "$BIN" ls 2>/dev/null | grep -qa sp_legacy
then pass; else
    fail "control: the record still carries the password, and still loads" \
         "master_pw is missing from sp_srv.json, or sp_legacy did not restore" \
         "protecting the file must not mean dropping what is in it: the runtime" \
         "has to come back after a restart with the password it was given"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
