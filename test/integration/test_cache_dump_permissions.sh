#!/usr/bin/env bash
# Integration test: a cache's --persistent dump is not readable by the machine.
#
# ─── WHAT THIS IS ABOUT ─────────────────────────────────────────────────────
#
# cache_store::save_v2() created its file with a literal 0644, so every account
# on the machine could read whatever the application had cached.  Measured on
# 1df25e8, one SET and a second uid:
#
#     SET session_token abc-super-secret
#     uid nobody: strings c1.rdb  ->  session_token
#                                     abc-super-secret
#
# And this is not only disclosure.  cache_instance::start() calls
# cache_store::load() on the same path, so the dump is not a record of what the
# cache held — it is what the cache will hold on its next start.  0644 does not
# let another user rewrite the file, but replacing it needs write permission on
# the DIRECTORY rather than the file, and the directory is whatever the
# operator passed to --persistent.  The mode is what this build controls.
#
# Companion to test_state_file_permissions.sh: same invariant, different writer.
# The runtime records were the first half of it and had two write paths; this
# one has exactly one — save() delegates to save_v2() and nothing else opens the
# dump for writing — which is why this file is shorter and says so.
#
# ─── THE CONTROL ────────────────────────────────────────────────────────────
#
# A cache that lost its data would pass "nobody can read it" too.  The last
# assertion reads the value back through the cache after the tightening.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate cachedump

PORT=$((SL_PORT_BASE + 1205))
VAL="abc-super-secret-$$"

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    "$BIN" stop   cd_cache >/dev/null 2>&1 || true
    "$BIN" remove cd_cache >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a cache dump is not the machine's to read ==="

# The dump lives beside the socket, in a directory opened on purpose: the mode
# on the FILE is the subject, and a mktemp 0700 above it would pass this test
# against the 0644 build for a reason that has nothing to do with the file.
chmod 0711 "$SOCKETLEY_TMPD" 2>/dev/null || true
DUMP="$SOCKETLEY_TMPD/cd.rdb"

daemon_start "$BIN"

"$BIN" create cache cd_cache -p "$PORT" --persistent "$DUMP" -s >/dev/null 2>&1
for _ in $(seq 1 40); do "$BIN" ls 2>/dev/null | grep -qa cd_cache && break; sleep 0.1; done
sleep 0.5
printf 'SET session_token %s\r\n' "$VAL" | timeout 5 nc -q1 127.0.0.1 "$PORT" >/dev/null 2>&1
sleep 0.3

# The dump is written on stop.
"$BIN" stop cd_cache >/dev/null 2>&1 || true
for _ in $(seq 1 50); do [ -f "$DUMP" ] && break; sleep 0.1; done
sleep 0.5

# ── 1. the mode the cache wrote it with ─────────────────────────────────────
MODE=$(stat -c '%a' "$DUMP" 2>/dev/null || echo "?")
if [ "$MODE" = "600" ]; then pass; else
    fail "the dump is written 0600" \
         "got mode $MODE on $DUMP" \
         "0644 was a literal in save_v2; a cache holds whatever the" \
         "application put in it, and start() loads this file back"
fi

# ── 2. a second uid, if this machine has one to lend ────────────────────────
if sudo -n true 2>/dev/null && id -u nobody >/dev/null 2>&1; then
    OUT=$(sudo -n -u nobody sh -c "cat '$DUMP'" 2>&1 | strings 2>/dev/null || true)
    case "$OUT" in
        *"$VAL"*)
            fail "another uid cannot read what was cached" \
                 "uid nobody read the dump and it contains the cached value" \
                 "the dump is loaded back by cache_instance::start(), so it is" \
                 "what the cache will hold, not merely what it held" ;;
        *)
            pass ;;
    esac
else
    echo "  NOTE: no passwordless sudo / nobody here — the second-uid half is"
    echo "        skipped.  Assertion 1 holds on its own: 0600 admits one uid."
fi

# ── 3. the upgrade path ─────────────────────────────────────────────────────
#
# A dump an older version left.  It is not replaced until the next save, which
# for a cache that is running and never stopped is never — so the repair has to
# happen where the daemon opens it, which is the load.
chmod 644 "$DUMP"
: > "$SOCKETLEY_DLOG"
"$BIN" start cd_cache >/dev/null 2>&1 || true
sleep 1.0

U_MODE=$(stat -c '%a' "$DUMP" 2>/dev/null || echo "?")
if [ "$U_MODE" = "600" ]; then pass; else
    fail "a dump an older version left is narrowed when it is loaded" \
         "got mode $U_MODE after the cache started" \
         "saving at 0600 does nothing for a dump that is already on disk"
fi

if grep -qa "cache: tightened" "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    fail "the repair says what it did" \
         "no 'cache: tightened' line in this daemon's log" \
         "an operator whose cached data was readable until this start has no" \
         "other way to find that out"
fi

# ── 4. control: the cache still has its data ────────────────────────────────
GOT=$(printf 'GET session_token\r\n' | timeout 5 nc -q1 127.0.0.1 "$PORT" 2>/dev/null | tr -d '\r\n' || true)
case "$GOT" in
    *"$VAL"*) pass ;;
    *) fail "control: the value survived the tightening and the reload" \
            "GET session_token returned '$GOT', wanted '$VAL'" \
            "protecting the dump must not mean losing it: the cache has to come" \
            "back with what it was persisted holding" ;;
esac

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
