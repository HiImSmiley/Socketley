#!/usr/bin/env bash
# Integration test: TTL expiry semantics.
#
# Covers two classes of bug that unit tests cannot reach, because both depend on
# a live runtime rather than on cache_store in isolation:
#
#   1. Lazy expiry on commands that overwrite or remove a key.  DEL and GETSET
#      succeed on an already-expired key, so unlike SET/LPUSH/SADD they cannot
#      discover staleness by failing — they have to check up front, or DEL
#      reports a key it should have reported as absent and GETSET hands back a
#      value that should already be gone.
#
#   2. TTLs restored from a persistence file.  The runtime keeps a flag telling
#      it whether any key carries an expiry, and that flag gates both the
#      periodic sweep and every lazy check.  If loading a store does not seed
#      the flag, keys restored with a TTL never expire at all.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
daemon_isolate cachettl
PORT=19280
STORE="/tmp/test-cache-ttl-$$.bin"
PASS=0; FAIL=0; TOTAL=0


cleanup() {
    "$BIN" stop ttlcache 2>/dev/null || true
    sleep 0.5
    "$BIN" remove ttlcache 2>/dev/null || true
    # Must not be the last command without a guard: under run_all.sh a daemon is
    # already running, so the one started below exits immediately and this kill
    # fails.  An EXIT trap ending on a non-zero status makes the whole script
    # report failure even though every assertion passed.
    rm -f "$STORE"
    daemon_stop
}
trap cleanup EXIT

assert_eq() {
    TOTAL=$((TOTAL+1))
    local got="$1" expected="$2" label="$3"
    if [ "$got" = "$expected" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$label]: got '$got', expected '$expected'"
    fi
}

send_cmd() {
    echo "$1" | nc -q 1 127.0.0.1 "$PORT" 2>/dev/null | tr -d '\r'
}

echo "=== Integration: cache TTL expiry ==="

# stdout must be redirected as well, not just stderr: a backgrounded daemon
# inherits the script's stdout, and if that is a pipe the reader never sees EOF
# while the daemon lives — the caller hangs instead of getting the results.
daemon_start "$BIN"

create_ok "cache created" "$BIN" create cache ttlcache -p "$PORT" --persistent "$STORE"
"$BIN" start ttlcache 2>&1 || true
sleep 0.5

# ─── Lazy expiry on destructive commands (text protocol) ───

assert_eq "$(send_cmd 'setex dk 1 v')" "ok" "SETEX dk"
assert_eq "$(send_cmd 'setex gk 1 v')" "ok" "SETEX gk"
assert_eq "$(send_cmd 'setex ek 1 v')" "ok" "SETEX ek"
sleep 2

# DEL on an expired key must report a miss, not a successful delete.
assert_eq "$(send_cmd 'del dk')" "nil" "DEL on expired key"
# GETSET must not hand back the stale value as the previous one.
assert_eq "$(send_cmd 'getset gk newval')" "nil" "GETSET on expired key"
# Guard for the paths that already checked, so a future refactor cannot
# silently drop them too.
assert_eq "$(send_cmd 'exists ek')" "0" "EXISTS on expired key"
assert_eq "$(send_cmd 'get ek')" "nil" "GET on expired key"

# ─── Same semantics over RESP ───

if command -v redis-cli >/dev/null 2>&1; then
    rcli() { redis-cli -p "$PORT" "$@" 2>/dev/null; }
    rcli SETEX rdk 1 v >/dev/null
    rcli SETEX rgk 1 v >/dev/null
    sleep 2
    assert_eq "$(rcli DEL rdk)"           "0" "RESP DEL on expired key"
    assert_eq "$(rcli GETSET rgk newval)" ""  "RESP GETSET on expired key"
else
    echo "  SKIP: redis-cli not installed, RESP cases not covered"
fi

# ─── TTLs restored from persistence are still enforced ───
#
# This is where the flag actually bites.  In normal operation the 100 ms sweep
# removes expired keys long before anyone asks about them, which hides a missing
# lazy check almost perfectly.  After a restart the flag is what decides whether
# that sweep runs at all — so a store reloaded from disk with the flag cleared
# leaves both the sweep and every gated lazy check disabled at once.
#
# Ordering matters here.  GET goes through check_expiry_and_get_ptr(), which is
# NOT gated by the flag, and it deletes the expired key as a side effect.  A GET
# anywhere before the assertions below would clean up the very state under test
# and the whole section would pass regardless.  Nothing may touch these keys
# through an ungated path until they have been checked.

# The TTL has to outlive everything between here and the assertions, because
# load() drops keys that already expired while the runtime was down — a key
# gone for that reason would satisfy the checks below without proving anything.
# send_cmd costs about a second each (nc -q 1), plus two for the stop/start, so
# 10 s leaves a comfortable margin over the ~5 s spent getting there.
assert_eq "$(send_cmd 'setex pa 10 va')" "ok" "SETEX pa before restart"
assert_eq "$(send_cmd 'setex pb 10 vb')" "ok" "SETEX pb before restart"
assert_eq "$(send_cmd 'setex pc 10 vc')" "ok" "SETEX pc before restart"

"$BIN" stop ttlcache 2>&1 || true    # teardown saves the store
sleep 1
"$BIN" start ttlcache 2>&1 || true   # setup reloads it
sleep 8                              # now past the 10 s TTL

# EXISTS is gated by the flag and has no cleanup side effect.
assert_eq "$(send_cmd 'exists pa')" "0" "EXISTS on TTL key restored from disk"
# TTL is gated too: an expired key must report -2 (no such key).
assert_eq "$(send_cmd 'ttl pb')" "-2" "TTL on TTL key restored from disk"
# DEL cannot detect staleness by failing, so it needs the up-front check.
assert_eq "$(send_cmd 'del pc')" "nil" "DEL on TTL key restored from disk"

# ─── The periodic sweep actually runs ───
#
# Everything above would still pass if expiry only ever happened lazily, on
# access.  The sweep is what reclaims keys nobody asks for again, and it is only
# armed while keys with a TTL exist — so a runtime that forgets to arm it leaks
# those keys until something touches them.
#
# keys_expired comes from the sweep alone and is read through the stats command,
# which never goes near the key, so this assertion cannot be satisfied by a lazy
# check standing in for the timer.
# `|| true` on the pipeline, and it is the grep that needs it more than the
# stats: `grep -oP` exits 1 when the field is simply not there, which is the
# normal answer for a runtime a refused create never built.  Both readings below
# are written `BEFORE=$(expired_count)` / `AFTER=$(expired_count)` — simple
# commands whose status is this pipeline's — so under `set -euo pipefail` the
# file ended at the first of them with no `Results` line.  Empty is a fine
# answer to hand back: the assertion prints "keys_expired went unset -> unset",
# which names the problem, and it cannot print anything if the file is gone.
expired_count() {
    "$BIN" stats ttlcache 2>&1 | grep -oP 'keys_expired:\K[0-9]+' | head -1 || true
}

BEFORE=$(expired_count)
assert_eq "$(send_cmd 'setex sweepkey 1 sv')" "ok" "SETEX sweepkey"
sleep 3
AFTER=$(expired_count)

# The delta is what matters, not the absolute value: earlier steps in this file
# leave unrelated keys behind (GETSET recreates its key without a TTL), so the
# store is legitimately non-empty here and asserting on the total key count
# would only measure the rest of the test.
TOTAL=$((TOTAL+1))
if [ "${AFTER:-0}" -gt "${BEFORE:-0}" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [sweep ran]: keys_expired went ${BEFORE:-unset} -> ${AFTER:-unset}, expected an increase"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
