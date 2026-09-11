#!/usr/bin/env bash
# Integration test: an `edit` that is refused leaves the runtime as it found it.
#
# ─── WHAT IT DID INSTEAD ────────────────────────────────────────────────────
#
# The edit parsers apply as they parse -- each case validates its value and
# calls the setter on the spot -- so a refusal on the fourth flag left the
# first three in the runtime. Measured, on a server created with
# --max-connections 10 --rate-limit 5:
#
#   edit x --max-connections 3 --bogus-flag     -> "unknown flag", exit 1,
#                                                  max_connections now 3
#   edit x --rate-limit 9 --max-connections -1  -> "invalid value",  exit 1,
#                                                  rate_limit now 9
#   edit c --max-connections 3 --maxmemory 100  -> refused,          exit 1,
#                                                  max_connections now 3
#
# The operator is told no. Nothing suggests looking, and a typo is the most
# ordinary way to reach all three.
#
# It is not even a change that survives: save_runtime() sits past every one of
# those returns, so `show` reported the new value and the next daemon start read
# the old one from disk. The runtime and its own state file disagreed until
# something else saved it.
#
# ─── WHY ONE ROLLBACK AND NOT FOUR ──────────────────────────────────────────
#
# Three of the fields were already captured and restored -- the TLS set,
# --shards with --listen, and the server's four -- each in its own block for its
# own refusal, and each silent about every flag applied before it. A fourth
# place needing the same thing is what says it belongs in one, so cmd_edit takes
# one snapshot of everything its parsers can touch and every refusal path calls
# the same restore.
#
# ─── AND THE HALF THAT MUST NOT CHANGE ──────────────────────────────────────
#
# A rollback that fires too eagerly is worse than none: a build that restored on
# SUCCESS too would satisfy every assertion above and quietly do nothing at all.
# So each case is paired with a good edit of the same flags.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate editrollback

P_SRV=$((SL_PORT_BASE+1960))
P_CACHE=$((SL_PORT_BASE+1962))
NAMES="er_srv er_cache"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "expected '$2', got '$3'"; fi; }

cleanup() {
    for n in $NAMES; do "$BIN" stop "$n"   >/dev/null 2>&1 || true; done
    sleep 0.3
    for n in $NAMES; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

# One field out of `show`, without a JSON parser in the assertion.
f() { "$BIN" show "$1" 2>/dev/null | sed -n "s/^ *\"$2\": *\(.*\)$/\1/p" | sed 's/,$//;s/^"//;s/"$//'; }

echo "=== Integration: a refused edit changes nothing ==="
daemon_start "$BIN"

create_ok "a server to edit" "$BIN" create server er_srv -p "$P_SRV" \
    --max-connections 10 --rate-limit 5 --idle-timeout 30
create_ok "and a cache"      "$BIN" create cache er_cache -p "$P_CACHE" \
    --max-connections 10

check "the server starts where its flags put it" "10" "$(f er_srv max_connections)"
check "and its second flag too"                  "5"  "$(f er_srv rate_limit)"

# ─── 1. A flag nobody knows, after one that is fine ─────────────────────────
RC=0; OUT=$("$BIN" edit er_srv --max-connections 3 --bogus-flag 2>&1) || RC=$?
check "an unknown flag is refused"        "1"  "$RC"
check "and the flag before it is undone"  "10" "$(f er_srv max_connections)"
case "$OUT" in *"unknown flag"*) ok ;;
    *) bad "the refusal still names the flag" "got '$OUT'" ;; esac

# ─── 2. A value out of range, after one that is fine ────────────────────────
RC=0; OUT=$("$BIN" edit er_srv --rate-limit 9 --max-connections -1 2>&1) || RC=$?
check "a bad value is refused"                "1"  "$RC"
check "and the flag before it is undone"      "5"  "$(f er_srv rate_limit)"
check "and the bad one changed nothing"       "10" "$(f er_srv max_connections)"

# ─── 3. A flag that belongs to `import`, after one that is fine ─────────────
RC=0; OUT=$("$BIN" edit er_cache --max-connections 3 --maxmemory 100 2>&1) || RC=$?
check "a cache-only flag is refused by edit" "1"  "$RC"
check "and the flag before it is undone"     "10" "$(f er_cache max_connections)"

# ─── 4. A set that comes out incompatible ───────────────────────────────────
# The case the three old blocks existed for, now going through the same
# restore: a legal master server edited to --mode inout keeps its password, so
# the pair has to go back together or the runtime is left in a state no
# `create` could have produced.
"$BIN" edit er_srv --mode master --master-pw secret >/dev/null 2>&1 || true
check "the server is a master now"  "master" "$(f er_srv mode)"
RC=0; OUT=$("$BIN" edit er_srv --mode inout 2>&1) || RC=$?
check "an incompatible set is refused" "1"      "$RC"
check "and the mode is unchanged"      "master" "$(f er_srv mode)"
check "with its password"              "secret" "$(f er_srv master_pw)"

# ─── 5. The half that must still work ───────────────────────────────────────
# Restoring on success would satisfy every assertion above and do nothing at
# all, so the same flags are edited legally and have to take.
OUT=$("$BIN" edit er_srv --no-master-pw 2>&1) || true
OUT=$("$BIN" edit er_srv --mode inout 2>&1) || true
check "a legal mode change still takes" "inout" "$(f er_srv mode)"

OUT=$("$BIN" edit er_srv --max-connections 7 --rate-limit 3 --idle-timeout 44 2>&1) || true
if [ -z "$OUT" ]; then ok; else bad "a good multi-flag edit is accepted" "got '$OUT'"; fi
check "all three took: max_connections" "7"  "$(f er_srv max_connections)"
check "rate_limit"                      "3"  "$(f er_srv rate_limit)"
check "idle_timeout"                    "44" "$(f er_srv idle_timeout)"

# ─── 6. And the state file agrees with `show` ───────────────────────────────
# The other half of the defect: save_runtime() is past the refusals, so a
# partially applied edit left the runtime and its own file disagreeing.
STATE_DIR=$(sed -n 's/.*state directory: \(.*\)$/\1/p' "$SOCKETLEY_DLOG" | tail -1)
RC=0; "$BIN" edit er_srv --max-connections 5 --bogus-flag >/dev/null 2>&1 || RC=$?
check "one more refusal, for the file" "1" "$RC"
# Waited for, not read at once: save_runtime() queues the write on the
# persistence thread, so `show` answers from the instance while the file is
# still catching up -- and reading it immediately measures that lag rather than
# the edit.
WANT=$(f er_srv max_connections)
ON_DISK=""
for _ in $(seq 1 40); do
    ON_DISK=$(sed -n 's/^ *"max_connections": *\([0-9]*\).*$/\1/p' \
              "$STATE_DIR/er_srv.json" 2>/dev/null | head -1)
    [ "$ON_DISK" = "$WANT" ] && break
    sleep 0.1
done
if [ -f "$STATE_DIR/er_srv.json" ]; then
    check "the file says what show says" "$WANT" "${ON_DISK:-<none>}"
else
    bad "the state file is there to compare" "$STATE_DIR/er_srv.json is missing"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
[ "$FAIL" -eq 0 ]
