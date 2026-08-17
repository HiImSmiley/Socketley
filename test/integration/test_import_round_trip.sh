#!/usr/bin/env bash
# Integration test: the show → import round trip the man page documents.
#
# The man page has described this pair as a round trip for as long as the daemon
# has had cmd_import:
#
#     socketley show name > cfg.json
#     # edit cfg.json
#     socketley import name "$(cat cfg.json)"
#
# The daemon half was never broken — interactive `edit` dumps, opens $EDITOR and
# sends the result through the very same IPC command, so it runs every day. What
# was missing was the CLI's dispatch case for the word `import`, so the word fell
# through to cli_runtime_action and was sent as the NAME of a runtime to act on:
#
#     $ socketley import foo '{}'
#     runtime not found: import          (exit 1)
#
# The exit code was right, which is part of why nobody noticed.
#
# ─── WHY THIS TESTS THE WORKFLOW AND NOT THE COMMAND ────────────────────────
#
# A test that called `import` with a hand-written blob would have passed against
# a broken round trip, because a hand-written blob is not what `show` prints:
# `show` pretty-prints, and IPC frames one command per line, so a CLI that
# forwarded its argument verbatim would send the daemon everything up to the
# first newline — `import name {` — and get "invalid JSON" back. The blob test
# stays green; the documented workflow stays broken.
#
# So every assertion below starts from real `show` output and ends by comparing
# `show` output. Two halves, and both are needed:
#
#   * identity — feed the document straight back and the runtime is unchanged.
#     Catches an import that drops or mangles fields.
#   * change   — alter exactly one field and it takes, with nothing else moving.
#     Catches an import that parses the document and applies none of it, which
#     the identity half alone would call a pass.
#
# Run against two runtime types, because their documents do not have the same
# shape: a server's carries mode and the connection limits, a cache's carries
# persistent_path, cache_mode, max_memory and eviction.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate importrt
SVR_PORT=$((SL_PORT_BASE+820))
CACHE_PORT=$((SL_PORT_BASE+821))
PARTIAL_PORT=$((SL_PORT_BASE+822))
BS_PORT=$((SL_PORT_BASE+823))
PASS=0; FAIL=0; TOTAL=0
WORK="/tmp/test-import-$$"

cleanup() {
    "$BIN" remove rt_svr 2>/dev/null || true
    "$BIN" remove rt_cache 2>/dev/null || true
    "$BIN" remove rt_partial 2>/dev/null || true
    "$BIN" remove rt_bs 2>/dev/null || true
    rm -rf "$WORK"
    daemon_stop
}
trap cleanup EXIT

ok()   { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad()  { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL: $1"; }

# assert_same LABEL FILE_A FILE_B — two config documents are byte-identical
assert_same() {
    local label=$1 a=$2 b=$3
    if diff -u "$a" "$b" >"$WORK/diff.txt" 2>&1; then
        ok
    else
        bad "$label"
        sed 's/^/    /' "$WORK/diff.txt"
    fi
}

# assert_rc LABEL EXPECTED ACTUAL
assert_rc() {
    local label=$1 want=$2 got=$3
    if [ "$got" = "$want" ]; then ok; else bad "$label (exit $got, expected $want)"; fi
}

# assert_contains LABEL HAYSTACK NEEDLE
assert_contains() {
    local label=$1 hay=$2 needle=$3
    if grep -qF "$needle" <<<"$hay"; then
        ok
    else
        bad "$label: expected '$needle' in: $hay"
    fi
}

echo "=== Integration: show/import round trip ==="

mkdir -p "$WORK"
daemon_start "$BIN"

# ── SERVER ───────────────────────────────────────────────────────────────────
# Non-default settings throughout, so an import that quietly resets a field to
# its default is a visible difference rather than a coincidence.
"$BIN" create server rt_svr -p "$SVR_PORT" \
    --max-connections 7 --rate-limit 3 --global-rate-limit 11 \
    --idle-timeout 42 -g rtgroup --mode in >/dev/null 2>&1

"$BIN" show rt_svr > "$WORK/svr.json"

# The document really is multi-line — the property that made the naive forward
# truncate it. If `show` ever starts emitting one line, the rest of this file
# stops testing what it says it tests.
if [ "$(wc -l < "$WORK/svr.json")" -gt 1 ]; then ok; else bad "show output is not multi-line"; fi

# 1. Documented form: the whole document as one quoted argument.
RC=0; "$BIN" import rt_svr "$(cat "$WORK/svr.json")" >/dev/null 2>&1 || RC=$?
assert_rc "server import (argument form)" 0 "$RC"
"$BIN" show rt_svr > "$WORK/svr-after-arg.json"
assert_same "server unchanged after argument-form round trip" "$WORK/svr.json" "$WORK/svr-after-arg.json"

# 2. Piped form: show straight into import, no quoting and no length ceiling.
RC=0; "$BIN" show rt_svr | "$BIN" import rt_svr >/dev/null 2>&1 || RC=$?
assert_rc "server import (stdin form)" 0 "$RC"
"$BIN" show rt_svr > "$WORK/svr-after-pipe.json"
assert_same "server unchanged after piped round trip" "$WORK/svr.json" "$WORK/svr-after-pipe.json"

# 3. Change exactly one field and prove it took — and that nothing else moved.
#    Without this, an import that accepted the document and applied none of it
#    would pass every assertion above.
sed 's/"rate_limit": 3/"rate_limit": 77/' "$WORK/svr.json" > "$WORK/svr-edited.json"
if ! diff -q "$WORK/svr.json" "$WORK/svr-edited.json" >/dev/null; then ok; else bad "edit produced no change to import"; fi

RC=0; "$BIN" import rt_svr "$(cat "$WORK/svr-edited.json")" >/dev/null 2>&1 || RC=$?
assert_rc "server import (one field changed)" 0 "$RC"
"$BIN" show rt_svr > "$WORK/svr-after-edit.json"
assert_same "server took the edit and nothing else" "$WORK/svr-edited.json" "$WORK/svr-after-edit.json"

# ── CACHE ────────────────────────────────────────────────────────────────────
# A different document: persistent_path, cache_mode, max_memory, eviction.
# 4M, not 4mb.  It was written "4mb" here, and parse_size_suffix took the
# digits and dropped the rest — so this cache was configured to FOUR BYTES and
# the line read as four megabytes to everyone since.  Nothing caught it because
# this file asserts that the round trip preserves the value, never what the
# value is.  The parser refuses an unknown suffix now, which is what turned a
# silent misreading into a failing create and brought the typo up.
"$BIN" create cache rt_cache -p "$CACHE_PORT" \
    --maxmemory 4M --eviction allkeys-lru --mode admin \
    --persistent "$WORK/cache.aof" >/dev/null 2>&1

"$BIN" show rt_cache > "$WORK/cache.json"
assert_contains "cache document carries the cache-only fields" "$(cat "$WORK/cache.json")" '"eviction"'

RC=0; "$BIN" show rt_cache | "$BIN" import rt_cache >/dev/null 2>&1 || RC=$?
assert_rc "cache import (stdin form)" 0 "$RC"
"$BIN" show rt_cache > "$WORK/cache-after.json"
assert_same "cache unchanged after round trip" "$WORK/cache.json" "$WORK/cache-after.json"

sed 's/"eviction": "allkeys-lru"/"eviction": "allkeys-random"/' "$WORK/cache.json" \
    > "$WORK/cache-edited.json"
RC=0; "$BIN" import rt_cache "$(cat "$WORK/cache-edited.json")" >/dev/null 2>&1 || RC=$?
assert_rc "cache import (eviction changed)" 0 "$RC"
"$BIN" show rt_cache > "$WORK/cache-after-edit.json"
assert_same "cache took the eviction change and nothing else" \
    "$WORK/cache-edited.json" "$WORK/cache-after-edit.json"

# ── THE ORIGINAL SYMPTOM ─────────────────────────────────────────────────────
# The exact string the bug produced. `import` must be read as a command, so an
# unknown runtime name must be reported as the name — never as "import".
RC=0; OUT=$("$BIN" import no_such_runtime '{}' 2>&1) || RC=$?
assert_rc "import against a missing runtime exits 1" 1 "$RC"
assert_contains "the missing runtime is named, not the command" "$OUT" "runtime not found: no_such_runtime"
if grep -qF "runtime not found: import" <<<"$OUT"; then
    bad "'import' is still being treated as a runtime name"
else
    ok
fi

# An empty document is refused rather than applied as "clear every field".
RC=0; OUT=$(printf '' | "$BIN" import rt_svr 2>&1) || RC=$?
assert_rc "empty stdin document exits 1" 1 "$RC"

# ── A NUMBER THAT IS ONLY PARTLY A NUMBER ────────────────────────────────────
#
# json_get_int and its three siblings wrapped std::sto* in a try/catch, which
# caught "abc" and did nothing for "55abc": sto* stops at the first character it
# cannot use and returns what it read.  So a field with a typo in its tail was
# applied as the digits in front of it, and the document the operator edited did
# not mean what it said.
#
# The default is what an ABSENT key already gives, so a malformed value now
# behaves exactly like a missing one.  That is also no change for a value that
# will not parse at all — sto*("abc") already threw and already landed here.
"$BIN" import rt_svr \
    '{"name":"rt_svr","type":"server","port":'"$SVR_PORT"',"max_connections":"55abc"}' \
    >/dev/null 2>&1 || true
if "$BIN" show rt_svr | grep -q '"max_connections": 55'; then
    bad "a half-numeric value was applied as its prefix (max_connections became 55)"
else
    ok
fi

# Paired with it: a clean value still lands, or the assertion above would pass
# on a build that stopped reading numbers altogether.
"$BIN" import rt_svr \
    '{"name":"rt_svr","type":"server","port":'"$SVR_PORT"',"max_connections":42}' \
    >/dev/null 2>&1 || true
if "$BIN" show rt_svr | grep -q '"max_connections": 42'; then ok
else bad "a clean numeric value no longer imports (max_connections is not 42)"; fi

# ── A FIELD THE DOCUMENT DOES NOT MENTION IS NOT A FIELD BEING CLEARED ───────
#
# Every field in runtime_config has a default and import applied all of them,
# so a partial document cleared everything it left out.  Measured against a
# runtime with a port, a log path, two limits and a full TLS set:
#
#     socketley import c '{"name":"c"}'   -> exit 0, no output
#     ... and seven fields were gone, TLS among them.
#
# A runtime configured to speak TLS answered in cleartext afterwards, and the
# command that did it reported success.
"$BIN" remove rt_partial >/dev/null 2>&1 || true
"$BIN" create server rt_partial -p "$PARTIAL_PORT" \
    --max-conn 77 --idle-timeout 45 --log /tmp/rt_partial.log \
    --tls --cert /tmp/rt.pem --key /tmp/rt.key >/dev/null 2>&1
"$BIN" show rt_partial > "$WORK/partial-before.json"
"$BIN" import rt_partial '{"name":"rt_partial"}' >/dev/null 2>&1 || true
"$BIN" show rt_partial > "$WORK/partial-after.json"
assert_same "a document naming only the name changes nothing else" \
    "$WORK/partial-before.json" "$WORK/partial-after.json"

# And the escape hatch it replaces: clearing is still possible, written out.
# Without this the assertion above passes on a build where import stopped
# applying anything at all.
"$BIN" import rt_partial \
    '{"name":"rt_partial","tls":false,"cert_path":"","key_path":""}' >/dev/null 2>&1 || true
if "$BIN" show rt_partial | grep -q '"tls": true'; then
    bad "an explicit \"tls\": false no longer clears TLS"
else
    ok
fi

# ── A VALUE ENDING IN A BACKSLASH ────────────────────────────────────────────
#
# compact_json in the CLI decided a quote was a delimiter unless the character
# before it was a backslash — right for \" and wrong for \\", where the
# backslash is itself escaped and the quote really does close the string.  From
# there in_string stayed true, every newline survived, and IPC frames one
# command per line: the daemon got the first fragment as the whole import and
# the rest as commands of its own.  The fragment is truncated JSON, which
# parse_json_string accepted, so this exact round trip dropped every field after
# the backslash and reported success.
# A runtime of its own, and not the one above.  Written first against
# rt_partial, this assertion did not go red on the broken build at all: the
# partial-import case just before it had already cleared that runtime, so there
# was nothing left after log_file for the truncation to lose.  The fields have
# to sit AFTER the backslash in the document for their loss to be visible, and
# `show` emits log_file before max_connections and idle_timeout.
"$BIN" remove rt_bs >/dev/null 2>&1 || true
"$BIN" create server rt_bs -p "$BS_PORT" --max-conn 66 --idle-timeout 34 >/dev/null 2>&1
"$BIN" edit rt_bs --log 'C:\' >/dev/null 2>&1 || true
"$BIN" show rt_bs > "$WORK/bs-before.json"

# The document really does contain the escaped backslash, and the two fields
# that have to survive it really are behind it.  Without these the round-trip
# assertion below is about a case that never happened.  assert_contains greps
# -F, so the needle is the two literal characters the file holds.
assert_contains "the document carries an escaped backslash" \
    "$(cat "$WORK/bs-before.json")" 'C:\\'
assert_contains "a field sits behind the backslash to be lost" \
    "$(cat "$WORK/bs-before.json")" '"idle_timeout": 34'

"$BIN" show rt_bs | "$BIN" import rt_bs >/dev/null 2>&1 || true
"$BIN" show rt_bs > "$WORK/bs-after.json"
assert_same "a value ending in a backslash survives the round trip" \
    "$WORK/bs-before.json" "$WORK/bs-after.json"

# ── A NAME import MAY NOT GIVE ───────────────────────────────────────────────
#
# create() validated names and rename() — the door import comes through — did
# not, so import could produce a runtime whose name broke `ls --json` and whose
# state file collided with every other invalidly-named runtime in one shared
# invalid.json.
RC=0
OUT=$("$BIN" import rt_partial '{"name":"q\"uote/../x"}' 2>&1) || RC=$?
assert_rc "import refuses a name create would refuse" 1 "$RC"
assert_contains "the refusal names the rule, not 'already taken'" "$OUT" "invalid runtime name"

# The consequence, asserted directly: the listing has to stay parseable.
if "$BIN" ls --json 2>/dev/null | python3 -c 'import json,sys; json.load(sys.stdin)' 2>/dev/null; then
    ok
else
    bad "ls --json is not valid JSON"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
