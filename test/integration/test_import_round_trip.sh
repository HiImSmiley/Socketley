#!/usr/bin/env bash
# The CLI had no dispatch case for `import`, so the word was sent as the name
# of a runtime to act on and the documented workflow was broken while the
# daemon half ran every day through interactive `edit` -- and a hand-written
# blob would not catch it, because `show` pretty-prints and IPC frames one
# command per line; so every assertion starts from real `show` output and ends
# by comparing it, in two halves, since identity alone would call an import
# that applies nothing a pass, run against two runtime types whose documents do
# not have the same shape.
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

# The document really is multi-line, which is the property that made the naive
# forward truncate it.
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

# Change exactly one field and prove it took with nothing else moving, without
# which an import that applied none of the document would pass every assertion
# above.
sed 's/"rate_limit": 3/"rate_limit": 77/' "$WORK/svr.json" > "$WORK/svr-edited.json"
if ! diff -q "$WORK/svr.json" "$WORK/svr-edited.json" >/dev/null; then ok; else bad "edit produced no change to import"; fi

RC=0; "$BIN" import rt_svr "$(cat "$WORK/svr-edited.json")" >/dev/null 2>&1 || RC=$?
assert_rc "server import (one field changed)" 0 "$RC"
"$BIN" show rt_svr > "$WORK/svr-after-edit.json"
assert_same "server took the edit and nothing else" "$WORK/svr-edited.json" "$WORK/svr-after-edit.json"

# ── CACHE ────────────────────────────────────────────────────────────────────
# 4M and not 4mb, because parse_size_suffix took the digits and dropped the
# rest -- so this cache was configured to four bytes and read as four
# megabytes, which nothing caught since this file asserts the round trip
# preserves a value and never what the value is.
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
if ! diff -q "$WORK/cache.json" "$WORK/cache-edited.json" >/dev/null; then ok; else bad "eviction edit produced no change to import"; fi
RC=0; "$BIN" import rt_cache "$(cat "$WORK/cache-edited.json")" >/dev/null 2>&1 || RC=$?
assert_rc "cache import (eviction changed)" 0 "$RC"
"$BIN" show rt_cache > "$WORK/cache-after-edit.json"
assert_same "cache took the eviction change and nothing else" \
    "$WORK/cache-edited.json" "$WORK/cache-after-edit.json"

# ── THE ORIGINAL SYMPTOM ─────────────────────────────────────────────────────
# The exact string the bug produced: `import` must be read as a command, so an
# unknown runtime name is reported as the name.
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

# std::sto* stops at the first character it cannot use and returns what it
# read, so a field with a typo in its tail was applied as the digits in front
# of it -- and a malformed value now behaves exactly like a missing one.
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

# Every field has a default and import applied all of them, so a partial
# document cleared everything it left out -- a runtime configured to speak TLS
# answered in cleartext afterwards and the command reported success.
"$BIN" remove rt_partial >/dev/null 2>&1 || true
"$BIN" create server rt_partial -p "$PARTIAL_PORT" \
    --max-conn 77 --idle-timeout 45 --log "$WORK/rt_partial.log" \
    --tls --cert /tmp/rt.pem --key /tmp/rt.key >/dev/null 2>&1
"$BIN" show rt_partial > "$WORK/partial-before.json"
# Without TLS on before the import, both checks below would hold for a runtime that never had it.
if grep -q '"tls": true' "$WORK/partial-before.json"; then ok
else bad "the partial-import runtime starts with TLS on"; fi
"$BIN" import rt_partial '{"name":"rt_partial"}' >/dev/null 2>&1 || true
"$BIN" show rt_partial > "$WORK/partial-after.json"
assert_same "a document naming only the name changes nothing else" \
    "$WORK/partial-before.json" "$WORK/partial-after.json"

# The escape hatch it replaces: clearing is still possible, written out,
# without which the assertion above passes on a build where import stopped
# applying anything.
"$BIN" import rt_partial \
    '{"name":"rt_partial","tls":false,"cert_path":"","key_path":""}' >/dev/null 2>&1 || true
if "$BIN" show rt_partial | grep -q '"tls": true'; then
    bad "an explicit \"tls\": false no longer clears TLS"
else
    ok
fi

# ── A VALUE ENDING IN A BACKSLASH ────────────────────────────────────────────
# compact_json read a quote as a delimiter unless the previous character was a
# backslash, which is wrong for an escaped backslash, so the daemon got the
# first fragment as the whole import and the rest as commands of its own -- and
# it needs a runtime of its own, because the fields have to sit after the
# backslash in the document for their loss to be visible.
"$BIN" remove rt_bs >/dev/null 2>&1 || true
"$BIN" create server rt_bs -p "$BS_PORT" --max-conn 66 --idle-timeout 34 >/dev/null 2>&1
# Absolute, because --log now refuses a relative path -- a relative one
# resolves against the DAEMON's working directory, and this fixture used to
# leave a file called C:\ in the repository root once --log started opening
# the file it was given.  The fixture is about the trailing backslash in the
# JSON and nothing else, so where it points does not matter.
"$BIN" edit rt_bs --log "$WORK/C:\\" >/dev/null 2>&1 || true
"$BIN" show rt_bs > "$WORK/bs-before.json"

# The document really does contain the escaped backslash and the two fields
# that must survive it really are behind it, or the round-trip assertion below
# is about a case that never happened.
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

# ── A PARTIAL DOCUMENT AGAINST A RUNNING RUNTIME ────────────────────────────
#
# "A field the document does not mention is left alone. Only what is named is
# applied, so a partial document changes only those fields." The apply below
# follows that -- every setter is `if (has(key))` -- and the restart checks
# above it did not: they compared cfg.port, cfg.tls, cfg.shards and four more
# against the instance, and a field the document omits arrives as the PARSER'S
# DEFAULT.  So port 0 read as "change the port to 0" and a runtime running on
# any port at all was answered
#
#     cannot change port while running
#
# for a change nobody had asked for.  Measured: the identical document applied
# cleanly against the same runtime stopped, and left the port where it was --
# which is what says it is the check and not the document.
RP=$((SL_PORT_BASE+826))
"$BIN" remove rt_run >/dev/null 2>&1 || true
"$BIN" create server rt_run -p "$RP" -s >/dev/null 2>&1
sleep 0.8

RC=0
OUT=$("$BIN" import rt_run '{"name":"rt_run","max_connections":42}' 2>&1) || RC=$?
assert_rc "a partial document is applied to a running runtime" 0 "$RC"
assert_contains "and the field it named took" \
    "$("$BIN" show rt_run 2>/dev/null)" '"max_connections": 42'
assert_contains "while the port it did not name is untouched" \
    "$("$BIN" show rt_run 2>/dev/null)" "\"port\": $RP"

# The other half, or a build that had simply dropped the checks would pass
# everything above: a document that NAMES a different value for one of them is
# still refused, by its own sentence.
RC=0; OUT=$("$BIN" import rt_run "{\"name\":\"rt_run\",\"port\":$((RP+5))}" 2>&1) || RC=$?
assert_rc "a port the document does name is still refused while running" 1 "$RC"
assert_contains "with the sentence that belongs to it" "$OUT" "cannot change port while running"

RC=0; OUT=$("$BIN" import rt_run '{"name":"rt_run","shards":4}' 2>&1) || RC=$?
assert_rc "and so is a shard count" 1 "$RC"
assert_contains "with its own" "$OUT" "cannot change the shard count while running"

RC=0; OUT=$("$BIN" import rt_run '{"name":"rt_run","udp":true}' 2>&1) || RC=$?
assert_rc "and a protocol" 1 "$RC"

# Naming the value it already has is not a change and must not be read as one.
RC=0; OUT=$("$BIN" import rt_run "{\"name\":\"rt_run\",\"port\":$RP}" 2>&1) || RC=$?
assert_rc "naming the port it already has is accepted" 0 "$RC"

"$BIN" stop rt_run >/dev/null 2>&1 || true
"$BIN" remove rt_run >/dev/null 2>&1 || true

# A document refused for a field after its new name changes nothing, the name included.
"$BIN" create server rn_a -p $((SL_PORT_BASE+827)) >/dev/null 2>&1 || true
RC=0; OUT=$("$BIN" import rn_a '{"name":"rn_b","log_file":"relative.log"}' 2>&1) || RC=$?
assert_rc "a document with a relative log file is refused" 1 "$RC"
if "$BIN" ls --name 2>/dev/null | grep -qx rn_a && ! "$BIN" ls --name 2>/dev/null | grep -qx rn_b; then ok
else bad "a refused import leaves the name it had (ls: $("$BIN" ls --name 2>/dev/null | tr '\n' ' '))"; fi
"$BIN" remove rn_a >/dev/null 2>&1 || true; "$BIN" remove rn_b >/dev/null 2>&1 || true

# ── A NAME OTHERS RELY ON ───────────────────────────────────────────────────
#
# A proxy naming a runtime as its backend, and a server naming a cache, are left naming nothing by its rename; it is
# refused with each of them said, and taken once nothing names it.
"$BIN" create cache rn_kv -p $((SL_PORT_BASE+828)) >/dev/null 2>&1 || true
"$BIN" create server rn_web -p $((SL_PORT_BASE+829)) --cache rn_kv >/dev/null 2>&1 || true
"$BIN" create proxy rn_px -p $((SL_PORT_BASE+830)) --backend rn_web >/dev/null 2>&1 || true
RC=0; OUT=$("$BIN" import rn_kv '{"name":"rn_kv2"}' 2>&1) || RC=$?
assert_rc "a runtime another names is not renamed" 1 "$RC"
assert_contains "and what names it is said" "$OUT" "rn_web --cache rn_kv"
RC=0; OUT=$("$BIN" import rn_web '{"name":"rn_web2"}' 2>&1) || RC=$?
assert_contains "a proxy's backend is one that names it" "$OUT" "rn_px --backend rn_web"
"$BIN" remove rn_px >/dev/null 2>&1 || true
RC=0; "$BIN" import rn_web '{"name":"rn_web2"}' >/dev/null 2>&1 || RC=$?
assert_rc "with nothing naming it, it is renamed" 0 "$RC"
"$BIN" remove rn_web2 >/dev/null 2>&1 || true; "$BIN" remove rn_web >/dev/null 2>&1 || true; "$BIN" remove rn_kv >/dev/null 2>&1 || true
"$BIN" create idp rn_auth -p $((SL_PORT_BASE+831)) --issuer https://auth.example.test >/dev/null 2>&1 || true
"$BIN" create tunnel rn_edge --mode edge -p $((SL_PORT_BASE+832)) --idp rn_auth >/dev/null 2>&1 || true
RC=0; OUT=$("$BIN" import rn_auth '{"name":"rn_auth2"}' 2>&1) || RC=$?
assert_rc "an idp an edge signs people in at is not renamed" 1 "$RC"
assert_contains "and the edge is said" "$OUT" "rn_edge --idp rn_auth"
"$BIN" remove rn_edge >/dev/null 2>&1 || true; "$BIN" remove rn_auth >/dev/null 2>&1 || true

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
