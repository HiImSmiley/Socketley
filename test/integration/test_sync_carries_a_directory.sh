#!/usr/bin/env bash
# Integration test: the sync runtime carrying a directory to a storage (--mode out).
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a type that cannot be made, shown, listed, stopped, started or removed,
#     or whose settings do not survive a restart of the daemon
#   * -p or --shards taken on a runtime that listens on nothing, and a missing
#     --dir, --storage or --credentials not refused at create
#   * a file in the directory not reaching the bucket, reaching it under the
#     wrong key, or arriving with other bytes than it has here
#   * a file below a subdirectory flattened, or one --exclude names carried --
#     after a space in the list, or below a directory it names
#   * a file carried again on the next walk although nothing about it changed,
#     which would send a whole directory every hour for ever
#   * a changed file NOT carried again -- the failure a size-only check makes
#   * a file deleted here left on the far side, which is what the index exists
#     to prevent, including across a restart of the runtime
#   * --prefix ignored, so two jobs into one bucket overwrite each other
#   * a storage that refuses the credentials failing silently rather than
#     counting and saying so
#   * a --storage naming a runtime of this daemon not reaching it, which needs
#     the port out of the map the daemon sends the worker and not a guess
#   * a mode that is not carried yet accepted at create and failing at start,
#     where the operator does not see the reason
#   * the index world-readable, or kept somewhere other than the state dir
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate sync1
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1970))
trap 'daemon_stop' EXIT

echo "=== Integration: a sync runtime carries a directory ==="

daemon_start "$BIN"
mkdir -p "$T/stg" "$T/src/sub"
KEY=AKIASYNCCARRY0000000
SEC=syncsecretcarrysyncsecretcarry00
"$BIN" create storage box -p "$P" --dir "$T/stg" --access-key "$KEY" --secret-key "$SEC" -s >/dev/null 2>&1
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$P/" && break; sleep 0.1; done
S() { curl -s --user "$KEY:$SEC" --aws-sigv4 'aws:amz:us-east-1:s3' "$@"; }
S -o /dev/null -X PUT "http://127.0.0.1:$P/photos"
# Every key in the bucket, sorted, on one line.
keys() { S "http://127.0.0.1:$P/photos" | grep -o '<Key>[^<]*</Key>' | sed 's/<[^>]*>//g' | sort | tr '\n' ' ' | sed 's/ $//'; }
# A field of the runtime's stats.
st() { "$BIN" stats up 2>/dev/null | sed -n "s/^$1://p"; }
# Waits up to $1 seconds for `st $2` to equal $3.
until_st() { local i; for i in $(seq 1 "$1"); do [ "$(st "$2")" = "$3" ] && return 0; sleep 1; done; return 1; }

printf 'one\n' > "$T/src/a.txt"
printf 'two\n' > "$T/src/sub/b.txt"
printf 'nope\n' > "$T/src/c.tmp"
mkdir -p "$T/src/node_modules/dep"
printf 'nope\n' > "$T/src/notes.md"
printf 'nope\n' > "$T/src/sub/old.md.bak"
printf 'nope\n' > "$T/src/node_modules/dep/index.js"
mkdir -p "$T/src/sub/node_modules"
printf 'nope\n' > "$T/src/sub/node_modules/deep.js"
cat > "$T/creds" <<EOF
# the key this job signs with
access_key = $KEY
secret_key = $SEC
EOF

# ─── what create refuses ────────────────────────────────────────────────────
expect "a sync with no --dir is refused" \
    "$("$BIN" create sync bad --storage "box/photos" --credentials "$T/creds" 2>&1 | grep -c -- '--dir')" 1
expect "with no --storage" \
    "$("$BIN" create sync bad --dir "$T/src" --credentials "$T/creds" 2>&1 | grep -c -- '--storage')" 1
expect "with no credentials" \
    "$("$BIN" create sync bad --dir "$T/src" --storage "box/photos" 2>&1 | grep -c -- '--credentials is required')" 1
expect "a --storage with no bucket" \
    "$("$BIN" create sync bad --dir "$T/src" --storage "box" --credentials "$T/creds" 2>&1 | grep -c 'bucket')" 1
expect "and a mode that is not carried yet, when it is made rather than at its first start" \
    "$("$BIN" create sync bad --dir "$T/src" --storage "box/photos" --credentials "$T/creds" --mode in 2>&1 | grep -c 'not carried yet')" 1
expect "a port, since it listens on nothing" \
    "$("$BIN" create sync bad -p 1234 --dir "$T/src" --storage "box/photos" --credentials "$T/creds" 2>&1 | grep -c -- '-p')" 1
expect "and --shards, which would write one index from several processes" \
    "$("$BIN" create sync bad --shards 4 --dir "$T/src" --storage "box/photos" --credentials "$T/creds" 2>&1 | grep -c -- '--shards')" 1
expect "none of the refused ones was made" "$("$BIN" ls 2>/dev/null | grep -c ' bad ')" 0

# ─── carrying ───────────────────────────────────────────────────────────────
"$BIN" create sync up --dir "$T/src" --storage "box/photos" --credentials "$T/creds" \
    --mode out --exclude '*.tmp, **.md*,node_modules' --every 2s -s >/dev/null 2>&1
until_st 30 carried 2
expect "the runtime runs and listens on no port" "$("$BIN" ls 2>/dev/null | grep ' up ' | grep -c 'sync')" 1
expect "both files are carried, none an --exclude pattern names" "$(keys)" "a.txt sub/b.txt"
expect "a file's bytes arrive as they are here" "$(S "http://127.0.0.1:$P/photos/sub/b.txt")" two
expect "and the index holds what was carried" "$(st indexed)" 2
expect "with nothing waiting and nothing failed" "$(st waiting) $(st failures)" "0 0"

# ─── a walk that finds nothing new ──────────────────────────────────────────
before=$(st carried)
sleep 5
expect "a file nothing changed about is not carried again" "$(st carried)" "$before"

# ─── a change, and a removal ────────────────────────────────────────────────
# The same length as before, so only the time says it changed.
printf 'ONE\n' > "$T/src/a.txt"
rm "$T/src/sub/b.txt"
until_st 30 removed 1
expect "a file whose bytes changed but not its length is carried again" "$(S "http://127.0.0.1:$P/photos/a.txt")" ONE
expect "a file deleted here is taken off the far side" "$(keys)" "a.txt"
expect "and the index says so" "$(st indexed)" 1

# ─── the index outlives the runtime ─────────────────────────────────────────
"$BIN" stop up >/dev/null 2>&1
"$BIN" start up >/dev/null 2>&1
for _ in $(seq 1 30); do [ -n "$(st indexed)" ] && break; sleep 1; done
sleep 4
expect "a runtime started again carries nothing it already had" "$(st carried) $(st indexed)" "0 1"
file=$(find "$HOME" -name 'up.index' -type f | head -1)
expect "the index is in the state directory, private" "$(stat -c %a "$file" 2>/dev/null) $(dirname "$file" | xargs basename)" "600 sync"

# ─── a prefix ───────────────────────────────────────────────────────────────
mkdir -p "$T/src2"
printf 'p\n' > "$T/src2/d.txt"
"$BIN" create sync pre --dir "$T/src2" --storage "box/photos" --credentials "$T/creds" \
    --prefix laptop --every 2s -s >/dev/null 2>&1
for _ in $(seq 1 30); do [ "$("$BIN" stats pre 2>/dev/null | sed -n 's/^carried://p')" = 1 ] && break; sleep 1; done
expect "--prefix puts the keys below it" "$(keys)" "a.txt laptop/d.txt"

# ─── an address instead of a runtime's name ─────────────────────────────────
mkdir -p "$T/src4" && printf 'addr\n' > "$T/src4/f.txt"
"$BIN" create sync byaddr --dir "$T/src4" --storage "127.0.0.1:$P/photos" --credentials "$T/creds" \
    --prefix byaddr --every 2s -s >/dev/null 2>&1
for _ in $(seq 1 30); do [ "$("$BIN" stats byaddr 2>/dev/null | sed -n 's/^carried://p')" = 1 ] && break; sleep 1; done
expect "a host and a port carry as a runtime's name does" "$(S "http://127.0.0.1:$P/photos/byaddr/f.txt")" addr
"$BIN" remove byaddr >/dev/null 2>&1

# ─── credentials the storage refuses ────────────────────────────────────────
sed "s/$SEC/wrongsecretwrongsecretwrongsec00/" "$T/creds" > "$T/bad.creds"
mkdir -p "$T/src3" && printf 'x\n' > "$T/src3/e.txt"
"$BIN" create sync no --dir "$T/src3" --storage "box/photos" --credentials "$T/bad.creds" --every 2s -s >/dev/null 2>&1
# An empty answer is a runtime that has not started yet, not a failure count of none.
for _ in $(seq 1 30); do v=$("$BIN" stats no 2>/dev/null | sed -n 's/^failures://p'); [ -n "$v" ] && [ "$v" != 0 ] && break; sleep 1; done
expect "a storage that refuses the signature is counted and said" \
    "$("$BIN" stats no 2>/dev/null | sed -n 's/^last_error://p' | grep -c '403')" 1
expect "and nothing of that job reached the bucket" "$(keys)" "a.txt byaddr/f.txt laptop/d.txt"

# ─── the configuration survives ─────────────────────────────────────────────
expect "show says what it was made with" \
    "$("$BIN" show up 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["mode"], d["exclude"], d["every"])')" \
    "out *.tmp, **.md*,node_modules 2"
"$BIN" remove no >/dev/null 2>&1
"$BIN" remove pre >/dev/null 2>&1
expect "a removed sync is gone" "$("$BIN" ls 2>/dev/null | grep -cE ' (no|pre) ')" 0

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
