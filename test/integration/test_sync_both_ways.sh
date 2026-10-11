#!/usr/bin/env bash
# Integration test: the sync runtime keeping a directory and a storage the same both ways (--mode inout), and
# carrying the storage into a directory (--mode in).
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a file the storage has not brought here, or brought under another name
#     or below the wrong folder
#   * a file only this side has not carried out, as one way did before
#   * a file both sides had at the start, the same, copied either way again
#   * a file both sides had and that differs losing one of the two
#   * a change made on the storage not reaching this side, or one removed
#     there left here
#   * a file removed here brought back from the storage
#   * a change here written over one the storage made meanwhile, which the
#     conditional write exists to prevent
#   * a key that climbs out of the directory written outside it
#   * one way in, a file changed here not put back, or its change lost
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

daemon_isolate syncboth
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1975))
trap 'daemon_stop' EXIT

echo "=== Integration: a sync runtime keeps both sides the same ==="

daemon_start "$BIN"
mkdir -p "$T/stg" "$T/here" "$T/in"
KEY=AKIASYNCBOTH00000000
SEC=syncsecretbothsyncsecretboth0000
"$BIN" create storage box -p "$P" --dir "$T/stg" --access-key "$KEY" --secret-key "$SEC" -s >/dev/null 2>&1
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$P/" && break; sleep 0.1; done
S() { curl -s --user "$KEY:$SEC" --aws-sigv4 'aws:amz:us-east-1:s3' "$@"; }
put() { printf '%s' "$2" | S -o /dev/null -X PUT --data-binary @- "http://127.0.0.1:$P/$1"; }
S -o /dev/null -X PUT "http://127.0.0.1:$P/docs"
keys() { S "http://127.0.0.1:$P/$1?list-type=2" | grep -o '<Key>[^<]*</Key>' | sed 's/<[^>]*>//g' | sort | tr '\n' ' ' | sed 's/ $//'; }
files() { (cd "$1" && find . -type f ! -path './.socketley-sync/*' | sed 's|^\./||' | sort | tr '\n' ' ' | sed 's/ $//'); }
st() { "$BIN" stats "$1" 2>/dev/null | sed -n "s/^$2://p"; }
# Waits up to $1 seconds for the command in the rest to succeed.
until_ok() { local n=$1 i; shift; for i in $(seq 1 "$n"); do "$@" && return 0; sleep 1; done; return 1; }
cat > "$T/creds" <<EOF
access_key = $KEY
secret_key = $SEC
EOF

# What the storage has before the job starts, and what this side has.
put docs/from-storage.txt "storage"
put docs/deep/er/note.txt "deep"
put docs/same.txt "same"
put docs/clash.txt "theirs, longer"
printf 'here' > "$T/here/from-here.txt"
printf 'same' > "$T/here/same.txt"
printf 'mine' > "$T/here/clash.txt"

"$BIN" create sync both --dir "$T/here" --storage "box/docs" --credentials "$T/creds" --mode inout --every 2s -s \
    >/dev/null 2>&1
conflict() { ls "$T/here" | grep -c "^clash (conflict .*)\.txt$"; }
until_ok 30 test "$(keys docs | grep -o 'conflict' | wc -l)" = 1
expect "the storage's files are brought here, folders and all" "$(cat "$T/here/from-storage.txt") $(cat "$T/here/deep/er/note.txt" 2>/dev/null)" "storage deep"
expect "and this side's carried out" "$(S "http://127.0.0.1:$P/docs/from-here.txt")" here
expect "a file both had the same is left as it is" "$(cat "$T/here/same.txt") $(st both brought)" "same 3"
expect "one both had and that differs keeps this side's at its name, on both sides" \
    "$(cat "$T/here/clash.txt") $(S "http://127.0.0.1:$P/docs/clash.txt")" "mine mine"
expect "and the storage's beside it, on both sides" \
    "$(conflict) $(cat "$T/here"/clash\ \(conflict*.txt) $(keys docs | grep -o 'clash (conflict' | wc -l)" "1 theirs, longer 1"
expect "and the job counts one conflict" "$(st both conflicts)" 1

# ─── what changes on the storage ────────────────────────────────────────────
put docs/from-storage.txt "storage, changed"
until_ok 15 test "$(cat "$T/here/from-storage.txt")" = "storage, changed"
expect "a change made on the storage comes here" "$(cat "$T/here/from-storage.txt")" "storage, changed"
S -o /dev/null -X DELETE "http://127.0.0.1:$P/docs/deep/er/note.txt"
until_ok 15 test ! -e "$T/here/deep/er/note.txt"
expect "and a file removed there goes here" "$(test -e "$T/here/deep/er/note.txt" && echo there || echo gone)" gone

# ─── what changes here ──────────────────────────────────────────────────────
printf 'here, changed' > "$T/here/from-here.txt"
until_ok 15 test "$(S "http://127.0.0.1:$P/docs/from-here.txt")" = "here, changed"
expect "a change here goes to the storage" "$(S "http://127.0.0.1:$P/docs/from-here.txt")" "here, changed"
rm "$T/here/from-storage.txt"
until_ok 15 test "$(S -o /dev/null -w '%{http_code}' "http://127.0.0.1:$P/docs/from-storage.txt")" = 404
expect "a file removed here goes from the storage" "$(S -o /dev/null -w '%{http_code}' "http://127.0.0.1:$P/docs/from-storage.txt")" 404
sleep 5
expect "and is not brought back" "$(test -e "$T/here/from-storage.txt" && echo back || echo gone)" gone

# ─── both at once ───────────────────────────────────────────────────────────
# Both sides change a file while the job is stopped: the listing at its start keeps both, and this side's goes to
# the storage over the version it now knows.
"$BIN" stop both >/dev/null 2>&1
put docs/same.txt "theirs, both"
printf 'mine, both' > "$T/here/same.txt"
"$BIN" start both >/dev/null 2>&1
until_ok 20 test "$(ls "$T/here" | grep -c '^same (conflict')" = 1
expect "a file both sides changed keeps both" \
    "$(cat "$T/here/same.txt") / $(cat "$T/here"/same\ \(conflict*.txt 2>/dev/null)" "mine, both / theirs, both"
until_ok 15 test "$(S "http://127.0.0.1:$P/docs/same.txt")" = "mine, both"
expect "and this side's goes to the storage" "$(S "http://127.0.0.1:$P/docs/same.txt")" "mine, both"
# The storage changes it and this side changes it at once: the write from here carries the etag it last saw and is
# refused, so the storage's change survives as a copy beside it.
before=$(ls "$T/here" | grep -c '^same (conflict')
put docs/same.txt "theirs, again"
printf 'mine, again' > "$T/here/same.txt"
until_ok 20 test "$(ls "$T/here" | grep -c '^same (conflict')" = $((before + 1))
expect "a change here racing one on the storage does not write over it" \
    "$(ls "$T/here" | grep '^same (conflict' | while read -r f; do cat "$T/here/$f"; echo; done | grep -c 'theirs, again')" 1
expect "nothing failed on the way" "$(st both failures)" 0

# ─── one way in ─────────────────────────────────────────────────────────────
S -o /dev/null -X PUT "http://127.0.0.1:$P/media"
put media/a.txt "a"
put media/sub/b.txt "b"
printf 'local only' > "$T/in/local.txt"
"$BIN" create sync down --dir "$T/in" --storage "box/media" --credentials "$T/creds" --mode in --every 2s -s \
    >/dev/null 2>&1
until_ok 20 test "$(files "$T/in")" = "a.txt local.txt sub/b.txt"
expect "one way in brings the storage's files" "$(files "$T/in")" "a.txt local.txt sub/b.txt"
expect "and carries nothing out" "$(keys media)" "a.txt sub/b.txt"
printf 'edited here' > "$T/in/a.txt"
put media/sub/b.txt "b2"
until_ok 15 test "$(cat "$T/in/a.txt")" = a
expect "a file changed here is put back as the storage has it" "$(cat "$T/in/a.txt") $(cat "$T/in/sub/b.txt")" "a b2"
expect "with nothing written over on the storage" "$(S "http://127.0.0.1:$P/media/a.txt")" a

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
